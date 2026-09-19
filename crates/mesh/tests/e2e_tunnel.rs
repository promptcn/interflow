//! End-to-end tunnel test: hub + ingress agent + egress agent + echo backend,
//! verifying that TCP traffic crosses the tunnel byte for byte.

#![allow(
    clippy::all,
    clippy::pedantic,
    clippy::nursery,
    clippy::panic,
    clippy::unwrap_used,
    clippy::expect_used,
    missing_docs,
    dead_code,
    unused_mut
)]
use interflow_core::protocol::StreamProto;
use interflow_mesh::config::{EgressRule, IngressRule};
use interflow_testkit::{
    agent_config, echo_round_trip, echo_server, hub_config, pick_ephemeral_port,
    spawn_agent_registered, spawn_hub, wait_for_tcp,
};
use std::time::Duration;

fn certs() -> &'static interflow_testkit::certs::TestCerts {
    static C: std::sync::OnceLock<interflow_testkit::certs::TestCerts> = std::sync::OnceLock::new();
    C.get_or_init(|| interflow_testkit::certs::TestCerts::generate("e2e", "agent"))
}

/// Top-level scenario: client → ingress → hub → egress → echo backend,
/// returned unchanged.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn full_tunnel_echo_round_trip() {
    // 1. Backend echo server
    let (echo_addr, _echo_handle) = echo_server().await;

    // 2. Ports for each component
    let hub_port = pick_ephemeral_port();
    let ingress_listen_port = pick_ephemeral_port();

    // 3. Hub config: allow ingress → egress
    let hub_cfg = hub_config(hub_port, certs(), Vec::new());
    let _hub = spawn_hub(hub_cfg).await;

    // 4. Egress agent: forwards requests to the echo server
    let mut egress_cfg = agent_config("egress", hub_port, certs());
    egress_cfg.egress = vec![EgressRule {
        name: "echo".to_string(),
        target_addr: echo_addr,

        target_protocol: StreamProto::Tcp,
        udp_idle_timeout_secs: None,
    }];
    let _egress = spawn_agent_registered(egress_cfg).await;

    // 5. Ingress agent: listens on a local port and forwards streams to the
    // egress agent
    let mut ingress_cfg = agent_config("ingress", hub_port, certs());
    ingress_cfg.ingress = vec![IngressRule {
        name: "to-egress".to_string(),
        listen_addr: format!("127.0.0.1:{ingress_listen_port}").parse().unwrap(),
        target_agent: "egress".to_string(),
        remote_addr: Some(echo_addr.to_string()),

        listen_protocol: StreamProto::Tcp,
        idle_timeout_secs: None,
        udp_per_ip_pps: 0,
        udp_per_ip_bytes_per_sec: 0,
        udp_egress_bytes_per_sec: 0,
    }];
    let _ingress = spawn_agent_registered(ingress_cfg).await;

    // 6. Wait for the ingress listener to be ready
    let ingress_addr: std::net::SocketAddr =
        format!("127.0.0.1:{ingress_listen_port}").parse().unwrap();
    wait_for_tcp(ingress_addr, Duration::from_secs(15))
        .await
        .expect("ingress listener ready");

    // 7. Send data and expect it back unchanged
    let payload = b"hello interflow tunnel\n".repeat(4);
    let response = echo_round_trip(ingress_addr, &payload)
        .await
        .expect("round trip");
    assert_eq!(response, payload);
}
