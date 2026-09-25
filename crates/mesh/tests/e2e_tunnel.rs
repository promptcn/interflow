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
use interflow_mesh::config::{EgressRule, EgressTarget, IngressRule};
use interflow_testkit::{
    agent_config, echo_round_trip, echo_server, hub_config, spawn_agent_registered, spawn_hub,
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

    // 2. Hub: port 0 = kernel-assigned at bind (no pick-then-bind race)
    let hub_cfg = hub_config(0, certs(), Vec::new());
    let _hub = spawn_hub(hub_cfg).await;
    let hub_port = _hub.local_addr().expect("hub bound").port();

    // 3. Egress agent: forwards requests to the echo server
    let mut egress_cfg = agent_config("egress", hub_port, certs());
    egress_cfg.egress = vec![EgressRule {
        name: "echo".to_string(),
        target: EgressTarget::Addr(echo_addr),

        target_protocol: StreamProto::Tcp,
        udp_idle_timeout_secs: None,
    }];
    let _egress = spawn_agent_registered(egress_cfg).await;

    // 4. Ingress agent: listens on a kernel-assigned local port and forwards
    // streams to the egress agent
    let mut ingress_cfg = agent_config("ingress", hub_port, certs());
    ingress_cfg.ingress = vec![IngressRule {
        name: "to-egress".to_string(),
        listen_addr: "127.0.0.1:0".parse().unwrap(),
        target_agent: "egress".to_string(),
        remote_addr: Some(echo_addr.to_string()),

        listen_protocol: StreamProto::Tcp,
        idle_timeout_secs: None,
        udp_per_ip_pps: 0,
        udp_per_ip_bytes_per_sec: 0,
        udp_egress_bytes_per_sec: 0,
    }];
    let _ingress = spawn_agent_registered(ingress_cfg).await;
    // The bound-address report IS the readiness contract — no TCP probing.
    let ingress_addr = _ingress
        .wait_ingress_addr("to-egress", Duration::from_secs(15))
        .await
        .expect("ingress listener bound");

    // 5. Send data and expect it back unchanged
    let payload = b"hello interflow tunnel\n".repeat(4);
    let response = echo_round_trip(ingress_addr, &payload)
        .await
        .expect("round trip");
    assert_eq!(response, payload);
}
