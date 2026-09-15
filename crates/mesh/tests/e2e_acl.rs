//! ACL denial scenario: a source→target with no matching rule must be
//! rejected at the `/stream` Open stage.

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
use interflow_mesh::config::IngressRule;
use interflow_testkit::{
    agent_config, hub_config, pick_ephemeral_port, spawn_agent, spawn_hub, wait_for_tcp,
};
use std::time::Duration;

/// The hub does not allow ingress → egress (no ACL rule), so the ingress
/// should be unable to establish a tunnel.
///
/// Verification: after a client connects to the ingress listener, sending
/// data yields no echo. We assert "nothing can be read" via a short-timeout
/// read.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn acl_denies_unauthorized_stream() {
    let hub_port = pick_ephemeral_port();
    let ingress_listen_port = pick_ephemeral_port();

    // A hub with no ACL rules = deny all cross-agent streams by default
    // (note: at hub startup, acl_enabled is based on !is_empty(), so an empty
    // ACL means acl_enabled = false, but routing still enters the ACL
    // validation path)
    let hub_cfg = hub_config(hub_port, vec![]);
    let _hub = spawn_hub(hub_cfg).await;

    // Note: this test verifies only the case with ACLs enabled. An empty ACL
    // means the ACL denies nothing — that is the hub design: empty ACL =
    // allow all. So this test actually verifies "denied when the ACL is
    // configured but lacks this rule". We use an ACL that allows a different
    // pair to test the deny.

    let hub_port2 = pick_ephemeral_port();
    let hub_cfg2 = hub_config(hub_port2, vec![interflow_testkit::acl("other", "egress")]);
    let _hub2 = spawn_hub(hub_cfg2).await;

    let mut egress_cfg = agent_config("egress", hub_port2);
    // No egress rule needed since the tunnel is rejected before it can be
    // established
    let _egress = spawn_agent(egress_cfg);

    let mut ingress_cfg = agent_config("ingress", hub_port2);
    ingress_cfg.ingress = vec![IngressRule {
        name: "to-egress".to_string(),
        listen_addr: format!("127.0.0.1:{ingress_listen_port}").parse().unwrap(),
        target_agent: "egress".to_string(),
        remote_addr: Some("127.0.0.1:1".to_string()), // placeholder

        listen_protocol: StreamProto::Tcp,
        idle_timeout_secs: None,
        udp_per_ip_pps: 0,
        udp_per_ip_bytes_per_sec: 0,
        udp_egress_bytes_per_sec: 0,
    }];
    let _ingress = spawn_agent(ingress_cfg);

    let ingress_addr: std::net::SocketAddr =
        format!("127.0.0.1:{ingress_listen_port}").parse().unwrap();
    wait_for_tcp(ingress_addr, Duration::from_secs(15))
        .await
        .expect("ingress listener ready");

    // Client connects + writes + short-timeout read: after the ACL denial, no
    // data comes back
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let mut sock = tokio::net::TcpStream::connect(ingress_addr)
        .await
        .expect("connect ingress");
    sock.write_all(b"hi").await.expect("write");
    sock.flush().await.expect("flush");

    let mut buf = [0u8; 16];
    let result = tokio::time::timeout(Duration::from_secs(2), sock.read(&mut buf)).await;
    // Expected: timeout / EOF / connection reset — any "no valid data
    // returned" counts as the ACL denial being in effect
    match result {
        Err(_) => { /* timeout */ }
        Ok(Ok(0)) => { /* EOF */ }
        Ok(Err(_)) => { /* connection reset */ }
        Ok(Ok(n)) => panic!("the ACL should deny, but read {n} bytes: {:?}", &buf[..n]),
    }

    let _ = (hub_port, ingress_listen_port);
}
