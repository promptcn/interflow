//! Platform smoke: the path a production agent node actually runs, on
//! every CI platform.
//!
//! `home-win` is a Windows mesh agent in production; until this test the
//! Windows platform had zero automated coverage. The smoke is deliberately
//! minimal and platform-neutral: an h2 hub and two agents over loopback,
//! an agent registers, carries one TCP stream end to end (ingress →
//! hub → egress → echo), is stopped and restarted, re-registers and
//! carries a stream again. No signals, no process spawning, no
//! filesystem-permission semantics — exactly the surface a Windows node
//! exercises, nothing a Windows runner cannot.
//!
//! Cheap enough (seconds) to run everywhere; the Windows CI job runs it
//! beside the pure-assembly tests as its tier-2 gate.

#![allow(
    clippy::all,
    clippy::pedantic,
    clippy::nursery,
    clippy::panic,
    clippy::unwrap_used,
    clippy::expect_used,
    missing_docs
)]

use interflow_core::protocol::StreamProto;
use interflow_mesh::agent::AgentClient;
use interflow_mesh::agent::handle::AgentHandle;
use interflow_mesh::config::{AgentConfig, EgressRule, EgressTarget, IngressRule};
use interflow_testkit::{agent_config, hub_config, spawn_hub, wait_agent_connected, wait_for_tcp};
use std::net::SocketAddr;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

fn certs() -> &'static interflow_testkit::certs::TestCerts {
    static C: std::sync::OnceLock<interflow_testkit::certs::TestCerts> = std::sync::OnceLock::new();
    C.get_or_init(|| interflow_testkit::certs::TestCerts::generate("e2e", "platform-smoke"))
}

fn free_port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

fn egress_config(hub_port: u16, echo: SocketAddr) -> AgentConfig {
    let mut cfg = agent_config("smoke-egress", hub_port, certs());
    cfg.egress = vec![EgressRule {
        name: "echo".to_string(),
        target: EgressTarget::Addr(echo),
        target_protocol: StreamProto::Tcp,
        udp_idle_timeout_secs: None,
    }];
    cfg
}

fn ingress_config(hub_port: u16, listen: SocketAddr, echo: SocketAddr) -> AgentConfig {
    let mut cfg = agent_config("smoke-ingress", hub_port, certs());
    cfg.ingress = vec![IngressRule {
        name: "echo".to_string(),
        listen_addr: listen,
        listen_protocol: StreamProto::Tcp,
        target_agent: "smoke-egress".to_string(),
        remote_addr: Some(echo.to_string()),
        idle_timeout_secs: None,
        udp_per_ip_pps: 0,
        udp_per_ip_bytes_per_sec: 0,
        udp_egress_bytes_per_sec: 0,
    }];
    cfg
}

async fn start_connected(cfg: AgentConfig) -> AgentHandle {
    let handle = AgentClient::new(cfg).expect("agent build").start();
    assert!(
        wait_agent_connected(&handle, Duration::from_secs(15)).await,
        "agent must register within 15s: {:?}",
        handle.state()
    );
    handle
}

/// One TCP roundtrip through ingress → hub → egress → echo.
async fn echo_roundtrip(listen: SocketAddr, payload: &[u8]) {
    wait_for_tcp(listen, Duration::from_secs(10))
        .await
        .expect("ingress listener accepts");
    let echoed = tokio::time::timeout(Duration::from_secs(15), async {
        let mut client = tokio::net::TcpStream::connect(listen).await.unwrap();
        client.write_all(payload).await.unwrap();
        let mut echoed = vec![0u8; payload.len()];
        client.read_exact(&mut echoed).await.unwrap();
        echoed
    })
    .await
    .expect("the stream completes within 15s");
    assert_eq!(echoed, payload, "the echo path returns the payload intact");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn agent_registers_carries_a_stream_and_recovers_from_a_restart() {
    let hub = spawn_hub(hub_config(0, certs(), vec![])).await;
    let hub_port = hub.local_addr().expect("hub bound").port();
    let (echo, _echo_task) = interflow_testkit::echo_server().await;
    let listen: SocketAddr = format!("127.0.0.1:{}", free_port()).parse().unwrap();

    // Register: the far end first, then the node under test.
    let egress = start_connected(egress_config(hub_port, echo)).await;
    let ingress = start_connected(ingress_config(hub_port, listen, echo)).await;

    // One stream end to end.
    echo_roundtrip(listen, b"platform-smoke: first life").await;

    // Stop and restart the node (the operator restart / crash-recovery
    // shape): it re-registers under the same id and carries traffic again.
    ingress.shutdown_graceful().await.expect("ingress shutdown");
    let ingress = start_connected(ingress_config(hub_port, listen, echo)).await;
    echo_roundtrip(listen, b"platform-smoke: second life").await;

    ingress
        .shutdown_graceful()
        .await
        .expect("ingress shutdown 2");
    egress.shutdown_graceful().await.expect("egress shutdown");
}
