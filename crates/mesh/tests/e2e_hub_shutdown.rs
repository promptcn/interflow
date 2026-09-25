//! E2E: hub graceful shutdown (`run_until` + drain).
//!
//! - After the shutdown signal fires, `run_until` returns Ok within the time
//!   limit and the port is immediately rebindable
//! - Registered agents notice the disconnect (enter Reconnecting) and can be
//!   cleanly closed out via `shutdown_graceful`
//! - QUIC path: endpoint close (CONNECTION_CLOSE) → agent disconnect + UDP
//!   port release

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
use interflow_mesh::agent::{AgentClient, AgentState};
use interflow_mesh::config::{EgressRule, EgressTarget, TransportKind};
use interflow_mesh::hub::HubServer;
use interflow_testkit::{
    agent_config, agent_quic_config, echo_server, hub_config, hub_quic_config, wait_agent_connected,
};
use std::time::Duration;
use tokio_util::sync::CancellationToken;

fn certs() -> &'static interflow_testkit::certs::TestCerts {
    static C: std::sync::OnceLock<interflow_testkit::certs::TestCerts> = std::sync::OnceLock::new();
    C.get_or_init(|| interflow_testkit::certs::TestCerts::generate("e2e", "agent"))
}

/// `run_until`: an idle hub returns Ok within the time limit after shutdown
/// and releases its port.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn hub_run_until_returns_and_releases_port() {
    // Port 0 = kernel-assigned at bind: no pick-then-bind race window under
    // parallel `cargo test` (the readiness signal carries the real address).
    let cfg = hub_config(0, certs(), vec![]);
    let server = HubServer::new(cfg).expect("hub build");

    let token = CancellationToken::new();
    let (ready_tx, ready_rx) = tokio::sync::oneshot::channel();
    let hub_task = {
        let token = token.clone();
        tokio::spawn(async move { server.run_until_signalled(token, ready_tx).await })
    };
    // The signal IS the readiness contract (TCP bound + QUIC up) — no port
    // probing needed.
    let hub_port = ready_rx.await.expect("hub listeners ready").tcp.port();

    token.cancel();
    let result = tokio::time::timeout(Duration::from_secs(15), hub_task)
        .await
        .expect("run_until should return within 15s")
        .expect("hub task join")
        .expect("run_until should return Ok");
    let _ = result; // Result<(), InterflowError>: Ok(()) carries no payload

    // Port released (immediately rebindable)
    let relisted = std::net::TcpListener::bind(("127.0.0.1", hub_port));
    assert!(
        relisted.is_ok(),
        "the port must be immediately rebindable after shutdown"
    );
}

/// Shutdown with a registered agent present: the drain completes, the agent
/// notices the disconnect, and it can be gracefully closed out.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn hub_shutdown_drains_registered_agent() {
    let (echo_addr, _echo) = echo_server().await;

    // Port 0 = kernel-assigned; the readiness signal carries the real port.
    let cfg = hub_config(0, certs(), vec![]);
    let server = HubServer::new(cfg).expect("hub build");
    let token = CancellationToken::new();
    let (ready_tx, ready_rx) = tokio::sync::oneshot::channel();
    let hub_task = {
        let token = token.clone();
        tokio::spawn(async move { server.run_until_signalled(token, ready_tx).await })
    };
    let hub_port = ready_rx.await.expect("hub listeners ready").tcp.port();

    // egress agent connects directly to the hub
    let mut agent_cfg = agent_config("egress", hub_port, certs());
    agent_cfg.agent.transport = TransportKind::H2;
    agent_cfg.egress = vec![EgressRule {
        name: "echo".into(),
        target: EgressTarget::Addr(echo_addr),
        target_protocol: StreamProto::Tcp,
        udp_idle_timeout_secs: None,
    }];
    let agent = AgentClient::new(agent_cfg).expect("agent build").start();

    // Wait for the agent to be Connected (registration done, h2 connection
    // present)
    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    loop {
        if matches!(agent.state(), AgentState::Connected { .. }) {
            break;
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "agent did not connect within 10s (state: {:?})",
            agent.state()
        );
        tokio::time::sleep(Duration::from_millis(100)).await;
    }

    // Shutdown: the drain (GOAWAY + grace) should complete within the limit
    token.cancel();
    tokio::time::timeout(Duration::from_secs(15), hub_task)
        .await
        .expect("run_until should return within 15s")
        .expect("hub task join")
        .expect("run_until should return Ok");

    // The agent notices the disconnect: the h2 connection is closed →
    // Reconnecting (backoff >= 1s; polling can catch it)
    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    loop {
        if !matches!(agent.state(), AgentState::Connected { .. }) {
            break;
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "agent did not notice the hub shutdown within 10s (still Connected)"
        );
        tokio::time::sleep(Duration::from_millis(100)).await;
    }

    // The agent can be cleanly closed out (no hang despite the hub being dead)
    tokio::time::timeout(Duration::from_secs(5), agent.shutdown_graceful())
        .await
        .expect("shutdown_graceful should complete within 10s")
        .expect("shutdown_graceful Ok");
}

/// QUIC-path shutdown: endpoint close (CONNECTION_CLOSE delivered to the
/// agent) → drain completes, the agent notices the disconnect, and the UDP
/// port is released.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn hub_shutdown_closes_quic_endpoint() {
    let (echo_addr, _echo) = echo_server().await;

    // Port 0 = kernel-assigned; the readiness signal carries the real port
    // (QUIC shares it as the dual-stack second listener).
    let cfg = hub_quic_config(0, certs(), Vec::new());
    let server = HubServer::new(cfg).expect("hub build");
    let token = CancellationToken::new();
    let (ready_tx, ready_rx) = tokio::sync::oneshot::channel();
    let hub_task = {
        let token = token.clone();
        tokio::spawn(async move { server.run_until_signalled(token, ready_tx).await })
    };
    let hub_port = ready_rx.await.expect("hub listeners ready").tcp.port();

    // QUIC egress agent
    let mut agent_cfg = agent_quic_config("shutdown-egress", hub_port, certs());
    agent_cfg.egress = vec![EgressRule {
        name: "echo".into(),
        target: EgressTarget::Addr(echo_addr),
        target_protocol: StreamProto::Tcp,
        udp_idle_timeout_secs: None,
    }];
    let agent = interflow_testkit::spawn_agent(agent_cfg);
    assert!(
        wait_agent_connected(&agent, Duration::from_secs(15)).await,
        "QUIC agent did not connect within 15s (state: {:?})",
        agent.state()
    );

    token.cancel();
    tokio::time::timeout(Duration::from_secs(15), hub_task)
        .await
        .expect("run_until should return within 15s")
        .expect("hub task join")
        .expect("run_until should return Ok");

    // The agent notices the CONNECTION_CLOSE → leaves Connected
    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    loop {
        if !matches!(agent.state(), AgentState::Connected { .. }) {
            break;
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "QUIC agent did not notice the hub shutdown within 10s (still Connected)"
        );
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    tokio::time::timeout(Duration::from_secs(5), agent.shutdown_graceful())
        .await
        .expect("shutdown_graceful should complete within 10s")
        .expect("shutdown_graceful Ok");

    // The QUIC UDP port is released (same number as the TCP one; the quinn
    // driver releases its socket asynchronously — wait boundedly for the
    // rebind to succeed)
    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    loop {
        if std::net::UdpSocket::bind(("127.0.0.1", hub_port)).is_ok() {
            break;
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "the QUIC UDP port should be rebindable within 5s after shutdown"
        );
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}
