//! mTLS authentication scenarios: a client certificate issued by an
//! untrusted CA must never register; the trusted-CA control case registers.

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
use interflow_mesh::agent::AgentState;
use interflow_testkit::{
    agent_config, certs::TestCerts, hub_config, pick_ephemeral_port, spawn_agent,
};
use std::time::Duration;
use tokio::net::TcpStream;

fn certs() -> &'static TestCerts {
    static C: std::sync::OnceLock<TestCerts> = std::sync::OnceLock::new();
    C.get_or_init(|| TestCerts::generate("e2e-auth", "good-agent"))
}

/// An agent whose certificate comes from a CA the hub does not trust fails
/// the TLS handshake itself — the reconnect loop keeps failing and the agent
/// never reaches Connected.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn untrusted_ca_agent_fails_to_register() {
    let hub_port = pick_ephemeral_port();
    let hub_cfg = hub_config(hub_port, certs(), vec![]);
    let _hub = interflow_testkit::spawn_hub(hub_cfg).await;

    // A different TestCerts instance = a different CA the hub never trusted.
    let rogue = TestCerts::generate("rogue", "bad-agent");
    let (cert, key) = rogue.named_client_cert("bad-agent");
    let mut cfg = agent_config("bad-agent", hub_port, certs());
    cfg.tls = Some(interflow_mesh::config::AgentTlsConfig {
        enabled: true,
        ca_path: Some(rogue.ca_path().display().to_string()),
        client_cert_path: Some(cert.display().to_string()),
        client_key_path: Some(key.display().to_string()),
        hub_cert_fingerprint: None,
    });
    let agent_handle = spawn_agent(cfg);

    // Give the agent a few seconds to try registering (retries with backoff)
    tokio::time::sleep(Duration::from_secs(3)).await;

    // Never Connected: the agent is alive but stuck in the reconnect loop
    assert!(
        !matches!(
            agent_handle.state(),
            AgentState::Connected { .. }
                | interflow_mesh::agent::AgentState::Stopped
                | interflow_mesh::agent::AgentState::Failed { .. }
        ),
        "the agent should be stuck in the reconnect loop (actual state: {:?})",
        agent_handle.state()
    );

    // Meanwhile the hub port is still reachable (the hub was not taken down)
    let hub_addr: std::net::SocketAddr = format!("127.0.0.1:{hub_port}").parse().unwrap();
    assert!(
        TcpStream::connect(hub_addr).await.is_ok(),
        "the hub port should still be reachable"
    );

    let _ = agent_handle.shutdown_graceful().await;
}

/// The trusted-CA control case registers normally.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn trusted_ca_agent_can_register() {
    let hub_port = pick_ephemeral_port();
    let hub_cfg = hub_config(hub_port, certs(), vec![]);
    let _hub = interflow_testkit::spawn_hub(hub_cfg).await;

    let cfg = agent_config("good-agent", hub_port, certs());
    let agent_handle = spawn_agent(cfg);

    // Connected within a generous window (TLS handshake + register)
    let deadline = Duration::from_secs(10);
    let start = std::time::Instant::now();
    loop {
        if matches!(agent_handle.state(), AgentState::Connected { .. }) {
            break;
        }
        assert!(
            start.elapsed() < deadline,
            "agent never reached Connected (state: {:?})",
            agent_handle.state()
        );
        tokio::time::sleep(Duration::from_millis(100)).await;
    }

    let _ = agent_handle.shutdown_graceful().await;
}
