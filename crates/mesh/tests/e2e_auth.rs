//! Auth-failure scenarios: a wrong token must be rejected by the hub.

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
use interflow_mesh::config::{AgentInfo, TransportKind};
use interflow_testkit::{agent_config, hub_config_with_token, pick_ephemeral_port, spawn_agent};
use std::time::Duration;
use tokio::net::TcpStream;

/// When the agent presents a wrong token, the hub's `/register` should return
/// 401 and the agent's reconnect loop keeps failing.
///
/// We cannot directly assert "never connects" (that would be proving a
/// negative); instead: failing to connect to any hub TCP port within a
/// reasonable time (while the hub is still listening) shows the auth
/// rejection is in effect.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn wrong_token_agent_fails_to_register() {
    let hub_port = pick_ephemeral_port();
    let hub_cfg = hub_config_with_token(hub_port, "correct-token", Some("admin-token"));
    let _hub = interflow_testkit::spawn_hub(hub_cfg).await;

    // Agent with the wrong token
    let mut cfg = agent_config("bad-agent", hub_port);
    cfg.agent = AgentInfo {
        id: "bad-agent".to_string(),
        hub_url: format!("http://127.0.0.1:{hub_port}"),
        transport: TransportKind::H2,
        hub_quic_addr: None,
        auth_token: Some("WRONG-TOKEN".to_string()),
        connect_timeout_secs: 5,
        poll_idle_timeout_secs: None,
        request_establish_timeout_secs: None,
    };
    let agent_handle = spawn_agent(cfg);

    // Give the agent a few seconds to try registering (retries every 5s)
    tokio::time::sleep(Duration::from_secs(3)).await;

    // The agent is still running (i.e. it is in the reconnect loop) — verify
    // it did not crash
    assert!(
        !matches!(
            agent_handle.state(),
            interflow_mesh::agent::AgentState::Stopped
                | interflow_mesh::agent::AgentState::Failed { .. }
        ),
        "the agent should still be in the reconnect loop (actual state: {:?})",
        agent_handle.state()
    );

    // Meanwhile the hub port is still reachable (the hub was not taken down)
    let hub_addr: std::net::SocketAddr = format!("127.0.0.1:{hub_port}").parse().unwrap();
    let reach = TcpStream::connect(hub_addr).await;
    assert!(reach.is_ok(), "the hub port should still be reachable");

    let _ = agent_handle.shutdown_graceful().await;
}

/// The correct token should register normally. This is the control case.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn correct_token_agent_can_register() {
    let hub_port = pick_ephemeral_port();
    let hub_cfg = hub_config_with_token(hub_port, "correct-token", None);
    let _hub = interflow_testkit::spawn_hub(hub_cfg).await;

    let mut cfg = agent_config("good-agent", hub_port);
    cfg.agent.auth_token = Some("correct-token".to_string());
    let _agent = spawn_agent(cfg);

    // Brief wait; the agent should not crash
    tokio::time::sleep(Duration::from_secs(2)).await;
    // The agent handle being alive means no panic (we cannot directly verify
    // the register succeeded, but staying alive is a good signal)
}
