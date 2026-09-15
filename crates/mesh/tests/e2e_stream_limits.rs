//! E2E: verifies the hub's `max_streams_per_agent` / `max_streams_total`
//! rate limits take effect.
//!
//! Uses `AgentClient::connect_and_register` to obtain an HTTP/2
//! `SendRequest` and builds an `AgentTunnel` that sends `send_open` directly
//! over the streaming upload. After the 2026-09-12 upload streaming refactor,
//! rejections no longer carry a synchronous HTTP status; instead a `_close_`
//! frame returns via `/poll` (`CLOSE:{sid}:{reason}`) — acceptance is taken
//! from the target agent receiving the request-direction new-stream event,
//! and rejection from the sender's stream channel receiving a `_close_`
//! frame.

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
use interflow_core::protocol::{FrameType, StreamProto};
use interflow_core::tunnel::AgentTunnel;
use interflow_mesh::agent::AgentClient;
use interflow_mesh::config::{
    AGENT_CONFIG_VERSION, AgentConfig, AgentInfo, HubSecurityConfig, TransportKind,
};
use interflow_testkit::{hub_config, pick_ephemeral_port, spawn_hub};
use tokio::sync::mpsc;

/// Build and start a hub with the given security config; returns hub_port.
async fn start_hub(security: HubSecurityConfig) -> u16 {
    let hub_port = pick_ephemeral_port();
    let mut cfg = hub_config(hub_port, vec![]);
    cfg.security = security;
    spawn_hub(cfg).await;
    hub_port
}

/// Build a minimal agent config (no ingress/egress; used only for
/// registration + sending send_open).
fn minimal_agent(hub_port: u16, id: &str) -> AgentConfig {
    AgentConfig {
        config_version: AGENT_CONFIG_VERSION,
        agent: AgentInfo {
            id: id.to_string(),
            hub_url: format!("http://127.0.0.1:{hub_port}"),
            transport: TransportKind::H2,
            hub_quic_addr: None,
            auth_token: None,
            connect_timeout_secs: 5,
            poll_idle_timeout_secs: None,
        },
        ingress: vec![],
        egress: vec![],
        egress_backend_write_timeout_secs: 10,
        egress_resolve_timeout_secs: 5,
        egress_connect_timeout_secs: 5,
        max_incoming_streams: 256,
        max_stream_opens_per_sec: 100,
        stream_open_burst: 256,
        control: interflow_mesh::config::ControlConfig {
            enabled: false,
            ..interflow_mesh::config::ControlConfig::default()
        },
        security: interflow_mesh::config::SecurityConfig::default(),
        tls: None,
        logging: interflow_mesh::config::LoggingConfig {
            level: "warn".to_string(),
            format: interflow_mesh::config::LogFormat::Plain,
        },
    }
}

/// Connect to the hub + register + return an AgentTunnel (the caller holds
/// _conn_handle to keep it alive).
async fn connect_tunnel(
    hub_port: u16,
    agent_id: &str,
) -> (AgentTunnel, tokio::task::JoinHandle<()>) {
    let client = AgentClient::new(minimal_agent(hub_port, agent_id)).expect("agent build");
    let conn = client
        .connect_and_register()
        .await
        .expect("connect+register");
    let tunnel = AgentTunnel::from_sender(
        agent_id.to_string(),
        &format!("http://127.0.0.1:{hub_port}"),
        conn.send_request,
        None,
        tokio_util::sync::CancellationToken::new(),
        interflow_core::tunnel::H2Liveness::LEGACY,
    )
    .expect("tunnel");
    (tunnel, conn.conn_handle)
}

/// Register a real target agent (opening to an unregistered target now
/// receives a `_close_` rejection frame instead of a "black-hole stream" —
/// see the 2026-09-11 failure fix and the 2026-09-12 upload streaming
/// refactor).
async fn register_target(hub_port: u16, id: &str) -> (AgentTunnel, tokio::task::JoinHandle<()>) {
    connect_tunnel(hub_port, id).await
}

/// Assert that the open for `sid` is frame-level rejected: the sender's
/// stream channel receives a `_close_` frame whose reason contains `needle`.
async fn expect_open_rejected(tunnel: &AgentTunnel, sid: &str, needle: &str) {
    let mut rx = tunnel.register_stream(sid.to_string()).await;
    match tokio::time::timeout(std::time::Duration::from_secs(3), rx.recv()).await {
        Ok(Some(td)) => {
            assert!(
                matches!(td.stream_type, FrameType::Close),
                "expected a _close_ rejection frame, got {td:?}"
            );
            let reason = String::from_utf8_lossy(&td.data);
            assert!(
                reason.contains(needle),
                "rejection reason should contain {needle:?}: {reason}"
            );
        }
        other => panic!("expected {sid} to be rejected, got {other:?}"),
    }
}

/// Assert that the open for `sid` is accepted: the stream appears among the
/// target agent's request-direction new-stream events.
async fn expect_open_accepted(
    incoming: &mut mpsc::Receiver<interflow_core::tunnel::IncomingStream>,
    sid: &str,
) {
    let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(3);
    loop {
        let ev = tokio::time::timeout_at(deadline, incoming.recv())
            .await
            .unwrap_or_else(|_| panic!("timed out waiting for the Open event for {sid}"))
            .expect("incoming channel alive");
        if ev.open.stream_id == sid && matches!(ev.open.stream_type, FrameType::Open) {
            return;
        }
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn per_agent_cap_rejects_beyond_limit() {
    let hub_port = start_hub(HubSecurityConfig {
        max_streams_per_agent: 3,
        max_streams_total: 0, // no global limit
        ..HubSecurityConfig::default()
    })
    .await;

    let (dst, _dst_conn) = register_target(hub_port, "dst").await;
    let mut dst_incoming = dst.take_incoming_streams().await.expect("take incoming");
    let (tunnel, _conn) = connect_tunnel(hub_port, "src").await;

    // Open 3 streams: the acceptance signal is dst seeing the Open broadcasts
    for i in 0..3 {
        let sid = format!("s{i}");
        tunnel
            .send_open(&sid, "dst", None, StreamProto::Tcp)
            .await
            .unwrap_or_else(|_| panic!("open #{i} failed to enqueue"));
        expect_open_accepted(&mut dst_incoming, &sid).await;
    }

    // The 4th should be frame-level rejected (per-agent cap)
    tunnel
        .send_open("s3", "dst", None, StreamProto::Tcp)
        .await
        .expect("open enqueued");
    expect_open_rejected(&tunnel, "s3", "Per-agent stream limit").await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn per_agent_cap_isolates_agents() {
    let hub_port = start_hub(HubSecurityConfig {
        max_streams_per_agent: 2,
        max_streams_total: 0,
        ..HubSecurityConfig::default()
    })
    .await;

    let (dst, _dst_conn) = register_target(hub_port, "dst").await;
    let mut dst_incoming = dst.take_incoming_streams().await.expect("take incoming");
    let (tunnel_a, _conn_a) = connect_tunnel(hub_port, "agent-a").await;
    let (tunnel_b, _conn_b) = connect_tunnel(hub_port, "agent-b").await;

    // A opens its full 2
    tunnel_a
        .send_open("a0", "dst", None, StreamProto::Tcp)
        .await
        .expect("a0");
    expect_open_accepted(&mut dst_incoming, "a0").await;
    tunnel_a
        .send_open("a1", "dst", None, StreamProto::Tcp)
        .await
        .expect("a1");
    expect_open_accepted(&mut dst_incoming, "a1").await;
    // A's 3rd should be rejected
    tunnel_a
        .send_open("a2", "dst", None, StreamProto::Tcp)
        .await
        .expect("a2 enqueued");
    expect_open_rejected(&tunnel_a, "a2", "Per-agent stream limit").await;

    // B can still open (independent budget)
    tunnel_b
        .send_open("b0", "dst", None, StreamProto::Tcp)
        .await
        .expect("b0");
    expect_open_accepted(&mut dst_incoming, "b0").await;
    tunnel_b
        .send_open("b1", "dst", None, StreamProto::Tcp)
        .await
        .expect("b1");
    expect_open_accepted(&mut dst_incoming, "b1").await;
    tunnel_b
        .send_open("b2", "dst", None, StreamProto::Tcp)
        .await
        .expect("b2 enqueued");
    expect_open_rejected(&tunnel_b, "b2", "Per-agent stream limit").await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn global_cap_rejects_beyond_limit() {
    let hub_port = start_hub(HubSecurityConfig {
        max_streams_per_agent: 0, // no per-agent limit
        max_streams_total: 2,
        ..HubSecurityConfig::default()
    })
    .await;

    let (dst, _dst_conn) = register_target(hub_port, "dst").await;
    let mut dst_incoming = dst.take_incoming_streams().await.expect("take incoming");
    let (tunnel, _conn) = connect_tunnel(hub_port, "src").await;

    tunnel
        .send_open("g0", "dst", None, StreamProto::Tcp)
        .await
        .expect("g0");
    expect_open_accepted(&mut dst_incoming, "g0").await;
    tunnel
        .send_open("g1", "dst", None, StreamProto::Tcp)
        .await
        .expect("g1");
    expect_open_accepted(&mut dst_incoming, "g1").await;
    // The 3rd triggers the global cap (frame-level rejection)
    tunnel
        .send_open("g2", "dst", None, StreamProto::Tcp)
        .await
        .expect("g2 enqueued");
    expect_open_rejected(&tunnel, "g2", "Global stream limit").await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn close_releases_slot() {
    let hub_port = start_hub(HubSecurityConfig {
        max_streams_per_agent: 1,
        max_streams_total: 0,
        ..HubSecurityConfig::default()
    })
    .await;

    let (dst, _dst_conn) = register_target(hub_port, "dst").await;
    let mut dst_incoming = dst.take_incoming_streams().await.expect("take incoming");
    let (tunnel, _conn) = connect_tunnel(hub_port, "src").await;

    tunnel
        .send_open("c0", "dst", None, StreamProto::Tcp)
        .await
        .expect("c0");
    expect_open_accepted(&mut dst_incoming, "c0").await;
    tunnel
        .send_open("c1", "dst", None, StreamProto::Tcp)
        .await
        .expect("c1 enqueued");
    expect_open_rejected(&tunnel, "c1", "Per-agent stream limit").await;

    // After closing c0, opening again should work
    tunnel.send_close("c0").await.expect("close");
    // Give the hub a moment to process the close
    tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    tunnel
        .send_open("c1", "dst", None, StreamProto::Tcp)
        .await
        .expect("c1 after close");
    expect_open_accepted(&mut dst_incoming, "c1").await;
}
