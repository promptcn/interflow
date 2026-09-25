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
use interflow_mesh::config::HubSecurityConfig;
use interflow_testkit::{agent_config, hub_config, spawn_hub};
use tokio::sync::mpsc;

fn certs() -> &'static interflow_testkit::certs::TestCerts {
    static C: std::sync::OnceLock<interflow_testkit::certs::TestCerts> = std::sync::OnceLock::new();
    C.get_or_init(|| interflow_testkit::certs::TestCerts::generate("e2e", "agent"))
}

/// Deterministic canonical opaque stream id for bare-wire tests.
fn sid(n: u16) -> interflow_core::protocol::StreamId {
    // A deterministic nonzero id with the label encoded in the first bytes.
    let mut bytes = [0u8; 16];
    bytes[..2].copy_from_slice(&n.to_be_bytes());
    bytes[15] = 1;
    interflow_core::protocol::StreamId::from_bytes(bytes)
}

/// Build and start a hub with the given security config; returns the actual
/// bound port (kernel-assigned at bind — no pick-then-bind race).
async fn start_hub(security: HubSecurityConfig) -> u16 {
    let mut cfg = hub_config(0, certs(), vec![]);
    cfg.security = security;
    let hub = spawn_hub(cfg).await;
    hub.local_addr().expect("hub bound").port()
}

/// Connect to the hub + register + return an AgentTunnel (the caller holds
/// _conn_handle to keep it alive). The agent config is the testkit preset
/// (mTLS client certificate CN == agent id + `https://` hub URL — the hub is
/// mTLS-only model).
async fn connect_tunnel(
    hub_port: u16,
    agent_id: &str,
) -> (AgentTunnel, tokio::task::JoinHandle<()>) {
    let client = AgentClient::new(agent_config(agent_id, hub_port, certs())).expect("agent build");
    let conn = client
        .connect_and_register()
        .await
        .expect("connect+register");
    let tunnel = AgentTunnel::from_sender(
        conn.negotiated.circuit_token,
        &format!("http://127.0.0.1:{hub_port}"),
        conn.send_request,
        &interflow_core::tunnel::session_tasks::SessionTasks::new(
            tokio_util::sync::CancellationToken::new(),
        ),
        interflow_core::tunnel::H2Liveness::HEARTBEAT_DISABLED,
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
/// stream channel receives a hub-origin Close frame whose reason code
/// matches `expected`.
async fn expect_open_rejected(
    tunnel: &AgentTunnel,
    sid: interflow_core::protocol::StreamId,
    expected: interflow_core::protocol::CloseReason,
) {
    let mut rx = tunnel.register_stream(sid).await;
    match tokio::time::timeout(std::time::Duration::from_secs(3), rx.recv()).await {
        Ok(Some(td)) => {
            assert!(
                matches!(td.stream_type, FrameType::Close),
                "expected a hub Close rejection frame, got {td:?}"
            );
            let reason = interflow_core::protocol::CloseReason::from_payload(&td.data);
            assert_eq!(reason, expected, "rejection reason code mismatch for {sid}");
        }
        other => panic!("expected {sid} to be rejected, got {other:?}"),
    }
}

/// Assert that the open for `sid` is accepted: the stream appears among the
/// target agent's request-direction new-stream events.
async fn expect_open_accepted(
    incoming: &mut mpsc::Receiver<interflow_core::tunnel::IncomingStream>,
    sid: interflow_core::protocol::StreamId,
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
        let sid = sid(i);
        tunnel
            .send_open(sid, "dst", StreamProto::Tcp)
            .await
            .unwrap_or_else(|_| panic!("open #{i} failed to enqueue"));
        expect_open_accepted(&mut dst_incoming, sid).await;
    }

    // The 4th should be frame-level rejected (per-agent cap)
    tunnel
        .send_open(sid(3), "dst", StreamProto::Tcp)
        .await
        .expect("open enqueued");
    expect_open_rejected(
        &tunnel,
        sid(3),
        interflow_core::protocol::CloseReason::LocalLimit,
    )
    .await;
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
        .send_open(sid(10), "dst", StreamProto::Tcp)
        .await
        .expect("a0");
    expect_open_accepted(&mut dst_incoming, sid(10)).await;
    tunnel_a
        .send_open(sid(11), "dst", StreamProto::Tcp)
        .await
        .expect("a1");
    expect_open_accepted(&mut dst_incoming, sid(11)).await;
    // A's 3rd should be rejected
    tunnel_a
        .send_open(sid(12), "dst", StreamProto::Tcp)
        .await
        .expect("a2 enqueued");
    expect_open_rejected(
        &tunnel_a,
        sid(12),
        interflow_core::protocol::CloseReason::LocalLimit,
    )
    .await;

    // B can still open (independent budget)
    tunnel_b
        .send_open(sid(20), "dst", StreamProto::Tcp)
        .await
        .expect("b0");
    expect_open_accepted(&mut dst_incoming, sid(20)).await;
    tunnel_b
        .send_open(sid(21), "dst", StreamProto::Tcp)
        .await
        .expect("b1");
    expect_open_accepted(&mut dst_incoming, sid(21)).await;
    tunnel_b
        .send_open(sid(22), "dst", StreamProto::Tcp)
        .await
        .expect("b2 enqueued");
    expect_open_rejected(
        &tunnel_b,
        sid(22),
        interflow_core::protocol::CloseReason::LocalLimit,
    )
    .await;
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
        .send_open(sid(30), "dst", StreamProto::Tcp)
        .await
        .expect("g0");
    expect_open_accepted(&mut dst_incoming, sid(30)).await;
    tunnel
        .send_open(sid(31), "dst", StreamProto::Tcp)
        .await
        .expect("g1");
    expect_open_accepted(&mut dst_incoming, sid(31)).await;
    // The 3rd triggers the global cap (frame-level rejection)
    tunnel
        .send_open(sid(32), "dst", StreamProto::Tcp)
        .await
        .expect("g2 enqueued");
    expect_open_rejected(
        &tunnel,
        sid(32),
        interflow_core::protocol::CloseReason::LocalLimit,
    )
    .await;
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
        .send_open(sid(40), "dst", StreamProto::Tcp)
        .await
        .expect("c0");
    expect_open_accepted(&mut dst_incoming, sid(40)).await;
    tunnel
        .send_open(sid(41), "dst", StreamProto::Tcp)
        .await
        .expect("c1 enqueued");
    expect_open_rejected(
        &tunnel,
        sid(41),
        interflow_core::protocol::CloseReason::LocalLimit,
    )
    .await;

    // After closing c0, opening again should work
    tunnel.send_close(sid(40)).await.expect("close");
    // Give the hub a moment to process the close
    tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    tunnel
        .send_open(sid(42), "dst", StreamProto::Tcp)
        .await
        .expect("c1 after close");
    expect_open_accepted(&mut dst_incoming, sid(42)).await;
}
