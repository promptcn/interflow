//! E2E contract: an Open frame with an empty target agent is rejected on
//! both transport planes — fail-closed everywhere — but through different
//! gates. These tests pin that divergence as an explicit contract (the
//! pre-2026-09-18 `frame_open` empty-target branch was dead code left over
//! from the pre-streaming-upload architecture and has been removed; see the
//! module docs of `hub/routing.rs` for the reachable rejection points):
//!
//! - h2 plane: rejected at the upload payload-validation gate
//!   (`crates/mesh/src/hub/upload.rs`): `valid_agent_id` refuses the empty
//!   string, so the open never reaches `frame_open`; the sender's `_close_`
//!   frame (via /poll) carries the reason "invalid open payload".
//! - QUIC plane: the relay path performs no target form validation (a known
//!   asymmetry with the h2 gate); the empty target qualifies to
//!   `"{tenant}/"`, on which `tenant_policy_allows` fails closed
//!   (`split_qualified` → `None` → deny). The stream is closed with an
//!   empty-payload `_close_` frame — no reason text (the second observable
//!   difference between the gates).
//!
//! The shared invariant under protection: an empty-target open never creates
//! a stream on either plane. Aligning the two gates (form validation for the
//! QUIC plane) is deferred to the future shared stream-admission seam, not
//! done here.

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
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use interflow_core::protocol::{FrameType, StreamProto};
use interflow_core::tls::client::build_client_config;
use interflow_core::tunnel::quic::{QUIC_ALPN, QuicSessionParams, QuicTunnel};
use interflow_core::tunnel::session_tasks::SessionTasks;
use interflow_core::tunnel::{AgentTunnel, H2Liveness};
use interflow_mesh::agent::AgentClient;
use interflow_testkit::{
    agent_config, hub_config, hub_quic_config, pick_ephemeral_port, spawn_hub,
};
use tokio_util::sync::CancellationToken;

fn certs() -> &'static interflow_testkit::certs::TestCerts {
    static C: std::sync::OnceLock<interflow_testkit::certs::TestCerts> = std::sync::OnceLock::new();
    C.get_or_init(|| interflow_testkit::certs::TestCerts::generate("open-target-contract", "agent"))
}

/// h2 plane: an Open with an empty target is rejected at the upload payload
/// gate, before any routing — the `_close_` frame carries the gate's reason.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn h2_empty_target_open_rejected_at_upload_gate() {
    let hub_port = pick_ephemeral_port();
    spawn_hub(hub_config(hub_port, certs(), vec![])).await;

    let client = AgentClient::new(agent_config("src", hub_port, certs())).expect("agent build");
    let conn = client
        .connect_and_register()
        .await
        .expect("connect+register");
    let tunnel = AgentTunnel::from_sender(
        "src".to_string(),
        &format!("http://127.0.0.1:{hub_port}"),
        conn.send_request,
        &SessionTasks::new(CancellationToken::new()),
        H2Liveness::HEARTBEAT_DISABLED,
    )
    .expect("tunnel");
    let _conn_handle = conn.conn_handle;

    // The client-side send path performs no target validation — the empty
    // target reaches the hub's upload payload gate as-is.
    tunnel
        .send_open("e0", "", None, StreamProto::Tcp)
        .await
        .expect("open enqueued");

    let mut rx = tunnel.register_stream("e0".to_string()).await;
    match tokio::time::timeout(Duration::from_secs(3), rx.recv()).await {
        Ok(Some(td)) => {
            assert!(
                matches!(td.stream_type, FrameType::Close),
                "expected a _close_ rejection frame, got {td:?}"
            );
            let reason = String::from_utf8_lossy(&td.data);
            assert!(
                reason.contains("invalid open payload"),
                "the h2 gate's rejection reason must name the payload gate: {reason}"
            );
        }
        other => panic!("expected the empty-target open to be rejected, got {other:?}"),
    }
}

/// QUIC plane: no payload form validation exists; the empty target fails
/// closed at the tenant-policy gate (the malformed qualified key
/// `"{tenant}/"` splits to `None`) and the stream is closed without a reason
/// payload.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn quic_empty_target_open_denied_fail_closed() {
    let hub_port = pick_ephemeral_port();
    spawn_hub(hub_quic_config(hub_port, certs(), vec![])).await;

    let (cert, key) = certs().named_client_cert("quic-src");
    let tls = build_client_config(
        None,
        certs().ca_path().to_str(),
        cert.to_str(),
        key.to_str(),
        &[QUIC_ALPN],
    )
    .expect("client tls config");
    let server_addr: SocketAddr = format!("127.0.0.1:{hub_port}").parse().unwrap();

    // Direct QuicTunnel (the production QUIC client): register, then open a
    // stream with an empty target.
    let quic = QuicTunnel::connect(
        "quic-src".to_string(),
        server_addr,
        "127.0.0.1",
        tls,
        SessionTasks::new(CancellationToken::new()),
        QuicSessionParams::DEFAULT,
    )
    .await
    .expect("quic connect+register");
    let tunnel = AgentTunnel::from_transport(Arc::new(quic));

    tunnel
        .send_open("q0", "", None, StreamProto::Tcp)
        .await
        .expect("open sent");

    let mut rx = tunnel.register_stream("q0".to_string()).await;
    match tokio::time::timeout(Duration::from_secs(3), rx.recv()).await {
        Ok(Some(td)) => {
            assert!(
                matches!(td.stream_type, FrameType::Close),
                "expected a _close_ frame, got {td:?}"
            );
            assert!(
                td.data.is_empty(),
                "the QUIC gate closes without a reason payload: {td:?}"
            );
        }
        other => panic!("expected the empty-target open to be denied, got {other:?}"),
    }
}
