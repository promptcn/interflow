//! E2E contract: semantic targets are resolved by the control plane before
//! an Open is emitted. An empty target therefore fails during route-lease
//! negotiation on both transports and never produces a traffic frame.
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

use interflow_core::protocol::StreamProto;
use interflow_core::tls::client::build_client_config;
use interflow_core::tunnel::quic::{QUIC_ALPN, QuicSessionParams, QuicTunnel};
use interflow_core::tunnel::session_tasks::SessionTasks;
use interflow_core::tunnel::{AgentTunnel, H2Liveness};
use interflow_mesh::agent::AgentClient;
use interflow_testkit::{agent_config, hub_config, hub_quic_config, spawn_hub};
use tokio_util::sync::CancellationToken;

fn certs() -> &'static interflow_testkit::certs::TestCerts {
    static C: std::sync::OnceLock<interflow_testkit::certs::TestCerts> = std::sync::OnceLock::new();
    C.get_or_init(|| interflow_testkit::certs::TestCerts::generate("open-target-contract", "agent"))
}

/// h2 plane: an empty target is rejected by `POST /route`.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn h2_empty_target_route_lease_rejected() {
    let hub_port = spawn_hub(hub_config(0, certs(), vec![]))
        .await
        .local_addr()
        .expect("hub bound")
        .port();

    let client = AgentClient::new(agent_config("src", hub_port, certs())).expect("agent build");
    let conn = client
        .connect_and_register()
        .await
        .expect("connect+register");
    let tunnel = AgentTunnel::from_sender(
        conn.negotiated.circuit_token,
        &format!("http://127.0.0.1:{hub_port}"),
        conn.send_request,
        &SessionTasks::new(CancellationToken::new()),
        H2Liveness::HEARTBEAT_DISABLED,
    )
    .expect("tunnel");
    let _conn_handle = conn.conn_handle;

    let err = tunnel
        .send_open(
            interflow_testkit::opaque_stream_id("e0"),
            "",
            StreamProto::Tcp,
        )
        .await
        .expect_err("empty target must not receive a route lease");
    assert!(
        err.to_string().contains("route lease rejected"),
        "unexpected h2 route error: {err}"
    );
}

/// QUIC plane: an empty target fails closed during RouteRequest negotiation.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn quic_empty_target_route_lease_rejected() {
    let hub_port = spawn_hub(hub_quic_config(0, certs(), vec![]))
        .await
        .local_addr()
        .expect("hub bound")
        .port();

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

    let err = tunnel
        .send_open(
            interflow_testkit::opaque_stream_id("q0"),
            "",
            StreamProto::Tcp,
        )
        .await
        .expect_err("empty target must not receive a route lease");
    assert!(
        err.to_string().contains("route lease rejected"),
        "unexpected QUIC route error: {err}"
    );
}
