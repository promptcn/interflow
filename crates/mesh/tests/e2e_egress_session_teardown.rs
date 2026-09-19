//! E2E: stream lifecycle across session teardown (regression suite for the
//! 2026-09-14 fd-leak eradication).
//!
//! Background (docs/bug/2026-09-14-egress-fd-leak-session-rebuild.md): the
//! egress forwarder was a bare `tokio::spawn` unaware of the session token;
//! its only exit condition (`frames.recv() == None`) was pinned open by the
//! sender in the dispatch table — after a session rebuild the forwarder hung
//! forever, the backend TCP fds (local 5174/Vite etc.) were never released,
//! and long runs ended in EMFILE (os error 24). After the fix, three layers
//! of defense: the forwarder holds the session token, a tunnel termination
//! contract (shutdown clears the table), and a bounded session-level tracker
//! close-out.
//!
//! Scenarios:
//! - T1 after disconnect/rebuild (hub graceful shutdown → agent notices →
//!   teardown → reconnect), all silent long streams (simulating HMR/SSE:
//!   established then no traffic in either direction) have their backend
//!   connections closed within a bounded time, with `session_closed`
//!   attribution visible;
//! - T2 multiple rebuild rounds with no accumulation: backend active
//!   connections return to zero each round, total accepts exactly equal
//!   opened-streams x rounds, and teardown close-out has zero timeouts (no
//!   "child tasks that ignore the token");
//! - T3 after a rebuild, new streams work as usual (reconnect does not break
//!   the data plane) + user-level graceful shutdown completes within bounds.
//!
//! Must fail before the fix: silent streams' forwarders hung on
//! `frames.recv()`, and backend connections accumulated across rounds
//! (active count > K from round 1, eventually EMFILE).

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
use interflow_core::tunnel::AgentTunnel;
use interflow_mesh::agent::{AgentClient, AgentHandle, AgentState};
use interflow_testkit::{
    agent_config, hub_config, metrics_harness::counter_value, metrics_harness::eventually,
    metrics_harness::init_tracing, metrics_harness::metrics_handle,
    metrics_harness::wait_counter_at_least, pick_ephemeral_port, spawn_agent_registered, spawn_hub,
};
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;
use tokio::io::AsyncReadExt;
use tokio::net::TcpListener;

fn certs() -> &'static interflow_testkit::certs::TestCerts {
    static C: std::sync::OnceLock<interflow_testkit::certs::TestCerts> = std::sync::OnceLock::new();
    C.get_or_init(|| interflow_testkit::certs::TestCerts::generate("e2e", "agent"))
}

/// Silent streams established per round (simulating HMR WebSocket + SSE
/// long-lived connections).
const STREAMS_PER_ROUND: usize = 5;
/// Rebuild rounds: the leak accumulates across sessions; multiple rounds
/// assert "no accumulation".
const ROUNDS: usize = 3;
/// Upper-bound budget for one round of teardown: hub shutdown drain + agent
/// notice (keepalive worst case ~15s).
const TEARDOWN_DEADLINE: Duration = Duration::from_secs(20);
/// Reconnect wait (backoff 1-2s + registration).
const RECONNECT_DEADLINE: Duration = Duration::from_secs(30);

// ---------------------------------------------------------------------------
// metrics: install an in-process recorder and read snapshots directly
// (installed once, shared by all tests)
// ---------------------------------------------------------------------------

/// Initialize tracing according to RUST_LOG (silent if unset; idempotent on

// ---------------------------------------------------------------------------
// Silent backend: counts accepts, holds connections silently (no business
// data read or written, just waiting for EOF)
// ---------------------------------------------------------------------------

/// Silent long-lived backend (simulating a Vite HMR WebSocket / SSE):
/// - `accepted`: cumulative accepted connections (only grows across rounds;
///   asserts the exact number of opened streams);
/// - `active`: currently open connections (peer closes → EOF → decrement;
///   **the fd-release signal**).
async fn silent_backend() -> (SocketAddr, Arc<AtomicUsize>, Arc<AtomicUsize>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let accepted = Arc::new(AtomicUsize::new(0));
    let active = Arc::new(AtomicUsize::new(0));
    let (a2, c2) = (accepted.clone(), active.clone());
    tokio::spawn(async move {
        loop {
            let Ok((mut sock, _)) = listener.accept().await else {
                break;
            };
            a2.fetch_add(1, Ordering::SeqCst);
            c2.fetch_add(1, Ordering::SeqCst);
            let c3 = c2.clone();
            tokio::spawn(async move {
                // Silent hold: only probe for EOF/error (the peer truly
                // closing) to decrement the active count
                let mut buf = [0u8; 256];
                loop {
                    match sock.read(&mut buf).await {
                        Ok(0) | Err(_) => break,
                        Ok(_) => {}
                    }
                }
                c3.fetch_sub(1, Ordering::SeqCst);
            });
        }
    });
    (addr, accepted, active)
}

/// Bare-tunnel injection endpoint: connect to the hub + register + AgentTunnel
/// (frame-level direct send, with full control over the frame count).
async fn connect_tunnel(hub_port: u16, agent_id: &str) -> AgentTunnel {
    let client = AgentClient::new(agent_config(agent_id, hub_port, certs())).expect("agent build");
    let conn = client
        .connect_and_register()
        .await
        .expect("connect+register");
    AgentTunnel::from_sender(
        agent_id.to_string(),
        &format!("http://127.0.0.1:{hub_port}"),
        conn.send_request,
        &interflow_core::tunnel::session_tasks::SessionTasks::new(
            tokio_util::sync::CancellationToken::new(),
        ),
        interflow_core::tunnel::H2Liveness::HEARTBEAT_DISABLED,
    )
    .expect("tunnel")
}

// ---------------------------------------------------------------------------
// Main regression: multiple rounds of "open silent streams → stop the hub to
// trigger teardown → restart and reconnect" with no fd accumulation
// ---------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn session_rebuild_releases_silent_streams_without_accumulation() {
    let _ = metrics_handle(); // install the recorder as early as possible: the metrics macros cache per callsite
    init_tracing();
    let hub_port = pick_ephemeral_port();
    let mut hub = spawn_hub(hub_config(hub_port, certs(), vec![])).await;

    let (silent_addr, accepted, active) = silent_backend().await;
    // Registration gate: round 0's Opens address this egress immediately;
    // an unregistered target would be torn down with `_close_` and surface
    // as a confusing `eventually` timeout instead of a registration failure.
    let agent: AgentHandle = spawn_agent_registered(agent_config("eg", hub_port, certs())).await;

    let closed_before = counter_value("interflow_egress_stream_closed_total");
    let mut expected_accepted = 0usize;

    for round in 0..ROUNDS {
        // This round's injection endpoint (the previous one died with the old
        // hub)
        let inj = connect_tunnel(hub_port, "inj").await;

        // Open K silent streams (done at Open — after the egress dials the
        // backend, no traffic in either direction)
        for i in 0..STREAMS_PER_ROUND {
            let sid = format!("r{round}-s{i}");
            inj.send_open(&sid, "eg", Some(&silent_addr.to_string()), StreamProto::Tcp)
                .await
                .expect("open");
        }

        // All silent streams reach the backend (active = K: the previous
        // round's have all been released)
        eventually(
            || active.load(Ordering::SeqCst) == STREAMS_PER_ROUND,
            Duration::from_secs(10),
            &format!("round {round} silent streams established"),
        )
        .await;

        // Trigger session termination: gracefully stop the hub (GOAWAY/drain
        // → agent notices the disconnect → teardown)
        hub.shutdown().await.expect("hub graceful shutdown");

        // * Core assertion (must fail before the fix): session teardown
        // releases all silent streams' backend connections.
        // If the forwarder hangs on frames.recv(), the connections never
        // close and active accumulates across rounds.
        eventually(
            || active.load(Ordering::SeqCst) == 0,
            TEARDOWN_DEADLINE,
            &format!("round {round} backend connections back to zero after teardown (fd release)"),
        )
        .await;

        expected_accepted += STREAMS_PER_ROUND;
        assert_eq!(
            accepted.load(Ordering::SeqCst),
            expected_accepted,
            "total accepts must exactly equal opened-streams x rounds (no ghost reconnects / no losses)"
        );

        // Restart the hub and wait for the agent to reconnect (the next round
        // uses the new session's egress)
        hub = spawn_hub(hub_config(hub_port, certs(), vec![])).await;
        let deadline = tokio::time::Instant::now() + RECONNECT_DEADLINE;
        loop {
            if matches!(agent.state(), AgentState::Connected { .. }) {
                break;
            }
            assert!(
                tokio::time::Instant::now() < deadline,
                "agent did not reconnect within {RECONNECT_DEADLINE:?}: {:?}",
                agent.state()
            );
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    }

    // The stream-closed count covers all rounds (every silent stream went
    // through the unified close-out)
    wait_counter_at_least(
        "interflow_egress_stream_closed_total",
        closed_before + expected_accepted as u64,
        Duration::from_secs(5),
    )
    .await;
    // Session-termination attribution is visible (session_closed or
    // tunnel-death poisoning, depending on the teardown race)
    wait_counter_at_least(
        "interflow_agent_session_teardown_streams_killed_total",
        1,
        Duration::from_secs(5),
    )
    .await;
    // Bounded close-out with zero timeouts: no "child tasks that ignore the
    // token" (a sentinel metric for the structural regression)
    assert_eq!(
        counter_value("interflow_agent_session_drain_timeout_total"),
        0,
        "session-teardown close-out timed out (child tasks exist that ignore the token)"
    );

    // T3: the post-rebuild session's data plane works as usual (new streams
    // can be established and round-trip)
    let echo_addr = {
        // Simple echo backend
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            loop {
                let Ok((mut sock, _)) = listener.accept().await else {
                    break;
                };
                tokio::spawn(async move {
                    let mut buf = [0u8; 4096];
                    loop {
                        match sock.read(&mut buf).await {
                            Ok(0) | Err(_) => break,
                            Ok(n) => {
                                use tokio::io::AsyncWriteExt;
                                if sock.write_all(&buf[..n]).await.is_err() {
                                    break;
                                }
                            }
                        }
                    }
                });
            }
        });
        addr
    };
    let inj = connect_tunnel(hub_port, "inj2").await;
    {
        let mut rx = inj.register_stream("post-rebuild".to_string()).await;
        inj.send_open(
            "post-rebuild",
            "eg",
            Some(&echo_addr.to_string()),
            StreamProto::Tcp,
        )
        .await
        .expect("open after rebuild");
        inj.send_data("post-rebuild", bytes::Bytes::from_static(b"still-alive"))
            .await
            .expect("send after rebuild");
        let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
        let mut got = Vec::new();
        while got.len() < b"still-alive".len() {
            let td = tokio::time::timeout_at(deadline, rx.recv())
                .await
                .expect("reply timed out after rebuild")
                .expect("channel alive");
            assert!(
                !matches!(td.stream_type, interflow_core::protocol::FrameType::Close),
                "new stream closed prematurely after rebuild"
            );
            got.extend_from_slice(&td.data);
        }
        assert_eq!(got, b"still-alive", "data corruption after rebuild");
    }

    // T3b: user-level graceful shutdown completes within bounds (session-level
    // tracker fully closed out, zero structural warnings)
    tokio::time::timeout(Duration::from_secs(15), agent.shutdown_graceful())
        .await
        .expect("graceful shutdown timed out (possible task leak)")
        .expect("shutdown err");
    assert_eq!(
        counter_value("interflow_agent_session_drain_timeout_total"),
        0,
        "the shutdown path likewise must not have child tasks that ignore the token"
    );

    hub.shutdown().await.expect("final hub shutdown");
}
