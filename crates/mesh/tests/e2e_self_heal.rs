//! E2E: self-healing completeness — abnormal task exits must recover.
//!
//! The supervision layers exist to make *any* abnormal task exit recoverable:
//! a panic (or wedge) in a session-critical task, or in `run_session`'s own
//! frame, must end with the agent back in Connected serving traffic — never
//! a zombie Connected state, never a dead supervisor. Ordinary tests cannot
//! schedule such exits, so every case here injects one through the
//! `fault-injection` call points (see `interflow-core`'s `src/fault.rs`).
//!
//! Injection-ordering discipline (the hook is process-global and plans are
//! once-each): spawn the not-targeted agent FIRST and wait for registration
//! (its consult happened before the plan existed → not consumed), then arm
//! the plan, then spawn the targeted agent — the plan can only be consumed
//! by the target. Tests run serially (`just test-e2e`) and each clears the
//! hook up front.
//!
//! Every test pairs its green assertions with a `fired` check on the fault
//! log — a test that passes without the fault having fired is testing
//! nothing.

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
use bytes::Bytes;
use interflow_core::error::InterflowError;
use interflow_core::fault::FaultPoint;
use interflow_core::protocol::StreamProto;
use interflow_core::protocol::frame::FrameType;
use interflow_core::tunnel::AgentTunnel;
use interflow_mesh::agent::{AgentHandle, AgentState};
use interflow_mesh::config::{HeartbeatConfig, HubSecurityConfig};
use interflow_testkit::certs::TestCerts;
use interflow_testkit::fault::{self, FaultPlan};
use interflow_testkit::{
    acl, agent_config, agent_quic_config, echo_server, hub_config, hub_config_tuned,
    hub_quic_config, pick_ephemeral_port, spawn_agent, spawn_agent_registered, spawn_hub,
    tcp_egress_rule, wait_agent_connected,
};
use std::net::SocketAddr;
use std::time::Duration;

/// Generous budget for a full session rebuild (panic → backoff → reconnect →
/// register) under parallel-test load; the *red* signal is the budget
/// expiring, not the exact duration.
const REBUILD_BUDGET: Duration = Duration::from_secs(30);

/// The fault hook is process-global and plans are once-each, so this suite
/// must not interleave within one test binary. `just test-e2e` serializes
/// via `--test-threads=1`, but plain `cargo test` (and CI) runs test cases
/// in parallel — a binary-local mutex restores the ordering regardless of
/// the runner's thread count.
static SERIAL: std::sync::Mutex<()> = std::sync::Mutex::new(());

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// One request-direction stream through the facade, edge-listener style
/// (same shape as e2e_tunnel_facade): register the return channel, Open
/// toward the target agent, push a payload, collect the echoed bytes back.
async fn facade_round_trip(
    tunnel: &AgentTunnel,
    target_agent: &str,
    target_addr: SocketAddr,
    payload: &[u8],
) -> interflow_core::error::Result<Vec<u8>> {
    let sid = uuid::Uuid::new_v4().to_string();
    let mut data_rx = tunnel.register_stream(sid.clone()).await;
    tunnel
        .send_open(
            &sid,
            target_agent,
            Some(&target_addr.to_string()),
            StreamProto::Tcp,
        )
        .await?;
    tunnel
        .send_data(&sid, Bytes::copy_from_slice(payload))
        .await?;

    let mut got = Vec::with_capacity(payload.len());
    let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
    while got.len() < payload.len() {
        let frame = tokio::time::timeout_at(deadline, data_rx.recv())
            .await
            .expect("echo frame within deadline")
            .expect("stream channel must stay open until the echo completes");
        if frame.stream_type == FrameType::Close {
            let reason = String::from_utf8_lossy(&frame.data);
            tunnel.unregister_stream(&sid).await;
            return Err(InterflowError::connection(format!(
                "stream closed by the peer before the echo completed: {reason}"
            )));
        }
        got.extend_from_slice(&frame.data);
    }
    let _ = tunnel.send_close(&sid).await;
    tunnel.unregister_stream(&sid).await;
    Ok(got)
}

/// Round trip with retries until it succeeds or the budget expires — the
/// self-healing probe: while the session is rebuilding each attempt fails
/// fast (dead channel / peer CLOSE), and recovery is "a round trip works
/// again through the same facade".
async fn round_trip_eventually(
    tunnel: &AgentTunnel,
    target_agent: &str,
    target_addr: SocketAddr,
    payload: &[u8],
    budget: Duration,
) -> interflow_core::error::Result<Vec<u8>> {
    let deadline = tokio::time::Instant::now() + budget;
    loop {
        let last = facade_round_trip(tunnel, target_agent, target_addr, payload).await;
        match last {
            Ok(v) => return Ok(v),
            Err(e) => {
                if tokio::time::Instant::now() >= deadline {
                    return Err(e);
                }
                tokio::time::sleep(Duration::from_millis(200)).await;
            }
        }
    }
}

/// Waits until the agent's state is anything other than Connected (the
/// session ended — the visible half of "the death was noticed"). Returns
/// false on timeout.
async fn wait_state_left_connected(handle: &AgentHandle, timeout: Duration) -> bool {
    let deadline = tokio::time::Instant::now() + timeout;
    loop {
        if !matches!(handle.state(), AgentState::Connected { .. }) {
            return true;
        }
        if tokio::time::Instant::now() >= deadline {
            return false;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
}

/// Race-free form of "the session observably ended": subscribes at spawn
/// time (before any state can pass) and resolves true once the agent has
/// been Connected and then left it. Injected faults fire within
/// milliseconds of the first establish — the whole Connected →
/// Reconnecting → Connected cycle can complete before a polling observer
/// starts, so the transition must be captured from the stream, not polled.
fn watch_state_left_connected(
    handle: &AgentHandle,
    budget: Duration,
) -> tokio::task::JoinHandle<bool> {
    let mut rx = handle.subscribe_state();
    tokio::spawn(async move {
        let deadline = tokio::time::Instant::now() + budget;
        let mut seen_connected = matches!(&*rx.borrow_and_update(), AgentState::Connected { .. });
        loop {
            if seen_connected && !matches!(&*rx.borrow(), AgentState::Connected { .. }) {
                return true;
            }
            if tokio::time::Instant::now() >= deadline {
                return false;
            }
            match tokio::time::timeout_at(deadline, rx.changed()).await {
                Ok(Ok(())) => {
                    if matches!(&*rx.borrow_and_update(), AgentState::Connected { .. }) {
                        seen_connected = true;
                    }
                }
                _ => return false,
            }
        }
    })
}

/// Waits until the (TCP+QUIC dual-stack) port is bindable again — the
/// graceful hub drain releases the listeners asynchronously at task end,
/// and an immediate re-spawn can race the release.
async fn wait_port_rebindable(port: u16, timeout: Duration) -> bool {
    let deadline = tokio::time::Instant::now() + timeout;
    loop {
        let tcp_ok = std::net::TcpListener::bind(("127.0.0.1", port)).is_ok();
        let udp_ok = std::net::UdpSocket::bind(("127.0.0.1", port)).is_ok();
        if tcp_ok && udp_ok {
            return true;
        }
        if tokio::time::Instant::now() >= deadline {
            return false;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}

/// Whether the supervisor task died within `within`.
///
/// The state watch sender lives inside the supervisor (`EventSink`); a dead
/// supervisor drops it and `changed()` errors immediately. A live supervisor
/// with no state change pends — the timeout proves liveness.
async fn supervisor_died(handle: &AgentHandle, within: Duration) -> bool {
    let mut rx = handle.subscribe_state();
    rx.borrow_and_update();
    matches!(
        tokio::time::timeout(within, rx.changed()).await,
        Ok(Err(_)) // sender dropped = supervisor dead
    )
}

/// The standard h2 stack: echo backend + hub (front → egress) + a registered
/// egress agent. Returns (echo_addr, hub_port, egress).
async fn h2_stack_with_egress() -> (SocketAddr, u16, AgentHandle) {
    let (echo_addr, _echo_handle) = echo_server().await;
    let hub_port = pick_ephemeral_port();
    let _hub = spawn_hub(hub_config(hub_port, vec![acl("front", "egress")])).await;
    let mut egress_cfg = agent_config("egress", hub_port);
    egress_cfg.egress = vec![tcp_egress_rule("echo", echo_addr)];
    let egress = spawn_agent_registered(egress_cfg).await;
    (echo_addr, hub_port, egress)
}

/// A tuned fast-heartbeat hub config (aging window ≈ 2s) for the
/// stall-watchdog cases.
fn fast_heartbeat_h2_config(hub_port: u16) -> interflow_mesh::config::HubConfig {
    hub_config_tuned(
        hub_port,
        vec![acl("front", "egress")],
        HubSecurityConfig::default(),
        HeartbeatConfig {
            enabled: true,
            interval_secs: 1,
            max_missed: 1,
        },
    )
}

// ---------------------------------------------------------------------------
// T1: a panic in run_session's own frame must not kill the supervisor
// ---------------------------------------------------------------------------

/// `run_session` panics right after registration (session children already
/// spawned). The supervisor must convert that into a retry: agent back to
/// Connected, the facade round-trips again, and the supervisor demonstrably
/// survives (state stream still live).
///
/// Must fail before the fix: the panic propagates into the supervisor task
/// itself (run_session was directly awaited) — the state stream ends
/// (`supervisor_died` = true) and the agent never re-registers.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn session_panic_survives_and_reconnects() {
    let _serial = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
    fault::clear();
    let (echo_addr, hub_port, egress) = h2_stack_with_egress().await;

    let faults = fault::install(FaultPlan::new().panic_at(FaultPoint::AgentSessionAfterRegister));
    let front = spawn_agent(agent_config("front", hub_port));

    // Recovery: Connected again within the rebuild budget.
    assert!(
        wait_agent_connected(&front, REBUILD_BUDGET).await,
        "agent must re-register after a run_session panic (state: {:?})",
        front.state()
    );
    assert!(
        faults.fired(FaultPoint::AgentSessionAfterRegister),
        "the fault must actually have fired (guards against a vacuous green)"
    );

    // The facade round-trips after recovery.
    let tunnel = front.tunnel();
    let payload = b"session-panic-recovered\n".repeat(4);
    let got = round_trip_eventually(&tunnel, "egress", echo_addr, &payload, REBUILD_BUDGET)
        .await
        .expect("round trip after run_session panic recovery");
    assert_eq!(got, payload);

    // The supervisor survived: its state stream is still live.
    assert!(
        !supervisor_died(&front, Duration::from_secs(1)).await,
        "the supervisor itself must survive a session panic"
    );

    fault::clear();
    let _ = front.shutdown_graceful().await;
    let _ = egress.shutdown_graceful().await;
}

// ---------------------------------------------------------------------------
// T2: a panic in the h2 upload task must rebuild the session
// ---------------------------------------------------------------------------

/// The upload loop panics right after its first round establishes. The
/// session must end and rebuild; traffic must flow again.
///
/// Must fail before the fix: the upload task's JoinHandle is dropped at
/// spawn, so nothing observes the death. The poll loop keeps answering
/// heartbeats via the `POST /pong` fallback, the state stays Connected, and
/// every uplink send fails fast forever — the zombie shape.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn upload_task_panic_rebuilds_session() {
    let _serial = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
    let _ = tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .try_init();
    fault::clear();
    let (echo_addr, hub_port, egress) = h2_stack_with_egress().await;

    let faults = fault::install(FaultPlan::new().panic_at(FaultPoint::H2UploadLoopAfterEstablish));
    let front = spawn_agent(agent_config("front", hub_port));
    // Subscribe BEFORE the fault can fire (see the helper's doc comment).
    let left_connected = watch_state_left_connected(&front, REBUILD_BUDGET);
    assert!(
        wait_agent_connected(&front, Duration::from_secs(10)).await,
        "agent should connect initially (state: {:?})",
        front.state()
    );
    assert!(
        faults.fired(FaultPoint::H2UploadLoopAfterEstablish),
        "the upload-loop fault must have fired"
    );

    // NOTE on the failure shape: the upload stream's request body is owned
    // by the hyper connection driver once the request is sent, so the data
    // plane keeps flowing after the task dies — the gap is that nothing
    // watches or rebuilds the upload anymore. The invariant under test is
    // therefore "the session ends and rebuilds", not "traffic breaks".
    assert!(
        left_connected.await.unwrap_or(false),
        "the upload task's death must end the session (state stayed {:?} — death unobserved)",
        front.state()
    );

    let tunnel = front.tunnel();
    let payload = b"upload-panic-recovered\n".repeat(4);
    let got = round_trip_eventually(&tunnel, "egress", echo_addr, &payload, REBUILD_BUDGET)
        .await
        .expect("traffic must flow again after the upload task panics");
    assert_eq!(got, payload);

    fault::clear();
    let _ = front.shutdown_graceful().await;
    let _ = egress.shutdown_graceful().await;
}

// ---------------------------------------------------------------------------
// T3: a panic in the h2 poll task must rebuild the session
// ---------------------------------------------------------------------------

/// The poll loop panics right after connecting. The session must end and
/// rebuild; traffic must flow again.
///
/// Must fail before the fix: the poll task's death kills the in-task
/// receive watchdog with it; the upload loop keeps running (its streams are
/// rejected by the hub after eviction, but nothing cancels the session) —
/// the state stays Connected while inbound frames are never read again.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn poll_task_panic_rebuilds_session() {
    let _serial = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
    fault::clear();
    let (echo_addr, hub_port, egress) = h2_stack_with_egress().await;

    let faults = fault::install(FaultPlan::new().panic_at(FaultPoint::H2PollLoopAfterConnect));
    let front = spawn_agent(agent_config("front", hub_port));
    let left_connected = watch_state_left_connected(&front, REBUILD_BUDGET);
    assert!(
        wait_agent_connected(&front, Duration::from_secs(10)).await,
        "agent should connect initially (state: {:?})",
        front.state()
    );
    assert!(
        faults.fired(FaultPoint::H2PollLoopAfterConnect),
        "the poll-loop fault must have fired"
    );

    assert!(
        left_connected.await.unwrap_or(false),
        "the poll task's death must end the session (state stayed {:?} — death unobserved)",
        front.state()
    );

    let tunnel = front.tunnel();
    let payload = b"poll-panic-recovered\n".repeat(4);
    let got = round_trip_eventually(&tunnel, "egress", echo_addr, &payload, REBUILD_BUDGET)
        .await
        .expect("traffic must flow again after the poll task panics");
    assert_eq!(got, payload);

    fault::clear();
    let _ = front.shutdown_graceful().await;
    let _ = egress.shutdown_graceful().await;
}

// ---------------------------------------------------------------------------
// T4: a wedged (not dead) upload task must be caught by the stall heartbeat
// ---------------------------------------------------------------------------

/// The upload loop parks forever right after establishing (the channel stays
/// alive: uplink sends buffer as fake successes, so neither fast-fail nor
/// the egress send-stall detector can see it). Only a stall heartbeat on the
/// task itself can catch this: the session must end and rebuild.
///
/// Must fail before the fix: the wedged task never exits, the poll loop
/// keeps answering via `POST /pong`, the state stays Connected forever.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn wedged_upload_rebuilds_via_stall_watchdog() {
    let _serial = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
    fault::clear();
    let (echo_addr, _echo_handle) = echo_server().await;
    let hub_port = pick_ephemeral_port();
    let _hub = spawn_hub(fast_heartbeat_h2_config(hub_port)).await;
    let mut egress_cfg = agent_config("egress", hub_port);
    egress_cfg.egress = vec![tcp_egress_rule("echo", echo_addr)];
    let egress = spawn_agent_registered(egress_cfg).await;

    let faults = fault::install(FaultPlan::new().stall_at(FaultPoint::H2UploadLoopStall));
    let front = spawn_agent(agent_config("front", hub_port));
    assert!(
        wait_agent_connected(&front, Duration::from_secs(10)).await,
        "agent should connect initially (state: {:?})",
        front.state()
    );
    assert!(
        faults.fired(FaultPoint::H2UploadLoopStall),
        "the upload-loop stall must have fired"
    );

    // The wedged uplink must be noticed: the session ends (state leaves
    // Connected) within a heartbeat-derived window, then recovers.
    assert!(
        wait_state_left_connected(&front, Duration::from_secs(15)).await,
        "a wedged upload task must end the session (state stayed {:?} — stall not detected)",
        front.state()
    );

    let tunnel = front.tunnel();
    let payload = b"upload-stall-recovered\n".repeat(4);
    let got = round_trip_eventually(&tunnel, "egress", echo_addr, &payload, REBUILD_BUDGET)
        .await
        .expect("traffic must flow again after the upload task unwedges by rebuild");
    assert_eq!(got, payload);

    fault::clear();
    let _ = front.shutdown_graceful().await;
    let _ = egress.shutdown_graceful().await;
}

// ---------------------------------------------------------------------------
// T5: a supervisor-frame panic must be observable to embedders
// ---------------------------------------------------------------------------

/// Pins the embedder contract for the outermost layer: a panic in the
/// supervisor's own frame is *not* recoverable in-library — the embedder
/// (GUI auto-restart / edge health watch → systemd) owns that recovery. The
/// library must make the death unmistakable: `join()` resolves with an
/// error, the state stream ends, and the final state is neither Stopped nor
/// Failed (i.e. "not a legitimate end").
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn supervisor_panic_is_observable_to_embedders() {
    let _serial = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
    fault::clear();
    let faults = fault::install(FaultPlan::new().panic_at(FaultPoint::AgentSuperviseLoopTick));

    let closed_port = pick_ephemeral_port();
    let mut cfg = agent_config("doomed", closed_port);
    cfg.agent.connect_timeout_secs = 1;
    let handle = spawn_agent(cfg);

    // Observe the death through the state stream first (the embedder's
    // detection path): drain any legitimate state changes until the stream
    // ENDS, and the final state must not look like a legitimate stop.
    let mut rx = handle.subscribe_state();
    let deadline = tokio::time::Instant::now() + REBUILD_BUDGET;
    loop {
        match tokio::time::timeout_at(deadline, rx.changed()).await {
            Ok(Err(_)) => break,    // stream ended = supervisor death
            Ok(Ok(())) => continue, // a state change (e.g. Connecting) — keep waiting
            Err(_) => panic!("supervisor did not die within {REBUILD_BUDGET:?}"),
        }
    }
    assert!(
        faults.fired(FaultPoint::AgentSuperviseLoopTick),
        "the supervisor fault must have fired"
    );
    assert!(
        !matches!(
            rx.borrow().clone(),
            AgentState::Stopped | AgentState::Failed { .. }
        ),
        "final state after a supervisor death must not masquerade as a legitimate end (got {:?})",
        rx.borrow()
    );

    // And through join(): the error is the embedder's restart signal.
    let joined = tokio::time::timeout(REBUILD_BUDGET, handle.join()).await;
    match joined {
        Ok(Err(_)) => {} // JoinError surfaced — observable
        Ok(Ok(())) => panic!("a panicked supervisor must not join Ok"),
        Err(_) => panic!("join() must resolve after the supervisor dies"),
    }
    fault::clear();
}

// ---------------------------------------------------------------------------
// T6: QUIC parity — the same invariants on the QUIC transport
// ---------------------------------------------------------------------------

/// The QUIC control-read loop panics at start (heartbeat answering dead).
/// The session must rebuild — with the hub heartbeat DISABLED, so the only
/// thing that can notice the death is the agent's own task supervision (a
/// heartbeat-enabled hub would evict after its aging window and the live
/// closed-watcher would paper over the gap).
///
/// Before the fix: nothing at all notices — the agent zombies in Connected.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn quic_control_read_panic_rebuilds_session() {
    let _serial = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
    fault::clear();
    let certs = TestCerts::generate("self-heal", "self-heal");
    let (echo_addr, _echo_handle) = echo_server().await;
    let hub_port = pick_ephemeral_port();
    let mut hub_cfg = hub_quic_config(hub_port, &certs, vec![acl("front", "egress")]);
    hub_cfg.heartbeat = HeartbeatConfig {
        enabled: false,
        interval_secs: 15,
        max_missed: 4,
    };
    let _hub = spawn_hub(hub_cfg).await;

    let mut egress_cfg = agent_quic_config("egress", hub_port, &certs);
    egress_cfg.egress = vec![tcp_egress_rule("echo", echo_addr)];
    let egress = spawn_agent_registered(egress_cfg).await;

    let faults = fault::install(FaultPlan::new().panic_at(FaultPoint::QuicControlReadLoop));
    let front = spawn_agent(agent_quic_config("front", hub_port, &certs));
    let left_connected = watch_state_left_connected(&front, REBUILD_BUDGET);
    assert!(
        wait_agent_connected(&front, Duration::from_secs(10)).await,
        "agent should connect initially (state: {:?})",
        front.state()
    );
    assert!(
        faults.fired(FaultPoint::QuicControlReadLoop),
        "the QUIC control-read fault must have fired"
    );

    assert!(
        left_connected.await.unwrap_or(false),
        "the control-read task's death must end the session (state stayed {:?} — death unobserved)",
        front.state()
    );

    let tunnel = front.tunnel();
    let payload = b"quic-ctlread-recovered\n".repeat(4);
    let got = round_trip_eventually(&tunnel, "egress", echo_addr, &payload, REBUILD_BUDGET)
        .await
        .expect("traffic must flow again after the QUIC control-read task panics");
    assert_eq!(got, payload);

    fault::clear();
    let _ = front.shutdown_graceful().await;
    let _ = egress.shutdown_graceful().await;
}

/// The QUIC accept loop panics at start on the *egress* agent (inbound
/// stream intake dead while registration stays healthy). The session must
/// rebuild. Before the fix: every Open toward the agent hangs unanswered.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn quic_accept_loop_panic_rebuilds_session() {
    let _serial = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
    fault::clear();
    let certs = TestCerts::generate("self-heal", "self-heal");
    let (echo_addr, _echo_handle) = echo_server().await;
    let hub_port = pick_ephemeral_port();
    let mut hub_cfg = hub_quic_config(hub_port, &certs, vec![acl("front", "egress")]);
    hub_cfg.heartbeat = HeartbeatConfig {
        enabled: true,
        interval_secs: 1,
        max_missed: 1,
    };
    let _hub = spawn_hub(hub_cfg).await;

    // Ordering discipline: front first (its accept-loop consult precedes the
    // plan), then arm, then the targeted egress agent.
    let front = spawn_agent_registered(agent_quic_config("front", hub_port, &certs)).await;

    let faults = fault::install(FaultPlan::new().panic_at(FaultPoint::QuicAcceptLoop));
    let mut egress_cfg = agent_quic_config("egress", hub_port, &certs);
    egress_cfg.egress = vec![tcp_egress_rule("echo", echo_addr)];
    let egress = spawn_agent(egress_cfg);
    assert!(
        wait_agent_connected(&egress, Duration::from_secs(10)).await,
        "egress should connect initially (state: {:?})",
        egress.state()
    );
    assert!(
        faults.fired(FaultPoint::QuicAcceptLoop),
        "the QUIC accept-loop fault must have fired"
    );

    let tunnel = front.tunnel();
    let payload = b"quic-accept-recovered\n".repeat(4);
    let got = round_trip_eventually(&tunnel, "egress", echo_addr, &payload, REBUILD_BUDGET)
        .await
        .expect("traffic must flow again after the QUIC accept task panics");
    assert_eq!(got, payload);

    fault::clear();
    let _ = front.shutdown_graceful().await;
    let _ = egress.shutdown_graceful().await;
}

/// The QUIC closed-watcher (the transport's only client-side disconnect
/// sensor) panics at start; then the hub restarts. The agent must still
/// reconnect. Before the fix: the data loops die with the connection but
/// nothing ends the session — a permanent Connected zombie.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn quic_closed_watcher_panic_survives_hub_restart() {
    let _serial = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
    fault::clear();
    let certs = TestCerts::generate("self-heal", "self-heal");
    let (echo_addr, _echo_handle) = echo_server().await;
    let hub_port = pick_ephemeral_port();
    let hub_cfg = || {
        let mut c = hub_quic_config(hub_port, &certs, vec![acl("front", "egress")]);
        c.heartbeat = HeartbeatConfig {
            enabled: true,
            interval_secs: 1,
            max_missed: 1,
        };
        c
    };

    let _hub1 = spawn_hub(hub_cfg()).await;

    let mut egress_cfg = agent_quic_config("egress", hub_port, &certs);
    egress_cfg.egress = vec![tcp_egress_rule("echo", echo_addr)];
    let _egress_keep = spawn_agent_registered(egress_cfg).await;

    let faults = fault::install(FaultPlan::new().panic_at(FaultPoint::QuicClosedWatcher));
    let front = spawn_agent(agent_quic_config("front", hub_port, &certs));
    assert!(
        wait_agent_connected(&front, Duration::from_secs(10)).await,
        "agent should connect initially (state: {:?})",
        front.state()
    );
    assert!(
        faults.fired(FaultPoint::QuicClosedWatcher),
        "the closed-watcher fault must have fired"
    );

    // Hub death + return: the agent must re-register on its own. The
    // watcher fault was consumed at session-1 start; the post-restart
    // reconnect rides on the (healthy) session-2 watcher AND the data
    // loops' death contract — belt and braces, exactly the point.
    _hub1.shutdown().await.expect("first hub shutdown");
    assert!(
        wait_port_rebindable(hub_port, Duration::from_secs(10)).await,
        "hub port must become rebindable after graceful shutdown"
    );
    let _hub2 = spawn_hub(hub_cfg()).await;
    assert!(
        wait_agent_connected(&front, REBUILD_BUDGET).await,
        "agent must re-register after the hub restarts despite the dead closed-watcher (state: {:?})",
        front.state()
    );

    let tunnel = front.tunnel();
    let payload = b"quic-watcher-recovered\n".repeat(4);
    let got = round_trip_eventually(&tunnel, "egress", echo_addr, &payload, REBUILD_BUDGET)
        .await
        .expect("traffic must flow after reconnecting past the dead watcher");
    assert_eq!(got, payload);

    fault::clear();
    let _ = front.shutdown_graceful().await;
}

/// The QUIC control-write forwarder wedges at its first forwarded frame
/// (the first Pong — the Pong path dies while the connection stays
/// healthy). The stall heartbeat must end the session and rebuild it.
/// Before the fix: the hub evicts, the agent zombies in Connected.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn quic_control_write_stall_rebuilds_session() {
    let _serial = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
    fault::clear();
    let certs = TestCerts::generate("self-heal", "self-heal");
    let (echo_addr, _echo_handle) = echo_server().await;
    let hub_port = pick_ephemeral_port();
    let mut hub_cfg = hub_quic_config(hub_port, &certs, vec![acl("front", "egress")]);
    hub_cfg.heartbeat = HeartbeatConfig {
        enabled: true,
        interval_secs: 1,
        max_missed: 1,
    };
    let _hub = spawn_hub(hub_cfg).await;

    let mut egress_cfg = agent_quic_config("egress", hub_port, &certs);
    egress_cfg.egress = vec![tcp_egress_rule("echo", echo_addr)];
    let egress = spawn_agent_registered(egress_cfg).await;

    // The wedge point is the forwarder's first *forwarded* frame (the
    // first Pong — the Hello left the forwarder with the negotiation
    // upgrade). A fault plan is process-global and one-shot, so let egress
    // answer at least one Pong (≥3 heartbeat ticks at 1s) before
    // installing; otherwise the fault would land on egress's forwarder
    // instead of front's.
    tokio::time::sleep(Duration::from_secs(3)).await;

    let faults = fault::install(FaultPlan::new().stall_at(FaultPoint::QuicControlWriteStall));
    let mut front_cfg = agent_quic_config("front", hub_port, &certs);
    // Pin the stall window tight so the test asserts the watchdog path
    // independent of the negotiated derivation (the pinned 2s happens to
    // equal this hub's advertised 1s×(1+1) dead line).
    front_cfg.agent.task_stall_timeout_secs = Some(2);
    let front = spawn_agent(front_cfg);
    assert!(
        wait_agent_connected(&front, Duration::from_secs(10)).await,
        "agent should connect initially (state: {:?})",
        front.state()
    );
    // The wedge lands at the forwarder's first forwarded frame — the first
    // Pong, ~one heartbeat interval after registration (the Hello itself
    // no longer rides the forwarder) — so fire, not connect, is the wait
    // point.
    let fault_fired = {
        let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
        loop {
            if faults.fired(FaultPoint::QuicControlWriteStall) {
                break true;
            }
            if tokio::time::Instant::now() >= deadline {
                break false;
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    };
    assert!(fault_fired, "the control-write stall must have fired");

    assert!(
        wait_state_left_connected(&front, Duration::from_secs(15)).await,
        "a wedged control-write task must end the session (state stayed {:?} — stall not detected)",
        front.state()
    );

    let tunnel = front.tunnel();
    let payload = b"quic-ctlwrite-recovered\n".repeat(4);
    let got = round_trip_eventually(&tunnel, "egress", echo_addr, &payload, REBUILD_BUDGET)
        .await
        .expect("traffic must flow again after the control-write unwedges by rebuild");
    assert_eq!(got, payload);

    fault::clear();
    let _ = front.shutdown_graceful().await;
    let _ = egress.shutdown_graceful().await;
}
