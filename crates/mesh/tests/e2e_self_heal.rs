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
//! by the target. Cases within this binary run serialized (the `SERIAL`
//! mutex below) and each clears the hook up front.
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
    missing_docs
)]
use interflow_core::error::InterflowError;
use interflow_core::fault::FaultPoint;
use interflow_core::protocol::StreamProto;
use interflow_core::tls::{InnerTlsMaterial, inner_client_config};
use interflow_core::tunnel::AgentTunnel;
use interflow_core::tunnel::e2e::{E2eHandshakeOutcome, E2eTunnelIo, inner_tls_connect};
use interflow_core::tunnel::{InnerStreamHello, TargetSelector};
use interflow_mesh::agent::{AgentHandle, AgentState};
use interflow_mesh::config::{AgentConfig, HeartbeatConfig, HubSecurityConfig};
use interflow_testkit::fault::{self, FaultPlan};
use interflow_testkit::{
    agent_config, agent_quic_config, echo_server, hub_config, hub_config_tuned, hub_quic_config,
    refused_addr, spawn_agent, spawn_agent_registered, spawn_hub, tcp_egress_rule,
    wait_agent_connected,
};
use std::net::SocketAddr;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

fn certs() -> &'static interflow_testkit::certs::TestCerts {
    static C: std::sync::OnceLock<interflow_testkit::certs::TestCerts> = std::sync::OnceLock::new();
    C.get_or_init(|| interflow_testkit::certs::TestCerts::generate("e2e", "agent"))
}

/// Generous budget for a full session rebuild (panic → backoff → reconnect →
/// register) under parallel-test load; the *red* signal is the budget
/// expiring, not the exact duration.
const REBUILD_BUDGET: Duration = Duration::from_secs(30);

/// The fault hook is process-global and plans are once-each, so this suite
/// must not interleave within one test binary. A binary-local mutex
/// restores the ordering under libtest (`cargo test` runs cases in
/// parallel threads); under cargo-nextest each case is its own process, so
/// the mutex never contends — both runners keep the discipline.
static SERIAL: std::sync::Mutex<()> = std::sync::Mutex::new(());

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// One request-direction stream through the facade, edge-listener shape:
/// mandatory inner TLS + encrypted selector, payload, then echoed bytes.
async fn facade_round_trip(
    tunnel: &AgentTunnel,
    target_agent: &str,
    target_addr: SocketAddr,
    payload: &[u8],
) -> interflow_core::error::Result<Vec<u8>> {
    let sid = interflow_core::protocol::StreamId::random().unwrap();
    let data_rx = tunnel.register_stream(sid).await;
    tunnel
        .send_open_with(sid, target_agent, StreamProto::Tcp, true)
        .await?;

    let (cert, key) = certs().named_client_cert("front");
    let ca = certs().ca_path().display().to_string();
    let material = InnerTlsMaterial::from_paths(
        &[ca.as_str()],
        &cert.display().to_string(),
        &key.display().to_string(),
    )
    .map_err(|e| InterflowError::connection(format!("inner material")).with_source(e))?;
    let connector = tokio_rustls::TlsConnector::from(std::sync::Arc::new(
        inner_client_config(&material, target_agent)
            .map_err(|e| InterflowError::connection(format!("inner connector")).with_source(e))?,
    ));
    let adapter = E2eTunnelIo::ingress(data_rx, tunnel.clone(), sid);
    let mut tls = match inner_tls_connect(adapter, connector, Duration::from_secs(5)).await {
        E2eHandshakeOutcome::Established(tls, _) => tls,
        E2eHandshakeOutcome::Failed { error } => {
            tunnel.unregister_stream(sid).await;
            return Err(InterflowError::connection(format!(
                "inner TLS handshake failed: {error}"
            )));
        }
    };
    InnerStreamHello {
        source_principal: "front".to_owned(),
        source_fingerprint: material.leaf_fingerprint(),
        selector: TargetSelector::Address(target_addr.to_string()),
        correlation_id: *uuid::Uuid::new_v4().as_bytes(),
    }
    .write(&mut tls)
    .await?;
    tls.write_all(payload).await?;
    tls.flush().await?;

    let mut got = Vec::with_capacity(payload.len());
    let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
    while got.len() < payload.len() {
        let mut chunk = vec![0u8; payload.len() - got.len()];
        let n = match tokio::time::timeout_at(deadline, tls.read(&mut chunk)).await {
            Ok(Ok(0)) => {
                tunnel.unregister_stream(sid).await;
                return Err(InterflowError::connection(
                    "stream closed by the peer before the echo completed",
                ));
            }
            Ok(Ok(n)) => n,
            Ok(Err(e)) => {
                tunnel.unregister_stream(sid).await;
                return Err(
                    InterflowError::connection(format!("inner stream read failed")).with_source(e),
                );
            }
            Err(_) => {
                tunnel.unregister_stream(sid).await;
                return Err(InterflowError::connection("echo timed out"));
            }
        };
        got.extend_from_slice(&chunk[..n]);
    }
    let _ = tunnel.send_close(sid).await;
    tunnel.unregister_stream(sid).await;
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

/// Waits until one more session is established after `baseline` — the
/// monotonic proof that the supervisor observed the death and rebuilt
/// (`AgentHandle::sessions_established` cannot miss a rebuild, unlike a
/// state watcher: a watch channel keeps only the latest value, so a fast
/// Connected → Reconnecting → Connected cycle can be invisible to it).
async fn wait_session_rebuilt(handle: &AgentHandle, baseline: u64, timeout: Duration) -> bool {
    let deadline = tokio::time::Instant::now() + timeout;
    while handle.sessions_established() <= baseline {
        if tokio::time::Instant::now() >= deadline {
            return false;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    true
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
    let _hub = spawn_hub(hub_config(0, certs(), Vec::new())).await;
    let hub_port = _hub.local_addr().expect("hub bound").port();
    let mut egress_cfg = agent_config("egress", hub_port, certs());
    egress_cfg.egress = vec![tcp_egress_rule("echo", echo_addr)];
    let egress = spawn_agent_registered(egress_cfg).await;
    settle_fault_surface(echo_addr, agent_config("settle-probe", hub_port, certs())).await;
    (echo_addr, hub_port, egress)
}

/// Proves the stack's egress agent is past every once-each transport fault
/// point before the test arms its plan: `spawn_agent_registered` returns
/// while the streaming rounds (upload / poll first establish) are still
/// settling, and the fault hook is process-global — the plan raced those
/// settling rounds ~1-3% of runs (the harness's own egress consumed the
/// fault, the agent under test never died, "death/stall unobserved"). One
/// data round trip through a throwaway probe agent proves both rounds
/// established; the probe shuts down before the test's own agents spawn.
/// The hand-written counterpart of this discipline already existed in
/// `quic_accept_loop_panic_rebuilds_session` (front first, then arm).
async fn settle_fault_surface(echo_addr: SocketAddr, probe_cfg: AgentConfig) {
    let probe = spawn_agent(probe_cfg);
    let payload = b"fault-surface-settled\n".repeat(4);
    let got = round_trip_eventually(
        &probe.tunnel(),
        "egress",
        echo_addr,
        &payload,
        Duration::from_secs(10),
    )
    .await
    .expect("settle probe: one round trip through the stack's egress");
    assert_eq!(got, payload);
    let _ = probe.shutdown_graceful().await;
}

/// A tuned fast-heartbeat hub config (aging window ≈ 2s) for the
/// stall-watchdog cases.
fn fast_heartbeat_h2_config(hub_port: u16) -> interflow_mesh::config::HubConfig {
    hub_config_tuned(
        hub_port,
        certs(),
        Vec::new(),
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
    let front = spawn_agent(agent_config("front", hub_port, certs()));

    // Recovery: Connected again within the rebuild budget.
    assert!(
        wait_agent_connected(&front, REBUILD_BUDGET).await,
        "agent must re-register after a run_session panic (state: {:?})",
        front.state()
    );
    assert!(
        faults
            .wait_fired(
                FaultPoint::AgentSessionAfterRegister,
                Duration::from_secs(5)
            )
            .await,
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
    let front = spawn_agent(agent_config("front", hub_port, certs()));
    assert!(
        wait_agent_connected(&front, Duration::from_secs(10)).await,
        "agent should connect initially (state: {:?})",
        front.state()
    );
    assert!(
        faults
            .wait_fired(
                FaultPoint::H2UploadLoopAfterEstablish,
                Duration::from_secs(5)
            )
            .await,
        "the upload-loop fault must have fired"
    );

    // NOTE on the failure shape: the upload stream's request body is owned
    // by the hyper connection driver once the request is sent, so the data
    // plane keeps flowing after the task dies — the gap is that nothing
    // watches or rebuilds the upload anymore. The invariant under test is
    // therefore "the session ends and rebuilds", not "traffic breaks".
    assert!(
        wait_session_rebuilt(&front, 1, REBUILD_BUDGET).await,
        "the upload task's death must end the session (sessions established: {} — death unobserved)",
        front.sessions_established()
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
    let _ = tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .try_init();
    fault::clear();
    let (echo_addr, hub_port, egress) = h2_stack_with_egress().await;

    let faults = fault::install(FaultPlan::new().panic_at(FaultPoint::H2PollLoopAfterConnect));
    let front = spawn_agent(agent_config("front", hub_port, certs()));
    assert!(
        wait_agent_connected(&front, Duration::from_secs(10)).await,
        "agent should connect initially (state: {:?})",
        front.state()
    );
    assert!(
        faults
            .wait_fired(FaultPoint::H2PollLoopAfterConnect, Duration::from_secs(5))
            .await,
        "the poll-loop fault must have fired"
    );

    assert!(
        wait_session_rebuilt(&front, 1, REBUILD_BUDGET).await,
        "the poll task's death must end the session (sessions established: {} — death unobserved)",
        front.sessions_established()
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
    let _hub = spawn_hub(fast_heartbeat_h2_config(0)).await;
    let hub_port = _hub.local_addr().expect("hub bound").port();
    let mut egress_cfg = agent_config("egress", hub_port, certs());
    egress_cfg.egress = vec![tcp_egress_rule("echo", echo_addr)];
    let egress = spawn_agent_registered(egress_cfg).await;
    settle_fault_surface(echo_addr, agent_config("settle-probe", hub_port, certs())).await;

    let faults = fault::install(FaultPlan::new().stall_at(FaultPoint::H2UploadLoopStall));
    let front = spawn_agent(agent_config("front", hub_port, certs()));
    assert!(
        wait_agent_connected(&front, Duration::from_secs(10)).await,
        "agent should connect initially (state: {:?})",
        front.state()
    );
    assert!(
        faults
            .wait_fired(FaultPoint::H2UploadLoopStall, Duration::from_secs(5))
            .await,
        "the upload-loop stall must have fired"
    );

    // The wedged uplink must be noticed: the session ends (state leaves
    // Connected) within a heartbeat-derived window, then recovers. The
    // budget is deliberately generous: on slow shared CI runners the
    // watchdog's ticks get starved long past the ~2s aging window (the
    // detection still happens — just late); 15s was observed flaking there.
    assert!(
        wait_session_rebuilt(&front, 1, Duration::from_secs(60)).await,
        "a wedged upload task must end the session (sessions established: {} — stall not detected)",
        front.sessions_established()
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

    // Guaranteed-refused by construction (port 1 is below every ephemeral
    // range) — no pick-then-release race against parallel tests.
    let closed_port = refused_addr().port();
    let mut cfg = agent_config("doomed", closed_port, certs());
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
        faults
            .wait_fired(FaultPoint::AgentSuperviseLoopTick, Duration::from_secs(5))
            .await,
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
    let (echo_addr, _echo_handle) = echo_server().await;
    let mut hub_cfg = hub_quic_config(0, certs(), Vec::new());
    hub_cfg.heartbeat = HeartbeatConfig {
        enabled: false,
        interval_secs: 15,
        max_missed: 4,
    };
    let _hub = spawn_hub(hub_cfg).await;
    let hub_port = _hub.local_addr().expect("hub bound").port();

    let mut egress_cfg = agent_quic_config("egress", hub_port, certs());
    egress_cfg.egress = vec![tcp_egress_rule("echo", echo_addr)];
    let egress = spawn_agent_registered(egress_cfg).await;
    settle_fault_surface(
        echo_addr,
        agent_quic_config("settle-probe", hub_port, certs()),
    )
    .await;

    let faults = fault::install(FaultPlan::new().panic_at(FaultPoint::QuicControlReadLoop));
    let front = spawn_agent(agent_quic_config("front", hub_port, certs()));
    assert!(
        wait_agent_connected(&front, Duration::from_secs(10)).await,
        "agent should connect initially (state: {:?})",
        front.state()
    );
    assert!(
        faults
            .wait_fired(FaultPoint::QuicControlReadLoop, Duration::from_secs(5))
            .await,
        "the QUIC control-read fault must have fired"
    );

    assert!(
        wait_session_rebuilt(&front, 1, REBUILD_BUDGET).await,
        "the control-read task's death must end the session (sessions established: {} — death unobserved)",
        front.sessions_established()
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
    let (echo_addr, _echo_handle) = echo_server().await;
    let mut hub_cfg = hub_quic_config(0, certs(), Vec::new());
    hub_cfg.heartbeat = HeartbeatConfig {
        enabled: true,
        interval_secs: 1,
        max_missed: 1,
    };
    let _hub = spawn_hub(hub_cfg).await;
    let hub_port = _hub.local_addr().expect("hub bound").port();

    // Ordering discipline: front first (its accept-loop consult precedes the
    // plan), then arm, then the targeted egress agent.
    let front = spawn_agent_registered(agent_quic_config("front", hub_port, certs())).await;

    let faults = fault::install(FaultPlan::new().panic_at(FaultPoint::QuicAcceptLoop));
    let mut egress_cfg = agent_quic_config("egress", hub_port, certs());
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
    let (echo_addr, _echo_handle) = echo_server().await;
    // First bind :0 (kernel-assigned = owned at bind), then pin the
    // materialized port for the restart — the agents' hub address is baked
    // before hub 1 even exists.
    let hub_cfg = |port: u16| {
        let mut c = hub_quic_config(port, certs(), Vec::new());
        c.heartbeat = HeartbeatConfig {
            enabled: true,
            interval_secs: 1,
            max_missed: 1,
        };
        c
    };

    let _hub1 = spawn_hub(hub_cfg(0)).await;
    let hub_port = _hub1.local_addr().expect("hub bound").port();

    let mut egress_cfg = agent_quic_config("egress", hub_port, certs());
    egress_cfg.egress = vec![tcp_egress_rule("echo", echo_addr)];
    let _egress_keep = spawn_agent_registered(egress_cfg).await;

    let faults = fault::install(FaultPlan::new().panic_at(FaultPoint::QuicClosedWatcher));
    let front = spawn_agent(agent_quic_config("front", hub_port, certs()));
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
    _hub1.shutdown_graceful().await.expect("first hub shutdown");
    assert!(
        wait_port_rebindable(hub_port, Duration::from_secs(10)).await,
        "hub port must become rebindable after graceful shutdown"
    );
    let _hub2 = spawn_hub(hub_cfg(hub_port)).await;
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
    let (echo_addr, _echo_handle) = echo_server().await;
    let mut hub_cfg = hub_quic_config(0, certs(), Vec::new());
    hub_cfg.heartbeat = HeartbeatConfig {
        enabled: true,
        interval_secs: 1,
        max_missed: 1,
    };
    let _hub = spawn_hub(hub_cfg).await;
    let hub_port = _hub.local_addr().expect("hub bound").port();

    let mut egress_cfg = agent_quic_config("egress", hub_port, certs());
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
    let mut front_cfg = agent_quic_config("front", hub_port, certs());
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
        wait_session_rebuilt(&front, 1, Duration::from_secs(15)).await,
        "a wedged control-write task must end the session (sessions established: {} — stall not detected)",
        front.sessions_established()
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

/// The steady-state survival window (the 2026-10-07 zero-attribution case's
/// e2e gap): every existing self-heal test observes at rebuild-budget scale
/// — no case ever crosses the steady-state periodic horizon (the 15s
/// ingress reconcile / egress refresh ticks, the 10s policy pull, the 15s
/// heartbeat cadence). The 455991a field death (~18-21s after
/// establishment, both legs) fell exactly in that blind spot. This test
/// pins one QUIC session through a >=60s window at PRODUCTION cadence,
/// asserting:
/// - no rebuild: `sessions_established` stays at 1 (the monotonic counter
///   cannot miss a fast Connected → Reconnecting → Connected cycle);
/// - the state stays Connected;
/// - the data plane answers at ~20s/40s/60s — the field-death instants.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn quic_session_survives_steady_state_window() {
    let _serial = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
    fault::clear();
    let (echo_addr, _echo_handle) = echo_server().await;
    // Production cadence on purpose: the 15s heartbeat interval is what the
    // field deployment runs, and the window must cover the ticks that only
    // fire at that scale.
    let mut hub_cfg = hub_quic_config(0, certs(), Vec::new());
    hub_cfg.heartbeat = HeartbeatConfig {
        enabled: true,
        interval_secs: 15,
        max_missed: 4,
    };
    let _hub = spawn_hub(hub_cfg).await;
    let hub_port = _hub.local_addr().expect("hub bound").port();

    let mut egress_cfg = agent_quic_config("egress", hub_port, certs());
    egress_cfg.egress = vec![tcp_egress_rule("echo", echo_addr)];
    let egress = spawn_agent_registered(egress_cfg).await;
    let front = spawn_agent_registered(agent_quic_config("front", hub_port, certs())).await;
    assert_eq!(
        front.sessions_established(),
        1,
        "precondition: exactly one established session"
    );
    let tunnel = front.tunnel();

    // >=60s steady-state window: 4x the 15s reconcile/refresh/heartbeat
    // ticks, 6x the 10s policy pull — the field-death instants (~18-21s)
    // land well inside. The out-of-tree silence probe's budget (90s at this
    // cadence) must NOT trip on a healthy session.
    let window = Duration::from_secs(60);
    let started = tokio::time::Instant::now();
    let mut next_probe = started + Duration::from_secs(20);
    let mut probes_done = 0usize;
    while tokio::time::Instant::now() - started < window {
        tokio::time::sleep(Duration::from_millis(500)).await;
        assert_eq!(
            front.sessions_established(),
            1,
            "a healthy session must not rebuild inside the steady-state window"
        );
        assert!(
            matches!(front.state(), AgentState::Connected { .. }),
            "state drifted inside the window: {:?}",
            front.state()
        );
        if tokio::time::Instant::now() >= next_probe {
            let payload = b"steady-state-probe\n".repeat(4);
            let got = round_trip_eventually(
                &tunnel,
                "egress",
                echo_addr,
                &payload,
                Duration::from_secs(5),
            )
            .await
            .unwrap_or_else(|e| panic!("data plane dead at {:?}: {e}", next_probe - started));
            assert_eq!(got, payload);
            probes_done += 1;
            next_probe += Duration::from_secs(20);
        }
    }
    assert!(
        probes_done >= 3,
        "expected >=3 data-plane probes, got {probes_done}"
    );

    fault::clear();
    let _ = front.shutdown_graceful().await;
    let _ = egress.shutdown_graceful().await;
}

/// The demanding tier's e2e (the 2026-10-09 one-way-blackhole case,
/// reproduced): the hub swallows every liveness-probe roundtrip while its
/// heartbeat Pings keep flowing — so the agent's receive ledger stays FRESH
/// (the passive tier is blind by construction, exactly the incident's
/// unexplained residual) and the quinn connection object stays alive. Only
/// the demanding tier — which asks a question and believes only the answer
/// — can see the dead path: three unanswered probes (~30s cadence) must end
/// the session and rebuild it, and once the swallow is disarmed the session
/// must stabilize and serve traffic.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn quic_demanding_probe_rebuilds_when_the_hub_stops_answering() {
    let _serial = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
    let _ = tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .try_init();
    fault::clear();
    let (echo_addr, _echo_handle) = echo_server().await;
    // Production heartbeat cadence: the Pings keep the agent's ledger fed
    // for the whole window, pinning the passive tier out of the picture.
    let mut hub_cfg = hub_quic_config(0, certs(), Vec::new());
    hub_cfg.heartbeat = HeartbeatConfig {
        enabled: true,
        interval_secs: 15,
        max_missed: 4,
    };
    let _hub = spawn_hub(hub_cfg).await;
    let hub_port = _hub.local_addr().expect("hub bound").port();

    let mut egress_cfg = agent_quic_config("egress", hub_port, certs());
    egress_cfg.egress = vec![tcp_egress_rule("echo", echo_addr)];
    let egress = spawn_agent_registered(egress_cfg).await;
    let front = spawn_agent_registered(agent_quic_config("front", hub_port, certs())).await;
    assert_eq!(front.sessions_established(), 1);

    // Arm the swallow AFTER both agents registered (the injection-ordering
    // discipline): every future liveness roundtrip opens a stream the hub
    // drops without answering. stall_every_at = while-armed semantics, so
    // this is the standing blackhole for probe streams only.
    let faults =
        fault::install(FaultPlan::new().stall_every_at(FaultPoint::HubQuicSwallowLivenessProbe));
    // Let the first few post-arm probes be swallowed (the probe fires its
    // first demand ~30s after session start, then one per cadence; three
    // strikes ≈ 90-105s).
    assert!(
        faults
            .wait_fired(
                FaultPoint::HubQuicSwallowLivenessProbe,
                Duration::from_secs(60)
            )
            .await,
        "the swallow must have fired (the probe's demands reach the hub)"
    );
    assert!(
        wait_session_rebuilt(&front, 1, Duration::from_secs(150)).await,
        "three unanswered demanding probes must rebuild the session — the \
         path is dead while the heartbeat-fed ledger stayed fresh \
         (sessions established: {})",
        front.sessions_established()
    );

    // Disarm: the next rebuild's probes get answered — the session must
    // stabilize (no further rebuild across several probe cadences) and the
    // data plane must serve.
    fault::clear();
    assert!(
        wait_agent_connected(&front, Duration::from_secs(10)).await,
        "state must return to Connected after the swallow is disarmed: {:?}",
        front.state()
    );
    let stabilized_at = front.sessions_established();
    tokio::time::sleep(Duration::from_secs(70)).await;
    assert_eq!(
        front.sessions_established(),
        stabilized_at,
        "with the swallow disarmed the session must stop rebuilding \
         (2+ probe cadences elapsed)"
    );
    let tunnel = front.tunnel();
    let payload = b"liveness-recovered\n".repeat(4);
    let got = round_trip_eventually(&tunnel, "egress", echo_addr, &payload, REBUILD_BUDGET)
        .await
        .expect("traffic must flow again once the hub answers probes");
    assert_eq!(got, payload);

    let _ = front.shutdown_graceful().await;
    let _ = egress.shutdown_graceful().await;
}

/// The hub's eviction notice (the 2026-10-09 fix's fast path): when the
/// QUIC heartbeat dead line evicts an agent whose connection is still
/// transport-alive (the Pong path wedged, Pings still arriving), the hub's
/// best-effort CONNECTION_CLOSE rides the still-working reverse direction
/// and the agent rebuilds immediately — bounded by the hub's 2s dead line,
/// NOT by the agent's own much-longer stall line (pinned to 30s here:
/// without the close, the only death signal left is the 30s stall
/// watchdog, and this test's 15s budget fails).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn quic_heartbeat_evict_notice_reaches_the_agent_and_rebuilds_fast() {
    let _serial = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
    let _ = tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .try_init();
    fault::clear();
    let (echo_addr, _echo_handle) = echo_server().await;
    let mut hub_cfg = hub_quic_config(0, certs(), Vec::new());
    hub_cfg.heartbeat = HeartbeatConfig {
        enabled: true,
        interval_secs: 1,
        max_missed: 1,
    };
    let _hub = spawn_hub(hub_cfg).await;
    let hub_port = _hub.local_addr().expect("hub bound").port();

    let mut egress_cfg = agent_quic_config("egress", hub_port, certs());
    egress_cfg.egress = vec![tcp_egress_rule("echo", echo_addr)];
    let egress = spawn_agent_registered(egress_cfg).await;

    // Injection-ordering discipline (the plan is process-global and
    // one-shot): egress must answer at least one Pong — its forwarder's
    // fault consult happens on the first FORWARDED frame, a heartbeat
    // after registration — before the plan exists, or the wedge lands on
    // egress instead of front.
    tokio::time::sleep(Duration::from_secs(3)).await;

    // Wedge front's control-write forwarder on its first Pong (the
    // connection stays transport-alive; the hub's heartbeat deadline is
    // the eviction trigger).
    let faults = fault::install(FaultPlan::new().stall_at(FaultPoint::QuicControlWriteStall));
    let mut front_cfg = agent_quic_config("front", hub_port, certs());
    // Pin the agent's OWN stall line far above the hub's 2s dead line, so
    // the only sub-15s death signal available to the agent is the hub's
    // eviction close.
    front_cfg.agent.task_stall_timeout_secs = Some(30);
    let front = spawn_agent(front_cfg);
    assert!(
        wait_agent_connected(&front, Duration::from_secs(10)).await,
        "agent should connect initially (state: {:?})",
        front.state()
    );
    assert!(
        faults
            .wait_fired(FaultPoint::QuicControlWriteStall, Duration::from_secs(10))
            .await,
        "the control-write wedge must have fired"
    );
    assert!(
        wait_session_rebuilt(&front, 1, Duration::from_secs(15)).await,
        "the hub's eviction close must reach the agent well inside its own \
         30s stall line (sessions established: {})",
        front.sessions_established()
    );

    // The fault was one-shot: the rebuilt session is healthy — data-plane
    // proof that the rebuild landed on a working path.
    fault::clear();
    let tunnel = front.tunnel();
    let payload = b"evict-notice-recovered\n".repeat(4);
    let got = round_trip_eventually(&tunnel, "egress", echo_addr, &payload, REBUILD_BUDGET)
        .await
        .expect("traffic must flow on the post-notice rebuild");
    assert_eq!(got, payload);

    let _ = front.shutdown_graceful().await;
    let _ = egress.shutdown_graceful().await;
}

/// The out-of-tree silence probe must spare a healthy h2 session: with a
/// 1s heartbeat the poll watchdog is 2s, so the probe's budget is 4s —
/// running well past 3x that budget with zero rebuilds proves the probe
/// (and the frozen-ledger verdict behind it) cannot false-positive on a
/// session whose downlink is merely quiet between heartbeat pings.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn h2_out_of_tree_probe_spares_a_healthy_session() {
    let _serial = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
    fault::clear();
    let (echo_addr, _echo_handle) = echo_server().await;
    let mut hub_cfg = hub_config(0, certs(), Vec::new());
    hub_cfg.heartbeat = HeartbeatConfig {
        enabled: true,
        interval_secs: 1,
        max_missed: 1,
    };
    let _hub = spawn_hub(hub_cfg).await;
    let hub_port = _hub.local_addr().expect("hub bound").port();

    let mut egress_cfg = agent_config("egress", hub_port, certs());
    egress_cfg.egress = vec![tcp_egress_rule("echo", echo_addr)];
    let egress = spawn_agent_registered(egress_cfg).await;
    let front = spawn_agent_registered(agent_config("front", hub_port, certs())).await;
    assert_eq!(front.sessions_established(), 1);
    let tunnel = front.tunnel();

    // 15s > 3x the probe's 4s budget at this cadence
    let window = Duration::from_secs(15);
    let started = tokio::time::Instant::now();
    while tokio::time::Instant::now() - started < window {
        tokio::time::sleep(Duration::from_millis(250)).await;
        assert_eq!(
            front.sessions_established(),
            1,
            "the out-of-tree probe must not kill a healthy h2 session"
        );
        assert!(
            matches!(front.state(), AgentState::Connected { .. }),
            "state drifted: {:?}",
            front.state()
        );
    }
    let payload = b"h2-probe-spared\n".repeat(4);
    let got = round_trip_eventually(&tunnel, "egress", echo_addr, &payload, REBUILD_BUDGET)
        .await
        .expect("traffic must still flow after sitting out 3x the probe budget");
    assert_eq!(got, payload);

    fault::clear();
    let _ = front.shutdown_graceful().await;
    let _ = egress.shutdown_graceful().await;
}
