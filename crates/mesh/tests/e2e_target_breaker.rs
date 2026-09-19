//! E2E: per-target circuit breaker — one dead target must not starve healthy
//! targets (2026-09-16 starvation regression suite).
//!
//! Case file: `docs/bug/2026-09-16-egress-global-rate-limit-starvation.md`.
//! The incident: an edge route pointed at a dead local backend (config
//! error) plus a public retry loop flooded the agent with Opens; the
//! agent-wide stream-open rate budget was charged before the target was even
//! parsed, so the dead target's retries drained the bucket every healthy
//! route shared — all of them rejected with `rate_limited`.
//!
//! Scenarios:
//! - B1 (the incident's discriminating test): a dead-target Open storm
//!   trips the breaker after the threshold; subsequent storm Opens are
//!   rejected pre-dial (`target_circuit_open`) **without consuming the
//!   open-rate budget** — a healthy stream succeeds immediately afterwards
//!   with a budget too small to survive even one wasted token, and zero
//!   rate_limited drops occur in the whole test.
//! - B2 (self-healing): the backend comes up mid-test; after the cooldown
//!   one recovery probe is admitted, round-trips, and the target is fully
//!   re-admitted.
//! - B3 (opt-out): with the breaker disabled the old behavior returns —
//!   the storm dials on every Open and a healthy stream is rate-limited
//!   (the original starvation, now by choice).
//!
//! The metrics recorder is shared in-process and counters accumulate
//! monotonically; assertions use before/after deltas and tests serialize on
//! a lock (same pattern as `e2e_open_flood.rs`).

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
use interflow_core::protocol::{FrameType, StreamProto};
use interflow_core::tunnel::AgentTunnel;
use interflow_mesh::agent::AgentClient;
use interflow_testkit::{
    agent_config, echo_server, hub_config, metrics_harness::counter_value,
    metrics_harness::init_tracing, metrics_harness::metrics_handle,
    metrics_harness::wait_counter_at_least, pick_ephemeral_port, spawn_hub,
};
use std::net::SocketAddr;
use std::sync::OnceLock;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

fn certs() -> &'static interflow_testkit::certs::TestCerts {
    static C: std::sync::OnceLock<interflow_testkit::certs::TestCerts> = std::sync::OnceLock::new();
    C.get_or_init(|| interflow_testkit::certs::TestCerts::generate("e2e", "agent"))
}

static SERIAL: OnceLock<tokio::sync::Mutex<()>> = OnceLock::new();

async fn serial_lock() -> tokio::sync::MutexGuard<'static, ()> {
    SERIAL
        .get_or_init(|| tokio::sync::Mutex::new(()))
        .lock()
        .await
}

const OPEN_DROP_CIRCUIT: &str =
    "interflow_agent_open_dropped_total{reason=\"target_circuit_open\"}";
const OPEN_DROP_RATE: &str = "interflow_agent_open_dropped_total{reason=\"rate_limited\"}";
const CLOSED_CONNECT_FAILED: &str =
    "interflow_egress_stream_closed_total{reason=\"connect_failed\"}";
const BREAKER_OPENED: &str = "interflow_egress_target_breaker_transitions_total{state=\"open\"}";
const BREAKER_RECOVERED: &str =
    "interflow_egress_target_breaker_transitions_total{state=\"closed\"}";

// ---------------------------------------------------------------------------
// scaffolding (same bare-tunnel injection pattern as e2e_open_flood.rs)
// ---------------------------------------------------------------------------

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
        agent_id.to_string(),
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

/// Open a stream toward `target` and wait until it is rejected (Close
/// received); returns the elapsed time.
async fn open_until_rejected(inj: &AgentTunnel, sid: &str, target: &str) -> Duration {
    let started = std::time::Instant::now();
    let mut rx = inj.register_stream(sid.to_string()).await;
    inj.send_open(sid, "eg", Some(target), StreamProto::Tcp)
        .await
        .expect("open");
    let deadline = tokio::time::Instant::now() + Duration::from_secs(8);
    loop {
        let td = tokio::time::timeout_at(deadline, rx.recv())
            .await
            .expect("timed out waiting for the rejecting Close")
            .expect("channel alive");
        if matches!(td.stream_type, FrameType::Close) {
            return started.elapsed();
        }
    }
}

/// Full round trip (open + data + echo reply + close) against `target`.
async fn round_trip_closing(
    inj: &AgentTunnel,
    sid: &str,
    target: &str,
    payload: &[u8],
    deadline: Duration,
) -> Vec<u8> {
    let mut rx = inj.register_stream(sid.to_string()).await;
    inj.send_open(sid, "eg", Some(target), StreamProto::Tcp)
        .await
        .expect("open");
    inj.send_data(sid, Bytes::copy_from_slice(payload))
        .await
        .expect("send");
    // recv exactly payload.len bytes, panicking on Close
    let dl = tokio::time::Instant::now() + deadline;
    let mut got = Vec::with_capacity(payload.len());
    while got.len() < payload.len() {
        let td = tokio::time::timeout_at(dl, rx.recv())
            .await
            .expect("reply timed out")
            .expect("channel alive");
        assert!(
            !matches!(td.stream_type, FrameType::Close),
            "stream {sid} closed prematurely (rejected by a defense line)"
        );
        got.extend_from_slice(&td.data);
    }
    inj.send_close(sid).await.expect("close");
    got
}

/// Wait until the egress agent is ready via a healthy echo target.
async fn wait_egress_ready(inj: &AgentTunnel, echo_addr: SocketAddr) {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
    let mut attempt = 0u32;
    loop {
        attempt += 1;
        let sid = format!("probe-{attempt}");
        match round_trip_closing(
            inj,
            &sid,
            &echo_addr.to_string(),
            b"ping",
            Duration::from_secs(2),
        )
        .await
        {
            resp if resp == b"ping" => break,
            _ => {}
        }
        if tokio::time::Instant::now() >= deadline {
            panic!("egress agent not ready within 10s");
        }
        tokio::time::sleep(Duration::from_millis(250)).await;
    }
    tokio::time::sleep(Duration::from_millis(400)).await;
}

/// A raw-echo TCP listener bound on an explicitly chosen port (for the
/// recovery scenario: the port starts dead, the backend binds it later).
async fn echo_on_port(port: u16) -> SocketAddr {
    let listener = TcpListener::bind(("127.0.0.1", port))
        .await
        .expect("rebind port for recovery scenario");
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
}

/// A dead target: grab an ephemeral port, briefly hold it, release —
/// afterwards nothing listens there (connections are refused).
async fn dead_target() -> String {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    drop(listener);
    // Give the OS a moment to actually release the port.
    tokio::time::sleep(Duration::from_millis(50)).await;
    // Sanity: connecting must be refused right now.
    assert!(
        TcpStream::connect(("127.0.0.1", port)).await.is_err(),
        "test precondition: port {port} must be dead"
    );
    format!("127.0.0.1:{port}")
}

// ---------------------------------------------------------------------------
// B1: the incident's discriminating test
// ---------------------------------------------------------------------------

/// Budget: rate 2/s, burst 4; breaker threshold 3 (window 10s default,
/// cooldown 30s default — no recovery happens within this test). After the
/// readiness probe refills the bucket to 4: three dead-target Opens dial and
/// fail (3 tokens), the breaker trips; 50 storm Opens are then rejected
/// pre-dial with `target_circuit_open` and consume **zero** tokens; the
/// healthy round trip immediately afterwards succeeds on the single
/// remaining burst token — with the pre-fix gate order the same storm would
/// have consumed the whole bucket and the healthy stream would be
/// `rate_limited` for ≥500ms (2/s refill), failing this test.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn b1_dead_target_storm_does_not_starve_healthy() {
    let _serial = serial_lock().await;
    let _ = metrics_handle();
    init_tracing();
    let hub_port = pick_ephemeral_port();
    spawn_hub(hub_config(hub_port, certs(), vec![])).await;
    let (echo_addr, _echo) = echo_server().await;
    let dead = dead_target().await;

    let mut eg = agent_config("eg", hub_port, certs());
    eg.max_stream_opens_per_sec = 2;
    eg.stream_open_burst = 4;
    eg.max_incoming_streams = 0;
    eg.egress_target_breaker_failure_threshold = 3;
    eg.egress_target_breaker_window_secs = 10;
    eg.egress_target_breaker_cooldown_secs = 30;
    interflow_testkit::spawn_agent_registered(eg).await;

    let (inj, _conn) = connect_tunnel(hub_port, "inj").await;
    wait_egress_ready(&inj, echo_addr).await;
    // Refill the burst bucket fully (2/s ⇒ 2.5s ≥ burst 4).
    tokio::time::sleep(Duration::from_millis(2500)).await;

    let cf_before = counter_value(CLOSED_CONNECT_FAILED);
    let rate_before = counter_value(OPEN_DROP_RATE);
    let circuit_before = counter_value(OPEN_DROP_CIRCUIT);

    // Phase 1: three dials, all refused — the breaker trips.
    for i in 0..3 {
        let elapsed = open_until_rejected(&inj, &format!("b1-dial-{i}"), &dead).await;
        assert!(
            elapsed < Duration::from_secs(4),
            "refused dial must fail fast, got {elapsed:?}"
        );
    }
    wait_counter_at_least(BREAKER_OPENED, 1, Duration::from_secs(5)).await;

    // Phase 2: the storm — 50 Opens, all rejected pre-dial, no dial work.
    for i in 0..50 {
        let elapsed = open_until_rejected(&inj, &format!("b1-storm-{i}"), &dead).await;
        assert!(
            elapsed < Duration::from_secs(2),
            "circuit-open rejection must be fast, got {elapsed:?}"
        );
    }

    // Phase 3 (the regression): the healthy target still has budget — this
    // round trip must succeed immediately on the remaining burst token.
    let healthy_started = std::time::Instant::now();
    let got = round_trip_closing(
        &inj,
        "b1-healthy",
        &echo_addr.to_string(),
        b"ping",
        Duration::from_secs(2),
    )
    .await;
    assert_eq!(got, b"ping");
    assert!(
        healthy_started.elapsed() < Duration::from_millis(400),
        "healthy stream should not wait for a rate refill, took {:?}",
        healthy_started.elapsed()
    );

    // Bounded dial work + zero budget consumed by the storm.
    let cf_delta = counter_value(CLOSED_CONNECT_FAILED) - cf_before;
    assert_eq!(cf_delta, 3, "exactly threshold dials, got {cf_delta}");
    assert!(
        counter_value(OPEN_DROP_CIRCUIT) - circuit_before >= 50,
        "storm Opens must be rejected as target_circuit_open"
    );
    assert_eq!(
        counter_value(OPEN_DROP_RATE) - rate_before,
        0,
        "the dead-target storm must not consume the shared open-rate budget"
    );
}

// ---------------------------------------------------------------------------
// B2: self-healing when the backend comes up
// ---------------------------------------------------------------------------

/// Threshold 2, cooldown 2s; the rate limiter is disabled to isolate the
/// breaker dimension. The target starts dead (storm trips it), the backend
/// binds the port mid-test, and after the cooldown exactly one recovery
/// probe is admitted — it round-trips, the breaker recovers, and the target
/// is fully re-admitted.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn b2_recovery_after_backend_starts() {
    let _serial = serial_lock().await;
    let _ = metrics_handle();
    init_tracing();
    let hub_port = pick_ephemeral_port();
    spawn_hub(hub_config(hub_port, certs(), vec![])).await;
    let (echo_addr, _echo) = echo_server().await;
    let dead = dead_target().await;

    let mut eg = agent_config("eg", hub_port, certs());
    eg.max_stream_opens_per_sec = 0;
    eg.max_incoming_streams = 0;
    eg.egress_target_breaker_failure_threshold = 2;
    eg.egress_target_breaker_window_secs = 10;
    eg.egress_target_breaker_cooldown_secs = 2;
    interflow_testkit::spawn_agent_registered(eg).await;

    let (inj, _conn) = connect_tunnel(hub_port, "inj").await;
    wait_egress_ready(&inj, echo_addr).await;

    // Storm: trip the breaker on the dead target.
    for i in 0..5 {
        open_until_rejected(&inj, &format!("b2-storm-{i}"), &dead).await;
    }
    wait_counter_at_least(BREAKER_OPENED, 1, Duration::from_secs(5)).await;

    // The backend comes up on the very port the route points at.
    let revived = echo_on_port(dead.rsplit(':').next().unwrap().parse().unwrap()).await;

    // Still within the cooldown: rejected without dialing.
    open_until_rejected(&inj, "b2-still-open", &dead).await;

    // After the cooldown the recovery probe is admitted and round-trips.
    tokio::time::sleep(Duration::from_millis(2600)).await;
    let got = round_trip_closing(
        &inj,
        "b2-probe",
        &revived.to_string(),
        b"alive",
        Duration::from_secs(5),
    )
    .await;
    assert_eq!(got, b"alive");
    wait_counter_at_least(BREAKER_RECOVERED, 1, Duration::from_secs(5)).await;

    // Fully re-admitted: an immediate second stream succeeds too.
    let got = round_trip_closing(
        &inj,
        "b2-after",
        &revived.to_string(),
        b"again",
        Duration::from_secs(5),
    )
    .await;
    assert_eq!(got, b"again");
}

// ---------------------------------------------------------------------------
// B3: opt-out — disabled breaker restores the old (starving) behavior
// ---------------------------------------------------------------------------

/// Same storm with the breaker disabled: every Open dials, the tiny budget
/// (rate 2/s, burst 4) is drained by the dead target, and the healthy
/// stream is rejected `rate_limited` — the original incident mechanics,
/// available by explicit configuration choice.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn b3_disabled_breaker_restores_old_behavior() {
    let _serial = serial_lock().await;
    let _ = metrics_handle();
    init_tracing();
    let hub_port = pick_ephemeral_port();
    spawn_hub(hub_config(hub_port, certs(), vec![])).await;
    let (echo_addr, _echo) = echo_server().await;
    let dead = dead_target().await;

    let mut eg = agent_config("eg", hub_port, certs());
    eg.max_stream_opens_per_sec = 2;
    eg.stream_open_burst = 4;
    eg.max_incoming_streams = 0;
    eg.egress_target_breaker_enabled = false;
    interflow_testkit::spawn_agent_registered(eg).await;

    let (inj, _conn) = connect_tunnel(hub_port, "inj").await;
    wait_egress_ready(&inj, echo_addr).await;
    tokio::time::sleep(Duration::from_millis(2500)).await;

    let cf_before = counter_value(CLOSED_CONNECT_FAILED);
    let circuit_before = counter_value(OPEN_DROP_CIRCUIT);
    let rate_before = counter_value(OPEN_DROP_RATE);

    // Storm: without the breaker the dead target consumes the ENTIRE shared
    // budget (burst 4 dials; the remaining 6 Opens are rate_limited during
    // the storm itself).
    for i in 0..10 {
        open_until_rejected(&inj, &format!("b3-storm-{i}"), &dead).await;
    }
    let cf_delta = counter_value(CLOSED_CONNECT_FAILED) - cf_before;
    assert_eq!(
        cf_delta, 4,
        "disabled breaker: the dead target dials through the whole burst budget (got {cf_delta})"
    );
    assert!(
        counter_value(OPEN_DROP_RATE) - rate_before >= 1,
        "with no breaker the storm itself exhausts the shared budget"
    );
    assert_eq!(
        counter_value(OPEN_DROP_CIRCUIT) - circuit_before,
        0,
        "breaker disabled: no target_circuit_open rejections"
    );

    // The healthy stream is starved out: rejected (rate_limited).
    let elapsed = open_until_rejected(&inj, "b3-starved", &echo_addr.to_string()).await;
    assert!(
        elapsed < Duration::from_secs(3),
        "rate-limited rejection is fast, got {elapsed:?}"
    );
    assert!(
        counter_value(OPEN_DROP_RATE) - rate_before >= 1,
        "the storm drained the shared budget (the original starvation)"
    );
}
