//! E2E: per-target circuit breaker — one dead target must not starve healthy
//! targets (2026-09-16 starvation regression suite).
//!
//! Case file: `(internal design notes)`.
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
//! - B2 (self-healing via the cooldown path, prober disabled): the backend
//!   comes up mid-test; after the cooldown one recovery probe is admitted,
//!   round-trips, and the target is fully re-admitted. The passive path
//!   must stay covered — it is the fallback when the prober is off.
//! - B3 (opt-out): with the breaker disabled the old behavior returns —
//!   the storm dials on every Open and a healthy stream is rate-limited
//!   (the original starvation, now by choice).
//! - B4 (active recovery, 2026-10-18): with the prober on its default
//!   cadence and **zero inbound Opens after the trip**, a revived backend
//!   is re-admitted within the probe period — strictly before the cooldown
//!   could have elapsed. Pre-fix this cannot pass: passive recovery
//!   requires cooldown + an admitted probe stream.
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
    missing_docs
)]
use interflow_core::protocol::StreamProto;
use interflow_core::tls::{InnerTlsMaterial, inner_client_config};
use interflow_core::tunnel::AgentTunnel;
use interflow_core::tunnel::e2e::{E2eHandshakeOutcome, E2eTunnelIo, inner_tls_connect};
use interflow_core::tunnel::{InnerStreamHello, TargetSelector};
use interflow_mesh::agent::AgentClient;
use interflow_testkit::{
    agent_config, echo_server, hub_config, metrics_harness::counter_value,
    metrics_harness::gauge_value, metrics_harness::init_tracing, metrics_harness::metrics_handle,
    metrics_harness::wait_counter_at_least, spawn_hub,
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
const BREAKERS_OPEN: &str = "interflow_egress_target_breakers_open";

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

/// Establish production-shaped inner TLS and send the encrypted selector.
async fn open_inner_tls(
    inj: &AgentTunnel,
    sid: interflow_core::protocol::StreamId,
    target: &str,
) -> tokio_rustls::client::TlsStream<tokio::io::DuplexStream> {
    let rx = inj.register_stream(sid).await;
    inj.send_open_with(sid, "eg", StreamProto::Tcp, true)
        .await
        .expect("inner-TLS open");
    let (cert, key) = certs().named_client_cert("inj");
    let ca = certs().ca_path().display().to_string();
    let material = InnerTlsMaterial::from_paths(
        &[ca.as_str()],
        &cert.display().to_string(),
        &key.display().to_string(),
    )
    .expect("inner material");
    let connector = tokio_rustls::TlsConnector::from(
        inner_client_config(&material, "eg").expect("inner connector"),
    );
    let adapter = E2eTunnelIo::ingress(rx, inj.clone(), sid);
    let mut tls = match inner_tls_connect(adapter, connector, Duration::from_secs(5)).await {
        E2eHandshakeOutcome::Established(tls, _) => tls,
        E2eHandshakeOutcome::Failed { error } => panic!("inner TLS handshake: {error}"),
    };
    InnerStreamHello {
        source_principal: "inj".to_owned(),
        source_fingerprint: material.leaf_fingerprint(),
        selector: TargetSelector::Address(target.to_owned()),
        correlation_id: *uuid::Uuid::new_v4().as_bytes(),
    }
    .write(&mut tls)
    .await
    .expect("inner hello");
    tls
}

/// Open a stream toward `target` and wait until it is rejected.
async fn open_until_rejected(
    inj: &AgentTunnel,
    sid: interflow_core::protocol::StreamId,
    target: &str,
) -> Duration {
    let started = std::time::Instant::now();
    let mut tls = open_inner_tls(inj, sid, target).await;
    let mut probe = [0u8; 1];
    // Budget derivation (a function of the test's own timers, not a
    // number moved until green): the rejecting Close rides
    // ingress→hub→egress behind this test's own dial storm — the b3 case
    // bounds a full sequence at < 10s, so intra-test worst case ≈ 10s × 3
    // isolation margin = 30s. The serialized mesh tier (ci_test_stages.sh
    // caps --jobs 1 on <= 2-core runners, 2026-10-11 starvation backlog)
    // is what keeps the derivation valid: cross-test load no longer stacks
    // on the intra-test storm. The retired 8s→30s→60s ladder was exactly
    // that stacking — three rounds of moving the threshold instead of
    // removing the contention.
    let _ = tokio::time::timeout(Duration::from_secs(30), tls.read(&mut probe))
        .await
        .expect("timed out waiting for the rejecting Close")
        .expect_err("dead target must close the inner stream");
    started.elapsed()
}

/// Full round trip against `target`.
async fn round_trip_closing(
    inj: &AgentTunnel,
    sid: interflow_core::protocol::StreamId,
    target: &str,
    payload: &[u8],
    deadline: Duration,
) -> Vec<u8> {
    let mut tls = open_inner_tls(inj, sid, target).await;
    tls.write_all(payload).await.expect("send");
    tls.flush().await.expect("flush");
    let dl = tokio::time::Instant::now() + deadline;
    let mut got = Vec::with_capacity(payload.len());
    while got.len() < payload.len() {
        let mut chunk = vec![0u8; payload.len() - got.len()];
        let n = tokio::time::timeout_at(dl, tls.read(&mut chunk))
            .await
            .expect("reply timed out")
            .expect("stream alive");
        assert_ne!(n, 0, "stream {sid} closed prematurely (defense line)");
        got.extend_from_slice(&chunk[..n]);
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
        let sid = interflow_testkit::opaque_stream_id(&format!("probe-{attempt}"));
        match round_trip_closing(
            inj,
            sid,
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

/// A dead target: bind `:0` to materialize a port, then release — nothing
/// listens there (connections refused) until the recovery phase rebinds an
/// echo server on the same concrete port. Unix offers no
/// reserve-but-don't-listen primitive, so the release-to-revive gap is a
/// physical constraint; it is a few statements wide and fails loud (the
/// revive bind panics) if another process steals the port.
async fn dead_target() -> String {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    drop(listener);
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
    let hub = spawn_hub(hub_config(0, certs(), vec![])).await;
    let hub_port = hub.local_addr().expect("hub bound").port();
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
        let elapsed = open_until_rejected(
            &inj,
            interflow_testkit::opaque_stream_id(&format!("b1-dial-{i}")),
            &dead,
        )
        .await;
        assert!(
            elapsed < Duration::from_secs(4),
            "refused dial must fail fast, got {elapsed:?}"
        );
    }
    wait_counter_at_least(BREAKER_OPENED, 1, Duration::from_secs(5)).await;

    // Phase 2: the storm — 50 Opens, all rejected pre-dial, no dial work.
    for i in 0..50 {
        let elapsed = open_until_rejected(
            &inj,
            interflow_testkit::opaque_stream_id(&format!("b1-storm-{i}")),
            &dead,
        )
        .await;
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
        interflow_testkit::opaque_stream_id("b1-healthy"),
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
/// breaker dimension. **The recovery prober is disabled** — this scenario
/// owns the passive cooldown path (still the fallback when the prober is
/// off or its transport is unsupported); with the prober on, its 1s
/// loopback dial would close the entry before this test's own phases run
/// (that behavior is B4's to assert). The target starts dead (storm trips
/// it), the backend binds the port mid-test, and after the cooldown
/// exactly one recovery probe is admitted — it round-trips, the breaker
/// recovers, and the target is fully re-admitted.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn b2_recovery_after_backend_starts() {
    let _serial = serial_lock().await;
    let _ = metrics_handle();
    init_tracing();
    let hub = spawn_hub(hub_config(0, certs(), vec![])).await;
    let hub_port = hub.local_addr().expect("hub bound").port();
    let (echo_addr, _echo) = echo_server().await;
    let dead = dead_target().await;

    let mut eg = agent_config("eg", hub_port, certs());
    eg.max_stream_opens_per_sec = 0;
    eg.max_incoming_streams = 0;
    eg.egress_target_breaker_failure_threshold = 2;
    eg.egress_target_breaker_window_secs = 10;
    eg.egress_target_breaker_cooldown_secs = 2;
    eg.egress_recovery_probe_enabled = false;
    interflow_testkit::spawn_agent_registered(eg).await;

    let (inj, _conn) = connect_tunnel(hub_port, "inj").await;
    wait_egress_ready(&inj, echo_addr).await;

    // Storm: trip the breaker on the dead target.
    for i in 0..5 {
        open_until_rejected(
            &inj,
            interflow_testkit::opaque_stream_id(&format!("b2-storm-{i}")),
            &dead,
        )
        .await;
    }
    wait_counter_at_least(BREAKER_OPENED, 1, Duration::from_secs(5)).await;

    // The backend comes up on the very port the route points at.
    let revived = echo_on_port(dead.rsplit(':').next().unwrap().parse().unwrap()).await;

    // Still within the cooldown: rejected without dialing.
    open_until_rejected(
        &inj,
        interflow_testkit::opaque_stream_id("b2-still-open"),
        &dead,
    )
    .await;

    // After the cooldown the recovery probe is admitted and round-trips.
    tokio::time::sleep(Duration::from_millis(2600)).await;
    let got = round_trip_closing(
        &inj,
        interflow_testkit::opaque_stream_id("b2-probe"),
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
        interflow_testkit::opaque_stream_id("b2-after"),
        &revived.to_string(),
        b"again",
        Duration::from_secs(5),
    )
    .await;
    assert_eq!(got, b"again");
}

// ---------------------------------------------------------------------------
// B4: active recovery — the 2026-10-18 prober beats the cooldown
// ---------------------------------------------------------------------------

/// Threshold 2, cooldown 10s (deliberately long — it must NOT elapse
/// inside this test), prober on its default loopback cadence (1s). The
/// backend revives right after the trip; from that moment the test sends
/// **zero Opens toward the target** — yet the entry must recover within
/// the probe period and strictly before the cooldown. Passive recovery
/// cannot pass this: with no inbound Open there is no probe stream, and
/// the cooldown alone admits nothing.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn b4_active_recovery_beats_the_cooldown() {
    let _serial = serial_lock().await;
    let _ = metrics_handle();
    init_tracing();
    let hub = spawn_hub(hub_config(0, certs(), vec![])).await;
    let hub_port = hub.local_addr().expect("hub bound").port();
    let (echo_addr, _echo) = echo_server().await;
    let dead = dead_target().await;
    const COOLDOWN: Duration = Duration::from_secs(10);

    let mut eg = agent_config("eg", hub_port, certs());
    eg.max_stream_opens_per_sec = 0;
    eg.max_incoming_streams = 0;
    eg.egress_target_breaker_failure_threshold = 2;
    eg.egress_target_breaker_window_secs = 10;
    eg.egress_target_breaker_cooldown_secs = COOLDOWN.as_secs();
    interflow_testkit::spawn_agent_registered(eg).await;

    let (inj, _conn) = connect_tunnel(hub_port, "inj").await;
    wait_egress_ready(&inj, echo_addr).await;

    let gauge_before = gauge_value(BREAKERS_OPEN).unwrap_or(0.0);
    for i in 0..5 {
        open_until_rejected(
            &inj,
            interflow_testkit::opaque_stream_id(&format!("b4-storm-{i}")),
            &dead,
        )
        .await;
    }
    wait_counter_at_least(BREAKER_OPENED, 1, Duration::from_secs(5)).await;
    // The wired-open gauge (2026-10-18): the trip must publish the level.
    // Baseline-relative (a serialized sibling test may leave its own entry
    // OPEN in the process-global recorder — B1's dead target never
    // recovers).
    wait_gauge_at_least(BREAKERS_OPEN, gauge_before + 1.0, Duration::from_secs(5)).await;

    // The backend revives; the clock starts. No Open is sent toward the
    // target from here until recovery has been asserted.
    let revived = echo_on_port(dead.rsplit(':').next().unwrap().parse().unwrap()).await;
    let recovery_started = std::time::Instant::now();
    wait_counter_at_least(BREAKER_RECOVERED, 1, Duration::from_secs(5)).await;
    let elapsed = recovery_started.elapsed();
    assert!(
        elapsed < COOLDOWN,
        "active recovery must beat the {COOLDOWN:?} cooldown, took {elapsed:?} \
         (passive recovery would still be OPEN — no probe stream was ever sent)"
    );
    // …and the gauge came back down to the pre-trip level.
    wait_gauge_at_most(BREAKERS_OPEN, gauge_before, Duration::from_secs(5)).await;

    // Fully re-admitted: the first Open after recovery succeeds outright.
    let got = round_trip_closing(
        &inj,
        interflow_testkit::opaque_stream_id("b4-after"),
        &revived.to_string(),
        b"alive",
        Duration::from_secs(5),
    )
    .await;
    assert_eq!(got, b"alive");
}

/// Polls until the gauge reads ≥ `min` (level-triggered face of
/// [`wait_counter_at_least`]; the snapshot is the post-mortem).
async fn wait_gauge_at_least(metric: &str, min: f64, timeout: Duration) {
    interflow_testkit::wait::eventually(&format!("gauge {metric} >= {min}"), timeout, || {
        let v = gauge_value(metric).unwrap_or(f64::MIN);
        (v >= min)
            .then_some(v)
            .ok_or_else(|| format!("current {v} (snapshot:\n{})", metrics_handle().render()))
    })
    .await;
}

/// Polls until the gauge reads ≤ `max`.
async fn wait_gauge_at_most(metric: &str, max: f64, timeout: Duration) {
    interflow_testkit::wait::eventually(&format!("gauge {metric} <= {max}"), timeout, || {
        let v = gauge_value(metric).unwrap_or(f64::MAX);
        (v <= max)
            .then_some(v)
            .ok_or_else(|| format!("current {v} (snapshot:\n{})", metrics_handle().render()))
    })
    .await;
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
    let hub = spawn_hub(hub_config(0, certs(), vec![])).await;
    let hub_port = hub.local_addr().expect("hub bound").port();
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
        open_until_rejected(
            &inj,
            interflow_testkit::opaque_stream_id(&format!("b3-storm-{i}")),
            &dead,
        )
        .await;
    }
    let cf_delta = counter_value(CLOSED_CONNECT_FAILED) - cf_before;
    // The opted-out invariant is that the whole burst budget goes to the
    // dead target. The exact dial count is timing-dependent: refill
    // (rate 2/s) admits extra dials while the storm drains the bucket on
    // a slow runner (observed 5 on GitHub vs 4 locally), so assert the
    // bound, not the count.
    assert!(
        cf_delta >= 4,
        "disabled breaker: the dead target drains the whole burst budget (got {cf_delta})"
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

    // The healthy stream is starved out: rejected (rate_limited). "Fast"
    // keeps clear daylight under CI starvation: a rate-limited rejection is
    // immediate (seconds even on a starved 2vCPU runner), while riding the
    // dead-dial path instead would cost the 15s establish timeout.
    let elapsed = open_until_rejected(
        &inj,
        interflow_testkit::opaque_stream_id("b3-starved"),
        &echo_addr.to_string(),
    )
    .await;
    assert!(
        elapsed < Duration::from_secs(10),
        "rate-limited rejection is fast, got {elapsed:?}"
    );
    assert!(
        counter_value(OPEN_DROP_RATE) - rate_before >= 1,
        "the storm drained the shared budget (the original starvation)"
    );
}
