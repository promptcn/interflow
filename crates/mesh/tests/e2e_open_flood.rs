//! E2E: DoS-surface defenses against Open-frame flooding (2026-09-12 backlog
//! regression suite).
//!
//! Background: four
//! resource gaps in Open flooding — the event channel blocking without a
//! bound (can be triggered in a loop to evict the whole agent), no local
//! concurrency cap on the agent, no stream-open rate limit (the reflection
//! surface of churn against intranet backends), and no dial timeout (blackhole
//! addresses filling up the slots; wrapping dials in a timeout bounds
//! failures).
//!
//! Scenarios (the deterministic main regression for F1 lives in the core
//! `transport.rs` unit tests — bounded drop on event-channel saturation; what
//! follows are full-stack behavior regressions):
//! - F1 companion: after a flood of open/data/close cycles the session is
//!   healthy with zero drops
//! - F2: local concurrent-stream cap rejects and releases slots (B)
//! - F3: the stream-open rate limit keeps churn-driven backend connections
//!   within budget (C)
//! - F4: a failed dial is declared dead and releases the slot (D)
//! - F5: legitimate stream bursts suffer zero false rejections
//! - F6: no slot leaks after flooding (using the local cap as an exact probe)
//!
//! Note: the metrics recorder is shared in-process and counters accumulate
//! monotonically, so "exactly zero" assertions across tests hold only for
//! labels with a unique source within this binary (event_backlog); the
//! false-rejection dimension is verified via functional assertions (a rejected
//! stream receives Close, and the round-trip helper panics). A serial lock
//! between tests avoids parallel interference.

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
use interflow_core::tunnel::{AgentTunnel, TunnelData};
use interflow_mesh::agent::AgentClient;
use interflow_testkit::{
    agent_config, echo_server, hub_config, hub_config_tuned, metrics_harness::counter_value,
    metrics_harness::eventually, metrics_harness::init_tracing, metrics_harness::metrics_handle,
    metrics_harness::wait_counter_at_least, pick_ephemeral_port, spawn_agent, spawn_hub,
};
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::OnceLock;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;
use tokio::io::AsyncReadExt;
use tokio::net::TcpListener;

/// Serial test lock: multiple stacks within the same binary share the global
/// recorder; serializing avoids counter interference.
static SERIAL: OnceLock<tokio::sync::Mutex<()>> = OnceLock::new();

async fn serial_lock() -> tokio::sync::MutexGuard<'static, ()> {
    SERIAL
        .get_or_init(|| tokio::sync::Mutex::new(()))
        .lock()
        .await
}

// ---------------------------------------------------------------------------
// metrics: install an in-process recorder and read snapshots directly
// (installed once, shared by all tests)
// ---------------------------------------------------------------------------

const OPEN_DROP_BACKLOG: &str = "interflow_agent_open_dropped_total{reason=\"event_backlog\"}";
const OPEN_DROP_LOCAL: &str = "interflow_agent_open_dropped_total{reason=\"local_limit\"}";
const OPEN_DROP_RATE: &str = "interflow_agent_open_dropped_total{reason=\"rate_limited\"}";
const CLOSED_CONNECT_FAILED: &str =
    "interflow_egress_stream_closed_total{reason=\"connect_failed\"}";

// ---------------------------------------------------------------------------
// Test backends and bare-tunnel injection scaffolding
// ---------------------------------------------------------------------------

/// Counting backend: counts total connections and currently active
/// connections (reader-task exit = connection closed).
async fn counting_backend() -> (SocketAddr, Arc<AtomicUsize>, Arc<AtomicUsize>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let total = Arc::new(AtomicUsize::new(0));
    let active = Arc::new(AtomicUsize::new(0));
    let (t2, a2) = (total.clone(), active.clone());
    tokio::spawn(async move {
        loop {
            let Ok((mut sock, _)) = listener.accept().await else {
                break;
            };
            t2.fetch_add(1, Ordering::SeqCst);
            a2.fetch_add(1, Ordering::SeqCst);
            let a3 = a2.clone();
            tokio::spawn(async move {
                let mut buf = [0u8; 4096];
                // A read returning (EOF / error) means the peer has closed
                while matches!(sock.read(&mut buf).await, Ok(n) if n > 0) {}
                a3.fetch_sub(1, Ordering::SeqCst);
            });
        }
    });
    (addr, total, active)
}

/// Bare-tunnel injection endpoint: connect to the hub + register + AgentTunnel
/// (frame-level direct send, with full control over the frame count).
async fn connect_tunnel(
    hub_port: u16,
    agent_id: &str,
) -> (AgentTunnel, tokio::task::JoinHandle<()>) {
    let client = AgentClient::new(agent_config(agent_id, hub_port)).expect("agent build");
    let conn = client
        .connect_and_register()
        .await
        .expect("connect+register");
    let tunnel = AgentTunnel::from_sender(
        agent_id.to_string(),
        &format!("http://127.0.0.1:{hub_port}"),
        conn.send_request,
        None,
        &interflow_core::tunnel::session_tasks::SessionTasks::new(
            tokio_util::sync::CancellationToken::new(),
        ),
        interflow_core::tunnel::H2Liveness::HEARTBEAT_DISABLED,
    )
    .expect("tunnel");
    (tunnel, conn.conn_handle)
}

/// Bare-tunnel round trip (dynamic target): open + send payload + receive the
/// equal-length reply.
/// Panics on receiving Close (printing the reason) — a stream rejected by any
/// defense line fails here.
async fn tunnel_round_trip(
    inj: &AgentTunnel,
    sid: &str,
    target: SocketAddr,
    payload: &[u8],
    deadline: Duration,
) -> Vec<u8> {
    let mut rx = inj.register_stream(sid.to_string()).await;
    inj.send_open(sid, "eg", Some(&target.to_string()), StreamProto::Tcp)
        .await
        .expect("open");
    inj.send_data(sid, Bytes::copy_from_slice(payload))
        .await
        .expect("send");
    recv_exact_from(&mut rx, sid, payload.len(), deadline).await
}

/// Actively Close after the round trip: reclaim the agent-side slot so
/// probe/flood streams do not leak local concurrency quota.
async fn round_trip_closing(
    inj: &AgentTunnel,
    sid: &str,
    target: SocketAddr,
    payload: &[u8],
    deadline: Duration,
) -> Vec<u8> {
    let got = tunnel_round_trip(inj, sid, target, payload, deadline).await;
    inj.send_close(sid).await.expect("close");
    got
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

/// Wait until the egress agent is ready: probe-stream round trip succeeds or
/// times out (probe streams close themselves and occupy no slot).
async fn wait_egress_ready(inj: &AgentTunnel, echo_addr: SocketAddr) {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
    let mut attempt = 0u32;
    loop {
        attempt += 1;
        let sid = format!("probe-{attempt}");
        match round_trip_closing(inj, &sid, echo_addr, b"ping", Duration::from_secs(2)).await {
            resp if resp == b"ping" => break,
            _ => {}
        }
        if tokio::time::Instant::now() >= deadline {
            panic!("egress agent not ready within 10s");
        }
        tokio::time::sleep(Duration::from_millis(250)).await;
    }
    // The probe stream's Close relay + the agent-side finish (slot decrement)
    // need a little time to land; not waiting would make the immediately
    // following "fill the local quota" assertions miscount the probe stream as
    // active.
    tokio::time::sleep(Duration::from_millis(400)).await;
}

/// Flood with open/data/close cycles (sequential; passes only when all `n`
/// streams succeed).
async fn flood_cycles(inj: &AgentTunnel, echo_addr: SocketAddr, n: u32, tag: &str) {
    for i in 0..n {
        let sid = format!("{tag}-{i}");
        let got = round_trip_closing(inj, &sid, echo_addr, b"flood", Duration::from_secs(5)).await;
        assert_eq!(got, b"flood", "data corruption on flood stream {i}");
    }
}

// ---------------------------------------------------------------------------
// Scenarios
// ---------------------------------------------------------------------------

/// F1 companion: the hub's channel send timeout is pushed down to 2s (during
/// regression, the old unbounded blocking would trigger eviction amid the
/// flood and fail in-flight streams); 300 rounds of open/data/close flooding
/// all succeed, event_backlog drops nothing, and the session stays healthy
/// (the closing probe stream succeeds). The egress agent has rate/local limits
/// disabled, isolating the "flooding must not evict" dimension.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn f1_flood_does_not_break_session() {
    let _serial = serial_lock().await;
    let _ = metrics_handle(); // Install the recorder as early as possible: the metrics macros cache per callsite, emissions before installation are invisible
    init_tracing();
    let hub_port = pick_ephemeral_port();
    let security = interflow_mesh::config::HubSecurityConfig {
        channel_send_timeout_secs: 2,
        ..interflow_mesh::config::HubSecurityConfig::default()
    };
    spawn_hub(hub_config_tuned(
        hub_port,
        vec![],
        security,
        interflow_mesh::config::HeartbeatConfig::default(),
    ))
    .await;
    let (echo_addr, _echo) = echo_server().await;

    let mut eg = agent_config("eg", hub_port);
    eg.max_stream_opens_per_sec = 0;
    eg.max_incoming_streams = 0;
    spawn_agent(eg);

    let (inj, _conn) = connect_tunnel(hub_port, "inj").await;
    wait_egress_ready(&inj, echo_addr).await;

    let started = std::time::Instant::now();
    flood_cycles(&inj, echo_addr, 300, "f1").await;
    // All 300 rounds succeeding means no eviction (eviction kills in-flight
    // streams); incidentally verify the elapsed time is bounded
    assert!(
        started.elapsed() < Duration::from_secs(120),
        "abnormal flood duration: {:?}",
        started.elapsed()
    );
    assert_eq!(
        counter_value(OPEN_DROP_BACKLOG),
        0,
        "a healthy flood should not trigger event-backlog drops"
    );
    assert_eq!(counter_value("interflow_dispatch_stream_poisoned_total"), 0);

    // Closing probe: the session is still healthy
    let got =
        round_trip_closing(&inj, "f1-final", echo_addr, b"ping", Duration::from_secs(5)).await;
    assert_eq!(got, b"ping");
}

/// F2: local concurrent-stream cap (a second gate beyond the hub quota). Cap
/// of 4: the first 4 streams are established (the counting backend sees
/// exactly 4 connections); the 5th/6th are rejected (Close + local_limit
/// count, rejection without dialing); after closing one, the slot is released
/// and a new stream can be established and round-trip (echo backend).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn f2_local_stream_limit_rejects_and_releases() {
    let _serial = serial_lock().await;
    let _ = metrics_handle(); // Install the recorder as early as possible: the metrics macros cache per callsite, emissions before installation are invisible
    init_tracing();
    let hub_port = pick_ephemeral_port();
    spawn_hub(hub_config(hub_port, vec![])).await;
    let (echo_addr, _echo) = echo_server().await;
    let (backend, conns, _active) = counting_backend().await;

    let mut eg = agent_config("eg", hub_port);
    eg.max_incoming_streams = 4;
    eg.max_stream_opens_per_sec = 0;
    spawn_agent(eg);

    let (inj, _conn) = connect_tunnel(hub_port, "inj").await;
    wait_egress_ready(&inj, echo_addr).await;

    // First 4: open + data (kept open, filling the local quota)
    for i in 0..4u32 {
        let sid = format!("f2-keep-{i}");
        inj.send_open(&sid, "eg", Some(&backend.to_string()), StreamProto::Tcp)
            .await
            .expect("open");
        inj.send_data(&sid, Bytes::from_static(b"hi"))
            .await
            .expect("send");
    }
    eventually(
        || conns.load(Ordering::SeqCst) >= 4,
        Duration::from_secs(5),
        "all 4 streams connected to the backend",
    )
    .await;

    // 5th/6th: rejected by the local cap (Close returns to the source)
    let t5 = open_until_rejected(&inj, "f2-x5", &backend.to_string()).await;
    let t6 = open_until_rejected(&inj, "f2-x6", &backend.to_string()).await;
    assert!(t5 < Duration::from_secs(5) && t6 < Duration::from_secs(5));
    wait_counter_at_least(OPEN_DROP_LOCAL, 2, Duration::from_secs(5)).await;
    // Rejection without dialing: backend connections remain 4
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert_eq!(
        conns.load(Ordering::SeqCst),
        4,
        "cap rejection should not create backend connections"
    );

    // Slot release: close one, and a new stream can be established and
    // round-trip (the echo backend verifies end to end)
    inj.send_close("f2-keep-0").await.expect("close");
    tokio::time::sleep(Duration::from_millis(300)).await;
    let got =
        round_trip_closing(&inj, "f2-after", echo_addr, b"ping", Duration::from_secs(5)).await;
    assert_eq!(got, b"ping");
}

/// F3: stream-open rate limit (the churn reflection surface). Rate 5/s, burst
/// 10: after 30 rounds of high-speed open/close churn, the backend's total
/// connections stay within budget (< the full 30), with the over-rate portion
/// rejected and counted as rate_limited.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn f3_rate_limit_bounds_churn_connections() {
    let _serial = serial_lock().await;
    let _ = metrics_handle(); // Install the recorder as early as possible: the metrics macros cache per callsite, emissions before installation are invisible
    init_tracing();
    let hub_port = pick_ephemeral_port();
    spawn_hub(hub_config(hub_port, vec![])).await;
    let (echo_addr, _echo) = echo_server().await;
    let (backend, conns, _active) = counting_backend().await;

    let mut eg = agent_config("eg", hub_port);
    eg.max_stream_opens_per_sec = 5;
    eg.stream_open_burst = 10;
    eg.max_incoming_streams = 0;
    spawn_agent(eg);

    let (inj, _conn) = connect_tunnel(hub_port, "inj").await;
    wait_egress_ready(&inj, echo_addr).await;
    // The readiness probe consumed burst-bucket tokens: wait 2.2s for the rate
    // bucket to fully refill (5/s x 2.2s >= burst 10), so that the churn
    // budget assertions (10 burst dials + 5/s sustained) are unaffected by
    // probe noise.
    tokio::time::sleep(Duration::from_millis(2200)).await;

    // High-speed churn: 30 rounds of back-to-back open+close (no waiting for
    // round trips)
    for i in 0..30u32 {
        let sid = format!("f3-churn-{i}");
        inj.send_open(&sid, "eg", Some(&backend.to_string()), StreamProto::Tcp)
            .await
            .expect("open");
        inj.send_close(&sid).await.expect("close");
    }
    // Wait for events to drain and connections to settle
    tokio::time::sleep(Duration::from_secs(2)).await;
    let total = conns.load(Ordering::SeqCst);
    assert!(
        total >= 10,
        "stream opens within the burst bucket (10) should all dial, got {total}"
    );
    assert!(
        total <= 24,
        "backend connections {total} exceed the rate budget (burst 10 + 5/s x test duration); churn reflection surface not converged"
    );
    wait_counter_at_least(OPEN_DROP_RATE, 30 - 24, Duration::from_secs(5)).await;
}

/// F4: bounded convergence of dial failures (plan D). connect/resolve
/// timeouts pushed down to 1s, local concurrency cap 1: the target is a
/// **guaranteed-rejecting** closed local port (blackhole IPs behave
/// inconsistently across environments — some VPN/tun setups accept any
/// connection — and cannot serve as a deterministic test target; the three
/// dial-failure kinds, rejected/unreachable/timeout, share the same finish
/// path in the code). Assert: the failed-dial stream is declared dead within
/// budget (Close returned), the connect_failed counter is visible, and the
/// slot is released immediately afterward — a subsequent normal stream can be
/// established (if the slot were still occupied it would be rejected with
/// local_limit and the round-trip helper would fail).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn f4_dial_failure_frees_slot() {
    let _serial = serial_lock().await;
    let _ = metrics_handle(); // Install the recorder as early as possible: the metrics macros cache per callsite, emissions before installation are invisible
    init_tracing();
    let hub_port = pick_ephemeral_port();
    spawn_hub(hub_config(hub_port, vec![])).await;
    let (echo_addr, _echo) = echo_server().await;
    // A closed local port: the connection is guaranteed to be refused
    // (ECONNREFUSED), deterministic across environments
    let refused_addr = format!("127.0.0.1:{}", interflow_testkit::pick_ephemeral_port());

    let mut eg = agent_config("eg", hub_port);
    eg.egress_connect_timeout_secs = 1;
    eg.egress_resolve_timeout_secs = 1;
    eg.max_incoming_streams = 1;
    eg.max_stream_opens_per_sec = 0;
    spawn_agent(eg);

    let (inj, _conn) = connect_tunnel(hub_port, "inj").await;
    wait_egress_ready(&inj, echo_addr).await;

    // Failed-dial stream: occupies the only slot and must be declared dead
    // within budget with a Close returned
    let elapsed = open_until_rejected(&inj, "f4-dial-fail", &refused_addr).await;
    assert!(
        elapsed < Duration::from_secs(4),
        "the failed-dial stream should be declared dead within budget, got {elapsed:?}"
    );
    wait_counter_at_least(CLOSED_CONNECT_FAILED, 1, Duration::from_secs(5)).await;

    // Slot-release verification: local concurrency cap is 1; if the
    // failed-dial stream did not release it, this stream would be rejected
    let got =
        round_trip_closing(&inj, "f4-after", echo_addr, b"ping", Duration::from_secs(5)).await;
    assert_eq!(got, b"ping");
}

/// F5: legitimate stream bursts suffer zero false rejections. Default
/// defense parameters (rate 100/s, burst 256, local 256): 100 streams are
/// established quickly, all round-trip successfully, and all are reclaimed —
/// any false rejection by a defense line would make the receive helper get a
/// Close and panic.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn f5_legit_burst_not_rejected() {
    let _serial = serial_lock().await;
    let _ = metrics_handle(); // Install the recorder as early as possible: the metrics macros cache per callsite, emissions before installation are invisible
    init_tracing();
    let hub_port = pick_ephemeral_port();
    spawn_hub(hub_config(hub_port, vec![])).await;
    let (echo_addr, _echo) = echo_server().await;

    let eg = agent_config("eg", hub_port); // all defaults: 100/s + burst 256 + local 256
    spawn_agent(eg);

    let (inj, _conn) = connect_tunnel(hub_port, "inj").await;
    wait_egress_ready(&inj, echo_addr).await;

    // Burst: 100 streams established back to back (channels registered once
    // and kept, avoiding overwrite frame loss)
    let mut streams = Vec::new();
    for i in 0..100u32 {
        let sid = format!("f5-burst-{i}");
        let rx = inj.register_stream(sid.clone()).await;
        inj.send_open(&sid, "eg", Some(&echo_addr.to_string()), StreamProto::Tcp)
            .await
            .expect("open");
        inj.send_data(&sid, Bytes::from_static(b"x"))
            .await
            .expect("send");
        streams.push((sid, rx));
    }
    // All receive the echo (any rejection would surface as a false positive),
    // then reclaim them one by one
    for (sid, mut rx) in streams {
        let got = recv_exact_from(&mut rx, &sid, 1, Duration::from_secs(5)).await;
        assert_eq!(got, b"x", "corrupted echo on stream {sid}");
        inj.send_close(&sid).await.expect("close");
    }
    assert_eq!(counter_value(OPEN_DROP_BACKLOG), 0);
}

/// F6: no slot leaks after flooding. Local concurrency cap of 8 acts as an
/// exact probe: after 60 rounds of churn, 8 streams must be simultaneously
/// establishable (any leaked slot would make the 8th rejected with
/// local_limit); after closing out, the backend's active connections reach
/// zero.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn f6_no_slot_leak_after_flood() {
    let _serial = serial_lock().await;
    let _ = metrics_handle(); // Install the recorder as early as possible: the metrics macros cache per callsite, emissions before installation are invisible
    init_tracing();
    let hub_port = pick_ephemeral_port();
    spawn_hub(hub_config(hub_port, vec![])).await;
    let (echo_addr, _echo) = echo_server().await;

    let mut eg = agent_config("eg", hub_port);
    eg.max_incoming_streams = 8;
    spawn_agent(eg);

    let (inj, _conn) = connect_tunnel(hub_port, "inj").await;
    wait_egress_ready(&inj, echo_addr).await;

    // Flood churn: 60 rounds of establish/reclaim
    flood_cycles(&inj, echo_addr, 60, "f6").await;
    // The trailing churn streams' Close relays/finishes may still be in
    // flight: settle before running the full-table probe, otherwise lingering
    // slots would be misjudged as leaks.
    tokio::time::sleep(Duration::from_millis(500)).await;

    // Leak probe: 8 streams established simultaneously (the local concurrency
    // cap being exactly 8); channels registered once and kept
    let mut streams = Vec::new();
    for i in 0..8u32 {
        let sid = format!("f6-full-{i}");
        let rx = inj.register_stream(sid.clone()).await;
        inj.send_open(&sid, "eg", Some(&echo_addr.to_string()), StreamProto::Tcp)
            .await
            .expect("open");
        inj.send_data(&sid, Bytes::from_static(b"leak?"))
            .await
            .expect("send");
        streams.push((sid, rx));
    }
    // All 8 receive the echo (any rejection with local_limit means a slot
    // leak); reclaim them one by one
    for (sid, mut rx) in streams {
        recv_exact_from(&mut rx, &sid, 5, Duration::from_secs(5)).await;
        inj.send_close(&sid).await.expect("close");
    }
}

/// Receive exactly `n` bytes on an already-registered channel; panics on Close
/// (printing the reason).
async fn recv_exact_from(
    rx: &mut tokio::sync::mpsc::Receiver<TunnelData>,
    sid: &str,
    n: usize,
    deadline: Duration,
) -> Vec<u8> {
    let deadline = tokio::time::Instant::now() + deadline;
    let mut got = Vec::with_capacity(n);
    while got.len() < n {
        let td = tokio::time::timeout_at(deadline, rx.recv())
            .await
            .expect("reply timed out")
            .expect("channel alive");
        assert!(
            !matches!(td.stream_type, FrameType::Close),
            "stream {sid} closed prematurely: {:?}",
            String::from_utf8_lossy(&td.data)
        );
        got.extend_from_slice(&td.data);
    }
    got
}
