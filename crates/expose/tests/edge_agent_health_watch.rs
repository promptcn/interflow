//! Edge internal-agent outer supervision (regression tests for
//! docs/bug/2026-09-16-edge-self-dial-agent-no-reregister.md §4.3/§4.4).
//!
//! The edge's internal agent is now a supervised auto-reconnect client; its
//! own failures are normal operation. What must never happen again is the
//! incident's silent wedge: a recovery path that stops making progress —
//! and stops *talking* — while the process keeps serving a black hole.
//!
//! Covered contracts of [`interflow_expose::edge::watch_agent_health`] and
//! [`interflow_expose::edge::wait_initial_registration`]:
//!
//! 1. wedged recovery (no state change at all while non-connected for the
//!    whole window) trips the watch — the process exits, systemd restarts;
//! 2. an *alive but struggling* supervisor (state cycling through
//!    Connecting/Reconnecting with bounded gaps) never trips it;
//! 3. a healthy Connected agent never trips it;
//! 4. `wait_initial_registration` bounds startup: a wedged first connect
//!    fails the edge's startup instead of hanging it.

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
use interflow_core::fault::FaultPoint;
use interflow_expose::edge::{wait_initial_registration, watch_agent_health};
use interflow_mesh::agent::AgentClient;
use interflow_testkit::fault::{self, FaultPlan};
use interflow_testkit::{agent_config, pick_ephemeral_port, spawn_agent_registered, spawn_hub};
use std::time::Duration;
use tokio::net::TcpListener;

// The fault hook is process-global: keep this binary's fault-injected case
// from interleaving with the others (cargo test runs cases in parallel).
static FAULT_SERIAL: std::sync::Mutex<()> = std::sync::Mutex::new(());

/// Accepts TCP connections and then goes silent forever (no bytes either
/// way): a connect+register against it hangs until the establish timeout.
async fn spawn_black_hole() -> std::net::SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind black hole");
    let addr = listener.local_addr().expect("black hole addr");
    tokio::spawn(async move {
        let mut held = Vec::new();
        while let Ok((stream, _)) = listener.accept().await {
            held.push(stream); // hold the socket open, never read/write
        }
    });
    addr
}

/// Wedge shape: the first connect hangs (black hole + a huge establish
/// bound), so the state machine enters Connecting once and then goes totally
/// silent — exactly the "recovery wedged" class the outer watch exists for.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn wedged_supervisor_trips_the_watch() {
    let certs = interflow_testkit::certs::TestCerts::generate("health", "healthy");
    let _serial = FAULT_SERIAL.lock().unwrap_or_else(|e| e.into_inner());
    let black_hole = spawn_black_hole().await;
    let mut cfg = agent_config("wedged", black_hole.port(), &certs);
    cfg.agent.hub_url = format!("http://{black_hole}");
    // Effectively unbounded establish: the connect hangs inside
    // run_session, no state change ever follows the initial Connecting.
    cfg.agent.connect_timeout_secs = 10_000;
    let agent = AgentClient::new(cfg).unwrap().start();

    // The watch must trip within ~recovery_timeout (plus test slack)
    let started = std::time::Instant::now();
    let reason = tokio::time::timeout(
        Duration::from_secs(8),
        watch_agent_health(&agent, Duration::from_secs(2)),
    )
    .await
    .expect("watch must trip on a wedged supervisor")
    .to_string();
    assert!(
        started.elapsed() < Duration::from_secs(8),
        "watch tripped far too late: {:?}",
        started.elapsed()
    );
    assert!(
        reason.contains("no state change"),
        "trip reason should name the wedge shape, got: {reason}"
    );

    agent.shutdown_graceful().await.expect("agent shutdown");
}

/// Startup bound: a wedged first registration fails `wait_initial_registration`
/// within its timeout instead of hanging edge startup forever.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn wedged_first_registration_fails_startup_boundedly() {
    let certs = interflow_testkit::certs::TestCerts::generate("health", "healthy");
    let _serial = FAULT_SERIAL.lock().unwrap_or_else(|e| e.into_inner());
    let black_hole = spawn_black_hole().await;
    let mut cfg = agent_config("wedged-startup", black_hole.port(), &certs);
    cfg.agent.hub_url = format!("http://{black_hole}");
    cfg.agent.connect_timeout_secs = 10_000;
    let agent = AgentClient::new(cfg).unwrap().start();

    let started = std::time::Instant::now();
    let res = tokio::time::timeout(
        Duration::from_secs(5),
        wait_initial_registration(&agent, Duration::from_secs(1)),
    )
    .await
    .expect("wait_initial_registration must be bounded");
    assert!(res.is_err(), "a wedged first connect must fail startup");
    assert!(
        started.elapsed() < Duration::from_secs(5),
        "startup wait bounded, took {:?}",
        started.elapsed()
    );

    agent.shutdown_graceful().await.expect("agent shutdown");
}

/// Alive-but-struggling shape: connection refused, the supervisor keeps
/// cycling Connecting → Reconnecting with bounded gaps — the watch must NOT
/// trip (restart churn would not help; this is normal operation).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn struggling_but_alive_supervisor_never_trips_the_watch() {
    let certs = interflow_testkit::certs::TestCerts::generate("health", "healthy");
    let _serial = FAULT_SERIAL.lock().unwrap_or_else(|e| e.into_inner());
    // A port with nothing listening: every attempt fails fast.
    let dead_port = pick_ephemeral_port();
    let mut cfg = agent_config("struggling", dead_port, &certs);
    cfg.agent.hub_url = format!("http://127.0.0.1:{dead_port}");
    cfg.agent.connect_timeout_secs = 2;
    let agent = AgentClient::new(cfg).unwrap().start();

    // Recovery window long enough that consecutive backoffs (1..=4s in the
    // first cycles) stay inside it; observe ~6s without a trip.
    let outcome = tokio::time::timeout(
        Duration::from_secs(6),
        watch_agent_health(&agent, Duration::from_secs(5)),
    )
    .await;
    assert!(
        outcome.is_err(),
        "an alive supervisor cycling states must not trip the health watch (tripped with: {:?})",
        outcome.map(|reason| reason.to_string()).err()
    );

    agent.shutdown_graceful().await.expect("agent shutdown");
}

/// Healthy shape: Connected state, the watch stays silent.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn healthy_agent_never_trips_the_watch() {
    let _certs = interflow_testkit::certs::TestCerts::generate("health", "healthy");
    let certs = interflow_testkit::certs::TestCerts::generate("health", "healthy");
    let _serial = FAULT_SERIAL.lock().unwrap_or_else(|e| e.into_inner());
    let hub_port = pick_ephemeral_port();
    let _hub = spawn_hub(interflow_testkit::hub_config(hub_port, &certs, vec![])).await;
    let agent = spawn_agent_registered(agent_config("healthy", hub_port, &certs)).await;

    let outcome = tokio::time::timeout(
        Duration::from_secs(2),
        watch_agent_health(&agent, Duration::from_secs(1)),
    )
    .await;
    assert!(
        outcome.is_err(),
        "a healthy Connected agent must not trip the health watch"
    );

    agent.shutdown_graceful().await.expect("agent shutdown");
}

/// Dead-supervisor shape (2026-09-16 panic-containment hardening): a panic
/// in the supervisor's OWN frame is the outermost in-process layer — the
/// state stream ends with a final state that is neither Stopped nor Failed.
/// The watch must treat the stream end as death and trip immediately (the
/// process exits, systemd restarts) — not spin on it, not stay silent.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn dead_supervisor_trips_the_watch_via_stream_end() {
    let certs = interflow_testkit::certs::TestCerts::generate("health", "healthy");
    let _serial = FAULT_SERIAL.lock().unwrap_or_else(|e| e.into_inner());
    fault::clear();

    let hub_port = pick_ephemeral_port();
    let _hub = spawn_hub(interflow_testkit::hub_config(hub_port, &certs, vec![])).await;

    let faults = fault::install(FaultPlan::new().panic_at(FaultPoint::AgentSuperviseLoopTick));
    let mut cfg = agent_config("doomed-supervisor", hub_port, &certs);
    cfg.agent.connect_timeout_secs = 2;
    let agent = AgentClient::new(cfg).unwrap().start();

    let started = std::time::Instant::now();
    let reason = tokio::time::timeout(
        Duration::from_secs(10),
        watch_agent_health(&agent, Duration::from_secs(60)),
    )
    .await
    .expect("watch must trip on a dead supervisor")
    .to_string();
    assert!(
        started.elapsed() < Duration::from_secs(10),
        "a dead supervisor must trip the watch immediately, took {:?}",
        started.elapsed()
    );
    assert!(
        reason.contains("state channel closed"),
        "trip reason should name the stream-end death shape, got: {reason}"
    );
    assert!(
        faults.fired(FaultPoint::AgentSuperviseLoopTick),
        "the supervisor fault must have fired (guards against a vacuous green)"
    );

    fault::clear();
    // shutdown_graceful on a dead supervisor surfaces the JoinError — the
    // documented contract; tolerating it here is the point.
    assert!(agent.shutdown_graceful().await.is_err());
}
