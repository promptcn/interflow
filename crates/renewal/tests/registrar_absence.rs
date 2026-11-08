//! Registrar absence across the renewal window — identity-plane event
//! matrix row 1 (`crates/mesh/tests/identity_lifecycle_matrix.rs`;
//! (internal design notes)).
//!
//! The existing ladder case (`scheduler.rs::failed_renewals_back_off_then_
//! recover`) exercises a registrar that is UP and answering 503; this is
//! the other shape — the registrar is GONE (connection refused) when the
//! 50% line arrives, stays gone through several ladder rungs, and comes
//! back at the same address. The invariants: the ladder keeps retrying
//! (never gives up, never spaces the CRL polls), nothing fails closed
//! early (expiry and the CRL bound are both still ahead), and the first
//! attempt after revival converges in one pass — one rotation, one
//! `rotation_succeeded`, the CRL lane healed.
//!
//! The absence window is bounded on purpose: the CRL freshness bound (1h,
//! monotonic) is its own, separately-locked invariant (`scheduler.rs::
//! crl_pull_failures_beyond_one_hour_fail_closed`); here the registrar
//! returns well inside it so the case isolates the ladder.

mod common;

use common::*;
use interflow_identity::issuance::LeafTtl;
use interflow_registrar::fault;
use interflow_renewal::CrlPollFace;
use interflow_testkit::clock::FakeClock;
use interflow_testkit::registrar::RegistrarFixtureOptions;
use std::sync::Arc;
use std::time::Duration;

/// Waits until nothing accepts at `addr` (the killed fixture's listener
/// is released a tick after `kill()` returns); `false` if it still does.
async fn wait_unreachable(addr: std::net::SocketAddr) -> bool {
    for _ in 0..200 {
        if tokio::net::TcpStream::connect(addr).await.is_err() {
            return true;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    false
}

#[tokio::test]
async fn registrar_unreachable_across_the_window_backs_off_and_converges_on_revival() {
    let _serial = SERIAL.lock().await;
    capture::install_once();
    capture::clear();
    fault::clear_hook();
    // 1h leaves: the 50% line is 30 fake minutes out; expiry 60.
    let fixture = agent_fixture("1h").await;
    prime_crls(&fixture.pack_dir).await;
    let before = active_set(&fixture.pack_dir);

    let face = Arc::new(CrlPollFace::new());
    let clock = FakeClock::at_real_now();
    let scheduler = spawn_scheduler(&fixture.pack_dir, &clock, &face);

    // 29 healthy minutes: polls succeed, the line is not yet crossed.
    assert!(!drive_chunks(&clock, &scheduler, Duration::from_secs(60), 29).await);
    let healthy = face.snapshot();
    assert_eq!(healthy.failures_total, 0, "healthy polls before the outage");

    // The registrar vanishes right before the window opens.
    let addr = fixture.registrar.addr();
    fixture.registrar.kill();
    assert!(
        wait_unreachable(addr).await,
        "registrar at {addr} still accepts connections after kill"
    );

    // 11 more minutes (now 40): the line was crossed at 30 against a dead
    // endpoint — attempts at 30, 31, 33, 37 on the ladder (60s / 2m / 4m /
    // 8m), every one a connection-class failure; CRL polls fail too but
    // the bound (1h) is far; expiry (60) is far. The loop must still be
    // running, material untouched.
    let finished = drive_chunks(&clock, &scheduler, Duration::from_secs(60), 11).await;
    assert!(
        !finished,
        "no early fail-closed while the registrar is gone"
    );
    let failures_during_outage = capture::count("rotation_failed");
    assert!(
        failures_during_outage >= 3,
        "the ladder kept retrying through the outage: {failures_during_outage} attempts"
    );
    assert!(
        capture::count("registrar request failed") >= 3,
        "each attempt failed in the connection class the ladder reacts to"
    );
    assert!(
        capture::count("crl_stale") >= 1,
        "the CRL lane reported its failed polls"
    );
    let during = face.snapshot();
    assert!(
        during.failures_total >= 1,
        "the face counted the failed polls: {}",
        during.failures_total
    );
    assert_eq!(
        during.last_success_unix, healthy.last_success_unix,
        "no successful poll during the outage → the confirmation instant froze"
    );
    assert_eq!(
        active_set(&fixture.pack_dir).sequence,
        before.sequence,
        "nothing rotated while the registrar was gone"
    );
    assert_eq!(capture::count("rotation_succeeded"), 0);

    // Revival at the same address, same issuer store, same TTL.
    let revived = interflow_testkit::registrar::spawn_registrar(RegistrarFixtureOptions::revive(
        &fixture.registrar,
        LeafTtl::from_seconds(3600).expect("1h ttl"),
    ))
    .await;
    revived.wait_ready().await;

    // The next ladder rung (45) lands on a live registrar: one attempt,
    // one rotation, clean exit — single-pass convergence.
    let result = drive_to_completion(&clock, scheduler, Duration::from_secs(60), 10).await;
    result.expect("the first attempt after revival renews");
    let after = active_set(&fixture.pack_dir);
    assert_eq!(after.sequence, before.sequence + 1, "exactly one rotation");
    assert_ne!(
        after.entries["agent-main"].serial, before.entries["agent-main"].serial,
        "the leaf material changed"
    );
    assert_eq!(
        capture::count("rotation_succeeded"),
        1,
        "exactly one success — no double renewal on recovery"
    );
    assert_eq!(
        capture::count("rotation_failed"),
        failures_during_outage,
        "no failure after the registrar returned"
    );
    let healed = face.snapshot();
    assert!(
        healed.last_success_unix > during.last_success_unix,
        "the CRL lane healed on revival: {} → {}",
        during.last_success_unix,
        healed.last_success_unix
    );
    // The ladder spaced attempts, never CRL polls.
    assert!(
        clock
            .sleep_requests()
            .iter()
            .all(|slept| *slept <= Duration::from_secs(60)),
        "backoff never spaces CRL polls: {:?}",
        clock.sleep_requests()
    );
    fault::clear_hook();
    let _ = revived.shutdown().await;
}
