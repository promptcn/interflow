//! Scheduler-direct tests over the injected clock
//!:
//! 50%-TTL threshold triggering, the backoff ladder, expiry fail-closed,
//! the 10% warning band, the offline watch's once-only 20% warning, and
//! the CRL staleness bound.
//!
//! Every case drives the REAL scheduler loop against a REAL in-process
//! registrar over HTTPS — only time is faked. The fixture (`common/`,
//! shared with the clock-skew and registrar-absence binaries) mirrors
//! `crates/cli/tests/renewal.rs` (issuer store → `serve` → `plan::apply`),
//! so the packs under test are production-shaped. Most cases ask for 1h
//! leaves (the registrar-tier floor) so the 50% line sits 30 fake minutes
//! out instead of 12 fake hours.
//!
//! Serial discipline: the registrar fault hook and the tracing capture
//! buffer are process-global (the same discipline as core's fault tests),
//! so every case takes [`SERIAL`] first.

mod common;

use common::*;
use interflow_identity::issuance::IssuerStore;
use interflow_registrar::fault::{self, FaultAction, FaultPoint};
use interflow_renewal::CrlPollFace;
use interflow_testkit::clock::FakeClock;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

// ---------------------------------------------------------------------------
// G1: 50%-TTL threshold natural triggering
// ---------------------------------------------------------------------------

#[tokio::test]
async fn scheduler_renews_at_half_ttl_and_not_before() {
    let _serial = SERIAL.lock().await;
    capture::install_once();
    capture::clear();
    fault::clear_hook();
    // 1h leaves: the 50% line sits ~30 fake minutes out.
    let fixture = agent_fixture("1h").await;
    prime_crls(&fixture.pack_dir).await;

    let before = active_set(&fixture.pack_dir);
    let clock = FakeClock::at_real_now();
    let scheduler = spawn_scheduler(&fixture.pack_dir, &clock, &Arc::new(CrlPollFace::new()));

    // 28 of the 30 minutes: still short of the threshold — the scheduler
    // must stay parked on its poll sleeps, credentials untouched.
    let finished = drive_chunks(&clock, &scheduler, Duration::from_secs(60), 28).await;
    assert!(!finished, "no exit before the 50% line");
    let mid = active_set(&fixture.pack_dir);
    assert_eq!(mid.sequence, before.sequence, "no renewal before 50% TTL");
    assert!(
        mid.entries["agent-main"].serial == before.entries["agent-main"].serial,
        "no material change before 50% TTL"
    );

    // Cross the line: the next loop iteration renews for real and the
    // scheduler returns Ok onto the supervisor restart.
    let result = drive_to_completion(&clock, scheduler, Duration::from_secs(60), 5).await;
    result.expect("renewal at the 50% line succeeds");
    let after = active_set(&fixture.pack_dir);
    assert_eq!(after.sequence, before.sequence + 1, "one rotation");
    assert_ne!(
        after.entries["agent-main"].serial, before.entries["agent-main"].serial,
        "the leaf material changed"
    );
    assert!(capture::count("rotation_succeeded") >= 1);
    // The pre-threshold phase paces at the CRL poll cadence, never longer.
    assert!(
        clock
            .sleep_requests()
            .iter()
            .all(|slept| *slept <= Duration::from_secs(60)),
        "poll sleeps stay at the CRL cadence: {:?}",
        clock.sleep_requests()
    );
    fault::clear_hook();
}

// ---------------------------------------------------------------------------
// G1: backoff ladder + retry-then-recover
// ---------------------------------------------------------------------------

#[tokio::test]
async fn failed_renewals_back_off_then_recover() {
    let _serial = SERIAL.lock().await;
    capture::install_once();
    capture::clear();
    fault::clear_hook();
    let fixture = agent_fixture("1h").await;
    prime_crls(&fixture.pack_dir).await;

    let clock = FakeClock::at_real_now();
    // First two /v1/renew requests 503; the third succeeds (renew +
    // confirm complete the rotation).
    let plan_hook = RenewFault::install(2, &clock);
    let scheduler = spawn_scheduler(&fixture.pack_dir, &clock, &Arc::new(CrlPollFace::new()));

    // 30s chunks so attempt gaps resolve the ladder steps.
    let result = drive_to_completion(&clock, scheduler, Duration::from_secs(30), 260).await;
    result.expect("recovery after two failures");
    fault::clear_hook();

    let attempts = plan_hook.consult_times();
    assert_eq!(
        attempts.len(),
        3,
        "exactly three renewal attempts: {attempts:?}"
    );
    // The ladder gates attempts: 60s after the first failure, 2m after the
    // second (chunked driving adds at most one 30s chunk of slack; a
    // broken gate retrying every loop tick would land at ~30s).
    let first_gap = attempts[1] - attempts[0];
    let second_gap = attempts[2] - attempts[1];
    assert!(
        first_gap >= time::Duration::seconds(59) && first_gap < time::Duration::seconds(90),
        "second attempt ~60s out: {first_gap}"
    );
    assert!(
        second_gap >= time::Duration::seconds(119) && second_gap < time::Duration::seconds(150),
        "third attempt ~2m out: {second_gap}"
    );
    // Both failures left their rotation_failed banner.
    assert_eq!(capture::count("rotation_failed"), 2);
    // The recovery really rotated.
    assert!(capture::count("rotation_succeeded") >= 1);
    // CRL polling kept its ≤60s cadence throughout the backoff window —
    // the ladder spaces attempts, never CRL polls.
    assert!(
        clock
            .sleep_requests()
            .iter()
            .all(|slept| *slept <= Duration::from_secs(60)),
        "backoff never spaces CRL polls: {:?}",
        clock.sleep_requests()
    );
}

// ---------------------------------------------------------------------------
// G1: expiry fail-closed
// ---------------------------------------------------------------------------

#[tokio::test]
async fn expired_credentials_fail_closed() {
    let _serial = SERIAL.lock().await;
    capture::install_once();
    capture::clear();
    fault::clear_hook();
    let fixture = agent_fixture("1h").await;
    prime_crls(&fixture.pack_dir).await;

    // Renewal permanently failing keeps the loop alive past the 50% line,
    // so the leaf's own expiry is what the scheduler must refuse to
    // outlive.
    let clock = FakeClock::at_real_now();
    let _plan_hook = RenewFault::install(usize::MAX, &clock);
    let scheduler = spawn_scheduler(&fixture.pack_dir, &clock, &Arc::new(CrlPollFace::new()));
    // 70 minutes into a 1h leaf (5-minute chunks).
    let result = drive_to_completion(&clock, scheduler, Duration::from_mins(5), 16).await;
    fault::clear_hook();
    let err = result.expect_err("expiry must fail closed");
    assert!(
        err.to_string()
            .contains("active credential expired — refusing to continue without renewal"),
        "expiry message: {err}"
    );
}

// ---------------------------------------------------------------------------
// G1: the 10% warning band
// ---------------------------------------------------------------------------

#[tokio::test]
async fn less_than_ten_percent_ttl_logs_the_expiry_warning() {
    let _serial = SERIAL.lock().await;
    capture::install_once();
    capture::clear();
    fault::clear_hook();
    // 24h leaves: threshold at 12h, the 10% warning band opens at 21.6h.
    // Renewal permanently failing keeps the scheduler looping past the
    // threshold with the backoff ladder capped at 15m, so gate-open
    // iterations (the ones that carry the banner) land inside the band.
    let fixture = agent_fixture("24h").await;
    prime_crls(&fixture.pack_dir).await;

    let clock = FakeClock::at_real_now();
    let plan_hook = RenewFault::install(usize::MAX, &clock);
    let scheduler = spawn_scheduler(&fixture.pack_dir, &clock, &Arc::new(CrlPollFace::new()));

    // 23h in: inside the warning band, short of expiry.
    let finished = drive_chunks(&clock, &scheduler, Duration::from_mins(30), 46).await;
    assert!(!finished, "still retrying, not expired");
    scheduler.abort();
    fault::clear_hook();

    assert!(
        capture::count("credential_expiry_warning: less than 10% TTL remains") >= 1,
        "warning band banner present"
    );
    assert!(
        !plan_hook.consult_times().is_empty(),
        "renewal attempts actually happened"
    );
}

// ---------------------------------------------------------------------------
// G1: offline_watch — once-only 20% warning + expiry fail-closed (the
// 2026-09-25 regression lock: the trigger fires at 20% remaining, not 80%)
// ---------------------------------------------------------------------------

#[tokio::test]
async fn offline_watch_warns_once_at_twenty_percent_then_fails_closed() {
    let _serial = SERIAL.lock().await;
    capture::install_once();
    capture::clear();
    fault::clear_hook();
    let (_dir, pack_dir) = offline_pack_dir();

    let clock = FakeClock::at_real_now();
    let scheduler = spawn_scheduler(&pack_dir, &clock, &Arc::new(CrlPollFace::new()));

    // 180d leaves: the warning band opens below 20% remaining (< 36d left
    // ⇒ first possible at day 145). 143 days in, nothing may have fired —
    // a regression to the pre-2026-09-25 80%-remaining trigger would have
    // fired around day 36.
    let finished = drive_chunks(&clock, &scheduler, Duration::from_hours(24), 143).await;
    assert!(!finished, "offline watch keeps running");
    assert_eq!(
        capture::count("credential_expiry_warning"),
        0,
        "no warning while more than 20% of the leaf remains"
    );

    // Into the band: fires, and only once however long the watch runs.
    drive_chunks(&clock, &scheduler, Duration::from_hours(24), 4).await;
    assert_eq!(
        capture::count("credential_expiry_warning"),
        1,
        "the offline warning fires exactly once"
    );

    // Past expiry: fail closed, still exactly one warning.
    let result = drive_to_completion(&clock, scheduler, Duration::from_hours(24), 40).await;
    let err = result.expect_err("offline expiry must fail closed");
    assert!(
        err.to_string().contains("offline credentials do not renew"),
        "offline expiry message: {err}"
    );
    assert_eq!(
        capture::count("credential_expiry_warning"),
        1,
        "the once-flag holds across the rest of the leaf's life"
    );
}

// ---------------------------------------------------------------------------
// G2: registrar unreachable — the client-side error mapping
// ---------------------------------------------------------------------------

#[tokio::test]
async fn unreachable_registrar_maps_to_connection_error() {
    let _serial = SERIAL.lock().await;
    capture::install_once();
    fault::clear_hook();
    let fixture = agent_fixture("1h").await;

    // Kill the registrar and wait for the port to stop answering.
    fixture.registrar.kill();
    let ca = {
        let issuer = IssuerStore::open(fixture.registrar.issuer_dir());
        issuer
            .realm_issuer()
            .expect("realm issuer")
            .cert_pem()
            .to_owned()
    };
    for _ in 0..100 {
        let probe = interflow_testkit::http::direct_client()
            .add_root_certificate(
                reqwest::Certificate::from_pem(ca.as_bytes()).expect("root certificate"),
            )
            .build()
            .expect("probe client");
        if probe
            .get(format!("{}/health", fixture.registrar.endpoint()))
            .send()
            .await
            .is_err()
        {
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }

    // A forced renewal against the dead endpoint must surface as a
    // connection-class error (the class the backoff ladder reacts to).
    let err = interflow_renewal::renew_all(&fixture.pack_dir, true)
        .await
        .expect_err("unreachable registrar must fail");
    assert!(
        err.to_string().contains("registrar request failed"),
        "connection-class mapping: {err}"
    );
}

// ---------------------------------------------------------------------------
// G3: CRL staleness fail-closed (pull failing > 1h ⇒ refuse to continue)
// ---------------------------------------------------------------------------

#[tokio::test]
async fn crl_pull_failures_beyond_one_hour_fail_closed() {
    let _serial = SERIAL.lock().await;
    capture::install_once();
    capture::clear();
    fault::clear_hook();
    // 24h leaves: the threshold (12h out) never interferes with a ~70min
    // drive, so renewal is not part of this case.
    let fixture = agent_fixture("24h").await;
    prime_crls(&fixture.pack_dir).await;

    let pulls = Arc::new(AtomicUsize::new(0));
    let hook_pulls = Arc::clone(&pulls);
    fault::install_hook(Arc::new(move |point: FaultPoint| {
        if point == FaultPoint::Crls {
            hook_pulls.fetch_add(1, Ordering::SeqCst);
            FaultAction::ServiceUnavailable
        } else {
            FaultAction::Continue
        }
    }));

    let clock = FakeClock::at_real_now();
    let scheduler = spawn_scheduler(&fixture.pack_dir, &clock, &Arc::new(CrlPollFace::new()));
    // 10-minute chunks: the bound is 1h, so the fail-closed lands on chunk
    // ~7; short of the bound the loop must keep polling.
    let result = drive_to_completion(&clock, scheduler, Duration::from_mins(10), 10).await;
    fault::clear_hook();
    let err = result.expect_err("staleness bound must fail closed");
    assert!(
        err.to_string()
            .contains("CRL freshness bound exceeded — refusing unrevocable credentials"),
        "staleness message: {err}"
    );
    assert!(
        pulls.load(Ordering::SeqCst) >= 6,
        "pulls kept their cadence while stale: {}",
        pulls.load(Ordering::SeqCst)
    );
}

/// The recovery half of the staleness bound (identity-plane matrix row 3,
/// `crates/mesh/tests/identity_lifecycle_matrix.rs`): pulls that fail for
/// a while and then succeed again BEFORE the bound never fail closed. The
/// face counts exactly the injected failures, its confirmation instant
/// freezes through the outage and advances again on the first good poll,
/// and the loop simply carries on — self-healing, no restart needed.
#[tokio::test]
async fn crl_pull_recovers_before_the_bound_without_failing_closed() {
    let _serial = SERIAL.lock().await;
    capture::install_once();
    capture::clear();
    fault::clear_hook();
    // 24h leaves: the threshold (12h out) never interferes.
    let fixture = agent_fixture("24h").await;
    prime_crls(&fixture.pack_dir).await;

    // Exactly the first three pulls fail; the registrar then answers again.
    const INJECTED_FAILURES: u64 = 3;
    let pulls = Arc::new(AtomicUsize::new(0));
    let hook_pulls = Arc::clone(&pulls);
    fault::install_hook(Arc::new(move |point: FaultPoint| {
        if point != FaultPoint::Crls {
            return FaultAction::Continue;
        }
        let pull = u64::try_from(hook_pulls.fetch_add(1, Ordering::SeqCst)).unwrap_or(u64::MAX);
        if pull < INJECTED_FAILURES {
            FaultAction::ServiceUnavailable
        } else {
            FaultAction::Continue
        }
    }));

    let face = Arc::new(CrlPollFace::new());
    let started_at = face.snapshot().last_success_unix;
    let clock = FakeClock::at_real_now();
    let scheduler = spawn_scheduler(&fixture.pack_dir, &clock, &face);

    // Into the outage (the spawned task's first pass lands on the first
    // chunk): failed polls are counted, the confirmation instant has not
    // moved.
    assert!(!drive_chunks(&clock, &scheduler, Duration::from_secs(60), 1).await);
    let outage = face.snapshot();
    assert!(
        outage.failures_total >= 1,
        "the failed polls count: {}",
        outage.failures_total
    );
    assert_eq!(
        outage.last_success_unix, started_at,
        "no success yet → the confirmation instant is frozen"
    );

    // Five more polls: the remaining injected failures, then healthy
    // answers.
    assert!(
        !drive_chunks(&clock, &scheduler, Duration::from_secs(60), 5).await,
        "a recovered CRL lane keeps the loop running"
    );
    fault::clear_hook();
    let healed = face.snapshot();
    assert_eq!(
        healed.failures_total, INJECTED_FAILURES,
        "exactly the injected failures counted — none after recovery"
    );
    assert!(
        healed.last_success_unix > started_at,
        "the confirmation instant advanced again on the first good poll: {} → {}",
        started_at,
        healed.last_success_unix
    );
    assert_eq!(
        capture::count("CRL freshness bound exceeded"),
        0,
        "a recovery inside the bound never fails closed"
    );
    assert!(
        u64::try_from(pulls.load(Ordering::SeqCst)).unwrap_or(u64::MAX) > INJECTED_FAILURES,
        "polls continued past the outage: {}",
        pulls.load(Ordering::SeqCst)
    );
    scheduler.abort();
}

// ---------------------------------------------------------------------------
// CRL-poll liveness face
// ---------------------------------------------------------------------------

/// Steady-state no-change polls ARE successes: the face's confirmation
/// instant must advance every poll while `failures_total` stays zero —
/// this is exactly the "polled, nothing moved" leg the old loop-local
/// variable kept invisible.
#[tokio::test]
async fn crl_poll_face_advances_on_no_change_polls() {
    let _serial = SERIAL.lock().await;
    capture::install_once();
    capture::clear();
    fault::clear_hook();
    // 24h leaves: the renewal threshold never fires during the drive.
    let fixture = agent_fixture("24h").await;
    prime_crls(&fixture.pack_dir).await;

    let face = Arc::new(CrlPollFace::new());
    let started_at = face.snapshot().last_success_unix;
    let clock = FakeClock::at_real_now();
    let scheduler = spawn_scheduler(&fixture.pack_dir, &clock, &face);
    // Three 60s chunks → three polls, each a no-change `Ok(false)`.
    let finished = drive_chunks(&clock, &scheduler, Duration::from_secs(60), 3).await;
    assert!(!finished, "the scheduler keeps polling (no exit expected)");
    let snap = face.snapshot();
    assert_eq!(snap.failures_total, 0, "healthy polls are not failures");
    assert!(
        snap.last_success_unix >= started_at + 2 * 60,
        "the confirmation instant advanced with the polls: started {started_at}, now {}",
        snap.last_success_unix
    );
}

/// Failed polls count and the confirmation instant freezes: the level the
/// hub-side sweeper will classify as silent once it crosses
/// [`interflow_renewal::CRL_SILENT_AFTER_SECS`].
#[tokio::test]
async fn crl_poll_face_counts_failures_and_freezes_recency() {
    let _serial = SERIAL.lock().await;
    capture::install_once();
    capture::clear();
    fault::clear_hook();
    let fixture = agent_fixture("24h").await;
    prime_crls(&fixture.pack_dir).await;
    // The fault hook covers ONLY the driven polls: installing it before
    // the prime would fail the prime's own first-write pull, and
    // prime_crls would never return (it awaits the first-write exit).

    fault::install_hook(Arc::new(|point: FaultPoint| {
        if point == FaultPoint::Crls {
            FaultAction::ServiceUnavailable
        } else {
            FaultAction::Continue
        }
    }));
    let face = Arc::new(CrlPollFace::new());
    let started_at = face.snapshot().last_success_unix;
    let clock = FakeClock::at_real_now();
    let scheduler = spawn_scheduler(&fixture.pack_dir, &clock, &face);
    let finished = drive_chunks(&clock, &scheduler, Duration::from_secs(60), 3).await;
    fault::clear_hook();
    assert!(!finished, "short of the 1h bound the loop keeps polling");
    let snap = face.snapshot();
    assert!(
        snap.failures_total >= 3,
        "every failed poll counts: {}",
        snap.failures_total
    );
    assert_eq!(
        snap.last_success_unix, started_at,
        "no successful poll → the confirmation instant never moves"
    );
}

// ---------------------------------------------------------------------------
// The backoff stage rides the face (2026-10-20 connection-quality face).
// ---------------------------------------------------------------------------

#[test]
fn backoff_stage_rides_the_face_through_the_ladder() {
    let face = std::sync::Arc::new(CrlPollFace::new());
    assert_eq!(face.snapshot().backoff_failures, 0, "fresh face: no stage");
    face.note_backoff(1);
    assert_eq!(face.snapshot().backoff_failures, 1);
    face.note_backoff(5);
    assert_eq!(
        face.snapshot().backoff_failures,
        5,
        "the ladder caps at 5 stages"
    );
    face.note_backoff(0);
    assert_eq!(
        face.snapshot().backoff_failures,
        0,
        "a landed rotation resets (the process ends, the face mirrors it)"
    );
}
