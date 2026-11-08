//! Clock-skew fault injection for the renewal scheduler
//!
//! The scheduler judges every time-anchored decision on ITS host's clock,
//! while the credentials it judges were issued against the registrar's.
//! These cases put a fixed offset between the two (the agent runs behind
//! or ahead of its issuer) and pin what each wall-anchored decision does
//! under the disagreement — and, through the fake clock's independent
//! axes, pin which clock each decision reads at all: the `Clock` contract
//! assigns threshold / warning / expiry math to the wall and the CRL
//! freshness bound to the monotonic clock, and that assignment is
//! asserted here rather than merely documented.
//!
//! What a skewed scheduler can and cannot change: it moves WHEN the
//! scheduler acts (every wall decision shifts by exactly the skew), never
//! WHAT it issues — `renew_all_at` takes the scheduler's reading only for
//! the 50% gate; the leaf the registrar signs carries the registrar's
//! clock. The fresh-material assertions below are that boundary.
//!
//! Each case drives the REAL scheduler loop against a REAL in-process
//! registrar over HTTPS (the shared `common/` fixture); only time is
//! faked. Serial discipline as in `scheduler.rs`.

mod common;

use common::*;
use interflow_registrar::fault::{self, FaultAction, FaultPoint};
use interflow_renewal::CrlPollFace;
use interflow_testkit::clock::FakeClock;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;
use time::OffsetDateTime;

/// The renewed leaf is the registrar's work: its expiry sits one TTL past
/// the REAL instant of issuance, whatever the scheduler's clock read.
fn assert_fresh_leaf_is_issuer_anchored(pack_dir: &std::path::Path, ttl: time::Duration) {
    let fresh = earliest_expiry(pack_dir);
    let real_remaining = fresh - OffsetDateTime::now_utc();
    assert!(
        real_remaining > ttl - time::Duration::minutes(5) && real_remaining <= ttl,
        "the fresh leaf expires one TTL past the real issuance instant, not past the \
         scheduler's skewed reading: real remaining {real_remaining}"
    );
}

// ---------------------------------------------------------------------------
// Behind the issuer: the scheduler renews when ITS clock crosses 50% —
// late in real terms by exactly the skew — and the material it receives
// is anchored to the issuer, so the lateness does not compound.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn slow_clock_renews_at_half_of_its_own_view() {
    let _serial = SERIAL.lock().await;
    capture::install_once();
    capture::clear();
    fault::clear_hook();
    let fixture = agent_fixture("1h").await;
    prime_crls(&fixture.pack_dir).await;
    let before = active_set(&fixture.pack_dir);
    let expiry = earliest_expiry(&fixture.pack_dir);
    let threshold = expiry - time::Duration::minutes(30);

    // The host runs 10 minutes behind the registrar: the 50% line, 30 real
    // minutes out, is 40 scheduler-minutes out.
    let skew = -time::Duration::minutes(10);
    let clock = FakeClock::at_real_now_skewed(skew);
    let scheduler = spawn_scheduler(&fixture.pack_dir, &clock, &Arc::new(CrlPollFace::new()));

    // 38 scheduler-minutes in: a true-clock scheduler would have renewed
    // eight minutes ago; this one still reads 32 minutes remaining and
    // must keep polling.
    let finished = drive_chunks(&clock, &scheduler, Duration::from_secs(60), 38).await;
    assert!(!finished, "no exit before the scheduler's own 50% line");
    assert!(
        clock.now() < threshold,
        "the skewed reading is still short of the threshold"
    );
    let mid = active_set(&fixture.pack_dir);
    assert_eq!(
        mid.sequence, before.sequence,
        "no renewal on the issuer's 50%"
    );

    // Its own crossing: renews, exits onto the supervisor restart.
    let result = drive_to_completion(&clock, scheduler, Duration::from_secs(60), 5).await;
    result.expect("renewal at the scheduler's own 50% line succeeds");
    assert!(
        clock.now() >= threshold,
        "the renewal landed on the scheduler's crossing"
    );
    let after = active_set(&fixture.pack_dir);
    assert_eq!(after.sequence, before.sequence + 1, "one rotation");
    assert_ne!(
        after.entries["agent-main"].serial, before.entries["agent-main"].serial,
        "the leaf material changed"
    );
    assert!(capture::count("rotation_succeeded") >= 1);

    // The skew moved WHEN; it did not leak into WHAT: the fresh leaf is
    // one TTL past the real issuance instant, which is shorter than one
    // TTL past the scheduler's reading would have been.
    assert_fresh_leaf_is_issuer_anchored(&fixture.pack_dir, time::Duration::hours(1));
    assert!(
        earliest_expiry(&fixture.pack_dir) < clock.now() + time::Duration::hours(1),
        "an expiry derived from the slow clock would sit later than the issuer's"
    );
    fault::clear_hook();
}

// ---------------------------------------------------------------------------
// Ahead of the issuer, past the leaf: fail-closed on the first pass. The
// leaf is really valid — the loss is availability, in the conservative
// direction (refuse rather than serve on a credential the host believes
// expired), and no dial happens first.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn fast_clock_past_the_leaf_fails_closed_before_any_renewal() {
    let _serial = SERIAL.lock().await;
    capture::install_once();
    capture::clear();
    fault::clear_hook();
    let fixture = agent_fixture("1h").await;
    prime_crls(&fixture.pack_dir).await;
    let before = active_set(&fixture.pack_dir);
    let expiry = earliest_expiry(&fixture.pack_dir);

    // 65 minutes ahead of a 1h leaf: the host reads the leaf as expired
    // while the issuer still has ~60 minutes on it.
    let clock = FakeClock::at_real_now_skewed(time::Duration::minutes(65));
    let consults = RenewFault::install(0, &clock);
    let scheduler = spawn_scheduler(&fixture.pack_dir, &clock, &Arc::new(CrlPollFace::new()));
    let result = drive_to_completion(&clock, scheduler, Duration::from_secs(60), 2).await;
    fault::clear_hook();

    let err = result.expect_err("a host clock past the leaf fails closed");
    assert!(
        err.to_string()
            .contains("active credential expired — refusing to continue without renewal"),
        "expiry message: {err}"
    );
    assert!(
        consults.consult_times().is_empty(),
        "the refusal precedes any renewal dial: {:?}",
        consults.consult_times()
    );
    assert_eq!(
        active_set(&fixture.pack_dir).sequence,
        before.sequence,
        "nothing rotated"
    );
    assert!(
        expiry - OffsetDateTime::now_utc() > time::Duration::minutes(55),
        "the leaf is really valid — this is the conservative direction's cost"
    );
}

// ---------------------------------------------------------------------------
// Ahead of the issuer, inside the half: the gate is already open on the
// first pass, so the scheduler renews ~skew early in real terms. Safe
// direction (one rotation sooner than needed), fresh material anchored
// to the issuer.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn fast_clock_inside_the_half_renews_on_the_first_pass() {
    let _serial = SERIAL.lock().await;
    capture::install_once();
    capture::clear();
    fault::clear_hook();
    let fixture = agent_fixture("1h").await;
    prime_crls(&fixture.pack_dir).await;
    let before = active_set(&fixture.pack_dir);
    let old_expiry = earliest_expiry(&fixture.pack_dir);

    // 35 minutes ahead: the host reads 25 minutes remaining on a leaf the
    // issuer has ~60 minutes on — the 50% gate is open at once.
    let clock = FakeClock::at_real_now_skewed(time::Duration::minutes(35));
    let consults = RenewFault::install(0, &clock);
    let scheduler = spawn_scheduler(&fixture.pack_dir, &clock, &Arc::new(CrlPollFace::new()));
    let result = drive_to_completion(&clock, scheduler, Duration::from_secs(60), 2).await;
    fault::clear_hook();

    result.expect("the open gate renews on the first pass");
    assert_eq!(
        consults.consult_times().len(),
        1,
        "exactly one renewal dial: {:?}",
        consults.consult_times()
    );
    let after = active_set(&fixture.pack_dir);
    assert_eq!(after.sequence, before.sequence + 1, "one rotation");
    assert!(
        old_expiry - OffsetDateTime::now_utc() > time::Duration::minutes(55),
        "renewed while the issuer still had most of the TTL on the old leaf — early, not late"
    );
    assert_fresh_leaf_is_issuer_anchored(&fixture.pack_dir, time::Duration::hours(1));
    assert!(capture::count("rotation_succeeded") >= 1);
}

// ---------------------------------------------------------------------------
// Behind the issuer with the registrar refusing: the ladder opens at the
// scheduler's 50%, the 10% warning follows it (order intact), and the
// fail-closed lands at the scheduler's expiry — exactly |skew| after the
// real one. That overshoot is the bounded cost of a slow clock; the hub
// judges the same leaf on its own clock and refuses it at the real expiry.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn slow_clock_keeps_warning_after_backoff_and_fails_closed_skew_late() {
    let _serial = SERIAL.lock().await;
    capture::install_once();
    capture::clear();
    fault::clear_hook();
    // 24h leaves: the 10% band (2.4h) is wider than the ladder's 15m cap,
    // so gate-open passes land inside it (the same shape as the unskewed
    // warning case).
    let fixture = agent_fixture("24h").await;
    prime_crls(&fixture.pack_dir).await;
    let expiry = earliest_expiry(&fixture.pack_dir);

    let skew = -time::Duration::minutes(30);
    let clock = FakeClock::at_real_now_skewed(skew);
    let _refusal = RenewFault::install(usize::MAX, &clock);
    let scheduler = spawn_scheduler(&fixture.pack_dir, &clock, &Arc::new(CrlPollFace::new()));

    // 46 half-hour chunks from a start 30m behind issuance: the scheduler
    // reads 22.5h past issuance — inside the band (opens at 21.6h), short
    // of its expiry reading (24h).
    let finished = drive_chunks(&clock, &scheduler, Duration::from_mins(30), 46).await;
    assert!(
        !finished,
        "still retrying, not expired on the scheduler's clock"
    );
    let first_failure = capture::first_index("rotation_failed").expect("the ladder started");
    let first_warning =
        capture::first_index("credential_expiry_warning: less than 10% TTL remains")
            .expect("the warning band was reached");
    assert!(
        first_failure < first_warning,
        "the ladder opens at 50% and the warning follows at 90%: failure@{first_failure} \
         warning@{first_warning}"
    );

    // On to the scheduler's expiry: fail-closed there, which is |skew|
    // past the issuer's expiry.
    let result = drive_to_completion(&clock, scheduler, Duration::from_mins(30), 6).await;
    fault::clear_hook();
    let err = result.expect_err("expiry on the scheduler's clock fails closed");
    assert!(
        err.to_string().contains("active credential expired"),
        "expiry message: {err}"
    );
    assert!(
        clock.now() >= expiry,
        "fail-closed waits for the scheduler's own expiry reading"
    );
    let real_at_failure = clock.now() - skew;
    assert!(
        real_at_failure >= expiry - skew,
        "in real terms the fail-closed landed at least |skew| past the issuer's expiry: \
         real {real_at_failure}, issuer expiry {expiry}"
    );
    assert!(
        clock.now() < expiry + time::Duration::minutes(31),
        "and on the first pass past it (30m chunks)"
    );
}

// ---------------------------------------------------------------------------
// Which clock does each decision read? The contract: the CRL freshness
// bound follows the monotonic axis (wall steps, either direction, are
// invisible to it), the renewal threshold follows the wall (monotonic
// time alone never opens it). Two cases, one axis each.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn crl_staleness_bound_follows_the_monotonic_clock_not_the_wall() {
    let _serial = SERIAL.lock().await;
    capture::install_once();
    capture::clear();
    fault::clear_hook();
    // 24h leaves: the threshold (12h out) never interferes.
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
    // Three failed polls, three monotonic minutes: far short of the bound.
    assert!(!drive_chunks(&clock, &scheduler, Duration::from_secs(60), 3).await);
    assert!(pulls.load(Ordering::SeqCst) >= 3);

    // A +2h wall step (an NTP correction): the next poll still fails, and
    // the bound — four monotonic minutes since the last success — holds.
    clock.step_wall(time::Duration::hours(2));
    assert!(
        !drive_chunks(&clock, &scheduler, Duration::from_secs(60), 1).await,
        "a forward wall jump must not trip the freshness bound"
    );
    // A −3h wall step (the clock corrected back below where it started):
    // equally invisible — the bound never reads "fresher" either.
    clock.step_wall(-time::Duration::hours(3));
    assert!(
        !drive_chunks(&clock, &scheduler, Duration::from_secs(60), 1).await,
        "a backward wall jump must not trip the freshness bound"
    );
    let pulls_before_bound = pulls.load(Ordering::SeqCst);
    assert!(pulls_before_bound >= 5, "polls kept their cadence");

    // One monotonic hour with the wall standing still: the parked poll
    // wakes, fails, and the bound trips — on the axis the contract names.
    clock.advance_monotonic_only(Duration::from_hours(1));
    settle(&clock, &scheduler).await;
    let result = scheduler.await.expect("scheduler join");
    fault::clear_hook();
    let err = result.expect_err("the monotonic bound fails closed");
    assert!(
        err.to_string()
            .contains("CRL freshness bound exceeded — refusing unrevocable credentials"),
        "staleness message: {err}"
    );
}

#[tokio::test]
async fn renewal_threshold_follows_the_wall_clock_not_the_monotonic() {
    let _serial = SERIAL.lock().await;
    capture::install_once();
    capture::clear();
    fault::clear_hook();
    let fixture = agent_fixture("1h").await;
    prime_crls(&fixture.pack_dir).await;
    let before = active_set(&fixture.pack_dir);

    let clock = FakeClock::at_real_now();
    let scheduler = spawn_scheduler(&fixture.pack_dir, &clock, &Arc::new(CrlPollFace::new()));

    // Forty monotonic minutes with the wall frozen at issuance: the poll
    // wakes, but the wall reads zero elapsed — the 50% line (30 wall
    // minutes out) is not crossed and nothing rotates.
    clock.advance_monotonic_only(Duration::from_mins(40));
    settle(&clock, &scheduler).await;
    assert!(
        !scheduler.is_finished(),
        "monotonic time alone opens nothing"
    );
    assert_eq!(
        active_set(&fixture.pack_dir).sequence,
        before.sequence,
        "no renewal on monotonic elapsed"
    );

    // A +31m wall step crosses the line; the next poll sees it and renews.
    clock.step_wall(time::Duration::minutes(31));
    let result = drive_to_completion(&clock, scheduler, Duration::from_secs(60), 3).await;
    result.expect("the wall crossing renews");
    assert_eq!(
        active_set(&fixture.pack_dir).sequence,
        before.sequence + 1,
        "one rotation on the wall crossing"
    );
    fault::clear_hook();
}
