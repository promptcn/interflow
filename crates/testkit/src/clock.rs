//! A controllable fake clock for scheduler tests (the
//! `interflow_renewal::Clock` seam).
//!
//! Model: one shared time state whose wall and monotonic readings advance
//! together. `sleep` **parks** until the test advances fake time past the
//! sleep's deadline, so the future under test makes progress exactly when
//! the test says so — no busy loop, no real waiting. Every requested sleep
//! duration is also recorded; the ledger is the behavior record (poll
//! cadence, backoff ladders) the tests assert against.
//!
//! Wakeups are deadline-driven: `advance` wakes every parked sleep whose
//! deadline came due, including intermediate ones (advancing one hour past
//! ten stacked 60s sleeps fires all ten).
//!
//! Two fault axes ride on top of the lockstep model
//!:
//!
//! - **Skew** — [`FakeClock::at_real_now_skewed`] starts the wall reading
//!   a fixed offset away from real time. Credentials are issued against
//!   the registrar's (real) clock, so the scheduler under test then reads
//!   expiry math through a host clock that runs ahead of or behind its
//!   issuer — the two-ends-disagree shape every wall-anchored decision
//!   must be judged under.
//! - **Wall jumps vs. monotonic time** — [`FakeClock::step_wall`] moves the
//!   wall alone (an NTP step; parked sleeps are keyed on the monotonic
//!   reading, so nothing wakes) and [`FakeClock::advance_monotonic_only`]
//!   moves the monotonic reading alone. Together they let a test ask which
//!   axis an arbitration follows: the `Clock` contract pins threshold /
//!   warning / expiry math to the wall and the CRL freshness bound to the
//!   monotonic clock, and that assignment is now assertable rather than
//!   documented.

use interflow_renewal::Clock;
use std::future::Future;
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll, Waker};
use std::time::Duration;
use time::OffsetDateTime;

/// A fake [`Clock`]: clone-cheap handles share one time state.
#[derive(Debug, Clone)]
pub struct FakeClock {
    state: Arc<Mutex<State>>,
}

#[derive(Debug)]
struct State {
    wall: OffsetDateTime,
    monotonic: Duration,
    /// Parked sleeps, keyed by id: `(deadline, waker)`.
    parked: Vec<(u64, Duration, Option<Waker>)>,
    next_id: u64,
    /// Every sleep duration requested, in request order.
    sleep_requests: Vec<Duration>,
}

impl FakeClock {
    /// A fake clock starting at `start` (wall); the monotonic epoch is 0.
    #[must_use]
    pub fn new(start: OffsetDateTime) -> Self {
        Self {
            state: Arc::new(Mutex::new(State {
                wall: start,
                monotonic: Duration::ZERO,
                parked: Vec::new(),
                next_id: 0,
                sleep_requests: Vec::new(),
            })),
        }
    }

    /// A fake clock whose wall reading starts at the real current time
    /// (pack expiry math is absolute, so tests anchored to just-issued
    /// certificates want to start near "now").
    #[must_use]
    pub fn at_real_now() -> Self {
        Self::new(OffsetDateTime::now_utc())
    }

    /// A fake clock whose wall reading starts `skew` away from the real
    /// current time: the view of a host whose clock runs ahead of
    /// (positive) or behind (negative) the registrar that issued the
    /// credentials under test. Expiry math on this clock disagrees with the
    /// issuer by exactly `skew` — the fault the skew cases are about.
    #[must_use]
    pub fn at_real_now_skewed(skew: time::Duration) -> Self {
        Self::new(OffsetDateTime::now_utc() + skew)
    }

    /// The current fake wall reading.
    #[must_use]
    pub fn now(&self) -> OffsetDateTime {
        self.state.lock().expect("fake clock lock poisoned").wall
    }

    /// Advances fake time (wall and monotonic together) by `by`, waking
    /// every parked sleep whose deadline came due.
    pub fn advance(&self, by: std::time::Duration) {
        self.step(
            time::Duration::try_from(by).unwrap_or(time::Duration::MAX),
            by,
        );
    }

    /// Steps the wall reading alone by `by` (signed: a forward or backward
    /// NTP-style correction) while the monotonic reading stands still.
    /// Parked sleeps are deadline-keyed on the monotonic reading, so none
    /// wake — exactly the behavior of a real monotonic clock through a
    /// wall step. Wall-anchored decisions see the jump on their next pass;
    /// monotonic-anchored ones must not.
    pub fn step_wall(&self, by: time::Duration) {
        self.step(by, Duration::ZERO);
    }

    /// Advances the monotonic reading alone by `by` (waking due sleeps)
    /// while the wall reading stands still — the complement of
    /// [`Self::step_wall`]: a monotonic-anchored bound crosses, a
    /// wall-anchored threshold does not.
    pub fn advance_monotonic_only(&self, by: Duration) {
        self.step(time::Duration::ZERO, by);
    }

    /// The one mutation path: moves each axis by its own amount, then
    /// wakes every parked sleep whose (monotonic) deadline came due.
    fn step(&self, wall: time::Duration, monotonic: Duration) {
        let due: Vec<Waker> = {
            let mut state = self.state.lock().expect("fake clock lock poisoned");
            state.monotonic += monotonic;
            state.wall += wall;
            let now = state.monotonic;
            let mut still_parked = Vec::with_capacity(state.parked.len());
            let mut due = Vec::new();
            for (id, deadline, waker) in state.parked.drain(..) {
                if deadline <= now {
                    due.extend(waker);
                } else {
                    still_parked.push((id, deadline, waker));
                }
            }
            state.parked = still_parked;
            due
        };
        // Wake outside the lock: a woken task may consult the clock right
        // away and must not deadlock against our guard.
        for waker in due {
            waker.wake();
        }
    }

    /// Every sleep duration requested so far, in order — the pacing record.
    #[must_use]
    pub fn sleep_requests(&self) -> Vec<Duration> {
        self.state
            .lock()
            .expect("fake clock lock poisoned")
            .sleep_requests
            .clone()
    }

    /// The quiescence signal for chunked driving: at least one sleep is
    /// parked and every parked deadline lies in the fake future. A wake's
    /// processing (real I/O, consults whose timestamps the tests assert
    /// on) runs with the previous sleep already consumed — parked is
    /// empty then — so this is exactly "the woken work finished and
    /// re-parked", independent of how slow the runner's real time is.
    #[must_use]
    pub fn all_parked_beyond_now(&self) -> bool {
        let state = self.state.lock().expect("fake clock lock poisoned");
        !state.parked.is_empty()
            && state
                .parked
                .iter()
                .all(|(_, deadline, _)| *deadline > state.monotonic)
    }
}

impl Clock for FakeClock {
    fn now_utc(&self) -> OffsetDateTime {
        self.now()
    }

    fn monotonic(&self) -> Duration {
        self.state
            .lock()
            .expect("fake clock lock poisoned")
            .monotonic
    }

    fn sleep(&self, duration: Duration) -> Pin<Box<dyn Future<Output = ()> + Send>> {
        let deadline;
        let id;
        {
            let mut state = self.state.lock().expect("fake clock lock poisoned");
            state.sleep_requests.push(duration);
            deadline = state.monotonic + duration;
            id = state.next_id;
            state.next_id += 1;
        }
        Box::pin(FakeSleep {
            state: Arc::clone(&self.state),
            id,
            deadline,
        })
    }
}

/// The future behind [`FakeClock::sleep`]: pending until the shared state's
/// monotonic reading passes `deadline`.
struct FakeSleep {
    state: Arc<Mutex<State>>,
    id: u64,
    deadline: Duration,
}

impl Future for FakeSleep {
    type Output = ();

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<()> {
        let mut state = self.state.lock().expect("fake clock lock poisoned");
        if state.monotonic >= self.deadline {
            state.parked.retain(|(id, _, _)| *id != self.id);
            return Poll::Ready(());
        }
        match state.parked.iter_mut().find(|(id, _, _)| *id == self.id) {
            Some((_, _, waker)) => *waker = Some(cx.waker().clone()),
            None => state
                .parked
                .push((self.id, self.deadline, Some(cx.waker().clone()))),
        }
        Poll::Pending
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::task::Wake;

    #[test]
    fn zero_sleep_completes_without_advancing() {
        let clock = FakeClock::new(OffsetDateTime::UNIX_EPOCH);
        let mut sleep = std::pin::pin!(clock.sleep(Duration::ZERO));
        let waker = Waker::from(Arc::new(NoopWaker));
        let mut cx = Context::from_waker(&waker);
        assert!(sleep.as_mut().poll(&mut cx).is_ready());
        assert_eq!(clock.sleep_requests(), vec![Duration::ZERO]);
    }

    #[test]
    fn sleep_parks_until_advance_reaches_deadline() {
        let clock = FakeClock::new(OffsetDateTime::UNIX_EPOCH);
        let mut sleep = std::pin::pin!(clock.sleep(Duration::from_secs(60)));
        let waker = Waker::from(Arc::new(NoopWaker));
        let mut cx = Context::from_waker(&waker);
        assert!(sleep.as_mut().poll(&mut cx).is_pending());

        clock.advance(Duration::from_secs(30));
        assert!(sleep.as_mut().poll(&mut cx).is_pending());

        clock.advance(Duration::from_secs(30));
        assert!(sleep.as_mut().poll(&mut cx).is_ready());
        assert_eq!(clock.monotonic(), Duration::from_secs(60));
    }

    #[test]
    fn one_advance_wakes_every_intermediate_deadline() {
        let clock = FakeClock::new(OffsetDateTime::UNIX_EPOCH);
        // Ten stacked 60s sleeps (the poll-loop cadence shape): a single
        // one-hour advance must satisfy all of them.
        let mut sleeps: Vec<Pin<Box<dyn Future<Output = ()> + Send>>> = (0..10)
            .map(|_| clock.sleep(Duration::from_secs(60)))
            .collect();
        let waker = Waker::from(Arc::new(NoopWaker));
        let mut cx = Context::from_waker(&waker);
        for sleep in &mut sleeps {
            assert!(sleep.as_mut().poll(&mut cx).is_pending());
        }
        clock.advance(Duration::from_secs(600));
        for sleep in &mut sleeps {
            assert!(sleep.as_mut().poll(&mut cx).is_ready());
        }
        assert_eq!(clock.sleep_requests().len(), 10);
    }

    /// A wall step (either direction) moves only the wall: the monotonic
    /// reading holds and no parked sleep wakes — the monotonic axis is
    /// blind to NTP corrections by construction.
    #[test]
    fn wall_step_moves_the_wall_alone_and_wakes_nothing() {
        let clock = FakeClock::new(OffsetDateTime::UNIX_EPOCH);
        let mut sleep = std::pin::pin!(clock.sleep(Duration::from_secs(60)));
        let waker = Waker::from(Arc::new(NoopWaker));
        let mut cx = Context::from_waker(&waker);
        assert!(sleep.as_mut().poll(&mut cx).is_pending());

        clock.step_wall(time::Duration::hours(2));
        assert_eq!(
            clock.now(),
            OffsetDateTime::UNIX_EPOCH + time::Duration::hours(2)
        );
        assert_eq!(clock.monotonic(), Duration::ZERO, "monotonic holds");
        assert!(sleep.as_mut().poll(&mut cx).is_pending(), "no wake");

        clock.step_wall(-time::Duration::hours(3));
        assert_eq!(
            clock.now(),
            OffsetDateTime::UNIX_EPOCH - time::Duration::hours(1),
            "a backward step is a legal wall correction"
        );
        assert_eq!(clock.monotonic(), Duration::ZERO);
        assert!(sleep.as_mut().poll(&mut cx).is_pending());
    }

    /// A monotonic-only advance wakes due sleeps while the wall holds —
    /// the complement: wall-anchored math sees nothing, deadlines fire.
    #[test]
    fn monotonic_only_advance_wakes_sleeps_and_holds_the_wall() {
        let clock = FakeClock::new(OffsetDateTime::UNIX_EPOCH);
        let mut sleep = std::pin::pin!(clock.sleep(Duration::from_secs(60)));
        let waker = Waker::from(Arc::new(NoopWaker));
        let mut cx = Context::from_waker(&waker);
        assert!(sleep.as_mut().poll(&mut cx).is_pending());

        clock.advance_monotonic_only(Duration::from_secs(60));
        assert!(sleep.as_mut().poll(&mut cx).is_ready());
        assert_eq!(clock.monotonic(), Duration::from_secs(60));
        assert_eq!(clock.now(), OffsetDateTime::UNIX_EPOCH, "wall holds");
    }

    /// The skewed constructor offsets the wall from real time by exactly
    /// the requested amount, either direction.
    #[test]
    fn skewed_constructor_offsets_the_wall_from_real_time() {
        let behind = FakeClock::at_real_now_skewed(-time::Duration::minutes(30));
        let real = OffsetDateTime::now_utc();
        let gap = real - behind.now();
        assert!(
            gap >= time::Duration::minutes(30) && gap < time::Duration::minutes(31),
            "behind by ~30m: {gap}"
        );
        let ahead = FakeClock::at_real_now_skewed(time::Duration::hours(2));
        let gap = ahead.now() - OffsetDateTime::now_utc();
        assert!(
            gap > time::Duration::minutes(119) && gap <= time::Duration::hours(2),
            "ahead by ~2h: {gap}"
        );
        assert_eq!(behind.monotonic(), Duration::ZERO, "skew is wall-only");
    }

    struct NoopWaker;

    impl Wake for NoopWaker {
        fn wake(self: Arc<Self>) {}
    }
}
