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

    /// The current fake wall reading.
    #[must_use]
    pub fn now(&self) -> OffsetDateTime {
        self.state.lock().expect("fake clock lock poisoned").wall
    }

    /// Advances fake time (wall and monotonic together) by `by`, waking
    /// every parked sleep whose deadline came due.
    pub fn advance(&self, by: std::time::Duration) {
        let due: Vec<Waker> = {
            let mut state = self.state.lock().expect("fake clock lock poisoned");
            state.monotonic += by;
            state.wall += time::Duration::try_from(by).unwrap_or(time::Duration::MAX);
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

    struct NoopWaker;

    impl Wake for NoopWaker {
        fn wake(self: Arc<Self>) {}
    }
}
