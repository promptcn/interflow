//! The bounded keyed state store behind every per-client rate limiter.
//!
//! governor's default keyed store is an unbounded map — a key's first check
//! inserts it and nothing ever removes it — so on a listener keyed by
//! remote address the table grows with every distinct source the internet
//! sends.
//! [`BoundedStore`] plugs into governor's [`StateStore`] extension point —
//! governor still owns the GCRA arithmetic — and owns the lifecycle the
//! default store leaves to its user:
//!
//! - **Lossless idle expiry.** Every shard keeps two generations of keys and
//!   rotates them once per rotation period P (one full burst refill plus one
//!   emission interval, see [`rotation_period`]). A key untouched for a
//!   whole generation is dropped with it. It has then been idle for at least
//!   P, so its theoretical arrival time (TAT) lies at least one emission
//!   interval in the past — exactly the predicate governor's own
//!   `retain_recent` deletes by. The dropped state is indistinguishable from
//!   a key never seen: no rate-limit decision changes.
//! - **A hard bound.** Each generation of each shard holds a fixed number of
//!   keys, so the store never tracks more than its capacity however many
//!   distinct sources arrive. A new key meeting a full generation forces an
//!   early rotation, and the older generation — the keys untouched since the
//!   last rotation — is forgotten. That is the only place state with
//!   outstanding debt can be lost, and only for keys idle for a generation:
//!   every key touched since keeps its state (an abuser still hammering is
//!   touched on every attempt, rejected or not), and a new client is always
//!   admitted. Overflow degrades accuracy for idle keys; it never fails
//!   closed.
//! - **O(1) amortized maintenance.** A rotation drops a whole generation in
//!   one deallocation (entries are plain data); there is no background task
//!   and no sweep over the table on the request path.

use std::collections::HashMap;
use std::hash::{BuildHasher, Hash, RandomState};
use std::mem;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Mutex, MutexGuard, PoisonError};
use std::time::Duration;

use governor::Quota;
use governor::clock::{Clock, Reference};
use governor::nanos::Nanos;
use governor::state::StateStore;
use governor::state::keyed::ShrinkableKeyedStateStore;
use metrics::{Counter, Gauge};
use tracing::warn;

/// log2 of [`SHARDS`].
const SHARD_BITS: u32 = 4;

/// Shard count. Fixed rather than derived from the CPU count, so the memory
/// bound and the tests are reproducible; the admission paths using the
/// store run far below the rate at which 16 short critical sections contend.
const SHARDS: usize = 1 << SHARD_BITS;

/// Gauge: keys a store tracks right now, labelled `limiter`. Maintained by
/// deltas, so stores sharing a label (one per UDP rule) sum.
const TRACKED_GAUGE: &str = "interflow_rate_limit_tracked_clients";

/// Counter: keys dropped by capacity-forced rotations, labelled `limiter` —
/// an upper bound on the states whose outstanding debt was forgotten (some
/// of them were idle long enough to be fresh anyway).
const CAPACITY_EVICTIONS_COUNTER: &str = "interflow_rate_limit_capacity_evictions";

/// Minimum spacing between two capacity-pressure warnings of one store.
const PRESSURE_WARN_INTERVAL: Duration = Duration::from_mins(1);

/// The rotation period P for `quota`: one full burst refill — the most debt
/// a key can carry past its last allowed cell, since an allowed cell never
/// pushes the TAT more than one burst window ahead — plus one emission
/// interval, the margin governor's `retain_recent` keeps. A key idle for P
/// therefore has a TAT at least one emission interval in the past.
pub(super) fn rotation_period(quota: Quota) -> Nanos {
    Nanos::from(quota.burst_size_replenished_in() + quota.replenish_interval())
}

/// A key count as a gauge value (exact below 2^32, saturating above).
fn count_as_f64(n: usize) -> f64 {
    f64::from(u32::try_from(n).unwrap_or(u32::MAX))
}

/// Locks a shard. Poison recovery by `into_inner`: a shard holds plain
/// data whose invariants every mutation keeps, so another thread's panic
/// must not take the limiter down with it.
fn lock<T>(shard: &Mutex<T>) -> MutexGuard<'_, T> {
    shard.lock().unwrap_or_else(PoisonError::into_inner)
}

/// A store's shards: one mutex-wrapped two-generation table per shard.
type Shards<K, I> = Box<[Mutex<Shard<K, I>>]>;

/// A governor keyed state store with lossless idle expiry and a hard
/// capacity (see the module docs).
pub(super) struct BoundedStore<K, C: Clock> {
    /// The key space, split by [`Self::shard_hasher`].
    shards: Shards<K, C::Instant>,
    /// Picks a key's shard. Randomly keyed per store (and independent of
    /// the in-shard tables' own random hashers): a client cannot compute
    /// which keys land in a victim's shard — overflowing that one shard
    /// would wash out the victim's idle debt at 1/16 of the cost of the
    /// whole table.
    shard_hasher: RandomState,
    /// The limiter's clock (a clone): drives rotation and the warning
    /// throttle.
    clock: C,
    /// Reference instant for [`Self::next_warn_ns`].
    origin: C::Instant,
    /// Rotation period P ([`rotation_period`]).
    period: Nanos,
    /// Keys one generation of one shard may hold.
    generation_capacity: usize,
    /// `limiter` label value; also names the store in the pressure warning.
    label: &'static str,
    /// [`TRACKED_GAUGE`] handle.
    tracked: Gauge,
    /// [`CAPACITY_EVICTIONS_COUNTER`] handle.
    capacity_evictions: Counter,
    /// Nanoseconds after [`Self::origin`] before which no further pressure
    /// warning is logged; a CAS claims each warning slot.
    next_warn_ns: AtomicU64,
    /// Capacity evictions not yet reported by a warning.
    unreported_evictions: AtomicU64,
}

/// One shard: two generations of key → theoretical arrival time.
struct Shard<K, I> {
    /// Keys touched since [`Self::rotated_at`].
    current: HashMap<K, Nanos>,
    /// Keys of the generation before. Touching one promotes it back into
    /// [`Self::current`]; the rest are dropped at the next rotation.
    previous: HashMap<K, Nanos>,
    /// When the generations last rotated.
    rotated_at: I,
}

/// What one operation did to the store's population (applied to the
/// metrics after the shard lock is released).
struct Change<I> {
    /// When the operation ran.
    now: I,
    /// Keys newly tracked (0 or 1).
    added: usize,
    /// Keys dropped by a time-based (lossless) rotation.
    expired: usize,
    /// Keys dropped by a capacity-forced rotation.
    evicted: usize,
}

impl<K, I> Shard<K, I> {
    /// Keys tracked in both generations.
    fn len(&self) -> usize {
        self.current.len() + self.previous.len()
    }
}

impl<K: Hash + Eq, I: Reference> Shard<K, I> {
    /// An empty shard whose first generation starts at `now`.
    fn new(now: I) -> Self {
        Self {
            current: HashMap::new(),
            previous: HashMap::new(),
            rotated_at: now,
        }
    }

    /// Time-based rotation; returns how many keys it dropped. Lossless: a
    /// dropped key has been idle for at least `period` (module docs).
    fn rotate_if_due(&mut self, now: I, period: Nanos) -> usize {
        let elapsed = now.duration_since(self.rotated_at);
        if elapsed < period {
            return 0;
        }
        let dropped = if elapsed.saturating_sub(period) < period {
            let dropped = self.previous.len();
            self.previous = mem::take(&mut self.current);
            dropped
        } else {
            // Every operation rotates first, so `current` only holds keys
            // touched within one period of `rotated_at`: two periods on,
            // they have been idle for a whole period too.
            let dropped = self.len();
            self.current = HashMap::new();
            self.previous = HashMap::new();
            dropped
        };
        self.rotated_at = now;
        dropped
    }

    /// Inserts a key absent from [`Self::current`], forcing an early
    /// rotation when that generation is full. Returns how many keys the
    /// forced rotation dropped (0 without one).
    fn admit(&mut self, key: K, tat: Nanos, now: I, generation_capacity: usize) -> usize {
        let mut evicted = 0;
        if self.current.len() >= generation_capacity {
            evicted = self.previous.len();
            self.previous = mem::take(&mut self.current);
            // Restart the period: the demoted keys were touched up to now,
            // and only a whole period untouched makes dropping them lossless.
            self.rotated_at = now;
        }
        self.current.insert(key, tat);
        evicted
    }
}

impl<K: Hash + Eq, C: Clock> BoundedStore<K, C> {
    /// A store for limiters running `quota` on `clock`, tracking at most
    /// `capacity` keys (rounded down to a whole number of keys per
    /// generation per shard, at least one), reported under `label`.
    pub(super) fn new(quota: Quota, capacity: usize, clock: C, label: &'static str) -> Self {
        let now = clock.now();
        Self {
            shards: (0..SHARDS).map(|_| Mutex::new(Shard::new(now))).collect(),
            shard_hasher: RandomState::new(),
            origin: now,
            period: rotation_period(quota),
            generation_capacity: (capacity / (2 * SHARDS)).max(1),
            label,
            tracked: metrics::gauge!(TRACKED_GAUGE, "limiter" => label),
            capacity_evictions: metrics::counter!(CAPACITY_EVICTIONS_COUNTER, "limiter" => label),
            next_warn_ns: AtomicU64::new(0),
            unreported_evictions: AtomicU64::new(0),
            clock,
        }
    }

    /// The most keys the store can track at once.
    pub(super) const fn capacity(&self) -> usize {
        SHARDS * 2 * self.generation_capacity
    }

    /// The index of the shard `key` lives in (the hash's top bits).
    fn shard_index(&self, key: &K) -> usize {
        let index = self.shard_hasher.hash_one(key) >> (u64::BITS - SHARD_BITS);
        usize::try_from(index).expect("a SHARD_BITS-wide index fits usize")
    }

    /// The shard `key` lives in.
    fn shard(&self, key: &K) -> &Mutex<Shard<K, C::Instant>> {
        &self.shards[self.shard_index(key)]
    }

    /// Applies one operation's population change to the metrics, and
    /// reports capacity pressure (throttled to one warning per
    /// [`PRESSURE_WARN_INTERVAL`], carrying the evictions since the last).
    fn account(&self, change: &Change<C::Instant>) {
        let removed = change.expired + change.evicted;
        if change.added > removed {
            self.tracked.increment(count_as_f64(change.added - removed));
        } else if removed > change.added {
            self.tracked.decrement(count_as_f64(removed - change.added));
        }
        if change.evicted == 0 {
            return;
        }
        let evicted = u64::try_from(change.evicted).unwrap_or(u64::MAX);
        self.capacity_evictions.increment(evicted);
        self.unreported_evictions
            .fetch_add(evicted, Ordering::Relaxed);
        let now_ns = change.now.duration_since(self.origin).as_u64();
        let due = self.next_warn_ns.load(Ordering::Relaxed);
        if now_ns < due {
            return;
        }
        let next = now_ns.saturating_add(Nanos::from(PRESSURE_WARN_INTERVAL).as_u64());
        if self
            .next_warn_ns
            .compare_exchange(due, next, Ordering::Relaxed, Ordering::Relaxed)
            .is_err()
        {
            return;
        }
        let forgotten = self.unreported_evictions.swap(0, Ordering::Relaxed);
        warn!(
            limiter = self.label,
            forgotten,
            capacity = self.capacity(),
            "per-client rate-limit table at capacity: forgot {forgotten} client state(s) idle \
             for a generation since the last report — sustained distinct-source pressure \
             (scan or flood), or a capacity too small for this listener"
        );
    }
}

impl<K, C> StateStore for BoundedStore<K, C>
where
    K: Hash + Eq + Clone,
    C: Clock,
{
    type Key = K;

    fn measure_and_replace<T, F, E>(&self, key: &K, f: F) -> Result<T, E>
    where
        F: Fn(Option<Nanos>) -> Result<(T, Nanos), E>,
    {
        let (decision, change) = {
            let mut shard = lock(self.shard(key));
            // Read under the lock: a shard's rotation instants never run
            // backwards.
            let now = self.clock.now();
            let mut change = Change {
                now,
                added: 0,
                expired: shard.rotate_if_due(now, self.period),
                evicted: 0,
            };
            let decision = if let Some(tat) = shard.current.get_mut(key) {
                let decision = f(Some(*tat));
                if let Ok((_, next)) = &decision {
                    *tat = *next;
                }
                decision
            } else {
                // Touching a key of the older generation promotes it whatever
                // the decision: an abuser hammering through rejections stays
                // tracked, its debt intact.
                let prior = shard.previous.remove(key);
                let decision = f(prior);
                let keep = match &decision {
                    Ok((_, next)) => Some(*next),
                    Err(_) => prior,
                };
                if let Some(tat) = keep {
                    change.added = usize::from(prior.is_none());
                    change.evicted = shard.admit(key.clone(), tat, now, self.generation_capacity);
                }
                decision
            };
            (decision, change)
        };
        self.account(&change);
        decision.map(|(outcome, _)| outcome)
    }
}

/// governor's housekeeping contract. Rotation already does the lossless
/// part continuously; these exist so the store is a complete governor store
/// (`RateLimiter::len` and friends work over it).
impl<K, C> ShrinkableKeyedStateStore<K> for BoundedStore<K, C>
where
    K: Hash + Eq + Clone,
    C: Clock,
{
    fn retain_recent(&self, drop_below: Nanos) {
        let mut dropped = 0;
        for shard in &*self.shards {
            let mut shard = lock(shard);
            let before = shard.len();
            shard.current.retain(|_, tat| *tat > drop_below);
            shard.previous.retain(|_, tat| *tat > drop_below);
            dropped += before - shard.len();
        }
        self.tracked.decrement(count_as_f64(dropped));
    }

    fn shrink_to_fit(&self) {
        for shard in &*self.shards {
            let mut shard = lock(shard);
            shard.current.shrink_to_fit();
            shard.previous.shrink_to_fit();
        }
    }

    fn len(&self) -> usize {
        self.shards.iter().map(|shard| lock(shard).len()).sum()
    }

    fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

impl<K, C: Clock> Drop for BoundedStore<K, C> {
    /// The keys still tracked leave the gauge with the store: a rebuilt
    /// limiter (UDP limits are rebuilt on hot reload) must not leave its
    /// predecessor's population behind.
    fn drop(&mut self) {
        let remaining: usize = self
            .shards
            .iter_mut()
            .map(|shard| {
                shard
                    .get_mut()
                    .unwrap_or_else(PoisonError::into_inner)
                    .len()
            })
            .sum();
        self.tracked.decrement(count_as_f64(remaining));
    }
}

/// Test-only population drivers. Production never forces expiry: a shard
/// rotates lazily on its next touch, and the hard bound does not depend on
/// quiet shards being swept.
#[cfg(test)]
impl<K: Hash + Eq + Clone, C: Clock> BoundedStore<K, C> {
    /// Tracks `key` with a placeholder TAT (drive the population and its
    /// metrics without a RateLimiter).
    pub(super) fn track_for_test(&self, key: &K) {
        let _ = self.measure_and_replace(key, |tat| -> Result<((), Nanos), ()> {
            Ok(((), Nanos::from(tat.map_or(1_u64, |t| t.as_u64() + 1))))
        });
    }

    /// Drops both generations of every shard NOW (the deterministic,
    /// every-shard form of idle expiry the tests assert against).
    pub(super) fn expire_all_for_test(&self) {
        let now = self.clock.now();
        let mut dropped = 0;
        for shard in &*self.shards {
            let mut shard = lock(shard);
            dropped += shard.len();
            shard.current = HashMap::new();
            shard.previous = HashMap::new();
            shard.rotated_at = now;
        }
        self.tracked.decrement(count_as_f64(dropped));
    }

    /// The shard index `key` maps to in THIS store (shard choice is
    /// randomly keyed per store; tests that need two keys in one shard
    /// search with it).
    pub(super) fn shard_index_for_test(&self, key: &K) -> usize {
        self.shard_index(key)
    }

    /// Keys one generation of one shard may hold.
    pub(super) const fn generation_capacity_for_test(&self) -> usize {
        self.generation_capacity
    }

    /// The largest allocation (`HashMap::capacity`) of any generation table
    /// — the memory face of the key bound.
    pub(super) fn max_table_capacity_for_test(&self) -> usize {
        self.shards
            .iter()
            .map(|shard| {
                let shard = lock(shard);
                shard.current.capacity().max(shard.previous.capacity())
            })
            .max()
            .unwrap_or(0)
    }
}
