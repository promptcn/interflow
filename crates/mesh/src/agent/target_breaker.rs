//! Per-target connect-phase circuit breaker (egress hardening, 2026-09-16).
//!
//! Companion case file: `(internal design notes)`
//! — a dead backend target whose public caller retried in a loop drained the
//! agent-wide stream-open rate budget (charged before the target was even
//! parsed), starving every healthy route on the same agent. The breaker adds
//! the missing per-target health memory: connect-phase failures (resolve /
//! connect / UDP connect) are counted per target inside a sliding window;
//! once a target exceeds the threshold it is tripped OPEN, and subsequent
//! Opens to it are rejected **pre-dial and without consuming the shared open
//! budget** — one target's pathology is no longer contagious.
//!
//! The same state machine is reused by the expose edge as a **route breaker**
//! ([`BreakerKind::Route`], keyed by host, evidence = the close reasons
//! relayed by the agent). One behavioral contract covers both uses:
//!
//! - [`TargetBreakers::check`] tells the caller **which** admission it got:
//!   `Allow` (healthy), `Probe` (OPEN but the recovery probe of this
//!   interval), or `Reject`. Callers that derive health from the admitted
//!   stream's outcome (the edge route breaker) key their accounting off the
//!   `Probe` verdict — see `route_evidence` in `expose::edge::listener`.
//! - Failure evidence comes in two strengths. [`TargetBreakers::note_failure`]
//!   is direct (the dial itself failed) and re-arms a tripped entry.
//!   [`TargetBreakers::note_soft_failure`] is derivative (e.g. the edge
//!   receiving the agent's `target_circuit_open`): it counts toward tripping
//!   while CLOSED but never re-arms an OPEN entry — two breaker layers
//!   feeding each other's cooldowns is an interlock, not isolation.
//!
//! State machine (per target, agent-level, survives session rebuilds — same
//! rationale as the rate limiter in [`super::egress::EgressRuntime`]):
//!
//! ```text
//!            ≥ threshold failures in window
//! CLOSED ────────────────────────────────────► OPEN (reject all)
//!    ▲                                            │  cooldown elapses
//!    │ probe succeeds (entry removed)             ▼
//!    └──────────────────────── HALF_OPEN ◄── admit ≤1 probe / probe_interval
//!                                             (probe fails ⇒ re-arm OPEN;
//!                                              soft failure ⇒ no re-arm)
//! ```
//!
//! Design notes:
//! - **Window counting, not consecutive counting**: a flapping backend that
//!   fails every other attempt still trips — successes while CLOSED do not
//!   erase failure history (the breaker's job is budget isolation: what
//!   matters is the failure *rate*, and a flapping target drains the shared
//!   open budget exactly like a dead one). Only a successful *probe* of a
//!   tripped target removes the entry (full recovery).
//! - **Probe throttling instead of in-flight tracking**: after the cooldown
//!   elapses, at most one Open per `PROBE_INTERVAL` is admitted as a probe.
//!   A lost probe (a stream that never reports back) self-corrects after one
//!   interval — no permanently stuck HALF_OPEN state — and the effective
//!   probe rate toward a dead target is bounded at 1/cooldown.
//! - **Only connect-phase failures count** (resolve / TCP connect / UDP
//!   connect). Post-connection pathologies (`BackendWriteTimeout` etc.) are
//!   a different disease; the breaker's semantics is strictly
//!   *reachability*.
//! - **Bounded memory**: entries are dropped on success; failure history is
//!   pruned to the window at counting time; the table is hard-capped with a
//!   closed-first, least-recently-touched eviction.

use interflow_core::config::params::BreakerPolicy;
use std::collections::{HashMap, VecDeque};
use std::sync::Mutex;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use tokio::time::Instant;
use tracing::{debug, info, warn};

/// Hard cap on tracked targets; beyond it an entry is evicted (CLOSED
/// entries first, then least recently touched). 1024 distinct concurrently
/// -failing targets is far beyond any legitimate deployment and bounds the
/// table to a few hundred KiB.
const MAX_TRACKED_TARGETS: usize = 1024;

/// Minimum spacing between recovery probes toward the same OPEN target.
/// Only relevant when a probe's outcome is lost; a failing probe re-arms the
/// full cooldown anyway.
const PROBE_INTERVAL: Duration = Duration::from_secs(1);

/// Which plane a breaker table guards: selects log wording and metric names
/// so journal readers can tell an agent-side target trip from an edge-side
/// route trip apart.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BreakerKind {
    /// Agent egress: per-dial-target reachability (agent → backend).
    Egress,
    /// Expose edge: per-host route health (edge → route, evidence = relayed
    /// close reasons).
    Route,
}

impl BreakerKind {
    /// Human wording for log lines ("target breaker tripped" vs "route
    /// breaker tripped").
    const fn label(self) -> &'static str {
        match self {
            Self::Egress => "target breaker",
            Self::Route => "route breaker",
        }
    }

    /// The trip/recovery transition counter name. The egress name predates
    /// the route reuse and is asserted by mesh e2e; the route name keeps
    /// edge observability honest (an edge process must not emit
    /// egress-named counters).
    const fn transitions_metric(self) -> &'static str {
        match self {
            Self::Egress => "interflow_egress_target_breaker_transitions_total",
            Self::Route => "interflow_edge_route_breaker_transitions_total",
        }
    }
}

/// Verdict for one Open against a target.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BreakerDecision {
    /// Healthy (or unseen) target — proceed to the budgeted gates.
    Allow,
    /// Target OPEN, but this Open is the admitted recovery probe (cooldown
    /// elapsed, ≤1 per `PROBE_INTERVAL`) — proceed, and report the outcome:
    /// callers that derive health from the stream itself key their success
    /// accounting off this verdict. Callers without outcome reporting treat
    /// it exactly like [`BreakerDecision::Allow`].
    Probe,
    /// Target tripped OPEN — reject pre-dial, without consuming budget.
    Reject,
}

/// Per-target breaker table. Agent-level (shared across sessions); held by
/// [`super::egress::EgressRuntime`] next to the open-rate limiter.
pub struct TargetBreakers {
    kind: BreakerKind,
    cfg: BreakerPolicy,
    inner: Mutex<HashMap<String, BreakerEntry>>,
    /// Number of entries currently tripped (OPEN); feeds the
    /// `interflow_egress_target_breakers_open` gauge.
    tripped: AtomicUsize,
}

#[derive(Debug)]
struct BreakerEntry {
    /// `false` = CLOSED (counting failures), `true` = OPEN (rejecting).
    /// HALF_OPEN is not a stored state: it is the "cooldown elapsed,
    /// probing at most one per PROBE_INTERVAL" regime inside OPEN (see
    /// module docs).
    open: bool,
    /// Windowed connect-failure timestamps (meaningful while CLOSED).
    failures: VecDeque<Instant>,
    /// OPEN: earliest instant at which a probe may be admitted.
    deadline: Instant,
    /// OPEN: instant the last probe was admitted.
    last_probe: Instant,
    /// LRU touch for the hard-cap eviction.
    last_touch: Instant,
}

impl TargetBreakers {
    #[must_use]
    pub fn new(kind: BreakerKind, cfg: BreakerPolicy) -> Self {
        Self {
            kind,
            cfg,
            inner: Mutex::new(HashMap::new()),
            tripped: AtomicUsize::new(0),
        }
    }

    /// Current number of tripped targets (test-only accessor; no gauge is
    /// wired to it).
    #[cfg(test)]
    fn tripped_count(&self) -> usize {
        self.tripped.load(Ordering::Relaxed)
    }

    /// Gate one Open. Cheap (one lock + arithmetic); called before the
    /// budgeted gates so a tripped target costs nothing from the shared
    /// open-rate budget.
    pub fn check(&self, target: &str) -> BreakerDecision {
        let now = Instant::now();
        let mut inner = self.lock();
        let Some(entry) = inner.get_mut(target) else {
            return BreakerDecision::Allow; // never failed: healthy by definition
        };
        entry.last_touch = now;
        if !entry.open {
            return BreakerDecision::Allow;
        }
        if now < entry.deadline {
            return BreakerDecision::Reject;
        }
        // Cooldown elapsed: admit at most one probe per PROBE_INTERVAL. The
        // probe keeps the entry OPEN; success removes it, failure re-arms
        // the full cooldown.
        if now >= entry.last_probe + PROBE_INTERVAL {
            entry.last_probe = now;
            debug!("{} admitting recovery probe: {target}", self.kind.label());
            BreakerDecision::Probe
        } else {
            BreakerDecision::Reject
        }
    }

    /// Record a **direct** connect-phase failure (the dial itself failed).
    /// The first failure for an unseen target creates the entry (so
    /// `failure_threshold = 1` trips on the very first failure); a failure
    /// reported while OPEN re-arms the full cooldown.
    pub fn note_failure(&self, target: &str) {
        self.record_failure(target, false);
    }

    /// Record **derivative** failure evidence — not the backend failing, but
    /// a peer protection reacting as if it had (the edge receiving the
    /// agent's `target_circuit_open`). Counts toward tripping exactly like a
    /// direct failure while CLOSED, but is a no-op while OPEN: second-hand
    /// evidence must never extend an outage, or two breaker layers lock each
    /// other open (the §3.3 interlock of
    /// (internal design notes)).
    pub fn note_soft_failure(&self, target: &str) {
        self.record_failure(target, true);
    }

    /// Shared failure-recording body; `soft` only changes the OPEN-entry
    /// branch (re-arm vs ignore).
    fn record_failure(&self, target: &str, soft: bool) {
        let now = Instant::now();
        let mut inner = self.lock();

        if let Some(entry) = inner.get_mut(target) {
            entry.last_touch = now;
            if entry.open {
                if !soft {
                    // Direct failure reported by a probe (or an Open that
                    // raced the trip): re-arm the full cooldown.
                    entry.deadline = now + self.cfg.cooldown;
                    debug!("{} re-armed: {target}", self.kind.label());
                }
                return;
            }
            entry.failures.push_back(now);
            Self::prune_window(entry, now, self.cfg.failure_window);
            if entry.failures.len() >= self.cfg.failure_threshold as usize {
                self.trip(entry, target, now);
            }
            return;
        }

        // Unseen target: enforce the hard cap, then insert with one failure.
        if inner.len() >= MAX_TRACKED_TARGETS
            && let Some(victim) = eviction_candidate(&inner)
            && let Some(removed) = inner.remove(&victim)
            && removed.open
        {
            // Evicting a tripped entry: it simply stops being tracked;
            // fresh failures will re-trip it.
            self.tripped.fetch_sub(1, Ordering::Relaxed);
            debug!("{} table full, evicting {}", self.kind.label(), victim);
        }
        let mut entry = BreakerEntry {
            open: false,
            failures: VecDeque::from([now]),
            deadline: now,
            last_probe: now,
            last_touch: now,
        };
        if self.cfg.failure_threshold <= 1 {
            self.trip(&mut entry, target, now);
        }
        inner.insert(target.to_string(), entry);
    }

    /// Report a successful backend connection. For a **tripped** target this
    /// is the recovery probe succeeding — the entry is removed and the
    /// target fully re-admitted. For a CLOSED entry it is a no-op: failure
    /// history lives out its window (windowed failure-rate semantics — a
    /// flapping target must not dodge the threshold via interleaved
    /// successes).
    pub fn note_success(&self, target: &str) {
        let mut inner = self.lock();
        let Some(entry) = inner.get_mut(target) else {
            return; // common case: healthy target never tracked
        };
        entry.last_touch = Instant::now();
        if !entry.open {
            return;
        }
        inner.remove(target);
        self.tripped.fetch_sub(1, Ordering::Relaxed);
        metrics::counter!(self.kind.transitions_metric(), "state" => "closed").increment(1);
        info!(
            "{} recovered: {target} (probe succeeded)",
            self.kind.label()
        );
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, HashMap<String, BreakerEntry>> {
        self.inner
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    /// Trip a CLOSED entry OPEN. Warn once per trip — the per-stream
    /// rejections stay at debug so a retry storm does not flood the log.
    fn trip(&self, entry: &mut BreakerEntry, target: &str, now: Instant) {
        entry.open = true;
        entry.deadline = now + self.cfg.cooldown;
        entry.last_probe = now;
        self.tripped.fetch_add(1, Ordering::Relaxed);
        metrics::counter!(self.kind.transitions_metric(), "state" => "open").increment(1);
        warn!(
            "{} tripped: {target} ({} connect failures within {:?}; rejecting pre-dial for {:?})",
            self.kind.label(),
            entry.failures.len(),
            self.cfg.failure_window,
            self.cfg.cooldown
        );
    }

    fn prune_window(entry: &mut BreakerEntry, now: Instant, window: Duration) {
        while entry
            .failures
            .front()
            .is_some_and(|t| now.duration_since(*t) > window)
        {
            entry.failures.pop_front();
        }
    }
}

/// Pick the eviction victim when the hard cap is hit: CLOSED entries first
/// (their loss is cheapest — a fresh failure recreates them), then the
/// least recently touched.
fn eviction_candidate(inner: &HashMap<String, BreakerEntry>) -> Option<String> {
    inner
        .iter()
        .min_by_key(|(_, e)| (e.open, e.last_touch))
        .map(|(k, _)| k.clone())
}

#[cfg(test)]
#[allow(
    clippy::panic,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::missing_docs_in_private_items
)]
mod tests {
    use super::*;
    use std::time::Duration;

    fn table(threshold: u32, window: Duration, cooldown: Duration) -> TargetBreakers {
        TargetBreakers::new(
            BreakerKind::Egress,
            BreakerPolicy {
                failure_threshold: threshold,
                failure_window: window,
                cooldown,
            },
        )
    }

    /// Threshold reached within the window trips; rejections follow.
    #[tokio::test(start_paused = true)]
    async fn trips_after_threshold_in_window() {
        let t = table(5, Duration::from_secs(10), Duration::from_secs(30));
        for i in 0..4 {
            t.note_failure("127.0.0.1:3001");
            assert_eq!(
                t.check("127.0.0.1:3001"),
                BreakerDecision::Allow,
                "before threshold (failure {i})"
            );
        }
        t.note_failure("127.0.0.1:3001");
        assert_eq!(t.check("127.0.0.1:3001"), BreakerDecision::Reject);
        assert_eq!(t.tripped_count(), 1);
        // Other targets are unaffected: isolation, not global state.
        assert_eq!(t.check("127.0.0.1:5174"), BreakerDecision::Allow);
    }

    /// Failures spaced beyond the window age out and never accumulate to the
    /// threshold (a slowly-leaking backend is not a storm).
    #[tokio::test(start_paused = true)]
    async fn window_aging_prevents_trip() {
        let t = table(5, Duration::from_secs(10), Duration::from_secs(30));
        for _ in 0..10 {
            t.note_failure("slow-leak");
            tokio::time::advance(Duration::from_secs(11)).await;
        }
        assert_eq!(t.check("slow-leak"), BreakerDecision::Allow);
        assert_eq!(t.tripped_count(), 0);
    }

    /// Successes while CLOSED do not erase windowed history (a flapping
    /// target must not dodge the threshold via interleaved successes).
    #[tokio::test(start_paused = true)]
    async fn flapping_failures_still_trip() {
        let t = table(5, Duration::from_secs(10), Duration::from_secs(30));
        for _ in 0..4 {
            t.note_failure("flap");
            t.note_success("flap");
        }
        t.note_failure("flap");
        assert_eq!(t.check("flap"), BreakerDecision::Reject);
    }

    /// After the cooldown elapses exactly one probe is admitted (flagged as
    /// `Probe`, not `Allow` — callers key their outcome accounting off the
    /// verdict); its success recovers the entry fully.
    #[tokio::test(start_paused = true)]
    async fn cooldown_single_probe_then_recover() {
        let t = table(2, Duration::from_secs(10), Duration::from_secs(30));
        t.note_failure("tgt");
        t.note_failure("tgt");
        assert_eq!(t.check("tgt"), BreakerDecision::Reject);

        tokio::time::advance(Duration::from_secs(31)).await;
        // First open after cooldown = the probe.
        assert_eq!(t.check("tgt"), BreakerDecision::Probe);
        // A second open within PROBE_INTERVAL is rejected.
        assert_eq!(t.check("tgt"), BreakerDecision::Reject);
        // Probe succeeds → entry removed, fully re-admitted.
        t.note_success("tgt");
        assert_eq!(t.check("tgt"), BreakerDecision::Allow);
        assert_eq!(t.tripped_count(), 0);
    }

    /// A failing probe re-arms the full cooldown.
    #[tokio::test(start_paused = true)]
    async fn probe_failure_re_arms_cooldown() {
        let t = table(2, Duration::from_secs(10), Duration::from_secs(30));
        t.note_failure("tgt");
        t.note_failure("tgt");
        tokio::time::advance(Duration::from_secs(31)).await;
        assert_eq!(t.check("tgt"), BreakerDecision::Probe);
        t.note_failure("tgt"); // probe failed
        assert_eq!(t.check("tgt"), BreakerDecision::Reject);
        tokio::time::advance(Duration::from_secs(29)).await;
        assert_eq!(t.check("tgt"), BreakerDecision::Reject); // still within re-armed cooldown
        tokio::time::advance(Duration::from_secs(2)).await;
        assert_eq!(t.check("tgt"), BreakerDecision::Probe); // next probe
    }

    /// Soft (derivative) failure evidence: accumulates toward tripping while
    /// CLOSED, but never re-arms an OPEN entry — second-hand evidence must
    /// not extend an outage, or two breaker layers lock each other open.
    #[tokio::test(start_paused = true)]
    async fn soft_failure_trips_when_closed_but_never_re_arms() {
        let t = table(2, Duration::from_secs(10), Duration::from_secs(30));
        // While CLOSED it counts like a direct failure.
        t.note_soft_failure("tgt");
        assert_eq!(t.check("tgt"), BreakerDecision::Allow);
        t.note_soft_failure("tgt");
        assert_eq!(t.check("tgt"), BreakerDecision::Reject);
        assert_eq!(t.tripped_count(), 1);

        tokio::time::advance(Duration::from_secs(31)).await;
        assert_eq!(t.check("tgt"), BreakerDecision::Probe);
        // The probe comes back with only derivative evidence (e.g. the
        // agent-side breaker is still OPEN): it must NOT re-arm the cooldown…
        t.note_soft_failure("tgt");
        // …so past PROBE_INTERVAL the next probe is admitted, not locked out
        // for another full cooldown.
        tokio::time::advance(PROBE_INTERVAL + Duration::from_millis(1)).await;
        assert_eq!(
            t.check("tgt"),
            BreakerDecision::Probe,
            "soft failure must not re-arm an OPEN entry"
        );
        // Contrast: a direct failure on the probe does re-arm.
        t.note_failure("tgt");
        tokio::time::advance(PROBE_INTERVAL + Duration::from_millis(1)).await;
        assert_eq!(t.check("tgt"), BreakerDecision::Reject);
    }

    /// threshold = 1 trips on the very first failure.
    #[tokio::test(start_paused = true)]
    async fn threshold_one_trips_immediately() {
        let t = table(1, Duration::from_secs(10), Duration::from_secs(30));
        t.note_failure("fragile");
        assert_eq!(t.check("fragile"), BreakerDecision::Reject);
    }

    /// A lost probe (outcome never reported) self-corrects after
    /// PROBE_INTERVAL: the next open becomes the new probe.
    #[tokio::test(start_paused = true)]
    async fn lost_probe_self_corrects() {
        let t = table(2, Duration::from_secs(10), Duration::from_secs(30));
        t.note_failure("tgt");
        t.note_failure("tgt");
        tokio::time::advance(Duration::from_secs(31)).await;
        assert_eq!(t.check("tgt"), BreakerDecision::Probe); // probe admitted, then lost
        tokio::time::advance(PROBE_INTERVAL + Duration::from_millis(1)).await;
        assert_eq!(t.check("tgt"), BreakerDecision::Probe); // re-probe admitted
    }

    /// The hard cap evicts CLOSED entries first (cheapest loss), then the
    /// least recently touched.
    #[tokio::test(start_paused = true)]
    async fn eviction_prefers_closed_then_oldest() {
        let now = Instant::now();
        let entry = |open: bool, age_ago: Duration| BreakerEntry {
            open,
            failures: VecDeque::from([now - age_ago]),
            deadline: now,
            last_probe: now,
            last_touch: now - age_ago,
        };
        let mut inner = HashMap::new();
        inner.insert("open-new".to_string(), entry(true, Duration::from_secs(1)));
        inner.insert(
            "closed-old".to_string(),
            entry(false, Duration::from_mins(1)),
        );
        inner.insert(
            "closed-new".to_string(),
            entry(false, Duration::from_secs(1)),
        );

        assert_eq!(eviction_candidate(&inner).as_deref(), Some("closed-old"));

        inner.remove("closed-old");
        // With only one CLOSED entry left it is still preferred over OPEN.
        assert_eq!(eviction_candidate(&inner).as_deref(), Some("closed-new"));

        inner.remove("closed-new");
        assert_eq!(eviction_candidate(&inner).as_deref(), Some("open-new"));
    }
}
