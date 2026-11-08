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
//!   open budget exactly like a dead one). A tripped entry is removed only by
//!   a **successful probe** — a real Open admitted post-cooldown, or the
//!   background bare-TCP recovery prober
//!   ([`super::breaker_probe`], 2026-10-18) whose success calls the same
//!   `note_success` without consuming any stream budget.
//! - **Probe throttling instead of in-flight tracking**: after the cooldown
//!   elapses, at most one Open per `PROBE_INTERVAL` is admitted as a probe.
//!   A lost probe (a stream that never reports back) self-corrects after one
//!   interval — no permanently stuck HALF_OPEN state — and the effective
//!   probe rate toward a dead target is bounded at 1/cooldown.
//! - **Egress keys are transport-namespaced** ([`dial_key`]): the same
//!   `host:port` dialed over TCP and over UDP keeps two independent entries —
//!   a TCP connect failure says nothing about UDP health (and vice versa),
//!   so evidence must not pool across transports. The route kind (keyed by
//!   host) has no transport dimension and uses the bare key.
//! - **Only connect-phase failures count** (resolve / TCP connect / UDP
//!   connect). Post-connection pathologies (`BackendWriteTimeout` etc.) are
//!   a different disease; the breaker's semantics is strictly
//!   *reachability*.
//! - **Bounded memory**: entries are dropped on success; failure history is
//!   pruned to the window at counting time; the table is hard-capped with a
//!   closed-first, least-recently-touched eviction.

use interflow_core::config::params::BreakerPolicy;
use interflow_core::protocol::StreamProto;
use std::collections::{HashMap, VecDeque};
use std::sync::Mutex;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use tokio::sync::watch;
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

    /// The "entries currently OPEN" gauge name, set at every trip/recovery
    /// transition (2026-10-18: wired for real — the field comment had
    /// promised this gauge since the 2026-09-16 origin without any emitter
    /// existing).
    const fn open_gauge(self) -> &'static str {
        match self {
            Self::Egress => "interflow_egress_target_breakers_open",
            Self::Route => "interflow_edge_route_breakers_open",
        }
    }
}

/// Namespaces an egress dial target by transport.
///
/// The breaker key for a TCP-path dial is `tcp:host:port`, for a UDP-path
/// dial `udp:host:port`. All egress `check`/`note_*` call sites and the
/// recovery prober go through this one constructor, so the two failure
/// populations can never pool (the 2026-10-18 active-recovery
/// prerequisite: a bare-TCP probe must not "heal" a UDP-tripped entry,
/// and a UDP resolve failure must not count against TCP routing).
#[must_use]
pub fn dial_key(proto: StreamProto, target: &str) -> String {
    match proto {
        StreamProto::Tcp => format!("tcp:{target}"),
        StreamProto::Udp => format!("udp:{target}"),
    }
}

/// One OPEN breaker entry as the read face carries it — the level's row
/// material (2026-10-19 open-set face).
///
/// WHICH target, WHEN it tripped, WHEN the recovery machinery last
/// touched it. The set + these instants are the whole face: a stuck-OPEN
/// entry reads as an old `opened_unix`, a dead recovery prober as a
/// `last_probe_unix` that stops advancing while the entry stays open.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BreakerOpenRow {
    /// The breaker key: agent egress dial keys (`tcp:host:port` /
    /// `udp:host:port`, see [`dial_key`]); edge route hosts bare.
    pub target: String,
    /// Unix seconds of the trip (the entry's last closed→open
    /// transition).
    pub opened_unix: u64,
    /// Unix seconds of the last admitted recovery probe (egress kind) /
    /// last touch (route kind). `0` = never.
    pub last_probe_unix: u64,
}

/// Live open-set telemetry for one breaker table.
///
/// The authoritative latest snapshot lives in the watch channel itself
/// (rows are a `Vec`, not copy atomics); `snapshot()` borrows-and-clones
/// it. Same birth-receiver and subscription contracts as
/// [`super::peer_watch::PeerWatchState`]: the table publishes on every
/// open-set change (trip / recovery removal / cap eviction), sorted by
/// target — an unchanged set never re-sends.
#[derive(Debug)]
pub struct BreakerWatchState {
    tx: watch::Sender<Vec<BreakerOpenRow>>,
    #[allow(dead_code)] // alive for the channel's lifetime, not read here
    rx: watch::Receiver<Vec<BreakerOpenRow>>,
    /// Publishes that actually landed (change-guarded sends only) — the
    /// no-chatter assertion's test seam.
    sends: AtomicUsize,
}

impl Default for BreakerWatchState {
    fn default() -> Self {
        let (tx, rx) = watch::channel(Vec::new());
        Self {
            tx,
            rx,
            sends: AtomicUsize::new(0),
        }
    }
}

impl BreakerWatchState {
    /// Reads the latest open set (empty = every tracked target healthy).
    pub fn snapshot(&self) -> Vec<BreakerOpenRow> {
        self.tx.borrow().clone()
    }

    /// Subscribes to open-set changes from here on; errors once the
    /// table — and every handle to this state — is gone.
    pub fn subscribe(&self) -> watch::Receiver<Vec<BreakerOpenRow>> {
        self.rx.clone()
    }

    /// One change-guarded publish: an unchanged set never wakes the
    /// watchers (a quiet table must not degenerate its subscribers into
    /// polling).
    fn publish(&self, rows: Vec<BreakerOpenRow>) {
        if self.tx.borrow().as_slice() != rows.as_slice() {
            let _ = self.tx.send(rows);
            self.sends.fetch_add(1, Ordering::Relaxed);
        }
    }

    /// The count of change-guarded publishes that landed (tests only).
    #[cfg(test)]
    fn send_count(&self) -> usize {
        self.sends.load(Ordering::Relaxed)
    }
}

fn unix_now() -> u64 {
    u64::try_from(interflow_identity::expiry::now_unix()).unwrap_or(0)
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
    /// Log attribution (`AgentInfo::effective_log_name`): trip/recovery
    /// lines carry it so breaker activity lands in the GUI "This node" view.
    node: String,
    cfg: BreakerPolicy,
    inner: Mutex<HashMap<String, BreakerEntry>>,
    /// Number of entries currently tripped (OPEN); every transition point
    /// publishes it to the kind's `open_gauge` (see [`BreakerKind::open_gauge`]).
    tripped: AtomicUsize,
    /// The open-set read face (2026-10-19): present exactly when an
    /// owner wanted the set observable (the agent's egress runtime, the
    /// edge's route table feeding the hub row); `None` keeps the table
    /// metrics-only, the pre-face behavior.
    face: Option<std::sync::Arc<BreakerWatchState>>,
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
    /// Unix seconds of the trip (0 = never tripped / CLOSED); the open
    /// face's "最近转变时刻".
    opened_unix: u64,
    /// Unix seconds of the last admitted probe / touch; the dead-prober
    /// signature when it stops advancing on a still-open entry.
    last_probe_unix: u64,
}

impl TargetBreakers {
    #[must_use]
    pub fn new(kind: BreakerKind, node: String, cfg: BreakerPolicy) -> Self {
        Self {
            kind,
            node,
            cfg,
            inner: Mutex::new(HashMap::new()),
            tripped: AtomicUsize::new(0),
            face: None,
        }
    }

    /// [`Self::new`] with the open-set read face attached — the table
    /// publishes the currently-OPEN rows (plus their transition and
    /// probe instants) on every open-set change.
    #[must_use]
    pub fn with_face(
        kind: BreakerKind,
        node: String,
        cfg: BreakerPolicy,
        face: std::sync::Arc<BreakerWatchState>,
    ) -> Self {
        Self {
            face: Some(face),
            ..Self::new(kind, node, cfg)
        }
    }

    /// Current number of tripped targets (test-only accessor; production
    /// readers use the `open_gauge` metric or [`Self::open_targets`]).
    #[cfg(test)]
    fn tripped_count(&self) -> usize {
        self.tripped.load(Ordering::Relaxed)
    }

    /// Snapshot of the currently OPEN (tripped) keys, unordered. The
    /// recovery prober's scan face: one lock, one collect; empty result =
    /// nothing to probe this tick (the prober's idle exit — no separate
    /// gauge poll needed).
    pub fn open_targets(&self) -> Vec<String> {
        self.lock()
            .iter()
            .filter(|(_, entry)| entry.open)
            .map(|(key, _)| key.clone())
            .collect()
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
            let unix = unix_now();
            entry.last_probe_unix = unix;
            debug!(node = %self.node, "{} admitting recovery probe: {target}", self.kind.label());
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
        // Whether the OPEN count moved this call — the face/gauge publish
        // happens ONCE at the end, with the guard still held but no
        // outstanding entry borrow (re-locking here would self-deadlock:
        // the std Mutex is not reentrant).
        let mut open_count_moved = false;

        if let Some(entry) = inner.get_mut(target) {
            entry.last_touch = now;
            if entry.open {
                if !soft {
                    // Direct failure reported by a probe (or an Open that
                    // raced the trip): re-arm the full cooldown.
                    entry.deadline = now + self.cfg.cooldown;
                    debug!(node = %self.node, "{} re-armed: {target}", self.kind.label());
                }
                return;
            }
            entry.failures.push_back(now);
            Self::prune_window(entry, now, self.cfg.failure_window);
            if entry.failures.len() >= self.cfg.failure_threshold as usize {
                self.trip_entry(entry, target, now);
                open_count_moved = true;
            }
        } else {
            // Unseen target: enforce the hard cap, then insert with one
            // failure.
            if inner.len() >= MAX_TRACKED_TARGETS
                && let Some(victim) = eviction_candidate(&inner)
                && let Some(removed) = inner.remove(&victim)
                && removed.open
            {
                // Evicting a tripped entry: it simply stops being tracked;
                // fresh failures will re-trip it.
                self.tripped.fetch_sub(1, Ordering::Relaxed);
                open_count_moved = true;
                debug!(node = %self.node, "{} table full, evicting {}", self.kind.label(), victim);
            }
            let mut entry = BreakerEntry {
                open: false,
                failures: VecDeque::from([now]),
                deadline: now,
                last_probe: now,
                last_touch: now,
                opened_unix: 0,
                last_probe_unix: unix_now(),
            };
            if self.cfg.failure_threshold <= 1 {
                self.trip_entry(&mut entry, target, now);
                open_count_moved = true;
            }
            inner.insert(target.to_string(), entry);
        }
        if open_count_moved {
            self.publish_open_gauge(&inner);
        }
    }

    /// Report a successful backend connection. For a **tripped** target this
    /// is the recovery probe succeeding — the entry is removed and the
    /// target fully re-admitted; returns `true`. For a CLOSED entry it is a
    /// no-op (returns `false`): failure history lives out its window
    /// (windowed failure-rate semantics — a flapping target must not dodge
    /// the threshold via interleaved successes).
    pub fn note_success(&self, target: &str) -> bool {
        let mut inner = self.lock();
        let Some(entry) = inner.get_mut(target) else {
            return false; // common case: healthy target never tracked
        };
        entry.last_touch = Instant::now();
        if !entry.open {
            return false;
        }
        inner.remove(target);
        self.tripped.fetch_sub(1, Ordering::Relaxed);
        self.publish_open_gauge(&inner);
        metrics::counter!(self.kind.transitions_metric(), "state" => "closed").increment(1);
        info!(
            node = %self.node,
            "{} recovered: {target} (probe succeeded)",
            self.kind.label()
        );
        true
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, HashMap<String, BreakerEntry>> {
        self.inner
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    /// Publishes the OPEN-entry count after every transition (trip, recovery
    /// removal, cap eviction) — the gauge is level-triggered, so a missed
    /// publisher would only be visible as a stale value until the next
    /// transition of the same table. The 2026-10-19 open-set face rides
    /// the same single publication point: the currently-OPEN rows (with
    /// their transition and probe instants), re-sent only when the set
    /// actually changed (a quiet table never wakes its watchers).
    fn publish_open_gauge(&self, inner: &HashMap<String, BreakerEntry>) {
        metrics::gauge!(self.kind.open_gauge()).set(crate::hub::state::count_as_f64(
            self.tripped.load(Ordering::Relaxed),
        ));
        if let Some(face) = &self.face {
            let mut rows: Vec<BreakerOpenRow> = inner
                .iter()
                .filter(|(_, entry)| entry.open)
                .map(|(target, entry)| BreakerOpenRow {
                    target: target.clone(),
                    opened_unix: entry.opened_unix,
                    last_probe_unix: entry.last_probe_unix,
                })
                .collect();
            rows.sort_by(|a, b| a.target.cmp(&b.target));
            face.publish(rows);
        }
    }

    /// Trip a CLOSED entry OPEN — the entry mutation + counter + log half
    /// only. The gauge/face publish is the CALLER's (it holds the table
    /// guard; see [`Self::record_failure`]'s publish note and
    /// [`Self::note_success`]). Warn once per trip — the per-stream
    /// rejections stay at debug so a retry storm does not flood the log.
    fn trip_entry(&self, entry: &mut BreakerEntry, target: &str, now: Instant) {
        entry.open = true;
        entry.deadline = now + self.cfg.cooldown;
        entry.last_probe = now;
        let unix = unix_now();
        entry.opened_unix = unix;
        entry.last_probe_unix = unix;
        self.tripped.fetch_add(1, Ordering::Relaxed);
        metrics::counter!(self.kind.transitions_metric(), "state" => "open").increment(1);
        warn!(
            node = %self.node,
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
            "test-node".to_string(),
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
            opened_unix: 0,
            last_probe_unix: 0,
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

    /// Transport-namespaced dial keys keep the TCP and UDP populations of
    /// the same `host:port` fully independent: TCP failures trip only the
    /// TCP entry, and a TCP recovery (the bare-TCP prober) cannot "heal" a
    /// UDP-tripped entry — the correctness prerequisite of the 2026-10-18
    /// active recovery.
    #[tokio::test(start_paused = true)]
    async fn dial_keys_split_transports() {
        use interflow_core::protocol::StreamProto;
        let t = table(2, Duration::from_secs(10), Duration::from_secs(30));
        let tcp = dial_key(StreamProto::Tcp, "127.0.0.1:5174");
        let udp = dial_key(StreamProto::Udp, "127.0.0.1:5174");
        assert_ne!(tcp, udp);

        // TCP-side failures trip the TCP entry only.
        t.note_failure(&tcp);
        t.note_failure(&tcp);
        assert_eq!(t.check(&tcp), BreakerDecision::Reject);
        assert_eq!(t.check(&udp), BreakerDecision::Allow);
        assert_eq!(t.tripped_count(), 1);

        // A bare-TCP probe success (the prober's note_success) removes the
        // TCP entry without touching a UDP entry tripped independently.
        t.note_failure(&udp);
        t.note_failure(&udp);
        t.note_success(&tcp);
        assert_eq!(t.check(&tcp), BreakerDecision::Allow);
        assert_eq!(t.check(&udp), BreakerDecision::Reject);
    }

    /// The open-set face (2026-10-19): trips publish rows with their
    /// transition and probe instants, recovery removes them, and an
    /// unchanged set never re-sends.
    #[tokio::test(start_paused = true)]
    async fn open_set_face_publishes_rows_on_changes_only() {
        let face = std::sync::Arc::new(BreakerWatchState::default());
        let t = TargetBreakers::with_face(
            BreakerKind::Egress,
            "test-node".to_owned(),
            BreakerPolicy {
                failure_threshold: 1,
                failure_window: Duration::from_secs(10),
                cooldown: Duration::from_secs(30),
            },
            std::sync::Arc::clone(&face),
        );
        assert!(
            face.snapshot().is_empty(),
            "a healthy table publishes nothing"
        );

        // Trip one: the row carries the target and a real transition
        // instant (the "最近转变时刻" the face promises).
        t.note_failure("tcp:a:1");
        let rows = face.snapshot();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].target, "tcp:a:1");
        assert!(rows[0].opened_unix > 0, "the trip instant is populated");
        assert!(rows[0].last_probe_unix > 0);

        // A no-transition touch (another failure while OPEN re-arms the
        // cooldown but the SET is unchanged... which does change the row
        // only via re-arm — the set SHAPE is what the face keys on; the
        // re-arm does not alter the row material, so no re-send).
        let before = face.send_count();
        t.note_failure("tcp:a:1");
        assert_eq!(
            face.send_count(),
            before,
            "an unchanged open set never re-sends"
        );

        // A second trip adds its row (deterministically ordered).
        t.note_failure("tcp:b:2");
        let rows = face.snapshot();
        assert_eq!(
            rows.iter().map(|r| r.target.as_str()).collect::<Vec<_>>(),
            ["tcp:a:1", "tcp:b:2"],
            "rows are sorted by target"
        );

        // Recovery removes exactly that row.
        t.note_success("tcp:a:1");
        let rows = face.snapshot();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].target, "tcp:b:2");
    }

    /// `open_targets` lists exactly the tripped keys — the prober's scan
    /// face (and its idle-exit signal when empty).
    #[tokio::test(start_paused = true)]
    async fn open_targets_lists_only_tripped() {
        let t = table(1, Duration::from_secs(10), Duration::from_secs(30));
        assert_eq!(t.open_targets(), Vec::<String>::new());
        t.note_failure("a");
        t.note_failure("b");
        t.note_success("b");
        let mut open = t.open_targets();
        open.sort();
        assert_eq!(open, ["a".to_string()]);
    }
}
