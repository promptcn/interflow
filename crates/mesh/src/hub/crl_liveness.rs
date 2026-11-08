//! Level-triggered CRL-poll liveness — the face material behind the fleet
//! faces' `crl_last_success_unix` + `crl_failures_total`
//!
//! The renewal loop's CRL poll had no face at all: `last_crl_success` was
//! a loop-local variable feeding only the 1h fail-closed bound, so a
//! silently-hung poll loop (the task wedges without erroring — the bound
//! is checked BY the loop, so it never fires) was invisible on every read
//! face, indistinguishable from a long legitimate quiet period between
//! CRL changes. The agent now publishes its level
//! (`interflow_renewal::CrlPollFace`) and a reporter pushes it here over
//! the session control plane; this table is the hub's copy.
//!
//! THE design law of this face: a row's recency is the level's own
//! confirmation instant (`last_success_unix` as the REPORT carries it),
//! never the report's arrival time. The reporter is transport, not truth
//! — a hung loop with a perfectly healthy reporter keeps sending a frozen
//! confirmation instant, and that freeze is exactly the silence the
//! [`CrlLiveness::sweep`] below classifies. Recording the arrival instant
//! instead would make the face read fresh forever and defeat its only
//! purpose.
//!
//! Bump discipline (see `hub::floor_clock`): a row's first sighting, its
//! revival from silent, or a fresh→silent crossing found by the sweep. A
//! steady re-report of the same level — recency advancing inside the
//! fresh class, `failures_total` ticking up during a registrar outage —
//! bumps NOTHING: a clock that ticks every poll interval would degenerate
//! the floor watch into polling (the same doctrine as the policy
//! watermarks' steady 304). The failure counter is diagnostic material
//! for the next re-read, not a trigger.
//!
//! The self slot is this hub process's OWN renewal loop (pack-built hubs
//! and expose edges run one beside the engine; the assembly layer copies
//! the face here on a 30s cadence). Same classification, same bump rules
//! — a hub that stops polling its registrar is as unreadable as an agent
//! that does, and this is the only structural place that shows.

use std::collections::{BTreeMap, HashMap};
use std::sync::Mutex;

use interflow_core::tunnel::transport::CrlLivenessReport;
use tokio_util::sync::CancellationToken;
use tokio_util::task::TaskTracker;

use interflow_renewal::CRL_SILENT_AFTER_SECS;

/// The sweep cadence — same shape as the policy face's: detection latency
/// is bounded by the silent threshold plus one sweep; the cost is a
/// lock-guarded scan with zero bumps in steady state.
const CRL_FACE_SWEEP_INTERVAL: std::time::Duration = std::time::Duration::from_secs(5);

/// One node's face row (the wire-visible level: confirmation instant plus
/// the failure counter).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CrlLivenessRow {
    /// Unix seconds of the node's last successful CRL poll (no-change
    /// included — "polled, nothing moved").
    pub last_success_unix: u64,
    /// Cumulative failed polls since the node's process started.
    pub failures_total: u64,
    /// The renewal backoff ladder's current stage (consecutive failed
    /// renewal attempts, 0 = none) — the connection-quality face's
    /// `backoff stage N/5` (additive, 2026-10-20).
    pub renewal_backoff_failures: u32,
    /// The stage's observed maximum today (UTC day rollover).
    pub renewal_backoff_max_today: u32,
}

impl From<&CrlLivenessReport> for CrlLivenessRow {
    fn from(report: &CrlLivenessReport) -> Self {
        Self {
            last_success_unix: report.last_success_unix,
            failures_total: report.failures_total,
            renewal_backoff_failures: report.renewal_backoff_failures.unwrap_or(0),
            renewal_backoff_max_today: report.renewal_backoff_failures.unwrap_or(0),
        }
    }
}

/// Internal row state (the recency class is face-derivable and never
/// serialized — consumers judge `last_success_unix` against their own
/// capture anchor).
#[derive(Debug)]
struct Row {
    face: CrlLivenessRow,
    /// The UTC day `renewal_backoff_max_today` was last advanced in.
    backoff_day: u32,
    /// Whether the sweep has already marked this row silent (one bump per
    /// class transition).
    silent: bool,
}

/// The shared liveness table.
///
/// In-memory by design — after a hub restart every online agent's next
/// report re-populates its row within one reporter interval, and the
/// first-sighting bump makes that refill push-visible to floor watchers
/// (the policy watermarks' restart contract, verbatim).
pub struct CrlLiveness {
    inner: Mutex<HashMap<String, Row>>,
    /// This hub process's own renewal loop (written by the assembly
    /// layer's copy task; `None` until the hub has one to show).
    self_row: Mutex<Option<Row>>,
    floor: crate::hub::floor_clock::FloorClock,
}

/// Age of a confirmation instant against `now` — the class input shared
/// by record (revival check) and sweep (crossing check).
const fn age_secs(last_success_unix: u64, now_unix: u64) -> u64 {
    now_unix.saturating_sub(last_success_unix)
}

/// Whether a level reads fresh at `now_unix`.
const fn is_fresh(last_success_unix: u64, now_unix: u64) -> bool {
    age_secs(last_success_unix, now_unix) <= CRL_SILENT_AFTER_SECS
}

/// The UTC day number of a unix instant (the max-today tracker's
/// rollover key).
fn utc_day(now_unix: u64) -> u32 {
    u32::try_from(now_unix / 86_400).unwrap_or(u32::MAX)
}

/// Advances the row's backoff bookkeeping: day rollover resets the
/// maximum, and the reported stage can never lower the day's peak.
fn advance_backoff_max(row: &mut Row, reported_stage: u32, now_unix: u64) {
    let day = utc_day(now_unix);
    if row.backoff_day != day {
        row.backoff_day = day;
        row.face.renewal_backoff_max_today = 0;
    }
    row.face.renewal_backoff_failures = reported_stage;
    row.face.renewal_backoff_max_today = row.face.renewal_backoff_max_today.max(reported_stage);
}

impl CrlLiveness {
    pub fn new(floor: crate::hub::floor_clock::FloorClock) -> Self {
        Self {
            inner: Mutex::new(HashMap::new()),
            self_row: Mutex::new(None),
            floor,
        }
    }

    /// Records one agent report. `now_unix` is the HUB's clock — the only
    /// clock that judges recency (the report's arrival instant never
    /// enters the stored face; see the module docs).
    ///
    /// Bumps the floor clock only on an observable face change: first
    /// sighting, or revival (a silent row reporting a fresh level again).
    pub fn record(&self, agent: &str, report: &CrlLivenessReport, now_unix: u64) {
        let face = CrlLivenessRow::from(report);
        let mut inner = self
            .inner
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let face_changed = if let Some(row) = inner.get_mut(agent) {
            let revived = row.silent && is_fresh(face.last_success_unix, now_unix);
            // The confirmation instant never regresses (the agent's own
            // face already fetch-maxes it); the failure counter is
            // REPLACED by the report's value — it is the node's current
            // level, and a restarted process legitimately restarts it at
            // zero (a level, not an audit ledger).
            row.face.last_success_unix = row.face.last_success_unix.max(face.last_success_unix);
            row.face.failures_total = face.failures_total;
            advance_backoff_max(row, face.renewal_backoff_failures, now_unix);
            if is_fresh(row.face.last_success_unix, now_unix) {
                row.silent = false;
            }
            revived
        } else {
            let mut row = Row {
                face,
                backoff_day: utc_day(now_unix),
                silent: !is_fresh(face.last_success_unix, now_unix),
            };
            advance_backoff_max(&mut row, face.renewal_backoff_failures, now_unix);
            inner.insert(agent.to_owned(), row);
            true
        };
        drop(inner);
        if face_changed {
            self.floor.bump();
        }
    }

    /// Records this hub process's own renewal level (the assembly layer's
    /// copy task). Same bump rules as [`Self::record`].
    pub fn record_self(&self, report: &CrlLivenessReport, now_unix: u64) {
        let face = CrlLivenessRow::from(report);
        let mut slot = self
            .self_row
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let face_changed = if let Some(row) = slot.as_mut() {
            let revived = row.silent && is_fresh(face.last_success_unix, now_unix);
            row.face.last_success_unix = row.face.last_success_unix.max(face.last_success_unix);
            row.face.failures_total = face.failures_total;
            advance_backoff_max(row, face.renewal_backoff_failures, now_unix);
            if is_fresh(row.face.last_success_unix, now_unix) {
                row.silent = false;
            }
            revived
        } else {
            let mut row = Row {
                face,
                backoff_day: utc_day(now_unix),
                silent: !is_fresh(face.last_success_unix, now_unix),
            };
            advance_backoff_max(&mut row, face.renewal_backoff_failures, now_unix);
            *slot = Some(row);
            true
        };
        drop(slot);
        if face_changed {
            self.floor.bump();
        }
    }

    /// Re-classifies recency: rows whose confirmation instant is older
    /// than the silent threshold enter the silent class (bumping the floor
    /// clock once per sweep that produced transitions — the watchers
    /// re-read the whole face, so one version advance covers a batch).
    /// The self slot is classified in the same pass. Returns the number
    /// of transitions fired.
    pub fn sweep(&self, now_unix: u64) -> usize {
        let mut transitions = 0usize;
        {
            let mut inner = self
                .inner
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            transitions += inner
                .values_mut()
                .filter(|row| !row.silent && !is_fresh(row.face.last_success_unix, now_unix))
                .map(|row| row.silent = true)
                .count();
        }
        {
            let mut slot = self
                .self_row
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            if let Some(row) = slot.as_mut()
                && !row.silent
                && !is_fresh(row.face.last_success_unix, now_unix)
            {
                row.silent = true;
                transitions += 1;
            }
        }
        if transitions > 0 {
            self.floor.bump();
            metrics::counter!("interflow_hub_crl_silent_transitions_total")
                .increment(u64::try_from(transitions).unwrap_or(u64::MAX));
        }
        transitions
    }

    /// The agent face: every node that ever reported to this hub process,
    /// in deterministic order.
    pub fn face(&self) -> BTreeMap<String, CrlLivenessRow> {
        let inner = self
            .inner
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        inner.iter().map(|(k, row)| (k.clone(), row.face)).collect()
    }

    /// The hub's own renewal level, when this process runs one.
    pub fn self_face(&self) -> Option<CrlLivenessRow> {
        self.self_row
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .as_ref()
            .map(|row| row.face)
    }
}

/// One report landed over either transport face. The single entry the h2
/// handler and the QUIC dispatch arm call — the identity/registration
/// gate is the callers' (same standing as the target-recovery notice);
/// this fn is the recording half only.
pub(crate) fn record_via_state(
    state: &crate::hub::state::HubState,
    agent: &str,
    report: &CrlLivenessReport,
) {
    state.crl_liveness.record(
        agent,
        report,
        u64::try_from(interflow_identity::expiry::now_unix()).unwrap_or(0),
    );
}

/// The copy cadence for the self slot: two samples per CRL poll, same
/// reasoning as the agent-side reporter's interval.
const CRL_SELF_REPORT_INTERVAL: std::time::Duration = std::time::Duration::from_secs(30);

/// The hub-process assembly's copy task: feeds THIS hub's own renewal
/// face into the self slot on a fixed cadence.
///
/// Pack-built hubs and expose edges run a renewal loop beside the engine
/// (whoever spawns it also spawns this). The face is read at send time —
/// a hung loop's frozen level lands verbatim, which is the silence the
/// sweep classifies.
pub fn spawn_self_reporter(
    state: std::sync::Arc<crate::hub::state::HubState>,
    face: std::sync::Arc<interflow_renewal::CrlPollFace>,
    shutdown: CancellationToken,
) {
    tokio::spawn(async move {
        // Register at spawn (same discipline as the sweeper rows).
        state.watchdog.register(
            "crl_self_reporter",
            CRL_SELF_REPORT_INTERVAL.as_secs(),
            u64::try_from(interflow_identity::expiry::now_unix()).unwrap_or(0),
        );
        let mut ticker = tokio::time::interval(CRL_SELF_REPORT_INTERVAL);
        ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        loop {
            tokio::select! {
                () = shutdown.cancelled() => break,
                _ = ticker.tick() => {}
            }
            let snap = face.snapshot();
            state.watchdog.tick(
                "crl_self_reporter",
                CRL_SELF_REPORT_INTERVAL.as_secs(),
                u64::try_from(interflow_identity::expiry::now_unix()).unwrap_or(0),
            );
            state.crl_liveness.record_self(
                &CrlLivenessReport {
                    last_success_unix: snap.last_success_unix,
                    failures_total: snap.failures_total,
                    renewal_backoff_failures: Some(snap.backoff_failures),
                },
                u64::try_from(interflow_identity::expiry::now_unix()).unwrap_or(0),
            );
        }
    });
}

/// Managed entry point of the recency sweeper.
///
/// When the loop body exits abnormally (including a panic), log it, count
/// it, and restart — the heartbeat supervisor's discipline. A liveness
/// detector that can silently vanish would be its own bug class.
pub fn spawn_crl_liveness_sweeper(
    state: std::sync::Arc<crate::hub::state::HubState>,
    tasks: &TaskTracker,
    shutdown: CancellationToken,
) {
    tasks.spawn(async move {
        // Register at spawn: the row (and its first-sighting bump) exists
        // before the hub answers anything.
        state.watchdog.register(
            "crl_face_sweep",
            CRL_FACE_SWEEP_INTERVAL.as_secs(),
            u64::try_from(interflow_identity::expiry::now_unix()).unwrap_or(0),
        );
        loop {
            let inner = tokio::spawn(run_crl_liveness_sweeper(state.clone(), shutdown.clone()));
            match inner.await {
                Ok(()) => break,
                Err(e) => {
                    metrics::counter!("interflow_hub_crl_face_sweeper_restarts").increment(1);
                    tracing::error!(
                        "CRL-liveness sweeper exited abnormally ({e}), restarting after \
                         {CRL_FACE_SWEEP_INTERVAL:?}"
                    );
                    tokio::select! {
                        () = shutdown.cancelled() => break,
                        () = tokio::time::sleep(CRL_FACE_SWEEP_INTERVAL) => {}
                    }
                }
            }
        }
    });
}

/// The sweep loop: every interval, re-classify recency. Steady state bumps
/// nothing; a fresh→silent crossing bumps exactly once.
async fn run_crl_liveness_sweeper(
    state: std::sync::Arc<crate::hub::state::HubState>,
    shutdown: CancellationToken,
) {
    loop {
        tokio::select! {
            () = shutdown.cancelled() => break,
            () = tokio::time::sleep(CRL_FACE_SWEEP_INTERVAL) => {}
        }
        state.watchdog.tick(
            "crl_face_sweep",
            CRL_FACE_SWEEP_INTERVAL.as_secs(),
            u64::try_from(interflow_identity::expiry::now_unix()).unwrap_or(0),
        );
        state
            .crl_liveness
            .sweep(u64::try_from(interflow_identity::expiry::now_unix()).unwrap_or(0));
    }
}

impl crate::hub::service::HubService {
    /// `POST /crls/liveness` — one node's CRL-poll liveness level. Same
    /// standing as the target-recovery notice: the requester is the
    /// connection's identity AND must be a registered agent; the report
    /// lands under that identity only (never a body-supplied name). The
    /// body is the JSON [`CrlLivenessReport`]; the answer is a bare ack —
    /// landing is the confirmation.
    pub(crate) async fn handle_crl_liveness(
        &self,
        req: hyper::Request<hyper::body::Incoming>,
    ) -> interflow_core::error::Result<hyper::Response<crate::hub::state::HubResponseBody>> {
        use http_body_util::BodyExt as _;
        use hyper::StatusCode;
        let Some(identity) = self.identity().await else {
            return Ok(crate::hub::service::text_response(
                StatusCode::UNAUTHORIZED,
                "Client certificate required",
            ));
        };
        if identity.tenant.as_ref() == crate::hub::state::CONTROL_TENANT {
            return Ok(crate::hub::service::text_response(
                StatusCode::FORBIDDEN,
                "control principals do not report CRL liveness",
            ));
        }
        let agent = crate::hub::qualified_agent_id(&identity.tenant, &identity.agent);
        {
            let agents = self.state.agents.read().await;
            if !agents.contains_key(&agent) {
                return Ok(crate::hub::service::json_response(
                    StatusCode::FORBIDDEN,
                    serde_json::json!({
                        "ok": false,
                        "reason": format!("{agent} is not a registered agent")
                    })
                    .to_string(),
                ));
            }
        }
        let collected = http_body_util::Limited::new(req.into_body(), 64 * 1024)
            .collect()
            .await
            .map_err(|e| {
                interflow_core::error::InterflowError::protocol(
                    "CRL-liveness report read failed (or exceeds 64 KiB)".to_string(),
                )
                .with_source(e)
            })?;
        let report: CrlLivenessReport =
            serde_json::from_slice(&collected.to_bytes()).map_err(|e| {
                interflow_core::error::InterflowError::protocol(
                    "CRL-liveness report is malformed".to_string(),
                )
                .with_source(e)
            })?;
        record_via_state(&self.state, &agent, &report);
        Ok(crate::hub::service::json_response(
            StatusCode::OK,
            serde_json::json!({ "ok": true }).to_string(),
        ))
    }
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
    use interflow_core::tunnel::transport::CrlLivenessReport;

    fn table() -> (CrlLiveness, crate::hub::floor_clock::FloorClock) {
        let clock = crate::hub::floor_clock::FloorClock::new();
        (CrlLiveness::new(clock.clone()), clock)
    }

    fn report(last_success_unix: u64, failures_total: u64) -> CrlLivenessReport {
        CrlLivenessReport {
            last_success_unix,
            failures_total,
            renewal_backoff_failures: None,
        }
    }

    #[test]
    fn bump_discipline_first_sighting_steady_and_failures() {
        let (table, clock) = table();
        table.record("site/a", &report(1_000, 0), 1_002);
        assert_eq!(clock.version(), 1, "first sighting is face-visible");
        // Steady re-report of an advanced level: recency moves inside the
        // fresh class, the clock must not.
        table.record("site/a", &report(1_060, 0), 1_062);
        assert_eq!(clock.version(), 1);
        // The failure counter ticking during an outage is diagnostic
        // material, not a trigger.
        table.record("site/a", &report(1_060, 3), 1_062);
        assert_eq!(clock.version(), 1);
        let face = table.face();
        let row = face.get("site/a").unwrap();
        assert_eq!(row.last_success_unix, 1_060);
        assert_eq!(row.failures_total, 3);
    }

    #[test]
    fn recency_is_the_levels_instant_not_the_arrival() {
        let (table, clock) = table();
        // A hung loop (frozen at 1_000) whose healthy reporter keeps
        // delivering at now=1_400: the row must read by the LEVEL's age,
        // not stay fresh by arrival.
        table.record("site/a", &report(1_000, 0), 1_002);
        table.record("site/a", &report(1_000, 9), 1_400);
        assert_eq!(
            table.sweep(1_400),
            1,
            "the frozen level crosses the silent threshold"
        );
        assert_eq!(clock.version(), 2, "the crossing is push-visible");
        // The next report of the still-frozen level does not revive.
        table.record("site/a", &report(1_000, 10), 1_500);
        assert_eq!(clock.version(), 2);
    }

    #[test]
    fn sweep_marks_silent_once_revival_bumps_and_stays_quiet() {
        let (table, clock) = table();
        table.record("site/a", &report(1_000, 0), 1_000);
        table.record("site/b", &report(1_002, 0), 1_002);
        assert_eq!(clock.version(), 2);
        // Both cross in the same sweep (the anchor is past the YOUNGER
        // row's threshold too): one version advance per batch.
        assert_eq!(table.sweep(1_002 + CRL_SILENT_AFTER_SECS + 1), 2);
        assert_eq!(clock.version(), 3);
        // Staying silent is not news again.
        assert_eq!(table.sweep(1_700), 0);
        assert_eq!(clock.version(), 3);
        // Revival: a fresh level arriving on a silent row.
        table.record("site/a", &report(1_710, 0), 1_712);
        assert_eq!(clock.version(), 4);
        assert_eq!(table.sweep(1_715), 0);
    }

    #[test]
    fn self_slot_classifies_and_bumps_like_a_row() {
        let (table, clock) = table();
        table.record_self(&report(1_000, 0), 1_000);
        assert_eq!(clock.version(), 1);
        assert_eq!(
            table.self_face().map(|row| row.last_success_unix),
            Some(1_000)
        );
        assert_eq!(table.sweep(1_000 + CRL_SILENT_AFTER_SECS + 1), 1);
        assert_eq!(clock.version(), 2);
        table.record_self(&report(2_000, 0), 2_002);
        assert_eq!(clock.version(), 3, "revival of the self slot bumps");
    }

    #[test]
    fn first_sighting_of_an_already_silent_level_never_reads_fresh() {
        let (table, _clock) = table();
        // A node whose last poll predates its first report to this hub
        // (hub restart, long outage): the row is born silent, and the
        // sweep must not fire a second transition for it.
        table.record("site/a", &report(100, 0), 1_000);
        assert_eq!(table.sweep(1_001), 0, "born silent — no crossing");
    }
}
