//! The hub's node-status table — the fleet faces' carrier for the
//! engine-level levels only the node itself can observe
//!
//! One report channel (`POST /node/status` on h2, the NodeStatus frame
//! pair on QUIC), one table: each agent's LATEST report, stored verbatim
//! under the reporting identity. The report is the LEVEL, not a
//! heartbeat (the CRL-liveness doctrine): the reporter reads the
//! engine's shared state at send time, so a wedged engine keeps
//! producing reports whose levels stay frozen — consumers judge the
//! levels' own instants (e.g. `last_byte_unix` against their capture
//! anchor), never the report's arrival time. Recency of the whole report
//! matters only for staleness degradation (a row whose report stopped
//! arriving reads unknown, never stale-current), carried by
//! `reported_unix`.
//!
//! Bump discipline (see `hub::floor_clock`): a row's first sighting, a
//! stream-set membership change, or a fossil-class crossing (a stream
//! entering/leaving the fossil band against the single-source
//! thresholds) — a steady re-report of the same shape with drifting
//! instants bumps NOTHING (a clock that ticks every report interval
//! would degenerate the floor watch into polling). Rows never leave: an
//! offline agent keeps its last report (the ledger-only remembrance
//! shape — the fossil question matters most exactly while the node is
//! down).

use std::collections::{BTreeMap, HashMap};
use std::sync::Mutex;

use interflow_core::tunnel::transport::NodeStatusReport;
use tokio_util::sync::CancellationToken;
use tokio_util::task::TaskTracker;

use crate::agent::stream_activity::{
    FOSSIL_IDLE_MULTIPLE, FOSSIL_UNBUDGETED_DAYS_SECS, fossil_after_secs,
};

/// One agent's stored report (the levels plus the arrival instant for
/// staleness degradation).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NodeStatusRow {
    /// The report's stream-activity levels, name-sorted.
    pub streams: Vec<interflow_core::tunnel::transport::NodeStreamActivity>,
    /// The report's connection-quality window stats (the supervisor
    /// domain's levels). `None` on older agents.
    pub connection: Option<interflow_core::tunnel::transport::ConnectionQualityWire>,
    /// Unix seconds the report landed (arrival, NOT truth — used only to
    /// degrade a row whose reports stopped).
    pub reported_unix: u64,
}

/// Whether one stream's activity level reads fossil.
///
/// The pure judgment shared by the bump discipline (the band crossing
/// drives the clock) and every consumer (doctor, the GUI). `now_unix`
/// is the READER's capture instant.
pub const fn stream_is_fossil(
    last_byte_unix: u64,
    idle_budget_secs: Option<u32>,
    now_unix: u64,
) -> bool {
    let age = now_unix.saturating_sub(last_byte_unix);
    match idle_budget_secs {
        Some(budget) => age > fossil_after_secs(budget, FOSSIL_IDLE_MULTIPLE),
        None => age > FOSSIL_UNBUDGETED_DAYS_SECS,
    }
}

/// Internal row state (the fossil band membership is bookkeeping for the
/// bump discipline — one bump per crossing).
#[derive(Debug)]
struct Row {
    face: NodeStatusRow,
    /// Which streams were in the fossil band at the last observation
    /// (name set) — membership change bumps.
    fossil_set: std::collections::BTreeSet<String>,
    /// The stream names at the last observation — membership change bumps.
    stream_set: std::collections::BTreeSet<String>,
}

/// The shared table (in-memory by design — after a hub restart every
/// online agent's next report re-populates its row within one reporter
/// interval; the first-sighting bump makes the refill push-visible).
pub struct NodeStatus {
    inner: Mutex<HashMap<String, Row>>,
    floor: crate::hub::floor_clock::FloorClock,
}

impl NodeStatus {
    pub fn new(floor: crate::hub::floor_clock::FloorClock) -> Self {
        Self {
            inner: Mutex::new(HashMap::new()),
            floor,
        }
    }

    /// Records one agent report. `now_unix` is the HUB's clock at arrival
    /// (the staleness-degradation anchor only).
    pub fn record(&self, agent: &str, report: &NodeStatusReport, now_unix: u64) {
        let face = NodeStatusRow {
            streams: report.streams.clone(),
            connection: report.connection,
            reported_unix: now_unix,
        };
        let mut inner = self
            .inner
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let stream_set: std::collections::BTreeSet<String> =
            report.streams.iter().map(|s| s.name.clone()).collect();
        let fossil_set: std::collections::BTreeSet<String> = report
            .streams
            .iter()
            .filter(|s| stream_is_fossil(s.last_byte_unix, s.idle_budget_secs, now_unix))
            .map(|s| s.name.clone())
            .collect();
        // The connection section's COUNTABLE transitions bump (the
        // reconnect rate and the timeout count are the face's verdict
        // drivers); percentile drift inside a window does not — the same
        // steady-state discipline as every sibling face.
        let connection_class = |report: &NodeStatusReport| -> Option<(u32, u32)> {
            report
                .connection
                .map(|c| (c.reconnects_last_hour, c.rtt_timeouts))
        };
        let face_changed = if let Some(row) = inner.get_mut(agent) {
            let moved = row.stream_set != stream_set
                || row.fossil_set != fossil_set
                || connection_class_changed(row, report, connection_class);
            row.face = face;
            row.stream_set = stream_set;
            row.fossil_set = fossil_set;
            moved
        } else {
            inner.insert(
                agent.to_owned(),
                Row {
                    face,
                    fossil_set,
                    stream_set,
                },
            );
            true
        };
        drop(inner);
        if face_changed {
            self.floor.bump();
        }
    }

    /// The face: every agent that ever reported, in deterministic order.
    pub fn face(&self) -> BTreeMap<String, NodeStatusRow> {
        let inner = self
            .inner
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        inner
            .iter()
            .map(|(k, row)| (k.clone(), row.face.clone()))
            .collect()
    }
}

/// Whether the connection section's countable class moved between the
/// stored row and the incoming report (first connection section
/// included — an upgrading agent's levels appear push-visible).
fn connection_class_changed(
    row: &Row,
    report: &NodeStatusReport,
    class: impl Fn(&NodeStatusReport) -> Option<(u32, u32)>,
) -> bool {
    let old = row
        .face
        .connection
        .map(|c| (c.reconnects_last_hour, c.rtt_timeouts));
    let new = class(report);
    old != new
}

/// One report landed over either transport face. The single entry the h2
/// handler and the QUIC dispatch arm call — the identity/registration
/// gate is the callers' (same standing as the CRL-liveness report);
/// this fn is the recording half only.
pub(crate) fn record_via_state(
    state: &crate::hub::state::HubState,
    agent: &str,
    report: &NodeStatusReport,
) {
    state.node_status.record(
        agent,
        report,
        u64::try_from(interflow_identity::expiry::now_unix()).unwrap_or(0),
    );
}

impl crate::hub::service::HubService {
    /// `POST /node/status` — one node's engine-level status report. Same
    /// standing as the CRL-liveness report: the requester is the
    /// connection's identity AND must be a registered agent; the report
    /// lands under that identity only (never a body-supplied name). The
    /// body is the JSON [`NodeStatusReport`]; the answer is a bare ack —
    /// landing is the confirmation.
    pub(crate) async fn handle_node_status(
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
                "control principals do not report node status",
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
                    "node-status report read failed (or exceeds 64 KiB)".to_string(),
                )
                .with_source(e)
            })?;
        let report: NodeStatusReport =
            serde_json::from_slice(&collected.to_bytes()).map_err(|e| {
                interflow_core::error::InterflowError::protocol(
                    "node-status report is malformed".to_string(),
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

/// Managed entry point of the staleness sweeper placeholder — none yet:
/// the table's rows degrade by `reported_unix` at READ time (a consumer
/// compares it against its own capture anchor), so no sweep task is
/// owed. Kept as documentation of the deliberate asymmetry with the
/// recency-class faces (policy/CRL/watchdog sweep because their silence
/// must reach the PUSH contract; the fossil face's band crossings are
/// report-driven and already bump).
#[allow(dead_code)]
fn no_sweeper_by_design(_tasks: &TaskTracker, _shutdown: CancellationToken) {}

#[cfg(test)]
#[allow(
    clippy::panic,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::missing_docs_in_private_items
)]
mod tests {
    use super::*;
    use interflow_core::tunnel::transport::NodeStreamActivity;

    fn table() -> (NodeStatus, crate::hub::floor_clock::FloorClock) {
        let clock = crate::hub::floor_clock::FloorClock::new();
        (NodeStatus::new(clock.clone()), clock)
    }

    fn activity(name: &str, byte_age: u64, budget: Option<u32>) -> NodeStreamActivity {
        NodeStreamActivity {
            name: name.to_owned(),
            last_byte_unix: 100_000 - byte_age,
            idle_budget_secs: budget,
        }
    }

    fn report(streams: Vec<NodeStreamActivity>) -> NodeStatusReport {
        NodeStatusReport {
            connection: None,
            streams,
        }
    }

    #[test]
    fn bump_discipline_first_sighting_membership_and_band() {
        let (table, clock) = table();
        table.record(
            "site/a",
            &report(vec![activity("svc", 10, Some(300))]),
            100_000,
        );
        assert_eq!(clock.version(), 1, "first sighting is face-visible");
        // Steady re-report: same membership, instants drifting inside the
        // fresh band — the clock must not tick.
        table.record(
            "site/a",
            &report(vec![activity("svc", 15, Some(300))]),
            100_020,
        );
        assert_eq!(clock.version(), 1);
        // A stream appears: membership change.
        table.record(
            "site/a",
            &report(vec![activity("svc", 5, Some(300)), activity("db", 0, None)]),
            100_030,
        );
        assert_eq!(clock.version(), 2);
        // A stream disappears: membership change.
        table.record(
            "site/a",
            &report(vec![activity("svc", 5, Some(300))]),
            100_040,
        );
        assert_eq!(clock.version(), 3);
    }

    #[test]
    fn fossil_band_crossing_bumps_once_per_direction() {
        let (table, clock) = table();
        // A 300s-budget stream goes fossil past 10×300 = 3000s of quiet.
        // Every record anchors at the same `now` (the byte_age alone
        // decides the class; arrival instants only ride `reported_unix`).
        let now = 100_000u64;
        table.record(
            "site/a",
            &report(vec![activity("svc", 2_900, Some(300))]),
            now,
        );
        assert_eq!(clock.version(), 1);
        // Still inside the band: no crossing.
        table.record(
            "site/a",
            &report(vec![activity("svc", 2_990, Some(300))]),
            now,
        );
        assert_eq!(clock.version(), 1);
        // Past the band: the crossing bumps.
        table.record(
            "site/a",
            &report(vec![activity("svc", 3_010, Some(300))]),
            now,
        );
        assert_eq!(clock.version(), 2);
        // Deeper into the band: not news again.
        table.record(
            "site/a",
            &report(vec![activity("svc", 3_500, Some(300))]),
            now,
        );
        assert_eq!(clock.version(), 2);
        // Traffic resumes: the re-fresh crossing bumps.
        table.record("site/a", &report(vec![activity("svc", 0, Some(300))]), now);
        assert_eq!(clock.version(), 3);
    }

    #[test]
    fn the_row_keeps_its_last_report_when_the_node_goes_silent() {
        let (table, _clock) = table();
        table.record("site/a", &report(vec![activity("svc", 0, None)]), 100_000);
        // No further reports: the face keeps the last levels (the fossil
        // question matters most exactly while the node is down).
        let face = table.face();
        let row = face.get("site/a").unwrap();
        assert_eq!(row.streams.len(), 1);
        assert_eq!(row.reported_unix, 100_000);
    }
}
