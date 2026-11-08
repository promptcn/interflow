//! The hub's stream-intent face: the operator's pause/resume mailbox and
//! the fleet-observability face of every agent's paused streams
//!
//! Two halves, one table:
//!
//! - **The mailbox** (`enqueue`): operator-issued pause/resume ops, queued
//!   per agent and delivered by the agent's intent watcher on its next
//!   exchange. Deliberately NOT persisted: the pause intent's truth lives
//!   on the node (`<pack>/state/paused_streams.json` — kept across
//!   restarts, absent from a fresh install), and a durable hub-side
//!   desired-set would outlive the declaring node instance and quietly
//!   re-impose stale intent on a re-provisioned one. A hub restart that
//!   loses an undelivered op is self-revealing — the face shows the
//!   stream unpaused and the operator re-issues (the same
//!   deliberately-in-memory discipline as the state-transfer ledgers).
//!
//!   The mailbox is itself floor-visible since 2026-10-20
//!  : an op
//!   queued for an offline leg can sit for days, and "something is
//!   waiting, for how long, was anything dropped" is exactly the level a
//!   read face owes. Enqueue bumps (a rare operator verb); an exchange
//!   that retires ops bumps; the steady-state re-report of the same set
//!   still does not.
//!
//! - **The face** (`exchange`/`face`): what each agent REPORTS its pause
//!   set to be. This is the source the snapshot/doctor/GUI read — the
//!   reported actual state, not the operator's desire — so a hub restart
//!   self-heals within one watch interval as agents re-report. An offline
//!   agent keeps its last report (the ledger-only remembrance shape: the
//!   paused state matters most exactly while the node is down).
//!
//! Ack discipline: an op delivered in one exchange is removed when the
//! NEXT report arrives (the agent applies what it receives before
//! reporting again — its watcher loop guarantees that order by
//! construction). No sequence numbers, no durable ack: ops are idempotent
//! set add/remove on the node.

use std::collections::{BTreeSet, HashMap, VecDeque};
use std::sync::Mutex;

use interflow_core::error::{InterflowError, Result};
use interflow_core::tunnel::transport::{StreamIntentOp, StreamIntentOps, StreamIntentReport};
use serde::{Deserialize, Serialize};
use tracing::warn;

/// Per-agent pending/actual state.
#[derive(Default)]
struct AgentIntents {
    pending: VecDeque<PendingOp>,
    actual: BTreeSet<String>,
    /// Unix seconds of the last report; 0 = never (the face stays absent
    /// until the agent has spoken once).
    last_report_unix: u64,
    /// Ops dropped by the capacity guard (the oldest undelivered one per
    /// overflow) — cumulative for this hub process. The re-issue decision
    /// ("did the hub throw my op away?") reads this, not the journal.
    dropped_total: u64,
}

/// One queued op with its delivery state.
struct PendingOp {
    op: StreamIntentOp,
    /// Delivered in a previous exchange; removed when the next report
    /// arrives (the report reflects its application).
    delivered: bool,
    /// Unix seconds of the enqueue — the mailbox watermark's age anchor.
    queued_at_unix: u64,
}

/// Upper bound on pending ops per agent. Operator verbs are rare and
/// idempotent; a bound exists so a runaway script cannot grow the table
/// unbounded — the OLDEST undelivered op is dropped with a warn.
const MAX_PENDING_OPS: usize = 128;

/// The shared registry (in-memory by design — see the module docs).
#[derive(Default)]
pub struct StreamIntents {
    inner: Mutex<HashMap<String, AgentIntents>>,
    /// The floor version clock: bumped when an agent's REPORTED face
    /// changes, and — since the mailbox became floor-visible (2026-10-20)
    /// — when the mailbox's shape moves too (an op queued, ops retired).
    /// The steady-state exchange every watch interval re-reports the same
    /// set with the same mailbox and must not tick the clock.
    floor: crate::hub::floor_clock::FloorClock,
}

/// One queued op rendered for the wire (`"pause ollama"` style).
fn op_label(op: &StreamIntentOp) -> String {
    match op {
        StreamIntentOp::Pause { name } => format!("pause {name}"),
        StreamIntentOp::Resume { name } => format!("resume {name}"),
    }
}

/// The mailbox watermark face for one agent.
///
/// What is waiting, since when, and whether the capacity guard ever
/// dropped an op.
/// Ages are consumer-side (judged against the reader's capture anchor) —
/// the face carries the raw instants.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MailboxFace {
    /// Ops occupying the mailbox (undelivered AND delivered-unacked — an
    /// unconfirmed op is still the operator's open loop).
    pub pending_count: u32,
    /// Unix seconds of the oldest queued op (`None` only when the mailbox
    /// is empty and only drops remain to report).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub oldest_queued_unix: Option<u64>,
    /// The oldest op, rendered (`"pause ollama"`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub oldest_op: Option<String>,
    /// Ops dropped by the capacity guard, cumulative for this hub
    /// process. Dropped is dropped: the re-issue decision reads this
    /// counter, not the journal warn.
    pub dropped_total: u64,
}

impl StreamIntents {
    pub fn new(floor: crate::hub::floor_clock::FloorClock) -> Self {
        Self {
            floor,
            ..Self::default()
        }
    }

    /// Queues one operator op for `agent`. Idempotent at the application
    /// layer (the node's set ops are); returns whether the op was queued.
    /// The mailbox is floor-visible: an operator verb is rare, and the
    /// face's "something is now waiting" reading is push-worthy.
    pub fn enqueue(&self, agent: &str, op: StreamIntentOp) -> bool {
        let now = u64::try_from(interflow_identity::expiry::now_unix()).unwrap_or(0);
        let mut inner = self
            .inner
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let entry = inner.entry(agent.to_string()).or_default();
        if entry.pending.len() >= MAX_PENDING_OPS
            && let Some(dropped) = entry.pending.pop_front()
        {
            entry.dropped_total += 1;
            warn!(
                agent,
                op = ?dropped.op,
                "stream-intent mailbox at capacity ({MAX_PENDING_OPS}); dropping the oldest undelivered op"
            );
        }
        entry.pending.push_back(PendingOp {
            op,
            delivered: false,
            queued_at_unix: now,
        });
        drop(inner);
        self.floor.bump();
        true
    }

    /// One agent exchange: record the report (the face), retire delivered
    /// ops (this report reflects their application), and hand out the
    /// undelivered rest. The clock bumps when the REPORTED face moved
    /// (first report or a changed paused set) OR the mailbox's shape
    /// moved (ops retired) — the steady-state exchange every watch
    /// interval re-reports the same set with the same mailbox and must
    /// not tick the clock (a clock that ticks every interval turns the
    /// floor watch into polling).
    pub fn exchange(&self, agent: &str, report: &StreamIntentReport) -> StreamIntentOps {
        let mut inner = self
            .inner
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let entry = inner.entry(agent.to_string()).or_default();
        let reported: BTreeSet<String> = report.paused.iter().cloned().collect();
        let face_changed = entry.last_report_unix == 0 || entry.actual != reported;
        entry.actual = reported;
        entry.last_report_unix = u64::try_from(interflow_identity::expiry::now_unix()).unwrap_or(0);
        let mailbox_before = entry.pending.len();
        entry.pending.retain(|pending| !pending.delivered);
        let ops = entry
            .pending
            .iter()
            .map(|pending| pending.op.clone())
            .collect::<Vec<_>>();
        for pending in &mut entry.pending {
            pending.delivered = true;
        }
        let mailbox_changed = entry.pending.len() != mailbox_before;
        drop(inner);
        if face_changed || mailbox_changed {
            self.floor.bump();
        }
        StreamIntentOps { ops }
    }

    /// The face: the agent's last reported paused set. `None` until the
    /// agent has reported once (an honest absence, not an empty pause).
    pub fn face(&self, agent: &str) -> Option<Vec<String>> {
        let inner = self
            .inner
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        inner
            .get(agent)
            .filter(|entry| entry.last_report_unix > 0)
            .map(|entry| entry.actual.iter().cloned().collect())
    }

    /// The mailbox watermark face: `None` when the agent has neither
    /// waiting ops nor a drop on record (the honest clean reading, not a
    /// zero-shaped block).
    pub fn mailbox_face(&self, agent: &str) -> Option<MailboxFace> {
        let inner = self
            .inner
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let entry = inner.get(agent)?;
        if entry.pending.is_empty() && entry.dropped_total == 0 {
            return None;
        }
        let oldest = entry.pending.front();
        Some(MailboxFace {
            pending_count: u32::try_from(entry.pending.len()).unwrap_or(u32::MAX),
            oldest_queued_unix: oldest.map(|op| op.queued_at_unix),
            oldest_op: oldest.map(|op| op_label(&op.op)),
            dropped_total: entry.dropped_total,
        })
    }

    /// Whether any op is still in the mailbox for `agent` — delivered but
    /// unacked included (the CLI's queued-vs-applied answer: the FACE
    /// decides "applied", the mailbox decides "still in flight").
    pub fn has_pending(&self, agent: &str) -> bool {
        let inner = self
            .inner
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        inner
            .get(agent)
            .is_some_and(|entry| !entry.pending.is_empty())
    }
}

/// The QUIC arm's exchange (the session IS the registered agent — its
/// qualified key is the reporter; the face and mailbox land under that
/// identity only).
pub(crate) fn exchange_via_state(
    state: &crate::hub::state::HubState,
    agent: &str,
    report: &StreamIntentReport,
) -> StreamIntentOps {
    state.stream_intents.exchange(agent, report)
}

impl crate::hub::service::HubService {
    /// `POST /streams/intent` — an agent's periodic exchange: report in,
    /// pending ops out. The requester is the connection's identity AND
    /// must be a registered agent (the same standing the proposals
    /// submission requires); the report lands under that identity only,
    /// never under a body-supplied name.
    pub(crate) async fn handle_stream_intent_exchange(
        &self,
        req: hyper::Request<hyper::body::Incoming>,
    ) -> Result<hyper::Response<crate::hub::state::HubResponseBody>> {
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
                "control principals do not exchange stream intents",
            ));
        }
        let agent = crate::hub::qualified_agent_id(&identity.tenant, &identity.agent);
        {
            let agents = self.state.agents.read().await;
            if !agents.contains_key(&agent) {
                return Ok(crate::hub::service::json_response(
                    StatusCode::FORBIDDEN,
                    serde_json::json!({ "ok": false, "reason": format!("{agent} is not a registered agent") }).to_string(),
                ));
            }
        }
        let collected = http_body_util::Limited::new(req.into_body(), 64 * 1024)
            .collect()
            .await
            .map_err(|e| {
                InterflowError::protocol(
                    "stream-intent report read failed (or exceeds 64 KiB)".to_string(),
                )
                .with_source(e)
            })?;
        let report: StreamIntentReport =
            serde_json::from_slice(&collected.to_bytes()).map_err(|e| {
                InterflowError::protocol("stream-intent report is malformed".to_string())
                    .with_source(e)
            })?;
        let ops = self.state.stream_intents.exchange(&agent, &report);
        Ok(crate::hub::service::json_response(
            StatusCode::OK,
            serde_json::to_string(&ops)?,
        ))
    }

    /// The operator's pause/resume pair: queue one op for the named agent
    /// (control-principal gated) and answer with the current face —
    /// already-applied detection for the CLI's idempotent wording.
    pub(crate) async fn handle_stream_op(
        &self,
        req: hyper::Request<hyper::body::Incoming>,
        agent: &str,
        pause: bool,
    ) -> Result<hyper::Response<crate::hub::state::HubResponseBody>> {
        use http_body_util::BodyExt as _;
        use hyper::StatusCode;
        if let Err(reason) = self
            .require_control(if pause {
                "pause a stream"
            } else {
                "resume a stream"
            })
            .await
        {
            return Ok(crate::hub::service::json_response(
                StatusCode::FORBIDDEN,
                serde_json::json!({ "ok": false, "reason": reason }).to_string(),
            ));
        }
        let collected = http_body_util::Limited::new(req.into_body(), 16 * 1024)
            .collect()
            .await
            .map_err(|e| {
                InterflowError::protocol("stream-intent op body read failed".to_string())
                    .with_source(e)
            })?;
        let body: serde_json::Value =
            serde_json::from_slice(&collected.to_bytes()).map_err(|e| {
                InterflowError::protocol("stream-intent op body is not JSON".to_string())
                    .with_source(e)
            })?;
        let Some(name) = body.get("name").and_then(|v| v.as_str()) else {
            return Ok(crate::hub::service::text_response(
                StatusCode::BAD_REQUEST,
                "body must be {\"name\": \"<stream>\"}",
            ));
        };
        let op = if pause {
            StreamIntentOp::Pause {
                name: name.to_string(),
            }
        } else {
            StreamIntentOp::Resume {
                name: name.to_string(),
            }
        };
        self.state.stream_intents.enqueue(agent, op);
        self.state.audit.record(
            if pause {
                interflow_core::security::audit::AuditKind::StreamPauseQueued {
                    agent: agent.to_string(),
                    stream: name.to_string(),
                }
            } else {
                interflow_core::security::audit::AuditKind::StreamResumeQueued {
                    agent: agent.to_string(),
                    stream: name.to_string(),
                }
            },
            Some("control".to_string()),
            None,
        );
        let answer = crate::hub::stream_intents::IntentQueued {
            paused_streams: self.state.stream_intents.face(agent),
            pending: self.state.stream_intents.has_pending(agent),
        };
        Ok(crate::hub::service::json_response(
            StatusCode::OK,
            serde_json::to_string(&answer)?,
        ))
    }
}

// ---------------------------------------------------------------------------
// Operator-side clients (the CLI and the GUI Deploy face drive these with
// a minted control credential — same dial discipline as the proposals
// clients).
// ---------------------------------------------------------------------------

/// The operator's answer for one pause/resume call: queued now, plus the
/// face as the hub currently knows it (already-applied detection).
#[derive(Debug, serde::Serialize, serde::Deserialize)]
pub struct IntentQueued {
    /// The agent's last reported paused set (`None` = never reported).
    #[serde(default)]
    pub paused_streams: Option<Vec<String>>,
    /// An undelivered op is waiting for the agent (it is offline or has
    /// not exchanged since).
    pub pending: bool,
}

/// Queues one op on the hub's control plane and returns the current face.
pub async fn queue_op(
    hub_endpoint: &str,
    ca_path: &std::path::Path,
    client_cert_path: &std::path::Path,
    client_key_path: &std::path::Path,
    agent: &str,
    op: &StreamIntentOp,
) -> Result<IntentQueued> {
    let path = match op {
        StreamIntentOp::Pause { .. } => format!("/streams/{agent}/pause"),
        StreamIntentOp::Resume { .. } => format!("/streams/{agent}/resume"),
    };
    let name = match op {
        StreamIntentOp::Pause { name } | StreamIntentOp::Resume { name } => name,
    };
    let body = serde_json::json!({ "name": name }).to_string();
    let future = async {
        use http_body_util::BodyExt as _;
        let mut send_request = crate::hub::policy::control_plane_dial(
            hub_endpoint,
            crate::hub::policy::ServerTrust::Ca(ca_path),
            client_cert_path,
            client_key_path,
        )
        .await?;
        let request = hyper::Request::builder()
            .method(hyper::Method::POST)
            .uri(path)
            .body(
                http_body_util::Full::<bytes::Bytes>::new(bytes::Bytes::from(body))
                    .map_err(|never| match never {})
                    .boxed(),
            )
            .map_err(|e| {
                InterflowError::protocol("stream-intent request build".to_string()).with_source(e)
            })?;
        let response = tokio::time::timeout(
            std::time::Duration::from_secs(10),
            send_request.send_request(request),
        )
        .await
        .map_err(|_| InterflowError::connection("stream-intent queue timed out"))??;
        let status = response.status();
        let collected = http_body_util::Limited::new(response.into_body(), 64 * 1024)
            .collect()
            .await
            .map_err(|e| {
                InterflowError::protocol("stream-intent response read failed".to_string())
                    .with_source(e)
            })?;
        let bytes = collected.to_bytes();
        if !status.is_success() {
            return Err(InterflowError::connection(format!(
                "stream-intent queue rejected: {status} — {}",
                String::from_utf8_lossy(&bytes)
            )));
        }
        serde_json::from_slice(&bytes).map_err(|e| {
            InterflowError::protocol("stream-intent answer is malformed".to_string()).with_source(e)
        })
    };
    tokio::time::timeout(std::time::Duration::from_secs(10), future)
        .await
        .map_err(|_| {
            InterflowError::connection(
                "stream-intent queue timed out (>10s) — is the mesh hub reachable?".to_string(),
            )
        })?
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

    fn pause(name: &str) -> StreamIntentOp {
        StreamIntentOp::Pause {
            name: name.to_string(),
        }
    }

    fn resume(name: &str) -> StreamIntentOp {
        StreamIntentOp::Resume {
            name: name.to_string(),
        }
    }

    fn report(names: &[&str]) -> StreamIntentReport {
        StreamIntentReport {
            paused: names.iter().map(std::string::ToString::to_string).collect(),
        }
    }

    fn intents() -> (StreamIntents, crate::hub::floor_clock::FloorClock) {
        let clock = crate::hub::floor_clock::FloorClock::new();
        (StreamIntents::new(clock.clone()), clock)
    }

    #[test]
    fn bump_discipline_face_moves_mailbox_moves_steady_does_not() {
        let (intents, clock) = intents();
        // The mailbox is floor-visible (2026-10-20): an operator verb is
        // rare and push-worthy.
        intents.enqueue("t/a", pause("s"));
        assert_eq!(clock.version(), 1, "an op queued is face-visible");
        intents.enqueue("t/a", pause("s2"));
        assert_eq!(clock.version(), 2);
        // First report: the face materializes (absent → present); the ops
        // deliver but stay in the mailbox (delivered-unacked) — one bump.
        intents.exchange("t/a", &report(&[]));
        assert_eq!(clock.version(), 3);
        // The next report retires the delivered ops (mailbox 2→0): the
        // shape moved, the bump fires even though the SET is steady.
        intents.exchange("t/a", &report(&[]));
        assert_eq!(clock.version(), 4);
        // Now truly steady — same set, empty mailbox: no bump.
        intents.exchange("t/a", &report(&[]));
        assert_eq!(clock.version(), 4);
        // The set changes: bump.
        intents.exchange("t/a", &report(&["s"]));
        assert_eq!(clock.version(), 5);
        intents.exchange("t/a", &report(&["s", "s2"]));
        assert_eq!(clock.version(), 6);
        // Steady again: quiet.
        intents.exchange("t/a", &report(&["s", "s2"]));
        assert_eq!(clock.version(), 6);
    }

    #[test]
    fn mailbox_face_reports_waiting_ops_oldest_age_and_drops() {
        let (intents, _clock) = intents();
        // Clean reads as an honest absence, not a zero-shaped block.
        intents.exchange("t/a", &report(&[]));
        assert_eq!(intents.mailbox_face("t/a"), None);
        // One op waiting: count + the queued instant + the label.
        intents.enqueue("t/a", pause("ollama"));
        let face = intents.mailbox_face("t/a").expect("one op waiting");
        assert_eq!(face.pending_count, 1);
        assert_eq!(face.oldest_op.as_deref(), Some("pause ollama"));
        assert!(face.oldest_queued_unix.is_some());
        assert_eq!(face.dropped_total, 0);
        // Delivery keeps the op in flight (unconfirmed application); the
        // next report retires it and the face reads clean again.
        intents.exchange("t/a", &report(&[]));
        assert_eq!(intents.mailbox_face("t/a").unwrap().pending_count, 1);
        intents.exchange("t/a", &report(&["ollama"]));
        assert_eq!(
            intents.mailbox_face("t/a"),
            None,
            "applied and reported — nothing waiting"
        );
    }

    #[test]
    fn mailbox_cap_drops_oldest_undelivered() {
        let (intents, _clock) = intents();
        for i in 0..MAX_PENDING_OPS {
            intents.enqueue("t/a", pause(&format!("s{i}")));
        }
        intents.enqueue("t/a", pause("overflow"));
        let face = intents.mailbox_face("t/a").expect("mailbox is full");
        assert_eq!(face.pending_count, u32::try_from(MAX_PENDING_OPS).unwrap());
        assert_eq!(face.dropped_total, 1, "the overflow dropped one op");
        assert_eq!(face.oldest_op.as_deref(), Some("pause s1"));
        // Dropped is dropped: the counter survives even after the queue
        // drains — the re-issue decision reads it.
        intents.exchange("t/a", &report(&[]));
        let ops = intents.exchange("t/a", &report(&[]));
        assert_eq!(ops.ops.len(), 0, "a drained mailbox hands out nothing");
        assert_eq!(
            intents.mailbox_face("t/a").map(|f| f.dropped_total),
            Some(1),
            "a drained mailbox with history keeps the drop counter"
        );
    }

    #[test]
    fn exchange_delivers_then_acks_on_next_report() {
        let (intents, _clock) = intents();
        intents.enqueue("t/a", pause("s"));
        // First exchange: report empty, op delivered.
        let ops = intents.exchange("t/a", &report(&[]));
        assert_eq!(ops.ops, vec![pause("s")]);
        assert!(intents.has_pending("t/a"));
        // Second exchange (agent applied the op before re-reporting): the
        // delivered op is retired, nothing further is delivered.
        let ops = intents.exchange("t/a", &report(&["s"]));
        assert_eq!(ops.ops, Vec::<StreamIntentOp>::new());
        assert!(!intents.has_pending("t/a"));
        assert_eq!(intents.face("t/a"), Some(vec!["s".to_string()]));
    }

    #[test]
    fn face_stays_absent_until_first_report() {
        let (intents, _clock) = intents();
        intents.enqueue("t/a", pause("s"));
        assert_eq!(intents.face("t/a"), None, "queued ≠ reported");
        intents.exchange("t/a", &report(&[]));
        assert_eq!(intents.face("t/a"), Some(Vec::<String>::new()));
    }

    #[test]
    fn local_changes_interleave_without_losing_pending_ops() {
        // The GUI's in-process pause bypasses the mailbox: the report shows
        // the stream paused while the queued op is still undelivered. The
        // op must still be delivered (the operator's explicit resume below
        // relies on ordering), never silently retired by the matching
        // report.
        let (intents, _clock) = intents();
        intents.enqueue("t/a", resume("s"));
        let ops = intents.exchange("t/a", &report(&["s"]));
        assert_eq!(
            ops.ops,
            vec![resume("s")],
            "the undelivered op still delivers"
        );
        // Applied and re-reported as resumed:
        let ops = intents.exchange("t/a", &report(&[]));
        assert_eq!(ops.ops, Vec::<StreamIntentOp>::new());
    }

    #[test]
    fn cap_delivery_hands_out_everything_the_queue_holds() {
        let (intents, _clock) = intents();
        for i in 0..MAX_PENDING_OPS {
            intents.enqueue("t/a", pause(&format!("s{i}")));
        }
        intents.enqueue("t/a", pause("overflow"));
        let ops = intents.exchange("t/a", &report(&[]));
        assert_eq!(ops.ops.len(), MAX_PENDING_OPS);
        assert_eq!(
            ops.ops.first(),
            Some(&pause("s1")),
            "s0 was dropped as the oldest"
        );
        assert_eq!(ops.ops.last(), Some(&pause("overflow")));
    }
}
