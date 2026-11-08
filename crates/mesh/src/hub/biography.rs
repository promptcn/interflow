//! `GET /audit/biography` — one agent's event biography, one query
//!
//! The events were always in `audit.jsonl`; the operator endpoint and
//! the cross-machine correlation were not — every incident timeline was
//! ssh + journalctl + manual timestamp alignment. This face turns the
//! ledger into a query: filter one leg's records (the qualified-id
//! fields directly, the circuit-keyed kinds through the agent's current
//! circuit), newest first, bounded by a `since` window.
//!
//! Additive-evolution honesty (see [`record_mentions_agent`]): records
//! older than the `agent` field's introduction link only through the
//! CURRENT circuit — a rotated-away circuit's pre-field history is not
//! silently attributed. `verify` remains the integrity command; this is
//! the read.

use std::path::PathBuf;

use interflow_core::security::audit::{
    AuditKind, audit_file_paths, read_audit_records, record_mentions_agent,
};

use crate::hub::state::HubResponseBody;
use http::{Response, StatusCode};
use interflow_core::error::{InterflowError, Result};
use serde::{Deserialize, Serialize};

/// One biography row, as the endpoint answers.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BiographyRow {
    /// ISO 8601 UTC timestamp.
    pub ts: String,
    /// The event kind (snake_case tag).
    pub kind: String,
    /// A human-readable one-line rendering (reasons expanded, contexts
    /// carried — the timeline reads without a legend).
    pub detail: String,
}

/// Renders one record's detail line — the reason/circuit/build
/// expansions the backlog asks for (the watcher-misfire and revoke
/// recovery chains read as stories, not kind tags).
pub fn describe(kind: &AuditKind) -> String {
    match kind {
        AuditKind::AgentRegistered {
            circuit,
            agent,
            build,
        } => format!(
            "registered (circuit {}…, agent {agent}, build {})",
            &circuit[..8.min(circuit.len())],
            build.as_deref().unwrap_or("unknown"),
        ),
        AuditKind::AgentEvicted {
            circuit,
            agent,
            reason,
        } => format!(
            "evicted (reason={reason}, circuit {}…, agent {agent}, evicted=true)",
            &circuit[..8.min(circuit.len())],
        ),
        AuditKind::AgentRegisterDenied { reason } => {
            format!("registration denied ({reason})")
        }
        AuditKind::PolicyPulled { generation, .. } => {
            format!("policy pulled (generation {generation})")
        }
        AuditKind::CredentialExpiry {
            phase,
            remaining_secs,
            ..
        } => format!("credential phase → {phase} ({remaining_secs}s remaining)"),
        AuditKind::StreamPauseQueued { stream, .. } => {
            format!("pause queued (stream {stream})")
        }
        AuditKind::StreamResumeQueued { stream, .. } => {
            format!("resume queued (stream {stream})")
        }
        AuditKind::MaintenanceDeclared { .. } => "maintenance declared".to_owned(),
        AuditKind::MaintenanceLifted { via, .. } => {
            format!("maintenance lifted (via {via})")
        }
        AuditKind::MaintenanceDeparture { reason, .. } => format!(
            "departed under maintenance (reason={reason}, maintenance_departed=true, evicted=false)"
        ),
        AuditKind::PolicyPublished { generation } => {
            format!("policy published (generation {generation})")
        }
        AuditKind::PolicyPublishDenied { reason } => {
            format!("policy publish denied ({reason})")
        }
        AuditKind::CrlPublished { applied, evicted } => format!(
            "CRLs applied ({:?}){}",
            applied,
            if evicted.is_empty() {
                String::new()
            } else {
                format!(", evicted {evicted:?}")
            }
        ),
        AuditKind::CrlPublishDenied { reason } => {
            format!("CRL publish denied ({reason})")
        }
        AuditKind::StreamOpened { stream_id, .. } => {
            format!("stream opened ({}…)", &stream_id[..8.min(stream_id.len())])
        }
        AuditKind::StreamClosed { stream_id, .. } => {
            format!("stream closed ({}…)", &stream_id[..8.min(stream_id.len())])
        }
        AuditKind::StreamDenied {
            stream_id, reason, ..
        } => format!(
            "stream denied ({}…, {reason})",
            &stream_id[..8.min(stream_id.len())]
        ),
        AuditKind::ConnLimitExceeded { .. } => "connection limit exceeded".to_owned(),
        AuditKind::RuleAdded { name, .. } => format!("stream rule added ({name})"),
        AuditKind::RuleRemoved { name, .. } => format!("stream rule removed ({name})"),
        AuditKind::ConfigReloaded => "config reloaded".to_owned(),
        AuditKind::ConfigReloadFailed { error } => {
            format!("config reload failed ({error})")
        }
        AuditKind::ProposalSubmitted {
            id,
            target_agent,
            remote_addr,
            ..
        } => format!("proposal submitted ({id} → {target_agent} at {remote_addr})"),
        AuditKind::ProposalSubmitDenied { reason, .. } => {
            format!("proposal denied ({reason})")
        }
        AuditKind::ProposalApproved { id, generation } => {
            format!("proposal approved ({id}, generation {generation})")
        }
        AuditKind::ProposalRejected { id, reason } => {
            format!("proposal rejected ({id}: {reason})")
        }
        AuditKind::ProposalExpired { id, .. } => format!("proposal expired ({id})"),
        AuditKind::ProposalQueueQuarantined { path, error, .. } => {
            format!("proposal queue quarantined ({path}: {error})")
        }
    }
}

/// Assembles the biography rows for `agent`, newest first.
///
/// Rows fall within the `since_secs` window. The audit directory and the
/// current circuit come from live hub state; pure so the
/// filtering/ordering is unit-testable without a hub.
pub fn assemble_biography(
    audit_dir: Option<&std::path::Path>,
    agent: &str,
    since_secs: u64,
    current_circuit: Option<&str>,
    now_unix: i64,
) -> Vec<BiographyRow> {
    let Some(dir) = audit_dir else {
        return Vec::new();
    };
    let paths: Vec<PathBuf> = audit_file_paths(dir);
    let since_iso_bound = now_unix - i64::try_from(since_secs).unwrap_or(i64::MAX);
    let mut rows: Vec<((String, u64), BiographyRow)> = read_audit_records(&paths)
        .into_iter()
        .filter(|record| {
            // Window bound on the parsed timestamp (RFC 3339 prefixes
            // sort lexically; a malformed ts stays included — the read
            // face degrades, never hides).
            let in_window = parse_iso_to_unix(&record.ts).is_none_or(|ts| ts >= since_iso_bound);
            in_window && record_mentions_agent(&record.kind, agent, current_circuit)
        })
        .map(|record| {
            let key = (record.ts.clone(), record.sequence);
            let row = BiographyRow {
                ts: record.ts,
                kind: kind_tag(&record.kind),
                detail: describe(&record.kind),
            };
            (key, row)
        })
        .collect();
    // Newest first: ISO 8601 UTC strings sort lexically; records written
    // within the same second (the ledger's resolution) order by the
    // chain's monotonic sequence, so the tie never falls back to file
    // order.
    rows.sort_by(|a, b| b.0.cmp(&a.0));
    rows.into_iter().map(|(_, row)| row).collect()
}

/// The serde tag of one kind (snake_case) — mirrored here because the
/// tag is derived by serde, not stored.
fn kind_tag(kind: &AuditKind) -> String {
    serde_json::to_value(kind)
        .ok()
        .and_then(|value| {
            value
                .get("kind")
                .and_then(serde_json::Value::as_str)
                .map(str::to_owned)
        })
        .unwrap_or_else(|| "unknown".to_owned())
}

/// Best-effort RFC 3339 → unix seconds (the audit timestamps' format).
/// `None` on anything unparseable (the caller keeps the row — a read
/// face degrades per record).
fn parse_iso_to_unix(ts: &str) -> Option<i64> {
    interflow_identity::expiry::parse_rfc3339_unix(ts).ok()
}

impl crate::hub::service::HubService {
    /// `GET /audit/biography?agent=<qualified>&since_secs=<n>` — one
    /// leg's event biography, newest first. Control-principal gated like
    /// every operator read.
    pub(crate) async fn handle_audit_biography(
        &self,
        req: hyper::Request<hyper::body::Incoming>,
    ) -> Result<Response<HubResponseBody>> {
        let Some(identity) = self.identity().await else {
            return Ok(super::service::text_response(
                StatusCode::UNAUTHORIZED,
                "Client certificate required",
            ));
        };
        if identity.tenant.as_ref() != crate::hub::state::CONTROL_TENANT {
            return Ok(super::service::text_response(
                StatusCode::FORBIDDEN,
                "biography query requires a control-plane principal (realm-anchored)",
            ));
        }
        let mut agent: Option<String> = None;
        let mut since_secs: Option<u64> = None;
        if let Some(query) = req.uri().query() {
            for pair in query.split('&') {
                let Some((key, value)) = pair.split_once('=') else {
                    continue;
                };
                match key {
                    "agent" => agent = Some(value.to_owned()),
                    "since_secs" => since_secs = value.parse().ok(),
                    _ => {}
                }
            }
        }
        let Some(agent) = agent else {
            return Ok(super::service::text_response(
                StatusCode::BAD_REQUEST,
                "query must carry ?agent=<qualified-id>",
            ));
        };
        let since_secs = since_secs.unwrap_or(48 * 3600);
        let audit_dir = self
            .state
            .config
            .read()
            .await
            .audit
            .path
            .as_ref()
            .and_then(|path| {
                std::path::Path::new(path)
                    .parent()
                    .map(std::path::Path::to_path_buf)
            });
        let current_circuit = {
            let registry = self.state.agents.read().await;
            match registry.get(&agent) {
                Some(session) => {
                    let st = session.read().await;
                    Some(st.circuit.to_hex())
                }
                None => None,
            }
        };
        let rows = assemble_biography(
            audit_dir.as_deref(),
            &agent,
            since_secs,
            current_circuit.as_deref(),
            interflow_identity::expiry::now_unix(),
        );
        let body = serde_json::json!({ "agent": agent, "rows": rows }).to_string();
        Ok(super::service::json_response(StatusCode::OK, body))
    }
}

// ---------------------------------------------------------------------------
// Operator-side client (the CLI's `doctor biography` dials this with a
// minted control credential — same discipline as the snapshot query).
// ---------------------------------------------------------------------------

/// The biography answer document.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BiographyDoc {
    /// The queried agent.
    pub agent: String,
    /// The rows, newest first.
    pub rows: Vec<BiographyRow>,
}

/// Queries one agent's event biography (`GET /audit/biography`).
///
/// Same credential discipline as [`crate::hub::snapshot::query_fleet_snapshot`];
/// one-shot, 10s-bounded.
pub async fn query_biography(
    hub_endpoint: &str,
    ca_path: &std::path::Path,
    client_cert_path: &std::path::Path,
    client_key_path: &std::path::Path,
    agent: &str,
    since_secs: u64,
) -> Result<BiographyDoc> {
    use http_body_util::BodyExt;

    let future = async {
        let mut send_request = crate::hub::policy::control_plane_dial(
            hub_endpoint,
            crate::hub::policy::ServerTrust::Ca(ca_path),
            client_cert_path,
            client_key_path,
        )
        .await?;
        let uri = format!("/audit/biography?agent={agent}&since_secs={since_secs}");
        let request = hyper::Request::builder()
            .method(hyper::Method::GET)
            .uri(uri)
            .body(
                http_body_util::Full::<bytes::Bytes>::new(bytes::Bytes::new())
                    .map_err(|never| match never {})
                    .boxed(),
            )
            .map_err(|e| {
                InterflowError::protocol("biography query build".to_string()).with_source(e)
            })?;
        let response = send_request.send_request(request).await?;
        let status = response.status();
        let collected = BodyExt::collect(response.into_body()).await.map_err(|e| {
            InterflowError::protocol("biography query body".to_string()).with_source(e)
        })?;
        let text = String::from_utf8_lossy(&collected.to_bytes()).to_string();
        if status == StatusCode::NOT_FOUND {
            return Err(InterflowError::connection(format!(
                "hub {hub_endpoint} does not carry the biography face — upgrade the hub"
            )));
        }
        if status != StatusCode::OK {
            return Err(InterflowError::connection(format!(
                "biography query rejected: {status} — {text}"
            )));
        }
        serde_json::from_str(&text).map_err(|e| {
            InterflowError::protocol(format!(
                "biography query 200 with an unparseable body: {e} — {text:?}"
            ))
        })
    };
    tokio::time::timeout(std::time::Duration::from_secs(10), future)
        .await
        .map_err(|_| {
            InterflowError::connection(
                "biography query timed out (>10s) — is the mesh hub reachable?",
            )
        })?
}

#[cfg(test)]
mod tests {
    use super::*;

    const TS: &str = "2026-10-20T00:00:00Z";

    fn record(sequence: u64, kind_json: &str) -> String {
        format!(
            r#"{{"source_id":"hub","sequence":{sequence},"ts":"{TS}",{kind_json},"previous_hash":"{}","record_hash":"{sequence}"}}"#,
            sequence - 1
        )
    }

    const DECLARED: &str = r#""kind":"maintenance_declared","agent":"ws/node""#;
    const PAUSED: &str = r#""kind":"stream_pause_queued","agent":"ws/node","stream":"svc""#;

    fn kinds(dir: &std::path::Path) -> Vec<String> {
        // `now` = the records' own instant (2026-10-20T00:00:00Z).
        assemble_biography(Some(dir), "ws/node", 48 * 3600, None, 1_792_454_400)
            .into_iter()
            .map(|row| row.kind)
            .collect()
    }

    /// Same-second records (the ledger's resolution) order by the chain
    /// sequence, newest first — never by the order they sit in the file.
    #[test]
    fn same_second_rows_order_by_sequence_not_file_order() {
        let dir = tempfile::tempdir().expect("tempdir");
        // Written in chain order: the later op (sequence 2) must lead.
        std::fs::write(
            dir.path().join("audit.jsonl"),
            format!("{}\n{}\n", record(1, DECLARED), record(2, PAUSED)),
        )
        .expect("ledger");
        assert_eq!(
            kinds(dir.path()),
            ["stream_pause_queued", "maintenance_declared"]
        );

        // The same two records in reverse file order: the answer is the same.
        std::fs::write(
            dir.path().join("audit.jsonl"),
            format!("{}\n{}\n", record(2, PAUSED), record(1, DECLARED)),
        )
        .expect("ledger");
        assert_eq!(
            kinds(dir.path()),
            ["stream_pause_queued", "maintenance_declared"]
        );
    }
}
