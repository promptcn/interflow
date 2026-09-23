//! Audit log: a structured JSONL writer, separated from ordinary logs for
//! easy SIEM ingestion.
//!
//! Event kinds are listed in [`AuditKind`]; write policy: line-buffered
//! append, a single writer thread, and multiple producers delivering via
//! mpsc. Failures only warn and never block the main path.

use crate::config::AuditConfig;
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::Mutex;
use std::time::SystemTime;
use tokio::fs::OpenOptions;
use tokio::io::AsyncWriteExt;
use tokio::sync::mpsc;
use tracing::warn;

/// Audit event kinds.
#[derive(Debug, Clone, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum AuditKind {
    /// Agent registered successfully.
    AgentRegistered {
        /// The opaque connection circuit.
        circuit: String,
    },
    /// Agent registration denied (wrong token, identity mismatch, etc.).
    AgentRegisterDenied {
        /// The denial reason.
        reason: String,
    },
    /// Agent evicted (poll grace expiry / heartbeat loss / data send timeout).
    AgentEvicted {
        /// The opaque connection circuit.
        circuit: String,
        /// The eviction reason (`send_timeout` / `poll_grace_expired` / `heartbeat_missed`).
        reason: String,
    },
    /// A stream was opened.
    StreamOpened {
        /// The opaque stream id.
        stream_id: String,
        /// The source circuit.
        source_circuit: String,
        /// The opaque route lease.
        route: String,
    },
    /// A stream was denied (ACL / anti-spoofing).
    StreamDenied {
        /// The opaque stream id.
        stream_id: String,
        /// The source circuit.
        source_circuit: String,
        /// Optional source IP. Only agent-side edge audits carry it; hub
        /// stream audits never couple a circuit to a network address.
        #[serde(rename = "source", skip_serializing_if = "Option::is_none")]
        source_ip: Option<String>,
        /// The denial reason.
        reason: String,
    },
    /// A stream was closed (normal completion or abnormal disconnect).
    StreamClosed {
        /// The opaque stream id.
        stream_id: String,
        /// The source circuit.
        source_circuit: String,
    },
    /// Connection denied (per-IP or global limit exceeded).
    ConnLimitExceeded {
        /// The peer IP.
        peer_ip: String,
        /// The limit category that fired: `per_ip` or `total`.
        scope: String,
    },
    /// Dynamic rule added (control API).
    RuleAdded {
        /// The rule category (ingress / egress).
        rule_kind: String,
        /// The rule name.
        name: String,
    },
    /// Dynamic rule removed.
    RuleRemoved {
        /// The rule category (ingress / egress).
        rule_kind: String,
        /// The rule name.
        name: String,
    },
    /// Config hot-reload succeeded.
    ConfigReloaded,
    /// Config hot-reload failed.
    ConfigReloadFailed {
        /// The error description.
        error: String,
    },
}

/// One audit record.
#[derive(Debug, Clone, Serialize)]
pub struct AuditEvent {
    /// Stable identifier for this audit source.
    pub source_id: String,
    /// Per-source monotonic sequence.
    pub sequence: u64,
    /// ISO 8601 UTC timestamp.
    pub ts: String,
    /// The event kind and details.
    #[serde(flatten)]
    pub kind: AuditKind,
    /// The initiating identity (authenticated agent_id); may be empty.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub actor: Option<String>,
    /// The peer TCP address.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub peer: Option<String>,
    /// Hex-encoded SHA-256 of the previous record.
    pub previous_hash: String,
    /// Hex-encoded SHA-256(prev_hash || canonical event bytes).
    pub record_hash: String,
}

#[derive(Debug, Default)]
struct AuditChainState {
    sequence: u64,
    previous_hash: [u8; 32],
}

/// Background audit sink. Clone-friendly (Arc inside).
#[derive(Clone)]
pub struct AuditSink {
    tx: Option<Arc<mpsc::Sender<AuditMsg>>>,
    source_id: String,
    chain: Arc<Mutex<AuditChainState>>,
}

/// Writer channel message: an audit event, or a flush receipt request (FIFO guarantees events before the receipt are on disk).
enum AuditMsg {
    Event(Box<AuditEvent>),
    Flush(tokio::sync::oneshot::Sender<()>),
}

impl AuditSink {
    /// Constructs a disabled sink (no-op). Corresponds to `[audit] enabled = false`.
    pub fn disabled() -> Self {
        // disabled() cannot generate a process-specific source ID in const fn;
        // it never emits, so fixed values are safe.
        Self {
            tx: None,
            source_id: String::new(),
            chain: Arc::new(Mutex::new(AuditChainState::default())),
        }
    }

    /// Spawns the audit writer background task and returns a sink for delivering events.
    ///
    /// - Creates the file if absent; appends if present.
    /// - The writer task runs independently; file write failures only warn
    ///   and do not abort.
    ///
    /// # Panics
    ///
    /// When `config.enabled` and a path is set, must be called from within a
    /// Tokio runtime context (it spawns the writer task); it panics
    /// otherwise.
    pub fn spawn(config: &AuditConfig) -> Self {
        if !config.enabled {
            return Self::disabled();
        }
        let Some(path) = config.path.clone() else {
            warn!("[audit] enabled = true but path is missing, audit disabled");
            return Self::disabled();
        };

        let (tx, mut rx) = mpsc::channel::<AuditMsg>(256);
        let tx = Arc::new(tx);
        let source_id = source_id();

        tokio::spawn(async move {
            writer_task(&PathBuf::from(path), &mut rx).await;
        });

        Self {
            tx: Some(tx),
            source_id,
            chain: Arc::new(Mutex::new(AuditChainState::default())),
        }
    }

    /// Delivers an event (best-effort: dropped with a log line if the channel is full).
    pub fn record(&self, kind: AuditKind, actor: Option<String>, peer: Option<String>) {
        let Some(tx) = &self.tx else { return };
        let mut state = self
            .chain
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let rollback = (state.sequence, state.previous_hash);
        let event = seal_event(
            &mut state,
            &self.source_id,
            now_iso8601(),
            kind,
            actor,
            peer,
        );
        if let Err(mpsc::error::TrySendError::Full(_)) =
            tx.try_send(AuditMsg::Event(Box::new(event)))
        {
            // The record never crossed the channel, so restore the sequence and
            // chain head rather than publishing an unobservable gap.
            state.sequence = rollback.0;
            state.previous_hash = rollback.1;
            metrics::counter!("interflow_hub_audit_dropped").increment(1);
        }
        // Dropping when the writer has exited (Closed) is expected behavior
    }

    /// Waits until all previously delivered events are on disk (shutdown drain).
    ///
    /// Channel FIFO: when the writer reaches the Flush message, all earlier
    /// events have been written; confirmed via the oneshot receipt. Returns
    /// immediately if the writer has exited.
    pub async fn flush(&self) {
        let Some(tx) = &self.tx else { return };
        let (otx, orx) = tokio::sync::oneshot::channel();
        if tx.send(AuditMsg::Flush(otx)).await.is_ok() {
            let _ = orx.await;
        }
    }
}

fn seal_event(
    state: &mut AuditChainState,
    source_id: &str,
    ts: String,
    kind: AuditKind,
    actor: Option<String>,
    peer: Option<String>,
) -> AuditEvent {
    state.sequence = state.sequence.saturating_add(1);
    let mut event = AuditEvent {
        source_id: source_id.to_owned(),
        sequence: state.sequence,
        ts,
        kind,
        actor,
        peer,
        previous_hash: hex::encode(state.previous_hash),
        record_hash: String::new(),
    };
    let canonical = serde_json::to_vec(&event).unwrap_or_default();
    let mut hasher = Sha256::new();
    hasher.update(state.previous_hash);
    hasher.update(canonical);
    let hash: [u8; 32] = hasher.finalize().into();
    event.record_hash = hex::encode(hash);
    state.previous_hash = hash;
    event
}

fn source_id() -> String {
    let nanos = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .map_or(0, |d| d.as_nanos());
    let mut hasher = Sha256::new();
    hasher.update(nanos.to_be_bytes());
    hasher.update(std::process::id().to_be_bytes());
    hex::encode(hasher.finalize())
}

async fn writer_task(path: &PathBuf, rx: &mut mpsc::Receiver<AuditMsg>) {
    let mut file = match OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
        .await
    {
        Ok(f) => f,
        Err(e) => {
            warn!(
                "failed to open audit file {}: {e}; audit disabled",
                path.display()
            );
            return;
        }
    };

    while let Some(msg) = rx.recv().await {
        let json = match msg {
            AuditMsg::Flush(otx) => {
                // Events enqueued ahead of Flush have all been written and
                // flushed line by line by the time we get here
                let _ = otx.send(());
                continue;
            }
            AuditMsg::Event(event) => match serde_json::to_string(&event) {
                Ok(s) => s,
                Err(e) => {
                    warn!("audit serialization failed: {e}");
                    continue;
                }
            },
        };
        if let Err(e) = file.write_all(json.as_bytes()).await {
            warn!("audit write failed: {e}");
            continue;
        }
        if let Err(e) = file.write_all(b"\n").await {
            warn!("audit newline write failed: {e}");
            continue;
        }
        // line-buffered: flush once per line. Could switch to periodic flush
        // for batch-heavy workloads.
        let _ = file.flush().await;
    }
}

fn now_iso8601() -> String {
    // Format convention: 2026-07-10T08:46:12Z — whole seconds, always UTC.
    // The sealed `ts` field of audit records is locked to this shape by tests.
    format_iso8601(time::OffsetDateTime::now_utc())
}

/// Formats an instant as `YYYY-MM-DDTHH:MM:SSZ` (no fractional seconds).
fn format_iso8601(t: time::OffsetDateTime) -> String {
    const FORMAT: &[time::format_description::FormatItem<'static>] =
        time::macros::format_description!("[year]-[month]-[day]T[hour]:[minute]:[second]Z");
    // Fails only for years outside 0..=9999, which cannot occur for wall-clock
    // UTC timestamps.
    t.format(FORMAT)
        .expect("ISO-8601 formatting of a UTC timestamp cannot fail")
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

    #[test]
    fn iso8601_format_known_instants() {
        let fmt =
            |secs: i64| format_iso8601(time::OffsetDateTime::from_unix_timestamp(secs).unwrap());
        // 1970-01-01 00:00:00 UTC
        assert_eq!(fmt(0), "1970-01-01T00:00:00Z");
        // 2026-01-01 00:00:00 UTC — the audit-chain test anchor
        assert_eq!(fmt(1_767_225_600), "2026-01-01T00:00:00Z");
        // 2024-01-01 00:00:00 UTC
        assert_eq!(fmt(1_704_067_200), "2024-01-01T00:00:00Z");
        // Leap-day boundaries: 2024-02-29 23:59:59 / 2024-03-01 00:00:00 UTC
        assert_eq!(fmt(1_709_251_199), "2024-02-29T23:59:59Z");
        assert_eq!(fmt(1_709_251_200), "2024-03-01T00:00:00Z");
    }

    #[test]
    fn disabled_sink_swallows_events() {
        let sink = AuditSink::disabled();
        sink.record(
            AuditKind::AgentRegistered {
                circuit: "12078a05e14f4e2c99b1679be1df7c30".into(),
            },
            None,
            None,
        );
        // no panic = pass
    }

    #[test]
    fn sealed_records_form_a_chain() {
        let mut state = AuditChainState::default();
        let a = seal_event(
            &mut state,
            "source",
            "2026-01-01T00:00:00Z".into(),
            AuditKind::ConfigReloaded,
            None,
            None,
        );
        let b = seal_event(
            &mut state,
            "source",
            "2026-01-01T00:00:01Z".into(),
            AuditKind::ConfigReloaded,
            None,
            None,
        );
        assert_eq!(a.sequence, 1);
        assert_eq!(b.sequence, 2);
        assert_eq!(b.previous_hash, a.record_hash);
        assert_ne!(a.record_hash, b.record_hash);
    }

    #[test]
    fn stream_audit_records_contain_no_semantic_identities() {
        let mut state = AuditChainState::default();
        let event = seal_event(
            &mut state,
            "hub",
            "2026-01-01T00:00:00Z".into(),
            AuditKind::StreamOpened {
                stream_id: "12078a05e14f4e2c99b1679be1df7c30".into(),
                source_circuit: "22078a05e14f4e2c99b1679be1df7c30".into(),
                route: "32078a05e14f4e2c99b1679be1df7c30".into(),
            },
            Some("42078a05e14f4e2c99b1679be1df7c30".into()),
            None,
        );
        let json = serde_json::to_string(&event).unwrap();
        assert!(json.contains("source_circuit"));
        for semantic in ["tenant-secret", "workspace-secret", "agent-secret"] {
            assert!(!json.contains(semantic), "audit leaked {semantic}: {json}");
        }
    }
}
