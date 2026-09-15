//! Audit log: a structured JSONL writer, separated from ordinary logs for
//! easy SIEM ingestion.
//!
//! Event kinds are listed in [`AuditKind`]; write policy: line-buffered
//! append, a single writer thread, and multiple producers delivering via
//! mpsc. Failures only warn and never block the main path.

use crate::config::AuditConfig;
use serde::Serialize;
use std::path::PathBuf;
use std::sync::Arc;
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
        /// The agent id.
        agent_id: String,
    },
    /// Agent registration denied (wrong token, identity mismatch, etc.).
    AgentRegisterDenied {
        /// The denial reason.
        reason: String,
    },
    /// Agent evicted (poll grace expiry / heartbeat loss / data send timeout).
    AgentEvicted {
        /// The agent id.
        agent_id: String,
        /// The eviction reason (`send_timeout` / `poll_grace_expired` / `heartbeat_missed`).
        reason: String,
    },
    /// A stream was opened.
    StreamOpened {
        /// The stream id.
        stream_id: String,
        /// The source agent.
        source: String,
        /// The target agent.
        target: String,
    },
    /// A stream was denied (ACL / anti-spoofing).
    StreamDenied {
        /// The stream id.
        stream_id: String,
        /// The source agent.
        source: String,
        /// The denial reason.
        reason: String,
    },
    /// A stream was closed (normal completion or abnormal disconnect).
    StreamClosed {
        /// The stream id.
        stream_id: String,
        /// The source agent.
        source: String,
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
}

/// Background audit sink. Clone-friendly (Arc inside).
#[derive(Clone)]
pub struct AuditSink {
    tx: Option<Arc<mpsc::Sender<AuditMsg>>>,
}

/// Writer channel message: an audit event, or a flush receipt request (FIFO guarantees events before the receipt are on disk).
enum AuditMsg {
    Event(AuditEvent),
    Flush(tokio::sync::oneshot::Sender<()>),
}

impl AuditSink {
    /// Constructs a disabled sink (no-op). Corresponds to `[audit] enabled = false`.
    pub const fn disabled() -> Self {
        Self { tx: None }
    }

    /// Spawns the audit writer background task and returns a sink for delivering events.
    ///
    /// - Creates the file if absent; appends if present.
    /// - The writer task runs independently; file write failures only warn
    ///   and do not abort.
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

        tokio::spawn(async move {
            writer_task(&PathBuf::from(path), &mut rx).await;
        });

        Self { tx: Some(tx) }
    }

    /// Delivers an event (best-effort: dropped with a log line if the channel is full).
    pub fn record(&self, kind: AuditKind, actor: Option<String>, peer: Option<String>) {
        let Some(tx) = &self.tx else { return };
        let event = AuditEvent {
            ts: now_iso8601(),
            kind,
            actor,
            peer,
        };
        if let Err(mpsc::error::TrySendError::Full(_)) = tx.try_send(AuditMsg::Event(event)) {
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
    // SystemTime → ISO 8601 UTC, avoiding a chrono dependency (format
    // convention: 2026-07-10T08:46:12Z)
    let dur = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap_or_default();
    let secs = dur.as_secs();
    let (y, mo, d, h, mi, s) = epoch_to_ymdhms(secs);
    format!("{y:04}-{mo:02}-{d:02}T{h:02}:{mi:02}:{s:02}Z")
}

/// Unix epoch seconds → UTC (year, month, day, hour, minute, second).
///
/// Implemented with plain arithmetic to avoid a chrono dependency. The
/// algorithm comes from Howard Hinnant's date algorithms.
#[allow(
    clippy::cast_possible_truncation,
    clippy::cast_possible_wrap,
    clippy::cast_sign_loss
)]
const fn epoch_to_ymdhms(secs: u64) -> (i32, u32, u32, u32, u32, u32) {
    let days = (secs / 86_400) as i64;
    let rem = secs % 86_400;
    let hour = (rem / 3600) as u32;
    let minute = ((rem % 3600) / 60) as u32;
    let second = (rem % 60) as u32;

    // days is the count of days since 1970-01-01; convert to (y, m, d) with
    // Hinnant's algorithm
    let z = days + 719_468; // 1970-01-01 corresponds to z=719468
    let era = if z >= 0 {
        z / 146_097
    } else {
        (z - 146_096) / 146_097
    };
    let doe = (z - era * 146_097) as u64;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe as i64 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let month = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    let y = if month <= 2 { y + 1 } else { y };

    (y as i32, month, day, hour, minute, second)
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
    fn epoch_to_ymdhms_known_value() {
        // 1970-01-01 00:00:00 UTC
        assert_eq!(epoch_to_ymdhms(0), (1970, 1, 1, 0, 0, 0));
        // 2026-01-01 00:00:00 UTC = 1767225600
        assert_eq!(epoch_to_ymdhms(1_767_225_600), (2026, 1, 1, 0, 0, 0));
        // 2026-07-10 08:46:12 UTC ≈ 178_... verify with a known instant instead
        // 2024-01-01 00:00:00 UTC = 1704067200
        assert_eq!(epoch_to_ymdhms(1_704_067_200), (2024, 1, 1, 0, 0, 0));
    }

    #[test]
    fn disabled_sink_swallows_events() {
        let sink = AuditSink::disabled();
        sink.record(
            AuditKind::AgentRegistered {
                agent_id: "x".into(),
            },
            None,
            None,
        );
        // no panic = pass
    }
}
