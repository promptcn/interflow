//! Audit log: a structured JSONL writer, separated from ordinary logs for
//! easy SIEM ingestion.
//!
//! Event kinds are listed in [`AuditKind`]; write policy: line-buffered
//! append, a single writer task, and multiple producers delivering via
//! mpsc, with periodic `fsync` (and a mandatory one at every seal/flush)
//! so a crash costs at most the tail of the current fsync window, never
//! the whole file. Failures only warn and never block the main path.
//!
//! # Ledger lifecycle (rotation)
//!
//! The active file `audit.jsonl` grows until [`AuditRotation::max_bytes`],
//! then it is sealed: flush + `fsync` + rename to
//! `audit-<UTC compact timestamp>-<zero-padded first sequence>.jsonl`
//! (optionally gzip-compressed to `.jsonl.gz` in the background), a fresh
//! active file opens, and segments beyond `keep` / `retention_days` are
//! deleted. Sealing is append-only bookkeeping — record contents are
//! never touched — and the in-memory hash chain keeps advancing across
//! segments, so the first record of a new segment chains onto the last
//! record of the previous one. On startup an existing non-empty active
//! file (a previous process's chain — the chain state is per-process,
//! see [`AuditSink::spawn`]) is sealed first: one active file always
//! carries exactly one chain. Archival integrity is "every retained
//! segment full-chain verifiable"; deleting segments beyond retention
//! truncates a chain's head, and the remaining segments stay internally
//! verifiable (each record carries its predecessor's hash). Replays and
//! offline verification go through [`verify_audit_files`] (the
//! `interflow audit verify` product face).

use crate::config::{AuditConfig, AuditRotation};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::Mutex;
use std::time::SystemTime;
use tokio::fs::OpenOptions;
use tokio::io::AsyncWriteExt;
use tokio::sync::mpsc;
use tracing::warn;

/// Audit event kinds.
///
/// `Serialize` writes records; `Deserialize` exists for
/// [`verify_audit_files`] / `interflow audit verify` (replaying a ledger
/// is part of the ledger's contract).
#[derive(Debug, Clone, Serialize, Deserialize)]
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
        #[serde(rename = "source", default, skip_serializing_if = "Option::is_none")]
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
    /// A signed policy update was published through the control plane
    /// (accepted + persisted; the reload watcher applies it).
    PolicyPublished {
        /// The policy generation that was published.
        generation: u64,
    },
    /// A signed policy update was rejected at publication (bad signature /
    /// rollback / malformed).
    PolicyPublishDenied {
        /// The rejection category.
        reason: String,
    },
    /// An agent pulled the current signed policy bytes.
    PolicyPulled {
        /// The policy generation served.
        generation: u64,
        /// The pulling agent's qualified id.
        agent: String,
    },
    /// An agent's connection certificate crossed a credential-expiry
    /// phase boundary (`healthy` → `warn` → `critical`, or back to
    /// `healthy` after a rotation). State-transition accounting: one event
    /// per crossing, never per observation tick.
    CredentialExpiry {
        /// The agent whose leaf crossed a phase boundary (qualified id).
        agent: String,
        /// The phase now in effect: `warn` (<20% of the leaf lifetime
        /// remains), `critical` (<10%, or expired), or `healthy` (back —
        /// the hub-side evidence that a rotation landed).
        phase: String,
        /// Remaining seconds of the leaf (negative once expired).
        remaining_secs: i64,
        /// The leaf's `notAfter` (unix seconds).
        not_after_unix: i64,
    },
}

/// One audit record.
#[derive(Debug, Clone, Serialize, Deserialize)]
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
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub actor: Option<String>,
    /// The peer TCP address.
    #[serde(default, skip_serializing_if = "Option::is_none")]
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
        let rotation = config.rotation.clone();
        let path = PathBuf::from(path);

        tokio::spawn(async move {
            writer_task(&path, &rotation, &mut rx).await;
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

/// fsync cadence: sync at most this many records (or this long) behind.
/// A crash costs at most the tail of the current window — never the whole
/// file — at a cost the (post-dedup) audit event rate cannot feel.
const SYNC_EVERY_RECORDS: usize = 128;
const SYNC_EVERY: std::time::Duration = std::time::Duration::from_secs(5);

/// The writer's mutable file state (everything rotation touches).
struct WriterFile {
    file: tokio::fs::File,
    /// Bytes written into the current active file (rotation threshold).
    written: u64,
    /// Sequence of the first record written into the current active file
    /// (segment naming); 0 while the file is still empty.
    first_sequence: u64,
    /// Records and time since the last `sync_all`.
    since_sync: usize,
    last_sync: std::time::Instant,
}

/// A sealed segment awaiting compression (kept by stem so pruning can
/// exclude segments still being compressed).
struct PendingCompress {
    stem: String,
    handle: tokio::task::JoinHandle<()>,
}

async fn writer_task(path: &Path, rotation: &AuditRotation, rx: &mut mpsc::Receiver<AuditMsg>) {
    // Startup pre-rotation: a non-empty active file is a previous
    // process's chain (the chain state is per-process). Seal it before
    // writing so one active file carries exactly one chain — otherwise
    // the restarted source's sequence-1 records interleave with the old
    // tail and neither chain replays.
    let mut compressing: Vec<PendingCompress> = Vec::new();
    if tokio::fs::metadata(path).await.is_ok_and(|m| m.len() > 0)
        && let Err(e) = seal_startup(path, rotation, &mut compressing).await
    {
        // Sealing is best-effort: failing to archive must not disable
        // auditing. The old chain's tail stays in place (appending a new
        // chain after it degrades replay of that one file only).
        warn!("failed to seal existing audit file {}: {e}", path.display());
    }
    let Some(mut out) = open_active(path).await else {
        return;
    };
    while let Some(msg) = rx.recv().await {
        let (sequence, json) = match msg {
            AuditMsg::Flush(otx) => {
                // Drain point: everything before this message is written
                // and line-flushed already; take the receipt only after a
                // real fsync, so "flushed" means durable, not just handed
                // to the OS.
                let _ = out.file.sync_all().await;
                out.since_sync = 0;
                out.last_sync = std::time::Instant::now();
                let _ = otx.send(());
                continue;
            }
            AuditMsg::Event(event) => {
                let sequence = event.sequence;
                match serde_json::to_string(&event) {
                    Ok(json) => (sequence, json),
                    Err(e) => {
                        warn!("audit serialization failed: {e}");
                        continue;
                    }
                }
            }
        };
        if out.first_sequence == 0 {
            // First record of this active file — it names the future
            // segment.
            out.first_sequence = sequence;
        }
        if let Err(e) = out.file.write_all(json.as_bytes()).await {
            warn!("audit write failed: {e}");
            continue;
        }
        if let Err(e) = out.file.write_all(b"\n").await {
            warn!("audit newline write failed: {e}");
            continue;
        }
        // line-buffered: flush once per line. Could switch to periodic flush
        // for batch-heavy workloads.
        let _ = out.file.flush().await;
        out.written += json.len() as u64 + 1;
        out.since_sync += 1;
        if out.since_sync >= SYNC_EVERY_RECORDS || out.last_sync.elapsed() >= SYNC_EVERY {
            let _ = out.file.sync_all().await;
            out.since_sync = 0;
            out.last_sync = std::time::Instant::now();
        }
        if rotation.max_bytes > 0 && out.written >= rotation.max_bytes {
            // Seal: durable-close the active file, rename it to its
            // segment name, open a fresh active file — in that order (the
            // fresh open must come after the rename, or its handle would
            // point at the renamed-away inode). A crash between the rename
            // and the reopen costs nothing: the sealed segment is already
            // durable and the next start re-creates the active file.
            let sealed_first = out.first_sequence;
            let WriterFile { file: old, .. } = out;
            let _ = old.sync_all().await;
            drop(old); // rename with an open handle fails on Windows
            let name = segment_name(SystemTime::now(), sealed_first);
            if let Err(e) = tokio::fs::rename(path, path.with_file_name(&name)).await {
                warn!("failed to seal audit segment {name}: {e}");
                // The old file stays under the active name; the reopened
                // file below is the same file (append continues).
            }
            out = match open_active(path).await {
                Some(w) => w,
                None => return,
            };
            prune_and_compress(path, rotation, &mut compressing).await;
        }
    }
    let _ = out.file.sync_all().await;
}

/// Opens (creates) the active audit file. `None` (with a warn) if the
/// filesystem refuses — audit then runs disabled, exactly as today.
async fn open_active(path: &Path) -> Option<WriterFile> {
    match OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
        .await
    {
        Ok(file) => Some(WriterFile {
            file,
            written: 0,
            first_sequence: 0,
            since_sync: 0,
            last_sync: std::time::Instant::now(),
        }),
        Err(e) => {
            warn!(
                "failed to open audit file {}: {e}; audit disabled",
                path.display()
            );
            None
        }
    }
}

/// Seals the active file found at startup: read its first line (to name
/// the segment after the sequence it starts at), rename it away.
async fn seal_startup(
    path: &Path,
    rotation: &AuditRotation,
    compressing: &mut Vec<PendingCompress>,
) -> std::io::Result<()> {
    use tokio::io::AsyncReadExt;
    let mut file = OpenOptions::new().read(true).open(path).await?;
    let mut buf = vec![0u8; 4096];
    // One line is enough to name the segment.
    let n = file.read(&mut buf).await?;
    let head = String::from_utf8_lossy(&buf[..n]);
    drop(file); // rename with an open handle fails on Windows
    let first_sequence = head
        .lines()
        .next()
        .and_then(|line| serde_json::from_str::<serde_json::Value>(line).ok())
        .and_then(|v| v.get("sequence").and_then(serde_json::Value::as_u64))
        .unwrap_or(1);
    let name = segment_name(SystemTime::now(), first_sequence);
    tokio::fs::rename(path, path.with_file_name(&name)).await?;
    prune_and_compress(path, rotation, compressing).await;
    Ok(())
}

/// Retention/pruning pass + background compression of the newest bare
/// segment. Runs on the writer's serial path, so segment state needs no
/// further locking; only the gzip itself is offloaded (blocking pool).
async fn prune_and_compress(
    path: &Path,
    rotation: &AuditRotation,
    compressing: &mut Vec<PendingCompress>,
) {
    // Reap finished compression tasks (their segments are now .gz and
    // fully prunable).
    compressing.retain(|p| !p.handle.is_finished());
    let inflight: Vec<String> = compressing.iter().map(|p| p.stem.clone()).collect();

    let Some(dir) = path.parent() else { return };
    let mut segments = match list_segments(dir).await {
        Ok(s) => s,
        Err(e) => {
            warn!("audit segment listing failed: {e}");
            return;
        }
    };
    // Newest-first by stem (stems sort by timestamp+sequence).
    segments.sort();
    segments.reverse();

    for (i, stem) in segments.iter().enumerate() {
        let beyond_keep = rotation.keep > 0 && i >= rotation.keep;
        let expired =
            rotation.retention_days > 0 && segment_age_expired(stem, rotation.retention_days);
        if !beyond_keep && !expired {
            continue;
        }
        // A segment still being compressed is not prunable this round —
        // deleting the source of an in-flight gzip would corrupt the
        // archive. The next rotation re-evaluates it.
        if inflight.contains(stem) {
            continue;
        }
        for ext in [".jsonl", ".jsonl.gz"] {
            let p = dir.join(format!("{stem}{ext}"));
            if tokio::fs::remove_file(&p).await.is_ok() {
                tracing::debug!("audit segment pruned: {}", p.display());
            }
        }
    }

    if !rotation.compress {
        return;
    }
    // Compress the newest still-bare segment (older ones were compressed
    // when they were the newest; a failed or still-running one is picked
    // up again next round via the inflight guard).
    let mut target: Option<(String, std::path::PathBuf)> = None;
    for stem in &segments {
        if inflight.contains(stem) {
            continue;
        }
        let bare = dir.join(format!("{stem}.jsonl"));
        if tokio::fs::metadata(&bare).await.is_ok() {
            target = Some((stem.clone(), bare));
            break;
        }
    }
    let Some((stem, bare)) = target else {
        return;
    };
    let gz = dir.join(format!("{stem}.jsonl.gz"));
    let handle = tokio::task::spawn_blocking(move || {
        if let Err(e) = gzip_file(&bare, &gz) {
            warn!("audit segment compression failed (kept uncompressed): {e}");
            return;
        }
        if let Err(e) = std::fs::remove_file(&bare) {
            warn!("audit segment compression cleanup failed: {e}");
        }
    });
    compressing.push(PendingCompress { stem, handle });
}

/// gzip one file into another (std fs; runs on the blocking pool).
fn gzip_file(src: &Path, dst: &Path) -> std::io::Result<()> {
    use flate2::Compression;
    use flate2::write::GzEncoder;
    use std::io::{Read, Write};
    let mut input = std::fs::File::open(src)?;
    let output = std::fs::File::create(dst)?;
    let mut encoder = GzEncoder::new(output, Compression::default());
    let mut buf = vec![0u8; 64 * 1024];
    loop {
        let n = input.read(&mut buf)?;
        if n == 0 {
            break;
        }
        encoder.write_all(&buf[..n])?;
    }
    let output = encoder.finish()?;
    output.sync_all()
}

/// Segment stems (`audit-<ts>-<seq>`, no extension) present in `dir`,
/// the active file excluded.
async fn list_segments(dir: &Path) -> std::io::Result<Vec<String>> {
    use std::collections::BTreeSet;
    let mut dir = tokio::fs::read_dir(dir).await?;
    let mut stems = BTreeSet::new();
    while let Some(entry) = dir.next_entry().await? {
        let name = entry.file_name();
        let Some(name) = name.to_str() else { continue };
        for ext in [".jsonl", ".jsonl.gz"] {
            if let Some(stem) = name.strip_suffix(ext)
                && stem.starts_with("audit-")
            {
                stems.insert(stem.to_owned());
            }
        }
    }
    Ok(stems.into_iter().collect())
}

/// `true` when the segment's embedded timestamp is older than
/// `retention_days` (the name's timestamp is the authoritative seal time).
fn segment_age_expired(stem: &str, retention_days: u64) -> bool {
    let Some(ts) = stem.split('-').nth(1) else {
        return false;
    };
    let parse = |s: &str| {
        time::PrimitiveDateTime::parse(
            s,
            &time::macros::format_description!("[year][month][day]T[hour][minute][second]Z"),
        )
        .ok()
        .map(time::PrimitiveDateTime::assume_utc)
    };
    match parse(ts) {
        Some(then) => {
            time::OffsetDateTime::now_utc() - then
                > time::Duration::days(retention_days.cast_signed())
        }
        None => false,
    }
}

/// `audit-<compact UTC>-<zero-padded sequence>.jsonl` — sorts by
/// timestamp, then by first sequence within the same second.
fn segment_name(when: SystemTime, first_sequence: u64) -> String {
    let t = time::OffsetDateTime::from(when).to_offset(time::UtcOffset::UTC);
    const FORMAT: &[time::format_description::FormatItem<'static>] =
        time::macros::format_description!("[year][month][day]T[hour][minute][second]Z");
    let ts = t
        .format(FORMAT)
        .expect("ISO-8601 formatting of a UTC timestamp cannot fail");
    format!("audit-{ts}-{first_sequence:016}.jsonl")
}

fn now_iso8601() -> String {
    // Format convention: 2026-07-10T08:46:12Z — whole seconds, always UTC.
    // The sealed `ts` field of audit records is locked to this shape by tests.
    format_iso8601(time::OffsetDateTime::now_utc())
}

// ---------------------------------------------------------------------------
// Ledger verification (replay) — `interflow audit verify`
// ---------------------------------------------------------------------------

/// What a successful verification of a ledger (or ledger excerpt) found.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuditVerifyReport {
    /// Records examined.
    pub records: usize,
    /// Files (segments + active) examined.
    pub segments: usize,
    /// Distinct chains (per-process ledgers; one per writer lifetime).
    pub chains: usize,
    /// Whether the FIRST record of the input was not a chain start
    /// (sequence 1, zero previous hash) — normal when retention already
    /// pruned the oldest segments of a long-running chain.
    pub truncated_start: bool,
}

/// Where and why a chain broke.
#[derive(Debug, Clone)]
pub struct AuditVerifyError {
    /// The file containing the offending record.
    pub file: PathBuf,
    /// 1-based line number within that file.
    pub line: usize,
    /// Human-readable break description.
    pub reason: String,
}

impl std::fmt::Display for AuditVerifyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}:{}: {}", self.file.display(), self.line, self.reason)
    }
}

impl std::error::Error for AuditVerifyError {}

/// The all-zero previous hash — the first record of every chain.
const ZERO_HASH_HEX: &str = "0000000000000000000000000000000000000000000000000000000000000000";

/// Verifies a sequence of audit files (segments in chain order, the
/// active file last — [`discover_audit_files`] produces exactly that).
///
/// Every record's `record_hash` is recomputed, sequences advance by one
/// within a chain, `previous_hash` links each record to its predecessor,
/// and a source change is only accepted as a fresh chain (sequence 1,
/// zero previous hash).
pub fn verify_audit_files(paths: &[PathBuf]) -> Result<AuditVerifyReport, AuditVerifyError> {
    use std::io::BufRead as _;
    let mut report = AuditVerifyReport {
        records: 0,
        segments: 0,
        chains: 0,
        truncated_start: false,
    };
    // The (chain head) the previous record established.
    let mut prev: Option<(String, u64, String)> = None;
    for path in paths {
        let is_gz = path.extension().is_some_and(|e| e == "gz");
        let reader: Box<dyn std::io::BufRead> = if is_gz {
            let file = std::fs::File::open(path).map_err(|e| AuditVerifyError {
                file: path.clone(),
                line: 0,
                reason: format!("cannot open: {e}"),
            })?;
            Box::new(std::io::BufReader::new(flate2::read::GzDecoder::new(file)))
        } else {
            let file = std::fs::File::open(path).map_err(|e| AuditVerifyError {
                file: path.clone(),
                line: 0,
                reason: format!("cannot open: {e}"),
            })?;
            Box::new(std::io::BufReader::new(file))
        };
        report.segments += 1;
        for (idx, line) in reader.lines().enumerate() {
            let line = line.map_err(|e| AuditVerifyError {
                file: path.clone(),
                line: idx + 1,
                reason: format!("read error: {e}"),
            })?;
            if line.trim().is_empty() {
                continue;
            }
            let lineno = idx + 1;
            let mut event: AuditEvent =
                serde_json::from_str(&line).map_err(|e| AuditVerifyError {
                    file: path.clone(),
                    line: lineno,
                    reason: format!("record is not valid audit JSON: {e}"),
                })?;
            // Recompute the record hash exactly the way it was sealed:
            // SHA-256(previous-hash bytes || canonical JSON with an empty
            // record_hash). serde's struct field order is declaration
            // order, so the canonical bytes are reproducible.
            let claimed = std::mem::take(&mut event.record_hash);
            let previous_bytes = hex::decode(&event.previous_hash).unwrap_or_default();
            event.record_hash = String::new();
            let canonical = serde_json::to_vec(&event).unwrap_or_default();
            let mut hasher = Sha256::new();
            hasher.update(&previous_bytes);
            hasher.update(&canonical);
            let digest: [u8; 32] = hasher.finalize().into();
            let recomputed = hex::encode(digest);
            if recomputed != claimed {
                return Err(AuditVerifyError {
                    file: path.clone(),
                    line: lineno,
                    reason: format!(
                        "record_hash mismatch: record claims {claimed}, recomputed {recomputed}"
                    ),
                });
            }
            match &prev {
                None => {
                    report.chains += 1;
                    report.truncated_start =
                        !(event.sequence == 1 && event.previous_hash == ZERO_HASH_HEX);
                }
                Some((source, sequence, record_hash)) => {
                    if event.source_id == *source {
                        if event.sequence != sequence + 1 {
                            return Err(AuditVerifyError {
                                file: path.clone(),
                                line: lineno,
                                reason: format!(
                                    "sequence break: expected {}, found {}",
                                    sequence + 1,
                                    event.sequence
                                ),
                            });
                        }
                        if &event.previous_hash != record_hash {
                            return Err(AuditVerifyError {
                                file: path.clone(),
                                line: lineno,
                                reason: "hash-chain break: previous_hash does not match the \
                                     preceding record's record_hash"
                                    .to_string(),
                            });
                        }
                    } else {
                        // A new writer lifetime: only acceptable as a
                        // fresh chain.
                        if event.sequence != 1 || event.previous_hash != ZERO_HASH_HEX {
                            return Err(AuditVerifyError {
                                file: path.clone(),
                                line: lineno,
                                reason: format!(
                                    "source change to {} without a fresh chain start \
                                     (sequence 1, zero previous hash)",
                                    event.source_id
                                ),
                            });
                        }
                        report.chains += 1;
                    }
                }
            }
            prev = Some((event.source_id.clone(), event.sequence, claimed));
            report.records += 1;
        }
    }
    Ok(report)
}

/// Discovers a ledger's files under `dir` in chain order.
///
/// Sealed segments sort by name (timestamp + sequence), the active
/// `audit.jsonl` comes last. Missing files are simply absent from the
/// result; an empty result means "no ledger here".
pub fn discover_audit_files(dir: &Path) -> Vec<PathBuf> {
    let mut segments = list_segments_blocking(dir);
    segments.sort();
    let mut files: Vec<PathBuf> = segments
        .into_iter()
        .map(|stem| {
            // Prefer the compressed form when both somehow exist.
            let gz = dir.join(format!("{stem}.jsonl.gz"));
            if gz.exists() {
                gz
            } else {
                dir.join(format!("{stem}.jsonl"))
            }
        })
        .collect();
    let active = dir.join("audit.jsonl");
    if active.exists() {
        files.push(active);
    }
    files
}

/// Synchronous sibling of the writer's segment listing (verification is
/// an offline, one-shot tool).
fn list_segments_blocking(dir: &Path) -> Vec<String> {
    use std::collections::BTreeSet;
    let Ok(entries) = std::fs::read_dir(dir) else {
        return Vec::new();
    };
    let mut stems = BTreeSet::new();
    for entry in entries.flatten() {
        let file_name = entry.file_name();
        let Some(name) = file_name.to_str() else {
            continue;
        };
        for ext in [".jsonl", ".jsonl.gz"] {
            if let Some(stem) = name.strip_suffix(ext)
                && stem.starts_with("audit-")
            {
                stems.insert(stem.to_owned());
            }
        }
    }
    stems.into_iter().collect()
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
                stream_id: "12078a05e14f4e2c99b1679be1dfc30".into(),
                source_circuit: "22078a05e14f4e2c99b1679be1dfc30".into(),
                route: "32078a05e14f4e2c99b1679be1dfc30".into(),
            },
            Some("42078a05e14f4e2c99b1679be1dfc30".into()),
            None,
        );
        let json = serde_json::to_string(&event).unwrap();
        assert!(json.contains("source_circuit"));
        for semantic in ["tenant-secret", "workspace-secret", "agent-secret"] {
            assert!(!json.contains(semantic), "audit leaked {semantic}: {json}");
        }
    }

    // -----------------------------------------------------------------
    // Rotation / retention / verification
    // -----------------------------------------------------------------

    fn test_config(dir: &std::path::Path, rotation: AuditRotation) -> AuditConfig {
        AuditConfig {
            enabled: true,
            path: Some(dir.join("audit.jsonl").display().to_string()),
            rotation,
        }
    }

    async fn write_events(sink: &AuditSink, n: usize) {
        for _ in 0..n {
            sink.record(AuditKind::ConfigReloaded, None, None);
        }
        sink.flush().await;
    }

    #[tokio::test]
    async fn rotates_at_threshold_and_chains_across_segments() {
        let dir = tempfile::tempdir().unwrap();
        let rotation = AuditRotation {
            // One record is ~400 bytes; two per segment.
            max_bytes: 600,
            keep: 10,
            retention_days: 0,
            compress: false,
        };
        let sink = AuditSink::spawn(&test_config(dir.path(), rotation));
        write_events(&sink, 6).await;
        let files = discover_audit_files(dir.path());
        let segments = files
            .iter()
            .filter(|f| f.file_name().unwrap() != "audit.jsonl")
            .count();
        assert!(segments >= 2, "expected rotation, files: {files:?}");
        // The full ledger — across segments + active — replays as one
        // unbroken chain: sequences advance, hashes link across segment
        // boundaries.
        let report = verify_audit_files(&files).unwrap();
        assert_eq!(report.records, 6);
        assert_eq!(report.chains, 1);
        assert!(!report.truncated_start);
    }

    #[tokio::test]
    async fn keep_prunes_old_segments() {
        let dir = tempfile::tempdir().unwrap();
        let rotation = AuditRotation {
            max_bytes: 600,
            keep: 2,
            retention_days: 0,
            compress: false,
        };
        let sink = AuditSink::spawn(&test_config(dir.path(), rotation));
        write_events(&sink, 10).await;
        let files = discover_audit_files(dir.path());
        let segments = files
            .iter()
            .filter(|f| f.file_name().unwrap() != "audit.jsonl")
            .count();
        assert!(
            segments <= 2,
            "keep=2 must cap sealed segments at 2 (found {segments})"
        );
        // Whatever survived still verifies (the chain head was pruned;
        // the remainder is internally consistent).
        let report = verify_audit_files(&files).unwrap();
        assert_eq!(report.chains, 1);
    }

    #[tokio::test]
    async fn retention_prunes_expired_segment_names() {
        let dir = tempfile::tempdir().unwrap();
        // A segment sealed long before any retention window.
        let ancient = dir
            .path()
            .join("audit-20200101T000000Z-0000000000000001.jsonl");
        std::fs::write(&ancient, "{}\n").unwrap();
        let rotation = AuditRotation {
            max_bytes: 600,
            keep: 10,
            retention_days: 365,
            compress: false,
        };
        let sink = AuditSink::spawn(&test_config(dir.path(), rotation));
        // Startup seals the (just-written) active file first, then events
        // rotate; every prune pass must drop the 2020 segment by name.
        write_events(&sink, 4).await;
        assert!(
            !ancient.exists(),
            "retention_days=365 must prune a 2020-dated segment"
        );
    }

    #[tokio::test]
    async fn compresses_rotated_segments_and_verifies_gzip() {
        let dir = tempfile::tempdir().unwrap();
        let rotation = AuditRotation {
            max_bytes: 600,
            keep: 10,
            retention_days: 0,
            compress: true,
        };
        let sink = AuditSink::spawn(&test_config(dir.path(), rotation));
        write_events(&sink, 6).await;
        // Compression runs on the blocking pool; wait for the newest
        // sealed segment to become .gz.
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
        loop {
            let bare = std::fs::read_dir(dir.path())
                .unwrap()
                .filter_map(std::result::Result::ok)
                .any(|e| {
                    e.file_name().to_string_lossy().starts_with("audit-")
                        && e.file_name().to_string_lossy().ends_with(".jsonl")
                });
            let gz = std::fs::read_dir(dir.path())
                .unwrap()
                .filter_map(std::result::Result::ok)
                .any(|e| e.file_name().to_string_lossy().ends_with(".jsonl.gz"));
            if (!bare && gz) || std::time::Instant::now() > deadline {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        }
        let files = discover_audit_files(dir.path());
        assert!(
            files
                .iter()
                .any(|f| f.extension().is_some_and(|e| e == "gz")),
            "sealed segments must be gzip-compressed: {files:?}"
        );
        // The gzipped ledger replays transparently.
        let report = verify_audit_files(&files).unwrap();
        assert_eq!(report.records, 6);
        assert_eq!(report.chains, 1);
    }

    #[tokio::test]
    async fn startup_seals_existing_active_file() {
        let dir = tempfile::tempdir().unwrap();
        // A previous process's ledger: one legitimate record (its own
        // chain, sequence 1, zero previous hash).
        let mut old_state = AuditChainState::default();
        let old = seal_event(
            &mut old_state,
            "old-process",
            "2026-01-01T00:00:00Z".into(),
            AuditKind::ConfigReloaded,
            None,
            None,
        );
        std::fs::write(
            dir.path().join("audit.jsonl"),
            serde_json::to_string(&old).unwrap() + "\n",
        )
        .unwrap();
        let rotation = AuditRotation {
            max_bytes: 64 * 1024 * 1024,
            keep: 10,
            retention_days: 0,
            compress: false,
        };
        let sink = AuditSink::spawn(&test_config(dir.path(), rotation));
        write_events(&sink, 2).await;
        // The old content became a segment; the fresh active file carries
        // exactly the new chain (2 records), not an interleave.
        let files = discover_audit_files(dir.path());
        let report = verify_audit_files(&files).unwrap();
        assert_eq!(report.records, 3, "2 fresh records + the sealed old one");
        assert_eq!(report.chains, 2, "the old process's chain + the new one");
        let active = std::fs::read_to_string(dir.path().join("audit.jsonl")).unwrap();
        let new_chain_lines = active.lines().count();
        assert_eq!(new_chain_lines, 2, "active file holds only the new chain");
    }

    #[test]
    fn verify_reports_a_broken_chain() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("audit.jsonl");
        let mut state = AuditChainState::default();
        let events: Vec<_> = (0..3)
            .map(|i| {
                seal_event(
                    &mut state,
                    "src",
                    format!("2026-01-01T00:00:0{i}Z"),
                    AuditKind::ConfigReloaded,
                    None,
                    None,
                )
            })
            .collect();
        let mut lines: Vec<String> = events
            .iter()
            .map(|e| serde_json::to_string(e).unwrap())
            .collect();
        // Tamper with the middle record's timestamp without resealing.
        let tampered = lines[1].replace("00:00:01", "00:00:09");
        assert_ne!(tampered, lines[1]);
        lines[1] = tampered;
        std::fs::write(&path, lines.join("\n") + "\n").unwrap();
        let err = verify_audit_files(std::slice::from_ref(&path)).unwrap_err();
        assert_eq!(err.file, path);
        assert_eq!(err.line, 2, "the tampered record is line 2: {err}");
        assert!(err.reason.contains("record_hash mismatch"), "{err}");
    }

    #[test]
    fn verify_flags_sequence_gap() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("audit.jsonl");
        let mut state = AuditChainState::default();
        let a = seal_event(
            &mut state,
            "src",
            "2026-01-01T00:00:00Z".into(),
            AuditKind::ConfigReloaded,
            None,
            None,
        );
        let _b = seal_event(
            &mut state,
            "src",
            "2026-01-01T00:00:01Z".into(),
            AuditKind::ConfigReloaded,
            None,
            None,
        );
        let c = seal_event(
            &mut state,
            "src",
            "2026-01-01T00:00:02Z".into(),
            AuditKind::ConfigReloaded,
            None,
            None,
        );
        // Write a and c, dropping b's line: the replayed ledger has a
        // sequence hole (and c chains onto the missing record).
        std::fs::write(
            &path,
            format!(
                "{}\n{}\n",
                serde_json::to_string(&a).unwrap(),
                serde_json::to_string(&c).unwrap()
            ),
        )
        .unwrap();
        let err = verify_audit_files(&[path]).unwrap_err();
        assert!(
            err.reason.contains("sequence break") || err.reason.contains("hash-chain break"),
            "{err}"
        );
    }
}
