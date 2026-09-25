//! Audit log configuration.

use serde::{Deserialize, Serialize};

/// Audit log rotation policy.
///
/// Sealing a segment is append-only bookkeeping: the active `audit.jsonl`
/// is flushed, fsynced, and renamed to `audit-<UTC compact>-<zero-padded
/// first sequence>.jsonl` (optionally gzip-compressed to `.jsonl.gz`), and
/// a fresh active file is opened. The in-memory hash chain keeps advancing
/// across segments — the first record of a new segment chains onto the
/// last record of the previous one — so rotation never touches record
/// contents; archival integrity is "every segment full-chain verifiable
/// while retained".
///
/// Defaults protect existing deployments with zero configuration changes:
/// rotation on at a conservative threshold, gzip on, a generous retention.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuditRotation {
    /// Size threshold that triggers a rotation, in bytes. `0` disables
    /// rotation (the explicit escape hatch back to unbounded growth).
    pub max_bytes: u64,
    /// How many sealed segments (`.jsonl` + `.jsonl.gz` together) to keep.
    /// Oldest beyond the count are deleted at rotation time.
    pub keep: usize,
    /// Sealed segments older than this (by the rotation timestamp in the
    /// segment name) are deleted at rotation time. `0` disables the
    /// age-based bound.
    pub retention_days: u64,
    /// Whether sealed segments are gzip-compressed in the background
    /// (`.jsonl` → `.jsonl.gz`).
    pub compress: bool,
}

impl Default for AuditRotation {
    fn default() -> Self {
        Self {
            max_bytes: 64 * 1024 * 1024,
            keep: 32,
            retention_days: 365,
            compress: true,
        }
    }
}

/// Audit log configuration.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuditConfig {
    /// Whether auditing is enabled.
    #[serde(default)]
    pub enabled: bool,
    /// JSONL file path.
    #[serde(default)]
    pub path: Option<String>,
    /// Rotation / compression / retention policy. Defaults rotate; an
    /// existing configuration file without a `[audit.rotation]` section
    /// gets the protective defaults.
    #[serde(default)]
    pub rotation: AuditRotation,
}
