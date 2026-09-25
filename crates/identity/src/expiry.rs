//! Leaf-credential expiry phasing — the single source of the "how close
//! to expiry is this credential" math, consumed by the GUI card/detail
//! views, `interflow doctor`, and the hub's per-agent credential-expiry
//! observations. One module so every surface shows the same phase for the
//! same credential at the same moment.

use serde::{Deserialize, Serialize};

/// Remaining-lifetime fraction below which a leaf counts as `Warn`
/// (amber on every surface). 20% of the leaf TTL.
pub const WARN_RATIO: f64 = 0.2;

/// Remaining-lifetime fraction below which a leaf counts as `Critical`
/// (red on every surface). 10% of the leaf TTL. An already-expired
/// credential is the deepest form of Critical (negative remaining).
pub const CRITICAL_RATIO: f64 = 0.1;

/// The expiry phase of a leaf credential.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LeafPhase {
    /// More than `WARN_RATIO` of the TTL remains.
    Healthy,
    /// Less than `WARN_RATIO` remains — rotate soon.
    Warn,
    /// Less than `CRITICAL_RATIO` remains (or already expired).
    Critical,
}

impl LeafPhase {
    /// The lowercase phase name used in audit records and CLI output
    /// (`healthy` / `warn` / `critical`).
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Healthy => "healthy",
            Self::Warn => "warn",
            Self::Critical => "critical",
        }
    }
}

/// A leaf's phase plus the raw remaining seconds (negative once expired).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct LeafHealth {
    pub phase: LeafPhase,
    pub remaining_secs: i64,
}

/// Phases a leaf from its expiry and the TTL it was issued with.
///
/// This is the pack-side entry (GUI / doctor): the pack's
/// `leaf_ttl_secs` is the issuance fact (renewal and rotation both sign
/// at exactly that TTL), so `remaining / ttl` is the true remaining
/// fraction.
pub fn leaf_phase_from_ttl(not_after_unix: i64, ttl_secs: u64, now_unix: i64) -> LeafHealth {
    let remaining = not_after_unix - now_unix;
    let phase = phase_of(remaining, ttl_secs.min(i64::MAX as u64) as i64);
    LeafHealth {
        phase,
        remaining_secs: remaining,
    }
}

/// Phases a leaf from its certificate validity window alone.
///
/// This is the hub-side entry: a hub sees the connecting certificate's
/// `notBefore`/`notAfter` and nothing else, so the TTL is derived from
/// the certificate itself — no configuration, works identically for the
/// registrar tier (24h leaves) and the offline tier (90d/180d leaves).
/// Equivalent to [`leaf_phase_from_ttl`] for any certificate issued at
/// its full validity window.
pub fn leaf_phase_from_validity(
    not_before_unix: i64,
    not_after_unix: i64,
    now_unix: i64,
) -> LeafHealth {
    let total = (not_after_unix - not_before_unix).max(0);
    let remaining = not_after_unix - now_unix;
    LeafHealth {
        phase: phase_of(remaining, total),
        remaining_secs: remaining,
    }
}

fn phase_of(remaining_secs: i64, total_secs: i64) -> LeafPhase {
    // A degenerate window (total <= 0) cannot express a fraction; treat
    // it as the deepest phase rather than silently calling it healthy.
    if total_secs <= 0 {
        return LeafPhase::Critical;
    }
    let remaining = f64::from(i32::try_from(remaining_secs.max(0)).unwrap_or(i32::MAX));
    let total = f64::from(i32::try_from(total_secs.max(0)).unwrap_or(i32::MAX));
    let ratio = remaining / total;
    if remaining_secs <= 0 || ratio < CRITICAL_RATIO {
        LeafPhase::Critical
    } else if ratio < WARN_RATIO {
        LeafPhase::Warn
    } else {
        LeafPhase::Healthy
    }
}

/// Human-facing remaining-lifetime text: whole days at `≥1d`,
/// `"<1d"` below that, `"expired"` at or past zero. Every surface (GUI
/// card, tray tooltip, doctor, hub log) uses this so the numbers agree.
pub fn format_remaining(remaining_secs: i64) -> String {
    if remaining_secs <= 0 {
        "expired".to_string()
    } else if remaining_secs < 86_400 {
        "<1d".to_string()
    } else {
        format!("{}d", remaining_secs / 86_400)
    }
}

/// Wall-clock unix seconds (the phasing input — `Instant` cannot express
/// calendar time). Never fails; pre-epoch clocks yield 0.
pub fn now_unix() -> i64 {
    use std::time::SystemTime;
    SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .map(|d| i64::try_from(d.as_secs()).unwrap_or(i64::MAX))
        .unwrap_or(0)
}

/// RFC 3339 UTC rendering of a unix timestamp (expiry surfaces show this
/// so "when exactly" needs no local conversion guesswork).
pub fn format_rfc3339(unix: i64) -> String {
    time::OffsetDateTime::from_unix_timestamp(unix)
        .map(|t| {
            t.format(&time::format_description::well_known::Rfc3339)
                .unwrap_or_default()
        })
        .unwrap_or_else(|_| unix.to_string())
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    const DAY: i64 = 86_400;

    #[test]
    fn phase_boundaries_at_20_and_10_percent() {
        let ttl = 90 * DAY;
        // 20% of 90d = 18d, 10% = 9d. "Less than" is strict: exactly at
        // the boundary the higher phase still holds.
        assert_eq!(phase_of(18 * DAY - 1, ttl), LeafPhase::Warn);
        assert_eq!(phase_of(18 * DAY, ttl), LeafPhase::Healthy);
        assert_eq!(phase_of(17 * DAY, ttl), LeafPhase::Warn);
        assert_eq!(phase_of(9 * DAY - 1, ttl), LeafPhase::Critical);
        assert_eq!(phase_of(9 * DAY, ttl), LeafPhase::Warn);
        assert_eq!(phase_of(8 * DAY, ttl), LeafPhase::Critical);
        // Comfortably inside: 45d of a 90d leaf.
        assert_eq!(phase_of(45 * DAY, ttl), LeafPhase::Healthy);
        // A fresh 180d leaf.
        assert_eq!(phase_of(179 * DAY, 180 * DAY), LeafPhase::Healthy);
    }

    #[test]
    fn expired_and_degenerate_windows_are_critical() {
        assert_eq!(phase_of(0, 90 * DAY), LeafPhase::Critical);
        assert_eq!(phase_of(-DAY, 90 * DAY), LeafPhase::Critical);
        assert_eq!(phase_of(1, 0), LeafPhase::Critical);
    }

    #[test]
    fn both_entries_agree_for_a_fully_issued_leaf() {
        let ttl = 90 * DAY;
        let now = 82 * DAY; // 8d left: under the 10% line
        let from_ttl = leaf_phase_from_ttl(ttl, ttl as u64, now);
        let from_validity = leaf_phase_from_validity(0, ttl, now);
        assert_eq!(from_ttl, from_validity);
        assert_eq!(from_ttl.phase, LeafPhase::Critical);
        assert_eq!(from_ttl.remaining_secs, 8 * DAY);
    }

    #[test]
    fn remaining_text_is_stable() {
        assert_eq!(format_remaining(45 * DAY), "45d");
        assert_eq!(format_remaining(9 * DAY), "9d");
        assert_eq!(format_remaining(23 * 3600), "<1d");
        assert_eq!(format_remaining(0), "expired");
        assert_eq!(format_remaining(-5), "expired");
    }
}
