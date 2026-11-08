//! The agent engine's connection-quality windows — the node-side half
//! of the connection-quality face
//!
//! `doctor link` answers "is it up NOW"; chronic degradation needs a
//! window. Two in-memory rings (no persistence — a restart resets the
//! recent-trend level, the honest bound; history belongs to the
//! biography face):
//!
//! - **Reconnects**: every session establishment's instant, one-hour
//!   window — the "通几十秒即死" one-way-blackhole shape is a RECONNECT
//!   RATE, visible only over time.
//! - **Liveness RTT**: every demanding-probe roundtrip (the out-of-tree
//!   probe's own question), ten-minute window — the elapsed on answers,
//!   a timeout mark on strikes. The QUIC p99-spike portrait (3× median)
//!   was a one-off measurement; now it is a standing level.
//!
//! Both rings are written from their existing observation points (the
//! supervisor's establish counter, the probe's roundtrip) and read at
//! report time by the node-status reporter — the level doctrine again:
//! a wedged engine's reporter keeps shipping frozen numbers.

use std::collections::VecDeque;
use std::sync::Mutex;

/// The reconnect window (the backlog's "最近一小时").
pub const RECONNECT_WINDOW_SECS: u64 = 3600;
/// Bound on retained reconnect instants (far above any legitimate
/// churn; the window prune is the real bound).
const RECONNECT_CAP: usize = 256;
/// The RTT window (the backlog's 10m).
pub const RTT_WINDOW_SECS: u64 = 600;
/// Bound on retained RTT samples.
const RTT_CAP: usize = 512;
/// The p99-vs-median spike factor that earns a degradation note (the
/// 2026-09-28 QUIC portrait's criterion — p99 at 3× the median). The
/// doctor renders from it; single-sourced here.
pub const P99_SPIKE_FACTOR: u64 = 3;

/// One RTT observation: the elapsed millis of an answered demanding
/// roundtrip, or a timeout mark.
#[derive(Debug, Clone, Copy)]
struct RttSample {
    unix_ms: u64,
    /// `None` = the roundtrip went unanswered (probe deadline).
    elapsed_ms: Option<u64>,
}

#[derive(Debug, Default)]
struct Quality {
    reconnects: VecDeque<u64>,
    rtt: VecDeque<RttSample>,
}

/// The read-side level the reporter ships (mirrors the wire shape;
/// core-local so this crate's serde stays put).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ConnectionQualityFace {
    /// Establishments inside the reconnect window.
    pub reconnects_last_hour: u32,
    /// Median answered roundtrip in the RTT window (`None` = no
    /// answered sample — timeouts-only is carried by the counter).
    pub rtt_p50_ms: Option<u64>,
    /// 99th-percentile answered roundtrip.
    pub rtt_p99_ms: Option<u64>,
    /// Unanswered demanding roundtrips in the RTT window — the
    /// one-way-blackhole leading signal (probes time out while the
    /// heartbeat stays in-register).
    pub rtt_timeouts: u32,
    /// Total samples in the RTT window (answered + timeouts) — the
    /// confidence denominator.
    pub rtt_samples: u32,
}

/// The shared, process-lifetime rings.
pub struct ConnectionRings {
    inner: Mutex<Quality>,
}

impl Default for ConnectionRings {
    fn default() -> Self {
        Self::new()
    }
}

impl ConnectionRings {
    pub fn new() -> Self {
        Self {
            inner: Mutex::new(Quality::default()),
        }
    }

    /// One session establishment (the supervisor's establish point).
    pub fn note_established(&self, now_unix: u64) {
        let mut inner = self
            .inner
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        inner.reconnects.push_back(now_unix);
        while inner.reconnects.len() > RECONNECT_CAP
            || inner
                .reconnects
                .front()
                .is_some_and(|t| now_unix.saturating_sub(*t) > RECONNECT_WINDOW_SECS)
        {
            if inner.reconnects.pop_front().is_none() {
                break;
            }
        }
    }

    /// One demanding-roundtrip observation: `Some(elapsed_ms)` answered,
    /// `None` timed out.
    pub fn note_rtt(&self, elapsed_ms: Option<u64>, now_unix_ms: u64) {
        let mut inner = self
            .inner
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        inner.rtt.push_back(RttSample {
            unix_ms: now_unix_ms,
            elapsed_ms,
        });
        while inner.rtt.len() > RTT_CAP
            || inner
                .rtt
                .front()
                .is_some_and(|s| now_unix_ms.saturating_sub(s.unix_ms) > RTT_WINDOW_SECS * 1000)
        {
            if inner.rtt.pop_front().is_none() {
                break;
            }
        }
    }

    /// The level at `now_unix` (seconds — the window math's clock).
    pub fn snapshot(&self, now_unix: u64) -> ConnectionQualityFace {
        let inner = self
            .inner
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let reconnects_last_hour = u32::try_from(
            inner
                .reconnects
                .iter()
                .filter(|t| now_unix.saturating_sub(**t) <= RECONNECT_WINDOW_SECS)
                .count(),
        )
        .unwrap_or(u32::MAX);
        let now_ms = now_unix.saturating_mul(1000);
        let mut answered: Vec<u64> = Vec::new();
        let mut timeouts = 0u32;
        let mut samples = 0u32;
        for sample in &inner.rtt {
            if now_ms.saturating_sub(sample.unix_ms) > RTT_WINDOW_SECS * 1000 {
                continue;
            }
            samples = samples.saturating_add(1);
            match sample.elapsed_ms {
                Some(ms) => answered.push(ms),
                None => timeouts = timeouts.saturating_add(1),
            }
        }
        answered.sort_unstable();
        // Nearest-rank index as an exact ratio: floor((n - 1) · num / den),
        // the same value the float form produced, without the casts.
        let percentile = |num: usize, den: usize| -> Option<u64> {
            if answered.is_empty() {
                return None;
            }
            let idx = (answered.len() - 1) * num / den;
            Some(answered[idx.min(answered.len() - 1)])
        };
        ConnectionQualityFace {
            reconnects_last_hour,
            rtt_p50_ms: percentile(1, 2),
            rtt_p99_ms: percentile(99, 100),
            rtt_timeouts: timeouts,
            rtt_samples: samples,
        }
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

    #[test]
    fn reconnect_window_prunes_and_counts() {
        let rings = ConnectionRings::new();
        rings.note_established(1_000);
        rings.note_established(1_600);
        rings.note_established(1_800);
        // All three inside the hour at t=1_800.
        assert_eq!(rings.snapshot(1_800).reconnects_last_hour, 3);
        // At t=4_601 the 1_000 sample aged out (age 3_601s > 3_600s
        // window); the other two remain.
        assert_eq!(rings.snapshot(4_601).reconnects_last_hour, 2);
        // Far future: none (and the prunes keep the ring bounded).
        assert_eq!(rings.snapshot(100_000).reconnects_last_hour, 0);
    }

    #[test]
    fn rtt_percentiles_and_timeouts_over_the_window() {
        let rings = ConnectionRings::new();
        // 100 answered samples 1..=100ms at t≈0, plus 3 timeouts.
        for ms in 1..=100u64 {
            rings.note_rtt(Some(ms), 100_000_000 + ms);
        }
        for _ in 0..3 {
            rings.note_rtt(None, 100_000_200);
        }
        let face = rings.snapshot(100_100);
        assert_eq!(face.rtt_samples, 103);
        assert_eq!(face.rtt_timeouts, 3);
        assert_eq!(face.rtt_p50_ms, Some(50));
        assert_eq!(face.rtt_p99_ms, Some(99));
        // A timeouts-only window: no percentiles, the counter carries
        // the story.
        for _ in 0..10 {
            rings.note_rtt(None, 100_600_000);
        }
        let face = rings.snapshot(100_700);
        assert_eq!(face.rtt_p50_ms, None);
        assert_eq!(face.rtt_timeouts, 10);
    }
}
