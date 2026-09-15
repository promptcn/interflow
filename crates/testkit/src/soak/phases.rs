//! Periodic phase scheduling: a silent window at each cycle's tail, with a burst on
//! recovery; the timeline goes into the artifact.

use crate::backend::{BackendPhase, SseBackendHandle};
use std::time::{Duration, Instant};
use tokio_util::sync::CancellationToken;

/// Kind of phase (human-readable form in the artifact).
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PhaseKind {
    /// Normal sending.
    Normal,
    /// Silence (the tail silent window).
    Silent,
}

impl From<BackendPhase> for PhaseKind {
    fn from(p: BackendPhase) -> Self {
        match p {
            BackendPhase::Normal => PhaseKind::Normal,
            BackendPhase::Silent => PhaseKind::Silent,
        }
    }
}

/// One phase's start and end (Instant for analysis; converted to seconds relative to the
/// scenario start when serialized).
#[derive(Debug, Clone, Copy)]
pub struct PhaseSpan {
    pub kind: PhaseKind,
    pub start: Instant,
    pub end: Instant,
}

/// Phase timeline: silent-window attribution (whether an observed gap falls inside an
/// expected silent window).
#[derive(Debug, Clone, Default)]
pub struct PhaseTimeline {
    spans: Vec<PhaseSpan>,
}

impl PhaseTimeline {
    /// Whether the `[start, end]` interval overlaps any silent window (with `slack` of
    /// tolerance on both sides).
    pub fn overlaps_silence(&self, start: Instant, end: Instant, slack: Duration) -> bool {
        self.spans.iter().any(|s| {
            s.kind == PhaseKind::Silent
                && s.start.checked_sub(slack).is_none_or(|lo| end >= lo)
                && s.end + slack > start
        })
    }

    /// Number of silent windows.
    pub fn silence_count(&self) -> usize {
        self.spans
            .iter()
            .filter(|s| s.kind == PhaseKind::Silent)
            .count()
    }

    /// Serialize as seconds relative to `t0` (for the artifact).
    pub fn to_secs(&self, t0: Instant) -> Vec<SerializedSpan> {
        self.spans
            .iter()
            .map(|s| SerializedSpan {
                kind: s.kind,
                start_secs: s.start.duration_since(t0).as_secs_f64(),
                end_secs: s.end.duration_since(t0).as_secs_f64(),
            })
            .collect()
    }
}

/// A phase interval in the artifact.
#[derive(Debug, serde::Serialize)]
pub struct SerializedSpan {
    pub kind: PhaseKind,
    pub start_secs: f64,
    pub end_secs: f64,
}

/// Run phase scheduling until `total` is exhausted or cancelled.
///
/// Structure: `Normal(cycle - silence) → Silent(silence) → loop`; if the run ends while
/// in the Silent phase, one extra flip back to Normal is appended (so the consumer side
/// receives the recovery burst before its deadline).
pub async fn run_phases(
    backend: SseBackendHandle,
    cycle: Duration,
    silence: Duration,
    total: Duration,
    cancel: CancellationToken,
) -> PhaseTimeline {
    let t0 = Instant::now();
    let normal_for = cycle.saturating_sub(silence);
    let mut phase = BackendPhase::Normal;
    let mut span_start = t0;
    let mut spans: Vec<PhaseSpan> = Vec::new();

    loop {
        let remaining = total.saturating_sub(t0.elapsed());
        if remaining.is_zero() {
            break;
        }
        let wait = if phase == BackendPhase::Silent {
            silence.min(remaining)
        } else {
            normal_for.min(remaining)
        };
        let cancelled = tokio::select! {
            _ = tokio::time::sleep(wait) => false,
            _ = cancel.cancelled() => true,
        };
        let now = Instant::now();
        spans.push(PhaseSpan {
            kind: phase.into(),
            start: span_start,
            end: now,
        });
        span_start = now;
        phase = match phase {
            BackendPhase::Normal => BackendPhase::Silent,
            BackendPhase::Silent => BackendPhase::Normal,
        };
        backend.set_phase(phase);
        if cancelled {
            break;
        }
    }

    // Guarantee a return to Normal at the end (the consumer side can observe the
    // recovery; the timeline gets a closing interval)
    if phase == BackendPhase::Silent {
        spans.push(PhaseSpan {
            kind: PhaseKind::Silent,
            start: span_start,
            end: Instant::now(),
        });
        backend.set_phase(BackendPhase::Normal);
    }

    PhaseTimeline { spans }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tl(kinds: &[(PhaseKind, u64, u64)]) -> PhaseTimeline {
        // Fake-Instant semantics: constructing spans directly requires real Instants —
        // here they are built as offsets relative to now.
        let now = Instant::now();
        PhaseTimeline {
            spans: kinds
                .iter()
                .map(|&(k, s, e)| PhaseSpan {
                    kind: k,
                    start: now + Duration::from_secs(s),
                    end: now + Duration::from_secs(e),
                })
                .collect(),
        }
    }

    #[test]
    fn overlap_detects_silence_windows() {
        let t = tl(&[(PhaseKind::Normal, 0, 10), (PhaseKind::Silent, 10, 15)]);
        let now = Instant::now();
        // gap entirely inside the silence
        assert!(t.overlaps_silence(
            now + Duration::from_secs(10),
            now + Duration::from_secs(14),
            Duration::from_secs(1)
        ));
        // gap in the normal segment
        assert!(!t.overlaps_silence(
            now + Duration::from_secs(2),
            now + Duration::from_secs(5),
            Duration::from_secs(1)
        ));
        // gap right after the silent window's trailing edge counts as overlap within slack
        assert!(t.overlaps_silence(
            now + Duration::from_secs(15),
            now + Duration::from_secs(16),
            Duration::from_secs(2)
        ));
        assert_eq!(t.silence_count(), 1);
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn scheduler_ends_in_normal_phase() {
        use crate::backend::sse_backend;
        let (_addr, backend, _task) = sse_backend(64, Duration::from_millis(10)).await;
        let cancel = CancellationToken::new();
        // 2 cycles: 0.2s cycle / 0.1s silence / 0.5s total
        let timeline = run_phases(
            backend.clone(),
            Duration::from_millis(200),
            Duration::from_millis(100),
            Duration::from_millis(500),
            cancel,
        )
        .await;
        assert!(
            backend.phase() == BackendPhase::Normal,
            "the scheduler must end back in Normal"
        );
        assert!(timeline.silence_count() >= 1, "at least one silent window");
    }
}
