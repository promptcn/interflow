//! Metrics utilities: nearest-rank percentiles over nanos samples and aggregate types.

/// Per-stream latency statistics (samples in nanos).
#[derive(Debug, Clone, Copy, serde::Serialize)]
pub struct LatencyStats {
    /// Number of samples.
    pub samples: usize,
    /// p50 (nanos).
    pub p50_ns: u64,
    /// p95 (nanos).
    pub p95_ns: u64,
    /// p99 (nanos).
    pub p99_ns: u64,
    /// Maximum (nanos).
    pub max_ns: u64,
}

/// Sort in place and compute latency quantiles. Empty samples return all zeros.
pub fn latency_stats(mut samples: Vec<u64>) -> LatencyStats {
    if samples.is_empty() {
        return LatencyStats {
            samples: 0,
            p50_ns: 0,
            p95_ns: 0,
            p99_ns: 0,
            max_ns: 0,
        };
    }
    samples.sort_unstable();
    let max = samples[samples.len() - 1];
    LatencyStats {
        samples: samples.len(),
        p50_ns: percentile(&samples, 0.50),
        p95_ns: percentile(&samples, 0.95),
        p99_ns: percentile(&samples, 0.99),
        max_ns: max,
    }
}

/// Nearest-rank percentile: `sorted[(ceil(p*n)-1)]`.
/// Panics on an empty ascending-sorted input — callers use the [`latency_stats`]
/// wrapper instead.
pub fn percentile(sorted: &[u64], p: f64) -> u64 {
    assert!(!sorted.is_empty(), "percentile of empty");
    let n = sorted.len();
    let rank = ((p * n as f64).ceil() as usize).clamp(1, n);
    sorted[rank - 1]
}

/// Human-readable duration (<1s uses ms with 2 decimals; >=1s uses seconds).
pub fn fmt_ms(ns: u64) -> String {
    let ms = ns as f64 / 1e6;
    if ms >= 1000.0 {
        format!("{:.2}s", ms / 1000.0)
    } else {
        format!("{ms:.2}ms")
    }
}
