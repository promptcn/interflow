//! Prometheus-snapshot assertion harness for e2e tests.
//!
//! One shared global recorder (`metrics::set_global_recorder`) + rendering
//! helpers: tests assert on counter deltas (`counter_value` matches the
//! metric family exactly, summing label variants) instead of holding
//! recorder handles. `init_tracing` wires test output to `RUST_LOG` when
//! set (silent otherwise).

use metrics_exporter_prometheus::PrometheusBuilder;
use metrics_exporter_prometheus::PrometheusHandle;
use std::sync::OnceLock;
use std::time::Duration;

/// Installs a test tracing subscriber honoring `RUST_LOG` (no-op without
/// it, so plain `cargo test` output stays clean).
pub fn init_tracing() {
    static ONCE: OnceLock<()> = OnceLock::new();
    ONCE.get_or_init(|| {
        if std::env::var("RUST_LOG").is_ok() {
            let _ = tracing_subscriber::fmt()
                .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
                .with_test_writer()
                .try_init();
        }
    });
}

/// The global recorder handle (installed on first use).
pub fn metrics_handle() -> &'static PrometheusHandle {
    static METRICS: OnceLock<PrometheusHandle> = OnceLock::new();
    METRICS.get_or_init(|| {
        let recorder = PrometheusBuilder::new().build_recorder();
        let handle = recorder.handle();
        let _ = metrics::set_global_recorder(recorder);
        handle
    })
}

/// Summed value of the counter family `metric`.
///
/// Exact-name matching on both sides:
///
/// - a bare family name (`interflow_egress_stream_closed_total`) sums every
///   rendered line of that family, label variants included;
/// - a name with a label selector (`..._total{reason="backend_closed"}`)
///   sums only lines whose rendered key equals the selector exactly.
///
/// A prefix like `foo` can never match `foobar` again (the old
/// `starts_with` did — silently corrupting assertions whenever one metric
/// name was a prefix of another).
pub fn counter_value(metric: &str) -> u64 {
    let family = metric.split('{').next().unwrap_or(metric);
    metrics_handle()
        .render()
        .lines()
        .filter_map(|line| line.split_once(' '))
        .filter(|(k, _)| {
            let key_family = k.split('{').next().unwrap_or(k);
            if metric.contains('{') {
                // selector form: the rendered key must match exactly
                *k == metric
            } else {
                key_family == family
            }
        })
        .filter_map(|(_, v)| v.trim().parse::<u64>().ok())
        .sum()
}

/// Polls until `counter_value(metric)` >= `min`; panics with the full
/// snapshot on timeout (the snapshot is the only post-mortem a global
/// recorder can offer).
pub async fn wait_counter_at_least(metric: &str, min: u64, timeout: Duration) {
    let deadline = tokio::time::Instant::now() + timeout;
    loop {
        let v = counter_value(metric);
        if v >= min {
            return;
        }
        if tokio::time::Instant::now() >= deadline {
            panic!(
                "timed out waiting for metric {metric} >= {min}, current {v} (snapshot:\n{})",
                metrics_handle().render()
            );
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
}

/// Polls an arbitrary condition until it holds or the timeout elapses
/// (200ms period); panics with `what` on timeout.
pub async fn eventually<F: Fn() -> bool>(cond: F, timeout: Duration, what: &str) {
    let deadline = tokio::time::Instant::now() + timeout;
    loop {
        if cond() {
            return;
        }
        if tokio::time::Instant::now() >= deadline {
            panic!("timed out waiting for {what}");
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    /// The old `starts_with` matching let a bare `foo` also sum `foobar`
    /// lines — silently corrupting assertions. Exact family matching must
    /// keep the two apart, and a label selector must select exactly.
    #[test]
    fn counter_value_matches_families_exactly() {
        let _ = metrics_handle(); // install the global recorder
        // Unique names so parallel test binaries never collide
        metrics::counter!("interflow_test_exact_family_total").increment(2);
        metrics::counter!("interflow_test_exact_family_total", "reason" => "a").increment(3);
        metrics::counter!("interflow_test_exact_family_total_suffix_total").increment(100);

        // bare family name: sums every label variant, nothing more
        assert_eq!(counter_value("interflow_test_exact_family_total"), 5);

        // label selector: only the matching rendered line
        assert_eq!(
            counter_value("interflow_test_exact_family_total{reason=\"a\"}"),
            3
        );

        // a name that is a strict prefix of another matches nothing extra
        assert_eq!(counter_value("interflow_test_exact_family"), 0);
        // and the longer name never bleeds into the shorter query
        assert_eq!(
            counter_value("interflow_test_exact_family_total_suffix_total"),
            100
        );

        // absent metrics read zero (never panic, never match prefixes)
        assert_eq!(counter_value("interflow_test_absent_metric_total"), 0);
    }
}
