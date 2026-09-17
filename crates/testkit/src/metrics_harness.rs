//! Prometheus-snapshot assertion harness for e2e tests.
//!
//! One shared global recorder (`metrics::set_global_recorder`) + rendering
//! helpers: tests assert on counter deltas (`counter_value` sums every
//! metric whose name starts with the prefix, covering label variants)
//! instead of holding recorder handles. `init_tracing` wires test output
//! to `RUST_LOG` when set (silent otherwise).

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

/// Summed value of every counter whose rendered name starts with
/// `metric_prefix` (label variants included).
pub fn counter_value(metric_prefix: &str) -> u64 {
    metrics_handle()
        .render()
        .lines()
        .filter_map(|line| line.split_once(' '))
        .filter(|(k, _)| k.starts_with(metric_prefix))
        .filter_map(|(_, v)| v.trim().parse::<u64>().ok())
        .sum()
}

/// Polls until `counter_value(prefix) >= min`; panics with the full
/// snapshot on timeout (the snapshot is the only post-mortem a global
/// recorder can offer).
pub async fn wait_counter_at_least(metric_prefix: &str, min: u64, timeout: Duration) {
    let deadline = tokio::time::Instant::now() + timeout;
    loop {
        let v = counter_value(metric_prefix);
        if v >= min {
            return;
        }
        if tokio::time::Instant::now() >= deadline {
            panic!(
                "timed out waiting for metric {metric_prefix} >= {min}, current {v} (snapshot:\n{})",
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
