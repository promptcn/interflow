//! Logging and metrics initialization.
//!
//! - [`set_log_level`] supports re-setting the level at runtime via SIGHUP.
//! - [`init_logging`] accepts `format = "plain" | "json"`, defaulting to plain.
//! - [`init_metrics`] starts the Prometheus exporter on a dedicated listener.

use serde::{Deserialize, Serialize};
use std::sync::OnceLock;
use tracing_subscriber::reload::Handle;
use tracing_subscriber::{EnvFilter, Registry, layer::SubscriberExt, util::SubscriberInitExt};

type LogHandle = Handle<EnvFilter, Registry>;

static LOG_HANDLE: OnceLock<LogHandle> = OnceLock::new();

/// Log format.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum LogFormat {
    /// Plain text (default).
    #[default]
    Plain,
    /// Structured JSON.
    Json,
}

/// Initializes logging (first call) or updates the level (subsequent calls).
///
/// `format` only takes effect on the first call — a Subscriber cannot be
/// replaced once initialized.
pub fn init_logging(level: &str, format: LogFormat) {
    if let Some(handle) = LOG_HANDLE.get() {
        match EnvFilter::try_new(level) {
            Ok(env_filter) => {
                if let Err(e) = handle.reload(env_filter) {
                    tracing::warn!("failed to hot-reload log level (keeping previous level): {e}");
                }
            }
            Err(e) => {
                // A typo in a hot-reloaded filter must not silently drop the
                // process back to `info`; keep the previous level and say so.
                tracing::warn!("invalid log level filter {level:?} (keeping previous level): {e}");
            }
        }
        return;
    }

    let env_filter = EnvFilter::try_new(level).unwrap_or_else(|_| EnvFilter::new("info"));
    let (filter_layer, reload_handle) = tracing_subscriber::reload::Layer::new(env_filter);

    match LOG_HANDLE.set(reload_handle) {
        Ok(()) => {
            let registry = tracing_subscriber::registry().with(filter_layer);
            match format {
                LogFormat::Plain => registry
                    .with(tracing_subscriber::fmt::layer().with_target(true))
                    .init(),
                LogFormat::Json => registry
                    .with(tracing_subscriber::fmt::layer().with_target(true).json())
                    .init(),
            }
        }
        // Concurrent initialization race: another thread already initialized;
        // this thread's format choice is discarded.
        Err(_winner) => tracing::debug!(
            "logging already initialized by a concurrent call, ignoring this format argument"
        ),
    }
}

/// Updates the log level at runtime (equivalent to `init_logging(level, LogFormat::Plain)`).
pub fn set_log_level(level: &str) {
    init_logging(level, LogFormat::Plain);
}

/// Starts the Prometheus exporter on the given address. Failures only log, never abort.
///
/// Note: in the current version of metrics-exporter-prometheus 0.17 the path
/// is fixed at `/metrics`; the `path` parameter is only used for log display.
pub fn init_metrics(listen_addr: std::net::SocketAddr, path: &str) {
    match metrics_exporter_prometheus::PrometheusBuilder::new()
        .with_http_listener(listen_addr)
        .install()
    {
        Ok(()) => {
            tracing::info!("Prometheus metrics enabled: http://{listen_addr}{path}");
        }
        Err(e) => tracing::warn!("failed to enable Prometheus metrics: {e}"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The OnceLock global makes the first-init path single-shot for the
    /// whole test binary, so the init/hot-reload sequence lives in one test.
    #[test]
    fn init_then_hot_reload_survives_invalid_filters() {
        init_logging("info", LogFormat::Plain);
        // Hot switch: the level reloads; the format of the first call stays
        // in effect — a Subscriber cannot be replaced once initialized.
        set_log_level("interflow_mesh=debug");
        set_log_level("debug");
        // An invalid directive must not panic (previous level kept).
        set_log_level("interflow_mesh=not-a-level");
    }
}
