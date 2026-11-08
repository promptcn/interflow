//! Logging and metrics initialization.
//!
//! - [`set_log_level`] supports re-setting the level at runtime via SIGHUP.
//! - [`init_logging`] accepts `format = "plain" | "json"`, defaulting to plain;
//!   ANSI color follows [`ansi_enabled`] (`NO_COLOR` / `CLICOLOR_FORCE` / tty).
//! - [`TARGET_TRANSPORT_STATS`] is the filterable target of the QUIC
//!   transport-stats samplers.
//! - [`init_metrics`] starts the Prometheus exporter on a dedicated listener.

use serde::{Deserialize, Serialize};
use std::io::IsTerminal;
use std::sync::OnceLock;
use tracing_subscriber::reload::Handle;
use tracing_subscriber::{EnvFilter, Registry, layer::SubscriberExt, util::SubscriberInitExt};

type LogHandle = Handle<EnvFilter, Registry>;

static LOG_HANDLE: OnceLock<LogHandle> = OnceLock::new();

/// Dedicated tracing target of the QUIC transport-stats samplers.
///
/// Hub-side and egress-side twins sample at a 10 s cadence. The
/// CC-forensics anchor of the 2026-09-16 quic-stall case file must stay
/// reachable without opening crate-wide debug — enable with a filter
/// directive like `info,transport_stats=debug`.
pub const TARGET_TRANSPORT_STATS: &str = "transport_stats";

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
                    .with(
                        tracing_subscriber::fmt::layer()
                            .with_target(true)
                            .with_ansi(ansi_enabled()),
                    )
                    .init(),
                LogFormat::Json => registry
                    .with(
                        tracing_subscriber::fmt::layer()
                            .with_target(true)
                            .with_ansi(false)
                            .json(),
                    )
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

/// ANSI coloring decision for log output.
///
/// Conventional precedence: `NO_COLOR` (any non-empty value) turns color
/// off unconditionally; `CLICOLOR_FORCE` (any value other than `0`) forces
/// it on; otherwise color follows whether stdout is a terminal. Redirected
/// output (files, pipes) therefore carries no escape sequences.
pub fn ansi_enabled() -> bool {
    let no_color = std::env::var_os("NO_COLOR").is_some_and(|v| !v.is_empty());
    let force = std::env::var_os("CLICOLOR_FORCE").is_some_and(|v| v != "0");
    decide_ansi(no_color, force, std::io::stdout().is_terminal())
}

const fn decide_ansi(no_color: bool, force_color: bool, is_tty: bool) -> bool {
    if no_color {
        false
    } else {
        force_color || is_tty
    }
}

/// Starts the Prometheus exporter on the given address.
///
/// Failures only log, never abort. Returns the address the exporter is
/// reachable on — a `:0` (kernel-assigned) port materializes here, so
/// callers hosting the exporter on an ephemeral port read it from this
/// instead of racing a pick-then-bind window.
///
/// Note: in the current version of metrics-exporter-prometheus (0.18) the
/// path is fixed at `/metrics`, and the builder accepts only a `SocketAddr`
/// (no pre-bound listener, no address report). The port is therefore
/// materialized by a synchronous bind→read→release→hand-off sequence inside
/// this function — the release-to-rebind gap is a few microseconds on one
/// thread, the tightest the upstream API allows.
pub fn init_metrics(listen_addr: std::net::SocketAddr, path: &str) -> Option<std::net::SocketAddr> {
    let actual = {
        let probe = std::net::TcpListener::bind(listen_addr).ok()?;
        probe.local_addr().ok()?
    };
    match metrics_exporter_prometheus::PrometheusBuilder::new()
        .with_http_listener(actual)
        .install()
    {
        Ok(()) => {
            tracing::info!("Prometheus metrics enabled: http://{actual}{path}");
            Some(actual)
        }
        Err(e) => {
            tracing::warn!("failed to enable Prometheus metrics: {e}");
            None
        }
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

    #[test]
    fn ansi_decision_precedence() {
        // NO_COLOR wins over everything.
        assert!(!decide_ansi(true, true, true));
        // CLICOLOR_FORCE keeps color on non-terminals (piping into a pager).
        assert!(decide_ansi(false, true, false));
        // Default: follow the terminal.
        assert!(decide_ansi(false, false, true));
        assert!(!decide_ansi(false, false, false));
    }

    #[test]
    fn transport_stats_target_is_stable_and_filterable() {
        // A bare word without `::` — EnvFilter matches it as a target
        // directive distinct from every module path, and the filter string
        // soak/config files rely on stays stable.
        assert_eq!(TARGET_TRANSPORT_STATS, "transport_stats");
        assert!(!TARGET_TRANSPORT_STATS.contains("::"));
        assert!(EnvFilter::try_new(format!("info,{TARGET_TRANSPORT_STATS}=debug")).is_ok());
    }
}
