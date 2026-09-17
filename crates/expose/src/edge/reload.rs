//! SIGHUP hot reload: re-read `routes.toml` and swap the [`HostRouter`]
//! routing table wholesale, applying the optional `[logging]` section when
//! present.
//!
//! Behavior mirrors `crates/mesh/src/hub/reload.rs`: a 5-second debounce
//! window; on parse failure the old table is kept. Logging follows the same
//! contract — `level` hot-reloads via [`telemetry::set_log_level`], while a
//! `format` change only draws a "requires a restart" warning (a Subscriber
//! cannot be replaced once initialized). One parse feeds both applications,
//! so a single file read can never update routes but not logging.
//! No-op on non-Unix platforms.

use crate::edge::{HostRouter, RoutesConfig};
use std::sync::Arc;

/// Debounce window: consecutive SIGHUPs within this window trigger only one reload.
#[cfg(unix)]
// Single-sourced with the hub config-reload loop (core params::ops).
const DEBOUNCE: std::time::Duration = interflow_core::config::params::SIGHUP_RELOAD_DEBOUNCE;

/// Spawns a background task listening for SIGHUP. Effective on Unix platforms only.
pub fn spawn_reload_task(routes_path: String, router: Arc<HostRouter>) {
    #[cfg(unix)]
    {
        tokio::spawn(async move {
            use tokio::signal;
            use tracing::{debug, error, info, warn};

            let mut sighup = match signal::unix::signal(signal::unix::SignalKind::hangup()) {
                Ok(s) => s,
                Err(e) => {
                    error!("failed to register SIGHUP handler: {e}");
                    return;
                }
            };
            let mut last_reload: Option<std::time::Instant> = None;
            loop {
                sighup.recv().await;
                if let Some(last) = last_reload
                    && last.elapsed() < DEBOUNCE
                {
                    debug!("SIGHUP debounce: ignoring repeated signal");
                    continue;
                }
                last_reload = Some(std::time::Instant::now());
                info!("received SIGHUP, reloading routes.toml...");
                match RoutesConfig::load(&routes_path) {
                    Ok(cfg) => {
                        router.apply(&cfg);
                        if let Some(logging) = &cfg.logging {
                            // Warn while the previous filter is still active,
                            // then switch: the new level governs everything after.
                            if logging.format != interflow_core::telemetry::log_format() {
                                warn!(
                                    "log format change requires a restart (kept the startup format)"
                                );
                            }
                            // Only claim success when the directive actually
                            // parses; an invalid one keeps the previous level.
                            match interflow_core::telemetry::validate_log_filter(&logging.level) {
                                Ok(()) => {
                                    interflow_core::telemetry::set_log_level(&logging.level);
                                    info!(level = %logging.level, "log level reloaded");
                                }
                                Err(e) => error!(
                                    level = %logging.level,
                                    error = %e,
                                    "invalid [logging] level in routes.toml, keeping the previous log level"
                                ),
                            }
                        }
                        info!(host_count = router.len(), "routes.toml reloaded");
                    }
                    Err(e) => error!(
                        error = %e,
                        "routes.toml reload failed, keeping the previous routing table and log level"
                    ),
                }
            }
        });
    }
    #[cfg(not(unix))]
    {
        let _ = (routes_path, router);
    }
}
