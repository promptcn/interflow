//! SIGHUP hot reload: log level, limit atomics, TLS configuration, hub configuration.

#[cfg(unix)]
use crate::config::load_hub_config;
// Unconditional: the spawn_reload_task signature references HubLimits on all
// platforms (the non-Unix body is a no-op, but the type must still resolve).
use crate::hub::state::HubLimits;
use crate::hub::{SharedHubConfig, SharedTlsAcceptor};
#[cfg(unix)]
use interflow_core::telemetry;
#[cfg(unix)]
use interflow_core::tls::build_tls_acceptor;
#[cfg(unix)]
use std::sync::atomic::Ordering;
#[cfg(unix)]
use tokio::signal;
#[cfg(unix)]
use tracing::{debug, error, info};

/// Debounce window: consecutive SIGHUPs within this window trigger at most one reload.
#[cfg(unix)]
const DEBOUNCE: std::time::Duration = std::time::Duration::from_secs(5);

/// Spawns a background task listening for SIGHUP. Only effective on Unix platforms.
///
/// What gets reloaded:
/// 1. Log level ([`telemetry::set_log_level`])
/// 2. Limit atomics (ACL toggle / stream count caps / dispatch timeout / poll grace, see [`HubLimits`])
/// 3. TLS configuration (rebuild `TlsAcceptor`)
/// 4. The entire `HubConfig`
///
/// Any failed step is logged but does not exit; the old configuration keeps
/// serving. Exits together with the task group when the hub shutdown signal fires.
pub fn spawn_reload_task(
    config_path: String,
    config_lock: SharedHubConfig,
    tls_acceptor_lock: SharedTlsAcceptor,
    limits: HubLimits,
    tasks: &tokio_util::task::TaskTracker,
    shutdown: tokio_util::sync::CancellationToken,
) {
    #[cfg(unix)]
    {
        tasks.spawn(async move {
            let mut sighup = match signal::unix::signal(signal::unix::SignalKind::hangup()) {
                Ok(s) => s,
                Err(e) => {
                    error!("Failed to register SIGHUP handler: {e}");
                    return;
                }
            };
            let mut last_reload: Option<std::time::Instant> = None;
            loop {
                tokio::select! {
                    () = shutdown.cancelled() => break,
                    _ = sighup.recv() => {}
                }
                if let Some(last) = last_reload
                    && last.elapsed() < DEBOUNCE
                {
                    debug!("SIGHUP debounce: ignoring duplicate signal");
                    continue;
                }
                last_reload = Some(std::time::Instant::now());
                info!("Received SIGHUP, reloading configuration...");
                reload_once(&config_path, &config_lock, &tls_acceptor_lock, &limits).await;
            }
        });
    }
    #[cfg(not(unix))]
    {
        let _ = (
            config_path,
            config_lock,
            tls_acceptor_lock,
            limits,
            tasks,
            shutdown,
        );
        // SIGHUP is not supported on non-Unix platforms; no-op.
    }
}

#[cfg(unix)]
async fn reload_once(
    config_path: &str,
    config_lock: &SharedHubConfig,
    tls_acceptor_lock: &SharedTlsAcceptor,
    limits: &HubLimits,
) {
    match load_hub_config(config_path) {
        Ok(new_config) => {
            // 1. Update log level
            telemetry::set_log_level(&new_config.logging.level);

            // 2. Update limit atomics (lock-free reads on the hot path)
            limits
                .acl_enabled
                .store(!new_config.acl.is_empty(), Ordering::Relaxed);

            // 3. Update TLS configuration (normalized at the loading layer: Some means enabled)
            let new_tls_acceptor = new_config
                .tls
                .as_ref()
                .and_then(|tls_config| {
                    match build_tls_acceptor(&tls_config.cert_path, &tls_config.key_path) {
                        Ok(acceptor) => Some(acceptor),
                        Err(e) => {
                            error!("TLS reload failed: {e}");
                            None
                        }
                    }
                })
                .flatten();

            {
                let mut tls_w = tls_acceptor_lock.write().await;
                *tls_w = new_tls_acceptor;
            }

            // 4. Update stream count caps and channel timeouts
            limits
                .max_streams_per_agent
                .store(new_config.security.max_streams_per_agent, Ordering::Relaxed);
            limits
                .max_streams_total
                .store(new_config.security.max_streams_total, Ordering::Relaxed);
            limits.channel_send_timeout_secs.store(
                new_config.security.channel_send_timeout_secs,
                Ordering::Relaxed,
            );
            limits
                .poll_grace_secs
                .store(new_config.security.poll_grace_secs, Ordering::Relaxed);

            // 5. Update hub configuration
            {
                let mut w = config_lock.write().await;
                *w = new_config;
            }
            info!("Configuration reloaded");
        }
        Err(e) => error!("Failed to load configuration: {e}"),
    }
}
