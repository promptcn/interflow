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
use tracing::{debug, error, info, warn};

/// Debounce window: consecutive SIGHUPs within this window trigger at most one reload.
#[cfg(unix)]
// Single-sourced with the edge routes-reload loop (core params::ops).
const DEBOUNCE: std::time::Duration = interflow_core::config::params::SIGHUP_RELOAD_DEBOUNCE;

/// Spawns a background task listening for SIGHUP. Only effective on Unix platforms.
///
/// The reload contract, made explicit (see [`restart_required_changes`]):
///
/// **Reloaded immediately** — logging level; limit atomics (ACL toggle /
/// stream caps / `channel_send_timeout` / `poll_grace`, see [`HubLimits`]);
/// the TLS acceptor; the heartbeat cadence (the loop re-reads config every
/// tick); the whole `HubConfig` document every reader sees afterwards.
///
/// **Applied to NEW connections only** — `[transport.h2]` keepalive and
/// `[transport.quic]` idle/keepalive/datagram tuning (transport configs are
/// built per accepted connection).
///
/// **Requires a restart** — `server.listen_addr`, the connection caps
/// (`security.max_connections_*`; the tracker is built once at startup),
/// `transport.quic.enabled` / `transport.quic.listen_addr` (the UDP listener
/// is bound once), and `metrics.*` (the exporter is spawned once). A reload
/// that changes any of these logs a per-field warning instead of silently
/// pretending the whole file was applied.
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

/// Fields whose values are bound into long-lived structures at startup (the
/// TCP listener, the connection tracker, the QUIC listener, the metrics
/// exporter) and therefore cannot take effect via SIGHUP. Returns the
/// dotted paths of every such field that differs between the old and the
/// new configuration, so the reload can warn per field instead of
/// silently ignoring the change.
#[cfg(unix)]
fn restart_required_changes(
    old: &crate::config::HubConfig,
    new: &crate::config::HubConfig,
) -> Vec<&'static str> {
    let mut changed = Vec::new();
    if old.server.listen_addr != new.server.listen_addr {
        changed.push("server.listen_addr");
    }
    if old.security.max_connections_per_ip != new.security.max_connections_per_ip {
        changed.push("security.max_connections_per_ip");
    }
    if old.security.max_connections_total != new.security.max_connections_total {
        changed.push("security.max_connections_total");
    }
    if old.transport.quic.enabled != new.transport.quic.enabled {
        changed.push("transport.quic.enabled");
    }
    if old.transport.quic.listen_addr != new.transport.quic.listen_addr {
        changed.push("transport.quic.listen_addr");
    }
    if old.metrics.enabled != new.metrics.enabled
        || old.metrics.listen_addr != new.metrics.listen_addr
        || old.metrics.path != new.metrics.path
    {
        changed.push("metrics.*");
    }
    changed
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
            let old_config = { config_lock.read().await.clone() };
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
                    match build_tls_acceptor(
                        &tls_config.cert_path,
                        &tls_config.key_path,
                        tls_config.min_version,
                    ) {
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

            // 5. Honest reload contract: surface every restart-required
            //    field the operator changed, instead of letting
            //    "Configuration reloaded" imply the whole file took effect.
            let restart_required = restart_required_changes(&old_config, &new_config);
            if !restart_required.is_empty() {
                warn!(
                    "SIGHUP: {} changed but only takes effect after a restart (ignored): {}",
                    restart_required.len(),
                    restart_required.join(", ")
                );
            }

            // 6. Update hub configuration
            {
                let mut w = config_lock.write().await;
                *w = new_config;
            }
            info!("Configuration reloaded");
        }
        Err(e) => error!("Failed to load configuration: {e}"),
    }
}

#[cfg(all(test, unix))]
#[allow(clippy::panic, clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use crate::config::{
        AclConfig, AuthConfig, AuthMode, HubConfig, HubSecurityConfig, MetricsConfig, ServerConfig,
        StaticTokenConfig,
    };
    use interflow_core::config::{AuditConfig, LoggingConfig};

    fn hub_config() -> HubConfig {
        HubConfig {
            config_version: crate::config::HUB_CONFIG_VERSION,
            server: ServerConfig {
                listen_addr: "127.0.0.1:6666".parse().unwrap(),
            },
            auth: AuthConfig {
                mode: AuthMode::StaticToken,
                allow_anonymous: false,
                rate_limit_per_minute: 30,
                static_token: Some(StaticTokenConfig {
                    agent: Some("t".to_string()),
                    admin: None,
                }),
                mtls: None,
            },
            tls: None,
            acl: AclConfig::default(),
            security: HubSecurityConfig::default(),
            heartbeat: crate::config::HeartbeatConfig::default(),
            transport: Default::default(),
            metrics: MetricsConfig::default(),
            audit: AuditConfig::default(),
            logging: LoggingConfig::default(),
        }
    }

    /// The contract: exactly the startup-bound fields are flagged; genuinely
    /// reloadable fields (limits, heartbeat, transport tuning, TLS) never
    /// produce a false restart warning.
    #[test]
    fn restart_required_detection_is_exact() {
        let old = hub_config();

        // Identical configs → nothing flagged.
        assert!(restart_required_changes(&old, &old).is_empty());

        // Genuinely reloadable changes → still nothing flagged.
        let mut new = hub_config();
        new.security.max_streams_per_agent = 99;
        new.security.poll_grace_secs = 45;
        new.heartbeat.interval_secs = 30;
        new.transport.h2.keepalive_interval_secs = 7;
        new.transport.quic.max_idle_timeout_ms = 45_000;
        assert!(
            restart_required_changes(&old, &new).is_empty(),
            "reloadable changes must not be flagged as restart-required"
        );

        // Each startup-bound field is flagged by name.
        let mut new = hub_config();
        new.server.listen_addr = "127.0.0.1:7777".parse().unwrap();
        assert_eq!(
            restart_required_changes(&old, &new),
            vec!["server.listen_addr"]
        );

        let mut new = hub_config();
        new.security.max_connections_per_ip = 8;
        assert_eq!(
            restart_required_changes(&old, &new),
            vec!["security.max_connections_per_ip"]
        );

        let mut new = hub_config();
        new.transport.quic.enabled = true;
        assert_eq!(
            restart_required_changes(&old, &new),
            vec!["transport.quic.enabled"]
        );

        let mut new = hub_config();
        new.metrics.enabled = true;
        assert_eq!(restart_required_changes(&old, &new), vec!["metrics.*"]);
    }
}
