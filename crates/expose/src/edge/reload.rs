//! SIGHUP hot reload: re-read `routes.toml` and swap the [`HostRouter`]
//! routing table wholesale.
//!
//! Behavior mirrors `crates/mesh/src/hub/reload.rs`: a 5-second debounce
//! window; on parse failure the old table is kept.
//! No-op on non-Unix platforms.

use crate::edge::HostRouter;
use std::sync::Arc;

/// Debounce window: consecutive SIGHUPs within this window trigger only one reload.
#[cfg(unix)]
const DEBOUNCE: std::time::Duration = std::time::Duration::from_secs(5);

/// Spawns a background task listening for SIGHUP. Effective on Unix platforms only.
pub fn spawn_reload_task(routes_path: String, router: Arc<HostRouter>) {
    #[cfg(unix)]
    {
        tokio::spawn(async move {
            use tokio::signal;
            use tracing::{debug, error, info};

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
                match router.reload(&routes_path) {
                    Ok(()) => info!(host_count = router.len(), "routes.toml reloaded"),
                    Err(e) => error!(
                        error = %e,
                        "routes.toml reload failed, keeping the previous routing table"
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
