//! `HubServer` — slim orchestrator.
//!
//! Only responsible for: assembling configuration, starting TLS, assembling
//! shared state, spawning the SIGHUP task, and the accept loop.
//! All concrete logic lives in submodules:
//! - Authentication and routing: [`crate::hub::service`]
//! - `/register`: [`crate::hub::registration`]
//! - `/stream`: [`crate::hub::routing`]
//! - `/poll`: [`crate::hub::poll`]
//! - `/agents`: [`crate::hub::handlers`]
//! - TLS: [`interflow_core::tls`]
//! - Hot reload: [`crate::hub::reload`]
//! - accept: [`crate::hub::accept`]
//! - Auth rate limiting: [`interflow_core::security::rate_limit`]

use crate::config::AuthMode;
use crate::config::HubConfig;
use crate::hub::accept::{AcceptContext, handle_connection};
use crate::hub::reload::spawn_reload_task;
use crate::hub::{
    ActiveStream, SharedAgents, SharedHubConfig, SharedStreamCounts, SharedTlsAcceptor,
};
use interflow_core::error::Result;
use interflow_core::security::{AuditKind, AuditSink, AuthRateLimiter, ConnTracker};
use interflow_core::tls::{build_mtls_acceptor, build_tls_acceptor};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;
use tokio::net::TcpListener;
use tokio::sync::RwLock;
use tracing::{info, warn};

/// Shutdown drain deadline: upper bound for waiting on connection tasks to
/// close out; on timeout, return forcibly.
const DRAIN_TIMEOUT: Duration = Duration::from_secs(10);

/// Hub server orchestrator.
pub struct HubServer {
    config: SharedHubConfig,
    config_path: String,
    agents: SharedAgents,
    active_streams: Arc<RwLock<HashMap<String, ActiveStream>>>,
    tls_acceptor: SharedTlsAcceptor,
    limits: crate::hub::state::HubLimits,
    rate_limiter: Option<Arc<AuthRateLimiter>>,
    stream_counts: SharedStreamCounts,
    audit: AuditSink,
    conn_tracker: Arc<ConnTracker>,
}

impl HubServer {
    /// Assembles a hub server. TLS is initialized here (failures return an
    /// error immediately rather than being deferred to accept).
    pub fn new(config: HubConfig, config_path: String) -> Result<Self> {
        let limits = crate::hub::state::HubLimits::from_config(&config);
        let original_audit_config = config.audit.clone();
        let conn_tracker = Arc::new(ConnTracker::new(
            config.security.max_connections_per_ip,
            config.security.max_connections_total,
        ));

        let rate_limiter = AuthRateLimiter::new(config.auth.rate_limit_per_minute).map(Arc::new);
        if rate_limiter.is_some() {
            info!(
                "Auth rate limiting enabled: {} requests/min/IP",
                config.auth.rate_limit_per_minute
            );
        }

        // Normalized at the loading layer: Some(tls) means enabled.
        let tls_acceptor = if let Some(tls_config) = &config.tls {
            match config.auth.mode {
                AuthMode::Mtls => {
                    let Some(mtls_cfg) = &config.auth.mtls else {
                        return Err(interflow_core::error::InterflowError::config(
                            "[auth] mode = \"mtls\" is missing the [auth.mtls] section".to_string(),
                        ));
                    };
                    info!("mTLS enabled (client cert required, CN bound to agent identity)");
                    Some(build_mtls_acceptor(
                        &tls_config.cert_path,
                        &tls_config.key_path,
                        &mtls_cfg.ca_path,
                        tls_config.min_version,
                    )?)
                }
                AuthMode::StaticToken | AuthMode::Anonymous => {
                    info!("TLS enabled (no client cert verification)");
                    build_tls_acceptor(
                        &tls_config.cert_path,
                        &tls_config.key_path,
                        tls_config.min_version,
                    )?
                }
            }
        } else {
            if matches!(config.auth.mode, AuthMode::Mtls) {
                warn!(
                    "[auth] mode = \"mtls\" but [tls] is not configured; starting without TLS, authentication is effectively anonymous"
                );
            }
            None
        };

        Ok(Self {
            config: Arc::new(RwLock::new(config)),
            config_path,
            agents: Arc::new(RwLock::new(HashMap::new())),
            active_streams: Arc::new(RwLock::new(HashMap::new())),
            tls_acceptor: Arc::new(RwLock::new(tls_acceptor)),
            limits,
            rate_limiter,
            stream_counts: Arc::new(std::sync::Mutex::new(HashMap::new())),
            audit: AuditSink::spawn(&original_audit_config),
            conn_tracker,
        })
    }

    /// Runs until the server dies (error or task end) — the embedding entry
    /// point (e.g. the expose edge), where hub death is a whole-process
    /// failure and no graceful shutdown exists. Equivalent to
    /// [`Self::run_until`] with a token that never fires.
    pub async fn run(self) -> Result<()> {
        self.run_until(tokio_util::sync::CancellationToken::new())
            .await
    }

    /// Runs until `shutdown` fires or an error occurs; completes a graceful
    /// drain before returning.
    ///
    /// Drain order: stop TCP accept → close the QUIC endpoint (CONNECTION_CLOSE
    /// delivered to all agents) → GOAWAY on h2 connections → wait for the task
    /// group to close out (deadline [`DRAIN_TIMEOUT`]; on timeout return
    /// forcibly, connections still open are closed by process exit / runtime
    /// drop) → flush the audit log.
    pub async fn run_until(self, shutdown: tokio_util::sync::CancellationToken) -> Result<()> {
        self.run_until_inner(shutdown, None).await
    }

    /// [`Self::run_until`] with an external readiness signal: `ready` fires
    /// once the TCP listener is bound and the QUIC listener is up, just
    /// before the accept loop starts. Callers that need "accepting by the
    /// time this returns" (embedding, test harnesses) get an exact signal
    /// instead of probing the port.
    pub async fn run_until_signalled(
        self,
        shutdown: tokio_util::sync::CancellationToken,
        ready: tokio::sync::oneshot::Sender<()>,
    ) -> Result<()> {
        self.run_until_inner(shutdown, Some(ready)).await
    }

    async fn run_until_inner(
        self,
        shutdown: tokio_util::sync::CancellationToken,
        ready: Option<tokio::sync::oneshot::Sender<()>>,
    ) -> Result<()> {
        let listen_addr = { self.config.read().await.server.listen_addr };
        let listener = TcpListener::bind(&listen_addr).await?;
        info!("Hub server listening on: {}", listen_addr);

        // Background task group: reload / QUIC listener / per-connection tasks
        // all attach to the tracker; drain waits for all of them
        let tasks = tokio_util::task::TaskTracker::new();

        // Spawn the SIGHUP hot-reload task
        spawn_reload_task(
            self.config_path.clone(),
            self.config.clone(),
            self.tls_acceptor.clone(),
            self.limits.clone(),
            &tasks,
            shutdown.clone(),
        );

        // Global heartbeat supervision loop: a single managed task serves all
        // agents (liveness checks + Ping dispatch), eliminating per-agent
        // stray heartbeat tasks (2026-09-13 root fix for data-plane stalls,
        // mechanism B).
        crate::hub::heartbeat::spawn_heartbeat_supervisor(
            crate::hub::state::HubHandles {
                agents: self.agents.clone(),
                active_streams: self.active_streams.clone(),
                stream_counts: self.stream_counts.clone(),
                audit: self.audit.clone(),
                config: self.config.clone(),
                poll_grace_secs: self.limits.poll_grace_secs.clone(),
            },
            &tasks,
            shutdown.clone(),
        );

        // QUIC dual-stack listener (when enabled; failures propagate
        // immediately — configuration errors must not silently degrade)
        crate::hub::quic::spawn_quic_listener(AcceptContext {
            agents: self.agents.clone(),
            config: self.config.clone(),
            active_streams: self.active_streams.clone(),
            tls_acceptor: self.tls_acceptor.clone(),
            limits: self.limits.clone(),
            rate_limiter: self.rate_limiter.clone(),
            stream_counts: self.stream_counts.clone(),
            audit: self.audit.clone(),
            tasks: tasks.clone(),
            shutdown: shutdown.clone(),
        })
        .await?;

        let conn_tracker = self.conn_tracker.clone();
        let ctx = AcceptContext {
            agents: self.agents.clone(),
            config: self.config.clone(),
            active_streams: self.active_streams.clone(),
            tls_acceptor: self.tls_acceptor.clone(),
            limits: self.limits.clone(),
            rate_limiter: self.rate_limiter.clone(),
            stream_counts: self.stream_counts.clone(),
            audit: self.audit.clone(),
            tasks: tasks.clone(),
            shutdown: shutdown.clone(),
        };

        // Both listeners are up (TCP bound above, QUIC spawned just before):
        // anyone waiting on the readiness signal may connect now. A dropped
        // receiver just means nobody is waiting.
        if let Some(ready) = ready {
            let _ = ready.send(());
        }

        loop {
            let (stream, addr) = tokio::select! {
                () = shutdown.cancelled() => break,
                res = listener.accept() => res?,
            };
            // TCP_NODELAY: disable Nagle to reduce small-packet latency
            // (significant for HTTP/2 multiplexing)
            let _ = stream.set_nodelay(true);
            // Connection-level rate limiting: check synchronously before
            // spawning the task (avoids wasting resources on a handshake
            // before rejection)
            let Some(guard) = conn_tracker.try_acquire(addr.ip()) else {
                metrics::counter!("interflow_hub_conn_rejected").increment(1);
                self.audit.record(
                    AuditKind::ConnLimitExceeded {
                        peer_ip: addr.ip().to_string(),
                        scope: "conn_limit".into(),
                    },
                    None,
                    Some(addr.to_string()),
                );
                warn!("Connection rejected (per-IP or global limit exceeded): {addr}");
                drop(stream); // explicit close
                continue;
            };

            let ctx = ctx.clone();
            tasks.spawn(async move {
                // guard auto-releases on Drop when the task ends
                let _guard = guard;
                if let Err(e) = handle_connection(ctx, stream, addr).await {
                    tracing::error!("Connection handling failed: {}", e);
                }
            });
        }

        // ---- Graceful drain ----
        info!(
            "Hub shutting down: no longer accepting connections, draining (limit {DRAIN_TIMEOUT:?})"
        );
        tasks.close();
        if tokio::time::timeout(DRAIN_TIMEOUT, tasks.wait())
            .await
            .is_err()
        {
            warn!(
                "Hub drain timed out ({} connections not closed out), returning forcibly",
                self.conn_tracker.total()
            );
        }
        self.audit.flush().await;
        info!("Hub has shut down");
        Ok(())
    }
}
