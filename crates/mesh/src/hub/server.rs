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

use crate::config::HubConfig;
use crate::hub::accept::AcceptContext;
use crate::hub::reload::spawn_reload_task;
use crate::hub::state::SharedTlsPlane;
use crate::hub::{ActiveStream, SharedAgents, SharedHubConfig, SharedStreamCounts};
use interflow_core::error::{InterflowError, Result};
use interflow_core::security::{AuditSink, AuthRateLimiter, ConnTracker};
use interflow_core::tls::{TenantTrustRoot, TlsPlane, build_tls_plane};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;
use tokio::net::TcpListener;
use tokio::sync::RwLock;
use tracing::{info, warn};

/// Shutdown drain deadline: upper bound for waiting on connection tasks to
/// close out; on timeout, return forcibly.
const DRAIN_TIMEOUT: Duration = Duration::from_secs(10);

/// Builds the runtime TLS plane from the config's tenant trust table:
/// loads each tenant CA, builds the merged-root acceptor and the
/// per-tenant derivation set. Shared by startup and the SIGHUP reload.
pub(crate) fn build_runtime_tls_plane(cfg: &HubConfig) -> Result<TlsPlane> {
    let Some(tls) = &cfg.tls else {
        return Err(InterflowError::config(
            "mTLS requires [tls] to be configured (client certificates are verified at the TLS handshake)",
        ));
    };
    let mut roots = Vec::with_capacity(cfg.auth.tenants.len());
    for tenant in &cfg.auth.tenants {
        let pem = std::fs::read(&tenant.ca_path).map_err(|e| {
            InterflowError::config(format!(
                "tenant '{}' CA read failed ({}): {e}",
                tenant.name, tenant.ca_path
            ))
        })?;
        roots.push(TenantTrustRoot::from_pem(
            &tenant.name,
            tenant.trusted_gateway,
            &pem,
        )?);
    }
    build_tls_plane(&tls.cert_path, &tls.key_path, &roots, tls.min_version)
}

/// Hub server orchestrator.
pub struct HubServer {
    config: SharedHubConfig,
    config_path: String,
    agents: SharedAgents,
    active_streams: Arc<RwLock<HashMap<String, ActiveStream>>>,
    tls_plane: SharedTlsPlane,
    limits: crate::hub::state::HubLimits,
    rate_limiter: Option<Arc<AuthRateLimiter>>,
    stream_counts: SharedStreamCounts,
    audit: AuditSink,
    conn_tracker: Arc<ConnTracker>,
}

impl HubServer {
    /// Assembles a hub server. The mTLS TLS plane (acceptor + tenant
    /// derivation set) is initialized here; failures return an error
    /// immediately rather than being deferred to accept.
    pub fn new(config: HubConfig, config_path: String) -> Result<Self> {
        let _limits = crate::hub::state::HubLimits::from_config(&config);
        let _original_audit_config = config.audit.clone();
        let _conn_tracker = Arc::new(ConnTracker::new(
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

        // mTLS-only: the TLS plane is built from the tenant trust table.
        // Validation guarantees non-empty tenants + [tls] present; the
        // builder re-checks (the embedded edge constructs configs
        // programmatically, bypassing the config-file validator).
        let plane = build_runtime_tls_plane(&config)?;
        Self::with_tls_plane(config, config_path, plane)
    }

    /// [`Self::new`] with a prebuilt TLS plane — the embedded edge's entry
    /// point: it mixes in-memory trust roots (tenant CAs from the CLI plus
    /// the per-restart gateway principal) that have no ca_path files.
    pub fn with_tls_plane(config: HubConfig, config_path: String, plane: TlsPlane) -> Result<Self> {
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
        let tls_plane: SharedTlsPlane = Arc::new(std::sync::RwLock::new(Arc::new(plane)));
        info!(
            "mTLS enabled: {} tenant trust root(s), client certs required, identity = (tenant, CN)",
            config.auth.tenants.len()
        );

        Ok(Self {
            config: Arc::new(RwLock::new(config)),
            config_path,
            agents: Arc::new(RwLock::new(HashMap::new())),
            active_streams: Arc::new(RwLock::new(HashMap::new())),
            tls_plane,
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
            self.tls_plane.clone(),
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
        let ctx = AcceptContext {
            agents: self.agents.clone(),
            config: self.config.clone(),
            active_streams: self.active_streams.clone(),
            tls_plane: self.tls_plane.clone(),
            limits: self.limits.clone(),
            rate_limiter: self.rate_limiter.clone(),
            stream_counts: self.stream_counts.clone(),
            audit: self.audit.clone(),
            conn_tracker: self.conn_tracker.clone(),
            tasks: tasks.clone(),
            shutdown: shutdown.clone(),
        };

        crate::hub::quic::spawn_quic_listener(ctx.clone()).await?;

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
            // (significant for HTTP/2 multiplexing). Per-IP rate limiting
            // and connection caps run inside the connection task, after the
            // PROXY-protocol negotiation keys them on the real client IP.
            let _ = stream.set_nodelay(true);
            let ctx = ctx.clone();
            tasks.spawn(async move {
                if let Err(e) = crate::hub::accept::handle_connection(ctx, stream, addr).await {
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
