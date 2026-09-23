//! `HubServer` — slim orchestrator.
//!
//! Only responsible for: assembling configuration, starting TLS, assembling
//! shared state, and the accept loop.
//! All concrete logic lives in submodules:
//! - Authentication and routing: [`crate::hub::service`]
//! - `/register`: [`crate::hub::registration`]
//! - `/stream`: [`crate::hub::routing`]
//! - `/poll`: [`crate::hub::poll`]
//! - `/agents`: [`crate::hub::handlers`]
//! - TLS: [`interflow_core::tls`]
//! - accept: [`crate::hub::accept`]
//! - Auth rate limiting: [`interflow_core::security::rate_limit`]

use crate::config::HubConfig;
use crate::hub::SharedHubConfig;
use crate::hub::state::HubState;
use crate::hub::state::SharedTlsPlane;
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
/// per-tenant derivation set.
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
                "tenant '{}' CA read failed ({})",
                tenant.name, tenant.ca_path
            ))
            .with_source(e)
        })?;
        let mut crls = Vec::new();
        if let Some(crl_path) = &tenant.crl_path {
            crls.push(interflow_core::tls::load_crl(crl_path)?);
        }
        roots.push(TenantTrustRoot::from_pem_with_crls(
            &tenant.name,
            tenant.trusted_gateway,
            &pem,
            &crls,
        )?);
    }
    build_tls_plane(&tls.cert_path, &tls.key_path, &roots, tls.min_version)
}

/// Hub server orchestrator.
pub struct HubServer {
    state: Arc<HubState>,
}

impl HubServer {
    /// Assembles a hub server. The mTLS TLS plane (acceptor + tenant
    /// derivation set) is initialized here; failures return an error
    /// immediately rather than being deferred to accept.
    pub fn new(config: HubConfig) -> Result<Self> {
        // mTLS-only: the TLS plane is built from the tenant trust table.
        // Validation guarantees non-empty tenants + [tls] present; the
        // builder re-checks (the embedded edge constructs configs
        // programmatically, bypassing the pack validator).
        let plane = build_runtime_tls_plane(&config)?;
        Self::with_tls_plane(config, plane)
    }

    /// [`Self::new`] with a prebuilt TLS plane — the embedded edge's entry
    /// point: it mixes in-memory trust roots (tenant CAs from the CLI plus
    /// the stable gateway principal) that have no ca_path files.
    pub fn with_tls_plane(config: HubConfig, plane: TlsPlane) -> Result<Self> {
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
        let config: SharedHubConfig = Arc::new(RwLock::new(config));
        let state = Arc::new(HubState {
            agents: Arc::new(RwLock::new(HashMap::new())),
            route_leases: Arc::new(RwLock::new(HashMap::new())),
            config,
            active_streams: Arc::new(RwLock::new(HashMap::new())),
            tls_plane,
            limits,
            rate_limiter,
            stream_counts: Arc::new(std::sync::Mutex::new(HashMap::new())),
            audit: AuditSink::spawn(&original_audit_config),
            conn_tracker,
            tasks: tokio_util::task::TaskTracker::new(),
            shutdown: tokio_util::sync::CancellationToken::new(),
        });

        Ok(Self { state })
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

    /// A handle for fronting listeners that dispatch already-handshaken
    /// connections into this hub (the ingress's public-port SNI
    /// multiplexing). Cheap to clone; shares the hub's state and lifecycle.
    pub fn dispatch_handle(&self) -> HubDispatchHandle {
        HubDispatchHandle {
            state: Arc::clone(&self.state),
        }
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
        let (listen_addr, node) = {
            let config = self.state.config.read().await;
            (
                config.server.listen_addr,
                config
                    .server
                    .node_name
                    .clone()
                    .unwrap_or_else(|| "hub".to_string()),
            )
        };
        let listener = TcpListener::bind(&listen_addr).await?;
        info!(node = %node, "Hub server listening on: {listen_addr}");

        // Background task group: QUIC listener / per-connection tasks
        // all attach to the tracker; drain waits for all of them
        let tasks = tokio_util::task::TaskTracker::new();
        // Adopt this run's shutdown token + task group into the shared state:
        // connection tasks, the QUIC listener, and the drain all select on
        // the SAME token (the constructor's placeholder is per-run replaced).
        let state = Arc::new(HubState {
            tasks: tasks.clone(),
            shutdown: shutdown.clone(),
            ..(*self.state).clone()
        });

        // Global heartbeat supervision loop: a single managed task serves all
        // agents (liveness checks + Ping dispatch), eliminating per-agent
        // stray heartbeat tasks (2026-09-13 root fix for data-plane stalls,
        // mechanism B).
        crate::hub::heartbeat::spawn_heartbeat_supervisor(
            state.clone(),
            &state.tasks,
            state.shutdown.clone(),
        );

        // QUIC dual-stack listener (when enabled; failures propagate
        // immediately — configuration errors must not silently degrade)
        crate::hub::quic::spawn_quic_listener(state.clone()).await?;

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
            let conn_state = state.clone();
            state.tasks.spawn(async move {
                if let Err(e) =
                    crate::hub::accept::handle_connection(conn_state, stream, addr).await
                {
                    tracing::error!("Connection handling failed: {}", e);
                }
            });
        }

        // ---- Graceful drain ----
        info!(
            node = %node,
            "Hub shutting down: no longer accepting connections, draining (limit {DRAIN_TIMEOUT:?})"
        );
        tasks.close();
        if tokio::time::timeout(DRAIN_TIMEOUT, tasks.wait())
            .await
            .is_err()
        {
            warn!(
                node = %node,
                "Hub drain timed out ({} connections not closed out), returning forcibly",
                state.conn_tracker.total()
            );
        }
        state.audit.flush().await;
        info!(node = %node, "Hub has shut down");
        Ok(())
    }
}

/// Serves connections a fronting listener already handshook with the hub
/// plane's own configuration.
///
/// The ingress's public 443 dispatches control-plane SNIs here.
/// Admission (rate limit, connection caps)
/// was already held by the dispatching listener; identity, tenant derivation
/// and the h2 service are exactly the TCP accept loop's.
#[derive(Clone)]
pub struct HubDispatchHandle {
    state: Arc<HubState>,
}

impl HubDispatchHandle {
    /// Serves one dispatched mTLS connection until it closes.
    pub async fn serve_tls<S>(
        &self,
        stream: tokio_rustls::server::TlsStream<S>,
        peer: std::net::SocketAddr,
    ) -> Result<()>
    where
        S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
    {
        crate::hub::accept::serve_established(Arc::clone(&self.state), stream, peer, peer.ip())
            .await
    }
}
