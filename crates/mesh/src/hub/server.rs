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
use interflow_core::security::{AuditKind, AuditSink, AuthRateLimiter, ConnTracker};
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

/// The actually-bound hub listener addresses.
///
/// Delivered by [`HubServer::run_until_signalled`]'s readiness signal; `:0`
/// faces materialize here instead of racing a pick-then-bind window. `quic`
/// is `None` when QUIC is disabled, and equals `tcp` in derived dual-stack
/// mode (one shared port).
#[derive(Debug, Clone, Copy)]
pub struct HubReady {
    /// The TCP listener's bound address.
    pub tcp: std::net::SocketAddr,
    /// The QUIC listener's bound address (an explicit `Some(:0)`
    /// `transport.quic.listen_addr` materializes here; written back into
    /// the shared config the same way the TCP address is).
    pub quic: Option<std::net::SocketAddr>,
}

impl HubServer {
    /// Assembles a hub server around an injected audit sink. The mTLS TLS
    /// plane (acceptor + tenant derivation set) is initialized here;
    /// failures return an error immediately rather than being deferred to
    /// accept.
    ///
    /// The sink is a parameter, not a `config.audit` spawn: one process
    /// keeps one ledger (the embedded edge shares its edge sink here), and
    /// a second writer on one path corrupts both chains — see the
    /// single-writer invariant on `interflow_core::security::audit`.
    /// `config.audit` remains pure configuration data, consumed by
    /// composition roots that own the spawn decision (`pack::run_hub`,
    /// `HubHandle::spawn`).
    pub fn new(config: HubConfig, audit: AuditSink) -> Result<Self> {
        // mTLS-only: the TLS plane is built from the tenant trust table.
        // Validation guarantees non-empty tenants + [tls] present; the
        // builder re-checks (the embedded edge constructs configs
        // programmatically, bypassing the pack validator).
        let plane = build_runtime_tls_plane(&config)?;
        Self::with_tls_plane(config, plane, audit)
    }

    /// [`Self::new`] with a prebuilt TLS plane — the embedded edge's entry
    /// point: it mixes in-memory trust roots (tenant CAs from the CLI plus
    /// the stable gateway principal) that have no ca_path files. The audit
    /// sink is likewise the caller's (for the edge, the very sink its
    /// connection denials go to — one process, one ledger).
    pub fn with_tls_plane(config: HubConfig, plane: TlsPlane, audit: AuditSink) -> Result<Self> {
        let limits = crate::hub::state::HubLimits::from_config(&config);
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
        // The policy publication channel: a bad key fails assembly (never a
        // silently-dead control face).
        let policy_channel = match (
            config.policy.verifier_key_hex.clone(),
            config.policy.state_policy_dir.clone(),
        ) {
            (Some(key_hex), Some(dir)) => {
                let embedded_dir = config
                    .policy
                    .embedded_policy_dir
                    .clone()
                    .unwrap_or_else(|| dir.clone());
                // Fail-loud validity probe: hex decodes and names a real
                // verifying key, or assembly fails.
                interflow_identity::policy::RuntimePolicy::verifying_key_from_hex(&key_hex)
                    .map_err(|e| {
                        InterflowError::config("policy verifying key is malformed".to_string())
                            .with_source(e)
                    })?;
                Some(Arc::new(crate::hub::state::PolicyChannel {
                    verifier_key_hex: key_hex,
                    dir,
                    embedded_dir,
                    floor: std::sync::atomic::AtomicU64::new(config.policy.generation),
                    cached: std::sync::RwLock::new(None),
                }))
            }
            _ => None,
        };
        // The proposal queue rides the policy channel's presence (its
        // funnel validates against the serving policy) and its state dir
        // (`<pack>/state/proposals.json`, beside `state/policy`).
        //
        // A corrupt queue file is neither fatal nor silent: the data plane
        // keeps serving (a 72h-TTL approval queue must not take every
        // tenant's connectivity down), the corrupt file is quarantined
        // beside the queue, one audit event records exactly what was lost,
        // and the face restarts empty — requesters resubmit. Only when the
        // quarantine move itself fails does the face stay down: persisting
        // over the corrupt file would destroy the evidence.
        let proposals = match policy_channel.as_ref() {
            None => None,
            Some(channel) => {
                let path = channel
                    .dir
                    .parent()
                    .map(|state_dir| state_dir.join("proposals.json"));
                match crate::hub::proposals::ProposalStore::load(path.clone()) {
                    Ok(store) => Some(store),
                    Err(e) => {
                        let path_text = path
                            .as_ref()
                            .map_or_else(|| "-".to_owned(), |p| p.display().to_string());
                        let quarantined_as = path
                            .as_deref()
                            .and_then(crate::hub::proposals::quarantine_corrupt_queue);
                        warn!(
                            "proposal queue at {path_text} failed to load: {e}; quarantined as {}",
                            quarantined_as.as_ref().map_or_else(
                                || "NOTHING (move failed; proposals face stays down)".to_owned(),
                                |p| p.display().to_string()
                            )
                        );
                        audit.record(
                            AuditKind::ProposalQueueQuarantined {
                                path: path_text,
                                quarantined_as: quarantined_as
                                    .as_ref()
                                    .map(|p| p.display().to_string()),
                                error: e.to_string(),
                            },
                            None,
                            None,
                        );
                        if quarantined_as.is_some() {
                            // The corrupt file is out of the way — an empty
                            // queue with a live persistence path.
                            crate::hub::proposals::ProposalStore::load(path).ok()
                        } else {
                            None
                        }
                    }
                }
            }
        };
        let proposals = proposals.map(Arc::new);
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
            audit,
            policy_channel,
            policy_pull_ledger: Arc::new(std::sync::Mutex::new(HashMap::new())),
            proposals,
            stale_watermark_ledger: Arc::new(std::sync::Mutex::new(HashMap::new())),
            expiry_ledger: Arc::new(std::sync::Mutex::new(HashMap::new())),
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
    /// with the actually-bound listener address once the TCP listener is
    /// bound and the QUIC listener is up, just before the accept loop starts.
    /// Callers that need "accepting by the time this returns" (embedding,
    /// test harnesses) get an exact signal instead of probing the port — and
    /// a `:0` (kernel-assigned) listen address materializes here, which lets
    /// parallel tests own ports without any pick-then-bind race window.
    pub async fn run_until_signalled(
        self,
        shutdown: tokio_util::sync::CancellationToken,
        ready: tokio::sync::oneshot::Sender<HubReady>,
    ) -> Result<()> {
        self.run_until_inner(shutdown, Some(ready)).await
    }

    async fn run_until_inner(
        self,
        shutdown: tokio_util::sync::CancellationToken,
        ready: Option<tokio::sync::oneshot::Sender<HubReady>>,
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
        let bound_addr = listener.local_addr()?;
        // A `:0` listen address (kernel-assigned port) materializes here:
        // write the concrete endpoint back so the QUIC dual-stack listener
        // (which shares the port) and later config readers see the real
        // address, not the placeholder.
        if listen_addr.port() == 0 {
            self.state.config.write().await.server.listen_addr = bound_addr;
        }
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

        // The signed-policy ACL hot-swap watcher: intrinsic to a pack-built
        // hub (the config's policy plane names the pack) — every runner of
        // this future (the binary, the GUI handle, each e2e) gets it by
        // construction; no embedder wiring exists to forget
        let policy_pack_dir = state.config.read().await.policy.pack_dir.clone();
        if let Some(pack_dir) = policy_pack_dir {
            crate::pack::spawn_hub_policy_reload(
                &pack_dir,
                Arc::clone(&state.config),
                &state.shutdown,
                &state.tasks,
            );
        }

        // QUIC dual-stack listener (when enabled; failures propagate
        // immediately — configuration errors must not silently degrade)
        let quic_addr = crate::hub::quic::spawn_quic_listener(state.clone()).await?;

        // Both listeners are up (TCP bound above, QUIC spawned just before):
        // anyone waiting on the readiness signal may connect now. A dropped
        // receiver just means nobody is waiting.
        if let Some(ready) = ready {
            let _ = ready.send(HubReady {
                tcp: bound_addr,
                quic: quic_addr,
            });
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
