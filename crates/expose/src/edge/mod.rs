//! `Edge` fused component: runs a HubServer + EdgeListener in a single process.
//!
//! Flow:
//! 1. Start [`interflow_mesh::hub::HubServer`] (listens on 127.0.0.1:internal_port, mTLS-only)
//! 2. Once the hub is up, start one internal agent session **per authorized
//!    workspace** (each with that workspace's scoped ingress principal,
//!    supervised auto-reconnect) and take the session-slot tunnel facades
//! 3. Inject the tunnels into [`EdgeListener`] (listens on the public
//!    listen_addr), routing by Host to the route's workspace session
//!
//! Public request path: client → frontend proxy (TLS) → edge listener →
//! tunnel (loopback HTTP/2) → hub → remote expose client (egress agent,
//! h2 or QUIC) → local service.
//!
//! Recovery model: each internal agent's session deaths (connection-level
//! errors included) are rebuilt in process by the supervisor — the facades
//! held by the listener ride across rebuilds, and during a reconnect gap
//! opens fail fast. [`watch_agent_health`] is the outer belt over all
//! sessions: only a wedged recovery (sustained state silence) or a no-retry
//! failure ends the process for a systemd restart.
//!
//! With `quic_listen` set, the embedded hub additionally accepts expose
//! clients over QUIC (one QUIC stream per tunnel stream). The edge's own
//! dials stay on h2: the hub relays across transports (h2 source ↔ quic
//! target), so enabling QUIC requires no change in the EdgeListener path.

pub mod acme;
pub mod host_router;
pub mod ingress_identity;
pub mod listener;

pub use acme::{AcmeOptions, AcmeRuntime};
/// Tests and external crates reference this via
/// `interflow_expose::edge::{Route, HostRouter}`.
pub use host_router::{HostRouter, Route};
pub use ingress_identity::{IngressIdentity, IngressPrincipal, WorkspaceTrust};

use crate::edge::listener::{EdgeListener, WorkspaceSession};
use interflow_core::config::AuditConfig;
use interflow_core::error::{InterflowError, Result};
use interflow_core::security::ProxyProtocolConfig;
use interflow_core::security::ProxyProtocolPolicy;
use interflow_core::security::XffMode;
use interflow_core::security::XffPolicy;
use interflow_core::security::{AuditSink, AuthRateLimiter, ConnTracker};
use interflow_core::tls::TenantTrustRoot;
use interflow_mesh::agent::client::AgentClient;
use interflow_mesh::config::{
    AclConfig, AgentConfig, AgentTlsConfig as TlsConfig, AuthConfig, ControlConfig, HubConfig,
    HubQuicConfig, HubSecurityConfig, HubTlsConfig, HubTransportConfig, LoggingConfig,
    ServerConfig,
};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;
use tracing::{error, info};

/// Head-peek constants and Host validation live in core's shared
/// `http_head` module (one parser for the Host peek, XFF and ACME paths).
pub(crate) use interflow_core::security::http_head::{
    HOST_MAX_LEN, HTTP_HEAD_MAX_BYTES, is_valid_host,
};

/// Host-header peek timeout for public connections (mitigates slow-loris
/// connection dragging).
const HOST_PEEK_TIMEOUT: Duration = Duration::from_secs(10);

/// TLS handshake deadline for public connections (ACME mode): the ClientHello
/// read and the handshake completion are each bounded; a stalled handshake
/// counts `interflow_edge_tls_handshake_timeout` and the connection closes
/// silently (mitigates slow-drip ClientHello and handshake floods).
const TLS_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);

/// Default public-stream idle timeout in seconds.
pub const DEFAULT_STREAM_IDLE_TIMEOUT_SECS: u64 = 300;

/// Default per-IP new-connection rate limit per minute for direct (ACME)
/// topologies.
///
/// The browser's own HTTP keepalive keeps new connections rare, and there
/// is no front proxy to shield the listener, so a tight cap preserves most
/// of its connect-loop defense.
pub const DEFAULT_NEW_CONN_RATE_PER_IP_PER_MINUTE: u32 = 30;

/// Default per-IP new-connection rate limit per minute for fronted topologies
/// (nginx/`proxy_pass` in front).
///
/// Each proxied request opens a **new** edge connection (conn → tunnel
/// stream is one-to-one; the front cannot reuse them), so a single user's
/// normal SPA browsing alone exceeds the direct default. 600/min matches
/// the reference front's own `limit_req 10r/s` — the edge gate aligns with
/// what the front lets through anyway, while still capping connect floods
/// (see (internal design notes)).
pub const DEFAULT_FRONTED_NEW_CONN_RATE_PER_IP_PER_MINUTE: u32 = 600;

/// Default route-breaker policy (10 failures / 60s window / 30s cooldown).
pub const DEFAULT_ROUTE_BREAKER: RouteBreakerPolicy = RouteBreakerPolicy {
    enabled: true,
    failure_threshold: 10,
    failure_window_secs: 60,
    cooldown_secs: 30,
};

/// Default outer health-watch timeout over the internal agents, in seconds.
///
/// DERIVED, not hand-picked: the hub eviction dead line (75s at the default
/// cadence) + the supervisor's 30s backoff cap + one connect attempt (15s) —
/// see `interflow_core::config::params::liveness::recovery_budget`. An agent
/// struggling to reconnect inside this window is normal operation (no
/// restart churn), while true supervisor silence beyond it means the
/// recovery path itself is broken (the 2026-09-16 incident class) and only a
/// process restart can help.
pub const DEFAULT_AGENT_RECOVERY_TIMEOUT_SECS: u64 =
    interflow_core::config::params::liveness::recovery_budget(
        &interflow_core::config::params::liveness::HeartbeatCadence::DEFAULT,
    )
    .as_secs();

/// Route-level circuit breaker policy (keyed by public host).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RouteBreakerPolicy {
    /// Master switch.
    pub enabled: bool,
    /// Backend-failure closes within the window required to trip a route.
    pub failure_threshold: u32,
    /// Sliding window (seconds) for counting backend-failure closes.
    pub failure_window_secs: u64,
    /// Cooldown (seconds) a tripped route stays OPEN before one recovery
    /// probe connection is admitted.
    pub cooldown_secs: u64,
}

impl Default for RouteBreakerPolicy {
    fn default() -> Self {
        DEFAULT_ROUTE_BREAKER
    }
}

/// Public-listener governance: real-IP restoration, resource caps, and
/// timeout/breaker budgets.
#[derive(Debug, Clone)]
pub struct EdgeListenerPolicy {
    /// PROXY protocol negotiation on the public listener (restores real
    /// client IPs behind a PROXY-v2-capable front; see
    /// [`x_forwarded_for`][Self::x_forwarded_for] for the standard nginx
    /// HTTP topology).
    pub proxy_protocol: ProxyProtocolConfig,
    /// X-Forwarded-For restoration on the public listener (the standard
    /// nginx HTTP `proxy_pass` leg — stock nginx cannot emit the PROXY
    /// protocol on this leg). Shares `proxy_protocol.trusted_proxies`.
    pub x_forwarded_for: XffMode,
    /// Per-IP new-connection limit per minute; 0 = unlimited.
    pub new_conn_rate_per_ip_per_minute: u32,
    /// Public-stream idle timeout. The pump's read/write halves share one
    /// budget: "an upper bound on surviving without bytes in either
    /// direction"; must be ≤ the front proxy's `proxy_read_timeout`.
    pub stream_idle_timeout: Duration,
    /// Route-level circuit breaker (agent close reasons count per host; a
    /// tripped route's new public connections close right after the Host
    /// lookup — without an Open through the tunnel — until a recovery probe
    /// succeeds).
    pub route_breaker: RouteBreakerPolicy,
}

impl Default for EdgeListenerPolicy {
    fn default() -> Self {
        Self {
            proxy_protocol: ProxyProtocolConfig::default(),
            x_forwarded_for: XffMode::Off,
            new_conn_rate_per_ip_per_minute: DEFAULT_NEW_CONN_RATE_PER_IP_PER_MINUTE,
            stream_idle_timeout: Duration::from_secs(DEFAULT_STREAM_IDLE_TIMEOUT_SECS),
            route_breaker: RouteBreakerPolicy::default(),
        }
    }
}

/// The control endpoint's server identity (the embedded hub plane).
#[derive(Debug, Clone)]
pub struct ControlEndpointTls {
    /// Certificate PEM path.
    pub cert: PathBuf,
    /// Private key PEM path.
    pub key: PathBuf,
}

/// Public-HTTPS termination mode.
#[derive(Debug, Clone)]
pub enum PublicTls {
    /// A front proxy terminates TLS (frontend-proxy / manual): the public
    /// listener is plain TCP and restores the client IP from
    /// X-Forwarded-For / PROXY protocol.
    Fronted,
    /// The ingress terminates public HTTPS itself with ACME (HTTP-01 +
    /// TLS-ALPN-01, automatic renewal; `https://` redirect on port 80).
    Acme(AcmeOptions),
}

/// The actually-bound listener addresses of a running edge.
///
/// Delivered by [`run_until_signalled`]'s readiness signal: every `:0` face
/// materializes here instead of racing a pick-then-bind window. `control`
/// is the embedded hub (TCP+QUIC dual-stack on one port).
#[derive(Debug, Clone, Copy)]
pub struct EdgeReady {
    /// Public listener (`EdgeListener`).
    pub public: SocketAddr,
    /// Control endpoint (embedded hub server).
    pub control: SocketAddr,
    /// Control endpoint's dedicated QUIC face, when configured on its own
    /// port (a `Some(:0)` materializes here); `None` when QUIC is off or
    /// derived dual-stack (same port as `control`).
    pub control_quic: Option<SocketAddr>,
    /// ACME HTTP-01/redirect face, when enabled and successfully bound
    /// (`None` when the :80 bind failed non-fatally or ACME is off).
    pub acme_http: Option<SocketAddr>,
}

/// Edge startup configuration — typed, pack-native. Paths are filesystem
/// paths (not display strings); routes arrive resolved from the signed
/// runtime policy, never via an intermediate file.
#[derive(Debug, Clone)]

pub struct EdgeConfig {
    /// Public listen address (the front proxy passes traffic here; in ACME
    /// mode this is the TLS-terminating listener itself).
    pub listen_addr: SocketAddr,
    /// Internal control-endpoint listen address (loopback).
    pub control_listen_addr: SocketAddr,
    /// Control endpoint server identity. Mandatory: the embedded hub
    /// verifies client certificates at the TLS handshake.
    pub control_tls: ControlEndpointTls,
    /// PROXY protocol negotiation on the control listener. Fronted
    /// topologies sit behind the nginx stream fragment which emits PROXY
    /// protocol (v1 on stock nginx, v2 where available) on the
    /// mTLS-passthrough control leg; mode `On` (optional-accept, loopback
    /// trusted) keeps the edge's own headerless loopback self-dials working.
    /// Independent of `listener.proxy_protocol` (public leg uses XFF by
    /// design).
    ///
    /// Known and accepted: with pp active the hub's
    /// `AuthConfig.rate_limit_per_minute` and ConnTracker key on the real
    /// client IP, so the edge's internal self-dials share one
    /// 127.0.0.1 bucket — equivalent to the pp-off status quo (they also
    /// keyed 127.0.0.1); workspace counts are small and reconnects are
    /// backoff-supervised.
    pub control_proxy_protocol: ProxyProtocolConfig,
    /// One trust anchor per authorized workspace (its issuer CA).
    pub workspace_trust: Vec<WorkspaceTrust>,
    /// One workspace-scoped ingress principal per authorized workspace.
    /// At least one is required; every route's workspace must be covered.
    pub principals: Vec<IngressPrincipal>,
    /// Resolved routes (from the signed runtime policy, in memory).
    pub routes: Vec<Route>,
    /// Optional: QUIC listen address for the embedded control endpoint
    /// (e.g. `0.0.0.0:16666`). `Some` enables the QUIC transport for expose
    /// clients; the address must be publicly reachable (UDP datagrams
    /// cannot ride an HTTP proxy leg).
    pub quic_listen: Option<SocketAddr>,
    /// Optional audit log JSONL path. `None` disables auditing.
    pub audit_path: Option<PathBuf>,
    /// Public-listener governance.
    pub listener: EdgeListenerPolicy,
    /// Public-HTTPS termination mode.
    pub public_tls: PublicTls,
    /// Outer health-watch timeout over the internal agents: if an agent
    /// stays non-connected with **no state change at all** for this long
    /// (recovery wedged), or enters the no-retry `Failed` state, the edge
    /// exits so systemd can restart it. Normal reconnect cycling never
    /// trips this.
    pub agent_recovery_timeout: Duration,
    /// Single-public-port mode (ACME topologies): the control endpoint's
    /// server name, dispatched from the public TLS listener by ClientHello
    /// SNI. `None` keeps the control plane on its own `control_listen_addr`
    /// port only.
    pub control_dispatch_host: Option<String>,
    /// Log attribution name override (display only; `None` = the public
    /// listen address). Embedders hosting several engines in one process
    /// (the GUI) set this to a per-slot unique value so captured log lines
    /// stay separable; routing, TLS, and certificate semantics never read
    /// it. Same contract as the agent side's `ExposeArgs::log_name` /
    /// `AgentInfo::log_name`.
    pub log_name: Option<String>,
}

impl EdgeConfig {
    /// The value log sites attribute this edge's events to (display only)
    /// — the same contract as `AgentInfo::effective_log_name`, so every
    /// edge line carries the `node` field the GUI's "This node" filter
    /// matches. Standalone (CLI) runs have no override and attribute to
    /// their public listen address, which identifies the unit in journal
    /// logs.
    pub fn effective_log_name(&self) -> String {
        self.log_name
            .clone()
            .unwrap_or_else(|| self.listen_addr.to_string())
    }
}

impl Default for EdgeConfig {
    fn default() -> Self {
        Self {
            listen_addr: "0.0.0.0:0".parse().expect("valid addr"),
            control_listen_addr: "127.0.0.1:0".parse().expect("valid addr"),
            control_tls: ControlEndpointTls {
                cert: PathBuf::new(),
                key: PathBuf::new(),
            },
            control_proxy_protocol: ProxyProtocolConfig::default(),
            workspace_trust: Vec::new(),
            principals: Vec::new(),
            routes: Vec::new(),
            quic_listen: None,
            audit_path: None,
            listener: EdgeListenerPolicy::default(),
            public_tls: PublicTls::Fronted,
            agent_recovery_timeout: Duration::from_secs(DEFAULT_AGENT_RECOVERY_TIMEOUT_SECS),
            control_dispatch_host: None,
            log_name: None,
        }
    }
}

/// The effective recovery-watch timeout: nonsense values are floored to 1s,
/// and an explicit override below the structural budget draws a loud
/// warning — a struggling-but-healthy agent would be restart-churned.
fn agent_recovery_timeout(config: &EdgeConfig) -> Duration {
    let timeout = config.agent_recovery_timeout.max(Duration::from_secs(1));
    let budget = interflow_core::config::params::liveness::recovery_budget(
        &interflow_core::config::params::liveness::HeartbeatCadence::DEFAULT,
    );
    if timeout < budget {
        tracing::warn!(
            node = %config.effective_log_name(),
            effective = timeout.as_secs(),
            structural_budget_secs = budget.as_secs(),
            "agent recovery timeout is below the eviction+backoff budget; a struggling \
             internal agent will be restart-churned"
        );
    }
    timeout
}

/// Start Edge: spawn control endpoint + one session per workspace + run the
/// listener. Blocks the caller until the edge dies (no graceful stop —
/// process exit is the shutdown path).
///
/// Readiness is still signalled internally (sd_notify under a `Type=notify`
/// unit once every listener is bound; no-op elsewhere) — only the external
/// `oneshot` face of the signal is absent.
pub async fn run(config: EdgeConfig) -> Result<()> {
    // The dropped receiver turns the readiness send into a no-op; the barrier
    // (and the sd_notify it fires) runs regardless.
    let (ready, _ready_rx) = tokio::sync::oneshot::channel();
    run_until_signalled(config, tokio_util::sync::CancellationToken::new(), ready).await
}

/// [`run`] with an external shutdown signal.
///
/// Resolves `Ok(())` promptly on cancellation after a cooperative teardown —
/// the public listener stops accepting, the internal control endpoint drains
/// (GOAWAY / CONNECTION_CLOSE, its own deadline), the internal agents shut
/// down gracefully, the ACME :80 listener releases its port, and the audit
/// sink flushes. Failure exits run the same teardown before propagating.
pub async fn run_until(
    config: EdgeConfig,
    shutdown: tokio_util::sync::CancellationToken,
) -> Result<()> {
    run_until_inner(config, shutdown, None).await
}

/// [`run_until`] with an external readiness signal.
///
/// `ready` fires (and `sd_notify(READY=1)` goes out under a `Type=notify`
/// unit) once the edge actually serves — public listener bound AND control
/// endpoint up. This is the readiness channel consumers used to fake with
/// TCP liveness probes.
pub async fn run_until_signalled(
    config: EdgeConfig,
    shutdown: tokio_util::sync::CancellationToken,
    ready: tokio::sync::oneshot::Sender<EdgeReady>,
) -> Result<()> {
    run_until_inner(config, shutdown, Some(ready)).await
}

async fn run_until_inner(
    config: EdgeConfig,
    shutdown: tokio_util::sync::CancellationToken,
    ready: Option<tokio::sync::oneshot::Sender<EdgeReady>>,
) -> Result<()> {
    // Attribution for every edge-side log line (display only): the GUI's
    // "This node" filter matches on this value, the standalone CLI falls
    // back to the public listen address.
    let node = config.effective_log_name();
    // 0. The control endpoint is mTLS-only: without its server identity the
    //    handshake cannot verify client certificates — fail before any bind.
    if config.control_tls.cert.as_os_str().is_empty()
        || config.control_tls.key.as_os_str().is_empty()
    {
        return Err(InterflowError::config(
            "the control endpoint requires its server identity (cert + key)",
        ));
    }
    // 0a. Validate the identity/route graph before any listener binds.
    if config.principals.is_empty() {
        return Err(InterflowError::config(
            "the ingress requires at least one workspace principal",
        ));
    }
    let identity = Arc::new(IngressIdentity::new(
        config.principals.clone(),
        config.workspace_trust.clone(),
    )?);

    // 0a. Real-IP restoration is one mechanism per topology: the PROXY
    //     protocol preamble and the X-Forwarded-For HTTP header describe
    //     mutually exclusive fronting hops. Allowing both would make the
    //     effective-IP source ambiguous per connection.
    if config.listener.proxy_protocol.mode != interflow_core::security::ProxyProtocolMode::Off
        && config.listener.x_forwarded_for.enabled()
    {
        return Err(InterflowError::config(
            "proxy-protocol and x-forwarded-for are mutually exclusive: PROXY protocol \
             suits a PROXY-capable front (LB / nginx stream), X-Forwarded-For suits the \
             standard nginx HTTP proxy_pass leg — enable exactly one",
        ));
    }

    // 0b. Workspace trust table: each principal's chain anchors in its own
    //     workspace's issuer (no separate cross-workspace root exists).
    let mut workspace_roots = Vec::with_capacity(config.workspace_trust.len());
    for trust in &config.workspace_trust {
        let pem = std::fs::read(&trust.ca).map_err(|e| {
            InterflowError::config(format!(
                "workspace '{}' CA read failed ({})",
                trust.workspace,
                trust.ca.display()
            ))
            .with_source(e)
        })?;
        let mut crls = Vec::new();
        if let Some(crl_path) = workspace_crl_path(&trust.ca) {
            crls.push(interflow_core::tls::load_crl(&crl_path)?);
        }
        workspace_roots.push(TenantTrustRoot::from_pem_with_crls(
            &trust.workspace,
            false,
            &pem,
            &crls,
        )?);
    }

    // 1. Install the routing table (in memory, from the signed policy) and
    //    pre-assemble every route's inner-TLS material. A missing anchor or
    //    stale principal pair is a startup error, not a per-connection
    //    downgrade decision.
    let router = Arc::new(HostRouter::from_routes(&config.routes)?);
    if router.is_empty() {
        return Err(InterflowError::config(
            "the routing table is empty; at least one route is required to forward",
        ));
    }
    for route in &config.routes {
        identity.material_for(&route.workspace)?;
    }
    info!(
        node = %node,
        "edge identity: {} workspace principal(s), {} route(s)",
        config.principals.len(),
        router.len()
    );

    // 2. Audit sink (shared by edge connection denials + hub audit events)
    let audit_cfg = AuditConfig {
        enabled: config.audit_path.is_some(),
        path: config.audit_path.as_ref().map(|p| p.display().to_string()),
        // Rotation defaults (64 MiB / keep 32 / gzip) apply — a
        // long-lived edge ledger must never grow unbounded.
        rotation: Default::default(),
    };
    let audit = AuditSink::spawn(&audit_cfg);
    if audit_cfg.enabled {
        info!(
            node = %node,
            "audit logging enabled → {}",
            config.audit_path.as_ref().expect("checked").display()
        );
    }

    // 3. Connection tracker: derived from the same source as the hub defaults
    //    (HubSecurityConfig), no duplicated literals
    let hub_sec = HubSecurityConfig::default();
    let conn_tracker = Arc::new(ConnTracker::new(
        hub_sec.max_connections_per_ip,
        hub_sec.max_connections_total,
    ));

    // 3b. Per-IP new-connection rate limit (defends against connect loop
    //     attacks; checked before conn_tracker)
    let rate_limiter =
        AuthRateLimiter::new(config.listener.new_conn_rate_per_ip_per_minute).map(Arc::new);
    if rate_limiter.is_some() {
        info!(
            node = %node,
            "enabled edge per-IP new-connection rate limit: {} per minute per IP",
            config.listener.new_conn_rate_per_ip_per_minute
        );
    }

    // 4. Assemble the control endpoint config and spawn the HubServer. The
    //    TLS plane is built here from the in-memory trust table.
    let hub_cfg = build_hub_config(&config, &audit_cfg);
    let plane = interflow_core::tls::build_tls_plane(
        &config.control_tls.cert.display().to_string(),
        &config.control_tls.key.display().to_string(),
        &workspace_roots,
        interflow_core::tls::TlsMinVersion::V1_2,
    )?;
    let hub_plane_config = plane.config.clone();

    let hub_server = interflow_mesh::hub::HubServer::with_tls_plane(hub_cfg, plane)?;
    // Single-public-port mode: remember the hub's TLS configuration and a
    // serve handle before the server task owns them, so the public listener
    // can dispatch control-plane SNIs into the same plane.
    let control_dispatch =
        config
            .control_dispatch_host
            .clone()
            .map(|host| listener::ControlDispatch {
                host,
                config: hub_plane_config.clone(),
                hub: hub_server.dispatch_handle(),
            });
    // Child token: the hub drains on ANY exit path of run_until (external
    // cancellation or a component failure), not just process death.
    let hub_token = tokio_util::sync::CancellationToken::new();
    let hub_run_token = hub_token.clone();
    let (hub_ready_tx, hub_ready_rx) = tokio::sync::oneshot::channel();
    let mut hub_task = tokio::spawn(async move {
        hub_server
            .run_until_signalled(hub_run_token, hub_ready_tx)
            .await
    });
    info!(
        node = %node,
        "control endpoint starting (internal listen {})",
        config.control_listen_addr
    );

    // 5. Wait for the control endpoint's own readiness signal (TCP + QUIC
    //    bound, just before its accept loops). Replaces the old TCP
    //    self-probe: no synthetic connection, and a bind failure surfaces
    //    as the task's error instead of a probe timeout.
    let hub_start = tokio::select! {
        ready = hub_ready_rx => ready
            .map_err(|_| "exited before signalling readiness".to_string()),
        hub_res = &mut hub_task => Err(match hub_res {
            Ok(Ok(())) => "returned normally (should not happen)".to_string(),
            Ok(Err(e)) => e.to_string(),
            Err(e) => format!("join failed: {e}"),
        }),
    };
    let hub_ready = match hub_start {
        Ok(ready) => ready,
        Err(reason) => {
            return Err(InterflowError::connection(format!(
                "internal control endpoint failed to start: {reason}"
            )));
        }
    };
    let control_addr = hub_ready.tcp;
    // The edge self-dial uses cert pinning (see
    // build_workspace_agent_config), so the ServerName takes no part in
    // verification; the URL uses the hub's actually-bound IP literal (a :0
    // control port materializes above), avoiding the localhost→::1
    // IPv6/IPv4 mismatch risk.
    let hub_url = format!("https://{control_addr}");

    // 6. Start one internal agent session per workspace (supervised
    //    auto-reconnect): each dials the local control endpoint with its
    //    workspace's principal and, on any session death —
    //    connection-level errors included — the supervisor reconnects and
    //    re-registers in process, the same battle-tested path every expose
    //    client runs. The tunnels handed to the listener are session-slot
    //    facades: they ride across session rebuilds, and during a reconnect
    //    gap opens fail fast (the front proxy surfaces an immediate 502
    //    instead of a black hole).
    let mut tunnels: HashMap<String, WorkspaceSession> =
        HashMap::with_capacity(config.principals.len());
    let mut agents = Vec::with_capacity(config.principals.len());
    for principal in &config.principals {
        let (agent_id, agent_cfg) = build_workspace_agent_config(principal, &config, &hub_url)?;
        let agent = AgentClient::new(agent_cfg)?.start();
        wait_initial_registration(&node, &agent, Duration::from_secs(30)).await?;
        tunnels.insert(
            principal.workspace.clone(),
            WorkspaceSession {
                agent_id,
                tunnel: agent.tunnel(),
            },
        );
        agents.push((principal.workspace.clone(), agent));
    }
    info!(
        node = %node,
        "edge internal agents started ({} workspace session(s), supervised auto-reconnect)",
        agents.len()
    );

    // 7. Run the public listener; if the control endpoint, the listener, or
    //    any internal agent's recovery dies, fail as a whole — once the
    //    control endpoint is dead every tunnel dial from the listener fails,
    //    and continuing to serve would only produce black-hole connections.
    //    The agents' own session deaths are NOT in this set: the supervisor
    //    rebuilds them in process (step 6); only a supervisor that stops
    //    making progress for a sustained stretch (watch_agent_health) is a
    //    whole-process failure.
    let route_breaker = config.listener.route_breaker.enabled.then(|| {
        Arc::new(interflow_mesh::agent::target_breaker::TargetBreakers::new(
            interflow_mesh::agent::target_breaker::BreakerKind::Route,
            interflow_core::config::params::BreakerPolicy {
                failure_threshold: config.listener.route_breaker.failure_threshold.max(1),
                failure_window: Duration::from_secs(
                    config.listener.route_breaker.failure_window_secs.max(1),
                ),
                cooldown: Duration::from_secs(config.listener.route_breaker.cooldown_secs.max(1)),
            },
        ))
    });
    // 7a. Public-HTTPS termination: in ACME mode the ingress terminates
    //     TLS itself (HTTP-01 + TLS-ALPN-01 + renewal); in fronted modes
    //     the listener stays plain TCP behind the proxy. The :80 face gets
    //     the SAME tracker/limiter/audit instances as the :443 listener —
    //     one shared budget across both public ports, keyed on the TCP peer
    //     IP, so the documented per-IP/total limits keep one meaning.
    //     The runtime handle is kept for the teardown path (its :80
    //     listener must release the port when the edge stops).
    let mut acme_runtime: Option<acme::AcmeRuntime> = None;
    let public_tls_planes = match &config.public_tls {
        PublicTls::Fronted => None,
        PublicTls::Acme(options) => {
            let mut options = options.clone();
            // The certificate SAN set derives from the resolved routes; the
            // HTTP-01/redirect listener address stays caller-owned (the
            // pack bootstrap pins it to the public IP's port 80).
            options.hosts = config
                .routes
                .iter()
                .map(|r| r.host.clone())
                .collect::<Vec<_>>();
            let runtime = acme::spawn(
                &options,
                config.listen_addr.port(),
                &node,
                acme::AcmeConnGovernance {
                    conn_tracker: Arc::clone(&conn_tracker),
                    rate_limiter: rate_limiter.clone(),
                    audit: audit.clone(),
                },
            )?;
            let planes = listener::PublicTlsPlanes {
                challenge: runtime.challenge_config(),
                default: runtime.default_config(),
                host_allowlist: runtime.host_allowlist(),
                control: control_dispatch.map(Arc::new),
            };
            acme_runtime = Some(runtime);
            Some(planes)
        }
    };
    let proxy_policy = Arc::new(ProxyProtocolPolicy::from_config(
        &config.listener.proxy_protocol,
    )?);
    let xff_policy = Arc::new(XffPolicy::new(
        config.listener.x_forwarded_for,
        &config.listener.proxy_protocol.trusted_proxies,
    )?);
    let listener = EdgeListener {
        listen_addr: config.listen_addr,
        node: node.clone(),
        router,
        tunnels,
        tls: public_tls_planes,
        host_peek_timeout: HOST_PEEK_TIMEOUT,
        stream_idle_timeout: config.listener.stream_idle_timeout,
        conn_tracker,
        rate_limiter,
        // Clone: the original stays owned by run_until for the teardown's
        // audit flush (the listener's copy serves its connection denials).
        audit: audit.clone(),
        route_breaker,
        proxy_policy,
        xff_policy,
        identity,
    };
    let (listener_ready_tx, listener_ready_rx) = tokio::sync::oneshot::channel();
    let listener_task = listener.run_signalled(listener_ready_tx);
    tokio::pin!(listener_task);

    // Outer health supervision over every internal agent, fanned into one
    // channel so the whole-process select stays shape-stable regardless of
    // how many workspaces this ingress serves. The watchers hold state
    // subscriptions only — `agents` stays owned here for the teardown path.
    let (health_tx, mut health_rx) = tokio::sync::mpsc::channel::<(String, String)>(1);
    let recovery_timeout = agent_recovery_timeout(&config);
    for (workspace, agent) in &agents {
        let tx = health_tx.clone();
        let rx = agent.subscribe_state();
        let workspace = workspace.clone();
        tokio::spawn(async move {
            let reason = watch_agent_health(rx, recovery_timeout).await;
            let _ = tx.send((workspace, reason)).await;
        });
    }
    drop(health_tx);

    // --- Readiness barrier (run_until_signalled callers only) ---
    // The edge counts as serving once its two listener faces are up: the
    // public listener (signal above) and the control endpoint (step 5).
    // That is exactly what the old consumers faked with TCP liveness
    // probes; firing it here also releases a `Type=notify` start job via
    // sd_notify. Terminal events (listener death, cancellation, control
    // endpoint death, agent recovery failure) stay live during the wait and
    // resolve the run without firing ready. The ACME :80 face stays
    // best-effort out of the barrier by design (its bind failure is
    // non-fatal to the edge; the privilege question is tracked in the
    // ACME hardening backlog).
    let early_outcome = if let Some(outer_ready) = ready {
        let barrier = async {
            // `Err` = the listener future ended before binding — its
            // error surfaces through the steady-state select below, and
            // ready must not fire.
            if let Ok(public) = listener_ready_rx.await {
                interflow_util::systemd::notify_ready();
                // The ACME :80 bind attempt completes (or fails) within
                // microseconds of the runtime spawn — give it a bounded
                // window here so the ready snapshot carries the address
                // deterministically, while keeping the face best-effort
                // (bind failure stays None, non-fatal by design).
                let acme_http = match acme_runtime.as_ref() {
                    Some(runtime) => {
                        let deadline = tokio::time::Instant::now() + Duration::from_secs(1);
                        loop {
                            if let Some(addr) = runtime.http_local_addr() {
                                break Some(addr);
                            }
                            if tokio::time::Instant::now() >= deadline {
                                break None;
                            }
                            tokio::time::sleep(Duration::from_millis(10)).await;
                        }
                    }
                    None => None,
                };
                let _ = outer_ready.send(EdgeReady {
                    public,
                    control: control_addr,
                    control_quic: hub_ready.quic,
                    acme_http,
                });
            }
        };
        tokio::pin!(barrier);
        tokio::select! {
            () = &mut barrier => None,
            res = &mut listener_task => Some(res.map_err(InterflowError::from)),
            () = shutdown.cancelled() => Some(Ok(())),
            hub_res = &mut hub_task => Some(Err(InterflowError::connection(format!(
                "internal control endpoint has stopped: {}",
                match hub_res {
                    Ok(Ok(())) => "returned normally (should not happen)".to_string(),
                    Ok(Err(e)) => e.to_string(),
                    Err(e) => format!("join failed: {e}"),
                }
            )))),
            health = health_rx.recv() => {
                let (workspace, reason) = health.expect("senders alive until run returns");
                error!(node = %node, "edge internal agent (workspace {workspace}) health watch tripped: {reason}");
                Some(Err(InterflowError::connection(format!(
                    "edge internal agent (workspace {workspace}) recovery failed: {reason}"
                ))))
            }
        }
    } else {
        drop(listener_ready_rx);
        None
    };

    // Borrowed arms (`&mut`) keep `hub_task` owned here for the teardown.
    let outcome = if let Some(outcome) = early_outcome {
        outcome
    } else {
        tokio::select! {
            res = &mut listener_task => res.map_err(InterflowError::from),
            () = shutdown.cancelled() => Ok(()),
            hub_res = &mut hub_task => {
                let reason = match hub_res {
                    Ok(Ok(())) => "returned normally (should not happen)".to_string(),
                    Ok(Err(e)) => e.to_string(),
                    Err(e) => format!("join failed: {e}"),
                };
                Err(InterflowError::connection(format!(
                    "internal control endpoint has stopped: {reason}"
                )))
            }
            health = health_rx.recv() => {
                let (workspace, reason) = health.expect("senders alive until run returns");
                error!(node = %node, "edge internal agent (workspace {workspace}) health watch tripped: {reason}");
                Err(InterflowError::connection(format!(
                    "edge internal agent (workspace {workspace}) recovery failed: {reason}"
                )))
            }
        }
    };

    // ---- Cooperative teardown (every exit path) ----
    // Order: stop the public faces (the listener future ends with the select;
    // its in-flight connection tasks end with their streams — the same
    // boundary as process exit), release the ACME :80 port, drain the
    // internal control endpoint, shut the internal agents down, flush audit.
    // Teardown failures are logged, not propagated: the outcome of the run
    // (what the caller acts on) is already decided above.
    if let Some(acme) = &acme_runtime {
        acme.shutdown();
    }
    hub_token.cancel();
    match hub_task.await {
        Ok(Ok(())) => {}
        Ok(Err(e)) => error!(node = %node, "internal control endpoint drain failed: {e}"),
        Err(e) => error!(node = %node, "internal control endpoint task join failed: {e}"),
    }
    let stops = agents
        .into_iter()
        .map(|(_, agent)| agent.shutdown_graceful());
    for res in futures::future::join_all(stops).await {
        if let Err(e) = res {
            error!(node = %node, "internal agent shutdown failed: {e}");
        }
    }
    audit.flush().await;
    outcome
}

/// Waits for an internal agent's first successful registration (or fails on
/// the no-retry `Failed` state / timeout): startup must not serve a listener
/// whose tunnel facades cannot possibly work yet.
pub async fn wait_initial_registration(
    node: &str,
    agent: &interflow_mesh::agent::AgentHandle,
    timeout: Duration,
) -> Result<()> {
    let mut rx = agent.subscribe_state();
    let deadline = tokio::time::Instant::now() + timeout;
    loop {
        // Snapshot before matching: the watch Ref (significant Drop) must not
        // live across the match scrutinee.
        let state = rx.borrow_and_update().clone();
        match state {
            interflow_mesh::agent::AgentState::Connected { agent_id } => {
                info!(node = %node, "edge internal agent registered as {agent_id}");
                return Ok(());
            }
            interflow_mesh::agent::AgentState::Failed { error } => {
                return Err(InterflowError::config(format!(
                    "edge internal agent failed to start: {error}"
                )));
            }
            _ => {}
        }
        if tokio::time::timeout_at(deadline, rx.changed())
            .await
            .is_err()
        {
            return Err(InterflowError::connection(format!(
                "edge internal agent did not register within {timeout:?}"
            )));
        }
    }
}

/// Outer supervision over one supervised internal agent; resolves with a
/// reason string when the process should fail fast:
///
/// - `Failed` — a configuration-class error; the supervisor will not retry.
/// - no state change at all while non-`Connected` for `recovery_timeout` —
///   the supervisor itself is wedged (a bug of the recovery path — the exact
///   class of the 2026-09-16 incident) or the control endpoint is
///   unreachable without the supervisor even cycling states. Restarting the
///   process is then the only remaining lever (systemd `Restart=on-failure`).
///
/// Deliberately NOT tripped by: state *flapping* while non-connected
/// (`Connecting`/`Reconnecting` alternating) — that is the supervisor alive
/// and working, just not succeeding yet; churning process restarts would not
/// help and would drop the in-process control endpoint with it. Every
/// observed state change re-arms the window; only true silence exceeds it.
pub async fn watch_agent_health(
    agent: tokio::sync::watch::Receiver<interflow_mesh::agent::AgentState>,
    recovery_timeout: Duration,
) -> String {
    let mut rx = agent;
    loop {
        let state = rx.borrow_and_update().clone();
        match state {
            interflow_mesh::agent::AgentState::Connected { .. } => {
                // Healthy: wait for the next transition, unbounded.
                if rx.changed().await.is_err() {
                    return "agent state channel closed".to_string();
                }
            }
            interflow_mesh::agent::AgentState::Failed { error } => {
                return format!("agent failed (no-retry error): {error}");
            }
            other => {
                // Non-connected with a re-armed window: any further state
                // change (the supervisor cycling) re-arms it again; only
                // total silence trips. A stream END here (changed()
                // erroring rather than timing out) is a dead supervisor —
                // before the 2026-09-16 hardening this branch spun on it
                // in a hot loop instead of tripping the recovery.
                match tokio::time::timeout(recovery_timeout, rx.changed()).await {
                    Ok(Ok(())) => {}
                    Ok(Err(_)) => {
                        return "agent state channel closed while not Connected — supervisor died"
                            .to_string();
                    }
                    Err(_) => {
                        return format!(
                            "agent stayed in {other:?} with no state change for over \
                             {recovery_timeout:?} — supervisor recovery presumed wedged"
                        );
                    }
                }
            }
        }
    }
}

/// Build the control endpoint config: mTLS-only, one trust entry per
/// workspace issuer. Workspace isolation is enforced by the control
/// endpoint's default inter-workspace-deny policy — each session opens only
/// within its own workspace, so no ACL entries are needed for routing.
fn build_hub_config(config: &EdgeConfig, audit_cfg: &AuditConfig) -> HubConfig {
    HubConfig {
        server: ServerConfig {
            listen_addr: config.control_listen_addr,
            // The embedded control endpoint logs under the edge's
            // attribution (the hub engine's own `node_name` mechanism), so
            // its lines land in the hosting node's log view too.
            node_name: Some(config.effective_log_name()),
            // Fronted topologies: the nginx stream fragment fronts the
            // control leg with PROXY protocol (see `control_proxy_protocol`);
            // direct topologies keep the default (off) — the TCP peer is
            // the agent.
            proxy_protocol: config.control_proxy_protocol.clone(),
        },
        // The trust table is injected via `with_tls_plane` (in-memory roots);
        // this config section carries only the rate limit.
        auth: AuthConfig {
            rate_limit_per_minute: 30,
            tenants: Vec::new(),
        },
        tls: Some(HubTlsConfig {
            enabled: true,
            cert_path: config.control_tls.cert.display().to_string(),
            key_path: config.control_tls.key.display().to_string(),
            min_version: interflow_core::tls::TlsMinVersion::V1_2,
        }),
        acl: AclConfig::default(),
        security: Default::default(),
        heartbeat: Default::default(),
        metrics: Default::default(),
        audit: audit_cfg.clone(),
        // No policy publication face on the embedded expose edge — that is
        // the mesh hub's control plane.
        policy: Default::default(),
        logging: LoggingConfig::default(),
        transport: HubTransportConfig {
            quic: HubQuicConfig {
                // Three states: None = QUIC off for the control endpoint.
                // Some(:0) = derived dual-stack — the QUIC listener follows
                // the control TCP port (when control is also :0, the hub's
                // TCP write-back lands before the QUIC spawn reads it, so
                // both faces share one kernel-assigned port). Some(concrete)
                // = an explicit QUIC face on its own port.
                enabled: config.quic_listen.is_some(),
                listen_addr: config.quic_listen.filter(|a| a.port() != 0),
                ..HubQuicConfig::default()
            },
            ..HubTransportConfig::default()
        },
    }
}

fn workspace_crl_path(anchor: &Path) -> Option<String> {
    // Live refresh first, the rotate-embedded snapshot (trust/crls) second —
    // mirrors interflow_identity::pack::crl_path_for (the engine crate
    // deliberately does not depend on the identity crate).
    let pack_root = anchor.parent()?.parent()?;
    let stem = anchor.file_stem()?.to_string_lossy();
    let file = format!("{stem}.crl.pem");
    let live = pack_root.join("state").join("crls").join(&file);
    if live.is_file() {
        return Some(live.display().to_string());
    }
    let embedded = pack_root.join("trust").join("crls").join(&file);
    embedded.is_file().then(|| embedded.display().to_string())
}

/// Build one workspace session's agent config: dial the local control
/// endpoint with that workspace's principal.
///
/// The self-dial stays on h2 regardless of `quic_listen`: it is a loopback
/// connection (no WAN loss to recover from), and the control endpoint
/// relays across transports, so a QUIC expose client is reachable from
/// this h2 tunnel.
///
/// Outer endpoint verification uses cert pinning: read the control
/// certificate, compute the SHA256 fingerprint and fill it into
/// `hub_cert_fingerprint`; `AgentClient` verifies the leaf cert bytes with
/// `PinnedCertVerifier`, bypassing the CA + hostname chain entirely. Edge
/// and control endpoint are the same process, so the trust model needs no
/// CA chain; pinning also avoids SAN fabrication and IP/IPv6 resolution
/// pitfalls across versions.
fn build_workspace_agent_config(
    principal: &IngressPrincipal,
    config: &EdgeConfig,
    hub_url: &str,
) -> Result<(String, AgentConfig)> {
    let fingerprint = sha256_of_pem_cert(&config.control_tls.cert)?;
    let agent_id =
        interflow_core::tls::extract_cn_from_pem_file(&principal.cert.display().to_string())?
            .ok_or_else(|| {
                InterflowError::config(format!(
                    "ingress principal {} has no CN — the engine id is CN-bound",
                    principal.cert.display()
                ))
            })?;
    let trust = config
        .workspace_trust
        .iter()
        .find(|t| t.workspace == principal.workspace)
        .ok_or_else(|| {
            InterflowError::config(format!(
                "workspace {:?} has an ingress principal but no trust anchor",
                principal.workspace
            ))
        })?;
    let tls = Some(TlsConfig {
        enabled: true,
        // Outer endpoint verification is pinned above. This anchor also
        // seeds the mandatory inner runtime: the workspace CA verifies both
        // this principal's own chain and the peer agents of its workspace.
        ca_path: Some(trust.ca.display().to_string()),
        client_cert_path: Some(principal.cert.display().to_string()),
        client_key_path: Some(principal.key.display().to_string()),
        hub_cert_fingerprint: Some(fingerprint),
    });

    Ok((
        agent_id.clone(),
        AgentConfig {
            agent: interflow_mesh::config::AgentInfo {
                id: agent_id,
                hub_url: hub_url.to_string(),
                // The internal agents log under the edge's attribution (the
                // agent engine's own `log_name` mechanism), so their lines
                // land in the hosting node's log view too.
                log_name: Some(config.effective_log_name()),
                ..interflow_mesh::config::AgentInfo::default()
            },
            control: ControlConfig {
                enabled: false,
                ..ControlConfig::default()
            },
            tls,
            ..AgentConfig::default()
        },
    ))
}

/// Read a PEM-encoded cert file, extract the DER of the first CERTIFICATE
/// block, and return the SHA256 hex.
fn sha256_of_pem_cert(path: &std::path::Path) -> Result<String> {
    use interflow_core::error::InterflowError;
    let path_display = path.display().to_string();
    let pem_bytes = std::fs::read(path).map_err(|e| {
        InterflowError::config(format!(
            "failed to read control endpoint cert {path_display}"
        ))
        .with_source(e)
    })?;
    let der = rustls_pemfile::certs(&mut &pem_bytes[..])
        .next()
        .ok_or_else(|| {
            InterflowError::config(format!(
                "control endpoint cert {path_display} has no PEM CERTIFICATE block"
            ))
        })?
        .map_err(|e| {
            InterflowError::config(format!(
                "failed to parse control endpoint cert {path_display}"
            ))
            .with_source(e)
        })?;
    Ok(interflow_util::sha256_hex(&der))
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use interflow_certs::SanName;
    use interflow_core::tls::make_pinned_verifier;
    use rustls::client::danger::ServerCertVerifier;
    use rustls::pki_types::{ServerName, UnixTime};
    use std::io::Cursor;

    /// Replicates the edge self-dial path: compute the SHA256 fingerprint
    /// from the control endpoint cert, build a `PinnedCertVerifier`;
    /// verification should pass for any ServerName (pinning ignores
    /// hostname).
    #[test]
    fn self_dial_pinned_verifier_accepts_control_cert() {
        let dir = tempfile::tempdir().unwrap();
        let certs = interflow_certs::generate(
            dir.path(),
            &[SanName::Dns("tunnel.example.com".to_owned())],
            "main",
            &[],
        )
        .unwrap();
        let fingerprint = sha256_of_pem_cert(&PathBuf::from(&certs.hub_cert)).unwrap();
        assert_eq!(fingerprint.len(), 64, "SHA256 hex should be 64 characters");

        let verifier = make_pinned_verifier(&fingerprint).unwrap();
        let pem = std::fs::read(&certs.hub_cert).unwrap();
        let der = rustls_pemfile::certs(&mut Cursor::new(&pem))
            .next()
            .unwrap()
            .unwrap();
        let end_entity = der;

        // Pinning ignores ServerName: 127.0.0.1 (the actual URL host of the
        // edge self-dial) should pass
        let name: ServerName<'static> = "127.0.0.1".try_into().unwrap();
        let result = verifier.verify_server_cert(&end_entity, &[], &name, &[], UnixTime::now());
        assert!(
            result.is_ok(),
            "pinned verifier should accept a matching fingerprint: {:?}",
            result.err()
        );

        // Any DNS name should also pass — pinning does not look at ServerName
        let name: ServerName<'static> = "anything.local".try_into().unwrap();
        let result = verifier.verify_server_cert(&end_entity, &[], &name, &[], UnixTime::now());
        assert!(
            result.is_ok(),
            "pinned verifier should ignore ServerName: {:?}",
            result.err()
        );
    }

    /// The pinned verifier must reject a mismatched fingerprint — make sure
    /// it is not a blanket accept.
    #[test]
    fn self_dial_pinned_verifier_rejects_wrong_fingerprint() {
        let dir = tempfile::tempdir().unwrap();
        let certs = interflow_certs::generate(
            dir.path(),
            &[SanName::Dns("tunnel.example.com".to_owned())],
            "main",
            &[],
        )
        .unwrap();
        let wrong_hex = "0".repeat(64);
        let verifier = make_pinned_verifier(&wrong_hex).unwrap();
        let pem = std::fs::read(&certs.hub_cert).unwrap();
        let der = rustls_pemfile::certs(&mut Cursor::new(&pem))
            .next()
            .unwrap()
            .unwrap();
        let end_entity = der;
        let name: ServerName<'static> = "127.0.0.1".try_into().unwrap();
        let result = verifier.verify_server_cert(&end_entity, &[], &name, &[], UnixTime::now());
        assert!(
            result.is_err(),
            "pinned verifier must not accept a wrong fingerprint"
        );
    }

    /// `sha256_of_pem_cert` should return Err for missing/invalid paths,
    /// not panic.
    #[test]
    fn sha256_of_pem_cert_handles_missing_file() {
        let result = sha256_of_pem_cert(&PathBuf::from("/nonexistent/hub.crt"));
        assert!(result.is_err());
    }

    /// `sha256_of_pem_cert` should return Err for files without a
    /// CERTIFICATE block.
    #[test]
    fn sha256_of_pem_cert_rejects_non_pem() {
        let dir = tempfile::tempdir().unwrap();
        let junk = dir.path().join("junk.pem");
        std::fs::write(&junk, b"not a pem file").unwrap();
        let result = sha256_of_pem_cert(&junk);
        assert!(result.is_err());
    }
}
