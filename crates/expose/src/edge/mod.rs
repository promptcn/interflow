//! `Edge` fused component: runs a HubServer + EdgeListener in a single process.
//!
//! Flow:
//! 1. Start [`interflow_mesh::hub::HubServer`] (listens on 127.0.0.1:internal_port, static-token auth)
//! 2. Once the hub is up, start the internal agent (agent_id=`edge`, supervised
//!    auto-reconnect) and take the session-slot tunnel facade from its handle
//! 3. Inject the tunnel into [`EdgeListener`] (listens on the public listen_addr), routing by Host to the target agent
//!
//! Public request path: client → nginx (TLS) → edge listener → tunnel (loopback HTTP/2)
//! → hub → remote expose client (egress agent, h2 or QUIC) → local service.
//!
//! Recovery model: the internal agent's session deaths (connection-level errors
//! included) are rebuilt in process by the supervisor — the facade held by the
//! listener rides across rebuilds, and during a reconnect gap opens fail fast.
//! [`watch_agent_health`] is the outer belt: only a wedged recovery (sustained
//! state silence) or a no-retry failure ends the process for a systemd restart.
//!
//! With `quic_listen` set, the embedded hub additionally accepts expose
//! clients over QUIC (one QUIC stream per tunnel stream). The edge's own
//! dial stays on h2: the hub relays across transports (h2 source ↔ quic
//! target), so enabling QUIC requires no change in the EdgeListener path.

pub mod host_router;
pub mod listener;
pub mod reload;

/// Tests and external crates reference this via `interflow_expose::edge::{Route, RoutesConfig}`.
pub use host_router::{HostRouter, Route, RoutesConfig};

use crate::edge::listener::EdgeListener;
use interflow_core::config::AuditConfig;
use interflow_core::security::{AuditSink, AuthRateLimiter, ConnTracker};
use interflow_mesh::agent::client::AgentClient;
use interflow_mesh::config::{
    AclConfig, AgentTlsConfig as TlsConfig, AuthConfig, AuthMode, ControlConfig,
    HUB_CONFIG_VERSION, HubConfig, HubQuicConfig, HubSecurityConfig, LoggingConfig, ServerConfig,
    StaticTokenConfig,
};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tracing::{error, info};

/// Host-header peek timeout for public connections (mitigates slow-loris connection dragging).
const HOST_PEEK_TIMEOUT: Duration = Duration::from_secs(10);

/// Default public-stream idle timeout in seconds. Source of the CLI `--stream-idle-timeout-secs` default.
pub const DEFAULT_STREAM_IDLE_TIMEOUT_SECS: u64 = 300;

/// Default outer health-watch timeout over the internal agent, in seconds.
/// Source of the CLI `--agent-recovery-timeout-secs` default.
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

/// The effective recovery-watch timeout: 0/nonsense is floored to 1s, and an
/// explicit override below the structural budget draws a loud warning — a
/// struggling-but-healthy agent would be restarted in a loop.
fn agent_recovery_timeout(args: &EdgeArgs) -> Duration {
    let secs = args.agent_recovery_timeout_secs.max(1);
    let budget = interflow_core::config::params::liveness::recovery_budget(
        &interflow_core::config::params::liveness::HeartbeatCadence::DEFAULT,
    );
    if Duration::from_secs(secs) < budget {
        tracing::warn!(
            effective = secs,
            structural_budget_secs = budget.as_secs(),
            "--agent-recovery-timeout-secs is below the eviction+backoff budget;              a struggling internal agent will be restart-churned"
        );
    }
    Duration::from_secs(secs)
}

/// Edge startup arguments.
pub struct EdgeArgs {
    /// Public listen address (nginx proxy_passes traffic here).
    pub listen_addr: SocketAddr,
    /// Internal hub listen address (127.0.0.1 only).
    pub hub_listen_addr: SocketAddr,
    /// Host routing table (`routes.toml` path).
    pub routes_path: String,
    /// Agent token (both edge itself and remote expose clients register with the hub using this token).
    pub agent_token: String,
    /// Optional: hub TLS certificate (if nginx already terminates TLS, edge needs no TLS of its own).
    ///
    /// When [`EdgeArgs::quic_listen`] is set, the certificate additionally
    /// serves the QUIC plane presented to public expose clients: its SAN must
    /// cover the hostname clients dial in `hub_quic_addr`, and clients must
    /// trust its issuer (public CA, or a CA distributed via `ca_path`).
    pub hub_tls: Option<EdgeHubTls>,
    /// Optional: QUIC listen address for the embedded hub (e.g.
    /// `0.0.0.0:16666`). `Some` enables the QUIC transport for expose
    /// clients; requires [`EdgeArgs::hub_tls`] (QUIC mandates TLS).
    ///
    /// Must be a publicly reachable address — unlike `hub_listen_addr`
    /// (loopback behind nginx TCP proxying), QUIC datagrams cannot ride the
    /// nginx HTTP path; the UDP port is exposed directly.
    pub quic_listen: Option<SocketAddr>,
    /// Optional: audit log JSONL path. None disables auditing.
    pub audit_path: Option<String>,
    /// Per-IP new-connection limit per minute; 0 = unlimited. Default 30.
    /// Prevents connect→peek Host→disconnect loop attacks from bypassing the concurrency cap.
    pub new_conn_rate_per_ip_per_minute: u32,
    /// Public-stream idle timeout (seconds). The pump's read/write halves share one
    /// budget: "an upper bound on surviving without bytes in either direction";
    /// must be ≤ nginx `proxy_read_timeout`.
    pub stream_idle_timeout_secs: u64,
    /// Route-level circuit breaker master switch: agent close reasons
    /// (`connect_failed` / `target_circuit_open`) are counted per host; a
    /// tripped route's new public connections are closed immediately after
    /// the Host lookup — **without** an Open through the tunnel — until a
    /// recovery probe succeeds (2026-09-16 reason-propagation hardening).
    pub route_breaker_enabled: bool,
    /// Backend-failure closes within the window required to trip a route.
    pub route_breaker_failure_threshold: u32,
    /// Sliding window (seconds) for counting backend-failure closes per route.
    pub route_breaker_window_secs: u64,
    /// Cooldown (seconds) a tripped route stays OPEN before one recovery
    /// probe connection is admitted.
    pub route_breaker_cooldown_secs: u64,
    /// Outer health-watch timeout over the internal agent (seconds): if the
    /// agent stays non-connected with **no state change at all** for this
    /// long (recovery wedged), or enters the no-retry `Failed` state, the
    /// edge exits so systemd can restart it. Normal reconnect cycling never
    /// trips this.
    pub agent_recovery_timeout_secs: u64,
}

impl Default for EdgeArgs {
    fn default() -> Self {
        Self {
            listen_addr: "0.0.0.0:0".parse().expect("valid addr"),
            hub_listen_addr: "127.0.0.1:0".parse().expect("valid addr"),
            routes_path: String::new(),
            agent_token: String::new(),
            hub_tls: None,
            quic_listen: None,
            audit_path: None,
            new_conn_rate_per_ip_per_minute: 30,
            stream_idle_timeout_secs: DEFAULT_STREAM_IDLE_TIMEOUT_SECS,
            route_breaker_enabled: true,
            route_breaker_failure_threshold: 10,
            route_breaker_window_secs: 60,
            route_breaker_cooldown_secs: 30,
            agent_recovery_timeout_secs: DEFAULT_AGENT_RECOVERY_TIMEOUT_SECS,
        }
    }
}

/// Hub TLS configuration (for users who also want TLS on the hub).
pub struct EdgeHubTls {
    /// Certificate PEM path.
    pub cert_path: String,
    /// Private key PEM path.
    pub key_path: String,
}

/// Start Edge: spawn hub + dial + run the listener. Blocks the caller.
pub async fn run(args: EdgeArgs) -> interflow_core::error::Result<()> {
    // 0. QUIC plane prerequisites, before any listener binds: the hub's QUIC
    //    listener reuses the [tls] certificate set (QUIC mandates TLS), so
    //    fail fast with a pointed message instead of dying mid-startup inside
    //    the hub task.
    if args.quic_listen.is_some() && args.hub_tls.is_none() {
        return Err(interflow_core::error::InterflowError::config(
            "enabling the QUIC listener requires --hub-cert and --hub-key (QUIC mandates TLS)",
        ));
    }

    // 1. Load the routing table
    let router = Arc::new(HostRouter::load(&args.routes_path)?);
    if router.is_empty() {
        return Err(interflow_core::error::InterflowError::config(format!(
            "routing table {} is empty; at least one [[routes]] entry is required to forward",
            args.routes_path
        )));
    }
    info!("loaded {} routes from {}", router.len(), args.routes_path);

    // 1b. Start the SIGHUP hot-reload task (Unix platforms)
    reload::spawn_reload_task(args.routes_path.clone(), Arc::clone(&router));

    // 2. Audit sink (shared by edge connection denials + hub audit events)
    let audit_cfg = AuditConfig {
        enabled: args.audit_path.is_some(),
        path: args.audit_path.clone(),
    };
    let audit = AuditSink::spawn(&audit_cfg);
    if audit_cfg.enabled {
        info!(
            "audit logging enabled → {}",
            args.audit_path.as_ref().unwrap()
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
    let rate_limiter = AuthRateLimiter::new(args.new_conn_rate_per_ip_per_minute).map(Arc::new);
    if rate_limiter.is_some() {
        info!(
            "enabled edge per-IP new-connection rate limit: {} per minute per IP",
            args.new_conn_rate_per_ip_per_minute
        );
    }

    // 4. Assemble the hub config and spawn the HubServer
    let hub_cfg = build_hub_config(&args, &audit_cfg);
    let hub_port = args.hub_listen_addr.port();
    // The edge self-dial uses cert pinning (see build_edge_agent_config), so
    // the ServerName takes no part in verification; the URL uses the 127.0.0.1
    // IP literal to avoid the localhost→::1 IPv6/IPv4 mismatch risk.
    let hub_url = if args.hub_tls.is_some() {
        format!("https://127.0.0.1:{hub_port}")
    } else {
        format!("http://127.0.0.1:{hub_port}")
    };

    let hub_server = interflow_mesh::hub::HubServer::new(hub_cfg, "<edge-in-memory>".into())?;
    let hub_task = tokio::spawn(async move { hub_server.run().await });
    info!(
        "HubServer started (internal listen {})",
        args.hub_listen_addr
    );

    // 5. Wait for the hub listener to be ready (simple retry; avoids adding a health-check channel)
    wait_for_tcp(args.hub_listen_addr, std::time::Duration::from_secs(2)).await?;

    // 6. Start the internal agent (supervised auto-reconnect): dials the
    //    local hub as `edge` and, on any session death — connection-level
    //    errors included — the supervisor reconnects and re-registers in
    //    process, the same battle-tested path every expose client runs. The
    //    tunnel handed to the listener is the session-slot facade: it rides
    //    across session rebuilds, and during a reconnect gap opens fail fast
    //    (nginx surfaces an immediate 502 instead of a black hole).
    //
    //    Background: this used to be a one-shot dial whose only fail-fast
    //    trigger was the poll watchdog — which lives inside the poll loop and
    //    dies with it on connection-level errors, leaving a zombie listener
    //    (docs/bug/2026-09-16-edge-self-dial-agent-no-reregister.md).
    let edge_agent_cfg = build_edge_agent_config(&args, &hub_url)?;
    let agent = AgentClient::new(edge_agent_cfg)?.start();
    let tunnel = agent.tunnel();
    wait_initial_registration(&agent, Duration::from_secs(30)).await?;
    info!("Edge internal agent started (agent_id=edge, supervised auto-reconnect)");

    // 7. Run the public listener; if the hub, the listener, or the internal
    //    agent's recovery dies, fail as a whole — once the hub is dead every
    //    tunnel dial from the listener fails, and continuing to serve would
    //    only produce black-hole connections. The internal agent's own
    //    session deaths are NOT in this set: the supervisor rebuilds them in
    //    process (step 6); only a supervisor that stops making progress for
    //    a sustained stretch (watch_agent_health) is a whole-process
    //    failure.
    let route_breaker = args.route_breaker_enabled.then(|| {
        std::sync::Arc::new(interflow_mesh::agent::target_breaker::TargetBreakers::new(
            interflow_mesh::agent::target_breaker::BreakerKind::Route,
            interflow_core::config::params::BreakerPolicy {
                failure_threshold: args.route_breaker_failure_threshold.max(1),
                failure_window: Duration::from_secs(args.route_breaker_window_secs.max(1)),
                cooldown: Duration::from_secs(args.route_breaker_cooldown_secs.max(1)),
            },
        ))
    });
    let listener = EdgeListener {
        listen_addr: args.listen_addr,
        router,
        tunnel,
        host_peek_timeout: HOST_PEEK_TIMEOUT,
        stream_idle_timeout: Duration::from_secs(args.stream_idle_timeout_secs),
        conn_tracker,
        rate_limiter,
        audit,
        route_breaker,
    };
    let listener_task = listener.run();
    tokio::pin!(listener_task);
    let agent_health = watch_agent_health(&agent, agent_recovery_timeout(&args));
    tokio::pin!(agent_health);
    tokio::select! {
        res = &mut listener_task => Ok(res?),
        hub_res = hub_task => {
            let reason = match hub_res {
                Ok(Ok(())) => "returned normally (should not happen)".to_string(),
                Ok(Err(e)) => e.to_string(),
                Err(e) => format!("join failed: {e}"),
            };
            Err(interflow_core::error::InterflowError::connection(format!(
                "internal HubServer has stopped: {reason}"
            )))
        }
        // Outer supervision over the internal agent (the recovery path's own
        // failure handling): the supervisor reconnecting — even struggling —
        // is normal operation; only "no Connected state and no state change
        // at all for a sustained stretch" (wedged recovery, the 2026-09-16
        // incident class) or a no-retry Failed state ends the process, letting
        // systemd restart as the final backstop.
        health = &mut agent_health => {
            error!("edge internal agent health watch tripped: {health}");
            Err(interflow_core::error::InterflowError::connection(format!(
                "edge internal agent recovery failed: {health}"
            )))
        }
    }
}

/// Waits for the internal agent's first successful registration (or fails on
/// the no-retry `Failed` state / timeout): startup must not serve a listener
/// whose tunnel facade cannot possibly work yet.
pub async fn wait_initial_registration(
    agent: &interflow_mesh::agent::AgentHandle,
    timeout: Duration,
) -> interflow_core::error::Result<()> {
    let mut rx = agent.subscribe_state();
    let deadline = tokio::time::Instant::now() + timeout;
    loop {
        // Snapshot before matching: the watch Ref (significant Drop) must not
        // live across the match scrutinee.
        let state = rx.borrow_and_update().clone();
        match state {
            interflow_mesh::agent::AgentState::Connected { agent_id } => {
                info!("edge internal agent registered as {agent_id}");
                return Ok(());
            }
            interflow_mesh::agent::AgentState::Failed { error } => {
                return Err(interflow_core::error::InterflowError::config(format!(
                    "edge internal agent failed to start: {error}"
                )));
            }
            _ => {}
        }
        if tokio::time::timeout_at(deadline, rx.changed())
            .await
            .is_err()
        {
            return Err(interflow_core::error::InterflowError::connection(format!(
                "edge internal agent did not register within {timeout:?}"
            )));
        }
    }
}

/// Outer supervision over the supervised internal agent; resolves with a
/// reason string when the process should fail fast:
///
/// - `Failed` — a configuration-class error; the supervisor will not retry.
/// - no state change at all while non-`Connected` for `recovery_timeout` —
///   the supervisor itself is wedged (a bug of the recovery path — the exact
///   class of the 2026-09-16 incident) or the hub is unreachable without the
///   supervisor even cycling states. Restarting the process is then the only
///   remaining lever (systemd `Restart=on-failure`).
///
/// Deliberately NOT tripped by: state *flapping* while non-connected
/// (`Connecting`/`Reconnecting` alternating) — that is the supervisor alive
/// and working, just not succeeding yet; churning process restarts would not
/// help and would drop the in-process hub with it. Every observed state
/// change re-arms the window; only true silence exceeds it.
pub async fn watch_agent_health(
    agent: &interflow_mesh::agent::AgentHandle,
    recovery_timeout: Duration,
) -> String {
    let mut rx = agent.subscribe_state();
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

/// Build the hub config: anonymous mode (edge itself registers with a static token),
/// with an ACL allowing edge → any.
fn build_hub_config(args: &EdgeArgs, audit_cfg: &AuditConfig) -> HubConfig {
    // ACL left empty: dynamic routing relies on token auth (AclRule is an
    // exact agent_id set with no wildcard semantics).
    HubConfig {
        config_version: HUB_CONFIG_VERSION,
        server: ServerConfig {
            listen_addr: args.hub_listen_addr,
        },
        auth: AuthConfig {
            mode: AuthMode::StaticToken,
            allow_anonymous: false,
            rate_limit_per_minute: 0,
            static_token: Some(StaticTokenConfig {
                agent: Some(args.agent_token.clone()),
                admin: None,
            }),
            mtls: None,
        },
        tls: args
            .hub_tls
            .as_ref()
            .map(|t| interflow_mesh::config::HubTlsConfig {
                enabled: true,
                cert_path: t.cert_path.clone(),
                key_path: t.key_path.clone(),
                min_version: interflow_core::tls::TlsMinVersion::V1_2,
            }),
        acl: AclConfig::default(),
        security: Default::default(),
        heartbeat: Default::default(),
        metrics: Default::default(),
        audit: audit_cfg.clone(),
        logging: LoggingConfig::default(),
        transport: interflow_mesh::config::HubTransportConfig {
            quic: HubQuicConfig {
                enabled: args.quic_listen.is_some(),
                listen_addr: args.quic_listen,
                ..HubQuicConfig::default()
            },
            ..interflow_mesh::config::HubTransportConfig::default()
        },
    }
}

/// Build edge's own agent config: dial the local hub with the `edge` id.
///
/// The self-dial stays on h2 regardless of `quic_listen`: it is a loopback
/// connection (no WAN loss to recover from), and the hub relays across
/// transports, so a QUIC expose client is reachable from this h2 tunnel.
///
/// When TLS is enabled it uses cert pinning: read `hub_tls.cert_path`, compute the
/// SHA256 fingerprint and fill it into `hub_cert_fingerprint`;
/// `AgentClient::connect_tls_pinned` verifies the leaf cert bytes with
/// `PinnedCertVerifier`, bypassing the CA + hostname chain entirely. Edge and hub
/// are the same process, so the trust model needs no CA chain; pinning also avoids
/// SAN fabrication and IP/IPv6 resolution pitfalls across versions.
fn build_edge_agent_config(
    args: &EdgeArgs,
    hub_url: &str,
) -> interflow_core::error::Result<interflow_mesh::config::AgentConfig> {
    let tls = if let Some(hub_tls) = &args.hub_tls {
        let fingerprint = sha256_of_pem_cert(&hub_tls.cert_path)?;
        Some(TlsConfig {
            enabled: true,
            ca_path: None,
            client_cert_path: None,
            client_key_path: None,
            hub_cert_fingerprint: Some(fingerprint),
        })
    } else {
        None
    };

    Ok(interflow_mesh::config::AgentConfig {
        agent: interflow_mesh::config::AgentInfo {
            id: "edge".into(),
            hub_url: hub_url.to_string(),
            auth_token: Some(args.agent_token.clone()),
            ..interflow_mesh::config::AgentInfo::default()
        },
        control: ControlConfig {
            enabled: false,
            ..ControlConfig::default()
        },
        tls,
        ..interflow_mesh::config::AgentConfig::default()
    })
}

/// Read a PEM-encoded cert file, extract the DER of the first CERTIFICATE block, and return the SHA256 hex.
fn sha256_of_pem_cert(path: &str) -> interflow_core::error::Result<String> {
    use interflow_core::error::InterflowError;
    use sha2::{Digest, Sha256};
    let pem_bytes = std::fs::read(path).map_err(|e| {
        InterflowError::config(format!("failed to read hub cert {path}")).with_source(e)
    })?;
    let der = rustls_pemfile::certs(&mut &pem_bytes[..])
        .next()
        .ok_or_else(|| {
            InterflowError::config(format!("hub cert {path} has no PEM CERTIFICATE block"))
        })?
        .map_err(|e| {
            InterflowError::config(format!("failed to parse hub cert {path}")).with_source(e)
        })?;
    let mut hasher = Sha256::new();
    hasher.update(&der);
    Ok(hex::encode(hasher.finalize()))
}

/// Repeatedly TCP-connect to the target until success or timeout.
async fn wait_for_tcp(addr: SocketAddr, timeout: std::time::Duration) -> std::io::Result<()> {
    let deadline = tokio::time::Instant::now() + timeout;
    loop {
        match tokio::net::TcpStream::connect(addr).await {
            Ok(_) => return Ok(()),
            Err(e) => {
                if tokio::time::Instant::now() >= deadline {
                    return Err(e);
                }
                tokio::time::sleep(std::time::Duration::from_millis(50)).await;
            }
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use crate::cert_gen;
    use interflow_core::tls::make_pinned_verifier;
    use rustls::client::danger::ServerCertVerifier;
    use rustls::pki_types::{ServerName, UnixTime};
    use std::io::Cursor;
    use std::path::Path;

    /// Replicates the edge self-dial path: compute the SHA256 fingerprint from hub.crt,
    /// build a `PinnedCertVerifier`; verification should pass for any ServerName
    /// (pinning ignores hostname).
    #[test]
    fn self_dial_pinned_verifier_accepts_hub_cert() {
        let dir = tempfile::tempdir().unwrap();
        let certs = cert_gen::generate(dir.path(), "tunnel.example.com").unwrap();
        let fingerprint = sha256_of_pem_cert(&certs.hub_cert).unwrap();
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

    /// The pinned verifier must reject a mismatched fingerprint — make sure it is not a blanket accept.
    #[test]
    fn self_dial_pinned_verifier_rejects_wrong_fingerprint() {
        let dir = tempfile::tempdir().unwrap();
        let certs = cert_gen::generate(dir.path(), "tunnel.example.com").unwrap();
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

    /// `sha256_of_pem_cert` should return Err for missing/invalid paths, not panic.
    #[test]
    fn sha256_of_pem_cert_handles_missing_file() {
        let result = sha256_of_pem_cert("/nonexistent/hub.crt");
        assert!(result.is_err());
    }

    /// `sha256_of_pem_cert` should return Err for files without a CERTIFICATE block.
    #[test]
    fn sha256_of_pem_cert_rejects_non_pem() {
        let dir = tempfile::tempdir().unwrap();
        let junk = dir.path().join("junk.pem");
        std::fs::write(&junk, b"not a pem file").unwrap();
        let result = sha256_of_pem_cert(junk.to_str().unwrap());
        assert!(result.is_err());
        let _ = Path::new(""); // silence unused-import warning
    }
}
