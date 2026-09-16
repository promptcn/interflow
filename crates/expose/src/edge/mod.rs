//! `Edge` fused component: runs a HubServer + EdgeListener in a single process.
//!
//! Flow:
//! 1. Start [`interflow_mesh::hub::HubServer`] (listens on 127.0.0.1:internal_port, static-token auth)
//! 2. Once the hub is up, dial the local hub as agent_id=`edge` and construct an [`AgentTunnel`]
//! 3. Inject the tunnel into [`EdgeListener`] (listens on the public listen_addr), routing by Host to the target agent
//!
//! Public request path: client → nginx (TLS) → edge listener → tunnel (loopback HTTP/2)
//! → hub → remote expose client (egress agent, h2 or QUIC) → local service.
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
use interflow_core::tunnel::AgentTunnel;
use interflow_mesh::agent::client::AgentClient;
use interflow_mesh::config::{
    AGENT_CONFIG_VERSION, AclConfig, AgentTlsConfig as TlsConfig, AuthConfig, AuthMode,
    ControlConfig, HUB_CONFIG_VERSION, HubConfig, HubQuicConfig, HubSecurityConfig, LoggingConfig,
    SecurityConfig, ServerConfig, StaticTokenConfig,
};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tracing::info;

/// Host-header peek timeout for public connections (mitigates slow-loris connection dragging).
const HOST_PEEK_TIMEOUT: Duration = Duration::from_secs(10);

/// Default public-stream idle timeout in seconds. Source of the CLI `--stream-idle-timeout-secs` default.
pub const DEFAULT_STREAM_IDLE_TIMEOUT_SECS: u64 = 300;

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

    // 6. Dial the local hub as `edge` to obtain the tunnel
    let edge_agent_cfg = build_edge_agent_config(&args, &hub_url)?;
    let edge_client = AgentClient::new(edge_agent_cfg)?;
    let conn = edge_client.connect_and_register().await?;
    // Session liveness is derived from the registration negotiation (data-plane
    // Pong + poll watchdog). When the watchdog fires, edge_token.cancel() lets
    // the main select fail fast (aligning with the "fail whole if hub/listener
    // dies" philosophy; systemd restarts to self-heal), so we never keep
    // serving with a dead data plane and producing black-hole connections.
    let liveness = conn.h2_liveness();
    let edge_token = tokio_util::sync::CancellationToken::new();
    let tunnel = AgentTunnel::from_sender(
        "edge".to_string(),
        &hub_url,
        conn.send_request,
        Some(args.agent_token.clone()),
        edge_token.clone(),
        liveness,
    )?;
    info!("Edge dialed the local hub, agent_id=edge");

    // 7. Run the public listener; if the hub, the listener, or the edge's own
    //    data plane dies, fail as a whole — once the hub is dead every tunnel
    //    dial from the listener fails, and continuing to serve would only
    //    produce black-hole connections.
    let route_breaker = args.route_breaker_enabled.then(|| {
        std::sync::Arc::new(interflow_mesh::agent::target_breaker::TargetBreakers::new(
            interflow_mesh::agent::target_breaker::BreakerConfig {
                failure_threshold: args.route_breaker_failure_threshold.max(1),
                window: Duration::from_secs(args.route_breaker_window_secs.max(1)),
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
        // Poll watchdog fired (data-plane stall): fail-fast exit; systemd
        // restarts to self-heal
        () = edge_token.cancelled() => {
            Err(interflow_core::error::InterflowError::connection(
                "edge poll data-plane stall (receive-side watchdog triggered), fail-fast exit".to_string(),
            ))
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
                min_version: interflow_mesh::config::TlsVersion::V1_2,
            }),
        acl: AclConfig::default(),
        security: Default::default(),
        heartbeat: Default::default(),
        routes: Default::default(),
        metrics: Default::default(),
        audit: audit_cfg.clone(),
        logging: LoggingConfig::default(),
        quic: HubQuicConfig {
            enabled: args.quic_listen.is_some(),
            listen_addr: args.quic_listen,
            ..HubQuicConfig::default()
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
        config_version: AGENT_CONFIG_VERSION,
        agent: interflow_mesh::config::AgentInfo {
            id: "edge".into(),
            hub_url: hub_url.to_string(),
            transport: Default::default(),
            hub_quic_addr: None,
            auth_token: Some(args.agent_token.clone()),
            connect_timeout_secs: 15,
            poll_idle_timeout_secs: None,
        },
        ingress: vec![],
        egress: vec![],
        egress_backend_write_timeout_secs: 10,
        egress_resolve_timeout_secs: 5,
        egress_connect_timeout_secs: 5,
        max_incoming_streams: 256,
        max_stream_opens_per_sec: 100,
        stream_open_burst: 256,
        egress_target_breaker_enabled: true,
        egress_target_breaker_failure_threshold: 5,
        egress_target_breaker_window_secs: 10,
        egress_target_breaker_cooldown_secs: 30,
        control: ControlConfig {
            enabled: false,
            ..ControlConfig::default()
        },
        security: SecurityConfig::default(),
        tls,
        logging: LoggingConfig::default(),
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
