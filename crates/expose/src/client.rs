//! Local client for `interflow-expose expose <port>`.
//!
//! Builds a minimal `AgentConfig` in memory (a single egress rule, loopback
//! security policy) and reuses `interflow_mesh::agent::AgentClient` to run
//! the full egress agent protocol. Users never write toml — CLI arguments +
//! profile suffice.

use interflow_core::protocol::StreamProto;
use interflow_mesh::agent::{AgentClient, AgentHandle};
use interflow_mesh::config::{
    AgentConfig, AgentInfo, AgentTlsConfig as TlsConfig, ControlConfig, EgressRule, TransportKind,
};

/// Arguments needed to build the expose client.
#[derive(Clone)]
pub struct ExposeArgs {
    /// Local service ports (e.g. 3000); when routing by host, edge names the concrete
    /// remote_addr in the Open frame. The list is non-empty; each port maps to one
    /// egress rule (used as the fallback).
    pub local_ports: Vec<u16>,
    /// Hub URL.
    pub hub_url: String,
    /// Local agent_id — must equal the client certificate's CN (the hub binds
    /// identity at registration).
    pub agent_id: String,
    /// Client certificate PEM path (mTLS: the hub accepts nothing else).
    pub client_cert: Option<String>,
    /// Client key PEM path (0600).
    pub client_key: Option<String>,
    /// Trusted CA path (required when the hub uses a self-signed cert; None uses the system CA).
    pub ca_path: Option<String>,
    /// Transport toward the hub (h2 default; quic eliminates TCP head-of-line
    /// blocking but requires UDP egress).
    pub transport: TransportKind,
    /// Hub QUIC address (`host:port`). `None` derives it from `hub_url`'s
    /// host:port at config-assembly time (valid when the edge runs the QUIC
    /// listener on the same port number as its hub TCP listener — the
    /// dual-stack default).
    pub hub_quic_addr: Option<String>,
}

/// Derives the default agent_id: `expose-<hostname>-<random 4 bytes>`.
pub fn default_agent_id() -> String {
    let host = hostname_or_unknown();
    let rand4 = &uuid::Uuid::new_v4().to_string()[..8];
    format!("expose-{host}-{rand4}")
}

fn hostname_or_unknown() -> String {
    std::env::var("HOSTNAME")
        .or_else(|_| std::env::var("COMPUTERNAME"))
        .ok()
        .unwrap_or_else(|| "unknown".into())
}

/// Build tag (date + git hash injected at compile time by build.rs; also effective
/// when a GUI links this crate — no more guessing from file mtimes whether a binary
/// contains a fix).
const BUILD_TAG: &str = concat!(
    env!("INTERFLOW_BUILD_DATE"),
    "_",
    env!("INTERFLOW_GIT_HASH")
);

/// fd soft-limit raise (unix): baseline headroom for a long-running network proxy,
/// **not** a substitute for fixing leaks.
///
/// macOS GUI processes often get a soft limit of 256 — under internet-facing
/// tunneling, legitimate concurrency (browser multi-connections + scanner churn)
/// can exhaust it. Raise to min(hard limit, 65536), never lower; on failure only
/// warn (e.g. container hard-limit policies) — startup is unaffected.
#[cfg(unix)]
fn raise_nofile_limit() {
    const TARGET: u64 = 65_536;
    let Ok((soft, hard)) = rlimit::Resource::NOFILE.get() else {
        tracing::warn!("failed to read RLIMIT_NOFILE, keeping the current limit");
        return;
    };
    let new_soft = TARGET.min(hard);
    if new_soft <= soft {
        tracing::info!("fd soft limit {soft} already sufficient (hard limit {hard})");
        return;
    }
    match rlimit::Resource::NOFILE.set(new_soft, hard) {
        Ok(()) => tracing::info!("fd soft limit raised: {soft} -> {new_soft} (hard limit {hard})"),
        Err(e) => tracing::warn!("failed to raise fd soft limit ({soft} -> {new_soft}): {e}"),
    }
}

#[cfg(not(unix))]
fn raise_nofile_limit() {}

/// Assemble an in-memory AgentConfig and start the agent supervisor, returning the
/// handle immediately.
///
/// GUI / callers that need lifecycle control use this entry point;
/// see [`AgentHandle`] for state subscription and graceful shutdown.
pub fn start(args: &ExposeArgs) -> Result<AgentHandle, interflow_core::error::InterflowError> {
    if args.local_ports.is_empty() {
        return Err(interflow_core::error::InterflowError::config(
            "ExposeArgs.local_ports must not be empty (clap num_args=1.. guarantees this)",
        ));
    }
    let cfg = build_config(args)?;
    raise_nofile_limit();
    tracing::info!(
        "expose client starting (build {}): local 127.0.0.1:{:?} → hub {} (transport={}, agent_id={})",
        BUILD_TAG,
        args.local_ports,
        args.hub_url,
        match args.transport {
            TransportKind::H2 => "h2",
            TransportKind::Quic => "quic",
        },
        args.agent_id
    );
    Ok(AgentClient::new(cfg)?.start())
}

fn build_config(args: &ExposeArgs) -> Result<AgentConfig, interflow_core::error::InterflowError> {
    // Only meaningful for quic; h2 never dials it, so h2 configs stay clean.
    let hub_quic_addr = if args.transport == TransportKind::Quic {
        let addr = resolve_hub_quic_addr(&args.hub_url, args.hub_quic_addr.as_deref());
        if addr.is_none() {
            return Err(interflow_core::error::InterflowError::config(
                "transport = \"quic\" requires a hub QUIC address: pass --hub-quic-addr \
                 (host:port) or use a hub URL carrying an explicit port",
            ));
        }
        addr
    } else {
        None
    };

    // QUIC mandates TLS end-to-end: without a [tls] section the agent's QUIC
    // path pins an all-zero fingerprint and the handshake can never succeed.
    // For h2, TLS still follows the https:// scheme as before.
    let tls = if args.hub_url.starts_with("https://") || args.transport == TransportKind::Quic {
        Some(TlsConfig {
            enabled: true,
            ca_path: args.ca_path.clone(),
            client_cert_path: args.client_cert.clone(),
            client_key_path: args.client_key.clone(),
            hub_cert_fingerprint: None,
        })
    } else {
        None
    };

    let mut egress: Vec<EgressRule> = Vec::with_capacity(args.local_ports.len());
    for p in &args.local_ports {
        let target_addr = format!("127.0.0.1:{p}").parse().map_err(|e| {
            interflow_core::error::InterflowError::config(format!("failed to parse local port {p}"))
                .with_source(e)
        })?;
        egress.push(EgressRule {
            name: format!("expose-{p}"),
            target_addr,
            target_protocol: StreamProto::Tcp,
            udp_idle_timeout_secs: None,
        });
    }

    Ok(AgentConfig {
        agent: AgentInfo {
            id: args.agent_id.clone(),
            hub_url: args.hub_url.clone(),
            transport: args.transport,
            hub_quic_addr,
            ..AgentInfo::default()
        },
        egress,
        control: ControlConfig {
            enabled: false,
            ..ControlConfig::default()
        },
        tls,
        ..AgentConfig::default()
    })
}

/// Resolve the hub QUIC address: an explicit value wins; otherwise derive it
/// from the hub URL's authority — but only when the URL carries an explicit
/// port (implicit 80/443 would almost never be the tunnel's QUIC port, so we
/// decline instead of guessing). Derivation matches the edge-side default
/// where the QUIC listener shares the hub TCP port number (TCP and UDP are
/// independent protocols and can bind the same port).
fn resolve_hub_quic_addr(hub_url: &str, explicit: Option<&str>) -> Option<String> {
    if let Some(addr) = explicit.map(str::trim).filter(|s| !s.is_empty()) {
        return Some(addr.to_string());
    }
    let authority = hub_url
        .strip_prefix("https://")
        .or_else(|| hub_url.strip_prefix("http://"))
        .unwrap_or(hub_url);
    let authority = authority.split('/').next().unwrap_or(authority);
    // `host:port` (IPv6 hosts keep their brackets in the authority); a port
    // is mandatory for derivation.
    let port = authority.rsplit_once(':')?.1;
    if port.is_empty() || !port.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    Some(authority.to_string())
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    fn args(transport: TransportKind, hub_url: &str, hub_quic_addr: Option<&str>) -> ExposeArgs {
        ExposeArgs {
            local_ports: vec![3000],
            hub_url: hub_url.to_string(),
            agent_id: "a".into(),
            client_cert: None,
            client_key: None,
            ca_path: None,
            transport,
            hub_quic_addr: hub_quic_addr.map(str::to_string),
        }
    }

    #[test]
    fn resolve_hub_quic_addr_derives_from_explicit_port() {
        assert_eq!(
            resolve_hub_quic_addr("http://hub.example.com:16666", None),
            Some("hub.example.com:16666".into())
        );
        assert_eq!(
            resolve_hub_quic_addr("https://hub.example.com:6666/some/path", None),
            Some("hub.example.com:6666".into())
        );
        // IPv6 authority keeps its brackets (accepted by connect_quic_inner)
        assert_eq!(
            resolve_hub_quic_addr("http://[2001:db8::1]:16666", None),
            Some("[2001:db8::1]:16666".into())
        );
    }

    #[test]
    fn resolve_hub_quic_addr_declines_portless_urls() {
        // Implicit 80/443 is not a tunnel port guess we are willing to make
        assert_eq!(resolve_hub_quic_addr("http://hub.example.com", None), None);
        assert_eq!(resolve_hub_quic_addr("https://hub.example.com", None), None);
    }

    #[test]
    fn resolve_hub_quic_addr_explicit_wins_over_derivation() {
        assert_eq!(
            resolve_hub_quic_addr(
                "http://hub.example.com:16666",
                Some("edge.example.com:6667")
            ),
            Some("edge.example.com:6667".into())
        );
        // Blank explicit values fall through to derivation instead of
        // poisoning the config with an empty address
        assert_eq!(
            resolve_hub_quic_addr("http://hub.example.com:16666", Some("  ")),
            Some("hub.example.com:16666".into())
        );
    }

    #[test]
    fn build_config_quic_requires_derivable_addr() {
        let err =
            build_config(&args(TransportKind::Quic, "http://hub.example.com", None)).unwrap_err();
        assert!(
            err.to_string().contains("quic"),
            "error should name the quic requirement: {err}"
        );
    }

    #[test]
    fn build_config_quic_forces_tls_regardless_of_scheme() {
        // QUIC mandates TLS even over a plain http:// hub URL
        let cfg = build_config(&args(
            TransportKind::Quic,
            "http://hub.example.com:16666",
            None,
        ))
        .unwrap();
        assert!(cfg.tls.is_some(), "quic must assemble a [tls] section");
        assert_eq!(cfg.agent.transport, TransportKind::Quic);
        assert_eq!(
            cfg.agent.hub_quic_addr.as_deref(),
            Some("hub.example.com:16666")
        );

        // h2 keeps the scheme-driven behavior: plain http stays TLS-less
        let cfg = build_config(&args(
            TransportKind::H2,
            "http://hub.example.com:16666",
            None,
        ))
        .unwrap();
        assert!(cfg.tls.is_none());
        assert_eq!(cfg.agent.hub_quic_addr, None);
    }
}
