//! Local agent client for the ingress engine.
//!
//! Builds a minimal `AgentConfig` in memory (one named egress rule per
//! service, loopback security policy) and reuses `interflow_mesh::agent::
//! AgentClient` to run the full egress agent protocol. Users never write
//! toml — CLI arguments + profile suffice.

use interflow_core::protocol::StreamProto;
use interflow_mesh::agent::{AgentClient, AgentHandle};
use interflow_mesh::config::{
    AgentConfig, AgentInfo, AgentTlsConfig as TlsConfig, ControlConfig, EgressRule, TransportKind,
};

/// One local service an expose agent dials for (id + effective address).
///
/// The id names the egress rule, so the ingress selects by
/// `TargetSelector::Service(id)` and the mapping is explicit — never
/// positional.
#[derive(Debug, Clone)]
pub struct LocalService {
    /// Service id from the pack (unique per agent; the signed policy
    /// authorizes this identity, the node decides the dial target).
    pub id: String,
    /// Effective dial target (loopback by the engine's default-deny
    /// security policy).
    pub target_addr: std::net::SocketAddr,
    /// Origin tag, fixed where the resolution happens: `true` when the
    /// effective address came from a machine-local preference, `false`
    /// when it is the pack default. Same vocabulary as the GUI's
    /// `ServiceAddressDto::overridden`; log lines render it as the
    /// `(override|default)` suffix so "did my preference take effect" is
    /// answerable from the logs alone.
    pub overridden: bool,
}

/// Renders a resolved service list as `id=addr(override|default)` segments
/// (`web=127.0.0.1:5173(override) mail=127.0.0.1:25(default)`).
///
/// One vocabulary shared by every consumer — the expose client's startup
/// line and the GUI's `node starting` line — so the same list reads
/// identically wherever it surfaces.
pub fn service_log_summary(services: &[LocalService]) -> String {
    services
        .iter()
        .map(|s| {
            format!(
                "{}={}({})",
                s.id,
                s.target_addr,
                if s.overridden { "override" } else { "default" }
            )
        })
        .collect::<Vec<_>>()
        .join(" ")
}

/// Arguments needed to build the expose client.
#[derive(Clone)]
pub struct ExposeArgs {
    /// Local services (id + effective address); when routing by host, the
    /// edge names the service id in the Open frame and this agent resolves
    /// it against these rules. The list is non-empty; the first rule is the
    /// `Default`-selector fallback.
    pub services: Vec<LocalService>,
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
    /// Workspace ingress issuer CA PEM. Every expose egress verifies ingress
    /// inner-TLS streams against its own workspace's anchor.
    pub ingress_ca_path: Option<String>,
    /// Transport toward the hub (h2 default; quic eliminates TCP head-of-line
    /// blocking but requires UDP egress).
    pub transport: TransportKind,
    /// Hub QUIC address (`host:port`). `None` derives it from `hub_url`'s
    /// host:port at config-assembly time (valid when the edge runs the QUIC
    /// listener on the same port number as its hub TCP listener — the
    /// dual-stack default).
    pub hub_quic_addr: Option<String>,
    /// Log attribution name override (display only; `None` = the agent id,
    /// which on the product paths is the pack's node name). Embedders
    /// hosting several agents in one process (the GUI) set this to a
    /// per-slot unique value; registration and certificate semantics never
    /// read it.
    pub log_name: Option<String>,
}

impl ExposeArgs {
    /// The value log sites attribute this agent's events to (display only)
    /// — the same contract as `AgentInfo::effective_log_name`, so expose
    /// crate lines that fire before the mesh agent exists (and thus cannot
    /// read it off a config) still carry the node field the GUI's "This
    /// node" filter matches.
    pub fn effective_log_name(&self) -> &str {
        self.log_name.as_deref().unwrap_or(&self.agent_id)
    }
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
fn raise_nofile_limit(node: &str) {
    const TARGET: u64 = 65_536;
    let Ok((soft, hard)) = rlimit::Resource::NOFILE.get() else {
        tracing::warn!(node = %node, "failed to read RLIMIT_NOFILE, keeping the current limit");
        return;
    };
    let new_soft = TARGET.min(hard);
    if new_soft <= soft {
        tracing::info!(node = %node, "fd soft limit {soft} already sufficient (hard limit {hard})");
        return;
    }
    match rlimit::Resource::NOFILE.set(new_soft, hard) {
        Ok(()) => {
            tracing::info!(node = %node, "fd soft limit raised: {soft} -> {new_soft} (hard limit {hard})");
        }
        Err(e) => {
            tracing::warn!(node = %node, "failed to raise fd soft limit ({soft} -> {new_soft}): {e}");
        }
    }
}

#[cfg(not(unix))]
fn raise_nofile_limit(_node: &str) {}

/// Assemble an in-memory AgentConfig and start the agent supervisor, returning the
/// handle immediately.
///
/// GUI / callers that need lifecycle control use this entry point;
/// see [`AgentHandle`] for state subscription and graceful shutdown.
///
/// # Panics
///
/// Must be called from within a Tokio runtime context (the underlying
/// [`AgentClient::start`] spawns the supervisor); it panics otherwise.
pub fn start(args: &ExposeArgs) -> Result<AgentHandle, interflow_core::error::InterflowError> {
    if args.services.is_empty() {
        return Err(interflow_core::error::InterflowError::config(
            "ExposeArgs.services must not be empty (the pack must declare at least one \
             [[agent.*.services]] entry)",
        ));
    }
    let cfg = build_config(args)?;
    raise_nofile_limit(args.effective_log_name());
    tracing::info!(
        node = %args.effective_log_name(),
        "expose client starting (build {}): local services [{}] → hub {} (transport={}, \
         agent_id={})",
        BUILD_TAG,
        service_log_summary(&args.services),
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
    let Some(ingress_ca_path) = args.ingress_ca_path.clone() else {
        return Err(interflow_core::error::InterflowError::config(
            "expose requires the ingress trust anchor (ingress_ca_path) — run the agent \
             from its Credential Pack, which carries it",
        ));
    };
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
    let ingress_crl_path = ingress_crl_path(&ingress_ca_path);

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

    // One rule per service, named by the service id: the edge's
    // `TargetSelector::Service(id)` resolves against these names, making the
    // id→address mapping explicit instead of positional.
    let mut egress: Vec<EgressRule> = Vec::with_capacity(args.services.len());
    for service in &args.services {
        egress.push(EgressRule {
            name: service.id.clone(),
            target_addr: service.target_addr,
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
            log_name: args.log_name.clone(),
            ..AgentInfo::default()
        },
        egress,
        control: ControlConfig {
            enabled: false,
            ..ControlConfig::default()
        },
        tls,
        inner_tls: interflow_mesh::config::InnerTlsConfig {
            ingress_ca_path: Some(ingress_ca_path),
            crl_paths: ingress_crl_path.into_iter().collect(),
            ..interflow_mesh::config::InnerTlsConfig::default()
        },
        ..AgentConfig::default()
    })
}

fn ingress_crl_path(anchor: &str) -> Option<String> {
    // Live refresh first, the rotate-embedded snapshot (trust/crls) second —
    // mirrors interflow_identity::pack::crl_path_for (the engine crate
    // deliberately does not depend on the identity crate).
    let anchor_path = std::path::Path::new(anchor);
    let pack_root = anchor_path.parent()?.parent()?;
    let stem = anchor_path.file_stem()?.to_string_lossy();
    let file = format!("{stem}.crl.pem");
    let live = pack_root.join("state").join("crls").join(&file);
    if live.is_file() {
        return Some(live.display().to_string());
    }
    let embedded = pack_root.join("trust").join("crls").join(&file);
    embedded.is_file().then(|| embedded.display().to_string())
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
    // IPv6 hosts keep their brackets in the rendered authority (accepted by
    // connect_quic_inner); a port is mandatory for derivation.
    let parsed = interflow_util::parse_endpoint(hub_url).ok()?;
    parsed.explicit_port?;
    Some(parsed.authority_str().to_owned())
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    fn args(transport: TransportKind, hub_url: &str, hub_quic_addr: Option<&str>) -> ExposeArgs {
        ExposeArgs {
            log_name: None,
            services: vec![LocalService {
                id: "web".into(),
                target_addr: "127.0.0.1:3000".parse().unwrap(),
                overridden: false,
            }],
            hub_url: hub_url.to_string(),
            agent_id: "a".into(),
            client_cert: None,
            client_key: None,
            ca_path: None,
            ingress_ca_path: Some("gateway-ca.crt".into()),
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

    /// Attribution fallback: `None` names the agent id (the CLI's
    /// standalone logs), an embedder override (the GUI's per-slot value)
    /// wins verbatim — the same contract as `AgentInfo::effective_log_name`.
    #[test]
    fn effective_log_name_falls_back_to_agent_id() {
        let mut a = args(TransportKind::H2, "https://hub.example.com", None);
        assert_eq!(a.effective_log_name(), "a");
        a.log_name = Some("desktop·ab12cd34".into());
        assert_eq!(a.effective_log_name(), "desktop·ab12cd34");
    }

    /// The shared `id=addr(override|default)` vocabulary: one formatter,
    /// consumed by both the client's startup line and the GUI's
    /// `node starting` line, so the same list reads identically wherever
    /// it surfaces.
    #[test]
    fn service_log_summary_tags_origin() {
        let services = vec![
            LocalService {
                id: "web".into(),
                target_addr: "127.0.0.1:5173".parse().unwrap(),
                overridden: true,
            },
            LocalService {
                id: "mail".into(),
                target_addr: "127.0.0.1:25".parse().unwrap(),
                overridden: false,
            },
        ];
        assert_eq!(
            service_log_summary(&services),
            "web=127.0.0.1:5173(override) mail=127.0.0.1:25(default)"
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
