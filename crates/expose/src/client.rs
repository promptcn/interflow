//! Local client for `interflow-expose expose <port>`.
//!
//! Builds a minimal `AgentConfig` in memory (a single egress rule, loopback
//! security policy) and reuses `interflow_mesh::agent::AgentClient` to run
//! the full egress agent protocol. Users never write toml — CLI arguments +
//! profile suffice.

use interflow_core::protocol::StreamProto;
use interflow_mesh::agent::{AgentClient, AgentHandle};
use interflow_mesh::config::{
    AGENT_CONFIG_VERSION, AgentConfig, AgentInfo, AgentTlsConfig as TlsConfig, ControlConfig,
    EgressRule, LoggingConfig, SecurityConfig, TransportKind,
};

/// Arguments needed to build the expose client.
pub struct ExposeArgs {
    /// Local service ports (e.g. 3000); when routing by host, edge names the concrete
    /// remote_addr in the Open frame. The list is non-empty; each port maps to one
    /// egress rule (used as the fallback).
    pub local_ports: Vec<u16>,
    /// Hub URL.
    pub hub_url: String,
    /// Agent token for the hub.
    pub auth_token: String,
    /// Local agent_id (must match the one referenced in edge's routes.toml).
    pub agent_id: String,
    /// Trusted CA path (required when the hub uses a self-signed cert; None uses the system CA).
    pub ca_path: Option<String>,
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
        "expose client starting (build {}): local 127.0.0.1:{:?} → hub {} (agent_id={})",
        BUILD_TAG,
        args.local_ports,
        args.hub_url,
        args.agent_id
    );
    Ok(AgentClient::new(cfg)?.start())
}

fn build_config(args: &ExposeArgs) -> Result<AgentConfig, interflow_core::error::InterflowError> {
    let tls = if args.hub_url.starts_with("https://") {
        Some(TlsConfig {
            enabled: true,
            ca_path: args.ca_path.clone(),
            client_cert_path: None,
            client_key_path: None,
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
        config_version: AGENT_CONFIG_VERSION,
        agent: AgentInfo {
            id: args.agent_id.clone(),
            hub_url: args.hub_url.clone(),
            transport: TransportKind::H2,
            hub_quic_addr: None,
            auth_token: Some(args.auth_token.clone()),
            connect_timeout_secs: 15,
            poll_idle_timeout_secs: None,
        },
        ingress: vec![],
        egress,
        egress_backend_write_timeout_secs: 10,
        egress_resolve_timeout_secs: 5,
        egress_connect_timeout_secs: 5,
        max_incoming_streams: 256,
        max_stream_opens_per_sec: 100,
        stream_open_burst: 256,
        control: ControlConfig {
            enabled: false,
            ..ControlConfig::default()
        },
        security: SecurityConfig::default(),
        tls,
        logging: LoggingConfig::default(),
    })
}
