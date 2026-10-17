//! `HubConfig` / `AgentConfig` builders: minimal startable presets for tests and benches.
//!
//! Naming follows the original tests/common conventions (`hub_config` /
//! `agent_config` / `acl`...), so migration only needs import changes.

use crate::certs::TestCerts;
use interflow_core::protocol::StreamProto;
use interflow_core::tls::TlsMinVersion;
use interflow_mesh::config::{
    AclConfig, AclRule, AgentConfig, AgentInfo, AgentQuicConfig, AgentTlsConfig, AuthConfig,
    ControlConfig, EgressRule, EgressTarget, HeartbeatConfig, HubConfig, HubQuicConfig,
    HubSecurityConfig, HubTlsConfig, IngressRule, LivenessProbeConfig, LoggingConfig,
    MetricsConfig, ServerConfig, TenantConfig, TransportKind,
};
use std::net::SocketAddr;

/// The single tenant every testkit hub trusts (the `TestCerts` CA).
pub const TEST_TENANT: &str = "test";

/// Convenience constructor for a cross-tenant ACL exception rule.
pub fn acl(source_tenant: &str, source: &str, target_tenant: &str, target: &str) -> AclRule {
    AclRule {
        source_tenant: source_tenant.to_string(),
        source: source.to_string(),
        target_tenant: target_tenant.to_string(),
        target: target.to_string(),
    }
}

/// Build a minimal startable hub config: mTLS with the TestCerts CA as the
/// single `test` tenant, TLS on, optional cross-tenant ACL exceptions.
pub fn hub_config(listen_port: u16, certs: &TestCerts, acl_rules: Vec<AclRule>) -> HubConfig {
    hub_config_tuned(
        listen_port,
        certs,
        acl_rules,
        HubSecurityConfig::default(),
        HeartbeatConfig::default(),
    )
}

/// Build a hub config with tunable security / heartbeat parameters (eviction-type tests
/// use short timeouts).
pub fn hub_config_tuned(
    listen_port: u16,
    certs: &TestCerts,
    acl_rules: Vec<AclRule>,
    security: HubSecurityConfig,
    heartbeat: HeartbeatConfig,
) -> HubConfig {
    HubConfig {
        server: ServerConfig {
            listen_addr: format!("127.0.0.1:{listen_port}")
                .parse()
                .expect("listen addr"),
            node_name: None,
            hub_name: None,
            proxy_protocol: Default::default(),
        },
        auth: AuthConfig {
            rate_limit_per_minute: 0, // rate limiting disabled for tests
            tenants: vec![TenantConfig {
                name: TEST_TENANT.to_string(),
                ca_path: certs.ca_path().display().to_string(),
                crl_path: Some(certs.crl_path().display().to_string()),
                trusted_gateway: false,
            }],
        },
        tls: Some(HubTlsConfig {
            enabled: true,
            cert_path: certs.server_cert_path().display().to_string(),
            key_path: certs.server_key_path().display().to_string(),
            min_version: TlsMinVersion::V1_2,
        }),
        acl: AclConfig {
            rules: acl_rules.into_iter().collect(),
        },
        security,
        heartbeat,
        metrics: MetricsConfig::default(),
        policy: Default::default(),
        audit: Default::default(),
        logging: LoggingConfig::default(),
        transport: Default::default(),
    }
}

/// Build a QUIC-enabled hub config (QUIC and TCP share the same port as a
/// dual stack).
pub fn hub_quic_config(listen_port: u16, certs: &TestCerts, acl_rules: Vec<AclRule>) -> HubConfig {
    hub_quic_config_tuned(
        listen_port,
        certs,
        acl_rules,
        HubSecurityConfig::default(),
        HeartbeatConfig::default(),
        HubQuicConfig::default(),
    )
}

/// Build a QUIC-enabled hub config with full timer tuning (the e2e
/// clock-compression entry: heartbeat/security as `hub_config_tuned`, plus
/// the QUIC transport face — pair with `agent_quic_config_tuned` /
/// `quic_transport_compressed` so the idle timeout's negotiated minimum is
/// the compressed value on both ends).
#[allow(clippy::too_many_arguments)]
pub fn hub_quic_config_tuned(
    listen_port: u16,
    certs: &TestCerts,
    acl_rules: Vec<AclRule>,
    security: HubSecurityConfig,
    heartbeat: HeartbeatConfig,
    quic: HubQuicConfig,
) -> HubConfig {
    let mut cfg = hub_config_tuned(listen_port, certs, acl_rules, security, heartbeat);
    // One [tls] section serves both faces and QUIC mandates TLS 1.3: the
    // QUIC variant rides the 1.3 floor on both faces (validation rejects
    // the 1.2 + QUIC combination).
    if let Some(tls) = cfg.tls.as_mut() {
        tls.min_version = TlsMinVersion::V1_3;
    }
    cfg.transport.quic = HubQuicConfig {
        enabled: true,
        ..quic
    };
    cfg
}

/// Remove the hub's stream-count limits (throughput/stream-open benchmarks: the default
/// per-agent 256 triggers rejections under high-frequency stream opening, adding noise
/// unrelated to the benchmark's goal).
pub fn unlock_stream_limits(cfg: &mut HubConfig) {
    cfg.security.max_streams_per_agent = 0;
    cfg.security.max_streams_total = 0;
}

/// Build a minimal startable agent config (h2 + mTLS client certificate
/// signed by the TestCerts CA — the CN must equal `id`).
pub fn agent_config(id: &str, hub_port: u16, certs: &TestCerts) -> AgentConfig {
    let (cert, key) = certs.named_client_cert(id);
    AgentConfig {
        agent: AgentInfo {
            id: id.to_string(),
            hub_url: format!("https://127.0.0.1:{hub_port}"),
            // Test-only override: a shorter connect budget keeps failure
            // cases at second scale (production default is 15s).
            connect_timeout_secs: 5,
            ..AgentInfo::default()
        },
        tls: Some(AgentTlsConfig {
            enabled: true,
            ca_path: Some(certs.ca_path().display().to_string()),
            client_cert_path: Some(cert.display().to_string()),
            client_key_path: Some(key.display().to_string()),
            hub_cert_fingerprint: None,
        }),
        inner_tls: interflow_mesh::config::InnerTlsConfig {
            crl_paths: vec![certs.crl_path().display().to_string()],
            ..interflow_mesh::config::InnerTlsConfig::default()
        },
        control: ControlConfig {
            enabled: false,
            ..ControlConfig::default()
        },
        logging: LoggingConfig {
            level: "warn".to_string(), // reduce log noise by default in tests
            format: interflow_mesh::config::LogFormat::Plain,
        },
        ..AgentConfig::default()
    }
}

/// Build a QUIC agent config (mTLS, same certificate discipline as h2).
pub fn agent_quic_config(id: &str, hub_port: u16, certs: &TestCerts) -> AgentConfig {
    agent_quic_config_tuned(
        id,
        hub_port,
        certs,
        AgentQuicConfig::default(),
        LivenessProbeConfig::default(),
    )
}

/// Build a QUIC agent config with tunable transport + liveness-probe timers
/// (the e2e clock-compression entry; see `quic_transport_compressed` /
/// `liveness_probe_compressed`).
pub fn agent_quic_config_tuned(
    id: &str,
    hub_port: u16,
    certs: &TestCerts,
    quic: AgentQuicConfig,
    liveness_probe: LivenessProbeConfig,
) -> AgentConfig {
    let mut cfg = agent_config(id, hub_port, certs);
    cfg.agent.transport = TransportKind::Quic;
    cfg.agent.hub_quic_addr = Some(format!("127.0.0.1:{hub_port}"));
    cfg.transport.quic = quic;
    cfg.liveness_probe = liveness_probe;
    cfg
}

/// QUIC transport timers for e2e clock compression: idle 3s / keepalive 1s,
/// returned as the (hub, agent) pair — the QUIC idle timeout is negotiated
/// as the endpoints' minimum, so compressing one end only leaves the
/// production 30s default winning on the other.
///
/// Budget derivation for tests using this preset: a connection whose path
/// dies without a close frame is declared dead by quinn at ~3s on either
/// end (watcher wake / agent-side rebuild trigger).
pub fn quic_transport_compressed() -> (HubQuicConfig, AgentQuicConfig) {
    (
        HubQuicConfig {
            enabled: true,
            listen_addr: None,
            max_idle_timeout_ms: 3_000,
            keepalive_interval_ms: 1_000,
            ..HubQuicConfig::default()
        },
        AgentQuicConfig {
            max_idle_timeout_ms: 3_000,
            keepalive_interval_ms: 1_000,
        },
    )
}

/// Liveness-probe timers for e2e clock compression: worst-case demanding
/// tier detection ≈ `demand_every + strikes × (tick + demand_deadline)`
/// = 1 + 2 × (1 + 1) = **5s** — every probe-budget assertion derives from
/// this formula, never from observed timings.
pub fn liveness_probe_compressed() -> LivenessProbeConfig {
    LivenessProbeConfig {
        tick_secs: 1,
        demand_every_secs: 1,
        demand_deadline_secs: 1,
        demand_strikes: 2,
    }
}

/// A TCP egress rule.
pub fn tcp_egress_rule(name: &str, target: SocketAddr) -> EgressRule {
    EgressRule {
        name: name.to_string(),
        target: EgressTarget::Addr(target),
        target_protocol: StreamProto::Tcp,
        udp_idle_timeout_secs: None,
    }
}

/// A TCP ingress rule (`remote` = None means the rule's default routing).
pub fn tcp_ingress_rule(
    name: &str,
    listen: SocketAddr,
    target_agent: &str,
    remote: Option<SocketAddr>,
) -> IngressRule {
    IngressRule {
        name: name.to_string(),
        listen_addr: listen,
        listen_protocol: StreamProto::Tcp,
        target_agent: target_agent.to_string(),
        remote_addr: remote.map(|a| a.to_string()),
        idle_timeout_secs: None,
        udp_per_ip_pps: 0,
        udp_per_ip_bytes_per_sec: 0,
        udp_egress_bytes_per_sec: 0,
    }
}

/// A UDP egress rule.
pub fn udp_egress_rule(name: &str, target: SocketAddr) -> EgressRule {
    EgressRule {
        name: name.to_string(),
        target: EgressTarget::Addr(target),
        target_protocol: StreamProto::Udp,
        udp_idle_timeout_secs: None,
    }
}

/// A UDP ingress rule.
pub fn udp_ingress_rule(
    name: &str,
    listen: SocketAddr,
    target_agent: &str,
    remote: Option<SocketAddr>,
) -> IngressRule {
    IngressRule {
        name: name.to_string(),
        listen_addr: listen,
        listen_protocol: StreamProto::Udp,
        target_agent: target_agent.to_string(),
        remote_addr: remote.map(|a| a.to_string()),
        idle_timeout_secs: None,
        udp_per_ip_pps: 0,
        udp_per_ip_bytes_per_sec: 0,
        udp_egress_bytes_per_sec: 0,
    }
}
