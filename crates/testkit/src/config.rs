//! `HubConfig` / `AgentConfig` builders: minimal startable presets for tests and benches.
//!
//! Naming follows the original tests/common conventions (`hub_config` /
//! `agent_config` / `acl`...), so migration only needs import changes.

use crate::certs::TestCerts;
use interflow_core::protocol::StreamProto;
use interflow_mesh::config::{
    AGENT_CONFIG_VERSION, AclConfig, AclRule, AgentConfig, AgentInfo, AgentTlsConfig, AuthConfig,
    AuthMode, ControlConfig, EgressRule, HUB_CONFIG_VERSION, HeartbeatConfig, HubConfig,
    HubQuicConfig, HubSecurityConfig, HubTlsConfig, IngressRule, LoggingConfig, MetricsConfig,
    SecurityConfig, ServerConfig, StaticTokenConfig, TlsVersion, TransportKind,
};
use std::net::SocketAddr;

/// Convenience constructor for a test ACL rule.
pub fn acl(source: &str, target: &str) -> AclRule {
    AclRule {
        source: source.to_string(),
        target: target.to_string(),
    }
}

/// Build a minimal startable hub config: no TLS, allow_anonymous=true, optional ACL.
pub fn hub_config(listen_port: u16, acl_rules: Vec<AclRule>) -> HubConfig {
    hub_config_tuned(
        listen_port,
        acl_rules,
        HubSecurityConfig::default(),
        HeartbeatConfig::default(),
    )
}

/// Build a hub config with tunable security / heartbeat parameters (eviction-type tests
/// use short timeouts).
pub fn hub_config_tuned(
    listen_port: u16,
    acl_rules: Vec<AclRule>,
    security: HubSecurityConfig,
    heartbeat: HeartbeatConfig,
) -> HubConfig {
    HubConfig {
        config_version: HUB_CONFIG_VERSION,
        server: ServerConfig {
            listen_addr: format!("127.0.0.1:{listen_port}")
                .parse()
                .expect("listen addr"),
        },
        auth: AuthConfig {
            mode: AuthMode::Anonymous,
            allow_anonymous: true,
            rate_limit_per_minute: 0, // rate limiting disabled for tests
            static_token: None,
            mtls: None,
        },
        tls: None,
        acl: AclConfig {
            rules: acl_rules.into_iter().collect(),
        },
        security,
        heartbeat,
        routes: Default::default(),
        metrics: MetricsConfig::default(),
        audit: Default::default(),
        logging: LoggingConfig::default(),
        quic: Default::default(),
    }
}

/// Build a hub config with a static token (for auth-failure tests).
pub fn hub_config_with_token(
    listen_port: u16,
    agent_token: &str,
    admin_token: Option<&str>,
) -> HubConfig {
    HubConfig {
        config_version: HUB_CONFIG_VERSION,
        server: ServerConfig {
            listen_addr: format!("127.0.0.1:{listen_port}")
                .parse()
                .expect("listen addr"),
        },
        auth: AuthConfig {
            mode: AuthMode::StaticToken,
            allow_anonymous: false,
            rate_limit_per_minute: 0,
            static_token: Some(StaticTokenConfig {
                agent: Some(agent_token.to_string()),
                admin: admin_token.map(str::to_string),
            }),
            mtls: None,
        },
        tls: None,
        acl: AclConfig::default(),
        security: HubSecurityConfig::default(),
        heartbeat: HeartbeatConfig::default(),
        routes: Default::default(),
        metrics: MetricsConfig::default(),
        audit: Default::default(),
        logging: LoggingConfig::default(),
        quic: Default::default(),
    }
}

/// Build a QUIC-enabled hub config (TLS mandatory, anonymous mode; QUIC and TCP share the
/// same port as a dual stack).
pub fn hub_quic_config(listen_port: u16, certs: &TestCerts, acl_rules: Vec<AclRule>) -> HubConfig {
    let mut cfg = hub_config(listen_port, acl_rules);
    cfg.tls = Some(HubTlsConfig {
        enabled: true,
        cert_path: certs.server_cert_path().display().to_string(),
        key_path: certs.server_key_path().display().to_string(),
        min_version: TlsVersion::V1_3,
    });
    cfg.quic = HubQuicConfig {
        enabled: true,
        // Default: same port as TCP (TCP/UDP coexist independently)
        listen_addr: None,
        ..HubQuicConfig::default()
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

/// Build a minimal startable agent config (h2, anonymous, warn-level logs).
pub fn agent_config(id: &str, hub_port: u16) -> AgentConfig {
    AgentConfig {
        config_version: AGENT_CONFIG_VERSION,
        agent: AgentInfo {
            id: id.to_string(),
            hub_url: format!("http://127.0.0.1:{hub_port}"),
            transport: TransportKind::H2,
            hub_quic_addr: None,
            auth_token: None,
            connect_timeout_secs: 5,
            poll_idle_timeout_secs: None,
            request_establish_timeout_secs: None,
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
        tls: None,
        logging: LoggingConfig {
            level: "warn".to_string(), // reduce log noise by default in tests
            format: interflow_mesh::config::LogFormat::Plain,
        },
    }
}

/// Build a QUIC agent config (CA verification, no client certificate; mTLS scenarios add
/// the cert/key separately).
pub fn agent_quic_config(id: &str, hub_port: u16, certs: &TestCerts) -> AgentConfig {
    let mut cfg = agent_config(id, hub_port);
    cfg.agent.transport = TransportKind::Quic;
    cfg.agent.hub_quic_addr = Some(format!("127.0.0.1:{hub_port}"));
    cfg.tls = Some(AgentTlsConfig {
        enabled: true,
        ca_path: Some(certs.ca_path().display().to_string()),
        client_cert_path: None,
        client_key_path: None,
        hub_cert_fingerprint: None,
    });
    cfg
}

/// A TCP egress rule.
pub fn tcp_egress_rule(name: &str, target: SocketAddr) -> EgressRule {
    EgressRule {
        name: name.to_string(),
        target_addr: target,
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
        target_addr: target,
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
