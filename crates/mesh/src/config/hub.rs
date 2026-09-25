//! Hub engine configuration model.
//!
//! Constructed programmatically: the pack bootstrap (`crate::pack`) derives
//! it from a Credential Pack, the embedded expose edge assembles it
//! in-memory, and the dev soak harness hands it across the process boundary
//! as JSON. Structs keep `deny_unknown_fields` so handoffs reject unknown
//! fields. The `[auth]` section is required and must carry a non-empty
//! tenant trust table — authentication is mTLS-only, there are no credential
//! toggles (see [`validate`] for details).

use interflow_core::config::params::liveness::HeartbeatCadence;
use interflow_core::config::params::transport::{
    DEFAULT_QUIC_IDLE_TIMEOUT_MS, DEFAULT_QUIC_KEEPALIVE_INTERVAL,
};
use interflow_core::config::{AuditConfig, LoggingConfig};
use interflow_core::tunnel::negotiation::HeartbeatAd;
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::net::SocketAddr;

/// Hub configuration root structure.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HubConfig {
    /// Server listen configuration.
    pub server: ServerConfig,
    /// Authentication and authorization.
    #[serde(default)]
    pub auth: AuthConfig,
    /// TLS termination configuration (optional; strongly recommended in
    /// production).
    #[serde(default)]
    pub tls: Option<TlsConfig>,
    /// ACL rule set.
    #[serde(default)]
    pub acl: AclConfig,
    /// Connection-level rate limiting and resource protection.
    #[serde(default)]
    pub security: HubSecurityConfig,
    /// hub→agent application-layer heartbeat (Ping/Pong).
    #[serde(default)]
    pub heartbeat: HeartbeatConfig,
    /// Transport-layer tuning, shared schema shape with the agent
    /// (`[transport.h2]` / `[transport.quic]`) — both endpoints of a link
    /// expose the same knobs so there is no per-side tuning that silently
    /// cannot take effect (QUIC negotiates the idle timeout as the
    /// endpoints' minimum; raising only one side does nothing).
    #[serde(default)]
    pub transport: HubTransportConfig,
    /// Prometheus metrics export.
    #[serde(default)]
    pub metrics: MetricsConfig,
    /// Audit log.
    #[serde(default)]
    pub audit: AuditConfig,
    /// The signed-policy publication face: what `PUT /policy` verifies
    /// against and where accepted updates persist. Absent on non-pack hubs
    /// (the embedded expose edge) — the endpoint then 404s.
    #[serde(default)]
    pub policy: PolicyAdminConfig,
    /// Logging configuration.
    #[serde(default)]
    pub logging: LoggingConfig,
}

/// The signed-policy publication face (`PUT /policy`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(deny_unknown_fields, default)]
pub struct PolicyAdminConfig {
    /// The ed25519 policy verifying key (hex) — the trust bundle's
    /// `policy_key`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub verifier_key_hex: Option<String>,
    /// Where accepted updates persist (`<pack>/state/policy`) — the same
    /// files the reload watcher polls and nodes' manual drops use.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub state_policy_dir: Option<std::path::PathBuf>,
    /// The pack's embedded policy snapshot (`<pack>/policy`) — served when
    /// no update has been published yet.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub embedded_policy_dir: Option<std::path::PathBuf>,
    /// The generation this hub currently serves (anti-rollback floor for
    /// publications).
    #[serde(default)]
    pub generation: u64,
}

/// Hub-side transport tuning: h2 keepalive plus the QUIC listener section.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, default)]
#[derive(Default)]
pub struct HubTransportConfig {
    /// h2 (TCP) transport tuning.
    #[serde(default)]
    pub h2: H2TransportConfig,
    /// QUIC transport listener (optional; coexists with the TCP h2 dual
    /// stack).
    #[serde(default)]
    pub quic: HubQuicConfig,
}

// h2 keepalive tuning lives in [`crate::config::transport`] (one schema,
// one default source, shared with the agent).
use crate::config::transport::H2TransportConfig;

/// QUIC transport configuration (backlog §6.4; starting points follow the frp
/// defaults).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct HubQuicConfig {
    /// Whether the QUIC listener is enabled. Defaults to `false`.
    ///
    /// Enabling requires `[tls]` to provide certificates (QUIC mandates TLS
    /// and reuses the same certificate set with ALPN `"interflow"`).
    pub enabled: bool,
    /// QUIC UDP listen address. Defaults to the same port as
    /// `server.listen_addr` (TCP and UDP are independent and can share the
    /// port number).
    pub listen_addr: Option<SocketAddr>,
    /// Connection idle timeout in milliseconds. Defaults to 30_000 (frp
    /// default).
    pub max_idle_timeout_ms: u32,
    /// KeepAlive interval in milliseconds. Defaults to 10_000 (frp default).
    pub keepalive_interval_ms: u32,
    /// Maximum concurrent bidirectional streams per connection. Defaults to
    /// 4096 (not copying frp's 100k; keeps in step with the hub's existing
    /// `max_streams_total` quota system).
    pub max_concurrent_bidi_streams: u64,
    /// Whether UDP sessions use the QUIC DATAGRAM (RFC 9221) fast path.
    /// Defaults to `true`.
    ///
    /// Small datagrams (≤ the application-layer budget) travel as unreliable,
    /// unordered frames — UDP semantics with zero translation, so packet loss
    /// no longer head-of-line blocks the whole connection (a differentiator
    /// neither frp nor rathole achieves). Over-budget payloads and Open/Close
    /// control frames still travel on streams (reliable and ordered).
    pub datagram_enabled: bool,
}

impl Default for HubQuicConfig {
    fn default() -> Self {
        // QUIC transport values follow the shared transport profile (single
        // source with the agent endpoint — QUIC negotiates the idle timeout
        // as the endpoints' minimum, so both sides must agree by
        // construction, not by copied literals).
        Self {
            enabled: false,
            listen_addr: None,
            max_idle_timeout_ms: DEFAULT_QUIC_IDLE_TIMEOUT_MS,
            keepalive_interval_ms: u32::try_from(DEFAULT_QUIC_KEEPALIVE_INTERVAL.as_millis())
                .unwrap_or(30_000),
            max_concurrent_bidi_streams: 4096,
            datagram_enabled: true,
        }
    }
}

/// Hub resource protection and connection-level rate limiting.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct HubSecurityConfig {
    /// Maximum concurrent TCP connections per IP; 0 = unlimited. Defaults to
    /// 64.
    pub max_connections_per_ip: usize,
    /// Global maximum concurrent TCP connections; 0 = unlimited. Defaults to
    /// 4096.
    pub max_connections_total: usize,
    /// Maximum concurrent active streams per agent; 0 = unlimited. Defaults
    /// to 256. Prevents a single compromised agent from exhausting hub memory
    /// with a flood of stream opens.
    pub max_streams_per_agent: usize,
    /// Global maximum concurrent active streams; 0 = unlimited. Defaults to
    /// 100_000.
    pub max_streams_total: usize,
    /// Maximum seconds to wait when writing a single frame into an agent's
    /// channel; a timeout marks the agent unreachable: the agent is evicted
    /// (registry cleanup + orphaned streams) and the current request returns
    /// 503. Defaults to 30. Prevents `send().await` hanging forever under
    /// "agent dead + channel full" (the black-hole 502).
    pub channel_send_timeout_secs: u64,
    /// Grace period in seconds that an agent entry survives after its poll
    /// connection drops; it is evicted if no new /poll arrives within the
    /// grace period. Defaults to 30.
    ///
    /// Invariant (validated in [`crate::config::validate`]): the grace must
    /// be at least the supervisor's reconnect-backoff cap (`BACKOFF_CAP`,
    /// 30s) — a healthy agent riding out its worst-case backoff stays
    /// registered. A grace under a full backoff + connect attempt is still
    /// recoverable (the next `/poll` implicitly re-registers), but costs an
    /// avoidable eviction + orphan-stream sweep; the validator makes that
    /// trade-off an explicit operator decision instead of an accident.
    pub poll_grace_secs: u64,
}

impl Default for HubSecurityConfig {
    fn default() -> Self {
        Self {
            max_connections_per_ip: 64,
            max_connections_total: 4096,
            max_streams_per_agent: 256,
            max_streams_total: 100_000,
            channel_send_timeout_secs: 30,
            poll_grace_secs: 30,
        }
    }
}

/// hub→agent application-layer heartbeat configuration.
///
/// The hub periodically dispatches Ping frames to the agent's poll channel and
/// the agent answers via an uplink Pong frame. The heartbeat covers cases that
/// transport-layer keepalive cannot detect (e.g. the agent's application layer
/// is wedged while the connection stays alive).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct HeartbeatConfig {
    /// Whether it is enabled. Defaults to `true`.
    pub enabled: bool,
    /// Ping send interval in seconds. Defaults to 15.
    pub interval_secs: u64,
    /// Consecutive-miss threshold for declaring an agent lost: if no Pong is
    /// received for more than `interval_secs * (max_missed + 1)`, the agent is
    /// evicted. Defaults to 4.
    pub max_missed: u32,
}

impl Default for HeartbeatConfig {
    fn default() -> Self {
        // The cadence is the root of the whole liveness derivation chain
        // (see core `config::params::liveness`); this default IS the
        // canonical `HeartbeatCadence::DEFAULT`.
        let cadence = HeartbeatCadence::DEFAULT;
        Self {
            enabled: true,
            interval_secs: cadence.interval_secs,
            max_missed: cadence.max_missed,
        }
    }
}

impl From<&HeartbeatConfig> for HeartbeatCadence {
    fn from(cfg: &HeartbeatConfig) -> Self {
        Self {
            interval_secs: cfg.interval_secs,
            max_missed: cfg.max_missed,
        }
    }
}

impl From<&HeartbeatConfig> for HeartbeatAd {
    fn from(cfg: &HeartbeatConfig) -> Self {
        Self {
            interval_secs: cfg.interval_secs,
            max_missed: cfg.max_missed,
        }
    }
}

/// Server listen configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ServerConfig {
    /// Listen address.
    pub listen_addr: SocketAddr,
    /// Display name for log attribution (the pack's node name on the product
    /// path). Embedders hosting several nodes in one process key captured
    /// log events on the `node` field this feeds. Purely informational — no
    /// protocol or validation meaning.
    #[serde(default)]
    pub node_name: Option<String>,
    /// PROXY protocol negotiation (restores the real client IP behind an
    /// nginx `stream`/`proxy_pass` front). See
    /// `interflow_core::security::proxy_protocol` for the trust matrix.
    #[serde(default)]
    pub proxy_protocol: interflow_core::security::ProxyProtocolConfig,
}

/// Authentication configuration: mTLS-only, one trust entry per tenant.
///
/// There is exactly one authentication mode (client certificates) and no
/// credential toggles: the `[auth]` section carries the tenant trust table
/// and the registration rate limit, nothing else (RFC
/// (internal design notes) §3.1).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuthConfig {
    /// Maximum authentication attempts per IP per minute. 0 means unlimited.
    /// Defaults to 30. mTLS has no brute-forceable secret; the limiter's
    /// remaining job is churn/DoS suppression on the registration endpoints.
    #[serde(default = "default_rate_limit_per_minute")]
    pub rate_limit_per_minute: u32,
    /// Tenant trust table (`[[auth.tenants]]`): one named client CA per
    /// tenant. Validation requires it non-empty (an empty trust table can
    /// authenticate nobody) and `[tls]` present (mTLS implies TLS).
    #[serde(default)]
    pub tenants: Vec<TenantConfig>,
}

impl Default for AuthConfig {
    fn default() -> Self {
        Self {
            rate_limit_per_minute: default_rate_limit_per_minute(),
            tenants: Vec::new(),
        }
    }
}

/// One tenant's client-CA trust entry.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TenantConfig {
    /// Tenant name: `[A-Za-z0-9_-]`, 1–64 chars, no leading `_` (the `_`
    /// prefix is reserved for internal principals such as the expose edge
    /// gateway).
    pub name: String,
    /// Path to the tenant's client CA certificate PEM (public certificates
    /// only — the CA private key must never live on the hub host).
    pub ca_path: String,
    /// Path to a PEM CRL issued by this tenant's CA.
    #[serde(default)]
    pub crl_path: Option<String>,
    /// Gateway tenants may open streams across tenant boundaries. Legitimately
    /// used only by the expose edge's in-process principal; operator
    /// configuration should never set this.
    #[serde(default)]
    pub trusted_gateway: bool,
}

/// TLS server configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TlsConfig {
    /// Whether TLS is enabled.
    pub enabled: bool,
    /// Server certificate PEM path.
    pub cert_path: String,
    /// Server private key PEM path (must be 0600).
    pub key_path: String,
    /// Minimum TLS version. Defaults to "1.2". Enforced via rustls
    /// protocol selection in every server-config builder.
    #[serde(default = "default_tls_min_version")]
    pub min_version: interflow_core::tls::TlsMinVersion,
}

const fn default_tls_min_version() -> interflow_core::tls::TlsMinVersion {
    interflow_core::tls::TlsMinVersion::V1_2
}

/// ACL configuration wrapper. The `[[acl.rules]]` list — cross-tenant
/// exceptions only (same-tenant streams are allowed by default).
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AclConfig {
    /// Rule list.
    #[serde(default)]
    pub rules: HashSet<AclRule>,
}

impl AclConfig {
    /// Whether the rule set is empty.
    pub fn is_empty(&self) -> bool {
        self.rules.is_empty()
    }

    /// Whether a given rule is contained.
    pub fn contains(&self, rule: &AclRule) -> bool {
        self.rules.contains(rule)
    }
}

/// One ACL rule: a **cross-tenant exception** letting `source` open streams
/// to `target`.
///
/// Same-tenant streams are allowed by default and need no rule; an empty
/// rule set therefore means full inter-tenant isolation (the inverse of the
/// legacy "empty = allow-all" semantics).
#[derive(Debug, Clone, Serialize, Deserialize, Hash, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct AclRule {
    /// Initiating tenant.
    pub source_tenant: String,
    /// Initiating agent id (within `source_tenant`).
    pub source: String,
    /// Target tenant.
    pub target_tenant: String,
    /// Target agent id (within `target_tenant`).
    pub target: String,
}

/// Prometheus metrics export configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MetricsConfig {
    /// Whether it is enabled.
    #[serde(default)]
    pub enabled: bool,
    /// Listen address (loopback recommended).
    #[serde(default = "default_metrics_addr")]
    pub listen_addr: SocketAddr,
    /// Path.
    #[serde(default = "default_metrics_path")]
    pub path: String,
}

impl Default for MetricsConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            listen_addr: default_metrics_addr(),
            path: default_metrics_path(),
        }
    }
}

const fn default_rate_limit_per_minute() -> u32 {
    30
}

fn default_metrics_addr() -> SocketAddr {
    "127.0.0.1:9100"
        .parse()
        .expect("default metrics addr is valid")
}

fn default_metrics_path() -> String {
    "/metrics".to_string()
}

#[cfg(test)]
#[allow(
    clippy::panic,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::missing_docs_in_private_items
)]
mod tests {
    use super::*;

    #[test]
    fn acl_rules_round_trip() {
        let toml_str = r#"

[server]
listen_addr = "127.0.0.1:8080"

[auth]
rate_limit_per_minute = 30

[[auth.tenants]]
name = "acme"
ca_path = "certs/acme-ca.crt"

[[auth.tenants]]
name = "globex"
ca_path = "certs/globex-ca.crt"

[[acl.rules]]
source_tenant = "acme"
source = "ingress-01"
target_tenant = "globex"
target = "egress-01"

[[acl.rules]]
source_tenant = "acme"
source = "ingress-02"
target_tenant = "globex"
target = "egress-02"
"#;
        let config: HubConfig = toml::from_str(toml_str).expect("parse");
        assert_eq!(config.acl.rules.len(), 2);
        assert!(config.acl.rules.contains(&AclRule {
            source_tenant: "acme".to_string(),
            source: "ingress-01".to_string(),
            target_tenant: "globex".to_string(),
            target: "egress-01".to_string(),
        }));
    }

    #[test]
    fn empty_acl_when_no_rules() {
        let toml_str = r#"

[server]
listen_addr = "127.0.0.1:8080"

[auth]
[[auth.tenants]]
name = "acme"
ca_path = "certs/acme-ca.crt"
"#;
        let config: HubConfig = toml::from_str(toml_str).expect("parse");
        assert!(config.acl.is_empty());
        assert_eq!(config.auth.tenants.len(), 1);
        assert_eq!(config.auth.tenants[0].name, "acme");
    }

    #[test]
    fn deny_unknown_fields_rejects_typo() {
        let toml_str = r#"

[server]
listen_addr = "127.0.0.1:8080"
litsten_addr = "oops"
"#;
        let result: Result<HubConfig, _> = toml::from_str(toml_str);
        assert!(result.is_err(), "deny_unknown_fields should reject typos");
    }

    #[test]
    fn security_stream_caps_default() {
        let s = HubSecurityConfig::default();
        assert_eq!(s.max_streams_per_agent, 256);
        assert_eq!(s.max_streams_total, 100_000);
        assert_eq!(s.channel_send_timeout_secs, 30);
        assert_eq!(s.poll_grace_secs, 30);
    }

    #[test]
    fn heartbeat_defaults_and_parse() {
        let d = HeartbeatConfig::default();
        assert!(d.enabled);
        assert_eq!(d.interval_secs, 15);
        assert_eq!(d.max_missed, 4);

        let toml_str = r#"

[server]
listen_addr = "127.0.0.1:8080"

[auth]
[[auth.tenants]]
name = "acme"
ca_path = "certs/acme-ca.crt"

[security]
channel_send_timeout_secs = 5
poll_grace_secs = 2

[heartbeat]
enabled = false
interval_secs = 1
max_missed = 1
"#;
        let config: HubConfig = toml::from_str(toml_str).expect("parse");
        assert_eq!(config.security.channel_send_timeout_secs, 5);
        assert_eq!(config.security.poll_grace_secs, 2);
        assert!(!config.heartbeat.enabled);
        assert_eq!(config.heartbeat.interval_secs, 1);
        assert_eq!(config.heartbeat.max_missed, 1);
    }

    #[test]
    fn heartbeat_section_absent_uses_defaults() {
        let toml_str = r#"

[server]
listen_addr = "127.0.0.1:8080"

[auth]
[[auth.tenants]]
name = "acme"
ca_path = "certs/acme-ca.crt"
"#;
        let config: HubConfig = toml::from_str(toml_str).expect("parse");
        assert!(config.heartbeat.enabled);
        assert_eq!(config.heartbeat.interval_secs, 15);
        assert_eq!(config.heartbeat.max_missed, 4);
    }

    #[test]
    fn security_stream_caps_parse_from_toml() {
        let toml_str = r#"

[server]
listen_addr = "127.0.0.1:8080"

[auth]
[[auth.tenants]]
name = "acme"
ca_path = "certs/acme-ca.crt"

[security]
max_streams_per_agent = 8
max_streams_total = 128
"#;
        let config: HubConfig = toml::from_str(toml_str).expect("parse");
        assert_eq!(config.security.max_streams_per_agent, 8);
        assert_eq!(config.security.max_streams_total, 128);
    }

    #[test]
    fn security_stream_caps_default_when_absent() {
        let toml_str = r#"

[server]
listen_addr = "127.0.0.1:8080"

[auth]
[[auth.tenants]]
name = "acme"
ca_path = "certs/acme-ca.crt"
"#;
        let config: HubConfig = toml::from_str(toml_str).expect("parse");
        assert_eq!(config.security.max_streams_per_agent, 256);
        assert_eq!(config.security.max_streams_total, 100_000);
    }
}
