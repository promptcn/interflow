//! Hub configuration schema.
//!
//! All structs use `deny_unknown_fields` to guard against typos. The `[auth]`
//! section is required — either provide credentials or set an explicit
//! `allow_anonymous = true` (see [`validate`] for details).

use interflow_core::config::{AuditConfig, LoggingConfig};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::net::SocketAddr;

/// Current configuration schema version.
pub const HUB_CONFIG_VERSION: u32 = 2;

/// Hub configuration root structure.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HubConfig {
    /// Schema version; must equal [`HUB_CONFIG_VERSION`].
    pub config_version: u32,
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
    /// Static routing table (leave empty to enable dynamic routing: ingress
    /// agents self-register on connect).
    #[serde(default)]
    pub routes: HashMap<String, String>,
    /// Prometheus metrics export.
    #[serde(default)]
    pub metrics: MetricsConfig,
    /// Audit log.
    #[serde(default)]
    pub audit: AuditConfig,
    /// Logging configuration.
    #[serde(default)]
    pub logging: LoggingConfig,
    /// QUIC transport listener (optional; coexists with the TCP h2 dual
    /// stack).
    #[serde(default)]
    pub quic: HubQuicConfig,
}

/// QUIC transport configuration (backlog §6.4; starting points follow the frp
/// defaults).
#[derive(Debug, Clone, Serialize, Deserialize)]
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
        Self {
            enabled: false,
            listen_addr: None,
            max_idle_timeout_ms: 30_000,
            keepalive_interval_ms: 10_000,
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
    /// grace period. Defaults to 30. A healthy agent's poll reconnect backoff
    /// tops out at 5s, so the grace period easily tolerates transient
    /// disconnects.
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
/// the agent answers via `POST /pong`. The heartbeat covers cases that
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
        Self {
            enabled: true,
            interval_secs: 15,
            max_missed: 4,
        }
    }
}

/// Server listen configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ServerConfig {
    /// Listen address.
    pub listen_addr: SocketAddr,
}

/// Authentication configuration.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuthConfig {
    /// Authentication mode. Defaults to `static-token`.
    #[serde(default = "default_auth_mode")]
    pub mode: AuthMode,
    /// Whether anonymous access is allowed. Defaults to `false`.
    ///
    /// **Must never be set to `true` in production.** For local development
    /// only. [`validate`] requires at least one credential when this is
    /// `false`.
    #[serde(default)]
    pub allow_anonymous: bool,
    /// Maximum authentication attempts per IP per minute. 0 means unlimited.
    /// Defaults to 30.
    #[serde(default = "default_rate_limit_per_minute")]
    pub rate_limit_per_minute: u32,
    /// Static token credentials (required when `mode = "static-token"`).
    #[serde(default)]
    pub static_token: Option<StaticTokenConfig>,
    /// mTLS credentials (required when `mode = "mtls"`).
    #[serde(default)]
    pub mtls: Option<MtlsConfig>,
}

impl AuthConfig {
    /// Whether at least one credential is configured.
    pub fn has_any_credential(&self) -> bool {
        self.allow_anonymous
            || self
                .static_token
                .as_ref()
                .is_some_and(|s| s.agent.is_some())
            || self.mtls.is_some()
    }
}

/// Authentication mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum AuthMode {
    /// Static Bearer token comparison ([`StaticTokenConfig`]).
    #[default]
    StaticToken,
    /// TLS client certificate verification ([`MtlsConfig`]).
    Mtls,
    /// Anonymous (requires `allow_anonymous = true`).
    Anonymous,
}

/// Static token credentials.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StaticTokenConfig {
    /// Agent token (required for `/register`, `/poll` and `/stream`).
    pub agent: Option<String>,
    /// Admin token (required only for `/agents`; falls back to `agent` when
    /// unset).
    #[serde(default)]
    pub admin: Option<String>,
}

/// mTLS credentials.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MtlsConfig {
    /// Path to the trusted client CA certificate PEM.
    pub ca_path: String,
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
    /// Minimum TLS version. Defaults to "1.2".
    #[serde(default = "default_tls_min_version")]
    pub min_version: TlsVersion,
}

/// TLS version enum.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum TlsVersion {
    /// TLS 1.2
    #[serde(rename = "1.2")]
    V1_2,
    /// TLS 1.3
    #[serde(rename = "1.3")]
    V1_3,
}

/// ACL configuration wrapper. The `[[acl.rules]]` list.
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

/// One ACL rule: whether the `source` agent is allowed to open streams to the
/// `target` agent.
#[derive(Debug, Clone, Serialize, Deserialize, Hash, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct AclRule {
    /// Initiating agent id.
    pub source: String,
    /// Target agent id.
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

const fn default_auth_mode() -> AuthMode {
    AuthMode::StaticToken
}

const fn default_rate_limit_per_minute() -> u32 {
    30
}

const fn default_tls_min_version() -> TlsVersion {
    TlsVersion::V1_2
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
config_version = 2

[server]
listen_addr = "127.0.0.1:8080"

[auth]
mode = "static-token"

[auth.static_token]
agent = "agent-token"

[[acl.rules]]
source = "ingress-01"
target = "egress-01"

[[acl.rules]]
source = "ingress-02"
target = "egress-02"
"#;
        let config: HubConfig = toml::from_str(toml_str).expect("parse");
        assert_eq!(config.config_version, 2);
        assert_eq!(config.acl.rules.len(), 2);
        assert!(config.acl.rules.contains(&AclRule {
            source: "ingress-01".to_string(),
            target: "egress-01".to_string(),
        }));
    }

    #[test]
    fn empty_acl_when_no_rules() {
        let toml_str = r#"
config_version = 2

[server]
listen_addr = "127.0.0.1:8080"

[auth]
mode = "anonymous"
allow_anonymous = true
"#;
        let config: HubConfig = toml::from_str(toml_str).expect("parse");
        assert!(config.acl.is_empty());
        assert!(config.auth.allow_anonymous);
    }

    #[test]
    fn deny_unknown_fields_rejects_typo() {
        let toml_str = r#"
config_version = 2

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
config_version = 2

[server]
listen_addr = "127.0.0.1:8080"

[auth]
mode = "anonymous"
allow_anonymous = true

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
config_version = 2

[server]
listen_addr = "127.0.0.1:8080"

[auth]
mode = "anonymous"
allow_anonymous = true
"#;
        let config: HubConfig = toml::from_str(toml_str).expect("parse");
        assert!(config.heartbeat.enabled);
        assert_eq!(config.heartbeat.interval_secs, 15);
        assert_eq!(config.heartbeat.max_missed, 4);
    }

    #[test]
    fn security_stream_caps_parse_from_toml() {
        let toml_str = r#"
config_version = 2

[server]
listen_addr = "127.0.0.1:8080"

[auth]
mode = "anonymous"
allow_anonymous = true

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
config_version = 2

[server]
listen_addr = "127.0.0.1:8080"

[auth]
mode = "anonymous"
allow_anonymous = true
"#;
        let config: HubConfig = toml::from_str(toml_str).expect("parse");
        assert_eq!(config.security.max_streams_per_agent, 256);
        assert_eq!(config.security.max_streams_total, 100_000);
    }
}
