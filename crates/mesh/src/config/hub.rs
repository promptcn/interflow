//! Hub configuration schema.
//!
//! All structs use `deny_unknown_fields` to guard against typos. The `[auth]`
//! section is required — either provide credentials or set an explicit
//! `allow_anonymous = true` (see [`validate`] for details).

use interflow_core::config::params::liveness::HeartbeatCadence;
use interflow_core::config::params::transport::{
    DEFAULT_QUIC_IDLE_TIMEOUT_MS, DEFAULT_QUIC_KEEPALIVE_INTERVAL,
};
use interflow_core::config::{AuditConfig, LoggingConfig};
use interflow_core::tunnel::negotiation::HeartbeatAd;
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::net::SocketAddr;

/// Current configuration schema version.
///
/// v3 (2026-09-16, config-governance step 4): removed the dead `routes`
/// static-routing table (zero runtime references since dynamic
/// registration); moved `[quic]` into `[transport.quic]` and added
/// `[transport.h2]` (endpoint-symmetric keepalive, previously hard-coded);
/// `tls.min_version` now actually enforced (previously silently ignored).
pub const HUB_CONFIG_VERSION: u32 = 3;

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
    /// Logging configuration.
    #[serde(default)]
    pub logging: LoggingConfig,
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
pub use crate::config::transport::H2TransportConfig;

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
    /// Minimum TLS version. Defaults to "1.2". Enforced via rustls
    /// protocol-version selection (wired through every server-config
    /// builder since schema v3 — before that the value parsed but never
    /// reached rustls).
    #[serde(default = "default_tls_min_version")]
    pub min_version: interflow_core::tls::TlsMinVersion,
}

const fn default_tls_min_version() -> interflow_core::tls::TlsMinVersion {
    interflow_core::tls::TlsMinVersion::V1_2
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
config_version = 3

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
        assert_eq!(config.config_version, 3);
        assert_eq!(config.acl.rules.len(), 2);
        assert!(config.acl.rules.contains(&AclRule {
            source: "ingress-01".to_string(),
            target: "egress-01".to_string(),
        }));
    }

    #[test]
    fn empty_acl_when_no_rules() {
        let toml_str = r#"
config_version = 3

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
config_version = 3

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
config_version = 3

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
config_version = 3

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
config_version = 3

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
config_version = 3

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
