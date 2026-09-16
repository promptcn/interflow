//! Agent configuration schema.
//!
//! All structs use `deny_unknown_fields`. When the `[control]` section is
//! enabled, `auth_token` must be configured; binding to a non-loopback address
//! requires an explicit `allow_remote = true` (foot-gun protection).

use interflow_core::config::LoggingConfig;
use interflow_core::protocol::StreamProto;
use interflow_core::security::{ByteRateLimiter, UdpIngressLimiter};
use serde::{Deserialize, Serialize};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

/// Current configuration schema version.
pub const AGENT_CONFIG_VERSION: u32 = 2;

/// Agent configuration root structure.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AgentConfig {
    /// Schema version; must equal [`AGENT_CONFIG_VERSION`].
    pub config_version: u32,
    /// Basic agent information.
    pub agent: AgentInfo,
    /// Ingress rules (local listener → remote agent).
    #[serde(default)]
    pub ingress: Vec<IngressRule>,
    /// Egress rules (remote → local backend).
    #[serde(default)]
    pub egress: Vec<EgressRule>,
    /// Per-frame write stall tolerance for egress backends (seconds): if a TCP
    /// backend's receive-side stall makes a single `write_all` exceed this
    /// duration, the stream is declared dead (the backend connection is closed
    /// and a Close is sent to the peer) so other streams are not dragged down.
    /// Defaults to 10.
    #[serde(default = "default_egress_backend_write_timeout_secs")]
    pub egress_backend_write_timeout_secs: u64,
    /// Egress backend DNS resolution timeout (seconds): if `lookup_host`
    /// exceeds this duration the stream is declared dead. Prevents a broken
    /// resolver / slow domain from filling up all forwarder slots (default OS
    /// semantics can take tens of seconds). Defaults to 5.
    #[serde(default = "default_egress_resolve_timeout_secs")]
    pub egress_resolve_timeout_secs: u64,
    /// Egress backend TCP connect timeout (seconds): if `connect` exceeds this
    /// duration the stream is declared dead. Prevents black-hole addresses
    /// (unreachable IPs that never RST) from occupying all slots at the OS
    /// default of ~75s × the concurrency cap. Defaults to 5.
    #[serde(default = "default_egress_connect_timeout_secs")]
    pub egress_connect_timeout_secs: u64,
    /// Maximum concurrent inbound (request-direction) streams on the agent;
    /// 0 = unlimited.
    ///
    /// A second gate (defense in depth): even if the hub's
    /// `max_streams_per_agent` is loosened or misconfigured, the agent still
    /// enforces its own concurrency ceiling. Defaults to 256, aligned with the
    /// hub default.
    #[serde(default = "default_max_incoming_streams")]
    pub max_incoming_streams: usize,
    /// Maximum stream creation rate (opens/s); 0 = unlimited.
    ///
    /// Guards against the open/close churn reflection surface: churn can stay
    /// below the concurrency cap indefinitely, yet every Open triggers a
    /// resolve + connect against a real backend; the rate limit keeps
    /// sustained churn within budget. Defaults to 100 (a conservative starting
    /// point; tighten based on `interflow_agent_open_dropped_total`
    /// observations).
    #[serde(default = "default_max_stream_opens_per_sec")]
    pub max_stream_opens_per_sec: u32,
    /// Burst bucket capacity for stream creation: only effective when
    /// `max_stream_opens_per_sec > 0`.
    ///
    /// Should be ≥ `max_incoming_streams` so that a legitimate whole-table
    /// stream-creation spike passes in one go. Defaults to 256.
    #[serde(default = "default_stream_open_burst")]
    pub stream_open_burst: u32,
    /// Per-target circuit breaker master switch. When enabled, connect-phase
    /// failures (resolve/connect) are counted per backend target; once a
    /// target exceeds the failure threshold within the window, it is tripped
    /// OPEN and subsequent Opens to it are rejected pre-dial — without
    /// consuming the shared open-rate budget — so one dead target's retry
    /// storm cannot starve healthy targets sharing the same budget.
    ///
    /// Breaker state is agent-level and survives session rebuilds (same
    /// rationale as the rate limiter). Defaults to true.
    #[serde(default = "default_egress_target_breaker_enabled")]
    pub egress_target_breaker_enabled: bool,
    /// Failures within the sliding window required to trip a target's breaker.
    #[serde(default = "default_egress_target_breaker_failure_threshold")]
    pub egress_target_breaker_failure_threshold: u32,
    /// Sliding window (seconds) for counting connect-phase failures per
    /// target. Window-counting (not consecutive-counting) so a flapping
    /// backend failing every other attempt still trips.
    #[serde(default = "default_egress_target_breaker_window_secs")]
    pub egress_target_breaker_window_secs: u64,
    /// Cooldown (seconds) a tripped target stays OPEN before one HALF_OPEN
    /// probe is allowed through; a probe that succeeds closes the breaker
    /// (self-healing), one that fails re-arms it.
    #[serde(default = "default_egress_target_breaker_cooldown_secs")]
    pub egress_target_breaker_cooldown_secs: u64,
    /// Control API.
    #[serde(default)]
    pub control: ControlConfig,
    /// Egress target allowlist (SSRF protection).
    #[serde(default)]
    pub security: SecurityConfig,
    /// TLS client configuration (optional).
    #[serde(default)]
    pub tls: Option<TlsConfig>,
    /// Logging.
    #[serde(default)]
    pub logging: LoggingConfig,
}

/// Transport used toward the hub.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum TransportKind {
    /// HTTP/2 long-lived connection (POST /stream + GET /poll, the default).
    #[default]
    H2,
    /// QUIC native streams (custom frames written directly, eliminating TCP
    /// head-of-line blocking and per-frame HTTP exchanges).
    Quic,
}

/// Basic agent information.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AgentInfo {
    /// Agent ID (used for hub registration; must match ACL references).
    pub id: String,
    /// Hub URL (e.g. `https://hub.example.com:6666`).
    ///
    /// With `transport = "quic"` it is only used for host resolution /
    /// certificate validation; the QUIC port is `hub_quic_addr`.
    pub hub_url: String,
    /// Transport (defaults to h2).
    #[serde(default)]
    pub transport: TransportKind,
    /// The hub's QUIC listen address (`host:port`); required when
    /// `transport = "quic"`.
    #[serde(default)]
    pub hub_quic_addr: Option<String>,
    /// Bearer token; required when the hub has authentication enabled.
    #[serde(default)]
    pub auth_token: Option<String>,
    /// Overall timeout (seconds) for connecting to the hub (DNS + TCP + TLS
    /// handshake + registration).
    ///
    /// When the network stack misbehaves after wake-from-sleep, DNS/TLS can
    /// hang indefinitely without returning an error; without this timeout the
    /// supervisor would stay in Connecting forever (the GUI shows a fake
    /// "started" state). A timeout is treated as a retryable error.
    #[serde(default = "default_connect_timeout_secs")]
    pub connect_timeout_secs: u64,
    /// `/poll` receive-side watchdog timeout (seconds): if no frame at all
    /// (including heartbeat Pings) arrives for this duration, the data plane is
    /// declared stalled and the session is rebuilt.
    ///
    /// Defaults to `None` = derived automatically from the cadence negotiated
    /// at hub registration (heartbeat dead line + margin; auto-disabled when
    /// the hub advertises heartbeats as disabled — the poll stream is
    /// legitimately silent then). `Some(0)` disables it explicitly; `Some(n)`
    /// pins a fixed value (mainly for tests and deployments that disable hub
    /// heartbeats but still want stall detection).
    ///
    /// Background: h2 keepalive only proves the connection is alive;
    /// middleboxes can decouple it from dispatch on the poll stream, and a
    /// successful frame write on the hub side does not mean the peer received
    /// it (kernel/proxy buffers absorb writes) — a hub→agent stall can only be
    /// detected by the receiving end.
    #[serde(default)]
    pub poll_idle_timeout_secs: Option<u64>,
}

/// Ingress rule: local listener → forwarded to a remote agent.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IngressRule {
    /// Rule name (unique identifier, used for add/remove via the control API).
    pub name: String,
    /// Local listen address.
    pub listen_addr: SocketAddr,
    /// Listen protocol: `tcp` (default) or `udp`.
    ///
    /// UDP semantics: one tunnel stream (session) per client source address;
    /// each Data frame payload on the stream is exactly one complete
    /// datagram; the session is reclaimed after being idle for more than
    /// `idle_timeout_secs`.
    #[serde(default)]
    pub listen_protocol: StreamProto,
    /// Target agent ID.
    pub target_agent: String,
    /// Actual remote service address (dynamic addressing; optional).
    pub remote_addr: Option<String>,
    /// Stream idle timeout (seconds): the stream is closed when no data flows
    /// in either direction. Defaults per protocol: tcp = 300 / udp = 60.
    #[serde(default)]
    pub idle_timeout_secs: Option<u64>,
    /// UDP ingress per-source-IP packet rate limit (datagrams/s), against
    /// amplification attacks. 0 = unlimited. Only effective when
    /// `listen_protocol = "udp"`.
    #[serde(default = "default_udp_per_ip_pps")]
    pub udp_per_ip_pps: u32,
    /// UDP ingress per-source-IP byte rate limit (bytes/s). 0 = unlimited.
    /// Note: a single datagram larger than this value is dropped
    /// deterministically (raise it when exposing large-packet services).
    #[serde(default = "default_udp_per_ip_bytes_per_sec")]
    pub udp_per_ip_bytes_per_sec: u32,
    /// UDP return-path rate limit: per-session outbound (toward the public
    /// client) byte rate cap, preventing this node from being used as an
    /// amplification relay. 0 = unlimited.
    #[serde(default = "default_udp_egress_bytes_per_sec")]
    pub udp_egress_bytes_per_sec: u32,
}

impl IngressRule {
    /// The effective stream idle timeout for this rule.
    pub const fn effective_idle_timeout(&self) -> Duration {
        match self.idle_timeout_secs {
            Some(secs) => Duration::from_secs(secs),
            None => match self.listen_protocol {
                StreamProto::Tcp => Duration::from_mins(5),
                StreamProto::Udp => Duration::from_mins(1),
            },
        }
    }

    /// Ingress per-IP rate limiter (returns `None` when both values are 0,
    /// meaning disabled).
    pub fn udp_ingress_limiter(&self) -> Option<Arc<UdpIngressLimiter>> {
        UdpIngressLimiter::new(self.udp_per_ip_pps, self.udp_per_ip_bytes_per_sec).map(Arc::new)
    }

    /// Return-path per-session rate limiter (0 = `None`, disabled).
    pub fn udp_egress_limiter(&self) -> Option<Arc<ByteRateLimiter>> {
        ByteRateLimiter::new(self.udp_egress_bytes_per_sec).map(Arc::new)
    }
}

/// Egress rule: remote request → forwarded to a local backend.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EgressRule {
    /// Rule name.
    pub name: String,
    /// Local backend address.
    pub target_addr: SocketAddr,
    /// Backend protocol: `tcp` (default) or `udp`. Used as the fallback rule
    /// match when there is no dynamic target (ingress without `remote_addr`
    /// configured); when a dynamic target exists, the Open frame's protocol
    /// wins.
    #[serde(default)]
    pub target_protocol: StreamProto,
    /// UDP forwarder idle timeout (seconds): the session is closed and the
    /// peer notified when no traffic flows in either direction. Defaults to
    /// 60. Only effective for UDP streams (TCP backend connections follow EOF
    /// to close).
    #[serde(default)]
    pub udp_idle_timeout_secs: Option<u64>,
}

impl EgressRule {
    /// UDP forwarder idle timeout (defaults to 60s).
    pub fn effective_udp_idle_timeout(&self) -> Duration {
        Duration::from_secs(self.udp_idle_timeout_secs.unwrap_or(60))
    }
}

/// Egress allowlist configuration.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SecurityConfig {
    /// Allowed `host:port` / CIDR list; by default only loopback is allowed.
    #[serde(default)]
    pub allowed_targets: Vec<String>,
}

/// Control API configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ControlConfig {
    /// Whether the control API is enabled.
    #[serde(default = "default_control_enabled")]
    pub enabled: bool,
    /// Listen address. Defaults to loopback; non-loopback requires an
    /// explicit `allow_remote = true`.
    #[serde(default = "default_control_addr")]
    pub listen_addr: SocketAddr,
    /// Control API Bearer token; required when `enabled = true`.
    #[serde(default)]
    pub auth_token: Option<String>,
    /// Allow binding to non-loopback addresses (explicit foot-gun
    /// acknowledgment).
    #[serde(default)]
    pub allow_remote: bool,
}

impl Default for ControlConfig {
    fn default() -> Self {
        Self {
            enabled: default_control_enabled(),
            listen_addr: default_control_addr(),
            auth_token: None,
            allow_remote: false,
        }
    }
}

/// TLS client configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TlsConfig {
    /// Whether TLS is enabled.
    pub enabled: bool,
    /// Path to the trusted CA certificate PEM (optional; defaults to the
    /// system CA).
    #[serde(default)]
    pub ca_path: Option<String>,
    /// Client certificate PEM (for mTLS).
    #[serde(default)]
    pub client_cert_path: Option<String>,
    /// Client private key PEM (for mTLS).
    #[serde(default)]
    pub client_key_path: Option<String>,
    /// SHA256 fingerprint of the hub server certificate (hex, 64 chars;
    /// bypasses the system CA store).
    ///
    /// When set, this bypasses the system CA: only hub certificates matching
    /// this fingerprint are trusted. Defends against "malicious certificate
    /// inside the system CA" man-in-the-middle attacks. Mutually exclusive
    /// with `ca_path`: when both are configured, the fingerprint wins.
    ///
    /// Generate an SPKI fingerprint with
    /// `openssl x509 -in hub.crt -noout -pubkey | openssl pkey -pubin -outform der | sha256sum`,
    /// or fingerprint the whole certificate with
    /// `openssl x509 -in hub.crt -outform der | sha256sum`.
    #[serde(default)]
    pub hub_cert_fingerprint: Option<String>,
}

const fn default_udp_per_ip_pps() -> u32 {
    50
}

const fn default_udp_per_ip_bytes_per_sec() -> u32 {
    10 * 1024
}

const fn default_udp_egress_bytes_per_sec() -> u32 {
    256 * 1024
}

const fn default_control_enabled() -> bool {
    true
}

fn default_control_addr() -> SocketAddr {
    "127.0.0.1:9000"
        .parse()
        .expect("default control addr is valid")
}

const fn default_connect_timeout_secs() -> u64 {
    15
}

const fn default_egress_backend_write_timeout_secs() -> u64 {
    10
}

const fn default_egress_resolve_timeout_secs() -> u64 {
    5
}

const fn default_egress_connect_timeout_secs() -> u64 {
    5
}

const fn default_max_incoming_streams() -> usize {
    256
}

const fn default_max_stream_opens_per_sec() -> u32 {
    100
}

const fn default_stream_open_burst() -> u32 {
    256
}

const fn default_egress_target_breaker_enabled() -> bool {
    true
}

const fn default_egress_target_breaker_failure_threshold() -> u32 {
    5
}

const fn default_egress_target_breaker_window_secs() -> u64 {
    10
}

const fn default_egress_target_breaker_cooldown_secs() -> u64 {
    30
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
    fn agent_v2_parses_with_optional_sections() {
        let toml_str = r#"
config_version = 2

[agent]
id = "test-agent"
hub_url = "https://hub.example.com:6666"
auth_token = "secret"

[tls]
enabled = true
ca_path = "certs/ca.crt"

[[ingress]]
name = "rule-1"
listen_addr = "127.0.0.1:3001"
target_agent = "agent-2"
"#;
        let cfg: AgentConfig = toml::from_str(toml_str).expect("parse");
        assert_eq!(cfg.config_version, 2);
        assert_eq!(cfg.agent.id, "test-agent");
        assert_eq!(cfg.ingress.len(), 1);
    }

    #[test]
    fn open_flood_guard_fields_default_and_override() {
        // Defaults
        let toml_str = r#"
config_version = 2

[agent]
id = "x"
hub_url = "http://hub"
"#;
        let cfg: AgentConfig = toml::from_str(toml_str).expect("parse");
        assert_eq!(cfg.egress_resolve_timeout_secs, 5);
        assert_eq!(cfg.egress_connect_timeout_secs, 5);
        assert_eq!(cfg.max_incoming_streams, 256);
        assert_eq!(cfg.max_stream_opens_per_sec, 100);
        assert_eq!(cfg.stream_open_burst, 256);
        assert!(cfg.egress_target_breaker_enabled);
        assert_eq!(cfg.egress_target_breaker_failure_threshold, 5);
        assert_eq!(cfg.egress_target_breaker_window_secs, 10);
        assert_eq!(cfg.egress_target_breaker_cooldown_secs, 30);

        // Explicit overrides (fields with 0 = disabled semantics)
        let toml_str = r#"
config_version = 2
egress_resolve_timeout_secs = 2
egress_connect_timeout_secs = 3
max_incoming_streams = 0
max_stream_opens_per_sec = 0
stream_open_burst = 8
egress_target_breaker_enabled = false
egress_target_breaker_failure_threshold = 9
egress_target_breaker_window_secs = 20
egress_target_breaker_cooldown_secs = 60

[agent]
id = "x"
hub_url = "http://hub"
"#;
        let cfg: AgentConfig = toml::from_str(toml_str).expect("parse");
        assert_eq!(cfg.egress_resolve_timeout_secs, 2);
        assert_eq!(cfg.egress_connect_timeout_secs, 3);
        assert_eq!(cfg.max_incoming_streams, 0);
        assert_eq!(cfg.max_stream_opens_per_sec, 0);
        assert_eq!(cfg.stream_open_burst, 8);
        assert!(!cfg.egress_target_breaker_enabled);
        assert_eq!(cfg.egress_target_breaker_failure_threshold, 9);
        assert_eq!(cfg.egress_target_breaker_window_secs, 20);
        assert_eq!(cfg.egress_target_breaker_cooldown_secs, 60);
    }

    #[test]
    fn agent_v2_rejects_unknown_field() {
        let toml_str = r#"
config_version = 2

[agent]
id = "x"
hub_url = "https://x"
totaly_misspelled = true
"#;
        let result: Result<AgentConfig, _> = toml::from_str(toml_str);
        assert!(result.is_err());
    }

    #[test]
    fn ingress_udp_fields_parse_with_defaults() {
        let toml_str = r#"
config_version = 2

[agent]
id = "x"
hub_url = "http://hub"

[[ingress]]
name = "dns"
listen_addr = "0.0.0.0:5353"
listen_protocol = "udp"
target_agent = "eg"
remote_addr = "10.0.0.1:53"
"#;
        let cfg: AgentConfig = toml::from_str(toml_str).expect("parse");
        let rule = &cfg.ingress[0];
        assert_eq!(rule.listen_protocol, StreamProto::Udp);
        assert_eq!(rule.idle_timeout_secs, None);
        assert_eq!(rule.udp_per_ip_pps, 50);
        assert_eq!(rule.udp_per_ip_bytes_per_sec, 10 * 1024);
        assert_eq!(rule.udp_egress_bytes_per_sec, 256 * 1024);
        // Default UDP idle timeout is 60s
        assert_eq!(rule.effective_idle_timeout(), Duration::from_mins(1));
        // The default ingress rate limiter is available
        assert!(rule.udp_ingress_limiter().is_some());
        assert!(rule.udp_egress_limiter().is_some());
    }

    #[test]
    fn ingress_tcp_default_protocol_and_idle() {
        let toml_str = r#"
config_version = 2

[agent]
id = "x"
hub_url = "http://hub"

[[ingress]]
name = "web"
listen_addr = "0.0.0.0:8080"
target_agent = "eg"
"#;
        let cfg: AgentConfig = toml::from_str(toml_str).expect("parse");
        let rule = &cfg.ingress[0];
        assert_eq!(rule.listen_protocol, StreamProto::Tcp);
        assert_eq!(rule.effective_idle_timeout(), Duration::from_mins(5));
    }

    #[test]
    fn ingress_udp_overrides_parse() {
        let toml_str = r#"
config_version = 2

[agent]
id = "x"
hub_url = "http://hub"

[[ingress]]
name = "dns"
listen_addr = "0.0.0.0:5353"
listen_protocol = "udp"
target_agent = "eg"
idle_timeout_secs = 120
udp_per_ip_pps = 0
udp_per_ip_bytes_per_sec = 0
udp_egress_bytes_per_sec = 0
"#;
        let cfg: AgentConfig = toml::from_str(toml_str).expect("parse");
        let rule = &cfg.ingress[0];
        assert_eq!(rule.effective_idle_timeout(), Duration::from_mins(2));
        // All zeros = rate limiting disabled
        assert!(rule.udp_ingress_limiter().is_none());
        assert!(rule.udp_egress_limiter().is_none());
    }

    #[test]
    fn invalid_listen_protocol_rejected() {
        let toml_str = r#"
config_version = 2

[agent]
id = "x"
hub_url = "http://hub"

[[ingress]]
name = "x"
listen_addr = "0.0.0.0:53"
listen_protocol = "sctp"
target_agent = "eg"
"#;
        let result: Result<AgentConfig, _> = toml::from_str(toml_str);
        assert!(result.is_err());
    }

    #[test]
    fn egress_udp_fields_parse() {
        let toml_str = r#"
config_version = 2

[agent]
id = "x"
hub_url = "http://hub"

[[egress]]
name = "dns-out"
target_addr = "10.0.0.1:53"
target_protocol = "udp"
udp_idle_timeout_secs = 30
"#;
        let cfg: AgentConfig = toml::from_str(toml_str).expect("parse");
        let rule = &cfg.egress[0];
        assert_eq!(rule.target_protocol, StreamProto::Udp);
        assert_eq!(rule.effective_udp_idle_timeout(), Duration::from_secs(30));

        // Defaults to 60s
        let rule2 = EgressRule {
            name: "d".to_string(),
            target_addr: "127.0.0.1:1".parse().unwrap(),
            target_protocol: StreamProto::Udp,
            udp_idle_timeout_secs: None,
        };
        assert_eq!(rule2.effective_udp_idle_timeout(), Duration::from_mins(1));
    }
}
