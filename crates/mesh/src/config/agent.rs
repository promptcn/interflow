//! Agent configuration schema.
//!
//! All structs use `deny_unknown_fields`. When the `[control]` section is
//! enabled, `auth_token` must be configured; binding to a non-loopback address
//! requires an explicit `allow_remote = true` (foot-gun protection).

use interflow_core::config::LoggingConfig;
use interflow_core::config::params::BreakerPolicy;
use interflow_core::protocol::StreamProto;
use interflow_core::security::{ByteRateLimiter, UdpIngressLimiter};
use serde::{Deserialize, Serialize};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

/// Current configuration schema version.
///
/// v3 (2026-09-16, config-governance step 4): added the `[transport]`
/// section (`[transport.h2]` / `[transport.quic]`, endpoint-symmetric with
/// the hub) — previously these transport-layer values were hard-coded per
/// endpoint and the hub-side QUIC knobs could not take effect against the
/// agent's constants.
pub const AGENT_CONFIG_VERSION: u32 = 3;

/// Agent configuration root structure.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
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
    /// E2e encryption (agent↔agent inner TLS); default off = behavior
    /// unchanged.
    #[serde(default)]
    pub e2e: E2eConfig,
    /// Transport-layer tuning, endpoint-symmetric with the hub's
    /// `[transport]` (see [`crate::config::transport`]).
    #[serde(default)]
    pub transport: AgentTransportConfig,
    /// Logging.
    #[serde(default)]
    pub logging: LoggingConfig,
}

/// Agent-side transport tuning: h2 keepalive plus the QUIC endpoint
/// parameters.
///
/// Same knobs, same defaults as the hub side (the QUIC idle timeout is
/// negotiated as the endpoints' minimum — tune both sides together).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, default)]
#[derive(Default)]
pub struct AgentTransportConfig {
    /// h2 transport tuning.
    #[serde(default)]
    pub h2: crate::config::transport::H2TransportConfig,
    /// QUIC transport tuning.
    #[serde(default)]
    pub quic: crate::config::transport::AgentQuicConfig,
}

impl Default for AgentConfig {
    /// Production defaults — the single source every embedder (mesh CLI,
    /// expose client, expose edge self-dial, testkit) composes from via
    /// `AgentConfig::for_identity` + field overrides. The serde default
    /// fns below delegate to the same values, so TOML partial defaults and
    /// programmatic defaults can never drift apart.
    fn default() -> Self {
        Self {
            config_version: AGENT_CONFIG_VERSION,
            agent: AgentInfo::default(),
            ingress: Vec::new(),
            egress: Vec::new(),
            egress_backend_write_timeout_secs: default_egress_backend_write_timeout_secs(),
            egress_resolve_timeout_secs: default_egress_resolve_timeout_secs(),
            egress_connect_timeout_secs: default_egress_connect_timeout_secs(),
            max_incoming_streams: default_max_incoming_streams(),
            max_stream_opens_per_sec: default_max_stream_opens_per_sec(),
            stream_open_burst: default_stream_open_burst(),
            egress_target_breaker_enabled: default_egress_target_breaker_enabled(),
            egress_target_breaker_failure_threshold:
                default_egress_target_breaker_failure_threshold(),
            egress_target_breaker_window_secs: default_egress_target_breaker_window_secs(),
            egress_target_breaker_cooldown_secs: default_egress_target_breaker_cooldown_secs(),
            control: ControlConfig::default(),
            security: SecurityConfig::default(),
            tls: None,
            e2e: E2eConfig::default(),
            transport: AgentTransportConfig::default(),
            logging: LoggingConfig::default(),
        }
    }
}

impl AgentConfig {
    /// Production-default config for the given identity. Identity is the
    /// only part without a default (an agent is meaningless without it);
    /// everything else starts from [`AgentConfig::default`].
    pub fn for_identity(id: impl Into<String>, hub_url: impl Into<String>) -> Self {
        Self {
            agent: AgentInfo {
                id: id.into(),
                hub_url: hub_url.into(),
                ..AgentInfo::default()
            },
            ..Self::default()
        }
    }
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
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
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
    /// Tunnel request send-establishment timeout (seconds): the upper bound
    /// for one `/poll` or `/stream/up` request to reach response headers.
    /// Exceeding it is treated as connection death (session rebuild), because
    /// the receive-side watchdog can never observe this failure form — it
    /// only starts once headers arrive.
    ///
    /// Defaults to `None` = 15s (healthy hubs answer these headers
    /// immediately; the body then streams indefinitely). `Some(0)` keeps the
    /// default; `Some(n ≥ 1)` pins a value (tests, unusually slow links).
    #[serde(default)]
    pub request_establish_timeout_secs: Option<u64>,
    /// Session-critical task stall heartbeat timeout (seconds): a task that
    /// stops proving liveness for this long is judged *wedged* (alive but
    /// not progressing — the failure class the death contract cannot see,
    /// because a wedged task keeps its channels open and sends buffer as
    /// fake successes) and the session is rebuilt.
    ///
    /// Defaults to `None` = derived per transport from the hub-advertised
    /// heartbeat cadence (h2 and QUIC negotiate the same declaration; the
    /// fixed fallback applies only to disabled heartbeat).
    /// `Some(0)` disables stall supervision (death-only); `Some(n ≥ 1)`
    /// pins a value (tests, unusually slow links).
    #[serde(default)]
    pub task_stall_timeout_secs: Option<u64>,
}

impl Default for AgentInfo {
    /// Identity-less defaults: `id` / `hub_url` are empty and MUST be
    /// filled (see [`AgentConfig::for_identity`]); every tunable carries
    /// its production default so struct-update syntax stays exhaustive.
    fn default() -> Self {
        Self {
            id: String::new(),
            hub_url: String::new(),
            transport: TransportKind::default(),
            hub_quic_addr: None,
            connect_timeout_secs: default_connect_timeout_secs(),
            poll_idle_timeout_secs: None,
            request_establish_timeout_secs: None,
            task_stall_timeout_secs: None,
        }
    }
}

/// Ingress rule: local listener → forwarded to a remote agent.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
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
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
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
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SecurityConfig {
    /// Allowed `host:port` / CIDR list; by default only loopback is allowed.
    #[serde(default)]
    pub allowed_targets: Vec<String>,
}

/// Control API configuration.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
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
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
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

/// The per-tenant e2e encryption (agent↔agent inner TLS) mode.
///
/// Security semantics exist only for [`E2eMode::Required`] (encrypted) and
/// [`E2eMode::Off`] (current per-hop behavior); `opportunistic` is a
/// migration-window observation mode whose plaintext fallback cannot
/// distinguish an old peer from an active downgrade — never a security
/// claim (RFC docs/design/agent-e2e-encryption.md §4).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum E2eMode {
    /// Streams carry the inner TLS layer; a failed/absent handshake closes
    /// the stream — never a plaintext fallback (fail-closed).
    Required,
    /// Attempt the inner TLS handshake; on failure fall back to plaintext
    /// (migration window only).
    Opportunistic,
    /// Current behavior: per-hop TLS only, the hub terminates TLS and sees
    /// tunnel payloads.
    #[default]
    Off,
}

/// E2e encryption (agent↔agent inner TLS) configuration
/// (RFC docs/design/agent-e2e-encryption.md §5.1).
///
/// The inner layer reuses the `[tls]` client certificate pair verbatim —
/// no new key material. The tenant anchor for verifying peers is the same
/// file the agent already holds as `[tls] ca_path` (single-CA model);
/// `gateway_ca_path` / `extra_trusted_cas` add the gateway anchor and
/// cross-tenant exception anchors. Startup-only: the e2e runtime is
/// assembled once and does not participate in rule reload.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct E2eConfig {
    /// Mode (default `off`).
    pub mode: E2eMode,
    /// Handshake deadline in seconds for both sides (default 10; 0 is
    /// rejected — guards the stream table against handshake dribble).
    #[serde(default = "default_e2e_handshake_timeout_secs")]
    pub handshake_timeout_secs: u64,
    /// Egress side: the stable gateway anchor CA PEM
    /// (`certs gateway issue` output). In `required` mode, gateway streams
    /// must complete the inner handshake against this anchor — without it
    /// there is no cryptographically verifiable gateway exemption, only a
    /// hub assertion (spoofable), so such streams are rejected.
    #[serde(default)]
    pub gateway_ca_path: Option<String>,
    /// Cross-tenant exception anchors: the peer tenants' CA PEMs for ACL
    /// exception flows. Keep the set minimal — it is an audit item (RFC
    /// §8.2 #4).
    #[serde(default)]
    pub extra_trusted_cas: Vec<String>,
}

impl E2eConfig {
    /// Whether the inner TLS layer participates at all.
    pub fn enabled(&self) -> bool {
        self.mode != E2eMode::Off
    }
}

impl Default for E2eConfig {
    fn default() -> Self {
        Self {
            mode: E2eMode::default(),
            handshake_timeout_secs: default_e2e_handshake_timeout_secs(),
            gateway_ca_path: None,
            extra_trusted_cas: Vec::new(),
        }
    }
}

const fn default_e2e_handshake_timeout_secs() -> u64 {
    10
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

// The breaker default trio delegates to the canonical policy (single
// source; the JSON wire format of the policy rationale lives there).
const fn default_egress_target_breaker_failure_threshold() -> u32 {
    BreakerPolicy::EGRESS_DEFAULT.failure_threshold
}

const fn default_egress_target_breaker_window_secs() -> u64 {
    BreakerPolicy::EGRESS_DEFAULT.failure_window.as_secs()
}

const fn default_egress_target_breaker_cooldown_secs() -> u64 {
    BreakerPolicy::EGRESS_DEFAULT.cooldown.as_secs()
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
    fn agent_parses_with_optional_sections() {
        let toml_str = r#"
config_version = 3

[agent]
id = "test-agent"
hub_url = "https://hub.example.com:6666"

[tls]
enabled = true
ca_path = "certs/ca.crt"

[[ingress]]
name = "rule-1"
listen_addr = "127.0.0.1:3001"
target_agent = "agent-2"
"#;
        let cfg: AgentConfig = toml::from_str(toml_str).expect("parse");
        assert_eq!(cfg.config_version, 3);
        assert_eq!(cfg.agent.id, "test-agent");
        assert_eq!(cfg.ingress.len(), 1);
    }

    #[test]
    fn open_flood_guard_fields_default_and_override() {
        // Defaults
        let toml_str = r#"
config_version = 3

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
config_version = 3
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
    fn agent_rejects_unknown_field() {
        let toml_str = r#"
config_version = 3

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
config_version = 3

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
config_version = 3

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
config_version = 3

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
config_version = 3

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
config_version = 3

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

    /// Single-source contract: a TOML file with only the required identity
    /// fields parses into exactly `AgentConfig::for_identity` — the serde
    /// default fns and the `Default` impls cannot drift apart.
    #[test]
    fn serde_partial_defaults_match_programmatic_default() {
        let toml_str = r#"
config_version = 3

[agent]
id = "test-agent"
hub_url = "https://hub.example.com:6666"
"#;
        let parsed: AgentConfig = toml::from_str(toml_str).expect("parse");
        assert_eq!(
            parsed,
            AgentConfig::for_identity("test-agent", "https://hub.example.com:6666")
        );

        // The breaker trio comes from the canonical policy.
        let d = AgentConfig::default();
        assert_eq!(d.egress_target_breaker_failure_threshold, 5);
        assert_eq!(d.egress_target_breaker_window_secs, 10);
        assert_eq!(d.egress_target_breaker_cooldown_secs, 30);
        // e2e defaults to fully off (old configs parse with zero behavior
        // change).
        assert_eq!(d.e2e.mode, E2eMode::Off);
        assert_eq!(d.e2e.handshake_timeout_secs, 10);
    }

    /// The `[e2e]` section parses with its documented shape; a partial
    /// section keeps the defaults for the omitted fields.
    #[test]
    fn e2e_section_parses() {
        let toml_str = r#"
config_version = 3

[agent]
id = "a1"
hub_url = "https://hub.example.com:6666"

[e2e]
mode = "required"
gateway_ca_path = "certs/gateway-ca.crt"
extra_trusted_cas = ["certs/globex-ca.crt", "certs/initech-ca.crt"]
"#;
        let parsed: AgentConfig = toml::from_str(toml_str).expect("parse");
        assert_eq!(parsed.e2e.mode, E2eMode::Required);
        assert_eq!(parsed.e2e.handshake_timeout_secs, 10); // default kept
        assert_eq!(
            parsed.e2e.gateway_ca_path.as_deref(),
            Some("certs/gateway-ca.crt")
        );
        assert_eq!(parsed.e2e.extra_trusted_cas.len(), 2);
        assert!(parsed.e2e.enabled());

        // opportunistic parses; the unknown-mode typo must not.
        let opportunistic: AgentConfig = toml::from_str(
            "config_version = 3\n[agent]\nid = \"a\"\nhub_url = \"https://h\"\n\n[e2e]\nmode = \"opportunistic\"\n",
        )
        .expect("parse opportunistic");
        assert_eq!(opportunistic.e2e.mode, E2eMode::Opportunistic);
        assert!(
            toml::from_str::<AgentConfig>(
                "config_version = 3\n[agent]\nid = \"a\"\nhub_url = \"https://h\"\n\n[e2e]\nmode = \"preferred\"\n"
            )
            .is_err(),
            "the rejected alias must stay rejected (naming is a security-semantics decision, RFC §4)"
        );
    }

    /// `deny_unknown_fields` on the e2e section makes old binaries reject
    /// the new fields = forced paired upgrade, fail-fast (RFC §6).
    #[test]
    fn e2e_section_rejects_unknown_fields() {
        let toml_str = "config_version = 3\n[agent]\nid = \"a\"\nhub_url = \"https://h\"\n\n[e2e]\nmode = \"off\"\nmin_version = \"1.3\"\n";
        assert!(toml::from_str::<AgentConfig>(toml_str).is_err());
    }
}
