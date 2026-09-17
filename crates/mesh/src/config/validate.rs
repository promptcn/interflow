//! Load-time configuration validation.
//!
//! Design notes:
//! - **Collect all errors and return them at once**, avoiding the inefficient
//!   "fix one, restart, fix the next" loop
//! - Validation is purely functional: input `&XxxConfig`, output
//!   `Vec<ConfigError>`
//! - Called by [`crate::config::loader`] after `toml::from_str`

use crate::config::{AGENT_CONFIG_VERSION, AgentConfig, HUB_CONFIG_VERSION, HubConfig};
use std::path::Path;

/// A single configuration error.
#[derive(Debug, Clone, thiserror::Error)]
pub enum ConfigError {
    /// `config_version` does not match the current schema.
    #[error("config_version mismatch: expected {expected}, actual {actual}")]
    UnsupportedVersion { expected: u32, actual: u32 },

    /// `[auth]` has no credentials configured and no explicit
    /// `allow_anonymous = true`.
    #[error(
        "[auth] no credentials configured; anonymous access requires an explicit allow_anonymous = true"
    )]
    AuthRequired,

    /// No agent token configured under the `[auth.static_token]` mode.
    #[error("[auth.static_token] agent token is required (mode = \"static-token\")")]
    StaticTokenMissing,

    /// No CA configured under the `[auth.mtls]` mode.
    #[error("[auth.mtls] ca_path is required (mode = \"mtls\")")]
    MtlsCaMissing,

    /// TLS is enabled but the certificate or private key is missing.
    #[error("[tls] enabled = true requires both cert_path and key_path")]
    TlsIncomplete,

    /// Port collision.
    #[error("port collision: {a} and {b}")]
    PortCollision { a: String, b: String },

    /// Invalid ACL fields.
    #[error("invalid ACL rule (source = {source_agent:?}, target = {target_agent:?}): {reason}")]
    InvalidAclRule {
        source_agent: String,
        target_agent: String,
        reason: &'static str,
    },

    /// The audit path's parent directory is missing or not writable.
    #[error("audit.path parent directory is not writable: {path}")]
    AuditDirMissing { path: String },

    /// The agent has no ingress or egress rules.
    #[error("agent has no ingress or egress configured and will do nothing")]
    AgentNoop,

    /// `[control]` is enabled but auth_token is missing.
    #[error("[control] auth_token is required when enabled = true")]
    ControlAuthMissing,

    /// `[control]` binds to a non-loopback address without an explicit
    /// `allow_remote = true`.
    #[error("[control] binding to non-loopback ({addr}) requires an explicit allow_remote = true")]
    ControlRemoteWithoutFlag { addr: String },

    /// Free-form validation failure (diagnostics without structured fields,
    /// e.g. missing files or invalid field formats).
    #[error("{0}")]
    Invalid(String),
}

/// A list of configuration errors.
#[derive(Debug, Clone, Default)]
pub struct ConfigErrorList {
    errors: Vec<ConfigError>,
}

impl ConfigErrorList {
    /// Wraps a `Vec<ConfigError>` into a list.
    pub const fn new(errors: Vec<ConfigError>) -> Self {
        Self { errors }
    }

    /// Number of errors.
    pub const fn len(&self) -> usize {
        self.errors.len()
    }

    /// Whether it is empty.
    pub const fn is_empty(&self) -> bool {
        self.errors.is_empty()
    }

    /// Iterates over the errors.
    pub fn iter(&self) -> impl Iterator<Item = &ConfigError> {
        self.errors.iter()
    }
}

impl std::fmt::Display for ConfigErrorList {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let bullets: String = self
            .errors
            .iter()
            .map(|e| format!("  - {e}"))
            .collect::<Vec<_>>()
            .join("\n");
        write!(
            f,
            "configuration validation failed ({} errors):\n{}",
            self.errors.len(),
            bullets
        )
    }
}

impl std::error::Error for ConfigErrorList {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.errors.first().map(|e| e as &dyn std::error::Error)
    }
}

const MAX_CONFIG_ID_LEN: usize = 128;

fn valid_agent_id(s: &str) -> bool {
    // Disallow a leading `_`: the wire layer reserves sentinels (e.g.
    // `_response_`) that reuse the source_agent field
    !s.starts_with('_')
        && s.len() <= MAX_CONFIG_ID_LEN
        && !s.is_empty()
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_' || b == b'.')
}

const fn is_loopback(addr: std::net::SocketAddr) -> bool {
    addr.ip().is_loopback()
}

/// Validates the hub configuration.
///
/// `Ok(())` means it passed; `Err(ConfigErrorList)` means there are errors
/// (all of them included).
pub fn validate_hub(cfg: &HubConfig) -> Result<(), ConfigErrorList> {
    let mut errs = Vec::new();

    // 1. config_version
    if cfg.config_version != HUB_CONFIG_VERSION {
        errs.push(ConfigError::UnsupportedVersion {
            expected: HUB_CONFIG_VERSION,
            actual: cfg.config_version,
        });
    }

    // 2. auth must have credentials or an explicit allow_anonymous
    if !cfg.auth.has_any_credential() {
        errs.push(ConfigError::AuthRequired);
    }

    // 3. mode-specific required fields
    match cfg.auth.mode {
        crate::config::AuthMode::StaticToken => {
            let has_agent = cfg
                .auth
                .static_token
                .as_ref()
                .is_some_and(|s| s.agent.is_some());
            if !has_agent && !cfg.auth.allow_anonymous {
                errs.push(ConfigError::StaticTokenMissing);
            }
        }
        crate::config::AuthMode::Mtls => {
            if cfg.auth.mtls.is_none() && !cfg.auth.allow_anonymous {
                errs.push(ConfigError::MtlsCaMissing);
            }
        }
        crate::config::AuthMode::Anonymous => {
            // already covered by has_any_credential
        }
    }

    // 4. TLS completeness + file existence
    if let Some(tls) = &cfg.tls
        && tls.enabled
    {
        if !Path::new(&tls.cert_path).exists() {
            errs.push(ConfigError::Invalid(format!(
                "[tls] cert_path does not exist: {}",
                tls.cert_path
            )));
        }
        if !Path::new(&tls.key_path).exists() {
            errs.push(ConfigError::Invalid(format!(
                "[tls] key_path does not exist: {}",
                tls.key_path
            )));
        }
    }

    // 5. port collision (server vs metrics)
    if cfg.metrics.enabled && cfg.metrics.listen_addr == cfg.server.listen_addr {
        errs.push(ConfigError::PortCollision {
            a: cfg.server.listen_addr.to_string(),
            b: cfg.metrics.listen_addr.to_string(),
        });
    }

    // 6. ACL rule fields
    for rule in &cfg.acl.rules {
        if !valid_agent_id(&rule.source) {
            errs.push(ConfigError::InvalidAclRule {
                source_agent: rule.source.clone(),
                target_agent: rule.target.clone(),
                reason: "invalid source (max 128 chars, [A-Za-z0-9_.-])",
            });
        }
        if !valid_agent_id(&rule.target) {
            errs.push(ConfigError::InvalidAclRule {
                source_agent: rule.source.clone(),
                target_agent: rule.target.clone(),
                reason: "invalid target (max 128 chars, [A-Za-z0-9_.-])",
            });
        }
    }

    // 7. audit path parent directory (when enabled)
    if cfg.audit.enabled
        && let Some(path) = &cfg.audit.path
        && let Some(parent) = Path::new(path).parent()
        && !parent.is_dir()
    {
        errs.push(ConfigError::AuditDirMissing {
            path: parent.display().to_string(),
        });
    }

    // 8. heartbeat cadence sanity: an enabled heartbeat must actually tick.
    //    (interval = 0 previously degraded into a silent 30s fallback poll —
    //    indistinguishable from `enabled = false` in the config file.)
    if cfg.heartbeat.enabled && cfg.heartbeat.interval_secs == 0 {
        errs.push(ConfigError::Invalid(
            "[heartbeat] interval_secs must be >= 1 when enabled; to disable heartbeats use \
             enabled = false"
                .to_string(),
        ));
    }

    // 9. poll_grace must tolerate the agent supervisor's reconnect-backoff
    //    cap (`BACKOFF_CAP`, single-sourced in core `config::params`): a
    //    healthy agent riding out its worst-case backoff stays registered.
    //    Going below it is a legitimate choice (evicted agents implicitly
    //    re-register on their next /poll), but it must be deliberate.
    if cfg.security.poll_grace_secs < interflow_core::config::params::BACKOFF_CAP.as_secs() {
        errs.push(ConfigError::Invalid(format!(
            "[security] poll_grace_secs ({}) is below the supervisor backoff cap ({}s): \
             agents mid-backoff will be evicted (recoverable via implicit \
             re-registration, at the cost of an orphan-stream sweep)",
            cfg.security.poll_grace_secs,
            interflow_core::config::params::BACKOFF_CAP.as_secs()
        )));
    }

    // 10. transport-layer timing sanity: keepalive must be able to preempt
    //     the idle timeout (QUIC) / outlast its own interval (h2). These are
    //     the invariants the shared transport profile guarantees by default;
    //     explicit config must not break them.
    if cfg.transport.quic.enabled {
        if cfg.transport.quic.max_idle_timeout_ms == 0
            || cfg.transport.quic.keepalive_interval_ms == 0
        {
            errs.push(ConfigError::Invalid(
                "[transport.quic] max_idle_timeout_ms and keepalive_interval_ms must be > 0"
                    .to_string(),
            ));
        } else if u64::from(cfg.transport.quic.keepalive_interval_ms)
            >= u64::from(cfg.transport.quic.max_idle_timeout_ms)
        {
            errs.push(ConfigError::Invalid(
                "[transport.quic] keepalive_interval_ms must be < max_idle_timeout_ms \
                 (otherwise keepalives cannot preempt the idle timeout)"
                    .to_string(),
            ));
        }
    }
    if cfg.transport.h2.keepalive_interval_secs == 0 || cfg.transport.h2.keepalive_timeout_secs == 0
    {
        errs.push(ConfigError::Invalid(
            "[transport.h2] keepalive_interval_secs and keepalive_timeout_secs must be > 0"
                .to_string(),
        ));
    } else if cfg.transport.h2.keepalive_timeout_secs <= cfg.transport.h2.keepalive_interval_secs {
        errs.push(ConfigError::Invalid(
            "[transport.h2] keepalive_timeout_secs must be > keepalive_interval_secs".to_string(),
        ));
    }

    if errs.is_empty() {
        Ok(())
    } else {
        Err(ConfigErrorList::new(errs))
    }
}

/// Validates the agent configuration.
pub fn validate_agent(cfg: &AgentConfig) -> Result<(), ConfigErrorList> {
    let mut errs = Vec::new();

    if cfg.config_version != AGENT_CONFIG_VERSION {
        errs.push(ConfigError::UnsupportedVersion {
            expected: AGENT_CONFIG_VERSION,
            actual: cfg.config_version,
        });
    }

    if !valid_agent_id(&cfg.agent.id) {
        errs.push(ConfigError::Invalid(format!(
            "[agent] invalid id (max 128 chars, [A-Za-z0-9_.-]): {}",
            cfg.agent.id
        )));
    }

    // ingress target_agent validation
    for rule in &cfg.ingress {
        if !valid_agent_id(&rule.target_agent) {
            errs.push(ConfigError::Invalid(format!(
                "[[ingress]] {} invalid target_agent: {}",
                rule.name, rule.target_agent
            )));
        }
        if rule.idle_timeout_secs == Some(0) {
            errs.push(ConfigError::Invalid(format!(
                "[[ingress]] {} idle_timeout_secs must be greater than 0",
                rule.name
            )));
        }
    }

    // egress field validation
    for rule in &cfg.egress {
        if rule.udp_idle_timeout_secs == Some(0) {
            errs.push(ConfigError::Invalid(format!(
                "[[egress]] {} udp_idle_timeout_secs must be greater than 0",
                rule.name
            )));
        }
    }

    // timeout-class zeros are rejected outright (zero-value semantics are
    // reserved for limit-class knobs, where 0 = unlimited; a "0-second
    // timeout" is never what anyone wants, and the runtime used to silently
    // clamp it to 1s instead)
    if cfg.agent.connect_timeout_secs == 0 {
        errs.push(ConfigError::Invalid(
            "[agent] connect_timeout_secs must be >= 1".to_string(),
        ));
    }
    for (name, v) in [
        (
            "egress_backend_write_timeout_secs",
            cfg.egress_backend_write_timeout_secs,
        ),
        (
            "egress_resolve_timeout_secs",
            cfg.egress_resolve_timeout_secs,
        ),
        (
            "egress_connect_timeout_secs",
            cfg.egress_connect_timeout_secs,
        ),
    ] {
        if v == 0 {
            errs.push(ConfigError::Invalid(format!(
                "{name} must be >= 1 (0 is not a valid timeout; limit-class knobs are the \
                 only ones where 0 means unlimited)"
            )));
        }
    }
    if cfg.agent.request_establish_timeout_secs == Some(0) {
        errs.push(ConfigError::Invalid(
            "[agent] request_establish_timeout_secs: omit the field to keep the default \
             (0 is not a valid timeout)"
                .to_string(),
        ));
    }
    // (`poll_idle_timeout_secs = 0` and `task_stall_timeout_secs = 0` stay
    // valid: they are the documented explicit "disable" escape hatches.)

    // the open-rate burst bucket must absorb a whole-table stream-creation
    // spike in one go (the same invariant the derived event-channel
    // capacity enforces structurally in core)
    if cfg.max_incoming_streams > 0
        && cfg.max_stream_opens_per_sec > 0
        && u64::from(cfg.stream_open_burst)
            < u64::try_from(cfg.max_incoming_streams).unwrap_or(u64::MAX)
    {
        errs.push(ConfigError::Invalid(format!(
            "stream_open_burst ({}) must be >= max_incoming_streams ({}): a legitimate \
             whole-table creation spike must not trip the rate limiter",
            cfg.stream_open_burst, cfg.max_incoming_streams
        )));
    }

    // agent-side QUIC transport: same timing sanity as the hub's
    // (keepalive must be able to preempt the negotiated-minimum idle
    // timeout)
    if matches!(cfg.agent.transport, crate::config::TransportKind::Quic)
        && (cfg.transport.quic.max_idle_timeout_ms == 0
            || cfg.transport.quic.keepalive_interval_ms == 0
            || u64::from(cfg.transport.quic.keepalive_interval_ms)
                >= u64::from(cfg.transport.quic.max_idle_timeout_ms))
    {
        errs.push(ConfigError::Invalid(
            "[transport.quic] max_idle_timeout_ms and keepalive_interval_ms must be > 0 and \
             keepalive_interval_ms < max_idle_timeout_ms"
                .to_string(),
        ));
    }

    // per-target breaker validation
    if cfg.egress_target_breaker_enabled {
        if cfg.egress_target_breaker_failure_threshold == 0 {
            errs.push(ConfigError::Invalid(
                "egress_target_breaker_failure_threshold must be greater than 0 when the breaker is enabled"
                    .to_string(),
            ));
        }
        if cfg.egress_target_breaker_window_secs == 0 {
            errs.push(ConfigError::Invalid(
                "egress_target_breaker_window_secs must be greater than 0 when the breaker is enabled"
                    .to_string(),
            ));
        }
        if cfg.egress_target_breaker_cooldown_secs == 0 {
            errs.push(ConfigError::Invalid(
                "egress_target_breaker_cooldown_secs must be greater than 0 when the breaker is enabled"
                    .to_string(),
            ));
        }
    }

    // transport = "quic" requires hub_quic_addr
    if matches!(cfg.agent.transport, crate::config::TransportKind::Quic) {
        let addr_ok = cfg
            .agent
            .hub_quic_addr
            .as_ref()
            .is_some_and(|a| a.parse::<std::net::SocketAddr>().is_ok() || a.contains(':'));
        if !addr_ok {
            errs.push(ConfigError::Invalid(
                "[agent] transport = \"quic\" requires a valid hub_quic_addr (host:port)"
                    .to_string(),
            ));
        }
    }

    // control hardening
    if cfg.control.enabled {
        if cfg.control.auth_token.is_none() {
            errs.push(ConfigError::ControlAuthMissing);
        }
        if !is_loopback(cfg.control.listen_addr) && !cfg.control.allow_remote {
            errs.push(ConfigError::ControlRemoteWithoutFlag {
                addr: cfg.control.listen_addr.to_string(),
            });
        }
    }

    // TLS file existence (when enabled)
    if let Some(tls) = &cfg.tls
        && tls.enabled
    {
        if let Some(ca) = &tls.ca_path
            && !Path::new(ca).exists()
        {
            errs.push(ConfigError::Invalid(format!(
                "[tls] ca_path does not exist: {ca}"
            )));
        }
        if let Some(cert) = &tls.client_cert_path
            && !Path::new(cert).exists()
        {
            errs.push(ConfigError::Invalid(format!(
                "[tls] client_cert_path does not exist: {cert}"
            )));
        }
        if let Some(key) = &tls.client_key_path
            && !Path::new(key).exists()
        {
            errs.push(ConfigError::Invalid(format!(
                "[tls] client_key_path does not exist: {key}"
            )));
        }
    }

    if errs.is_empty() {
        Ok(())
    } else {
        Err(ConfigErrorList::new(errs))
    }
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
    use crate::config::*;

    fn base_hub_config() -> HubConfig {
        HubConfig {
            config_version: HUB_CONFIG_VERSION,
            server: ServerConfig {
                listen_addr: "127.0.0.1:6666".parse().unwrap(),
            },
            auth: AuthConfig {
                mode: AuthMode::StaticToken,
                allow_anonymous: false,
                rate_limit_per_minute: 30,
                static_token: Some(StaticTokenConfig {
                    agent: Some("agent-token".to_string()),
                    admin: None,
                }),
                mtls: None,
            },
            tls: None,
            acl: AclConfig::default(),
            security: Default::default(),
            heartbeat: Default::default(),
            metrics: Default::default(),
            audit: Default::default(),
            logging: Default::default(),
            transport: Default::default(),
        }
    }

    #[test]
    fn valid_hub_config_passes() {
        let cfg = base_hub_config();
        validate_hub(&cfg).expect("should pass");
    }

    #[test]
    fn missing_auth_rejected() {
        let mut cfg = base_hub_config();
        cfg.auth.static_token = None;
        cfg.auth.allow_anonymous = false;
        let err = validate_hub(&cfg).expect_err("should reject");
        assert!(err.iter().any(|e| matches!(e, ConfigError::AuthRequired)));
    }

    #[test]
    fn allow_anonymous_satisfies_auth() {
        let mut cfg = base_hub_config();
        cfg.auth.static_token = None;
        cfg.auth.allow_anonymous = true;
        validate_hub(&cfg).expect("should pass");
    }

    #[test]
    fn version_mismatch_rejected() {
        let mut cfg = base_hub_config();
        cfg.config_version = 99;
        validate_hub(&cfg).expect_err("should reject version");
    }

    #[test]
    fn heartbeat_zero_interval_rejected_when_enabled() {
        let mut cfg = base_hub_config();
        cfg.heartbeat.interval_secs = 0;
        let err = validate_hub(&cfg).expect_err("0 interval + enabled must reject");
        assert!(
            err.iter()
                .any(|e| matches!(e, ConfigError::Invalid(m) if m.contains("[heartbeat]")))
        );
        // ...but disabled heartbeats legitimately skip the cadence rule.
        cfg.heartbeat.enabled = false;
        validate_hub(&cfg).expect("disabled heartbeat with 0 interval passes");
    }

    #[test]
    fn poll_grace_below_backoff_cap_rejected() {
        let mut cfg = base_hub_config();
        cfg.security.poll_grace_secs = 10;
        let err = validate_hub(&cfg).expect_err("grace below BACKOFF_CAP must reject");
        assert!(
            err.iter()
                .any(|e| matches!(e, ConfigError::Invalid(m) if m.contains("poll_grace_secs")))
        );
        // Exactly at the cap passes (>= is the invariant).
        cfg.security.poll_grace_secs = interflow_core::config::params::BACKOFF_CAP.as_secs();
        validate_hub(&cfg).expect("grace == backoff cap passes");
    }

    #[test]
    fn quic_keepalive_must_preempt_idle_timeout() {
        let mut cfg = base_hub_config();
        cfg.transport.quic.enabled = true;
        cfg.transport.quic.keepalive_interval_ms = 40_000;
        let err = validate_hub(&cfg).expect_err("keepalive >= idle must reject");
        assert!(
            err.iter()
                .any(|e| matches!(e, ConfigError::Invalid(m) if m.contains("[transport.quic]")))
        );
        cfg.transport.quic.keepalive_interval_ms = 10_000;
        validate_hub(&cfg).expect("sane quic timing passes");
    }

    #[test]
    fn h2_keepalive_timeout_must_outlast_interval() {
        let mut cfg = base_hub_config();
        cfg.transport.h2.keepalive_interval_secs = 5;
        cfg.transport.h2.keepalive_timeout_secs = 5;
        let err = validate_hub(&cfg).expect_err("timeout == interval must reject");
        assert!(
            err.iter()
                .any(|e| matches!(e, ConfigError::Invalid(m) if m.contains("[transport.h2]")))
        );
        cfg.transport.h2.keepalive_timeout_secs = 10;
        validate_hub(&cfg).expect("sane h2 timing passes");
    }

    fn base_agent_config() -> AgentConfig {
        AgentConfig {
            control: ControlConfig {
                enabled: false,
                ..ControlConfig::default()
            },
            ..AgentConfig::for_identity("test-agent", "https://hub.example.com:6666")
        }
    }

    #[test]
    fn agent_zero_timeouts_rejected() {
        let mut cfg = base_agent_config();
        cfg.egress_backend_write_timeout_secs = 0;
        let err = validate_agent(&cfg).expect_err("zero egress timeout must reject");
        assert!(
            err.iter()
                .any(|e| matches!(e, ConfigError::Invalid(m) if m.contains("egress_backend")))
        );

        let mut cfg = base_agent_config();
        cfg.agent.connect_timeout_secs = 0;
        assert!(validate_agent(&cfg).is_err());

        let mut cfg = base_agent_config();
        cfg.agent.request_establish_timeout_secs = Some(0);
        let err = validate_agent(&cfg).expect_err("Some(0) establish must reject");
        assert!(
            err.iter()
                .any(|e| matches!(e, ConfigError::Invalid(m) if m.contains("request_establish")))
        );

        // The documented disable escape hatches stay valid.
        let mut cfg = base_agent_config();
        cfg.agent.poll_idle_timeout_secs = Some(0);
        cfg.agent.task_stall_timeout_secs = Some(0);
        validate_agent(&cfg).expect("documented Some(0) disables stay valid");
    }

    #[test]
    fn agent_burst_must_cover_stream_table() {
        let mut cfg = base_agent_config();
        cfg.max_incoming_streams = 512;
        cfg.stream_open_burst = 256;
        let err = validate_agent(&cfg).expect_err("burst < streams must reject");
        assert!(
            err.iter()
                .any(|e| matches!(e, ConfigError::Invalid(m) if m.contains("stream_open_burst")))
        );
        cfg.stream_open_burst = 512;
        validate_agent(&cfg).expect("burst == streams passes");
        // Unlimited stream cap (0) has no table bound to cover.
        cfg.max_incoming_streams = 0;
        cfg.stream_open_burst = 1;
        validate_agent(&cfg).expect("unlimited streams exempt the burst rule");
    }
}
