//! Transport-layer tuning shared by the hub and agent schemas.
//!
//! One `[transport.h2]` / `[transport.quic]` shape on both endpoints
//! (QUIC negotiates the idle timeout as the *minimum* of both endpoints).
//! With the same knobs and defaults on both sides, sourced from the shared
//! transport profile in core `config::params`, a link's transport behavior is
//! a property of the pair rather than an accident of which side was tuned.

use serde::{Deserialize, Serialize};
use std::time::Duration;

/// h2 HTTP/2 keepalive tuning — one schema shared verbatim by the hub and
/// agent TOMLs.
///
/// Defaults come from the shared transport profile (core
/// `config::params::transport`), so both ends detect a dead connection on
/// the same schedule by construction.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct H2TransportConfig {
    /// HTTP/2 PING keepalive interval (seconds). Defaults to 5.
    #[serde(default = "default_h2_keepalive_interval_secs")]
    pub keepalive_interval_secs: u64,
    /// Give-up window for a PING ACK beyond the interval (seconds).
    /// Defaults to 10.
    #[serde(default = "default_h2_keepalive_timeout_secs")]
    pub keepalive_timeout_secs: u64,
}

impl H2TransportConfig {
    /// The effective keepalive interval.
    pub const fn keepalive_interval(&self) -> std::time::Duration {
        std::time::Duration::from_secs(self.keepalive_interval_secs)
    }

    /// The effective keepalive timeout.
    pub const fn keepalive_timeout(&self) -> std::time::Duration {
        std::time::Duration::from_secs(self.keepalive_timeout_secs)
    }
}

impl Default for H2TransportConfig {
    fn default() -> Self {
        Self {
            keepalive_interval_secs: default_h2_keepalive_interval_secs(),
            keepalive_timeout_secs: default_h2_keepalive_timeout_secs(),
        }
    }
}

const fn default_h2_keepalive_interval_secs() -> u64 {
    interflow_core::config::params::transport::DEFAULT_H2_KEEPALIVE_INTERVAL.as_secs()
}

const fn default_h2_keepalive_timeout_secs() -> u64 {
    interflow_core::config::params::transport::DEFAULT_H2_KEEPALIVE_TIMEOUT.as_secs()
}

/// Agent-side QUIC transport tuning.
///
/// The hub exposes the same two knobs (plus listener-only fields) in
/// `[transport.quic]`; QUIC negotiates the idle timeout as the endpoints'
/// minimum, so a value raised on only one side has no effect — tune both
/// sides together.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct AgentQuicConfig {
    /// Connection idle timeout (milliseconds). Defaults to 30_000 (frp
    /// default; see the shared transport profile).
    #[serde(default = "default_quic_idle_timeout_ms")]
    pub max_idle_timeout_ms: u32,
    /// KeepAlive interval (milliseconds). Defaults to 10_000; must stay
    /// strictly below the idle timeout (validated).
    #[serde(default = "default_quic_keepalive_interval_ms")]
    pub keepalive_interval_ms: u32,
}

impl Default for AgentQuicConfig {
    fn default() -> Self {
        Self {
            max_idle_timeout_ms: default_quic_idle_timeout_ms(),
            keepalive_interval_ms: default_quic_keepalive_interval_ms(),
        }
    }
}

impl From<&AgentQuicConfig> for interflow_core::tunnel::quic::QuicEndpointParams {
    fn from(cfg: &AgentQuicConfig) -> Self {
        Self {
            max_idle_timeout_ms: cfg.max_idle_timeout_ms,
            keepalive_interval: Duration::from_millis(u64::from(cfg.keepalive_interval_ms)),
        }
    }
}

impl From<&crate::config::HubQuicConfig> for interflow_core::tunnel::quic::QuicEndpointParams {
    fn from(cfg: &crate::config::HubQuicConfig) -> Self {
        Self {
            max_idle_timeout_ms: cfg.max_idle_timeout_ms,
            keepalive_interval: Duration::from_millis(u64::from(cfg.keepalive_interval_ms)),
        }
    }
}

const fn default_quic_idle_timeout_ms() -> u32 {
    interflow_core::config::params::transport::DEFAULT_QUIC_IDLE_TIMEOUT_MS
}

fn default_quic_keepalive_interval_ms() -> u32 {
    u32::try_from(
        interflow_core::config::params::transport::DEFAULT_QUIC_KEEPALIVE_INTERVAL.as_millis(),
    )
    .unwrap_or(10_000)
}
