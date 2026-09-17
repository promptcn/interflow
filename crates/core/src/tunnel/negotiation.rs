//! Hub capability negotiation — one schema, two wire locations.
//!
//! The hub advertises its capabilities to the agent at registration time so
//! the agent can derive its liveness timeouts from the *advertised* cadence
//! instead of guessing. The same [`RegisterResponse`] JSON rides two wire
//! locations:
//!
//! - **h2**: the `POST /register` response body;
//! - **QUIC**: the `HelloAck` payload suffix — `[caps u8][capability JSON]`
//!   (see [`crate::tunnel::quic`]).
//!
//! Hub and agent deploy as a versioned pair (single-user deployment);
//! there is no version-skew handling. A declaration that is absent or
//! fails to parse is a protocol violation — registration fails and the
//! supervisor's retry cycle treats it like any other registration error.
//!
//! All timeout derivations delegate to
//! [`crate::config::params::HeartbeatCadence`] — this module translates
//! between the wire advertisement and the canonical derivation, and adds
//! nothing on top.

use crate::config::params::liveness::{HeartbeatCadence, TASK_STALL_FALLBACK_SECS};
use crate::error::{InterflowError, Result};
use serde::{Deserialize, Serialize};
use std::time::Duration;

/// The capability declaration: the `POST /register` response body (h2) and
/// the `HelloAck` payload suffix (QUIC), one JSON schema for both.
///
/// Pong transport is not negotiated — it is an invariant of the current
/// protocol: the reply rides the upstream data stream (h2 `/stream/up`) /
/// the control stream (QUIC), so the heartbeat itself proves the agent→hub
/// data path is alive.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct RegisterResponse {
    /// Hub heartbeat cadence. Unset = heartbeat disabled (the poll stream
    /// is legitimately silent; the agent watchdog should be disabled).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub heartbeat: Option<HeartbeatAd>,
}

impl RegisterResponse {
    /// Parses the capability declaration. An unparseable body is a
    /// protocol violation (hub and agent deploy as a pair), not a
    /// fallback trigger.
    pub fn parse(body: &[u8]) -> Result<Self> {
        serde_json::from_slice(body).map_err(|e| {
            InterflowError::protocol("hub capability declaration failed to parse").with_source(e)
        })
    }

    /// Poll receive-side watchdog derivation (h2 `/poll` path): the
    /// advertised cadence's watchdog (`dead line + jitter margin`).
    /// Heartbeat disabled → the poll stream is legitimately silent (no
    /// Pings) → the watchdog is disabled.
    ///
    /// Returns [`Duration::ZERO`] to indicate disabled.
    pub fn poll_watchdog(&self) -> Duration {
        match self.heartbeat {
            Some(hb) => HeartbeatCadence::from(hb).poll_watchdog(),
            None => Duration::ZERO,
        }
    }

    /// Critical-task stall timeout derivation (transport-independent): the
    /// advertised cadence's aging window WITHOUT the watchdog's jitter
    /// margin — a local task's heartbeat carries none of the network
    /// delivery jitter that margin covers. Fixed fallback when heartbeat
    /// is disabled: a wedged task must still be caught.
    pub fn task_stall_timeout(&self) -> Duration {
        match self.heartbeat {
            Some(hb) => HeartbeatCadence::from(hb).task_stall(),
            None => Duration::from_secs(TASK_STALL_FALLBACK_SECS),
        }
    }
}

/// The advertised hub heartbeat cadence.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub struct HeartbeatAd {
    /// Heartbeat interval (seconds).
    pub interval_secs: u64,
    /// Number of consecutive Pings allowed to go missing before declaring
    /// death (dead line = `interval*(max_missed+1)`).
    pub max_missed: u32,
}

impl From<HeartbeatAd> for HeartbeatCadence {
    fn from(ad: HeartbeatAd) -> Self {
        Self {
            interval_secs: ad.interval_secs,
            max_missed: ad.max_missed,
        }
    }
}

#[cfg(test)]
#[allow(clippy::panic, clippy::unwrap_used)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[test]
    fn unparseable_body_is_a_protocol_error() {
        // Plain text / empty / garbage: paired deployment means these are
        // protocol violations, not legacy hubs to fall back for.
        assert!(RegisterResponse::parse(b"Registered").is_err());
        assert!(RegisterResponse::parse(b"").is_err());
        assert!(RegisterResponse::parse(b"not json {").is_err());
    }

    #[test]
    fn full_body_parses() {
        let r = RegisterResponse::parse(br#"{"heartbeat":{"interval_secs":15,"max_missed":4}}"#)
            .unwrap();
        assert_eq!(
            r.heartbeat,
            Some(HeartbeatAd {
                interval_secs: 15,
                max_missed: 4
            })
        );
    }

    #[test]
    fn heartbeat_absent_means_disabled() {
        let r = RegisterResponse::parse(b"{}").unwrap();
        // Heartbeat disabled: the poll stream is legitimately silent; the
        // watchdog is disabled
        assert_eq!(r.poll_watchdog(), Duration::ZERO);
        // ... but a wedged task must still be caught
        assert_eq!(r.task_stall_timeout(), Duration::from_secs(30));
    }

    #[test]
    fn watchdog_derivation_matrix() {
        // Heartbeat enabled: dead line 15*(4+1)=75s + 30s margin
        let r = RegisterResponse::parse(br#"{"heartbeat":{"interval_secs":15,"max_missed":4}}"#)
            .unwrap();
        assert_eq!(r.poll_watchdog(), Duration::from_secs(105));
        assert_eq!(r.task_stall_timeout(), Duration::from_secs(75));
        // Aggressive parameters also derive correctly
        let r = RegisterResponse::parse(br#"{"heartbeat":{"interval_secs":1,"max_missed":0}}"#)
            .unwrap();
        assert_eq!(r.poll_watchdog(), Duration::from_secs(31));
        assert_eq!(r.task_stall_timeout(), Duration::from_secs(1));
    }
}
