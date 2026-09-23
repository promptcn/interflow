//! Hub capability negotiation — one schema, two wire locations.
//!
//! The hub advertises its capabilities to the agent at registration time so
//! the agent can derive its liveness timeouts from the *advertised* cadence
//! instead of guessing. The same [`RegisterResponse`] schema rides two wire
//! locations:
//!
//! - **h2**: the `POST /register` response body (JSON — idiomatic at an HTTP
//!   API boundary);
//! - **QUIC**: the `HelloAck` payload, a fixed-layout binary encoding
//!   ([`RegisterResponse::encode_wire`] /
//!   [`RegisterResponse::parse_wire`], (internal design notes) — the
//!   former `[caps u8][JSON]` hybrid is gone).
//!
//! Hub and agent deploy as a versioned pair (single-user deployment);
//! there is no version-skew handling. A declaration that is absent or
//! fails to parse is a protocol violation — registration fails and the
//! supervisor's retry cycle treats it like any other registration error.
//!
//! All timeout derivations delegate to
//! [`crate::config::params::liveness::HeartbeatCadence`] — this module translates
//! between the wire advertisement and the canonical derivation, and adds
//! nothing on top.

use crate::config::params::liveness::{HeartbeatCadence, TASK_STALL_FALLBACK_SECS};
use crate::error::{InterflowError, Result};
use crate::protocol::CircuitToken;
use bytes::{BufMut, Bytes, BytesMut};
use serde::{Deserialize, Serialize};
use std::time::Duration;

/// The capability declaration: the `POST /register` response body (h2) and
/// the `HelloAck` payload (QUIC), one schema for both.
///
/// Pong transport is not negotiated — it is an invariant of the current
/// protocol: the reply rides the upstream data stream (h2 `/stream/up`) /
/// the control stream (QUIC), so the heartbeat itself proves the agent→hub
/// data path is alive.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RegisterResponse {
    /// Connection-scoped opaque data-plane identity. Rotates on every agent
    /// TLS connection; unlike the heartbeat cadence it is mandatory.
    pub circuit_token: CircuitToken,

    /// Hub heartbeat cadence. Unset = heartbeat disabled (the poll stream
    /// is legitimately silent; the agent watchdog should be disabled).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub heartbeat: Option<HeartbeatAd>,
}

/// The h2 `/route` response: a source-session-scoped opaque route lease.
#[derive(Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct RouteResponse {
    pub route_token: crate::protocol::RouteToken,
}

/// The QUIC HelloAck binary payload layout (after the shared u32 caps word):
/// `[circuit 16 B][hb_present u8]` then, iff `hb_present == 1`,
/// `[interval_secs u32][max_missed u32]`, all big-endian.
const WIRE_HEARTBEAT_PRESENT: u8 = 1;

impl RegisterResponse {
    /// Parses the capability declaration. An unparseable body is a
    /// protocol violation (hub and agent deploy as a pair), not a
    /// fallback trigger.
    pub fn parse(body: &[u8]) -> Result<Self> {
        serde_json::from_slice(body).map_err(|e| {
            InterflowError::protocol("hub capability declaration failed to parse").with_source(e)
        })
    }

    /// Encodes the QUIC HelloAck binary payload: `[caps u32][circuit 16 B]
    /// [hb_present u8]([interval_secs u32][max_missed u32])`.
    pub fn encode_wire(&self, caps: u32) -> Bytes {
        let mut buf = BytesMut::with_capacity(4 + 16 + 1 + 8);
        buf.put_u32(caps);
        buf.put_slice(&self.circuit_token.to_bytes());
        match self.heartbeat {
            Some(hb) => {
                buf.put_u8(WIRE_HEARTBEAT_PRESENT);
                buf.put_u32(u32::try_from(hb.interval_secs).unwrap_or(u32::MAX));
                buf.put_u32(hb.max_missed);
            }
            None => buf.put_u8(0),
        }
        buf.freeze()
    }

    /// Decodes a QUIC HelloAck binary payload, returning `(caps, declaration)`.
    ///
    /// A truncated or over-long payload is a protocol violation (paired
    /// deployment, single format epoch — no fallback shapes). Parsing is
    /// length-checked step by step — no panicking byte-slice indexing.
    pub fn parse_wire(payload: &[u8]) -> Result<(u32, Self)> {
        let invalid = || InterflowError::protocol("hub HelloAck payload is malformed");
        let be_u32 = |b: &[u8]| u32::from_be_bytes([b[0], b[1], b[2], b[3]]);
        if payload.len() < 4 + 16 + 1 {
            return Err(invalid());
        }
        let caps = be_u32(&payload[..4]);
        let mut circuit = [0u8; 16];
        circuit.copy_from_slice(&payload[4..20]);
        let present = payload[20];
        let rest = &payload[21..];
        let heartbeat = if present == WIRE_HEARTBEAT_PRESENT {
            if rest.len() != 8 {
                return Err(invalid());
            }
            Some(HeartbeatAd {
                interval_secs: u64::from(be_u32(&rest[..4])),
                max_missed: be_u32(&rest[4..8]),
            })
        } else if present == 0 && rest.is_empty() {
            None
        } else {
            return Err(invalid());
        };
        Ok((
            caps,
            Self {
                circuit_token: CircuitToken::from_bytes(circuit),
                heartbeat,
            },
        ))
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
        let r = RegisterResponse::parse(
            br#"{"circuit_token":"12078a05e14f4e2c99b1679be1df7c30","heartbeat":{"interval_secs":15,"max_missed":4}}"#,
        )
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
        let r = RegisterResponse::parse(br#"{"circuit_token":"12078a05e14f4e2c99b1679be1df7c30"}"#)
            .unwrap();
        // Heartbeat disabled: the poll stream is legitimately silent; the
        // watchdog is disabled
        assert_eq!(r.poll_watchdog(), Duration::ZERO);
        // ... but a wedged task must still be caught
        assert_eq!(r.task_stall_timeout(), Duration::from_secs(30));
    }

    #[test]
    fn watchdog_derivation_matrix() {
        // Heartbeat enabled: dead line 15*(4+1)=75s + 30s margin
        let r = RegisterResponse::parse(
            br#"{"circuit_token":"12078a05e14f4e2c99b1679be1df7c30","heartbeat":{"interval_secs":15,"max_missed":4}}"#,
        )
            .unwrap();
        assert_eq!(r.poll_watchdog(), Duration::from_secs(105));
        assert_eq!(r.task_stall_timeout(), Duration::from_secs(75));
        // Aggressive parameters also derive correctly
        let r = RegisterResponse::parse(
            br#"{"circuit_token":"12078a05e14f4e2c99b1679be1df7c30","heartbeat":{"interval_secs":1,"max_missed":0}}"#,
        )
            .unwrap();
        assert_eq!(r.poll_watchdog(), Duration::from_secs(31));
        assert_eq!(r.task_stall_timeout(), Duration::from_secs(1));
    }

    /// The QUIC binary wire form round-trips both heartbeat states and
    /// preserves the caps word verbatim at byte 0.
    #[test]
    fn binary_wire_round_trip() {
        let capability = RegisterResponse {
            circuit_token: CircuitToken::from_hex("12078a05e14f4e2c99b1679be1df7c30").unwrap(),
            heartbeat: Some(HeartbeatAd {
                interval_secs: 15,
                max_missed: 4,
            }),
        };
        let payload = capability.encode_wire(0xA5A5_0101);
        assert_eq!(payload.len(), 4 + 16 + 1 + 8);
        let (caps, decoded) = RegisterResponse::parse_wire(&payload).unwrap();
        assert_eq!(caps, 0xA5A5_0101);
        assert_eq!(decoded, capability);
        assert_eq!(decoded.task_stall_timeout(), Duration::from_secs(75));

        let disabled = RegisterResponse {
            circuit_token: CircuitToken::from_hex("12078a05e14f4e2c99b1679be1df7c30").unwrap(),
            heartbeat: None,
        };
        let payload = disabled.encode_wire(0);
        assert_eq!(payload.len(), 4 + 16 + 1);
        let (caps, decoded) = RegisterResponse::parse_wire(&payload).unwrap();
        assert_eq!(caps, 0);
        assert_eq!(decoded, disabled);
        assert_eq!(decoded.task_stall_timeout(), Duration::from_secs(30));
    }

    /// Paired deployment: every malformed shape (empty, truncated header,
    /// truncated heartbeat, over-long) is a protocol violation.
    #[test]
    fn binary_wire_malformed_is_a_protocol_error() {
        let capability = RegisterResponse {
            circuit_token: CircuitToken::from_hex("12078a05e14f4e2c99b1679be1df7c30").unwrap(),
            heartbeat: Some(HeartbeatAd {
                interval_secs: 15,
                max_missed: 4,
            }),
        };
        assert!(RegisterResponse::parse_wire(&[]).is_err());
        assert!(RegisterResponse::parse_wire(&[0, 0, 0, 1, 0]).is_err());
        let full = capability.encode_wire(1);
        assert!(RegisterResponse::parse_wire(&full[..full.len() - 1]).is_err());
        let mut over = BytesMut::new();
        over.put_slice(&full[..]);
        over.put_u8(0xEE);
        let over: Bytes = over.freeze();
        assert!(RegisterResponse::parse_wire(&over).is_err());
        // hb_present must be exactly 0 or 1
        let mut bad_present = BytesMut::new();
        bad_present.put_slice(&full[..4 + 16]);
        bad_present.put_u8(7);
        let bad_present: Bytes = bad_present.freeze();
        assert!(RegisterResponse::parse_wire(&bad_present).is_err());
    }
}
