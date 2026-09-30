//! Control-plane exchange schemas — one schema per concept, one serializer,
//! two wire faces.
//!
//! Registration, route leasing, and rejection/diagnostics exchange payloads
//! whose schemas evolve (multi-field, optional fields, free text). Each
//! concept has exactly one serde derive here, serialized to JSON on both
//! wire faces:
//!
//! - **h2**: the `POST /register` / `POST /route` response bodies (JSON —
//!   idiomatic at an HTTP API boundary);
//! - **QUIC**: the Hello / HelloAck / RouteRequest / RouteAck / Error frame
//!   payloads — the same JSON, with transport-negotiation extras riding as
//!   top-level keys (`caps` via flatten) or in-band outcomes (`granted`).
//!
//! The data-plane frames (Open / Data / Close / Ping / Pong / OpenAck) keep
//! their fixed-layout binary payloads in the frame layer: hot path, fixed
//! trivial shapes (a 16-byte token, a single byte, or nothing) with no
//! evolution surface. Hand-written codecs remain exactly there and nowhere
//! else.
//!
//! History: the wire-format redesign removed the `[caps u8][JSON]` in-frame
//! hybrid but left the QUIC face with a second, hand-written binary codec
//! for the same schema — and the first drift specimen (h2 egress as a bare
//! IP vs QUIC egress as host:port) followed within a day
//!. The
//! 2026-09-29 unification completed the job: one serializer, and the
//! hybrid stays gone (`caps` is a JSON key, not a leading binary word).
//!
//! Hub and agent deploy as a versioned pair (single-user deployment);
//! there is no version-skew handling. An unparseable payload is a protocol
//! violation — registration fails and the supervisor's retry cycle treats
//! it like any other registration error. Within a parseable payload,
//! serde's tolerance applies on both faces alike: unknown keys are ignored,
//! missing optional fields default (heartbeat/egress absent = not
//! advertised), while `circuit_token` stays mandatory.
//!
//! All timeout derivations delegate to
//! [`crate::config::params::liveness::HeartbeatCadence`] — this module translates
//! between the wire advertisement and the canonical derivation, and adds
//! nothing on top.

use crate::config::params::liveness::{HeartbeatCadence, TASK_STALL_FALLBACK_SECS};
use crate::error::{InterflowError, Result};
use crate::protocol::{CircuitToken, RouteToken};
use bytes::Bytes;
use serde::{Deserialize, Serialize};
use std::time::Duration;

/// The capability declaration: the `POST /register` response body (h2) and
/// the flattened body of the HelloAck payload (QUIC), one schema for both.
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

    /// The egress IP the hub observed for this registration (the NAT/egress
    /// truth only the hub's socket sees) — the bare IP, no port: the QUIC
    /// source port is per-connection random and carries no signal, so both
    /// transports report the same form. Surfaced to the agent so embedders
    /// can show "hub-confirmed" connectivity detail without leaving the
    /// process; unset = the hub did not report one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub egress_ip: Option<String>,
}

/// The h2 `/route` response: a source-session-scoped opaque route lease.
/// The QUIC face's in-band counterpart is [`RouteAckWire`] below.
#[derive(Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct RouteResponse {
    pub route_token: crate::protocol::RouteToken,
}

/// The upper bound on a Hello agent id: the hub allocates a `String` from
/// wire input, so the id length is bounded before allocation (DoS surface).
const HELLO_AGENT_ID_MAX: usize = 128;

/// The upper bound on a RouteRequest target — same allocation-bounding
/// rationale, mirroring the h2 face's request-body cap.
const ROUTE_TARGET_MAX: usize = 256;

/// The HelloAck payload: the transport caps word plus the flattened
/// [`RegisterResponse`] — one JSON object, keys at the same level. `caps`
/// is a transport-negotiation bitfield (datagram fast path), not part of
/// the registration receipt, which is why it flattens in alongside rather
/// than joining [`RegisterResponse`].
#[derive(Debug, Serialize, Deserialize)]
struct HelloAckWire {
    caps: u32,
    #[serde(flatten)]
    response: RegisterResponse,
}

/// The Hello payload (agent→hub registration intent): the transport caps
/// word plus the intended semantic id.
#[derive(Debug, Serialize, Deserialize, PartialEq, Eq)]
struct HelloWire {
    caps: u32,
    agent_id: String,
}

/// The RouteRequest payload: the target agent's semantic id. The h2 face
/// carries the same value as the bare-text `POST /route` request body — a
/// single string with no schema, so the two faces share the length bound
/// ([`ROUTE_TARGET_MAX`]) rather than a codec.
#[derive(Debug, Serialize, Deserialize, PartialEq, Eq)]
struct RouteRequestWire {
    target: String,
}

/// The RouteAck payload: the in-band route receipt. `granted == false`
/// (no token) is the denial — the QUIC counterpart of the h2 face's `403`
/// text response: the frame contract has no per-correlation error channel
/// (Error frames are connection-scoped, stream_id zero), so the outcome
/// rides in-band instead.
#[derive(Debug, Serialize, Deserialize, PartialEq, Eq)]
struct RouteAckWire {
    granted: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    route_token: Option<RouteToken>,
}

/// The Error frame payload: a rejection/diagnostic code (constants in
/// `interflow_contract::error_code`) plus human-oriented text. The h2 face
/// expresses the same outcomes as an HTTP status + text body.
#[derive(Debug, Serialize, Deserialize, PartialEq, Eq)]
struct ErrorWire {
    code: u16,
    text: String,
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

    /// Encodes the QUIC HelloAck payload: one JSON object — the caps word
    /// as a top-level key next to the flattened declaration fields.
    pub fn encode_ack_payload(&self, caps: u32) -> Result<Bytes> {
        let wire = HelloAckWire {
            caps,
            response: self.clone(),
        };
        serde_json::to_vec(&wire).map(Bytes::from).map_err(|e| {
            InterflowError::protocol("hub capability declaration failed to encode").with_source(e)
        })
    }

    /// Decodes a QUIC HelloAck payload, returning `(caps, declaration)`.
    ///
    /// An unparseable payload is a protocol violation (paired deployment,
    /// single format epoch — no fallback shapes); within a parseable
    /// object, serde tolerance applies (unknown keys ignored, optional
    /// fields default).
    pub fn parse_ack_payload(payload: &[u8]) -> Result<(u32, Self)> {
        let wire: HelloAckWire = serde_json::from_slice(payload).map_err(|e| {
            InterflowError::protocol("hub HelloAck payload is malformed").with_source(e)
        })?;
        Ok((wire.caps, wire.response))
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

impl RouteResponse {
    /// Parses the h2 `/route` response body. An unparseable body is a
    /// protocol violation (paired deployment), not a fallback trigger.
    pub fn parse(body: &[u8]) -> Result<Self> {
        serde_json::from_slice(body).map_err(|e| {
            InterflowError::protocol("route lease receipt failed to parse").with_source(e)
        })
    }
}

/// Encodes the QUIC Hello payload (one JSON object).
///
/// `agent_id` is the agent's intended semantic id (validated by the hub
/// against the mTLS client-certificate CN — the intent declaration, not a
/// credential); the frame carries no credential material.
pub fn encode_hello_payload(caps: u32, agent_id: &str) -> Result<Bytes> {
    if agent_id.is_empty() {
        return Err(InterflowError::protocol("agent id is empty"));
    }
    if agent_id.len() > HELLO_AGENT_ID_MAX {
        return Err(InterflowError::protocol("agent id too long for Hello"));
    }
    let wire = HelloWire {
        caps,
        agent_id: agent_id.to_owned(),
    };
    serde_json::to_vec(&wire)
        .map(Bytes::from)
        .map_err(|e| InterflowError::protocol("Hello payload failed to encode").with_source(e))
}

/// Decodes a QUIC Hello payload, returning `(caps, agent_id)`.
///
/// A malformed payload — or an empty / over-long id — is a protocol
/// violation (paired deployment; the length bound is the hub's allocation
/// guard).
pub fn decode_hello_payload(payload: &[u8]) -> Result<(u32, String)> {
    let invalid = || InterflowError::protocol("Hello payload is malformed");
    let wire: HelloWire = serde_json::from_slice(payload).map_err(|_| invalid())?;
    if wire.agent_id.is_empty() || wire.agent_id.len() > HELLO_AGENT_ID_MAX {
        return Err(invalid());
    }
    Ok((wire.caps, wire.agent_id))
}

/// Encodes the QUIC RouteRequest payload (one JSON object).
pub fn encode_route_request_payload(target: &str) -> Result<Bytes> {
    if target.len() > ROUTE_TARGET_MAX {
        return Err(InterflowError::protocol("route target is too long"));
    }
    let wire = RouteRequestWire {
        target: target.to_owned(),
    };
    serde_json::to_vec(&wire).map(Bytes::from).map_err(|e| {
        InterflowError::protocol("RouteRequest payload failed to encode").with_source(e)
    })
}

/// Decodes a QUIC RouteRequest payload.
///
/// A malformed payload — or an over-long target — is a protocol violation
/// (the length bound is the hub's allocation guard, mirroring the h2 face's
/// request-body cap).
pub fn decode_route_request_payload(payload: &[u8]) -> Result<String> {
    let invalid = || InterflowError::protocol("RouteRequest payload is malformed");
    let wire: RouteRequestWire = serde_json::from_slice(payload).map_err(|_| invalid())?;
    if wire.target.len() > ROUTE_TARGET_MAX {
        return Err(invalid());
    }
    Ok(wire.target)
}

/// Encodes the QUIC RouteAck payload; `route == None` encodes a denial.
pub fn encode_route_ack_payload(route: Option<RouteToken>) -> Result<Bytes> {
    let wire = RouteAckWire {
        granted: route.is_some(),
        route_token: route,
    };
    serde_json::to_vec(&wire)
        .map(Bytes::from)
        .map_err(|e| InterflowError::protocol("RouteAck payload failed to encode").with_source(e))
}

/// Decodes a QUIC RouteAck payload; a denial decodes as `None`.
pub fn decode_route_ack_payload(payload: &[u8]) -> Result<Option<RouteToken>> {
    let wire: RouteAckWire = serde_json::from_slice(payload)
        .map_err(|_| InterflowError::protocol("RouteAck payload is malformed"))?;
    Ok(if wire.granted {
        wire.route_token.filter(|token| !token.is_zero())
    } else {
        None
    })
}

/// Encodes the Error frame payload (one JSON object).
pub fn encode_error_payload(code: u16, text: &str) -> Result<Bytes> {
    let wire = ErrorWire {
        code,
        text: text.to_owned(),
    };
    serde_json::to_vec(&wire)
        .map(Bytes::from)
        .map_err(|e| InterflowError::protocol("Error payload failed to encode").with_source(e))
}

/// Decodes an Error frame payload, returning `(code, text)`.
pub fn decode_error_payload(payload: &[u8]) -> Result<(u16, String)> {
    let wire: ErrorWire = serde_json::from_slice(payload)
        .map_err(|_| InterflowError::protocol("Error payload is malformed"))?;
    Ok((wire.code, wire.text))
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

    /// The QUIC HelloAck payload is the same JSON as the h2 body, with the
    /// caps word flattened in as a top-level key. Both heartbeat states and
    /// the egress field round-trip; the caps word survives verbatim.
    #[test]
    fn ack_payload_round_trip() {
        let capability = RegisterResponse {
            circuit_token: CircuitToken::from_hex("12078a05e14f4e2c99b1679be1df7c30").unwrap(),
            heartbeat: Some(HeartbeatAd {
                interval_secs: 15,
                max_missed: 4,
            }),
            egress_ip: None,
        };
        let payload = capability.encode_ack_payload(0xA5A5_0101).unwrap();
        // One JSON object: caps rides at the same level as the declaration
        // keys (the flatten layout is the contract).
        let obj: serde_json::Value = serde_json::from_slice(&payload).unwrap();
        assert_eq!(obj["caps"], serde_json::json!(0xA5A5_0101u32));
        assert!(obj.get("circuit_token").is_some());
        let (caps, decoded) = RegisterResponse::parse_ack_payload(&payload).unwrap();
        assert_eq!(caps, 0xA5A5_0101);
        assert_eq!(decoded, capability);
        assert_eq!(decoded.task_stall_timeout(), Duration::from_secs(75));

        let disabled = RegisterResponse {
            circuit_token: CircuitToken::from_hex("12078a05e14f4e2c99b1679be1df7c30").unwrap(),
            heartbeat: None,
            egress_ip: None,
        };
        let payload = disabled.encode_ack_payload(0).unwrap();
        let (caps, decoded) = RegisterResponse::parse_ack_payload(&payload).unwrap();
        assert_eq!(caps, 0);
        assert_eq!(decoded, disabled);
        assert_eq!(decoded.task_stall_timeout(), Duration::from_secs(30));

        // The egress field is the bare IP (no port) on both faces alike.
        let with_egress = RegisterResponse {
            circuit_token: CircuitToken::from_hex("12078a05e14f4e2c99b1679be1df7c30").unwrap(),
            heartbeat: None,
            egress_ip: Some("203.0.113.7".to_string()),
        };
        let payload = with_egress.encode_ack_payload(0).unwrap();
        let (_, decoded) = RegisterResponse::parse_ack_payload(&payload).unwrap();
        assert_eq!(decoded, with_egress);
        let r = RegisterResponse::parse(
            br#"{"circuit_token":"12078a05e14f4e2c99b1679be1df7c30","egress_ip":"203.0.113.7"}"#,
        )
        .unwrap();
        assert_eq!(r.egress_ip.as_deref(), Some("203.0.113.7"));
    }

    /// Paired deployment: every unparseable shape (empty, garbage, trailing
    /// bytes, missing mandatory field, wrong types) is a protocol violation.
    #[test]
    fn ack_payload_malformed_is_a_protocol_error() {
        let capability = RegisterResponse {
            circuit_token: CircuitToken::from_hex("12078a05e14f4e2c99b1679be1df7c30").unwrap(),
            heartbeat: Some(HeartbeatAd {
                interval_secs: 15,
                max_missed: 4,
            }),
            egress_ip: None,
        };
        assert!(RegisterResponse::parse_ack_payload(&[]).is_err());
        assert!(RegisterResponse::parse_ack_payload(b"not json {").is_err());
        // circuit_token is mandatory.
        assert!(RegisterResponse::parse_ack_payload(br#"{"caps":1}"#).is_err());
        // Trailing bytes after the JSON object.
        let full = capability.encode_ack_payload(1).unwrap();
        let trailing: Vec<u8> = full.iter().copied().chain([0xEE]).collect();
        assert!(RegisterResponse::parse_ack_payload(&trailing).is_err());
        // Wrong types.
        assert!(
            RegisterResponse::parse_ack_payload(
                br#"{"caps":"x","circuit_token":"12078a05e14f4e2c99b1679be1df7c30"}"#
            )
            .is_err()
        );
    }

    /// The Hello payload round-trips the caps word and the intended id;
    /// malformed payloads and boundary-violating ids are protocol
    /// violations in both directions.
    #[test]
    fn hello_payload_round_trip() {
        let payload = encode_hello_payload(0xA5A5_0101, "edge-1").unwrap();
        let (caps, name) = decode_hello_payload(&payload).unwrap();
        assert_eq!(caps, 0xA5A5_0101);
        assert_eq!(name, "edge-1");
        assert!(decode_hello_payload(&[]).is_err());
        assert!(decode_hello_payload(b"not json {").is_err());
        assert!(decode_hello_payload(br#"{"caps":1}"#).is_err()); // missing id
        assert!(decode_hello_payload(br#"{"caps":1,"agent_id":""}"#).is_err()); // empty id
        let over_long = format!(r#"{{"caps":1,"agent_id":"{}"}}"#, "x".repeat(129));
        assert!(decode_hello_payload(over_long.as_bytes()).is_err());
        assert!(encode_hello_payload(0, "").is_err());
        assert!(encode_hello_payload(0, &"x".repeat(129)).is_err());
        // The bound itself is inclusive on both sides.
        assert!(encode_hello_payload(0, &"x".repeat(128)).is_ok());
        let boundary = encode_hello_payload(0, &"x".repeat(128)).unwrap();
        assert!(decode_hello_payload(&boundary).is_ok());
    }

    /// RouteRequest/RouteAck payloads round-trip; granted/denied shapes and
    /// malformed rejections hold.
    #[test]
    fn route_payloads_round_trip() {
        let payload = encode_route_request_payload("lan-b/egress-1").unwrap();
        assert_eq!(
            decode_route_request_payload(&payload).unwrap(),
            "lan-b/egress-1"
        );
        assert!(encode_route_request_payload(&"x".repeat(257)).is_err());
        assert!(encode_route_request_payload(&"x".repeat(256)).is_ok());
        assert!(decode_route_request_payload(b"not json {").is_err());

        let route = RouteToken::random().unwrap();
        let ack = encode_route_ack_payload(Some(route)).unwrap();
        assert_eq!(decode_route_ack_payload(&ack).unwrap(), Some(route));
        // Denied: granted=false, no token.
        let denied = encode_route_ack_payload(None).unwrap();
        assert_eq!(decode_route_ack_payload(&denied).unwrap(), None);
        assert!(decode_route_ack_payload(b"").is_err());
        assert!(decode_route_ack_payload(b"not json {").is_err());
    }

    /// The Error payload round-trips; malformed shapes are rejected.
    #[test]
    fn error_payload_round_trip() {
        let payload = encode_error_payload(0x0001, "client certificate required").unwrap();
        let (code, text) = decode_error_payload(&payload).unwrap();
        assert_eq!(code, 0x0001);
        assert_eq!(text, "client certificate required");
        assert!(decode_error_payload(b"").is_err());
        assert!(decode_error_payload(b"not json {").is_err());
        let trailing: Vec<u8> = payload.iter().copied().chain(*b"!").collect();
        assert!(decode_error_payload(&trailing).is_err());
    }

    /// The h2 route receipt parses (and round-trips its own encoding).
    #[test]
    fn route_receipt_parses() {
        let receipt = RouteResponse {
            route_token: RouteToken::random().unwrap(),
        };
        let body = serde_json::to_vec(&receipt).unwrap();
        assert_eq!(RouteResponse::parse(&body).unwrap(), receipt);
        assert!(RouteResponse::parse(b"not json {").is_err());
        assert!(RouteResponse::parse(br"{}").is_err()); // token is mandatory
    }
}
