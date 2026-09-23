//! Wire frame encoding/decoding
//!.
//!
//! Frame format — fixed 41-byte header, all integers big-endian:
//! ```text
//! [magic(2)="IN" | ver(1) | type(1) | flags(1) |
//!  stream_id(16 raw) | circuit(16 raw) | payload_len(u32) | payload]
//! ```
//!
//! The magic and version bytes are repeated on *every* frame (not once per
//! connection): h2 carries frames in one shared long-lived body, so a decoder
//! that just skipped an unknown frame type must be able to resynchronize at
//! the next frame boundary, and a version mismatch is detected on any frame
//! rather than only at connection setup. The 3-byte cost is the accepted
//! trade for that robustness.
//!
//! Unknown-type policy: skip when `FLAG_MUST_UNDERSTAND` is not set;
//! protocol error when it is.
//!
//! Direction and origin live in the flags byte (which replaced the
//! reserved sentinel strings `_response_`/`_close_`/`_open_`/`_ping_`/`_hub_`):
//! `FLAG_RESPONSE` marks the egress→requester return path, `FLAG_HUB_ORIGIN`
//! marks hub-authored frames; in both cases the circuit field carries the
//! all-zero marker. The type × field contract below is enforced by the codec
//! on **both** sides — the table *is* the protocol:
//!
//! | type          | stream_id | circuit                          | flags                    |
//! |---------------|-----------|----------------------------------|--------------------------|
//! | Open          | stream    | requester circuit                | UDP/E2E allowed          |
//! | Data          | stream    | requester circuit / zero (resp)  | RESPONSE allowed         |
//! | Close         | stream    | requester circuit / zero         | RESPONSE, HUB_ORIGIN     |
//! | Hello         | zero      | zero                             | —                        |
//! | HelloAck      | zero      | zero                             | HUB_ORIGIN required      |
//! | Ping          | zero      | zero                             | HUB_ORIGIN required      |
//! | Pong          | zero      | sender circuit                   | —                        |
//! | OpenAck       | stream    | zero                             | HUB_ORIGIN required      |
//! | RouteRequest  | corr id   | zero                             | —                        |
//! | RouteAck      | corr id   | zero                             | HUB_ORIGIN required      |
//! | Error         | zero      | zero                             | HUB_ORIGIN required      |

use bytes::{BufMut, Bytes, BytesMut};
use interflow_contract::FORMAT_VERSION;

use super::token::{CircuitToken, StreamId};

const FRAME_MAGIC: [u8; 2] = *b"IN";
/// Upper bound for a single frame payload (4 MiB), guarding against giant allocations triggered by abnormal lengths.
pub const MAX_FRAME_PAYLOAD: usize = 4 * 1024 * 1024;
/// The fixed header size: magic(2) + ver(1) + type(1) + flags(1) +
/// stream_id(16) + circuit(16) + payload_len(4).
pub const FRAME_HEADER_LEN: usize = 41;

/// flags bit: the caller must understand this frame or tear down the connection.
pub const FLAG_MUST_UNDERSTAND: u8 = 0x01;
/// flags bit: **set on Open frames only** — the stream carries UDP datagram semantics.
///
/// Each Data frame's payload on the stream is exactly one complete UDP
/// datagram (no merging, no fragmentation); frame-loss semantics are decided
/// by per-stream channel backpressure (UDP naturally tolerates loss).
pub const FLAG_UDP: u8 = 0x08;
/// flags bit: **set on Open frames only** — the stream asks for the
/// agent↔agent inner TLS layer.
pub const FLAG_E2E: u8 = 0x10;
/// flags bit: response direction (egress → requester return path). Replaces
/// the former `_response_` sentinel; the circuit field must be the zero marker.
pub const FLAG_RESPONSE: u8 = 0x20;
/// flags bit: the frame was authored by the hub (HelloAck / Ping / OpenAck /
/// RouteAck / Error / Close notifications).
///
/// Replaces the former `_close_`, `_open_`, `_ping_`, `_hub_` sentinels and the
/// bare `"hub"` literal; the circuit field must be the zero marker.
pub const FLAG_HUB_ORIGIN: u8 = 0x40;
/// flags mask: the bits currently defined.
///
/// `COMPRESSED` (0x02) and `SIGNED` (0x04) were never defined here — inner
/// encryption is mandatory (Data payloads are ciphertext, incompressible)
/// and authentication is mTLS. Receive-side handling of unknown bits is
/// "ignore" (forward compatibility within the epoch); encode-side is
/// fail-fast rejection.
pub const FLAGS_KNOWN_MASK: u8 =
    FLAG_MUST_UNDERSTAND | FLAG_UDP | FLAG_E2E | FLAG_RESPONSE | FLAG_HUB_ORIGIN;

/// The carrying protocol of a tunnel stream (declared by the ingress rule, conveyed to egress via the Open frame).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum StreamProto {
    /// TCP byte stream (current behavior, default).
    #[default]
    Tcp,
    /// UDP datagram: each Data frame payload = one complete datagram.
    Udp,
}

impl StreamProto {
    /// The flags-bit representation on an Open frame.
    pub const fn as_flag(self) -> u8 {
        match self {
            Self::Tcp => 0,
            Self::Udp => FLAG_UDP,
        }
    }

    /// Recovers the protocol from Open frame flags.
    pub const fn from_frame_flags(flags: u8) -> Self {
        if flags & FLAG_UDP != 0 {
            Self::Udp
        } else {
            Self::Tcp
        }
    }
}

/// Frame types.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FrameType {
    /// Opens a new stream (control frame). Agent→hub payload: route token
    /// (16 raw bytes); hub→target relay: empty (requester identity is the
    /// header circuit).
    Open,
    /// Data frame.
    Data,
    /// Closes a stream (control frame). Payload: `[reason_code u8]`
    /// (0 = ordinary close; see `interflow_contract::close_reason_code`).
    Close,
    /// Handshake: the agent exposes capability bits to the hub.
    Hello,
    /// Handshake reply: the hub's selected capability bits + registration.
    HelloAck,
    /// Heartbeat request (hub-authored).
    Ping,
    /// Heartbeat reply.
    Pong,
    /// Session-establishment confirmation (QUIC DATAGRAM fast path, backlog §6.2 option 3):
    /// the hub sends it to the agent on the session stream after the relay is
    /// established; before the agent receives it, all Data for that stream
    /// rides stream carriage, and after receipt small datagrams go through
    /// `send_datagram` (eliminating first-packet out-of-order loss).
    OpenAck,
    /// Protocol-level error (payload is `[code u16][text]`).
    Error,
    /// Control-plane route lease request (payload is the semantic target).
    RouteRequest,
    /// Control-plane route lease response (payload is a route token).
    RouteAck,
}

impl FrameType {
    /// Serializes to the type byte.
    pub const fn as_byte(self) -> u8 {
        match self {
            Self::Open => 0x01,
            Self::Data => 0x02,
            Self::Close => 0x03,
            Self::Hello => 0x10,
            Self::HelloAck => 0x11,
            Self::Ping => 0x12,
            Self::Pong => 0x13,
            Self::OpenAck => 0x14,
            Self::Error => 0x20,
            Self::RouteRequest => 0x15,
            Self::RouteAck => 0x16,
        }
    }

    /// Deserializes. Returns known types only; unknown bytes return `None`, letting the caller decide skip vs disconnect.
    pub const fn from_byte(b: u8) -> Option<Self> {
        match b {
            0x01 => Some(Self::Open),
            0x02 => Some(Self::Data),
            0x03 => Some(Self::Close),
            0x10 => Some(Self::Hello),
            0x11 => Some(Self::HelloAck),
            0x12 => Some(Self::Ping),
            0x13 => Some(Self::Pong),
            0x14 => Some(Self::OpenAck),
            0x20 => Some(Self::Error),
            0x15 => Some(Self::RouteRequest),
            0x16 => Some(Self::RouteAck),
            _ => None,
        }
    }

    /// Whether only the hub may author this frame type (the codec requires
    /// `FLAG_HUB_ORIGIN` on these, which closes the agent-impersonates-hub
    /// window the former sentinels left open).
    const fn is_hub_only(self) -> bool {
        matches!(
            self,
            Self::HelloAck | Self::Ping | Self::OpenAck | Self::RouteAck | Self::Error
        )
    }
}

/// Where a frame came from, derived from flags + circuit (replacing the
/// former `FrameSource` sentinel strings). `Copy`: no allocation anywhere.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FrameOrigin {
    /// An agent authored this frame; the opaque circuit identifies which.
    Agent(CircuitToken),
    /// Response direction (egress → requester return path).
    Response,
    /// The hub authored this frame (identity is mTLS-implied).
    Hub,
}

impl FrameOrigin {
    /// Derives the origin from a frame's flags and circuit field.
    pub const fn from_parts(flags: u8, circuit: CircuitToken) -> Self {
        if flags & FLAG_HUB_ORIGIN != 0 {
            Self::Hub
        } else if flags & FLAG_RESPONSE != 0 {
            Self::Response
        } else {
            Self::Agent(circuit)
        }
    }
}

/// Evaluates the type × field contract table (module docs). Returns `false`
/// when the combination is structurally invalid — the caller rejects it
/// (encode: `None`; decode: `Error`).
const fn contract_ok(ft: FrameType, flags: u8, sid: StreamId, circuit: CircuitToken) -> bool {
    let hub = flags & FLAG_HUB_ORIGIN != 0;
    let resp = flags & FLAG_RESPONSE != 0;
    let stream_flags = flags & (FLAG_UDP | FLAG_E2E) != 0;
    let sid_zero = sid.is_zero();
    let circuit_zero = circuit.is_zero();

    // Global rules: hub never responds; origin flags imply an absent
    // circuit; UDP/E2E only ride Open; RESPONSE only rides Data/Close;
    // HUB_ORIGIN rides Close (notifications) and the hub-only types.
    if (hub && resp)
        || ((hub || resp) && !circuit_zero)
        || (stream_flags && !matches!(ft, FrameType::Open))
        || (resp && !matches!(ft, FrameType::Data | FrameType::Close))
        || (hub && !(ft.is_hub_only() || matches!(ft, FrameType::Close)))
        || (ft.is_hub_only() && !hub)
    {
        return false;
    }

    // Per-type field requiredness. `sid` names a stream on the traffic types
    // and a correlation id on the route types; the connection-level types
    // carry the zero marker.
    match ft {
        // Open carries both ids; Data/Close carry the circuit exactly when
        // neither origin flag is set; Pong re-identifies the sender.
        FrameType::Open => !sid_zero && !circuit_zero,
        FrameType::Data | FrameType::Close => !sid_zero && (circuit_zero == (hub || resp)),
        FrameType::Pong => sid_zero && !circuit_zero,
        FrameType::Hello | FrameType::HelloAck | FrameType::Ping | FrameType::Error => {
            sid_zero && circuit_zero
        }
        FrameType::OpenAck | FrameType::RouteRequest | FrameType::RouteAck => {
            !sid_zero && circuit_zero
        }
    }
}

/// Encodes one frame into `dst`.
///
/// Returns `None` for invalid input: unknown flag bits (caller bug,
/// fail-fast — nothing is written) or a violation of the type × field
/// contract. `stream_id`/`circuit` use the all-zero marker where the
/// contract table says the field is absent.
pub fn encode_frame(
    frame_type: FrameType,
    flags: u8,
    stream_id: StreamId,
    circuit: CircuitToken,
    payload: &[u8],
    dst: &mut BytesMut,
) -> Option<()> {
    if flags & !FLAGS_KNOWN_MASK != 0 {
        return None;
    }
    if payload.len() > MAX_FRAME_PAYLOAD {
        return None;
    }
    if !contract_ok(frame_type, flags, stream_id, circuit) {
        return None;
    }

    let needed = FRAME_HEADER_LEN + payload.len();
    dst.reserve(needed);
    dst.put_slice(&FRAME_MAGIC);
    dst.put_u8(FORMAT_VERSION);
    dst.put_u8(frame_type.as_byte());
    dst.put_u8(flags);
    dst.put_slice(&stream_id.to_bytes());
    dst.put_slice(&circuit.to_bytes());
    dst.put_u32(u32::try_from(payload.len()).unwrap_or(u32::MAX));
    dst.put_slice(payload);
    Some(())
}

/// Encodes only the frame header (without the payload bytes).
///
/// Used by the zero-copy send path: the caller first sends `dst` (the
/// header), then sends the payload's `Bytes` (no memcpy involved). Combined
/// with HTTP/2 body's multi-Frame nature, the agent-side buffer-accumulating
/// decoder needs no changes.
pub fn encode_frame_header(
    frame_type: FrameType,
    flags: u8,
    stream_id: StreamId,
    circuit: CircuitToken,
    payload_len: usize,
    dst: &mut BytesMut,
) -> Option<()> {
    if flags & !FLAGS_KNOWN_MASK != 0 {
        return None;
    }
    if payload_len > MAX_FRAME_PAYLOAD {
        return None;
    }
    if !contract_ok(frame_type, flags, stream_id, circuit) {
        return None;
    }

    dst.reserve(FRAME_HEADER_LEN);
    dst.put_slice(&FRAME_MAGIC);
    dst.put_u8(FORMAT_VERSION);
    dst.put_u8(frame_type.as_byte());
    dst.put_u8(flags);
    dst.put_slice(&stream_id.to_bytes());
    dst.put_slice(&circuit.to_bytes());
    dst.put_u32(u32::try_from(payload_len).unwrap_or(u32::MAX));
    Some(())
}

/// A decoded (owned) frame view. `payload` is a `Bytes` sliced zero-copy out of the original buffer.
///
/// When `decode_frame` returns `Ok`, the corresponding bytes have already
/// been split out of `buf`; the caller no longer needs `buf.advance()`.
#[derive(Debug, Clone)]
pub struct DecodedFrame {
    /// The frame type.
    pub frame_type: FrameType,
    /// The flags bits.
    pub flags: u8,
    /// The stream id (or route correlation id); the zero marker on
    /// connection-level frames.
    pub stream_id: StreamId,
    /// The originating agent's opaque circuit; the zero marker on
    /// hub-authored and response-direction frames.
    pub circuit: CircuitToken,
    /// The payload (zero-copy slice).
    pub payload: Bytes,
}

/// The result of attempting to decode one frame.
#[derive(Debug)]
pub enum DecodeOutcome {
    /// One frame fully decoded. The corresponding bytes have been consumed (split) from `buf`.
    Ok(DecodedFrame),
    /// Not enough data; waiting for more bytes. `buf` is unchanged.
    Pending,
    /// Unknown frame type. If `must_understand` is true, the caller should
    /// tear down the connection; otherwise it should skip this frame.
    /// The corresponding bytes have been consumed (split) from `buf`.
    UnknownType {
        /// Whether `FLAG_MUST_UNDERSTAND` was set; when true the connection should be torn down.
        must_understand: bool,
        /// The total byte length of the whole frame (header included).
        total_len: usize,
    },
    /// Protocol error (magic / version / contract violation / invalid
    /// length). The connection should be torn down.
    Error,
}

/// Attempts to decode one frame from `buf`.
///
/// - On `Ok` / `UnknownType`, the corresponding bytes have been consumed from
///   the head of `buf`.
/// - On `Pending` / `Error`, `buf` is left as-is (the caller decides whether
///   to clear on Error).
///
/// The whole fixed header (including `payload_len`) is validated before
/// waiting for payload bytes: an oversized or contract-violating header is
/// rejected without allocation. The `payload` shares the original buffer's
/// memory zero-copy via `Bytes` slicing.
pub fn decode_frame(buf: &mut BytesMut) -> DecodeOutcome {
    if buf.len() < FRAME_HEADER_LEN {
        return DecodeOutcome::Pending;
    }
    if buf[0..2] != FRAME_MAGIC {
        return DecodeOutcome::Error;
    }
    if buf[2] != FORMAT_VERSION {
        return DecodeOutcome::Error;
    }

    let type_byte = buf[3];
    let flags = buf[4];
    let mut sid_bytes = [0u8; 16];
    sid_bytes.copy_from_slice(&buf[5..21]);
    let mut circuit_bytes = [0u8; 16];
    circuit_bytes.copy_from_slice(&buf[21..37]);
    let payload_len = u32::from_be_bytes([buf[37], buf[38], buf[39], buf[40]]) as usize;
    if payload_len > MAX_FRAME_PAYLOAD {
        return DecodeOutcome::Error;
    }

    let sid = StreamId::from_bytes(sid_bytes);
    let circuit = CircuitToken::from_bytes(circuit_bytes);
    let must_understand = (flags & FLAG_MUST_UNDERSTAND) != 0;

    let Some(frame_type) = FrameType::from_byte(type_byte) else {
        // Unknown type: the type-specific contract cannot be evaluated; the
        // general length validity already passed. Consume and report.
        let total = FRAME_HEADER_LEN + payload_len;
        if buf.len() < total {
            return DecodeOutcome::Pending;
        }
        let _ = buf.split_to(total);
        return DecodeOutcome::UnknownType {
            must_understand,
            total_len: total,
        };
    };

    // The contract table is evaluated as soon as the fixed header is
    // available — before any payload wait.
    if !contract_ok(frame_type, flags, sid, circuit) {
        return DecodeOutcome::Error;
    }

    let total = FRAME_HEADER_LEN + payload_len;
    if buf.len() < total {
        return DecodeOutcome::Pending;
    }

    // Key zero-copy path: split the whole frame out, freeze it into Bytes,
    // then use slice to reference the payload portion, avoiding
    // Bytes::copy_from_slice.
    let frame_bytes = buf.split_to(total).freeze();
    let payload = frame_bytes.slice(FRAME_HEADER_LEN..total);

    DecodeOutcome::Ok(DecodedFrame {
        frame_type,
        flags,
        stream_id: sid,
        circuit,
        payload,
    })
}

/// Computes the total length of one whole frame (header + payload).
pub const fn decoded_frame_len(payload_len: usize) -> usize {
    FRAME_HEADER_LEN + payload_len
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

    fn sid() -> StreamId {
        StreamId::random().unwrap()
    }
    fn circuit() -> CircuitToken {
        CircuitToken::random().unwrap()
    }

    /// Contract-valid (type, flags) combos for the given tokens.
    fn valid_combos() -> Vec<(FrameType, u8)> {
        vec![
            (FrameType::Open, 0),
            (FrameType::Open, FLAG_UDP),
            (FrameType::Open, FLAG_E2E),
            (FrameType::Open, FLAG_UDP | FLAG_E2E),
            (FrameType::Open, FLAG_UDP | FLAG_MUST_UNDERSTAND),
            (FrameType::Data, 0),
            (FrameType::Data, FLAG_RESPONSE),
            (FrameType::Data, FLAG_MUST_UNDERSTAND),
            (FrameType::Close, 0),
            (FrameType::Close, FLAG_RESPONSE),
            (FrameType::Close, FLAG_HUB_ORIGIN),
            (FrameType::Hello, 0),
            (FrameType::Hello, FLAG_MUST_UNDERSTAND),
            (FrameType::HelloAck, FLAG_HUB_ORIGIN),
            (FrameType::Ping, FLAG_HUB_ORIGIN),
            (FrameType::Ping, FLAG_HUB_ORIGIN | FLAG_MUST_UNDERSTAND),
            (FrameType::Pong, 0),
            (FrameType::OpenAck, FLAG_HUB_ORIGIN),
            (FrameType::RouteRequest, 0),
            (FrameType::RouteAck, FLAG_HUB_ORIGIN),
            (FrameType::Error, FLAG_HUB_ORIGIN),
        ]
    }

    /// Resolves the contract-mandated field values for a (type, flags) combo.
    fn fields_for(ft: FrameType, flags: u8) -> (StreamId, CircuitToken) {
        let zero_sid = matches!(
            ft,
            FrameType::Hello
                | FrameType::HelloAck
                | FrameType::Ping
                | FrameType::Pong
                | FrameType::Error
        );
        let zero_circuit = match ft {
            FrameType::Open | FrameType::Pong => false,
            FrameType::Data | FrameType::Close => flags & (FLAG_RESPONSE | FLAG_HUB_ORIGIN) != 0,
            _ => true,
        };
        (
            if zero_sid { StreamId::ZERO } else { sid() },
            if zero_circuit {
                CircuitToken::ZERO
            } else {
                circuit()
            },
        )
    }

    #[test]
    fn round_trip_all_contract_valid_combos() {
        for (ft, flags) in valid_combos() {
            let (stream_id, circuit) = fields_for(ft, flags);
            let mut buf = BytesMut::new();
            assert!(
                encode_frame(ft, flags, stream_id, circuit, b"hello", &mut buf).is_some(),
                "{ft:?} flags={flags:#04x} must encode"
            );
            let mut rx = buf;
            let DecodeOutcome::Ok(f) = decode_frame(&mut rx) else {
                panic!("expected Ok for {ft:?} flags={flags:#04x}");
            };
            assert_eq!(f.frame_type, ft);
            assert_eq!(f.flags, flags);
            assert_eq!(f.stream_id, stream_id);
            assert_eq!(f.circuit, circuit);
            assert_eq!(f.payload.as_ref(), b"hello");
            assert!(rx.is_empty(), "decode_frame should have consumed buf");
        }
    }

    #[test]
    fn origin_derivation_matches_flags() {
        let c = circuit();
        assert_eq!(
            FrameOrigin::from_parts(0, c),
            FrameOrigin::Agent(c),
            "plain frames carry the agent circuit"
        );
        assert_eq!(
            FrameOrigin::from_parts(FLAG_RESPONSE, CircuitToken::ZERO),
            FrameOrigin::Response
        );
        assert_eq!(
            FrameOrigin::from_parts(FLAG_HUB_ORIGIN, CircuitToken::ZERO),
            FrameOrigin::Hub
        );
        assert_eq!(
            FrameOrigin::from_parts(FLAG_HUB_ORIGIN | FLAG_RESPONSE, CircuitToken::ZERO),
            FrameOrigin::Hub,
            "hub wins on the (invalid) combined bits"
        );
    }

    #[test]
    fn contract_violations_fail_closed_on_encode_and_decode() {
        let (sid_v, c_v) = (sid(), circuit());
        let violations: Vec<(FrameType, u8, StreamId, CircuitToken, &str)> = vec![
            // Global rules.
            (
                FrameType::Close,
                FLAG_HUB_ORIGIN | FLAG_RESPONSE,
                sid_v,
                CircuitToken::ZERO,
                "hub never responds",
            ),
            (
                FrameType::Data,
                FLAG_HUB_ORIGIN,
                sid_v,
                CircuitToken::ZERO,
                "HUB_ORIGIN not allowed on Data",
            ),
            (
                FrameType::Data,
                FLAG_RESPONSE,
                sid_v,
                c_v,
                "RESPONSE must drop the circuit",
            ),
            (
                FrameType::Close,
                FLAG_HUB_ORIGIN,
                sid_v,
                c_v,
                "HUB_ORIGIN must drop the circuit",
            ),
            (FrameType::Data, FLAG_UDP, sid_v, c_v, "UDP only rides Open"),
            (
                FrameType::Hello,
                FLAG_E2E,
                StreamId::ZERO,
                CircuitToken::ZERO,
                "E2E only rides Open",
            ),
            (
                FrameType::Open,
                FLAG_RESPONSE,
                sid_v,
                c_v,
                "Open is never response-direction",
            ),
            // Per-type field requiredness.
            (
                FrameType::Data,
                0,
                StreamId::ZERO,
                c_v,
                "Data needs a stream id",
            ),
            (
                FrameType::Open,
                0,
                sid_v,
                CircuitToken::ZERO,
                "Open needs the requester circuit",
            ),
            (
                FrameType::Hello,
                0,
                sid_v,
                CircuitToken::ZERO,
                "Hello has no stream id",
            ),
            (
                FrameType::Pong,
                0,
                StreamId::ZERO,
                CircuitToken::ZERO,
                "Pong needs the sender circuit",
            ),
            (
                FrameType::HelloAck,
                0,
                StreamId::ZERO,
                CircuitToken::ZERO,
                "HelloAck must be hub-origin",
            ),
            (
                FrameType::Ping,
                0,
                StreamId::ZERO,
                CircuitToken::ZERO,
                "Ping must be hub-origin",
            ),
        ];
        for (ft, flags, stream_id, circuit, why) in violations {
            let mut buf = BytesMut::new();
            assert!(
                encode_frame(ft, flags, stream_id, circuit, b"", &mut buf).is_none(),
                "encode must reject: {why}"
            );
            // Hand-build the violating wire image to prove decode rejects it
            // too (the codec is the contract on both sides).
            let mut raw = BytesMut::new();
            raw.put_slice(&FRAME_MAGIC);
            raw.put_u8(FORMAT_VERSION);
            raw.put_u8(ft.as_byte());
            raw.put_u8(flags);
            raw.put_slice(&stream_id.to_bytes());
            raw.put_slice(&circuit.to_bytes());
            raw.put_u32(0);
            assert!(
                matches!(decode_frame(&mut raw), DecodeOutcome::Error),
                "decode must reject: {why}"
            );
        }
    }

    #[test]
    fn decode_partial_returns_pending() {
        let mut buf = BytesMut::new();
        let (stream_id, circuit) = (sid(), circuit());
        encode_frame(FrameType::Data, 0, stream_id, circuit, b"payload", &mut buf).unwrap();
        for cut in 0..buf.len() {
            let mut partial = BytesMut::from(&buf[..cut]);
            assert!(matches!(decode_frame(&mut partial), DecodeOutcome::Pending));
        }
    }

    #[test]
    fn decode_bad_magic_errors() {
        let mut buf = BytesMut::from(&b"XX\x02\x02\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"[..]);
        assert!(matches!(decode_frame(&mut buf), DecodeOutcome::Error));
    }

    #[test]
    fn decode_wrong_format_version_errors_fail_closed() {
        let mut frame = BytesMut::new();
        encode_frame(FrameType::Data, 0, sid(), circuit(), b"p", &mut frame).unwrap();
        assert_eq!(frame[2], FORMAT_VERSION);
        // Any other version byte fails closed — derived from the current
        // value so the test survives the number itself being re-pointed.
        for wrong in [
            FORMAT_VERSION.wrapping_add(1),
            FORMAT_VERSION.wrapping_sub(1),
            0xFF,
        ] {
            if wrong == FORMAT_VERSION {
                continue;
            }
            let mut frame = BytesMut::new();
            encode_frame(FrameType::Data, 0, sid(), circuit(), b"p", &mut frame).unwrap();
            frame[2] = wrong;
            assert!(
                matches!(decode_frame(&mut frame), DecodeOutcome::Error),
                "version {wrong} must fail closed"
            );
        }
    }

    #[test]
    fn oversize_payload_encodes_as_none_and_decodes_as_error() {
        let huge = vec![0u8; MAX_FRAME_PAYLOAD + 1];
        let mut buf = BytesMut::new();
        assert!(encode_frame(FrameType::Data, 0, sid(), circuit(), &huge, &mut buf).is_none());
        // Hand-built oversized header (contract-valid otherwise) is rejected
        // at decode before any payload wait or allocation.
        let mut raw = BytesMut::new();
        raw.put_slice(&FRAME_MAGIC);
        raw.put_u8(FORMAT_VERSION);
        raw.put_u8(FrameType::Data.as_byte());
        raw.put_u8(0);
        raw.put_slice(&sid().to_bytes());
        raw.put_slice(&circuit().to_bytes());
        raw.put_u32(u32::try_from(MAX_FRAME_PAYLOAD + 1).unwrap_or(u32::MAX));
        assert!(matches!(decode_frame(&mut raw), DecodeOutcome::Error));
    }

    #[test]
    fn multiple_frames_back_to_back() {
        let (stream_id, circuit) = (sid(), circuit());
        let mut buf = BytesMut::new();
        encode_frame(
            FrameType::Open,
            FLAG_UDP | FLAG_E2E,
            stream_id,
            circuit,
            &[],
            &mut buf,
        )
        .unwrap();
        encode_frame(FrameType::Data, 0, stream_id, circuit, b"bar", &mut buf).unwrap();
        encode_frame(
            FrameType::Close,
            FLAG_HUB_ORIGIN,
            stream_id,
            CircuitToken::ZERO,
            &[3],
            &mut buf,
        )
        .unwrap();

        for expected in [
            (FrameType::Open, FLAG_UDP | FLAG_E2E),
            (FrameType::Data, 0),
            (FrameType::Close, FLAG_HUB_ORIGIN),
        ] {
            let outcome = decode_frame(&mut buf);
            let DecodeOutcome::Ok(f) = outcome else {
                panic!("expected Ok, got {outcome:?}");
            };
            assert_eq!((f.frame_type, f.flags), expected);
        }
        assert!(buf.is_empty());
    }

    #[test]
    fn unknown_type_without_must_understand_reports_skippable() {
        let mut buf = BytesMut::new();
        buf.put_slice(&FRAME_MAGIC);
        buf.put_u8(FORMAT_VERSION);
        buf.put_u8(0x77); // unknown type
        buf.put_u8(0); // flags
        buf.put_slice(&[0u8; 32]); // zero ids
        buf.put_u32(3);
        buf.extend_from_slice(b"xyz");

        let outcome = decode_frame(&mut buf);
        let DecodeOutcome::UnknownType {
            must_understand,
            total_len,
        } = outcome
        else {
            panic!("expected UnknownType, got {outcome:?}");
        };
        assert!(!must_understand);
        assert_eq!(total_len, FRAME_HEADER_LEN + 3);
        assert!(buf.is_empty(), "the unknown frame is consumed");
    }

    #[test]
    fn unknown_type_with_must_understand_reports_fatal() {
        let mut buf = BytesMut::new();
        buf.put_slice(&FRAME_MAGIC);
        buf.put_u8(FORMAT_VERSION);
        buf.put_u8(0x77);
        buf.put_u8(FLAG_MUST_UNDERSTAND);
        buf.put_slice(&[0u8; 32]);
        buf.put_u32(0);

        let outcome = decode_frame(&mut buf);
        match outcome {
            DecodeOutcome::UnknownType {
                must_understand, ..
            } => assert!(must_understand),
            _ => panic!("expected UnknownType"),
        }
    }

    #[test]
    fn unknown_flag_bits_fail_encode_fast() {
        let mut buf = BytesMut::new();
        // Passing an undefined bit (0x80 — and the removed 0x02/0x04 bits
        // 0x02/0x04) must be rejected, not silently masked off the wire.
        for bad in [0x80u8, 0x02, 0x04, 0xFE] {
            assert!(
                encode_frame(
                    FrameType::Ping,
                    bad,
                    StreamId::ZERO,
                    CircuitToken::ZERO,
                    b"",
                    &mut buf
                )
                .is_none(),
                "flags {bad:#04x} must fail encode"
            );
            assert!(
                encode_frame_header(
                    FrameType::Ping,
                    bad,
                    StreamId::ZERO,
                    CircuitToken::ZERO,
                    0,
                    &mut buf
                )
                .is_none(),
                "flags {bad:#04x} must fail header encode"
            );
        }
        assert!(buf.is_empty(), "nothing may be written on rejection");
    }

    #[test]
    fn header_encode_matches_full_encode_prefix() {
        let (stream_id, circuit) = (sid(), circuit());
        let mut full = BytesMut::new();
        let mut head = BytesMut::new();
        encode_frame(
            FrameType::Data,
            0,
            stream_id,
            circuit,
            b"payload",
            &mut full,
        )
        .unwrap();
        encode_frame_header(FrameType::Data, 0, stream_id, circuit, 7, &mut head).unwrap();
        assert_eq!(&head[..], &full[..FRAME_HEADER_LEN]);
        assert_eq!(head.len(), FRAME_HEADER_LEN);
        assert_eq!(decoded_frame_len(7), full.len());
    }

    #[test]
    fn stream_proto_flag_round_trip() {
        assert_eq!(StreamProto::Tcp.as_flag(), 0);
        assert_eq!(StreamProto::Udp.as_flag(), FLAG_UDP);
        assert_eq!(StreamProto::from_frame_flags(0), StreamProto::Tcp);
        assert_eq!(StreamProto::from_frame_flags(FLAG_UDP), StreamProto::Udp);
        // No misjudgment when combined with other flags
        assert_eq!(
            StreamProto::from_frame_flags(FLAG_MUST_UNDERSTAND),
            StreamProto::Tcp
        );
        assert_eq!(
            StreamProto::from_frame_flags(FLAG_E2E | FLAG_UDP),
            StreamProto::Udp
        );
    }
}
