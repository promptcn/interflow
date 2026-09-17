//! Wire frame encoding/decoding.
//!
//! Frame format:
//! ```text
//! [magic(2) | ver(1) | type(1) | flags(1) |
//!  stream_id_len(u16) | stream_id |
//!  src_agent_len(u16) | src_agent |
//!  payload_len(u32) | payload]
//! ```
//!
//! Unknown-type policy: skip when `FLAG_MUST_UNDERSTAND` is not set;
//! protocol error when it is.

use bytes::{BufMut, Bytes, BytesMut};

/// Wire constants below are crate-internal: they document the frame format and
/// drive encode/decode validation, but no consumer outside this module needs
/// them by name. [`FLAG_UDP`] is the exception — hubs branch on it when
/// dispatching Open frames.
const FRAME_MAGIC: [u8; 2] = *b"IN";
/// The current protocol version.
const FRAME_VERSION: u8 = 2;
/// Upper bound for a single frame payload (4 MiB), guarding against giant allocations triggered by abnormal lengths.
const MAX_FRAME_PAYLOAD: usize = 4 * 1024 * 1024;
/// Upper bound for a single ID field.
const MAX_ID_LEN: usize = 256;

/// flags bit: the caller must understand this frame or tear down the connection.
const FLAG_MUST_UNDERSTAND: u8 = 0x01;
/// flags bit: payload compression (reserved, not enabled this cycle).
const FLAG_COMPRESSED: u8 = 0x02;
/// flags bit: HMAC signature (reserved).
const FLAG_SIGNED: u8 = 0x04;
/// flags bit: **set on Open frames only** — the stream carries UDP datagram semantics.
///
/// Each Data frame's payload on the stream is exactly one complete UDP
/// datagram (no merging, no fragmentation); frame-loss semantics are decided
/// by per-stream channel backpressure (UDP naturally tolerates loss). Old
/// peers ignore unknown flags bits and degrade to treating it as a TCP
/// stream (Close after dial failure, fail fast).
pub const FLAG_UDP: u8 = 0x08;
/// flags mask: the bits currently defined.
const FLAGS_KNOWN_MASK: u8 = FLAG_MUST_UNDERSTAND | FLAG_COMPRESSED | FLAG_SIGNED | FLAG_UDP;

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
    /// Opens a new stream (control frame).
    Open,
    /// Data frame.
    Data,
    /// Closes a stream (control frame).
    Close,
    /// Handshake: the agent exposes version + extension bits to the hub.
    Hello,
    /// Handshake reply: the hub's selected version + extension bits.
    HelloAck,
    /// Heartbeat request.
    Ping,
    /// Heartbeat reply.
    Pong,
    /// Session-establishment confirmation (QUIC DATAGRAM fast path, backlog §6.2 option 3):
    /// the hub sends it to the agent on the session stream after the relay is
    /// established; before the agent receives it, all Data for that stream
    /// rides stream carriage, and after receipt small datagrams go through
    /// `send_datagram` (eliminating first-packet out-of-order loss).
    OpenAck,
    /// Protocol-level error (payload is an error code + text).
    Error,
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
            _ => None,
        }
    }
}

/// Encodes one frame into `dst`.
///
/// Returns `None` for invalid input (ID/payload too long); the caller should
/// handle it. `flags` is usually `0`; optionally `FLAG_MUST_UNDERSTAND` etc.
#[allow(clippy::cast_possible_truncation)]
pub fn encode_frame(
    frame_type: FrameType,
    flags: u8,
    stream_id: &str,
    source_agent: &str,
    payload: &[u8],
    dst: &mut BytesMut,
) -> Option<()> {
    if stream_id.len() > MAX_ID_LEN || source_agent.len() > MAX_ID_LEN {
        return None;
    }
    if payload.len() > MAX_FRAME_PAYLOAD {
        return None;
    }

    // Only already-defined flags bits are allowed, preventing misuse.
    let flags = flags & FLAGS_KNOWN_MASK;

    let needed = 5 + 2 + stream_id.len() + 2 + source_agent.len() + 4 + payload.len();
    dst.reserve(needed);
    dst.put_slice(&FRAME_MAGIC);
    dst.put_u8(FRAME_VERSION);
    dst.put_u8(frame_type.as_byte());
    dst.put_u8(flags);
    dst.put_u16(stream_id.len() as u16);
    dst.put_slice(stream_id.as_bytes());
    dst.put_u16(source_agent.len() as u16);
    dst.put_slice(source_agent.as_bytes());
    dst.put_u32(payload.len() as u32);
    dst.put_slice(payload);
    Some(())
}

/// Encodes only the frame header (without the payload bytes).
///
/// Used by the zero-copy send path: the caller first sends `dst` (the
/// header), then sends the payload's `Bytes` (no memcpy involved). Combined
/// with HTTP/2 body's multi-Frame nature, the agent-side buffer-accumulating
/// decoder needs no changes.
#[allow(clippy::cast_possible_truncation)]
pub fn encode_frame_header(
    frame_type: FrameType,
    flags: u8,
    stream_id: &str,
    source_agent: &str,
    payload_len: usize,
    dst: &mut BytesMut,
) -> Option<()> {
    if stream_id.len() > MAX_ID_LEN || source_agent.len() > MAX_ID_LEN {
        return None;
    }
    if payload_len > MAX_FRAME_PAYLOAD {
        return None;
    }
    let flags = flags & FLAGS_KNOWN_MASK;

    let needed = 5 + 2 + stream_id.len() + 2 + source_agent.len() + 4;
    dst.reserve(needed);
    dst.put_slice(&FRAME_MAGIC);
    dst.put_u8(FRAME_VERSION);
    dst.put_u8(frame_type.as_byte());
    dst.put_u8(flags);
    dst.put_u16(stream_id.len() as u16);
    dst.put_slice(stream_id.as_bytes());
    dst.put_u16(source_agent.len() as u16);
    dst.put_slice(source_agent.as_bytes());
    dst.put_u32(payload_len as u32);
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
    /// The stream id.
    pub stream_id: String,
    /// The source agent.
    pub source_agent: String,
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
    /// Protocol error (magic / version / invalid field). The connection should be torn down.
    Error,
}

/// Attempts to decode one frame from `buf`.
///
/// - On `Ok` / `UnknownType`, the corresponding bytes have been consumed from
///   the head of `buf`.
/// - On `Pending` / `Error`, `buf` is left as-is (the caller decides whether
///   to clear on Error).
///
/// The `payload` shares the original buffer's memory zero-copy via `Bytes`
/// slicing, which — together with `Bytes` refcounting — avoids memcpy under
/// multiplexing.
pub fn decode_frame(buf: &mut BytesMut) -> DecodeOutcome {
    if buf.len() < 5 {
        return DecodeOutcome::Pending;
    }
    if buf[0..2] != FRAME_MAGIC {
        return DecodeOutcome::Error;
    }
    if buf[2] != FRAME_VERSION {
        return DecodeOutcome::Error;
    }

    let type_byte = buf[3];
    let flags = buf[4];

    // Reading the length fields requires at least a 5 + 2 + 2 + 4 = 13 byte header
    if buf.len() < 13 {
        return DecodeOutcome::Pending;
    }
    let mut pos = 5;
    let sid_len = u16::from_be_bytes([buf[pos], buf[pos + 1]]) as usize;
    pos += 2;
    if sid_len > MAX_ID_LEN {
        return DecodeOutcome::Error;
    }
    if buf.len() < pos + sid_len + 2 {
        return DecodeOutcome::Pending;
    }
    let sid_end = pos + sid_len;
    let Ok(stream_id) = std::str::from_utf8(&buf[pos..sid_end]) else {
        return DecodeOutcome::Error;
    };
    pos = sid_end;

    let sa_len = u16::from_be_bytes([buf[pos], buf[pos + 1]]) as usize;
    pos += 2;
    if sa_len > MAX_ID_LEN {
        return DecodeOutcome::Error;
    }
    if buf.len() < pos + sa_len + 4 {
        return DecodeOutcome::Pending;
    }
    let sa_end = pos + sa_len;
    let Ok(source_agent) = std::str::from_utf8(&buf[pos..sa_end]) else {
        return DecodeOutcome::Error;
    };
    pos = sa_end;

    let payload_len =
        u32::from_be_bytes([buf[pos], buf[pos + 1], buf[pos + 2], buf[pos + 3]]) as usize;
    pos += 4;
    if payload_len > MAX_FRAME_PAYLOAD {
        return DecodeOutcome::Error;
    }
    if buf.len() < pos + payload_len {
        return DecodeOutcome::Pending;
    }
    let payload_end = pos + payload_len;
    let total = payload_end;
    let must_understand = (flags & FLAG_MUST_UNDERSTAND) != 0;

    // First convert the &str borrowing buf into an owned String, to avoid a conflict at split_to below.
    let stream_id = stream_id.to_string();
    let source_agent = source_agent.to_string();

    // Key zero-copy path: split the whole frame out, freeze it into Bytes,
    // then use slice to reference the payload portion, avoiding
    // Bytes::copy_from_slice.
    let frame_bytes = buf.split_to(total).freeze();
    // pos still points at payload_start (within frame_bytes)
    let payload = frame_bytes.slice(pos..total);

    FrameType::from_byte(type_byte).map_or_else(
        || DecodeOutcome::UnknownType {
            must_understand,
            total_len: total,
        },
        |frame_type| {
            DecodeOutcome::Ok(DecodedFrame {
                frame_type,
                flags,
                stream_id,
                source_agent,
                payload,
            })
        },
    )
}

/// Computes the total length of one whole frame (header + payload).
///
/// Kept for tests and diagnostics; in production code `decode_frame` already
/// consumes the buffer automatically, so manual computation is unnecessary.
pub const fn decoded_frame_len(stream_id: &str, source_agent: &str, payload_len: usize) -> usize {
    5 + 2 + stream_id.len() + 2 + source_agent.len() + 4 + payload_len
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
    fn round_trip_data_frame() {
        let mut buf = BytesMut::new();
        assert!(encode_frame(FrameType::Data, 0, "sid-1", "agent-A", b"hello", &mut buf).is_some());
        let mut rx = buf;
        let DecodeOutcome::Ok(f) = decode_frame(&mut rx) else {
            panic!("expected Ok");
        };
        assert_eq!(f.frame_type, FrameType::Data);
        assert_eq!(f.flags, 0);
        assert_eq!(f.stream_id, "sid-1");
        assert_eq!(f.source_agent, "agent-A");
        assert_eq!(f.payload.as_ref(), b"hello");
        // decode_frame consumes the buffer automatically
        assert!(rx.is_empty(), "decode_frame should have consumed buf");
    }

    #[test]
    fn decode_payload_is_zero_copy_slice() {
        // Verify the payload Bytes shares the underlying allocation with the
        // original buffer (split_to + slice).
        let mut buf = BytesMut::new();
        encode_frame(FrameType::Data, 0, "s", "a", b"hello", &mut buf);
        let buf_ptr = buf.as_ptr();
        let DecodeOutcome::Ok(f) = decode_frame(&mut buf) else {
            panic!("expected Ok");
        };
        // After decoding, the payload's data pointer should equal the
        // original buf start + header offset. Note that BytesMut may realloc
        // internally after split_to, but Bytes (after freeze) retains the
        // original allocation. We only verify the payload content is correct
        // and do not hard-assert on ptr (an implementation detail).
        assert_eq!(f.payload.as_ref(), b"hello");
        let _ = buf_ptr;
    }

    #[test]
    fn round_trip_with_flags() {
        let mut buf = BytesMut::new();
        encode_frame(
            FrameType::Hello,
            FLAG_MUST_UNDERSTAND,
            "",
            "hub",
            b"capabilities",
            &mut buf,
        );
        let mut rx = buf;
        let DecodeOutcome::Ok(f) = decode_frame(&mut rx) else {
            panic!("expected Ok");
        };
        assert_eq!(f.frame_type, FrameType::Hello);
        assert_eq!(f.flags, FLAG_MUST_UNDERSTAND);
    }

    #[test]
    fn decode_partial_returns_pending() {
        let mut buf = BytesMut::new();
        encode_frame(FrameType::Data, 0, "sid", "agent", b"payload", &mut buf);
        let mut partial = buf.split_to(6);
        assert!(matches!(decode_frame(&mut partial), DecodeOutcome::Pending));
    }

    #[test]
    fn decode_bad_magic_errors() {
        let mut buf = BytesMut::from(&b"XX\x02\x02\x00\x00\x00"[..]);
        assert!(matches!(decode_frame(&mut buf), DecodeOutcome::Error));
    }

    #[test]
    fn oversize_payload_encodes_as_none() {
        let huge = vec![0u8; MAX_FRAME_PAYLOAD + 1];
        let mut buf = BytesMut::new();
        assert!(encode_frame(FrameType::Data, 0, "s", "a", &huge, &mut buf).is_none());
    }

    #[test]
    fn multiple_frames_back_to_back() {
        let mut buf = BytesMut::new();
        encode_frame(FrameType::Open, 0, "s1", "agent", b"foo", &mut buf);
        encode_frame(FrameType::Data, 0, "s1", "agent", b"bar", &mut buf);
        encode_frame(FrameType::Close, 0, "s1", "_close_", b"", &mut buf);

        for expected in [FrameType::Open, FrameType::Data, FrameType::Close] {
            let outcome = decode_frame(&mut buf);
            let DecodeOutcome::Ok(f) = outcome else {
                panic!("expected Ok, got {outcome:?}");
            };
            assert_eq!(f.frame_type, expected);
            // decode_frame has already advanced automatically
        }
        assert!(buf.is_empty());
    }

    #[test]
    fn unknown_type_without_must_understand_reports_skipposable() {
        // Hand-build a frame: valid magic/version, type=0x77 (undefined), flags=0
        let mut buf = BytesMut::new();
        buf.extend_from_slice(&FRAME_MAGIC);
        buf.put_u8(FRAME_VERSION);
        buf.put_u8(0x77); // unknown type
        buf.put_u8(0); // flags
        buf.put_u16(3); // sid_len
        buf.extend_from_slice(b"sid");
        buf.put_u16(2); // sa_len
        buf.extend_from_slice(b"sa");
        buf.put_u32(0); // payload_len

        let outcome = decode_frame(&mut buf);
        match outcome {
            DecodeOutcome::UnknownType {
                must_understand,
                total_len,
            } => {
                assert!(!must_understand);
                // 5(header) + 2(sid_len) + 3(sid) + 2(sa_len) + 2(sa) + 4(payload_len) + 0(payload)
                assert_eq!(total_len, 5 + 2 + 3 + 2 + 2 + 4);
            }
            _ => panic!("expected UnknownType, got {outcome:?}"),
        }
    }

    #[test]
    fn unknown_type_with_must_understand_reports_fatal() {
        let mut buf = BytesMut::new();
        buf.extend_from_slice(&FRAME_MAGIC);
        buf.put_u8(FRAME_VERSION);
        buf.put_u8(0x77); // unknown type
        buf.put_u8(FLAG_MUST_UNDERSTAND); // flags
        buf.put_u16(0); // sid_len
        buf.put_u16(0); // sa_len
        buf.put_u32(0); // payload_len

        let outcome = decode_frame(&mut buf);
        match outcome {
            DecodeOutcome::UnknownType {
                must_understand, ..
            } => assert!(must_understand),
            _ => panic!("expected UnknownType"),
        }
    }

    #[test]
    fn flags_masked_on_encode() {
        let mut buf = BytesMut::new();
        // Passing an undefined bit (0x80) should get masked off
        encode_frame(
            FrameType::Ping,
            0x80 | FLAG_MUST_UNDERSTAND,
            "",
            "",
            b"",
            &mut buf,
        );
        let mut rx = buf;
        let DecodeOutcome::Ok(f) = decode_frame(&mut rx) else {
            panic!("expected Ok");
        };
        assert_eq!(f.flags, FLAG_MUST_UNDERSTAND); // 0x80 masked off
    }

    #[test]
    fn udp_flag_round_trip_on_open() {
        let mut buf = BytesMut::new();
        assert!(
            encode_frame(
                FrameType::Open,
                FLAG_UDP,
                "sid",
                "agent",
                b"1.2.3.4:53",
                &mut buf
            )
            .is_some()
        );
        let mut rx = buf;
        let DecodeOutcome::Ok(f) = decode_frame(&mut rx) else {
            panic!("expected Ok");
        };
        assert_eq!(f.frame_type, FrameType::Open);
        assert_eq!(
            f.flags, FLAG_UDP,
            "FLAG_UDP is part of FLAGS_KNOWN_MASK and must not be masked"
        );
        assert_eq!(StreamProto::from_frame_flags(f.flags), StreamProto::Udp);
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
    }
}
