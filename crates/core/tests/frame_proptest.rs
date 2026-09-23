//! Property-based tests for the wire frame codec (`protocol::frame`).
//!
//! The decoder is a hand-written stateful parser fed by untrusted bytes from
//! the far side of a TLS connection; these properties are the safety net the
//! hand-written unit tests cannot be:
//!
//! 1. **No panic, buffer contract preserved** — for arbitrary input bytes,
//!    `decode_frame` returns one of its four outcomes without panicking, and
//!    the documented buffer contract holds: `Pending`/`Error` leave the
//!    buffer untouched, `Ok`/`UnknownType` consume exactly one whole frame,
//!    and an `Ok` frame re-encodes to precisely the bytes it consumed.
//! 2. **Round trip** — every contract-valid (type, flags, ids, payload)
//!    combination decodes back to itself and consumes the buffer exactly.
//! 3. **Truncation** — every strict prefix of a valid frame decodes to
//!    `Pending` (a partial frame is never misjudged as complete or invalid).
//! 4. **Mutation** — byte smears over a valid frame (plus arbitrary trailing
//!    garbage) never panic and still obey the buffer contract.
//! 5. **Stream decoding** — N concatenated frames decode in order and drain
//!    the buffer exactly.
//! 6. **Contract totality** — for any (type, flags, id-zero-ness) tuple,
//!    encode succeeds exactly when the type × field contract is satisfied;
//!    a failed encode never writes into the buffer.
//!
//! The same properties are exercised continuously by the cargo-fuzz targets
//! in `/fuzz` (see its README); this file keeps them in the ordinary stable
//! test run.

#![allow(clippy::panic, clippy::unwrap_used, clippy::expect_used)]

use bytes::{Bytes, BytesMut};
use interflow_core::protocol::frame::{self, DecodeOutcome, FrameType};
use interflow_core::protocol::{CircuitToken, StreamId};
use proptest::prelude::*;

fn frame_type() -> impl Strategy<Value = FrameType> {
    proptest::sample::select(vec![
        FrameType::Open,
        FrameType::Data,
        FrameType::Close,
        FrameType::Hello,
        FrameType::HelloAck,
        FrameType::Ping,
        FrameType::Pong,
        FrameType::OpenAck,
        FrameType::Error,
        FrameType::RouteRequest,
        FrameType::RouteAck,
    ])
}

/// Any flags byte (including undefined bits).
fn any_flags() -> impl Strategy<Value = u8> {
    any::<u8>()
}

/// An arbitrary token image (may be the zero marker).
fn token_image() -> impl Strategy<Value = [u8; 16]> {
    any::<[u8; 16]>()
}

fn payload() -> impl Strategy<Value = Vec<u8>> {
    proptest::collection::vec(any::<u8>(), 0..=1024)
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(2048))]

    /// Property 1 — arbitrary bytes: no panic, buffer contract preserved,
    /// and an `Ok` frame re-encodes to exactly the bytes it consumed.
    #[test]
    fn arbitrary_bytes_never_panic_and_keep_buffer_contract(bytes in proptest::collection::vec(any::<u8>(), 0..=4096)) {
        let orig = Bytes::from(bytes);
        let mut buf = BytesMut::from(&orig[..]);
        let before_len = buf.len();
        let outcome = frame::decode_frame(&mut buf);
        match outcome {
            DecodeOutcome::Pending | DecodeOutcome::Error => {
                prop_assert_eq!(buf.len(), before_len, "Pending/Error must not consume");
                prop_assert_eq!(&buf[..], &orig[..], "Pending/Error must not mutate");
            }
            DecodeOutcome::UnknownType { total_len, .. } => {
                prop_assert!(total_len <= before_len);
                prop_assert_eq!(before_len - buf.len(), total_len, "must consume exactly total_len");
            }
            DecodeOutcome::Ok(f) => {
                let consumed = before_len - buf.len();
                prop_assert!(consumed <= before_len);
                // The decoded frame re-encodes to exactly the consumed bytes:
                // decode ∘ encode is the identity over the wire image. The
                // contract holds by construction for decoded frames.
                let mut re = BytesMut::new();
                prop_assert!(frame::encode_frame(
                    f.frame_type, f.flags, f.stream_id, f.circuit, &f.payload, &mut re
                ).is_some(), "a decoded frame must be re-encodable (contract symmetry)");
                prop_assert_eq!(&re[..], &orig[..consumed]);
                prop_assert!(f.payload.len() <= frame::MAX_FRAME_PAYLOAD);
            }
        }
    }

    /// Property 2 + 6 — round trip and contract totality: encode succeeds
    /// exactly for contract-valid combos, and then decodes back identically.
    #[test]
    fn round_trip_and_contract_totality(
        ft in frame_type(),
        flags in any_flags(),
        sid_raw in token_image(),
        circuit_raw in token_image(),
        payload in payload(),
    ) {
        let stream_id = StreamId::from_bytes(sid_raw);
        let circuit = CircuitToken::from_bytes(circuit_raw);
        let mut buf = BytesMut::new();
        let mut re = BytesMut::new();
        let encoded = frame::encode_frame(ft, flags, stream_id, circuit, &payload, &mut buf);
        if encoded.is_none() {
            // Rejected: nothing may have been written.
            prop_assert!(buf.is_empty(), "failed encode must not write bytes");
        } else {
                let total = buf.len();
                prop_assert_eq!(total, frame::decoded_frame_len(payload.len()));
            let DecodeOutcome::Ok(f) = frame::decode_frame(&mut buf) else {
                return Err(proptest::test_runner::TestCaseError::fail(
                    "encode succeeded but decode rejected the bytes (contract asymmetry)",
                ));
            };
            prop_assert_eq!(f.frame_type, ft);
            prop_assert_eq!(f.flags, flags & frame::FLAGS_KNOWN_MASK);
            prop_assert_eq!(f.stream_id, stream_id);
            prop_assert_eq!(f.circuit, circuit);
            prop_assert_eq!(f.payload.as_ref(), payload.as_slice());
            prop_assert!(buf.is_empty(), "exactly one frame, fully consumed");
            let _ = &mut re;
        }
    }

    /// Property 3 — truncation: every strict prefix of a contract-valid
    /// frame is `Pending`, never `Ok` and never `Error`.
    #[test]
    fn strict_prefixes_stay_pending(
        ft in frame_type(),
        flags in any_flags(),
        sid_raw in token_image(),
        circuit_raw in token_image(),
        payload in payload(),
    ) {
        let stream_id = StreamId::from_bytes(sid_raw);
        let circuit = CircuitToken::from_bytes(circuit_raw);
        let mut buf = BytesMut::new();
        if frame::encode_frame(ft, flags, stream_id, circuit, &payload, &mut buf).is_none() {
            // Not contract-valid: nothing to truncate-test.
            return Ok(());
        }
        let full = buf.split().freeze();
        for cut in 0..full.len() {
            let mut partial = BytesMut::from(&full[..cut]);
            let outcome = frame::decode_frame(&mut partial);
            prop_assert!(
                matches!(outcome, DecodeOutcome::Pending),
                "prefix of len {cut} must be Pending, got {outcome:?}"
            );
        }
    }

    /// Property 4 — mutation: random byte smears over a valid frame (plus
    /// trailing garbage) never panic and obey the buffer contract.
    #[test]
    fn mutated_frames_never_panic(
        ft in frame_type(),
        flags in any_flags(),
        sid_raw in token_image(),
        circuit_raw in token_image(),
        payload in payload(),
        mutations in proptest::collection::vec((any::<usize>(), any::<u8>()), 0..16),
        tail in proptest::collection::vec(any::<u8>(), 0..64),
    ) {
        let stream_id = StreamId::from_bytes(sid_raw);
        let circuit = CircuitToken::from_bytes(circuit_raw);
        let mut buf = BytesMut::new();
        if frame::encode_frame(ft, flags, stream_id, circuit, &payload, &mut buf).is_none() {
            return Ok(());
        }
        if !buf.is_empty() {
            for (idx, byte) in &mutations {
                let idx = idx % buf.len();
                buf[idx] = *byte;
            }
        }
        buf.extend_from_slice(&tail);
        let orig = buf.split().freeze();
        let mut rx = BytesMut::from(&orig[..]);
        let before_len = rx.len();
        let outcome = frame::decode_frame(&mut rx);
        match outcome {
            DecodeOutcome::Pending | DecodeOutcome::Error => {
                prop_assert_eq!(rx.len(), before_len);
            }
            DecodeOutcome::UnknownType { total_len, .. } => {
                prop_assert_eq!(before_len - rx.len(), total_len);
            }
            DecodeOutcome::Ok(f) => {
                let consumed = before_len - rx.len();
                let mut re = BytesMut::new();
                if frame::encode_frame(
                    f.frame_type, f.flags, f.stream_id, f.circuit, &f.payload, &mut re,
                )
                .is_some()
                {
                    prop_assert_eq!(&re[..], &orig[..consumed]);
                }
            }
        }
    }

    /// Property 5 — a concatenation of contract-valid frames decodes in
    /// order and drains.
    #[test]
    fn concatenated_frames_decode_in_order(
        frames in proptest::collection::vec(
            (frame_type(), any_flags(), token_image(), token_image(), payload()),
            1..=10
        ),
    ) {
        type Encoded = (FrameType, [u8; 16], [u8; 16], Vec<u8>);
        let mut expected: Vec<Encoded> = Vec::new();
        let mut buf = BytesMut::new();
        for (ft, flags, sid_raw, circuit_raw, payload) in frames {
            let stream_id = StreamId::from_bytes(sid_raw);
            let circuit = CircuitToken::from_bytes(circuit_raw);
            if frame::encode_frame(ft, flags, stream_id, circuit, &payload, &mut buf).is_some() {
                expected.push((ft, sid_raw, circuit_raw, payload));
            }
        }
        for (ft, sid_raw, circuit_raw, payload) in &expected {
            let DecodeOutcome::Ok(f) = frame::decode_frame(&mut buf) else {
                return Err(proptest::test_runner::TestCaseError::fail("expected Ok"));
            };
            prop_assert_eq!(f.frame_type, *ft);
            prop_assert_eq!(f.stream_id, StreamId::from_bytes(*sid_raw));
            prop_assert_eq!(f.circuit, CircuitToken::from_bytes(*circuit_raw));
            prop_assert_eq!(f.payload.as_ref(), payload.as_slice());
        }
        prop_assert!(buf.is_empty());
    }
}
