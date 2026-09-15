//! Wire protocol frame encoding/decoding.
//!
//! See the [`frame`] module docs for details.

pub mod frame;

pub use frame::{
    DecodeOutcome, DecodedFrame, FLAG_COMPRESSED, FLAG_MUST_UNDERSTAND, FLAG_SIGNED, FLAG_UDP,
    FRAME_MAGIC, FRAME_VERSION, FrameType, MAX_FRAME_PAYLOAD, StreamProto, decode_frame,
    decoded_frame_len, encode_frame, encode_frame_header,
};
