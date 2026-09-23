//! Wire protocol frame encoding/decoding.
//!
//! See the [`frame`] and [`close_reason`] module docs for details.

pub mod close_reason;
pub mod frame;
pub mod token;

pub use close_reason::CloseReason;
pub use frame::{
    FLAG_E2E, FLAG_HUB_ORIGIN, FLAG_MUST_UNDERSTAND, FLAG_RESPONSE, FLAG_UDP, FLAGS_KNOWN_MASK,
    FrameOrigin, FrameType, MAX_FRAME_PAYLOAD, StreamProto,
};
pub use token::{CircuitToken, RouteToken, StreamId};
