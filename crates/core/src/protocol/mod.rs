//! Wire protocol frame encoding/decoding.
//!
//! See the [`frame`] and [`close_reason`] module docs for details.

pub mod close_reason;
pub mod frame;

pub use close_reason::CloseReason;
pub use frame::{FLAG_E2E, FLAG_UDP, FrameType, MAX_FRAME_PAYLOAD, StreamProto};
