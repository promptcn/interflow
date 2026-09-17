//! Agent-side tunnel: transport abstraction + HTTP/2 backend + facade.
//!
//! - [`transport`]: the [`TunnelTransport`] trait, direction sentinels, and
//!   the inbound dispatcher
//! - [`chunking`]: h2 body chunk hygiene (the wire-safe chunking policy for
//!   every long-lived h2 tunnel body; see the 2026-09-17 GOAWAY churn bug)
//! - [`h2`]: the HTTP/2 backend (streaming `POST /stream/up` uplink +
//!   `GET /poll` downlink)
//! - [`agent`]: the [`AgentTunnel`] facade (consumers program against it)
//! - [`session_tasks`]: the per-session task supervisor (death contract +
//!   stall heartbeat)
//! - [`pump`]: the TCP tunnel stream pump (bidirectional transfer shared by
//!   expose edge / mesh ingress)

pub mod agent;
pub mod chunking;
pub mod h2;
pub mod negotiation;
pub mod pump;
pub mod quic;
pub mod session_tasks;
pub mod transport;

pub use chunking::ChunkHygiene;

pub use agent::{AgentTunnel, DEFAULT_REQUEST_ESTABLISH_TIMEOUT, H2Liveness, SessionSlot};
pub use h2::{H2RequestBody, empty_request_body};
pub use negotiation::{HeartbeatAd, RegisterResponse};
pub use pump::{PumpConfig, StreamPumpTarget, pump_tcp_stream};
pub use session_tasks::{Beat, SessionExitGuard, SessionTasks, TaskExit, TaskExitReason};
pub use transport::{
    CLOSE_SOURCE, FrameSource, IncomingStream, OPEN_SOURCE, PING_SOURCE, RESPONSE_SOURCE,
    TunnelData, TunnelTransport,
};
