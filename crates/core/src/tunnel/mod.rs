//! Agent-side tunnel: transport abstraction + HTTP/2 backend + facade.
//!
//! - [`transport`]: the [`TunnelTransport`] trait, direction sentinels, and
//!   the inbound dispatcher
//! - [`h2`]: the HTTP/2 backend (streaming `POST /stream/up` uplink +
//!   `GET /poll` downlink)
//! - [`agent`]: the [`AgentTunnel`] facade (consumers program against it)
//! - [`pump`]: the TCP tunnel stream pump (bidirectional transfer shared by
//!   expose edge / mesh ingress)

pub mod agent;
pub mod h2;
pub mod pump;
pub mod quic;
pub mod transport;

pub use agent::{AgentTunnel, H2Liveness};
pub use h2::{H2RequestBody, empty_request_body};
pub use pump::{PumpConfig, StreamPumpTarget, pump_tcp_stream};
pub use transport::{
    CLOSE_SOURCE, FrameSource, IncomingStream, OPEN_SOURCE, PING_SOURCE, RESPONSE_SOURCE,
    TunnelData, TunnelTransport,
};
