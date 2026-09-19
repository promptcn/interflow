//! Hub server module.
//!
//! Module layout (split out of the original `server.rs` god module):
//! - [`server`]    — `HubServer` orchestrator (listening + wiring dependencies)
//! - [`accept`]    — accept loop; TLS/plain traffic dispatched to hyper services
//! - [`service`]   — `HubService` (hyper `Service` implementation + request routing)
//! - [`registration`] — `/register` handling (agent registration + identity binding + implicit re-registration)
//! - [`routing`]   — frame-level stream routing (Open/Data/Close ACL checks + direction checks + dispatch)
//! - [`control`]   — control-plane dispatch (guaranteed-delivery channel for Open / `_close_` lifecycle notifications)
//! - [`upload`]    — `/stream/up` handling (streamed upload, mirror of /poll)
//! - [`poll`]      — `/poll` handling (streamed download + RxStream adapter)
//! - [`heartbeat`] — agent lifecycle (eviction primitive + Ping/Pong heartbeat + `/pong`)
//! - [`handlers`]  — administrative endpoints such as `/agents`
//! - [`state`]     — shared state: `TunnelData`, `AgentSession`, `ActiveStream`, aliases
//! - TLS certificate/private key loading and file permission checks: `interflow_core::tls`
//! - [`reload`]    — SIGHUP hot reload

pub mod accept;
pub mod control;
pub mod handlers;
pub mod heartbeat;
pub mod poll;
pub mod quic;
pub mod registration;
pub mod reload;
pub mod routing;
pub mod server;
pub mod service;
pub mod state;
pub mod upload;

pub use server::HubServer;
pub use state::{
    ActiveStream, AgentSession, HubCore, HubHandles, HubLimits, QuicAgentConn, SharedActiveStreams,
    SharedAgents, SharedHubConfig, SharedStreamCounts, SharedTlsPlane, StreamFace, TunnelData,
    qualified_agent_id,
};
