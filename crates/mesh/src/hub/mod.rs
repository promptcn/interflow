//! Hub server module.
//!
//! Module layout (split out of the original `server.rs` god module):
//! - [`server`]    — `HubServer` orchestrator (listening + wiring dependencies)
//! - [`handle`]    — `HubHandle`/`HubLifecycle`: spawn + state watch + graceful shutdown for embedders
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

pub mod accept;
pub mod control;
pub mod handle;
pub mod handlers;
pub mod heartbeat;
pub mod poll;
pub mod quic;
pub mod registration;
pub mod route;
pub mod routing;
pub mod server;
pub use server::HubDispatchHandle;
pub mod service;
pub mod state;
pub mod upload;

pub use handle::{HubHandle, HubLifecycle};
pub use server::HubServer;
pub use state::{
    ActiveStream, AgentSession, HubLimits, HubState, QuicAgentConn, SharedActiveStreams,
    SharedAgents, SharedHubConfig, SharedStreamCounts, SharedTlsPlane, StreamFace, TunnelData,
    qualified_agent_id,
};
