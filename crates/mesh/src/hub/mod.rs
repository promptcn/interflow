//! Hub server module.
//!
//! Module layout (split out of the original `server.rs` god module):
//! - [`server`]    — `HubServer` orchestrator (listening + wiring dependencies)
//! - [`handle`]    — `HubHandle`/`HubLifecycle`: spawn + state watch + graceful shutdown for embedders
//! - [`accept`]    — accept loop; TLS/plain traffic dispatched to hyper services
//! - [`service`]   — `HubService` (hyper `Service` implementation + request routing)
//! - [`registration`] — `/register` handling (agent registration + identity binding + implicit re-registration)
//! - [`routing`]   — frame-level stream routing (Open/Data/Close ACL checks + direction checks + dispatch)
//! - [`control`]   — control-plane dispatch (guaranteed-delivery channel for Open / Close lifecycle notifications)
//! - [`upload`]    — `/stream/up` handling (streamed upload, mirror of /poll)
//! - [`poll`]      — `/poll` handling (streamed download + RxStream adapter)
//! - [`heartbeat`] — agent lifecycle (eviction primitive + Ping/Pong heartbeat + `/pong`)
//! - [`handlers`]  — administrative endpoints such as `/agents`
//! - [`http`]      — wire contracts of the operator HTTP surface (typed `/agents` response)
//! - [`snapshot`]  — `GET /snapshot`: the fleet's steady-state picture (upgrade-acceptance data plane)
//! - [`crl`]       — the CRL hot-distribution channel (`PUT /crls`): plane hot-swap + revocation sweep
//! - [`crl_liveness`] — the CRL-poll liveness face (`POST /crls/liveness`): renewal-loop levels + recency sweep
//! - [`watchdog`]   — the resident-task armed-assertion face (register + tick + silence sweep)
//! - [`floor_clock`] — the floor version clock: the change signal `GET /policy/floor/version` holds on
//! - [`state`]     — shared state: `TunnelData`, `AgentSession`, `ActiveStream`, aliases
//! - TLS certificate/private key loading and file permission checks: `interflow_core::tls`

pub mod accept;
pub mod biography;
pub mod control;
pub mod credential_watermarks;
pub mod crl;
pub mod crl_liveness;
pub mod floor_clock;
pub mod handle;
pub mod handlers;
pub mod heartbeat;
pub mod http;
pub mod maintenance;
pub mod node_status;
pub mod policy;
pub mod policy_watermarks;
pub mod poll;
pub mod proposals;
pub mod quic;
pub mod registration;
pub mod route;
pub mod routing;
pub mod server;
pub use server::HubDispatchHandle;
pub mod service;
pub mod snapshot;
pub mod state;
pub mod stream_intents;
pub mod target_recovery;
#[cfg(test)]
pub(crate) mod test_support;
pub mod upload;
pub mod watchdog;

pub use crl::{CrlChannel, PublishCrlsOutcome, publish_crls};
pub use handle::{HubHandle, HubLifecycle};
pub use http::{AgentListEntry, LeafExpiry};
pub use server::HubServer;
pub use snapshot::{
    FLEET_SNAPSHOT_FORMAT_VERSION, FleetSnapshotAgent, FleetSnapshotDoc, FleetSnapshotHub,
    ServingSource, SnapshotTransport,
};
pub use state::{
    ActiveStream, AgentSession, HubLimits, HubState, QuicAgentConn, SharedActiveStreams,
    SharedAgents, SharedHubConfig, SharedStreamCounts, SharedTlsPlane, StreamFace, TunnelData,
    qualified_agent_id,
};
