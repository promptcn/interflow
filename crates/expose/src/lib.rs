//! Interflow expose library entry: ngrok-style public → private-network
//! tunnel — the engine behind the public-domain scenario.
//!
//! Lib-only by design: the `interflow` CLI (`ingress run` / `agent run`) and
//! the GUI drive it from Credential Packs; there is no standalone binary.

#![deny(unsafe_code)]

pub mod client;
pub mod edge;

// Re-exported: it appears in this crate's public API (`ExposeArgs.transport`,
// `Profile.transport`), so downstream users should not need the mesh crate
// just to name the type.
pub use interflow_mesh::config::TransportKind;
