//! Interflow expose library entry: ngrok-style public → private-network tunnel.
//!
//! Supports both lib (so tests can reference the edge / host_router modules)
//! and bin (CLI entry).

#![deny(unsafe_code)]

pub mod client;
pub mod edge;
pub mod init;
pub mod profile;

// Re-exported: it appears in this crate's public API (`ExposeArgs.transport`,
// `Profile.transport`), so downstream users should not need the mesh crate
// just to name the type.
pub use interflow_mesh::config::TransportKind;
