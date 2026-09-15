//! Interflow expose library entry: ngrok-style public → private-network tunnel.
//!
//! Supports both lib (so tests can reference the edge / host_router modules)
//! and bin (CLI entry).

#![deny(unsafe_code)]

pub mod cert_gen;
pub mod client;
pub mod edge;
pub mod init;
pub mod profile;
