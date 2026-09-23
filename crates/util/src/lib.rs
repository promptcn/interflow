//! Shared micro-utilities for Interflow's production crates.
//!
//! This crate is the home for utilities needed by crates that must stay
//! light (`interflow-identity`, `interflow-registrar` do not depend on
//! `interflow-core` and should not). Keep its dependency footprint minimal —
//! anything that would drag tokio/quinn/rustls in belongs in core instead.

pub mod atomic_write;
pub mod authority;
pub mod digest;
pub mod error_chain;
pub mod systemd;

pub use atomic_write::{WriteMode, atomic_write};
pub use authority::{EndpointAuthority, EndpointParseError, parse_authority, parse_endpoint};
pub use digest::sha256_hex;
pub use error_chain::format_chain;
