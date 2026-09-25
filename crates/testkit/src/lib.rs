//! Shared test / bench harness for interflow.
//!
//! A single source of truth: stack assembly, certificate generation, backends,
//! readiness probes, and impairment injection shared by the mesh's e2e tests and
//! benches. Cargo permits dev-dependency cycles (`interflow-mesh` dev-depends on
//! this crate while this crate depends on `interflow-mesh`; the same pattern as
//! tokio/tokio-test), so the production dependency graph is unaffected.
//!
//! Modules:
//! - [`certs`]: self-signed CA / server / client certificates (via interflow-certs)
//! - [`config`]: `HubConfig` / `AgentConfig` builders (test and bench presets)
//! - [`stack`]: in-process hub / agent assembly + graceful shutdown + readiness probes
//! - [`backend`]: echo / UDP echo / SSE timestamped-chunk backends (phased, with silence/burst support)
//! - [`impair`]: impairment proxies (TCP byte withholding to simulate lost-segment HOL / real UDP drops + delay)
//! - [`hub_http`]: consumer-side mirrors of the hub's operator HTTP contracts + the shared `GET /agents` e2e client
//! - [`metrics`]: quantiles and scenario result types (bench artifact schema)
//! - [`soak`]: long-running regression gate (real process topology + eight assertions; CLI in `bin/soak.rs`)

// dev-only harness: panicking directly on assembly failure is test-code convention
// (aligned with the tests/common header).
#![allow(
    clippy::all,
    clippy::pedantic,
    clippy::nursery,
    clippy::panic,
    clippy::unwrap_used,
    clippy::expect_used,
    missing_docs
)]

pub mod backend;
pub mod certs;
pub use certs::{tls_client_connect, tls_client_connect_with};
pub mod config;
#[cfg(feature = "fault-injection")]
pub mod fault;
pub mod hub_http;
pub mod impair;
pub mod metrics;
pub mod metrics_harness;
pub mod soak;
pub mod stack;

// Flat re-exports: tests/benches import the common pieces in one line via
// `use interflow_testkit::{...}` (certs/impair/metrics keep their namespaces to
// avoid name collisions with config types).
pub use backend::*;
pub use config::*;
pub use hub_http::*;
pub use stack::*;

/// Deterministic canonical opaque stream id for bare-wire tests.
pub fn opaque_stream_id(label: &str) -> interflow_core::protocol::StreamId {
    use std::collections::hash_map::DefaultHasher;
    use std::hash::{Hash as _, Hasher};

    let mut hasher = DefaultHasher::new();
    label.hash(&mut hasher);
    let value = hasher.finish() | 1;
    let mut bytes = [0u8; 16];
    bytes[..8].copy_from_slice(&value.to_be_bytes());
    bytes[8..].copy_from_slice(&value.to_le_bytes());
    // The OR-1 lineage guarantees nonzero.
    interflow_core::protocol::StreamId::from_bytes(bytes)
}
