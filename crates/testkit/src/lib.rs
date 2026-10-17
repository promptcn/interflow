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
//! - [`clock`]: a controllable fake clock for the renewal scheduler's `Clock` seam
//! - [`config`]: `HubConfig` / `AgentConfig` builders (test and bench presets)
//! - [`stack`]: in-process hub / agent assembly + graceful shutdown + readiness probes
//! - [`backend`]: echo / UDP echo / SSE timestamped-chunk backends (phased, with silence/burst support)
//! - [`impair`]: impairment proxies (TCP byte withholding to simulate lost-segment HOL / real UDP drops + delay)
//! - [`hub_http`]: consumer-side mirrors of the hub's operator HTTP contracts + the shared `GET /agents` e2e client
//! - [`http`]: the direct-dial reqwest constructor every test client goes through (ambient-proxy immunity)
//! - [`logging`]: global test-process tracing sink (stderr + ring mirror, `RUST_LOG`-overridable)
//! - [`metrics`]: quantiles and scenario result types (bench artifact schema)
//! - [`registrar`]: in-process registrar fixture (dead-then-alive port, asserted readiness)
//! - [`soak`]: long-running regression gate (real process topology + eight assertions; CLI in `bin/soak.rs`)
//! - [`supervisor`]: bounded Restart=on-success loop (the renewal exit contract's e2e harness)

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
pub mod clock;
pub mod config;
#[cfg(feature = "fault-injection")]
pub mod fault;
pub mod http;
pub mod hub_http;
pub mod impair;
pub mod logging;
pub mod metrics;
pub mod metrics_harness;
pub mod registrar;
pub mod soak;
pub mod stack;
pub mod supervisor;

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

/// Runner policy guard for every e2e suite assembled through this crate.
///
/// Plain libtest (`cargo test`) executes the workspace's test binaries as
/// one strictly sequential queue — a full run costs ~14 minutes where
/// cargo-nextest's per-test processes do the same work in ~5 (baseline
/// 730s → 158s, (internal design notes)). This
/// guard turns that mistake into a fast, loud failure at the first
/// stack/cert construction — seconds into the run — instead of a silent
/// slow one. Documentation alone does not hold this line; the binaries
/// hold it themselves.
///
/// Legitimate libtest surfaces are untouched: doctests
/// (`cargo test --doc`) never execute these binaries, and bench binaries
/// run with `--bench` (exempted below). Single-test iteration is
/// identical under nextest — same arguments, one process. IDE runners
/// that hardcode `cargo test` should switch (rust-analyzer:
/// `rust-analyzer.runnables.command = "nextest"`); the
/// `INTERFLOW_LIBTEST_OK=1` escape hatch exists for libtest-specific
/// debugging only.
pub fn assert_nextest_runner() {
    // cargo bench runs these same binaries in bench mode (`--bench` on the
    // argv); benches are single-binary invocations, not the slow queue
    // this guard exists for.
    if std::env::args().any(|a| a == "--bench") {
        return;
    }
    // nextest marks every test process with its reserved NEXTEST* env
    // namespace (it rejects user variables with that prefix, so presence
    // here is authoritative).
    let nextest = std::env::vars_os().any(|(k, _)| {
        let k = k.to_string_lossy();
        k == "NEXTEST" || k.starts_with("NEXTEST_")
    });
    if nextest || std::env::var_os("INTERFLOW_LIBTEST_OK").is_some() {
        return;
    }
    panic!(
        "this e2e suite is running under plain libtest (`cargo test`): libtest queues every \
         test binary sequentially — a full run takes ~14 min where cargo-nextest takes ~5 \
        \n\
         one suite:   cargo nextest run -p <pkg> --test <binary> [test-name]\n\
         full run:    just test\n\
         override:    INTERFLOW_LIBTEST_OK=1 (libtest-specific debugging only)"
    );
}
