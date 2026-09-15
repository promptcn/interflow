//! Soak long-running regression gate (backlog §1.7): a nightly liveness gate over a real
//! process topology + eight assertions.
//!
//! - [`proc`]: subprocess orchestration under test (real hub/agent binaries + TOML configs + SIGTERM)
//! - [`phases`]: periodic silence/burst scheduling and the timeline
//! - [`rss`]: per-PID memory sampling
//! - [`scrape`]: scraping the hub's production `/metrics` endpoint
//! - [`runner`]: scenario orchestration, assertions, artifact, and report (CLI in `bin/soak.rs`)
pub mod phases;
pub mod proc;
pub mod rss;
pub mod runner;
pub mod scrape;
