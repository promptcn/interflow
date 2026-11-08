//! Soak long-running regression gate (backlog §1.7): a nightly liveness gate over a real
//! process topology + an assertion suite (listed in [`runner`]).
//!
//! - [`proc`]: subprocess orchestration under test (real hub/agent binaries + TOML configs + SIGTERM)
//! - [`phases`]: periodic silence/burst scheduling and the timeline
//! - [`identity_churn`]: the visitor-identity churn phase (thousands of never-seen client
//!   addresses through the PROXY preamble; the per-client limiter's bound under pressure)
//! - [`rss`]: per-PID memory sampling
//! - [`scrape`]: scraping the hub's production `/metrics` endpoint
//! - [`retention`]: capacity-bounded retention of past runs' logs + post-run gzip
//! - [`runner`]: scenario orchestration, assertions, artifact, and report (CLI in `bin/soak.rs`)
pub mod error;
pub mod identity_churn;
pub mod phases;
pub mod proc;
pub mod retention;
pub mod rss;
pub mod runner;
pub mod scrape;
