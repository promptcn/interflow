//! Configuration types shared across scenarios.
//!
//! Scenario-specific configuration (`HubConfig`, `AgentConfig`, etc.) stays
//! in the `interflow-mesh` crate.

pub mod audit;
pub mod logging;
pub mod paths;
pub mod secret;

pub use audit::AuditConfig;
pub use logging::LoggingConfig;
pub use paths::{absolutize, anchor};
pub use secret::{is_indirection, maybe_resolve, resolve};
