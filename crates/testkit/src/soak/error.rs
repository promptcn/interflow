//! Typed soak errors (source messages preserved verbatim; the runner
//! renders them into the scenario result at the boundary).

use std::net::SocketAddr;

/// A soak failure: argument violation, environment resolution, subprocess
/// lifecycle, metrics scrape, or readiness probe.
#[derive(Debug, thiserror::Error)]
pub enum SoakError {
    /// Scenario argument / cross-parameter constraint violation.
    #[error("invalid arguments: {0}")]
    Args(String),
    /// Environment resolution (binary lookup, listener readiness).
    #[error("{0}")]
    Env(String),
    /// Subprocess lifecycle failure, attributed to the process name.
    #[error("process {process}: {message}")]
    Process {
        /// "hub" / "egress" / "ingress".
        process: &'static str,
        /// What failed.
        message: String,
    },
    /// Metrics endpoint scrape failure.
    #[error("scrape {addr}: {message}")]
    Scrape {
        /// The metrics endpoint that failed.
        addr: SocketAddr,
        /// What failed.
        message: String,
    },
    /// Data-path readiness probe failure.
    #[error("probe: {0}")]
    Probe(String),
    /// Generic message (assertion composition, startup sequencing).
    #[error("{0}")]
    Msg(String),
}

impl SoakError {
    /// Builds a generic message error.
    pub fn msg(message: impl Into<String>) -> Self {
        Self::Msg(message.into())
    }
}

/// Soak result alias.
pub type SoakResult<T> = std::result::Result<T, SoakError>;
