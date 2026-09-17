//! Logging configuration (schema shared by hub and agent).

use crate::telemetry::LogFormat;
use serde::{Deserialize, Serialize};

/// Logging configuration.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LoggingConfig {
    /// tracing level filter expression (e.g. `info,interflow=debug`).
    #[serde(default = "default_log_level")]
    pub level: String,
    /// Output format.
    #[serde(default)]
    pub format: LogFormat,
}

impl Default for LoggingConfig {
    fn default() -> Self {
        Self {
            level: default_log_level(),
            format: LogFormat::default(),
        }
    }
}

fn default_log_level() -> String {
    "info".to_string()
}
