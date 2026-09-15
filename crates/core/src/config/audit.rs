//! Audit log configuration.

use serde::{Deserialize, Serialize};

/// Audit log configuration.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuditConfig {
    /// Whether auditing is enabled.
    #[serde(default)]
    pub enabled: bool,
    /// JSONL file path.
    #[serde(default)]
    pub path: Option<String>,
}
