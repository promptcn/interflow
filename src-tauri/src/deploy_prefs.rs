//! Deploy-pane path persistence: the recent manifest/issuer/out triples,
//! in the GUI's prefs db ([`crate::prefs`], `deploy_recent` table). The
//! frontend owns dedupe/promotion and the cap; this layer stores the list
//! most-recent-first, one row per triple.

use serde::{Deserialize, Serialize};

/// One remembered deployment context — the three paths travel as a triple
/// so switching between deployments (e.g. the expose and mesh faces) is one
/// pick, never a mix-and-match of half-remembered paths.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeployContext {
    pub manifest: String,
    pub issuer: String,
    pub out: String,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct DeployPrefs {
    /// Most recent first; the frontend owns dedupe/promotion and the cap.
    pub recent: Vec<DeployContext>,
}

/// Loads the remembered contexts; an unreadable db is simply empty (paths
/// fall back to their defaults — never worth a dialog).
pub fn load() -> DeployPrefs {
    match crate::prefs::PrefsDb::open() {
        Ok(db) => db.deploy(),
        Err(e) => {
            tracing::warn!(node = "gui", "deploy prefs unreadable: {e}");
            DeployPrefs::default()
        }
    }
}

/// Persists the contexts (one transaction).
pub fn save(prefs: &DeployPrefs) -> Result<(), String> {
    let mut db = crate::prefs::PrefsDb::open().map_err(|e| e.to_string())?;
    db.save_deploy(prefs).map_err(|e| e.to_string())
}
