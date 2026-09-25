//! Deploy-pane path persistence: the recent manifest/issuer/out triples.
//!
//! A file of its own on purpose — `profile.toml` is owned by the node
//! manager through snapshot-style load-modify-save, so a deploy section
//! bolted onto it would be clobbered by the next node mutation. Same
//! conventions as the profile (structural shape, atomic write, 0600).

use serde::{Deserialize, Serialize};
use std::path::PathBuf;

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

fn prefs_path() -> Option<PathBuf> {
    dirs::config_dir().map(|base| base.join("interflow").join("deploy.toml"))
}

/// Loads the remembered contexts; a missing or unreadable file is simply
/// empty (paths fall back to their defaults — never worth a dialog).
pub fn load() -> DeployPrefs {
    let Some(path) = prefs_path() else {
        return DeployPrefs::default();
    };
    let Ok(raw) = std::fs::read_to_string(&path) else {
        return DeployPrefs::default();
    };
    toml::from_str(&raw).unwrap_or_default()
}

/// Persists the contexts atomically (0600 — config hygiene, same as the
/// profile).
pub fn save(prefs: &DeployPrefs) -> Result<(), String> {
    let Some(path) = prefs_path() else {
        return Err("cannot resolve the user config directory".to_string());
    };
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).map_err(|e| format!("create {}: {e}", parent.display()))?;
    }
    let text = toml::to_string_pretty(prefs).map_err(|e| format!("serialize deploy prefs: {e}"))?;
    interflow_util::atomic_write(
        &path,
        text.as_bytes(),
        interflow_util::WriteMode::PreserveOr(0o600),
    )
    .map_err(|e| format!("write {}: {e}", path.display()))
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    /// Round-trip through the real config-directory shape: structural TOML,
    /// unknown keys rejected loudly (the profile convention).
    #[test]
    fn prefs_round_trip_and_reject_unknown_keys() {
        let prefs = DeployPrefs {
            recent: vec![DeployContext {
                manifest: "~/interflow.toml".into(),
                issuer: "~/interflow-issuer".into(),
                out: "~/interflow-dist".into(),
            }],
        };
        let text = toml::to_string_pretty(&prefs).unwrap();
        assert_eq!(toml::from_str::<DeployPrefs>(&text).unwrap(), prefs);
        assert!(toml::from_str::<DeployPrefs>("bogus_key = 1\n").is_err());
    }
}
