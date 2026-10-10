//! GUI-wide preferences: the interface language — the single source of
//! truth shared by the webview UI, the tray, and Rust-authored
//! user-facing strings.
//!
//! A file of its own on purpose — same ownership rule as the deploy
//! prefs: `profile.toml` belongs to the node manager's snapshot-style
//! load-modify-save, so a language field bolted onto it would be
//! clobbered by the next node mutation. The frontend loads it at boot
//! (before first paint — no flash of the wrong language) and persists
//! switches through `gui_prefs_save`, which also rebuilds the tray so
//! every surface flips at once.

use serde::{Deserialize, Serialize};
use std::path::PathBuf;

/// The GUI's interface language. English is the default; Chinese is
/// opt-in via the header switch. The wire form ("en"/"zh") is shared by
/// the TOML file and the IPC DTO.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Lang {
    #[default]
    En,
    Zh,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct GuiPrefs {
    pub language: Lang,
}

fn prefs_path() -> Option<PathBuf> {
    dirs::config_dir().map(|base| base.join("interflow").join("gui.toml"))
}

/// Loads the preferences; a missing or unreadable file is simply the
/// default (English) — language must never block the GUI from coming up.
pub fn load() -> GuiPrefs {
    let Some(path) = prefs_path() else {
        return GuiPrefs::default();
    };
    let Ok(raw) = std::fs::read_to_string(&path) else {
        return GuiPrefs::default();
    };
    toml::from_str(&raw).unwrap_or_default()
}

/// Persists the preferences atomically (0600 — config hygiene, same as
/// the profile and the deploy prefs). By value: `GuiPrefs` is `Copy`.
pub fn save(prefs: GuiPrefs) -> Result<(), String> {
    let Some(path) = prefs_path() else {
        return Err("cannot resolve the user config directory".to_string());
    };
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).map_err(|e| format!("create {}: {e}", parent.display()))?;
    }
    let text = toml::to_string_pretty(&prefs).map_err(|e| format!("serialize gui prefs: {e}"))?;
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
    /// unknown keys rejected loudly, absent file defaults to English.
    #[test]
    fn prefs_round_trip_and_reject_unknown_keys() {
        let prefs = GuiPrefs { language: Lang::Zh };
        let text = toml::to_string_pretty(&prefs).unwrap();
        assert_eq!(text, "language = \"zh\"\n");
        assert_eq!(toml::from_str::<GuiPrefs>(&text).unwrap(), prefs);
        assert!(toml::from_str::<GuiPrefs>("bogus_key = 1\n").is_err());
        assert_eq!(toml::from_str::<GuiPrefs>("").unwrap(), GuiPrefs::default());
        assert_eq!(GuiPrefs::default().language, Lang::En);
    }
}
