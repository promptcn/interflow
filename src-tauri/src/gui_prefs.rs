//! GUI-wide preferences: the interface language and the current deployment
//! — the single source of truth shared by the webview UI, the tray, and
//! Rust-authored user-facing strings. The frontend loads it at boot
//! (before first paint — no flash of the wrong language) and persists
//! switches through `gui_prefs_save`, which also rebuilds the tray so
//! every surface flips at once.
//!
//! Storage is the GUI's prefs db ([`crate::prefs`], `gui` key-value table);
//! a missing or unreadable db is the defaults, so language can never block
//! the GUI from coming up.

use serde::{Deserialize, Serialize};

/// The GUI's interface language. English is the default; Chinese is
/// opt-in via the header switch. The wire form ("en"/"zh") is shared by
/// the db rows and the IPC DTO.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Lang {
    #[default]
    En,
    Zh,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct GuiPrefs {
    pub language: Lang,
    /// The deployment the app opens into (the root folder's path) — the
    /// new IA's root object. Absent on first run (the empty state points
    /// at onboarding instead of a remembered folder).
    pub current_deployment: Option<String>,
}

/// Loads the preferences; an unreadable db is simply the default (English)
/// — language must never block the GUI from coming up.
pub fn load() -> GuiPrefs {
    match crate::prefs::PrefsDb::open() {
        Ok(db) => db.gui(),
        Err(e) => {
            tracing::warn!(node = "gui", "gui prefs unreadable: {e}");
            GuiPrefs::default()
        }
    }
}

/// Persists the preferences (one transaction, per-key upsert).
pub fn save(prefs: &GuiPrefs) -> Result<(), String> {
    let mut db = crate::prefs::PrefsDb::open().map_err(|e| e.to_string())?;
    db.save_gui(prefs).map_err(|e| e.to_string())
}
