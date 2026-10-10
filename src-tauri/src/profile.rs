//! GUI profile persistence: the node list. Every node is a Credential Pack
//! directory plus a couple of runtime preferences; all node material
//! (identity, trust, services, endpoints) derives from the pack — nothing
//! else is persisted.
//!
//! The on-disk shape is detected structurally (repo convention: local files
//! carry no version counters). The shape (2026-09-22, the unified node
//! manager): a `[[nodes]]` list with per-node start-intent
//! (`desired_running` — Start means "keep it on", Stop "keep it off"; the
//! GUI restores the running set on launch). Unknown top-level keys are
//! rejected (`deny_unknown_fields`), so a shape this build does not
//! understand fails loudly — the pre-2026-09-22 single-tunnel shape
//! (`pack_dir`/`transport`/`hub_quic_addr` at top level) included.
//!
//! Paths:
//! - Linux: `~/.config/interflow/profile.toml`
//! - macOS: `~/Library/Application Support/interflow/profile.toml`
//! - Windows: `%APPDATA%\interflow\profile.toml`
//!
//! Relative `pack_dir` values anchor to the profile file's directory, never
//! to the process working directory.

use interflow_core::config::paths::anchor;
use interflow_core::error::{InterflowError, Result};
use interflow_mesh::config::TransportKind;
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

/// One machine-local service-address preference (id → dial target) on an
/// agent node — same layer as `transport` / `hub_quic_addr`, overriding the
/// pack's manifest-issued default.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ServiceAddressPref {
    pub id: String,
    pub address: String,
}

/// One managed node: a Credential Pack plus runtime preferences.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NodeEntry {
    /// Stable node id (UUID minted at add time; survives credential
    /// rotations, which rewrite the pack contents but not the profile).
    pub id: String,
    /// Directory of the installed Credential Pack.
    pub pack_dir: String,
    /// Transport toward the hub/control endpoint: `h2` (default) or `quic`.
    /// Agent nodes only.
    pub transport: Option<TransportKind>,
    /// Hub QUIC address (`host:port`); `None` derives it at runtime from the
    /// control endpoint's host:port. Agent nodes only.
    pub hub_quic_addr: Option<String>,
    /// Per-service dial-address preferences (expose agents): each entry
    /// overrides the pack default for that service id. Empty = all
    /// defaults. Entries for ids the pack no longer declares are inert
    /// (ignored with a warning at start).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub service_addresses: Vec<ServiceAddressPref>,
    /// Start intent: the node was running (by user intent) when last
    /// persisted. Restored on GUI launch.
    #[serde(default)]
    pub desired_running: bool,
}

/// Persisted GUI profile (the `[[nodes]]` shape).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct Profile {
    /// The managed nodes, in profile order.
    pub nodes: Vec<NodeEntry>,
}

impl Profile {
    /// A profile holding exactly these nodes.
    pub const fn new(nodes: Vec<NodeEntry>) -> Self {
        Self { nodes }
    }
}

/// Returns the profile file path (the parent directory is created on demand).
pub fn profile_path() -> Result<PathBuf> {
    let base = dirs::config_dir()
        .ok_or_else(|| InterflowError::config("cannot resolve user config directory"))?;
    Ok(base.join("interflow").join("profile.toml"))
}

/// Loads the profile from the user config directory. A missing file yields
/// an empty Profile (not treated as an error).
pub fn load() -> Result<Profile> {
    load_from(&profile_path()?)
}

/// Loads a profile from an explicit path. A missing file yields an empty
/// Profile. A relative `pack_dir` anchors to the profile file's directory.
/// Anything that is not the `[[nodes]]` shape fails loudly: the struct's
/// `deny_unknown_fields` names the offending key (this includes the
/// pre-2026-09-22 single-tunnel shape).
pub fn load_from(path: &Path) -> Result<Profile> {
    let raw = match std::fs::read_to_string(path) {
        Ok(s) => s,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            return Ok(Profile::new(Vec::new()));
        }
        Err(e) => return Err(e.into()),
    };
    // deny_unknown_fields + the struct-level `default`: an empty (or
    // comments-only) document deserializes to the empty profile; any other
    // shape fails with its unknown fields named.
    let mut profile: Profile = toml::from_str(&raw)?;
    let base = path
        .parent()
        .map_or_else(|| PathBuf::from("."), ToOwned::to_owned);
    for node in &mut profile.nodes {
        let anchored = anchor(&base, &node.pack_dir);
        node.pack_dir = anchored;
    }
    Ok(profile)
}

/// Saves the profile to the user config directory.
pub fn save(profile: &Profile) -> Result<()> {
    save_to(&profile_path()?, profile)
}

/// [`save`] at an explicit path (tests).
pub fn save_to(path: &Path, profile: &Profile) -> Result<()> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let s = toml::to_string_pretty(profile)
        .map_err(|e| InterflowError::config("profile serialization failed").with_source(e))?;
    // Atomic replace (was a plain fs::write): a crash mid-save must not
    // truncate the only copy of the profile. 0600: single-user config that
    // may carry internal endpoint addresses; existing bits are preserved.
    interflow_util::atomic_write(
        path,
        s.as_bytes(),
        interflow_util::WriteMode::PreserveOr(0o600),
    )?;
    tracing::info!(node = "gui", "profile written to {}", path.display());
    Ok(())
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    /// The pre-2026-09-22 single-tunnel shape (top-level
    /// `pack_dir`/`transport`/`hub_quic_addr`, retired with the unified node
    /// manager) is rejected loudly — no in-memory migration path survives.
    #[test]
    fn pre_unification_single_tunnel_shape_is_rejected() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("profile.toml");
        std::fs::write(
            &path,
            r#"
pack_dir = "packs/agent-desktop"
transport = "quic"
hub_quic_addr = "hub.example.com:16666"
"#,
        )
        .unwrap();
        let err = load_from(&path).unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("unknown field"), "wrong error: {msg}");
        assert!(
            ["pack_dir", "transport", "hub_quic_addr"]
                .iter()
                .any(|k| msg.contains(k)),
            "wrong error: {msg}"
        );
    }

    /// nodes-list profiles round-trip byte-stably (ids, intent bits,
    /// order) and reload without migration.
    #[test]
    fn nodes_profile_round_trips() {
        let profile = Profile::new(vec![
            NodeEntry {
                id: "id-a".into(),
                pack_dir: "/packs/hub-central".into(),
                transport: None,
                hub_quic_addr: None,
                service_addresses: Vec::new(),
                desired_running: true,
            },
            NodeEntry {
                id: "id-b".into(),
                pack_dir: "/packs/agent-lan-a".into(),
                transport: Some(TransportKind::Quic),
                hub_quic_addr: None,
                service_addresses: vec![ServiceAddressPref {
                    id: "web".into(),
                    address: "127.0.0.1:5173".into(),
                }],
                desired_running: false,
            },
        ]);
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("profile.toml");
        save_to(&path, &profile).unwrap();
        let reloaded = load_from(&path).unwrap();
        assert_eq!(reloaded, profile);
    }

    /// Profiles written before service-address preferences existed load
    /// with an empty preference set (the field defaults; skip-if-empty
    /// keeps the byte shape of untouched entries unchanged).
    #[test]
    fn pre_preference_profiles_load() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("profile.toml");
        std::fs::write(
            &path,
            r#"
[[nodes]]
id = "x"
pack_dir = "/p"
desired_running = true
"#,
        )
        .unwrap();
        let profile = load_from(&path).unwrap();
        assert_eq!(profile.nodes.len(), 1);
        assert!(profile.nodes[0].service_addresses.is_empty());
    }

    /// An empty or missing file is an empty profile, not an error.
    #[test]
    fn missing_and_empty_files_yield_empty_profile() {
        let dir = tempfile::tempdir().unwrap();
        let missing = load_from(&dir.path().join("nope.toml")).unwrap();
        assert_eq!(missing, Profile::new(Vec::new()));
        let empty = dir.path().join("profile.toml");
        std::fs::write(&empty, "# nothing\n").unwrap();
        assert_eq!(
            load_from(&empty).unwrap(),
            Profile::new(Vec::new()),
            "an empty file is the empty profile"
        );
    }

    /// A nodes-shaped file with an unknown top-level key fails loudly
    /// instead of silently dropping it — this is how a future shape (or a
    /// key from an abandoned dev build) is detected.
    #[test]
    fn unknown_top_level_keys_are_rejected() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("profile.toml");
        std::fs::write(
            &path,
            r#"
some_future_key = 99
[[nodes]]
id = "x"
pack_dir = "/p"
"#,
        )
        .unwrap();
        let err = load_from(&path).unwrap_err();
        assert!(
            err.to_string().contains("some_future_key"),
            "wrong error: {err}"
        );
    }
}
