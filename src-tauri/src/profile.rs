//! GUI profile persistence: the node list. Every node is a Credential Pack
//! directory plus a couple of runtime preferences; all node material
//! (identity, trust, services, endpoints) derives from the pack — nothing
//! else is persisted.
//!
//! The on-disk shape is detected structurally (repo convention: local files
//! carry no version counters). Current shape (2026-09-22, the unified node
//! manager): a `[[nodes]]` list with per-node start-intent
//! (`desired_running` — Start means "keep it on", Stop "keep it off"; the
//! GUI restores the running set on launch). The earlier single-tunnel shape
//! (a `pack_dir`/`transport`/`hub_quic_addr` triple) loads through an
//! in-memory migration into one entry; the file itself is rewritten on the
//! next mutation. Unknown top-level keys are rejected (`deny_unknown_fields`),
//! so a shape this build does not understand fails loudly.
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

/// The earlier single-tunnel shape (2026-09-17..2026-09-22): read-only,
/// migrated in memory into one entry of the current shape.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields, default)]
struct ProfileV1 {
    pack_dir: Option<String>,
    transport: Option<TransportKind>,
    hub_quic_addr: Option<String>,
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
/// Profile. Legacy single-tunnel files migrate to one entry (fresh id,
/// intent off). A relative `pack_dir` anchors to the profile file's
/// directory.
pub fn load_from(path: &Path) -> Result<Profile> {
    let raw = match std::fs::read_to_string(path) {
        Ok(s) => s,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            return Ok(Profile::new(Vec::new()));
        }
        Err(e) => return Err(e.into()),
    };
    let value: toml::Value = toml::from_str(&raw)?;
    let mut profile = if value.get("nodes").is_some() {
        // The nodes-list shape (the deny_unknown_fields on Profile rejects
        // mixed files, so a "nodes" key means this shape or a malformed
        // file — the latter fails here with a pointed serde error).
        value.try_into()?
    } else if value.get("pack_dir").is_some()
        || value.get("transport").is_some()
        || value.get("hub_quic_addr").is_some()
    {
        // Legacy single-tunnel shape → nodes list in memory; rewritten in
        // the current shape on the next mutation.
        let v1: ProfileV1 = value.try_into()?;
        Profile::new(vec![NodeEntry {
            id: uuid::Uuid::new_v4().to_string(),
            pack_dir: v1.pack_dir.unwrap_or_default(),
            transport: v1.transport,
            hub_quic_addr: v1.hub_quic_addr,
            service_addresses: Vec::new(),
            desired_running: false,
        }])
    } else {
        // An empty file (or only comments) — same as missing.
        Profile::new(Vec::new())
    };
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

/// [`save`] at an explicit path (tests, migration tooling).
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

    /// A legacy single-tunnel file migrates to one entry with intent off;
    /// ids are stable across a reload of the same file (persisted, not
    /// re-minted).
    #[test]
    fn legacy_profile_migrates_to_one_entry() {
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
        let profile = load_from(&path).unwrap();
        assert_eq!(profile.nodes.len(), 1);
        let node = &profile.nodes[0];
        assert!(!node.desired_running);
        assert_eq!(node.transport, Some(TransportKind::Quic));
        assert_eq!(node.hub_quic_addr.as_deref(), Some("hub.example.com:16666"));
        // Relative pack_dir anchored to the profile's directory.
        assert_eq!(
            node.pack_dir,
            dir.path().join("packs/agent-desktop").display().to_string()
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
            "an empty file must not be treated as v1"
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
