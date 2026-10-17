//! GUI profile persistence: the node list. Every node is a Credential Pack
//! directory plus a couple of runtime preferences; all node material
//! (identity, trust, services, endpoints) derives from the pack — nothing
//! else is persisted.
//!
//! Storage is the GUI's prefs db (one process-owned SQLite, [`crate::prefs`]):
//! the `nodes` table with the `ord` column preserving profile order. The
//! legacy `profile.toml` shape (`[[nodes]]`, unknown fields rejected) still
//! exists as the one-time import format; a `pack_dir` that was relative in
//! it anchored to the config directory, and still does on load.

use interflow_core::error::Result;
use interflow_mesh::config::TransportKind;
use serde::{Deserialize, Serialize};

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

/// Persisted GUI profile (the node list, in order).
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

/// Loads the node list from the prefs db. A fresh install yields an empty
/// profile; a db the GUI cannot open is an error the caller logs (the GUI
/// still comes up, node list degraded — the same contract the file had).
pub fn load() -> Result<Profile> {
    Ok(Profile::new(crate::prefs::PrefsDb::open()?.nodes()?))
}

/// Saves the node list to the prefs db (one transaction; order preserved).
pub fn save(profile: &Profile) -> Result<()> {
    crate::prefs::PrefsDb::open()?.save_nodes(&profile.nodes)?;
    tracing::debug!(node = "gui", "profile persisted to the prefs db");
    Ok(())
}
