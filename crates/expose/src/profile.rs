//! Profile persistence: saves the hub URL, token, and agent_id to the user
//! config directory, so subsequent `interflow-expose expose <port>` calls
//! need no repeated arguments.
//!
//! Paths:
//! - Linux: `~/.config/interflow/profile.toml`
//! - macOS: `~/Library/Application Support/interflow/profile.toml`
//! - Windows: `%APPDATA%\interflow\profile.toml`
//!
//! Relative `ca_path` values inside the profile anchor to the profile
//! file's directory (e.g. `~/.config/interflow/certs/ca.crt`), never to the
//! process working directory.

use interflow_core::config::paths::anchor;
use interflow_core::error::{InterflowError, Result};
use interflow_mesh::config::TransportKind;
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

/// Expose profile of the local user.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct Profile {
    /// Hub URL (e.g. `https://hub.example.com:6666`).
    pub hub_url: Option<String>,
    /// Agent token (the hub's `auth.static_token.agent`).
    pub auth_token: Option<String>,
    /// agent_id used by this machine's expose (edge's routes.toml must
    /// reference the same id).
    pub agent_id: Option<String>,
    /// Path to the trusted hub CA certificate PEM (required when the hub uses
    /// a self-signed cert).
    pub ca_path: Option<String>,
    /// Local ports used last time (for GUI form prefill).
    pub local_ports: Option<Vec<u16>>,
    /// Transport toward the hub: `h2` (default) or `quic`.
    ///
    /// QUIC needs UDP egress to the hub and TLS on every connection
    /// (`ca_path` or the system CA); the hub-side QUIC listener must be
    /// enabled on the edge (`--quic-listen`).
    pub transport: Option<TransportKind>,
    /// Hub QUIC address (`host:port`). `None` derives it at runtime from
    /// `hub_url`'s host:port — valid when the edge's QUIC listener shares
    /// the hub TCP port number (the dual-stack default).
    pub hub_quic_addr: Option<String>,
}

/// Returns the profile file path (the parent directory is created on demand).
pub fn profile_path() -> Result<PathBuf> {
    let base = dirs::config_dir()
        .ok_or_else(|| InterflowError::config("cannot resolve user config directory"))?;
    let dir = base.join("interflow");
    Ok(dir.join("profile.toml"))
}

/// Loads the profile from the user config directory. A missing file yields an
/// empty Profile (not treated as an error).
pub fn load() -> Result<Profile> {
    load_from(&profile_path()?)
}

/// Loads a profile from an explicit path. A missing file yields an empty
/// Profile (not treated as an error). A relative `ca_path` anchors to the
/// profile file's directory.
pub fn load_from(path: &Path) -> Result<Profile> {
    match std::fs::read_to_string(path) {
        Ok(s) => {
            let mut profile: Profile = toml::from_str(&s)?;
            if let Some(ca) = profile.ca_path.take() {
                let base = path
                    .parent()
                    .map_or_else(|| PathBuf::from("."), ToOwned::to_owned);
                profile.ca_path = Some(anchor(&base, &ca));
            }
            Ok(profile)
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(Profile::default()),
        Err(e) => Err(e.into()),
    }
}

/// Saves the profile to the user config directory (creates parent directories
/// automatically).
pub fn save(profile: &Profile) -> Result<()> {
    let path = profile_path()?;
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let s = toml::to_string_pretty(profile)
        .map_err(|e| InterflowError::config("profile serialization failed").with_source(e))?;
    std::fs::write(&path, s)?;
    tracing::info!("profile written to {}", path.display());
    Ok(())
}
