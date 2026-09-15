//! Configuration loader: TOML parsing → secret expansion → path anchoring →
//! load-time validation.
//!
//! Every relative filesystem path in a config file (TLS certs, mTLS CA,
//! audit log) anchors to the config file's directory, so loading is
//! independent of the process working directory. Anchored fields are
//! rewritten to absolute paths in the returned config; downstream consumers
//! (validation, TLS acceptors, audit writers, hot-reload) never do path
//! resolution of their own.

use crate::config::validate::{validate_agent, validate_hub};
use crate::config::{AgentConfig, HubConfig};
use interflow_core::config::paths::{absolutize, anchor};
use interflow_core::config::secret::maybe_resolve;
use interflow_core::error::{InterflowError, Result};
use std::fs;
use std::path::{Path, PathBuf};

/// Loads the hub configuration: TOML parsing → secret expansion → path
/// anchoring → [`validate_hub`] → normalization.
///
/// On validation failure, all errors are returned at once
/// ([`ConfigErrorList`]) so they can be fixed in a single pass.
pub fn load_hub_config<P: AsRef<Path>>(path: P) -> Result<HubConfig> {
    let cfg_path = absolutize(path.as_ref())?;
    let content = fs::read_to_string(&cfg_path)
        .map_err(|e| InterflowError::config(format!("cannot read config file: {e}")))?;

    let mut config: HubConfig = toml::from_str(&content)
        .map_err(|e| InterflowError::config(format!("config parse error: {e}")))?;

    let base = config_base_dir(&cfg_path);
    resolve_hub_secrets(&mut config, &base)?;
    anchor_hub_paths(&mut config, &base);
    validate_hub(&config).map_err(|e| InterflowError::config(e.to_string()))?;
    normalize_hub(&mut config);

    Ok(config)
}

/// Loads the agent configuration: TOML parsing → secret expansion → path
/// anchoring → [`validate_agent`] → normalization.
pub fn load_agent_config<P: AsRef<Path>>(path: P) -> Result<AgentConfig> {
    let cfg_path = absolutize(path.as_ref())?;
    let content = fs::read_to_string(&cfg_path)
        .map_err(|e| InterflowError::config(format!("cannot read config file: {e}")))?;

    let mut config: AgentConfig = toml::from_str(&content)
        .map_err(|e| InterflowError::config(format!("config parse error: {e}")))?;

    let base = config_base_dir(&cfg_path);
    resolve_agent_secrets(&mut config, &base)?;
    anchor_agent_paths(&mut config, &base);
    validate_agent(&config).map_err(|e| InterflowError::config(e.to_string()))?;
    normalize_agent(&mut config);

    Ok(config)
}

/// The config file's directory, used as the anchor for all relative paths
/// inside it. The config path is absolutized beforehand, so the parent is
/// never empty.
fn config_base_dir(cfg_path: &Path) -> PathBuf {
    cfg_path
        .parent()
        .map_or_else(|| PathBuf::from("."), ToOwned::to_owned)
}

/// Normalization: `Some(tls)` with `enabled = false` collapses to `None`
/// (one canonical representation per semantics, so runtime code no longer
/// handles the "Some but disabled" combination).
fn normalize_hub(cfg: &mut HubConfig) {
    if let Some(tls) = &cfg.tls
        && !tls.enabled
    {
        cfg.tls = None;
    }
}

/// Agent-side equivalent of [`normalize_hub`].
fn normalize_agent(cfg: &mut AgentConfig) {
    if let Some(tls) = &cfg.tls
        && !tls.enabled
    {
        cfg.tls = None;
    }
}

/// Expands all `${ENV}` / `@file:` references in the hub configuration's
/// secret / path fields. Relative `@file:` references resolve against the
/// config file's directory.
fn resolve_hub_secrets(cfg: &mut HubConfig, base: &Path) -> Result<()> {
    if let Some(static_token) = cfg.auth.static_token.as_mut() {
        if let Some(token) = static_token.agent.take() {
            static_token.agent = Some(maybe_resolve(&token, Some(base))?);
        }
        if let Some(token) = static_token.admin.take() {
            static_token.admin = Some(maybe_resolve(&token, Some(base))?);
        }
    }
    if let Some(mtls) = cfg.auth.mtls.as_mut() {
        mtls.ca_path = maybe_resolve(&mtls.ca_path, Some(base))?;
    }
    if let Some(tls) = cfg.tls.as_mut() {
        tls.cert_path = maybe_resolve(&tls.cert_path, Some(base))?;
        tls.key_path = maybe_resolve(&tls.key_path, Some(base))?;
    }
    if let Some(path) = cfg.audit.path.take() {
        cfg.audit.path = Some(maybe_resolve(&path, Some(base))?);
    }
    Ok(())
}

/// Anchors the hub configuration's relative filesystem paths against the
/// config file's directory (absolute values pass through). `metrics.path`
/// is an HTTP route, not a filesystem path, and is deliberately untouched.
fn anchor_hub_paths(cfg: &mut HubConfig, base: &Path) {
    if let Some(mtls) = cfg.auth.mtls.as_mut() {
        mtls.ca_path = anchor(base, &mtls.ca_path);
    }
    if let Some(tls) = cfg.tls.as_mut() {
        tls.cert_path = anchor(base, &tls.cert_path);
        tls.key_path = anchor(base, &tls.key_path);
    }
    if let Some(path) = cfg.audit.path.take() {
        cfg.audit.path = Some(anchor(base, &path));
    }
}

/// Expands all `${ENV}` / `@file:` references in the agent configuration's
/// secret / path fields. Relative `@file:` references resolve against the
/// config file's directory.
fn resolve_agent_secrets(cfg: &mut AgentConfig, base: &Path) -> Result<()> {
    if let Some(token) = cfg.agent.auth_token.take() {
        cfg.agent.auth_token = Some(maybe_resolve(&token, Some(base))?);
    }
    if let Some(token) = cfg.control.auth_token.take() {
        cfg.control.auth_token = Some(maybe_resolve(&token, Some(base))?);
    }
    if let Some(tls) = cfg.tls.as_mut() {
        if let Some(p) = tls.ca_path.take() {
            tls.ca_path = Some(maybe_resolve(&p, Some(base))?);
        }
        if let Some(p) = tls.client_cert_path.take() {
            tls.client_cert_path = Some(maybe_resolve(&p, Some(base))?);
        }
        if let Some(p) = tls.client_key_path.take() {
            tls.client_key_path = Some(maybe_resolve(&p, Some(base))?);
        }
    }
    Ok(())
}

/// Agent-side equivalent of [`anchor_hub_paths`].
fn anchor_agent_paths(cfg: &mut AgentConfig, base: &Path) {
    if let Some(tls) = cfg.tls.as_mut() {
        if let Some(p) = tls.ca_path.take() {
            tls.ca_path = Some(anchor(base, &p));
        }
        if let Some(p) = tls.client_cert_path.take() {
            tls.client_cert_path = Some(anchor(base, &p));
        }
        if let Some(p) = tls.client_key_path.take() {
            tls.client_key_path = Some(anchor(base, &p));
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)] // unwrap is test convention
mod tests {
    use super::*;
    use std::io::Write;

    /// Writes a minimal hub config referencing relative cert paths plus the
    /// dummy files it points at, in a fresh temp dir.
    fn write_hub_fixture(dir: &Path) {
        let certs = dir.join("certs");
        std::fs::create_dir_all(&certs).unwrap();
        for name in ["ca.crt", "hub.crt", "hub.key"] {
            std::fs::write(certs.join(name), b"dummy").unwrap();
        }
        let toml = r#"
config_version = 2

[server]
listen_addr = "127.0.0.1:16666"

[auth]
mode = "mtls"
allow_anonymous = false
rate_limit_per_minute = 30

  [auth.mtls]
  ca_path = "certs/ca.crt"

[tls]
enabled = true
cert_path = "certs/hub.crt"
key_path = "certs/hub.key"

[audit]
enabled = true
path = "./audit.jsonl"
"#;
        let mut f = std::fs::File::create(dir.join("hub.toml")).unwrap();
        write!(f, "{toml}").unwrap();
    }

    #[test]
    fn hub_relative_paths_anchor_to_config_dir() {
        let dir = std::env::temp_dir().join(format!(
            "interflow_loader_hub_{}_{}",
            std::process::id(),
            line!()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        write_hub_fixture(&dir);

        // Loaded via absolute path while the CWD is elsewhere (the crate
        // root has no certs/); anchoring, not the CWD, makes this pass.
        let cfg = load_hub_config(dir.join("hub.toml")).unwrap();
        let tls = cfg.tls.as_ref().unwrap();
        assert!(Path::new(&tls.cert_path).is_absolute());
        assert_eq!(
            tls.cert_path,
            dir.join("certs/hub.crt").display().to_string()
        );
        assert_eq!(
            tls.key_path,
            dir.join("certs/hub.key").display().to_string()
        );
        let mtls = cfg.auth.mtls.as_ref().unwrap();
        assert_eq!(mtls.ca_path, dir.join("certs/ca.crt").display().to_string());
        assert_eq!(
            cfg.audit.path.as_deref().unwrap(),
            dir.join("audit.jsonl").display().to_string()
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn agent_relative_paths_anchor_to_config_dir() {
        let dir = std::env::temp_dir().join(format!(
            "interflow_loader_agent_{}_{}",
            std::process::id(),
            line!()
        ));
        let certs = dir.join("certs");
        std::fs::create_dir_all(&certs).unwrap();
        std::fs::write(certs.join("ca.crt"), b"dummy").unwrap();
        let toml = r#"
config_version = 2

[agent]
id = "agent-x"
hub_url = "https://127.0.0.1:16666"
auth_token = "dev-token"

[tls]
enabled = true
ca_path = "certs/ca.crt"

[control]
enabled = false

[[ingress]]
name = "to-agent-2"
listen_addr = "127.0.0.1:13001"
target_agent = "agent-2"
remote_addr = "127.0.0.1:13000"
"#;
        let mut f = std::fs::File::create(dir.join("agent.toml")).unwrap();
        write!(f, "{toml}").unwrap();

        let cfg = load_agent_config(dir.join("agent.toml")).unwrap();
        let tls = cfg.tls.as_ref().unwrap();
        let ca = tls.ca_path.as_deref().unwrap();
        assert!(Path::new(ca).is_absolute());
        assert_eq!(ca, dir.join("certs/ca.crt").display().to_string());
        let _ = std::fs::remove_dir_all(&dir);
    }
}
