//! Host routing table: `Host` header → `(agent_id, remote_addr)`.
//!
//! The configuration source is `routes.toml`:
//! ```toml
//! [[routes]]
//! host = "myapp.example.com"
//! agent_id = "expose-myapp"
//! remote_addr = "127.0.0.1:3000"
//!
//! # Optional: same `[logging]` schema as hub.toml/agent.toml. When present,
//! # SIGHUP hot-reloads `level`; a `format` change needs a restart. Absent
//! # means logging is not managed by this file (a `--log-level` flag survives
//! # SIGHUP).
//! [logging]
//! level = "info,interflow_mesh=debug"
//! ```

use arc_swap::ArcSwap;
use interflow_core::config::LoggingConfig;
use interflow_core::error::{InterflowError, Result};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;

/// A single routing rule.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Route {
    /// Host header of public requests (lowercase, no port).
    pub host: String,
    /// The corresponding local expose agent_id.
    pub agent_id: String,
    /// Target address the egress agent dials (where the local service
    /// actually listens).
    pub remote_addr: SocketAddr,
}

/// Root of the routing-table config file.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RoutesConfig {
    /// List of routing rules.
    #[serde(default)]
    pub routes: Vec<Route>,
    /// Optional logging overrides (same schema as the hub/agent `[logging]`
    /// section). `None` (section absent) = logging is not managed by this
    /// file: startup falls back to `--log-level`/`info`, and SIGHUP leaves
    /// the level untouched.
    #[serde(default)]
    pub logging: Option<LoggingConfig>,
}

/// In-process host routing table. Internally holds a wholesale-replaceable
/// snapshot in an `ArcSwap`, supporting runtime SIGHUP hot reload; the read
/// side is lock-free.
#[derive(Debug, Clone)]
pub struct HostRouter {
    inner: Arc<ArcSwap<HashMap<String, Route>>>,
}

impl RoutesConfig {
    /// Reads + parses `routes.toml` → [`RoutesConfig`]. Shared by the initial
    /// load, the SIGHUP reload task, and the CLI's best-effort logging
    /// pre-read, so every path sees the same schema and validation.
    pub fn load(path: &str) -> Result<Self> {
        let s = std::fs::read_to_string(path).map_err(|e| {
            InterflowError::config(format!("failed to read routing table {path}")).with_source(e)
        })?;
        toml::from_str(&s).map_err(|e| {
            InterflowError::config(format!("failed to parse routing table {path}")).with_source(e)
        })
    }
}

impl HostRouter {
    /// Constructs from a `RoutesConfig`.
    pub fn from_config(cfg: &RoutesConfig) -> Self {
        Self {
            inner: Arc::new(ArcSwap::from_pointee(cfg_to_map(cfg))),
        }
    }

    /// Loads from a TOML file and constructs.
    pub fn load(path: &str) -> Result<Self> {
        Ok(Self::from_config(&RoutesConfig::load(path)?))
    }

    /// Looks up a host. The `host` argument is normalized (lowercased, port
    /// stripped).
    pub fn lookup(&self, host: &str) -> Option<Route> {
        self.inner.load().get(&normalize_host(host)).cloned()
    }

    /// Swaps in the routing table from an already-parsed config. Public so
    /// the SIGHUP reload task can apply routes and logging from a single
    /// parse (one file read can never update routes but not logging).
    pub fn apply(&self, cfg: &RoutesConfig) {
        self.inner.store(Arc::new(cfg_to_map(cfg)));
    }

    /// Re-reads `routes.toml` and swaps the routing table wholesale. On parse
    /// failure the old table is kept.
    pub fn reload(&self, path: &str) -> Result<()> {
        self.apply(&RoutesConfig::load(path)?);
        Ok(())
    }

    /// Number of registered hosts.
    pub fn len(&self) -> usize {
        self.inner.load().len()
    }

    /// Whether the table is empty.
    pub fn is_empty(&self) -> bool {
        self.inner.load().len() == 0
    }
}

/// Normalizes a Host header: strip the port suffix, lowercase, trim whitespace.
fn normalize_host(s: &str) -> String {
    let trimmed = s.trim().to_ascii_lowercase();
    // Strip the `:port` suffix (e.g. `myapp.example.com:8080` → `myapp.example.com`)
    match trimmed.rsplit_once(':') {
        Some((host, _port)) if !host.is_empty() => host.to_string(),
        _ => trimmed,
    }
}

/// Normalizes a `RoutesConfig` into a host→Route map (hosts already normalized).
fn cfg_to_map(cfg: &RoutesConfig) -> HashMap<String, Route> {
    cfg.routes
        .iter()
        .map(|r| (normalize_host(&r.host), r.clone()))
        .collect()
}

#[cfg(test)]
#[allow(
    clippy::panic,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::missing_docs_in_private_items
)]
mod tests {
    use super::*;

    #[test]
    fn normalize_handles_port_and_case() {
        assert_eq!(normalize_host("MyApp.Example.COM:443"), "myapp.example.com");
        assert_eq!(normalize_host("  myapp.example.com  "), "myapp.example.com");
        assert_eq!(normalize_host("myapp.example.com"), "myapp.example.com");
    }

    #[test]
    fn lookup_finds_registered_host() {
        let cfg = RoutesConfig {
            routes: vec![Route {
                host: "MyApp.Example.com".into(),
                agent_id: "expose-myapp".into(),
                remote_addr: "127.0.0.1:3000".parse().unwrap(),
            }],
            logging: None,
        };
        let router = HostRouter::from_config(&cfg);
        assert!(router.lookup("myapp.example.com").is_some());
        assert!(router.lookup("myapp.example.com:8443").is_some());
        assert!(router.lookup("MYAPP.EXAMPLE.COM").is_some());
        assert!(router.lookup("other.example.com").is_none());
    }

    #[test]
    fn logging_section_parses_and_stays_optional() {
        // Absent section → None (logging not managed by the file).
        let cfg: RoutesConfig = toml::from_str(
            r#"
[[routes]]
host = "a.example.com"
agent_id = "agent-a"
remote_addr = "127.0.0.1:3000"
"#,
        )
        .unwrap();
        assert_eq!(cfg.logging, None);

        // Present section → level + format round-trip.
        let cfg: RoutesConfig = toml::from_str(
            r#"
[[routes]]
host = "a.example.com"
agent_id = "agent-a"
remote_addr = "127.0.0.1:3000"

[logging]
level = "info,interflow_mesh=debug"
format = "json"
"#,
        )
        .unwrap();
        let logging = cfg.logging.expect("logging section");
        assert_eq!(logging.level, "info,interflow_mesh=debug");
        assert_eq!(logging.format, interflow_core::telemetry::LogFormat::Json);

        // Level-only section keeps the shared LoggingConfig defaults.
        let cfg: RoutesConfig = toml::from_str(
            r#"
[logging]
level = "debug"
"#,
        )
        .unwrap();
        assert_eq!(
            cfg.logging.as_ref().map(|l| l.level.as_str()),
            Some("debug")
        );

        // deny_unknown_fields extends into the [logging] section.
        assert!(
            toml::from_str::<RoutesConfig>(
                r#"
[logging]
level = "debug"
unknown_key = 1
"#,
            )
            .is_err()
        );
    }

    /// After a successful reload, lookup immediately sees the new routing
    /// table (covers backlog §7 matrix items 1-3), and the same single parse
    /// surfaces the `[logging]` section for the reload task to apply.
    #[test]
    fn reload_swaps_routing_table() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("routes.toml");

        std::fs::write(
            &path,
            r#"
[[routes]]
host = "a.example.com"
agent_id = "agent-a"
remote_addr = "127.0.0.1:3000"
"#,
        )
        .unwrap();
        let router = HostRouter::load(path.to_str().unwrap()).unwrap();
        assert!(router.lookup("a.example.com").is_some());
        assert!(router.lookup("b.example.com").is_none());

        // Rewrite the file (drop a, add b, start managing logging); after
        // reload the old host is gone, the new host takes effect, and the
        // logging section is visible from the same parse
        std::fs::write(
            &path,
            r#"
[[routes]]
host = "b.example.com"
agent_id = "agent-b"
remote_addr = "127.0.0.1:4000"

[logging]
level = "debug"
"#,
        )
        .unwrap();
        let cfg = RoutesConfig::load(path.to_str().unwrap()).unwrap();
        router.apply(&cfg);
        assert!(
            router.lookup("a.example.com").is_none(),
            "old route should be gone"
        );
        let b = router
            .lookup("b.example.com")
            .expect("new route should take effect");
        assert_eq!(b.agent_id, "agent-b");
        assert_eq!(
            cfg.logging.as_ref().map(|l| l.level.as_str()),
            Some("debug"),
            "reload parse must expose the logging section too"
        );

        // Feed it broken TOML: the previous snapshot is kept (b still hits)
        std::fs::write(&path, b"not valid toml {{{").unwrap();
        assert!(RoutesConfig::load(path.to_str().unwrap()).is_err());
        assert!(
            router.lookup("b.example.com").is_some(),
            "old routes should be kept on parse failure"
        );
    }
}
