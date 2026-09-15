//! Host routing table: `Host` header → `(agent_id, remote_addr)`.
//!
//! The configuration source is `routes.toml`:
//! ```toml
//! [[routes]]
//! host = "myapp.example.com"
//! agent_id = "expose-myapp"
//! remote_addr = "127.0.0.1:3000"
//! ```

use arc_swap::ArcSwap;
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
}

/// In-process host routing table. Internally holds a wholesale-replaceable
/// snapshot in an `ArcSwap`, supporting runtime SIGHUP hot reload; the read
/// side is lock-free.
#[derive(Debug, Clone)]
pub struct HostRouter {
    inner: Arc<ArcSwap<HashMap<String, Route>>>,
}

impl HostRouter {
    /// Constructs from a `RoutesConfig`.
    pub fn from_config(cfg: RoutesConfig) -> Self {
        Self {
            inner: Arc::new(ArcSwap::from_pointee(cfg_to_map(cfg))),
        }
    }

    /// Loads from a TOML file and constructs.
    pub fn load(path: &str) -> Result<Self> {
        let cfg: RoutesConfig = read_parse(path)?;
        Ok(Self::from_config(cfg))
    }

    /// Looks up a host. The `host` argument is normalized (lowercased, port
    /// stripped).
    pub fn lookup(&self, host: &str) -> Option<Route> {
        self.inner.load().get(&normalize_host(host)).cloned()
    }

    /// Re-reads `routes.toml` and swaps the routing table wholesale. On parse
    /// failure the old table is kept.
    pub fn reload(&self, path: &str) -> Result<()> {
        let cfg: RoutesConfig = read_parse(path)?;
        self.inner.store(Arc::new(cfg_to_map(cfg)));
        Ok(())
    }

    /// Number of registered hosts.
    pub fn len(&self) -> usize {
        self.inner.load().len()
    }

    /// Whether the table is empty.
    pub fn is_empty(&self) -> bool {
        self.inner.load().is_empty()
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

/// Reads + parses `routes.toml` → `RoutesConfig`. Shared by `load` and
/// `reload` to keep both paths behaving identically.
fn read_parse(path: &str) -> Result<RoutesConfig> {
    let s = std::fs::read_to_string(path).map_err(|e| {
        InterflowError::config(format!("failed to read routing table {path}")).with_source(e)
    })?;
    toml::from_str(&s).map_err(|e| {
        InterflowError::config(format!("failed to parse routing table {path}")).with_source(e)
    })
}

/// Normalizes a `RoutesConfig` into a host→Route map (hosts already normalized).
fn cfg_to_map(cfg: RoutesConfig) -> HashMap<String, Route> {
    cfg.routes
        .into_iter()
        .map(|r| (normalize_host(&r.host), r))
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
        };
        let router = HostRouter::from_config(cfg);
        assert!(router.lookup("myapp.example.com").is_some());
        assert!(router.lookup("myapp.example.com:8443").is_some());
        assert!(router.lookup("MYAPP.EXAMPLE.COM").is_some());
        assert!(router.lookup("other.example.com").is_none());
    }

    /// After a successful reload, lookup immediately sees the new routing
    /// table (covers backlog §7 matrix items 1-3).
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

        // Rewrite the file (drop a, add b); after reload the old host is gone
        // and the new host takes effect
        std::fs::write(
            &path,
            r#"
[[routes]]
host = "b.example.com"
agent_id = "agent-b"
remote_addr = "127.0.0.1:4000"
"#,
        )
        .unwrap();
        router.reload(path.to_str().unwrap()).unwrap();
        assert!(
            router.lookup("a.example.com").is_none(),
            "old route should be gone"
        );
        let b = router
            .lookup("b.example.com")
            .expect("new route should take effect");
        assert_eq!(b.agent_id, "agent-b");

        // Feed it broken TOML: the previous snapshot is kept (b still hits)
        std::fs::write(&path, b"not valid toml {{{").unwrap();
        assert!(router.reload(path.to_str().unwrap()).is_err());
        assert!(
            router.lookup("b.example.com").is_some(),
            "old routes should be kept on parse failure"
        );
    }
}
