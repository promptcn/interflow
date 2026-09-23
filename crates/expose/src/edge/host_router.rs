//! Host routing table: `Host` header → `(workspace, agent_id, service_id)`.
//!
//! Production source: the Credential Pack's **signed runtime policy**,
//! resolved in memory at startup (`HostRouter::from_routes`). A pack
//! generation is immutable — route changes go through `rotate`, never a file
//! edit, so there is no file schema and no hot-reload path.

use interflow_core::error::{InterflowError, Result};
use std::collections::HashMap;
use std::sync::Arc;

/// A single routing rule.
#[derive(Debug, Clone)]
pub struct Route {
    /// Host header of public requests (lowercase, no port).
    pub host: String,
    /// Owning workspace: the Open target resolves to `(workspace,
    /// agent_id)` — a route pointing at an agent registered under another
    /// workspace simply finds no target and is rejected (fail closed).
    pub workspace: String,
    /// The corresponding local expose agent_id (must be registered under
    /// `workspace`; its certificate CN must equal it).
    pub agent_id: String,
    /// The service the edge asks the agent for, **by id**: the agent
    /// resolves the id to its own effective dial target (pack default or
    /// machine-local preference). The edge never carries an address, so a
    /// compromised ingress can only select among the services the target
    /// agent itself declares.
    pub service_id: String,
}

/// In-process host routing table. Built once from the signed policy and
/// immutable afterwards; the read side is lock-free.
#[derive(Debug, Clone)]
pub struct HostRouter {
    inner: Arc<HashMap<String, Route>>,
}

impl HostRouter {
    /// Constructs from already-resolved in-memory routes (host →
    /// workspace/agent/address bindings from the signed policy). A duplicate
    /// (normalized) host is a configuration error — the legacy silent
    /// last-wins hid route hijacks and typos; now construction fails loudly
    /// instead.
    pub fn from_routes(routes: &[Route]) -> Result<Self> {
        Ok(Self {
            inner: Arc::new(routes_to_map(routes)?),
        })
    }

    /// Looks up a host. The `host` argument is normalized (lowercased, port
    /// and IPv6 brackets stripped). A value that does not parse as an
    /// authority cannot match: every registered key is parser-derived, so an
    /// unparseable Host header simply never routes (fail closed).
    pub fn lookup(&self, host: &str) -> Option<Route> {
        let key = normalize_host(host)?;
        self.inner.get(&key).cloned()
    }

    /// Number of registered hosts.
    pub fn len(&self) -> usize {
        self.inner.len()
    }

    /// Whether the table is empty.
    pub fn is_empty(&self) -> bool {
        self.inner.is_empty()
    }
}

/// Normalizes a Host header via the shared authority parser: lowercase,
/// port-stripped, IPv6 brackets removed (`[::1]:8443` → `::1`). `None` when
/// the value is not a valid authority — the old `rsplit_once(':')` mangling
/// turned `[::1]` into `"[:",` which could never match a configured host.
fn normalize_host(s: &str) -> Option<String> {
    let lowered = s.trim().to_ascii_lowercase();
    interflow_util::parse_authority(&lowered)
        .ok()
        .map(|parsed| parsed.host)
}

/// Normalizes a route list into a host→Route map (hosts already normalized).
/// Route keys must parse as authorities — an unparseable key is a
/// configuration error rather than a silently unroutable route. Duplicate
/// hosts (after normalization) are rejected — silent last-wins would let a
/// typo or a tampered policy hijack a route.
fn routes_to_map(routes: &[Route]) -> Result<HashMap<String, Route>> {
    let mut map = HashMap::with_capacity(routes.len());
    for r in routes {
        let key = normalize_host(&r.host).ok_or_else(|| {
            InterflowError::config(format!(
                "invalid host in routing table: {:?} (expected host[:port], IPv6 in brackets)",
                r.host
            ))
        })?;
        if map.contains_key(&key) {
            return Err(InterflowError::config(format!(
                "duplicate host in routing table: {key} (each host must be mapped exactly once)"
            )));
        }
        map.insert(key, r.clone());
    }
    Ok(map)
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

    fn route(host: &str, agent_id: &str) -> Route {
        Route {
            host: host.into(),
            workspace: "acme".into(),
            agent_id: agent_id.into(),
            service_id: "web".into(),
        }
    }

    #[test]
    fn normalize_handles_port_and_case() {
        let norm = |s: &str| normalize_host(s).unwrap();
        assert_eq!(norm("MyApp.Example.COM:443"), "myapp.example.com");
        assert_eq!(norm("  myapp.example.com  "), "myapp.example.com");
        assert_eq!(norm("myapp.example.com"), "myapp.example.com");
        // The IPv6 fix: brackets and port are stripped to the bare address
        // (the old rsplit_once logic produced "[::1]" / "[:")
        assert_eq!(norm("[::1]:8443"), "::1");
        assert_eq!(norm("[2001:DB8::1]"), "2001:db8::1");
    }

    #[test]
    fn unparseable_hosts_never_match_or_load() {
        // Lookup side: fail closed — no route can be matched by garbage
        assert_eq!(normalize_host("::1"), None);
        assert_eq!(normalize_host(""), None);
        assert_eq!(normalize_host("host/path"), None);

        // Construction side: an unparseable route key is a loud config error
        assert!(HostRouter::from_routes(&[route("::1", "agent-a")]).is_err());
    }

    #[test]
    fn ipv6_routes_route_via_bracketed_host_headers() {
        let router = HostRouter::from_routes(&[route("[2001:db8::10]:443", "agent-a")]).unwrap();
        let found = router
            .lookup("[2001:db8::10]:8443")
            .expect("bracketed IPv6 Host must route");
        assert_eq!(found.agent_id, "agent-a");
    }

    #[test]
    fn lookup_finds_registered_host() {
        let router =
            HostRouter::from_routes(&[route("MyApp.Example.com", "expose-myapp")]).unwrap();
        assert!(router.lookup("myapp.example.com").is_some());
        assert!(router.lookup("myapp.example.com:8443").is_some());
        assert!(router.lookup("MYAPP.EXAMPLE.COM").is_some());
        assert!(router.lookup("other.example.com").is_none());
    }

    #[test]
    fn from_routes_installs_in_memory_table() {
        let router = HostRouter::from_routes(&[route("a.example.com", "agent-a")]).unwrap();
        let found = router.lookup("a.example.com").expect("route installed");
        assert_eq!(found.workspace, "acme");
        assert_eq!(found.agent_id, "agent-a");
    }

    #[test]
    fn duplicate_normalized_host_fails_loudly() {
        // "dup.example.com" and "dup.example.com:443" normalize to one key:
        // the second would silently shadow the first under last-wins.
        let err = HostRouter::from_routes(&[
            route("dup.example.com", "x"),
            route("dup.example.com:443", "y"),
        ])
        .unwrap_err();
        assert!(err.to_string().contains("duplicate host"));
    }
}
