//! Cross-session truth of actually-bound ingress listener addresses.
//!
//! A `:0` (kernel-assigned) ingress listen port materializes here at bind.
//! The table is agent-scoped and shared across session rebuilds, which is
//! what makes a `:0` config viable at all: when a session ends its listeners
//! are torn down, and the next session's rebuild consults this table to
//! re-bind the same concrete address (port pinning). Embedders and tests
//! therefore read a stable address from [`AgentHandle`](crate::agent::AgentHandle)
//! instead of racing a pick-then-bind window.
//!
//! Entries survive session teardown by design; only an explicit rule removal
//! (control API) forgets them. A pinned rebind that finds the address taken
//! falls back to the configured `:0` and records the fresh address — the pin
//! is a best-effort stability guarantee, not an ownership claim.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::RwLock;
use std::time::Duration;
use tokio::sync::watch;

#[derive(Debug)]
pub struct IngressAddrs {
    addrs: RwLock<HashMap<String, SocketAddr>>,
    /// Bumped on every mutation so `wait_addr` observers wake. The watch
    /// carries only a version counter; the map is read through
    /// `get`/`snapshot` under the lock.
    version: watch::Sender<u64>,
}

impl IngressAddrs {
    pub(crate) fn new() -> Self {
        let (version, _) = watch::channel(0);
        Self {
            addrs: RwLock::new(HashMap::new()),
            version,
        }
    }

    /// Record (or update) the actually-bound address of a rule.
    pub(crate) fn set(&self, rule: &str, addr: SocketAddr) {
        let mut guard = self.addrs.write().expect("ingress addrs lock");
        guard.insert(rule.to_string(), addr);
        drop(guard);
        self.version.send_modify(|v| *v = v.wrapping_add(1));
    }

    /// Forget a rule's address. Called on explicit rule removal only — a
    /// session teardown keeps the entry so the rebuild can pin to it.
    pub(crate) fn remove(&self, rule: &str) {
        let mut guard = self.addrs.write().expect("ingress addrs lock");
        let removed = guard.remove(rule).is_some();
        drop(guard);
        if removed {
            self.version.send_modify(|v| *v = v.wrapping_add(1));
        }
    }

    /// The pinned address for a rule, if any session has bound one.
    pub fn get(&self, rule: &str) -> Option<SocketAddr> {
        self.addrs
            .read()
            .expect("ingress addrs lock")
            .get(rule)
            .copied()
    }

    /// Snapshot of every rule's currently-recorded address.
    pub fn snapshot(&self) -> HashMap<String, SocketAddr> {
        self.addrs.read().expect("ingress addrs lock").clone()
    }

    /// Resolve once the rule has a bound address, or `None` when the timeout
    /// elapses (or the owning agent is gone and the table can no longer
    /// change).
    pub async fn wait_addr(&self, rule: &str, timeout: Duration) -> Option<SocketAddr> {
        let mut rx = self.version.subscribe();
        let deadline = tokio::time::Instant::now() + timeout;
        loop {
            if let Some(addr) = self.get(rule) {
                return Some(addr);
            }
            tokio::select! {
                changed = rx.changed() => {
                    if changed.is_err() {
                        return None;
                    }
                }
                () = tokio::time::sleep_until(deadline) => return None,
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn addr(port: u16) -> SocketAddr {
        ([127, 0, 0, 1], port).into()
    }

    #[tokio::test]
    async fn wait_addr_resolves_immediately_when_present() {
        let t = IngressAddrs::new();
        t.set("r", addr(1));
        assert_eq!(t.get("r"), Some(addr(1)));
        assert_eq!(
            t.wait_addr("r", Duration::from_millis(10)).await,
            Some(addr(1))
        );
    }

    #[tokio::test]
    async fn wait_addr_wakes_on_set_and_times_out() {
        let t = std::sync::Arc::new(IngressAddrs::new());
        let setter = {
            let t = std::sync::Arc::clone(&t);
            tokio::spawn(async move {
                tokio::time::sleep(Duration::from_millis(20)).await;
                t.set("r", addr(2));
            })
        };
        assert_eq!(
            t.wait_addr("r", Duration::from_secs(1)).await,
            Some(addr(2))
        );
        setter.await.unwrap();
        assert_eq!(
            t.wait_addr("missing", Duration::from_millis(10)).await,
            None
        );
    }

    #[test]
    fn remove_forgets_only_the_named_rule() {
        let t = IngressAddrs::new();
        t.set("a", addr(1));
        t.set("b", addr(2));
        t.remove("a");
        assert_eq!(t.get("a"), None);
        assert_eq!(t.get("b"), Some(addr(2)));
        // Removing an absent rule is a no-op.
        t.remove("a");
        assert_eq!(t.get("b"), Some(addr(2)));
    }
}
