//! Cross-session truth of the ingress LISTENER face (what is actually
//! serving, not what the policy wants).
//!
//! The 2026-10-07 hot-reapply incident showed the health planes only ever
//! reflected the policy face (state generation green while a listener had
//! silently vanished). This table is the actual-state counterpart of the
//! rule store: the reconciler records every bound address and every bind
//! failure here, embedders (GUI/tests) read it from
//! [`AgentHandle`](crate::agent::AgentHandle), so "the listener is gone"
//! is a queryable state, not archaeology.
//!
//! Entries live for the process lifetime (the face survives session
//! teardown, like [`IngressAddrs`]); a rule removal clears its entry.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
#[cfg(test)]
use std::time::Duration;
use tokio::sync::watch;

/// One rule's listener face: where it is serving, or why it is not.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct ListenerStatus {
    /// The actually-bound address (`None` = no listener is up for the rule).
    pub bound_addr: Option<SocketAddr>,
    /// The last bind failure (`None` = healthy). A bound listener with a
    /// `Some` error means a reconciler retry is pending (the previous
    /// listener keeps serving; see the replace path in `agent::ingress`).
    pub last_error: Option<String>,
}

impl ListenerStatus {
    const fn bound(addr: SocketAddr) -> Self {
        Self {
            bound_addr: Some(addr),
            last_error: None,
        }
    }

    const fn failed(error: String) -> Self {
        Self {
            bound_addr: None,
            last_error: Some(error),
        }
    }

    /// True when a listener is actually serving this rule.
    pub const fn is_bound(&self) -> bool {
        self.bound_addr.is_some()
    }
}

/// The whole table as one cheap-to-clone value — what the watch channel
/// pushes on every mutation.
pub type ListenerTable = Arc<HashMap<String, ListenerStatus>>;

/// Agent-scoped listener-status table (shared across session rebuilds).
///
/// Single source of truth: the map lives INSIDE the watch channel. Readers
/// either snapshot ([`Self::snapshot`]) or subscribe
/// ([`Self::subscribe`]) — subscribers receive the full table on every
/// change and hold only the receiver, so their tasks ride down with the
/// agent handle that owns the sender (the same hold-only-the-subscription
/// contract the policy/peers watchers enforce; a subscriber holding a
/// table reference back into this struct would form a liveness cycle).
#[derive(Debug)]
pub struct IngressListeners {
    state: watch::Sender<ListenerTable>,
}

impl IngressListeners {
    pub(crate) fn new() -> Self {
        let (state, _) = watch::channel(Arc::new(HashMap::new()));
        Self { state }
    }

    fn record(&self, rule: &str, status: ListenerStatus) {
        self.state.send_if_modified(|table| {
            let mut next = (**table).clone();
            next.insert(rule.to_string(), status);
            *table = Arc::new(next);
            true
        });
    }

    /// Record a listener now serving `rule` at `addr` (clears any stale
    /// bind error).
    pub(crate) fn set_bound(&self, rule: &str, addr: SocketAddr) {
        self.record(rule, ListenerStatus::bound(addr));
    }

    /// Record that the latest bind attempt for `rule` failed.
    pub(crate) fn set_failed(&self, rule: &str, error: String) {
        self.record(rule, ListenerStatus::failed(error));
    }

    /// Forget a rule (explicit rule removal). Removing an absent rule does
    /// not fire a change.
    pub(crate) fn remove(&self, rule: &str) {
        self.state.send_if_modified(|table| {
            if !table.contains_key(rule) {
                return false;
            }
            let mut next = (**table).clone();
            next.remove(rule);
            *table = Arc::new(next);
            true
        });
    }

    /// One rule's current status.
    pub fn get(&self, rule: &str) -> Option<ListenerStatus> {
        self.state.borrow().get(rule).cloned()
    }

    /// Snapshot of every rule's status.
    pub fn snapshot(&self) -> HashMap<String, ListenerStatus> {
        (**self.state.borrow()).clone()
    }

    /// Subscribe to the table's push face: a watch receiver carrying the
    /// FULL table on every mutation. Embedders mirroring this plane as
    /// events (the GUI's listeners forwarder) wake, clone the current
    /// value, and go back to sleep — no polling, and no reference held
    /// back into this struct.
    pub fn subscribe(&self) -> watch::Receiver<ListenerTable> {
        self.state.subscribe()
    }

    /// Resolve once the rule has a bound listener, or `None` when the
    /// timeout elapses (or the owning agent is gone and the table can no
    /// longer change).
    #[cfg(test)]
    async fn wait_bound(&self, rule: &str, timeout: Duration) -> Option<SocketAddr> {
        let mut rx = self.subscribe();
        let deadline = tokio::time::Instant::now() + timeout;
        loop {
            // Bind the watch Ref outside the `if let` scrutinee (a
            // significant-Drop temporary would otherwise hold the watch
            // read lock through the whole expression).
            let bound = rx.borrow().get(rule).and_then(|s| s.bound_addr);
            if let Some(addr) = bound {
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
    async fn wait_bound_resolves_immediately_when_serving() {
        let t = IngressListeners::new();
        t.set_bound("r", addr(1));
        assert_eq!(t.get("r").unwrap().bound_addr, Some(addr(1)));
        assert_eq!(
            t.wait_bound("r", Duration::from_millis(10)).await,
            Some(addr(1))
        );
    }

    #[tokio::test]
    async fn wait_bound_wakes_on_set_and_times_out() {
        let t = std::sync::Arc::new(IngressListeners::new());
        let setter = {
            let t = std::sync::Arc::clone(&t);
            tokio::spawn(async move {
                tokio::time::sleep(Duration::from_millis(20)).await;
                t.set_bound("r", addr(2));
            })
        };
        assert_eq!(
            t.wait_bound("r", Duration::from_secs(1)).await,
            Some(addr(2))
        );
        setter.await.unwrap();
        assert_eq!(
            t.wait_bound("missing", Duration::from_millis(10)).await,
            None
        );
    }

    #[test]
    fn failure_is_queryable_and_cleared_by_a_later_bind() {
        let t = IngressListeners::new();
        t.set_failed("r", "AddrInUse".into());
        let status = t.get("r").unwrap();
        assert!(!status.is_bound());
        assert_eq!(status.last_error.as_deref(), Some("AddrInUse"));

        t.set_bound("r", addr(3));
        let status = t.get("r").unwrap();
        assert!(status.is_bound());
        assert_eq!(status.last_error, None, "a good bind clears the error");

        t.remove("r");
        assert!(t.get("r").is_none());
        // Removing an absent rule is a no-op.
        t.remove("r");
    }
}
