//! The expose face's node-side service address table.
//!
//! Effective address = machine-local override ?? signed-policy default ??
//! pack-rendered default — one table shared by everyone who re-derives the
//! egress rules: the policy watcher (each verified generation) and the live
//! override channel (the GUI's address edit), so both change sources flow
//! through the same resolution and neither can drift from the other.
//!
//! The pack defaults are immutable for the life of the engine (they are
//! pack material); overrides are the mutable machine preference. The
//! change signal is a `watch` channel so the watcher can re-derive on an
//! override edit without any embedder-side polling — mirroring the
//! rule-store version channel the reconcilers already speak.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::sync::watch;

/// Shared, interior-mutable address table.
///
/// Clones share state (the embedder keeps one to write overrides while the
/// engine holds another to resolve) — the handle is the capability.
#[derive(Debug, Clone, Default)]
pub struct ServiceAddresses {
    inner: Arc<std::sync::RwLock<Table>>,
    change_tx: watch::Sender<u64>,
}

/// Same handle, or same table contents — the change channel is identity,
/// not value. (`AgentConfig` derives `PartialEq`/`Eq`; the sync primitives
/// inside cannot, so the comparison is the table's.)
impl PartialEq for ServiceAddresses {
    fn eq(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.inner, &other.inner)
            || *self
                .inner
                .read()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                == *other
                    .inner
                    .read()
                    .unwrap_or_else(std::sync::PoisonError::into_inner)
    }
}
impl Eq for ServiceAddresses {}

#[derive(Debug, Default, PartialEq, Eq)]
struct Table {
    /// Pack-rendered defaults (`node.toml`): id → address.
    defaults: HashMap<String, SocketAddr>,
    /// Machine-local preferences: id → address. May carry ids the current
    /// policy does not declare yet — a hot-added service picks its
    /// preference up on arrival.
    overrides: HashMap<String, SocketAddr>,
}

impl ServiceAddresses {
    /// A table seeded with the pack defaults and the machine's current
    /// preferences.
    pub fn new(
        defaults: impl IntoIterator<Item = (String, SocketAddr)>,
        overrides: impl IntoIterator<Item = (String, SocketAddr)>,
    ) -> Self {
        let table = Table {
            defaults: defaults.into_iter().collect(),
            overrides: overrides.into_iter().collect(),
        };
        let (change_tx, _) = watch::channel(0);
        Self {
            inner: Arc::new(std::sync::RwLock::new(table)),
            change_tx,
        }
    }

    /// Resolves one service id's effective dial target. The signed-policy
    /// default sits between the override and the pack default: a policy
    /// that carries an address is newer than this pack's render (the whole
    /// point of the hot channel), so it outranks the pack snapshot — but
    /// never the machine's own preference.
    ///
    /// `None` means no source names an address for the id — the caller
    /// skips the service (a hot-added id whose policy and pack both lack
    /// an address) and says so.
    pub fn resolve(&self, id: &str, signed_default: Option<&str>) -> Option<SocketAddr> {
        let table = self
            .inner
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if let Some(addr) = table.overrides.get(id) {
            return Some(*addr);
        }
        if let Some(raw) = signed_default {
            return raw.parse().ok().or_else(|| table.defaults.get(id).copied());
        }
        table.defaults.get(id).copied()
    }

    /// The resolved view across every id the table knows (defaults ∪
    /// overrides, id-sorted): `(id, effective address, overridden)` — the
    /// startup line's and the read models' shape.
    pub fn resolved(&self) -> Vec<(String, SocketAddr, bool)> {
        let table = self
            .inner
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let mut ids: std::collections::BTreeSet<&String> = table.defaults.keys().collect();
        ids.extend(table.overrides.keys());
        ids.into_iter()
            .filter_map(|id| {
                let addr = table
                    .overrides
                    .get(id)
                    .or_else(|| table.defaults.get(id))
                    .copied()?;
                Some((id.clone(), addr, table.overrides.contains_key(id)))
            })
            .collect()
    }

    /// Literal-seed shorthand (`&[("web", addr)]`) — tests and embedders
    /// that would otherwise spell `LocalService` structs by hand.
    pub fn of(defaults: &[(&str, SocketAddr)], overrides: &[(&str, SocketAddr)]) -> Self {
        Self::new(
            defaults.iter().map(|(id, a)| ((*id).to_owned(), *a)),
            overrides.iter().map(|(id, a)| ((*id).to_owned(), *a)),
        )
    }

    /// Sets (or, with `None`, clears) one machine-local preference and
    /// signals the change. Bumping the `watch` value is the entire
    /// propagation story — the policy watcher re-derives the egress table
    /// from its cached current policy, and the next Open dials the new
    /// target. Established streams are untouched (same contract as a
    /// policy reload).
    pub fn set_override(&self, id: &str, address: Option<SocketAddr>) {
        let mut table = self
            .inner
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if let Some(addr) = address {
            table.overrides.insert(id.to_owned(), addr);
        } else {
            table.overrides.remove(id);
        }
        self.change_tx.send_modify(|v| *v += 1);
    }

    /// The machine's current preferences (the GUI persistence read model).
    pub fn overrides(&self) -> HashMap<String, SocketAddr> {
        self.inner
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .overrides
            .clone()
    }

    /// Subscribes to override changes. The initial value is the current
    /// counter; the watcher re-derives whenever it moves.
    pub fn subscribe(&self) -> watch::Receiver<u64> {
        self.change_tx.subscribe()
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    fn addr(port: u16) -> SocketAddr {
        format!("127.0.0.1:{port}").parse().unwrap()
    }

    /// The resolution ladder: override beats everything; a signed default
    /// outranks the pack snapshot; the pack default is the floor; an id
    /// with no source resolves to nothing.
    #[test]
    fn resolution_ladder_is_override_then_signed_then_pack() {
        let table = ServiceAddresses::new(
            [
                ("web".to_owned(), addr(3000)),
                ("db".to_owned(), addr(5432)),
            ],
            [("db".to_owned(), addr(6000))],
        );
        assert_eq!(
            table.resolve("web", Some("127.0.0.1:3001")),
            Some(addr(3001))
        );
        assert_eq!(table.resolve("db", None), Some(addr(6000)));
        assert_eq!(table.resolve("web", None), Some(addr(3000)));
        assert_eq!(
            table.resolve("new", Some("127.0.0.1:9999")),
            Some(addr(9999))
        );
        assert_eq!(table.resolve("new", None), None);
        // A malformed signed default falls back to the pack snapshot
        // rather than poisoning the service.
        assert_eq!(
            table.resolve("web", Some("not an address")),
            Some(addr(3000))
        );
    }

    /// An override edit signals exactly one change and reads back; clearing
    /// restores the signed/pack ladder.
    #[tokio::test]
    async fn override_edits_signal_and_clear() {
        let table = ServiceAddresses::new([("web".to_owned(), addr(3000))], []);
        let mut changes = table.subscribe();
        table.set_override("web", Some(addr(8080)));
        assert!(changes.changed().await.is_ok());
        assert_eq!(table.resolve("web", None), Some(addr(8080)));
        assert_eq!(table.overrides()["web"], addr(8080));
        table.set_override("web", None);
        assert!(changes.changed().await.is_ok());
        assert_eq!(table.resolve("web", None), Some(addr(3000)));
        assert!(table.overrides().is_empty());
    }
}
