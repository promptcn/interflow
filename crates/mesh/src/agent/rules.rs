//! `RuleStore`: the agent's cross-session rule truth (in-memory state +
//! write-through persistence).
//!
//! All control-plane adds/removes go through this, in the order
//! "persist first, then memory":
//! - persistence failure -> memory untouched; the caller (handler) rolls back
//!   the runtime side effects that already took effect (listeners), keeping
//!   the invariant **API 2xx = persisted to disk**;
//! - between a successful persist and the in-memory update there is an
//!   extremely narrow crash window where the file briefly leads memory; it is
//!   self-healed by `resync_from_disk` on the next session (externally
//!   hand-edited configs converge for the same reason).
//!
//! On session establishment the rules are resynced from disk: re-read +
//! re-validate the config file and wholesale-replace the in-memory tables;
//! on failure the last-known state is kept and a log is emitted (a typo in
//! the config file must not block tunnel reconnection).

use crate::agent::persist::{FileRulePersister, RuleEdit, RulePersister};
use crate::config::{AgentConfig, EgressRule, IngressRule, load_agent_config};
use futures::future::BoxFuture;
use interflow_core::error::{InterflowError, Result};
use serde::Serialize;
use std::path::PathBuf;
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::{error, info};

/// Rule origin: loaded from the config file / changed at runtime via the
/// control API.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum RuleOrigin {
    /// Loaded from the config file at startup or session resync.
    File,
    /// Added or changed at runtime via the control API (already written back
    /// to the file synchronously).
    Api,
}

/// `GET /ingress` response entry: rule fields flattened + origin annotation.
#[derive(Debug, Serialize)]
pub struct IngressRuleView {
    /// The rule itself (fields flattened to the top level).
    #[serde(flatten)]
    pub rule: IngressRule,
    /// Origin annotation (drift visibility).
    pub origin: RuleOrigin,
}

/// `GET /egress` response entry: rule fields flattened + origin annotation.
#[derive(Debug, Serialize)]
pub struct EgressRuleView {
    /// The rule itself (fields flattened to the top level).
    #[serde(flatten)]
    pub rule: EgressRule,
    /// Origin annotation (drift visibility).
    pub origin: RuleOrigin,
}

/// Alias for the control-plane rule-change result.
pub type RuleChangeResult = std::result::Result<(), RuleChangeError>;

/// Rule-change failure reason (the HTTP layer maps this to 404 / 500).
#[derive(Debug, thiserror::Error)]
pub enum RuleChangeError {
    /// The rule does not exist in the runtime tables.
    #[error("rule not found: {0}")]
    NotFound(String),
    /// Persistence failed (memory and runtime side effects were rolled back
    /// or never took effect).
    #[error("persistence failed: {0}")]
    Persist(#[from] InterflowError),
}

/// In-memory rule entries.
struct Inner {
    ingress: Vec<(IngressRule, RuleOrigin)>,
    egress: Vec<(EgressRule, RuleOrigin)>,
}

/// Rule truth shared across sessions.
pub struct RuleStore {
    inner: RwLock<Inner>,
    persister: Arc<dyn RulePersister>,
    /// Source config file path; `None` = purely in-memory (no persistence, no
    /// resync).
    source_path: Option<PathBuf>,
}

/// In-memory persistence backend (the behavior when `AgentClient::new` has no
/// file path; equivalent to the old implementation).
struct NoopPersister;

impl RulePersister for NoopPersister {
    fn persist(&self, _edit: RuleEdit) -> BoxFuture<'static, Result<()>> {
        Box::pin(async { Ok(()) })
    }
}

fn rule_change(kind: &'static str, operation: &'static str, result: &'static str) {
    metrics::counter!("interflow_agent_rule_change_total", "kind" => kind, "operation" => operation, "result" => result)
        .increment(1);
}

impl RuleStore {
    /// Build from the startup config. A `path` of `None` means purely
    /// in-memory (no disk writes, no resync).
    pub fn from_config(config: &AgentConfig, path: Option<PathBuf>) -> Arc<Self> {
        let persister: Arc<dyn RulePersister> = match &path {
            Some(p) => Arc::new(FileRulePersister::new(p)),
            None => Arc::new(NoopPersister),
        };
        Arc::new(Self {
            inner: RwLock::new(Inner {
                ingress: config
                    .ingress
                    .iter()
                    .cloned()
                    .map(|r| (r, RuleOrigin::File))
                    .collect(),
                egress: config
                    .egress
                    .iter()
                    .cloned()
                    .map(|r| (r, RuleOrigin::File))
                    .collect(),
            }),
            persister,
            source_path: path,
        })
    }

    /// Add (or replace by same name) an ingress rule: file first, then memory.
    pub async fn add_ingress(&self, rule: IngressRule) -> RuleChangeResult {
        let name = rule.name.clone();
        if let Err(e) = self
            .persister
            .persist(RuleEdit::AddIngress(rule.clone()))
            .await
        {
            rule_change("ingress", "add", "error");
            error!(rule = %name, error = %e, "ingress rule persist failed, memory unchanged");
            return Err(RuleChangeError::Persist(e));
        }
        let mut inner = self.inner.write().await;
        upsert(&mut inner.ingress, rule, RuleOrigin::Api);
        drop(inner);
        rule_change("ingress", "add", "ok");
        info!(target: "audit", rule = %name, kind = "ingress", "control API persisted new ingress rule");
        Ok(())
    }

    /// Remove an ingress rule: file first, then memory.
    pub async fn remove_ingress(&self, name: &str) -> RuleChangeResult {
        let inner = self.inner.write().await;
        if !inner.ingress.iter().any(|(r, _)| r.name == name) {
            return Err(RuleChangeError::NotFound(name.to_string()));
        }
        drop(inner);
        if let Err(e) = self
            .persister
            .persist(RuleEdit::RemoveIngress(name.to_string()))
            .await
        {
            rule_change("ingress", "remove", "error");
            error!(rule = name, error = %e, "ingress rule removal persist failed, memory unchanged");
            return Err(RuleChangeError::Persist(e));
        }
        let mut inner = self.inner.write().await;
        inner.ingress.retain(|(r, _)| r.name != name);
        drop(inner);
        rule_change("ingress", "remove", "ok");
        info!(target: "audit", rule = name, "control API persisted ingress rule removal");
        Ok(())
    }

    /// Add (or replace by same name) an egress rule: file first, then memory.
    pub async fn add_egress(&self, rule: EgressRule) -> RuleChangeResult {
        let name = rule.name.clone();
        if let Err(e) = self
            .persister
            .persist(RuleEdit::AddEgress(rule.clone()))
            .await
        {
            rule_change("egress", "add", "error");
            error!(rule = %name, error = %e, "egress rule persist failed, memory unchanged");
            return Err(RuleChangeError::Persist(e));
        }
        let mut inner = self.inner.write().await;
        upsert(&mut inner.egress, rule, RuleOrigin::Api);
        drop(inner);
        rule_change("egress", "add", "ok");
        info!(target: "audit", rule = %name, kind = "egress", "control API persisted new egress rule");
        Ok(())
    }

    /// Remove an egress rule: file first, then memory.
    pub async fn remove_egress(&self, name: &str) -> RuleChangeResult {
        let inner = self.inner.write().await;
        if !inner.egress.iter().any(|(r, _)| r.name == name) {
            return Err(RuleChangeError::NotFound(name.to_string()));
        }
        drop(inner);
        if let Err(e) = self
            .persister
            .persist(RuleEdit::RemoveEgress(name.to_string()))
            .await
        {
            rule_change("egress", "remove", "error");
            error!(rule = name, error = %e, "egress rule removal persist failed, memory unchanged");
            return Err(RuleChangeError::Persist(e));
        }
        let mut inner = self.inner.write().await;
        inner.egress.retain(|(r, _)| r.name != name);
        drop(inner);
        rule_change("egress", "remove", "ok");
        info!(target: "audit", rule = name, "control API persisted egress rule removal");
        Ok(())
    }

    /// Ingress rule snapshot (for the handler to start listeners).
    pub async fn ingress_snapshot(&self) -> Vec<IngressRule> {
        self.inner
            .read()
            .await
            .ingress
            .iter()
            .map(|(r, _)| r.clone())
            .collect()
    }

    /// Egress rule snapshot (for the handler's hot-path matching).
    pub async fn egress_snapshot(&self) -> Vec<EgressRule> {
        self.inner
            .read()
            .await
            .egress
            .iter()
            .map(|(r, _)| r.clone())
            .collect()
    }

    /// Look up an ingress rule by name (for listener compensation after a
    /// Remove whose persistence failed).
    pub async fn get_ingress(&self, name: &str) -> Option<IngressRule> {
        self.inner
            .read()
            .await
            .ingress
            .iter()
            .find(|(r, _)| r.name == name)
            .map(|(r, _)| r.clone())
    }

    /// `GET /ingress` view.
    pub async fn ingress_views(&self) -> Vec<IngressRuleView> {
        self.inner
            .read()
            .await
            .ingress
            .iter()
            .map(|(r, o)| IngressRuleView {
                rule: r.clone(),
                origin: *o,
            })
            .collect()
    }

    /// `GET /egress` view.
    pub async fn egress_views(&self) -> Vec<EgressRuleView> {
        self.inner
            .read()
            .await
            .egress
            .iter()
            .map(|(r, o)| EgressRuleView {
                rule: r.clone(),
                origin: *o,
            })
            .collect()
    }

    /// Re-read the config file to refresh the in-memory tables on session
    /// establishment (a no-op in purely in-memory mode).
    ///
    /// Externally hand-edited configs therefore converge to the file on
    /// tunnel reconnection; on read/validation failure the last-known state
    /// is kept (a typo must not block reconnection), with the drift surfaced
    /// explicitly via an `error`-level log.
    pub async fn resync_from_disk(&self) {
        let Some(path) = self.source_path.clone() else {
            return;
        };
        let loaded = tokio::task::spawn_blocking(move || load_agent_config(&path)).await;
        match loaded {
            Ok(Ok(cfg)) => {
                let mut inner = self.inner.write().await;
                let prev_ingress = inner.ingress.len();
                let prev_egress = inner.egress.len();
                *inner = Inner {
                    ingress: cfg
                        .ingress
                        .into_iter()
                        .map(|r| (r, RuleOrigin::File))
                        .collect(),
                    egress: cfg
                        .egress
                        .into_iter()
                        .map(|r| (r, RuleOrigin::File))
                        .collect(),
                };
                info!(
                    ingress = inner.ingress.len(),
                    egress = inner.egress.len(),
                    "Session resync: rule tables refreshed from config file (previously ingress={}, egress={})",
                    prev_ingress,
                    prev_egress
                );
            }
            Ok(Err(e)) => {
                error!(error = %e, "Session resync failed, keeping last-known rules (file and memory may have diverged)");
            }
            Err(e) => {
                error!(error = %e, "Session resync task join failed, keeping last-known rules");
            }
        }
    }
}

/// Replace by same name (keeping the existing order) or append.
fn upsert<R: RuleName>(rules: &mut Vec<(R, RuleOrigin)>, rule: R, origin: RuleOrigin) {
    if let Some(slot) = rules.iter_mut().find(|(r, _)| r.name() == rule.name()) {
        slot.0 = rule;
        slot.1 = origin;
    } else {
        rules.push((rule, origin));
    }
}

/// Uniform access to a rule's name (used by the `upsert` generic).
trait RuleName {
    fn name(&self) -> &str;
}

impl RuleName for IngressRule {
    fn name(&self) -> &str {
        &self.name
    }
}

impl RuleName for EgressRule {
    fn name(&self) -> &str {
        &self.name
    }
}

/// Always-failing persistence backend (for testing rollback paths).
#[cfg(test)]
#[allow(
    clippy::panic,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::missing_docs_in_private_items
)]
pub(crate) struct FailingPersister;

#[cfg(test)]
impl RulePersister for FailingPersister {
    fn persist(&self, _edit: RuleEdit) -> BoxFuture<'static, Result<()>> {
        Box::pin(async {
            Err(InterflowError::Io(std::io::Error::other(
                "injected persistence failure",
            )))
        })
    }
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

    fn base_config() -> AgentConfig {
        let cfg: AgentConfig = toml::from_str(
            r#"
config_version = 2

[agent]
id = "a"
hub_url = "https://hub"

[[ingress]]
name = "seed"
listen_addr = "127.0.0.1:14001"
target_agent = "remote"
"#,
        )
        .unwrap();
        cfg
    }

    fn ingress(name: &str, port: u16) -> IngressRule {
        toml::from_str(&format!(
            r#"name = "{name}"
listen_addr = "127.0.0.1:{port}"
target_agent = "remote""#
        ))
        .unwrap()
    }

    fn egress(name: &str, port: u16) -> EgressRule {
        toml::from_str(&format!(
            r#"name = "{name}"
target_addr = "127.0.0.1:{port}""#
        ))
        .unwrap()
    }

    /// Store constructor with a designated persistence backend (for tests).
    fn store_with(persister: Arc<dyn RulePersister>) -> Arc<RuleStore> {
        Arc::new(RuleStore {
            inner: RwLock::new(Inner {
                ingress: vec![(ingress("seed", 1), RuleOrigin::File)],
                egress: vec![],
            }),
            persister,
            source_path: None,
        })
    }

    #[tokio::test]
    async fn noop_persister_add_remove_flow() {
        let store = store_with(Arc::new(NoopPersister));
        store.add_ingress(ingress("api-rule", 2)).await.unwrap();
        store.add_egress(egress("eg", 3)).await.unwrap();

        let views = store.ingress_views().await;
        assert_eq!(views.len(), 2);
        // seed came from the file, api-rule from the API
        assert_eq!(views[0].origin, RuleOrigin::File);
        assert_eq!(views[1].origin, RuleOrigin::Api);
        assert_eq!(views[1].rule.name, "api-rule");

        store.remove_ingress("api-rule").await.unwrap();
        store.remove_egress("eg").await.unwrap();
        assert_eq!(store.ingress_snapshot().await.len(), 1);
        assert!(store.egress_snapshot().await.is_empty());
    }

    #[tokio::test]
    async fn remove_unknown_returns_not_found() {
        let store = RuleStore::from_config(&base_config(), None);
        let err = store.remove_ingress("ghost").await.unwrap_err();
        assert!(matches!(err, RuleChangeError::NotFound(_)));
    }

    #[tokio::test]
    async fn persist_failure_leaves_memory_untouched() {
        let store = store_with(Arc::new(FailingPersister));
        let before = store.ingress_snapshot().await;

        let err = store.add_ingress(ingress("doomed", 2)).await.unwrap_err();
        assert!(matches!(err, RuleChangeError::Persist(_)));

        let err = store
            .remove_ingress("seed") // exists in memory, but persistence failed
            .await
            .unwrap_err();
        assert!(matches!(err, RuleChangeError::Persist(_)));

        // Memory has neither the addition nor the removal
        let after = store.ingress_snapshot().await;
        assert_eq!(after.len(), before.len());
        assert_eq!(after[0].name, before[0].name);
        assert_eq!(store.get_ingress("seed").await.unwrap().name, "seed");
    }

    #[tokio::test]
    async fn same_name_add_replaces_in_place() {
        let store = store_with(Arc::new(NoopPersister));
        store
            .add_ingress(ingress("seed", 9999)) // same name as seed
            .await
            .unwrap();
        let snap = store.ingress_snapshot().await;
        assert_eq!(snap.len(), 1, "same-name replace must not append");
        assert_eq!(snap[0].listen_addr.port(), 9999);
    }
}
