//! `RuleStore`: the agent's cross-session rule truth (in-memory state).
//!
//! All control-plane adds/removes go through this. Rules are held in memory
//! across reconnects within the process lifetime; the durable source of a
//! pack-driven agent is its signed policy — runtime additions live exactly
//! as long as the process (there is no config file to write back to).

use crate::config::{AgentConfig, EgressRule, IngressRule};
use serde::Serialize;
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::info;

/// Rule origin: seeded from the startup policy / changed at runtime via the
/// control API.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum RuleOrigin {
    /// Seeded from the startup policy.
    Startup,
    /// Added or changed at runtime via the control API.
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

/// Rule-change failure reason (the HTTP layer maps this to 404).
#[derive(Debug, thiserror::Error)]
pub enum RuleChangeError {
    /// The rule does not exist in the runtime tables.
    #[error("rule not found: {0}")]
    NotFound(String),
}

/// In-memory rule entries.
struct Inner {
    ingress: Vec<(IngressRule, RuleOrigin)>,
    egress: Vec<(EgressRule, RuleOrigin)>,
}

/// Rule truth shared across sessions.
pub struct RuleStore {
    inner: RwLock<Inner>,
}

fn rule_change(kind: &'static str, operation: &'static str, result: &'static str) {
    metrics::counter!("interflow_agent_rule_change_total", "kind" => kind, "operation" => operation, "result" => result)
        .increment(1);
}

impl RuleStore {
    /// Build from the startup config.
    pub fn from_config(config: &AgentConfig) -> Arc<Self> {
        Arc::new(Self {
            inner: RwLock::new(Inner {
                ingress: config
                    .ingress
                    .iter()
                    .cloned()
                    .map(|r| (r, RuleOrigin::Startup))
                    .collect(),
                egress: config
                    .egress
                    .iter()
                    .cloned()
                    .map(|r| (r, RuleOrigin::Startup))
                    .collect(),
            }),
        })
    }

    /// Add (or replace by same name) an ingress rule.
    pub async fn add_ingress(&self, rule: IngressRule) -> RuleChangeResult {
        let name = rule.name.clone();
        let mut inner = self.inner.write().await;
        upsert(&mut inner.ingress, rule, RuleOrigin::Api);
        drop(inner);
        rule_change("ingress", "add", "ok");
        info!(target: "audit", rule = %name, kind = "ingress", "control API added ingress rule");
        Ok(())
    }

    /// Remove an ingress rule.
    pub async fn remove_ingress(&self, name: &str) -> RuleChangeResult {
        let mut inner = self.inner.write().await;
        if !inner.ingress.iter().any(|(r, _)| r.name == name) {
            return Err(RuleChangeError::NotFound(name.to_string()));
        }
        inner.ingress.retain(|(r, _)| r.name != name);
        drop(inner);
        rule_change("ingress", "remove", "ok");
        info!(target: "audit", rule = name, "control API removed ingress rule");
        Ok(())
    }

    /// Add (or replace by same name) an egress rule.
    pub async fn add_egress(&self, rule: EgressRule) -> RuleChangeResult {
        let name = rule.name.clone();
        let mut inner = self.inner.write().await;
        upsert(&mut inner.egress, rule, RuleOrigin::Api);
        drop(inner);
        rule_change("egress", "add", "ok");
        info!(target: "audit", rule = %name, kind = "egress", "control API added egress rule");
        Ok(())
    }

    /// Remove an egress rule.
    pub async fn remove_egress(&self, name: &str) -> RuleChangeResult {
        let mut inner = self.inner.write().await;
        if !inner.egress.iter().any(|(r, _)| r.name == name) {
            return Err(RuleChangeError::NotFound(name.to_string()));
        }
        inner.egress.retain(|(r, _)| r.name != name);
        drop(inner);
        rule_change("egress", "remove", "ok");
        info!(target: "audit", rule = name, "control API removed egress rule");
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
        let mut cfg = AgentConfig::default();
        cfg.agent.id = "a".into();
        cfg.agent.hub_url = "https://hub".into();
        cfg
    }

    fn ingress(name: &str, port: u16) -> IngressRule {
        IngressRule {
            name: name.into(),
            listen_addr: format!("127.0.0.1:{port}").parse().unwrap(),
            listen_protocol: interflow_core::protocol::StreamProto::Tcp,
            target_agent: "remote".into(),
            remote_addr: None,
            idle_timeout_secs: None,
            udp_per_ip_pps: 0,
            udp_per_ip_bytes_per_sec: 0,
            udp_egress_bytes_per_sec: 0,
        }
    }

    fn egress(name: &str, port: u16) -> EgressRule {
        EgressRule {
            name: name.into(),
            target_addr: format!("127.0.0.1:{port}").parse().unwrap(),
            target_protocol: interflow_core::protocol::StreamProto::Tcp,
            udp_idle_timeout_secs: None,
        }
    }

    #[tokio::test]
    async fn add_remove_flow() {
        let mut cfg = base_config();
        cfg.ingress.push(ingress("seed", 1));
        let store = RuleStore::from_config(&cfg);
        store.add_ingress(ingress("api-rule", 2)).await.unwrap();
        store.add_egress(egress("eg", 3)).await.unwrap();

        let views = store.ingress_views().await;
        assert_eq!(views.len(), 2);
        // seed came from the startup policy, api-rule from the API
        assert_eq!(views[0].origin, RuleOrigin::Startup);
        assert_eq!(views[1].origin, RuleOrigin::Api);
        assert_eq!(views[1].rule.name, "api-rule");

        store.remove_ingress("api-rule").await.unwrap();
        store.remove_egress("eg").await.unwrap();
        assert_eq!(store.ingress_snapshot().await.len(), 1);
        assert!(store.egress_snapshot().await.is_empty());
    }

    #[tokio::test]
    async fn remove_unknown_returns_not_found() {
        let store = RuleStore::from_config(&base_config());
        let err = store.remove_ingress("ghost").await.unwrap_err();
        assert!(matches!(err, RuleChangeError::NotFound(_)));
    }

    #[tokio::test]
    async fn same_name_add_replaces_in_place() {
        let mut cfg = base_config();
        cfg.ingress.push(ingress("seed", 1));
        let store = RuleStore::from_config(&cfg);
        store
            .add_ingress(ingress("seed", 9999)) // same name as seed
            .await
            .unwrap();
        let snap = store.ingress_snapshot().await;
        assert_eq!(snap.len(), 1, "same-name replace must not append");
        assert_eq!(snap[0].listen_addr.port(), 9999);
    }
}
