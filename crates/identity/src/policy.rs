//! Signed runtime policy: Route + Service declarations, signed by the realm
//! policy key, with a monotonic generation for anti-rollback.
//!
//! Credential Packs carry an *initial* signed snapshot for first boot; after
//! that, runtime updates flow through the control plane and every node
//! refuses generations lower than the highest it has persisted.

use crate::issuance::{sign_policy, verify_policy_signature};
use crate::manifest::MeshProtocol;
use crate::{Error, Result};
use ed25519_dalek::{SigningKey, VerifyingKey};
use interflow_contract::Generation;
use interflow_util::sha256_hex;
use serde::{Deserialize, Serialize};
use std::path::Path;

/// The runtime policy snapshot.
///
/// Every field is required in the sealed document — the renderer always
/// serializes the full canonical shape (empty faces as `key = []`), so a
/// missing key means a truncated or forged document and must fail loudly.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RuntimePolicy {
    /// Rotation generation shared with the enclosing Credential Pack.
    pub generation: Generation,
    pub routes: Vec<PolicyRoute>,
    pub services: Vec<PolicyService>,
    /// The ingress nodes allowed to open workspace flows
    /// (`workspace → [ingress node]`).
    pub ingress_authorizations: Vec<IngressAuthorization>,
    /// The site-to-site streams agents are authorized to open
    /// (`source agent → target agent` at `remote_addr`). The hub derives its
    /// cross-workspace admission table from these entries; agents resolve
    /// their local data-plane rules from the same signed bytes.
    pub mesh: Vec<PolicyMeshStream>,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct PolicyRoute {
    pub host: String,
    /// `<workspace>/<agent>/<service>`.
    pub service: String,
}

/// A declared service. The policy signs only the service **id** — where the
/// agent dials (`address`) is node-side by design: the pack's `node.toml`
/// carries the manifest-issued default and a machine-local preference may
/// override it (expose addresses are "where this machine's own traffic
/// lands", never a cross-machine authorization). Compare `PolicyMeshStream`
/// , whose `remote_addr` stays signed (an authorization pair).
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct PolicyService {
    pub workspace: String,
    pub agent: String,
    pub id: String,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct IngressAuthorization {
    pub workspace: String,
    pub ingress: String,
}

/// One authorized site-to-site stream: `source_agent` may ask
/// `target_agent` to dial `remote_addr` (the target declares the matching
/// egress rule, so both sides of the flow are signer-approved).
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct PolicyMeshStream {
    pub source_workspace: String,
    pub source_agent: String,
    pub target_workspace: String,
    pub target_agent: String,
    pub remote_addr: String,
    pub protocol: MeshProtocol,
}

impl RuntimePolicy {
    /// Renders the policy for a manifest (derived — the manifest stays the
    /// desired-state source of truth).
    pub(crate) fn from_manifest(
        manifest: &crate::manifest::Manifest,
        generation: Generation,
    ) -> Self {
        let mut services = Vec::new();
        for (agent, config) in &manifest.agent {
            for service in &config.services {
                services.push(PolicyService {
                    workspace: config.workspace.clone(),
                    agent: agent.clone(),
                    id: service.id.clone(),
                });
            }
        }
        services.sort_by(|a, b| {
            (a.workspace.as_str(), a.agent.as_str(), a.id.as_str()).cmp(&(
                b.workspace.as_str(),
                b.agent.as_str(),
                b.id.as_str(),
            ))
        });
        let mut authorizations = Vec::new();
        for (ingress, config) in &manifest.ingress {
            for workspace in &config.workspaces {
                authorizations.push(IngressAuthorization {
                    workspace: workspace.clone(),
                    ingress: ingress.clone(),
                });
            }
        }
        authorizations.sort();
        let mut mesh = Vec::new();
        for (agent, config) in &manifest.agent {
            for rule in &config.mesh_ingress {
                let Some(target) = manifest.agent.get(&rule.target_agent) else {
                    continue; // manifest validation already rejects this
                };
                mesh.push(PolicyMeshStream {
                    source_workspace: config.workspace.clone(),
                    source_agent: agent.clone(),
                    target_workspace: target.workspace.clone(),
                    target_agent: rule.target_agent.clone(),
                    remote_addr: rule.remote_addr.clone(),
                    protocol: rule.protocol,
                });
            }
        }
        mesh.sort();
        Self {
            generation,
            routes: manifest
                .route
                .iter()
                .map(|r| PolicyRoute {
                    host: r.host.clone(),
                    service: r.service.clone(),
                })
                .collect(),
            services,
            ingress_authorizations: authorizations,
            mesh,
        }
    }

    /// Canonical TOML bytes — the exact bytes that are signed.
    pub fn to_bytes(&self) -> Result<Vec<u8>> {
        toml::to_string_pretty(self)
            .map(|s| s.into_bytes())
            .map_err(|e| Error::serialize("runtime policy".to_string()).with_source(e))
    }

    pub fn parse(bytes: &[u8]) -> Result<Self> {
        toml::from_str(&String::from_utf8_lossy(bytes))
            .map_err(|e| Error::policy("policy parse".to_string()).with_source(e))
    }

    /// Digest of the canonical bytes.
    pub fn digest(&self) -> Result<String> {
        let bytes = self.to_bytes()?;
        Ok(format!("sha256:{}", sha256_hex(&bytes)))
    }

    /// Serializes + signs, returning `(policy.toml bytes, signature)`.
    pub fn signed(&self, signer: &SigningKey) -> Result<(Vec<u8>, Vec<u8>)> {
        let bytes = self.to_bytes()?;
        let sig = sign_policy(signer, &bytes);
        Ok((bytes, sig))
    }

    /// Verifies a signature over policy bytes.
    pub fn verify(bytes: &[u8], signature: &[u8], verifier: &VerifyingKey) -> Result<Self> {
        let policy = Self::parse(bytes)?;
        verify_policy_signature(verifier, bytes, signature)?;
        Ok(policy)
    }

    /// Enforces anti-rollback: `persisted` is the highest generation this node
    /// has ever accepted.
    pub fn check_not_rollback(&self, persisted: u64) -> Result<()> {
        if self.generation < persisted {
            return Err(Error::policy(format!(
                "policy generation {} is older than the highest previously seen generation \
                 {persisted} — refusing rollback",
                self.generation
            )));
        }
        Ok(())
    }

    /// Resolves one route's `workspace/agent/service` reference to its
    /// service declaration (identity only — the dial address lives
    /// node-side: pack default + machine-local preference).
    pub fn find_service(&self, reference: &str) -> Option<&PolicyService> {
        self.services
            .iter()
            .find(|s| format!("{}/{}/{}", s.workspace, s.agent, s.id) == reference)
    }
}

/// A signed policy snapshot on disk (`policy.toml` + `policy.sig`).
#[derive(Debug, Clone)]
pub struct SignedPolicyFiles {
    pub policy: RuntimePolicy,
    pub signature: Vec<u8>,
}

impl SignedPolicyFiles {
    /// Writes `policy/policy.toml` + `policy/policy.sig` under `dir`.
    pub fn save(&self, dir: &Path) -> Result<()> {
        let dir = dir.join("policy");
        std::fs::create_dir_all(&dir).map_err(|e| Error::Io {
            path: dir.display().to_string(),
            source: e,
        })?;
        let bytes = self.policy.to_bytes()?;
        std::fs::write(dir.join("policy.toml"), &bytes).map_err(|e| Error::Io {
            path: dir.join("policy.toml").display().to_string(),
            source: e,
        })?;
        std::fs::write(dir.join("policy.sig"), &self.signature).map_err(|e| Error::Io {
            path: dir.join("policy.sig").display().to_string(),
            source: e,
        })?;
        Ok(())
    }

    /// Loads and verifies against `verifier`.
    pub fn load(dir: &Path, verifier: &VerifyingKey) -> Result<Self> {
        let bytes = std::fs::read(dir.join("policy.toml")).map_err(|e| Error::Io {
            path: dir.join("policy.toml").display().to_string(),
            source: e,
        })?;
        let signature = std::fs::read(dir.join("policy.sig")).map_err(|e| Error::Io {
            path: dir.join("policy.sig").display().to_string(),
            source: e,
        })?;
        let policy = RuntimePolicy::verify(&bytes, &signature, verifier)?;
        Ok(Self { policy, signature })
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn rollback_is_rejected() {
        let policy = RuntimePolicy {
            generation: 3,
            routes: vec![],
            services: vec![],
            ingress_authorizations: vec![],
            mesh: vec![],
        };
        policy.check_not_rollback(2).unwrap();
        let err = policy.check_not_rollback(4).unwrap_err();
        assert!(err.to_string().contains("rollback"));
    }

    #[test]
    fn mesh_streams_derive_from_manifest_ingress_rules() {
        let manifest = crate::manifest::Manifest::parse(
            r#"
[realm]
id = "promptcn"
[registrar]
endpoint = "https://registrar.example.com"
[mesh.hub.central]
endpoint = "hub.example.com:6666"
[workspace.a]
[workspace.b]
[agent.lan-a]
workspace = "a"
[[agent.lan-a.mesh_ingress]]
name = "svc"
listen = "127.0.0.1:3001"
target_agent = "lan-b"
remote_addr = "10.0.0.5:80"
[agent.lan-b]
workspace = "b"
[[agent.lan-b.mesh_egress]]
name = "svc"
target_addr = "10.0.0.5:80"
"#,
        )
        .unwrap();
        let policy = RuntimePolicy::from_manifest(&manifest, 1);
        assert_eq!(policy.mesh.len(), 1);
        let stream = &policy.mesh[0];
        assert_eq!(stream.source_workspace, "a");
        assert_eq!(stream.target_workspace, "b");
        assert_eq!(stream.remote_addr, "10.0.0.5:80");
        // Cross-workspace streams are exactly what the hub's admission
        // table derives from.
        assert_ne!(stream.source_workspace, stream.target_workspace);
    }

    /// The policy signs service **ids** only — where the agent dials is
    /// node-side (pack default + machine-local preference).
    #[test]
    fn services_carry_no_address() {
        let manifest = crate::manifest::Manifest::parse(
            r#"
[realm]
id = "promptcn"
control_endpoint = "edge.example.com:8443"
[registrar]
endpoint = "https://registrar.example.com"
[workspace.a]
[ingress.edge]
workspaces = ["a"]
[[route]]
host = "web.example.com"
service = "a/lan-a/web"
[agent.lan-a]
workspace = "a"
[[agent.lan-a.services]]
id = "web"
address = "127.0.0.1:3000"
"#,
        )
        .unwrap();
        let policy = RuntimePolicy::from_manifest(&manifest, 1);
        assert_eq!(policy.services.len(), 1);
        let bytes = policy.to_bytes().unwrap();
        let text = String::from_utf8_lossy(&bytes);
        assert!(text.contains("id = \"web\""));
        assert!(!text.contains("address"), "policy must not sign addresses");
    }

    /// Packs rendered before the address demotion carry `address` keys in
    /// their signed policy.toml. Those bytes still parse (serde ignores the
    /// retired key; the signature verifies over the raw bytes) and the node
    /// falls back to the node.toml default — no FORMAT_VERSION bump.
    #[test]
    fn retired_address_key_still_loads() {
        let old_shape = r#"
generation = 1
routes = []
services = [{ workspace = "a", agent = "lan-a", id = "web", address = "127.0.0.1:3000" }]
ingress_authorizations = []
mesh = []
"#;
        let policy = RuntimePolicy::parse(old_shape.as_bytes()).unwrap();
        assert_eq!(policy.services.len(), 1);
        assert_eq!(policy.services[0].id, "web");
    }
}
