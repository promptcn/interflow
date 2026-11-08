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
use hex;
use interflow_contract::Generation;
use interflow_util::sha256_hex;
use serde::{Deserialize, Serialize};
use std::path::Path;

/// The runtime policy snapshot.
///
/// Every field is required in the sealed document — the renderer always
/// serializes the full canonical shape (empty faces as `key = []`), so a
/// missing key means a truncated or forged document and must fail loudly.
/// Unknown keys likewise fail loudly (`deny_unknown_fields`): a typo in a
/// policy field must never pass verification against old semantics.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RuntimePolicy {
    /// Rotation generation. The pack-embedded snapshot shares the pack's
    /// generation at render time; after that the policy generation evolves
    /// on its own (signed policy updates bump it without re-signing any
    /// identity), and every node refuses a generation lower than the
    /// highest it has applied.
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
    /// The serve-side mesh rules: what each agent offers to dial for its
    /// peers. Serve agents derive their engine egress rules — and the egress
    /// allowlist (`allowed_targets`) — from these entries, so adding or
    /// widening an offer is a policy change, not an identity re-sign.
    pub mesh_egress: Vec<PolicyMeshEgress>,
    /// The fleet roster: every node the manifest declares (ingress, agent,
    /// hub), signed as the realm's desired state (format epoch 3). Membership
    /// is a signed fact, so retirement and renaming are detectable on any
    /// machine that carries a current pack: a unit or pack whose `(kind,
    /// node)` is absent from the newest roster it can see is leftovers from a
    /// retired or renamed node, not a member the signer forgot. Host-side
    /// reconciliation (`doctor host`, `node install`'s closing sweep) and the
    /// operator's `doctor` faces read this face; the data plane does not.
    pub nodes: Vec<PolicyNode>,
}

/// One fleet-roster row: the kind spelling matches [`crate::pack::PackKind`]'s
/// `as_str` (`ingress` / `agent` / `hub`).
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PolicyNode {
    pub kind: String,
    pub node: String,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PolicyRoute {
    pub host: String,
    /// `<workspace>/<agent>/<service>`.
    pub service: String,
}

/// A declared service. The **id** is the only authorization fact; the
/// optional `address` is the issuer-supplied **default dial target** — a
/// convenience hint, never binding: the node's machine-local preference
/// always wins (expose addresses are "where this machine's own traffic
/// lands", never a cross-machine authorization). Compare
/// `PolicyMeshStream`, whose `remote_addr` stays signed as an actual
/// authorization pair. Carrying the default lets a policy-only service add
/// reach nodes whose packs were not re-rendered — a new id would otherwise
/// arrive with no address anywhere on the machine.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PolicyService {
    pub workspace: String,
    pub agent: String,
    pub id: String,
    /// Default dial target (`host:port`) from the manifest — required: the
    /// manifest demands one for every declared service and the issuer signs
    /// it verbatim.
    pub address: String,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IngressAuthorization {
    pub workspace: String,
    pub ingress: String,
}

/// One authorized site-to-site stream: `source_agent` may ask
/// `target_agent` to dial `remote_addr` (the target declares the matching
/// egress rule, so both sides of the flow are signer-approved). Carries the
/// listen-side rule face: the serving agent binds `listen` under this
/// `name` and applies `idle_timeout_secs` to the stream.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PolicyMeshStream {
    pub source_workspace: String,
    pub source_agent: String,
    pub target_workspace: String,
    pub target_agent: String,
    /// The listen-side rule name (rule identity on the serving agent).
    pub name: String,
    /// The loopback listen address (`host:port`) on the source agent.
    pub listen: String,
    pub remote_addr: String,
    pub protocol: MeshProtocol,
    /// Stream idle budget override (defaults per protocol when absent).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub idle_timeout_secs: Option<u64>,
}

/// One serve-side mesh rule as signed into the policy: the offer an agent
/// makes to its peers — exactly one of `target_addr` (one concrete service)
/// or `target_cidr` (an authorized range, any port inside it). The serving
/// agent derives its engine egress rules and its egress allowlist from
/// these entries.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PolicyMeshEgress {
    /// The serving agent's workspace.
    pub workspace: String,
    /// The serving agent's id.
    pub agent: String,
    pub name: String,
    pub protocol: MeshProtocol,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub target_addr: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub target_cidr: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub udp_idle_timeout_secs: Option<u64>,
}

impl PolicyMeshEgress {
    /// The allowlist entry this offer contributes (`host:port` or `ip/prefix`).
    pub fn authorization(&self) -> &str {
        self.target_cidr
            .as_deref()
            .or(self.target_addr.as_deref())
            .unwrap_or("")
    }
}

impl RuntimePolicy {
    /// Renders the policy for a manifest (derived — the manifest stays the
    /// desired-state source of truth). Public: `plan apply`'s policy-update
    /// path signs exactly this derivation.
    pub fn from_manifest(manifest: &crate::manifest::Manifest, generation: Generation) -> Self {
        let mut services = Vec::new();
        for (agent, config) in &manifest.agent {
            for service in &config.services {
                services.push(PolicyService {
                    workspace: config.workspace.clone(),
                    agent: agent.clone(),
                    id: service.id.clone(),
                    address: service.address.clone(),
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
                    name: rule.name.clone(),
                    listen: rule.listen.clone(),
                    remote_addr: rule.remote_addr.clone(),
                    protocol: rule.protocol,
                    idle_timeout_secs: rule.idle_timeout_secs,
                });
            }
        }
        mesh.sort();
        let mut mesh_egress = Vec::new();
        for (agent, config) in &manifest.agent {
            for rule in &config.mesh_egress {
                mesh_egress.push(PolicyMeshEgress {
                    workspace: config.workspace.clone(),
                    agent: agent.clone(),
                    name: rule.name.clone(),
                    protocol: rule.protocol,
                    target_addr: rule.target_addr.clone(),
                    target_cidr: rule.target_cidr.clone(),
                    udp_idle_timeout_secs: rule.udp_idle_timeout_secs,
                });
            }
        }
        mesh_egress.sort();
        let mut nodes = Vec::new();
        for ingress in manifest.ingress.keys() {
            nodes.push(PolicyNode {
                kind: "ingress".to_owned(),
                node: ingress.clone(),
            });
        }
        for agent in manifest.agent.keys() {
            nodes.push(PolicyNode {
                kind: "agent".to_owned(),
                node: agent.clone(),
            });
        }
        for hub in manifest.mesh.hub.keys() {
            nodes.push(PolicyNode {
                kind: "hub".to_owned(),
                node: hub.clone(),
            });
        }
        nodes.sort();
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
            mesh_egress,
            nodes,
        }
    }

    /// Canonical TOML bytes — the exact bytes that are signed.
    pub fn to_bytes(&self) -> Result<Vec<u8>> {
        toml::to_string_pretty(self)
            .map(|s| s.into_bytes())
            .map_err(|e| Error::serialize("runtime policy".to_string()).with_source(e))
    }

    pub fn parse(bytes: &[u8]) -> Result<Self> {
        toml::from_str(&String::from_utf8_lossy(bytes)).map_err(|e| {
            // The strict face's rejections must name the offending key in the
            // top-level message (not only the source chain) — an operator
            // staring at a failed load needs the typo, not "policy parse".
            Error::policy(format!("policy parse: {e}"))
        })
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

    /// Parses a hex-encoded verifying key (the trust bundle's `policy_key`
    /// face) — the shape the hub's publication endpoint and reload watchers
    /// carry.
    pub fn verifying_key_from_hex(verifier_hex: &str) -> Result<VerifyingKey> {
        let key_bytes = hex::decode(verifier_hex.trim())
            .map_err(|e| Error::trust("policy verifying key".to_string()).with_source(e))?;
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&key_bytes);
        VerifyingKey::from_bytes(&arr)
            .map_err(|e| Error::trust("policy verifying key".to_string()).with_source(e))
    }

    /// Verifies a signature against a hex-encoded verifying key (the trust
    /// bundle's `policy_key` face) — the shape the hub's publication
    /// endpoint and reload watchers carry.
    pub fn verify_with_hex_key(bytes: &[u8], signature: &[u8], verifier_hex: &str) -> Result<Self> {
        let verifier = Self::verifying_key_from_hex(verifier_hex)?;
        Self::verify(bytes, signature, &verifier)
    }

    /// Enforces anti-rollback: `persisted` is the highest generation this node
    /// has ever accepted. The comparison goes through the watermark-floor
    /// half of the generational-handle contract
    /// ([`interflow_contract::generation::floor_epoch`]) — the same single
    /// compare-before-mutate implementation every rotation guard shares.
    pub fn check_not_rollback(&self, persisted: u64) -> Result<()> {
        if let interflow_contract::generation::Verdict::Superseded(floor) =
            interflow_contract::generation::floor_epoch(&self.generation, &persisted)
        {
            return Err(Error::policy(format!(
                "policy generation {} is older than the highest previously seen generation \
                 {floor} — refusing rollback",
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
            mesh_egress: vec![],
            nodes: vec![],
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
        // The listen-side rule face rides the same signed row.
        assert_eq!(stream.name, "svc");
        assert_eq!(stream.listen, "127.0.0.1:3001");
        // Cross-workspace streams are exactly what the hub's admission
        // table derives from.
        assert_ne!(stream.source_workspace, stream.target_workspace);
        // The serve-side offers are signed too — one per egress rule.
        assert_eq!(policy.mesh_egress.len(), 1);
        let offer = &policy.mesh_egress[0];
        assert_eq!(offer.workspace, "b");
        assert_eq!(offer.agent, "lan-b");
        assert_eq!(offer.authorization(), "10.0.0.5:80");
    }

    /// Range offers sign the CIDR face: the authorization entry a serve
    /// agent widens its allowlist with.
    #[test]
    fn mesh_egress_face_signs_range_offers() {
        let manifest = crate::manifest::Manifest::parse(
            r#"
[realm]
id = "promptcn"
[registrar]
endpoint = "https://registrar.example.com"
[mesh.hub.central]
endpoint = "hub.example.com:6666"
[workspace.main]
[agent.lan-a]
workspace = "main"
[[agent.lan-a.mesh_ingress]]
name = "svc"
listen = "127.0.0.1:3001"
target_agent = "lan-b"
remote_addr = "127.0.0.1:8055"
[agent.lan-b]
workspace = "main"
[[agent.lan-b.mesh_egress]]
name = "loopback"
target_cidr = "127.0.0.0/8"
udp_idle_timeout_secs = 90
"#,
        )
        .unwrap();
        let policy = RuntimePolicy::from_manifest(&manifest, 4);
        let offer = &policy.mesh_egress[0];
        assert_eq!(offer.authorization(), "127.0.0.0/8");
        assert_eq!(offer.udp_idle_timeout_secs, Some(90));
        // Round trip through the canonical signed bytes keeps the face.
        let bytes = policy.to_bytes().unwrap();
        let parsed = RuntimePolicy::parse(&bytes).unwrap();
        assert_eq!(parsed, policy);
    }

    /// The address rides the signed policy as the issuer's **default dial
    /// target** — non-authoritative (the machine-local preference always
    /// wins node-side), but present: a policy-only service add must reach
    /// nodes whose packs were not re-rendered. The 2026-09-23 demotion
    /// removed it because pack re-renders carried the default anyway; the
    /// hot channel removes that carrier, so the default travels the one
    /// signed channel that remains.
    #[test]
    fn services_carry_the_default_address() {
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
        assert_eq!(policy.services[0].address, "127.0.0.1:3000");
        let bytes = policy.to_bytes().unwrap();
        let parsed = RuntimePolicy::parse(&bytes).unwrap();
        assert_eq!(
            parsed.services[0].address, "127.0.0.1:3000",
            "the default survives the signed round trip"
        );
    }

    /// A policy without a service address, without the mesh_egress key, or
    /// without the fleet roster, fails closed — one policy shape per format
    /// epoch, no absent-field vintages to tolerate (the format epoch gates
    /// compatibility instead).
    #[test]
    fn absent_required_policy_fields_fail_closed() {
        let no_address = r#"
generation = 1
routes = []
services = [{ workspace = "a", agent = "lan-a", id = "web" }]
ingress_authorizations = []
mesh = []
mesh_egress = []
nodes = []
"#;
        assert!(RuntimePolicy::parse(no_address.as_bytes()).is_err());
        let no_egress = r#"
generation = 1
routes = []
services = [{ workspace = "a", agent = "lan-a", id = "web", address = "127.0.0.1:3000" }]
ingress_authorizations = []
mesh = []
nodes = []
"#;
        assert!(RuntimePolicy::parse(no_egress.as_bytes()).is_err());
        let no_roster = r#"
generation = 1
routes = []
services = []
ingress_authorizations = []
mesh = []
mesh_egress = []
"#;
        assert!(
            RuntimePolicy::parse(no_roster.as_bytes()).is_err(),
            "the roster is a required face since format epoch 3"
        );
    }

    /// A typo'd top-level key fails loudly instead of signing past it.
    #[test]
    fn unknown_top_level_key_is_rejected() {
        let shape = r#"
generation = 1
routes = []
services = []
ingress_authorizations = []
mesh = []
mesh_egress = []
nodes = []
routez = []
"#;
        assert!(RuntimePolicy::parse(shape.as_bytes()).is_err());
    }

    /// The fleet roster signs every declared node — ingress, agent, and hub
    /// alike (hubs were nameless in every earlier signed face; the roster is
    /// what makes a hub's retirement detectable on the host). Rows sort by
    /// (kind, node) so the canonical bytes are stable regardless of table
    /// order in the manifest, and the face survives the signed round trip.
    #[test]
    fn nodes_face_signs_the_full_fleet_roster() {
        let manifest = crate::manifest::Manifest::parse(
            r#"
[realm]
id = "promptcn"
control_endpoint = "edge.example.com:8443"
[registrar]
endpoint = "https://registrar.example.com"
[public_tls]
mode = "frontend-proxy"
[workspace.a]
[ingress.edge]
workspaces = ["a"]
[agent.lan-a]
workspace = "a"
[[agent.lan-a.services]]
id = "web"
address = "127.0.0.1:3000"
[agent.lan-b]
workspace = "a"
[[agent.lan-b.mesh_ingress]]
name = "svc"
listen = "127.0.0.1:3001"
target_agent = "lan-c"
remote_addr = "127.0.0.1:8055"
[agent.lan-c]
workspace = "a"
[[agent.lan-c.mesh_egress]]
name = "svc"
target_addr = "127.0.0.1:8055"
[[route]]
host = "web.example.com"
service = "a/lan-a/web"
[mesh.hub.central]
endpoint = "hub.example.com:6666"
"#,
        )
        .unwrap();
        let policy = RuntimePolicy::from_manifest(&manifest, 1);
        let expected: Vec<(String, String)> = vec![
            ("agent".into(), "lan-a".into()),
            ("agent".into(), "lan-b".into()),
            ("agent".into(), "lan-c".into()),
            ("hub".into(), "central".into()),
            ("ingress".into(), "edge".into()),
        ];
        let got: Vec<(String, String)> = policy
            .nodes
            .iter()
            .map(|n| (n.kind.clone(), n.node.clone()))
            .collect();
        assert_eq!(got, expected, "sorted by (kind, node)");
        let bytes = policy.to_bytes().unwrap();
        let parsed = RuntimePolicy::parse(&bytes).unwrap();
        assert_eq!(parsed.nodes, policy.nodes, "roster survives the round trip");
        // The TOML face spells one [[nodes]] table per row — the shape every
        // lenient host-side reader parses.
        let text = String::from_utf8_lossy(&bytes);
        assert!(text.contains("[[nodes]]"), "roster rows as tables: {text}");
        assert!(
            text.contains("kind = \"ingress\"") && text.contains("node = \"edge\""),
            "roster carries the ingress row: {text}"
        );
    }
}
