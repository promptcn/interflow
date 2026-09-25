//! Credential Packs: the standardized distribution object for node identity.
//!
//! A pack is **self-describing** (kind, realm, workspace, node, generation,
//! expiry), **role-bound** (an agent pack cannot start as an ingress and
//! vice versa), **verifiable** (digest manifest, key/cert match, principal
//! path, chain anchor, expiry, trust consistency) and **minimal** (an agent
//! pack never carries ingress keys; no pack ever carries issuer keys).
//!
//! Runtime format: a directory (`pack.toml` + `identity/` + `trust/` +
//! `policy/` + `SHA256SUMS`). Distribution format: `*.iflowpack` — an
//! age-encrypted tar of that directory.
//! Submodules by lifecycle stage:
//! - [`render`]: manifest -> pack directories (plan apply / pack issue);
//! - [`load`]: directory -> validated [`CredentialPack`];
//! - [`sealed`]: age-encrypted `.iflowpack` distribution (seal / install).

pub mod load;
pub mod render;
pub mod sealed;

use crate::PrincipalPath;
use crate::policy::RuntimePolicy;
use crate::trust::TrustBundle;
use interflow_contract::Generation;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::path::PathBuf;

/// Which role a pack may start.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum PackKind {
    Ingress,
    Agent,
    /// A site-to-site mesh hub node: control-endpoint server identity plus
    /// the realm-scoped hub client principal that authorizes renewal.
    Hub,
}

impl PackKind {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Ingress => "ingress",
            Self::Agent => "agent",
            Self::Hub => "hub",
        }
    }
}

impl std::fmt::Display for PackKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// `pack.toml` — the self-describing metadata.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PackMetadata {
    pub format_version: u8,
    pub kind: PackKind,
    pub realm: String,
    /// Agent packs carry exactly one workspace (their membership).
    /// Ingress packs serve the workspaces listed in the runtime policy
    /// (`ingress_authorizations`) and carry one credential per workspace.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub workspace: Option<String>,
    pub node: String,
    /// Rotation generation shared by this pack and its Trust Bundle / Policy.
    pub generation: Generation,
    pub created: String,
    pub expires: String,
    /// The control endpoint agents/ingresses dial.
    pub control_endpoint: String,
    /// End-entity credential lifetime in seconds.
    pub leaf_ttl_secs: u64,
    /// How this deployment's credentials live. Omitted on registrar packs so
    /// their byte shape is unchanged (offline packs require a current
    /// binary). Renewal scheduling derives from this field — pack readers
    /// never see the server-side choice.
    #[serde(default, skip_serializing_if = "identity_mode_is_registrar")]
    pub identity_mode: crate::manifest::IdentityMode,
    /// HTTPS registrar endpoint used for unattended renewal; `None` in
    /// offline deployments (rotate/revoke are manual).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub registrar_endpoint: Option<String>,
}

fn identity_mode_is_registrar(mode: &crate::manifest::IdentityMode) -> bool {
    matches!(mode, crate::manifest::IdentityMode::Registrar)
}

/// Where a verifier finds the CRL for one issuer: the live `state/crls`
/// directory first (registrar refresh), then the `trust/crls` snapshot
/// embedded at rotate time (offline deployments). CRLs are signed by the
/// issuer, so the snapshot needs no extra integrity story.
pub fn crl_path_for(pack_dir: &std::path::Path, issuer_stem: &str) -> Option<std::path::PathBuf> {
    let file = format!("{issuer_stem}.crl.pem");
    let live = pack_dir.join("state").join("crls").join(&file);
    if live.is_file() {
        return Some(live);
    }
    let embedded = pack_dir.join("trust").join("crls").join(&file);
    embedded.is_file().then_some(embedded)
}

/// `node.toml` — the node's runtime configuration rendered from the
/// manifest (listen addresses, public TLS mode, agent services).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NodeConfig {
    pub kind: PackKind,
    pub node: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub listen: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub control_listen: Option<String>,
    /// Single-public-port mode (ACME topologies): connections with this
    /// SNI on the public listener are dispatched to the control plane, so
    /// the deployment needs only 443. `None` on fronted topologies (the
    /// front proxy's stream map owns that dispatch) and whenever the
    /// control endpoint keeps its own port.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub control_dispatch_host: Option<String>,
    pub public_tls: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub public_tls_email: Option<String>,
    /// ACME directory URL override (`None` = Let's Encrypt production).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub public_tls_directory: Option<String>,
    /// Agent services: the manifest-issued **default** dial targets (a
    /// machine-local preference may override each one at run time; the
    /// signed policy carries the ids only).
    pub services: Vec<NodeService>,
    /// Site-to-site runtime rules — present on mesh-role agent packs (the
    /// hub dial target plus this agent's local rules). Absent on expose
    /// packs.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mesh: Option<NodeMeshConfig>,
    /// Ingress public-listener governance overrides (present on ingress
    /// packs only when the manifest sets them; absent = engine defaults for
    /// the pack's topology).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub edge: Option<NodeEdgeConfig>,
}

/// Ingress `[edge]` overrides carried in `node.toml`: public-listener
/// governance the deployment pins explicitly. Absent fields fall back to
/// the engine's topology-aware default (the whole section is omitted from
/// the rendered `node.toml` when the manifest sets none of it).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub struct NodeEdgeConfig {
    /// Per-IP new-connection limit per minute on the public listener
    /// (0 = unlimited). Absent = engine default for the topology
    /// (fronted 600 / direct 30 — a front proxy opens one new connection
    /// per proxied request, so its budget must scale with request rate,
    /// not browser behavior).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub new_conn_rate_per_ip_per_minute: Option<u32>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NodeMeshConfig {
    /// The mesh hub this agent dials (`https://host:port`). The site-to-site
    /// rules themselves live in the signed policy (`policy/policy.toml`) —
    /// node-local dial info is all `node.toml` carries for the mesh face.
    pub hub_endpoint: String,
    /// Legacy pre-policy-face fields (rules carried here before the
    /// policy-identity separation). Parsed so an old pack gets a precise
    /// migration error instead of a bare unknown-field parse failure;
    /// a non-empty value is rejected at load and the renderer never
    /// writes these.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub ingress: Vec<crate::manifest::MeshIngressRule>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub egress: Vec<crate::manifest::MeshEgressRule>,
}

/// One declared agent service and its manifest-issued default address
/// (where the agent dials unless a machine-local preference overrides it).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NodeService {
    pub id: String,
    pub address: String,
}

/// A loaded, fully validated credential pack.
#[derive(Debug, Clone)]
pub struct CredentialPack {
    pub metadata: PackMetadata,
    pub dir: PathBuf,
    /// kind → workspace → identity (leaf PEM path inside `identity/`).
    /// For agents: `agent/<workspace>`; for ingresses: `control` plus one
    /// `ingress/<workspace>` entry per authorized workspace.
    pub identities: BTreeMap<String, BTreeMap<String, IdentityEntry>>,
    pub trust: TrustBundle,
    pub policy: RuntimePolicy,
    pub policy_signature: Vec<u8>,
    pub node_config: NodeConfig,
    /// sha256 over the SHA256SUMS manifest content.
    pub pack_digest: String,
}

#[derive(Debug, Clone)]
pub struct IdentityEntry {
    pub principal: PrincipalPath,
    pub cert_pem: String,
    pub key_pem: String,
    /// `spiffe://...` URI SAN carried by the certificate.
    pub uri_san: Option<String>,
    /// Leaf CN (the engine's CN == node binding).
    pub cn: String,
    pub not_after_unix: i64,
}

/// The issuance result for one node (directory on disk).
pub struct IssuedPack {
    pub dir: PathBuf,
    pub metadata: PackMetadata,
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::load::validate_generation;
    use super::render::write_digests;
    use super::render::{AgentCredentialPack, HubCredentialPack, IngressCredentialPack};
    use super::sealed::{SealKey, install, seal};
    use super::*;
    use crate::issuance::IssuerStore;
    use crate::manifest::Manifest;
    use interflow_contract::FORMAT_VERSION;

    fn manifest_text() -> String {
        r#"
[realm]
id = "promptcn"
control_endpoint = "relay.example.com:16666"
[identity]
leaf_ttl = "24h"
[registrar]
endpoint = "https://registrar.example.com"
[ingress.edge]
workspaces = ["main"]
[workspace.main]
[agent.desktop]
workspace = "main"
[[agent.desktop.services]]
id = "asr"
address = "127.0.0.1:8080"
[[route]]
host = "asr.example.com"
service = "main/desktop/asr"
"#
        .to_owned()
    }

    #[test]
    fn rendered_packs_load_and_validate() {
        let tmp = tempfile::tempdir().unwrap();
        let issuer = IssuerStore::open(tmp.path().join("issuer"));
        issuer.ensure_realm().unwrap();
        issuer.ensure_workspace("main").unwrap();
        issuer.ensure_policy_key().unwrap();
        let manifest = Manifest::parse(&manifest_text()).unwrap();

        let ingress_out = tmp.path().join("packs/ingress-edge");
        let issued =
            IngressCredentialPack::render(&issuer, &manifest, "edge", 1, &ingress_out).unwrap();
        assert_eq!(issued.metadata.kind, PackKind::Ingress);
        assert_eq!(issued.metadata.format_version, FORMAT_VERSION);
        assert_eq!(issued.metadata.leaf_ttl_secs, 86_400);
        assert_eq!(
            issued.metadata.registrar_endpoint.as_deref(),
            Some("https://registrar.example.com")
        );
        let pack = CredentialPack::load(&ingress_out).unwrap();
        assert_eq!(pack.metadata.generation, 1);
        assert_eq!(pack.trust.metadata.generation, 1);
        assert_eq!(pack.policy.generation, 1);
        assert_eq!(pack.summary().generation, 1);
        assert_eq!(
            pack.primary_identity().unwrap().principal.to_string(),
            "spiffe://promptcn/control/edge"
        );
        assert_eq!(pack.ingress_identities().unwrap().len(), 1);
        assert_eq!(
            pack.ingress_identities().unwrap()["main"]
                .principal
                .to_string(),
            "spiffe://promptcn/main/ingress/edge"
        );

        let agent_out = tmp.path().join("packs/agent-desktop");
        AgentCredentialPack::render(&issuer, &manifest, "desktop", 1, &agent_out).unwrap();
        let agent_pack = CredentialPack::load(&agent_out).unwrap();
        assert_eq!(
            agent_pack.primary_identity().unwrap().principal.to_string(),
            "spiffe://promptcn/main/agent/desktop"
        );
    }

    #[test]
    fn retired_pack_format_field_is_rejected() {
        let tmp = tempfile::tempdir().unwrap();
        let issuer = IssuerStore::open(tmp.path().join("issuer"));
        issuer.ensure_realm().unwrap();
        issuer.ensure_workspace("main").unwrap();
        issuer.ensure_policy_key().unwrap();
        let manifest = Manifest::parse(&manifest_text()).unwrap();
        let out = tmp.path().join("pack");
        AgentCredentialPack::render(&issuer, &manifest, "desktop", 1, &out).unwrap();

        let metadata_path = out.join("pack.toml");
        let original = std::fs::read_to_string(&metadata_path).unwrap();
        let retired_fields = [
            format!("{}{}", "schema_", "version"),
            format!("{}{}", "re", "vision"),
        ];
        for retired_field in retired_fields {
            let metadata = original.replace("format_version = 1", &format!("{retired_field} = 2"));
            std::fs::write(&metadata_path, metadata).unwrap();

            let err = CredentialPack::load(&out).unwrap_err();
            let chain = interflow_util::format_chain(&err);
            assert!(
                chain.contains("unknown field") && chain.contains(&retired_field),
                "expected a parse error naming the replacement field: {chain}"
            );
        }
        std::fs::write(
            &metadata_path,
            original.replace("format_version = 1", "format_version = 2"),
        )
        .unwrap();
        let err = CredentialPack::load(&out).unwrap_err();
        assert!(
            err.to_string().contains("pack format_version must be 1"),
            "expected format-version fail-closed rejection: {err}"
        );
    }

    #[test]
    fn embedded_generation_mismatch_is_rejected() {
        let tmp = tempfile::tempdir().unwrap();
        let issuer = IssuerStore::open(tmp.path().join("issuer"));
        issuer.ensure_realm().unwrap();
        issuer.ensure_workspace("main").unwrap();
        issuer.ensure_policy_key().unwrap();
        let manifest = Manifest::parse(&manifest_text()).unwrap();
        let out = tmp.path().join("pack");
        AgentCredentialPack::render(&issuer, &manifest, "desktop", 7, &out).unwrap();
        let pack = CredentialPack::load(&out).unwrap();
        assert_eq!(pack.metadata.generation, 7);

        let mut stale_policy = pack.policy.clone();
        stale_policy.generation = 6;
        let err = validate_generation(7, &pack.trust, &stale_policy).unwrap_err();
        assert!(err.to_string().contains("generation mismatch"), "{err}");
    }

    #[test]
    fn tampered_pack_fails_digest_verification() {
        let tmp = tempfile::tempdir().unwrap();
        let issuer = IssuerStore::open(tmp.path().join("issuer"));
        issuer.ensure_realm().unwrap();
        issuer.ensure_workspace("main").unwrap();
        issuer.ensure_policy_key().unwrap();
        let manifest = Manifest::parse(&manifest_text()).unwrap();
        let out = tmp.path().join("pack");
        AgentCredentialPack::render(&issuer, &manifest, "desktop", 1, &out).unwrap();
        let cert = out.join("identity/agent-main.crt");
        let pem = std::fs::read_to_string(&cert).unwrap();
        std::fs::write(
            &cert,
            pem.replace("BEGIN CERTIFICATE", "BEGIN CERTIFICATE "),
        )
        .unwrap();
        assert!(CredentialPack::load(&out).is_err());
    }

    #[test]
    fn wrong_role_pack_is_rejected() {
        let tmp = tempfile::tempdir().unwrap();
        let issuer = IssuerStore::open(tmp.path().join("issuer"));
        issuer.ensure_realm().unwrap();
        issuer.ensure_workspace("main").unwrap();
        issuer.ensure_policy_key().unwrap();
        let manifest = Manifest::parse(&manifest_text()).unwrap();
        let out = tmp.path().join("pack");
        AgentCredentialPack::render(&issuer, &manifest, "desktop", 1, &out).unwrap();
        // Flip the declared kind: the identity set must fail role binding.
        let pack_toml = out.join("pack.toml");
        let text = std::fs::read_to_string(&pack_toml).unwrap();
        std::fs::write(
            &pack_toml,
            text.replace("kind = \"agent\"", "kind = \"ingress\""),
        )
        .unwrap();
        write_digests(&out).unwrap();
        assert!(CredentialPack::load(&out).is_err());
    }

    /// M2 acceptance: a workspace-A ingress credential must not verify
    /// against workspace B's trust anchors (chain anchoring provides the
    /// workspace isolation; the runtime derives workspace membership from
    /// exactly this verification).
    #[test]
    fn workspace_isolation_is_enforced_by_trust_anchoring() {
        use tokio_rustls::rustls::pki_types::UnixTime;
        use tokio_rustls::rustls::server::WebPkiClientVerifier;

        let _ = tokio_rustls::rustls::crypto::aws_lc_rs::default_provider().install_default();
        let tmp = tempfile::tempdir().unwrap();
        let issuer = IssuerStore::open(tmp.path().join("issuer"));
        issuer.ensure_realm().unwrap();
        issuer.ensure_workspace("main").unwrap();
        issuer.ensure_workspace("billing").unwrap();
        issuer.ensure_policy_key().unwrap();
        let manifest = Manifest::parse(&manifest_text()).unwrap();

        let ingress_dir = tmp.path().join("ingress");
        IngressCredentialPack::render(&issuer, &manifest, "edge", 1, &ingress_dir).unwrap();
        let pack = CredentialPack::load(&ingress_dir).unwrap();
        let principal = pack.ingress_identities().unwrap()["main"].clone();

        // main's issuer verifies the principal...
        let main_ca =
            std::fs::read_to_string(ingress_dir.join("trust/workspace-main.crt")).unwrap();
        let main_certs = crate::pem_certs(main_ca.as_bytes()).unwrap();
        let mut main_roots = tokio_rustls::rustls::RootCertStore::empty();
        for c in &main_certs {
            main_roots.add(c.clone().into()).unwrap();
        }
        let main_verifier = WebPkiClientVerifier::builder(main_roots.into())
            .build()
            .unwrap();
        let leaf = crate::pem_certs(principal.cert_pem.as_bytes())
            .unwrap()
            .remove(0);
        let leaf: tokio_rustls::rustls::pki_types::CertificateDer<'static> = leaf.into();
        main_verifier
            .verify_client_cert(&leaf, &[], UnixTime::now())
            .unwrap();

        // ...billing's issuer does NOT.
        let manifest_two =
            Manifest::parse(&format!("{}[workspace.billing]\n", manifest_text())).unwrap();
        let _ = &manifest_two;
        let billing_ca = issuer
            .workspace_issuer("billing")
            .unwrap()
            .cert_pem()
            .to_owned();
        let billing_certs = crate::pem_certs(billing_ca.as_bytes()).unwrap();
        let mut billing_roots = tokio_rustls::rustls::RootCertStore::empty();
        for c in &billing_certs {
            billing_roots.add(c.clone().into()).unwrap();
        }
        let billing_verifier = WebPkiClientVerifier::builder(billing_roots.into())
            .build()
            .unwrap();
        assert!(
            billing_verifier
                .verify_client_cert(&leaf, &[], UnixTime::now())
                .is_err(),
            "workspace-A ingress credential must not verify against workspace B anchors"
        );
    }

    #[test]
    fn sealed_pack_round_trip() {
        let tmp = tempfile::tempdir().unwrap();
        let issuer = IssuerStore::open(tmp.path().join("issuer"));
        issuer.ensure_realm().unwrap();
        issuer.ensure_workspace("main").unwrap();
        issuer.ensure_policy_key().unwrap();
        let manifest = Manifest::parse(&manifest_text()).unwrap();
        let out = tmp.path().join("pack");
        AgentCredentialPack::render(&issuer, &manifest, "desktop", 1, &out).unwrap();
        std::fs::create_dir_all(out.join("state/acme")).unwrap();
        std::fs::write(out.join("state/acme/runtime.txt"), b"node-local").unwrap();
        let sealed = tmp.path().join("agent.iflowpack");
        seal(
            &out,
            &sealed,
            &SealKey::Passphrase("correct horse".to_owned()),
        )
        .unwrap();
        let installed = tmp.path().join("installed");
        let pack = install(&sealed, &installed, "correct horse").unwrap();
        assert_eq!(pack.metadata.node, "desktop");
        assert!(!installed.join("state/acme/runtime.txt").exists());
        assert!(install(&sealed, &tmp.path().join("nope"), "wrong").is_err());
    }

    /// A cross-workspace site-to-site manifest: lan-a (workspace `alpha`)
    /// forwards into lan-b (workspace `beta`).
    fn mesh_manifest_text() -> String {
        r#"
[realm]
id = "promptcn"
[identity]
leaf_ttl = "24h"
[registrar]
endpoint = "https://registrar.example.com"
[mesh.hub.central]
listen = "0.0.0.0:6666"
endpoint = "hub.example.com:6666"
[workspace.alpha]
[workspace.beta]
[agent.lan-a]
workspace = "alpha"
[[agent.lan-a.mesh_ingress]]
name = "svc"
listen = "127.0.0.1:3001"
target_agent = "lan-b"
remote_addr = "127.0.0.1:3000"
[agent.lan-b]
workspace = "beta"
[[agent.lan-b.mesh_egress]]
name = "svc"
target_addr = "127.0.0.1:3000"
"#
        .to_owned()
    }

    fn mesh_issuer(tmp: &tempfile::TempDir) -> IssuerStore {
        let issuer = IssuerStore::open(tmp.path().join("issuer"));
        issuer.ensure_realm().unwrap();
        issuer.ensure_workspace("alpha").unwrap();
        issuer.ensure_workspace("beta").unwrap();
        issuer.ensure_policy_key().unwrap();
        issuer
    }

    #[test]
    fn hub_pack_renders_loads_and_is_role_bound() {
        let tmp = tempfile::tempdir().unwrap();
        let issuer = mesh_issuer(&tmp);
        let manifest = Manifest::parse(&mesh_manifest_text()).unwrap();

        let out = tmp.path().join("packs/hub-central");
        let issued = HubCredentialPack::render(&issuer, &manifest, "central", 1, &out).unwrap();
        assert_eq!(issued.metadata.kind, PackKind::Hub);
        assert_eq!(issued.metadata.control_endpoint, "hub.example.com:6666");
        assert!(issued.metadata.workspace.is_none());

        let pack = CredentialPack::load(&out).unwrap();
        assert_eq!(
            pack.primary_identity().unwrap().principal.to_string(),
            "spiffe://promptcn/control/central"
        );
        // The renewal-authorizing hub client principal rides along.
        let hub_entry = &pack.identities["hub"]["promptcn"];
        assert_eq!(
            hub_entry.principal.to_string(),
            "spiffe://promptcn/hub/central"
        );
        // The trust table covers every workspace with mesh agents.
        let mut anchors: Vec<&str> = pack
            .trust
            .metadata
            .issuers
            .keys()
            .map(String::as_str)
            .collect();
        anchors.sort();
        assert_eq!(
            anchors,
            vec!["control", "workspace/alpha", "workspace/beta"]
        );
        // The listen address is node config, the mesh streams are signed.
        assert_eq!(pack.node_config.listen.as_deref(), Some("0.0.0.0:6666"));
        assert_eq!(pack.policy.mesh.len(), 1);

        // Role-bound: a hub pack cannot start as an agent or ingress.
        assert!(pack.ingress_identities().is_err());
        let pack_toml = out.join("pack.toml");
        let text = std::fs::read_to_string(&pack_toml).unwrap();
        for kind in ["agent", "ingress"] {
            std::fs::write(
                &pack_toml,
                text.replace("kind = \"hub\"", &format!("kind = \"{kind}\"")),
            )
            .unwrap();
            write_digests(&out).unwrap();
            assert!(
                CredentialPack::load(&out).is_err(),
                "hub pack must not start as {kind}"
            );
        }
    }

    #[test]
    fn mesh_agent_pack_carries_rules_and_cross_workspace_trust() {
        let tmp = tempfile::tempdir().unwrap();
        let issuer = mesh_issuer(&tmp);
        let manifest = Manifest::parse(&mesh_manifest_text()).unwrap();

        let out = tmp.path().join("packs/agent-lan-a");
        AgentCredentialPack::render(&issuer, &manifest, "lan-a", 1, &out).unwrap();
        let pack = CredentialPack::load(&out).unwrap();
        assert_eq!(
            pack.primary_identity().unwrap().principal.to_string(),
            "spiffe://promptcn/alpha/agent/lan-a"
        );
        // node.toml carries node-local dial info only — the rules ride the
        // signed policy.
        let mesh = pack.node_config.mesh.as_ref().expect("mesh role");
        assert_eq!(mesh.hub_endpoint, "hub.example.com:6666");
        assert!(mesh.ingress.is_empty() && mesh.egress.is_empty());
        let stream = &pack.policy.mesh[0];
        assert_eq!(stream.source_agent, "lan-a");
        assert_eq!(stream.target_agent, "lan-b");
        assert_eq!(stream.listen, "127.0.0.1:3001");
        assert_eq!(stream.name, "svc");
        // The agent dials the hub, not an expose control endpoint.
        assert_eq!(pack.metadata.control_endpoint, "hub.example.com:6666");
        // Cross-workspace peer anchors ride in the trust bundle.
        assert!(pack.trust.issuers.contains_key("workspace/alpha"));
        assert!(pack.trust.issuers.contains_key("workspace/beta"));

        // The egress side needs the source's anchor for inner peer
        // verification — mutual inner TLS. Its offer lives in the signed
        // policy's egress face.
        let out_b = tmp.path().join("packs/agent-lan-b");
        AgentCredentialPack::render(&issuer, &manifest, "lan-b", 1, &out_b).unwrap();
        let pack_b = CredentialPack::load(&out_b).unwrap();
        let offer = &pack_b.policy.mesh_egress[0];
        assert_eq!(offer.agent, "lan-b");
        assert_eq!(offer.target_addr.as_deref(), Some("127.0.0.1:3000"));
        assert!(pack_b.trust.issuers.contains_key("workspace/alpha"));

        // Expose manifests (no mesh face) render packs without the mesh
        // field.
        let expose_out = tmp.path().join("packs/agent-desktop");
        issuer.ensure_workspace("main").unwrap();
        let expose_manifest = Manifest::parse(&manifest_text()).unwrap();
        AgentCredentialPack::render(&issuer, &expose_manifest, "desktop", 1, &expose_out).unwrap();
        let expose_pack = CredentialPack::load(&expose_out).unwrap();
        assert!(expose_pack.node_config.mesh.is_none());
        assert!(expose_pack.policy.mesh.is_empty());
    }

    /// Renders a signed policy update into `state/policy` — the node-local
    /// update channel.
    fn write_policy_update(
        issuer: &IssuerStore,
        out: &std::path::Path,
        policy: &crate::policy::RuntimePolicy,
    ) {
        let signer = issuer.policy_signer().unwrap();
        let (bytes, signature) = policy.signed(&signer).unwrap();
        let dir = out.join("state/policy");
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("policy.toml"), &bytes).unwrap();
        std::fs::write(dir.join("policy.sig"), &signature).unwrap();
    }

    fn update_policy_face(generation: u64, remote_port: u16) -> crate::policy::RuntimePolicy {
        use crate::policy::*;
        RuntimePolicy {
            generation,
            routes: vec![],
            services: vec![],
            ingress_authorizations: vec![],
            mesh: vec![PolicyMeshStream {
                source_workspace: "alpha".to_owned(),
                source_agent: "lan-a".to_owned(),
                target_workspace: "beta".to_owned(),
                target_agent: "lan-b".to_owned(),
                name: "svc".to_owned(),
                listen: "127.0.0.1:3001".to_owned(),
                remote_addr: format!("127.0.0.1:{remote_port}"),
                protocol: crate::manifest::MeshProtocol::Tcp,
                idle_timeout_secs: None,
            }],
            mesh_egress: vec![PolicyMeshEgress {
                workspace: "beta".to_owned(),
                agent: "lan-b".to_owned(),
                name: "svc".to_owned(),
                protocol: crate::manifest::MeshProtocol::Tcp,
                target_addr: Some(format!("127.0.0.1:{remote_port}")),
                target_cidr: None,
                udp_idle_timeout_secs: None,
            }],
        }
    }

    /// A newer signed bundle in `state/policy` supersedes the embedded
    /// snapshot at load — the policy evolves without re-signing any identity.
    #[test]
    fn state_policy_update_supersedes_embedded_snapshot() {
        let tmp = tempfile::tempdir().unwrap();
        let issuer = mesh_issuer(&tmp);
        let manifest = Manifest::parse(&mesh_manifest_text()).unwrap();
        let out = tmp.path().join("packs/agent-lan-a");
        AgentCredentialPack::render(&issuer, &manifest, "lan-a", 1, &out).unwrap();
        let embedded = CredentialPack::load_runtime(&out).unwrap();
        assert_eq!(embedded.policy.generation, 1);
        assert_eq!(embedded.policy.mesh[0].remote_addr, "127.0.0.1:3000");

        write_policy_update(&issuer, &out, &update_policy_face(2, 9443));
        let updated = CredentialPack::load_runtime(&out).unwrap();
        assert_eq!(updated.policy.generation, 2);
        assert_eq!(updated.policy.mesh[0].remote_addr, "127.0.0.1:9443");
        // The running node's watcher API accepts it against the embedded
        // floor and rejects a replay afterwards.
        assert!(updated.policy_update(1).unwrap().is_some());
    }

    /// Rollback and tampering are rejected by category — the embedded
    /// snapshot keeps serving (fail-keep), and the watcher-facing API names
    /// the failure.
    #[test]
    fn state_policy_rollback_and_tamper_are_rejected_fail_keep() {
        let tmp = tempfile::tempdir().unwrap();
        let issuer = mesh_issuer(&tmp);
        let manifest = Manifest::parse(&mesh_manifest_text()).unwrap();
        let out = tmp.path().join("packs/agent-lan-a");
        AgentCredentialPack::render(&issuer, &manifest, "lan-a", 3, &out).unwrap();

        // A bundle older than the embedded generation.
        write_policy_update(&issuer, &out, &update_policy_face(2, 9443));
        let pack = CredentialPack::load_runtime(&out).unwrap();
        assert_eq!(
            pack.policy.generation, 3,
            "a rolled-back update must not supersede the embedded snapshot"
        );
        let err = pack.policy_update(3).unwrap_err().to_string();
        assert!(err.contains("rollback"), "category must be named: {err}");

        // A tampered signature (bytes edited after signing).
        write_policy_update(&issuer, &out, &update_policy_face(9, 9443));
        let dir = out.join("state/policy");
        let bytes = std::fs::read(dir.join("policy.toml")).unwrap();
        let mut tampered = bytes.clone();
        tampered[0] ^= 0xff;
        std::fs::write(dir.join("policy.toml"), tampered).unwrap();
        let pack = CredentialPack::load_runtime(&out).unwrap();
        assert_eq!(pack.policy.generation, 3);
        let err = pack.policy_update(3).unwrap_err().to_string();
        assert!(
            err.contains("signature") || err.contains("parse"),
            "category must be named: {err}"
        );
    }

    /// Packs from before the policy-identity separation (rules in
    /// node.toml) fail with the migration instruction, not a bare parse
    /// error.
    #[test]
    fn pre_separation_pack_is_rejected_with_migration_hint() {
        let tmp = tempfile::tempdir().unwrap();
        let issuer = mesh_issuer(&tmp);
        let manifest = Manifest::parse(&mesh_manifest_text()).unwrap();
        let out = tmp.path().join("packs/agent-lan-a");
        AgentCredentialPack::render(&issuer, &manifest, "lan-a", 1, &out).unwrap();

        // Rewrite node.toml in the pre-separation shape (rules inline) and
        // re-fold the digest manifest so only the layout differs.
        let rendered = std::fs::read_to_string(out.join("node.toml")).unwrap();
        let legacy = format!(
            "{rendered}\n[[mesh.ingress]]\nname = \"svc\"\nlisten = \"127.0.0.1:3001\"\n\
             target_agent = \"lan-b\"\nremote_addr = \"127.0.0.1:3000\"\n"
        );
        std::fs::write(out.join("node.toml"), legacy).unwrap();
        write_digests(&out).unwrap();

        let err = CredentialPack::load_runtime(&out).unwrap_err().to_string();
        assert!(
            err.contains("predates the signed-policy rule face"),
            "migration hint must be present: {err}"
        );
    }

    #[test]
    fn acme_public_443_enables_control_dispatch() {
        let tmp = tempfile::tempdir().unwrap();
        let issuer = IssuerStore::open(tmp.path().join("issuer"));
        issuer.ensure_realm().unwrap();
        issuer.ensure_workspace("main").unwrap();
        issuer.ensure_policy_key().unwrap();
        // The fixture defaults to ACME + 0.0.0.0:443 → the control endpoint's
        // DNS host rides the public port.
        let manifest = Manifest::parse(&manifest_text()).unwrap();
        let out = tmp.path().join("packs/ingress-edge");
        IngressCredentialPack::render(&issuer, &manifest, "edge", 1, &out).unwrap();
        let node_toml = std::fs::read_to_string(out.join("node.toml")).unwrap();
        assert!(
            node_toml.contains("control_dispatch_host = \"relay.example.com\""),
            "acme 443 ingress carries the dispatch host: {node_toml}"
        );

        // Fronted topology: no in-process dispatch (the front proxy's stream
        // map owns it), and the field stays out of node.toml entirely.
        let fronted_text = manifest_text().replacen(
            "[ingress.edge]",
            "[public_tls]\nmode = \"frontend-proxy\"\n\n[ingress.edge]",
            1,
        );
        let fronted = Manifest::parse(&fronted_text).unwrap();
        let out2 = tmp.path().join("packs/ingress-edge-fronted");
        IngressCredentialPack::render(&issuer, &fronted, "edge", 1, &out2).unwrap();
        let node_toml2 = std::fs::read_to_string(out2.join("node.toml")).unwrap();
        assert!(
            !node_toml2.contains("control_dispatch_host"),
            "fronted ingress does not dispatch in-process: {node_toml2}"
        );
    }

    /// `[ingress.<node>.edge]` overrides ride the manifest → node.toml leg:
    /// absent overrides render no section (old packs unchanged, engine
    /// topology defaults apply); explicit ones land verbatim and survive the
    /// digest-verified load.
    #[test]
    fn ingress_edge_overrides_render_into_node_toml() {
        let tmp = tempfile::tempdir().unwrap();
        let issuer = IssuerStore::open(tmp.path().join("issuer"));
        issuer.ensure_realm().unwrap();
        issuer.ensure_workspace("main").unwrap();
        issuer.ensure_policy_key().unwrap();

        let manifest = Manifest::parse(&manifest_text()).unwrap();
        let out = tmp.path().join("packs/ingress-edge");
        IngressCredentialPack::render(&issuer, &manifest, "edge", 1, &out).unwrap();
        let node_toml = std::fs::read_to_string(out.join("node.toml")).unwrap();
        assert!(
            !node_toml.contains("[edge]"),
            "absent manifest overrides must not render an [edge] section: {node_toml}"
        );

        let tuned_text = manifest_text().replacen(
            "[workspace.main]",
            "[ingress.edge.edge]\nnew_conn_rate_per_ip_per_minute = 120\n\n[workspace.main]",
            1,
        );
        let tuned = Manifest::parse(&tuned_text).unwrap();
        let out2 = tmp.path().join("packs/ingress-edge-tuned");
        IngressCredentialPack::render(&issuer, &tuned, "edge", 1, &out2).unwrap();
        let pack = CredentialPack::load(&out2).unwrap();
        assert_eq!(
            pack.node_config
                .edge
                .as_ref()
                .and_then(|edge| edge.new_conn_rate_per_ip_per_minute),
            Some(120),
            "the [edge] override must survive the digest-verified load"
        );
        let node_toml2 = std::fs::read_to_string(out2.join("node.toml")).unwrap();
        assert!(
            node_toml2.contains("[edge]\nnew_conn_rate_per_ip_per_minute = 120"),
            "the override renders as a readable TOML section: {node_toml2}"
        );
    }

    /// node.toml's `[edge]` section is optional (old packs parse), carries
    /// its knob optionally, and stays strict against unknown fields like the
    /// rest of NodeConfig.
    #[test]
    fn node_edge_config_serde_is_optional_and_strict() {
        let base =
            "kind = \"ingress\"\nnode = \"edge\"\npublic_tls = \"frontend-proxy\"\nservices = []\n";
        let parsed: NodeConfig = toml::from_str(base).unwrap();
        assert!(
            parsed.edge.is_none(),
            "a node.toml without [edge] must parse"
        );

        // 0 = unlimited is a legitimate explicit override and must survive.
        let with_edge = format!("{base}\n[edge]\nnew_conn_rate_per_ip_per_minute = 0\n");
        let parsed: NodeConfig = toml::from_str(&with_edge).unwrap();
        assert_eq!(
            parsed.edge.unwrap().new_conn_rate_per_ip_per_minute,
            Some(0)
        );

        let empty_section = format!("{base}\n[edge]\n");
        let parsed: NodeConfig = toml::from_str(&empty_section).unwrap();
        assert_eq!(
            parsed.edge.unwrap(),
            NodeEdgeConfig {
                new_conn_rate_per_ip_per_minute: None
            },
            "a present-but-empty [edge] still means topology defaults"
        );

        let garbage = format!("{base}\n[edge]\nsurprise = 1\n");
        assert!(
            toml::from_str::<NodeConfig>(&garbage).is_err(),
            "unknown [edge] fields must be rejected (deny_unknown_fields)"
        );
    }
}
