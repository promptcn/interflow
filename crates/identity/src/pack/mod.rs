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
use crate::{Error, Result};
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

/// Canonical optional-string serde for the pack's machine formats: the key
/// is **always written** (`None` renders as `""`) and **always required**
/// (a missing key is a pre-canonical pack — fail closed with a re-render
/// error, never a silent default). One byte-form per state: there is no
/// "absent ≡ engine default" ambiguity left.
mod canonical_opt_string {
    pub fn serialize<S: serde::Serializer>(
        value: &Option<String>,
        serializer: S,
    ) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(value.as_deref().unwrap_or(""))
    }

    pub fn deserialize<'de, D: serde::Deserializer<'de>>(
        deserializer: D,
    ) -> Result<Option<String>, D::Error> {
        let raw: String = serde::Deserialize::deserialize(deserializer)?;
        Ok(if raw.is_empty() { None } else { Some(raw) })
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
    /// (`ingress_authorizations`) and carry one credential per workspace;
    /// they render `workspace = ""`.
    #[serde(with = "canonical_opt_string")]
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
    /// How this deployment's credentials live — written unconditionally
    /// (canonical form; renewal scheduling derives from this field, and pack
    /// readers never see the server-side choice).
    pub identity_mode: crate::manifest::IdentityMode,
    /// HTTPS registrar endpoint used for unattended renewal; `""` in offline
    /// deployments (rotate/revoke are manual).
    #[serde(with = "canonical_opt_string")]
    pub registrar_endpoint: Option<String>,
    /// Non-normative provenance stamp: which renderer build produced this
    /// pack (`interflow_buildinfo::VERSION_WITH_TAG`). Purely diagnostic —
    /// loaders never branch on it; the next format-breaking upgrade question
    /// ("which era is this pack?") becomes read-and-diff instead of content
    /// archaeology. Digest-covered like the rest of pack.toml.
    pub rendered_by: String,
}

/// Where a verifier finds the CRL for one issuer — **statically determined
/// by the deployment's identity tier**, never probed between sources.
///
/// Registrar packs read the node-local live-refresh directory `state/crls`
/// (the renewal scheduler populates it and restarts onto changes; its
/// absence merely means "not refreshed yet" — the tier's fail-loud for
/// unrevocable credentials is the scheduler's 1h staleness bound, not the
/// boot path). Offline packs read the apply/rotate-embedded snapshot in
/// `trust/crls`; a missing snapshot is a **render defect** (every offline
/// apply/rotate embeds one) and fails loud with the recovery action.
/// Either way a stray file in the other directory can never change the
/// CRL source. CRLs are signed by the issuer, so the snapshot needs no
/// extra integrity story.
/// ((internal design notes) §2;
/// earlier contract: (internal design notes) P1-1)
pub fn crl_path_for(
    pack_dir: &std::path::Path,
    mode: crate::manifest::IdentityMode,
    issuer_stem: &str,
) -> Result<Option<std::path::PathBuf>> {
    let file = format!("{issuer_stem}.crl.pem");
    match mode {
        crate::manifest::IdentityMode::Registrar => {
            let live = pack_dir.join("state").join("crls").join(&file);
            Ok(live.is_file().then_some(live))
        }
        crate::manifest::IdentityMode::Offline => {
            let embedded = pack_dir.join("trust").join("crls").join(&file);
            if embedded.is_file() {
                Ok(Some(embedded))
            } else {
                Err(Error::pack(format!(
                    "offline pack carries no embedded CRL snapshot for issuer {issuer_stem:?} \
                     in trust/crls — a render defect; re-apply or rotate the pack"
                )))
            }
        }
    }
}

/// `node.toml` — the node's runtime configuration rendered from the
/// manifest (listen addresses, public TLS mode, agent services).
///
/// Canonical form: every scalar key is always written ("" = no value / face
/// off — same rule the agent packs' `public_tls = ""` already followed), so
/// one byte-form expresses each state. The two structural sections (`mesh`,
/// `edge`) are the deliberate exception: a table cannot carry a null, and
/// their **presence** is role structure (a non-mesh agent has no mesh face),
/// not a default choice — when present, their contents are canonical and
/// complete.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NodeConfig {
    pub kind: PackKind,
    pub node: String,
    /// The node's listener address ("" on kinds that never listen).
    #[serde(with = "canonical_opt_string")]
    pub listen: Option<String>,
    /// Control-plane listener address ("" where not served).
    #[serde(with = "canonical_opt_string")]
    pub control_listen: Option<String>,
    /// The node's QUIC (UDP) listen address, rendered from the manifest's
    /// `quic_listen` — the control endpoint's face on ingress packs
    /// (`[ingress.<node>]`), the hub's face on hub packs
    /// (`[mesh.hub.<name>]`). `""` keeps the QUIC transport off; a concrete
    /// address is already validation-checked (non-loopback, concrete port)
    /// and parsed into the engine config at boot.
    #[serde(with = "canonical_opt_string")]
    pub quic_listen: Option<String>,
    /// Single-public-port mode (ACME topologies): connections with this
    /// SNI on the public listener are dispatched to the control plane, so
    /// the deployment needs only 443. `""` on fronted topologies (the front
    /// proxy's stream map owns that dispatch) and whenever the control
    /// endpoint keeps its own port.
    #[serde(with = "canonical_opt_string")]
    pub control_dispatch_host: Option<String>,
    pub public_tls: String,
    /// ACME account contact email ("" when the manifest sets none).
    #[serde(with = "canonical_opt_string")]
    pub public_tls_email: Option<String>,
    /// ACME directory URL — the renderer resolves the unset manifest value
    /// to the concrete Let's Encrypt production URL, so the pack always
    /// names the directory it will dial.
    pub public_tls_directory: String,
    /// Agent services: the manifest-issued **default** dial targets (a
    /// machine-local preference may override each one at run time; the
    /// signed policy carries the ids only).
    pub services: Vec<NodeService>,
    /// The manifest-issued **default** dial transport for an agent pack
    /// (`"h2"` / `"quic"`, resolved at render time — unset becomes `"h2"`;
    /// `""` on kinds that do not dial). A machine-local preference
    /// overrides it at run time; headless nodes dial exactly this.
    pub transport: String,
    /// Site-to-site runtime rules — present on mesh-role agent packs (the
    /// hub dial target plus this agent's local rules). Absent on expose
    /// packs (structural: this pack has no mesh face).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mesh: Option<NodeMeshConfig>,
    /// Ingress public-listener governance, **fully resolved at render time**
    /// (manifest overrides over the deployment topology's defaults).
    /// Present on every ingress pack; absent on kinds with no public
    /// listener (structural).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub edge: Option<NodeEdgeConfig>,
}

/// Ingress `[edge]` section in canonical `node.toml`: the public-listener
/// governance this deployment pins, with every knob concrete — the renderer
/// resolves topology defaults when the manifest leaves a field unset, so
/// "absent ≡ engine default" and "explicit default value" collapse into one
/// form. (The manifest side keeps its own partial-tolerant
/// [`crate::manifest::EdgeOverrides`] for human authoring.)
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NodeEdgeConfig {
    /// Per-IP new-connection limit per minute on the public listener
    /// (0 = unlimited). Fronted topologies default to 600 (a front proxy
    /// opens one new connection per proxied request, so its budget must
    /// scale with request rate, not browser behavior); direct ones to 30.
    pub new_conn_rate_per_ip_per_minute: u32,
    /// Public-listener `X-Forwarded-For` mode: `"off"` / `"on"` /
    /// `"required"` (fronted defaults to `required` — nothing but the front
    /// may talk to the listener; direct defaults to `off`).
    pub x_forwarded_for: String,
    /// Control-listener PROXY protocol mode: `"on"` / `"off"` (fronted
    /// defaults to `on` — the front's SNI map emits the preamble on every
    /// target including the mTLS-passthrough control leg; direct defaults to
    /// `off`). Loopback trust stays engine-fixed.
    pub control_proxy_protocol: String,
    /// ACME HTTP-01 challenge listener (`host:port`); the renderer pins the
    /// `0.0.0.0:80` default the ACME protocol practically requires
    /// (port-80 reachability), an explicit value moves the challenge
    /// listener behind a forward or onto another interface.
    pub acme_http_listen: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NodeMeshConfig {
    /// The mesh hub this agent dials (`https://host:port`). The site-to-site
    /// rules themselves live in the signed policy (`policy/policy.toml`) —
    /// node-local dial info is all `node.toml` carries for the mesh face.
    /// (Pre-separation packs that carry inline `ingress`/`egress` rules here
    /// fail the `deny_unknown_fields` parse; re-render them with
    /// `plan apply`.)
    pub hub_endpoint: String,
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
    /// Whether the live policy came from the node-local update channel
    /// (`state/policy`) rather than the pack's embedded snapshot — the
    /// provenance face for "which distribution channel this node is
    /// actually running" (an update accepted from the hub lands there too).
    pub policy_from_state_channel: bool,
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

        // Canonical form (2026-10-10): pack.toml names the tier and the
        // renderer build even on the registrar default, and every scalar
        // key is written — "" where the value does not apply.
        let pack_toml = std::fs::read_to_string(ingress_out.join("pack.toml")).unwrap();
        assert!(
            pack_toml.contains("identity_mode = \"registrar\""),
            "the tier is always written: {pack_toml}"
        );
        assert!(
            pack_toml.contains(&format!(
                "rendered_by = \"{}\"",
                interflow_buildinfo::VERSION_WITH_TAG
            )),
            "the renderer build tag is always written: {pack_toml}"
        );
        assert!(
            pack_toml.contains("workspace = \"\""),
            "ingress packs carry no single workspace: {pack_toml}"
        );
        let node_toml = std::fs::read_to_string(ingress_out.join("node.toml")).unwrap();
        assert!(
            node_toml.contains("quic_listen = \"\""),
            "an off QUIC face is an explicit empty value: {node_toml}"
        );
        assert!(
            node_toml.contains(
                "public_tls_directory = \"https://acme-v02.api.letsencrypt.org/directory\""
            ),
            "the unset ACME directory resolves to the concrete production URL: {node_toml}"
        );
        let edge = pack
            .node_config
            .edge
            .as_ref()
            .expect("ingress edge section");
        assert_eq!(edge.new_conn_rate_per_ip_per_minute, 30);
        assert_eq!(edge.x_forwarded_for, "off");
        assert_eq!(edge.control_proxy_protocol, "off");
        assert_eq!(edge.acme_http_listen, "0.0.0.0:80");

        let agent_out = tmp.path().join("packs/agent-desktop");
        AgentCredentialPack::render(&issuer, &manifest, "desktop", 1, &agent_out).unwrap();
        let agent_pack = CredentialPack::load(&agent_out).unwrap();
        assert_eq!(
            agent_pack.primary_identity().unwrap().principal.to_string(),
            "spiffe://promptcn/main/agent/desktop"
        );
        assert_eq!(
            agent_pack.node_config.transport, "h2",
            "an unset manifest transport resolves to the explicit h2 default"
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
        let node_toml = std::fs::read_to_string(out.join("node.toml")).unwrap();
        assert!(
            !node_toml.contains("[[mesh."),
            "no rule tables ride node.toml: {node_toml}"
        );
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

    /// Packs from before the policy-identity separation (inline rules in
    /// node.toml) are rejected by the `deny_unknown_fields` parse — the
    /// unknown field is named, and the pack must be re-rendered.
    #[test]
    fn pre_separation_pack_is_rejected() {
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

        let err = CredentialPack::load_runtime(&out).unwrap_err();
        // The field name rides the error's source chain (serde detail).
        let mut msg = err.to_string();
        let mut source = std::error::Error::source(&err);
        while let Some(e) = source {
            msg.push('\n');
            msg.push_str(&e.to_string());
            source = e.source();
        }
        assert!(
            msg.contains("unknown field") && msg.contains("ingress"),
            "the offending field must be named: {msg}"
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
        // map owns it) — canonical form still writes the key, as an explicit
        // empty value.
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
            node_toml2.contains("control_dispatch_host = \"\""),
            "fronted ingress does not dispatch in-process: {node_toml2}"
        );
    }

    /// `[ingress.<node>.edge]` overrides ride the manifest → node.toml leg:
    /// absent overrides still render a **complete** section (the topology's
    /// defaults, resolved at render time — the fixture is ACME/direct);
    /// explicit ones land verbatim and survive the digest-verified load.
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
            node_toml.contains("[edge]\n"),
            "every ingress pack carries an [edge] section: {node_toml}"
        );
        for (key, direct_default) in [
            ("new_conn_rate_per_ip_per_minute", "30"),
            ("x_forwarded_for", "\"off\""),
            ("control_proxy_protocol", "\"off\""),
            ("acme_http_listen", "\"0.0.0.0:80\""),
        ] {
            assert!(
                node_toml.contains(&format!("{key} = {direct_default}")),
                "unset {key} resolves to the direct-topology default: {node_toml}"
            );
        }

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
                .expect("canonical edge section")
                .new_conn_rate_per_ip_per_minute,
            120,
            "the [edge] override must survive the digest-verified load"
        );
        let node_toml2 = std::fs::read_to_string(out2.join("node.toml")).unwrap();
        assert!(
            node_toml2.contains("[edge]\nnew_conn_rate_per_ip_per_minute = 120"),
            "the override renders as a readable TOML section: {node_toml2}"
        );
    }

    /// node.toml's `[edge]` section is canonical (all four knobs concrete and
    /// required) and strict (unknown fields rejected, missing fields
    /// rejected — a pre-canonical pack fails closed with a re-render error,
    /// never a silent engine default).
    #[test]
    fn node_edge_config_serde_is_canonical_and_strict() {
        let scalars = "kind = \"ingress\"\nnode = \"edge\"\nlisten = \"0.0.0.0:443\"\n\
                       control_listen = \"127.0.0.1:16666\"\nquic_listen = \"\"\n\
                       control_dispatch_host = \"\"\npublic_tls = \"frontend-proxy\"\n\
                       public_tls_email = \"\"\npublic_tls_directory = \"\"\nservices = []\n\
                       transport = \"\"\n";
        let edge = "[edge]\nnew_conn_rate_per_ip_per_minute = 30\n\
                    x_forwarded_for = \"required\"\ncontrol_proxy_protocol = \"on\"\n\
                    acme_http_listen = \"0.0.0.0:80\"\n";
        let full = format!("{scalars}{edge}");
        let parsed: NodeConfig = toml::from_str(&full).unwrap();
        let parsed_edge = parsed.edge.expect("present [edge]");
        assert_eq!(parsed_edge.new_conn_rate_per_ip_per_minute, 30);
        assert_eq!(parsed_edge.x_forwarded_for, "required");
        assert_eq!(parsed_edge.control_proxy_protocol, "on");
        assert_eq!(parsed_edge.acme_http_listen, "0.0.0.0:80");
        assert!(
            parsed.quic_listen.is_none() && parsed.transport.is_empty(),
            "the explicit empty value reads back as off / no-dial-face"
        );

        // Every canonical scalar key is required: dropping one is a
        // pre-canonical pack, not a silent default.
        for key in ["quic_listen", "transport", "public_tls_directory"] {
            let stripped = full
                .lines()
                .filter(|line| !line.starts_with(key))
                .collect::<Vec<_>>()
                .join("\n");
            let err = toml::from_str::<NodeConfig>(&stripped).unwrap_err();
            assert!(
                err.to_string().contains("missing field"),
                "dropping {key} must fail closed (missing field), got: {err}"
            );
        }

        // Every [edge] knob is required: a partial section is a render
        // defect, not "absent ≡ topology default".
        let partial = format!("{scalars}[edge]\nnew_conn_rate_per_ip_per_minute = 0\n");
        let err = toml::from_str::<NodeConfig>(&partial).unwrap_err();
        assert!(
            err.to_string().contains("missing field"),
            "a partial [edge] section must fail closed, got: {err}"
        );
        // 0 = unlimited is a legitimate explicit override and survives.
        let unlimited = full.replace(
            "new_conn_rate_per_ip_per_minute = 30",
            "new_conn_rate_per_ip_per_minute = 0",
        );
        let parsed: NodeConfig = toml::from_str(&unlimited).unwrap();
        assert_eq!(
            parsed.edge.unwrap().new_conn_rate_per_ip_per_minute,
            0,
            "0 (unlimited) must survive the round trip"
        );

        let garbage = format!("{scalars}[edge]\nsurprise = 1\n");
        assert!(
            toml::from_str::<NodeConfig>(&garbage).is_err(),
            "unknown [edge] fields must be rejected (deny_unknown_fields)"
        );
    }

    /// The canonical optional-string helper: one byte-form per state — `None`
    /// renders as "" and parses back to `None`; a missing key is an error.
    #[test]
    fn canonical_opt_string_has_one_byte_form() {
        #[derive(serde::Serialize, serde::Deserialize, PartialEq, Eq, Debug)]
        struct Holder {
            #[serde(with = "super::canonical_opt_string")]
            value: Option<String>,
        }
        let none = toml::to_string(&Holder { value: None }).unwrap();
        assert!(
            none.contains("value = \"\""),
            "None renders as the explicit empty string: {none}"
        );
        let round: Holder = toml::from_str(&none).unwrap();
        assert_eq!(round.value, None);

        let some = toml::to_string(&Holder {
            value: Some("0.0.0.0:16666".to_owned()),
        })
        .unwrap();
        assert!(some.contains("value = \"0.0.0.0:16666\""));
        let round: Holder = toml::from_str(&some).unwrap();
        assert_eq!(round.value.as_deref(), Some("0.0.0.0:16666"));

        assert!(
            toml::from_str::<Holder>("").is_err(),
            "a missing key must fail closed (pre-canonical byte shape)"
        );
    }

    /// The CRL source is statically pinned by the identity tier — never
    /// probed between directories. Registrar: the live `state/crls` only
    /// (absent = Ok(None), the scheduler's convergence). Offline: the
    /// embedded `trust/crls` only (absent = render defect, fail loud). A
    /// stray file in the other directory changes nothing.
    #[test]
    fn crl_path_is_pinned_by_identity_mode() {
        use crate::manifest::IdentityMode;
        let tmp = tempfile::tempdir().unwrap();
        let live = tmp.path().join("state/crls/control.crl.pem");
        let embedded = tmp.path().join("trust/crls/control.crl.pem");
        std::fs::create_dir_all(live.parent().unwrap()).unwrap();
        std::fs::create_dir_all(embedded.parent().unwrap()).unwrap();

        // Both present: each tier reads its own directory, no preference
        // probing between them.
        std::fs::write(&live, "live").unwrap();
        std::fs::write(&embedded, "embedded").unwrap();
        assert_eq!(
            crl_path_for(tmp.path(), IdentityMode::Registrar, "control").unwrap(),
            Some(live.clone())
        );
        assert_eq!(
            crl_path_for(tmp.path(), IdentityMode::Offline, "control").unwrap(),
            Some(embedded.clone())
        );

        // Registrar with no live file yet (fresh install before the first
        // scheduler refresh): absence is a lifecycle fact, not an error —
        // and the embedded snapshot must NOT be silently consulted.
        std::fs::remove_file(&live).unwrap();
        assert_eq!(
            crl_path_for(tmp.path(), IdentityMode::Registrar, "control").unwrap(),
            None
        );

        // Offline with no embedded snapshot: render defect, fail loud with
        // the recovery action.
        std::fs::remove_file(&embedded).unwrap();
        let err = crl_path_for(tmp.path(), IdentityMode::Offline, "control").unwrap_err();
        assert!(
            err.to_string().contains("render defect"),
            "wrong error: {err}"
        );
    }

    /// The QUIC face and the agent dial transport ride the manifest →
    /// node.toml leg: unset fields render their **explicit** canonical value
    /// (`quic_listen = ""` = off, `transport = "h2"` = the resolved default);
    /// explicit ones land verbatim and survive the digest-verified load.
    #[test]
    fn quic_fields_render_into_node_toml() {
        let tmp = tempfile::tempdir().unwrap();
        let issuer = IssuerStore::open(tmp.path().join("issuer"));
        issuer.ensure_realm().unwrap();
        issuer.ensure_workspace("main").unwrap();
        issuer.ensure_policy_key().unwrap();

        // Unset: both keys are still written — an off QUIC face and the
        // resolved h2 default are explicit values, not absent keys.
        let manifest = Manifest::parse(&manifest_text()).unwrap();
        let out = tmp.path().join("packs/ingress-edge");
        IngressCredentialPack::render(&issuer, &manifest, "edge", 1, &out).unwrap();
        let node_toml = std::fs::read_to_string(out.join("node.toml")).unwrap();
        assert!(
            node_toml.contains("quic_listen = \"\""),
            "an unset quic_listen renders as the explicit empty value: {node_toml}"
        );
        let agent_out = tmp.path().join("packs/agent-desktop");
        AgentCredentialPack::render(&issuer, &manifest, "desktop", 1, &agent_out).unwrap();
        let agent_toml = std::fs::read_to_string(agent_out.join("node.toml")).unwrap();
        assert!(
            agent_toml.contains("transport = \"h2\""),
            "an unset transport resolves to the explicit h2: {agent_toml}"
        );

        // Explicit: the fixture's control endpoint carries an explicit
        // port, so the quic cross-check is satisfiable.
        let tuned_text = manifest_text()
            .replacen(
                "[ingress.edge]\nworkspaces = [\"main\"]",
                "[ingress.edge]\nworkspaces = [\"main\"]\nquic_listen = \"0.0.0.0:16666\"",
                1,
            )
            .replacen(
                "[agent.desktop]\nworkspace = \"main\"",
                "[agent.desktop]\nworkspace = \"main\"\ntransport = \"quic\"",
                1,
            );
        let tuned = Manifest::parse(&tuned_text).unwrap();
        let out2 = tmp.path().join("packs/ingress-edge-quic");
        IngressCredentialPack::render(&issuer, &tuned, "edge", 1, &out2).unwrap();
        let pack = CredentialPack::load(&out2).unwrap();
        assert_eq!(
            pack.node_config.quic_listen.as_deref(),
            Some("0.0.0.0:16666"),
            "quic_listen must survive the digest-verified load"
        );
        let node_toml2 = std::fs::read_to_string(out2.join("node.toml")).unwrap();
        assert!(
            node_toml2.contains("quic_listen = \"0.0.0.0:16666\""),
            "quic_listen renders as readable TOML: {node_toml2}"
        );

        let agent_out2 = tmp.path().join("packs/agent-desktop-quic");
        AgentCredentialPack::render(&issuer, &tuned, "desktop", 1, &agent_out2).unwrap();
        let agent_pack = CredentialPack::load(&agent_out2).unwrap();
        assert_eq!(
            agent_pack.node_config.transport, "quic",
            "the signed transport default must survive the digest-verified load"
        );
    }

    /// The mesh face rides the same manifest → node.toml leg as the expose
    /// face: the hub's `quic_listen` and a mesh agent's dial `transport`
    /// render their explicit canonical values when unset (`""` / `"h2"`)
    /// and land verbatim — surviving the digest-verified load — when set.
    #[test]
    fn mesh_quic_fields_render_into_node_toml() {
        let tmp = tempfile::tempdir().unwrap();
        let issuer = IssuerStore::open(tmp.path().join("issuer"));
        issuer.ensure_realm().unwrap();
        issuer.ensure_workspace("alpha").unwrap();
        issuer.ensure_workspace("beta").unwrap();
        issuer.ensure_policy_key().unwrap();

        // Unset: both keys are still written (canonical form).
        let manifest = Manifest::parse(&mesh_manifest_text()).unwrap();
        let hub_out = tmp.path().join("packs/hub-central");
        HubCredentialPack::render(&issuer, &manifest, "central", 1, &hub_out).unwrap();
        let node_toml = std::fs::read_to_string(hub_out.join("node.toml")).unwrap();
        assert!(
            node_toml.contains("quic_listen = \"\""),
            "an unset hub quic_listen renders as the explicit empty value: {node_toml}"
        );
        let agent_out = tmp.path().join("packs/agent-lan-a");
        AgentCredentialPack::render(&issuer, &manifest, "lan-a", 1, &agent_out).unwrap();
        let agent_toml = std::fs::read_to_string(agent_out.join("node.toml")).unwrap();
        assert!(
            agent_toml.contains("transport = \"h2\""),
            "an unset transport resolves to the explicit h2: {agent_toml}"
        );

        // Explicit: the hub endpoint carries an explicit port, so the quic
        // cross-check is satisfiable.
        let tuned = Manifest::parse(
            &mesh_manifest_text()
                .replacen(
                    "[mesh.hub.central]\nlisten",
                    "[mesh.hub.central]\nquic_listen = \"0.0.0.0:6666\"\nlisten",
                    1,
                )
                .replacen(
                    "[agent.lan-a]\nworkspace = \"alpha\"",
                    "[agent.lan-a]\nworkspace = \"alpha\"\ntransport = \"quic\"",
                    1,
                ),
        )
        .unwrap();
        let hub_out2 = tmp.path().join("packs/hub-central-quic");
        HubCredentialPack::render(&issuer, &tuned, "central", 1, &hub_out2).unwrap();
        let pack = CredentialPack::load(&hub_out2).unwrap();
        assert_eq!(
            pack.node_config.quic_listen.as_deref(),
            Some("0.0.0.0:6666"),
            "hub quic_listen must survive the digest-verified load"
        );
        let node_toml2 = std::fs::read_to_string(hub_out2.join("node.toml")).unwrap();
        assert!(
            node_toml2.contains("quic_listen = \"0.0.0.0:6666\""),
            "hub quic_listen renders as readable TOML: {node_toml2}"
        );

        let agent_out2 = tmp.path().join("packs/agent-lan-a-quic");
        AgentCredentialPack::render(&issuer, &tuned, "lan-a", 1, &agent_out2).unwrap();
        let agent_pack = CredentialPack::load(&agent_out2).unwrap();
        assert_eq!(
            agent_pack.node_config.transport, "quic",
            "the signed transport default must survive the digest-verified load"
        );
    }
}
