//! Pack rendering: manifest -> pack directory (plan apply / pack issue).
//!
//! One renderer per pack kind; the shared directory layout (`pack.toml`,
//! `node.toml`, `identity/`, `trust/`, `policy/`, `SHA256SUMS`) is assembled
//! by [`render_pack`].

use super::{IssuedPack, NodeConfig, NodeMeshConfig, NodeService, PackKind, PackMetadata};
use crate::issuance::{IdentityMaterial, IssuerStore};
use crate::policy::RuntimePolicy;
use crate::timestamp::{rfc3339, rfc3339_now};
use crate::trust::TrustBundle;
use crate::{Error, PrincipalKind, Result};
use interflow_contract::{FORMAT_VERSION, Generation};
use interflow_util::sha256_hex;
use std::collections::BTreeMap;
use std::path::Path;

// ---------------------------------------------------------------------------
// Rendering (plan apply / pack issue)
// ---------------------------------------------------------------------------

/// Renders the ingress pack: control-endpoint identity + one
/// workspace-scoped ingress principal per authorized workspace.
pub struct IngressCredentialPack;

impl IngressCredentialPack {
    pub fn render(
        store: &IssuerStore,
        manifest: &crate::manifest::Manifest,
        node: &str,
        generation: Generation,
        out: &Path,
    ) -> Result<IssuedPack> {
        let ingress_cfg = manifest.ingress.get(node).ok_or_else(|| {
            Error::pack(format!(
                "ingress node {node:?} is not declared in the manifest",
            ))
        })?;
        let ttl = manifest.effective_leaf_ttl()?;
        let control = store.issue_control_endpoint_with_ttl(
            &manifest.realm.id,
            node,
            &manifest.realm.control_endpoint,
            ttl,
        )?;

        let mut principals: BTreeMap<String, IdentityMaterial> = BTreeMap::new();
        principals.insert("control-endpoint".to_owned(), control);
        for workspace in &ingress_cfg.workspaces {
            let material = store.issue_workspace_member_with_ttl(
                &manifest.realm.id,
                workspace,
                PrincipalKind::Ingress,
                node,
                ttl,
            )?;
            principals.insert(format!("ingress/{workspace}"), material);
        }
        let expires = principals
            .values()
            .map(|m| m.not_after)
            .min()
            .ok_or_else(|| Error::pack("ingress pack carries no identities".to_owned()))?;
        // Single-public-port mode (P2): in ACME topologies where the ingress
        // itself terminates TLS on 443, the control endpoint's server name
        // rides the same port via ClientHello SNI dispatch. Fronted
        // topologies keep their own dispatch at the front proxy.
        let control_dispatch_host = match manifest.public_tls.mode {
            crate::manifest::PublicTlsMode::Acme
                if ingress_cfg
                    .listen
                    .rsplit_once(':')
                    .is_some_and(|(_, p)| p == "443") =>
            {
                dns_host(&manifest.realm.control_endpoint)
            }
            _ => None,
        };
        let node_config = NodeConfig {
            kind: PackKind::Ingress,
            node: node.to_owned(),
            listen: Some(ingress_cfg.listen.clone()),
            control_listen: Some(ingress_cfg.control_listen.clone()),
            control_dispatch_host,
            public_tls: match manifest.public_tls.mode {
                crate::manifest::PublicTlsMode::Acme => "acme".to_owned(),
                crate::manifest::PublicTlsMode::FrontendProxy => "frontend-proxy".to_owned(),
                crate::manifest::PublicTlsMode::Manual => "manual".to_owned(),
            },
            public_tls_email: manifest.public_tls.email.clone(),
            public_tls_directory: manifest.public_tls.directory.clone(),
            services: Vec::new(),
            mesh: None,
            edge: ingress_cfg.edge.clone(),
        };
        let trust_workspaces: Vec<String> = principals
            .keys()
            .filter_map(|k| k.split_once('/').map(|(_, ws)| ws.to_owned()))
            .collect();
        render_pack(
            out,
            PackMetadata {
                format_version: FORMAT_VERSION,
                kind: PackKind::Ingress,
                realm: manifest.realm.id.clone(),
                workspace: None,
                node: node.to_owned(),
                generation,
                created: rfc3339_now()?,
                expires: rfc3339(expires)?,
                control_endpoint: manifest.realm.control_endpoint.clone(),
                leaf_ttl_secs: ttl.duration().whole_seconds().max(0) as u64,
                identity_mode: manifest.identity.mode,
                registrar_endpoint: if manifest.registrar.endpoint.is_empty() {
                    None
                } else {
                    Some(manifest.registrar.endpoint.clone())
                },
            },
            principals,
            store,
            manifest,
            node_config,
            &trust_workspaces,
        )
    }
}

/// Renders the agent pack: one workspace-scoped agent principal.
///
/// Mesh-role agents additionally carry their site-to-site rules in the node
/// config and the trust anchors of every workspace they peer with.
pub struct AgentCredentialPack;

impl AgentCredentialPack {
    pub fn render(
        store: &IssuerStore,
        manifest: &crate::manifest::Manifest,
        node: &str,
        generation: Generation,
        out: &Path,
    ) -> Result<IssuedPack> {
        let agent_cfg = manifest.agent.get(node).ok_or_else(|| {
            Error::pack(format!(
                "agent node {node:?} is not declared in the manifest"
            ))
        })?;
        let ttl = manifest.effective_leaf_ttl()?;
        let material = store.issue_workspace_member_with_ttl(
            &manifest.realm.id,
            &agent_cfg.workspace,
            PrincipalKind::Agent,
            node,
            ttl,
        )?;
        let expires = material.not_after;
        let mesh_role = manifest.agent_has_mesh_role(node);
        let hub_endpoint = || {
            manifest
                .mesh_hub_endpoint()
                .map(str::to_owned)
                .ok_or_else(|| {
                    Error::pack(
                        "mesh-role agent requires a [mesh.hub.<name>] declaration".to_owned(),
                    )
                })
        };
        let node_config = NodeConfig {
            kind: PackKind::Agent,
            node: node.to_owned(),
            listen: None,
            control_listen: None,
            control_dispatch_host: None,
            public_tls: String::new(),
            public_tls_email: None,
            public_tls_directory: None,
            services: agent_cfg
                .services
                .iter()
                .map(|s| NodeService {
                    id: s.id.clone(),
                    address: s.address.clone(),
                })
                .collect(),
            mesh: match mesh_role {
                true => Some(NodeMeshConfig {
                    hub_endpoint: hub_endpoint()?,
                    ingress: agent_cfg.mesh_ingress.clone(),
                    egress: agent_cfg.mesh_egress.clone(),
                }),
                false => None,
            },
            edge: None,
        };
        // A mesh-role agent dials the hub, not the expose control endpoint.
        let dial_endpoint = if mesh_role {
            hub_endpoint()?
        } else {
            manifest.realm.control_endpoint.clone()
        };
        let trust_workspaces = if mesh_role {
            manifest.mesh_trust_workspaces(node)
        } else {
            vec![agent_cfg.workspace.clone()]
        };
        let mut principals = BTreeMap::new();
        principals.insert(format!("agent/{}", agent_cfg.workspace), material);
        render_pack(
            out,
            PackMetadata {
                format_version: FORMAT_VERSION,
                kind: PackKind::Agent,
                realm: manifest.realm.id.clone(),
                workspace: Some(agent_cfg.workspace.clone()),
                node: node.to_owned(),
                generation,
                created: rfc3339_now()?,
                expires: rfc3339(expires)?,
                control_endpoint: dial_endpoint,
                leaf_ttl_secs: ttl.duration().whole_seconds().max(0) as u64,
                identity_mode: manifest.identity.mode,
                registrar_endpoint: if manifest.registrar.endpoint.is_empty() {
                    None
                } else {
                    Some(manifest.registrar.endpoint.clone())
                },
            },
            principals,
            store,
            manifest,
            node_config,
            &trust_workspaces,
        )
    }
}

/// Renders the site-to-site hub pack: the control-endpoint server identity
/// (SAN = the hub's dial address) plus the realm-scoped hub client principal
/// that authorizes the hub's registrar renewal traffic. The trust bundle
/// carries every workspace the hub admits (its tenant trust table).
pub struct HubCredentialPack;

impl HubCredentialPack {
    pub fn render(
        store: &IssuerStore,
        manifest: &crate::manifest::Manifest,
        node: &str,
        generation: Generation,
        out: &Path,
    ) -> Result<IssuedPack> {
        let hub_cfg = manifest.mesh.hub.get(node).ok_or_else(|| {
            Error::pack(format!(
                "hub node {node:?} is not declared under [mesh.hub] in the manifest"
            ))
        })?;
        let ttl = manifest.effective_leaf_ttl()?;
        let control = store.issue_control_endpoint_with_ttl(
            &manifest.realm.id,
            node,
            &hub_cfg.endpoint,
            ttl,
        )?;
        let hub_member = store.issue_hub_member_with_ttl(&manifest.realm.id, node, ttl)?;
        let mut principals: BTreeMap<String, IdentityMaterial> = BTreeMap::new();
        principals.insert("control-endpoint".to_owned(), control);
        principals.insert(format!("hub/{}", manifest.realm.id), hub_member);
        let expires = principals
            .values()
            .map(|m| m.not_after)
            .min()
            .ok_or_else(|| Error::pack("hub pack carries no identities".to_owned()))?;
        let trust_workspaces = manifest.mesh_served_workspaces();
        if trust_workspaces.is_empty() {
            return Err(Error::pack(
                "hub pack carries no workspace trust anchor — declare mesh rules on at \
                 least one agent"
                    .to_owned(),
            ));
        }
        let node_config = NodeConfig {
            kind: PackKind::Hub,
            node: node.to_owned(),
            listen: Some(hub_cfg.listen.clone()),
            control_listen: None,
            control_dispatch_host: None,
            public_tls: String::new(),
            public_tls_email: None,
            public_tls_directory: None,
            services: Vec::new(),
            mesh: None,
            edge: None,
        };
        render_pack(
            out,
            PackMetadata {
                format_version: FORMAT_VERSION,
                kind: PackKind::Hub,
                realm: manifest.realm.id.clone(),
                workspace: None,
                node: node.to_owned(),
                generation,
                created: rfc3339_now()?,
                expires: rfc3339(expires)?,
                control_endpoint: hub_cfg.endpoint.clone(),
                leaf_ttl_secs: ttl.duration().whole_seconds().max(0) as u64,
                identity_mode: manifest.identity.mode,
                registrar_endpoint: if manifest.registrar.endpoint.is_empty() {
                    None
                } else {
                    Some(manifest.registrar.endpoint.clone())
                },
            },
            principals,
            store,
            manifest,
            node_config,
            &trust_workspaces,
        )
    }
}

#[allow(clippy::too_many_arguments)]
fn render_pack(
    out: &Path,
    metadata: PackMetadata,
    principals: BTreeMap<String, IdentityMaterial>,
    store: &IssuerStore,
    manifest: &crate::manifest::Manifest,
    node_config: NodeConfig,
    trust_workspaces: &[String],
) -> Result<IssuedPack> {
    // Trust bundle: realm issuer + the workspace issuers this pack's role
    // needs to anchor (per-kind derivation — see the render functions).
    let mut issuers = BTreeMap::new();
    issuers.insert(
        "control".to_owned(),
        store.realm_issuer()?.cert_pem().to_owned(),
    );
    for workspace in trust_workspaces {
        issuers.insert(
            format!("workspace/{workspace}"),
            store.workspace_issuer(workspace)?.cert_pem().to_owned(),
        );
    }
    let policy_key = hex::encode(store.policy_verifier()?.as_bytes());
    let trust = TrustBundle::build(&metadata.realm, metadata.generation, &policy_key, issuers)?;
    let policy = RuntimePolicy::from_manifest(manifest, metadata.generation);
    let (policy_bytes, signature) = policy.signed(&store.policy_signer()?)?;

    // Directory layout.
    let identity_dir = out.join("identity");
    let trust_dir = out.join("trust");
    let policy_dir = out.join("policy");
    for dir in [&identity_dir, &trust_dir, &policy_dir] {
        std::fs::create_dir_all(dir).map_err(|e| Error::Io {
            path: dir.display().to_string(),
            source: e,
        })?;
    }
    for (name, material) in &principals {
        let stem = name.replace('/', "-");
        let cert_path = identity_dir.join(format!("{stem}.crt"));
        let key_path = identity_dir.join(format!("{stem}.key"));
        std::fs::write(&cert_path, &material.chain_pem).map_err(|e| Error::Io {
            path: cert_path.display().to_string(),
            source: e,
        })?;
        write_private_key(&key_path, &material.key_pem)?;
    }
    trust.save(&trust_dir)?;
    let toml_bytes = toml::to_string_pretty(&metadata)
        .map_err(|e| Error::serialize("pack.toml".to_string()).with_source(e))?
        .into_bytes();
    std::fs::write(out.join("pack.toml"), &toml_bytes).map_err(|e| Error::Io {
        path: out.join("pack.toml").display().to_string(),
        source: e,
    })?;
    let node_toml = toml::to_string_pretty(&node_config)
        .map_err(|e| Error::serialize("node.toml".to_string()).with_source(e))?;
    std::fs::write(out.join("node.toml"), node_toml).map_err(|e| Error::Io {
        path: out.join("node.toml").display().to_string(),
        source: e,
    })?;
    std::fs::write(policy_dir.join("policy.toml"), &policy_bytes).map_err(|e| Error::Io {
        path: policy_dir.join("policy.toml").display().to_string(),
        source: e,
    })?;
    std::fs::write(policy_dir.join("policy.sig"), &signature).map_err(|e| Error::Io {
        path: policy_dir.join("policy.sig").display().to_string(),
        source: e,
    })?;
    write_digests(out)?;
    Ok(IssuedPack {
        dir: out.to_owned(),
        metadata,
    })
}

// ---------------------------------------------------------------------------
// Digest manifest
// ---------------------------------------------------------------------------

/// (Re)writes the pack's `SHA256SUMS` over every non-state file. Public so
/// `rotate` can fold the embedded CRL snapshot (`trust/crls/`) into the
/// digest manifest.
pub fn write_digests(dir: &Path) -> Result<()> {
    let mut entries = collect_files(dir, dir)?;
    entries.sort();
    let mut sums = String::new();
    for rel in entries {
        let bytes = std::fs::read(dir.join(&rel)).map_err(|e| Error::Io {
            path: dir.join(&rel).display().to_string(),
            source: e,
        })?;
        sums.push_str(&format!("{}  {}\n", sha256_hex(&bytes), rel));
    }
    let path = dir.join("SHA256SUMS");
    std::fs::write(&path, sums).map_err(|e| Error::Io {
        path: path.display().to_string(),
        source: e,
    })?;
    Ok(())
}

fn collect_files(root: &Path, dir: &Path) -> Result<Vec<String>> {
    let mut out = Vec::new();
    for entry in std::fs::read_dir(dir).map_err(|e| Error::Io {
        path: dir.display().to_string(),
        source: e,
    })? {
        let entry = entry.map_err(|e| Error::Io {
            path: dir.display().to_string(),
            source: e,
        })?;
        let path = entry.path();
        if path.is_dir() {
            out.extend(collect_files(root, &path)?);
        } else {
            let rel = path
                .strip_prefix(root)
                .map_err(|e| Error::pack("path handling".to_string()).with_source(e))?
                .to_string_lossy()
                .replace('\\', "/");
            if rel != "SHA256SUMS" && rel != "state" && !rel.starts_with("state/") {
                out.push(rel);
            }
        }
    }
    Ok(out)
}

/// The endpoint's host when it is a DNS name (an IP literal carries no SNI,
/// so public-port dispatch cannot key on it).
fn dns_host(endpoint: &str) -> Option<String> {
    let rest = endpoint.split_once("://").map_or(endpoint, |(_, r)| r);
    let host = rest.split_once(':').map_or(rest, |(h, _)| h);
    let looks_dns = !host.is_empty()
        && host
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '.'));
    let is_ip = host.parse::<std::net::IpAddr>().is_ok();
    (looks_dns && !is_ip).then(|| host.to_ascii_lowercase())
}

fn write_private_key(path: &Path, pem: &str) -> Result<()> {
    std::fs::write(path, pem).map_err(|e| Error::Io {
        path: path.display().to_string(),
        source: e,
    })?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut perms = std::fs::metadata(path)
            .map_err(|e| Error::Io {
                path: path.display().to_string(),
                source: e,
            })?
            .permissions();
        perms.set_mode(0o600);
        std::fs::set_permissions(path, perms).map_err(|e| Error::Io {
            path: path.display().to_string(),
            source: e,
        })?;
    }
    Ok(())
}
