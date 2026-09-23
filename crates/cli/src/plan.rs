//! `setup`, `plan validate`, `plan apply`, `rotate`, `revoke` — shared by
//! the `interflow` binary and the GUI's deploy page.
//!
//! Every operation returns its human-readable output lines instead of
//! printing: the CLI prints them, the GUI streams them into the deploy pane.

/// The line sink the operations below write to (CLI prints them, the GUI
/// streams them).
macro_rules! outln {
    ($lines:expr, $($arg:tt)*) => {
        $lines.push(format!($($arg)*))
    };
}

use crate::render;
use interflow_identity::issuance::IssuerStore;
use interflow_identity::manifest::{Manifest, PublicTlsMode};
use interflow_identity::pack::CredentialPack;
use interflow_identity::pack::render::{
    AgentCredentialPack, HubCredentialPack, IngressCredentialPack,
};
use interflow_identity::revocation::{RevocationEntry, RevocationList, build_crl};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

/// Renders the starter manifest template (the `setup` parameters).
pub fn setup_template(
    realm: &str,
    control_endpoint: &str,
    registrar_endpoint: &str,
    host: &str,
    agent: &str,
    service: &str,
    service_address: &str,
) -> String {
    let service_ref = format!("default/{agent}/{service}");
    format!(
        r#"# Interflow deployment manifest — the single source of truth.
# Edit, then run: interflow plan apply
[realm]
id = "{realm}"
control_endpoint = "{control_endpoint}"

[public_tls]
mode = "acme"          # acme | frontend-proxy | manual

[identity]
leaf_ttl = "24h"       # 1h–24h (registrar tier; the offline tier takes 7d–365d)
# mode = "offline"     # single-operator alternative: long-lived leaves, no
#                       # registrar, manual rotate/revoke — remove [registrar]

[registrar]
endpoint = "{registrar_endpoint}"

[ingress.edge]
workspaces = ["default"]
# listen = "0.0.0.0:443"
# control_listen = "127.0.0.1:16666"

[workspace.default]

[agent.{agent}]
workspace = "default"

[[agent.{agent}.services]]
id = "{service}"
address = "{service_address}"

[[route]]
host = "{host}"
service = "{service_ref}"
"#
    )
}

pub fn validate(manifest_path: &Path) -> interflow_core::error::Result<Vec<String>> {
    let mut lines = Vec::new();
    let manifest = Manifest::load(manifest_path).map_err(crate::runtime::pack_error)?;
    let services = manifest.service_index();
    outln!(
        lines,
        "✔ manifest {} is valid: realm {}, {} workspace(s), {} agent(s), {} service(s), \
         {} route(s), {} ingress(es), {} mesh hub(s), {} mesh stream(s)",
        manifest_path.display(),
        manifest.realm.id,
        manifest.workspace.len(),
        manifest.agent.len(),
        services.len(),
        manifest.route.len(),
        manifest.ingress.len(),
        manifest.mesh.hub.len(),
        manifest
            .agent
            .values()
            .map(|a| a.mesh_ingress.len())
            .sum::<usize>(),
    );
    for route in &manifest.route {
        outln!(lines, "  route {} → {}", route.host, route.service);
    }
    for (agent, cfg) in &manifest.agent {
        for rule in &cfg.mesh_ingress {
            outln!(
                lines,
                "  mesh    {agent}/{} → {} at {}",
                rule.name,
                rule.target_agent,
                rule.remote_addr
            );
        }
    }
    match manifest.public_tls.mode {
        PublicTlsMode::Acme => outln!(lines, "  public TLS: ACME (automatic)"),
        PublicTlsMode::FrontendProxy => {
            outln!(lines, "  public TLS: frontend proxy (config rendered)");
        }
        PublicTlsMode::Manual => outln!(lines, "  public TLS: manual (expert)"),
    }
    Ok(lines)
}

pub fn apply(
    manifest_path: &Path,
    issuer_dir: &Path,
    out_root: &Path,
) -> interflow_core::error::Result<Vec<String>> {
    let mut lines = Vec::new();
    let manifest = Manifest::load(manifest_path).map_err(crate::runtime::pack_error)?;
    let issuer = IssuerStore::open(issuer_dir);
    issuer.ensure_realm().map_err(crate::runtime::pack_error)?;
    issuer
        .ensure_policy_key()
        .map_err(crate::runtime::pack_error)?;
    for workspace in manifest.workspace.keys() {
        issuer
            .ensure_workspace(workspace)
            .map_err(crate::runtime::pack_error)?;
    }

    let mut rendered_packs = Vec::new();
    for node in manifest.mesh.hub.keys() {
        let out = out_root.join("packs").join(format!("hub-{node}"));
        let pack = HubCredentialPack::render(&issuer, &manifest, node, 1, &out)
            .map_err(crate::runtime::pack_error)?;
        rendered_packs.push(pack);
    }
    for node in manifest.ingress.keys() {
        let out = out_root.join("packs").join(format!("ingress-{node}"));
        let pack = IngressCredentialPack::render(&issuer, &manifest, node, 1, &out)
            .map_err(crate::runtime::pack_error)?;
        rendered_packs.push(pack);
    }
    for node in manifest.agent.keys() {
        let out = out_root.join("packs").join(format!("agent-{node}"));
        let pack = AgentCredentialPack::render(&issuer, &manifest, node, 1, &out)
            .map_err(crate::runtime::pack_error)?;
        rendered_packs.push(pack);
    }
    // Deployment artifacts: per-node units, the registrar unit (registrar
    // deployments), frontend-proxy nginx fragments and the bootstrap script —
    // all derived from the manifest (render.rs owns the layout convention).
    for pack in &rendered_packs {
        let mesh_role = pack.metadata.kind == interflow_identity::pack::PackKind::Hub
            || manifest.agent_has_mesh_role(&pack.metadata.node);
        render::write_node_unit(
            out_root,
            pack.metadata.kind,
            &pack.metadata.node,
            mesh_role,
            render::DEFAULT_INSTALL_ROOT,
        )?;
    }
    if render::has_registrar(&manifest) {
        render::write_registrar_unit(out_root, &manifest, render::DEFAULT_INSTALL_ROOT)?;
    }
    render::write_nginx_fragments(out_root, &manifest)?;
    render::write_install_sh(out_root, &manifest)?;
    if manifest.public_tls.mode == PublicTlsMode::Acme {
        for host in manifest.route.iter().map(|r| r.host.as_str()) {
            outln!(
                lines,
                "note: public TLS mode is ACME for {host}: point DNS at the ingress and \
                 ensure ports 80/443 are reachable; if a front proxy occupies them, switch \
                 [public_tls].mode to \"frontend-proxy\""
            );
        }
    }

    outln!(
        lines,
        "✔ applied {} → {}",
        manifest_path.display(),
        out_root.display()
    );
    outln!(
        lines,
        "  issuer store: {} (keep secret — never distribute)",
        issuer_dir.display()
    );
    for node in manifest.mesh.hub.keys() {
        outln!(
            lines,
            "  hub      {node}: {}",
            out_root.join("packs").join(format!("hub-{node}")).display()
        );
    }
    for node in manifest.ingress.keys() {
        outln!(
            lines,
            "  ingress  {node}: {}",
            out_root
                .join("packs")
                .join(format!("ingress-{node}"))
                .display()
        );
    }
    for node in manifest.agent.keys() {
        outln!(
            lines,
            "  agent    {node}: {}",
            out_root
                .join("packs")
                .join(format!("agent-{node}"))
                .display()
        );
    }
    if !manifest.mesh.hub.is_empty() || !manifest.ingress.is_empty() {
        outln!(lines, "deploy, per server:");
        outln!(
            lines,
            "  1. copy this dist tree to the server (or just its node's pack + install.sh)"
        );
        outln!(
            lines,
            "  2. sudo bash install.sh   # once per server: user, dirs, bin/ (no units)"
        );
        outln!(
            lines,
            "  3. per node:  sudo interflow node install --pack packs/<kind>-<node>   # pack + unit + enable"
        );
        if render::has_registrar(&manifest) {
            outln!(
                lines,
                "  registrar host: follow the bootstrap in systemd/interflow-registrar.service"
            );
        }
    }
    if manifest.public_tls.mode == PublicTlsMode::FrontendProxy {
        outln!(
            lines,
            "nginx (frontend proxy): hook the fragments in nginx/ into your nginx —"
        );
        outln!(lines, "  http:   include /etc/nginx/interflow/http/*.conf;");
        outln!(
            lines,
            "  stream: stream {{ include /etc/nginx/interflow/stream/*.conf; }}   # nginx.conf top level"
        );
        outln!(
            lines,
            "  then reload nginx and verify: interflow doctor ingress --pack <pack>"
        );
    }
    if render::has_registrar(&manifest) {
        outln!(
            lines,
            "registrar server: copy the issuer store to {}/registrar/issuer,",
            render::DEFAULT_INSTALL_ROOT
        );
        outln!(
            lines,
            "  then run the certificate command recorded in systemd/interflow-registrar.service"
        );
    }
    Ok(lines)
}

pub fn rotate(
    manifest_path: &Path,
    issuer_dir: &Path,
    node: &str,
    current_pack: Option<&Path>,
    out: Option<&Path>,
) -> interflow_core::error::Result<Vec<String>> {
    let mut lines = Vec::new();
    let manifest = Manifest::load(manifest_path).map_err(crate::runtime::pack_error)?;
    let issuer = IssuerStore::open(issuer_dir);
    issuer.ensure_realm().map_err(crate::runtime::pack_error)?;
    issuer
        .ensure_policy_key()
        .map_err(crate::runtime::pack_error)?;
    for workspace in manifest.workspace.keys() {
        issuer
            .ensure_workspace(workspace)
            .map_err(crate::runtime::pack_error)?;
    }
    let (kind, name) = node.split_once('/').ok_or_else(|| {
        interflow_core::error::InterflowError::config(
            "node must be `ingress/<name>`, `agent/<name>` or `hub/<name>`",
        )
    })?;
    let next_generation = match current_pack {
        Some(path) => {
            CredentialPack::load(path)
                .map_err(crate::runtime::pack_error)?
                .metadata
                .generation
                + 1
        }
        None => 1,
    };
    let out_dir: PathBuf = out.map_or_else(
        || {
            let base = current_pack.map_or_else(
                || PathBuf::from("dist/packs"),
                |p| p.parent().unwrap_or_else(|| Path::new(".")).to_path_buf(),
            );
            base.join(format!("{kind}-{name}-gen{next_generation}"))
        },
        ToOwned::to_owned,
    );
    let pack = match kind {
        "ingress" => {
            IngressCredentialPack::render(&issuer, &manifest, name, next_generation, &out_dir)
                .map_err(crate::runtime::pack_error)?
        }
        "hub" => HubCredentialPack::render(&issuer, &manifest, name, next_generation, &out_dir)
            .map_err(crate::runtime::pack_error)?,
        "agent" => AgentCredentialPack::render(&issuer, &manifest, name, next_generation, &out_dir)
            .map_err(crate::runtime::pack_error)?,
        other => {
            return Err(interflow_core::error::InterflowError::config(format!(
                "unknown node kind {other:?} (expected ingress, agent or hub)"
            )));
        }
    };
    // Offline tier: fold the issuer store's current deny list into the new
    // pack as a CRL snapshot (trust/crls/) — revocation travels with the
    // pack, no distribution service needed. Freshness horizon = the new
    // leaf's own lifetime.
    if manifest.identity.mode == interflow_identity::manifest::IdentityMode::Offline {
        embed_revocation_snapshot(
            &issuer,
            issuer_dir,
            &manifest,
            &out_dir,
            pack.metadata.leaf_ttl_secs,
        )?;
        outln!(
            lines,
            "  embedded revocation snapshot in trust/crls/ (covers every issuer)"
        );
    }
    outln!(
        lines,
        "✔ rotated {node} → generation {} at {}",
        next_generation,
        out_dir.display()
    );
    if let Some(old) = current_pack {
        outln!(
            lines,
            "  rollback: the old pack at {} stays valid until its own expiry",
            old.display()
        );
    }
    outln!(
        lines,
        "  next: distribute the new pack, restart the node, then:"
    );
    outln!(
        lines,
        "    interflow identity inspect --pack {}",
        out_dir.display()
    );
    outln!(
        lines,
        "    interflow doctor {} --pack {}",
        kind,
        out_dir.display()
    );
    let _ = pack;
    Ok(lines)
}

/// Builds a CRL per relevant issuer from the deny list and writes them into
/// `<pack>/trust/crls/`, then re-folds `SHA256SUMS` so the snapshot is
/// tamper-evident alongside the rest of the pack.
fn embed_revocation_snapshot(
    issuer: &IssuerStore,
    issuer_dir: &Path,
    manifest: &Manifest,
    out_dir: &Path,
    horizon_secs: u64,
) -> interflow_core::error::Result<()> {
    use interflow_identity::revocation::build_crl_with_horizon;
    use std::collections::BTreeSet;

    let list = RevocationList::load(issuer_dir).map_err(crate::runtime::pack_error)?;
    let mut by_issuer: BTreeMap<String, Vec<String>> = BTreeMap::new();
    for entry in &list.entries {
        by_issuer
            .entry(entry.issuer.clone())
            .or_default()
            .push(entry.serial.clone());
    }
    let mut issuers: BTreeSet<String> = BTreeSet::from(["control".to_owned()]);
    issuers.extend(
        manifest
            .workspace
            .keys()
            .map(|ws| format!("workspace/{ws}")),
    );
    issuers.extend(by_issuer.keys().cloned());
    let dir = out_dir.join("trust").join("crls");
    std::fs::create_dir_all(&dir)?;
    let horizon = time::Duration::seconds(i64::try_from(horizon_secs).unwrap_or(i64::MAX));
    for issuer_name in issuers {
        let loaded = match issuer_name.as_str() {
            "control" => issuer.realm_issuer().map_err(crate::runtime::pack_error)?,
            ws => issuer
                .workspace_issuer(ws.trim_start_matches("workspace/"))
                .map_err(crate::runtime::pack_error)?,
        };
        let serials = by_issuer.get(&issuer_name).cloned().unwrap_or_default();
        let crl = build_crl_with_horizon(&loaded, &serials, list.entries.len() as u64 + 1, horizon)
            .map_err(crate::runtime::pack_error)?;
        let path = dir.join(format!("{}.crl.pem", issuer_name.replace('/', "-")));
        std::fs::write(&path, crl)?;
    }
    interflow_identity::pack::render::write_digests(out_dir).map_err(crate::runtime::pack_error)?;
    Ok(())
}

pub fn revoke(
    issuer_dir: &Path,
    pack_dir: &Path,
    reason: &str,
) -> interflow_core::error::Result<Vec<String>> {
    let mut lines = Vec::new();
    let pack = CredentialPack::load(pack_dir).map_err(crate::runtime::pack_error)?;
    let issuer = IssuerStore::open(issuer_dir);
    let mut list = RevocationList::load(issuer_dir).map_err(crate::runtime::pack_error)?;
    let now = time::OffsetDateTime::now_utc()
        .format(&time::format_description::well_known::Rfc3339)
        .map_err(|e| {
            interflow_core::error::InterflowError::config("revocation timestamp failed")
                .with_source(e)
        })?;
    // Record every credential serial carried by the pack.
    let mut by_issuer: BTreeMap<String, Vec<String>> = BTreeMap::new();
    for buckets in pack.identities.values() {
        for entry in buckets.values() {
            let serial = interflow_identity::revocation::cert_serial_hex(&entry.cert_pem)
                .map_err(crate::runtime::pack_error)?;
            let issuer_name = match &entry.principal.workspace {
                Some(ws) => format!("workspace/{ws}"),
                None => "control".to_owned(),
            };
            by_issuer
                .entry(issuer_name.clone())
                .or_default()
                .push(serial.clone());
            list.entries.push(RevocationEntry {
                serial,
                issuer: issuer_name,
                reason: reason.to_owned(),
                revoked_at: now.clone(),
                pack_digest: Some(pack.pack_digest.clone()),
            });
        }
    }
    if let Ok(Some(active)) =
        interflow_identity::credentials::ActiveCredentialSet::load_existing(&pack)
    {
        for credential in active.entries.values() {
            let issuer_name = match credential.principal.workspace.as_deref() {
                Some(ws) => format!("workspace/{ws}"),
                None => "control".to_owned(),
            };
            by_issuer
                .entry(issuer_name.clone())
                .or_default()
                .push(credential.serial.clone());
            list.entries.push(RevocationEntry {
                serial: credential.serial.clone(),
                issuer: issuer_name,
                reason: reason.to_owned(),
                revoked_at: now.clone(),
                pack_digest: Some(pack.pack_digest.clone()),
            });
        }
    }
    list.save(issuer_dir).map_err(crate::runtime::pack_error)?;
    // Regenerate CRLs per affected issuer.
    for (issuer_name, serials) in &by_issuer {
        let loaded = match issuer_name.as_str() {
            "control" => issuer.realm_issuer().map_err(crate::runtime::pack_error)?,
            ws => issuer
                .workspace_issuer(ws.trim_start_matches("workspace/"))
                .map_err(crate::runtime::pack_error)?,
        };
        let crl = build_crl(&loaded, serials, list.entries.len() as u64)
            .map_err(crate::runtime::pack_error)?;
        let path = issuer_dir.join(format!("{}.crl.pem", issuer_name.replace('/', "-")));
        std::fs::write(&path, crl)?;
        outln!(
            lines,
            "✔ revoked {serials:?} by {issuer_name}; CRL → {}",
            path.display()
        );
    }
    outln!(
        lines,
        "next: re-apply packs so every node picks up the updated trust \
         (`interflow plan apply`), then verify with `interflow doctor`"
    );
    Ok(lines)
}
