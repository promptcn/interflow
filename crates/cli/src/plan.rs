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
use interflow_identity::issuance::AppliedState;
use interflow_identity::issuance::IssuerStore;
use interflow_identity::issuance::StoreBinding;
use interflow_identity::manifest::{Manifest, PublicTlsMode};
use interflow_identity::pack::CredentialPack;
use interflow_identity::pack::render::{
    AgentCredentialPack, HubCredentialPack, IngressCredentialPack,
};
use interflow_identity::policy::RuntimePolicy;
use interflow_identity::revocation::{RevocationEntry, RevocationList, build_crl};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

/// sha256 of the manifest with every agent's mesh rule lists emptied — the
/// identity/trust/dial face. `plan apply` diffs this against the applied
/// state: unchanged face + moved rules = the policy-only fast path (no
/// re-render, no re-sign).
/// Writes a PEM private key with owner-only permissions (the ephemeral
/// publish credential).
fn write_private_key_file(path: &Path, pem: &str) -> interflow_core::error::Result<()> {
    std::fs::write(path, pem).map_err(interflow_core::error::InterflowError::Io)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut perms = std::fs::metadata(path)
            .map_err(interflow_core::error::InterflowError::Io)?
            .permissions();
        perms.set_mode(0o600);
        std::fs::set_permissions(path, perms).map_err(interflow_core::error::InterflowError::Io)?;
    }
    Ok(())
}

fn stripped_manifest_digest(manifest: &Manifest) -> interflow_core::error::Result<String> {
    let mut stripped = manifest.clone();
    for agent in stripped.agent.values_mut() {
        agent.mesh_ingress.clear();
        agent.mesh_egress.clear();
    }
    let text = serde_json::to_string(&stripped).map_err(|e| {
        interflow_core::error::InterflowError::config("manifest serialization".to_string())
            .with_source(e)
    })?;
    Ok(format!(
        "sha256:{}",
        interflow_util::sha256_hex(text.as_bytes())
    ))
}

/// sha256 of one pack directory's digest manifest (the SHA256SUMS content).
fn pack_dir_digest(dir: &Path) -> interflow_core::error::Result<String> {
    let text = std::fs::read_to_string(dir.join("SHA256SUMS"))
        .map_err(interflow_core::error::InterflowError::Io)?;
    Ok(format!(
        "sha256:{}",
        interflow_util::sha256_hex(text.as_bytes())
    ))
}

/// The policy-only fast path: the identity face is unchanged, only mesh
/// rules moved. Signs the next policy generation, writes the bundle for
/// manual distribution, and publishes to the mesh hub when it is reachable
/// (the hub cascades to online agents; offline agents catch up on
/// reconnect). No pack is re-rendered and no identity is re-signed — the
/// whole point of the policy-identity separation.
fn apply_policy_only(
    issuer: &IssuerStore,
    manifest: &Manifest,
    prev: &AppliedState,
    out_root: &Path,
    lines: &mut Vec<String>,
) -> interflow_core::error::Result<()> {
    let bundle_dir = out_root.join("policy");
    let mut generation = prev.policy_generation + 1;

    // The local bookkeeping may lag the hub's floor (another operator
    // published from a different machine, or a full render reset the
    // counter); a 409 names the floor and this re-signs at floor+1, once.
    let mut published = false;
    for attempt in 0..2 {
        let policy = RuntimePolicy::from_manifest(manifest, generation);
        let (bytes, signature) = policy
            .signed(&issuer.policy_signer().map_err(crate::runtime::pack_error)?)
            .map_err(crate::runtime::pack_error)?;
        std::fs::create_dir_all(&bundle_dir).map_err(interflow_core::error::InterflowError::Io)?;
        std::fs::write(bundle_dir.join("policy.toml"), &bytes)
            .map_err(interflow_core::error::InterflowError::Io)?;
        std::fs::write(bundle_dir.join("policy.sig"), &signature)
            .map_err(interflow_core::error::InterflowError::Io)?;
        outln!(
            lines,
            "✔ policy-only change: mesh rules moved, identity face unchanged — signed policy              generation {generation} (no pack re-rendered, no identity re-signed)"
        );
        let endpoint = manifest
            .mesh
            .hub
            .values()
            .next()
            .map(|hub| hub.endpoint.clone())
            .unwrap_or_default();
        match publish_with_ephemeral_credential(
            issuer,
            &manifest.realm.id,
            &endpoint,
            &bytes,
            &signature,
            lines,
        ) {
            PublishResult::Published(accepted) => {
                generation = accepted;
                published = true;
                break;
            }
            PublishResult::Conflict(floor) if attempt == 0 => {
                outln!(
                    lines,
                    "  hub floor is generation {floor} (local bookkeeping lagged) — re-signing                      at {} and retrying",
                    floor + 1
                );
                generation = floor + 1;
            }
            PublishResult::Conflict(_) | PublishResult::Unreachable => break,
        }
    }
    if !published {
        outln!(
            lines,
            "  manual distribution: copy {}/policy.toml + policy.sig into every node's              <pack>/state/policy/ (the reload watcher applies them, ≤10s)",
            bundle_dir.display()
        );
    }

    let digest = format!(
        "sha256:{}",
        interflow_util::sha256_hex(
            &RuntimePolicy::from_manifest(manifest, generation)
                .to_bytes()
                .map_err(crate::runtime::pack_error)?
        )
    );
    issuer
        .record_applied(&AppliedState {
            stripped_manifest_digest: prev.stripped_manifest_digest.clone(),
            policy_generation: generation,
            policy_digest: digest,
            packs: prev.packs.clone(),
        })
        .map_err(crate::runtime::pack_error)?;
    Ok(())
}

/// How one publication attempt landed.
enum PublishResult {
    /// The hub accepted; it now serves this generation.
    Published(u64),
    /// Rejected as a rollback; carries the hub's current floor.
    Conflict(u64),
    /// The hub could not be reached (degrade to manual distribution).
    Unreachable,
}

/// Materializes a short-lived control credential (realm-anchored hub member
/// principal) + the realm anchor into a private temp dir, publishes, and
/// cleans up. The async publish runs on a dedicated thread with its own
/// runtime so both the CLI (async main) and the GUI (blocking pool) can
/// call it synchronously.
fn publish_with_ephemeral_credential(
    issuer: &IssuerStore,
    realm: &str,
    endpoint: &str,
    bytes: &[u8],
    signature: &[u8],
    lines: &mut Vec<String>,
) -> PublishResult {
    if endpoint.is_empty() {
        return PublishResult::Unreachable;
    }
    let outcome = (|| {
        let ttl = interflow_identity::issuance::LeafTtl::new(time::Duration::hours(1));
        let material = issuer
            .issue_hub_member_with_ttl(realm, "plan-apply", ttl)
            .map_err(crate::runtime::pack_error)?;
        let dir = std::env::temp_dir().join(format!(
            "interflow-policy-publish-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or_default()
        ));
        let _ = std::fs::create_dir_all(&dir);
        let (ca, cert, key) = (
            dir.join("ca.crt"),
            dir.join("client.crt"),
            dir.join("client.key"),
        );
        std::fs::write(
            &ca,
            issuer
                .realm_issuer()
                .map_err(crate::runtime::pack_error)?
                .cert_pem(),
        )
        .map_err(interflow_core::error::InterflowError::Io)?;
        std::fs::write(&cert, &material.chain_pem)
            .map_err(interflow_core::error::InterflowError::Io)?;
        write_private_key_file(&key, &material.key_pem)?;

        let moved = (
            endpoint.to_owned(),
            ca,
            cert,
            key,
            bytes.to_vec(),
            signature.to_vec(),
        );
        let handle = std::thread::spawn(move || {
            let rt = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .map_err(|e| {
                    interflow_core::error::InterflowError::config("publish runtime".to_string())
                        .with_source(e)
                })?;
            rt.block_on(interflow_mesh::hub::policy::publish_policy(
                &moved.0, &moved.1, &moved.2, &moved.3, &moved.4, &moved.5,
            ))
        });
        let outcome = handle.join().map_err(|_| {
            interflow_core::error::InterflowError::config(
                "policy publish thread panicked".to_string(),
            )
        })??;
        let _ = std::fs::remove_dir_all(&dir);
        interflow_core::error::Result::<_>::Ok(outcome)
    })();
    match outcome {
        Ok(interflow_mesh::hub::policy::PublishOutcome::Published { generation }) => {
            outln!(
                lines,
                "  published to hub {endpoint} → generation {generation}; online agents hot-apply"
            );
            PublishResult::Published(generation)
        }
        Ok(interflow_mesh::hub::policy::PublishOutcome::RollbackConflict {
            current_generation,
        }) => PublishResult::Conflict(current_generation),
        Err(e) => {
            outln!(
                lines,
                "  hub {endpoint} unreachable ({e}) — falling back to manual distribution"
            );
            PublishResult::Unreachable
        }
    }
}

/// Enforces the issuer store's trust-root isolation contract at every entry
/// point that mints material (`plan apply`, `plan rotate`; the GUI deploy
/// page rides the same functions):
///
/// - unbound store → bind it (first use, or a store older than bindings);
/// - different realm → hard error, no override: a realm is an identity, a
///   rename is a new one — there is no legitimate reuse to allow;
/// - same realm, different manifest file → hard error unless
///   `allow_shared`: one issuer across manifests merges their blast radii,
///   exactly what the contract exists to prevent. The override is for the
///   one legitimate case — the same deployment after a move/rename — and
///   rebinds;
/// - same realm, same file → silent refresh (normal edits and rotations
///   never trip anything).
///
fn enforce_store_binding(
    issuer_dir: &Path,
    manifest: &Manifest,
    manifest_path: &Path,
    allow_shared: bool,
    lines: &mut Vec<String>,
) -> interflow_core::error::Result<()> {
    let issuer = IssuerStore::open(issuer_dir);
    let next =
        StoreBinding::capture(manifest, manifest_path).map_err(crate::runtime::pack_error)?;
    match issuer.binding().map_err(crate::runtime::pack_error)? {
        None => {
            issuer
                .record_binding(&next)
                .map_err(crate::runtime::pack_error)?;
            outln!(
                lines,
                "  issuer store bound to realm {} (manifest {})",
                next.realm,
                next.manifest_path
            );
        }
        Some(current) => {
            if current.realm != next.realm {
                return Err(interflow_core::error::InterflowError::config(format!(
                    "issuer store {} is bound to realm {:?} — one issuer store signs exactly \
                     one realm. Give realm {:?} its own --issuer directory (a second scenario \
                     always gets both: its own realm id and its own store)",
                    issuer_dir.display(),
                    current.realm,
                    next.realm
                )));
            }
            if current.manifest_path != next.manifest_path && !allow_shared {
                return Err(interflow_core::error::InterflowError::config(format!(
                    "issuer store {} is already bound to the manifest {} (realm {:?}, bound \
                     {}) — sharing one issuer store across manifests merges their trust roots, \
                     so a leaked pack's blast radius spans both deployments. A separate \
                     scenario needs its own realm id and --issuer directory; if this is the \
                     same deployment after a move or rename, re-run with \
                     --issuer-allow-shared to rebind",
                    issuer_dir.display(),
                    current.manifest_path,
                    current.realm,
                    current.bound_at
                )));
            }
            if current.manifest_path != next.manifest_path {
                outln!(
                    lines,
                    "  re-bound issuer store to {} (--issuer-allow-shared)",
                    next.manifest_path
                );
            }
            // Same lineage, or an explicit rebind: refresh digest + stamp.
            issuer
                .record_binding(&next)
                .map_err(crate::runtime::pack_error)?;
        }
    }
    Ok(())
}

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

/// Renders the site-to-site (mesh) starter skeleton: realm + offline
/// identity + one hub.
///
/// Deliberately no placeholder agent — `validate` requires at least one,
/// and the first `node add` is what brings the manifest over that line, so
/// the skeleton carries zero fake values. The blueprint is the real
/// `deployments/promptcn/site-to-site/interflow.toml`.
pub fn setup_mesh_template(realm: &str, hub_name: &str, hub_endpoint: &str) -> String {
    format!(
        r#"# Interflow site-to-site mesh manifest — the single source of truth.
# Add agents (see below), then run: interflow plan apply
[realm]
id = "{realm}"

# Offline tier: no registrar, long-lived leaves, manual rotate/revoke —
# the usual choice for unattended site machines. The registrar tier
# (automatic renewal) is described in (internal design notes).
[identity]
mode = "offline"
leaf_ttl = "90d"

# The public relay LAN agents dial. `endpoint` is the dial address agents
# use and the SAN source of the hub's server credential — a hostname that
# resolves directly to this machine (not one hidden behind a proxy).
[mesh.hub.{hub_name}]
listen = "0.0.0.0:6666"
endpoint = "{hub_endpoint}"

[workspace.main]

# The manifest needs at least one agent before `plan apply` — add yours:
#   service side:  interflow node add agent/<name> --mesh-egress <rule>:127.0.0.1:8080
#   connect side:  interflow node add agent/<name> --mesh-ingress <rule>:127.0.0.1:8080:127.0.0.1:8080@<peer>
"#
    )
}

// ---------------------------------------------------------------------------
// Structured manifest appends (`node add`; shared with the GUI issue wizard)
// ---------------------------------------------------------------------------
//
// The types and the pure transform live in [`crate::manifest_edit`] beside
// the form editor's ops (one document model, one write discipline);
// re-exported here because `plan` is the operator-facing umbrella both the
// CLI binary and the GUI commands already speak.
pub use crate::manifest_edit::{
    AddMeshEgressSpec, AddMeshIngressSpec, AddNodeKind, AddNodeOutcome, AddNodeSpec, AddServiceSpec,
};

/// Appends one node to the manifest — non-destructively and fail-closed.
///
/// The pure core in [`manifest_edit::add_node_in_text`] carries the full
/// validation funnel; toml_edit keeps every comment and the operator's
/// layout; a silent `.bak` is one-generation insurance.
pub fn add_node(
    manifest_path: &Path,
    spec: &AddNodeSpec,
) -> interflow_core::error::Result<AddNodeOutcome> {
    crate::manifest_edit::add_node(manifest_path, spec)
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
        for rule in &cfg.mesh_egress {
            outln!(
                lines,
                "  mesh    {agent}/{} serves {} ({})",
                rule.name,
                rule.authorization(),
                match rule.protocol {
                    interflow_identity::manifest::MeshProtocol::Tcp => "tcp",
                    interflow_identity::manifest::MeshProtocol::Udp => "udp",
                }
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
    allow_shared: bool,
) -> interflow_core::error::Result<Vec<String>> {
    let mut lines = Vec::new();
    let manifest = Manifest::load(manifest_path).map_err(crate::runtime::pack_error)?;
    enforce_store_binding(
        issuer_dir,
        &manifest,
        manifest_path,
        allow_shared,
        &mut lines,
    )?;
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

    // The policy-only fast path: the identity/trust/dial face is unchanged
    // and only mesh rules moved → sign the next policy generation and
    // publish; no pack is re-rendered, no identity is re-signed, no
    // endpoint is touched.
    let stripped_now = stripped_manifest_digest(&manifest)?;
    if let Some(prev) = issuer.applied_state().map_err(crate::runtime::pack_error)?
        && prev.stripped_manifest_digest == stripped_now
    {
        let candidate = RuntimePolicy::from_manifest(&manifest, prev.policy_generation);
        let candidate_digest = format!(
            "sha256:{}",
            interflow_util::sha256_hex(&candidate.to_bytes().map_err(crate::runtime::pack_error)?)
        );
        if candidate_digest == prev.policy_digest {
            outln!(
                lines,
                "✔ manifest already applied — policy generation {} is live, nothing to do",
                prev.policy_generation
            );
            return Ok(lines);
        }
        apply_policy_only(&issuer, &manifest, &prev, out_root, &mut lines)?;
        return Ok(lines);
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

    // Record the applied state — the diff base for the next apply's
    // policy-only fast path (packs carry the render-time policy snapshot;
    // a later policy-only update rides its own generation track).
    let mut packs = BTreeMap::new();
    for pack in &rendered_packs {
        if let Ok(digest) = pack_dir_digest(&pack.dir) {
            packs.insert(pack.metadata.node.clone(), digest);
        }
    }
    let embedded_policy = RuntimePolicy::from_manifest(&manifest, 1);
    issuer
        .record_applied(&AppliedState {
            stripped_manifest_digest: stripped_now,
            policy_generation: 1,
            policy_digest: format!(
                "sha256:{}",
                interflow_util::sha256_hex(
                    &embedded_policy
                        .to_bytes()
                        .map_err(crate::runtime::pack_error)?
                )
            ),
            packs,
        })
        .map_err(crate::runtime::pack_error)?;

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
        outln!(
            lines,
            "  or encrypt:  interflow pack seal --pack packs/<kind>-<node> --generate-passphrase"
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
    allow_shared: bool,
) -> interflow_core::error::Result<Vec<String>> {
    let mut lines = Vec::new();
    let manifest = Manifest::load(manifest_path).map_err(crate::runtime::pack_error)?;
    enforce_store_binding(
        issuer_dir,
        &manifest,
        manifest_path,
        allow_shared,
        &mut lines,
    )?;
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
    // Refresh the applied state's policy bookkeeping: the rotated pack
    // embeds the manifest's policy at the new generation (nodes may still
    // serve a higher generation from their state channel — the publish
    // path's floor-retry reconciles).
    if let Some(applied) = issuer.applied_state().map_err(crate::runtime::pack_error)? {
        let policy = RuntimePolicy::from_manifest(&manifest, next_generation);
        issuer
            .record_applied(&AppliedState {
                stripped_manifest_digest: applied.stripped_manifest_digest,
                policy_generation: next_generation,
                policy_digest: format!(
                    "sha256:{}",
                    interflow_util::sha256_hex(
                        &policy.to_bytes().map_err(crate::runtime::pack_error)?
                    )
                ),
                packs: applied.packs,
            })
            .map_err(crate::runtime::pack_error)?;
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

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use interflow_identity::manifest::Manifest;

    const EXPOSE_MANIFEST: &str = r#"# operator comment — must survive a structured append
[realm]
id = "test"
control_endpoint = "relay.example.com:443"

[identity]
mode = "offline"
leaf_ttl = "90d"

[ingress.edge]
workspaces = ["default"]

[workspace.default]

[agent.existing]
workspace = "default"

[[agent.existing.services]]
id = "svc"
address = "127.0.0.1:8080"

[[route]]
host = "app.example.com"
service = "default/existing/svc"
"#;

    fn write_manifest(dir: &Path, text: &str) -> PathBuf {
        let path = dir.join("interflow.toml");
        std::fs::write(&path, text).unwrap();
        path
    }

    fn expose_spec(node: &str) -> AddNodeSpec {
        AddNodeSpec {
            kind: AddNodeKind::Agent,
            node: node.into(),
            workspace: None,
            services: vec![AddServiceSpec {
                id: "asr".into(),
                address: "127.0.0.1:8090".into(),
            }],
            mesh_ingress: vec![],
            mesh_egress: vec![],
            ingress_workspaces: vec![],
            hub_endpoint: None,
        }
    }

    /// An expose agent append lands as a parseable node, inherits the sole
    /// workspace, and leaves the operator's comments untouched.
    #[test]
    fn add_expose_agent_appends_and_keeps_comments() {
        let dir = tempfile::tempdir().unwrap();
        let path = write_manifest(dir.path(), EXPOSE_MANIFEST);
        let outcome = add_node(&path, &expose_spec("desktop2")).unwrap();
        let rewritten = std::fs::read_to_string(&path).unwrap();
        assert!(
            rewritten.contains("# operator comment — must survive a structured append"),
            "comments must survive: {rewritten}"
        );
        assert!(rewritten.contains("[agent.desktop2]"), "{rewritten}");
        let manifest = Manifest::parse(&rewritten).unwrap();
        let agent = manifest.agent.get("desktop2").unwrap();
        assert_eq!(agent.workspace, "default", "sole workspace inherited");
        assert_eq!(agent.services.len(), 1);
        assert_eq!(outcome.pack_dir_name, "agent-desktop2");
        assert_eq!(outcome.manifest_text, rewritten);
    }

    /// The mesh skeleton carries zero placeholder agents, so it is not
    /// applicable on its own — the first egress append is what makes it a
    /// valid manifest.
    #[test]
    fn mesh_skeleton_goes_valid_on_first_add() {
        let dir = tempfile::tempdir().unwrap();
        let skeleton = setup_mesh_template("test-mesh", "central", "mesh.example.com:6666");
        assert!(
            Manifest::parse(&skeleton).is_err(),
            "no agent yet — skeleton must not pretend to be deployable"
        );
        let path = write_manifest(dir.path(), &skeleton);
        let spec = AddNodeSpec {
            kind: AddNodeKind::Agent,
            node: "home-win".into(),
            workspace: None,
            services: vec![],
            mesh_ingress: vec![],
            mesh_egress: vec![AddMeshEgressSpec {
                name: "loopback-services".into(),
                udp: false,
                target_addr: None,
                target_cidr: Some("127.0.0.0/8".into()),
            }],
            ingress_workspaces: vec![],
            hub_endpoint: None,
        };
        add_node(&path, &spec).unwrap();
        let rewritten = std::fs::read_to_string(&path).unwrap();
        let manifest = Manifest::parse(&rewritten).unwrap();
        let agent = manifest.agent.get("home-win").unwrap();
        assert_eq!(agent.workspace, "main", "sole workspace of the skeleton");
        assert_eq!(
            manifest.mesh.hub["central"].endpoint, "mesh.example.com:6666",
            "the skeleton's hub is untouched"
        );
    }

    /// Mesh ingress rules render with udp only when asked (tcp is the
    /// serde default and stays omitted). The serve-side peer must exist
    /// first — validate resolves `target_agent` against declared agents.
    #[test]
    fn add_mesh_ingress_agent_renders_rules() {
        let dir = tempfile::tempdir().unwrap();
        let path = write_manifest(
            dir.path(),
            &setup_mesh_template("test-mesh", "central", "mesh.example.com:6666"),
        );
        // Serve side first (the ingress rules below dial it): tcp is the
        // default, udp gets its own paired authorization — validate checks
        // ingress↔egress pairing by protocol AND address.
        add_node(
            &path,
            &AddNodeSpec {
                kind: AddNodeKind::Agent,
                node: "home-win".into(),
                workspace: None,
                services: vec![],
                mesh_ingress: vec![],
                mesh_egress: vec![
                    AddMeshEgressSpec {
                        name: "loopback-services".into(),
                        udp: false,
                        target_addr: None,
                        target_cidr: Some("127.0.0.0/8".into()),
                    },
                    AddMeshEgressSpec {
                        name: "loopback-udp".into(),
                        udp: true,
                        target_addr: None,
                        target_cidr: Some("127.0.0.0/8".into()),
                    },
                ],
                ingress_workspaces: vec![],
                hub_endpoint: None,
            },
        )
        .unwrap();
        let tcp = add_node(
            &path,
            &AddNodeSpec {
                kind: AddNodeKind::Agent,
                node: "leo".into(),
                workspace: None,
                services: vec![],
                mesh_ingress: vec![
                    AddMeshIngressSpec {
                        name: "ollama".into(),
                        listen: "127.0.0.1:11434".into(),
                        udp: false,
                        target_agent: "home-win".into(),
                        remote_addr: "127.0.0.1:11434".into(),
                        idle_timeout_secs: None,
                    },
                    AddMeshIngressSpec {
                        name: "dns".into(),
                        listen: "127.0.0.1:5353".into(),
                        udp: true,
                        target_agent: "home-win".into(),
                        remote_addr: "127.0.0.1:53".into(),
                        idle_timeout_secs: None,
                    },
                ],
                mesh_egress: vec![],
                ingress_workspaces: vec![],
                hub_endpoint: None,
            },
        )
        .unwrap();
        let rewritten = std::fs::read_to_string(&path).unwrap();
        assert!(!tcp.pack_dir_name.is_empty());
        let manifest = Manifest::parse(&rewritten).unwrap();
        let rules = &manifest.agent["leo"].mesh_ingress;
        assert_eq!(rules.len(), 2);
        assert_eq!(rules[0].name, "ollama");
        assert!(
            !rewritten.contains("protocol = \"tcp\""),
            "tcp stays implicit"
        );
        assert!(rewritten.contains("protocol = \"udp\""));
    }

    /// An ingress append lands with its workspaces (validate demands each
    /// served workspace already has a services agent — "extra" would be
    /// refused, so the fixture serves the populated default workspace).
    #[test]
    fn add_ingress_node() {
        let dir = tempfile::tempdir().unwrap();
        let path = write_manifest(dir.path(), EXPOSE_MANIFEST);
        add_node(
            &path,
            &AddNodeSpec {
                kind: AddNodeKind::Ingress,
                node: "edge2".into(),
                workspace: None,
                services: vec![],
                mesh_ingress: vec![],
                mesh_egress: vec![],
                ingress_workspaces: vec!["default".into()],
                hub_endpoint: None,
            },
        )
        .unwrap();
        let manifest = Manifest::parse(&std::fs::read_to_string(&path).unwrap()).unwrap();
        assert_eq!(manifest.ingress["edge2"].workspaces, vec!["default"]);
    }

    /// A hub appends to a mesh manifest that has none yet — v1 allows
    /// exactly one hub per realm, and it must serve at least one mesh
    /// agent, so the fixture declares the serve side first.
    #[test]
    fn add_hub_node() {
        let dir = tempfile::tempdir().unwrap();
        let path = write_manifest(
            dir.path(),
            r#"[realm]
id = "test-mesh"

[identity]
mode = "offline"
leaf_ttl = "90d"

[workspace.main]

[agent.home-win]
workspace = "main"

[[agent.home-win.mesh_egress]]
name = "loopback"
target_cidr = "127.0.0.0/8"
"#,
        );
        add_node(
            &path,
            &AddNodeSpec {
                kind: AddNodeKind::Hub,
                node: "central".into(),
                workspace: None,
                services: vec![],
                mesh_ingress: vec![],
                mesh_egress: vec![],
                ingress_workspaces: vec![],
                hub_endpoint: Some("mesh.example.com:6666".into()),
            },
        )
        .unwrap();
        let manifest = Manifest::parse(&std::fs::read_to_string(&path).unwrap()).unwrap();
        assert_eq!(
            manifest.mesh.hub["central"].endpoint,
            "mesh.example.com:6666"
        );
        assert_eq!(
            manifest.mesh.hub["central"].listen, "0.0.0.0:6666",
            "default"
        );
    }

    /// A node name taken by any of the three tables is refused with the
    /// manifest byte-identical.
    #[test]
    fn duplicate_node_is_refused_untouched() {
        let dir = tempfile::tempdir().unwrap();
        let path = write_manifest(dir.path(), EXPOSE_MANIFEST);
        let before = std::fs::read(&path).unwrap();
        let err = add_node(&path, &expose_spec("existing")).unwrap_err();
        assert!(err.to_string().contains("already exists"), "{err}");
        assert_eq!(std::fs::read(&path).unwrap(), before);
    }

    /// An append the validator rejects (egress CIDR inside the SSRF
    /// blocklist) writes nothing and leaves no backup behind.
    #[test]
    fn invalid_append_writes_nothing() {
        let dir = tempfile::tempdir().unwrap();
        let path = write_manifest(
            dir.path(),
            &setup_mesh_template("test-mesh", "central", "mesh.example.com:6666"),
        );
        let before = std::fs::read(&path).unwrap();
        let spec = AddNodeSpec {
            kind: AddNodeKind::Agent,
            node: "evil".into(),
            workspace: None,
            services: vec![],
            mesh_ingress: vec![],
            mesh_egress: vec![AddMeshEgressSpec {
                name: "link-local".into(),
                udp: false,
                target_addr: None,
                target_cidr: Some("169.254.0.0/16".into()),
            }],
            ingress_workspaces: vec![],
            hub_endpoint: None,
        };
        let err = add_node(&path, &spec).unwrap_err();
        // The rejection text rides the source chain (pack_error wraps the
        // manifest error), so walk it instead of matching the top layer.
        let mut chain = err.to_string();
        let mut source: &dyn std::error::Error = &err;
        while let Some(next) = source.source() {
            chain.push_str(&next.to_string());
            source = next;
        }
        assert!(
            chain.contains("SSRF blocklist"),
            "validator must reject the blocklist CIDR: {chain}"
        );
        assert_eq!(std::fs::read(&path).unwrap(), before, "file untouched");
        let mut backup = path.as_os_str().to_os_string();
        backup.push(".bak");
        assert!(
            !PathBuf::from(backup).exists(),
            "no backup when nothing was written"
        );
    }
}
