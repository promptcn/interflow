//! `setup`, `plan validate`, `plan apply`, `rotate`, `revoke` — shared by
//! the `interflow-cli` binary and the GUI's deploy page.
//!
//! Every operation returns its human-readable output lines instead of
//! printing: the CLI prints them, the GUI streams them into the deploy pane.

/// The line sink the operations below write to (CLI prints them, the GUI
/// streams them).
macro_rules! pushln {
    ($lines:expr, $($arg:tt)*) => {
        $lines.push(format!($($arg)*))
    };
}

use crate::render;
use interflow_identity::issuance::IssuerStore;
use interflow_identity::issuance::StoreBinding;
use interflow_identity::issuance::{AppliedKind, AppliedState};
use interflow_identity::manifest::{Manifest, PublicTlsMode};
use interflow_identity::pack::render::{
    AgentCredentialPack, HubCredentialPack, IngressCredentialPack,
};
use interflow_identity::policy::RuntimePolicy;
use interflow_identity::revocation::{RevocationEntry, RevocationList, build_crl};
use interflow_identity::{PackTreeStale, pack_digest_of, pack_generation_of, probe_pack_format};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

/// sha256 of the manifest with every agent's policy-carried lists emptied
/// (mesh rules, services, routes) — the identity/trust/dial face. `plan
/// apply` diffs this against the applied state: unchanged face + moved
/// policy content = the policy-only fast path (no re-render, no re-sign).
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
        // Services are policy material too (the signed default address
        // rides the policy since 2026-10-10), and so are routes: both
        // hot-apply on every node kind, so they belong to the policy-only
        // face. A stale pack node.toml default is shadowed by the signed
        // default in the resolve ladder until the next full render.
        agent.services.clear();
    }
    stripped.route.clear();
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
/// The first hub's endpoint — the control-plane dial target for the policy
/// floor query and the publish (empty when the manifest declares no hub;
/// every control-plane call degrades to local watermarks / manual
/// distribution).
fn manifest_hub_endpoint(manifest: &Manifest) -> String {
    if let Some(hub) = manifest.mesh.hub.values().next() {
        return hub.endpoint.clone();
    }
    // Expose-only deployment: the ingress's control endpoint carries the
    // same policy face (serving to agents, publication to the operator —
    // the 2026-10-10 wiring). Loopback by default: unreachable from
    // another machine degrades to guided manual distribution, same as a
    // mesh hub behind an unreachable address.
    manifest
        .ingress
        .values()
        .next()
        .map(|ingress| ingress.control_listen.clone())
        .unwrap_or_default()
}

fn apply_policy_only(
    issuer: &IssuerStore,
    manifest: &Manifest,
    manifest_text: &str,
    prev: &AppliedState,
    out_root: &Path,
    pre_queried_hub: Option<interflow_mesh::hub::policy::PolicyFloorQuery>,
    lines: &mut Vec<String>,
) -> interflow_core::error::Result<u64> {
    let bundle_dir = out_root.join("policy");
    let endpoint = manifest_hub_endpoint(manifest);
    // Mint above every observable watermark: local bookkeeping, the dist
    // artifacts, and — queried BEFORE signing — the running hub's floor
    // (another operator may have published from a different machine, or a
    // past full render may have reset the bookkeeping). The 409-retry below
    // stays as the race backstop. `pre_queried_hub` reuses the gate's dial.
    let (floor, _) = policy_mint_floor(
        issuer,
        out_root,
        &endpoint,
        &manifest.realm.id,
        pre_queried_hub,
        lines,
    );
    let mut generation = floor + 1;

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
        pushln!(
            lines,
            "✔ policy-only change: rules / services / routes moved, identity face unchanged — signed              policy generation {generation} (no pack re-rendered, no identity re-signed)"
        );
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
            PublishResult::Conflict(hub_floor) if attempt == 0 => {
                pushln!(
                    lines,
                    "  hub floor is generation {hub_floor} (advanced since the pre-flight query) —                      re-signing at {} and retrying",
                    hub_floor + 1
                );
                generation = hub_floor + 1;
            }
            PublishResult::Conflict(_) | PublishResult::Unreachable | PublishResult::Rejected => {
                break;
            }
        }
    }
    if !published {
        pushln!(
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
        .record_applied(
            &AppliedState {
                stripped_manifest_digest: prev.stripped_manifest_digest.clone(),
                policy_generation: generation,
                policy_digest: digest,
                packs: prev.packs.clone(),
            },
            Some(manifest_text),
            AppliedKind::PolicyOnly,
        )
        .map_err(crate::runtime::pack_error)?;
    Ok(generation)
}

/// How one publication attempt landed.
enum PublishResult {
    /// The hub accepted; it now serves this generation.
    Published(u64),
    /// Rejected as a rollback; carries the hub's current floor.
    Conflict(u64),
    /// The hub refused the bundle outright (bad signature, wrong principal
    /// class, …) — distinct from unreachable: retrying the same bytes
    /// cannot succeed. The refusal's reason is narrated into `lines` where
    /// the wire outcome is mapped; the apply loops only need the stop
    /// signal.
    Rejected,
    /// The hub could not be reached (degrade to manual distribution).
    Unreachable,
}

/// A short-lived control credential (realm-anchored hub member principal)
/// materialized into a private temp dir — one minting serves the whole
/// apply round (the hub floor query and the publish), the Drop cleans up.
struct ControlCredential {
    dir: std::path::PathBuf,
    ca: std::path::PathBuf,
    cert: std::path::PathBuf,
    key: std::path::PathBuf,
}

impl ControlCredential {
    fn mint(issuer: &IssuerStore, realm: &str) -> interflow_core::error::Result<Self> {
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
        Ok(Self { dir, ca, cert, key })
    }

    /// Runs one control-plane call on a dedicated thread with its own
    /// runtime so both the CLI (async main) and the GUI (blocking pool)
    /// can drive it synchronously.
    fn call<T, F, Fut>(&self, endpoint: &str, f: F) -> interflow_core::error::Result<T>
    where
        F: FnOnce(String, std::path::PathBuf, std::path::PathBuf, std::path::PathBuf) -> Fut
            + Send
            + 'static,
        Fut: std::future::Future<Output = interflow_core::error::Result<T>> + Send + 'static,
        T: Send + 'static,
    {
        let moved = (
            endpoint.to_owned(),
            self.ca.clone(),
            self.cert.clone(),
            self.key.clone(),
        );
        let handle = std::thread::spawn(move || {
            let rt = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .map_err(|e| {
                    interflow_core::error::InterflowError::config("publish runtime".to_string())
                        .with_source(e)
                })?;
            rt.block_on(f(moved.0, moved.1, moved.2, moved.3))
        });
        handle.join().map_err(|_| {
            interflow_core::error::InterflowError::config(
                "policy publish thread panicked".to_string(),
            )
        })?
    }
}

impl Drop for ControlCredential {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

/// Queries the running hub's policy watermarks — the anti-rollback floor
/// (including absorbed remote-node watermarks) AND the generation it
/// actually serves (the no-op gate's split detector). `None` = unreachable
/// (the caller degrades to local watermarks only).
fn hub_watermarks_with_ephemeral_credential(
    issuer: &IssuerStore,
    realm: &str,
    endpoint: &str,
) -> Option<interflow_mesh::hub::policy::PolicyFloorQuery> {
    if endpoint.is_empty() {
        return None;
    }
    let cred = ControlCredential::mint(issuer, realm).ok()?;
    match cred.call(endpoint, |ep, ca, cert, key| async move {
        interflow_mesh::hub::policy::query_policy_floor(&ep, &ca, &cert, &key).await
    }) {
        Ok(watermarks) => Some(watermarks),
        Err(e) => {
            tracing::debug!("hub policy watermark query failed: {e}");
            None
        }
    }
}

/// Publishes with a freshly minted control credential; maps the wire
/// outcome onto [`PublishResult`] and narrates into `lines`.
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
        let cred = ControlCredential::mint(issuer, realm)?;
        let payload = bytes.to_vec();
        let proof = signature.to_vec();
        cred.call(endpoint, move |ep, ca, cert, key| {
            let bytes = payload;
            let signature = proof;
            async move {
                interflow_mesh::hub::policy::publish_policy(
                    &ep, &ca, &cert, &key, &bytes, &signature,
                )
                .await
            }
        })
    })();
    match outcome {
        Ok(interflow_mesh::hub::policy::PublishOutcome::Published { generation }) => {
            pushln!(
                lines,
                "  published to hub {endpoint} → generation {generation}; online agents hot-apply"
            );
            PublishResult::Published(generation)
        }
        Ok(interflow_mesh::hub::policy::PublishOutcome::RollbackConflict {
            current_generation,
        }) => PublishResult::Conflict(current_generation),
        Ok(interflow_mesh::hub::policy::PublishOutcome::Rejected { status, detail }) => {
            pushln!(
                lines,
                "  hub {endpoint} REFUSED the bundle (HTTP {status}: {detail}) — check the \
                 hub's trust anchor / control principal; falling back to manual distribution"
            );
            PublishResult::Rejected
        }
        Err(e) => {
            pushln!(
                lines,
                "  hub {endpoint} unreachable ({e}) — falling back to manual distribution"
            );
            PublishResult::Unreachable
        }
    }
}

/// Reads the issuer store's current CRL files (`<issuer>/<stem>.crl.pem`,
/// the naming `revoke` writes) — the material the CRL push lane
/// distributes. Empty when no revocation was ever recorded.
fn issuer_crl_material(issuer_dir: &Path) -> std::collections::BTreeMap<String, String> {
    let mut crls = std::collections::BTreeMap::new();
    let Ok(entries) = std::fs::read_dir(issuer_dir) else {
        return crls;
    };
    for entry in entries.flatten() {
        let file_name = entry.file_name();
        let Some(stem) = file_name
            .to_str()
            .and_then(|name| name.strip_suffix(".crl.pem"))
        else {
            continue;
        };
        if let Ok(pem) = std::fs::read_to_string(entry.path()) {
            crls.insert(stem.to_owned(), pem);
        }
    }
    crls
}

/// Pushes the issuer's current CRLs to the hub's `PUT /crls` — the
/// revocation lane's emergency leg. The hub hot-swaps its verification
/// plane onto the pushed set: revoked credentials are rejected on new
/// connections within seconds (no restart) and any live session holding
/// one is evicted. Best-effort with honest narration, exactly like the
/// policy publish.
fn publish_crls_with_ephemeral_credential(
    issuer: &IssuerStore,
    realm: &str,
    endpoint: &str,
    crls: &std::collections::BTreeMap<String, String>,
    lines: &mut Vec<String>,
) {
    use interflow_mesh::hub::crl::PublishCrlsOutcome;
    if endpoint.is_empty() {
        pushln!(
            lines,
            "  this manifest names no hub endpoint — CRL push skipped; the hub picks the \
             revocation up at its next pack install"
        );
        return;
    }
    let outcome = (|| {
        let cred = ControlCredential::mint(issuer, realm)?;
        let payload = crls.clone();
        cred.call(endpoint, move |ep, ca, cert, key| {
            let crls = payload;
            async move {
                interflow_mesh::hub::crl::publish_crls(&ep, &ca, &cert, &key, &crls).await
            }
        })
    })();
    let numbers = |map: &std::collections::BTreeMap<String, u64>| {
        map.iter()
            .map(|(stem, n)| format!("{stem}→{n}"))
            .collect::<Vec<_>>()
            .join(", ")
    };
    match outcome {
        Ok(PublishCrlsOutcome::Applied {
            numbers: map,
            evicted,
        }) => {
            pushln!(
                lines,
                "  pushed CRLs to hub {endpoint} ({}) — the hub rejects the revoked \
                 credentials on new connections now, no restart",
                numbers(&map)
            );
            if !evicted.is_empty() {
                pushln!(
                    lines,
                    "  evicted live session(s) holding revoked credentials: {}",
                    evicted.join(", ")
                );
            }
        }
        Ok(PublishCrlsOutcome::RollbackConflict { current }) => {
            pushln!(
                lines,
                "  hub {endpoint} REFUSED the CRLs as a rollback (its counters: {}) — the \
                 issuer store sits BEHIND the hub; investigate before re-recording",
                numbers(&current)
            );
        }
        Ok(PublishCrlsOutcome::Rejected {
            status: 404,
            detail,
        }) => {
            pushln!(
                lines,
                "  hub {endpoint} has no CRL face (HTTP 404: {detail}) — an older hub \
                 build; enforce via node install + restart, and upgrade the hub to close \
                 the gap"
            );
        }
        Ok(PublishCrlsOutcome::Rejected { status, detail }) => {
            pushln!(
                lines,
                "  hub {endpoint} REFUSED the CRLs (HTTP {status}: {detail}) — check the \
                 hub's trust anchor / control principal"
            );
        }
        Err(e) => {
            pushln!(
                lines,
                "  hub {endpoint} unreachable ({e}) — the revocation is NOT enforced at \
                 the hub yet; re-run revoke with --manifest (or plan apply) once reachable"
            );
        }
    }
}

/// The `generation` field of one policy.toml, tolerant of anything else in
/// the file (a probe, not a parse — corrupt/missing artifacts simply do not
/// contribute to the floor).
#[derive(serde::Deserialize)]
struct GenerationProbe {
    generation: u64,
}

fn policy_toml_generation(path: &std::path::Path) -> Option<u64> {
    let text = std::fs::read_to_string(path).ok()?;
    toml::from_str::<GenerationProbe>(&text)
        .ok()
        .map(|probe| probe.generation)
}

/// The highest policy generation observable in the dist tree — the mint
/// floor's local half. Every artifact is something this operator lineage
/// has already signed and distributed, so minting below any of them
/// manufactures a rollback (2026-10-06 generation-reset fix):
///
/// - `policy/policy.toml` — the last signed update bundle;
/// - `packs/*/policy/policy.toml` — the packs' embedded snapshots;
/// - `packs/*/state/policy/policy.toml` — the node-local channel mirrors,
///   the surviving watermark of record when the issuer store's own
///   bookkeeping has been reset underneath a live fleet.
fn dist_policy_floor(out_root: &Path) -> u64 {
    let mut floor =
        policy_toml_generation(&out_root.join("policy").join("policy.toml")).unwrap_or(0);
    let packs = out_root.join("packs");
    if let Ok(entries) = std::fs::read_dir(&packs) {
        for entry in entries.flatten() {
            let pack_dir = entry.path();
            floor = floor
                .max(
                    policy_toml_generation(&pack_dir.join("policy").join("policy.toml"))
                        .unwrap_or(0),
                )
                .max(
                    policy_toml_generation(
                        &pack_dir.join("state").join("policy").join("policy.toml"),
                    )
                    .unwrap_or(0),
                );
        }
    }
    floor
}

/// The floor the next minted generation must clear: the maximum of every
/// observable watermark — the issuer store's bookkeeping, the dist tree's
/// signed artifacts, and (when reachable) the running hub's anti-rollback
/// floor. `pre_queried_hub` lets a caller that already dialed the hub this
/// round (the no-op gate) reuse its answer instead of dialing again.
/// Returns `(floor, hub_watermarks)`; the hub half is `None` when the hub
/// was unreachable (the caller narrates, minting proceeds on local
/// watermarks — a publish 409 remains the race backstop).
fn policy_mint_floor(
    issuer: &IssuerStore,
    out_root: &Path,
    endpoint: &str,
    realm: &str,
    pre_queried_hub: Option<interflow_mesh::hub::policy::PolicyFloorQuery>,
    lines: &mut Vec<String>,
) -> (u64, Option<interflow_mesh::hub::policy::PolicyFloorQuery>) {
    let bookkeeping = issuer
        .applied_state()
        .map_err(crate::runtime::pack_error)
        .ok()
        .flatten()
        .map_or(0, |state| state.policy_generation);
    let dist_floor = dist_policy_floor(out_root);
    let hub = pre_queried_hub
        .or_else(|| hub_watermarks_with_ephemeral_credential(issuer, realm, endpoint));
    let floor = bookkeeping
        .max(dist_floor)
        .max(hub.as_ref().map_or(0, |w| w.floor));
    if floor > 0 {
        pushln!(
            lines,
            "  policy generation continues above the highest observed watermark {floor} \
             (issuer bookkeeping {bookkeeping}, dist artifacts {dist_floor}, hub floor {}, hub serving {})",
            hub.as_ref()
                .map_or_else(|| "unreachable".to_string(), |w| w.floor.to_string()),
            hub.as_ref().map_or_else(
                || "unreachable".to_string(),
                |w| w
                    .serving
                    .map_or_else(|| "not reported".to_string(), |s| s.to_string())
            )
        );
    }
    (floor, hub)
}

/// The no-op gate's full watermark picture — every dimension a digest match
/// must be cross-checked against before "nothing to do" is true.
///
/// A struct on purpose (the 2026-10-07 blind spot came from a bare
/// parameter list that grew to three of four dimensions: three equal
/// numbers masked the fourth — the hub's actual serving generation):
/// adding a dimension without comparing it is now a structural decision,
/// not a discipline matter.
struct PolicyWatermarks {
    /// The issuer store's bookkeeping generation.
    bookkeeping: u64,
    /// The highest policy generation in the dist tree's signed artifacts.
    dist: u64,
    /// The running hub's answer, when reachable: its anti-rollback floor
    /// (including absorbed remote-node watermarks) and the generation it
    /// actually serves (`serving` may be `None` on an older hub).
    hub: Option<interflow_mesh::hub::policy::PolicyFloorQuery>,
}

/// Why a digest match is NOT a no-op — every divergence shape has a name
/// and its own narration (the re-publish line names what it reconciles).
enum Divergence {
    /// Dist artifacts sit above the bookkeeping: a split the ledger can no
    /// longer see — a node state mirror is the surviving watermark of
    /// record.
    DistAboveBookkeeping { dist: u64, bookkeeping: u64 },
    /// The hub floor moved past the bookkeeping: another operator
    /// published from a different machine.
    HubFloorAhead { floor: u64, bookkeeping: u64 },
    /// The hub floor fell behind the bookkeeping: a hub reinstalled from
    /// an older pack, before any agent re-reported its watermark.
    HubFloorBehind { floor: u64, bookkeeping: u64 },
    /// The hub is SERVING below the bookkeeping while its floor agrees —
    /// the lineage-loss shape (reinstall + watermark absorption: the
    /// absorbed floor masks the lost serving lineage). Three equal numbers
    /// used to hide this fourth one.
    HubServingBehind { serving: u64, bookkeeping: u64 },
}

impl Divergence {
    fn narrate(&self) -> String {
        match *self {
            Self::DistAboveBookkeeping { dist, bookkeeping } => format!(
                "dist artifacts {dist} sit above the issuer bookkeeping {bookkeeping} (a node \
                 state mirror is the surviving watermark of record)"
            ),
            Self::HubFloorAhead { floor, bookkeeping } => format!(
                "hub floor {floor} is ahead of the issuer bookkeeping {bookkeeping} (another \
                 operator published from a different machine)"
            ),
            Self::HubFloorBehind { floor, bookkeeping } => format!(
                "hub floor {floor} is behind the issuer bookkeeping {bookkeeping} (a hub \
                 reinstalled from an older pack)"
            ),
            Self::HubServingBehind {
                serving,
                bookkeeping,
            } => format!(
                "hub is SERVING generation {serving} while the bookkeeping sits at \
                 {bookkeeping} (serving lineage lost — a reinstalled hub whose floor absorbed \
                 the fleet's watermarks)"
            ),
        }
    }
}

/// The gate's verdict on one watermark picture.
enum GateVerdict {
    /// Every observable watermark agrees with the bookkeeping — the digest
    /// match is a genuine no-op.
    NoOp,
    /// A divergence needs a re-publish above the watermarks to reconcile
    /// (minting at max(watermarks)+1 lands above every dimension,
    /// including `serving` — publication converges the split).
    Republish(Divergence),
}

const fn policy_no_op_verdict(w: &PolicyWatermarks) -> GateVerdict {
    if w.dist > w.bookkeeping {
        return GateVerdict::Republish(Divergence::DistAboveBookkeeping {
            dist: w.dist,
            bookkeeping: w.bookkeeping,
        });
    }
    // An unreachable hub contributes no signal; dist artifacts merely
    // trailing the bookkeeping (the manual-distribution mirror behind a
    // live hub) leave the fleet correctly served, so neither opens the
    // gate.
    let Some(hub) = w.hub else {
        return GateVerdict::NoOp;
    };
    if hub.floor > w.bookkeeping {
        return GateVerdict::Republish(Divergence::HubFloorAhead {
            floor: hub.floor,
            bookkeeping: w.bookkeeping,
        });
    }
    if hub.floor < w.bookkeeping {
        return GateVerdict::Republish(Divergence::HubFloorBehind {
            floor: hub.floor,
            bookkeeping: w.bookkeeping,
        });
    }
    // The floor agrees — now the dimension the floor used to mask: what
    // the hub actually serves. `None` (an older hub that cannot report
    // serving) contributes no signal.
    if let Some(serving) = hub.serving
        && serving < w.bookkeeping
    {
        return GateVerdict::Republish(Divergence::HubServingBehind {
            serving,
            bookkeeping: w.bookkeeping,
        });
    }
    GateVerdict::NoOp
}

/// The pack directories THIS manifest would render, sorted — the shared
/// enumeration of the gate's tree probes (format freshness, trust
/// freshness).
fn expected_pack_dirs(manifest: &Manifest) -> Vec<String> {
    let mut expected: Vec<String> = Vec::new();
    for node in manifest.mesh.hub.keys() {
        expected.push(format!("hub-{node}"));
    }
    for node in manifest.ingress.keys() {
        expected.push(format!("ingress-{node}"));
    }
    for node in manifest.agent.keys() {
        expected.push(format!("agent-{node}"));
    }
    expected.sort();
    expected
}

/// The apply gate's pack-tree probe: walks the pack directories THIS
/// manifest would render and reports the first one that is not in the
/// current pack format. "Already applied" is a claim about the observable
/// output tree — a pack the strict loader would refuse (a retired vintage,
/// a damaged pack.toml, a wiped dist) means the tree is not applied,
/// whatever the bookkeeping remembers, so the manifest "unchanged" branch
/// must not short-circuit. Packs of nodes no longer in the manifest are
/// deliberately not probed: apply does not render them, and their vintage
/// must not block a legitimate no-op.
fn stale_pack_in_tree(out_root: &Path, manifest: &Manifest) -> Option<(String, PackTreeStale)> {
    expected_pack_dirs(manifest).into_iter().find_map(|dir| {
        probe_pack_format(&out_root.join("packs").join(&dir)).map(|reason| (dir, reason))
    })
}

/// Why the gate's trust-freshness probe called a pack's embedded
/// revocation snapshot stale.
#[derive(Debug, Clone, PartialEq, Eq)]
enum TrustSnapshotStale {
    /// The pack carries no `trust/crls/<stem>.crl.pem` for an issuer the
    /// deny list holds entries under.
    MissingCrl { issuer: String },
    /// The embedded CRL parses but does not revoke a serial the deny list
    /// attributes to its issuer — a revoke moved after this pack rendered.
    SerialNotEmbedded { issuer: String, serial: String },
    /// The embedded CRL failed to read or parse — a damaged snapshot
    /// re-renders (self-heal) rather than failing the gate.
    UnreadableCrl { issuer: String, detail: String },
}

impl TrustSnapshotStale {
    fn narrate(&self) -> String {
        match self {
            Self::MissingCrl { issuer } => {
                format!("no embedded CRL for {issuer} while the deny list holds entries")
            }
            Self::SerialNotEmbedded { issuer, serial } => format!(
                "issuer {issuer} revoked serial {serial} after this pack rendered — the \
                 snapshot predates the revoke"
            ),
            Self::UnreadableCrl { issuer, detail } => {
                format!("the embedded CRL for {issuer} is unreadable ({detail})")
            }
        }
    }
}

/// The apply gate's trust-freshness probe: the issuer's deny list vs the
/// CRL snapshot each rendered pack embeds. "Already applied" is also a
/// claim about the TRUST face — a revoke that moved the deny list after
/// the packs were rendered leaves every node still admitting the revoked
/// credential, whatever the policy bookkeeping remembers, so the
/// manifest-unchanged branch must not short-circuit.
///
/// The comparison is semantic (does each pack's embedded CRL revoke every
/// deny-list serial of its issuer), never bytewise: an embedded CRL is
/// re-signed with fresh timestamps at every render, so equal bytes are
/// impossible even in perfect sync. Registrar-tier deployments read their
/// CRL from the live `state/crls` lane instead and are not probed.
fn stale_trust_snapshot_in_tree(
    issuer_dir: &Path,
    out_root: &Path,
    manifest: &Manifest,
) -> interflow_core::error::Result<Option<(String, TrustSnapshotStale)>> {
    use interflow_identity::revocation::crl_revokes_serial;
    if manifest.identity.mode != interflow_identity::manifest::IdentityMode::Offline {
        return Ok(None);
    }
    let list = RevocationList::load(issuer_dir).map_err(crate::runtime::pack_error)?;
    if list.entries.is_empty() {
        return Ok(None);
    }
    let mut by_issuer: std::collections::BTreeMap<String, Vec<&RevocationEntry>> =
        std::collections::BTreeMap::new();
    for entry in &list.entries {
        by_issuer
            .entry(entry.issuer.clone())
            .or_default()
            .push(entry);
    }
    for dir in expected_pack_dirs(manifest) {
        let pack = out_root.join("packs").join(&dir);
        for (issuer_name, entries) in &by_issuer {
            let crl_path = pack
                .join("trust")
                .join("crls")
                .join(format!("{}.crl.pem", issuer_name.replace('/', "-")));
            let Ok(text) = std::fs::read_to_string(&crl_path) else {
                return Ok(Some((
                    dir,
                    TrustSnapshotStale::MissingCrl {
                        issuer: issuer_name.clone(),
                    },
                )));
            };
            for entry in entries {
                match crl_revokes_serial(&text, &entry.serial) {
                    Ok(Some(true)) => {}
                    Ok(_) => {
                        return Ok(Some((
                            dir,
                            TrustSnapshotStale::SerialNotEmbedded {
                                issuer: issuer_name.clone(),
                                serial: entry.serial.clone(),
                            },
                        )));
                    }
                    Err(e) => {
                        return Ok(Some((
                            dir,
                            TrustSnapshotStale::UnreadableCrl {
                                issuer: issuer_name.clone(),
                                detail: e.to_string(),
                            },
                        )));
                    }
                }
            }
        }
    }
    Ok(None)
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
            let store_id = issuer
                .store_uuid()
                .map_err(crate::runtime::pack_error)?
                .unwrap_or_default();
            pushln!(
                lines,
                "  issuer store {} bound to realm {} (manifest {})",
                store_id,
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
                pushln!(
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
# Edit, then run: interflow-cli plan apply
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
# quic_listen = "0.0.0.0:16666"  # optional QUIC (UDP) face for the control endpoint

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
/// promptcn mesh deployment manifest (live copy at
/// `~/interflow-deployments/promptcn-mesh/interflow.toml`).
pub fn setup_mesh_template(realm: &str, hub_name: &str, hub_endpoint: &str) -> String {
    format!(
        r#"# Interflow site-to-site mesh manifest — the single source of truth.
# Add agents (see below), then run: interflow-cli plan apply
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
# quic_listen = "0.0.0.0:6666"  # optional QUIC (UDP) face; same port number
#                                # as listen, different stack. Agents opt in
#                                # per node: transport = "quic" under [agent.*]
endpoint = "{hub_endpoint}"

[workspace.main]

# The manifest needs at least one agent before `plan apply` — add yours:
#   service side:  interflow-cli node add agent/<name> --mesh-egress <rule>:127.0.0.1:8080
#   connect side:  interflow-cli node add agent/<name> --mesh-ingress <rule>:127.0.0.1:8080:127.0.0.1:8080@<peer>
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
    pushln!(
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
        pushln!(lines, "  route {} → {}", route.host, route.service);
    }
    for (agent, cfg) in &manifest.agent {
        for rule in &cfg.mesh_ingress {
            pushln!(
                lines,
                "  mesh    {agent}/{} → {} at {}",
                rule.name,
                rule.target_agent,
                rule.remote_addr
            );
        }
        for rule in &cfg.mesh_egress {
            pushln!(
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
        PublicTlsMode::Acme => pushln!(lines, "  public TLS: ACME (automatic)"),
        PublicTlsMode::FrontendProxy => {
            pushln!(lines, "  public TLS: frontend proxy (config rendered)");
        }
        PublicTlsMode::Manual => pushln!(lines, "  public TLS: manual (expert)"),
    }
    Ok(lines)
}

/// What one `apply` landed on.
///
/// The human-readable report lines (what the CLI prints verbatim) plus the
/// structured outcome the GUI's Deploy face renders directly (the
/// minted/current generation behind its Apply-result card; every Ok path
/// lands on exactly one).
#[derive(Debug, Clone)]
pub struct ApplyReport {
    pub lines: Vec<String>,
    /// The policy generation this apply minted — or, on a no-op, the live
    /// generation it confirmed.
    pub generation: u64,
}

/// The bookkeeping-level pre-check behind the GUI's "unapplied changes"
/// face.
///
/// Compare the manifest against the issuer store's applied state, WITHOUT
/// minting or dialing anything (apply re-runs the full watermark-aware
/// funnel; this answers only "would apply do anything, and which kind").
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChangeState {
    /// No applied state in this issuer store — the first apply performs a
    /// full render.
    NeverApplied,
    /// The manifest matches the applied state exactly (`generation` is the
    /// live bookkeeping generation).
    Applied { generation: u64 },
    /// Only the policy face moved (mesh rules, services, routes, idle
    /// budgets) — the next apply takes the policy-only fast path; every
    /// node kind hot-applies within a watcher period.
    PolicyEditsPending,
    /// The identity/trust/dial face changed — the next apply re-renders
    /// every pack.
    IdentityEditsPending,
}

/// Computes [`ChangeState`] for one manifest against one issuer store.
pub fn change_state(
    manifest_path: &Path,
    issuer_dir: &Path,
) -> interflow_core::error::Result<ChangeState> {
    let manifest = Manifest::load(manifest_path).map_err(crate::runtime::pack_error)?;
    let issuer = IssuerStore::open(issuer_dir);
    let Some(prev) = issuer.applied_state().map_err(crate::runtime::pack_error)? else {
        return Ok(ChangeState::NeverApplied);
    };
    let stripped_now = stripped_manifest_digest(&manifest)?;
    if prev.stripped_manifest_digest != stripped_now {
        return Ok(ChangeState::IdentityEditsPending);
    }
    let candidate = RuntimePolicy::from_manifest(&manifest, prev.policy_generation);
    let candidate_digest = format!(
        "sha256:{}",
        interflow_util::sha256_hex(&candidate.to_bytes().map_err(crate::runtime::pack_error)?)
    );
    if candidate_digest == prev.policy_digest {
        Ok(ChangeState::Applied {
            generation: prev.policy_generation,
        })
    } else {
        Ok(ChangeState::PolicyEditsPending)
    }
}

/// The drift view — `plan diff`, the declaration-vs-applied review face
/// (the same shape `kubectl diff` answers for submitted-vs-live).
///
/// The classification ([`change_state`]) headlines; the body is a line
/// diff of the declaration against the exact text the last apply
/// snapshotted, so what the next `plan apply` would change reads line by
/// line before anything is minted. Stores whose applied state predates
/// snapshots (absorbed from the legacy `applied.json`) classify but carry
/// no text to diff — one apply records the baseline.
pub fn diff(manifest_path: &Path, issuer_dir: &Path) -> interflow_core::error::Result<Vec<String>> {
    let mut lines = Vec::new();
    let state = change_state(manifest_path, issuer_dir)?;
    match state {
        ChangeState::NeverApplied => {
            pushln!(
                lines,
                "never applied — the next `plan apply` performs the full first render"
            );
            return Ok(lines);
        }
        ChangeState::Applied { generation } => pushln!(
            lines,
            "the declaration matches the applied state (policy generation {generation}) — \
             nothing to apply"
        ),
        ChangeState::PolicyEditsPending => pushln!(
            lines,
            "policy-face edits pending — the next `plan apply` takes the policy-only fast \
             path (no pack re-rendered, no identity re-signed)"
        ),
        ChangeState::IdentityEditsPending => pushln!(
            lines,
            "identity-face edits pending — the next `plan apply` re-renders every pack"
        ),
    }
    let issuer = IssuerStore::open(issuer_dir);
    let Some(applied_text) = issuer
        .applied_manifest_text()
        .map_err(crate::runtime::pack_error)?
    else {
        pushln!(
            lines,
            "no declaration snapshot exists for the applied state (it predates snapshots) — \
             apply once to record the drift baseline"
        );
        return Ok(lines);
    };
    let current = std::fs::read_to_string(manifest_path)
        .map_err(interflow_core::error::InterflowError::Io)?;
    let text_diff = similar::TextDiff::from_lines(&applied_text, &current);
    let mut buf = Vec::new();
    {
        let mut unified = text_diff.unified_diff();
        unified.context_radius(3).header("applied", "declaration");
        unified.to_writer(&mut buf)?;
    }
    let body: Vec<String> = String::from_utf8_lossy(&buf)
        .lines()
        .map(str::to_owned)
        .collect();
    if body.is_empty() {
        pushln!(lines, "no textual drift against the applied declaration");
    } else {
        lines.extend(body);
    }
    Ok(lines)
}

/// Lists the hub's stream-proposal queue (the operator's approve/reject
/// face) with a minted control credential. `None` = the manifest names no
/// hub endpoint.
pub fn list_proposals(
    manifest_path: &Path,
    issuer_dir: &Path,
) -> interflow_core::error::Result<Option<Vec<interflow_mesh::hub::proposals::ControlProposal>>> {
    let manifest = Manifest::load(manifest_path).map_err(crate::runtime::pack_error)?;
    let endpoint = manifest_hub_endpoint(&manifest);
    if endpoint.is_empty() {
        return Ok(None);
    }
    let issuer = IssuerStore::open(issuer_dir);
    issuer.ensure_realm().map_err(crate::runtime::pack_error)?;
    let cred = ControlCredential::mint(&issuer, &manifest.realm.id)?;
    let list = cred.call(&endpoint, |ep, ca, cert, key| async move {
        interflow_mesh::hub::proposals::list_proposals(&ep, &ca, &cert, &key).await
    })?;
    Ok(Some(list))
}

/// Records the operator's rejection at the hub (the requester's GUI shows
/// the reason as its receipt).
pub fn reject_proposal(
    manifest_path: &Path,
    issuer_dir: &Path,
    id: &str,
    reason: &str,
) -> interflow_core::error::Result<()> {
    let manifest = Manifest::load(manifest_path).map_err(crate::runtime::pack_error)?;
    let endpoint = manifest_hub_endpoint(&manifest);
    if endpoint.is_empty() {
        return Err(interflow_core::error::InterflowError::config(
            "the manifest names no hub endpoint — nowhere to record the rejection".to_string(),
        ));
    }
    let issuer = IssuerStore::open(issuer_dir);
    issuer.ensure_realm().map_err(crate::runtime::pack_error)?;
    let cred = ControlCredential::mint(&issuer, &manifest.realm.id)?;
    let id = id.to_owned();
    let reason = reason.to_owned();
    cred.call(&endpoint, move |ep, ca, cert, key| async move {
        interflow_mesh::hub::proposals::reject_proposal(&ep, &ca, &cert, &key, &id, &reason).await
    })?;
    Ok(())
}

/// The APPROVE orchestration — one function the GUI Deploy face and the
/// CLI `proposals approve` both drive.
///
/// kube-CSR shape: the decision is the operator's; the manifest stays the
/// single source of truth:
///
/// 1. fetch the proposal (its rule + requester) from the hub's queue;
/// 2. apply the SAME pure edit the form editor applies
///    (`UpsertMeshIngress` on the requester's agent section — skipped
///    when an identical rule is already in place, e.g. a re-approve
///    after a crashed notify);
/// 3. refuse if the edit introduces new issues (the funnel's phrasing);
/// 4. save (`.bak` + atomic) — the one write path;
/// 5. `apply` — the ordinary mint + publish, whose watermark-aware no-op
///    gate makes a double-approve harmless;
/// 6. record the decision at the hub (carrying the minted generation).
pub fn approve_proposal(
    manifest_path: &Path,
    issuer_dir: &Path,
    out_root: &Path,
    id: &str,
    allow_shared: bool,
) -> interflow_core::error::Result<ApplyReport> {
    let manifest_before = Manifest::load(manifest_path).map_err(crate::runtime::pack_error)?;
    let endpoint = manifest_hub_endpoint(&manifest_before);
    if endpoint.is_empty() {
        return Err(interflow_core::error::InterflowError::config(
            "the manifest names no hub endpoint — nowhere to read the proposal from".to_string(),
        ));
    }
    let issuer = IssuerStore::open(issuer_dir);
    issuer.ensure_realm().map_err(crate::runtime::pack_error)?;

    // 1. The proposal (and its decision state).
    let id = id.to_owned();
    let proposal = {
        let cred = ControlCredential::mint(&issuer, &manifest_before.realm.id)?;
        let list = cred.call(&endpoint, move |ep, ca, cert, key| async move {
            interflow_mesh::hub::proposals::list_proposals(&ep, &ca, &cert, &key).await
        })?;
        list.into_iter().find(|p| p.id == id).ok_or_else(|| {
            interflow_core::error::InterflowError::config(format!(
                "proposal {id} does not exist (expired or already cleared)"
            ))
        })?
    };
    if proposal.status != interflow_mesh::hub::proposals::StoredStatus::Pending {
        return Err(interflow_core::error::InterflowError::config(format!(
            "proposal {id} is already decided: {:?}",
            proposal.status
        )));
    }
    let requester_agent = proposal
        .requester
        .rsplit('/')
        .next()
        .unwrap_or(&proposal.requester)
        .to_owned();

    // 2. The same pure edit the form editor applies. The freshness token
    // captured here rides to the save — an editor saving over this file
    // mid-approval surfaces as a conflict, not a clobber.
    let document = crate::manifest_edit::read_manifest(manifest_path)?;
    let text = document.text;
    let issues_before = crate::manifest_edit::summarize(&text)
        .map(|s| s.issues)
        .unwrap_or_default();
    let rule = &proposal.rule;
    let protocol = match rule.protocol {
        interflow_core::tunnel::transport::StreamProtoWire::Tcp => {
            interflow_identity::manifest::MeshProtocol::Tcp
        }
        interflow_core::tunnel::transport::StreamProtoWire::Udp => {
            interflow_identity::manifest::MeshProtocol::Udp
        }
    };
    let already_live = manifest_before
        .agent
        .get(&requester_agent)
        .is_some_and(|cfg| {
            cfg.mesh_ingress.iter().any(|r| {
                r.name == rule.name
                    && r.listen == rule.listen
                    && r.protocol == protocol
                    && r.target_agent == rule.target_agent
                    && r.remote_addr == rule.remote_addr
                    && r.idle_timeout_secs == rule.idle_timeout_secs
            })
        });
    let next_text = if already_live {
        text
    } else {
        crate::manifest_edit::apply_edit(
            &text,
            &crate::manifest_edit::ManifestEdit::UpsertMeshIngress(
                crate::manifest_edit::MeshIngressEdit {
                    agent: requester_agent,
                    name: rule.name.clone(),
                    listen: rule.listen.clone(),
                    protocol,
                    target_agent: rule.target_agent.clone(),
                    remote_addr: rule.remote_addr.clone(),
                    idle_timeout_secs: rule.idle_timeout_secs,
                },
            ),
        )?
    };

    // 3. No new issues may ride the approval.
    let issues_after = crate::manifest_edit::summarize(&next_text)
        .map(|s| s.issues)
        .unwrap_or_default();
    let new_issues: Vec<String> = issues_after
        .iter()
        .filter(|i| !issues_before.contains(i))
        .cloned()
        .collect();
    if !new_issues.is_empty() {
        return Err(interflow_core::error::InterflowError::config(format!(
            "approving proposal {id} would leave the manifest invalid: {}",
            new_issues.join("; ")
        )));
    }

    // 4. The one write path, then 5. the ordinary apply (default backup
    // init: an already-configured store passes through silently).
    if !already_live {
        crate::manifest_edit::save_manifest(manifest_path, &next_text, Some(&document.digest))?;
    }
    let report = apply(
        manifest_path,
        issuer_dir,
        out_root,
        allow_shared,
        &BackupInitOptions::default(),
        false,
    )?;

    // 6. Record the decision (idempotent at the hub; a failed notify
    // leaves the proposal pending — re-approving re-runs a no-op apply).
    let cred = ControlCredential::mint(&issuer, &manifest_before.realm.id)?;
    cred.call(&endpoint, move |ep, ca, cert, key| async move {
        interflow_mesh::hub::proposals::approve_proposal(
            &ep,
            &ca,
            &cert,
            &key,
            &id,
            report.generation,
        )
        .await
    })?;
    Ok(report)
}

/// Queries the running hub's operator overview (watermarks + the fleet's
/// presence/pull convergence) with a freshly minted control credential.
///
/// The GUI Deploy face's Apply-result/convergence card and the fleet
/// table's online column render from this. `None` = the manifest names no
/// hub endpoint (nothing to ask).
pub fn hub_overview(
    manifest_path: &Path,
    issuer_dir: &Path,
) -> interflow_core::error::Result<Option<interflow_mesh::hub::policy::HubOverview>> {
    Ok(
        with_hub_control_credential(manifest_path, issuer_dir, |ep, ca, cert, key| async move {
            interflow_mesh::hub::policy::query_hub_overview(&ep, &ca, &cert, &key).await
        })?
        .map(|(_, overview)| overview),
    )
}

/// The shared plumbing behind every CLI operator query against a running
/// hub.
///
/// Load the manifest, mint a throwaway control credential from the issuer
/// store, run one query on the credential's dedicated runtime. Returns
/// `(hub_endpoint, query_result)` — the endpoint rides along so persisted
/// artifacts (the steady-state snapshot among them) record WHERE the
/// picture was captured. `None` = the manifest names no hub endpoint.
pub fn with_hub_control_credential<T, F, Fut>(
    manifest_path: &Path,
    issuer_dir: &Path,
    query: F,
) -> interflow_core::error::Result<Option<(String, T)>>
where
    F: FnOnce(String, PathBuf, PathBuf, PathBuf) -> Fut + Send + 'static,
    Fut: std::future::Future<Output = interflow_core::error::Result<T>> + Send + 'static,
    T: Send + 'static,
{
    let manifest = Manifest::load(manifest_path).map_err(crate::runtime::pack_error)?;
    let endpoint = manifest_hub_endpoint(&manifest);
    if endpoint.is_empty() {
        return Ok(None);
    }
    let issuer = IssuerStore::open(issuer_dir);
    issuer.ensure_realm().map_err(crate::runtime::pack_error)?;
    let cred = ControlCredential::mint(&issuer, &manifest.realm.id)?;
    let out = cred.call(&endpoint, query)?;
    Ok(Some((endpoint, out)))
}

/// How `plan apply` initializes the issuer-store backup on first touch of
/// an unconfigured store (`--no-issuer-backup` skips everything).
#[derive(Clone, Default)]
pub struct BackupInitOptions {
    /// Leave the store unbacked (CI, throwaway stores) — `doctor issuer`
    /// keeps flagging it.
    pub skip: bool,
    /// Encrypt to this age recipient (`age1...`) instead of generating a
    /// new offline identity — for operators who pre-generate their key.
    pub recipient: Option<String>,
    /// Directory versioned backups land in (default: `<issuer>-backups`).
    pub backup_dir: Option<PathBuf>,
    /// Also write the one-time generated identity to this path (e.g. a
    /// mounted USB stick) instead of only printing it.
    pub identity_out: Option<PathBuf>,
}

/// One-time backup setup for a store that has none. Already-configured
/// stores pass through silently — this runs on every apply, costs one
/// `backup.json` read, and only acts the first time (or the first time
/// after an operator opted out).
fn ensure_backup_configured(
    issuer_dir: &Path,
    opts: &BackupInitOptions,
    lines: &mut Vec<String>,
) -> interflow_core::error::Result<()> {
    use interflow_identity::backup as store_backup;
    if opts.skip {
        return Ok(());
    }
    if store_backup::config(issuer_dir)
        .map_err(crate::runtime::pack_error)?
        .is_some()
    {
        return Ok(());
    }
    let backup_dir = opts
        .backup_dir
        .clone()
        .unwrap_or_else(|| store_backup::default_backup_dir(issuer_dir));
    // The returned config carries the canonicalized backup dir — the one
    // absolute location every later run from any CWD will use; that is
    // what gets announced, not the input path.
    let (cfg, generated) = if let Some(recipient) = &opts.recipient {
        let cfg = store_backup::configure(
            issuer_dir,
            recipient,
            &backup_dir,
            store_backup::DEFAULT_RETENTION,
        )
        .map_err(crate::runtime::pack_error)?;
        (cfg, None)
    } else {
        let identity = store_backup::generate_identity().map_err(crate::runtime::pack_error)?;
        let cfg = store_backup::configure(
            issuer_dir,
            &identity.recipient,
            &backup_dir,
            store_backup::DEFAULT_RETENTION,
        )
        .map_err(crate::runtime::pack_error)?;
        (cfg, Some(identity))
    };
    pushln!(
        lines,
        "✔ issuer store backup configured — every change now checkpoints an encrypted, \
         versioned copy to {}",
        cfg.backup_dir.display()
    );
    if let Some(identity) = generated {
        pushln!(
            lines,
            "  ┌─ ONE-TIME RECOVERY IDENTITY — store it OFFLINE (password manager / printed) ─┐"
        );
        pushln!(lines, "  │ {}", identity.secret);
        pushln!(
            lines,
            "  │ It is the ONLY key that can restore backups. It is never stored on this"
        );
        pushln!(
            lines,
            "  │ machine; losing it makes every backup permanently unreadable."
        );
        pushln!(
            lines,
            "  └──────────────────────────────────────────────────────────────────────────┘"
        );
        if let Some(out) = &opts.identity_out {
            interflow_util::atomic_write(
                out,
                format!("{}\n", identity.secret).as_bytes(),
                interflow_util::WriteMode::Set(0o600),
            )?;
            pushln!(
                lines,
                "  recovery identity also written to {} (0600) — move that medium offline",
                out.display()
            );
        }
    }
    Ok(())
}

pub fn apply(
    manifest_path: &Path,
    issuer_dir: &Path,
    out_root: &Path,
    allow_shared: bool,
    backup: &BackupInitOptions,
    force_rerender: bool,
) -> interflow_core::error::Result<ApplyReport> {
    let mut lines = Vec::new();
    // One read feeds both the parsed struct and the declaration snapshot
    // recorded with the applied state — the two cannot diverge mid-apply.
    let manifest_text = std::fs::read_to_string(manifest_path)
        .map_err(interflow_core::error::InterflowError::from)?;
    let manifest = Manifest::parse(&manifest_text).map_err(crate::runtime::pack_error)?;
    enforce_store_binding(
        issuer_dir,
        &manifest,
        manifest_path,
        allow_shared,
        &mut lines,
    )?;
    // The issuer store is the deployment's entire signing capability — set
    // up its automatic backup BEFORE creating any material, so the very
    // first CA is captured by the very first checkpoint.
    ensure_backup_configured(issuer_dir, backup, &mut lines)?;
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
    if force_rerender {
        pushln!(
            lines,
            "⚠ --force-rerender: the no-op gate is skipped — every pack re-renders above the \
             watermarks (generation continuity preserved)"
        );
    } else if let Some(prev) = issuer.applied_state().map_err(crate::runtime::pack_error)?
        && prev.stripped_manifest_digest == stripped_now
    {
        // Pack-tree freshness (2026-10-12 fix): a digest match plus agreeing
        // watermarks still says nothing about the PACK format vintage. A
        // stale pack tree (retired format, missing pack.toml) is not
        // "applied" in any useful sense — and the policy-only path would
        // leave it stale forever. Fall through to the full render, which
        // re-renders every pack above the watermarks; the fresh tree then
        // converges back to no-ops.
        if let Some((pack_dir, reason)) = stale_pack_in_tree(out_root, &manifest) {
            pushln!(
                lines,
                "✔ manifest unchanged, but packs/{pack_dir} is stale — {} — re-rendering every \
                 pack above the watermarks to the current format",
                reason.narrate()
            );
        } else if let Some((pack_dir, reason)) =
            stale_trust_snapshot_in_tree(issuer_dir, out_root, &manifest)?
        {
            // The trust twin of the format probe above: a revoke that moved
            // the deny list since the packs rendered means the tree is not
            // "applied" in any security sense — fall through to the full
            // render so every pack re-embeds the current CRL snapshot (the
            // hub, if reachable, additionally receives the push below).
            pushln!(
                lines,
                "✔ manifest unchanged, but packs/{pack_dir} carries a stale trust snapshot — \
                 {} — re-rendering every pack so trust/crls/ picks up the issuer's current \
                 deny list",
                reason.narrate()
            );
        } else {
            let candidate = RuntimePolicy::from_manifest(&manifest, prev.policy_generation);
            let candidate_digest = format!(
                "sha256:{}",
                interflow_util::sha256_hex(
                    &candidate.to_bytes().map_err(crate::runtime::pack_error)?
                )
            );
            if candidate_digest == prev.policy_digest {
                // Watermark-aware no-op gate (2026-10-06 fix): a digest match
                // alone no longer proves "applied" — the bookkeeping may sit
                // below a split it cannot see (node state mirrors, a
                // reinstalled hub, another operator's higher publish). Only
                // when EVERY observable watermark — including, since the
                // 2026-10-07 fix, what the hub actually SERVES — agrees with
                // the bookkeeping is this a true no-op; otherwise the same
                // manifest is re-published ABOVE the watermarks — exactly what
                // the hub's inverted-watermark WARN tells the operator to do
                let endpoint = manifest_hub_endpoint(&manifest);
                let watermarks = PolicyWatermarks {
                    bookkeeping: prev.policy_generation,
                    dist: dist_policy_floor(out_root),
                    hub: hub_watermarks_with_ephemeral_credential(
                        &issuer,
                        &manifest.realm.id,
                        &endpoint,
                    ),
                };
                match policy_no_op_verdict(&watermarks) {
                    GateVerdict::NoOp => {
                        pushln!(
                            lines,
                            "✔ manifest already applied — policy generation {} is live, nothing to do",
                            prev.policy_generation
                        );
                        if !endpoint.is_empty() && watermarks.hub.is_none() {
                            pushln!(
                                lines,
                                "  hub {endpoint} unreachable — its serving generation was not \
                                 verified; re-run apply once the hub is reachable"
                            );
                        } else if watermarks.hub.is_some_and(|hub| hub.serving.is_none()) {
                            pushln!(
                                lines,
                                "  hub {endpoint} did not report its serving generation (an older \
                                 hub build) — serving was not verified; upgrade the hub to close \
                                 the gap"
                            );
                        }
                        return Ok(ApplyReport {
                            lines,
                            generation: prev.policy_generation,
                        });
                    }
                    GateVerdict::Republish(divergence) => {
                        pushln!(
                            lines,
                            "✔ manifest unchanged, but the watermarks diverge from the issuer \
                             bookkeeping (bookkeeping {}, dist artifacts {}, hub floor {}, hub \
                             serving {}) — {} — re-publishing above the watermarks to reconcile",
                            watermarks.bookkeeping,
                            watermarks.dist,
                            watermarks.hub.map_or_else(
                                || "unreachable".to_string(),
                                |hub| hub.floor.to_string()
                            ),
                            watermarks.hub.map_or_else(
                                || "unreachable".to_string(),
                                |hub| hub
                                    .serving
                                    .map_or_else(|| "not reported".to_string(), |s| s.to_string())
                            ),
                            divergence.narrate()
                        );
                        let generation = apply_policy_only(
                            &issuer,
                            &manifest,
                            &manifest_text,
                            &prev,
                            out_root,
                            watermarks.hub,
                            &mut lines,
                        )?;
                        return Ok(ApplyReport { lines, generation });
                    }
                }
            }
            let generation = apply_policy_only(
                &issuer,
                &manifest,
                &manifest_text,
                &prev,
                out_root,
                None,
                &mut lines,
            )?;
            return Ok(ApplyReport { lines, generation });
        }
    }

    // Generation continuity (2026-10-06 fix): the identity face changed, so
    // every pack re-renders — but the policy generation RIDES ON, minted
    // above every observable watermark (issuer bookkeeping, the dist tree's
    // signed artifacts — including the node state mirrors — and the running
    // hub's floor). The former hard reset to 1 froze every online agent
    // holding a higher watermark: anti-rollback refused all subsequent
    // policies, silently.
    let endpoint = manifest_hub_endpoint(&manifest);
    let (floor, _) = policy_mint_floor(
        &issuer,
        out_root,
        &endpoint,
        &manifest.realm.id,
        None,
        &mut lines,
    );
    let mut render_generation = floor + 1;
    let mut published = false;
    let mut rendered_packs = Vec::new();
    for attempt in 0..2 {
        rendered_packs.clear();
        for node in manifest.mesh.hub.keys() {
            let out = out_root.join("packs").join(format!("hub-{node}"));
            let pack = HubCredentialPack::render(&issuer, &manifest, node, render_generation, &out)
                .map_err(crate::runtime::pack_error)?;
            rendered_packs.push(pack);
        }
        for node in manifest.ingress.keys() {
            let out = out_root.join("packs").join(format!("ingress-{node}"));
            let pack =
                IngressCredentialPack::render(&issuer, &manifest, node, render_generation, &out)
                    .map_err(crate::runtime::pack_error)?;
            rendered_packs.push(pack);
        }
        for node in manifest.agent.keys() {
            let out = out_root.join("packs").join(format!("agent-{node}"));
            let pack =
                AgentCredentialPack::render(&issuer, &manifest, node, render_generation, &out)
                    .map_err(crate::runtime::pack_error)?;
            rendered_packs.push(pack);
        }
        // Deployment artifacts: per-node units, the registrar unit (registrar
        // deployments), frontend-proxy nginx fragments and the bootstrap
        // script — all derived from the manifest (render.rs owns the layout
        // convention). Idempotent writes: a conflict re-render rewrites them.
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

        // Mirror the render-generation bundle into dist/policy: the manual
        // distribution channel must never trail what the packs embed.
        let policy = RuntimePolicy::from_manifest(&manifest, render_generation);
        let (policy_bytes, policy_signature) = policy
            .signed(&issuer.policy_signer().map_err(crate::runtime::pack_error)?)
            .map_err(crate::runtime::pack_error)?;
        let bundle_dir = out_root.join("policy");
        std::fs::create_dir_all(&bundle_dir).map_err(interflow_core::error::InterflowError::Io)?;
        std::fs::write(bundle_dir.join("policy.toml"), &policy_bytes)
            .map_err(interflow_core::error::InterflowError::Io)?;
        std::fs::write(bundle_dir.join("policy.sig"), &policy_signature)
            .map_err(interflow_core::error::InterflowError::Io)?;

        // Publish: the identity change's policy face reaches every online
        // agent within one watch interval (≤10s); the pack swap that
        // follows carries only the identity face. One distribution rhythm,
        // both faces.
        match publish_with_ephemeral_credential(
            &issuer,
            &manifest.realm.id,
            &endpoint,
            &policy_bytes,
            &policy_signature,
            &mut lines,
        ) {
            PublishResult::Published(accepted) => {
                render_generation = accepted;
                published = true;
                break;
            }
            PublishResult::Conflict(hub_floor) if attempt == 0 => {
                pushln!(
                    lines,
                    "  hub floor is generation {hub_floor} (advanced since the pre-flight                      query) — re-rendering packs at {} and retrying",
                    hub_floor + 1
                );
                render_generation = hub_floor + 1;
            }
            // Second conflict, an outright refusal, or an unreachable hub:
            // narrated by the publish helper; the packs + dist/policy mirror
            // stand for manual distribution.
            PublishResult::Conflict(_) | PublishResult::Rejected | PublishResult::Unreachable => {
                break;
            }
        }
    }
    if !published {
        pushln!(
            lines,
            "  manual distribution: copy {}/policy.toml + policy.sig into every node's              <pack>/state/policy/ (the reload watcher applies them, ≤10s)",
            out_root.join("policy").display()
        );
    }
    // Close the staging windows this render supersedes: the bases now sit at
    // `render_generation`, minted above every staging watermark (the floor
    // scans them), so every surviving `-genN` directory of the rendered
    // nodes is strictly older than its base — the same janitor rotate runs
    // at its close. Until 0.11.x apply re-rendered the bases and forgot the
    // staging family entirely, which is exactly how consumed shells
    // accumulated beside advanced bases.
    let packs_root = out_root.join("packs");
    for node in manifest.mesh.hub.keys() {
        sweep_superseded_staging(&mut lines, &packs_root, "hub", node, render_generation);
    }
    for node in manifest.ingress.keys() {
        sweep_superseded_staging(&mut lines, &packs_root, "ingress", node, render_generation);
    }
    for node in manifest.agent.keys() {
        sweep_superseded_staging(&mut lines, &packs_root, "agent", node, render_generation);
    }
    // Offline tier: fold the issuer store's current deny list into every
    // rendered pack as a CRL snapshot (trust/crls/) — the same contract
    // rotate applies, so "offline packs carry their embedded revocation
    // snapshot" holds from generation 1 (the CRL source is statically the
    // embedded snapshot; a pack without it would fail loud as a render
    // defect at every consumer). Freshness horizon = the new leaves' own
    // lifetime.
    if manifest.identity.mode == interflow_identity::manifest::IdentityMode::Offline {
        for pack in &rendered_packs {
            embed_revocation_snapshot(
                &issuer,
                issuer_dir,
                &manifest,
                &pack.dir,
                pack.metadata.leaf_ttl_secs,
            )?;
        }
        pushln!(
            lines,
            "  embedded revocation snapshot in trust/crls/ of every pack (covers every issuer)"
        );
        // Deliver the same deny list to the running hub over the control
        // plane — the offline tier has no pull lane of its own, so the
        // render pushes: the hub hot-swaps onto the fresh CRLs without a
        // node install + restart (idempotent by crl_number).
        publish_crls_with_ephemeral_credential(
            &issuer,
            &manifest.realm.id,
            &endpoint,
            &issuer_crl_material(issuer_dir),
            &mut lines,
        );
    }
    if manifest.public_tls.mode == PublicTlsMode::Acme {
        for host in manifest.route.iter().map(|r| r.host.as_str()) {
            pushln!(
                lines,
                "note: public TLS mode is ACME for {host}: point DNS at the ingress and \
                 ensure ports 80/443 are reachable; if a front proxy occupies them, switch \
                 [public_tls].mode to \"frontend-proxy\""
            );
        }
    }

    // Record the applied state — the diff base for the next apply's
    // policy-only fast path (packs carry the render-time policy snapshot;
    // a later policy-only update rides its own generation track, continued
    // from THIS generation — the counter never resets).
    let mut packs = BTreeMap::new();
    for pack in &rendered_packs {
        if let Ok(digest) = pack_dir_digest(&pack.dir) {
            packs.insert(pack.metadata.node.clone(), digest);
        }
    }
    let embedded_policy = RuntimePolicy::from_manifest(&manifest, render_generation);
    issuer
        .record_applied(
            &AppliedState {
                stripped_manifest_digest: stripped_now,
                policy_generation: render_generation,
                policy_digest: format!(
                    "sha256:{}",
                    interflow_util::sha256_hex(
                        &embedded_policy
                            .to_bytes()
                            .map_err(crate::runtime::pack_error)?
                    )
                ),
                packs,
            },
            Some(&manifest_text),
            AppliedKind::FullRender,
        )
        .map_err(crate::runtime::pack_error)?;

    pushln!(
        lines,
        "✔ applied {} → {}",
        manifest_path.display(),
        out_root.display()
    );
    pushln!(
        lines,
        "  issuer store: {} (keep secret — never distribute)",
        issuer_dir.display()
    );
    for node in manifest.mesh.hub.keys() {
        pushln!(
            lines,
            "  hub      {node}: {}",
            out_root.join("packs").join(format!("hub-{node}")).display()
        );
    }
    for node in manifest.ingress.keys() {
        pushln!(
            lines,
            "  ingress  {node}: {}",
            out_root
                .join("packs")
                .join(format!("ingress-{node}"))
                .display()
        );
    }
    for node in manifest.agent.keys() {
        pushln!(
            lines,
            "  agent    {node}: {}",
            out_root
                .join("packs")
                .join(format!("agent-{node}"))
                .display()
        );
    }
    if !manifest.mesh.hub.is_empty() || !manifest.ingress.is_empty() {
        pushln!(lines, "deploy, per server:");
        pushln!(
            lines,
            "  1. copy this dist tree to the server (or just its node's pack + install.sh)"
        );
        pushln!(
            lines,
            "  2. sudo bash install.sh   # once per server: user, dirs, bin/ (no units)"
        );
        pushln!(
            lines,
            "  3. per node:  sudo interflow-cli node install --pack packs/<kind>-<node>   # pack + unit + enable"
        );
        pushln!(
            lines,
            "  or encrypt:  interflow-cli pack seal --pack packs/<kind>-<node> --generate-passphrase"
        );
        if render::has_registrar(&manifest) {
            pushln!(
                lines,
                "  registrar host: follow the bootstrap in systemd/interflow-registrar.service"
            );
        }
    }
    if manifest.public_tls.mode == PublicTlsMode::FrontendProxy {
        pushln!(
            lines,
            "nginx (frontend proxy): hook the fragments in nginx/ into your nginx —"
        );
        pushln!(lines, "  http:   include /etc/nginx/interflow/http/*.conf;");
        pushln!(
            lines,
            "  stream: stream {{ include /etc/nginx/interflow/stream/*.conf; }}   # nginx.conf top level"
        );
        pushln!(
            lines,
            "  then reload nginx and verify: interflow-cli doctor ingress --pack <pack>"
        );
    }
    if render::has_registrar(&manifest) {
        pushln!(
            lines,
            "registrar server: copy the issuer store to {}/registrar/issuer,",
            render::DEFAULT_INSTALL_ROOT
        );
        pushln!(
            lines,
            "  then run the certificate command recorded in systemd/interflow-registrar.service"
        );
    }
    Ok(ApplyReport {
        lines,
        generation: render_generation,
    })
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
    // One read feeds both the parsed struct and the declaration snapshot
    // recorded with the refreshed applied state.
    let manifest_text = std::fs::read_to_string(manifest_path)
        .map_err(interflow_core::error::InterflowError::from)?;
    let manifest = Manifest::parse(&manifest_text).map_err(crate::runtime::pack_error)?;
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
    // The generation number is self-describing in pack.toml and valid across
    // format vintages — and rotate REPLACES the pack, it does not consume
    // it, so the strict loader's usability gate has no business here. A
    // retired-vintage pack stays rotatable.
    let next_generation = match current_pack {
        Some(path) => pack_generation_of(path).map_err(crate::runtime::pack_error)? + 1,
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
        pushln!(
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
            .record_applied(
                &AppliedState {
                    stripped_manifest_digest: applied.stripped_manifest_digest,
                    policy_generation: next_generation,
                    policy_digest: format!(
                        "sha256:{}",
                        interflow_util::sha256_hex(
                            &policy.to_bytes().map_err(crate::runtime::pack_error)?
                        )
                    ),
                    packs: applied.packs,
                },
                Some(&manifest_text),
                AppliedKind::Rotate,
            )
            .map_err(crate::runtime::pack_error)?;
    }
    pushln!(
        lines,
        "✔ rotated {node} → generation {} at {}",
        next_generation,
        out_dir.display()
    );
    if let Some(old) = current_pack {
        pushln!(
            lines,
            "  rollback: the old pack at {} stays valid until its own expiry",
            old.display()
        );
    }
    // 方案C: the closing janitorial sweep — this render supersedes every
    // earlier staging window of the node.
    if let Some(base) = out_dir.parent() {
        sweep_superseded_staging(&mut lines, base, kind, name, next_generation);
    }
    pushln!(
        lines,
        "  next: distribute the new pack, restart the node, then:"
    );
    pushln!(
        lines,
        "    interflow-cli identity inspect --pack {}",
        out_dir.display()
    );
    pushln!(
        lines,
        "    interflow-cli doctor {} --pack {}",
        kind,
        out_dir.display()
    );
    let _ = pack;
    Ok(lines)
}

/// The staging-window janitor shared by rotate and the full-render apply:
/// staging directories of generations BELOW `floor_generation` for this node
/// are superseded — remove them so the dist tree (and the GUI Packs view)
/// does not accumulate consumed shells. Strictly scoped: the directory name
/// must be exactly this node's staging name at a lower generation, AND the
/// directory's own pack must agree on node + generation (the lenient probe)
/// — base packs, other nodes' directories (including look-alike names) and
/// unreadable candidates are never touched. Best-effort by design: callers
/// invoke it only after their own success; a failed removal is a warning
/// line, never a failure.
fn sweep_superseded_staging(
    lines: &mut Vec<String>,
    packs_root: &Path,
    kind: &str,
    name: &str,
    floor_generation: u64,
) {
    let staging_prefix = format!("{kind}-{name}-gen");
    let mut cleaned = Vec::new();
    let mut warnings = Vec::new();
    if let Ok(entries) = std::fs::read_dir(packs_root) {
        for entry in entries.flatten() {
            let dir_name = entry.file_name().to_string_lossy().into_owned();
            let Some(suffix) = dir_name.strip_prefix(&staging_prefix) else {
                continue;
            };
            let Ok(staging_gen) = suffix.parse::<u64>() else {
                continue;
            };
            if staging_gen >= floor_generation {
                continue;
            }
            let agrees = interflow_identity::pack_node_and_generation_of(&entry.path())
                .is_ok_and(|(node, generation)| node == name && generation == staging_gen);
            if !agrees {
                continue;
            }
            match std::fs::remove_dir_all(entry.path()) {
                Ok(()) => cleaned.push(dir_name),
                Err(e) => warnings.push(format!("{dir_name}: {e}")),
            }
        }
    }
    for dir_name in cleaned {
        pushln!(
            lines,
            "  cleaned staging: {dir_name} (superseded by generation {floor_generation})"
        );
    }
    for warning in warnings {
        pushln!(
            lines,
            "  warning: could not clean superseded staging {warning}"
        );
    }
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
    let mut by_issuer: BTreeMap<String, Vec<RevocationEntry>> = BTreeMap::new();
    for entry in &list.entries {
        by_issuer
            .entry(entry.issuer.clone())
            .or_default()
            .push(entry.clone());
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
        let entries = by_issuer.get(&issuer_name).cloned().unwrap_or_default();
        let crl = build_crl_with_horizon(&loaded, &entries, list.next_crl_number, horizon)
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
    manifest_path: Option<&Path>,
    include_active_credentials: bool,
) -> interflow_core::error::Result<Vec<String>> {
    let mut lines = Vec::new();
    // The revocation lane reads the certificates directly instead of
    // CredentialPack::load: everything the deny list needs (serial, issuer
    // attribution) lives in the certs themselves, and revoking is the one
    // operation that must work exactly when a pack is NOT usable — a
    // retired format vintage, a damaged pack.toml, a leaked legacy copy on
    // a compromised node. The usability gate never blocks the emergency
    // lane.
    //
    // Two revocation domains, owned by different things:
    // - `identity/*.crt` is the PACK's own bootstrap material — revoking a
    //   pack always denies it.
    // - `state/credentials` is the NODE's renewal ledger: it follows the
    //   node across pack generations (an update carries it over verbatim),
    //   so the same pointer can equally belong to a live node or to a
    //   retired archive. Following it implicitly evicted live nodes when
    //   operators revoked superseded archives (the 2026-10-13 incident);
    //   the domain is now explicit — `--include-active-credentials` is the
    //   operator's statement that the node's runtime credential itself
    //   must die.
    let mut revoked_identities = interflow_identity::scan_revocation_identities(pack_dir)
        .map_err(crate::runtime::pack_error)?;
    let active_credentials = interflow_identity::scan_active_credentials(pack_dir);
    if include_active_credentials {
        revoked_identities.extend(active_credentials.iter().cloned());
    } else if !active_credentials.is_empty() {
        let mut skipped = Vec::new();
        for credential in &active_credentials {
            skipped.push(
                interflow_identity::revocation::cert_serial_hex(&credential.cert_pem)
                    .map_err(crate::runtime::pack_error)?,
            );
        }
        pushln!(
            lines,
            "⚠ state/credentials serials {skipped:?} NOT revoked — the renewal ledger follows \
             the NODE, not pack generations (a running node still authenticates with it, \
             whichever pack directory points at it); revoking it evicts that live node. Pass \
             --include-active-credentials if killing the node's runtime credential is the \
             intent."
        );
    }
    if revoked_identities.is_empty() {
        return Err(interflow_core::error::InterflowError::config(format!(
            "{} carries no revocable identities (no identity/*.crt found) — refusing to record \
             an empty revocation",
            pack_dir.display()
        )));
    }
    let pack_digest = pack_digest_of(pack_dir);
    let issuer = IssuerStore::open(issuer_dir);
    let mut list = RevocationList::load(issuer_dir).map_err(crate::runtime::pack_error)?;
    let now = time::OffsetDateTime::now_utc()
        .format(&time::format_description::well_known::Rfc3339)
        .map_err(|e| {
            interflow_core::error::InterflowError::config("revocation timestamp failed")
                .with_source(e)
        })?;
    // Record every credential serial carried by the pack.
    let mut by_issuer: BTreeMap<String, Vec<RevocationEntry>> = BTreeMap::new();
    for identity in &revoked_identities {
        let serial = interflow_identity::revocation::cert_serial_hex(&identity.cert_pem)
            .map_err(crate::runtime::pack_error)?;
        let issuer_name = match &identity.principal.workspace {
            Some(ws) => format!("workspace/{ws}"),
            None => "control".to_owned(),
        };
        let record = RevocationEntry {
            serial,
            issuer: issuer_name.clone(),
            reason: reason.to_owned(),
            revoked_at: now.clone(),
            pack_digest: pack_digest.clone(),
        };
        by_issuer
            .entry(issuer_name)
            .or_default()
            .push(record.clone());
        list.record(record);
    }
    list.save(issuer_dir).map_err(crate::runtime::pack_error)?;
    // Regenerate CRLs per affected issuer.
    for (issuer_name, entries) in &by_issuer {
        let loaded = match issuer_name.as_str() {
            "control" => issuer.realm_issuer().map_err(crate::runtime::pack_error)?,
            ws => issuer
                .workspace_issuer(ws.trim_start_matches("workspace/"))
                .map_err(crate::runtime::pack_error)?,
        };
        let crl = build_crl(&loaded, entries, list.next_crl_number)
            .map_err(crate::runtime::pack_error)?;
        let path = issuer_dir.join(format!("{}.crl.pem", issuer_name.replace('/', "-")));
        std::fs::write(&path, crl)?;
        let serials: Vec<&str> = entries.iter().map(|e| e.serial.as_str()).collect();
        pushln!(
            lines,
            "✔ revoked {serials:?} by {issuer_name}; CRL → {}",
            path.display()
        );
    }
    // The deny list is security state too (a lost deny list resurrects
    // revoked credentials) — checkpoint the store now that it changed.
    issuer.checkpoint().map_err(crate::runtime::pack_error)?;
    // The emergency leg: deliver the fresh CRLs to the hub's control plane
    // (`PUT /crls`). The hub hot-swaps its verification plane onto them —
    // the revoked credentials are rejected on new connections within
    // seconds, no restart, and any live session holding one is evicted.
    // This is the whole point of revoking: the door locks when the
    // command returns, not after a re-render + node install + restart
    // chain the operator had to know about.
    match manifest_path {
        Some(path) => {
            // Best-effort: the revocation itself already succeeded — a
            // manifest that will not parse must not fail the command,
            // only forfeit the push (narrated).
            match std::fs::read_to_string(path)
                .map_err(interflow_core::error::InterflowError::Io)
                .and_then(|text| Manifest::parse(&text).map_err(crate::runtime::pack_error))
            {
                Ok(manifest) => {
                    let endpoint = manifest_hub_endpoint(&manifest);
                    publish_crls_with_ephemeral_credential(
                        &issuer,
                        &manifest.realm.id,
                        &endpoint,
                        &issuer_crl_material(issuer_dir),
                        &mut lines,
                    );
                }
                Err(e) => {
                    pushln!(
                        lines,
                        "  --manifest {} could not be read ({e}) — CRL push skipped; the                          revocation stands, deliver it via `plan apply` or a re-run with a                          valid manifest",
                        path.display()
                    );
                }
            }
        }
        None => {
            pushln!(
                lines,
                "  no --manifest given — the CRL push to the hub was skipped; re-run with \
                 --manifest <interflow.toml> for seconds-level enforcement (no hub restart), \
                 or deliver via `plan apply` below"
            );
        }
    }
    pushln!(
        lines,
        "next: `interflow-cli plan apply` re-renders every pack so offline legs pick up the \
         updated trust/crls/ (the gate senses the moved deny list by itself) — swap the pack \
         on each offline leg to finish; verify with `interflow-cli doctor link --issuer \
         <dir> --pack <dir>`"
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

    /// The no-op gate's watermark verdict, shape by shape. The gate itself
    /// (which sources feed these numbers) is covered end-to-end by
    /// `policy_apply_diff.rs` / `policy_apply_hub_reinstall.rs`; this pins
    /// the decision table — including the 2026-10-07 serving dimension the
    /// three-number form used to mask.
    #[test]
    fn no_op_gate_verdict_covers_every_watermark_shape() {
        use interflow_mesh::hub::policy::PolicyFloorQuery;
        let agree = |bookkeeping, dist, hub| {
            matches!(
                policy_no_op_verdict(&PolicyWatermarks {
                    bookkeeping,
                    dist,
                    hub
                }),
                GateVerdict::NoOp
            )
        };
        // Everything agrees with the bookkeeping — the one true no-op.
        assert!(agree(
            2,
            2,
            Some(PolicyFloorQuery {
                floor: 2,
                serving: Some(2)
            })
        ));
        // Hub unreachable is no signal, not a divergence.
        assert!(agree(2, 2, None));
        // An older hub that cannot report its serving generation: no
        // serving signal, no divergence from it.
        assert!(agree(
            2,
            2,
            Some(PolicyFloorQuery {
                floor: 2,
                serving: None
            })
        ));
        // Dist artifacts trailing the bookkeeping (manual-distribution
        // mirror behind a live hub) leave the fleet correctly served.
        assert!(agree(
            2,
            1,
            Some(PolicyFloorQuery {
                floor: 2,
                serving: Some(2)
            })
        ));
        // The 2026-10-06 field shape: a node state mirror above the
        // bookkeeping (hub reinstalled below it).
        assert!(!agree(
            2,
            5,
            Some(PolicyFloorQuery {
                floor: 1,
                serving: Some(1)
            })
        ));
        // A hub reinstalled from an older pack: floor below the bookkeeping.
        assert!(!agree(
            2,
            2,
            Some(PolicyFloorQuery {
                floor: 1,
                serving: Some(1)
            })
        ));
        // Another operator published from a different machine: floor above
        // the bookkeeping.
        assert!(!agree(
            2,
            2,
            Some(PolicyFloorQuery {
                floor: 3,
                serving: Some(3)
            })
        ));
        // A split the hub cannot see still opens the gate via dist.
        assert!(!agree(2, 5, None));

        // The 2026-10-07 blind-spot shape: floor absorbed the fleet's
        // watermarks (== bookkeeping) while the hub still serves the
        // reinstalled pack's embedded generation — three equal numbers
        // masking the fourth. The gate must open.
        let verdict = policy_no_op_verdict(&PolicyWatermarks {
            bookkeeping: 2,
            dist: 2,
            hub: Some(PolicyFloorQuery {
                floor: 2,
                serving: Some(1),
            }),
        });
        assert!(matches!(
            &verdict,
            GateVerdict::Republish(Divergence::HubServingBehind {
                serving: 1,
                bookkeeping: 2
            })
        ));
        // And its narration names the shape (the operator line must be
        // self-explaining).
        let GateVerdict::Republish(divergence) = verdict else {
            unreachable!("checked above")
        };
        assert!(divergence.narrate().contains("SERVING generation 1"));
        // Serving at the bookkeeping (or above, which the floor arm already
        // catches) keeps the gate shut.
        assert!(agree(
            2,
            2,
            Some(PolicyFloorQuery {
                floor: 2,
                serving: Some(2)
            })
        ));
    }
}

/// [`change_state`] + [`ApplyReport`] — the GUI Deploy overview's
/// bookkeeping face, machine-locked end to end against a real issuer
/// store: never-applied → applied(gen 1) → a stream edit reads
/// policy-pending → apply lands gen 2 → an identity edit reads
/// identity-pending. The hub endpoint points at a closed loopback port
/// (fast, deterministic refusal → the manual-drop distribution path).
#[test]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
fn change_state_and_apply_report_track_the_bookkeeping() {
    fn mesh_text(remote_port: u16, realm: &str) -> String {
        format!(
            r#"
[realm]
id = "{realm}"
[identity]
mode = "offline"
leaf_ttl = "7d"
[mesh.hub.promptcn]
listen = "127.0.0.1:16666"
endpoint = "127.0.0.1:1"
[workspace.main]
[agent.leo-mesh]
workspace = "main"
[[agent.leo-mesh.mesh_ingress]]
name = "ollama"
listen = "127.0.0.1:24001"
target_agent = "home-win"
remote_addr = "127.0.0.1:{remote_port}"
[agent.home-win]
workspace = "main"
[[agent.home-win.mesh_egress]]
name = "loopback"
target_cidr = "127.0.0.0/8"
"#
        )
    }
    let dir = tempfile::tempdir().unwrap();
    let manifest = dir.path().join("interflow.toml");
    let issuer = dir.path().join("issuer");
    let out = dir.path().join("dist");

    std::fs::write(&manifest, mesh_text(11434, "cs-test")).unwrap();
    assert!(matches!(
        change_state(&manifest, &issuer).unwrap(),
        ChangeState::NeverApplied
    ));

    let report = apply(
        &manifest,
        &issuer,
        &out,
        false,
        &BackupInitOptions::default(),
        false,
    )
    .unwrap();
    assert_eq!(report.generation, 1, "first apply mints generation 1");
    assert!(
        report.lines.iter().any(|l| l.contains("✔ applied")),
        "{:?}",
        report.lines
    );
    match change_state(&manifest, &issuer).unwrap() {
        ChangeState::Applied { generation } => assert_eq!(generation, 1),
        other => panic!("expected Applied(1), got {other:?}"),
    }
    // The drift view agrees with the bookkeeping: applied, no drift.
    let drift = diff(&manifest, &issuer).unwrap();
    assert!(
        drift
            .iter()
            .any(|l| l.contains("matches the applied state")),
        "{drift:?}"
    );
    assert!(
        drift.iter().any(|l| l.contains("no textual drift")),
        "{drift:?}"
    );

    // A stream-face edit (the remote port moved): policy-pending.
    std::fs::write(&manifest, mesh_text(11435, "cs-test")).unwrap();
    assert!(matches!(
        change_state(&manifest, &issuer).unwrap(),
        ChangeState::PolicyEditsPending
    ));
    // The drift view headlines the classification and shows the line move.
    let drift = diff(&manifest, &issuer).unwrap();
    assert!(
        drift
            .iter()
            .any(|l| l.contains("policy-face edits pending")),
        "{drift:?}"
    );
    assert!(
        drift.iter().any(|l| l.contains("--- applied"))
            && drift.iter().any(|l| l.contains("+++ declaration")),
        "{drift:?}"
    );
    assert!(
        drift
            .iter()
            .any(|l| l.contains("-remote_addr = \"127.0.0.1:11434\"")),
        "{drift:?}"
    );
    assert!(
        drift
            .iter()
            .any(|l| l.contains("+remote_addr = \"127.0.0.1:11435\"")),
        "{drift:?}"
    );
    let report = apply(
        &manifest,
        &issuer,
        &out,
        false,
        &BackupInitOptions::default(),
        false,
    )
    .unwrap();
    assert_eq!(report.generation, 2, "policy-only apply mints gen 2");
    assert!(matches!(
        change_state(&manifest, &issuer).unwrap(),
        ChangeState::Applied { generation: 2 }
    ));

    // An identity-face edit (the realm id moved): identity-pending.
    std::fs::write(&manifest, mesh_text(11435, "cs-test-2")).unwrap();
    assert!(matches!(
        change_state(&manifest, &issuer).unwrap(),
        ChangeState::IdentityEditsPending
    ));
}
