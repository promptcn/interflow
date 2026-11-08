//! `plan stage` — the per-host minimal staging tree, produced and verified.
//!
//! Assembling a host's staging tree by hand failed three times in as many
//! weeks:
//! `install.sh` run outside the dist root resolved `bin/` against the CWD,
//! a flat-laid staging directory hit the script's then-fail-open `bin/`
//! branch, and a `cp` missing `-R` dropped every pack subdirectory. The
//! correct shape lived only in runbooks and operator memory; this command
//! makes it machine-checked end to end:
//!
//! - the dist tree `plan apply` rendered is the pack source — apply stays
//!   the only pack writer (one generation, fleet-consistent), stage only
//!   packages. The freshness gate reuses the same [`super::classify_fork`]
//!   decision diff and apply share: staging is refused exactly when the
//!   next apply would re-render packs (the full-render fork; the
//!   policy-only fast path and the re-publish leave pack bytes untouched,
//!   so staging under them ships exactly the bytes apply leaves behind);
//! - nginx fragments are NOT copied from dist — stage re-renders them from
//!   the manifest with this build (the same pure functions apply renders
//!   with), so a staged fragment can never be an older build's output. The
//!   vintage line in each fragment's header is the receipt, and any dist
//!   lag is named as an ℹ. This is the fragments' freshness face: pack
//!   bytes have the fork gate, `bin/` the artifact gate, the fragments an
//!   always-fresh render
//!  ;
//! - `bin/` comes from the artifact record: a `build-manifest.*.json` is
//!   consumed when present (commit must match this build, each artifact's
//!   sha256 re-hashed, the build tag scanned out of the bytes), exact
//!   canonical names otherwise — the §10.18 "stale linux build" class dies
//!   here, at production time;
//! - the pack copy runs through the product's recursive copier and the
//!   staged copy is validated by `CredentialPack::load_runtime` — the same
//!   funnel `node install` validates through, moved from install time to
//!   staging time;
//! - `stage-manifest.json` lists every file with its sha256;
//!   `install.sh --verify-staging` (and the install path itself, whenever
//!   the manifest is present) verifies the transferred tree against it
//!   before anything is installed;
//! - a deterministic tar + sha256 pair is always emitted — the scp path is
//!   a single file, and re-staging reproduces both byte for byte.
//!
//! Every host's tree is self-sufficient for fresh installs and upgrades
//! alike: `interflow-cli` always ships (the target host runs
//! `node install` with it), `interflow-mesh` when the node's unit execs it
//! or the host is an ingress edge (the §10.15 dual-binary face). The tree
//! holds exactly the host's materials — never another node's pack, never a
//! unit (`node install` writes those), never the policy mirror (each pack
//! embeds its own).
//!
//! One physical machine hosting several nodes stages ONE tree: `--host
//! <kind>/<node> --with <kind>/<node>` (repeatable). The machine's minimal
//! face is the union of its nodes' faces — `bin/` and `install.sh` once,
//! every node's pack, the nginx fragment union — one scp, one
//! `--verify-staging`, one `install.sh`, then `node install` per node

use super::{ApplyFork, FullRenderReason, ReadFace, classify_fork, narration};
use crate::manifest_edit::AddNodeKind;
use crate::node_install::copy_dir_recursive;
use crate::render;
use interflow_buildinfo::{BUILD_TAG, VERSION_WITH_TAG, find_build_tags};
use interflow_core::error::{InterflowError, Result};
use interflow_identity::manifest::{Manifest, PublicTlsMode};
use interflow_identity::pack::{CredentialPack, PackKind};
use serde::Deserialize;
use std::path::{Path, PathBuf};

/// The staging manifest's file name, at the staging tree root.
const STAGE_MANIFEST_FILE: &str = "stage-manifest.json";
/// The staging manifest's `kind` marker — also the ownership marker that
/// makes re-staging over a previous tree safe to wipe.
const STAGE_MANIFEST_KIND: &str = "plan-stage";

/// `plan stage` options — the command's whole surface.
pub struct StageOptions {
    /// The primary host to stage for: `agent/<name>`, `ingress/<name>` or
    /// `hub/<name>` (the `node add` grammar), as declared in the manifest.
    pub host: String,
    /// Additional nodes staged into the same tree (the machine's other
    /// roles), same grammar, each exactly once.
    pub with: Vec<String>,
    pub manifest: PathBuf,
    /// Issuer store directory — read-only here (the freshness gate's
    /// baseline), the same default as diff/apply.
    pub issuer: PathBuf,
    /// The dist root `plan apply` rendered — the pack source.
    pub out: PathBuf,
    /// Directory holding the built engine binaries; a
    /// `build-manifest.*.json` record is consumed when present.
    pub artifacts: PathBuf,
    /// Staging output directory (default `stage/<kind>-<node>`, or the
    /// `+`-joined names for a multi-node tree).
    pub to: Option<PathBuf>,
}

/// One staged node — the resolved form of a `--host`/`--with` argument.
struct StagedNode {
    kind: PackKind,
    node: String,
    /// The agent's mesh role (hubs and ingress edges are always
    /// dual-binary; this is the agent's declaration only).
    mesh_role: bool,
    /// The pack directory name, `<kind>-<node>`.
    dir_name: String,
    /// The CLI spelling, `<kind>/<node>`.
    host: String,
}

/// `plan stage`'s output lines, mirroring [`super::ApplyReport`].
pub struct StageReport {
    pub lines: Vec<String>,
}

/// Produces one machine's minimal staging tree (one node, or several via
/// `--with`).
///
/// Verified `bin/`, every staged node's validated pack, the nginx
/// fragment union (any ingress node, frontend-proxy) freshly rendered,
/// one `install.sh`, one `stage-manifest.json`, and the deterministic
/// tar+sha256 pair beside the tree. See the [module docs](self) for the
/// gates.
pub fn stage(opts: &StageOptions) -> Result<StageReport> {
    let hosts = resolve_hosts(opts)?;
    let face = ReadFace::load(&opts.manifest, &opts.issuer)?;
    let manifest = &face.manifest;
    let mut nodes = Vec::new();
    for (kind, node) in hosts {
        ensure_declared(manifest, kind, &node)?;
        let mesh_role = kind == PackKind::Agent && manifest.agent_has_mesh_role(&node);
        nodes.push(StagedNode {
            kind,
            mesh_role,
            dir_name: format!("{}-{node}", kind.as_str()),
            host: format!("{}/{}", kind.as_str(), node),
            node,
        });
    }

    // The freshness gate — the same fork decision diff narrates and apply
    // executes, read with no hub dial. Only the full-render fork refuses:
    // it is the one fork that changes pack bytes. The fork is the
    // manifest's, so one decision covers every staged node.
    let (fork, _) = classify_fork(&face.inputs(&opts.issuer, &opts.out), || None)?;
    let mut lines = Vec::new();
    match &fork {
        ApplyFork::FullRender(reason) => return Err(refuse_full_render(&nodes, reason)),
        ApplyFork::PolicyOnly { .. } => lines.push(format!(
            "ℹ {} — staging the current pack baseline; nodes hot-apply the new \
             generation from the hub",
            narration::policy_edits_pending()
        )),
        ApplyFork::NoOp { prev, .. } => lines.push(format!(
            "ℹ {} — staging exactly that tree",
            narration::applied_matches(prev.policy_generation)
        )),
        ApplyFork::Republish {
            prev,
            watermarks,
            divergence,
            ..
        } => lines.push(format!(
            "ℹ {} — the re-publish does not touch pack bytes; staging them",
            narration::watermarks_diverged_preview(
                prev.policy_generation,
                watermarks.dist,
                divergence
            )
        )),
    }

    // The nginx fragments — rendered fresh by THIS build from the CURRENT
    // declaration (never copied from dist, whose renderer vintage may lag
    // this CLI by any number of versions). The union of the staged ingress
    // nodes' vhosts plus the shared set, once; the dist copies are compared
    // and any lag is named: dist's role here is apply's record, not the
    // material source.
    let manifest_sha = face.manifest_sha256();
    let ingress_nodes: Vec<String> = nodes
        .iter()
        .filter(|node| node.kind == PackKind::Ingress)
        .map(|node| node.node.clone())
        .collect();
    let fragments =
        if !ingress_nodes.is_empty() && manifest.public_tls.mode == PublicTlsMode::FrontendProxy {
            let set = render::nginx_fragment_set(manifest, &manifest_sha, Some(&ingress_nodes))?;
            let drifted: Vec<String> = set
                .iter()
                .filter(|piece| {
                    std::fs::read(opts.out.join(&piece.rel))
                        .map_or(true, |bytes| bytes != piece.body.as_bytes())
                })
                .map(|piece| piece.rel.clone())
                .collect();
            if !drifted.is_empty() {
                lines.push(narration::stage_fragments_re_rendered(&drifted));
            }
            set
        } else {
            Vec::new()
        };

    let dir_name = match &nodes[..] {
        [one] => one.dir_name.clone(),
        many => many
            .iter()
            .map(|node| node.dir_name.as_str())
            .collect::<Vec<_>>()
            .join("+"),
    };
    let to = opts
        .to
        .clone()
        .unwrap_or_else(|| PathBuf::from("stage").join(&dir_name));
    let parent = to
        .parent()
        .map_or_else(|| PathBuf::from("."), ToOwned::to_owned);
    std::fs::create_dir_all(&parent)?;
    if to.exists() && !is_our_stage_tree(&to) {
        return Err(InterflowError::config(format!(
            "{} already exists and is not a plan stage tree — refusing to overwrite it",
            to.display()
        )));
    }
    if to.exists() {
        std::fs::remove_dir_all(&to)?;
    }
    let staging = parent.join(format!(".{dir_name}.staging-{}", std::process::id()));
    if staging.exists() {
        std::fs::remove_dir_all(&staging)?;
    }
    std::fs::create_dir_all(&staging)?;

    if let Err(e) = build_tree(&staging, opts, manifest, &manifest_sha, &nodes, &fragments) {
        // Refusals leave no half tree behind — the whole attempt is undone.
        let _ = std::fs::remove_dir_all(&staging);
        return Err(e);
    }
    std::fs::rename(&staging, &to)?;

    let tar_path = write_tar_pair(&to, &dir_name)?;
    let file_count = count_files(&to)?;

    let staged_names = nodes
        .iter()
        .map(|node| node.host.as_str())
        .collect::<Vec<_>>()
        .join(", ");
    lines.push(format!(
        "✔ staged {staged_names} → {} ({file_count} files)",
        to.display()
    ));
    for name in host_binaries_union(&nodes) {
        lines.push(format!("  bin/{name} (tag {BUILD_TAG})"));
    }
    for node in &nodes {
        lines.push(format!(
            "  packs/{} — product copier + load_runtime verified (digests, identity, policy)",
            node.dir_name
        ));
    }
    if !fragments.is_empty() {
        lines.push(format!(
            "  nginx/ — {} fragments (rendered by this build; the shared set + {} vhost(s), \
             vintage in each header)",
            fragments.len(),
            ingress_nodes.len()
        ));
    }
    lines.push(format!(
        "  install.sh + {STAGE_MANIFEST_FILE} (sha256 per file) + {} + .sha256",
        tar_path.display()
    ));
    lines.push("transfer & install:".to_owned());
    lines.push(format!(
        "  1. scp {}.tar {}.tar.sha256 <host>:/tmp/",
        to.display(),
        to.display()
    ));
    lines.push(format!(
        "  2. on <host>: cd /tmp && sha256sum -c {dir_name}.tar.sha256 && tar -xf {dir_name}.tar"
    ));
    lines.push(format!(
        "  3. bash {dir_name}/install.sh --verify-staging   # transfer-integrity gate"
    ));
    lines.push(format!(
        "  4. sudo bash {dir_name}/install.sh               # user, dirs, bin/"
    ));
    for (i, node) in nodes.iter().enumerate() {
        lines.push(format!(
            "  {}. sudo interflow-cli node install --pack {dir_name}/packs/{}",
            5 + i,
            node.dir_name
        ));
    }
    Ok(StageReport { lines })
}

/// Parses the `--host` + `--with` arguments into the staged node list —
/// the `node add` grammar throughout, each node exactly once (a machine
/// hosts a node once; staging it twice is a typo, not an intent).
fn resolve_hosts(opts: &StageOptions) -> Result<Vec<(PackKind, String)>> {
    let mut hosts: Vec<(PackKind, String)> = Vec::new();
    for spec in std::iter::once(&opts.host).chain(opts.with.iter()) {
        let (kind, node) = resolve_host(spec)?;
        if hosts.iter().any(|(k, n)| *k == kind && *n == node) {
            return Err(InterflowError::config(format!(
                "{spec} is staged twice — pass each node exactly once"
            )));
        }
        hosts.push((kind, node));
    }
    Ok(hosts)
}

/// Parses `<kind>/<node>` into the pack kind + node name (the `node add`
/// grammar — one host spelling across the CLI).
fn resolve_host(host: &str) -> Result<(PackKind, String)> {
    let (add_kind, node) = AddNodeKind::parse(host)?;
    let kind = match add_kind {
        AddNodeKind::Agent => PackKind::Agent,
        AddNodeKind::Ingress => PackKind::Ingress,
        AddNodeKind::Hub => PackKind::Hub,
    };
    Ok((kind, node))
}

/// The host must be declared — staging never invents a node.
fn ensure_declared(manifest: &Manifest, kind: PackKind, node: &str) -> Result<()> {
    let declared = match kind {
        PackKind::Ingress => manifest.ingress.contains_key(node),
        PackKind::Agent => manifest.agent.contains_key(node),
        PackKind::Hub => manifest.mesh.hub.contains_key(node),
    };
    if declared {
        Ok(())
    } else {
        Err(InterflowError::config(format!(
            "host {}/{} is not declared in the manifest",
            kind.as_str(),
            node
        )))
    }
}

/// Staging is refused exactly when the next apply would re-render the
/// packs: the refusal quotes the diff face's own verdict (single-sourced
/// in [`narration`]), names every staged node the refusal covers, and
/// names the way out.
fn refuse_full_render(nodes: &[StagedNode], reason: &FullRenderReason) -> InterflowError {
    let verdict = match reason {
        FullRenderReason::FirstRender => narration::never_applied(),
        FullRenderReason::IdentityEdit => narration::identity_edits_pending(),
        FullRenderReason::StaleTree(stale) => narration::pack_tree_stale_preview(stale),
    };
    let names = nodes
        .iter()
        .map(|node| node.host.as_str())
        .collect::<Vec<_>>()
        .join(", ");
    InterflowError::config(format!(
        "refusing to stage {names} — the next `plan apply` re-renders every pack: {verdict}. \
         Run `plan apply` first; `plan stage` ships only the pack bytes the current \
         declaration already renders."
    ))
}

/// The engine binaries a host's tree carries: `interflow-cli` always (the
/// target host runs `node install` with it — one self-sufficient face for
/// fresh installs and upgrades), `interflow-mesh` when the node's unit
/// execs it (the [`render::node_engine_binary`] rule) or the host is an
/// ingress edge (the §10.15 dual-binary face).
fn host_binaries(kind: PackKind, mesh_role: bool) -> Vec<&'static str> {
    let mut names = vec!["interflow-cli"];
    if kind == PackKind::Hub || mesh_role || kind == PackKind::Ingress {
        names.push("interflow-mesh");
    }
    names
}

/// The engine binaries the whole machine tree carries: the union of every
/// staged node's face, derived from the same [`host_binaries`] rule — one
/// copy per machine, not one per node.
fn host_binaries_union(nodes: &[StagedNode]) -> Vec<&'static str> {
    let mut names: Vec<&'static str> = Vec::new();
    for node in nodes {
        for name in host_binaries(node.kind, node.mesh_role) {
            if !names.contains(&name) {
                names.push(name);
            }
        }
    }
    names
}

/// Builds the staging tree inside `staging` — every gate that can refuse
/// runs here, before the tree is moved into place.
fn build_tree(
    staging: &Path,
    opts: &StageOptions,
    manifest: &Manifest,
    manifest_sha: &str,
    nodes: &[StagedNode],
    fragments: &[render::RenderedFragment],
) -> Result<()> {
    // bin/ — the machine's union face, verified against the artifact record
    // (or exact names when no record exists), then installed under
    // canonical names.
    let binaries = resolve_binaries(&opts.artifacts, &host_binaries_union(nodes))?;
    for binary in &binaries {
        install_binary(&binary.source, &staging.join("bin").join(binary.name))?;
    }

    // Every staged node's pack — copied by the product's recursive copier
    // and validated through the same funnel node install uses. A missing
    // source names its node.
    for node in nodes {
        let pack_src = opts.out.join("packs").join(&node.dir_name);
        if !pack_src.is_dir() {
            return Err(InterflowError::config(format!(
                "pack source for {} is missing from the dist tree ({}) — run `plan apply` first",
                node.host,
                pack_src.display()
            )));
        }
        let pack_dst = staging.join("packs").join(&node.dir_name);
        copy_dir_recursive(&pack_src, &pack_dst)?;
        CredentialPack::load_runtime(&pack_dst).map_err(crate::runtime::pack_error)?;
    }

    // nginx fragments — the fresh render composed in `stage` (this build,
    // the current declaration), written at their own relative paths.
    render::write_fragments(staging, fragments)?;

    // install.sh — rendered fresh from the manifest (a pure function; on
    // the staged fork it is byte-identical to the copy in dist), so the
    // shipped script always carries the current fail-closed semantics.
    render::write_install_sh(staging, manifest, manifest_sha)?;

    // The staging manifest itself — every file, sha256 each, sorted,
    // timestamp-free: the tree is a byte-stable function of its inputs.
    // The hosts array is the machine's whole bill of nodes.
    let files = collect_files_sorted(staging)?;
    let hosts: Vec<String> = nodes.iter().map(|node| node.host.clone()).collect();
    std::fs::write(
        staging.join(STAGE_MANIFEST_FILE),
        render_stage_manifest(&hosts, &files),
    )?;
    Ok(())
}

/// Whether `dir` is a tree this command produced (its manifest carries our
/// kind marker) — the ownership check that makes re-staging a safe wipe.
fn is_our_stage_tree(dir: &Path) -> bool {
    let Ok(text) = std::fs::read_to_string(dir.join(STAGE_MANIFEST_FILE)) else {
        return false;
    };
    let Ok(value) = serde_json::from_str::<serde_json::Value>(&text) else {
        return false;
    };
    value.get("kind").and_then(|k| k.as_str()) == Some(STAGE_MANIFEST_KIND)
}

fn count_files(dir: &Path) -> Result<usize> {
    Ok(collect_files_sorted(dir)?.len())
}

// ---------------------------------------------------------------------------
// bin/ — the artifact record and the content gate
// ---------------------------------------------------------------------------

/// One resolved engine binary: canonical staging name, verified source
/// path, and the sha256 the build record demands (absent on the
/// exact-name fallback, where the content gate alone stands guard).
#[derive(Debug)]
struct BinarySource {
    name: &'static str,
    source: PathBuf,
    recorded_sha256: Option<String>,
}

/// Resolves the engine binaries from `artifacts`, refusing anything the
/// record (or, without one, the bytes) does not vouch for.
fn resolve_binaries(artifacts: &Path, names: &[&'static str]) -> Result<Vec<BinarySource>> {
    if !artifacts.is_dir() {
        return Err(InterflowError::config(format!(
            "artifacts directory {} not found — pass --artifacts <dir> holding the built \
             engine binaries",
            artifacts.display()
        )));
    }
    if BUILD_TAG == "unknown" {
        return Err(InterflowError::config(
            "this interflow-cli was built outside a git tree (build tag \"unknown\") — \
             artifact builds cannot be verified; build from a git checkout to stage",
        ));
    }
    let records = build_manifest_records(artifacts)?;
    if records.is_empty() {
        resolve_by_exact_names(artifacts, names)
    } else {
        resolve_from_records(artifacts, &records, names)
    }
}

/// guard's `build-manifest.*.json` (schema 2) — the machine-readable
/// record of what was built, from where, at which commit. Only the fields
/// the gate consumes are named; the rest (script, timestamps, tree state)
/// are ignored by the deserializer.
#[derive(Deserialize)]
struct BuildManifestRecord {
    git: BuildManifestGit,
    artifacts: Vec<BuildManifestArtifact>,
}

#[derive(Deserialize)]
struct BuildManifestGit {
    commit: String,
}

#[derive(Deserialize)]
struct BuildManifestArtifact {
    name: String,
    sha256: String,
}

fn build_manifest_records(artifacts: &Path) -> Result<Vec<(String, BuildManifestRecord)>> {
    let mut files: Vec<String> = std::fs::read_dir(artifacts)?
        .collect::<std::io::Result<Vec<_>>>()?
        .into_iter()
        .map(|entry| entry.file_name().to_string_lossy().into_owned())
        .filter(|name| {
            Path::new(name).extension().is_some_and(|ext| ext == "json")
                && name.starts_with("build-manifest.")
        })
        .collect();
    files.sort();
    let mut records = Vec::new();
    for name in files {
        let text = std::fs::read_to_string(artifacts.join(&name))?;
        let record: BuildManifestRecord = serde_json::from_str(&text).map_err(|e| {
            InterflowError::config(format!(
                "build manifest {}/{name} does not parse — the artifact record is corrupt",
                artifacts.display()
            ))
            .with_source(e)
        })?;
        records.push((name, record));
    }
    Ok(records)
}

/// The hash component of a build tag (`2026-11-02_c8906cb[-dirty]` →
/// `c8906cb`) — what the record's full commit must start with.
fn tag_hash(tag: &str) -> &str {
    let rest = tag.split_once('_').map_or(tag, |(_, rest)| rest);
    rest.strip_suffix("-dirty").unwrap_or(rest)
}

/// Record-driven resolution: exactly one manifest must both match this
/// build's commit and carry every needed binary. Zero candidates reports
/// why per manifest (stale commit — the §10.18 class — or missing
/// binaries); more than one demands a single-platform artifacts dir.
fn resolve_from_records(
    artifacts: &Path,
    records: &[(String, BuildManifestRecord)],
    names: &[&'static str],
) -> Result<Vec<BinarySource>> {
    let expected = tag_hash(BUILD_TAG);
    let mut candidates: Vec<(String, Vec<BinarySource>)> = Vec::new();
    let mut why_not: Vec<String> = Vec::new();
    for (file, record) in records {
        if !record.git.commit.starts_with(expected) {
            why_not.push(format!(
                "{file} records commit {} but this build is {BUILD_TAG}",
                record.git.commit
            ));
            continue;
        }
        let mut resolved = Vec::new();
        let mut missing = Vec::new();
        for name in names {
            let prefix = format!("{name}-");
            let matches: Vec<&BuildManifestArtifact> = record
                .artifacts
                .iter()
                .filter(|a| a.name == *name || a.name.starts_with(&prefix))
                .collect();
            if let [one] = matches.as_slice() {
                resolved.push(BinarySource {
                    name,
                    source: artifacts.join(&one.name),
                    recorded_sha256: Some(one.sha256.clone()),
                });
            } else {
                missing.push(*name);
            }
        }
        if missing.is_empty() {
            candidates.push((file.clone(), resolved));
        } else {
            why_not.push(format!(
                "{file} carries no artifact for {}",
                missing.join(", ")
            ));
        }
    }
    match candidates.len() {
        1 => {
            let (_, resolved) = candidates.pop().expect("len checked above");
            verify_binaries(&resolved)?;
            Ok(resolved)
        }
        0 => Err(InterflowError::config(format!(
            "no build-manifest in {} vouches for this build ({BUILD_TAG}): {}. Rebuild with \
             the build scripts (e.g. scripts/build-linux.sh) or point --artifacts at the \
             matching artifact set",
            artifacts.display(),
            why_not.join("; ")
        ))),
        _ => {
            let files = candidates
                .iter()
                .map(|(file, _)| file.as_str())
                .collect::<Vec<_>>()
                .join(", ");
            Err(InterflowError::config(format!(
                "multiple build-manifests in {} match this build and carry the binaries \
                 ({files}) — point --artifacts at a single platform's artifact set",
                artifacts.display()
            )))
        }
    }
}

/// The no-record path (a `target/release`-style directory): exact
/// canonical names, content-gated — a bare name match is never enough.
fn resolve_by_exact_names(artifacts: &Path, names: &[&'static str]) -> Result<Vec<BinarySource>> {
    let mut resolved = Vec::new();
    for name in names {
        let source = artifacts.join(name);
        if !source.is_file() {
            return Err(InterflowError::config(format!(
                "engine binary {name} not found in {} — no build-manifest record exists there, \
                 so exact canonical names are required (artifacts/ produced by the build \
                 scripts carries the record)",
                artifacts.display()
            )));
        }
        resolved.push(BinarySource {
            name,
            source,
            recorded_sha256: None,
        });
    }
    verify_binaries(&resolved)?;
    Ok(resolved)
}

/// The content gate, defense in depth: the recorded sha256 (when a record
/// vouches) must match the bytes on disk, and the bytes must carry this
/// build's tag — a cross-built Linux binary cannot be executed here, so
/// the tag is scanned out of the bytes instead (guard's `_guard_grep_tag`
/// in Rust form).
fn verify_binaries(sources: &[BinarySource]) -> Result<()> {
    for source in sources {
        let bytes = std::fs::read(&source.source)?;
        let digest = interflow_util::sha256_hex(&bytes);
        if let Some(recorded) = &source.recorded_sha256
            && recorded != &digest
        {
            return Err(InterflowError::config(format!(
                "artifact {} does not match its build-manifest entry (expected {recorded}, \
                 found {digest}) — the file changed after the build shipped it",
                source.source.display()
            )));
        }
        let found = find_build_tags(&bytes);
        if !found.iter().any(|tag| tag == BUILD_TAG) {
            let mut seen: Vec<&str> = found.iter().map(String::as_str).collect();
            seen.sort_unstable();
            seen.dedup();
            return Err(InterflowError::config(format!(
                "artifact {} does not carry this build's tag ({BUILD_TAG}) — found [{}] — \
                 refusing to stage binaries from a different build",
                source.source.display(),
                seen.join(", ")
            )));
        }
    }
    Ok(())
}

fn install_binary(src: &Path, dest: &Path) -> Result<()> {
    if let Some(parent) = dest.parent() {
        std::fs::create_dir_all(parent)?;
    }
    std::fs::copy(src, dest)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut perms = std::fs::metadata(dest)?.permissions();
        perms.set_mode(0o755);
        std::fs::set_permissions(dest, perms)?;
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// stage-manifest.json — deterministic, one file per line
// ---------------------------------------------------------------------------

/// One staged file's record.
struct StagedFile {
    rel: String,
    sha256: String,
    bytes: u64,
}

/// Every regular file under `root`, sorted, with forward-slash relative
/// paths (the shared sorted walk; the sort makes the manifest a pure
/// function of the tree).
fn collect_files_sorted(root: &Path) -> Result<Vec<StagedFile>> {
    let mut files = Vec::new();
    for entry in interflow_util::walk_sorted(root)? {
        if entry.is_dir {
            continue;
        }
        let bytes = std::fs::read(root.join(&entry.rel))?;
        files.push(StagedFile {
            sha256: interflow_util::sha256_hex(&bytes),
            bytes: bytes.len() as u64,
            rel: entry.rel,
        });
    }
    Ok(files)
}

/// Renders the staging manifest. One file entry per line with fixed
/// spacing — `install.sh --verify-staging` greps exactly this shape, and
/// the pair ships in the same tree (the plan_stage tests run the real
/// script against the real manifest, so the two cannot drift). Schema 2
/// carries the machine's whole node list (`hosts`, an array — a
/// multi-node tree is one machine's bill, not a chain of primaries);
/// schema 1's single `host` string retired with the `--with` batch.
fn render_stage_manifest(hosts: &[String], files: &[StagedFile]) -> String {
    fn put(out: &mut String, line: &str) {
        out.push_str(line);
        out.push('\n');
    }
    let mut out = String::new();
    put(&mut out, "{");
    put(&mut out, "  \"schema\": 2,");
    put(&mut out, &format!("  \"kind\": \"{STAGE_MANIFEST_KIND}\","));
    put(
        &mut out,
        &format!("  \"hosts\": {},", serde_json::json!(hosts)),
    );
    put(
        &mut out,
        &format!(
            "  \"generated_by\": {},",
            serde_json::json!(VERSION_WITH_TAG)
        ),
    );
    put(&mut out, "  \"files\": [");
    for (i, file) in files.iter().enumerate() {
        let comma = if i + 1 == files.len() { "" } else { "," };
        put(
            &mut out,
            &format!(
                "    {{\"path\": {}, \"sha256\": \"{}\", \"bytes\": {}}}{comma}",
                serde_json::json!(file.rel),
                file.sha256,
                file.bytes
            ),
        );
    }
    put(&mut out, "  ]");
    put(&mut out, "}");
    out
}

// ---------------------------------------------------------------------------
// The deterministic tar — ustar via the tar crate, headers built by hand
// ---------------------------------------------------------------------------

/// The ustar name field's capacity. Staging refuses longer paths rather
/// than letting the tar crate split them into `prefix` + `name` — the
/// digest consumers only ever meet shapes the writer chose.
const USTAR_NAME_MAX: usize = 100;

/// Writes `<tree>.tar` (entries under `<root_name>/`) plus the
/// `sha256sum -c` companion `<tree>.tar.sha256`. mtime/uid/gid are zeroed,
/// modes normalized, and paths sorted, so the tar is a byte-stable
/// function of the tree's contents: re-staging reproduces both files
/// exactly. The system `tar` is not used — it stamps mtimes and ownership,
/// forking the digest per run; the tar crate's header API lets us spell
/// every field instead.
fn write_tar_pair(tree: &Path, root_name: &str) -> Result<PathBuf> {
    let entries = collect_tree(tree)?;
    let root_entry = format!("{root_name}/");
    let mut names = vec![root_entry];
    for entry in &entries {
        names.push(if entry.is_dir {
            format!("{root_name}/{}/", entry.rel)
        } else {
            format!("{root_name}/{}", entry.rel)
        });
    }
    for name in &names {
        if name.len() > USTAR_NAME_MAX {
            return Err(InterflowError::config(format!(
                "staging path {name:?} exceeds the ustar name field — refusing to tar"
            )));
        }
    }
    let mut tar: Vec<u8> = Vec::new();
    {
        let mut builder = tar::Builder::new(&mut tar);
        append_entry(&mut builder, &names[0], 0o755, 0, true, &[])?;
        for (entry, name) in entries.iter().zip(&names[1..]) {
            let bytes = if entry.is_dir {
                Vec::new()
            } else {
                std::fs::read(tree.join(&entry.rel))?
            };
            append_entry(
                &mut builder,
                name,
                normalized_mode(entry),
                bytes.len() as u64,
                entry.is_dir,
                &bytes,
            )?;
        }
        builder.finish().map_err(|e| {
            InterflowError::config("finishing the staging tar".to_string()).with_source(e)
        })?;
    }
    let parent = tree.parent().unwrap_or_else(|| Path::new("."));
    let tar_name = format!(
        "{}.tar",
        tree.file_name().map_or_else(
            || root_name.to_owned(),
            |n| n.to_string_lossy().into_owned()
        )
    );
    let tar_path = parent.join(&tar_name);
    std::fs::write(&tar_path, &tar)?;
    let sha256 = interflow_util::sha256_hex(&tar);
    std::fs::write(
        parent.join(format!("{tar_name}.sha256")),
        format!("{sha256}  {tar_name}\n"),
    )?;
    Ok(tar_path)
}

/// One tar entry, on-disk relative.
struct TarEntry {
    rel: String,
    is_dir: bool,
    /// The executability fact (unix), from which the normalized mode
    /// derives — the tar depends on content and executability only, never
    /// on umask accidents in the staged tree.
    executable: bool,
}

fn collect_tree(root: &Path) -> Result<Vec<TarEntry>> {
    Ok(interflow_util::walk_sorted(root)?
        .into_iter()
        .map(|entry| TarEntry {
            rel: entry.rel,
            is_dir: entry.is_dir,
            executable: !entry.is_dir && entry.mode & 0o111 != 0,
        })
        .collect())
}

/// Directories and executables are 0755, other files 0644.
const fn normalized_mode(entry: &TarEntry) -> u32 {
    if entry.is_dir || entry.executable {
        0o755
    } else {
        0o644
    }
}

/// One appended entry: a ustar header with zeroed identity (uid/gid/mtime)
/// and a hand-set checksum, so the archive bytes are ours end to end.
fn append_entry<W: std::io::Write>(
    builder: &mut tar::Builder<W>,
    name: &str,
    mode: u32,
    size: u64,
    is_dir: bool,
    bytes: &[u8],
) -> Result<()> {
    let mut header = tar::Header::new_ustar();
    header.set_mode(mode);
    header.set_uid(0);
    header.set_gid(0);
    header.set_size(size);
    header.set_mtime(0);
    header.set_entry_type(if is_dir {
        tar::EntryType::Directory
    } else {
        tar::EntryType::Regular
    });
    header.set_path(name)?;
    header.set_cksum();
    builder.append(&header, bytes).map_err(|e| {
        InterflowError::config(format!("writing the staging tar entry {name:?}")).with_source(e)
    })?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The host material rule: cli always; mesh for hubs, mesh-role
    /// agents and ingress edges.
    #[test]
    fn host_binaries_matrix() {
        assert_eq!(
            host_binaries(PackKind::Ingress, false),
            vec!["interflow-cli", "interflow-mesh"]
        );
        assert_eq!(
            host_binaries(PackKind::Hub, true),
            vec!["interflow-cli", "interflow-mesh"]
        );
        assert_eq!(
            host_binaries(PackKind::Agent, true),
            vec!["interflow-cli", "interflow-mesh"]
        );
        assert_eq!(host_binaries(PackKind::Agent, false), vec!["interflow-cli"]);
    }

    fn staged_node(kind: PackKind, node: &str, mesh_role: bool) -> StagedNode {
        StagedNode {
            kind,
            mesh_role,
            dir_name: format!("{}-{node}", kind.as_str()),
            host: format!("{}/{}", kind.as_str(), node),
            node: node.to_owned(),
        }
    }

    /// The machine face is the UNION of its nodes' faces — one copy per
    /// machine: the ECS pair (ingress + hub) carries one dual-binary set,
    /// and a plain-agent addition never adds `interflow-mesh` back.
    #[test]
    fn host_binaries_union_is_the_machine_face() {
        let ecs = vec![
            staged_node(PackKind::Ingress, "edge", false),
            staged_node(PackKind::Hub, "promptcn", true),
        ];
        assert_eq!(
            host_binaries_union(&ecs),
            vec!["interflow-cli", "interflow-mesh"]
        );
        let mut with_plain_agent = ecs;
        with_plain_agent.push(staged_node(PackKind::Agent, "desktop", false));
        assert_eq!(
            host_binaries_union(&with_plain_agent),
            vec!["interflow-cli", "interflow-mesh"]
        );
        assert_eq!(
            host_binaries_union(&[staged_node(PackKind::Agent, "solo", false)]),
            vec!["interflow-cli"]
        );
    }

    #[test]
    fn host_grammar_follows_node_add() {
        assert_eq!(
            resolve_host("ingress/edge").expect("parses"),
            (PackKind::Ingress, "edge".to_owned())
        );
        assert!(resolve_host("gateway/edge").is_err());
        assert!(resolve_host("hub").is_err());
    }

    #[test]
    fn tag_hash_extraction() {
        assert_eq!(tag_hash("2026-11-02_c8906cb"), "c8906cb");
        assert_eq!(tag_hash("2026-11-02_c8906cb-dirty"), "c8906cb");
        assert_eq!(tag_hash("unknown"), "unknown");
    }

    /// Builds a fake artifacts directory: platform-named binaries
    /// embedding the given tag plus a schema-2 build-manifest recording
    /// them — the same shape scripts/build-linux.sh + guard produce.
    fn fake_artifacts(dir: &Path, tag: &str, commit_prefix: &str) {
        let cli = dir.join("interflow-cli-linux-x86_64");
        let mesh = dir.join("interflow-mesh-linux-x86_64");
        std::fs::write(&cli, format!("cli bytes carrying {tag}")).expect("write cli");
        std::fs::write(&mesh, format!("mesh bytes carrying {tag}")).expect("write mesh");
        let cli_sha = interflow_util::sha256_hex(&std::fs::read(&cli).expect("read cli"));
        let mesh_sha = interflow_util::sha256_hex(&std::fs::read(&mesh).expect("read mesh"));
        write_build_manifest(
            dir,
            "build-manifest.build-linux.json",
            commit_prefix,
            &[
                ("interflow-cli-linux-x86_64", &cli_sha),
                ("interflow-mesh-linux-x86_64", &mesh_sha),
            ],
        );
    }

    fn write_build_manifest(dir: &Path, file: &str, commit_prefix: &str, entries: &[(&str, &str)]) {
        let mut commit = commit_prefix.to_owned();
        while commit.len() < 40 {
            commit.push('0');
        }
        let artifacts = entries
            .iter()
            .map(|(name, sha)| {
                format!("{{\"name\":\"{name}\",\"source\":\"s\",\"sha256\":\"{sha}\",\"bytes\":1}}")
            })
            .collect::<Vec<_>>()
            .join(",");
        std::fs::write(
            dir.join(file),
            format!(
                "{{\"schema\":2,\"script\":\"build-linux\",\"timestamp_utc\":\"x\",\"git\":\
                 {{\"describe\":\"x\",\"commit\":\"{commit}\"}},\"tree_state\":\"clean\",\
                 \"escape_hatch\":null,\"artifacts\":[{artifacts}]}}"
            ),
        )
        .expect("write manifest");
    }

    fn expected_tag() -> String {
        // The real gate runs against the compiled-in BUILD_TAG; the test
        // binary and the library share it.
        BUILD_TAG.to_owned()
    }

    fn expected_hash() -> String {
        tag_hash(BUILD_TAG).to_owned()
    }

    /// The record path: matching commit + matching sha256 + tag in the
    /// bytes resolves both binaries.
    #[test]
    fn record_path_resolves_verified_binaries() {
        let tmp = tempfile::tempdir().expect("tempdir");
        fake_artifacts(tmp.path(), &expected_tag(), &expected_hash());
        let resolved =
            resolve_binaries(tmp.path(), &["interflow-cli", "interflow-mesh"]).expect("resolves");
        assert_eq!(resolved.len(), 2);
        assert_eq!(resolved[0].name, "interflow-cli");
        assert_eq!(
            resolved[0].source,
            tmp.path().join("interflow-cli-linux-x86_64")
        );
        assert_eq!(resolved[1].name, "interflow-mesh");
    }

    /// A record from a different commit (the §10.18 stale-linux class)
    /// refuses with expected/found.
    #[test]
    fn stale_commit_refuses() {
        let tmp = tempfile::tempdir().expect("tempdir");
        fake_artifacts(tmp.path(), "2020-01-01_deadbee", "deadbee");
        let err = resolve_binaries(tmp.path(), &["interflow-cli", "interflow-mesh"])
            .expect_err("stale record refuses");
        let text = err.to_string();
        assert!(text.contains("no build-manifest"), "{text}");
        assert!(text.contains(BUILD_TAG), "{text}");
        assert!(text.contains("deadbee"), "{text}");
    }

    /// Bytes that no longer match the record's sha256 refuse — the file
    /// changed after the build shipped it.
    #[test]
    fn sha_mismatch_refuses() {
        let tmp = tempfile::tempdir().expect("tempdir");
        fake_artifacts(tmp.path(), &expected_tag(), &expected_hash());
        // Corrupt the mesh artifact under the recorded name.
        let mesh = tmp.path().join("interflow-mesh-linux-x86_64");
        std::fs::write(&mesh, format!("tampered, still tagged {}", expected_tag()))
            .expect("write mesh");
        let err = resolve_binaries(tmp.path(), &["interflow-cli", "interflow-mesh"])
            .expect_err("sha mismatch refuses");
        assert!(
            err.to_string()
                .contains("does not match its build-manifest entry"),
            "{}",
            err
        );
    }

    /// A record that vouches for the bytes but bytes from another build
    /// (the tag scan disagrees) refuses — defense in depth.
    #[test]
    fn content_gate_refuses_foreign_tag() {
        let tmp = tempfile::tempdir().expect("tempdir");
        // Manifest for THIS build's commit, artifacts carrying an old tag,
        // and the record re-written for those foreign bytes — only the tag
        // scan can catch it.
        let cli = tmp.path().join("interflow-cli-linux-x86_64");
        let mesh = tmp.path().join("interflow-mesh-linux-x86_64");
        std::fs::write(&cli, "foreign build 2020-01-01_deadbee").expect("write cli");
        std::fs::write(&mesh, "foreign build 2020-01-01_deadbee").expect("write mesh");
        let cli_sha = interflow_util::sha256_hex(&std::fs::read(&cli).expect("read"));
        let mesh_sha = interflow_util::sha256_hex(&std::fs::read(&mesh).expect("read"));
        write_build_manifest(
            tmp.path(),
            "build-manifest.build-linux.json",
            &expected_hash(),
            &[
                ("interflow-cli-linux-x86_64", &cli_sha),
                ("interflow-mesh-linux-x86_64", &mesh_sha),
            ],
        );
        let err = resolve_binaries(tmp.path(), &["interflow-cli", "interflow-mesh"])
            .expect_err("foreign tag refuses");
        let text = err.to_string();
        assert!(
            text.contains("refusing to stage binaries from a different build"),
            "{text}"
        );
    }

    /// Two records matching this build and carrying the binaries refuse —
    /// a single-platform artifacts set is required.
    #[test]
    fn ambiguous_records_refuse() {
        let tmp = tempfile::tempdir().expect("tempdir");
        fake_artifacts(tmp.path(), &expected_tag(), &expected_hash());
        let first = std::fs::read_to_string(tmp.path().join("build-manifest.build-linux.json"))
            .expect("read manifest");
        std::fs::write(
            tmp.path().join("build-manifest.build-linux-arm64.json"),
            first,
        )
        .expect("write second manifest");
        let err = resolve_binaries(tmp.path(), &["interflow-cli", "interflow-mesh"])
            .expect_err("ambiguity refuses");
        assert!(err.to_string().contains("single platform"), "{}", err);
    }

    /// No record at all (a target/release-style directory): exact
    /// canonical names + the content gate.
    #[test]
    fn exact_name_fallback_resolves() {
        let tmp = tempfile::tempdir().expect("tempdir");
        std::fs::write(
            tmp.path().join("interflow-cli"),
            format!("release cli {tag}", tag = expected_tag()),
        )
        .expect("write cli");
        let resolved = resolve_binaries(tmp.path(), &["interflow-cli"]).expect("resolves");
        assert_eq!(resolved.len(), 1);
        let err = resolve_binaries(tmp.path(), &["interflow-cli", "interflow-mesh"])
            .expect_err("missing mesh refuses");
        assert!(
            err.to_string().contains("interflow-mesh not found"),
            "{}",
            err
        );
    }

    /// The manifest is valid JSON, sorted, single-line entries, and the
    /// exact shape the bash gate greps. Schema 2: the machine's node list
    /// is an array — a single-node tree and a `--with` tree share one
    /// shape.
    #[test]
    fn stage_manifest_shape() {
        let files = vec![
            StagedFile {
                rel: "bin/interflow-cli".to_owned(),
                sha256: "a".repeat(64),
                bytes: 7,
            },
            StagedFile {
                rel: "install.sh".to_owned(),
                sha256: "b".repeat(64),
                bytes: 9,
            },
        ];
        let hosts = vec!["ingress/edge".to_owned()];
        let text = render_stage_manifest(&hosts, &files);
        let value: serde_json::Value = serde_json::from_str(&text).expect("valid json");
        assert_eq!(value["schema"], 2);
        assert_eq!(value["kind"], STAGE_MANIFEST_KIND);
        assert_eq!(value["hosts"], serde_json::json!(hosts));
        assert_eq!(value["generated_by"], serde_json::json!(VERSION_WITH_TAG));
        assert_eq!(value["files"].as_array().expect("files").len(), 2);
        // The grep target: one line per entry, fixed spacing, 64 hex.
        assert!(
            text.contains(&format!(
                "    {{\"path\": \"bin/interflow-cli\", \"sha256\": \"{}\", \"bytes\": 7}},",
                "a".repeat(64)
            )),
            "{text}"
        );
        // Deterministic: same input, same bytes.
        assert_eq!(text, render_stage_manifest(&hosts, &files));
        // A multi-node tree lists every node, in the order staged.
        let merged = render_stage_manifest(
            &["ingress/edge".to_owned(), "hub/promptcn".to_owned()],
            &files,
        );
        let merged_value: serde_json::Value = serde_json::from_str(&merged).expect("valid json");
        assert_eq!(
            merged_value["hosts"],
            serde_json::json!(["ingress/edge", "hub/promptcn"])
        );
    }

    /// The tar is a valid ustar the system tar can list, and byte-stable
    /// across runs.
    #[test]
    #[cfg(unix)]
    fn deterministic_tar_round_trip() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let tree = tmp.path().join("ingress-edge");
        std::fs::create_dir_all(tree.join("bin")).expect("dirs");
        std::fs::write(tree.join("bin/interflow-cli"), b"engine").expect("write");
        std::fs::write(tree.join("install.sh"), b"#!/bin/sh\n").expect("write");
        let tar = write_tar_pair(&tree, "ingress-edge").expect("tar");
        let first = std::fs::read(&tar).expect("read tar");
        let again = write_tar_pair(&tree, "ingress-edge").expect("tar again");
        let second = std::fs::read(&again).expect("read tar again");
        assert_eq!(
            first, second,
            "re-staging must reproduce the tar byte for byte"
        );
        // The system tar reads it back.
        let listing = std::process::Command::new("tar")
            .arg("-tf")
            .arg(&tar)
            .output()
            .expect("run tar");
        assert!(listing.status.success(), "system tar must read our ustar");
        let names = String::from_utf8_lossy(&listing.stdout).to_string();
        assert!(names.contains("ingress-edge/"), "{names}");
        assert!(names.contains("ingress-edge/bin/interflow-cli"), "{names}");
        assert!(names.contains("ingress-edge/install.sh"), "{names}");
        // And extracts it intact.
        let unpack = tempfile::tempdir().expect("unpack dir");
        let status = std::process::Command::new("tar")
            .arg("-xf")
            .arg(&tar)
            .current_dir(unpack.path())
            .status()
            .expect("run tar extract");
        assert!(status.success());
        assert_eq!(
            std::fs::read(unpack.path().join("ingress-edge/bin/interflow-cli")).expect("read back"),
            b"engine"
        );
    }

    /// The ustar header our writer builds, verified byte by byte: POSIX
    /// magic, zeroed identity, the mode we normalized, the size in octal,
    /// and a checksum that follows the ustar spaces rule.
    #[test]
    fn ustar_header_fields() {
        let mut header = tar::Header::new_ustar();
        header.set_mode(0o755);
        header.set_uid(0);
        header.set_gid(0);
        header.set_size(u64::from(0o12345u32));
        header.set_mtime(0);
        header.set_entry_type(tar::EntryType::Regular);
        header.set_path("some/name").expect("short path");
        header.set_cksum();
        let header = header.as_bytes();
        assert_eq!(&header[257..263], b"ustar\0");
        assert_eq!(header[156], b'0');
        assert_eq!(&header[100..107], b"0000755".as_slice());
        assert_eq!(&header[108..115], b"0000000".as_slice()); // uid
        assert_eq!(&header[136..147], b"00000000000".as_slice()); // mtime = 0
        // size: 11 zero-padded octal digits + NUL (0o12345 → 5 digits).
        assert_eq!(&header[124..135], b"00000012345".as_slice());
        assert_eq!(header[135], 0);
        // The checksum is the header sum with the checksum field read as
        // eight spaces (the ustar rule), stored as six octal digits.
        let mut sum: u32 = 0;
        for (i, byte) in header.iter().enumerate() {
            let byte = if (148..156).contains(&i) { b' ' } else { *byte };
            sum = sum.wrapping_add(u32::from(byte));
        }
        // The stored checksum (spelled as the tar crate's octal-into-field
        // form) equals the spaces-rule sum numerically.
        let stored: String = header[148..156]
            .iter()
            .take_while(|b| **b != 0 && **b != b' ')
            .map(|b| char::from(*b))
            .collect();
        let stored = u32::from_str_radix(&stored, 8).expect("octal checksum");
        assert_eq!(stored, sum);
    }

    /// Modes are normalized, not inherited: the archive's bytes depend on
    /// content and executability only — a umask accident in the staged
    /// tree cannot fork the digest.
    #[test]
    #[cfg(unix)]
    fn tar_modes_are_normalized() {
        use std::os::unix::fs::PermissionsExt;
        let tmp = tempfile::tempdir().expect("tempdir");
        let tree = tmp.path().join("modes");
        std::fs::create_dir_all(&tree).expect("dirs");
        std::fs::write(tree.join("plain"), b"data").expect("write");
        std::fs::write(tree.join("runner"), b"#!/bin/sh\n").expect("write");
        std::fs::set_permissions(tree.join("plain"), std::fs::Permissions::from_mode(0o600))
            .expect("chmod");
        std::fs::set_permissions(tree.join("runner"), std::fs::Permissions::from_mode(0o700))
            .expect("chmod");
        let tar_path = write_tar_pair(&tree, "modes").expect("tar");
        let mut archive = tar::Archive::new(std::fs::File::open(&tar_path).expect("open"));
        let modes: Vec<(String, u32)> = archive
            .entries()
            .expect("entries")
            .map(|entry| {
                let entry = entry.expect("entry");
                let mode = entry.header().mode().expect("mode");
                let name = entry.path().expect("path").to_string_lossy().into_owned();
                (name, mode)
            })
            .collect();
        assert!(modes.contains(&("modes/".to_owned(), 0o755)), "{modes:?}");
        assert!(
            modes.contains(&("modes/plain".to_owned(), 0o644)),
            "0600 in the tree lands as 0644 in the archive: {modes:?}"
        );
        assert!(
            modes.contains(&("modes/runner".to_owned(), 0o755)),
            "{modes:?}"
        );
    }
}
