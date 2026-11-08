//! `plan stage` — the per-host minimal staging tree, through the shipped
//! binary against real `plan apply` output
//!
//! The acceptance matrix, machine-locked: each host role stages exactly its
//! material set (zero extra files — never another node's pack), the three
//! staging incidents refuse at production time (stale artifact build,
//! missing artifact, corrupt pack), the freshness gate refuses until the
//! declaration is the one the dist tree renders, re-staging is
//! byte-stable, and the real `install.sh --verify-staging` gates a
//! transferred tree (a flipped byte, a missing file and a stray file all
//! fail it). The nginx fragments are always THIS build's fresh render (a
//! dist tree lagging the build never ships), and one machine hosting
//! several nodes stages ONE tree via `--with` — the union of its
//! single-node trees minus one duplicated base.
//!
//! Artifacts are fixtures shaped like the real thing: platform-named
//! binaries embedding this build's tag plus the schema-2 build-manifest
//! guard writes (the shipped binary under test and this test file compile
//! in the same `BUILD_TAG`).

mod common;

use common::{RunOutcome, run};
use interflow_buildinfo::BUILD_TAG;
use std::path::{Path, PathBuf};
use std::process::Command;

/// Expose face: frontend-proxy ingress + one plain (service-only) agent —
/// the ingress role stages nginx fragments and both binaries.
const EXPOSE_MANIFEST: &str = r#"
[realm]
id = "stage-expose"
control_endpoint = "127.0.0.1:16666"

[public_tls]
mode = "frontend-proxy"

[identity]
mode = "offline"
leaf_ttl = "90d"

[ingress.edge]
workspaces = ["main"]
listen = "127.0.0.1:8443"
control_listen = "127.0.0.1:16666"

[workspace.main]

[agent.desktop]
workspace = "main"

[[agent.desktop.services]]
id = "asr"
address = "127.0.0.1:8080"

[[route]]
host = "asr.example.com"
service = "main/desktop/asr"
"#;

/// Mesh face: one hub + a mesh-role agent pair — the hub and mesh-agent
/// roles stage the dual-binary set, no nginx. The hub endpoint is a closed
/// loopback port so apply degrades to manual distribution (fast,
/// deterministic).
const MESH_MANIFEST: &str = r#"
[realm]
id = "stage-mesh"

[identity]
mode = "offline"
leaf_ttl = "7d"

[mesh.hub.promptcn]
listen = "127.0.0.1:16666"
endpoint = "127.0.0.1:1"

[workspace.main]

[agent.connector]
workspace = "main"

[[agent.connector.mesh_ingress]]
name = "ragflow"
listen = "127.0.0.1:18000"
target_agent = "backend"
remote_addr = "127.0.0.1:80"

[agent.backend]
workspace = "main"

[[agent.backend.mesh_egress]]
name = "ragflow"
target_addr = "127.0.0.1:80"
"#;

/// The ECS shape: one machine hosting an ingress edge AND a hub — the
/// `--with` face. The hub endpoint is a closed loopback port (manual
/// distribution, fast and deterministic) and the topology is
/// frontend-proxy, so the merged tree carries the hub's pack beside the
/// ingress's nginx fragments.
const MERGED_MANIFEST: &str = r#"
[realm]
id = "stage-merged"
control_endpoint = "127.0.0.1:16666"

[public_tls]
mode = "frontend-proxy"

[identity]
mode = "offline"
leaf_ttl = "90d"

[mesh.hub.promptcn]
listen = "127.0.0.1:6666"
endpoint = "127.0.0.1:1"

[ingress.edge]
workspaces = ["main"]
listen = "127.0.0.1:8443"
control_listen = "127.0.0.1:16666"

[workspace.main]

[agent.desktop]
workspace = "main"

[[agent.desktop.services]]
id = "asr"
address = "127.0.0.1:8080"

[[route]]
host = "asr.example.com"
service = "main/desktop/asr"

[agent.connector]
workspace = "main"

[[agent.connector.mesh_ingress]]
name = "ragflow"
listen = "127.0.0.1:18000"
target_agent = "backend"
remote_addr = "127.0.0.1:80"

[agent.backend]
workspace = "main"

[[agent.backend.mesh_egress]]
name = "ragflow"
target_addr = "127.0.0.1:80"
"#;

/// Writes an artifacts set for this build: platform-named binaries
/// embedding `BUILD_TAG` plus the schema-2 build-manifest guard writes
/// (commit = this build's hash, zero-padded to the full form).
fn write_artifacts(dir: &Path, tag: &str, commit_hash: &str) {
    std::fs::create_dir_all(dir).unwrap();
    let mut entries = Vec::new();
    for name in ["interflow-cli-linux-x86_64", "interflow-mesh-linux-x86_64"] {
        std::fs::write(dir.join(name), format!("{name} engine bytes, build {tag}")).unwrap();
        let sha = interflow_util::sha256_hex(&std::fs::read(dir.join(name)).unwrap());
        entries.push(format!(
            "{{\"name\":\"{name}\",\"source\":\"s\",\"sha256\":\"{sha}\",\"bytes\":1}}"
        ));
    }
    let mut commit = commit_hash.to_owned();
    while commit.len() < 40 {
        commit.push('0');
    }
    std::fs::write(
        dir.join("build-manifest.build-linux.json"),
        format!(
            "{{\"schema\":2,\"script\":\"build-linux\",\"timestamp_utc\":\"x\",\"git\":\
             {{\"describe\":\"x\",\"commit\":\"{commit}\"}},\"tree_state\":\"clean\",\
             \"escape_hatch\":null,\"artifacts\":[{}]}}",
            entries.join(",")
        ),
    )
    .unwrap();
}

/// This build's tag hash, as the shipped binary under test sees it.
fn this_build_hash() -> String {
    let rest = BUILD_TAG
        .split_once('_')
        .map_or(BUILD_TAG, |(_, rest)| rest);
    rest.strip_suffix("-dirty").unwrap_or(rest).to_owned()
}

struct Env {
    dir: PathBuf,
}

impl Env {
    /// A fresh environment: manifest written, artifacts for this build in
    /// place, no apply yet.
    fn fresh(manifest_text: &str) -> Self {
        let env = Self {
            dir: tempfile::tempdir().unwrap().keep(),
        };
        std::fs::write(env.dir.join("interflow.toml"), manifest_text).unwrap();
        write_artifacts(&env.dir.join("artifacts"), BUILD_TAG, &this_build_hash());
        env
    }

    /// A fresh applied environment.
    fn applied(manifest_text: &str) -> Self {
        let env = Self::fresh(manifest_text);
        let applied = env.apply();
        assert!(applied.success, "fixture apply: {}", applied.stderr);
        env
    }

    fn manifest_path(&self) -> PathBuf {
        self.dir.join("interflow.toml")
    }

    fn manifest(&self) -> String {
        self.manifest_path().display().to_string()
    }

    fn rewrite_manifest(&self, from: &str, to: &str) {
        let text = std::fs::read_to_string(self.manifest_path()).unwrap();
        assert!(text.contains(from), "fixture edit anchor {from:?} missing");
        std::fs::write(self.manifest_path(), text.replace(from, to)).unwrap();
    }

    fn dist(&self) -> PathBuf {
        self.dir.join("dist")
    }

    fn stage_root(&self) -> PathBuf {
        self.dir.join("stage")
    }

    fn staged(&self, host: &str) -> PathBuf {
        self.stage_root().join(host.replace('/', "-"))
    }

    fn apply(&self) -> RunOutcome {
        let issuer = self.dir.join("issuer").display().to_string();
        let out = self.dist().display().to_string();
        run(&[
            "plan",
            "apply",
            "--manifest",
            &self.manifest(),
            "--issuer",
            &issuer,
            "--out",
            &out,
        ])
    }

    fn stage(&self, host: &str) -> RunOutcome {
        let artifacts = self.dir.join("artifacts").display().to_string();
        let to = self.staged(host).display().to_string();
        let issuer = self.dir.join("issuer").display().to_string();
        let out = self.dist().display().to_string();
        run(&[
            "plan",
            "stage",
            "--host",
            host,
            "--manifest",
            &self.manifest(),
            "--issuer",
            &issuer,
            "--out",
            &out,
            "--artifacts",
            &artifacts,
            "--to",
            &to,
        ])
    }

    /// Stages one merged machine tree: `--host <primary> --with <each>`.
    /// The output directory mirrors the default naming, the specs joined
    /// by `+`.
    fn stage_with(&self, host: &str, with: &[&str]) -> RunOutcome {
        let manifest = self.manifest();
        let issuer = self.dir.join("issuer").display().to_string();
        let out = self.dist().display().to_string();
        let artifacts = self.dir.join("artifacts").display().to_string();
        let to = self.staged_merged(host, with).display().to_string();
        let mut args = vec!["plan", "stage", "--host", host];
        for spec in with {
            args.push("--with");
            args.push(spec);
        }
        args.extend([
            "--manifest",
            &manifest,
            "--issuer",
            &issuer,
            "--out",
            &out,
            "--artifacts",
            &artifacts,
            "--to",
            &to,
        ]);
        run(&args)
    }

    fn staged_merged(&self, host: &str, with: &[&str]) -> PathBuf {
        let dir_name = std::iter::once(host)
            .chain(with.iter().copied())
            .map(|spec| spec.replace('/', "-"))
            .collect::<Vec<_>>()
            .join("+");
        self.stage_root().join(dir_name)
    }
}

/// Every regular file under `dir`, sorted, forward-slash relative.
fn walk_files(dir: &Path) -> Vec<String> {
    fn walk(dir: &Path, prefix: &str, out: &mut Vec<String>) {
        let mut entries: Vec<_> = std::fs::read_dir(dir)
            .unwrap()
            .collect::<Result<_, _>>()
            .unwrap();
        entries.sort_by_key(std::fs::DirEntry::file_name);
        for entry in entries {
            let name = entry.file_name().to_string_lossy().into_owned();
            let rel = if prefix.is_empty() {
                name
            } else {
                format!("{prefix}/{name}")
            };
            if entry.file_type().unwrap().is_dir() {
                walk(&entry.path(), &rel, out);
            } else {
                out.push(rel);
            }
        }
    }
    let mut files = Vec::new();
    walk(dir, "", &mut files);
    files
}

/// The wrapper set every staging tree carries around its pack.
const TREE_WRAPPER: [&str; 4] = [
    "bin/interflow-cli",
    "bin/interflow-mesh",
    "install.sh",
    "stage-manifest.json",
];
const TREE_WRAPPER_CLI_ONLY: [&str; 3] = ["bin/interflow-cli", "install.sh", "stage-manifest.json"];

/// Asserts the staged tree is EXACTLY the wrapper set + the dist pack's
/// file set (+ the given extras, e.g. nginx) — the zero-extra-files lock:
/// never another node's pack, never a unit, never the policy mirror.
fn assert_minimal_face(env: &Env, host: &str, wrapper: &[&str], extras: &[&str]) {
    let dir_name = host.replace('/', "-");
    let mut expected: Vec<String> = wrapper.iter().map(|s| (*s).to_owned()).collect();
    expected.extend(
        walk_files(&env.dist().join("packs").join(&dir_name))
            .into_iter()
            .map(|rel| format!("packs/{dir_name}/{rel}")),
    );
    expected.extend(extras.iter().map(|s| (*s).to_owned()));
    expected.sort();
    let got = walk_files(&env.staged(host));
    assert_eq!(
        got, expected,
        "{host}: the staging tree must be exactly the host's minimal face"
    );

    // The staging manifest lists exactly the tree minus itself.
    let manifest: serde_json::Value = serde_json::from_str(
        &std::fs::read_to_string(env.staged(host).join("stage-manifest.json")).unwrap(),
    )
    .unwrap();
    let listed: Vec<&str> = manifest["files"]
        .as_array()
        .unwrap()
        .iter()
        .map(|f| f["path"].as_str().unwrap())
        .collect();
    let tree_minus_manifest: Vec<&str> = got
        .iter()
        .map(String::as_str)
        .filter(|p| *p != "stage-manifest.json")
        .collect();
    assert_eq!(listed, tree_minus_manifest, "{host}: manifest ↔ tree");

    // The tar pair ships beside the tree.
    assert!(env.stage_root().join(format!("{dir_name}.tar")).is_file());
    assert!(
        env.stage_root()
            .join(format!("{dir_name}.tar.sha256"))
            .is_file()
    );
}

fn verify_staging(tree: &Path) -> std::process::Output {
    Command::new("bash")
        .arg(tree.join("install.sh"))
        .arg("--verify-staging")
        .output()
        .unwrap()
}

// ---------------------------------------------------------------------------
// The role × content matrix (acceptance #1)
// ---------------------------------------------------------------------------

#[test]
fn ingress_stage_is_the_dual_binary_face_with_nginx() {
    let env = Env::applied(EXPOSE_MANIFEST);
    let staged = env.stage("ingress/edge");
    assert!(staged.success, "{}", staged.stderr);
    assert!(
        staged.stdout.contains("✔ staged ingress/edge"),
        "{}",
        staged.stdout
    );
    assert_minimal_face(
        &env,
        "ingress/edge",
        &TREE_WRAPPER,
        &[
            "nginx/stream/interflow-stream.conf",
            "nginx/http/interflow-shared.conf",
            "nginx/http/interflow-http.conf",
            "nginx/http/interflow-vhost-edge.conf",
        ],
    );
    // The binaries are the verified artifacts (this build's tag), not
    // something the dist tree carried.
    let mesh =
        std::fs::read_to_string(env.staged("ingress/edge").join("bin/interflow-mesh")).unwrap();
    assert!(mesh.contains(BUILD_TAG), "{mesh}");
}

#[test]
fn plain_agent_stage_is_cli_only_and_carries_no_foreign_pack() {
    let env = Env::applied(EXPOSE_MANIFEST);
    let staged = env.stage("agent/desktop");
    assert!(staged.success, "{}", staged.stderr);
    // No nginx, no second binary — and (via the exact set) no other
    // node's pack: the §10.15 minimal face, machine-locked.
    assert_minimal_face(&env, "agent/desktop", &TREE_WRAPPER_CLI_ONLY, &[]);
}

#[test]
fn hub_stage_is_the_dual_binary_face_without_nginx() {
    let env = Env::applied(MESH_MANIFEST);
    let staged = env.stage("hub/promptcn");
    assert!(staged.success, "{}", staged.stderr);
    assert_minimal_face(&env, "hub/promptcn", &TREE_WRAPPER, &[]);
}

#[test]
fn mesh_agent_stage_is_the_dual_binary_face() {
    let env = Env::applied(MESH_MANIFEST);
    let staged = env.stage("agent/connector");
    assert!(staged.success, "{}", staged.stderr);
    assert_minimal_face(&env, "agent/connector", &TREE_WRAPPER, &[]);
}

// ---------------------------------------------------------------------------
// The three incidents, injected (acceptance #2 + #4)
// ---------------------------------------------------------------------------

/// ① / ② (+ the §10.18 factory miss): artifacts from a stale build —
/// the record's commit and the bytes' tag both belong to another build —
/// refuse before anything is staged.
#[test]
fn stale_artifact_build_refuses() {
    let env = Env::applied(EXPOSE_MANIFEST);
    write_artifacts(&env.dir.join("artifacts"), "2020-01-01_deadbee", "deadbee");
    let staged = env.stage("ingress/edge");
    assert!(!staged.success, "a stale artifact set must refuse");
    assert!(
        staged.stderr.contains("no build-manifest")
            && staged.stderr.contains(BUILD_TAG)
            && staged.stderr.contains("deadbee"),
        "expected/found must both be named: {}",
        staged.stderr
    );
    assert!(
        !env.staged("ingress/edge").exists(),
        "a refusal must leave no half tree"
    );
}

/// ②'s shape at the record level: the record matches this build but does
/// not carry one of the host's binaries (the mesh file itself stays on
/// disk — the record decides, not the directory listing).
#[test]
fn incomplete_artifact_record_refuses() {
    let env = Env::applied(MESH_MANIFEST);
    let record_path = env.dir.join("artifacts/build-manifest.build-linux.json");
    let mut record: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&record_path).unwrap()).unwrap();
    record["artifacts"] = serde_json::Value::Array(
        record["artifacts"]
            .as_array()
            .unwrap()
            .iter()
            .filter(|entry| entry["name"].as_str().unwrap() != "interflow-mesh-linux-x86_64")
            .cloned()
            .collect(),
    );
    std::fs::write(&record_path, serde_json::to_string(&record).unwrap()).unwrap();
    let staged = env.stage("hub/promptcn");
    assert!(!staged.success, "a record missing a binary must refuse");
    assert!(
        staged.stderr.contains("interflow-mesh"),
        "{}",
        staged.stderr
    );
    assert!(!env.staged("hub/promptcn").exists());
}

/// ③: a pack whose subdirectories went missing (the `cp` without `-R`
/// shape) refuses at staging time — `load_runtime` fails on the staged
/// copy, not at install time on the server.
#[test]
fn corrupt_dist_pack_refuses() {
    let env = Env::applied(EXPOSE_MANIFEST);
    std::fs::remove_dir_all(env.dist().join("packs/agent-desktop/identity")).unwrap();
    let staged = env.stage("agent/desktop");
    assert!(!staged.success, "a pack missing its identity/ must refuse");
    assert!(
        staged.stderr.contains("credential pack error"),
        "{}",
        staged.stderr
    );
    assert!(
        !env.staged("agent/desktop").exists(),
        "a refusal must leave no half tree"
    );
}

// ---------------------------------------------------------------------------
// The freshness gate (acceptance: staging ships the current declaration)
// ---------------------------------------------------------------------------

#[test]
fn freshness_gate_refuses_until_the_declaration_is_rendered() {
    let env = Env::applied(MESH_MANIFEST);

    // An identity-face edit pending (the hub endpoint feeds SANs) → the
    // next apply re-renders → staging refuses, quoting diff's verdict.
    env.rewrite_manifest("endpoint = \"127.0.0.1:1\"", "endpoint = \"127.0.0.1:2\"");
    let staged = env.stage("hub/promptcn");
    assert!(!staged.success, "pending identity edits must refuse");
    assert!(
        staged.stderr.contains("refusing to stage")
            && staged.stderr.contains("identity-face edits pending"),
        "{}",
        staged.stderr
    );
    assert!(!env.staged("hub/promptcn").exists());

    // Applied → stageable; the tree is the current render.
    let applied = env.apply();
    assert!(applied.success, "{}", applied.stderr);
    let staged = env.stage("hub/promptcn");
    assert!(staged.success, "{}", staged.stderr);

    // A policy-face edit rides the fast path, which does not touch pack
    // bytes — staging proceeds and says so (the pack baseline ships; nodes
    // hot-apply the new generation from the hub). Both sides of the mesh
    // rule move together (the declaration validates symmetric rules).
    env.rewrite_manifest("127.0.0.1:80", "127.0.0.1:81");
    let staged = env.stage("hub/promptcn");
    assert!(staged.success, "{}", staged.stderr);
    assert!(
        staged.stdout.contains("policy-face edits pending"),
        "{}",
        staged.stdout
    );
}

#[test]
fn never_applied_refuses() {
    let env = Env::fresh(EXPOSE_MANIFEST);
    let staged = env.stage("ingress/edge");
    assert!(!staged.success, "staging before any apply must refuse");
    assert!(
        staged.stderr.contains("refusing to stage") && staged.stderr.contains("never applied"),
        "{}",
        staged.stderr
    );
}

// ---------------------------------------------------------------------------
// The transfer gate (acceptance #3) — the real bash, the real tree
// ---------------------------------------------------------------------------

#[test]
fn verify_staging_gates_a_transferred_tree() {
    let env = Env::applied(EXPOSE_MANIFEST);
    let tree = env.staged("ingress/edge");
    let staged = env.stage("ingress/edge");
    assert!(staged.success, "{}", staged.stderr);

    let pristine = verify_staging(&tree);
    assert!(
        pristine.status.success(),
        "a pristine tree must verify: {}",
        String::from_utf8_lossy(&pristine.stderr)
    );

    // A flipped byte anywhere in the tree fails the gate.
    let bin = tree.join("bin/interflow-mesh");
    let mut bytes = std::fs::read(&bin).unwrap();
    bytes[0] ^= 0xff;
    std::fs::write(&bin, &bytes).unwrap();
    assert!(
        !verify_staging(&tree).status.success(),
        "a flipped byte must fail the gate"
    );

    // Re-staging is the honest repair: the marker wipe rebuilds the tree.
    let staged = env.stage("ingress/edge");
    assert!(staged.success, "{}", staged.stderr);
    assert!(verify_staging(&tree).status.success());

    // A stray file the manifest does not list fails the gate.
    std::fs::write(tree.join("stray.txt"), "hand-added").unwrap();
    assert!(
        !verify_staging(&tree).status.success(),
        "an unlisted file must fail the gate"
    );

    // A listed file gone missing fails the gate.
    let staged = env.stage("ingress/edge");
    assert!(staged.success, "{}", staged.stderr);
    std::fs::remove_file(tree.join("packs/ingress-edge/pack.toml")).unwrap();
    assert!(
        !verify_staging(&tree).status.success(),
        "a missing listed file must fail the gate"
    );
}

// ---------------------------------------------------------------------------
// Determinism & idempotence (acceptance: re-staging is byte-stable)
// ---------------------------------------------------------------------------

#[test]
fn restaging_is_byte_stable_and_wipes_strays() {
    let env = Env::applied(MESH_MANIFEST);
    let staged = env.stage("hub/promptcn");
    assert!(staged.success, "{}", staged.stderr);
    let dir_name = "hub-promptcn";
    let first_manifest =
        std::fs::read(env.stage_root().join(dir_name).join("stage-manifest.json")).unwrap();
    let first_tar = std::fs::read(env.stage_root().join(format!("{dir_name}.tar"))).unwrap();

    // A stray file inside our own tree disappears on the re-stage (the
    // marker wipe owns the directory), and the outputs reproduce byte for
    // byte.
    std::fs::write(env.staged("hub/promptcn").join("stray.txt"), "leftover").unwrap();
    let staged = env.stage("hub/promptcn");
    assert!(staged.success, "{}", staged.stderr);
    assert!(!env.staged("hub/promptcn").join("stray.txt").exists());
    let second_manifest =
        std::fs::read(env.staged("hub/promptcn").join("stage-manifest.json")).unwrap();
    let second_tar = std::fs::read(env.stage_root().join(format!("{dir_name}.tar"))).unwrap();
    assert_eq!(first_manifest, second_manifest, "manifest must be stable");
    assert_eq!(first_tar, second_tar, "tar must be stable");
}

// ---------------------------------------------------------------------------
// The fragment re-render — the fragments' freshness face
// ---------------------------------------------------------------------------

/// The nginx fragments every ingress staging tree carries.
const NGINX_FRAGMENT_RELS: [&str; 4] = [
    "nginx/stream/interflow-stream.conf",
    "nginx/http/interflow-shared.conf",
    "nginx/http/interflow-http.conf",
    "nginx/http/interflow-vhost-edge.conf",
];

/// Asserts every staged fragment is exactly THIS build's fresh render —
/// the same pure functions `plan apply` renders with, vintage header
/// naming this build and the manifest's digest. The library call is the
/// single source: the test cannot drift from the renderer.
fn assert_fragments_are_the_fresh_render(env: &Env, node: &str) {
    let manifest_text = std::fs::read_to_string(env.manifest_path()).unwrap();
    let sha = interflow_util::sha256_hex(manifest_text.as_bytes());
    let manifest = interflow_identity::manifest::Manifest::parse(&manifest_text).unwrap();
    let set = interflow_cli::render::nginx_fragment_set(&manifest, &sha, Some(&[node.to_owned()]))
        .unwrap();
    assert_eq!(set.len(), 4, "shared three + the host's own vhost");
    for piece in &set {
        let staged =
            std::fs::read(env.staged(&format!("ingress/{node}")).join(&piece.rel)).unwrap();
        assert_eq!(
            staged,
            piece.body.as_bytes(),
            "{}: the staged fragment must be this build's render",
            piece.rel
        );
    }
}

/// Stale fragments in dist never reach a staging tree: the fragments are
/// re-rendered by this build from the current declaration, the drift is
/// named (exactly the lagging file), and the staged copy is byte-identical
/// to the fresh render whatever dist carries — `--verify-staging` green
/// included, because the tree itself is current, not merely
/// self-consistent.
#[test]
fn stale_dist_fragments_never_reach_the_staging_tree() {
    let env = Env::applied(EXPOSE_MANIFEST);
    // Dist carries a tampered fragment — the shape of an older build's
    // renderer output (or anything else having rewritten it).
    let vhost = env.dist().join("nginx/http/interflow-vhost-edge.conf");
    std::fs::write(&vhost, "# an older build's fragment output\n").unwrap();
    let staged = env.stage("ingress/edge");
    assert!(staged.success, "{}", staged.stderr);
    assert!(
        staged
            .stdout
            .contains("nginx fragments re-rendered from the current declaration"),
        "the drift sentinel must fire: {}",
        staged.stdout
    );
    // Exactly the lagging file is named — the untouched three stay silent.
    assert!(
        staged
            .stdout
            .contains("(nginx/http/interflow-vhost-edge.conf)"),
        "{}",
        staged.stdout
    );
    assert!(
        !staged.stdout.contains("interflow-stream.conf"),
        "an untouched fragment must not be named: {}",
        staged.stdout
    );
    assert_fragments_are_the_fresh_render(&env, "edge");
    assert!(
        verify_staging(&env.staged("ingress/edge")).status.success(),
        "the re-rendered tree must verify"
    );
}

/// A current dist tree (same build, same declaration) produces zero noise:
/// no drift ℹ, and the staged fragments are byte-identical to dist's —
/// apply and stage render from one source.
#[test]
fn fresh_dist_fragments_stage_silently_and_byte_identically() {
    let env = Env::applied(EXPOSE_MANIFEST);
    let staged = env.stage("ingress/edge");
    assert!(staged.success, "{}", staged.stderr);
    assert!(
        !staged.stdout.contains("re-rendered"),
        "a current dist tree must not produce a drift ℹ: {}",
        staged.stdout
    );
    for rel in NGINX_FRAGMENT_RELS {
        let dist_bytes = std::fs::read(env.dist().join(rel)).unwrap();
        let staged_bytes = std::fs::read(env.staged("ingress/edge").join(rel)).unwrap();
        assert_eq!(dist_bytes, staged_bytes, "{rel}: one render source");
    }
}

// ---------------------------------------------------------------------------
// The merged host tree (`--with`) — one machine, one tree
// ---------------------------------------------------------------------------

/// The ECS shape stages ONE tree: the file set is exactly the union of the
/// two single-node trees (one shared base — bin/ and install.sh once, not
/// twice), every shared file byte-identical, one manifest listing both
/// nodes, one tar pair — and the real transfer gate accepts it.
#[test]
fn with_stages_one_merged_tree_per_machine() {
    let env = Env::applied(MERGED_MANIFEST);
    // The reference faces: each node staged alone.
    let ingress = env.stage("ingress/edge");
    assert!(ingress.success, "{}", ingress.stderr);
    let hub = env.stage("hub/promptcn");
    assert!(hub.success, "{}", hub.stderr);

    let merged = env.stage_with("ingress/edge", &["hub/promptcn"]);
    assert!(merged.success, "{}", merged.stderr);
    assert!(
        merged
            .stdout
            .contains("✔ staged ingress/edge, hub/promptcn"),
        "{}",
        merged.stdout
    );
    assert!(
        merged.stdout.contains("packs/ingress-edge")
            && merged.stdout.contains("packs/hub-promptcn"),
        "{}",
        merged.stdout
    );

    // The union file set: every single-tree file appears once (the base is
    // not duplicated — zero extra files beyond the union).
    let tree = env.staged_merged("ingress/edge", &["hub/promptcn"]);
    let mut union: Vec<String> = walk_files(&env.staged("ingress/edge"));
    for rel in walk_files(&env.staged("hub/promptcn")) {
        if !union.contains(&rel) {
            union.push(rel);
        }
    }
    union.sort();
    assert_eq!(
        walk_files(&tree),
        union,
        "the merged tree is exactly the union of the single-node trees"
    );

    // Every shared file is byte-identical to the single trees' copies
    // (binaries from one artifact gate, one install.sh render, the same
    // fresh nginx render). The staging manifest is the one honest
    // exception: it lists the whole machine.
    for rel in &union {
        if rel == "stage-manifest.json" {
            continue;
        }
        let bytes = std::fs::read(tree.join(rel)).unwrap();
        let in_ingress = env.staged("ingress/edge").join(rel);
        let in_hub = env.staged("hub/promptcn").join(rel);
        if in_ingress.is_file() {
            assert_eq!(bytes, std::fs::read(&in_ingress).unwrap(), "{rel}");
        }
        if in_hub.is_file() {
            assert_eq!(bytes, std::fs::read(&in_hub).unwrap(), "{rel}");
        }
    }

    // One manifest covering the machine, one tar pair — and the real gate
    // accepts the tree.
    let manifest: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(tree.join("stage-manifest.json")).unwrap())
            .unwrap();
    assert_eq!(
        manifest["hosts"],
        serde_json::json!(["ingress/edge", "hub/promptcn"])
    );
    assert_eq!(manifest["schema"], 2);
    assert!(
        env.stage_root()
            .join("ingress-edge+hub-promptcn.tar")
            .is_file()
    );
    assert!(
        env.stage_root()
            .join("ingress-edge+hub-promptcn.tar.sha256")
            .is_file()
    );
    assert!(
        verify_staging(&tree).status.success(),
        "the merged tree must verify"
    );
}

/// `--with` follows the same declaration law as `--host`, and a node is
/// staged exactly once — a machine hosts a node once; twice is a typo.
#[test]
fn with_must_be_declared_and_unique() {
    let env = Env::applied(MERGED_MANIFEST);
    let staged = env.stage_with("ingress/edge", &["agent/ghost"]);
    assert!(!staged.success, "an undeclared --with node must refuse");
    assert!(
        staged.stderr.contains("agent/ghost is not declared"),
        "{}",
        staged.stderr
    );
    assert!(
        !env.staged_merged("ingress/edge", &["agent/ghost"]).exists(),
        "a refusal must leave no half tree"
    );

    let staged = env.stage_with("ingress/edge", &["ingress/edge"]);
    assert!(!staged.success, "a node staged twice must refuse");
    assert!(
        staged.stderr.contains("ingress/edge is staged twice"),
        "{}",
        staged.stderr
    );
}

/// The freshness gate is the manifest's — one full-render fork refuses the
/// whole machine tree, and the refusal names every node it covers.
#[test]
fn with_full_render_refusal_names_every_node() {
    let env = Env::applied(MERGED_MANIFEST);
    // An identity-face edit (the hub endpoint feeds SANs) → the next apply
    // re-renders every pack → the whole machine tree refuses.
    env.rewrite_manifest("endpoint = \"127.0.0.1:1\"", "endpoint = \"127.0.0.1:2\"");
    let staged = env.stage_with("ingress/edge", &["hub/promptcn"]);
    assert!(!staged.success, "pending identity edits must refuse");
    assert!(
        staged
            .stderr
            .contains("refusing to stage ingress/edge, hub/promptcn")
            && staged.stderr.contains("identity-face edits pending"),
        "{}",
        staged.stderr
    );
    assert!(
        !env.staged_merged("ingress/edge", &["hub/promptcn"])
            .exists()
    );
}

/// One manifest covers the whole machine: a missing listed file in ANY
/// node's pack fails the real transfer gate.
#[test]
fn with_tree_transfer_gate_covers_every_node() {
    let env = Env::applied(MERGED_MANIFEST);
    let staged = env.stage_with("ingress/edge", &["hub/promptcn"]);
    assert!(staged.success, "{}", staged.stderr);
    let tree = env.staged_merged("ingress/edge", &["hub/promptcn"]);
    assert!(verify_staging(&tree).status.success());
    std::fs::remove_file(tree.join("packs/hub-promptcn/pack.toml")).unwrap();
    assert!(
        !verify_staging(&tree).status.success(),
        "a missing file in the second node's pack must fail the gate"
    );
}

// ---------------------------------------------------------------------------
// Small refusals
// ---------------------------------------------------------------------------

#[test]
fn host_must_be_declared_in_the_manifest() {
    let env = Env::applied(EXPOSE_MANIFEST);
    let staged = env.stage("ingress/ghost");
    assert!(!staged.success);
    assert!(
        staged.stderr.contains("ingress/ghost is not declared"),
        "{}",
        staged.stderr
    );
    let staged = env.stage("gateway/edge");
    assert!(!staged.success);
}

#[test]
fn refuses_to_overwrite_a_foreign_directory() {
    let env = Env::applied(EXPOSE_MANIFEST);
    let to = env.staged("ingress/edge");
    std::fs::create_dir_all(&to).unwrap();
    std::fs::write(to.join("operator-data.txt"), "not ours").unwrap();
    let staged = env.stage("ingress/edge");
    assert!(!staged.success, "a foreign directory must not be wiped");
    assert!(
        staged.stderr.contains("not a plan stage tree"),
        "{}",
        staged.stderr
    );
    assert!(to.join("operator-data.txt").is_file());
}
