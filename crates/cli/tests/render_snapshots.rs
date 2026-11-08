//! Byte-stable snapshot tests for the manifest-derived deployment artifacts
//! (systemd units, nginx fragments, install.sh).
//!
//! One component is exempt from byte-stability BY POLICY: every artifact's
//! vintage line names the compiling build (`# rendered by interflow-cli
//! <BUILD_TAG> …`), so the tag component legitimately varies per commit and
//! a golden tree is not supposed to pin it. The test therefore (a) asserts
//! every vintage line is present and exactly formed — built by the same
//! `render::vintage_comment`/`render::build_vintage_comment` the renderer
//! uses, digest included — and only then (b) normalizes the tag on BOTH
//! sides before the byte compare. Everything else stays byte-locked.
//!
//! Regenerate intentionally with:
//!   UPDATE_SNAPSHOTS=1 cargo test -p interflow-cli --test render_snapshots

use interflow_cli::render;
use interflow_identity::manifest::Manifest;
use interflow_identity::pack::PackKind;
use std::path::{Path, PathBuf};

/// Expose topology (public domain → LAN services) behind a frontend proxy,
/// with a registrar.
const EXPOSE_MANIFEST: &str = r#"
[realm]
id = "promptcn"
control_endpoint = "example.com:16666"

[public_tls]
mode = "frontend-proxy"

[identity]
leaf_ttl = "24h"

[registrar]
endpoint = "https://registrar.example.com"

[ingress.edge]
workspaces = ["main"]
listen = "0.0.0.0:8443"
control_listen = "0.0.0.0:16666"

[workspace.main]

[agent.desktop]
workspace = "main"

[[agent.desktop.services]]
id = "asr"
address = "127.0.0.1:8080"

[[agent.desktop.services]]
id = "tts"
address = "127.0.0.1:8000"

[[route]]
host = "asr.example.com"
service = "main/desktop/asr"

[[route]]
host = "tts.example.com"
service = "main/desktop/tts"
"#;

/// Site-to-site mesh topology with a registrar.
const MESH_MANIFEST: &str = r#"
[realm]
id = "promptcn"

[registrar]
endpoint = "https://registrar.example.com"

[mesh.hub.promptcn]
listen = "0.0.0.0:6666"
endpoint = "example.com:6666"

[workspace.main]

[agent.alpha]
workspace = "main"

[[agent.alpha.mesh_ingress]]
name = "ragflow"
listen = "127.0.0.1:18000"
target_agent = "beta"
remote_addr = "127.0.0.1:80"

[agent.beta]
workspace = "main"

[[agent.beta.mesh_egress]]
name = "ragflow"
target_addr = "127.0.0.1:80"
"#;

/// The offline tier (single operator, no registrar): expose topology behind
/// a frontend proxy — no registrar unit, no registrar bootstrap section.
const OFFLINE_MANIFEST: &str = r#"
[realm]
id = "promptcn"
control_endpoint = "example.com:16666"

[public_tls]
mode = "frontend-proxy"

[identity]
mode = "offline"
leaf_ttl = "90d"

[ingress.edge]
workspaces = ["main"]
listen = "0.0.0.0:8443"
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

/// Mirrors the artifact section of `plan::apply` (everything but the packs,
/// which carry issuance timestamps and are covered by the flow tests).
fn write_artifacts(manifest: &Manifest, manifest_text: &str, out: &Path) {
    let manifest_sha = interflow_util::sha256_hex(manifest_text.as_bytes());
    let mut nodes: Vec<(PackKind, String, bool)> = Vec::new();
    for node in manifest.mesh.hub.keys() {
        nodes.push((PackKind::Hub, node.clone(), true));
    }
    for node in manifest.ingress.keys() {
        nodes.push((PackKind::Ingress, node.clone(), false));
    }
    for node in manifest.agent.keys() {
        nodes.push((
            PackKind::Agent,
            node.clone(),
            manifest.agent_has_mesh_role(node),
        ));
    }
    for (kind, node, mesh_role) in nodes {
        render::write_node_unit(out, kind, &node, mesh_role, render::DEFAULT_INSTALL_ROOT)
            .expect("node unit renders");
    }
    if render::has_registrar(manifest) {
        render::write_registrar_unit(out, manifest, render::DEFAULT_INSTALL_ROOT, &manifest_sha)
            .expect("registrar unit renders");
    }
    render::write_nginx_fragments(out, manifest, &manifest_sha).expect("nginx fragments render");
    render::write_install_sh(out, manifest, &manifest_sha).expect("install.sh renders");
}

fn collect_files(root: &Path, dir: &Path, out: &mut Vec<PathBuf>) {
    for entry in std::fs::read_dir(dir).expect("read dir") {
        let entry = entry.expect("dir entry");
        if entry.file_type().expect("file type").is_dir() {
            collect_files(root, &entry.path(), out);
        } else {
            out.push(
                entry
                    .path()
                    .strip_prefix(root)
                    .expect("prefix")
                    .to_path_buf(),
            );
        }
    }
}

fn copy_tree(from: &Path, to: &Path) {
    interflow_util::copy_dir_recursive(from, to).expect("copy golden tree");
}

/// Replaces the build-tag component of ANY vintage line with a
/// placeholder. Golden trees carry the tag of the commit that last
/// regenerated them, which legitimately differs from this build's — the
/// manifest digest (the line's other component) stays byte-locked.
fn normalize_vintage(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for line in text.split_inclusive('\n') {
        if let Some(rest) = line.strip_prefix("# rendered by interflow-cli ") {
            out.push_str("# rendered by interflow-cli <BUILD_TAG>");
            if let Some((_, tail)) = rest.split_once(" from ") {
                out.push_str(" from ");
                out.push_str(tail);
            }
        } else {
            out.push_str(line);
        }
    }
    out
}

fn assert_stable(case: &str, manifest_text: &str) {
    let manifest = Manifest::parse(manifest_text).expect("manifest parses");
    let tmp = tempfile::tempdir().expect("tempdir");
    write_artifacts(&manifest, manifest_text, tmp.path());
    let golden = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/snapshots/render")
        .join(case);
    if std::env::var_os("UPDATE_SNAPSHOTS").is_some() {
        if golden.exists() {
            std::fs::remove_dir_all(&golden).expect("clear golden tree");
        }
        copy_tree(tmp.path(), &golden);
        eprintln!("snapshots updated for {case}");
    }
    let mut got = Vec::new();
    collect_files(tmp.path(), tmp.path(), &mut got);
    got.sort();
    let mut want = Vec::new();
    collect_files(&golden, &golden, &mut want);
    want.sort();
    assert_eq!(
        got, want,
        "rendered file set for {case} differs from the snapshot tree \
         (regenerate with UPDATE_SNAPSHOTS=1 if intentional)"
    );
    // The vintage lines come first, exactly formed and digest-locked:
    // built by the same functions the renderer uses, so an absent or
    // malformed line fails HERE — the normalization below must never be
    // able to hide it.
    let manifest_sha = interflow_util::sha256_hex(manifest_text.as_bytes());
    for rel in &got {
        let produced = std::fs::read_to_string(tmp.path().join(rel)).expect("produced file");
        let rel_s = rel.to_string_lossy();
        let expected_line = if rel_s.starts_with("nginx/")
            || rel_s == "install.sh"
            || rel_s == "systemd/interflow-registrar.service"
        {
            render::vintage_comment(&manifest_sha)
        } else if rel_s.starts_with("systemd/") {
            render::build_vintage_comment()
        } else {
            continue;
        };
        assert!(
            produced.contains(&expected_line),
            "{case}/{} must carry its vintage line (built by the same source as the renderer)",
            rel.display()
        );
    }
    for rel in &got {
        let produced = std::fs::read_to_string(tmp.path().join(rel)).expect("produced file");
        let expected = std::fs::read_to_string(golden.join(rel)).expect("golden file");
        assert_eq!(
            normalize_vintage(&produced),
            normalize_vintage(&expected),
            "byte drift in {case}/{} (regenerate with UPDATE_SNAPSHOTS=1 if intentional)",
            rel.display()
        );
    }
    // The bootstrap script must stay valid bash (same gate as the shipped
    // examples contract).
    let install = tmp.path().join("install.sh");
    let status = std::process::Command::new("bash")
        .arg("-n")
        .arg(&install)
        .status()
        .expect("run bash -n");
    assert!(status.success(), "install.sh for {case} fails bash -n");
    // Ownership boundary: install.sh is machine bootstrap only. Unit
    // placement and service management belong to `node install` (node
    // units) and the registrar unit's header bootstrap — never to the
    // script.
    let install_sh = std::fs::read_to_string(&install).expect("read install.sh");
    assert!(
        !install_sh.contains("systemctl"),
        "install.sh for {case} must not manage services — that belongs to node install"
    );
    assert!(
        !install_sh.contains("/etc/systemd"),
        "install.sh for {case} must not install units — a machine gets a unit only \
         when that node's pack lands on it (node install)"
    );
    // The staging gate ships with every install.sh (the execution-level
    // gates live in plan_stage.rs; this keeps the template honest even
    // where a tree is never staged).
    assert!(
        install_sh.contains("--verify-staging") && install_sh.contains("SCRIPT_DIR="),
        "install.sh for {case} must anchor paths at its own directory and carry \
         the staging verification gate"
    );
}

#[test]
fn expose_frontend_proxy_artifacts_are_stable() {
    assert_stable("expose", EXPOSE_MANIFEST);
}

#[test]
fn mesh_site_to_site_artifacts_are_stable() {
    assert_stable("mesh", MESH_MANIFEST);
}

#[test]
fn offline_artifacts_are_stable() {
    assert_stable("offline", OFFLINE_MANIFEST);
}
