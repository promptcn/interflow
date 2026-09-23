//! Byte-stable snapshot tests for the manifest-derived deployment artifacts
//! (systemd units, nginx fragments, install.sh).
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
fn write_artifacts(manifest: &Manifest, out: &Path) {
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
        render::write_registrar_unit(out, manifest, render::DEFAULT_INSTALL_ROOT)
            .expect("registrar unit renders");
    }
    render::write_nginx_fragments(out, manifest).expect("nginx fragments render");
    render::write_install_sh(out, manifest).expect("install.sh renders");
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
    std::fs::create_dir_all(to).expect("create golden dir");
    for entry in std::fs::read_dir(from).expect("read dir") {
        let entry = entry.expect("dir entry");
        let target = to.join(entry.file_name());
        if entry.file_type().expect("file type").is_dir() {
            copy_tree(&entry.path(), &target);
        } else {
            std::fs::copy(entry.path(), target).expect("copy golden file");
        }
    }
}

fn assert_stable(case: &str, manifest_text: &str) {
    let manifest = Manifest::parse(manifest_text).expect("manifest parses");
    let tmp = tempfile::tempdir().expect("tempdir");
    write_artifacts(&manifest, tmp.path());
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
    for rel in &got {
        let produced = std::fs::read_to_string(tmp.path().join(rel)).expect("produced file");
        let expected = std::fs::read_to_string(golden.join(rel)).expect("golden file");
        assert_eq!(
            produced,
            expected,
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
