#![cfg(unix)]
//! Execution-level tests for the generated `install.sh` — the real script,
//! run end-to-end in its self-contained `--root` layout (the same contract
//! `node install --root` offers). The byte-identical skip is the point: a
//! second realm's install on the same machine must leave unchanged binaries
//! — same inode, same mtime — or the disk-swap detection fires on nodes
//! running the very same build. Unix-only end to end: the script is a bash
//! bootstrap and the assertions ride the inode, so the file compiles empty
//! elsewhere (the msvc clippy face died on `std::os::unix` before the gate).

use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::process::Command;

const MANIFEST: &str = r#"
[realm]
id = "promptcn"
control_endpoint = "127.0.0.1:26666"
[identity]
mode = "offline"
[ingress.edge]
workspaces = ["default"]
listen = "127.0.0.1:18443"
[workspace.default]
[agent.desktop]
workspace = "default"
[[agent.desktop.services]]
id = "asr"
address = "127.0.0.1:18080"
[[route]]
host = "asr.example.com"
service = "default/desktop/asr"
"#;

/// A rendered staging tree: install.sh + bin/ with the given binaries.
fn staging_tree(bins: &[(&str, &[u8])]) -> (tempfile::TempDir, PathBuf) {
    let tmp = tempfile::tempdir().expect("tempdir");
    let tree = tmp.path().to_path_buf();
    let manifest = interflow_identity::Manifest::parse(MANIFEST).expect("manifest fixture parses");
    let sha = interflow_util::sha256_hex(MANIFEST.as_bytes());
    let script = interflow_cli::render::install_sh(&manifest, &sha);
    std::fs::write(tree.join("install.sh"), script).unwrap();
    std::fs::create_dir_all(tree.join("bin")).unwrap();
    for (name, bytes) in bins {
        std::fs::write(tree.join("bin").join(name), bytes).unwrap();
    }
    (tmp, tree)
}

fn run_script(tree: &Path, args: &[&str]) -> std::process::Output {
    Command::new("bash")
        .arg(tree.join("install.sh"))
        .args(args)
        .output()
        .expect("spawn install.sh")
}

fn inode_of(path: &Path) -> (u64, std::time::SystemTime) {
    let meta = std::fs::metadata(path).expect("binary exists");
    (meta.ino(), meta.modified().expect("mtime"))
}

/// The two-state acceptance: identical bytes skip (inode untouched), new or
/// changed bytes copy (inode moves). A partial update takes each path per
/// binary.
#[test]
fn byte_identical_bins_skip_changed_bins_copy() {
    let (_tree_guard, tree) = staging_tree(&[
        ("interflow-cli", b"#!/bin/sh\necho cli-v1\n"),
        ("interflow-mesh", b"#!/bin/sh\necho mesh-v1\n"),
    ]);
    let dst = tempfile::tempdir().expect("dst");
    let root = dst.path().display().to_string();

    // First run: nothing on disk — everything copies, nothing claims a skip.
    let first = run_script(&tree, &["--root", &root]);
    assert!(
        first.status.success(),
        "{}",
        String::from_utf8_lossy(&first.stderr)
    );
    let out = String::from_utf8_lossy(&first.stdout);
    assert!(
        !out.contains("unchanged (skipped)"),
        "a fresh copy skips nothing: {out}"
    );
    let cli = dst.path().join("bin/interflow-cli");
    let (cli_ino_1, cli_mtime_1) = inode_of(&cli);

    // Second run, byte-identical tree: every binary skipped, inode + mtime
    // untouched — the A1 disk-swap detection stays silent by construction.
    let second = run_script(&tree, &["--root", &root]);
    assert!(
        second.status.success(),
        "{}",
        String::from_utf8_lossy(&second.stderr)
    );
    let out = String::from_utf8_lossy(&second.stdout);
    assert!(
        out.contains("install.sh: bin/interflow-cli unchanged (skipped)"),
        "the skip says so: {out}"
    );
    assert!(
        out.contains("install.sh: bin/interflow-mesh unchanged (skipped)"),
        "{out}"
    );
    assert_eq!(
        inode_of(&cli),
        (cli_ino_1, cli_mtime_1),
        "same bytes, same inode"
    );

    // Partial update: cli changes, mesh does not — one copies, one skips.
    std::fs::write(tree.join("bin/interflow-cli"), b"#!/bin/sh\necho cli-v2\n").unwrap();
    std::fs::write(
        tree.join("bin/interflow-registrar"),
        b"#!/bin/sh\necho reg-v1\n",
    )
    .unwrap();
    let third = run_script(&tree, &["--root", &root]);
    assert!(
        third.status.success(),
        "{}",
        String::from_utf8_lossy(&third.stderr)
    );
    let out = String::from_utf8_lossy(&third.stdout);
    assert!(
        out.contains("bin/interflow-mesh unchanged (skipped)"),
        "{out}"
    );
    assert!(
        !out.contains("bin/interflow-cli unchanged"),
        "changed bytes copy: {out}"
    );
    assert!(
        !out.contains("bin/interflow-registrar unchanged"),
        "new files copy: {out}"
    );
    let (cli_ino_3, _) = inode_of(&cli);
    assert_ne!(cli_ino_3, cli_ino_1, "a real change replaces the inode");
    assert!(dst.path().join("bin/interflow-registrar").exists());

    // The self-contained layout carries the packs root too — the tree a
    // container or test sandbox gets.
    assert!(
        dst.path().join("packs").is_dir(),
        "packs/ prepared under --root"
    );
}

/// The default path stays fail-closed: without --root the script demands
/// root (the test runner is not root), and argument typos never fall
/// through to a partial run.
#[test]
fn default_path_gates_root_and_unknown_arguments() {
    let (_tree_guard, tree) = staging_tree(&[("interflow-cli", b"#!/bin/sh\n")]);

    let plain = run_script(&tree, &[]);
    assert!(!plain.status.success(), "no --root and no root ⇒ refuse");
    assert!(
        String::from_utf8_lossy(&plain.stderr).contains("must run as root"),
        "{}",
        String::from_utf8_lossy(&plain.stderr)
    );

    let unknown = run_script(&tree, &["--converge"]);
    assert!(!unknown.status.success(), "unknown flags refuse");
    assert!(
        String::from_utf8_lossy(&unknown.stderr).contains("unknown argument"),
        "{}",
        String::from_utf8_lossy(&unknown.stderr)
    );

    let no_arg = run_script(&tree, &["--root"]);
    assert!(
        !no_arg.status.success(),
        "--root without a directory refuses"
    );
    assert!(
        String::from_utf8_lossy(&no_arg.stderr).contains("needs a directory argument"),
        "{}",
        String::from_utf8_lossy(&no_arg.stderr)
    );
}
