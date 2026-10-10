//! The issuer-store backup drill, end to end against the real binary:
//! apply auto-configures backups → mutations checkpoint automatically →
//! the store is destroyed → restore rebuilds it with identical CAs →
//! doctor + verify confirm. Every identifier is fictional.
//!
//! This is the "backup without a drill is Schrödinger's backup" acceptance
//! from (internal design notes) — the
//! loss branch is walked for real, in a test, on every run.

use std::path::{Path, PathBuf};
use std::process::Command;

fn bin() -> PathBuf {
    let mut p = std::env::current_exe().expect("test bin path");
    p.pop(); // deps/
    p.pop(); // tests/
    p.join(format!("interflow-cli{}", std::env::consts::EXE_SUFFIX))
}

fn run_output(args: &[&str]) -> String {
    let output = Command::new(bin())
        .args(args)
        .output()
        .expect("spawn interflow");
    let stdout = String::from_utf8_lossy(&output.stdout).into_owned();
    assert!(
        output.status.success(),
        "interflow {args:?} failed:\nstdout: {stdout}\nstderr: {}",
        String::from_utf8_lossy(&output.stderr),
    );
    stdout
}

fn run_fail(args: &[&str]) -> String {
    let output = Command::new(bin())
        .args(args)
        .output()
        .expect("spawn interflow");
    let stdout = String::from_utf8_lossy(&output.stdout).into_owned();
    assert!(
        !output.status.success(),
        "interflow {args:?} unexpectedly succeeded:\n{stdout}"
    );
    stdout
}

/// A dedicated fictional deployment (realm `corvus`, loopback endpoints,
/// agent `heron`) — the shape of the expose starter, with none of its
/// real identifiers.
fn manifest() -> String {
    r#"
[realm]
id = "corvus"
control_endpoint = "127.0.0.1:26666"
[public_tls]
mode = "frontend-proxy"
[identity]
leaf_ttl = "24h"
[registrar]
endpoint = "https://registrar.invalid"
[ingress.edge]
workspaces = ["default"]
listen = "127.0.0.1:18443"
control_listen = "127.0.0.1:26666"
[workspace.default]
[agent.heron]
workspace = "default"
[[agent.heron.services]]
id = "asr"
address = "127.0.0.1:18080"
[[route]]
host = "asr.example.com"
service = "default/heron/asr"
"#
    .to_owned()
}

fn newest_backup(backup_dir: &Path) -> PathBuf {
    let mut versions: Vec<PathBuf> = std::fs::read_dir(backup_dir)
        .expect("backup dir readable")
        .filter_map(std::result::Result::ok)
        .map(|e| e.path())
        .filter(|p| {
            p.extension().is_some_and(|e| e == "age")
                && p.file_name()
                    .and_then(|n| n.to_str())
                    .is_some_and(|n| n.starts_with("issuer-"))
        })
        .collect();
    assert!(
        !versions.is_empty(),
        "at least one backup version must exist"
    );
    versions.sort();
    versions.pop().expect("newest version")
}

fn realm_fingerprint(issuer_dir: &Path) -> String {
    interflow_identity::issuance::IssuerStore::open(issuer_dir)
        .realm_issuer()
        .expect("realm issuer loads")
        .fingerprint()
        .expect("fingerprint")
}

#[test]
fn apply_configures_backups_and_the_loss_branch_recovers() {
    let dir = tempfile::tempdir().expect("tempdir");
    let manifest_path = dir.path().join("interflow.toml");
    std::fs::write(&manifest_path, manifest()).expect("write manifest");
    let issuer = dir.path().join("issuer");
    let issuer_str = issuer.display().to_string();
    let dist = dir.path().join("dist");
    let backup_dir = dir.path().join("issuer-backups");

    // The test pre-generates the offline key (the `--backup-recipient`
    // path operators use for zero-secrets-on-machine); apply then
    // configures + checkpoints without printing any secret.
    let identity = interflow_identity::backup::generate_identity().expect("identity");
    let identity_file = dir.path().join("offline-identity.txt");
    std::fs::write(&identity_file, &identity.secret).expect("write identity");

    let apply_out = run_output(&[
        "plan",
        "apply",
        "--manifest",
        &manifest_path.display().to_string(),
        "--issuer",
        &issuer_str,
        "--out",
        &dist.display().to_string(),
        "--backup-recipient",
        &identity.recipient,
    ]);
    assert!(
        apply_out.contains("issuer store backup configured"),
        "apply must announce the backup setup:\n{apply_out}"
    );
    assert!(
        !apply_out.contains("AGE-SECRET-KEY"),
        "a pre-supplied recipient must never generate a secret on this machine:\n{apply_out}"
    );
    assert!(
        backup_dir.join("backup.json").exists() || issuer.join("backup.json").exists(),
        "backup.json lands inside the store"
    );
    assert!(
        std::fs::read_dir(&backup_dir).expect("backup dir").count() >= 1,
        "checkpoint versions landed in the sibling backup dir"
    );

    // Health: status reports currency, doctor's trial-decrypt passes.
    let status_out = run_output(&["issuer", "backup", "status", "--dir", &issuer_str]);
    assert!(
        status_out.contains("newest backup matches the current store content"),
        "{status_out}"
    );
    let doctor_out = run_output(&[
        "doctor",
        "issuer",
        "--dir",
        &issuer_str,
        "--identity",
        &identity_file.display().to_string(),
    ]);
    assert!(doctor_out.contains("drill"), "{doctor_out}");

    // The loss branch: the store's signing capability is destroyed.
    let original_fingerprint = realm_fingerprint(&issuer);
    std::fs::remove_file(issuer.join("realm-issuer.key")).expect("destroy the realm CA key");

    // Verify still works (the backup is self-contained).
    let newest = newest_backup(&backup_dir);
    let verify_out = run_output(&[
        "issuer",
        "verify",
        "--backup",
        &newest.display().to_string(),
        "--identity",
        &identity_file.display().to_string(),
    ]);
    assert!(
        verify_out.contains("decrypts and parses cleanly"),
        "{verify_out}"
    );

    // Restore into a fresh directory: same CA, the whole PKI face reads back.
    let restored = dir.path().join("issuer-restored");
    let restore_out = run_output(&[
        "issuer",
        "restore",
        "--backup",
        &newest.display().to_string(),
        "--identity",
        &identity_file.display().to_string(),
        "--to",
        &restored.display().to_string(),
    ]);
    assert!(
        restore_out.contains("issuer store restored"),
        "{restore_out}"
    );
    assert_eq!(realm_fingerprint(&restored), original_fingerprint);
    interflow_identity::issuance::IssuerStore::open(&restored)
        .ensure_realm()
        .expect("restored realm pair validates");
    interflow_identity::issuance::IssuerStore::open(&restored)
        .ensure_workspace("default")
        .expect("restored workspace pair validates");

    // A wrong identity must not open the backup (fail closed, loud).
    let wrong = interflow_identity::backup::generate_identity().expect("wrong identity");
    let wrong_file = dir.path().join("wrong-identity.txt");
    std::fs::write(&wrong_file, &wrong.secret).expect("write wrong identity");
    run_fail(&[
        "issuer",
        "verify",
        "--backup",
        &newest.display().to_string(),
        "--identity",
        &wrong_file.display().to_string(),
    ]);
}
