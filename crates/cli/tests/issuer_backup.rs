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

/// [`run_output`] with an explicit working directory — the CWD-independence
/// drill: the same command run from different directories must agree.
fn run_output_in(cwd: &Path, args: &[&str]) -> String {
    let output = Command::new(bin())
        .args(args)
        .current_dir(cwd)
        .output()
        .expect("spawn interflow");
    let stdout = String::from_utf8_lossy(&output.stdout).into_owned();
    assert!(
        output.status.success(),
        "interflow {args:?} (cwd {}) failed:\nstdout: {stdout}\nstderr: {}",
        cwd.display(),
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

    // The restored store carries NO backup configuration — the old machine's
    // absolute backup_dir never travels
    assert!(
        restore_out.contains("backup config never travels"),
        "restore must say backups are not configured:\n{restore_out}"
    );
    assert!(
        restore_out.contains(&identity.recipient),
        "restore prints the reusable recipient for copy-paste:\n{restore_out}"
    );
    let restored_str = restored.display().to_string();
    let status_out = run_fail(&["issuer", "backup", "status", "--dir", &restored_str]);
    assert!(
        status_out.contains("no backup configuration"),
        "restored store must read as unconfigured, not as the old machine's path:\n{status_out}"
    );
    // Re-arm backups with the SAME recovery identity the operator holds.
    run_output(&[
        "issuer",
        "backup",
        "init",
        "--dir",
        &restored_str,
        "--recipient",
        &identity.recipient,
    ]);
    run_output(&["issuer", "backup", "now", "--dir", &restored_str]);
    let status_out = run_output(&["issuer", "backup", "status", "--dir", &restored_str]);
    assert!(
        status_out.contains("newest backup matches the current store content"),
        "re-armed backups are healthy:\n{status_out}"
    );

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

#[test]
fn backup_configuration_is_cwd_independent_end_to_end() {
    // The exact 2026-10-10 invocation shape that planted the CWD bug:
    // init run FROM the deployment tree root with RELATIVE --dir and
    // --backup-dir. What lands on disk must be the absolute (v2) location,
    // and every later command must agree no matter where it runs from —
    // (internal design notes).
    let dir = tempfile::tempdir().expect("tempdir");
    let deploy_root = dir.path().join("deploy");
    std::fs::create_dir_all(&deploy_root).expect("mkdir deploy root");
    let identity = interflow_identity::backup::generate_identity().expect("identity");

    let init_out = run_output_in(
        &deploy_root,
        &[
            "issuer",
            "backup",
            "init",
            "--dir",
            "issuer",
            "--backup-dir",
            "issuer-backups",
            "--recipient",
            &identity.recipient,
        ],
    );
    assert!(
        init_out.contains("backups configured"),
        "init announces the configured location:\n{init_out}"
    );

    let backup_json =
        std::fs::read_to_string(deploy_root.join("issuer").join("backup.json")).expect("read");
    let cfg: interflow_identity::backup::BackupConfig =
        serde_json::from_str(&backup_json).expect("parse backup.json");
    assert_eq!(cfg.version, 2, "new configurations are v2");
    assert!(
        cfg.backup_dir.is_absolute(),
        "the stored location is absolute, not the relative input: {backup_json}"
    );

    // Checkpoint from the deployment root…
    run_output_in(
        &deploy_root,
        &["issuer", "backup", "now", "--dir", "issuer"],
    );

    // …and status from a foreign CWD (the test harness's own directory)
    // with an absolute --dir: same store, same versions, green currency.
    let issuer_abs = deploy_root.join("issuer").display().to_string();
    let status_out = run_output(&["issuer", "backup", "status", "--dir", &issuer_abs]);
    assert!(
        status_out.contains("newest backup matches the current store content"),
        "status from a foreign CWD must see the versions:\n{status_out}"
    );
    assert!(status_out.contains("backup dir:"), "{status_out}");

    // A third CWD (the tempdir itself, not the deploy root) agrees.
    let status_again = run_output_in(
        dir.path(),
        &["issuer", "backup", "status", "--dir", &issuer_abs],
    );
    assert!(
        status_again.contains("newest backup matches the current store content"),
        "{status_again}"
    );
}

fn count_versions(backup_dir: &Path) -> usize {
    std::fs::read_dir(backup_dir)
        .expect("backup dir readable")
        .filter_map(std::result::Result::ok)
        .filter(|e| {
            let path = e.path();
            path.extension().is_some_and(|ext| ext == "age")
                && path
                    .file_name()
                    .and_then(|n| n.to_str())
                    .is_some_and(|n| n.starts_with("issuer-"))
        })
        .count()
}

#[test]
fn relocate_moves_backups_to_a_second_medium_end_to_end() {
    let dir = tempfile::tempdir().expect("tempdir");
    let issuer = dir.path().join("issuer");
    let issuer_str = issuer.display().to_string();
    let first = dir.path().join("first-medium");
    let second = dir.path().join("second-medium");
    let identity = interflow_identity::backup::generate_identity().expect("identity");
    let identity_file = dir.path().join("identity.txt");
    std::fs::write(&identity_file, &identity.secret).expect("identity file");

    run_output(&[
        "issuer",
        "backup",
        "init",
        "--dir",
        &issuer_str,
        "--backup-dir",
        &first.display().to_string(),
        "--recipient",
        &identity.recipient,
    ]);
    run_output(&["issuer", "backup", "now", "--dir", &issuer_str]);
    let first_versions = count_versions(&first);
    assert!(first_versions >= 1, "a version landed in the first medium");

    // The sanctioned second-medium move.
    let out = run_output(&[
        "issuer",
        "backup",
        "relocate",
        "--dir",
        &issuer_str,
        "--backup-dir",
        &second.display().to_string(),
    ]);
    assert!(
        out.contains("first backup in the new location"),
        "relocate checkpoints immediately:\n{out}"
    );
    assert!(
        out.contains(&format!("{first_versions} prior version(s) remain in")),
        "relocate narrates the preserved history:\n{out}"
    );

    // Status now tracks the second medium, green currency.
    let status_out = run_output(&["issuer", "backup", "status", "--dir", &issuer_str]);
    assert!(
        status_out.contains("newest backup matches the current store content"),
        "{status_out}"
    );
    let second_canonical = second.canonicalize().expect("second medium canonical");
    assert!(
        status_out.contains(&second_canonical.display().to_string()),
        "status reports the NEW location:\n{status_out}"
    );
    assert_eq!(
        count_versions(&first),
        first_versions,
        "the old medium keeps its history untouched"
    );

    // The preserved history stays readable by the SAME recovery identity.
    let verify_out = run_output(&[
        "issuer",
        "verify",
        "--backup",
        &newest_backup(&first).display().to_string(),
        "--identity",
        &identity_file.display().to_string(),
    ]);
    assert!(
        verify_out.contains("decrypts and parses cleanly"),
        "{verify_out}"
    );

    // Re-running init on the now-configured store stays refused, pointing
    // at the two sanctioned mutations instead. The refusal goes to stderr.
    let refusal = Command::new(bin())
        .args([
            "issuer",
            "backup",
            "init",
            "--dir",
            &issuer_str,
            "--recipient",
            &identity.recipient,
        ])
        .output()
        .expect("spawn interflow");
    assert!(!refusal.status.success(), "init must stay one-time");
    let refusal_text = format!(
        "{}{}",
        String::from_utf8_lossy(&refusal.stdout),
        String::from_utf8_lossy(&refusal.stderr)
    );
    assert!(
        refusal_text.contains("issuer backup rekey")
            && refusal_text.contains("issuer backup relocate"),
        "the refusal names both sanctioned paths:\n{refusal_text}"
    );
}
