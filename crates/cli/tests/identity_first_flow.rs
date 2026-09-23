//! End-to-end flow test for the unified `interflow` CLI:
//! setup → plan validate/apply → pack inspect → doctor → seal/install →
//! rotate → revoke. Exercises the real binary against a temp deployment.

use std::path::{Path, PathBuf};
use std::process::Command;

fn bin() -> PathBuf {
    let mut p = std::env::current_exe().expect("test bin path");
    p.pop(); // deps/
    p.pop(); // tests/
    p.join(format!("interflow{}", std::env::consts::EXE_SUFFIX))
}

fn run(args: &[&str], env: &[(&str, &str)]) {
    let mut cmd = Command::new(bin());
    cmd.args(args);
    for (k, v) in env {
        cmd.env(k, v);
    }
    let output = cmd.output().expect("spawn interflow");
    assert!(
        output.status.success(),
        "interflow {args:?} failed:\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );
}

fn manifest() -> String {
    r#"
[realm]
id = "promptcn"
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
[agent.desktop]
workspace = "default"
[[agent.desktop.services]]
id = "asr"
address = "127.0.0.1:18080"
[[route]]
host = "asr.example.com"
service = "default/desktop/asr"
"#
    .to_owned()
}

#[test]
fn full_identity_first_flow() {
    let dir = tempfile_dir();
    let manifest_path = dir.join("interflow.toml");
    std::fs::write(&manifest_path, manifest()).unwrap();

    let manifest_str = manifest_path_str(&manifest_path);
    run(&["plan", "validate", "--manifest", &manifest_str], &[]);
    run(
        &[
            "plan",
            "apply",
            "--manifest",
            manifest_str.as_str(),
            "--issuer",
            &dir.join("issuer").display().to_string(),
            "--out",
            &dir.join("dist").display().to_string(),
        ],
        &[],
    );
    let ingress = dir.join("dist/packs/ingress-edge");
    let agent = dir.join("dist/packs/agent-desktop");

    run(
        &["pack", "inspect", "--pack", &ingress.display().to_string()],
        &[],
    );
    run(
        &[
            "identity",
            "inspect",
            "--pack",
            &agent.display().to_string(),
        ],
        &[],
    );
    run(
        &[
            "doctor",
            "ingress",
            "--pack",
            &ingress.display().to_string(),
        ],
        &[],
    );
    run(
        &[
            "doctor",
            "route",
            "asr.example.com",
            "--pack",
            &ingress.display().to_string(),
        ],
        &[],
    );
    run(
        &["doctor", "trust", "--pack", &ingress.display().to_string()],
        &[],
    );

    // Seal + install.
    let sealed = dir.join("agent.iflowpack");
    run(
        &[
            "pack",
            "seal",
            "--pack",
            &agent.display().to_string(),
            "--out",
            &sealed.display().to_string(),
            "--passphrase",
        ],
        &[("INTERFLOW_PACK_PASSPHRASE", "correct horse")],
    );
    run(
        &[
            "pack",
            "install",
            "--sealed",
            &sealed.display().to_string(),
            "--out",
            &dir.join("installed").display().to_string(),
            "--passphrase",
        ],
        &[("INTERFLOW_PACK_PASSPHRASE", "correct horse")],
    );

    // Rotate + revoke.
    run(
        &[
            "rotate",
            "--manifest",
            manifest_str.as_str(),
            "--issuer",
            &dir.join("issuer").display().to_string(),
            "agent/desktop",
            "--pack",
            &agent.display().to_string(),
        ],
        &[],
    );
    let rotated = dir.join("dist/packs/agent-desktop-gen2");
    let rotated_pack = interflow_identity::CredentialPack::load(&rotated).unwrap();
    assert_eq!(rotated_pack.metadata.generation, 2);
    assert_eq!(rotated_pack.trust.metadata.generation, 2);
    assert_eq!(rotated_pack.policy.generation, 2);
    run(
        &[
            "revoke",
            "--issuer",
            &dir.join("issuer").display().to_string(),
            "--pack",
            &agent.display().to_string(),
            "--reason",
            "test",
        ],
        &[],
    );
}

/// A wrong-role pack must refuse to run as another role.
#[test]
fn role_bound_packs_refuse_wrong_runtime() {
    let dir = tempfile_dir();
    let manifest_path = dir.join("interflow.toml");
    std::fs::write(&manifest_path, manifest()).unwrap();
    let manifest_str = manifest_path_str(&manifest_path);
    run(
        &[
            "plan",
            "apply",
            "--manifest",
            &manifest_str,
            "--issuer",
            &dir.join("issuer").display().to_string(),
            "--out",
            &dir.join("dist").display().to_string(),
        ],
        &[],
    );
    let agent = dir.join("dist/packs/agent-desktop");
    let output = Command::new(bin())
        .args(["ingress", "run", "--pack", &agent.display().to_string()])
        .output()
        .unwrap();
    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("cannot start as an ingress"),
        "expected role-bound refusal, got: {stderr}"
    );
}

fn manifest_path_str(p: &Path) -> String {
    p.display().to_string()
}

fn tempfile_dir() -> PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "interflow-cli-e2e-{}-{}",
        std::process::id(),
        uuid_like()
    ));
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

fn uuid_like() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or_default();
    format!("{nanos:x}")
}
