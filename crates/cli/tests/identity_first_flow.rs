//! End-to-end flow test for the unified `interflow-cli` CLI:
//! setup → plan validate/apply → pack inspect → doctor → seal/install →
//! rotate → revoke. Exercises the real binary against a temp deployment.

use std::path::{Path, PathBuf};
use std::process::Command;

fn bin() -> PathBuf {
    let mut p = std::env::current_exe().expect("test bin path");
    p.pop(); // deps/
    p.pop(); // tests/
    p.join(format!("interflow-cli{}", std::env::consts::EXE_SUFFIX))
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

/// `plan validate` is where the QUIC fail-fasts land: a loopback QUIC face
/// could never be dialed (its UDP port bypasses the front proxy), and a
/// `quic` agent default has no derivable dial address under an
/// implicit-port control endpoint. The mesh face mirrors both on the hub
/// leg, plus the cross-check that a quic dial needs a hub that actually
/// opened its QUIC face.
/// ((internal design notes),
/// (internal design notes))
#[test]
fn plan_validate_rejects_broken_quic_config() {
    // Loopback QUIC face on the ingress.
    let loopback_face = manifest().replacen(
        "control_listen = \"127.0.0.1:26666\"",
        "control_listen = \"127.0.0.1:26666\"\nquic_listen = \"127.0.0.1:36666\"",
        1,
    );
    // quic agent default + implicit-port control endpoint (the fixture
    // dials 127.0.0.1:26666 — swap to a portless endpoint first).
    let implicit_port = manifest()
        .replacen(
            "control_endpoint = \"127.0.0.1:26666\"",
            "control_endpoint = \"tunnel.example.com\"",
            1,
        )
        .replacen(
            "[agent.desktop]\nworkspace = \"default\"",
            "[agent.desktop]\nworkspace = \"default\"\ntransport = \"quic\"",
            1,
        );
    // The mesh leg: a site-to-site section with an agent pair.
    let mesh_section = "\n[mesh.hub.central]\nlisten = \"0.0.0.0:6666\"\nendpoint = \"mesh.example.com:6666\"\n\
        [agent.lan-a]\nworkspace = \"default\"\n\
        [[agent.lan-a.mesh_ingress]]\nname = \"svc\"\nlisten = \"127.0.0.1:13001\"\n\
        target_agent = \"lan-b\"\nremote_addr = \"127.0.0.1:13000\"\n\
        [agent.lan-b]\nworkspace = \"default\"\n\
        [[agent.lan-b.mesh_egress]]\nname = \"svc\"\ntarget_addr = \"127.0.0.1:13000\"\n";
    let mesh_quic_agent = mesh_section.replacen(
        "[agent.lan-a]\nworkspace = \"default\"",
        "[agent.lan-a]\nworkspace = \"default\"\ntransport = \"quic\"",
        1,
    );
    // Loopback QUIC face on the hub.
    let mesh_loopback = format!(
        "{}{}",
        manifest(),
        mesh_section.replacen(
            "listen = \"0.0.0.0:6666\"",
            "listen = \"0.0.0.0:6666\"\nquic_listen = \"127.0.0.1:6666\"",
            1,
        )
    );
    // quic mesh agent + implicit-port hub endpoint: no derivable UDP
    // address.
    let mesh_implicit = format!(
        "{}{}",
        manifest(),
        mesh_quic_agent.replacen("mesh.example.com:6666", "mesh.example.com", 1)
    );
    // quic mesh agent against a hub that never opened its QUIC face:
    // runtime would only surface this as connect timeouts.
    let mesh_no_face = format!("{}{}", manifest(), mesh_quic_agent);
    for (text, expected) in [
        (loopback_face, "loopback"),
        (implicit_port, "explicit port"),
        (mesh_loopback, "loopback"),
        (mesh_implicit, "explicit port"),
        (mesh_no_face, "declares no quic_listen"),
    ] {
        let dir = tempfile_dir();
        let manifest_path = dir.join("interflow.toml");
        std::fs::write(&manifest_path, text).unwrap();
        let output = Command::new(bin())
            .args([
                "plan",
                "validate",
                "--manifest",
                &manifest_path.display().to_string(),
            ])
            .output()
            .unwrap();
        assert!(!output.status.success(), "mutation must be rejected");
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(
            stderr.contains(expected),
            "expected {expected:?} in refusal, got: {stderr}"
        );
    }
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
