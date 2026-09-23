//! Integration tests for `interflow node install` (P0-1): the real binary
//! against a temp deployment — first install, idempotent upgrade, sealed
//! `.iflowpack` input, non-root refusal, missing pack.

use std::path::{Path, PathBuf};
use std::process::Command;

fn bin() -> PathBuf {
    let mut p = std::env::current_exe().expect("test bin path");
    p.pop(); // deps/
    p.pop(); // tests/
    p.join(format!("interflow{}", std::env::consts::EXE_SUFFIX))
}

struct RunOutcome {
    success: bool,
    stdout: String,
    stderr: String,
}

fn run(args: &[&str], env: &[(&str, &str)]) -> RunOutcome {
    let mut cmd = Command::new(bin());
    cmd.args(args);
    for (k, v) in env {
        cmd.env(k, v);
    }
    let output = cmd.output().expect("spawn interflow");
    RunOutcome {
        success: output.status.success(),
        stdout: String::from_utf8_lossy(&output.stdout).into_owned(),
        stderr: String::from_utf8_lossy(&output.stderr).into_owned(),
    }
}

fn run_ok(args: &[&str], env: &[(&str, &str)]) -> RunOutcome {
    let out = run(args, env);
    assert!(
        out.success,
        "interflow {args:?} failed:\nstdout: {}\nstderr: {}",
        out.stdout, out.stderr,
    );
    out
}

const MANIFEST: &str = r#"
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
"#;

/// A temp deployment with `plan apply` already run: issuer + dist packs.
struct Deployment {
    dir: PathBuf,
}

impl Deployment {
    fn apply() -> Self {
        let dir = tempfile::tempdir().expect("tempdir").keep();
        std::fs::write(dir.join("interflow.toml"), MANIFEST).unwrap();
        let manifest = dir.join("interflow.toml").display().to_string();
        let issuer = dir.join("issuer").display().to_string();
        let out = dir.join("dist").display().to_string();
        run_ok(
            &[
                "plan",
                "apply",
                "--manifest",
                &manifest,
                "--issuer",
                &issuer,
                "--out",
                &out,
            ],
            &[],
        );
        Self { dir }
    }

    fn pack(&self, name: &str) -> String {
        self.dir.join("dist/packs").join(name).display().to_string()
    }
}

fn unit_bytes(root: &Path) -> String {
    std::fs::read_to_string(root.join("systemd/interflow-ingress-edge.service"))
        .expect("unit written")
}

#[test]
fn first_install_lays_out_pack_and_unit() {
    let deploy = Deployment::apply();
    let srv = tempfile::tempdir().expect("tempdir");
    let root = srv.path().display().to_string();
    let out = run_ok(
        &[
            "node",
            "install",
            "--pack",
            &deploy.pack("ingress-edge"),
            "--root",
            &root,
        ],
        &[],
    );
    assert!(
        out.stdout.contains("✔ installed ingress node edge"),
        "{}",
        out.stdout
    );

    let installed = srv.path().join("packs/ingress-edge");
    assert!(
        installed.join("pack.toml").exists(),
        "pack lands in the stable path"
    );
    // The unit is the same pure function plan apply rendered — bound to this
    // root's server-side pack path.
    let expected = interflow_cli::render::node_unit(
        &root,
        interflow_identity::pack::PackKind::Ingress,
        "edge",
        false,
    );
    assert_eq!(unit_bytes(srv.path()), expected);
    // Keys stay private through the copy.
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        for entry in std::fs::read_dir(installed.join("identity")).expect("identity dir") {
            let path = entry.expect("entry").path();
            if path.extension().is_some_and(|e| e == "key") {
                let mode = std::fs::metadata(&path).expect("meta").permissions().mode();
                assert_eq!(mode & 0o777, 0o600, "{} must be 0600", path.display());
            }
        }
    }
}

#[test]
fn re_run_upgrades_and_keeps_previous() {
    let deploy = Deployment::apply();
    let srv = tempfile::tempdir().expect("tempdir");
    let root = srv.path().display().to_string();
    let pack = deploy.pack("ingress-edge");
    run_ok(&["node", "install", "--pack", &pack, "--root", &root], &[]);
    // A fresh apply issues new material; installing it upgrades in place.
    let manifest = deploy.dir.join("interflow.toml").display().to_string();
    let issuer = deploy.dir.join("issuer").display().to_string();
    let out = deploy.dir.join("dist").display().to_string();
    run_ok(
        &[
            "plan",
            "apply",
            "--manifest",
            &manifest,
            "--issuer",
            &issuer,
            "--out",
            &out,
        ],
        &[],
    );
    let result = run_ok(&["node", "install", "--pack", &pack, "--root", &root], &[]);
    assert!(result.stdout.contains("upgraded"), "{}", result.stdout);
    assert!(srv.path().join("packs/ingress-edge/pack.toml").exists());
    assert!(
        srv.path()
            .join("packs/ingress-edge.previous/pack.toml")
            .exists(),
        "the previous install is kept as .previous"
    );
}

#[test]
fn sealed_iflowpack_installs() {
    let deploy = Deployment::apply();
    let sealed = deploy.dir.join("edge.iflowpack");
    let sealed_str = sealed.display().to_string();
    run_ok(
        &[
            "pack",
            "seal",
            "--pack",
            &deploy.pack("ingress-edge"),
            "--out",
            &sealed_str,
        ],
        &[("INTERFLOW_PACK_PASSPHRASE", "correct horse battery staple")],
    );
    let srv = tempfile::tempdir().expect("tempdir");
    let root = srv.path().display().to_string();
    run_ok(
        &["node", "install", "--pack", &sealed_str, "--root", &root],
        &[("INTERFLOW_PACK_PASSPHRASE", "correct horse battery staple")],
    );
    assert!(srv.path().join("packs/ingress-edge/pack.toml").exists());
}

#[test]
fn system_root_refuses_non_root() {
    let deploy = Deployment::apply();
    // No --root: system layout, tests run unprivileged → refuse with a hint.
    let out = run(
        &["node", "install", "--pack", &deploy.pack("ingress-edge")],
        &[],
    );
    assert!(!out.success, "must refuse: stdout={}", out.stdout);
    assert!(
        out.stderr.contains("root"),
        "must explain the root requirement: {}",
        out.stderr
    );
}

#[test]
fn missing_pack_fails_cleanly() {
    let srv = tempfile::tempdir().expect("tempdir");
    let root = srv.path().display().to_string();
    let out = run(
        &[
            "node",
            "install",
            "--pack",
            "/nonexistent/pack",
            "--root",
            &root,
        ],
        &[],
    );
    assert!(!out.success);
    assert!(
        out.stderr.contains("neither a pack directory nor") || out.stderr.contains("No such"),
        "clear error for a missing source: {}",
        out.stderr
    );
}

/// `swap_pack_into` — the GUI update-in-place primitive: state/ survives
/// the swap, the previous install is kept as `<target>.previous`, and the
/// returned pack loads from the final location.
#[test]
fn swap_pack_into_preserves_state_and_keeps_previous() {
    let deploy = Deployment::apply();
    let srv = tempfile::tempdir().expect("tempdir");
    let target = srv.path().join("my-node");
    let source = PathBuf::from(deploy.pack("ingress-edge"));

    // First swap creates the target.
    let pack = interflow_cli::node_install::swap_pack_into(&source, &target, None, true)
        .expect("first swap installs");
    assert!(target.join("pack.toml").exists());

    // Node-local state appears under the target (what a running node
    // writes: credentials, ACME, CRLs).
    let creds = target.join("state/credentials");
    std::fs::create_dir_all(&creds).unwrap();
    std::fs::write(creds.join("active.pem"), b"node-local material").unwrap();

    // A fresh apply issues a new generation; swapping it in must carry the
    // state over and keep the previous pack as a sibling `.previous`.
    let manifest = deploy.dir.join("interflow.toml").display().to_string();
    let issuer = deploy.dir.join("issuer").display().to_string();
    let out = deploy.dir.join("dist").display().to_string();
    run_ok(
        &[
            "plan",
            "apply",
            "--manifest",
            &manifest,
            "--issuer",
            &issuer,
            "--out",
            &out,
        ],
        &[],
    );
    let upgraded = interflow_cli::node_install::swap_pack_into(&source, &target, None, true)
        .expect("upgrade swap");
    assert!(
        upgraded.metadata.generation >= pack.metadata.generation,
        "a fresh apply never rolls the generation back"
    );
    assert_eq!(
        std::fs::read(target.join("state/credentials/active.pem")).unwrap(),
        b"node-local material",
        "node-local state must survive the swap"
    );
    assert!(
        srv.path().join("my-node.previous/pack.toml").exists(),
        "the previous install is kept as .previous"
    );
    assert!(!target.parent().unwrap().join(".staging-swap-0").exists());
}
