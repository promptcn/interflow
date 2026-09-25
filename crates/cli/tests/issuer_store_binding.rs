//! Integration tests for the issuer store's binding contract
//!:
//! one store = one realm = one manifest lineage. Trust roots cannot merge
//! silently; the only way through is the explicit `--issuer-allow-shared`
//! rebind (same deployment after a move), and realm changes never pass.

use std::path::PathBuf;
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

fn run(args: &[&str]) -> RunOutcome {
    let output = Command::new(bin())
        .args(args)
        .output()
        .expect("spawn interflow");
    RunOutcome {
        success: output.status.success(),
        stdout: String::from_utf8_lossy(&output.stdout).into_owned(),
        stderr: String::from_utf8_lossy(&output.stderr).into_owned(),
    }
}

/// A minimal valid manifest; `realm`, `host` and the service port vary per
/// scenario so different files are genuinely different manifests.
fn manifest_text(realm: &str, host: &str, port: u16) -> String {
    format!(
        r#"
[realm]
id = "{realm}"
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
address = "127.0.0.1:{port}"
[[route]]
host = "{host}"
service = "default/desktop/asr"
"#
    )
}

struct Env {
    dir: PathBuf,
}

impl Env {
    fn new() -> Self {
        let dir = tempfile::tempdir().expect("tempdir").keep();
        Self { dir }
    }

    fn write_manifest(&self, name: &str, realm: &str, host: &str, port: u16) -> String {
        let path = self.dir.join(name);
        std::fs::write(&path, manifest_text(realm, host, port)).unwrap();
        path.display().to_string()
    }

    fn issuer(&self) -> String {
        self.dir.join("issuer").display().to_string()
    }

    fn out(&self, name: &str) -> String {
        self.dir.join(name).display().to_string()
    }

    fn apply(&self, manifest: &str, out: &str, allow_shared: bool) -> RunOutcome {
        let mut args: Vec<&str> = vec!["plan", "apply", "--manifest", manifest];
        let issuer = self.issuer();
        let out_dir = self.out(out);
        args.extend(["--issuer", &issuer, "--out", &out_dir]);
        if allow_shared {
            args.push("--issuer-allow-shared");
        }
        run(&args)
    }
}

#[test]
fn first_apply_binds_then_stays_silent_across_reruns_and_edits() {
    let env = Env::new();
    let a = env.write_manifest("a.toml", "promptcn", "asr.example.com", 18080);

    let first = env.apply(&a, "dist", false);
    assert!(first.success, "{}\n{}", first.stdout, first.stderr);
    assert!(
        first
            .stdout
            .contains("issuer store bound to realm promptcn"),
        "{}",
        first.stdout
    );
    assert!(env.dir.join("issuer/binding.json").exists());

    // Re-run: same lineage, nothing to say.
    let second = env.apply(&a, "dist", false);
    assert!(second.success);
    assert!(
        !second.stdout.contains("bound to realm"),
        "a same-lineage rerun must be silent: {}",
        second.stdout
    );

    // Edit in place (new service port): still the same manifest file.
    std::fs::write(
        env.dir.join("a.toml"),
        manifest_text("promptcn", "asr.example.com", 18081),
    )
    .unwrap();
    let edited = env.apply(&a, "dist", false);
    assert!(edited.success, "{}\n{}", edited.stdout, edited.stderr);
    assert!(!edited.stdout.contains("bound to realm"));
}

#[test]
fn a_second_manifest_sharing_the_realm_needs_the_explicit_override() {
    let env = Env::new();
    let a = env.write_manifest("a.toml", "promptcn", "asr.example.com", 18080);
    let b = env.write_manifest("b.toml", "promptcn", "asr2.example.com", 18090);
    env.apply(&a, "dist-a", false);

    let refused = env.apply(&b, "dist-b", false);
    assert!(!refused.success, "must refuse: {}", refused.stdout);
    let canonical_a = std::fs::canonicalize(env.dir.join("a.toml"))
        .unwrap()
        .display()
        .to_string();
    assert!(
        refused.stderr.contains(&canonical_a),
        "the binding manifest must be named: {}",
        refused.stderr
    );
    assert!(
        refused.stderr.contains("--issuer-allow-shared"),
        "the override must be named: {}",
        refused.stderr
    );
    assert!(
        refused.stderr.contains("blast radius"),
        "the consequence must be explained: {}",
        refused.stderr
    );

    // The override proceeds and rebinds — and the rebind is real: the
    // previous manifest now needs the override itself.
    let allowed = env.apply(&b, "dist-b", true);
    assert!(allowed.success, "{}\n{}", allowed.stdout, allowed.stderr);
    assert!(
        allowed.stdout.contains("re-bound issuer store"),
        "{}",
        allowed.stdout
    );
    let back = env.apply(&a, "dist-a", false);
    assert!(!back.success, "the lineage key moved with the rebind");
}

#[test]
fn a_different_realm_never_passes_even_with_the_override() {
    let env = Env::new();
    let a = env.write_manifest("a.toml", "promptcn", "asr.example.com", 18080);
    let other = env.write_manifest("other.toml", "promptcn-mesh", "mesh.example.com", 18091);
    env.apply(&a, "dist-a", false);

    for allow_shared in [false, true] {
        let refused = env.apply(&other, "dist-other", allow_shared);
        assert!(
            !refused.success,
            "a realm change must never pass (allow_shared={allow_shared})"
        );
        assert!(
            refused
                .stderr
                .contains("one issuer store signs exactly one realm"),
            "{}",
            refused.stderr
        );
        assert!(
            refused.stderr.contains("promptcn-mesh"),
            "the refused realm must be named: {}",
            refused.stderr
        );
    }
}

/// Stores created before bindings existed (material minted by hand or by an
/// older binary) bind silently on the first apply that sees them.
#[test]
fn a_legacy_store_is_bound_on_first_apply() {
    let env = Env::new();
    let issuer = interflow_identity::issuance::IssuerStore::open(env.dir.join("issuer"));
    issuer.ensure_realm().unwrap();
    issuer.ensure_policy_key().unwrap();
    issuer.ensure_workspace("default").unwrap();

    let a = env.write_manifest("a.toml", "promptcn", "asr.example.com", 18080);
    let out = env.apply(&a, "dist", false);
    assert!(out.success, "{}\n{}", out.stdout, out.stderr);
    assert!(
        out.stdout.contains("issuer store bound to realm promptcn"),
        "{}",
        out.stdout
    );
}

#[test]
fn rotate_enforces_the_same_contract() {
    let env = Env::new();
    let a = env.write_manifest("a.toml", "promptcn", "asr.example.com", 18080);
    let b = env.write_manifest("b.toml", "promptcn", "asr2.example.com", 18090);
    env.apply(&a, "dist", false);
    let pack = env
        .dir
        .join("dist/packs/agent-desktop")
        .display()
        .to_string();

    let rotate_b = run(&[
        "rotate",
        "--manifest",
        &b,
        "--issuer",
        &env.issuer(),
        "agent/desktop",
        "--pack",
        &pack,
    ]);
    assert!(!rotate_b.success, "rotate must enforce the binding too");
    assert!(
        rotate_b.stderr.contains("--issuer-allow-shared"),
        "{}",
        rotate_b.stderr
    );

    // The same manifest rotates freely.
    let rotate_a = run(&[
        "rotate",
        "--manifest",
        &a,
        "--issuer",
        &env.issuer(),
        "agent/desktop",
        "--pack",
        &pack,
    ]);
    assert!(rotate_a.success, "{}\n{}", rotate_a.stdout, rotate_a.stderr);
}
