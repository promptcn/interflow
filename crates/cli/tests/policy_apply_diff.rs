//! `plan apply`'s policy-only fast path:
//! when the manifest's identity/trust/dial face is unchanged and only mesh
//! rules moved, apply signs the next policy generation and publishes it —
//! no pack is re-rendered, no identity is re-signed. The hub endpoint
//! points at a closed port so publication degrades to the manual-drop
//! artifact (fast refusal, no network dependency).

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

/// A mesh manifest: one hub + one stream. `ingress_port`/`remote_port` are
/// the rule face (the part a policy-only change moves); the hub endpoint
/// points at a closed loopback port so publication fails fast and
/// deterministically.
fn manifest_text(ingress_port: u16, remote_port: u16, extra_rule: bool) -> String {
    let second = if extra_rule {
        format!(
            "\n[[agent.leo-mesh.mesh_ingress]]\nname = \"tts\"\nlisten = \
             \"127.0.0.1:{second_listen}\"\ntarget_agent = \"home-win\"\nremote_addr = \
             \"127.0.0.1:{second_remote}\"\n",
            second_listen = ingress_port + 100,
            second_remote = remote_port + 100,
        )
    } else {
        String::new()
    };
    format!(
        r#"
[realm]
id = "promptcn-mesh"
[identity]
mode = "offline"
leaf_ttl = "7d"
[mesh.hub.promptcn]
listen = "127.0.0.1:16666"
endpoint = "127.0.0.1:1"
[workspace.main]
[agent.leo-mesh]
workspace = "main"
[[agent.leo-mesh.mesh_ingress]]
name = "ollama"
listen = "127.0.0.1:{ingress_port}"
target_agent = "home-win"
remote_addr = "127.0.0.1:{remote_port}"{second}
[agent.home-win]
workspace = "main"
[[agent.home-win.mesh_egress]]
name = "loopback"
target_cidr = "127.0.0.0/8"
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

    /// The deployment edits its manifest in place — the store's binding
    /// contract anchors one file per realm.
    fn write_manifest(&self, text: &str) -> String {
        let path = self.dir.join("interflow.toml");
        std::fs::write(&path, text).unwrap();
        path.display().to_string()
    }

    fn issuer(&self) -> String {
        self.dir.join("issuer").display().to_string()
    }

    fn out(&self) -> String {
        self.dir.join("dist").display().to_string()
    }

    fn apply(&self, manifest: &str) -> RunOutcome {
        let issuer = self.issuer();
        let out = self.out();
        run(&[
            "plan",
            "apply",
            "--manifest",
            manifest,
            "--issuer",
            &issuer,
            "--out",
            &out,
        ])
    }
}

/// The full acceptance: identity face unchanged + rules moved → policy-only
/// (packs untouched, bundle signed, generation advances); unchanged
/// manifest → "nothing to do"; identity face changed → full re-render.
#[test]
fn apply_routes_policy_only_changes_without_re_signing_packs() {
    let env = Env::new();

    // 1. First apply: full render.
    let v1 = env.write_manifest(&manifest_text(11434, 11434, false));
    let first = env.apply(&v1);
    assert!(first.success, "first apply: {}", first.stderr);
    let pack_dir = env.dir.join("dist/packs/agent-home-win");
    assert!(pack_dir.join("pack.toml").is_file());
    let pack_digest_before = std::fs::read_to_string(pack_dir.join("SHA256SUMS")).unwrap();
    assert!(!env.dir.join("dist/policy/policy.toml").is_file());

    // 2. Policy-only change: add the TTS rule pair.
    let v2 = env.write_manifest(&manifest_text(11434, 11434, true));
    let second = env.apply(&v2);
    assert!(second.success, "policy-only apply: {}", second.stderr);
    assert!(
        second.stdout.contains("policy-only change"),
        "must name the fast path: {}",
        second.stdout
    );
    // The packs are NOT re-rendered.
    let pack_digest_after = std::fs::read_to_string(pack_dir.join("SHA256SUMS")).unwrap();
    assert_eq!(
        pack_digest_before, pack_digest_after,
        "a policy-only change must not touch any pack"
    );
    // The signed bundle exists at generation 2, and the manual-distribution
    // fallback is narrated (the hub endpoint is a closed port).
    let bundle = env.dir.join("dist/policy/policy.toml");
    assert!(bundle.is_file(), "the bundle must land on disk");
    let text = std::fs::read_to_string(&bundle).unwrap();
    assert!(
        text.contains("generation = 2"),
        "generation must advance: {}",
        &text[text.find("generation").unwrap_or(0)
            ..(text.find("generation").unwrap_or(0) + 30).min(text.len())]
    );
    assert!(
        second.stdout.contains("manual distribution"),
        "unreachable hub must degrade to manual distribution: {}",
        second.stdout
    );

    // 3. Same manifest again: nothing to do.
    let third = env.apply(&v2);
    assert!(third.success, "no-op apply: {}", third.stderr);
    assert!(
        third.stdout.contains("nothing to do"),
        "must be a no-op: {}",
        third.stdout
    );

    // 4. Identity face change: full re-render.
    let identity_changed = manifest_text(11434, 11434, true).replace(
        "[mesh.hub.promptcn]\nlisten = \"127.0.0.1:16666\"",
        "[mesh.hub.promptcn]\nlisten = \"127.0.0.1:16667\"",
    );
    let v4 = env.write_manifest(&identity_changed);
    let fourth = env.apply(&v4);
    assert!(fourth.success, "identity-face apply: {}", fourth.stderr);
    assert!(
        !fourth.stdout.contains("policy-only change"),
        "an identity-face change must take the full-render path: {}",
        fourth.stdout
    );
    let pack_digest_final = std::fs::read_to_string(pack_dir.join("SHA256SUMS")).unwrap();
    assert_ne!(
        pack_digest_after, pack_digest_final,
        "the identity-face change must re-render packs"
    );
}

/// The bundle the fast path writes is exactly what a node accepts: drop it
/// into an agent pack's state channel and the loader takes it as the
/// authoritative policy.
#[test]
fn fast_path_bundle_is_node_loadable() {
    let env = Env::new();
    let v1 = env.write_manifest(&manifest_text(11435, 11435, false));
    assert!(env.apply(&v1).success);
    let v2 = env.write_manifest(&manifest_text(11435, 11435, true));
    let out = env.apply(&v2);
    assert!(out.success, "{}", out.stderr);

    let pack_dir = env.dir.join("dist/packs/agent-leo-mesh");
    let state_policy = pack_dir.join("state/policy");
    std::fs::create_dir_all(&state_policy).unwrap();
    std::fs::copy(
        env.dir.join("dist/policy/policy.toml"),
        state_policy.join("policy.toml"),
    )
    .unwrap();
    std::fs::copy(
        env.dir.join("dist/policy/policy.sig"),
        state_policy.join("policy.sig"),
    )
    .unwrap();
    let inspect = run(&[
        "identity",
        "inspect",
        "--pack",
        &pack_dir.display().to_string(),
    ]);
    assert!(inspect.success, "{}", inspect.stderr);
}
