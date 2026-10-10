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
    p.join(format!("interflow-cli{}", std::env::consts::EXE_SUFFIX))
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
    // The full render mirrors its bundle into dist/policy (generation 1) so
    // the manual-distribution channel never trails what the packs embed.
    let mirror = env.dir.join("dist/policy/policy.toml");
    assert!(mirror.is_file(), "the full render mirrors dist/policy");
    assert!(
        std::fs::read_to_string(&mirror)
            .unwrap()
            .contains("generation = 1"),
        "the mirror carries the render generation"
    );

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
    // Generation continuity (2026-10-06 fix): the counter RIDES ON through
    // the identity-face re-render — floor here is 2 (the policy-only
    // lineage), so the packs embed generation 3 and the mirror follows. The
    // former hard reset to 1 froze every online agent holding gen ≥ 2.
    assert!(
        fourth
            .stdout
            .contains("policy generation continues above the highest observed watermark 2"),
        "the mint floor must be narrated: {}",
        fourth.stdout
    );
    for (file, label) in [
        (pack_dir.join("policy/policy.toml"), "embedded policy"),
        (pack_dir.join("pack.toml"), "pack metadata"),
        (pack_dir.join("trust/bundle.toml"), "trust bundle"),
        (env.dir.join("dist/policy/policy.toml"), "dist mirror"),
    ] {
        let text = std::fs::read_to_string(&file).unwrap();
        assert!(
            text.contains("generation = 3"),
            "{label} must carry generation 3: {}",
            file.display()
        );
    }
    // 5. A policy-only change after the identity change continues from 3.
    let identity_changed_rules = manifest_text(11434, 11434, false).replace(
        "[mesh.hub.promptcn]\nlisten = \"127.0.0.1:16666\"",
        "[mesh.hub.promptcn]\nlisten = \"127.0.0.1:16667\"",
    );
    let v5 = env.write_manifest(&identity_changed_rules);
    let fifth = env.apply(&v5);
    assert!(
        fifth.success,
        "post-identity policy-only apply: {}",
        fifth.stderr
    );
    assert!(
        std::fs::read_to_string(env.dir.join("dist/policy/policy.toml"))
            .unwrap()
            .contains("generation = 4"),
        "the fast path must sign generation 4 after the re-render at 3"
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

/// The mint floor's dist scan includes the node state mirrors
/// (`packs/*/state/policy`): when the issuer store's bookkeeping sits at a
/// LOW generation while a pack's state channel holds a higher watermark —
/// the 2026-10-06 field incident's exact shape (bookkeeping reset
/// underneath a live fleet) — the next full render must mint ABOVE the
/// state mirror, not above the bookkeeping.
#[test]
fn identity_change_mints_above_node_state_watermarks() {
    let env = Env::new();
    let v1 = env.write_manifest(&manifest_text(11440, 11440, false));
    assert!(env.apply(&v1).success);

    // A node-local state channel holding generation 5 — the surviving
    // watermark of record. The floor probe only reads the number (content
    // need not verify: minting higher is always safe under monotonicity,
    // and only a LOWER floor could manufacture a rollback).
    let state_policy = env.dir.join("dist/packs/agent-home-win/state/policy");
    std::fs::create_dir_all(&state_policy).unwrap();
    std::fs::write(state_policy.join("policy.toml"), "generation = 5\n").unwrap();

    // Identity-face change → full render. Floor = max(bookkeeping 1, dist
    // artifacts 5) = 5 → the packs embed 6.
    let identity_changed = manifest_text(11440, 11440, false).replace(
        "[mesh.hub.promptcn]\nlisten = \"127.0.0.1:16666\"",
        "[mesh.hub.promptcn]\nlisten = \"127.0.0.1:16668\"",
    );
    let v2 = env.write_manifest(&identity_changed);
    let out = env.apply(&v2);
    assert!(out.success, "{}", out.stderr);
    assert!(
        std::fs::read_to_string(env.dir.join("dist/packs/agent-home-win/policy/policy.toml"))
            .unwrap()
            .contains("generation = 6"),
        "the re-render must mint above the state watermark 5"
    );
}

/// The no-op gate is watermark-aware (2026-10-06 fix): the 2026-10-06
/// field's exact shape — bookkeeping gen 2, an UNCHANGED manifest, and a
/// node state mirror restored to gen 5 — must NOT short-circuit as
/// "nothing to do". The gate observes the split and re-publishes above the
/// watermarks (mint 6), which is precisely what the hub's inverted-
/// watermark WARN tells the operator to do. Before the fix the digest
/// match returned before `policy_mint_floor` ever ran, locking the
/// recovery path the floor mechanism was built for.
#[test]
fn unchanged_manifest_republishes_above_diverged_watermarks() {
    let env = Env::new();
    let v1 = env.write_manifest(&manifest_text(11442, 11442, false));
    assert!(env.apply(&v1).success);
    let v2 = env.write_manifest(&manifest_text(11442, 11442, true));
    assert!(env.apply(&v2).success, "policy-only apply: run stderr");

    // The restored `.bak-gen5` state mirror: a watermark of record the
    // issuer bookkeeping (gen 2) can no longer see. The hub endpoint is a
    // closed port, so the divergence must be caught by the dist scan.
    let state_policy = env.dir.join("dist/packs/agent-home-win/state/policy");
    std::fs::create_dir_all(&state_policy).unwrap();
    std::fs::write(state_policy.join("policy.toml"), "generation = 5\n").unwrap();

    // The SAME manifest again — previously "nothing to do".
    let out = env.apply(&v2);
    assert!(out.success, "{}", out.stderr);
    assert!(
        !out.stdout.contains("nothing to do"),
        "a watermark split must not be a no-op: {}",
        out.stdout
    );
    assert!(
        out.stdout
            .contains("the watermarks diverge from the issuer bookkeeping"),
        "the gate must narrate WHY an unchanged manifest re-publishes: {}",
        out.stdout
    );
    assert!(
        out.stdout
            .contains("policy generation continues above the highest observed watermark 5"),
        "the mint floor must clear the state mirror: {}",
        out.stdout
    );
    assert!(
        std::fs::read_to_string(env.dir.join("dist/policy/policy.toml"))
            .unwrap()
            .contains("generation = 6"),
        "the reconcile must mint generation 6 (above the watermark 5)"
    );
}
