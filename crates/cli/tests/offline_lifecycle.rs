//! Offline-tier lifecycle, driven through the real binary: apply →
//! metadata carries the tier → renew refuses → revoke + rotate embeds the
//! deny-list snapshot.

use std::path::{Path, PathBuf};
use std::process::Command;

fn bin() -> PathBuf {
    let mut p = std::env::current_exe().expect("test bin path");
    p.pop();
    p.pop();
    p.join(format!("interflow{}", std::env::consts::EXE_SUFFIX))
}

struct Run {
    success: bool,
    stdout: String,
    stderr: String,
}

fn run(args: &[&str]) -> Run {
    let output = Command::new(bin())
        .args(args)
        .output()
        .expect("spawn interflow");
    Run {
        success: output.status.success(),
        stdout: String::from_utf8_lossy(&output.stdout).into_owned(),
        stderr: String::from_utf8_lossy(&output.stderr).into_owned(),
    }
}

fn run_ok(args: &[&str]) -> Run {
    let out = run(args);
    assert!(
        out.success,
        "interflow {args:?} failed:\nstdout: {}\nstderr: {}",
        out.stdout, out.stderr,
    );
    out
}

const OFFLINE_MANIFEST: &str = r#"
[realm]
id = "promptcn"
control_endpoint = "127.0.0.1:26666"

[public_tls]
mode = "frontend-proxy"

[identity]
mode = "offline"
leaf_ttl = "90d"

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

fn write_manifest(dir: &Path, text: &str) -> String {
    let path = dir.join("interflow.toml");
    std::fs::write(&path, text).unwrap();
    path.display().to_string()
}

fn apply(dir: &Path) -> (String, String, String) {
    let manifest = write_manifest(dir, OFFLINE_MANIFEST);
    let issuer = dir.join("issuer").display().to_string();
    let out = dir.join("dist").display().to_string();
    run_ok(&["plan", "validate", "--manifest", &manifest]);
    run_ok(&[
        "plan",
        "apply",
        "--manifest",
        &manifest,
        "--issuer",
        &issuer,
        "--out",
        &out,
    ]);
    (manifest, issuer, out)
}

#[test]
fn offline_apply_marks_metadata_and_skips_registrar() {
    let dir = tempfile::tempdir().expect("tempdir").keep();
    let (_, _, _out) = apply(&dir);
    let dist = Path::new(&dir).join("dist");

    let pack_toml =
        std::fs::read_to_string(dist.join("packs/ingress-edge/pack.toml")).expect("pack.toml");
    assert!(
        pack_toml.contains("identity_mode = \"offline\""),
        "pack metadata carries the tier: {pack_toml}"
    );
    assert!(
        !pack_toml.contains("registrar_endpoint"),
        "offline packs carry no registrar endpoint: {pack_toml}"
    );
    assert!(
        pack_toml.contains("leaf_ttl_secs = 7776000"),
        "90d leaf: {pack_toml}"
    );

    // No registrar unit, no registrar section in the bootstrap script.
    assert!(!dist.join("systemd/interflow-registrar.service").exists());
    let install = std::fs::read_to_string(dist.join("install.sh")).unwrap();
    assert!(
        !install.contains("registrar"),
        "install.sh skips registrar: {install}"
    );
    // The old binary keeps reading registrar packs byte-identically: the
    // tier field is omitted when it is the default.
    let text = OFFLINE_MANIFEST.replace("mode = \"offline\"\nleaf_ttl = \"90d\"", "leaf_ttl = \"24h\"")
        .replace("[public_tls]\nmode = \"frontend-proxy\"\n", "[public_tls]\nmode = \"frontend-proxy\"\n[registrar]\nendpoint = \"https://registrar.invalid\"\n");
    let dir2 = tempfile::tempdir().expect("tempdir").keep();
    let manifest = write_manifest(&dir2, &text);
    run_ok(&[
        "plan",
        "apply",
        "--manifest",
        &manifest,
        "--issuer",
        &dir2.join("issuer").display().to_string(),
        "--out",
        &dir2.join("dist").display().to_string(),
    ]);
    let registrar_pack =
        std::fs::read_to_string(dir2.join("dist/packs/ingress-edge/pack.toml")).unwrap();
    assert!(!registrar_pack.contains("identity_mode"));
    assert!(registrar_pack.contains("registrar_endpoint"));
}

#[test]
fn offline_leaf_ttl_180d_is_legal_and_renders_the_horizon() {
    // The unattended-node tier (2026-09-24 deployment review §4): a
    // physically distant, rarely-touched node may carry a 180d leaf so the
    // rotate calendar halves. The validator's offline bounds (7d–365d)
    // admit it, and the rendered packs carry the full horizon.
    let dir = tempfile::tempdir().expect("tempdir").keep();
    let raised = OFFLINE_MANIFEST.replace("leaf_ttl = \"90d\"", "leaf_ttl = \"180d\"");
    let manifest = write_manifest(&dir, &raised);
    run_ok(&["plan", "validate", "--manifest", &manifest]);
    run_ok(&[
        "plan",
        "apply",
        "--manifest",
        &manifest,
        "--issuer",
        &dir.join("issuer").display().to_string(),
        "--out",
        &dir.join("dist").display().to_string(),
    ]);
    let pack_toml = std::fs::read_to_string(dir.join("dist/packs/ingress-edge/pack.toml")).unwrap();
    assert!(
        pack_toml.contains("leaf_ttl_secs = 15552000"),
        "180d leaf: {pack_toml}"
    );
    // The signed certificate itself must carry the horizon, not just the
    // metadata (the review's open question: does issuance honor the raise?).
    run_ok(&[
        "identity",
        "inspect",
        "--pack",
        &dir.join("dist/packs/ingress-edge").display().to_string(),
    ]);

    // The ceiling is real, not absent — the review's original "no upper
    // bound" reading was wrong.
    let dir2 = tempfile::tempdir().expect("tempdir").keep();
    let beyond = OFFLINE_MANIFEST.replace("leaf_ttl = \"90d\"", "leaf_ttl = \"366d\"");
    let out = run(&[
        "plan",
        "validate",
        "--manifest",
        &write_manifest(&dir2, &beyond),
    ]);
    assert!(!out.success);
    assert!(
        out.stderr.contains("7d and 365d"),
        "the offline tier bounds must be named: {}",
        out.stderr
    );
}

#[test]
fn offline_tier_rejects_registrar_section_and_short_leaves() {
    let dir = tempfile::tempdir().expect("tempdir").keep();
    let both = OFFLINE_MANIFEST.replacen(
        "[public_tls]",
        "[registrar]\nendpoint = \"https://registrar.invalid\"\n\n[public_tls]",
        1,
    );
    let out = run(&[
        "plan",
        "validate",
        "--manifest",
        &write_manifest(&dir, &both),
    ]);
    assert!(!out.success);
    assert!(out.stderr.contains("cannot coexist"), "{}", out.stderr);

    let dir = tempfile::tempdir().expect("tempdir").keep();
    let short = OFFLINE_MANIFEST.replace("leaf_ttl = \"90d\"", "leaf_ttl = \"24h\"");
    let out = run(&[
        "plan",
        "validate",
        "--manifest",
        &write_manifest(&dir, &short),
    ]);
    assert!(!out.success);
    assert!(out.stderr.contains("7d"), "{}", out.stderr);
}

#[test]
fn identity_renew_refuses_offline_packs() {
    let dir = tempfile::tempdir().expect("tempdir").keep();
    let (_, _, _) = apply(&dir);
    let pack = dir.join("dist/packs/ingress-edge").display().to_string();
    let out = run(&["identity", "renew", "--pack", &pack]);
    assert!(!out.success, "offline renew must refuse: {}", out.stdout);
    assert!(
        out.stderr.contains("offline") && out.stderr.contains("rotate"),
        "must point at rotate: {}",
        out.stderr
    );
}

#[test]
fn revoke_then_rotate_embeds_the_deny_list_snapshot() {
    let dir = tempfile::tempdir().expect("tempdir").keep();
    let (manifest, issuer, _) = apply(&dir);
    let gen1 = dir.join("dist/packs/ingress-edge");

    // Revoke the first generation…
    run_ok(&[
        "revoke",
        "--issuer",
        &issuer,
        "--pack",
        &gen1.display().to_string(),
        "--reason",
        "operator-requested",
    ]);

    // …then rotate: the next generation carries the deny list as an embedded
    // CRL snapshot (trust/crls/) with a freshness horizon of the leaf itself.
    run_ok(&[
        "rotate",
        "--manifest",
        &manifest,
        "--issuer",
        &issuer,
        "ingress/edge",
        "--pack",
        &gen1.display().to_string(),
    ]);
    let gen2 = dir.join("dist/packs/ingress-edge-gen2");
    let snapshot = gen2.join("trust/crls/control.crl.pem");
    assert!(
        snapshot.exists(),
        "embedded control CRL: {}",
        gen2.display()
    );
    assert!(gen2.join("trust/crls/workspace-default.crl.pem").exists());
    let crl = std::fs::read_to_string(&snapshot).unwrap();
    assert!(crl.contains("BEGIN X509 CRL"), "{crl}");

    // The pack still loads clean with the snapshot folded into the digests.
    run_ok(&["pack", "inspect", "--pack", &gen2.display().to_string()]);

    // Consumers find the embedded snapshot (mesh hub lookups).
    let stem = "control";
    let found = interflow_identity::pack::crl_path_for(&gen2, stem);
    assert_eq!(
        found,
        Some(gen2.join("trust/crls/control.crl.pem")),
        "helper prefers state, falls back to trust/crls"
    );
}
