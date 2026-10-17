//! Pack-format retirement, driven through the real binary: the apply gate
//! senses a stale pack tree and re-renders it, `--force-rerender` is the
//! explicit hatch, and revoke/rotate work on packs whose format the strict
//! loader refuses — the emergency lane never inherits the usability gate.

use std::path::{Path, PathBuf};
use std::process::Command;

fn bin() -> PathBuf {
    let mut p = std::env::current_exe().expect("test bin path");
    p.pop();
    p.pop();
    p.join(format!("interflow-cli{}", std::env::consts::EXE_SUFFIX))
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

fn apply(dir: &Path, extra: &[&str]) -> Run {
    let manifest = dir.join("interflow.toml").display().to_string();
    let issuer = dir.join("issuer").display().to_string();
    let out = dir.join("dist").display().to_string();
    let mut args = vec![
        "plan",
        "apply",
        "--manifest",
        &manifest,
        "--issuer",
        &issuer,
        "--out",
        &out,
    ];
    args.extend_from_slice(extra);
    run_ok(&args)
}

/// Rewrites a pack's pack.toml into the pre-canonical vintage: the
/// constant-field batch of 2026-10-10 made `workspace` (among others)
/// always-present, so dropping the line reproduces exactly the retirement
/// shape found in the field — content-equivalent, strict-unloadable.
fn deprecate_pack_format(pack_dir: &Path) {
    let path = pack_dir.join("pack.toml");
    let text = std::fs::read_to_string(&path).expect("pack.toml");
    let legacy = text
        .lines()
        .filter(|line| !line.starts_with("workspace"))
        .collect::<Vec<_>>()
        .join("\n");
    std::fs::write(&path, format!("{legacy}\n")).unwrap();
    assert!(
        interflow_identity::CredentialPack::load(pack_dir).is_err(),
        "fixture must be strict-unloadable: {}",
        pack_dir.display()
    );
}

#[test]
fn apply_auto_rerenders_stale_format_packs() {
    let dir = tempfile::tempdir().expect("tempdir").keep();
    std::fs::write(dir.join("interflow.toml"), OFFLINE_MANIFEST).unwrap();

    let first = apply(&dir, &[]);
    assert!(
        first.stdout.contains("✔ applied"),
        "first apply full-renders:\n{}",
        first.stdout
    );
    let packs = dir.join("dist/packs");
    deprecate_pack_format(&packs.join("ingress-edge"));
    deprecate_pack_format(&packs.join("agent-desktop"));

    // Same manifest, stale pack tree → the gate must NOT call it a no-op:
    // every pack re-renders above the watermarks (this replaces the dummy-
    // node two-pass ritual the 2026-10-10 batch had to improvise).
    let second = apply(&dir, &[]);
    assert!(
        second
            .stdout
            .contains("is stale — pack.toml does not parse as the current pack format"),
        "the stale pack must be narrated and re-rendered:\n{}",
        second.stdout
    );
    assert!(
        interflow_identity::CredentialPack::load(&packs.join("ingress-edge")).is_ok(),
        "the re-rendered tree is current-format again"
    );
    assert!(
        interflow_identity::CredentialPack::load(&packs.join("agent-desktop")).is_ok(),
        "every manifest pack re-rendered"
    );

    // Convergence: a fresh tree with an unchanged manifest is a true no-op.
    let third = apply(&dir, &[]);
    assert!(
        third.stdout.contains("manifest already applied"),
        "after the heal, apply converges back to no-op:\n{}",
        third.stdout
    );
}

#[test]
fn apply_force_rerender_mints_a_new_generation() {
    let dir = tempfile::tempdir().expect("tempdir").keep();
    std::fs::write(dir.join("interflow.toml"), OFFLINE_MANIFEST).unwrap();

    apply(&dir, &[]);
    let pack = dir.join("dist/packs/agent-desktop");
    let sums_before = std::fs::read_to_string(pack.join("SHA256SUMS")).unwrap();

    // The explicit hatch: unchanged manifest, forced full re-render. The
    // generation rides on (minted above the watermarks — no reset).
    let forced = apply(&dir, &["--force-rerender"]);
    assert!(
        forced.stdout.contains("--force-rerender"),
        "the forced run says so:\n{}",
        forced.stdout
    );
    let sums_after = std::fs::read_to_string(pack.join("SHA256SUMS")).unwrap();
    assert_ne!(
        sums_before, sums_after,
        "every pack re-rendered (fresh timestamps/digests)"
    );
    run_ok(&["pack", "inspect", "--pack", &pack.display().to_string()]);

    // And the bookkeeping still converges: a plain re-run is a no-op.
    let again = apply(&dir, &[]);
    assert!(
        again.stdout.contains("manifest already applied"),
        "post-force state is coherent:\n{}",
        again.stdout
    );
}

#[test]
fn revoke_of_a_legacy_format_pack_denies_its_certificates() {
    let dir = tempfile::tempdir().expect("tempdir").keep();
    std::fs::write(dir.join("interflow.toml"), OFFLINE_MANIFEST).unwrap();
    apply(&dir, &[]);

    let issuer = dir.join("issuer");
    let pack = dir.join("dist/packs/ingress-edge");
    let serials: Vec<String> = std::fs::read_dir(pack.join("identity"))
        .expect("identity dir")
        .filter_map(std::result::Result::ok)
        .filter(|e| e.path().extension().is_some_and(|ext| ext == "crt"))
        .map(|e| {
            interflow_identity::revocation::cert_serial_hex(
                &std::fs::read_to_string(e.path()).unwrap(),
            )
            .unwrap()
        })
        .collect();
    assert!(!serials.is_empty());

    deprecate_pack_format(&pack);
    let out = run_ok(&[
        "revoke",
        "--issuer",
        &issuer.display().to_string(),
        "--pack",
        &pack.display().to_string(),
        "--reason",
        "key-compromise",
    ]);
    assert!(
        out.stdout.contains("revoked"),
        "revoke narrates the denied serials:\n{}",
        out.stdout
    );

    // The deny list carries EVERY serial the pack's certificates declared —
    // revocation reached a pack the strict loader refuses.
    let deny: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(issuer.join("revocations.json")).unwrap())
            .unwrap();
    let recorded: Vec<&str> = deny["entries"]
        .as_array()
        .expect("entries")
        .iter()
        .map(|e| e["serial"].as_str().expect("serial"))
        .collect();
    for serial in &serials {
        assert!(
            recorded.contains(&serial.as_str()),
            "serial {serial} must be denied (recorded: {recorded:?})"
        );
    }
    assert!(
        issuer.join("control.crl.pem").exists(),
        "the control CRL was rebuilt"
    );
}

#[test]
fn rotate_of_a_legacy_format_pack_mints_the_next_generation() {
    let dir = tempfile::tempdir().expect("tempdir").keep();
    std::fs::write(dir.join("interflow.toml"), OFFLINE_MANIFEST).unwrap();
    apply(&dir, &[]);

    let pack = dir.join("dist/packs/ingress-edge");
    deprecate_pack_format(&pack);

    // rotate reads only the generation number — a retired-vintage pack stays
    // rotatable without any re-render ritual first.
    run_ok(&[
        "rotate",
        "--manifest",
        &dir.join("interflow.toml").display().to_string(),
        "--issuer",
        &dir.join("issuer").display().to_string(),
        "ingress/edge",
        "--pack",
        &pack.display().to_string(),
    ]);
    let gen2 = dir.join("dist/packs/ingress-edge-gen2");
    assert!(
        gen2.join("pack.toml").exists(),
        "the rotated pack rendered at the next generation"
    );
    run_ok(&["pack", "inspect", "--pack", &gen2.display().to_string()]);
}

/// 方案C: the closing janitorial sweep — the next rotate removes the
/// PREVIOUS rotations' staging directories (superseded generations of the
/// same node), keeps the fresh staging and the base pack (rollback
/// material), and says what it cleaned.
#[test]
fn rotate_cleans_superseded_staging_directories() {
    let dir = tempfile::tempdir().expect("tempdir").keep();
    std::fs::write(dir.join("interflow.toml"), OFFLINE_MANIFEST).unwrap();
    apply(&dir, &[]);

    let manifest = dir.join("interflow.toml").display().to_string();
    let issuer = dir.join("issuer").display().to_string();
    let base = dir.join("dist/packs/ingress-edge");

    // Two rotations: gen2, then gen3 from the gen2 staging.
    run_ok(&[
        "rotate",
        "--manifest",
        &manifest,
        "--issuer",
        &issuer,
        "ingress/edge",
        "--pack",
        &base.display().to_string(),
    ]);
    let gen2 = dir.join("dist/packs/ingress-edge-gen2");
    assert!(gen2.join("pack.toml").exists(), "fixture: gen2 staging");

    let out = run_ok(&[
        "rotate",
        "--manifest",
        &manifest,
        "--issuer",
        &issuer,
        "ingress/edge",
        "--pack",
        &gen2.display().to_string(),
    ]);

    let gen3 = dir.join("dist/packs/ingress-edge-gen3");
    assert!(
        gen3.join("pack.toml").exists(),
        "the fresh staging stays for distribution"
    );
    assert!(
        !gen2.exists(),
        "the superseded staging is cleaned — the consumed shell must not accumulate"
    );
    assert!(
        base.join("pack.toml").exists(),
        "the base pack (rollback material) is never touched by the sweep"
    );
    assert!(
        out.stdout.contains("cleaned staging: ingress-edge-gen2"),
        "the sweep must say what it cleaned: {}",
        out.stdout
    );
    run_ok(&["pack", "inspect", "--pack", &gen3.display().to_string()]);
}

/// The apply-side closure: a full render mints the bases above every
/// staging watermark, and must not leave the staging family behind —
/// until 0.11.x apply re-rendered the bases and forgot the windows, which
/// is exactly how consumed shells accumulated beside advanced bases.
#[test]
fn apply_closes_superseded_staging_directories() {
    let dir = tempfile::tempdir().expect("tempdir").keep();
    std::fs::write(dir.join("interflow.toml"), OFFLINE_MANIFEST).unwrap();
    apply(&dir, &[]);

    // Open a staging window: rotate the base → gen2.
    let manifest = dir.join("interflow.toml").display().to_string();
    let issuer = dir.join("issuer").display().to_string();
    let base = dir.join("dist/packs/ingress-edge");
    run_ok(&[
        "rotate",
        "--manifest",
        &manifest,
        "--issuer",
        &issuer,
        "ingress/edge",
        "--pack",
        &base.display().to_string(),
    ]);
    let gen2 = dir.join("dist/packs/ingress-edge-gen2");
    assert!(gen2.join("pack.toml").exists(), "fixture: gen2 staging");

    // A full render re-renders the base above every watermark (issuer
    // bookkeeping 2 + the gen2 staging's own policy mirror) — the staging
    // is now strictly older than its base and must be closed.
    let out = apply(&dir, &["--force-rerender"]);

    let base_toml = std::fs::read_to_string(base.join("pack.toml")).unwrap();
    assert!(
        base_toml.contains("generation = 3"),
        "the base re-rendered above the staging watermark: {base_toml}"
    );
    assert!(
        !gen2.exists(),
        "the superseded staging is closed — apply must not forget the staging family"
    );
    assert!(
        out.stdout.contains("cleaned staging: ingress-edge-gen2"),
        "the sweep must say what it cleaned: {}",
        out.stdout
    );
}
