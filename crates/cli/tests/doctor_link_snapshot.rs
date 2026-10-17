//! e2e: the fleet-snapshot tooling against a REAL hub — `status snapshot`
//! persistence, `status diff`, and `doctor link --hub` / `--to` through
//! the actual CLI binary (the same in-process hub harness as
//! policy_apply_hub_reinstall.rs). The manifest opts into the QUIC face
//! (`quic_listen`) so the agent-side probe's UDP layer has a real listener
//! to answer its version-negotiation trigger.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use interflow_core::security::AuditSink;
use interflow_identity::credentials::ActiveCredentialSet;
use interflow_identity::pack::CredentialPack;
use interflow_mesh::hub::HubServer;
use interflow_mesh::pack::build_hub_config;
use std::path::PathBuf;
use std::process::Command;

fn bin() -> PathBuf {
    let mut p = std::env::current_exe().expect("test bin path");
    p.pop(); // deps/
    p.pop(); // tests/
    p.join(format!("interflow-cli{}", std::env::consts::EXE_SUFFIX))
}

fn free_port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

fn manifest_text(hub_port: u16) -> String {
    format!(
        r#"
[realm]
id = "promptcn-mesh"
[identity]
mode = "offline"
leaf_ttl = "7d"
[mesh.hub.promptcn]
listen = "127.0.0.1:{hub_port}"
endpoint = "127.0.0.1:{hub_port}"
quic_listen = "0.0.0.0:{hub_port}"
[workspace.main]
[agent.leo-mesh]
workspace = "main"
[[agent.leo-mesh.mesh_ingress]]
name = "ollama"
listen = "127.0.0.1:11450"
target_agent = "home-win"
remote_addr = "127.0.0.1:11450"
[agent.home-win]
workspace = "main"
[[agent.home-win.mesh_egress]]
name = "loopback"
target_cidr = "127.0.0.0/8"
"#
    )
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

/// The full tool chain against a live hub: capture → persist → diff →
/// hub-side reading → agent-side three-layer probe (DNS/TCP/UDP/mTLS all
/// real, against the hub's real TLS and QUIC listeners).
#[tokio::test(flavor = "multi_thread")]
async fn snapshot_toolchain_reads_a_live_hub() {
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
    let hub_port = free_port();
    let dir = tempfile::tempdir().expect("tempdir").keep();
    let manifest = dir.join("interflow.toml");
    std::fs::write(&manifest, manifest_text(hub_port)).unwrap();
    let manifest_arg = manifest.display().to_string();
    let issuer_arg = dir.join("issuer").display().to_string();

    let apply = run(&[
        "plan",
        "apply",
        "--manifest",
        &manifest_arg,
        "--issuer",
        &issuer_arg,
        "--out",
        &dir.join("dist").display().to_string(),
    ]);
    assert!(apply.success, "apply: {}", apply.stderr);

    // Boot the hub from the rendered pack, exactly like a fresh install.
    let hub_dir = dir.join("dist/packs/hub-promptcn");
    let hub_pack = CredentialPack::load_runtime(&hub_dir).unwrap();
    let hub_active = ActiveCredentialSet::load_or_bootstrap(&hub_pack).unwrap();
    let hub_config = build_hub_config(&hub_pack, &hub_active, &hub_dir).unwrap();
    let audit = AuditSink::spawn(&hub_config.audit);
    let hub = HubServer::new(hub_config, audit).unwrap();
    let (ready_tx, ready_rx) = tokio::sync::oneshot::channel();
    let shutdown = tokio_util::sync::CancellationToken::new();
    let hub_task = tokio::spawn(hub.run_until_signalled(shutdown.clone(), ready_tx));
    ready_rx.await.unwrap();

    // status snapshot --out: the persisted envelope parses and carries the
    // wire schema + the capturing CLI's build.
    let snap_path = dir.join("before.json");
    let snap = run(&[
        "status",
        "snapshot",
        "--manifest",
        &manifest_arg,
        "--issuer",
        &issuer_arg,
        "--out",
        &snap_path.display().to_string(),
    ]);
    assert!(snap.success, "snapshot: {}", snap.stderr);
    let saved: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&snap_path).unwrap()).unwrap();
    assert_eq!(
        saved["snapshot"]["format_version"],
        interflow_mesh::hub::snapshot::FLEET_SNAPSHOT_FORMAT_VERSION,
        "{saved:?}"
    );
    assert!(
        saved["snapshot"]["hub"]["serving_generation"].is_u64(),
        "a fresh hub serves its embedded bundle: {saved:?}"
    );
    assert!(
        saved["cli_build"].as_str().is_some_and(|b| !b.is_empty()),
        "the envelope records the capturing CLI's build: {saved:?}"
    );

    // status diff against itself: a steady picture diffs clean.
    let diff = run(&[
        "status",
        "diff",
        &snap_path.display().to_string(),
        &snap_path.display().to_string(),
    ]);
    assert!(diff.success, "self-diff: {}", diff.stderr);
    assert!(diff.stdout.contains("serving gen"), "{}", diff.stdout);
    assert!(
        diff.stdout.contains("(steady window)"),
        "no eviction between identical captures: {}",
        diff.stdout
    );

    // doctor link --hub: the fleet reading renders from the same face.
    let hub_reading = run(&[
        "doctor",
        "link",
        "--hub",
        "--manifest",
        &manifest_arg,
        "--issuer",
        &issuer_arg,
    ]);
    assert!(hub_reading.success, "hub reading: {}", hub_reading.stderr);
    assert!(
        hub_reading.stdout.contains("serving policy gen"),
        "{}",
        hub_reading.stdout
    );
    assert!(
        hub_reading.stdout.contains("legs:"),
        "{}",
        hub_reading.stdout
    );

    // doctor link --to: the agent-side three-layer probe against the live
    // hub — real resolver, real TCP, real QUIC version negotiation, real
    // mTLS with the agent pack's credential.
    let agent_pack = dir.join("dist/packs/agent-leo-mesh");
    let probe = run(&[
        "doctor",
        "link",
        "--to",
        &format!("127.0.0.1:{hub_port}"),
        "--pack",
        &agent_pack.display().to_string(),
        "--manifest",
        &manifest_arg,
        "--issuer",
        &issuer_arg,
    ]);
    shutdown.cancel();
    let _ = hub_task.await;
    assert!(
        probe.success,
        "the three-layer probe must read green against a healthy hub:\nstdout: {}\nstderr: {}",
        probe.stdout, probe.stderr
    );
    assert!(
        probe.stdout.contains("[authentication]"),
        "{}",
        probe.stdout
    );
    assert!(
        probe.stdout.contains("version negotiation"),
        "the UDP layer's real answer: {}",
        probe.stdout
    );
    assert!(
        probe.stdout.contains("mTLS handshake OK"),
        "{}",
        probe.stdout
    );
    assert!(probe.stdout.contains("[authorization]"), "{}", probe.stdout);
    assert!(
        probe.stdout.contains("All layers healthy"),
        "{}",
        probe.stdout
    );
}

/// The revocation reading, both source tiers
/// ((internal design notes) +
/// (internal design notes)):
///
/// 1. `revoke --manifest` pushes the fresh CRLs to the LIVE hub — the hub
///    hot-swaps its verification plane, so the revoked pack's mTLS
///    handshake FAILS (✘ authentication, seconds-level, no restart);
/// 2. with `--issuer` in hand the authorization layer reads the issuer's
///    CURRENT CRLs and names the revocation (✘, independent of the hub);
/// 3. without the issuer the CRL line is the honest neutral downgrade (·,
///    never a fake ✔ for a carried snapshot).
#[tokio::test(flavor = "multi_thread")]
async fn revoked_pack_reads_red_with_issuer_and_neutral_without() {
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
    let hub_port = free_port();
    let dir = tempfile::tempdir().expect("tempdir").keep();
    let manifest = dir.join("interflow.toml");
    std::fs::write(&manifest, manifest_text(hub_port)).unwrap();
    let manifest_arg = manifest.display().to_string();
    let issuer_arg = dir.join("issuer").display().to_string();

    let apply = run(&[
        "plan",
        "apply",
        "--manifest",
        &manifest_arg,
        "--issuer",
        &issuer_arg,
        "--out",
        &dir.join("dist").display().to_string(),
    ]);
    assert!(apply.success, "apply: {}", apply.stderr);

    // Boot the hub from the rendered pack, exactly like a fresh install.
    let hub_dir = dir.join("dist/packs/hub-promptcn");
    let hub_pack = CredentialPack::load_runtime(&hub_dir).unwrap();
    let hub_active = ActiveCredentialSet::load_or_bootstrap(&hub_pack).unwrap();
    let hub_config = build_hub_config(&hub_pack, &hub_active, &hub_dir).unwrap();
    let audit = AuditSink::spawn(&hub_config.audit);
    let hub = HubServer::new(hub_config, audit).unwrap();
    let (ready_tx, ready_rx) = tokio::sync::oneshot::channel();
    let shutdown = tokio_util::sync::CancellationToken::new();
    let hub_task = tokio::spawn(hub.run_until_signalled(shutdown.clone(), ready_tx));
    ready_rx.await.unwrap();

    // Revoke with --manifest: the finisher pushes to the live hub.
    let agent_pack = dir.join("dist/packs/agent-leo-mesh");
    let revoke = run(&[
        "revoke",
        "--issuer",
        &issuer_arg,
        "--pack",
        &agent_pack.display().to_string(),
        "--reason",
        "superseded",
        "--manifest",
        &manifest_arg,
    ]);
    assert!(revoke.success, "revoke: {}", revoke.stderr);
    assert!(
        revoke.stdout.contains("pushed CRLs to hub"),
        "the push narration: {}",
        revoke.stdout
    );

    // The authoritative reading: the hub (hot-swapped) rejects the revoked
    // credential AT THE HANDSHAKE, and the issuer-side CRL check names the
    // revocation regardless of the hub.
    let probe = run(&[
        "doctor",
        "link",
        "--to",
        &format!("127.0.0.1:{hub_port}"),
        "--pack",
        &agent_pack.display().to_string(),
        "--manifest",
        &manifest_arg,
        "--issuer",
        &issuer_arg,
    ]);
    assert!(
        !probe.success,
        "the revoked pack must read red:\nstdout: {}\nstderr: {}",
        probe.stdout, probe.stderr
    );
    assert!(
        probe.stdout.contains("✘ [authentication]"),
        "the hot-swapped hub rejects at the handshake: {}",
        probe.stdout
    );
    assert!(
        probe.stdout.contains("mTLS handshake failed"),
        "{}",
        probe.stdout
    );
    assert!(
        probe.stdout.contains("✘ [authorization]"),
        "{}",
        probe.stdout
    );
    assert!(
        probe.stdout.contains("issuer CRL"),
        "the authorization layer names the issuer-side revocation: {}",
        probe.stdout
    );

    // The degraded reading: no issuer CRLs in hand — the CRL line is the
    // neutral downgrade, never a fake green for a carried snapshot.
    let probe2 = run(&[
        "doctor",
        "link",
        "--to",
        &format!("127.0.0.1:{hub_port}"),
        "--pack",
        &agent_pack.display().to_string(),
        "--manifest",
        &manifest_arg,
        "--issuer",
        &dir.join("absent-issuer").display().to_string(),
    ]);
    assert!(
        probe2.stdout.contains("· [authorization]"),
        "the carried snapshot reads as a neutral ·: {}",
        probe2.stdout
    );
    assert!(
        probe2.stdout.contains("carried CRL snapshot"),
        "{}",
        probe2.stdout
    );
    assert!(
        !probe2.stdout.contains("✔ [authorization]"),
        "a carried snapshot never vouches for its own pack: {}",
        probe2.stdout
    );

    shutdown.cancel();
    let _ = hub_task.await;
}
