//! The no-op gate vs a reinstalled hub (2026-10-06 fix, the field's other
//! half): the issuer bookkeeping sits at gen 2 while a hub booted from a
//! gen-1 pack reports floor 1 — an UNCHANGED manifest must re-publish
//! above the watermarks instead of "nothing to do". The hub runs in-process
//! (bootstrapped from the rendered pack, exactly like a fresh install from
//! stale artifacts); `plan apply` runs as the real CLI binary against it.

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

/// A mesh manifest whose hub endpoint is a REAL port (the in-process hub
/// listens there); the extra rule toggles the policy-only change.
fn manifest_text(hub_port: u16, extra_rule: bool) -> String {
    let second = if extra_rule {
        "\n[[agent.leo-mesh.mesh_ingress]]\nname = \"tts\"\nlisten = \
         \"127.0.0.1:11550\"\ntarget_agent = \"home-win\"\nremote_addr = \
         \"127.0.0.1:11550\"\n"
            .to_owned()
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
listen = "127.0.0.1:{hub_port}"
endpoint = "127.0.0.1:{hub_port}"
[workspace.main]
[agent.leo-mesh]
workspace = "main"
[[agent.leo-mesh.mesh_ingress]]
name = "ollama"
listen = "127.0.0.1:11450"
target_agent = "home-win"
remote_addr = "127.0.0.1:11450"{second}
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

    fn write_manifest(&self, text: &str) -> String {
        let path = self.dir.join("interflow.toml");
        std::fs::write(&path, text).unwrap();
        path.display().to_string()
    }

    fn apply(&self, manifest: &str) -> RunOutcome {
        let output = Command::new(bin())
            .args([
                "plan",
                "apply",
                "--manifest",
                manifest,
                "--issuer",
                self.dir.join("issuer").to_str().unwrap(),
                "--out",
                self.dir.join("dist").to_str().unwrap(),
            ])
            .output()
            .expect("spawn interflow");
        RunOutcome {
            success: output.status.success(),
            stdout: String::from_utf8_lossy(&output.stdout).into_owned(),
            stderr: String::from_utf8_lossy(&output.stderr).into_owned(),
        }
    }
}

struct RunOutcome {
    success: bool,
    stdout: String,
    stderr: String,
}

/// Bookkeeping gen 2 + a hub reinstalled from the gen-1 pack (floor 1) +
/// an UNCHANGED manifest → the watermark-aware gate re-publishes
/// generation 3 instead of "nothing to do" (which would leave every
/// gen-2 node frozen above the hub's lineage, the inverted-watermark WARN
/// with no CLI able to act on it).
///
/// Multi-thread runtime: the test blocks on the CLI subprocess while the
/// in-process hub must keep serving the CLI's control-plane dials — a
/// current-thread runtime would starve the hub task for the whole block.
#[tokio::test(flavor = "multi_thread")]
async fn hub_reinstall_below_bookkeeping_republishes_unchanged_manifest() {
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
    let hub_port = free_port();
    let env = Env::new();

    // Two applies with the hub DOWN: bookkeeping and dist reach gen 2; the
    // hub pack stays at its first render (gen 1) — policy-only changes
    // never re-render packs.
    let v1 = env.write_manifest(&manifest_text(hub_port, false));
    let first = env.apply(&v1);
    assert!(first.success, "first apply: {}", first.stderr);
    let v2 = env.write_manifest(&manifest_text(hub_port, true));
    let second = env.apply(&v2);
    assert!(second.success, "policy-only apply: {}", second.stderr);

    // The "reinstall": a hub booted from the gen-1 pack, floor seeded at
    // the embedded generation 1, below the issuer bookkeeping's 2.
    let hub_dir = env.dir.join("dist/packs/hub-promptcn");
    let hub_pack = CredentialPack::load_runtime(&hub_dir).unwrap();
    let hub_active = ActiveCredentialSet::load_or_bootstrap(&hub_pack).unwrap();
    let hub_config = build_hub_config(&hub_pack, &hub_active, &hub_dir).unwrap();
    let audit = AuditSink::spawn(&hub_config.audit);
    let hub = HubServer::new(hub_config, audit).unwrap();
    let (ready_tx, ready_rx) = tokio::sync::oneshot::channel();
    let shutdown = tokio_util::sync::CancellationToken::new();
    let hub_task = tokio::spawn(hub.run_until_signalled(shutdown.clone(), ready_tx));
    ready_rx.await.unwrap();

    // The UNCHANGED manifest: digest match, but the hub floor (1) has
    // fallen behind the bookkeeping (2) → re-publish at 3 repairs the
    // hub's lineage.
    let third = env.apply(&v2);
    shutdown.cancel();
    let _ = hub_task.await;
    assert!(third.success, "reconcile apply: {}", third.stderr);
    assert!(
        !third.stdout.contains("nothing to do"),
        "a hub floor below the bookkeeping must not be a no-op\nstdout: {}\nstderr: {}",
        third.stdout,
        third.stderr
    );
    assert!(
        third
            .stdout
            .contains("the watermarks diverge from the issuer bookkeeping"),
        "the gate must narrate the split: {}",
        third.stdout
    );
    assert!(
        third.stdout.contains(&format!(
            "published to hub 127.0.0.1:{hub_port} → generation 3"
        )),
        "the reconcile must publish generation 3 to the reinstalled hub: {}",
        third.stdout
    );
    assert!(
        std::fs::read_to_string(env.dir.join("dist/policy/policy.toml"))
            .unwrap()
            .contains("generation = 3"),
        "the reconcile bundle must be generation 3"
    );
}

/// The 2026-10-07 blind-spot shape, end to end: the reinstalled hub's floor
/// gets ABSORBED up to the issuer bookkeeping (an agent holding gen 2 pulls
/// with `x-policy-seen=2` → the hub's `fetch_max` floor lands at 2) while
/// the hub still SERVES its embedded generation 1. The pre-fix gate compared
/// three numbers (bookkeeping = dist = floor = 2) and called it a no-op; the
/// serving dimension must open the gate and re-publish generation 3.
#[tokio::test(flavor = "multi_thread")]
async fn hub_floor_absorbed_but_serving_behind_still_republishes() {
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
    let hub_port = free_port();
    let env = Env::new();

    // Two applies with the hub DOWN: bookkeeping and dist reach gen 2; the
    // hub pack stays at its first render (gen 1) — policy-only changes
    // never re-render packs (same setup as the sibling test above).
    let v1 = env.write_manifest(&manifest_text(hub_port, false));
    let first = env.apply(&v1);
    assert!(first.success, "first apply: {}", first.stderr);
    let v2 = env.write_manifest(&manifest_text(hub_port, true));
    let second = env.apply(&v2);
    assert!(second.success, "policy-only apply: {}", second.stderr);

    // The "reinstall": a hub booted from the gen-1 pack — floor seeded at
    // the embedded generation 1, serving the embedded snapshot.
    let hub_dir = env.dir.join("dist/packs/hub-promptcn");
    let hub_pack = CredentialPack::load_runtime(&hub_dir).unwrap();
    let hub_active = ActiveCredentialSet::load_or_bootstrap(&hub_pack).unwrap();
    let hub_config = build_hub_config(&hub_pack, &hub_active, &hub_dir).unwrap();
    let audit = AuditSink::spawn(&hub_config.audit);
    let hub = HubServer::new(hub_config, audit).unwrap();
    let (ready_tx, ready_rx) = tokio::sync::oneshot::channel();
    let shutdown = tokio_util::sync::CancellationToken::new();
    let hub_task = tokio::spawn(hub.run_until_signalled(shutdown.clone(), ready_tx));
    ready_rx.await.unwrap();

    // The absorption (the exact 4b33307 mechanism): a mesh agent built from
    // the rendered gen-1 agent pack registers and pulls with seen=2 — the
    // hub answers 304 at serving generation 1 and absorbs the reported
    // watermark into its floor (now 2 == the bookkeeping, masking the
    // serving split from every floor-only consumer).
    {
        use interflow_core::tunnel::{
            AgentTunnel, DEFAULT_REQUEST_ESTABLISH_TIMEOUT, H2Liveness, PolicyPull, SessionTasks,
        };
        let agent_dir = env.dir.join("dist/packs/agent-leo-mesh");
        let agent_pack = CredentialPack::load_runtime(&agent_dir).unwrap();
        let agent_active = ActiveCredentialSet::load_or_bootstrap(&agent_pack).unwrap();
        let config =
            interflow_mesh::pack::build_agent_config(&agent_pack, &agent_active, &agent_dir)
                .unwrap();
        let client = interflow_mesh::agent::AgentClient::new(config).unwrap();
        let conn = client.connect_and_register().await.unwrap();
        let token = tokio_util::sync::CancellationToken::new();
        let tasks = SessionTasks::new(token.clone());
        let tunnel = AgentTunnel::from_sender(
            conn.negotiated.circuit_token,
            &conn.hub_url,
            conn.send_request,
            &tasks,
            H2Liveness {
                incoming_streams_budget: 0,
                poll_watchdog: conn.negotiated.poll_watchdog(),
                establish_timeout: DEFAULT_REQUEST_ESTABLISH_TIMEOUT,
                task_stall_timeout: conn.negotiated.task_stall_timeout(),
            },
        )
        .unwrap();
        let pull = tunnel.pull_policy(2).await.unwrap();
        assert!(
            matches!(pull, PolicyPull::UpToDate { hub_generation: 1 }),
            "the reinstalled hub must serve its embedded generation 1 ({pull:?})"
        );
        // Release the session (poll/upload loops and the registration).
        token.cancel();
        tunnel.shutdown().await;
    }

    // The UNCHANGED manifest: floor now AGREES with the bookkeeping (2 ==
    // 2, absorbed) — only the serving dimension (hub serves 1 < 2) exposes
    // the split. The gate must open and re-publish 3.
    let third = env.apply(&v2);
    shutdown.cancel();
    let _ = hub_task.await;
    assert!(third.success, "reconcile apply: {}", third.stderr);
    assert!(
        !third.stdout.contains("nothing to do"),
        "an absorbed floor must not mask a serving split\nstdout: {}\nstderr: {}",
        third.stdout,
        third.stderr
    );
    assert!(
        third.stdout.contains("SERVING generation 1"),
        "the gate must name the serving divergence: {}",
        third.stdout
    );
    assert!(
        third.stdout.contains(&format!(
            "published to hub 127.0.0.1:{hub_port} → generation 3"
        )),
        "the reconcile must publish generation 3 to the reinstalled hub: {}",
        third.stdout
    );
    assert!(
        std::fs::read_to_string(env.dir.join("dist/policy/policy.toml"))
            .unwrap()
            .contains("generation = 3"),
        "the reconcile bundle must be generation 3"
    );
}
