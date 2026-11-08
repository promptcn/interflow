//! The policy face's LEVEL material, end to end on the pack-driven path
//!
//! Two acceptance shapes:
//!
//! 1. **Steady-state 304s populate the face.** An agent whose pack already
//!    carries the serving generation answers 304 on every watch tick — no
//!    `policy_pulled` audit event, ever. The OLD face (rendered from the
//!    edge ledger) read `never` for exactly this leg; the level watermark
//!    table must show the watermark AND its confirmation instant. The same
//!    phase then reboots the hub in-process: the in-memory table empties,
//!    and the refill (one pull after reconnect, first-sighting bump) is
//!    asserted — the "hub upgrade resets the face to never" regression
//!    nail.
//! 2. **A dead watcher's silence REACHES the push contract.** The fault
//!    point kills the agent's policy-watch task silently (the TaskTracker
//!    swallows the panic; the node stays otherwise healthy). No pull, no
//!    ledger row, no ordinary bump — the ONLY structural path to
//!    observability is the hub-side recency sweeper, whose fresh→silent
//!    transition must bump the floor version clock (the GUI's watcher
//!    wakes) while the face freezes at the last confirmation instant.
#![allow(
    clippy::all,
    clippy::pedantic,
    clippy::nursery,
    clippy::panic,
    clippy::unwrap_used,
    clippy::expect_used,
    missing_docs
)]

use interflow_core::security::AuditSink;
use interflow_identity::credentials::ActiveCredentialSet;
use interflow_identity::issuance::IssuerStore;
use interflow_identity::manifest::Manifest;
use interflow_identity::pack::CredentialPack;
use interflow_identity::pack::render::{AgentCredentialPack, HubCredentialPack};
use interflow_mesh::agent::AgentClient;
use interflow_mesh::agent::policy_watch::{POLICY_SILENT_AFTER_SECS, POLICY_WATCH_INTERVAL};
use interflow_mesh::hub::HubServer;
use interflow_mesh::pack::{build_agent_config, build_hub_config};
use interflow_testkit::wait::eventually_async;
use std::path::Path;
use std::time::Duration;

fn free_port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

async fn wait_connected(agent: &interflow_mesh::agent::AgentHandle) {
    let mut state = agent.subscribe_state();
    let deadline = tokio::time::Instant::now() + Duration::from_secs(30);
    loop {
        let now = state.borrow().clone();
        if matches!(now, interflow_mesh::agent::AgentState::Connected { .. }) {
            return;
        }
        if matches!(now, interflow_mesh::agent::AgentState::Failed { .. }) {
            panic!("agent failed: {now:?}");
        }
        let changed = tokio::time::timeout_at(deadline, state.changed());
        match changed.await {
            Ok(Ok(())) => {}
            _ => panic!("agent never connected (last state {now:?})"),
        }
    }
}

/// The shared site assembly: issuer + gen-1 packs + a live hub + one
/// connected agent (`main/lan-a`) + control-plane query credentials. The
/// agent's pack embeds generation 1 — every pull it ever makes is a
/// not-modified 304, which is exactly the population path under test.
struct Site {
    #[allow(dead_code)]
    dir: tempfile::TempDir,
    hub_dir: std::path::PathBuf,
    hub_port: u16,
    endpoint: String,
    ca: std::path::PathBuf,
    cert: std::path::PathBuf,
    key: std::path::PathBuf,
    hub_shutdown: tokio_util::sync::CancellationToken,
    hub_task: tokio::task::JoinHandle<()>,
    agent: interflow_mesh::agent::AgentHandle,
}

/// Boots a hub from `hub_dir` on `hub_port`, retrying the bind briefly
/// (a same-port rebirth races the previous listener's close-out).
async fn boot_hub(
    hub_dir: &Path,
    hub_port: u16,
) -> (
    tokio_util::sync::CancellationToken,
    tokio::task::JoinHandle<()>,
) {
    let mut last_err = String::new();
    for _ in 0..10 {
        let hub_pack = CredentialPack::load_runtime(hub_dir).unwrap();
        let hub_active = ActiveCredentialSet::load_or_bootstrap(&hub_pack).unwrap();
        let hub_config = build_hub_config(&hub_pack, &hub_active, hub_dir).unwrap();
        let audit = AuditSink::spawn(&hub_config.audit);
        let hub = HubServer::new(hub_config, audit).unwrap();
        let (ready_tx, ready_rx) = tokio::sync::oneshot::channel();
        let shutdown = tokio_util::sync::CancellationToken::new();
        let task = tokio::spawn({
            let shutdown = shutdown.clone();
            async move {
                let _ = hub.run_until_signalled(shutdown, ready_tx).await;
            }
        });
        match tokio::time::timeout(Duration::from_secs(2), ready_rx).await {
            Ok(Ok(_ready)) => return (shutdown, task),
            Ok(Err(_)) => panic!("hub task ended before readiness"),
            Err(_) => {
                let _ = task.await;
                last_err = "hub did not become ready within 2s (bind contention?)".to_owned();
            }
        }
        tokio::time::sleep(Duration::from_millis(300)).await;
    }
    panic!("hub never came up on port {hub_port}: {last_err}");
}

async fn site(tag: &str) -> Site {
    let hub_port = free_port();
    let listen_port = free_port();
    let remote_port = free_port();
    let dir = tempfile::tempdir().unwrap();
    let issuer = IssuerStore::open(dir.path().join("issuer"));
    issuer.ensure_realm().unwrap();
    issuer.ensure_workspace("main").unwrap();
    issuer.ensure_policy_key().unwrap();
    let manifest = Manifest::parse(&format!(
        r#"
[realm]
id = "test-{tag}"
[registrar]
endpoint = "https://registrar.example.com"
[mesh.hub.central]
listen = "127.0.0.1:{hub_port}"
endpoint = "127.0.0.1:{hub_port}"
[workspace.main]
[agent.lan-a]
workspace = "main"
[[agent.lan-a.mesh_ingress]]
name = "svc"
listen = "127.0.0.1:{listen_port}"
target_agent = "lan-b"
remote_addr = "127.0.0.1:{remote_port}"
[agent.lan-b]
workspace = "main"
[[agent.lan-b.mesh_egress]]
name = "svc"
target_addr = "127.0.0.1:{remote_port}"
"#
    ))
    .unwrap();

    let hub_dir = dir.path().join("packs/hub-central");
    HubCredentialPack::render(&issuer, &manifest, "central", 1, &hub_dir).unwrap();
    let agent_pack = dir.path().join("packs/agent-lan-a");
    AgentCredentialPack::render(&issuer, &manifest, "lan-a", 1, &agent_pack).unwrap();

    // The control-plane credential (realm-anchored, the operator class):
    // the same mint the pack_site_to_site overview assertions ride.
    let creds_dir = dir.path().join("control-creds");
    std::fs::create_dir_all(&creds_dir).unwrap();
    let ttl = interflow_identity::issuance::LeafTtl::new(time::Duration::hours(1));
    let material = issuer
        .issue_hub_member_with_ttl(&format!("test-{tag}"), "doctor-hub", ttl)
        .unwrap();
    let (ca, cert, key) = (
        creds_dir.join("ca.crt"),
        creds_dir.join("client.crt"),
        creds_dir.join("client.key"),
    );
    std::fs::write(&ca, issuer.realm_issuer().unwrap().cert_pem()).unwrap();
    std::fs::write(&cert, &material.chain_pem).unwrap();
    std::fs::write(&key, &material.key_pem).unwrap();

    let (hub_shutdown, hub_task) = boot_hub(&hub_dir, hub_port).await;

    let pack = CredentialPack::load_runtime(&agent_pack).unwrap();
    let active = ActiveCredentialSet::load_or_bootstrap(&pack).unwrap();
    let config = build_agent_config(&pack, &active, &agent_pack).unwrap();
    let agent = AgentClient::new(config).unwrap().start();
    wait_connected(&agent).await;

    Site {
        dir,
        hub_dir,
        hub_port,
        endpoint: format!("127.0.0.1:{hub_port}"),
        ca,
        cert,
        key,
        hub_shutdown,
        hub_task,
        agent,
    }
}

impl Site {
    async fn snapshot(&self) -> interflow_mesh::hub::snapshot::FleetSnapshotDoc {
        interflow_mesh::hub::snapshot::query_fleet_snapshot(
            &self.endpoint,
            &self.ca,
            &self.cert,
            &self.key,
        )
        .await
        .unwrap()
    }

    async fn overview(&self) -> interflow_mesh::hub::policy::HubOverview {
        interflow_mesh::hub::policy::query_hub_overview(
            &self.endpoint,
            &self.ca,
            &self.cert,
            &self.key,
        )
        .await
        .unwrap()
    }

    async fn floor_version(&self) -> u64 {
        interflow_mesh::hub::policy::watch_floor_version(
            &self.endpoint,
            &self.ca,
            &self.cert,
            &self.key,
            0,
            0,
        )
        .await
        .unwrap()
    }

    /// The hub's audit rows (absent file = no events).
    fn audit_pairs(&self) -> Vec<(String, u64)> {
        std::fs::read_to_string(self.hub_dir.join("audit.jsonl"))
            .unwrap_or_default()
            .lines()
            .filter_map(|line| serde_json::from_str::<serde_json::Value>(line).ok())
            .filter(|v| v.get("kind").and_then(|k| k.as_str()) == Some("policy_pulled"))
            .map(|v| {
                (
                    v.get("agent")
                        .and_then(|a| a.as_str())
                        .unwrap_or_default()
                        .to_string(),
                    v.get("generation")
                        .and_then(serde_json::Value::as_u64)
                        .unwrap_or(0),
                )
            })
            .collect()
    }
}

/// Waits (bounded) until the snapshot face reports `agent`'s LEVEL policy
/// face: the watermark plus a confirmation instant no older than
/// `max_age_secs` against the document's capture time. Returns
/// `(seen_generation, last_pull_unix)`.
async fn wait_level_face(site: &Site, agent: &str, max_age_secs: u64) -> (u64, u64) {
    eventually_async(
        "the level policy face to populate",
        Duration::from_secs(30),
        || async {
            let doc = site.snapshot().await;
            let row = doc
                .agents
                .iter()
                .find(|r| r.agent == agent)
                .ok_or_else(|| format!("no row for {agent} yet"))?;
            let seen = row
                .seen_generation
                .ok_or_else(|| format!("{agent} carries no watermark yet"))?;
            let last_pull = row
                .last_pull_unix
                .ok_or_else(|| format!("{agent} carries no confirmation instant yet: {row:?}"))?;
            let age = (doc.hub.captured_at_unix - last_pull as i64).max(0) as u64;
            if age <= max_age_secs {
                Ok((seen, last_pull))
            } else {
                Err(format!(
                    "{agent} last pulled {age}s before capture (> {max_age_secs}s)"
                ))
            }
        },
    )
    .await
}

/// Steady-state 304s land in the face (the "healthy but reads never"
/// regression nail), the audit stays edge-clean, and a hub reboot refills
/// the in-memory face within one pull of the reconnect.
#[tokio::test]
async fn uptodate_pulls_populate_the_face_and_refill_after_hub_restart() {
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
    let mut site = site("level").await;

    // The face populates with NO publish ever having happened: the agent's
    // pack already carries the serving generation, every pull answers 304,
    // and the level table records watermark + confirmation instant anyway.
    let (seen, _last_pull) =
        wait_level_face(&site, "main/lan-a", POLICY_WATCH_INTERVAL.as_secs() * 2).await;
    assert_eq!(seen, 1, "the embedded generation 1 is the steady watermark");

    // The same level material through the overview face (the GUI's data
    // source), including the recency anchor.
    let overview = site.overview().await;
    assert!(
        overview.captured_at_unix.is_some(),
        "the overview self-reports its capture instant: {overview:?}"
    );
    let row = overview
        .agents
        .iter()
        .find(|a| a.agent == "main/lan-a")
        .expect("overview lists the leg");
    assert_eq!(row.seen, Some(1));
    assert!(
        row.last_pull_unix.is_some(),
        "the overview carries the confirmation instant: {row:?}"
    );

    // The audit ledger stayed edge-clean: converging from the embedded
    // generation was never a distribution event, and the face learned it
    // without any. This pair of facts is exactly what the old face could
    // not hold together (it read `never` here).
    assert!(
        site.audit_pairs().is_empty(),
        "steady-state 304s are not ledger material: {:?}",
        site.audit_pairs()
    );

    // ---- The hub reboot: in-memory face empties, refill within one pull
    // of the reconnect (the upgrade-window regression: the OLD face reset
    // to `never` for every leg until the next publish).
    site.hub_shutdown.cancel();
    let _ = (&mut site.hub_task).await;
    let (shutdown, task) = boot_hub(&site.hub_dir, site.hub_port).await;

    // The agent reconnects (session rebuild) and its first connected pull
    // re-records the row — bounded generously for the rebuild, freshness
    // asserted against the capture instant once present.
    let (seen, last_pull) =
        wait_level_face(&site, "main/lan-a", POLICY_WATCH_INTERVAL.as_secs() * 2).await;
    assert_eq!(seen, 1, "the refill carries the same watermark");
    assert!(last_pull > 0);

    // The refill is push-visible: the rebooted clock (version 0 at boot)
    // has advanced past zero — a held floor watch would have woken.
    assert!(
        site.floor_version().await >= 1,
        "the first-sighting bump makes the refill wake floor watchers"
    );

    let _ = site.agent.shutdown_graceful().await;
    shutdown.cancel();
    let _ = task.await;
}

/// The silent-policy-face positive: kill the watcher task (the node stays
/// otherwise healthy), publish nothing, and the ABSENCE must become
/// observable — the frozen confirmation instant on the face and, the part
/// only the sweeper can provide, a floor-clock bump that wakes the push
/// contract.
#[tokio::test]
async fn dead_watcher_silent_transition_reaches_the_push_contract() {
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
    let site = site("silent").await;
    wait_level_face(&site, "main/lan-a", POLICY_WATCH_INTERVAL.as_secs() * 2).await;
    // Settle the OTHER level faces before pinning the version: each
    // records its first sighting with a bump (the node-status streams
    // face lands within one reporter interval of the connect), and this
    // test attributes THE next advance to the policy sweeper alone.
    let _ = eventually_async(
        "the node-status face's first report to land",
        Duration::from_secs(20),
        || async {
            let doc = site.snapshot().await;
            match doc.agents.iter().find(|r| r.agent == "main/lan-a") {
                Some(row) if !row.streams.is_empty() => Ok(()),
                Some(_) => Err("streams face still empty".to_owned()),
                None => Err("no row".to_owned()),
            }
        },
    )
    .await;
    let version_before = site.floor_version().await;

    // Kill the policy watcher: the panic rides the agent's TaskTracker (no
    // supervisor restart), modeling the silent task death.
    let faults = interflow_testkit::fault::install(
        interflow_testkit::fault::FaultPlan::new()
            .panic_at(interflow_core::fault::FaultPoint::AgentPolicyWatchTick),
    );
    assert!(
        faults
            .wait_fired(
                interflow_core::fault::FaultPoint::AgentPolicyWatchTick,
                POLICY_WATCH_INTERVAL * 2,
            )
            .await,
        "the armed plan must fire on the watcher's next tick"
    );

    // The panic lands at a tick HEAD, so one pull may have completed after
    // the snapshot that established convergence — read the frozen instant
    // from a snapshot taken AFTER the kill; it must never move again.
    let frozen_at = site
        .snapshot()
        .await
        .agents
        .iter()
        .find(|r| r.agent == "main/lan-a")
        .and_then(|r| r.last_pull_unix)
        .expect("the face stays populated after the kill");

    // The transition: nothing else moves (no publish, no pause, no
    // maintenance — a single leg in steady state), so a version advance
    // here IS the sweeper's fresh→silent bump. Budget = the silent
    // threshold + sweep cadence + a tick of slack.
    let version_after = eventually_async(
        "the silent transition to bump the floor clock",
        POLICY_WATCH_INTERVAL * 2 + Duration::from_secs(POLICY_SILENT_AFTER_SECS + 20),
        || async {
            let v = site.floor_version().await;
            if v > version_before {
                Ok(v)
            } else {
                Err(format!("version still {v} (before {version_before})"))
            }
        },
    )
    .await;
    assert!(version_after > version_before);

    // And the face tells the story the bump pointed at: the node reads
    // ONLINE (presence is a different plane), the watermark holds, and the
    // confirmation instant is frozen past the threshold — the doctor's
    // silent ⚠ reads exactly these fields.
    let doc = site.snapshot().await;
    let row = doc
        .agents
        .iter()
        .find(|r| r.agent == "main/lan-a")
        .expect("the leg keeps its row");
    assert!(
        row.online,
        "a dead policy watcher is not a dead node: {row:?}"
    );
    assert_eq!(row.seen_generation, Some(1));
    assert_eq!(
        row.last_pull_unix,
        Some(frozen_at),
        "no pull happened after the kill — the instant is frozen"
    );
    let age = (doc.hub.captured_at_unix - frozen_at as i64).max(0) as u64;
    assert!(
        age > POLICY_SILENT_AFTER_SECS,
        "the frozen face reads silent ({age}s > {POLICY_SILENT_AFTER_SECS}s)"
    );

    // Silence never touches the audit ledger (no distribution happened).
    assert!(site.audit_pairs().is_empty());

    interflow_testkit::fault::clear();
    let _ = site.agent.shutdown_graceful().await;
    site.hub_shutdown.cancel();
    let _ = site.hub_task.await;
}
