//! The CRL-poll liveness face, end to end on the agent wire path
//!
//! Three acceptance shapes:
//!
//! 1. **An advancing level populates the face.** The test agent carries a
//!    renewal face (the injection seam — no registrar runs here) that a
//!    side task keeps advancing; the client's REAL reporter ships it over
//!    the session control plane, and the hub's snapshot and floor rows
//!    must carry the confirmation instant, advancing with it.
//! 2. **Recency is the LEVEL's instant, never the report's arrival.** The
//!    side task freezes; the reporter keeps shipping (a healthy
//!    transporter over a wedged loop — exactly the failure shape the face
//!    exists for). Consecutive snapshots must show the confirmation
//!    instant CONSTANT while their capture anchors advance: the age the
//!    hub-side sweeper will classify grows honestly. (The 200s
//!    fresh→silent crossing and its floor bump are wall-clock-bound and
//!    unit-tested in `hub::crl_liveness`; the e2e proves the load-bearing
//!    precondition instead of waiting out the threshold.)
//! 3. **A hub restart refills from the next report.** The in-memory table
//!    empties; the agent's reconnect report repopulates the row, and the
//!    first-sighting bump is floor-version-visible.
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
use interflow_mesh::hub::HubServer;
use interflow_mesh::pack::{build_agent_config, build_hub_config};
use interflow_renewal::CrlPollFace;
use interflow_testkit::wait::eventually_async;
use std::path::Path;
use std::sync::Arc;
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

/// The shared site assembly: issuer + packs + a live hub + one connected
/// agent (`main/lan-a`) whose renewal face is the test's injection seam.
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
    face: Arc<CrlPollFace>,
}

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
    // The injection seam: the face the reporter ships AND the side task
    // drives — the renewal loop's stand-in (no registrar runs here).
    let face = Arc::new(CrlPollFace::new());
    let agent = AgentClient::with_renewal_face(config, Some(Arc::clone(&face)))
        .unwrap()
        .start();
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
        face,
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
}

/// Drives the face like a healthy poll loop: one successful poll per
/// second (faster than the real 60s cadence — the wire path under test
/// does not care). Returns the stop switch (freeze = the wedged loop).
fn spawn_poll_loop(face: &Arc<CrlPollFace>) -> tokio_util::sync::CancellationToken {
    let stop = tokio_util::sync::CancellationToken::new();
    let face = Arc::clone(face);
    let stop_for_task = stop.clone();
    tokio::spawn(async move {
        let mut ticker = tokio::time::interval(Duration::from_secs(1));
        ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        loop {
            tokio::select! {
                () = stop_for_task.cancelled() => break,
                _ = ticker.tick() => {}
            }
            face.note_success(u64::try_from(interflow_identity::expiry::now_unix()).unwrap_or(0));
        }
    });
    stop
}

/// Waits (bounded) until the snapshot face reports `agent`'s CRL-poll
/// level: a confirmation instant no older than `max_age_secs` against the
/// document's capture anchor.
async fn wait_crl_row(site: &Site, agent: &str, max_age_secs: u64) -> (u64, u64) {
    eventually_async(
        "the CRL-poll liveness face to populate",
        Duration::from_secs(30),
        || async {
            let doc = site.snapshot().await;
            let row = doc
                .agents
                .iter()
                .find(|r| r.agent == agent)
                .ok_or_else(|| format!("no row for {agent} yet"))?;
            let last = row
                .crl_last_success_unix
                .ok_or_else(|| format!("{agent} carries no CRL level yet: {row:?}"))?;
            let age = (doc.hub.captured_at_unix - last as i64).max(0) as u64;
            if age <= max_age_secs {
                Ok((last, row.crl_failures_total.unwrap_or(0)))
            } else {
                Err(format!(
                    "{agent} last succeeded {age}s before capture (> {max_age_secs}s)"
                ))
            }
        },
    )
    .await
}

/// Phase 1: an advancing level rides the wire into BOTH read faces —
/// the snapshot row and the floor payload — and keeps advancing.
#[tokio::test]
async fn advancing_level_populates_snapshot_and_floor() {
    let site = site("crl-live").await;
    let stop = spawn_poll_loop(&site.face);

    let (first, _) = wait_crl_row(&site, "main/lan-a", 15).await;
    // The floor payload carries the same level (the GUI fleet face's
    // source).
    let overview = site.overview().await;
    let row = overview
        .agents
        .iter()
        .find(|r| r.agent == "main/lan-a")
        .expect("floor row");
    assert_eq!(
        row.crl_last_success_unix,
        Some(first),
        "snapshot and floor agree on the level"
    );
    // And it advances with the loop.
    eventually_async(
        "the confirmation instant advances",
        Duration::from_secs(30),
        || async {
            let (next, _) = wait_crl_row(&site, "main/lan-a", 15).await;
            (next > first)
                .then_some(())
                .ok_or_else(|| format!("level stuck at {first} (the face must track the loop)"))
        },
    )
    .await;

    stop.cancel();
    site.hub_shutdown.cancel();
    let _ = site.hub_task.await;
    let _ = site.agent.shutdown_graceful().await;
}

/// Phase 2: THE design law — a frozen level with a healthy reporter must
/// read by its own instant, not stay fresh by arrival. Consecutive
/// snapshots show the confirmation instant CONSTANT while their capture
/// anchors advance (the age the sweeper will classify grows honestly).
#[tokio::test]
async fn frozen_level_reads_by_its_own_instant_not_arrival() {
    let site = site("crl-frozen").await;
    // One poll to populate, then freeze (the wedged-loop shape: the task
    // is gone; the reporter keeps shipping the frozen atomics).
    let stop = spawn_poll_loop(&site.face);
    let (populated, _) = wait_crl_row(&site, "main/lan-a", 15).await;
    stop.cancel();

    // Two snapshots a few seconds apart: the reporter's 30s tick may or
    // may not fire between them — irrelevant, the level cannot move.
    let doc1 = site.snapshot().await;
    tokio::time::sleep(Duration::from_secs(4)).await;
    let doc2 = site.snapshot().await;
    let row1 = doc1
        .agents
        .iter()
        .find(|r| r.agent == "main/lan-a")
        .unwrap();
    let row2 = doc2
        .agents
        .iter()
        .find(|r| r.agent == "main/lan-a")
        .unwrap();
    assert_eq!(
        row1.crl_last_success_unix, row2.crl_last_success_unix,
        "a wedged loop's level never moves"
    );
    assert_eq!(row2.crl_last_success_unix, Some(populated));
    let age1 = doc1.hub.captured_at_unix - populated as i64;
    let age2 = doc2.hub.captured_at_unix - populated as i64;
    assert!(
        age2 > age1,
        "the capture anchors advance ({age1} → {age2}) while the level stays put: the age \
         the hub-side sweeper classifies grows"
    );
    // The first capture may land in the very second the level was
    // populated (age 0 at second resolution); the law is carried by the
    // SECOND capture reading a positive age and the age growing between
    // the two — a hub stamping by arrival would read ~0 at both.
    assert!(
        age1 >= 0 && age2 > 0,
        "the frozen level reads as aging, never as fresh-by-arrival"
    );

    site.hub_shutdown.cancel();
    let _ = site.hub_task.await;
    let _ = site.agent.shutdown_graceful().await;
}

/// Phase 3: a hub restart empties the in-memory table; the agent's next
/// report repopulates the row, and the first-sighting bump is
/// floor-version-visible (the policy watermarks' restart contract,
/// verbatim).
#[tokio::test]
async fn hub_restart_refills_from_the_next_report() {
    let mut site = site("crl-restart").await;
    let stop = spawn_poll_loop(&site.face);
    let _ = wait_crl_row(&site, "main/lan-a", 15).await;
    let version_before = site.floor_version().await;

    site.hub_shutdown.cancel();
    let old_task = std::mem::replace(&mut site.hub_task, tokio::spawn(async {}));
    let _ = old_task.await;
    let (shutdown, task) = boot_hub(&site.hub_dir, site.hub_port).await;
    // The restarted hub's clock starts at zero again (in-process counter,
    // restart-self-healing by design): the push-visibility assertion
    // anchors on the NEW process's post-boot baseline, not the old one.
    let version_baseline = site.floor_version().await;
    // The agent reconnects on its supervised loop; its first report
    // after re-registration lands within the reporter's immediate pass.
    eventually_async(
        "the liveness row refills after the hub restart",
        Duration::from_secs(45),
        || async {
            let doc = site.snapshot().await;
            doc.agents
                .iter()
                .find(|r| r.agent == "main/lan-a")
                .and_then(|r| r.crl_last_success_unix)
                .map(|_| ())
                .ok_or_else(|| "no CRL level row after restart".to_owned())
        },
    )
    .await;
    // The refill is push-visible: the first-sighting bump advanced the
    // floor version past its pre-restart reading.
    let version_after = eventually_async(
        "the floor version advances past the post-boot baseline",
        Duration::from_secs(10),
        || async {
            let version = site.floor_version().await;
            (version > version_baseline)
                .then_some(version)
                .ok_or_else(|| format!("version {version} not past {version_baseline} yet"))
        },
    )
    .await;
    let _ = (version_before, version_after);

    stop.cancel();
    shutdown.cancel();
    let _ = task.await;
    let _ = site.agent.shutdown_graceful().await;
}
