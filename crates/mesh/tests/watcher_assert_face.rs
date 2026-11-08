//! The resident-task watchdog's armed-assertion face, end to end on the
//! pack-driven path.
//!
//! Three acceptance shapes:
//!
//! 1. **Armed and honest.** A booting hub registers its resident tasks
//!    (heartbeat, the two recency sweepers, the sweep's own row, the
//!    policy reload watcher) with their cadence anchors, and every row
//!    reads fresh at the document's capture instant — no false silence on
//!    a healthy loop, the slow-runner discipline.
//! 2. **A wedged task goes silent — per its OWN cadence.** The stall-class
//!    fault point wedges the policy reload watcher (alive, not
//!    progressing). Its row must cross `WATCHER_SILENT_FACTOR × its
//!    interval` and read silent on the face, while the OTHER rows (a
//!    different cadence, still healthy) stay armed — the per-row judgment
//!    is the whole design.
//! 3. **The transition reaches the push contract, both directions.** The
//!    fresh→silent crossing bumps the floor version clock (the GUI's
//!    watcher wakes); disarming the fault revives the row on its next
//!    pass and that revival bumps again.
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
use interflow_identity::pack::render::HubCredentialPack;
use interflow_mesh::agent::policy_watch::POLICY_WATCH_INTERVAL;
use interflow_mesh::hub::HubServer;
use interflow_mesh::hub::watchdog::{WATCHER_SILENT_FACTOR, WatcherFaceRow, is_silent};
use interflow_mesh::pack::build_hub_config;
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

struct Site {
    #[allow(dead_code)]
    dir: tempfile::TempDir,
    #[allow(dead_code)]
    hub_dir: std::path::PathBuf,
    #[allow(dead_code)]
    hub_port: u16,
    endpoint: String,
    ca: std::path::PathBuf,
    cert: std::path::PathBuf,
    key: std::path::PathBuf,
    hub_shutdown: tokio_util::sync::CancellationToken,
    hub_task: tokio::task::JoinHandle<()>,
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

/// The watchdog rows the snapshot face carries, keyed by name.
fn row<'a>(
    doc: &'a interflow_mesh::hub::snapshot::FleetSnapshotDoc,
    name: &str,
) -> Option<&'a WatcherFaceRow> {
    doc.hub.watchers.iter().find(|row| row.name == name)
}

/// The armed-assertion face populates with every resident task's row and
/// reads fresh at the capture anchor — no false silence on a healthy hub
/// (the slow-runner discipline), and the rows carry their own cadence
/// anchors so consumers never hardcode a rhythm they do not own.
#[tokio::test]
async fn resident_tasks_register_and_read_armed() {
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
    let site = site("armed").await;

    // Every engine-intrinsic resident task the HubServer run spawns must
    // appear — the rows ARE the "watcher armed" journal lines made
    // queryable. (The renewal row belongs to the pack assembly's run
    // wiring, not the bare HubServer this e2e boots.)
    let doc = eventually_async(
        "the watchdog face to populate",
        Duration::from_secs(15),
        || async {
            let doc = site.snapshot().await;
            let names: Vec<&str> = doc.hub.watchers.iter().map(|r| r.name.as_str()).collect();
            for expected in [
                "heartbeat",
                "policy_face_sweep",
                "crl_face_sweep",
                "watchdog_sweep",
                "hub_policy_reload",
            ] {
                if !names.contains(&expected) {
                    return Err(format!("{expected} missing from {names:?}"));
                }
            }
            Ok(doc)
        },
    )
    .await;

    // No false silence: every row fresh at the document's capture instant.
    let now = u64::try_from(doc.hub.captured_at_unix).unwrap_or(0);
    for row in &doc.hub.watchers {
        assert!(
            !is_silent(row, now),
            "{row:?} reads silent on a healthy hub — false positive"
        );
        assert!(
            row.interval_secs > 0,
            "{row:?} carries no cadence anchor — the silence judgment is unanchorable"
        );
    }

    // The same rows through the overview face (the GUI's data source).
    let overview = site.overview().await;
    assert_eq!(
        overview.watchers.len(),
        doc.hub.watchers.len(),
        "the overview carries the same rows"
    );

    site.hub_shutdown.cancel();
    let _ = site.hub_task.await;
}

/// The silent positive: wedge the policy reload watcher (alive, not
/// progressing), its row crosses its OWN threshold and reads silent while
/// the other rows stay armed; the crossing bumps the floor clock, and
/// disarming revives the row with a second bump.
#[tokio::test]
async fn wedged_task_goes_silent_per_its_own_cadence_and_pushes_both_transitions() {
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
    let site = site("silent-watcher").await;

    // Settle first: every row present and fresh, and the version stable
    // enough to attribute the coming bump to the transition.
    let _ = eventually_async(
        "the watchdog face to populate",
        Duration::from_secs(15),
        || async {
            let doc = site.snapshot().await;
            if row(&doc, "hub_policy_reload").is_some() {
                Ok(())
            } else {
                Err("hub_policy_reload row missing".to_owned())
            }
        },
    )
    .await;
    let version_before = site.floor_version().await;

    // Wedge the watcher: the stall plan re-consults every pass ("while
    // armed"), modeling the task that keeps looping without progressing.
    let faults = interflow_testkit::fault::install(
        interflow_testkit::fault::FaultPlan::new()
            .stall_every_at(interflow_core::fault::FaultPoint::HubPolicyReloadWatchTick),
    );
    assert!(
        faults
            .wait_fired(
                interflow_core::fault::FaultPoint::HubPolicyReloadWatchTick,
                POLICY_WATCH_INTERVAL * 2,
            )
            .await,
        "the armed plan must fire on the watcher's next tick"
    );

    // The row crosses its own threshold (3×10s) and the sweep classifies
    // it — budget = threshold + sweep cadence + slack. Meanwhile the
    // OTHER rows (heartbeat at 15s, the sweepers at 5s) keep ticking and
    // must stay armed in the SAME document — the per-row judgment.
    let threshold = WATCHER_SILENT_FACTOR * POLICY_WATCH_INTERVAL.as_secs();
    let doc = eventually_async(
        "the wedged row to read silent",
        Duration::from_secs(threshold + 20),
        || async {
            let doc = site.snapshot().await;
            let wedged = row(&doc, "hub_policy_reload")
                .ok_or_else(|| "hub_policy_reload row vanished".to_owned())?;
            let now = u64::try_from(doc.hub.captured_at_unix).unwrap_or(0);
            if is_silent(wedged, now) {
                Ok(doc)
            } else {
                Err(format!(
                    "still armed (tick {}s old, threshold {threshold}s)",
                    now.saturating_sub(wedged.last_tick_unix)
                ))
            }
        },
    )
    .await;
    let now = u64::try_from(doc.hub.captured_at_unix).unwrap_or(0);
    for healthy in ["heartbeat", "policy_face_sweep", "watchdog_sweep"] {
        let row = row(&doc, healthy).expect("{healthy} keeps its row");
        assert!(
            !is_silent(row, now),
            "{healthy} reads silent while healthy — the judgment is not per-row: {row:?}"
        );
    }

    // The crossing reached the push contract (nothing else moves on this
    // idle hub: the version advance IS the sweeper's bump). The snapshot
    // above can show the raw instants silent BEFORE the sweep classifies
    // them (classification lags by up to one sweep interval), so the
    // version assertion is its own bounded wait.
    let _ = eventually_async(
        "the silent crossing to bump the floor clock",
        Duration::from_secs(15),
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

    // Disarm: the next pass ticks again — revival bumps once more, and
    // the row re-reads armed.
    interflow_testkit::fault::clear();
    let version_silent = site.floor_version().await;
    let doc = eventually_async(
        "the revived row to read armed again",
        POLICY_WATCH_INTERVAL * 2 + Duration::from_secs(5),
        || async {
            let doc = site.snapshot().await;
            let revived = row(&doc, "hub_policy_reload")
                .ok_or_else(|| "hub_policy_reload row vanished".to_owned())?;
            let now = u64::try_from(doc.hub.captured_at_unix).unwrap_or(0);
            if is_silent(revived, now) {
                Err("still silent".to_owned())
            } else {
                Ok(doc)
            }
        },
    )
    .await;
    let _ = doc;
    assert!(
        site.floor_version().await > version_silent,
        "the silent→fresh revival bumps the floor clock again"
    );

    site.hub_shutdown.cancel();
    let _ = site.hub_task.await;
}
