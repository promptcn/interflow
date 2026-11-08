//! The stream-intent mailbox's watermark face, end to end on the
//! pack-driven path.
//!
//! Three acceptance shapes:
//!
//! 1. **A queued op becomes continuously visible.** An op queued for an
//!    offline leg shows on the fleet snapshot (`pending_count`, the
//!    oldest op's instant + label) within one read — the "queued,
//!    applies on next check-in" CLI message made continuous — and the
//!    enqueue bumps the floor version clock (the push contract carries
//!    it).
//! 2. **The capacity guard's drop is a first-class counter.** Filling
//!    the mailbox past its bound drops the oldest op: `dropped_total`
//!    on the face, surviving even after the queue drains (dropped is
//!    dropped — the re-issue decision reads it).
//! 3. **Delivery clears the waiting face.** The leg returns, its intent
//!    watcher exchanges, applies, and re-reports; the mailbox empties
//!    and the face reads clean again (the drop history excepted).
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
use interflow_core::tunnel::transport::StreamIntentOp;
use interflow_identity::credentials::ActiveCredentialSet;
use interflow_identity::issuance::IssuerStore;
use interflow_identity::manifest::Manifest;
use interflow_identity::pack::CredentialPack;
use interflow_identity::pack::render::{AgentCredentialPack, HubCredentialPack};
use interflow_mesh::agent::AgentClient;
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

struct Site {
    #[allow(dead_code)]
    dir: tempfile::TempDir,
    agent_pack: std::path::PathBuf,
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

    Site {
        dir,
        agent_pack,
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

    async fn queue(&self, name: &str) {
        interflow_mesh::hub::stream_intents::queue_op(
            &self.endpoint,
            &self.ca,
            &self.cert,
            &self.key,
            "main/lan-a",
            &StreamIntentOp::Pause {
                name: name.to_owned(),
            },
        )
        .await
        .unwrap();
    }
}

/// The full mailbox lifecycle: queue → visible with age + label →
/// capacity drop counted → delivery clears the waiting (the drop history
/// survives).
#[tokio::test]
async fn queued_ops_are_watermarked_drops_counted_and_delivery_clears() {
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
    let site = site("mailbox").await;

    // The leg connects once so its row and intent face exist, then goes
    // dark: ops queued for it sit in the mailbox (the acceptance shape —
    // "给离线腿排的 op 会在邮箱里躺到它回编").
    let pack = CredentialPack::load_runtime(&site.agent_pack).unwrap();
    let active = ActiveCredentialSet::load_or_bootstrap(&pack).unwrap();
    let config = build_agent_config(&pack, &active, &site.agent_pack).unwrap();
    let agent = AgentClient::new(config.clone()).unwrap().start();
    wait_connected(&agent).await;
    // Let the intent watcher report at least once (the face materializes).
    tokio::time::sleep(Duration::from_secs(12)).await;
    let _ = agent.shutdown_graceful().await;
    tokio::time::sleep(Duration::from_secs(1)).await;

    // Queue one op: the enqueue is push-visible and the snapshot carries
    // the waiting watermark within one read.
    let version_before = site.floor_version().await;
    site.queue("svc").await;
    assert!(
        site.floor_version().await > version_before,
        "an op queued is face-visible (the floor version advanced)"
    );
    let doc = eventually_async(
        "the queued op to show on the snapshot",
        Duration::from_secs(15),
        || async {
            let doc = site.snapshot().await;
            let face = doc
                .agents
                .iter()
                .find(|r| r.agent == "main/lan-a")
                .and_then(|r| r.pending_ops.as_ref())
                .ok_or_else(|| "no pending_ops face yet".to_owned())?;
            if face.pending_count == 1 {
                Ok(face.clone())
            } else {
                Err(format!("pending_count = {}", face.pending_count))
            }
        },
    )
    .await;
    assert_eq!(doc.oldest_op.as_deref(), Some("pause svc"));
    let oldest = doc.oldest_queued_unix.expect("one op carries its instant");
    assert!(oldest > 0);

    // Fill past the capacity bound (128): the OLDEST undelivered op (the
    // "svc" pause) drops, the counter records it. The face's oldest op
    // label moves to the second op.
    for i in 0..128 {
        site.queue(&format!("s{i}")).await;
    }
    let face = eventually_async(
        "the capacity drop to land on the face",
        Duration::from_secs(15),
        || async {
            let doc = site.snapshot().await;
            let face = doc
                .agents
                .iter()
                .find(|r| r.agent == "main/lan-a")
                .and_then(|r| r.pending_ops.as_ref())
                .ok_or_else(|| "no pending_ops face".to_owned())?;
            if face.dropped_total == 1 {
                Ok(face.clone())
            } else {
                Err(format!("dropped_total = {}", face.dropped_total))
            }
        },
    )
    .await;
    assert_eq!(face.oldest_op.as_deref(), Some("pause s0"));

    // The leg returns: its intent watcher exchanges, applies, and
    // re-reports; the mailbox empties and the waiting face clears — the
    // drop history survives (re-issue decision material).
    let agent = AgentClient::new(config).unwrap().start();
    wait_connected(&agent).await;
    let face = eventually_async(
        "delivery to clear the waiting face",
        Duration::from_secs(45),
        || async {
            let doc = site.snapshot().await;
            let face = doc
                .agents
                .iter()
                .find(|r| r.agent == "main/lan-a")
                .and_then(|r| r.pending_ops.as_ref());
            match face {
                None => Err("face still absent-or-clean read pending".to_owned()),
                Some(face) if face.pending_count > 0 => {
                    Err(format!("{} op(s) still waiting", face.pending_count))
                }
                Some(face) => Ok(face.clone()),
            }
        },
    )
    .await;
    assert_eq!(face.dropped_total, 1, "dropped is dropped — history stays");

    let _ = agent.shutdown_graceful().await;
    site.hub_shutdown.cancel();
    let _ = site.hub_task.await;
}
