//! The fossil-stream and session-headroom faces, end to end on the
//! pack-driven path
//!
//! Three acceptance shapes:
//!
//! 1. **The activity level reaches the face.** An armed ingress rule
//!    (listener bound, zero bytes so far) ships its baseline record —
//!    name, last-byte instant, the rule's own idle budget — through the
//!    node-status channel onto the fleet snapshot within a report
//!    interval: "mounted, listening" is now a queryable level.
//! 2. **Bytes through the pump advance it.** A real connection through
//!    the ingress listener (mandatory inner TLS, echo backend) touches
//!    the rule's activity cell at the pump's idle-deadline reset points
//!    — the level moves, and the hub's admission table shows the live
//!    stream in flight (per-leg and global).
//! 3. **Fresh reads fresh.** The just-touched level judges NOT fossil
//!    against the reader's capture anchor (the day-scale boundary math
//!    lives in the unit-locked pure functions on both engines).
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
use interflow_testkit::wait::eventually_async;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

fn pick_port() -> u16 {
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
        if matches!(
            *state.borrow(),
            interflow_mesh::agent::AgentState::Connected { .. }
        ) {
            return;
        }
        if matches!(
            *state.borrow(),
            interflow_mesh::agent::AgentState::Failed { .. }
        ) {
            panic!("agent failed: {:?}", state.borrow());
        }
        let changed = tokio::time::timeout_at(deadline, state.changed());
        match changed.await {
            Ok(Ok(())) => {}
            _ => panic!("agent never connected (last state {:?})", state.borrow()),
        }
    }
}

struct Site {
    #[allow(dead_code)]
    dir: tempfile::TempDir,
    listen_addr: std::net::SocketAddr,
    endpoint: String,
    ca: std::path::PathBuf,
    cert: std::path::PathBuf,
    key: std::path::PathBuf,
    client: interflow_mesh::agent::AgentHandle,
    egress: interflow_mesh::agent::AgentHandle,
    hub_shutdown: tokio_util::sync::CancellationToken,
    hub_task: tokio::task::JoinHandle<Result<(), interflow_core::error::InterflowError>>,
}

async fn site(tag: &str, echo_addr: std::net::SocketAddr, listen_port: u16) -> Site {
    let hub_port = pick_port();
    let dir = tempfile::tempdir().unwrap();
    let issuer = IssuerStore::open(dir.path().join("issuer"));
    issuer.ensure_realm().unwrap();
    issuer.ensure_workspace("alpha").unwrap();
    issuer.ensure_policy_key().unwrap();

    let manifest = Manifest::parse(&format!(
        r#"
[realm]
id = "fossil-{tag}"
[registrar]
endpoint = "https://registrar.example.com"
[mesh.hub.central]
listen = "127.0.0.1:{hub_port}"
endpoint = "127.0.0.1:{hub_port}"
[workspace.alpha]
[agent.egress]
workspace = "alpha"
[[agent.egress.mesh_egress]]
name = "api"
target_addr = "{echo_addr}"
[agent.client]
workspace = "alpha"
[[agent.client.mesh_ingress]]
name = "svc"
listen = "127.0.0.1:{listen_port}"
target_agent = "egress"
remote_addr = "{echo_addr}"
idle_timeout_secs = 300
"#
    ))
    .unwrap();

    let hub_dir = dir.path().join("packs/hub-central");
    HubCredentialPack::render(&issuer, &manifest, "central", 1, &hub_dir).unwrap();
    let egress_dir = dir.path().join("packs/agent-egress");
    AgentCredentialPack::render(&issuer, &manifest, "egress", 1, &egress_dir).unwrap();
    let client_dir = dir.path().join("packs/agent-client");
    AgentCredentialPack::render(&issuer, &manifest, "client", 1, &client_dir).unwrap();

    let hub_pack = CredentialPack::load_runtime(&hub_dir).unwrap();
    let hub_active = ActiveCredentialSet::load_or_bootstrap(&hub_pack).unwrap();
    let hub_cfg = build_hub_config(&hub_pack, &hub_active, &hub_dir).unwrap();
    let audit = AuditSink::spawn(&hub_cfg.audit);
    let hub = HubServer::new(hub_cfg, audit).unwrap();
    let (ready_tx, ready_rx) = tokio::sync::oneshot::channel();
    let shutdown = tokio_util::sync::CancellationToken::new();
    let hub_task = tokio::spawn(hub.run_until_signalled(shutdown.clone(), ready_tx));
    ready_rx.await.unwrap();

    // Control-plane credentials (the snapshot face's reader class).
    let creds_dir = dir.path().join("control-creds");
    std::fs::create_dir_all(&creds_dir).unwrap();
    let ttl = interflow_identity::issuance::LeafTtl::new(time::Duration::hours(1));
    let material = issuer
        .issue_hub_member_with_ttl(&format!("fossil-{tag}"), "doctor-hub", ttl)
        .unwrap();
    let (ca, cert, key) = (
        creds_dir.join("ca.crt"),
        creds_dir.join("client.crt"),
        creds_dir.join("client.key"),
    );
    std::fs::write(&ca, issuer.realm_issuer().unwrap().cert_pem()).unwrap();
    std::fs::write(&cert, &material.chain_pem).unwrap();
    std::fs::write(&key, &material.key_pem).unwrap();

    let egress_pack = CredentialPack::load_runtime(&egress_dir).unwrap();
    let egress_active = ActiveCredentialSet::load_or_bootstrap(&egress_pack).unwrap();
    let egress_cfg = build_agent_config(&egress_pack, &egress_active, &egress_dir).unwrap();
    let egress = AgentClient::new(egress_cfg).unwrap().start();
    wait_connected(&egress).await;

    let client_pack = CredentialPack::load_runtime(&client_dir).unwrap();
    let client_active = ActiveCredentialSet::load_or_bootstrap(&client_pack).unwrap();
    let client_cfg = build_agent_config(&client_pack, &client_active, &client_dir).unwrap();
    let client = AgentClient::new(client_cfg).unwrap().start();
    wait_connected(&client).await;
    assert!(
        tokio::time::timeout(Duration::from_secs(30), client.wait_ingress_ready())
            .await
            .expect("ingress-ready within 30s"),
        "the svc listener armed"
    );

    Site {
        dir,
        listen_addr: format!("127.0.0.1:{listen_port}").parse().unwrap(),
        endpoint: format!("127.0.0.1:{hub_port}"),
        ca,
        cert,
        key,
        client,
        egress,
        hub_shutdown: shutdown,
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
}

/// The full lifecycle: baseline on the face → bytes move the level and
/// the admission table counts the live stream → fresh judges fresh.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn activity_levels_and_session_headroom_reach_the_face() {
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
    let (echo_addr, _echo) = interflow_testkit::echo_server().await;
    let listen_port = pick_port();
    let site = site("face", echo_addr, listen_port).await;

    // 1. The armed rule's baseline record ships (within one report
    //    interval): the rule's OWN budget rides as the judgment anchor.
    let baseline = eventually_async(
        "the armed rule's baseline to reach the face",
        Duration::from_secs(20),
        || async {
            let doc = site.snapshot().await;
            let stream = doc
                .agents
                .iter()
                .find(|r| r.agent == "alpha/client")
                .and_then(|r| r.streams.iter().find(|s| s.name == "svc"))
                .ok_or_else(|| "no svc activity level yet".to_owned())?;
            Ok::<_, String>((stream.last_byte_unix, stream.idle_budget_secs))
        },
    )
    .await;
    assert_eq!(
        baseline.1,
        Some(300),
        "the rule's own idle budget anchors the judgment"
    );

    // 2. A real connection through the pump: the echo round trip proves
    //    bytes crossed, which touches the activity cell at the pump's
    //    idle-deadline reset points.
    let mut sock = tokio::net::TcpStream::connect(site.listen_addr)
        .await
        .unwrap();
    sock.write_all(b"fossil-face-payload").await.unwrap();
    let mut got = vec![0u8; b"fossil-face-payload".len()];
    tokio::time::timeout(Duration::from_secs(10), sock.read_exact(&mut got))
        .await
        .expect("echo through mandatory inner TLS")
        .expect("read");
    assert_eq!(got, b"fossil-face-payload");

    // While the connection is open, the admission table counts it (per
    // leg and globally) and the face carries the counts.
    let doc = eventually_async(
        "the live stream to count on the admission face",
        Duration::from_secs(15),
        || async {
            let doc = site.snapshot().await;
            let leg = doc
                .agents
                .iter()
                .find(|r| r.agent == "alpha/client")
                .ok_or_else(|| "no client row".to_owned())?;
            match leg.streams_in_flight {
                Some(n) if n >= 1 => Ok((doc, n)),
                other => Err(format!("streams_in_flight = {other:?}")),
            }
        },
    )
    .await;
    let (doc, _in_flight) = doc;
    assert!(
        doc.hub.streams_in_flight_total.unwrap_or(0) >= 1,
        "the global half carries the count too"
    );
    assert!(
        doc.hub.stream_limits.is_some(),
        "the headroom denominators ride the hub row"
    );

    // 3. The touched level judges NOT fossil at the reader's anchor (a
    //    300s budget reads fossil only past 10×300s of total silence).
    let now = u64::try_from(doc.hub.captured_at_unix).unwrap_or(0);
    let stream = doc
        .agents
        .iter()
        .find(|r| r.agent == "alpha/client")
        .and_then(|r| r.streams.iter().find(|s| s.name == "svc"))
        .expect("the level stays on the face");
    assert!(
        !interflow_mesh::hub::node_status::stream_is_fossil(
            stream.last_byte_unix,
            stream.idle_budget_secs,
            now
        ),
        "a just-touched stream reads fresh: {stream:?}"
    );
    assert!(
        stream.last_byte_unix >= baseline.0,
        "the pump touch advanced the level past the arm-time baseline"
    );

    drop(sock);
    let _ = site.client.shutdown_graceful().await;
    let _ = site.egress.shutdown_graceful().await;
    site.hub_shutdown.cancel();
    let _ = site.hub_task.await;
}
