//! The leg-biography query face, end to end on the pack-driven path
//!
//! Acceptance shapes:
//!
//! 1. **One query, the whole timeline.** The hub's audit ledger already
//!    carries the events (registered with the agent NAME — the additive
//!    field — a pause op queued, a maintenance declaration); the
//!    biography endpoint returns them newest-first with reasons
//!    expanded.
//! 2. **Agent-name attribution.** The fresh `registered` row names the
//!    leg directly (the additive `agent` field), not just the circuit.
//! 3. **Filtering is per-leg.** Another leg's events never leak in.
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
use std::time::Duration;

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
    endpoint: String,
    ca: std::path::PathBuf,
    cert: std::path::PathBuf,
    key: std::path::PathBuf,
    hub_shutdown: tokio_util::sync::CancellationToken,
    hub_task: tokio::task::JoinHandle<Result<(), interflow_core::error::InterflowError>>,
    agents: Vec<interflow_mesh::agent::AgentHandle>,
}

async fn site(tag: &str) -> Site {
    let hub_port = pick_port();
    let remote_port = pick_port();
    let dir = tempfile::tempdir().unwrap();
    let issuer = IssuerStore::open(dir.path().join("issuer"));
    issuer.ensure_realm().unwrap();
    issuer.ensure_workspace("alpha").unwrap();
    issuer.ensure_policy_key().unwrap();

    let manifest = Manifest::parse(&format!(
        r#"
[realm]
id = "bio-{tag}"
[registrar]
endpoint = "https://registrar.example.com"
[mesh.hub.central]
listen = "127.0.0.1:{hub_port}"
endpoint = "127.0.0.1:{hub_port}"
[workspace.alpha]
[agent.lan-a]
workspace = "alpha"
[[agent.lan-a.mesh_egress]]
name = "idle"
target_addr = "127.0.0.1:{remote_port}"
[agent.lan-b]
workspace = "alpha"
[[agent.lan-b.mesh_egress]]
name = "idle"
target_addr = "127.0.0.1:{remote_port}"
"#
    ))
    .unwrap();

    let hub_dir = dir.path().join("packs/hub-central");
    HubCredentialPack::render(&issuer, &manifest, "central", 1, &hub_dir).unwrap();
    for node in ["lan-a", "lan-b"] {
        let pack_dir = dir.path().join(format!("packs/agent-{node}"));
        AgentCredentialPack::render(&issuer, &manifest, node, 1, &pack_dir).unwrap();
    }

    let hub_pack = CredentialPack::load_runtime(&hub_dir).unwrap();
    let hub_active = ActiveCredentialSet::load_or_bootstrap(&hub_pack).unwrap();
    let hub_cfg = build_hub_config(&hub_pack, &hub_active, &hub_dir).unwrap();
    let audit = AuditSink::spawn(&hub_cfg.audit);
    let hub = HubServer::new(hub_cfg, audit).unwrap();
    let (ready_tx, ready_rx) = tokio::sync::oneshot::channel();
    let shutdown = tokio_util::sync::CancellationToken::new();
    let hub_task = tokio::spawn(hub.run_until_signalled(shutdown.clone(), ready_tx));
    ready_rx.await.unwrap();

    let creds_dir = dir.path().join("control-creds");
    std::fs::create_dir_all(&creds_dir).unwrap();
    let ttl = interflow_identity::issuance::LeafTtl::new(time::Duration::hours(1));
    let material = issuer
        .issue_hub_member_with_ttl(&format!("bio-{tag}"), "doctor-hub", ttl)
        .unwrap();
    let (ca, cert, key) = (
        creds_dir.join("ca.crt"),
        creds_dir.join("client.crt"),
        creds_dir.join("client.key"),
    );
    std::fs::write(&ca, issuer.realm_issuer().unwrap().cert_pem()).unwrap();
    std::fs::write(&cert, &material.chain_pem).unwrap();
    std::fs::write(&key, &material.key_pem).unwrap();

    let mut agents = Vec::new();
    for node in ["lan-a", "lan-b"] {
        let pack_dir = dir.path().join(format!("packs/agent-{node}"));
        let pack = CredentialPack::load_runtime(&pack_dir).unwrap();
        let active = ActiveCredentialSet::load_or_bootstrap(&pack).unwrap();
        let config = build_agent_config(&pack, &active, &pack_dir).unwrap();
        let agent = AgentClient::new(config).unwrap().start();
        wait_connected(&agent).await;
        agents.push(agent);
    }

    Site {
        dir,
        endpoint: format!("127.0.0.1:{hub_port}"),
        ca,
        cert,
        key,
        hub_shutdown: shutdown,
        hub_task,
        agents,
    }
}

/// The biography timeline as one query: registered (named), pause
/// queued, maintenance declared — newest first, per-leg filtered.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn one_query_renders_the_legs_timeline() {
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
    let site = site("timeline").await;

    // Two operator verbs on lan-a: a queued pause and a maintenance
    // declaration (both land in the audit ledger through the control
    // plane).
    interflow_mesh::hub::stream_intents::queue_op(
        &site.endpoint,
        &site.ca,
        &site.cert,
        &site.key,
        "alpha/lan-a",
        &StreamIntentOp::Pause {
            name: "idle".to_owned(),
        },
    )
    .await
    .unwrap();
    interflow_mesh::hub::maintenance::set_maintenance(
        &site.endpoint,
        &site.ca,
        &site.cert,
        &site.key,
        "alpha/lan-a",
        true,
    )
    .await
    .unwrap();

    // The biography: newest first, the three story rows present, the
    // registered row carrying the agent NAME (the additive field).
    let doc = eventually_async(
        "the biography to carry the full timeline",
        Duration::from_secs(15),
        || async {
            let doc = interflow_mesh::hub::biography::query_biography(
                &site.endpoint,
                &site.ca,
                &site.cert,
                &site.key,
                "alpha/lan-a",
                3600,
            )
            .await
            .map_err(|e| e.to_string())?;
            let kinds: Vec<&str> = doc.rows.iter().map(|r| r.kind.as_str()).collect();
            for expected in [
                "maintenance_declared",
                "stream_pause_queued",
                "agent_registered",
            ] {
                if !kinds.contains(&expected) {
                    return Err(format!("{expected} missing from {kinds:?}"));
                }
            }
            Ok(doc)
        },
    )
    .await;

    // Newest first: the operator verbs (both written after the
    // registration) lead — same-second writes tie in stable order, so
    // the assertion is on the registered row NOT leading.
    assert_ne!(
        doc.rows[0].kind,
        "agent_registered",
        "the timeline is newest-first: {:?}",
        doc.rows.iter().map(|r| r.kind.as_str()).collect::<Vec<_>>()
    );
    assert!(doc.rows[0].ts >= doc.rows[doc.rows.len() - 1].ts);
    // The registered row names the leg (the additive agent field) and
    // the circuit prefix (the correlation key both machines share).
    let registered = doc
        .rows
        .iter()
        .find(|r| r.kind == "agent_registered")
        .expect("registered row");
    assert!(
        registered.detail.contains("agent alpha/lan-a"),
        "the additive field attributes by name: {}",
        registered.detail
    );
    assert!(registered.detail.contains("circuit "));
    // Reason expansion: the pause row names the stream.
    let pause = doc
        .rows
        .iter()
        .find(|r| r.kind == "stream_pause_queued")
        .expect("pause row");
    assert!(pause.detail.contains("stream idle"), "{}", pause.detail);

    // Per-leg filtering: lan-b's biography has its own registered row
    // and none of lan-a's operator verbs.
    let other = interflow_mesh::hub::biography::query_biography(
        &site.endpoint,
        &site.ca,
        &site.cert,
        &site.key,
        "alpha/lan-b",
        3600,
    )
    .await
    .unwrap();
    assert!(
        other
            .rows
            .iter()
            .any(|r| r.kind == "agent_registered" && r.detail.contains("agent alpha/lan-b"))
    );
    assert!(
        !other.rows.iter().any(|r| r.kind == "maintenance_declared"),
        "another leg's verbs never leak in: {:?}",
        other
            .rows
            .iter()
            .map(|r| r.kind.as_str())
            .collect::<Vec<_>>()
    );

    for agent in site.agents {
        let _ = agent.shutdown_graceful().await;
    }
    site.hub_shutdown.cancel();
    let _ = site.hub_task.await;
}
