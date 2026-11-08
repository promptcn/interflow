//! The `GET /agents` client (`query_agents`), end to end on the
//! pack-driven path
//!
//! The doctor's agent-offline axis rides this face: a registered agent is
//! listed as online, a never-registered qualified id is ABSENT (the
//! authoritative "leg gone" reading the third-cause verdict asserts on),
//! and a wrong pinned fingerprint fails the dial closed — the pin is the
//! trust decision, not a hint.
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
use interflow_mesh::hub::http::query_agents;
use interflow_mesh::hub::policy::ServerTrust;
use interflow_mesh::pack::{build_agent_config, build_hub_config};
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

/// The roster the doctor reads: one live leg is listed online, an absent
/// leg is ABSENT (never inferred from silence), and the pinned dial fails
/// closed on a wrong fingerprint.
#[tokio::test]
async fn query_agents_lists_the_roster_and_fails_closed_on_a_wrong_pin() {
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
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
id = "agents-face-query"
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

    let hub_pack = CredentialPack::load_runtime(&hub_dir).unwrap();
    let hub_active = ActiveCredentialSet::load_or_bootstrap(&hub_pack).unwrap();
    let hub_config = build_hub_config(&hub_pack, &hub_active, &hub_dir).unwrap();
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
    tokio::time::timeout(Duration::from_secs(2), ready_rx)
        .await
        .expect("hub ready within 2s")
        .expect("hub task alive");

    let pack = CredentialPack::load_runtime(&agent_pack).unwrap();
    let active = ActiveCredentialSet::load_or_bootstrap(&pack).unwrap();
    let config = build_agent_config(&pack, &active, &agent_pack).unwrap();
    let agent = AgentClient::new(config).unwrap().start();
    wait_connected(&agent).await;

    // The query rides exactly the two credential classes the doctor uses:
    // the agent's own workspace-tenant material (the class `GET /agents`
    // is scoped to) and the hub's control-endpoint cert as the pin source
    // (the edge self-dial trust model).
    let (cert, key) = active.material_paths("agent-main").unwrap();
    let (control_cert, _) = hub_active.material_paths("control-endpoint").unwrap();
    let fingerprint =
        interflow_core::tls::sha256_of_pem_cert(&control_cert, "control endpoint").unwrap();

    let endpoint = format!("127.0.0.1:{hub_port}");
    let roster = query_agents(&endpoint, ServerTrust::Pinned(&fingerprint), &cert, &key)
        .await
        .unwrap();
    let row = roster
        .iter()
        .find(|e| e.agent == "main/lan-a")
        .expect("the registered leg is listed");
    assert!(row.online, "a connected agent reads online: {row:?}");
    assert!(
        roster.iter().all(|e| e.agent != "main/never-registered"),
        "an agent that never registered is ABSENT — the authoritative leg-gone reading, \
         never inferred from silence: {roster:?}"
    );

    // A wrong pin fails the dial closed — the fingerprint is the trust
    // decision, not a hint.
    let wrong_pin = "0".repeat(64);
    let rejected = query_agents(&endpoint, ServerTrust::Pinned(&wrong_pin), &cert, &key).await;
    assert!(
        rejected.is_err(),
        "a wrong pinned fingerprint must not connect"
    );

    let _ = agent.shutdown_graceful().await;
    shutdown.cancel();
    let _ = task.await;
}
