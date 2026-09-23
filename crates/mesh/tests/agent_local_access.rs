#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use interflow_identity::credentials::ActiveCredentialSet;
use interflow_identity::issuance::IssuerStore;
use interflow_identity::manifest::Manifest;
use interflow_identity::pack::CredentialPack;
use interflow_identity::pack::render::{AgentCredentialPack, HubCredentialPack};
use interflow_mesh::agent::AgentClient;
use interflow_mesh::hub::HubServer;
use interflow_mesh::pack::{build_agent_config, build_hub_config};
use std::net::{SocketAddr, TcpStream};
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

/// A real `interflow-mesh agent --pack` subprocess registers to a hub built
/// from the same issuer and serves its local ingress listener through the
/// mandatory inner TLS layer.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn agent_local_tcp_access_uses_inner_tls() {
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
    let hub_port = pick_port();
    let (echo_addr, _echo) = interflow_testkit::echo_server().await;
    let listen_port = pick_port();

    let dir = tempfile::tempdir().unwrap();
    let issuer = IssuerStore::open(dir.path().join("issuer"));
    issuer.ensure_realm().unwrap();
    issuer.ensure_workspace("alpha").unwrap();
    issuer.ensure_policy_key().unwrap();

    let manifest = Manifest::parse(&format!(
        r#"
[realm]
id = "agent-local"
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
name = "local"
listen = "127.0.0.1:{listen_port}"
target_agent = "egress"
remote_addr = "{echo_addr}"
"#
    ))
    .unwrap();

    let hub_dir = dir.path().join("packs/hub-central");
    HubCredentialPack::render(&issuer, &manifest, "central", 1, &hub_dir).unwrap();
    let egress_dir = dir.path().join("packs/agent-egress");
    AgentCredentialPack::render(&issuer, &manifest, "egress", 1, &egress_dir).unwrap();
    let client_dir = dir.path().join("packs/agent-client");
    AgentCredentialPack::render(&issuer, &manifest, "client", 1, &client_dir).unwrap();

    // Hub in-process from its pack (same issuer → the subprocess agent's
    // certificate chains to a trust-table tenant).
    let hub_pack = CredentialPack::load_runtime(&hub_dir).unwrap();
    let hub_active = ActiveCredentialSet::load_or_bootstrap(&hub_pack).unwrap();
    let hub_cfg = build_hub_config(&hub_pack, &hub_active, &hub_dir).unwrap();
    let hub = HubServer::new(hub_cfg).unwrap();
    let (ready_tx, ready_rx) = tokio::sync::oneshot::channel();
    let shutdown = tokio_util::sync::CancellationToken::new();
    let hub_task = tokio::spawn(hub.run_until_signalled(shutdown.clone(), ready_tx));
    ready_rx.await.unwrap();

    // The egress side runs in-process; the client side is the real binary.
    let egress_pack = CredentialPack::load_runtime(&egress_dir).unwrap();
    let egress_active = ActiveCredentialSet::load_or_bootstrap(&egress_pack).unwrap();
    let egress_cfg = build_agent_config(&egress_pack, &egress_active, &egress_dir).unwrap();
    let egress = AgentClient::new(egress_cfg).unwrap().start();
    wait_connected(&egress).await;

    let mut child = std::process::Command::new(env!("CARGO_BIN_EXE_interflow-mesh"))
        .args(["agent", "--pack", client_dir.to_str().unwrap()])
        .spawn()
        .unwrap();

    let listen_addr: SocketAddr = format!("127.0.0.1:{listen_port}").parse().unwrap();
    let deadline = tokio::time::Instant::now() + Duration::from_secs(30);
    loop {
        if TcpStream::connect(listen_addr).is_ok() {
            break;
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "agent local listener ready"
        );
        tokio::time::sleep(Duration::from_millis(50)).await;
    }

    let mut sock = tokio::net::TcpStream::connect(listen_addr).await.unwrap();
    sock.write_all(b"agent-local-payload").await.unwrap();
    let mut got = vec![0u8; b"agent-local-payload".len()];
    tokio::time::timeout(Duration::from_secs(10), sock.read_exact(&mut got))
        .await
        .expect("echo through mandatory inner TLS")
        .expect("read");
    assert_eq!(got, b"agent-local-payload");
    child.kill().unwrap();
    child.wait().unwrap();
    shutdown.cancel();
    let _ = hub_task.await;
}

/// The agent-side readiness signal: `wait_ingress_ready` resolves once the
/// session has bound its configured local ingress listener — the condition
/// `Type=notify` READY=1 gates on (and the one the removed install probes
/// used to fake with synthetic connections).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn ingress_ready_signal_accompanies_listener_bind() {
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
    let hub_port = pick_port();
    let (echo_addr, _echo) = interflow_testkit::echo_server().await;
    let listen_port = pick_port();

    let dir = tempfile::tempdir().unwrap();
    let issuer = IssuerStore::open(dir.path().join("issuer"));
    issuer.ensure_realm().unwrap();
    issuer.ensure_workspace("alpha").unwrap();
    issuer.ensure_policy_key().unwrap();

    let manifest = Manifest::parse(&format!(
        r#"
[realm]
id = "ready-signal"
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
name = "local"
listen = "127.0.0.1:{listen_port}"
target_agent = "egress"
remote_addr = "{echo_addr}"
"#
    ))
    .unwrap();

    let hub_dir = dir.path().join("packs/hub-central");
    HubCredentialPack::render(&issuer, &manifest, "central", 1, &hub_dir).unwrap();
    let client_dir = dir.path().join("packs/agent-client");
    AgentCredentialPack::render(&issuer, &manifest, "client", 1, &client_dir).unwrap();

    let hub_pack = CredentialPack::load_runtime(&hub_dir).unwrap();
    let hub_active = ActiveCredentialSet::load_or_bootstrap(&hub_pack).unwrap();
    let hub_cfg = build_hub_config(&hub_pack, &hub_active, &hub_dir).unwrap();
    let hub = HubServer::new(hub_cfg).unwrap();
    let (ready_tx, ready_rx) = tokio::sync::oneshot::channel();
    let shutdown = tokio_util::sync::CancellationToken::new();
    let hub_task = tokio::spawn(hub.run_until_signalled(shutdown.clone(), ready_tx));
    ready_rx.await.unwrap();

    let client_pack = CredentialPack::load_runtime(&client_dir).unwrap();
    let client_active = ActiveCredentialSet::load_or_bootstrap(&client_pack).unwrap();
    let client_cfg = build_agent_config(&client_pack, &client_active, &client_dir).unwrap();
    let client = AgentClient::new(client_cfg).unwrap().start();

    let ready = tokio::time::timeout(Duration::from_secs(30), client.wait_ingress_ready())
        .await
        .expect("ingress-ready signal within 30s");
    assert!(ready, "readiness must fire, not end, while the agent runs");

    // Honesty check: the listener accepts by signal-time.
    let listen_addr: SocketAddr = format!("127.0.0.1:{listen_port}").parse().unwrap();
    assert!(
        TcpStream::connect(listen_addr).is_ok(),
        "listener bound at ready-time"
    );

    client.shutdown_graceful().await.unwrap();
    shutdown.cancel();
    let _ = hub_task.await;
}
