//! Pack-path QUIC acceptance for the site-to-site face: the manifest's
//! `[mesh.hub] quic_listen` and a mesh agent's `transport = "quic"` must
//! ride the real render → digest-verified load → `build_*_config` chain
//! onto the engine — and the assembled configs must actually carry a live
//! tunnel over the wire.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use interflow_identity::credentials::ActiveCredentialSet;
use interflow_identity::issuance::IssuerStore;
use interflow_identity::manifest::Manifest;
use interflow_identity::pack::CredentialPack;
use interflow_identity::pack::render::{AgentCredentialPack, HubCredentialPack};
use interflow_mesh::agent::AgentClient;
use interflow_mesh::config::TransportKind;
use interflow_mesh::hub::HubServer;
use interflow_mesh::pack::{build_agent_config, build_hub_config};
use std::path::Path;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

fn free_port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

/// The wildcard form both passes validation and really binds: the hub
/// opens the UDP face on every interface while agents dial the loopback
/// endpoint (production documents use the public wildcard the same way).
fn quic_manifest(listen_port: u16, listen_port_a: u16, echo_port: u16) -> Manifest {
    Manifest::parse(&format!(
        r#"
[realm]
id = "test"
[registrar]
endpoint = "https://registrar.example.com"
[mesh.hub.central]
listen = "127.0.0.1:{listen_port}"
quic_listen = "0.0.0.0:{listen_port}"
endpoint = "127.0.0.1:{listen_port}"
[workspace.alpha]
[workspace.beta]
[agent.lan-a]
workspace = "alpha"
transport = "quic"
[[agent.lan-a.mesh_ingress]]
name = "svc"
listen = "127.0.0.1:{listen_port_a}"
target_agent = "lan-b"
remote_addr = "127.0.0.1:{echo_port}"
[agent.lan-b]
workspace = "beta"
[[agent.lan-b.mesh_egress]]
name = "svc"
target_addr = "127.0.0.1:{echo_port}"
"#
    ))
    .unwrap()
}

/// The signed fields survive the whole chain and land on the engine
/// configs: the hub opens its QUIC face at the signed address, and the
/// quic agent carries the UDP dial address derived from the signed hub
/// endpoint (same port number, different stack).
#[test]
fn quic_packs_assemble_the_engine_faces() {
    let hub_port = free_port();
    let listen_port = free_port();
    let echo_port = free_port();
    let dir = tempfile::tempdir().unwrap();
    let issuer = IssuerStore::open(dir.path().join("issuer"));
    issuer.ensure_realm().unwrap();
    issuer.ensure_workspace("alpha").unwrap();
    issuer.ensure_workspace("beta").unwrap();
    issuer.ensure_policy_key().unwrap();

    let manifest = quic_manifest(hub_port, listen_port, echo_port);
    let hub_dir = dir.path().join("packs/hub-central");
    HubCredentialPack::render(&issuer, &manifest, "central", 1, &hub_dir).unwrap();
    let pack_dir_a = dir.path().join("packs/agent-lan-a");
    AgentCredentialPack::render(&issuer, &manifest, "lan-a", 1, &pack_dir_a).unwrap();
    let pack_dir_b = dir.path().join("packs/agent-lan-b");
    AgentCredentialPack::render(&issuer, &manifest, "lan-b", 1, &pack_dir_b).unwrap();

    let hub_pack = CredentialPack::load_runtime(&hub_dir).unwrap();
    let hub_active = ActiveCredentialSet::load_or_bootstrap(&hub_pack).unwrap();
    let hub_config = build_hub_config(&hub_pack, &hub_active, &hub_dir).unwrap();
    assert!(hub_config.transport.quic.enabled);
    assert_eq!(
        hub_config.transport.quic.listen_addr,
        Some(format!("0.0.0.0:{hub_port}").parse().unwrap())
    );

    let pack = CredentialPack::load_runtime(&pack_dir_a).unwrap();
    let active = ActiveCredentialSet::load_or_bootstrap(&pack).unwrap();
    let config = build_agent_config(&pack, &active, &pack_dir_a).unwrap();
    assert_eq!(config.agent.transport, TransportKind::Quic);
    assert_eq!(
        config.agent.hub_quic_addr.as_deref(),
        Some(format!("127.0.0.1:{hub_port}").as_str()),
        "the QUIC dial address derives from the signed hub endpoint"
    );

    // The peer stays h2: opting in is per node, and the hub serves both
    // faces side by side.
    let pack = CredentialPack::load_runtime(&pack_dir_b).unwrap();
    let active = ActiveCredentialSet::load_or_bootstrap(&pack).unwrap();
    let config = build_agent_config(&pack, &active, &pack_dir_b).unwrap();
    assert_eq!(config.agent.transport, TransportKind::H2);
    assert_eq!(config.agent.hub_quic_addr, None);
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

/// The live proof: packs only — hub + a quic agent + an h2 agent
/// in-process, the hub's QUIC listener bound (`HubReady.quic`), and TCP
/// through the tunnel riding the QUIC dial leg end to end.
#[tokio::test]
async fn pack_quic_tunnel_forwards_tcp_over_the_wire() {
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
    let hub_port = free_port();
    let echo_port = free_port();
    let listen_port = free_port();

    // The service behind lan-b: a plain TCP echo server.
    let echo = tokio::net::TcpListener::bind(("127.0.0.1", echo_port))
        .await
        .unwrap();
    tokio::spawn(async move {
        loop {
            let Ok((mut sock, _)) = echo.accept().await else {
                break;
            };
            tokio::spawn(async move {
                let mut buf = [0u8; 1024];
                loop {
                    match sock.read(&mut buf).await {
                        Ok(0) | Err(_) => break,
                        Ok(n) => {
                            if sock.write_all(&buf[..n]).await.is_err() {
                                break;
                            }
                        }
                    }
                }
            });
        }
    });

    let dir = tempfile::tempdir().unwrap();
    let issuer = IssuerStore::open(dir.path().join("issuer"));
    issuer.ensure_realm().unwrap();
    issuer.ensure_workspace("alpha").unwrap();
    issuer.ensure_workspace("beta").unwrap();
    issuer.ensure_policy_key().unwrap();

    let manifest = quic_manifest(hub_port, listen_port, echo_port);
    let hub_dir = dir.path().join("packs/hub-central");
    HubCredentialPack::render(&issuer, &manifest, "central", 1, &hub_dir).unwrap();
    let pack_dir_a = dir.path().join("packs/agent-lan-a");
    AgentCredentialPack::render(&issuer, &manifest, "lan-a", 1, &pack_dir_a).unwrap();
    let pack_dir_b = dir.path().join("packs/agent-lan-b");
    AgentCredentialPack::render(&issuer, &manifest, "lan-b", 1, &pack_dir_b).unwrap();

    let hub_pack = CredentialPack::load_runtime(&hub_dir).unwrap();
    let hub_active = ActiveCredentialSet::load_or_bootstrap(&hub_pack).unwrap();
    let hub_config = build_hub_config(&hub_pack, &hub_active, &hub_dir).unwrap();
    let hub = HubServer::new(hub_config).unwrap();
    let (ready_tx, ready_rx) = tokio::sync::oneshot::channel();
    let shutdown = tokio_util::sync::CancellationToken::new();
    let hub_task = tokio::spawn(hub.run_until_signalled(shutdown.clone(), ready_tx));
    let ready = ready_rx.await.unwrap();
    assert_eq!(
        ready.quic,
        Some(format!("0.0.0.0:{hub_port}").parse().unwrap()),
        "the hub must report the QUIC listener bound"
    );

    let start = |pack_dir: &Path| {
        let pack = CredentialPack::load_runtime(pack_dir).unwrap();
        let active = ActiveCredentialSet::load_or_bootstrap(&pack).unwrap();
        let config = build_agent_config(&pack, &active, pack_dir).unwrap();
        AgentClient::new(config).unwrap().start()
    };
    let agent_b = start(&pack_dir_b);
    wait_connected(&agent_b).await;
    let agent_a = start(&pack_dir_a);
    wait_connected(&agent_a).await;

    // lan-a dials QUIC; the payload must come back through hub + both
    // agents + inner TLS from the beta side's echo server.
    let outcome = tokio::time::timeout(Duration::from_secs(30), async {
        let mut client = tokio::net::TcpStream::connect(("127.0.0.1", listen_port))
            .await
            .unwrap();
        client.write_all(b"ping-through-quic-pack").await.unwrap();
        let mut echoed = vec![0u8; b"ping-through-quic-pack".len()];
        client.read_exact(&mut echoed).await.unwrap();
        echoed
    })
    .await
    .unwrap();
    assert_eq!(outcome, b"ping-through-quic-pack");

    // A second stream keeps the QUIC session's stream multiplexing honest.
    let outcome2 = tokio::time::timeout(Duration::from_secs(30), async {
        let mut client = tokio::net::TcpStream::connect(("127.0.0.1", listen_port))
            .await
            .unwrap();
        client.write_all(b"second-quic-stream").await.unwrap();
        let mut echoed = vec![0u8; b"second-quic-stream".len()];
        client.read_exact(&mut echoed).await.unwrap();
        echoed
    })
    .await
    .unwrap();
    assert_eq!(outcome2, b"second-quic-stream");

    let _ = agent_a.shutdown_graceful().await;
    let _ = agent_b.shutdown_graceful().await;
    shutdown.cancel();
    let _ = hub_task.await;
}
