//! Ingress-side half-close regression pin, both hub transports.
//!
//! The 2026-10-17 proposal-approval Linux backlog narrowed to this shape:
//! the failing e2e was the only place where the probe half-closes its TCP
//! write side before reading the echo (`shutdown()` + `read_to_end`), and
//! the ingress pump's zero local-EOF drain window turned that FIN into a
//! bare stream Close racing the response through the hub. The fix landed in
//! the shared pump, but each transport serializes stream Close itself
//! beneath it — h2 body-frame paths vs QUIC close-frame paths, zero shared
//! code — so the pin runs twice: ingress-side QUIC and ingress-side h2,
//! each with a no-half-close control probe that must pass either way. (A
//! quadrant with no independent implementation code beneath the pump would
//! owe no pin of its own; both transports here do.)

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use interflow_core::security::AuditSink;
use interflow_identity::credentials::ActiveCredentialSet;
use interflow_identity::issuance::IssuerStore;
use interflow_identity::manifest::Manifest;
use interflow_identity::pack::CredentialPack;
use interflow_identity::pack::render::AgentCredentialPack;
use interflow_identity::pack::render::HubCredentialPack;
use interflow_mesh::agent::AgentClient;
use interflow_mesh::config::TransportKind;
use interflow_mesh::hub::HubServer;
use interflow_mesh::pack::{build_agent_config, build_hub_config};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

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
        if matches!(
            &*state.borrow(),
            interflow_mesh::agent::AgentState::Connected { .. }
        ) {
            return;
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "agent never connected (last {:?})",
            state.borrow()
        );
        tokio::time::sleep(Duration::from_millis(100)).await;
        let _ = state.changed().await;
    }
}

/// The proposal-approval probe shape: write, half-close, read the echo to
/// EOF. The half-close is the discriminator under test.
async fn half_close_roundtrip(addr: &str, payload: &[u8]) -> std::io::Result<Vec<u8>> {
    let mut sock = tokio::net::TcpStream::connect(addr).await?;
    sock.write_all(payload).await?;
    sock.shutdown().await?;
    let mut buf = Vec::new();
    sock.read_to_end(&mut buf).await?;
    Ok(buf)
}

/// The shape every green test uses: write, read exactly the echo back.
async fn plain_roundtrip(addr: &str, payload: &[u8]) -> std::io::Result<Vec<u8>> {
    let mut sock = tokio::net::TcpStream::connect(addr).await?;
    sock.write_all(payload).await?;
    let mut echoed = vec![0u8; payload.len()];
    sock.read_exact(&mut echoed).await?;
    Ok(echoed)
}

async fn ingress_half_close_scenario(transport: TransportKind) {
    interflow_testkit::logging::init_test_logging();
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
    let hub_port = free_port();
    let listen_port = free_port();
    let remote_port = free_port();

    let echo = tokio::net::TcpListener::bind(("127.0.0.1", remote_port))
        .await
        .unwrap();
    let echo_task = tokio::spawn(async move {
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
    issuer.ensure_workspace("main").unwrap();
    issuer.ensure_policy_key().unwrap();
    let manifest = Manifest::parse(&format!(
        r#"
[realm]
id = "test"
[registrar]
endpoint = "https://registrar.example.com"
[mesh.hub.central]
listen = "127.0.0.1:{hub_port}"
endpoint = "127.0.0.1:{hub_port}"
quic_listen = "0.0.0.0:{hub_port}"
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
    let pack_dir_a = dir.path().join("packs/agent-lan-a");
    AgentCredentialPack::render(&issuer, &manifest, "lan-a", 1, &pack_dir_a).unwrap();
    let pack_dir_b = dir.path().join("packs/agent-lan-b");
    AgentCredentialPack::render(&issuer, &manifest, "lan-b", 1, &pack_dir_b).unwrap();

    let hub_pack = CredentialPack::load_runtime(&hub_dir).unwrap();
    let hub_active = ActiveCredentialSet::load_or_bootstrap(&hub_pack).unwrap();
    let hub_config = build_hub_config(&hub_pack, &hub_active, &hub_dir).unwrap();
    let audit = AuditSink::spawn(&hub_config.audit);
    let hub = HubServer::new(hub_config, audit).unwrap();
    let (ready_tx, ready_rx) = tokio::sync::oneshot::channel();
    let shutdown = tokio_util::sync::CancellationToken::new();
    let hub_task = tokio::spawn(hub.run_until_signalled(shutdown.clone(), ready_tx));
    ready_rx.await.unwrap();

    // lan-a — the stream-OPENING agent — is the transport under test;
    // lan-b stays on h2 in both states.
    let agent_a = {
        let pack = CredentialPack::load_runtime(&pack_dir_a).unwrap();
        let active = ActiveCredentialSet::load_or_bootstrap(&pack).unwrap();
        let mut config = build_agent_config(&pack, &active, &pack_dir_a).unwrap();
        config.agent.transport = transport;
        if matches!(transport, TransportKind::Quic) {
            config.agent.hub_quic_addr = Some(format!("127.0.0.1:{hub_port}"));
        }
        AgentClient::new(config).unwrap().start()
    };
    wait_connected(&agent_a).await;
    let agent_b = {
        let pack = CredentialPack::load_runtime(&pack_dir_b).unwrap();
        let active = ActiveCredentialSet::load_or_bootstrap(&pack).unwrap();
        let config = build_agent_config(&pack, &active, &pack_dir_b).unwrap();
        AgentClient::new(config).unwrap().start()
    };
    wait_connected(&agent_b).await;

    let listen = format!("127.0.0.1:{listen_port}");
    let plane = match transport {
        TransportKind::Quic => "QUIC",
        TransportKind::H2 => "h2",
    };

    // Control: the plain (no half-close) probe must pass — it isolates the
    // discriminator below to the half-close itself.
    let deadline = tokio::time::Instant::now() + Duration::from_secs(30);
    loop {
        if let Ok(Ok(got)) =
            tokio::time::timeout(Duration::from_secs(5), plain_roundtrip(&listen, b"plain")).await
            && got == b"plain"
        {
            break;
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "plain (no half-close) probe never passed — the {plane} ingress plane is broken \
             beyond the half-close path"
        );
        tokio::time::sleep(Duration::from_millis(300)).await;
    }

    // The shape under test: half-close then read to EOF.
    let deadline = tokio::time::Instant::now() + Duration::from_secs(30);
    loop {
        let attempt = tokio::time::timeout(
            Duration::from_secs(5),
            half_close_roundtrip(&listen, b"proposal-e2e"),
        )
        .await
        .ok()
        .and_then(std::result::Result::ok)
        .unwrap_or_default();
        if attempt == b"proposal-e2e" {
            break;
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "half-close probe never echoed on the ingress-side {plane} leg"
        );
        tokio::time::sleep(Duration::from_millis(300)).await;
    }

    let _ = agent_a.shutdown_graceful().await;
    let _ = agent_b.shutdown_graceful().await;
    shutdown.cancel();
    let _ = hub_task.await;
    echo_task.abort();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn ingress_side_quic_survives_half_close_probe() {
    ingress_half_close_scenario(TransportKind::Quic).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn ingress_side_h2_survives_half_close_probe() {
    ingress_half_close_scenario(TransportKind::H2).await;
}
