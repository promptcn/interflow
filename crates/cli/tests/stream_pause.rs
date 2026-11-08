//! The operator verbs' end-to-end acceptance: the REAL CLI binary against
//! a REAL hub + agent (pack-driven), driving `stream pause|resume` and
//! `maintenance on|off` through the hub's control plane and asserting the
//! product-level outcomes — the port releases, the face converges, the
//! verbs are idempotent, and the maintenance declaration answers.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod common;
use common::run;

use std::path::{Path, PathBuf};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use interflow_core::security::AuditSink;
use interflow_identity::credentials::ActiveCredentialSet;
use interflow_identity::issuance::IssuerStore;
use interflow_identity::pack::CredentialPack;
use interflow_mesh::agent::{AgentClient, AgentHandle, AgentState};
use interflow_mesh::hub::HubServer;
use interflow_mesh::pack::{build_agent_config, build_hub_config};

fn free_port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

fn manifest_text(hub_port: u16, echo_port: u16, listen_port: u16) -> String {
    format!(
        r#"
[realm]
id = "pause-e2e"
[identity]
mode = "offline"
leaf_ttl = "7d"
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
remote_addr = "127.0.0.1:{echo_port}"
[agent.lan-b]
workspace = "main"
[[agent.lan-b.mesh_egress]]
name = "loopback"
target_cidr = "127.0.0.0/8"
"#
    )
}

async fn wait_connected(agent: &AgentHandle) {
    let mut state = agent.subscribe_state();
    let deadline = tokio::time::Instant::now() + Duration::from_secs(30);
    loop {
        let now = state.borrow().clone();
        if matches!(now, AgentState::Connected { .. }) {
            return;
        }
        if matches!(now, AgentState::Failed { .. }) {
            panic!("agent failed: {now:?}");
        }
        assert!(
            tokio::time::Instant::now() <= deadline,
            "agent never connected (last {now:?})"
        );
        tokio::time::sleep(Duration::from_millis(100)).await;
        let _ = state.changed().await;
    }
}

async fn tcp_roundtrip(addr: &std::net::SocketAddr, payload: &[u8]) -> std::io::Result<Vec<u8>> {
    let mut sock = tokio::net::TcpStream::connect(addr).await?;
    sock.write_all(payload).await?;
    sock.shutdown().await?;
    let mut buf = Vec::new();
    sock.read_to_end(&mut buf).await?;
    Ok(buf)
}

/// The control credential (the same plan-apply principal the CLI itself
/// mints — here materialized once for the test's own face reads).
fn materialize_creds(dir: &Path, issuer: &IssuerStore) -> (PathBuf, PathBuf, PathBuf) {
    use interflow_identity::issuance::LeafTtl;
    std::fs::create_dir_all(dir).unwrap();
    let ttl = LeafTtl::new(time::Duration::hours(1));
    let material = issuer
        .issue_hub_member_with_ttl("pause-e2e", "plan-apply", ttl)
        .unwrap();
    let ca = dir.join("ca.crt");
    let cert = dir.join("client.crt");
    let key = dir.join("client.key");
    std::fs::write(&ca, issuer.realm_issuer().unwrap().cert_pem()).unwrap();
    std::fs::write(&cert, &material.chain_pem).unwrap();
    std::fs::write(&key, &material.key_pem).unwrap();
    (ca, cert, key)
}

/// The full operator cycle: pause (port really frees) → double pause
/// (idempotent) → resume (serving again) → maintenance on/off (the
/// declaration answers and clears).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn stream_pause_resume_and_maintenance_verbs_end_to_end() {
    interflow_testkit::logging::init_test_logging();
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
    let hub_port = free_port();
    let echo_port = free_port();
    let listen_port = free_port();

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
    let manifest_path = dir.path().join("interflow.toml");
    let issuer_dir = dir.path().join("issuer");
    let out = dir.path().join("dist");
    std::fs::write(
        &manifest_path,
        manifest_text(hub_port, echo_port, listen_port),
    )
    .unwrap();

    let applied = run(&[
        "plan",
        "apply",
        "--manifest",
        manifest_path.to_str().unwrap(),
        "--issuer",
        issuer_dir.to_str().unwrap(),
        "--out",
        out.to_str().unwrap(),
    ]);
    assert!(
        applied.success,
        "{}\n--- stderr ---\n{}",
        applied.stdout, applied.stderr
    );

    // The hub and the source agent from the rendered packs.
    let hub_pack_dir = out.join("packs/hub-central");
    let hub_pack = CredentialPack::load_runtime(&hub_pack_dir).unwrap();
    let hub_active = ActiveCredentialSet::load_or_bootstrap(&hub_pack).unwrap();
    let hub_config = build_hub_config(&hub_pack, &hub_active, &hub_pack_dir).unwrap();
    let audit = AuditSink::spawn(&hub_config.audit);
    let hub = HubServer::new(hub_config, audit).unwrap();
    let (ready_tx, ready_rx) = tokio::sync::oneshot::channel();
    let shutdown = tokio_util::sync::CancellationToken::new();
    let hub_token = shutdown.clone();
    let hub_task = tokio::spawn(hub.run_until_signalled(hub_token, ready_tx));
    ready_rx.await.unwrap();

    let start_agent = |node: &str| {
        let pack_dir = out.join(format!("packs/agent-{node}"));
        let pack = CredentialPack::load_runtime(&pack_dir).unwrap();
        let active = ActiveCredentialSet::load_or_bootstrap(&pack).unwrap();
        let config = build_agent_config(&pack, &active, &pack_dir).unwrap();
        AgentClient::new(config).unwrap().start()
    };
    let agent_a = start_agent("lan-a");
    let agent_b = start_agent("lan-b");
    wait_connected(&agent_a).await;
    wait_connected(&agent_b).await;

    // The test's own control credential for face reads.
    let issuer = IssuerStore::open(&issuer_dir);
    let (op_ca, op_cert, op_key) = materialize_creds(&dir.path().join("op-creds"), &issuer);

    let listen_addr: std::net::SocketAddr = format!("127.0.0.1:{listen_port}").parse().unwrap();
    let payload = b"cli-verb-e2e";
    // Baseline round trip (retries absorb the watch/pull/apply latency).
    let deadline = tokio::time::Instant::now() + Duration::from_secs(45);
    loop {
        if let Ok(echoed) = tcp_roundtrip(&listen_addr, payload).await
            && echoed == payload
        {
            break;
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "baseline round trip never recovered"
        );
        tokio::time::sleep(Duration::from_millis(300)).await;
    }

    // ---- `stream pause` (the real binary) ----
    let paused = run(&[
        "stream",
        "pause",
        "--agent",
        "lan-a",
        "--name",
        "svc",
        "--manifest",
        manifest_path.to_str().unwrap(),
        "--issuer",
        issuer_dir.to_str().unwrap(),
    ]);
    assert!(
        paused.success,
        "stream pause failed:\n{}\n--- stderr ---\n{}",
        paused.stdout, paused.stderr
    );
    // The product outcome (whatever the verb's bounded wait observed):
    // the port frees and the face converges.
    let deadline = tokio::time::Instant::now() + Duration::from_secs(25);
    loop {
        let face = interflow_mesh::hub::snapshot::query_fleet_snapshot(
            &format!("127.0.0.1:{hub_port}"),
            &op_ca,
            &op_cert,
            &op_key,
        )
        .await
        .ok()
        .and_then(|doc| {
            doc.agents
                .into_iter()
                .find(|row| row.agent == "main/lan-a")
                .and_then(|row| row.paused_streams)
        })
        .is_some_and(|names| names.iter().any(|n| n == "svc"));
        if face {
            break;
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "the hub face never showed svc paused"
        );
        tokio::time::sleep(Duration::from_millis(300)).await;
    }
    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    loop {
        if std::net::TcpListener::bind(("127.0.0.1", listen_port)).is_ok() {
            break;
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "the port never freed after the pause"
        );
        tokio::time::sleep(Duration::from_millis(100)).await;
    }

    // Idempotent: a second pause succeeds quietly.
    let again = run(&[
        "stream",
        "pause",
        "--agent",
        "lan-a",
        "--name",
        "svc",
        "--manifest",
        manifest_path.to_str().unwrap(),
        "--issuer",
        issuer_dir.to_str().unwrap(),
    ]);
    assert!(
        again.success,
        "double pause must not error: {}",
        again.stderr
    );

    // ---- `stream resume` ----
    let resumed = run(&[
        "stream",
        "resume",
        "--agent",
        "lan-a",
        "--name",
        "svc",
        "--manifest",
        manifest_path.to_str().unwrap(),
        "--issuer",
        issuer_dir.to_str().unwrap(),
    ]);
    assert!(
        resumed.success,
        "stream resume failed:\n{}\n--- stderr ---\n{}",
        resumed.stdout, resumed.stderr
    );
    let deadline = tokio::time::Instant::now() + Duration::from_secs(45);
    loop {
        if let Ok(echoed) = tcp_roundtrip(&listen_addr, payload).await
            && echoed == payload
        {
            break;
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "round trip never recovered after resume"
        );
        tokio::time::sleep(Duration::from_millis(300)).await;
    }

    // ---- `maintenance on` / `off` ----
    let on = run(&[
        "maintenance",
        "on",
        "--agent",
        "lan-a",
        "--manifest",
        manifest_path.to_str().unwrap(),
        "--issuer",
        issuer_dir.to_str().unwrap(),
    ]);
    assert!(
        on.success,
        "maintenance on failed:\n{}\n--- stderr ---\n{}",
        on.stdout, on.stderr
    );
    let deadline = tokio::time::Instant::now() + Duration::from_secs(15);
    loop {
        let declared = interflow_mesh::hub::snapshot::query_fleet_snapshot(
            &format!("127.0.0.1:{hub_port}"),
            &op_ca,
            &op_cert,
            &op_key,
        )
        .await
        .ok()
        .and_then(|doc| {
            doc.agents
                .into_iter()
                .find(|row| row.agent == "main/lan-a")
                .and_then(|row| row.maintenance)
        })
        .unwrap_or(false);
        if declared {
            break;
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "the hub face never showed the maintenance declaration"
        );
        tokio::time::sleep(Duration::from_millis(300)).await;
    }
    let off = run(&[
        "maintenance",
        "off",
        "--agent",
        "lan-a",
        "--manifest",
        manifest_path.to_str().unwrap(),
        "--issuer",
        issuer_dir.to_str().unwrap(),
    ]);
    assert!(
        off.success,
        "maintenance off failed:\n{}\n--- stderr ---\n{}",
        off.stdout, off.stderr
    );

    let _ = agent_a.shutdown_graceful().await;
    let _ = agent_b.shutdown_graceful().await;
    shutdown.cancel();
    let _ = hub_task.await;
}
