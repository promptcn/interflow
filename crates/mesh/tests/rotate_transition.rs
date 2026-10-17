//! The rotate transition window
//! ((internal design notes) G5, the
//! automated twin of the 2026-10-12 pack-format-retirement rehearsal's
//! real-window leg): while the old and new generations coexist on disk, a
//! revoked OLD leaf must fail the hub's mTLS handshake at the same moment
//! the NEW pack's leaf builds a connection and carries traffic.
//!
//! The transition is driven the way an operator drives it: the real
//! `plan::rotate` renders generation 2, the retired serials are recorded
//! on the deny list, and the CRL set is hot-pushed to the running hub
//! (no restart) — the same lane `crl_hot_swap.rs` proved.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use interflow_core::security::AuditSink;
use interflow_identity::credentials::ActiveCredentialSet;
use interflow_identity::issuance::IssuerStore;
use interflow_identity::manifest::Manifest;
use interflow_identity::pack::CredentialPack;
use interflow_identity::pack::render::{AgentCredentialPack, HubCredentialPack};
use interflow_identity::revocation::{RevocationEntry, RevocationList, build_crl, cert_serial_hex};
use interflow_mesh::agent::AgentClient;
use interflow_mesh::hub::HubServer;
use interflow_mesh::hub::crl::{PublishCrlsOutcome, publish_crls};
use interflow_mesh::pack::{build_agent_config, build_hub_config};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
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

/// Mints the operator's control credential to temp files — the principal
/// class `PUT /crls` accepts. (Same shape as `crl_hot_swap.rs`.)
fn control_credential(issuer: &IssuerStore, realm: &str) -> (PathBuf, PathBuf, PathBuf) {
    let ttl = interflow_identity::issuance::LeafTtl::new(time::Duration::hours(1));
    let material = issuer
        .issue_hub_member_with_ttl(realm, "rotate-test", ttl)
        .unwrap();
    let dir = std::env::temp_dir().join(format!(
        "interflow-rotate-transition-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::create_dir_all(&dir).unwrap();
    let (ca, cert, key) = (
        dir.join("ca.pem"),
        dir.join("cert.pem"),
        dir.join("key.pem"),
    );
    std::fs::write(&ca, issuer.realm_issuer().unwrap().cert_pem()).unwrap();
    std::fs::write(&cert, &material.chain_pem).unwrap();
    std::fs::write(&key, &material.key_pem).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(&key, std::fs::Permissions::from_mode(0o600));
    }
    (ca, cert, key)
}

/// One raw mTLS dial with a pack's active leaf: `Ok` = handshake completed,
/// `Err` = the hub rejected the credentials at the handshake itself.
/// (Same shape as `crl_hot_swap.rs`.)
async fn mtls_handshake_dial(hub_port: u16, pack_dir: &Path) -> Result<(), String> {
    let pack_dir = pack_dir.to_path_buf();
    tokio::task::spawn_blocking(move || {
        let pack = CredentialPack::load_runtime(&pack_dir).unwrap();
        let active = ActiveCredentialSet::load_or_bootstrap(&pack).unwrap();
        let entry = active.entries.values().next().unwrap();
        let ca_pem = pack
            .trust
            .issuers
            .values()
            .cloned()
            .collect::<Vec<_>>()
            .join("\n");
        let dir = tempfile::tempdir().unwrap();
        let (ca, crt, key) = (
            dir.path().join("ca.pem"),
            dir.path().join("c.crt"),
            dir.path().join("c.key"),
        );
        std::fs::write(&ca, &ca_pem).unwrap();
        std::fs::write(&crt, &entry.cert_pem).unwrap();
        std::fs::write(&key, &entry.key_pem).unwrap();
        let config = interflow_core::tls::client::build_client_config(
            None,
            Some(&ca.display().to_string()),
            Some(&crt.display().to_string()),
            Some(&key.display().to_string()),
            &["h2"],
        )
        .map_err(|e| e.to_string())?;
        let name = rustls::pki_types::ServerName::try_from("127.0.0.1".to_owned())
            .map_err(|e| e.to_string())?;
        let mut conn = rustls::ClientConnection::new(std::sync::Arc::new(config), name)
            .map_err(|e| e.to_string())?;
        let addr: std::net::SocketAddr = format!("127.0.0.1:{hub_port}").parse().unwrap();
        let mut sock = std::net::TcpStream::connect_timeout(&addr, Duration::from_secs(5))
            .map_err(|e| e.to_string())?;
        let _ = sock.set_read_timeout(Some(Duration::from_secs(5)));
        let _ = sock.set_write_timeout(Some(Duration::from_secs(5)));
        while conn.is_handshaking() {
            if conn.wants_write() && conn.write_tls(&mut sock).is_err() {
                return Err("handshake write failed".to_owned());
            }
            if conn.wants_read() && conn.read_tls(&mut sock).is_err() {
                return Err("handshake read failed — the peer closed on us".to_owned());
            }
            if let Err(e) = conn.process_new_packets() {
                return Err(e.to_string());
            }
        }
        // Flush the final flight (TLS 1.3: the client's Finished carries
        // its certificate).
        if conn.wants_write() && conn.write_tls(&mut sock).is_err() {
            return Err("final flight write failed".to_owned());
        }
        let _ = sock.set_read_timeout(Some(Duration::from_secs(2)));
        let mut buf = [0u8; 512];
        match std::io::Read::read(&mut sock, &mut buf) {
            Err(e)
                if matches!(
                    e.kind(),
                    std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                ) =>
            {
                Ok(())
            }
            Err(e) => Err(format!("post-handshake read failed: {e}")),
            Ok(0) => Err("the peer closed the connection right after the handshake".to_owned()),
            Ok(n) => match conn.read_tls(&mut &buf[..n]).map_err(|e| e.to_string()) {
                Ok(_) => conn
                    .process_new_packets()
                    .map(|_| ())
                    .map_err(|e| e.to_string()),
                Err(e) => Err(e),
            },
        }
    })
    .await
    .map_err(|e| e.to_string())?
}

async fn echo_roundtrip(listen_port: u16) {
    let echoed = tokio::time::timeout(Duration::from_secs(30), async {
        let mut client = tokio::net::TcpStream::connect(("127.0.0.1", listen_port))
            .await
            .unwrap();
        client.write_all(b"rotate-transition").await.unwrap();
        let mut echoed = vec![0u8; b"rotate-transition".len()];
        client.read_exact(&mut echoed).await.unwrap();
        echoed
    })
    .await
    .unwrap();
    assert_eq!(echoed, b"rotate-transition");
}

#[tokio::test]
async fn rotate_transition_window_rejects_old_pack_and_serves_new() {
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
    let hub_port = free_port();
    let echo_port = free_port();
    let listen_port = free_port();

    // The far-end service behind lan-b.
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
                    match tokio::io::AsyncReadExt::read(&mut sock, &mut buf).await {
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
    let issuer_dir = dir.path().join("issuer");
    let issuer = IssuerStore::open(&issuer_dir);
    issuer.ensure_realm().unwrap();
    issuer.ensure_workspace("main").unwrap();
    issuer.ensure_policy_key().unwrap();

    let manifest_path = dir.path().join("interflow.toml");
    std::fs::write(
        &manifest_path,
        format!(
            r#"
[realm]
id = "test"
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
remote_addr = "127.0.0.1:{echo_port}"
[agent.lan-b]
workspace = "main"
[[agent.lan-b.mesh_egress]]
name = "svc"
target_addr = "127.0.0.1:{echo_port}"
"#
        ),
    )
    .unwrap();
    let manifest_text = std::fs::read_to_string(&manifest_path).unwrap();
    let manifest = Manifest::parse(&manifest_text).unwrap();

    // Generation 1 everywhere; the hub and lan-b are environment.
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

    let start = |pack_dir: PathBuf| {
        let pack = CredentialPack::load_runtime(&pack_dir).unwrap();
        let active = ActiveCredentialSet::load_or_bootstrap(&pack).unwrap();
        let config = build_agent_config(&pack, &active, &pack_dir).unwrap();
        AgentClient::new(config).unwrap().start()
    };
    let agent_b = start(pack_dir_b.clone());
    wait_connected(&agent_b).await;
    let agent_a = start(pack_dir_a.clone());
    wait_connected(&agent_a).await;

    // Baseline: generation 1 serves traffic and handshakes.
    echo_roundtrip(listen_port).await;
    mtls_handshake_dial(hub_port, &pack_dir_a)
        .await
        .expect("baseline: the generation-1 leaf handshakes");

    // THE ROTATE: the real operator path renders generation 2 beside the
    // still-valid generation 1 (rollback window: the old pack stays on
    // disk until its own expiry).
    interflow_cli::plan::rotate(
        &manifest_path,
        &issuer_dir,
        "agent/lan-a",
        Some(&pack_dir_a),
        None,
        false,
    )
    .expect("plan rotate");
    let pack_dir_a_gen2 = dir.path().join("packs/agent-lan-a-gen2");
    let gen2_toml = std::fs::read_to_string(pack_dir_a_gen2.join("pack.toml")).unwrap();
    assert!(
        gen2_toml.contains("generation = 2"),
        "the rotated pack carries generation 2: {gen2_toml}"
    );
    assert!(
        pack_dir_a.join("pack.toml").is_file(),
        "the old pack survives the window (rollback until its own expiry)"
    );

    // Retire the old material: generation 1's serials onto the deny list,
    // CRLs for every tenant issuer, hot-pushed to the running hub.
    let active_gen1 =
        ActiveCredentialSet::load_or_bootstrap(&CredentialPack::load_runtime(&pack_dir_a).unwrap())
            .unwrap();
    let mut list = RevocationList::default();
    for entry in active_gen1.entries.values() {
        list.record(RevocationEntry {
            serial: cert_serial_hex(&entry.cert_pem).unwrap(),
            issuer: "workspace/main".to_owned(),
            reason: "superseded".to_owned(),
            revoked_at: "2026-10-16T00:00:00Z".to_owned(),
            pack_digest: None,
        });
    }
    let pushed_number = list.next_crl_number;
    let crls = BTreeMap::from([
        (
            "workspace-main".to_owned(),
            build_crl(
                &issuer.workspace_issuer("main").unwrap(),
                &list.entries,
                pushed_number,
            )
            .unwrap(),
        ),
        (
            "control".to_owned(),
            build_crl(&issuer.realm_issuer().unwrap(), &[], 1).unwrap(),
        ),
    ]);
    let (ca, cert, key) = control_credential(&issuer, "test");
    let endpoint = format!("127.0.0.1:{hub_port}");
    let outcome = publish_crls(&endpoint, &ca, &cert, &key, &crls)
        .await
        .unwrap();
    match outcome {
        PublishCrlsOutcome::Applied { numbers, evicted } => {
            assert_eq!(
                numbers.get("workspace-main"),
                Some(&pushed_number),
                "the pushed counter is in force: {numbers:?}"
            );
            assert_eq!(
                evicted,
                vec!["main/lan-a".to_owned()],
                "the live generation-1 session is swept by the push"
            );
        }
        other => panic!("the transition push must apply: {other:?}"),
    }

    // THE WINDOW, asserted: in the same instant —
    //   the OLD pack's leaf is refused at the handshake itself,
    //   the NEW pack's leaf is accepted.
    let old = mtls_handshake_dial(hub_port, &pack_dir_a).await;
    assert!(
        old.is_err(),
        "the retired generation-1 leaf must fail the handshake — it completed instead"
    );
    mtls_handshake_dial(hub_port, &pack_dir_a_gen2)
        .await
        .expect("the generation-2 leaf handshakes in the same window");

    // And the new pack actually SERVES: the retired agent's session is
    // dead, the restarted node on generation 2 connects and carries
    // traffic end to end.
    let _ = agent_a.shutdown_graceful().await;
    let agent_a_gen2 = start(pack_dir_a_gen2.clone());
    wait_connected(&agent_a_gen2).await;
    echo_roundtrip(listen_port).await;

    let _ = agent_a_gen2.shutdown_graceful().await;
    let _ = agent_b.shutdown_graceful().await;
    shutdown.cancel();
    let _ = hub_task.await;
}
