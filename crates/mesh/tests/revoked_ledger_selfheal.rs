//! The load-path self-heal acceptance (the "救不回" half of the 2026-10-13
//! incident): a node whose renewal-ledger serial the CRL condemns, while its
//! bootstrap identities stay valid (what revoke without
//! `--include-active-credentials` produces), must shed the dead ledger on
//! restart and re-register with its bootstrap identity — no manual
//! `mv state/credentials …` rescue.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use interflow_core::security::AuditSink;
use interflow_identity::credentials::ActiveCredentialSet;
use interflow_identity::issuance::{IssuerStore, LeafTtl, generate_csr};
use interflow_identity::manifest::Manifest;
use interflow_identity::pack::CredentialPack;
use interflow_identity::pack::render::{AgentCredentialPack, HubCredentialPack};
use interflow_identity::revocation::{RevocationEntry, RevocationList, build_crl, cert_serial_hex};
use interflow_mesh::agent::AgentClient;
use interflow_mesh::hub::HubServer;
use interflow_mesh::hub::crl::{PublishCrlsOutcome, publish_crls};
use interflow_mesh::pack::{build_agent_config, build_hub_config};
use std::collections::BTreeMap;
use std::path::PathBuf;
use std::time::Duration;
use tokio::io::AsyncWriteExt;

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

/// The operator's control credential for `PUT /crls` (same mint as the CLI).
fn control_credential(issuer: &IssuerStore, realm: &str) -> (PathBuf, PathBuf, PathBuf) {
    let ttl = LeafTtl::new(time::Duration::hours(1));
    let material = issuer
        .issue_hub_member_with_ttl(realm, "selfheal-test", ttl)
        .unwrap();
    let dir = std::env::temp_dir().join(format!(
        "interflow-ledger-selfheal-{}-{}",
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

#[tokio::test]
async fn revoked_ledger_sheds_and_reregisters_with_the_bootstrap_identity() {
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
    let hub_port = free_port();
    let echo_port = free_port();
    let listen_port = free_port();

    // The far-end service (the registration path alone needs none of it,
    // but the manifest's mesh topology does).
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
    ))
    .unwrap();

    let hub_dir = dir.path().join("packs/hub-central");
    HubCredentialPack::render(&issuer, &manifest, "central", 1, &hub_dir).unwrap();
    let pack_dir = dir.path().join("packs/agent-lan-a");
    AgentCredentialPack::render(&issuer, &manifest, "lan-a", 1, &pack_dir).unwrap();

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

    // First boot: bootstrap identities (sequence 1). Then a renewal lands on
    // disk (sequence 2) — the ledger the incident's revoke condemned.
    let agent = start(pack_dir.clone());
    wait_connected(&agent).await;
    let _ = agent.shutdown_graceful().await;

    let pack = CredentialPack::load_runtime(&pack_dir).unwrap();
    let mut ledger = ActiveCredentialSet::load_or_bootstrap(&pack).unwrap();
    assert_eq!(ledger.sequence, 1);
    let identity_serial = cert_serial_hex(&pack.identities["agent"]["main"].cert_pem).unwrap();
    let expected = pack.identities["agent"]["main"].clone();
    let csr = generate_csr(&expected.principal, &[], false).unwrap();
    let material = issuer
        .workspace_issuer("main")
        .unwrap()
        .issue_csr(
            &expected.principal,
            &[],
            false,
            LeafTtl::default_ttl(),
            &csr.csr_pem,
        )
        .unwrap();
    ledger
        .renew(
            "agent-main",
            &expected,
            &material.chain_pem,
            &csr.key_pem,
            &pack,
        )
        .unwrap();
    let renewed_serial = ledger.entries["agent-main"].serial.clone();
    assert_ne!(renewed_serial, identity_serial);

    // Restart onto the renewed ledger: the node presents the renewed serial
    // (this is the running state the 23:24 hot-swap hit).
    let agent = start(pack_dir.clone());
    wait_connected(&agent).await;

    // The operator revokes the ledger serial (the explicit domain) and the
    // hub hot-swaps onto the CRL: the live session is evicted.
    let mut list = RevocationList::default();
    list.record(RevocationEntry {
        serial: renewed_serial.clone(),
        issuer: "workspace/main".to_owned(),
        reason: "key-compromise".to_owned(),
        revoked_at: "2026-10-13T00:00:00Z".to_owned(),
        pack_digest: None,
    });
    let ws_crl = build_crl(
        &issuer.workspace_issuer("main").unwrap(),
        &list.entries,
        list.next_crl_number,
    )
    .unwrap();
    let control_crl = build_crl(&issuer.realm_issuer().unwrap(), &[], 1).unwrap();
    let crls = BTreeMap::from([
        ("workspace-main".to_owned(), ws_crl.clone()),
        ("control".to_owned(), control_crl),
    ]);
    let (ca, cert, key) = control_credential(&issuer, "test");
    let outcome = publish_crls(&format!("127.0.0.1:{hub_port}"), &ca, &cert, &key, &crls)
        .await
        .unwrap();
    match outcome {
        PublishCrlsOutcome::Applied { evicted, .. } => {
            assert_eq!(
                evicted,
                vec!["main/lan-a".to_owned()],
                "the live session holding the revoked ledger serial is swept"
            );
        }
        other => panic!("push must apply: {other:?}"),
    }

    // The renewal scheduler's refresh drops the same CRL into the node's
    // live source (state/crls — the registrar tier's statically pinned
    // path). In production this is the 60s poll; here it lands directly.
    let live_crls = pack_dir.join("state/crls");
    std::fs::create_dir_all(&live_crls).unwrap();
    std::fs::write(live_crls.join("workspace-main.crl.pem"), &ws_crl).unwrap();

    // THE self-heal: restart. The load path sees the ledger serial on the
    // CRL, quarantines the sequence, and re-derives from the bootstrap
    // identities — the node is back with its (still-valid) identity serial.
    let _ = agent.shutdown_graceful().await;
    let agent = start(pack_dir.clone());
    wait_connected(&agent).await;

    let healed =
        ActiveCredentialSet::load_or_bootstrap(&CredentialPack::load_runtime(&pack_dir).unwrap())
            .unwrap();
    assert_eq!(
        healed.entries["agent-main"].serial, identity_serial,
        "the node serves its bootstrap identity after shedding the dead ledger"
    );
    let prefix: String = renewed_serial.chars().take(8).collect();
    assert!(
        pack_dir
            .join("state/credentials/quarantined")
            .join(format!("2-{prefix}"))
            .is_dir(),
        "the dead ledger stays on disk as the audit trail"
    );

    let _ = agent.shutdown_graceful().await;
    shutdown.cancel();
    let _ = hub_task.await;
}
