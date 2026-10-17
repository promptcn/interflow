//! The supervisor-restart closed loop
//!: the 50%
//! threshold crossed in REAL time → renewal against the real registrar →
//! the scheduler's clean exit through the REAL `mesh::pack::run_agent`
//! wiring → the supervisor (testkit's Restart=on-success loop) restarts
//! the node onto the newly selected material → the new leaf connects and
//! carries traffic, and the cycle repeats unattended.
//!
//! Only the leaf TTL is compressed (identity's `short-leaf-ttl` test
//! feature: 45s leaves ⇒ the threshold lands ~22s out); everything else —
//! wiring, clocks, TLS, the registrar — is the production path.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use interflow_core::security::AuditSink;
use interflow_identity::credentials::ActiveCredentialSet;
use interflow_identity::issuance::{IssuerStore, LeafTtl};
use interflow_identity::manifest::Manifest;
use interflow_identity::pack::CredentialPack;
use interflow_identity::pack::render::{AgentCredentialPack, HubCredentialPack};
use interflow_mesh::agent::AgentClient;
use interflow_mesh::hub::HubServer;
use interflow_mesh::pack::{build_agent_config, build_hub_config, run_agent};
use interflow_testkit::supervisor::restart_on_success;
use std::path::Path;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

const LEAF_TTL: i64 = 45;

fn free_port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

/// The agent pack's current (single) leaf serial — the "which material is
/// selected" observable across the restart loop.
fn active_serial(pack_dir: &Path) -> String {
    let pack = CredentialPack::load_runtime(pack_dir).unwrap();
    let active = ActiveCredentialSet::load_or_bootstrap(&pack).unwrap();
    active
        .entries
        .values()
        .next()
        .expect("agent pack carries a leaf")
        .serial
        .clone()
}

/// One echo roundtrip through the live ingress→hub→egress path, retried
/// for `window`; `false` = no roundtrip in the window (short-lived
/// segments may legitimately exit first — see the loop below).
async fn echoed_roundtrip(listen_port: u16, window: Duration) -> bool {
    let deadline = tokio::time::Instant::now() + window;
    loop {
        let attempt = tokio::time::timeout(Duration::from_secs(5), async {
            let mut client = tokio::net::TcpStream::connect(("127.0.0.1", listen_port))
                .await
                .ok()?;
            client.write_all(b"supervisor-restart").await.ok()?;
            let mut echoed = vec![0u8; b"supervisor-restart".len()];
            client.read_exact(&mut echoed).await.ok()?;
            Some(echoed)
        })
        .await;
        if let Some(echoed) = attempt.ok().flatten() {
            assert_eq!(echoed, b"supervisor-restart");
            return true;
        }
        if tokio::time::Instant::now() >= deadline {
            return false;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
}

#[tokio::test]
async fn renewal_exits_onto_supervisor_restart_with_new_material() {
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

    // The real registrar the agent renews against (45s leaves, matching
    // the manifest below — only under identity's short-leaf-ttl test
    // feature, which never reaches production graphs).
    let registrar = interflow_testkit::registrar::spawn_registrar(
        interflow_testkit::registrar::RegistrarFixtureOptions {
            ttl: LeafTtl::from_seconds(LEAF_TTL).unwrap(),
            ..interflow_testkit::registrar::RegistrarFixtureOptions::default()
        },
    )
    .await;
    registrar.wait_ready().await;
    let registrar_endpoint = registrar.endpoint().to_owned();
    let issuer = IssuerStore::open(registrar.issuer_dir());
    // The packs tree (the issuer lives in the registrar fixture's tempdir).
    let dir = tempfile::tempdir().unwrap();

    let manifest = Manifest::parse(&format!(
        r#"
[realm]
id = "test"
[identity]
leaf_ttl = "45s"
[registrar]
endpoint = "{registrar_endpoint}"
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

    // The hub is environment (manual assembly, no renewal scheduler of its
    // own here); lan-b is the far-end agent. lan-a is the node under
    // supervision.
    let hub_dir = dir.path().join("packs/hub-central");
    HubCredentialPack::render(&issuer, &manifest, "central", 1, &hub_dir).unwrap();
    let hub_pack = CredentialPack::load_runtime(&hub_dir).unwrap();
    let hub_active = ActiveCredentialSet::load_or_bootstrap(&hub_pack).unwrap();
    let hub_config = build_hub_config(&hub_pack, &hub_active, &hub_dir).unwrap();
    let audit = AuditSink::spawn(&hub_config.audit);
    let hub = HubServer::new(hub_config, audit).unwrap();
    let (ready_tx, ready_rx) = tokio::sync::oneshot::channel();
    let shutdown = tokio_util::sync::CancellationToken::new();
    let hub_task = tokio::spawn(hub.run_until_signalled(shutdown.clone(), ready_tx));
    ready_rx.await.unwrap();

    let pack_dir_b = dir.path().join("packs/agent-lan-b");
    AgentCredentialPack::render(&issuer, &manifest, "lan-b", 1, &pack_dir_b).unwrap();
    let agent_b = {
        let pack = CredentialPack::load_runtime(&pack_dir_b).unwrap();
        let active = ActiveCredentialSet::load_or_bootstrap(&pack).unwrap();
        let config = build_agent_config(&pack, &active, &pack_dir_b).unwrap();
        AgentClient::new(config).unwrap().start()
    };

    let pack_dir_a = dir.path().join("packs/agent-lan-a");
    AgentCredentialPack::render(&issuer, &manifest, "lan-a", 1, &pack_dir_a).unwrap();

    // The very first scheduler run on fresh material writes the CRL files
    // and exits onto a restart (the CRL first-write path — the same one
    // crates/cli/tests/renewal.rs rides). Prime it out here so the
    // supervised loop below observes pure renewal-threshold cycles.
    interflow_renewal::renewal_scheduler(&pack_dir_a)
        .await
        .unwrap();

    // THE loop: real run_agent wiring under the bounded supervisor.
    //
    // The honest production sequence on compressed leaves is an
    // ALTERNATION: a renewal cycle exits cleanly (~22s in), the restart
    // discovers the rotation bumped the CRL (the registrar retires the
    // replaced serial) and exits again within ~1s onto the fresh plane,
    // and only the following run settles into the next renewal cycle.
    // The budget below covers exactly one full alternation: renewal-exit
    // → CRL-exit → renewal-exit.
    #[derive(Clone)]
    struct Segment {
        before: String,
        after: String,
        ran_for: std::time::Duration,
        served_traffic: bool,
    }
    let segments: std::sync::Arc<std::sync::Mutex<Vec<Segment>>> = Default::default();
    let restarts = restart_on_success(
        || {
            // The returned future must own its world (FnMut() -> Fut cannot
            // borrow the closure's captures).
            let pack_dir = pack_dir_a.clone();
            let observed = std::sync::Arc::clone(&segments);
            let before = active_serial(&pack_dir);
            async move {
                let node_dir = pack_dir.clone();
                let node_started = std::time::Instant::now();
                let node = tokio::spawn(async move { run_agent(&node_dir).await });
                // Traffic probing rides its own task so `ran_for` measures
                // the NODE's life, not the probe window.
                let traffic = tokio::spawn(echoed_roundtrip(listen_port, Duration::from_secs(10)));
                let exit = node.await.unwrap();
                let ran_for = node_started.elapsed();
                let served_traffic = traffic.await.unwrap();
                observed.lock().unwrap().push(Segment {
                    before,
                    after: active_serial(&pack_dir),
                    ran_for,
                    served_traffic,
                });
                exit
            }
        },
        2,
    )
    .await
    .expect("every supervised segment exits cleanly");
    assert_eq!(restarts, 2, "renewal-exit → CRL-exit → renewal-exit");

    let seen = segments.lock().unwrap().clone();
    assert_eq!(seen.len(), 3);

    // Segment 1: the full cycle — serving traffic, then the threshold
    // arrives, the scheduler renews for real and exits cleanly.
    assert!(
        seen[0].served_traffic,
        "the first segment serves traffic on its starting material"
    );
    assert_ne!(
        seen[0].before, seen[0].after,
        "segment 1 completed a rotation"
    );
    assert!(
        seen[0].ran_for > Duration::from_secs(5),
        "a renewal segment runs to the threshold (~22s): {:?}",
        seen[0].ran_for
    );

    // Segment 2: the post-rotation CRL settle — the restart observes the
    // bumped CRL (the replaced serial is now revocable material) and exits
    // onto it almost immediately, material unchanged.
    assert!(
        seen[1].ran_for < Duration::from_secs(5),
        "the post-rotation restart settles onto the new CRL plane fast: {:?}",
        seen[1].ran_for
    );
    assert_eq!(
        seen[1].before, seen[1].after,
        "the CRL settle rotates nothing"
    );

    // Segment 3: the loop closes — restarted onto the post-rotation
    // material, serving traffic, renewing again unattended.
    assert!(
        seen[2].served_traffic,
        "the restarted node serves traffic on the rotated material"
    );
    assert_ne!(seen[2].before, seen[2].after, "segment 3 renews again");
    assert_ne!(
        seen[2].after, seen[0].after,
        "each cycle selects fresh material"
    );

    let _ = agent_b.shutdown_graceful().await;
    shutdown.cancel();
    let _ = hub_task.await;
}
