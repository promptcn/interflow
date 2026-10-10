//! Pack-path QUIC acceptance for the site-to-site face: the manifest's
//! `[mesh.hub] quic_listen` and a mesh agent's `transport = "quic"` must
//! ride the real render → digest-verified load → `build_*_config` chain
//! onto the engine — and the assembled configs must actually carry a live
//! tunnel over the wire.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use interflow_core::security::AuditSink;
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
    let audit = AuditSink::spawn(&hub_config.audit);
    let hub = HubServer::new(hub_config, audit).unwrap();
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

/// The QUIC leg's policy control plane (2026-10-06 transport-uniformity
/// fix): a policy PUBLISHED at the hub (the h2 management face, PUT
/// /policy) reaches a QUIC-dialing agent through the PolicyPull frame pair
/// — the same zero-touch acceptance the h2 leg has. Then the inversion
/// contract: an agent holding a watermark ABOVE what the hub serves keeps
/// it (anti-rollback holds over QUIC; the hub's answer carries its serving
/// generation and the watcher's telemetry exposes the deadlock shape).
#[tokio::test]
async fn hub_published_policy_reaches_quic_agents_over_the_control_plane() {
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
    let hub_port = free_port();
    let echo_port = free_port();
    let listen_v1 = free_port();
    let listen_v2 = free_port();

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

    let manifest_v1 = quic_manifest(hub_port, listen_v1, echo_port);
    let manifest_v2 = quic_manifest(hub_port, listen_v2, echo_port);
    let hub_dir = dir.path().join("packs/hub-central");
    HubCredentialPack::render(&issuer, &manifest_v1, "central", 1, &hub_dir).unwrap();
    let pack_dir_a = dir.path().join("packs/agent-lan-a");
    AgentCredentialPack::render(&issuer, &manifest_v1, "lan-a", 1, &pack_dir_a).unwrap();
    let pack_dir_b = dir.path().join("packs/agent-lan-b");
    AgentCredentialPack::render(&issuer, &manifest_v1, "lan-b", 1, &pack_dir_b).unwrap();

    let hub_pack = CredentialPack::load_runtime(&hub_dir).unwrap();
    let hub_active = ActiveCredentialSet::load_or_bootstrap(&hub_pack).unwrap();
    let hub_config = build_hub_config(&hub_pack, &hub_active, &hub_dir).unwrap();
    let audit = AuditSink::spawn(&hub_config.audit);
    let hub = HubServer::new(hub_config, audit).unwrap();
    let (ready_tx, ready_rx) = tokio::sync::oneshot::channel();
    let shutdown = tokio_util::sync::CancellationToken::new();
    let hub_task = tokio::spawn(hub.run_until_signalled(shutdown.clone(), ready_tx));
    ready_rx.await.unwrap();

    // The REAL start path: `AgentClient::start` spawns the policy watcher
    // intrinsically from the config's policy plane — the same path the CLI
    // binary and the GUI take (no test-local wiring left to drift from
    // production; (internal design notes)).
    let start = |pack_dir: &Path| {
        let pack = CredentialPack::load_runtime(pack_dir).unwrap();
        let active = ActiveCredentialSet::load_or_bootstrap(&pack).unwrap();
        let config = build_agent_config(&pack, &active, pack_dir).unwrap();
        let agent = AgentClient::new(config).unwrap().start();
        let watch_state = agent
            .policy_state()
            .expect("a pack-built config arms the policy watcher at start");
        (agent, watch_state)
    };
    let (agent_b, _) = start(&pack_dir_b);
    wait_connected(&agent_b).await;
    // lan-a is the QUIC-dialing subject.
    let (agent_a, watch_a) = start(&pack_dir_a);
    wait_connected(&agent_a).await;

    let round_trip = |port: u16, payload: &[u8]| {
        let payload = payload.to_vec();
        async move {
            let mut client = tokio::net::TcpStream::connect(("127.0.0.1", port)).await?;
            client.write_all(&payload).await?;
            let mut echoed = vec![0u8; payload.len()];
            client.read_exact(&mut echoed).await?;
            Ok::<Vec<u8>, std::io::Error>(echoed)
        }
    };
    assert_eq!(
        tokio::time::timeout(Duration::from_secs(30), round_trip(listen_v1, b"v1"))
            .await
            .unwrap()
            .unwrap(),
        b"v1"
    );

    // Publish generation 2 at the hub — the ONLY action; no file touches.
    let policy_v2 = interflow_identity::policy::RuntimePolicy::from_manifest(&manifest_v2, 2);
    let (bytes_v2, sig_v2) = policy_v2.signed(&issuer.policy_signer().unwrap()).unwrap();
    let creds_dir = dir.path().join("publish-creds");
    std::fs::create_dir_all(&creds_dir).unwrap();
    let ttl = interflow_identity::issuance::LeafTtl::new(time::Duration::hours(1));
    let material = issuer
        .issue_hub_member_with_ttl("test", "plan-apply", ttl)
        .unwrap();
    let (ca, cert, key) = (
        creds_dir.join("ca.crt"),
        creds_dir.join("client.crt"),
        creds_dir.join("client.key"),
    );
    std::fs::write(&ca, issuer.realm_issuer().unwrap().cert_pem()).unwrap();
    std::fs::write(&cert, &material.chain_pem).unwrap();
    std::fs::write(&key, &material.key_pem).unwrap();
    let outcome = interflow_mesh::hub::policy::publish_policy(
        &format!("127.0.0.1:{hub_port}"),
        &ca,
        &cert,
        &key,
        &bytes_v2,
        &sig_v2,
    )
    .await
    .unwrap();
    assert_eq!(
        outcome,
        interflow_mesh::hub::policy::PublishOutcome::Published { generation: 2 }
    );

    // The QUIC agent hot-applies within a watch interval: the NEW listener
    // live, the old one gone.
    let deadline = tokio::time::Instant::now() + Duration::from_secs(45);
    let mut live = false;
    while tokio::time::Instant::now() < deadline {
        if let Ok(Ok(got)) =
            tokio::time::timeout(Duration::from_secs(5), round_trip(listen_v2, b"v2")).await
            && got == b"v2"
        {
            live = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(500)).await;
    }
    assert!(live, "the published policy must reach the QUIC agent");
    assert!(
        tokio::net::TcpStream::connect(("127.0.0.1", listen_v1))
            .await
            .is_err(),
        "the old listener must be gone"
    );
    // The pull landed in the node-local channel — the exact files a restart
    // would reload.
    assert!(pack_dir_a.join("state/policy/policy.toml").is_file());

    // The pull channel's own health face converged with it: the watcher
    // has completed pulls (2026-10-07 — "never pulled" must be
    // distinguishable from "nothing to pull") and the hub's serving
    // generation is the converged one.
    assert!(
        watch_a
            .pull_last_ok_unix
            .load(std::sync::atomic::Ordering::Acquire)
            > 0,
        "the intrinsic watcher must complete control-plane pulls"
    );
    assert_eq!(
        watch_a
            .hub_generation
            .load(std::sync::atomic::Ordering::Acquire),
        2,
        "the watcher telemetry tracks the hub's serving generation"
    );
    assert_eq!(
        watch_a.seen.load(std::sync::atomic::Ordering::Acquire),
        2,
        "the applied watermark advances in telemetry"
    );

    // The audit ledger carries the distribution as a STATE TRANSITION: one
    // policy_pulled for (alpha/lan-a, 2), never per tick.
    let policy_pull_pairs = || -> Vec<(String, u64)> {
        std::fs::read_to_string(hub_dir.join("audit.jsonl"))
            .unwrap_or_default()
            .lines()
            .filter_map(|line| serde_json::from_str::<serde_json::Value>(line).ok())
            .filter(|v| v.get("kind").and_then(|k| k.as_str()) == Some("policy_pulled"))
            .map(|v| {
                (
                    v.get("agent")
                        .and_then(|a| a.as_str())
                        .unwrap_or_default()
                        .to_string(),
                    v.get("generation")
                        .and_then(serde_json::Value::as_u64)
                        .unwrap_or(0),
                )
            })
            .collect()
    };
    let deadline = tokio::time::Instant::now() + Duration::from_secs(15);
    loop {
        if policy_pull_pairs().contains(&("alpha/lan-a".to_owned(), 2u64)) {
            break;
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "gen 2 never reached the QUIC agent in the audit: {:?}",
            policy_pull_pairs()
        );
        tokio::time::sleep(Duration::from_millis(500)).await;
    }

    // Inversion — the 2026-10-06 incident shape: the node's watermark sits
    // ABOVE what the hub serves (a state-channel drop at generation 5 while
    // the hub is still at 2). The node must KEEP its watermark (the
    // anti-rollback contract holds over QUIC) while the telemetry exposes
    // the deadlock: seen=5, hub_generation=2.
    let policy_v5 = interflow_identity::policy::RuntimePolicy::from_manifest(&manifest_v2, 5);
    let (bytes_v5, sig_v5) = policy_v5.signed(&issuer.policy_signer().unwrap()).unwrap();
    std::fs::write(pack_dir_a.join("state/policy/policy.toml"), &bytes_v5).unwrap();
    std::fs::write(pack_dir_a.join("state/policy/policy.sig"), &sig_v5).unwrap();

    let load = |state: &std::sync::Arc<interflow_mesh::agent::PolicyWatchState>| {
        (
            state.seen.load(std::sync::atomic::Ordering::Acquire),
            state
                .hub_generation
                .load(std::sync::atomic::Ordering::Acquire),
        )
    };
    let deadline = tokio::time::Instant::now() + Duration::from_secs(45);
    loop {
        let (seen, hub_generation) = load(&watch_a);
        if seen == 5 && hub_generation == 2 {
            break;
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "inversion never became observable (seen={seen}, hub={hub_generation})"
        );
        tokio::time::sleep(Duration::from_millis(500)).await;
    }
    // No downgrade: the node-local channel still holds generation 5 and the
    // hub's serving generation never crept into it.
    assert!(
        std::fs::read_to_string(pack_dir_a.join("state/policy/policy.toml"))
            .unwrap()
            .contains("generation = 5"),
        "the node must keep its higher watermark"
    );

    // The subscription face — the engine-side half of the GUI's policy
    // event stream: converged snapshots must arrive as watcher EVENTS, not
    // only as polled atomics (the 2026-10-07 stale-panel bug was a consumer
    // with no way to hear them). Every tick publishes (last_tick moves),
    // so `changed()` firing at all is itself the liveness claim under test
    // — the loop below must traverse at least one real event, never the
    // subscription's seeded initial value.
    {
        let mut rx = watch_a.subscribe();
        let deadline = tokio::time::Instant::now() + Duration::from_secs(25);
        loop {
            rx.changed()
                .await
                .expect("the watcher must keep its snapshot sender alive");
            let snap = *rx.borrow_and_update();
            if snap.seen == 5 && snap.hub_generation == 2 && snap.pull_last_ok_unix > 0 {
                break;
            }
            assert!(
                tokio::time::Instant::now() < deadline,
                "the subscription face never carried the converged snapshot ({snap:?})"
            );
        }
    }

    // The reported watermark is machine-observable (2026-10-06 gate fix,
    // hub half): the floor ABSORBS the node's 5 — polled here because the
    // observability loop above can be satisfied by a pre-injection
    // response — so any issuer (even one whose bookkeeping sits at 2)
    // sees it via GET /policy/floor, and the rollback arbitration
    // enforces it: a gen-3 publish 409s at the absorbed floor, a gen-6
    // publish unfreezes the lineage.
    //
    // The serving half (2026-10-07 gate fix): while the floor absorbs 5,
    // `serving` keeps reporting what the hub actually serves (2) — the
    // divergence is exactly the lineage-split signature the no-op gate's
    // serving comparison exists to catch.
    let deadline = tokio::time::Instant::now() + Duration::from_secs(45);
    let absorbed_serving: Option<u64> = loop {
        let watermarks = interflow_mesh::hub::policy::query_policy_floor(
            &format!("127.0.0.1:{hub_port}"),
            &ca,
            &cert,
            &key,
        )
        .await
        .unwrap();
        if watermarks.floor == 5 {
            break watermarks.serving;
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "the hub floor never absorbed the reported watermark 5 (watermarks={watermarks:?})"
        );
        tokio::time::sleep(Duration::from_millis(500)).await;
    };
    assert_eq!(
        absorbed_serving,
        Some(2),
        "the absorbed floor must not mask what the hub actually serves"
    );
    let policy_v3 = interflow_identity::policy::RuntimePolicy::from_manifest(&manifest_v2, 3);
    let (bytes_v3, sig_v3) = policy_v3.signed(&issuer.policy_signer().unwrap()).unwrap();
    let outcome = interflow_mesh::hub::policy::publish_policy(
        &format!("127.0.0.1:{hub_port}"),
        &ca,
        &cert,
        &key,
        &bytes_v3,
        &sig_v3,
    )
    .await
    .unwrap();
    assert_eq!(
        outcome,
        interflow_mesh::hub::policy::PublishOutcome::RollbackConflict {
            current_generation: 5
        },
        "a publish below the absorbed watermark must be arbitrated away"
    );
    let policy_v6 = interflow_identity::policy::RuntimePolicy::from_manifest(&manifest_v2, 6);
    let (bytes_v6, sig_v6) = policy_v6.signed(&issuer.policy_signer().unwrap()).unwrap();
    let outcome = interflow_mesh::hub::policy::publish_policy(
        &format!("127.0.0.1:{hub_port}"),
        &ca,
        &cert,
        &key,
        &bytes_v6,
        &sig_v6,
    )
    .await
    .unwrap();
    assert_eq!(
        outcome,
        interflow_mesh::hub::policy::PublishOutcome::Published { generation: 6 },
        "publishing above the absorbed watermark unfreezes the lineage"
    );

    // The watchers ride the agents' own task groups now — shutting the
    // agents down ends them.
    let _ = agent_a.shutdown_graceful().await;
    let _ = agent_b.shutdown_graceful().await;
    shutdown.cancel();
    let _ = hub_task.await;
}
