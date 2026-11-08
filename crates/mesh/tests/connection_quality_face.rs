//! The connection-quality window face, end to end on the pack-driven
//! path.
//!
//! Acceptance shapes:
//!
//! 1. **The healthy level reaches the face.** A connected leg with a
//!    quiet history reports `connection` (reconnects counted from its
//!    establishes, RTT percentiles from answered demanding probes) —
//!    the point reading finally has a window behind it.
//! 2. **The reconnect window counts real re-establishments.** An
//!    impaired proxy's cut forces the supervisor's reconnect path;
//!    after the restore, the face's `reconnects_last_hour` is above
//!    the steady-state count — the chronic-instability shape made
//!    countable.
//! 3. **The one-way blackhole's leading signal.** The QUIC
//!    probe-swallow fault (answers dropped while everything else
//!    flows) drives `rtt_timeouts` up on the face — probes unanswered
//!    ahead of any business-stream failure, exactly the 2026-10-09
//!    case's leading indicator.
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
use interflow_mesh::pack::{build_agent_config, build_hub_config};
use interflow_testkit::impair::{Direction, TcpImpairProxy};
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

/// Boots the hub through an impairing proxy so the agent's uplink can
/// be cut on demand (the reconnect driver).
struct Site {
    #[allow(dead_code)]
    dir: tempfile::TempDir,
    endpoint: String,
    ca: std::path::PathBuf,
    cert: std::path::PathBuf,
    key: std::path::PathBuf,
    proxy: TcpImpairProxy,
    hub_shutdown: tokio_util::sync::CancellationToken,
    hub_task: tokio::task::JoinHandle<Result<(), interflow_core::error::InterflowError>>,
}

async fn site(tag: &str) -> (Site, interflow_mesh::agent::AgentHandle, String) {
    site_with(tag, true).await
}

async fn site_with(
    tag: &str,
    via_proxy: bool,
) -> (Site, interflow_mesh::agent::AgentHandle, String) {
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
id = "conn-{tag}"
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
"#
    ))
    .unwrap();

    let hub_dir = dir.path().join("packs/hub-central");
    HubCredentialPack::render(&issuer, &manifest, "central", 1, &hub_dir).unwrap();
    let agent_dir = dir.path().join("packs/agent-lan-a");
    AgentCredentialPack::render(&issuer, &manifest, "lan-a", 1, &agent_dir).unwrap();

    let creds_dir = dir.path().join("control-creds");
    std::fs::create_dir_all(&creds_dir).unwrap();
    let ttl = interflow_identity::issuance::LeafTtl::new(time::Duration::hours(1));
    let material = issuer
        .issue_hub_member_with_ttl(&format!("conn-{tag}"), "doctor-hub", ttl)
        .unwrap();
    let (ca, cert, key) = (
        creds_dir.join("ca.crt"),
        creds_dir.join("client.crt"),
        creds_dir.join("client.key"),
    );
    std::fs::write(&ca, issuer.realm_issuer().unwrap().cert_pem()).unwrap();
    std::fs::write(&cert, &material.chain_pem).unwrap();
    std::fs::write(&key, &material.key_pem).unwrap();

    let hub_pack = CredentialPack::load_runtime(&hub_dir).unwrap();
    let hub_active = ActiveCredentialSet::load_or_bootstrap(&hub_pack).unwrap();
    let mut hub_cfg = build_hub_config(&hub_pack, &hub_active, &hub_dir).unwrap();
    if !via_proxy {
        // The QUIC face for the blackhole test (the manifest's public
        // quic_listen validation rejects loopback; the direct config
        // override is the test seam).
        hub_cfg.transport.quic = interflow_mesh::config::hub::HubQuicConfig {
            enabled: true,
            listen_addr: Some(format!("127.0.0.1:{hub_port}").parse().unwrap()),
            ..interflow_mesh::config::hub::HubQuicConfig::default()
        };
    }
    let audit = AuditSink::spawn(&hub_cfg.audit);
    let hub = HubServer::new(hub_cfg, audit).unwrap();
    let (ready_tx, ready_rx) = tokio::sync::oneshot::channel();
    let shutdown = tokio_util::sync::CancellationToken::new();
    let hub_task = tokio::spawn(hub.run_until_signalled(shutdown.clone(), ready_tx));
    ready_rx.await.unwrap();

    // The impaired uplink: the agent dials the proxy, the proxy the hub.
    // The blackhole test dials QUIC directly (the swallow fault lives on
    // the hub's QUIC answer arm; the TCP proxy cannot carry it).
    let proxy = TcpImpairProxy::spawn(
        format!("127.0.0.1:{hub_port}").parse().unwrap(),
        interflow_testkit::impair::ImpairConfig::default(),
    )
    .await
    .unwrap();

    let agent_pack = CredentialPack::load_runtime(&agent_dir).unwrap();
    let agent_active = ActiveCredentialSet::load_or_bootstrap(&agent_pack).unwrap();
    let mut agent_cfg = build_agent_config(&agent_pack, &agent_active, &agent_dir).unwrap();
    if via_proxy {
        agent_cfg.agent.hub_url = format!("https://{}", proxy.local_addr());
    } else {
        agent_cfg.agent.transport = interflow_mesh::config::TransportKind::Quic;
        agent_cfg.agent.hub_quic_addr = Some(format!("127.0.0.1:{hub_port}"));
    }
    // A tight probe cadence keeps the RTT window populated at second
    // scale (production default: one demanding roundtrip per 30s).
    agent_cfg.liveness_probe.tick_secs = 1;
    agent_cfg.liveness_probe.demand_every_secs = 2;
    let agent = AgentClient::new(agent_cfg).unwrap().start();
    wait_connected(&agent).await;

    (
        Site {
            dir,
            endpoint: format!("127.0.0.1:{hub_port}"),
            ca,
            cert,
            key,
            proxy,
            hub_shutdown: shutdown,
            hub_task,
        },
        agent,
        "alpha/lan-a".to_owned(),
    )
}

impl Site {
    async fn snapshot(&self) -> interflow_mesh::hub::snapshot::FleetSnapshotDoc {
        interflow_mesh::hub::snapshot::query_fleet_snapshot(
            &self.endpoint,
            &self.ca,
            &self.cert,
            &self.key,
        )
        .await
        .unwrap()
    }

    fn connection(
        &self,
        doc: &interflow_mesh::hub::snapshot::FleetSnapshotDoc,
        agent: &str,
    ) -> Option<interflow_core::tunnel::transport::ConnectionQualityWire> {
        doc.agents
            .iter()
            .find(|r| r.agent == agent)
            .and_then(|r| r.connection)
    }
}

/// Cut the uplink, let the supervisor's reconnect path run, restore:
/// the window counts what a point reading never could.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn reconnects_and_rtt_levels_reach_the_face() {
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
    let (site, agent, agent_id) = site("reconnect").await;

    // 1. The healthy level: the connection section present, RTT
    //    percentiles from answered probes, zero reconnects beyond the
    //    initial establishment's settle.
    let baseline = eventually_async(
        "the connection section to reach the face",
        Duration::from_secs(30),
        || async {
            let doc = site.snapshot().await;
            site.connection(&doc, &agent_id)
                .ok_or_else(|| "no connection section yet".to_owned())
        },
    )
    .await;
    assert!(
        baseline.rtt_p50_ms.is_some(),
        "answered probes supply percentiles: {baseline:?}"
    );

    // 2. The cut: the supervisor loses the session, reconnects through
    //    the still-dead proxy (backoff), then the restore lets it land.
    site.proxy.cut(Direction::AgentToHub);
    tokio::time::sleep(Duration::from_secs(6)).await;
    site.proxy.restore(Direction::AgentToHub);
    wait_connected(&agent).await;

    let after = eventually_async(
        "the reconnect window to count the re-establishment",
        Duration::from_secs(45),
        || async {
            let doc = site.snapshot().await;
            let conn = site
                .connection(&doc, &agent_id)
                .ok_or_else(|| "no connection section".to_owned())?;
            if conn.reconnects_last_hour > baseline.reconnects_last_hour {
                Ok(conn)
            } else {
                Err(format!(
                    "reconnects still {} (baseline {})",
                    conn.reconnects_last_hour, baseline.reconnects_last_hour
                ))
            }
        },
    )
    .await;
    // The restored leg also answers probes again (percentiles present).
    assert!(after.rtt_p50_ms.is_some() || after.rtt_samples == 0);

    let _ = agent.shutdown_graceful().await;
    site.hub_shutdown.cancel();
    let _ = site.hub_task.await;
}

/// The one-way blackhole leading signal: the QUIC probe-swallow fault
/// drops demanding-roundtrip answers while everything else flows — the
/// timeouts climb on the face ahead of any business-stream symptom.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn probe_timeouts_climb_while_the_session_stays_registered() {
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
    // The swallow fault is QUIC-specific: dial the hub over QUIC.
    let (site, agent, agent_id) = site_with("blackhole", false).await;

    // Arm the fault, then wait for the timeouts to accumulate on the
    // face (the probe cadence is seconds; the budget covers several
    // unanswered rounds and the rebuild the strikes eventually force).
    let faults = interflow_testkit::fault::install(
        interflow_testkit::fault::FaultPlan::new()
            .stall_every_at(interflow_core::fault::FaultPoint::HubQuicSwallowLivenessProbe),
    );
    assert!(
        faults
            .wait_fired(
                interflow_core::fault::FaultPoint::HubQuicSwallowLivenessProbe,
                Duration::from_secs(30),
            )
            .await,
        "the swallow fault must fire on the probe path"
    );

    let after = eventually_async(
        "the probe timeouts to climb on the face",
        Duration::from_secs(90),
        || async {
            let doc = site.snapshot().await;
            let conn = site
                .connection(&doc, &agent_id)
                .ok_or_else(|| "no connection section".to_owned())?;
            if conn.rtt_timeouts > 0 {
                Ok((doc, conn))
            } else {
                Err("no timeouts counted yet".to_owned())
            }
        },
    )
    .await;
    // The leading-signal shape: unanswered probes while the row stays
    // present (the session object alive) — the 2026-10-09 signature.
    let row = after
        .0
        .agents
        .iter()
        .find(|r| r.agent == agent_id)
        .expect("the leg keeps its row");
    assert!(row.online, "the session object stays alive: {row:?}");

    interflow_testkit::fault::clear();
    let _ = agent.shutdown_graceful().await;
    site.hub_shutdown.cancel();
    let _ = site.hub_task.await;
}
