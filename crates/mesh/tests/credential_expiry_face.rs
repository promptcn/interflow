//! The credential-expiry fleet face, end to end on the pack-driven path
//!, on BOTH hub
//! transports.
//!
//! Dual-state by the 433bc12 doctrine: the h2 and QUIC registration arms
//! share zero registration code (h2 answers from `registration.rs`, QUIC
//! registers inline in `hub/quic.rs`) — the watermark ledger write is
//! registration-side-effect territory, so each transport owes its own pin
//! (the 2026-10-21 case file: the QUIC arm's missing ledger record left
//! an all-QUIC fleet's expiry face empty while this suite, h2-only, stayed
//! green).
//!
//! Acceptance shapes:
//!
//! 1. **The countdown reaches the face.** The hub's chain parse at
//!    registration becomes a retained per-leg level (notBefore/notAfter
//!    + the tier the span implies) — readable on the snapshot for legs
//!    that never pulled anything.
//! 2. **Tier inference + the offline day lines.** A 45d offline leaf
//!    reads offline/green-class; a 12d offline leaf sits under the
//!    yellow line (< 14d) with its window intact — classification math
//!    single-sourced in identity's expiry module.
//! 3. **The registrar tier's red class.** A 45s leaf (the test build's
//!    `short-leaf-ttl` floor) reads CRITICAL immediately against the
//!    hub-observed span: issuance backdates `notBefore` by an hour, so
//!    the span-relative thresholds (the same identity math the hub's
//!    own `credential_expiry` audit uses) put a leaf this short past
//!    the critical line from the first read — the red class observable
//!    without faking any clock.
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
use interflow_mesh::config::TransportKind;
use interflow_mesh::hub::HubServer;
use interflow_mesh::pack::{build_agent_config, build_hub_config};
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

struct Site {
    #[allow(dead_code)]
    dir: tempfile::TempDir,
    endpoint: String,
    ca: std::path::PathBuf,
    cert: std::path::PathBuf,
    key: std::path::PathBuf,
    hub_shutdown: tokio_util::sync::CancellationToken,
    hub_task: tokio::task::JoinHandle<()>,
}

async fn boot_hub(
    hub_dir: &std::path::Path,
) -> (
    tokio_util::sync::CancellationToken,
    tokio::task::JoinHandle<()>,
) {
    let hub_pack = CredentialPack::load_runtime(hub_dir).unwrap();
    let hub_active = ActiveCredentialSet::load_or_bootstrap(&hub_pack).unwrap();
    let hub_config = build_hub_config(&hub_pack, &hub_active, hub_dir).unwrap();
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
    ready_rx.await.unwrap();
    (shutdown, task)
}

/// Boots the hub and one agent per `leaves` entry; each agent's manifest
/// entry pins its own identity tier + leaf TTL (the pack render honors
/// it — this is the short-leaf dev facility the backlog names). Every
/// agent dials on `transport` (the hub is dual-stack in both states; the
/// snapshot query itself rides h2 control in both).
async fn site(
    leaves: &[(&str, &str, &str)],
    transport: TransportKind,
) -> (Site, Vec<interflow_mesh::agent::AgentHandle>) {
    let hub_port = pick_port();
    let dir = tempfile::tempdir().unwrap();
    let issuer = IssuerStore::open(dir.path().join("issuer"));
    issuer.ensure_realm().unwrap();
    issuer.ensure_workspace("alpha").unwrap();
    issuer.ensure_policy_key().unwrap();

    let remote_port = pick_port();
    let mut agents_toml = String::new();
    let mut handles = Vec::new();
    for (node, mode, ttl) in leaves {
        agents_toml.push_str(&format!(
            r#"[agent.{node}]
workspace = "alpha"
[[agent.{node}.mesh_egress]]
name = "idle"
target_addr = "127.0.0.1:{remote_port}"
"#
        ));
        let _ = (mode, ttl);
    }

    let manifest = Manifest::parse(&format!(
        r#"
[realm]
id = "cred-face"
[registrar]
endpoint = "https://registrar.example.com"
[mesh.hub.central]
listen = "127.0.0.1:{hub_port}"
endpoint = "127.0.0.1:{hub_port}"
quic_listen = "0.0.0.0:{hub_port}"
[workspace.alpha]
{agents_toml}
"#
    ))
    .unwrap();

    let hub_dir = dir.path().join("packs/hub-central");
    HubCredentialPack::render(&issuer, &manifest, "central", 1, &hub_dir).unwrap();

    for (node, mode, ttl) in leaves {
        let registrar_section = if *mode == "registrar" {
            r#"[registrar]
endpoint = "https://registrar.example.com"
"#
        } else {
            ""
        };
        let per_node = Manifest::parse(&format!(
            r#"
[realm]
id = "cred-face"
{registrar_section}[mesh.hub.central]
listen = "127.0.0.1:{hub_port}"
endpoint = "127.0.0.1:{hub_port}"
[workspace.alpha]
[identity]
mode = "{mode}"
leaf_ttl = "{ttl}"
[agent.{node}]
workspace = "alpha"
[[agent.{node}.mesh_egress]]
name = "idle"
target_addr = "127.0.0.1:{remote_port}"
"#
        ))
        .unwrap();
        let pack_dir = dir.path().join(format!("packs/agent-{node}"));
        AgentCredentialPack::render(&issuer, &per_node, node, 1, &pack_dir).unwrap();
        // Offline packs REQUIRE an embedded CRL snapshot per trust-table
        // issuer (a render contract the plan normally satisfies); the
        // test writes an empty one with the leaf's own horizon.
        if *mode == "offline" {
            let crl = interflow_identity::revocation::build_crl_with_horizon(
                &issuer.workspace_issuer("alpha").unwrap(),
                &[],
                1,
                time::Duration::days(46),
            )
            .unwrap();
            std::fs::create_dir_all(pack_dir.join("trust/crls")).unwrap();
            std::fs::write(pack_dir.join("trust/crls/workspace-alpha.crl.pem"), crl).unwrap();
        }
    }

    let (hub_shutdown, hub_task) = boot_hub(&hub_dir).await;

    let creds_dir = dir.path().join("control-creds");
    std::fs::create_dir_all(&creds_dir).unwrap();
    let ttl = interflow_identity::issuance::LeafTtl::new(time::Duration::hours(1));
    let material = issuer
        .issue_hub_member_with_ttl("cred-face", "doctor-hub", ttl)
        .unwrap();
    let (ca, cert, key) = (
        creds_dir.join("ca.crt"),
        creds_dir.join("client.crt"),
        creds_dir.join("client.key"),
    );
    std::fs::write(&ca, issuer.realm_issuer().unwrap().cert_pem()).unwrap();
    std::fs::write(&cert, &material.chain_pem).unwrap();
    std::fs::write(&key, &material.key_pem).unwrap();

    for (node, _mode, _ttl) in leaves {
        let pack_dir = dir.path().join(format!("packs/agent-{node}"));
        let pack = CredentialPack::load_runtime(&pack_dir).unwrap();
        let active = ActiveCredentialSet::load_or_bootstrap(&pack).unwrap();
        let mut config = build_agent_config(&pack, &active, &pack_dir).unwrap();
        config.agent.transport = transport;
        if matches!(transport, TransportKind::Quic) {
            config.agent.hub_quic_addr = Some(format!("127.0.0.1:{hub_port}"));
        }
        let agent = AgentClient::new(config).unwrap().start();
        wait_connected(&agent).await;
        handles.push(agent);
    }

    (
        Site {
            dir,
            endpoint: format!("127.0.0.1:{hub_port}"),
            ca,
            cert,
            key,
            hub_shutdown,
            hub_task,
        },
        handles,
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

    fn row(
        &self,
        doc: &interflow_mesh::hub::snapshot::FleetSnapshotDoc,
        agent: &str,
    ) -> interflow_mesh::hub::snapshot::FleetSnapshotAgent {
        doc.agents
            .iter()
            .find(|r| r.agent == agent)
            .cloned()
            .expect("row present")
    }
}

/// The countdown levels, the tier split, the offline day lines, and the
/// registrar tier aging to past-critical — all on one hub, on the given
/// transport.
async fn leaf_windows_scenario(transport: TransportKind) {
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
    let plane = match transport {
        TransportKind::Quic => "QUIC",
        TransportKind::H2 => "h2",
    };
    // (node, identity mode, leaf ttl): a green-class offline leaf, a
    // yellow-line offline leaf, and a registrar leaf short enough to
    // walk its phases inside the test (the short-leaf-ttl build floor).
    let (site, agents) = site(
        &[
            ("long", "offline", "45d"),
            ("short", "offline", "12d"),
            ("reg", "registrar", "45s"),
        ],
        transport,
    )
    .await;

    // 1+2: the windows and tiers reach the face; the offline day lines
    // classify with the identity module's own math.
    let doc = eventually_async(
        &format!("all three windows to reach the face over {plane}"),
        Duration::from_secs(20),
        || async {
            let doc = site.snapshot().await;
            for agent in ["alpha/long", "alpha/short", "alpha/reg"] {
                let row = doc.agents.iter().find(|r| r.agent == agent);
                if row.and_then(|r| r.leaf_not_after_unix).is_none() {
                    return Err(format!("{agent} carries no window yet"));
                }
            }
            Ok(doc)
        },
    )
    .await;
    let long = site.row(&doc, "alpha/long");
    assert_eq!(long.credential_mode.as_deref(), Some("offline"));
    let short = site.row(&doc, "alpha/short");
    assert_eq!(short.credential_mode.as_deref(), Some("offline"));
    let reg = site.row(&doc, "alpha/reg");
    assert_eq!(reg.credential_mode.as_deref(), Some("registrar"));

    let now = doc.hub.captured_at_unix;
    let days_left = |row: &interflow_mesh::hub::snapshot::FleetSnapshotAgent| {
        (row.leaf_not_after_unix.unwrap() - now) / 86_400
    };
    // 45d offline: green class (comfortably above the 14d line).
    assert!(days_left(&long) > interflow_identity::expiry::OFFLINE_WARN_DAYS);
    // 12d offline: under the yellow line, above the red line.
    let short_days = days_left(&short);
    assert!(
        short_days < interflow_identity::expiry::OFFLINE_WARN_DAYS
            && short_days >= interflow_identity::expiry::OFFLINE_CRITICAL_DAYS,
        "12d leaf sits in the yellow band ({short_days}d)"
    );

    // 3: the registrar leaf ages through its span-relative phases —
    // past critical once under 10% of the 45s span remains.
    // The registrar tier's red class: the same identity math the hub's
    // own expiry audit applies, judged against the capture anchor. A
    // 45s leaf under the ~1h issuance backdate is past the critical
    // line from the first read (see the module docs).
    let reg_health = interflow_identity::expiry::leaf_phase_from_validity(
        reg.leaf_not_before_unix.unwrap(),
        reg.leaf_not_after_unix.unwrap(),
        now,
    );
    assert!(
        matches!(
            reg_health.phase,
            interflow_identity::expiry::LeafPhase::Critical
        ),
        "the short registrar leaf reads critical (backdated span {reg_health:?})"
    );
    // The face's stored window is the ISSUED one (absolute); the row's
    // notAfter never moves.

    for agent in agents {
        let _ = agent.shutdown_graceful().await;
    }
    site.hub_shutdown.cancel();
    let _ = site.hub_task.await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn leaf_windows_reach_the_face_over_h2() {
    leaf_windows_scenario(TransportKind::H2).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn leaf_windows_reach_the_face_over_quic() {
    leaf_windows_scenario(TransportKind::Quic).await;
}
