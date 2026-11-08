//! In-crate hub unit-test fixture: the one `HubState` builder shared by
//! every hub module's tests. A second hand-rolled fixture would drift —
//! the exact disease the registration core cured at the source.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use crate::hub::state::{HubLimits, HubState, PolicyChannel};

fn empty_server_config() -> crate::config::ServerConfig {
    crate::config::ServerConfig {
        listen_addr: "127.0.0.1:0".parse().unwrap(),
        node_name: None,
        hub_name: None,
        proxy_protocol: interflow_core::security::ProxyProtocolConfig::default(),
    }
}

/// Enough of a HubConfig for the store paths (they never read it —
/// the field just must exist). Field-by-field because HubConfig has
/// no Default (assembly requires real values in production).
fn empty_hub_config() -> crate::config::HubConfig {
    crate::config::HubConfig {
        server: empty_server_config(),
        auth: crate::config::AuthConfig {
            rate_limit_per_minute: 0,
            max_tracked_clients: interflow_core::security::MAX_TRACKED_CLIENTS,
            tenants: vec![],
        },
        tls: None,
        acl: crate::config::AclConfig {
            rules: std::collections::HashSet::new(),
        },
        security: crate::config::HubSecurityConfig::default(),
        heartbeat: crate::config::HeartbeatConfig::default(),
        metrics: crate::config::MetricsConfig::default(),
        policy: crate::config::PolicyAdminConfig::default(),
        audit: interflow_core::config::AuditConfig::default(),
        logging: crate::config::LoggingConfig::default(),
        transport: crate::config::HubTransportConfig::default(),
    }
}

/// A minimal live HubState: disabled audit, no rate limiter, and a
/// REAL policy channel (an issuer-signed policy on disk — the funnel
/// validates against the verified serving bytes). The policy declares
/// lan-b offering 127.0.0.0/8 egress.
pub fn test_state(dir: &std::path::Path) -> HubState {
    let issuer = interflow_identity::issuance::IssuerStore::open(dir.join("issuer"));
    issuer.ensure_realm().unwrap();
    issuer.ensure_workspace("main").unwrap();
    issuer.ensure_policy_key().unwrap();
    let verifier_key_hex = hex::encode(issuer.policy_verifier().unwrap().as_bytes());
    let manifest = interflow_identity::manifest::Manifest::parse(
        r#"
[realm]
id = "unit"
[identity]
mode = "offline"
leaf_ttl = "7d"
[mesh.hub.h]
listen = "127.0.0.1:16666"
endpoint = "127.0.0.1:16666"
[workspace.main]
[agent.lan-a]
workspace = "main"
[[agent.lan-a.mesh_ingress]]
name = "svc"
listen = "127.0.0.1:24001"
target_agent = "lan-b"
remote_addr = "127.0.0.1:12345"
[agent.lan-b]
workspace = "main"
[[agent.lan-b.mesh_egress]]
name = "loopback"
target_cidr = "127.0.0.0/8"
"#,
    )
    .unwrap();
    let policy = interflow_identity::policy::RuntimePolicy::from_manifest(&manifest, 1);
    let (bytes, sig) = policy.signed(&issuer.policy_signer().unwrap()).unwrap();
    let policy_dir = dir.join("state/policy");
    std::fs::create_dir_all(&policy_dir).unwrap();
    std::fs::write(policy_dir.join("policy.toml"), &bytes).unwrap();
    std::fs::write(policy_dir.join("policy.sig"), &sig).unwrap();
    let channel = PolicyChannel {
        verifier_key_hex,
        dir: policy_dir.clone(),
        embedded_dir: policy_dir,
        floor: std::sync::atomic::AtomicU64::new(1),
        cached: std::sync::RwLock::new(None),
    };
    // The TLS plane: built directly from the shared test kit's
    // certificate files (the store paths never touch it — the field
    // just must exist).
    let certs = interflow_testkit::certs::TestCerts::generate("unit", "lan-a");
    let ca_pem = std::fs::read(certs.ca_path()).unwrap();
    let root =
        interflow_core::tls::TenantTrustRoot::from_pem_with_crls("main", false, &ca_pem, &[])
            .unwrap();
    let plane = interflow_core::tls::build_tls_plane(
        &certs.server_cert_path().display().to_string(),
        &certs.server_key_path().display().to_string(),
        &[root],
        interflow_core::tls::TlsMinVersion::V1_2,
    )
    .unwrap();
    let proposals_path = dir.join("state/proposals.json");
    HubState {
        agents: std::sync::Arc::new(tokio::sync::RwLock::new(std::collections::HashMap::new())),
        route_leases: std::sync::Arc::new(tokio::sync::RwLock::new(
            std::collections::HashMap::new(),
        )),
        config: std::sync::Arc::new(tokio::sync::RwLock::new(empty_hub_config())),
        active_streams: std::sync::Arc::new(crate::hub::state::ShardedStreams::new()),
        data_tx: std::sync::Arc::new(std::sync::RwLock::new(std::collections::HashMap::new())),
        tls_plane: std::sync::Arc::new(std::sync::RwLock::new(std::sync::Arc::new(plane))),
        crl_channel: None,
        crl_liveness: std::sync::Arc::new(crate::hub::crl_liveness::CrlLiveness::new(
            crate::hub::floor_clock::FloorClock::new(),
        )),
        watchdog: std::sync::Arc::new(crate::hub::watchdog::WatchdogRegistry::new(
            crate::hub::floor_clock::FloorClock::new(),
        )),
        node_status: std::sync::Arc::new(crate::hub::node_status::NodeStatus::new(
            crate::hub::floor_clock::FloorClock::new(),
        )),
        credential_watermarks: std::sync::Arc::new(
            crate::hub::credential_watermarks::CredentialWatermarks::new(
                crate::hub::floor_clock::FloorClock::new(),
            ),
        ),
        limits: HubLimits {
            max_streams_per_agent: std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0)),
            max_streams_total: std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0)),
            channel_send_timeout_secs: std::sync::Arc::new(std::sync::atomic::AtomicU64::new(30)),
            poll_grace_secs: std::sync::Arc::new(std::sync::atomic::AtomicU64::new(30)),
            datagram_enabled: std::sync::Arc::new(std::sync::atomic::AtomicBool::new(
                empty_hub_config().transport.quic.datagram_enabled,
            )),
        },
        rate_limiter: None,
        stream_counts: std::sync::Arc::new(std::sync::Mutex::new(std::collections::HashMap::new())),
        audit: interflow_core::security::AuditSink::spawn(&Default::default()),
        policy_channel: Some(std::sync::Arc::new(channel)),
        policy_pull_ledger: std::sync::Arc::new(std::sync::Mutex::new(
            std::collections::HashMap::new(),
        )),
        policy_watermarks: std::sync::Arc::new(
            crate::hub::policy_watermarks::PolicyWatermarks::new(
                crate::hub::floor_clock::FloorClock::new(),
            ),
        ),
        proposals: Some(std::sync::Arc::new(
            crate::hub::proposals::ProposalStore::load(Some(proposals_path)).unwrap(),
        )),
        stale_watermark_ledger: std::sync::Arc::new(std::sync::Mutex::new(
            std::collections::HashMap::new(),
        )),
        expiry_ledger: std::sync::Arc::new(std::sync::Mutex::new(std::collections::HashMap::new())),
        evicted_total: std::sync::Arc::new(std::sync::atomic::AtomicU64::new(0)),
        stream_intents: std::sync::Arc::new(crate::hub::stream_intents::StreamIntents::new(
            crate::hub::floor_clock::FloorClock::new(),
        )),
        maintenance: crate::hub::maintenance::MaintenanceLedger::load(
            Some(&dir.join("state")),
            crate::hub::floor_clock::FloorClock::new(),
        ),
        floor_clock: crate::hub::floor_clock::FloorClock::new(),
        target_recovery: std::sync::Arc::new(std::sync::RwLock::new(None)),
        route_breaker_face: std::sync::Arc::new(std::sync::RwLock::new(None)),
        proxy_policy: std::sync::Arc::new(
            interflow_core::security::ProxyProtocolPolicy::from_config(&Default::default())
                .expect("default proxy policy"),
        ),
        conn_tracker: std::sync::Arc::new(interflow_core::security::ConnTracker::new(0, 0)),
        tasks: tokio_util::task::TaskTracker::new(),
        shutdown: tokio_util::sync::CancellationToken::new(),
    }
}
