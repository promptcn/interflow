//! End-to-end acceptance for the pack-driven site-to-site path:
//! manifest → Credential Packs → hub + two agents in-process → TCP through
//! the tunnel, across two workspaces.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use interflow_core::security::AuditSink;
use interflow_identity::credentials::ActiveCredentialSet;
use interflow_identity::issuance::IssuerStore;
use interflow_identity::manifest::Manifest;
use interflow_identity::pack::CredentialPack;
use interflow_identity::pack::render::{AgentCredentialPack, HubCredentialPack};
use interflow_mesh::agent::AgentClient;
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

#[tokio::test]
async fn pack_site_to_site_forwards_tcp_across_workspaces() {
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

    let manifest = Manifest::parse(&format!(
        r#"
[realm]
id = "test"
[registrar]
endpoint = "https://registrar.example.com"
[mesh.hub.central]
listen = "127.0.0.1:{hub_port}"
endpoint = "127.0.0.1:{hub_port}"
[workspace.alpha]
[workspace.beta]
[agent.lan-a]
workspace = "alpha"
[[agent.lan-a.mesh_ingress]]
name = "svc"
listen = "127.0.0.1:{listen_port}"
target_agent = "lan-b"
remote_addr = "127.0.0.1:{echo_port}"
[agent.lan-b]
workspace = "beta"
[[agent.lan-b.mesh_egress]]
name = "svc"
target_addr = "127.0.0.1:{echo_port}"
"#
    ))
    .unwrap();

    let hub_dir = dir.path().join("packs/hub-central");
    HubCredentialPack::render(&issuer, &manifest, "central", 1, &hub_dir).unwrap();
    let pack_dir_a = dir.path().join("packs/agent-lan-a");
    AgentCredentialPack::render(&issuer, &manifest, "lan-a", 1, &pack_dir_a).unwrap();
    let pack_dir_b = dir.path().join("packs/agent-lan-b");
    AgentCredentialPack::render(&issuer, &manifest, "lan-b", 1, &pack_dir_b).unwrap();

    // Hub from the pack (config_path is only read on SIGHUP, which tests
    // never send).
    let hub_pack = CredentialPack::load_runtime(&hub_dir).unwrap();
    let hub_active = ActiveCredentialSet::load_or_bootstrap(&hub_pack).unwrap();
    let hub_config = build_hub_config(&hub_pack, &hub_active, &hub_dir).unwrap();
    let audit = AuditSink::spawn(&hub_config.audit);
    let hub = HubServer::new(hub_config, audit).unwrap();
    let (ready_tx, ready_rx) = tokio::sync::oneshot::channel();
    let shutdown = tokio_util::sync::CancellationToken::new();
    let hub_task = tokio::spawn(hub.run_until_signalled(shutdown.clone(), ready_tx));
    ready_rx.await.unwrap();

    // Agents from their packs.
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

    // Client on the alpha side connects to lan-a's listener; the payload
    // must come back through hub + both agents + inner TLS from the beta
    // side's echo server.
    let outcome = tokio::time::timeout(Duration::from_secs(30), async {
        let mut client = tokio::net::TcpStream::connect(("127.0.0.1", listen_port))
            .await
            .unwrap();
        client.write_all(b"ping-through-mesh").await.unwrap();
        let mut echoed = vec![0u8; b"ping-through-mesh".len()];
        client.read_exact(&mut echoed).await.unwrap();
        echoed
    })
    .await
    .unwrap();
    assert_eq!(outcome, b"ping-through-mesh");

    // Second stream on the same listener: the data plane keeps working.
    let outcome2 = tokio::time::timeout(Duration::from_secs(30), async {
        let mut client = tokio::net::TcpStream::connect(("127.0.0.1", listen_port))
            .await
            .unwrap();
        client.write_all(b"second-stream").await.unwrap();
        let mut echoed = vec![0u8; b"second-stream".len()];
        client.read_exact(&mut echoed).await.unwrap();
        echoed
    })
    .await
    .unwrap();
    assert_eq!(outcome2, b"second-stream");

    let _ = agent_a.shutdown_graceful().await;
    let _ = agent_b.shutdown_graceful().await;
    shutdown.cancel();
    let _ = hub_task.await;
}

/// Range egress at the render level: one `target_cidr` rule lands in the
/// engine as a Cidr egress rule plus the matching allowlist entry — the
/// chain manifest → pack → `SecurityConfig.allowed_targets` must carry the
/// range verbatim for `is_target_allowed` to widen against.
#[test]
fn pack_render_passes_cidr_authorization_from_the_manifest() {
    let hub_port = free_port();
    let any_loopback_port = free_port();
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
listen = "127.0.0.1:19001"
target_agent = "lan-b"
remote_addr = "127.0.0.1:{any_loopback_port}"
[agent.lan-b]
workspace = "main"
[[agent.lan-b.mesh_egress]]
name = "loopback"
target_cidr = "127.0.0.0/8"
udp_idle_timeout_secs = 90
"#
    ))
    .unwrap();

    let pack_dir_a = dir.path().join("packs/agent-lan-a");
    AgentCredentialPack::render(&issuer, &manifest, "lan-a", 1, &pack_dir_a).unwrap();
    let pack_dir_b = dir.path().join("packs/agent-lan-b");
    AgentCredentialPack::render(&issuer, &manifest, "lan-b", 1, &pack_dir_b).unwrap();

    let pack = CredentialPack::load_runtime(&pack_dir_b).unwrap();
    let active = ActiveCredentialSet::load_or_bootstrap(&pack).unwrap();
    let config = build_agent_config(&pack, &active, &pack_dir_b).unwrap();
    assert_eq!(config.security.allowed_targets, ["127.0.0.0/8"]);
    let rule = &config.egress[0];
    assert_eq!(rule.name, "loopback");
    assert!(matches!(
        rule.target,
        interflow_mesh::config::EgressTarget::Cidr(_)
    ));
    assert_eq!(rule.udp_idle_timeout_secs, Some(90));

    // The ingress side is unchanged by the peer's range offer.
    let pack = CredentialPack::load_runtime(&pack_dir_a).unwrap();
    let active = ActiveCredentialSet::load_or_bootstrap(&pack).unwrap();
    let config = build_agent_config(&pack, &active, &pack_dir_a).unwrap();
    assert!(config.security.allowed_targets.is_empty());
}

/// Range egress end to end: the serve side declares ONE loopback range and
/// no per-service rules; two ingress rules reach two different ports inside
/// the range — both forward. Adding the second service afterwards required
/// re-signing only the listen-side pack (the deployment gap this closes).
#[tokio::test]
async fn pack_site_to_site_range_authorizes_ports_without_per_service_egress() {
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
    let hub_port = free_port();
    let ollama_port = free_port();
    let tts_port = free_port();
    let listen_ollama = free_port();
    let listen_tts = free_port();

    let mut backends = Vec::new();
    for port in [ollama_port, tts_port] {
        let echo = tokio::net::TcpListener::bind(("127.0.0.1", port))
            .await
            .unwrap();
        let task = tokio::spawn(async move {
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
        backends.push(task);
    }

    let dir = tempfile::tempdir().unwrap();
    let issuer = IssuerStore::open(dir.path().join("issuer"));
    issuer.ensure_realm().unwrap();
    issuer.ensure_workspace("alpha").unwrap();
    issuer.ensure_workspace("beta").unwrap();
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
[workspace.alpha]
[workspace.beta]
[agent.lan-a]
workspace = "alpha"
[[agent.lan-a.mesh_ingress]]
name = "ollama"
listen = "127.0.0.1:{listen_ollama}"
target_agent = "lan-b"
remote_addr = "127.0.0.1:{ollama_port}"
[[agent.lan-a.mesh_ingress]]
name = "tts"
listen = "127.0.0.1:{listen_tts}"
target_agent = "lan-b"
remote_addr = "127.0.0.1:{tts_port}"
[agent.lan-b]
workspace = "beta"
[[agent.lan-b.mesh_egress]]
name = "loopback"
target_cidr = "127.0.0.0/8"
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

    for (port, payload) in [
        (listen_ollama, &b"via-ollama-range"[..]),
        (listen_tts, &b"via-tts-range"[..]),
    ] {
        let outcome = tokio::time::timeout(Duration::from_secs(30), async move {
            let mut client = tokio::net::TcpStream::connect(("127.0.0.1", port))
                .await
                .unwrap();
            client.write_all(payload).await.unwrap();
            let mut echoed = vec![0u8; payload.len()];
            client.read_exact(&mut echoed).await.unwrap();
            echoed
        })
        .await
        .unwrap();
        assert_eq!(outcome, payload);
    }

    let _ = agent_a.shutdown_graceful().await;
    let _ = agent_b.shutdown_graceful().await;
    shutdown.cancel();
    let _ = hub_task.await;
    for task in backends {
        task.abort();
    }
}

/// The manifest's idle knobs must survive the whole render chain: manifest
/// → Credential Pack → engine config. Unset stays unset (engine defaults
/// apply); set values arrive verbatim.
#[test]
fn pack_render_passes_idle_timeouts_from_the_manifest() {
    let hub_port = free_port();
    let silent_port = free_port();
    let delayed_port = free_port();
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
name = "tuned"
listen = "127.0.0.1:19001"
target_agent = "lan-b"
remote_addr = "127.0.0.1:{silent_port}"
idle_timeout_secs = 42
[[agent.lan-a.mesh_ingress]]
name = "default"
listen = "127.0.0.1:19002"
target_agent = "lan-b"
remote_addr = "127.0.0.1:{delayed_port}"
[agent.lan-b]
workspace = "main"
[[agent.lan-b.mesh_egress]]
name = "tuned"
target_addr = "127.0.0.1:{silent_port}"
udp_idle_timeout_secs = 7
[[agent.lan-b.mesh_egress]]
name = "default"
target_addr = "127.0.0.1:{delayed_port}"
"#
    ))
    .unwrap();

    let pack_dir_a = dir.path().join("packs/agent-lan-a");
    AgentCredentialPack::render(&issuer, &manifest, "lan-a", 1, &pack_dir_a).unwrap();
    let pack_dir_b = dir.path().join("packs/agent-lan-b");
    AgentCredentialPack::render(&issuer, &manifest, "lan-b", 1, &pack_dir_b).unwrap();

    for (pack_dir, expect_ingress) in [(&pack_dir_a, true), (&pack_dir_b, false)] {
        let pack = CredentialPack::load_runtime(pack_dir).unwrap();
        let active = ActiveCredentialSet::load_or_bootstrap(&pack).unwrap();
        let config = build_agent_config(&pack, &active, pack_dir).unwrap();
        if expect_ingress {
            let tuned = config.ingress.iter().find(|r| r.name == "tuned").unwrap();
            assert_eq!(tuned.idle_timeout_secs, Some(42));
            let default = config.ingress.iter().find(|r| r.name == "default").unwrap();
            assert_eq!(default.idle_timeout_secs, None);
        } else {
            let tuned = config.egress.iter().find(|r| r.name == "tuned").unwrap();
            assert_eq!(tuned.udp_idle_timeout_secs, Some(7));
            let default = config.egress.iter().find(|r| r.name == "default").unwrap();
            assert_eq!(default.udp_idle_timeout_secs, None);
        }
    }
}

/// The budget the manifest declares is the budget the stream lives by: a
/// silent stream is cut at `idle_timeout_secs`, and the same silence is
/// harmless once the rule raises it. (The default 5m semantics are covered
/// by the engine's own unit tests — here the knobs are small on purpose.)
#[tokio::test]
async fn pack_site_to_site_idle_timeout_cuts_silent_streams_and_spares_raised_ones() {
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
    let hub_port = free_port();
    let silent_port = free_port();
    let delayed_port = free_port();
    let listen_cut = free_port();
    let listen_keep = free_port();

    // Backend 1: accepts, reads, never speaks.
    let silent = tokio::net::TcpListener::bind(("127.0.0.1", silent_port))
        .await
        .unwrap();
    tokio::spawn(async move {
        loop {
            let Ok((mut sock, _)) = silent.accept().await else {
                break;
            };
            tokio::spawn(async move {
                let mut buf = [0u8; 1024];
                loop {
                    match sock.read(&mut buf).await {
                        Ok(0) | Err(_) => break,
                        Ok(_) => {}
                    }
                }
            });
        }
    });

    // Backend 2: accepts, reads, stays silent for 3s, then echoes — the
    // "non-streaming LLM call" shape.
    let delayed = tokio::net::TcpListener::bind(("127.0.0.1", delayed_port))
        .await
        .unwrap();
    tokio::spawn(async move {
        loop {
            let Ok((mut sock, _)) = delayed.accept().await else {
                break;
            };
            tokio::spawn(async move {
                let mut buf = [0u8; 1024];
                if sock.read(&mut buf).await.is_ok() {
                    tokio::time::sleep(Duration::from_secs(3)).await;
                    let _ = sock.write_all(&buf).await;
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
name = "cut"
listen = "127.0.0.1:{listen_cut}"
target_agent = "lan-b"
remote_addr = "127.0.0.1:{silent_port}"
idle_timeout_secs = 2
[[agent.lan-a.mesh_ingress]]
name = "keep"
listen = "127.0.0.1:{listen_keep}"
target_agent = "lan-b"
remote_addr = "127.0.0.1:{delayed_port}"
idle_timeout_secs = 30
[agent.lan-b]
workspace = "main"
[[agent.lan-b.mesh_egress]]
name = "cut"
target_addr = "127.0.0.1:{silent_port}"
[[agent.lan-b.mesh_egress]]
name = "keep"
target_addr = "127.0.0.1:{delayed_port}"
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

    // Cut: the 2s budget, not an error, ends the stream — EOF arrives
    // around the budget, never instantly.
    let began = std::time::Instant::now();
    let cut = tokio::time::timeout(Duration::from_secs(15), async {
        let mut client = tokio::net::TcpStream::connect(("127.0.0.1", listen_cut))
            .await
            .unwrap();
        client.write_all(b"anybody-there").await.unwrap();
        let mut buf = [0u8; 16];
        client.read(&mut buf).await.unwrap()
    })
    .await
    .unwrap();
    let elapsed = began.elapsed();
    assert_eq!(cut, 0, "the idle budget must end the stream with EOF");
    assert!(
        elapsed >= Duration::from_secs(1),
        "stream died at {elapsed:?} — that is not the 2s budget cutting it"
    );
    assert!(
        elapsed <= Duration::from_secs(6),
        "stream survived {elapsed:?} — the 2s budget did not cut it"
    );

    // Keep: 3s of silence under a 30s budget; the late response flows.
    let kept = tokio::time::timeout(Duration::from_secs(15), async {
        let mut client = tokio::net::TcpStream::connect(("127.0.0.1", listen_keep))
            .await
            .unwrap();
        client.write_all(b"late-echo").await.unwrap();
        let mut echoed = vec![0u8; b"late-echo".len()];
        client.read_exact(&mut echoed).await.unwrap();
        echoed
    })
    .await
    .unwrap();
    assert_eq!(kept, b"late-echo");

    let _ = agent_a.shutdown_graceful().await;
    let _ = agent_b.shutdown_graceful().await;
    shutdown.cancel();
    let _ = hub_task.await;
}

/// Signs a policy update and drops it into an agent pack's `state/policy`
/// update channel.
fn drop_policy_update(issuer: &IssuerStore, pack_dir: &Path, generation: u64, manifest: &Manifest) {
    let policy = interflow_identity::policy::RuntimePolicy::from_manifest(manifest, generation);
    let signer = issuer.policy_signer().unwrap();
    let (bytes, signature) = policy.signed(&signer).unwrap();
    let dir = pack_dir.join("state/policy");
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(dir.join("policy.toml"), bytes).unwrap();
    std::fs::write(dir.join("policy.sig"), signature).unwrap();
}

/// The policy-identity separation acceptance: a signed policy update
/// dropped into `state/policy` hot-applies on a RUNNING agent — a new
/// service answers without restart or pack swap, a removed service stops
/// accepting, an established stream on the removed service drains
/// naturally, and a tampered follow-up keeps the current policy serving.
#[tokio::test]
async fn policy_update_hot_reloads_rules_without_pack_swap() {
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
    let hub_port = free_port();
    let ollama_port = free_port();
    let tts_port = free_port();
    let listen_a = free_port();
    let listen_b = free_port();

    let mut backends = Vec::new();
    for port in [ollama_port, tts_port] {
        let echo = tokio::net::TcpListener::bind(("127.0.0.1", port))
            .await
            .unwrap();
        backends.push(tokio::spawn(async move {
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
        }));
    }

    let dir = tempfile::tempdir().unwrap();
    let issuer = IssuerStore::open(dir.path().join("issuer"));
    issuer.ensure_realm().unwrap();
    issuer.ensure_workspace("main").unwrap();
    issuer.ensure_policy_key().unwrap();

    let manifest_text = |remote_port: u16, listen_port: u16| {
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
remote_addr = "127.0.0.1:{remote_port}"
[agent.lan-b]
workspace = "main"
[[agent.lan-b.mesh_egress]]
name = "svc"
target_addr = "127.0.0.1:{remote_port}"
"#
        )
    };
    let manifest_v1 = Manifest::parse(&manifest_text(ollama_port, listen_a)).unwrap();
    // v2 replaces the offer: svc-a gone, svc-b (different backend + listen)
    // in its place — the TTS scenario.
    let manifest_v2 = Manifest::parse(&manifest_text(tts_port, listen_b)).unwrap();

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

    // The REAL start path: the engine arms the policy watcher from the
    // config's policy plane — the same path the CLI binary and the GUI
    // take (no test-local wiring left to drift from production).
    let start = |pack_dir: &Path| {
        let pack = CredentialPack::load_runtime(pack_dir).unwrap();
        let active = ActiveCredentialSet::load_or_bootstrap(&pack).unwrap();
        let config = build_agent_config(&pack, &active, pack_dir).unwrap();
        let agent = AgentClient::new(config).unwrap().start();
        assert!(
            agent.policy_state().is_some(),
            "a pack-built config arms the policy watcher at start"
        );
        agent
    };
    let agent_b = start(&pack_dir_b);
    wait_connected(&agent_b).await;
    let agent_a = start(&pack_dir_a);
    wait_connected(&agent_a).await;

    // Baseline: svc-a forwards.
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
        tokio::time::timeout(Duration::from_secs(30), round_trip(listen_a, b"via-a-v1"))
            .await
            .unwrap()
            .unwrap(),
        b"via-a-v1"
    );

    // An established svc-a stream that must survive the reload and drain
    // naturally (new flows are what a removed service rejects).
    let mut established = tokio::net::TcpStream::connect(("127.0.0.1", listen_a))
        .await
        .unwrap();
    established.write_all(b"established").await.unwrap();
    let mut echoed = vec![0u8; b"established".len()];
    established.read_exact(&mut echoed).await.unwrap();
    assert_eq!(echoed, b"established");

    // The signed update: generation 2, both agents' update channels.
    drop_policy_update(&issuer, &pack_dir_a, 2, &manifest_v2);
    drop_policy_update(&issuer, &pack_dir_b, 2, &manifest_v2);

    // The new service answers without restart or pack swap (the watcher
    // polls every 10s; allow generous margin).
    let deadline = tokio::time::Instant::now() + Duration::from_secs(60);
    let mut live_b = false;
    while tokio::time::Instant::now() < deadline {
        if let Ok(Ok(got)) =
            tokio::time::timeout(Duration::from_secs(5), round_trip(listen_b, b"via-b-v2")).await
            && got == b"via-b-v2"
        {
            live_b = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(500)).await;
    }
    assert!(live_b, "svc-b must hot-apply without a restart");

    // The removed service stops accepting new flows...
    assert!(
        tokio::net::TcpStream::connect(("127.0.0.1", listen_a))
            .await
            .is_err(),
        "svc-a's listener must be gone after the reload"
    );
    // ...while the established stream drains naturally.
    established.write_all(b"post-reload").await.unwrap();
    let mut drained = vec![0u8; b"post-reload".len()];
    tokio::time::timeout(
        Duration::from_secs(10),
        established.read_exact(&mut drained),
    )
    .await
    .unwrap()
    .unwrap();
    assert_eq!(drained, b"post-reload");

    // A tampered follow-up is rejected and the current policy keeps
    // serving: svc-b still answers, svc-a stays gone.
    drop_policy_update(&issuer, &pack_dir_a, 3, &manifest_v1);
    let tampered = pack_dir_a.join("state/policy/policy.toml");
    let mut bytes = std::fs::read(&tampered).unwrap();
    bytes[0] ^= 0xff;
    std::fs::write(&tampered, bytes).unwrap();
    tokio::time::sleep(Duration::from_secs(15)).await;
    assert_eq!(
        tokio::time::timeout(Duration::from_secs(10), round_trip(listen_b, b"still-v2"))
            .await
            .unwrap()
            .unwrap(),
        b"still-v2"
    );
    assert!(
        tokio::net::TcpStream::connect(("127.0.0.1", listen_a))
            .await
            .is_err()
    );

    // The watchers ride the agents' own task groups — agent shutdown ends them.
    let _ = agent_a.shutdown_graceful().await;
    let _ = agent_b.shutdown_graceful().await;
    shutdown.cancel();
    let _ = hub_task.await;
    for task in backends {
        task.abort();
    }
}

/// A same-port rule rename is a remove+add pair in one policy generation.
/// The reconciler's ordering contract (ingress.rs): the removal loop runs
/// before the add loop within a single pass and `stop_and_reap` is
/// abort+await, so the port is unserved only for the in-pass handoff —
/// never a watcher-interval hole. Locked here because a future reordering
/// (stop deferred to the next tick, or bind-new-first across names where
/// the new bind conflicts with the still-held port) would silently
/// reintroduce a multi-second hole; the bound below sits two orders of
/// magnitude under the 10s watcher interval such a regression would
/// produce, while staying above any legitimate round-trip jitter on a
/// starved 2-vCPU runner.
#[tokio::test]
async fn rule_rename_same_port_serves_through_the_handoff() {
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
    let hub_port = free_port();
    let backend_port = free_port();
    let listen_a = free_port();

    let echo = tokio::net::TcpListener::bind(("127.0.0.1", backend_port))
        .await
        .unwrap();
    let backend = tokio::spawn(async move {
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

    // v2 renames ONLY the source-side rule name — port, pairing, and the
    // serve-side offer are untouched (ingress and egress rule names are
    // independent identities; only the stream name moves).
    let manifest_text = |rule: &str| {
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
name = "{rule}"
listen = "127.0.0.1:{listen_a}"
target_agent = "lan-b"
remote_addr = "127.0.0.1:{backend_port}"
[agent.lan-b]
workspace = "main"
[[agent.lan-b.mesh_egress]]
name = "svc"
target_addr = "127.0.0.1:{backend_port}"
"#
        )
    };
    let manifest_v1 = Manifest::parse(&manifest_text("svc")).unwrap();
    let manifest_v2 = Manifest::parse(&manifest_text("svc2")).unwrap();

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

    // Baseline: the stream forwards.
    let mut probe = tokio::net::TcpStream::connect(("127.0.0.1", listen_a))
        .await
        .unwrap();
    probe.write_all(b"baseline").await.unwrap();
    let mut echoed = vec![0u8; b"baseline".len()];
    probe.read_exact(&mut echoed).await.unwrap();
    assert_eq!(echoed, b"baseline");
    drop(probe);

    // An established stream that must survive the rename: the removed-name
    // listener task is aborted, but its connection pumps hang off the
    // session tracker — the same drain semantics as a removed service.
    let mut established = tokio::net::TcpStream::connect(("127.0.0.1", listen_a))
        .await
        .unwrap();
    established.write_all(b"established").await.unwrap();
    let mut echoed = vec![0u8; b"established".len()];
    established.read_exact(&mut echoed).await.unwrap();
    assert_eq!(echoed, b"established");

    // Continuous dialer: a full connect→echo round trip counts as served;
    // any failure opens (or extends) a gap measured to the next success.
    let (stop_tx, mut stop_rx) = tokio::sync::mpsc::channel::<()>(1);
    let dialer = tokio::spawn(async move {
        let mut worst_gap = Duration::ZERO;
        let mut gap_start: Option<tokio::time::Instant> = None;
        let mut failed_dials = 0u64;
        loop {
            let attempt = async {
                let mut client = tokio::net::TcpStream::connect(("127.0.0.1", listen_a)).await?;
                client.write_all(b"ping").await?;
                let mut echoed = [0u8; 4];
                client.read_exact(&mut echoed).await?;
                Ok::<(), std::io::Error>(())
            };
            tokio::select! {
                _ = stop_rx.recv() => break,
                res = attempt => {
                    if matches!(res, Ok(())) {
                        if let Some(t0) = gap_start.take() {
                            worst_gap = worst_gap.max(t0.elapsed());
                        }
                    } else {
                        failed_dials += 1;
                        gap_start.get_or_insert_with(tokio::time::Instant::now);
                        tokio::time::sleep(Duration::from_millis(5)).await;
                    }
                }
            }
        }
        (worst_gap, failed_dials)
    });

    // The signed rename: generation 2 on both update channels (the
    // serve-side table is unchanged; production publishes to everyone).
    drop_policy_update(&issuer, &pack_dir_a, 2, &manifest_v2);
    drop_policy_update(&issuer, &pack_dir_b, 2, &manifest_v2);

    // Land it: the listener face shows the new name — and because the
    // removal loop precedes the add loop, svc2 bound implies svc gone.
    let deadline = tokio::time::Instant::now() + Duration::from_secs(60);
    loop {
        let snapshot = agent_a.ingress_listeners_snapshot();
        if snapshot.contains_key("svc2") {
            assert!(
                !snapshot.contains_key("svc"),
                "the old name must be removed in the same reconcile pass"
            );
            break;
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "rename never applied to the listener face (snapshot: {snapshot:?})"
        );
        tokio::time::sleep(Duration::from_millis(200)).await;
    }

    // Settle beat past the handoff, then collect the dialer's verdict.
    tokio::time::sleep(Duration::from_secs(2)).await;
    let _ = stop_tx.send(()).await;
    let (worst_gap, failed_dials) = dialer.await.unwrap();
    assert!(
        worst_gap < Duration::from_secs(2),
        "same-port rename left the port unserved for {worst_gap:?} \
         ({failed_dials} failed dials) — the reconcile pass must stop the \
         old name and bind the new one back to back"
    );

    // The established stream drains through the rename.
    established.write_all(b"post-rename").await.unwrap();
    let mut drained = vec![0u8; b"post-rename".len()];
    tokio::time::timeout(
        Duration::from_secs(10),
        established.read_exact(&mut drained),
    )
    .await
    .unwrap()
    .unwrap();
    assert_eq!(drained, b"post-rename");

    let _ = agent_a.shutdown_graceful().await;
    let _ = agent_b.shutdown_graceful().await;
    shutdown.cancel();
    let _ = hub_task.await;
    backend.abort();
}

/// The 2026-10-07 hot-reapply incident, machine-locked: a policy update
/// that only touches a CONNECTION-level knob of an EXISTING stream
/// (`idle_timeout_secs`, same name/listen/target) must hot-apply without
/// the listener ever moving — the old whole-struct diff treated this as a
/// replace and its close-then-rebind order could silently drop the
/// listener.
/// The new knob must also actually reach new connections (a silent no-op
/// would pass a mere "listener survived" check).
#[tokio::test]
async fn policy_param_change_hot_applies_without_listener_restart() {
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
    let hub_port = free_port();
    let echo_port = free_port();
    let listen_port = free_port();

    // The service behind lan-b: a plain TCP echo server.
    let echo = tokio::net::TcpListener::bind(("127.0.0.1", echo_port))
        .await
        .unwrap();
    let backend = tokio::spawn(async move {
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

    // Same shape for both generations — v2 differs ONLY in the knob.
    let manifest_text = |idle: Option<u64>| {
        let idle_line = match idle {
            Some(secs) => format!("idle_timeout_secs = {secs}"),
            None => String::new(),
        };
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
{idle_line}
[agent.lan-b]
workspace = "main"
[[agent.lan-b.mesh_egress]]
name = "svc"
target_addr = "127.0.0.1:{echo_port}"
"#
        )
    };
    let manifest_v1 = Manifest::parse(&manifest_text(None)).unwrap();
    // The incident's exact shape: connection-level param only. 2s so the
    // assertion can observe it (the tcp default is 300s).
    let manifest_v2 = Manifest::parse(&manifest_text(Some(2))).unwrap();

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

    let round_trip = |port: u16, payload: &[u8]| {
        let payload = payload.to_vec();
        async move {
            let mut client = tokio::net::TcpStream::connect(("127.0.0.1", port)).await?;
            client.write_all(&payload).await?;
            let mut echoed = vec![0u8; payload.len()];
            client.read_exact(&mut echoed).await?;
            Ok::<(tokio::net::TcpStream, Vec<u8>), std::io::Error>((client, echoed))
        }
    };

    // Baseline: the listener serves v1.
    let (_, echoed) =
        tokio::time::timeout(Duration::from_secs(30), round_trip(listen_port, b"via-v1"))
            .await
            .unwrap()
            .unwrap();
    assert_eq!(echoed, b"via-v1");

    // The signed update: generation 2, param-only change on the SAME
    // stream (the watcher polls every 10s; allow generous margin).
    drop_policy_update(&issuer, &pack_dir_a, 2, &manifest_v2);
    drop_policy_update(&issuer, &pack_dir_b, 2, &manifest_v2);
    let state_toml = pack_dir_a.join("state/policy/policy.toml");
    let deadline = tokio::time::Instant::now() + Duration::from_secs(60);
    loop {
        let applied =
            std::fs::read_to_string(&state_toml).is_ok_and(|body| body.contains("generation = 2"));
        if applied {
            break;
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "param-only policy update never applied (state file: {:?})",
            std::fs::read_to_string(&state_toml).ok()
        );
        tokio::time::sleep(Duration::from_millis(500)).await;
    }

    // The listener never moved: the SAME port still round-trips (this is
    // the assertion the incident failed — state said gen 8 while 9091 was
    // gone), and the actual-state face reports the rule bound.
    let (_, echoed) =
        tokio::time::timeout(Duration::from_secs(10), round_trip(listen_port, b"via-v2"))
            .await
            .unwrap()
            .unwrap();
    assert_eq!(echoed, b"via-v2");
    let status = agent_a.ingress_listener_status("svc").expect("status face");
    assert_eq!(
        status.bound_addr,
        Some(format!("127.0.0.1:{listen_port}").parse().unwrap())
    );
    assert_eq!(status.last_error, None);

    // And the knob must actually reach connections opened after the
    // change — poll with FRESH connections (the state file lands a moment
    // before the runtime face moves; a connection opened in that gap
    // serves the old budget). Under v2's 2s idle budget a silent post-echo
    // connection closes fast; v1's 300s default never does — a silent
    // no-op "keep the listener" fix passes everything above and fails
    // exactly here.
    let deadline = tokio::time::Instant::now() + Duration::from_secs(30);
    let mut knob_live = false;
    while tokio::time::Instant::now() < deadline {
        if let Ok(Ok((mut probe, echoed))) = tokio::time::timeout(
            Duration::from_secs(5),
            round_trip(listen_port, b"idle-probe"),
        )
        .await
            && echoed == b"idle-probe"
        {
            let mut buf = [0u8; 8];
            if tokio::time::timeout(Duration::from_secs(6), probe.read(&mut buf))
                .await
                .is_ok()
            {
                knob_live = true;
                break;
            }
        }
        tokio::time::sleep(Duration::from_millis(500)).await;
    }
    assert!(
        knob_live,
        "hot-applied 2s idle timeout never reached new connections"
    );

    let _ = agent_a.shutdown_graceful().await;
    let _ = agent_b.shutdown_graceful().await;
    shutdown.cancel();
    let _ = hub_task.await;
    backend.abort();
}

/// One raw one-shot mTLS request against the hub (test-side transport for
/// the register-gate assertion; the publish cases go through the real
/// `publish_policy` client).
async fn hub_mtls_request(
    hub_port: u16,
    ca: &std::path::Path,
    cert: &std::path::Path,
    key: &std::path::Path,
    method: &str,
    path: &str,
) -> (u16, String) {
    use http_body_util::BodyExt;
    use hyper_util::rt::{TokioExecutor, TokioIo};
    let tls_config = interflow_core::tls::client::build_client_config(
        None,
        Some(&ca.display().to_string()),
        Some(&cert.display().to_string()),
        Some(&key.display().to_string()),
        &["h2"],
    )
    .unwrap();
    let connector = tokio_rustls::TlsConnector::from(std::sync::Arc::new(tls_config));
    let stream = tokio::net::TcpStream::connect(("127.0.0.1", hub_port))
        .await
        .unwrap();
    let name = rustls::pki_types::ServerName::try_from("127.0.0.1")
        .unwrap()
        .to_owned();
    let tls = connector.connect(name, stream).await.unwrap();
    let (mut send, conn) = hyper::client::conn::http2::Builder::new(TokioExecutor::new())
        .handshake::<_, interflow_core::tunnel::H2RequestBody>(TokioIo::new(tls))
        .await
        .unwrap();
    tokio::spawn(async move {
        let _ = conn.await;
    });
    let body = http_body_util::Full::new(bytes::Bytes::new())
        .map_err(|never| match never {})
        .boxed();
    let request = hyper::Request::builder()
        .method(method)
        .uri(path)
        .header("x-agent-id", "plan-apply")
        .body(body)
        .unwrap();
    let response = send.send_request(request).await.unwrap();
    let status = response.status().as_u16();
    let body = response.into_body();
    let collected = body.collect().await.unwrap();
    (
        status,
        String::from_utf8_lossy(&collected.to_bytes()).into_owned(),
    )
}

/// Materializes a principal's credentials + the realm anchor for the
/// publish client (files, 0600 on the key).
fn materialize_creds(
    dir: &std::path::Path,
    issuer: &IssuerStore,
    realm: &str,
) -> (std::path::PathBuf, std::path::PathBuf, std::path::PathBuf) {
    use interflow_identity::issuance::LeafTtl;
    let ttl = LeafTtl::new(time::Duration::hours(1));
    let material = issuer
        .issue_hub_member_with_ttl(realm, "plan-apply", ttl)
        .unwrap();
    let ca = dir.join("ca.crt");
    let cert = dir.join("client.crt");
    let key = dir.join("client.key");
    std::fs::write(&ca, issuer.realm_issuer().unwrap().cert_pem()).unwrap();
    std::fs::write(&cert, &material.chain_pem).unwrap();
    std::fs::write(&key, &material.key_pem).unwrap();
    (ca, cert, key)
}

/// The `PUT /policy` control plane: the hub verifies the policy signature
/// against the trust bundle's key, enforces the monotonic generation, and
/// persists accepted bundles into its state channel — while rejecting
/// rollbacks (409 + floor), tampered signatures (400), workspace
/// principals (403), and control principals on the data plane (register
/// 403).
#[tokio::test]
async fn policy_publish_endpoint_verifies_persists_and_rejects() {
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
    let hub_port = free_port();

    let dir = tempfile::tempdir().unwrap();
    let issuer = IssuerStore::open(dir.path().join("issuer"));
    issuer.ensure_realm().unwrap();
    issuer.ensure_workspace("main").unwrap();
    issuer.ensure_policy_key().unwrap();

    let manifest_text = |remote_port: u16| {
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
[agent.leo]
workspace = "main"
[[agent.leo.mesh_ingress]]
name = "svc"
listen = "127.0.0.1:13001"
target_agent = "home"
remote_addr = "127.0.0.1:{remote_port}"
[agent.home]
workspace = "main"
[[agent.home.mesh_egress]]
name = "svc"
target_addr = "127.0.0.1:{remote_port}"
"#
        )
    };
    let manifest_v1 = Manifest::parse(&manifest_text(3000)).unwrap();
    let manifest_v2 = Manifest::parse(&manifest_text(9443)).unwrap();

    let hub_dir = dir.path().join("packs/hub-central");
    HubCredentialPack::render(&issuer, &manifest_v1, "central", 1, &hub_dir).unwrap();

    let hub_pack = CredentialPack::load_runtime(&hub_dir).unwrap();
    let hub_active = ActiveCredentialSet::load_or_bootstrap(&hub_pack).unwrap();
    let hub_config = build_hub_config(&hub_pack, &hub_active, &hub_dir).unwrap();
    // The publication face rides the pack-derived config.
    assert!(hub_config.policy.verifier_key_hex.is_some());
    assert_eq!(hub_config.policy.generation, 1);
    assert_eq!(hub_config.auth.tenants.len(), 2, "main + control");
    let audit = AuditSink::spawn(&hub_config.audit);
    let hub = HubServer::new(hub_config, audit).unwrap();
    let (ready_tx, ready_rx) = tokio::sync::oneshot::channel();
    let shutdown = tokio_util::sync::CancellationToken::new();
    let hub_task = tokio::spawn(hub.run_until_signalled(shutdown.clone(), ready_tx));
    ready_rx.await.unwrap();

    // Control credentials for the publisher.
    let creds_dir = dir.path().join("publish-creds");
    std::fs::create_dir_all(&creds_dir).unwrap();
    let (ca, cert, key) = materialize_creds(&creds_dir, &issuer, "test");

    // A control principal cannot register as a data-plane agent.
    let (status, _) = hub_mtls_request(hub_port, &ca, &cert, &key, "POST", "/register").await;
    assert_eq!(status, 403, "control principals must not register");

    // Sign + publish generation 2 → accepted, persisted, floor advances.
    let policy_v2 = interflow_identity::policy::RuntimePolicy::from_manifest(&manifest_v2, 2);
    let (bytes_v2, sig_v2) = policy_v2.signed(&issuer.policy_signer().unwrap()).unwrap();
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
    assert!(hub_dir.join("state/policy/policy.toml").is_file());
    assert!(hub_dir.join("state/policy/policy.sig").is_file());

    // A rolled-back bundle → 409 carrying the floor.
    let policy_v1_again = interflow_identity::policy::RuntimePolicy::from_manifest(&manifest_v1, 1);
    let (bytes_v1, sig_v1) = policy_v1_again
        .signed(&issuer.policy_signer().unwrap())
        .unwrap();
    let outcome = interflow_mesh::hub::policy::publish_policy(
        &format!("127.0.0.1:{hub_port}"),
        &ca,
        &cert,
        &key,
        &bytes_v1,
        &sig_v1,
    )
    .await
    .unwrap();
    assert_eq!(
        outcome,
        interflow_mesh::hub::policy::PublishOutcome::RollbackConflict {
            current_generation: 2
        }
    );

    // A tampered signature → rejected with a named error. A refusal is an
    // OUTCOME (not a transport error): retrying the same bytes cannot
    // succeed and the reason travels with the result.
    let mut tampered = bytes_v2.clone();
    tampered[0] ^= 0xff;
    let outcome = interflow_mesh::hub::policy::publish_policy(
        &format!("127.0.0.1:{hub_port}"),
        &ca,
        &cert,
        &key,
        &tampered,
        &sig_v2,
    )
    .await
    .unwrap();
    assert!(
        matches!(
            &outcome,
            interflow_mesh::hub::policy::PublishOutcome::Rejected { status: 400, .. }
        ),
        "tampered policy must be rejected as a 400 refusal: {outcome:?}"
    );

    // The floor query: the control-plane watermark the next mint must
    // clear — 2 after the accepted publish above. Same mTLS dial as the
    // publisher. `serving` must report the same generation: the accepted
    // publish is what the hub serves right now (the floor/serving pair is
    // the no-op gate's split detector — a divergence here is the
    // lineage-loss signature).
    let watermarks = interflow_mesh::hub::policy::query_policy_floor(
        &format!("127.0.0.1:{hub_port}"),
        &ca,
        &cert,
        &key,
    )
    .await
    .unwrap();
    assert_eq!(
        watermarks.floor, 2,
        "the floor must name the accepted generation"
    );
    assert_eq!(
        watermarks.serving,
        Some(2),
        "the hub must report the generation it actually serves"
    );

    // A workspace principal (an agent's own credential — straight from its
    // pack) must not publish: a compromised agent box cannot widen its own
    // authorization. Nor may it read the floor (control-plane face).
    let home_dir = dir.path().join("packs/agent-home");
    AgentCredentialPack::render(&issuer, &manifest_v1, "home", 1, &home_dir).unwrap();
    let agent_cert = home_dir.join("identity/agent-main.crt");
    let agent_key = home_dir.join("identity/agent-main.key");
    let outcome = interflow_mesh::hub::policy::publish_policy(
        &format!("127.0.0.1:{hub_port}"),
        &ca,
        &agent_cert,
        &agent_key,
        &bytes_v2,
        &sig_v2,
    )
    .await
    .unwrap();
    assert!(
        matches!(
            &outcome,
            interflow_mesh::hub::policy::PublishOutcome::Rejected { status: 403, .. }
        ),
        "an agent principal must not publish policy: {outcome:?}"
    );
    let err = interflow_mesh::hub::policy::query_policy_floor(
        &format!("127.0.0.1:{hub_port}"),
        &ca,
        &agent_cert,
        &agent_key,
    )
    .await
    .unwrap_err();
    assert!(
        err.to_string().contains("403"),
        "an agent principal must not query the floor: {err}"
    );

    shutdown.cancel();
    let _ = hub_task.await;
}

/// The zero-touch acceptance: an update PUBLISHED at the hub reaches both
/// agents over the control plane — no file drops, no restarts, no pack
/// swaps — and an agent that was offline during the publish catches up to
/// the latest generation on connect (never replaying intermediate ones).
/// Existing streams survive the change.
#[tokio::test]
async fn hub_published_policy_reaches_agents_over_the_control_plane() {
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
    let hub_port = free_port();
    let backend_v1 = free_port();
    let backend_v2 = free_port();
    let listen_v1 = free_port();
    let listen_v2 = free_port();

    let mut backends = Vec::new();
    for port in [backend_v1, backend_v2] {
        let echo = tokio::net::TcpListener::bind(("127.0.0.1", port))
            .await
            .unwrap();
        backends.push(tokio::spawn(async move {
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
        }));
    }

    let dir = tempfile::tempdir().unwrap();
    let issuer = IssuerStore::open(dir.path().join("issuer"));
    issuer.ensure_realm().unwrap();
    issuer.ensure_workspace("main").unwrap();
    issuer.ensure_policy_key().unwrap();

    let manifest_text = |listen_port: u16, remote_port: u16| {
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
remote_addr = "127.0.0.1:{remote_port}"
[agent.lan-b]
workspace = "main"
[[agent.lan-b.mesh_egress]]
name = "svc"
target_addr = "127.0.0.1:{remote_port}"
"#
        )
    };
    let manifest_v1 = Manifest::parse(&manifest_text(listen_v1, backend_v1)).unwrap();
    let manifest_v2 = Manifest::parse(&manifest_text(listen_v2, backend_v2)).unwrap();

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
    // lan-b starts "offline" — it comes up only AFTER the publish below.
    let (agent_a, watch_state_a) = start(&pack_dir_a);
    wait_connected(&agent_a).await;

    // Baseline through lan-b? Not yet online — start it for the baseline,
    // then take it down conceptually: the catch-up story is that a FRESH
    // lan-b (restarted, embedded generation 1) converges via pull.
    let (agent_b, _) = start(&pack_dir_b);
    wait_connected(&agent_b).await;

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

    // Both agents hot-apply from the hub within a watch interval.
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
    assert!(
        live,
        "the published policy must reach both agents untouched"
    );
    assert!(
        tokio::net::TcpStream::connect(("127.0.0.1", listen_v1))
            .await
            .is_err(),
        "the old listener must be gone"
    );

    // Offline catch-up: a FRESH lan-b (embedded generation 1, pack never
    // touched) converges to the latest generation through its first
    // connected ticks — the "skipped intermediate versions" contract.
    let _ = agent_b.shutdown_graceful().await;
    // Give the hub a moment to age the old registration out; the fresh
    // session re-registers anyway.
    tokio::time::sleep(Duration::from_secs(1)).await;
    let (agent_b2, _watch_state_b2) = start(&pack_dir_b);
    wait_connected(&agent_b2).await;
    let deadline = tokio::time::Instant::now() + Duration::from_secs(45);
    let mut caught_up = false;
    while tokio::time::Instant::now() < deadline {
        if let Ok(Ok(got)) =
            tokio::time::timeout(Duration::from_secs(5), round_trip(listen_v2, b"caught-up")).await
            && got == b"caught-up"
        {
            caught_up = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(500)).await;
    }
    assert!(caught_up, "a restarted agent must pull the latest policy");

    // The hub's audit trail carries the distribution as STATE TRANSITIONS
    // (the writer is async — poll until both agents have landed gen 2):
    // one `policy_pulled` record per (agent, generation), never per tick.
    let read_audit = || -> Vec<serde_json::Value> {
        std::fs::read_to_string(hub_dir.join("audit.jsonl"))
            .unwrap_or_default()
            .lines()
            .filter_map(|line| serde_json::from_str(line).ok())
            .collect()
    };
    let policy_pull_pairs = |lines: &[serde_json::Value]| -> Vec<(String, u64)> {
        lines
            .iter()
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
        if (
            policy_pull_pairs(&read_audit()).contains(&("main/lan-a".to_owned(), 2u64)),
            policy_pull_pairs(&read_audit()).contains(&("main/lan-b".to_owned(), 2u64)),
        ) == (true, true)
        {
            break;
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "gen 2 never reached both agents in the audit: {:?}",
            policy_pull_pairs(&read_audit())
        );
        tokio::time::sleep(Duration::from_millis(500)).await;
    }

    // Exact accounting across the whole run so far. Gen 1 NEVER appears:
    // the agents' packs carry it from issuance (their first pull presents
    // x-policy-seen=1 and gets 304 — not a hub distribution event). The
    // only ledger events are the generations the hub actually served:
    // gen 2 to each agent, once. The catch-up restarts (lan-b's two)
    // added nothing: a reconnecting agent already holding the serving
    // generation is a 304, not a ledger event.
    let pairs = policy_pull_pairs(&read_audit());
    for pair in [("main/lan-a", 2u64), ("main/lan-b", 2)] {
        assert_eq!(
            pairs.iter().filter(|p| (p.0.as_str(), p.1) == pair).count(),
            1,
            "pair {pair:?} must appear exactly once: {pairs:?}"
        );
    }
    assert_eq!(pairs.len(), 2, "no extra policy_pulled records: {pairs:?}");
    assert!(
        read_audit()
            .iter()
            .any(|v| v.get("kind").and_then(|k| k.as_str()) == Some("policy_published"))
    );

    // The operator overview (the GUI Apply-result/convergence card's data
    // source): the same control-credential floor query's full view — both
    // agents present, ONLINE (session presence, not just registration),
    // and their pulled watermarks at the served generation 2. This is the
    // "did every node receive generation N" answer rendered end to end.
    let overview = interflow_mesh::hub::policy::query_hub_overview(
        &format!("127.0.0.1:{hub_port}"),
        &ca,
        &cert,
        &key,
    )
    .await
    .unwrap();
    assert_eq!(overview.floor, 2, "overview floor mirrors the floor query");
    assert_eq!(overview.serving, Some(2));
    // The answer self-reports the answering hub's declared name — the
    // GUI keys row attribution on exactly this field.
    assert_eq!(
        overview.hub,
        Some("central".to_owned()),
        "overview must self-report the declared hub name"
    );
    for expected in ["main/lan-a", "main/lan-b"] {
        let row = overview
            .agents
            .iter()
            .find(|a| a.agent == expected)
            .unwrap_or_else(|| panic!("overview must list {expected}: {:?}", overview.agents));
        assert!(row.online, "{expected} must read online: {row:?}");
        assert_eq!(
            row.seen,
            Some(2),
            "{expected} must have pulled gen 2: {row:?}"
        );
    }

    // The fleet snapshot face (`GET /snapshot`) against the same live hub:
    // the upgrade-acceptance data plane. The published gen 2 lives in the
    // state channel, so the lineage origin must read state_lineage (the
    // same answer the boot journal line gives — asserted here as the
    // product's machine-readable form of that line); both legs carry a
    // session row (transport + 32-hex circuit + presence) and their pulled
    // watermark.
    let snapshot = interflow_mesh::hub::snapshot::query_fleet_snapshot(
        &format!("127.0.0.1:{hub_port}"),
        &ca,
        &cert,
        &key,
    )
    .await
    .unwrap();
    assert_eq!(
        snapshot.format_version,
        interflow_mesh::hub::snapshot::FLEET_SNAPSHOT_FORMAT_VERSION
    );
    assert_eq!(snapshot.hub.serving_generation, Some(2));
    assert_eq!(
        snapshot.hub.serving_source,
        Some(interflow_mesh::hub::snapshot::ServingSource::StateLineage),
        "gen 2 was published through the state channel: {snapshot:?}"
    );
    assert_eq!(snapshot.hub.floor_generation, 2);
    for expected in ["main/lan-a", "main/lan-b"] {
        let row = snapshot
            .agents
            .iter()
            .find(|a| a.agent == expected)
            .unwrap_or_else(|| panic!("snapshot must list {expected}: {:?}", snapshot.agents));
        assert!(row.online, "{expected} must read online: {row:?}");
        assert_eq!(
            row.seen_generation,
            Some(2),
            "{expected} watermark: {row:?}"
        );
        let circuit = row
            .circuit
            .as_ref()
            .expect("live session carries its circuit");
        assert_eq!(circuit.len(), 32, "canonical hex form: {row:?}");
        assert!(
            row.transport.is_some(),
            "live session carries its transport: {row:?}"
        );
    }

    // Steady state across a full watch interval (10s): zero new
    // policy_pulled records — the conditional request answers 304, and
    // even a same-generation re-serve dedupes in the ledger. Either way:
    // silence. The 304's x-policy-generation header still lands in the
    // watcher telemetry (the h2 client keeps it): hub == local == 2, the
    // healthy steady state.
    tokio::time::sleep(Duration::from_secs(12)).await;
    let steady = policy_pull_pairs(&read_audit());
    assert_eq!(
        steady.len(),
        2,
        "steady state must add zero policy_pulled records: {steady:?}"
    );
    assert_eq!(
        (
            watch_state_a
                .seen
                .load(std::sync::atomic::Ordering::Acquire),
            watch_state_a
                .hub_generation
                .load(std::sync::atomic::Ordering::Acquire)
        ),
        (2, 2),
        "the 304 header must reach the watcher telemetry"
    );

    // Offline catch-up with a NEW generation while lan-a is down (the
    // acceptance path: a node that missed a publish lands exactly ONE
    // policy_pulled on its first connected pull of the new generation).
    let _ = agent_a.shutdown_graceful().await;
    tokio::time::sleep(Duration::from_secs(1)).await;
    let policy_v3 = interflow_identity::policy::RuntimePolicy::from_manifest(&manifest_v2, 3);
    let (bytes_v3, sig_v3) = policy_v3.signed(&issuer.policy_signer().unwrap()).unwrap();
    let outcome_v3 = interflow_mesh::hub::policy::publish_policy(
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
        outcome_v3,
        interflow_mesh::hub::policy::PublishOutcome::Published { generation: 3 }
    );
    // lan-b is online: it lands exactly one (lan-b, 3).
    let deadline = tokio::time::Instant::now() + Duration::from_secs(15);
    loop {
        let got = policy_pull_pairs(&read_audit())
            .into_iter()
            .filter(|p| (p.0.as_str(), p.1) == ("main/lan-b", 3))
            .count();
        if got == 1 {
            break;
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "lan-b never landed gen 3: {:?}",
            policy_pull_pairs(&read_audit())
        );
        tokio::time::sleep(Duration::from_millis(500)).await;
    }
    // lan-a comes back: its local channel holds gen 2, the hub serves 3 —
    // one catch-up record, and the catch-up actually applies (the service
    // answers).
    let (agent_a_back, _watch_state_a_back) = start(&pack_dir_a);
    wait_connected(&agent_a_back).await;
    let deadline = tokio::time::Instant::now() + Duration::from_secs(30);
    loop {
        let got = policy_pull_pairs(&read_audit())
            .into_iter()
            .filter(|p| (p.0.as_str(), p.1) == ("main/lan-a", 3))
            .count();
        if got == 1 {
            break;
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "restarted lan-a never landed gen 3: {:?}",
            policy_pull_pairs(&read_audit())
        );
        tokio::time::sleep(Duration::from_millis(500)).await;
    }
    assert_eq!(
        tokio::time::timeout(
            Duration::from_secs(15),
            round_trip(listen_v2, b"caught-up-a")
        )
        .await
        .unwrap()
        .unwrap(),
        b"caught-up-a"
    );

    // Final ledger shape: 4 pairs (one per served generation per agent),
    // each exactly once; two publishes.
    tokio::time::sleep(Duration::from_secs(12)).await;
    let pairs = policy_pull_pairs(&read_audit());
    assert_eq!(pairs.len(), 4, "final ledger: {pairs:?}");
    for pair in [
        ("main/lan-a", 2u64),
        ("main/lan-b", 2),
        ("main/lan-a", 3),
        ("main/lan-b", 3),
    ] {
        assert_eq!(
            pairs.iter().filter(|p| (p.0.as_str(), p.1) == pair).count(),
            1,
            "pair {pair:?}: {pairs:?}"
        );
    }
    let published = read_audit()
        .iter()
        .filter(|v| v.get("kind").and_then(|k| k.as_str()) == Some("policy_published"))
        .count();
    assert_eq!(published, 2, "gen 2 + gen 3, nothing else");

    let _ = agent_a_back.shutdown_graceful().await;
    let _ = agent_b2.shutdown_graceful().await;
    shutdown.cancel();
    let _ = hub_task.await;
    for task in backends {
        task.abort();
    }
}

// ---------------------------------------------------------------------------
// Lifecycle-matrix rows 3 + 8: hub-restart serving lineage, and the
// transport-switch leg's policy pull.
// ---------------------------------------------------------------------------

/// Reads the hub's audit trail and returns the `(agent, generation)` pair of
/// every policy serve recorded so far (the durable observable for "this hub
/// actually served that generation to that agent").
fn audit_policy_pulls(hub_dir: &Path) -> Vec<(String, u64)> {
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
}

/// Waits until the TCP port is bindable again — a hub restart re-binds the
/// manifest-pinned listener, and the new hub cannot start until the old one
/// has fully released it.
async fn wait_port_rebindable(port: u16, budget: Duration) -> bool {
    let deadline = tokio::time::Instant::now() + budget;
    while tokio::time::Instant::now() < deadline {
        if std::net::TcpListener::bind(("127.0.0.1", port)).is_ok() {
            return true;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    false
}

/// Recursively copies a rendered pack directory (a pristine copy taken
/// before any node ran from it: no `state/`, no credential bootstrap — the
/// "re-provisioned node" shape).
fn copy_dir(src: &Path, dst: &Path) {
    std::fs::create_dir_all(dst).unwrap();
    for entry in std::fs::read_dir(src).unwrap() {
        let entry = entry.unwrap();
        let to = dst.join(entry.file_name());
        if entry.file_type().unwrap().is_dir() {
            copy_dir(&entry.path(), &to);
        } else {
            std::fs::copy(entry.path(), &to).unwrap();
        }
    }
}

/// Publishes `manifest` at `generation` to the hub's policy endpoint using
/// freshly issued plan-apply credentials (the `plan apply` control path,
/// exactly as the template tests drive it).
async fn publish_generation(
    issuer: &IssuerStore,
    dir: &Path,
    hub_port: u16,
    manifest: &Manifest,
    generation: u64,
) -> interflow_mesh::hub::policy::PublishOutcome {
    let policy = interflow_identity::policy::RuntimePolicy::from_manifest(manifest, generation);
    let (bytes, sig) = policy.signed(&issuer.policy_signer().unwrap()).unwrap();
    let creds_dir = dir.join(format!("publish-creds-{generation}"));
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
    interflow_mesh::hub::policy::publish_policy(
        &format!("127.0.0.1:{hub_port}"),
        &ca,
        &cert,
        &key,
        &bytes,
        &sig,
    )
    .await
    .unwrap()
}

/// Matrix row 3 — hub restart (refit): the serving lineage must survive the
/// restart **from persisted state**, not from the pack's embedded snapshot.
///
/// Shape: gen 1 embedded in every pack; gen 2 published over the control
/// plane and converged; then the hub process is replaced on the same port
/// and directory. A FRESH agent still carrying the gen-1 pack must converge
/// to gen 2 through the restarted hub — if the restart had reset serving to
/// the embedded snapshot (the 2026-10-07 lineage bug), that pull would 304
/// forever and the fresh agent would stay a generation behind, splitting
/// the fleet. The audit's `(lan-b, 2)` count proves the post-restart serve
/// happened (the pre-restart one is snapshotted away).
#[tokio::test]
async fn hub_restart_serves_persisted_lineage_and_agents_repull() {
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
    let hub_port = free_port();
    let backend_v1 = free_port();
    let backend_v2 = free_port();
    let listen_v1 = free_port();
    let listen_v2 = free_port();

    let mut backends = Vec::new();
    for port in [backend_v1, backend_v2] {
        let echo = tokio::net::TcpListener::bind(("127.0.0.1", port))
            .await
            .unwrap();
        backends.push(tokio::spawn(async move {
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
        }));
    }

    let dir = tempfile::tempdir().unwrap();
    let issuer = IssuerStore::open(dir.path().join("issuer"));
    issuer.ensure_realm().unwrap();
    issuer.ensure_workspace("main").unwrap();
    issuer.ensure_policy_key().unwrap();

    let manifest_text = |listen_port: u16, remote_port: u16| {
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
remote_addr = "127.0.0.1:{remote_port}"
[agent.lan-b]
workspace = "main"
[[agent.lan-b.mesh_egress]]
name = "svc"
target_addr = "127.0.0.1:{remote_port}"
"#
        )
    };
    let manifest_v1 = Manifest::parse(&manifest_text(listen_v1, backend_v1)).unwrap();
    let manifest_v2 = Manifest::parse(&manifest_text(listen_v2, backend_v2)).unwrap();

    let hub_dir = dir.path().join("packs/hub-central");
    HubCredentialPack::render(&issuer, &manifest_v1, "central", 1, &hub_dir).unwrap();
    let pack_dir_a = dir.path().join("packs/agent-lan-a");
    AgentCredentialPack::render(&issuer, &manifest_v1, "lan-a", 1, &pack_dir_a).unwrap();
    let pack_dir_b = dir.path().join("packs/agent-lan-b");
    AgentCredentialPack::render(&issuer, &manifest_v1, "lan-b", 1, &pack_dir_b).unwrap();
    // A pristine copy taken before any node ran from it: no node-local
    // `state/policy` — the re-provisioned node must get gen 2 from the
    // RESTARTED hub, not from its own leftovers.
    let pack_dir_b_pristine = dir.path().join("packs/agent-lan-b-pristine");
    copy_dir(&pack_dir_b, &pack_dir_b_pristine);

    // One AuditSink per audit path for the whole test (the sink guards
    // against duplicate writers): both hub incarnations share it — exactly
    // what a real restart does NOT do across processes, but the append-only
    // jsonl is the durable artifact either way.
    let build_hub_cfg = || {
        let hub_pack = CredentialPack::load_runtime(&hub_dir).unwrap();
        let hub_active = ActiveCredentialSet::load_or_bootstrap(&hub_pack).unwrap();
        build_hub_config(&hub_pack, &hub_active, &hub_dir).unwrap()
    };
    let audit = AuditSink::spawn(&build_hub_cfg().audit);
    let start_hub = |audit: &AuditSink| {
        let hub_config = build_hub_cfg();
        let hub = HubServer::new(hub_config, audit.clone()).unwrap();
        let (ready_tx, ready_rx) = tokio::sync::oneshot::channel();
        let shutdown = tokio_util::sync::CancellationToken::new();
        let task = tokio::spawn(hub.run_until_signalled(shutdown.clone(), ready_tx));
        async move { (task, shutdown, ready_rx.await.unwrap()) }
    };
    let start_agent = |pack_dir: &Path| {
        let pack = CredentialPack::load_runtime(pack_dir).unwrap();
        let active = ActiveCredentialSet::load_or_bootstrap(&pack).unwrap();
        let config = build_agent_config(&pack, &active, pack_dir).unwrap();
        AgentClient::new(config).unwrap().start()
    };
    async fn round_trip(port: u16, payload: &[u8]) -> std::io::Result<Vec<u8>> {
        let mut client = tokio::net::TcpStream::connect(("127.0.0.1", port)).await?;
        client.write_all(payload).await?;
        let mut echoed = vec![0u8; payload.len()];
        client.read_exact(&mut echoed).await?;
        Ok(echoed)
    }
    // Round trip until success or budget (absorbs reconnect + watch +
    // apply latency). Budget derivation: policy watch pull cadence (10s) ×
    // a few intervals + hot-apply + reconnect backoff (≤30s cap) — 45s.
    async fn round_trip_eventually(port: u16, payload: &[u8], budget: Duration, what: &str) {
        let deadline = tokio::time::Instant::now() + budget;
        loop {
            if let Ok(Ok(got)) =
                tokio::time::timeout(Duration::from_secs(5), round_trip(port, payload)).await
                && got == payload
            {
                return;
            }
            assert!(
                tokio::time::Instant::now() < deadline,
                "{what}: round trip via port {port} never recovered"
            );
            tokio::time::sleep(Duration::from_millis(500)).await;
        }
    }

    let (hub_task, shutdown, _ready) = start_hub(&audit).await;
    let agent_a = start_agent(&pack_dir_a);
    wait_connected(&agent_a).await;
    let agent_b = start_agent(&pack_dir_b);
    wait_connected(&agent_b).await;
    round_trip_eventually(listen_v1, b"v1", Duration::from_secs(45), "gen 1 baseline").await;

    // Generation 2 over the control plane; both agents converge.
    let outcome = publish_generation(&issuer, dir.path(), hub_port, &manifest_v2, 2).await;
    assert_eq!(
        outcome,
        interflow_mesh::hub::policy::PublishOutcome::Published { generation: 2 }
    );
    round_trip_eventually(
        listen_v2,
        b"v2",
        Duration::from_secs(45),
        "gen 2 convergence",
    )
    .await;
    assert!(
        tokio::net::TcpStream::connect(("127.0.0.1", listen_v1))
            .await
            .is_err(),
        "the gen-1 listener must be gone after the hot apply"
    );
    // Snapshot: exactly one (lan-b, 2) serve so far — the pre-restart one.
    assert_eq!(
        audit_policy_pulls(&hub_dir)
            .iter()
            .filter(|(a, g)| (a.as_str(), *g) == ("main/lan-b", 2))
            .count(),
        1
    );

    // Refit: the hub process is replaced on the same port and directory.
    shutdown.cancel();
    let _ = hub_task.await;
    assert!(
        wait_port_rebindable(hub_port, Duration::from_secs(10)).await,
        "hub port must become rebindable after shutdown"
    );
    let (hub_task, shutdown, _ready) = start_hub(&audit).await;

    // The agents reconnect on their own and the plane keeps serving gen 2
    // (their applied policy persists node-locally; the restarted hub must
    // not wedge or regress it).
    round_trip_eventually(
        listen_v2,
        b"post-restart",
        Duration::from_secs(45),
        "data plane across the hub restart",
    )
    .await;

    // The lineage assertion: a RE-PROVISIONED lan-b (pristine gen-1 pack,
    // no node-local state) converges to gen 2 THROUGH THE RESTARTED HUB. If
    // the restart had reset serving to the embedded snapshot, this pull
    // would 304 forever.
    let _ = agent_b.shutdown_graceful().await;
    tokio::time::sleep(Duration::from_secs(1)).await;
    let agent_b2 = start_agent(&pack_dir_b_pristine);
    wait_connected(&agent_b2).await;
    round_trip_eventually(
        listen_v2,
        b"fresh-catch-up",
        Duration::from_secs(45),
        "fresh gen-1 agent converging via the restarted hub",
    )
    .await;
    // …and the hub actually SERVED generation 2 after the restart (a second
    // (lan-b, 2) audit record that did not exist in the snapshot).
    let deadline = tokio::time::Instant::now() + Duration::from_secs(15);
    loop {
        let count = audit_policy_pulls(&hub_dir)
            .iter()
            .filter(|(a, g)| (a.as_str(), *g) == ("main/lan-b", 2))
            .count();
        if count >= 2 {
            break;
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "the restarted hub never served gen 2 to the fresh agent (serving lineage lost): {:?}",
            audit_policy_pulls(&hub_dir)
        );
        tokio::time::sleep(Duration::from_millis(500)).await;
    }

    let _ = agent_a.shutdown_graceful().await;
    let _ = agent_b2.shutdown_graceful().await;
    shutdown.cancel();
    let _ = hub_task.await;
    for task in backends {
        task.abort();
    }
}

/// Matrix row 8 — transport switch h2 → QUIC: the switched leg must pull the
/// current policy generation. The 2026-10-07 GUI bug shape: a node whose
/// transport changed to QUIC never fired the policy pull, so its rule table
/// silently froze a generation behind while staying green. The switch here
/// is the config-level restart (transport is chosen at process start — the
/// GUI's switch is exactly this): same identity, same pack, transport
/// overridden to QUIC.
#[tokio::test]
async fn transport_switch_leg_pulls_current_policy_generation() {
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
    let hub_port = free_port();
    let backend_v1 = free_port();
    let backend_v2 = free_port();
    let listen_v1 = free_port();
    let listen_v2 = free_port();

    let mut backends = Vec::new();
    for port in [backend_v1, backend_v2] {
        let echo = tokio::net::TcpListener::bind(("127.0.0.1", port))
            .await
            .unwrap();
        backends.push(tokio::spawn(async move {
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
        }));
    }

    let dir = tempfile::tempdir().unwrap();
    let issuer = IssuerStore::open(dir.path().join("issuer"));
    issuer.ensure_realm().unwrap();
    issuer.ensure_workspace("main").unwrap();
    issuer.ensure_policy_key().unwrap();

    // The hub carries BOTH faces (h2 + QUIC on the same port); the agents
    // start on the h2 default.
    let manifest_text = |listen_port: u16, remote_port: u16| {
        format!(
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
        )
    };
    let manifest_v1 = Manifest::parse(&manifest_text(listen_v1, backend_v1)).unwrap();
    let manifest_v2 = Manifest::parse(&manifest_text(listen_v2, backend_v2)).unwrap();

    let hub_dir = dir.path().join("packs/hub-central");
    HubCredentialPack::render(&issuer, &manifest_v1, "central", 1, &hub_dir).unwrap();
    let pack_dir_a = dir.path().join("packs/agent-lan-a");
    AgentCredentialPack::render(&issuer, &manifest_v1, "lan-a", 1, &pack_dir_a).unwrap();
    let pack_dir_b = dir.path().join("packs/agent-lan-b");
    AgentCredentialPack::render(&issuer, &manifest_v1, "lan-b", 1, &pack_dir_b).unwrap();

    let hub_pack = CredentialPack::load_runtime(&hub_dir).unwrap();
    let hub_active = ActiveCredentialSet::load_or_bootstrap(&hub_pack).unwrap();
    let hub_config = build_hub_config(&hub_pack, &hub_active, &hub_dir).unwrap();
    assert!(
        hub_config.transport.quic.enabled,
        "the manifest's quic_listen must enable the hub's QUIC face"
    );
    let audit = AuditSink::spawn(&hub_config.audit);
    let hub = HubServer::new(hub_config, audit).unwrap();
    let (ready_tx, ready_rx) = tokio::sync::oneshot::channel();
    let shutdown = tokio_util::sync::CancellationToken::new();
    let hub_task = tokio::spawn(hub.run_until_signalled(shutdown.clone(), ready_tx));
    ready_rx.await.unwrap();

    let start_agent = |pack_dir: &Path| {
        let pack = CredentialPack::load_runtime(pack_dir).unwrap();
        let active = ActiveCredentialSet::load_or_bootstrap(&pack).unwrap();
        let config = build_agent_config(&pack, &active, pack_dir).unwrap();
        AgentClient::new(config).unwrap().start()
    };
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

    // Generation 1 on the h2 leg (both agents default to h2).
    let agent_a = start_agent(&pack_dir_a);
    wait_connected(&agent_a).await;
    let agent_b = start_agent(&pack_dir_b);
    wait_connected(&agent_b).await;
    assert_eq!(
        tokio::time::timeout(Duration::from_secs(45), round_trip(listen_v1, b"v1"))
            .await
            .unwrap()
            .unwrap(),
        b"v1"
    );

    // The switch: same identity, same pack, transport overridden to QUIC
    // (the config-level switch — exactly the GUI's shape).
    let _ = agent_b.shutdown_graceful().await;
    tokio::time::sleep(Duration::from_secs(1)).await;
    let agent_b_quic = {
        let pack = CredentialPack::load_runtime(&pack_dir_b).unwrap();
        let active = ActiveCredentialSet::load_or_bootstrap(&pack).unwrap();
        let mut config = build_agent_config(&pack, &active, &pack_dir_b).unwrap();
        config.agent.transport = interflow_mesh::config::TransportKind::Quic;
        config.agent.hub_quic_addr = Some(format!("127.0.0.1:{hub_port}"));
        AgentClient::new(config).unwrap().start()
    };
    wait_connected(&agent_b_quic).await;
    // The switched leg carries traffic (QUIC registration + data plane).
    let deadline = tokio::time::Instant::now() + Duration::from_secs(45);
    loop {
        if let Ok(Ok(got)) =
            tokio::time::timeout(Duration::from_secs(5), round_trip(listen_v1, b"switched")).await
            && got == b"switched"
        {
            break;
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "the QUIC-switched leg must carry traffic before the publish"
        );
        tokio::time::sleep(Duration::from_millis(500)).await;
    }

    // Publish generation 2 — the QUIC leg must pull it (the 2026-10-07 bug:
    // the pull never fired and the node froze a generation behind, green).
    let outcome = publish_generation(&issuer, dir.path(), hub_port, &manifest_v2, 2).await;
    assert_eq!(
        outcome,
        interflow_mesh::hub::policy::PublishOutcome::Published { generation: 2 }
    );
    let deadline = tokio::time::Instant::now() + Duration::from_secs(45);
    loop {
        if let Ok(Ok(got)) =
            tokio::time::timeout(Duration::from_secs(5), round_trip(listen_v2, b"v2")).await
            && got == b"v2"
        {
            break;
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "the QUIC-switched leg never applied generation 2 (policy pull dead after the switch)"
        );
        tokio::time::sleep(Duration::from_millis(500)).await;
    }
    assert!(
        tokio::net::TcpStream::connect(("127.0.0.1", listen_v1))
            .await
            .is_err(),
        "the gen-1 listener must be gone after the QUIC-leg hot apply"
    );
    // Hub-side proof: the switched leg actually PULLED generation 2 (not
    // just lucky routing) — audit within 15s of the convergence above.
    let deadline = tokio::time::Instant::now() + Duration::from_secs(15);
    loop {
        if audit_policy_pulls(&hub_dir).contains(&("main/lan-b".to_owned(), 2u64)) {
            break;
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "no (lan-b, gen 2) policy_pulled record: {:?}",
            audit_policy_pulls(&hub_dir)
        );
        tokio::time::sleep(Duration::from_millis(500)).await;
    }

    let _ = agent_a.shutdown_graceful().await;
    let _ = agent_b_quic.shutdown_graceful().await;
    shutdown.cancel();
    let _ = hub_task.await;
    for task in backends {
        task.abort();
    }
}
