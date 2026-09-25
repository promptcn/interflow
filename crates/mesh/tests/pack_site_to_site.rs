//! End-to-end acceptance for the pack-driven site-to-site path:
//! manifest → Credential Packs → hub + two agents in-process → TCP through
//! the tunnel, across two workspaces.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

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
    let hub = HubServer::new(hub_config).unwrap();
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
    let hub = HubServer::new(hub_config).unwrap();
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
    let hub = HubServer::new(hub_config).unwrap();
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
    let hub = HubServer::new(hub_config).unwrap();
    let (ready_tx, ready_rx) = tokio::sync::oneshot::channel();
    let shutdown = tokio_util::sync::CancellationToken::new();
    let hub_task = tokio::spawn(hub.run_until_signalled(shutdown.clone(), ready_tx));
    ready_rx.await.unwrap();

    // Agents WITH their policy watchers — the production wiring.
    let start = |pack_dir: &Path| {
        let pack = CredentialPack::load_runtime(pack_dir).unwrap();
        let active = ActiveCredentialSet::load_or_bootstrap(&pack).unwrap();
        let config = build_agent_config(&pack, &active, pack_dir).unwrap();
        let client = AgentClient::new(config).unwrap();
        let agent = client.clone().start();
        let watcher =
            interflow_mesh::pack::spawn_policy_reload(pack_dir, client, Some(agent.tunnel()))
                .unwrap();
        (agent, watcher)
    };
    let (agent_b, watcher_b) = start(&pack_dir_b);
    wait_connected(&agent_b).await;
    let (agent_a, watcher_a) = start(&pack_dir_a);
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

    watcher_a.abort();
    watcher_b.abort();
    let _ = agent_a.shutdown_graceful().await;
    let _ = agent_b.shutdown_graceful().await;
    shutdown.cancel();
    let _ = hub_task.await;
    for task in backends {
        task.abort();
    }
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
    let hub = HubServer::new(hub_config).unwrap();
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

    // A tampered signature → rejected with a named error.
    let mut tampered = bytes_v2.clone();
    tampered[0] ^= 0xff;
    let err = interflow_mesh::hub::policy::publish_policy(
        &format!("127.0.0.1:{hub_port}"),
        &ca,
        &cert,
        &key,
        &tampered,
        &sig_v2,
    )
    .await
    .unwrap_err();
    assert!(
        err.to_string().contains("400"),
        "tampered policy must be rejected: {err}"
    );

    // A workspace principal (an agent's own credential — straight from its
    // pack) must not publish: a compromised agent box cannot widen its own
    // authorization.
    let home_dir = dir.path().join("packs/agent-home");
    AgentCredentialPack::render(&issuer, &manifest_v1, "home", 1, &home_dir).unwrap();
    let agent_cert = home_dir.join("identity/agent-main.crt");
    let agent_key = home_dir.join("identity/agent-main.key");
    let err = interflow_mesh::hub::policy::publish_policy(
        &format!("127.0.0.1:{hub_port}"),
        &ca,
        &agent_cert,
        &agent_key,
        &bytes_v2,
        &sig_v2,
    )
    .await
    .unwrap_err();
    assert!(
        err.to_string().contains("403"),
        "an agent principal must not publish policy: {err}"
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
    let hub = HubServer::new(hub_config).unwrap();
    let (ready_tx, ready_rx) = tokio::sync::oneshot::channel();
    let shutdown = tokio_util::sync::CancellationToken::new();
    let hub_task = tokio::spawn(hub.run_until_signalled(shutdown.clone(), ready_tx));
    ready_rx.await.unwrap();

    let start = |pack_dir: &Path| {
        let pack = CredentialPack::load_runtime(pack_dir).unwrap();
        let active = ActiveCredentialSet::load_or_bootstrap(&pack).unwrap();
        let config = build_agent_config(&pack, &active, pack_dir).unwrap();
        let client = AgentClient::new(config).unwrap();
        let agent = client.clone().start();
        let watcher =
            interflow_mesh::pack::spawn_policy_reload(pack_dir, client, Some(agent.tunnel()))
                .unwrap();
        (agent, watcher)
    };
    // lan-b starts "offline" — it comes up only AFTER the publish below.
    let (agent_a, watcher_a) = start(&pack_dir_a);
    wait_connected(&agent_a).await;

    // Baseline through lan-b? Not yet online — start it for the baseline,
    // then take it down conceptually: the catch-up story is that a FRESH
    // lan-b (restarted, embedded generation 1) converges via pull.
    let (agent_b, watcher_b) = start(&pack_dir_b);
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
    watcher_b.abort();
    let _ = agent_b.shutdown_graceful().await;
    // Give the hub a moment to age the old registration out; the fresh
    // session re-registers anyway.
    tokio::time::sleep(Duration::from_secs(1)).await;
    let (agent_b2, watcher_b2) = start(&pack_dir_b);
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

    // Steady state across a full watch interval (10s): zero new
    // policy_pulled records — the conditional request answers 304, and
    // even a same-generation re-serve dedupes in the ledger. Either way:
    // silence.
    tokio::time::sleep(Duration::from_secs(12)).await;
    let steady = policy_pull_pairs(&read_audit());
    assert_eq!(
        steady.len(),
        2,
        "steady state must add zero policy_pulled records: {steady:?}"
    );

    // Offline catch-up with a NEW generation while lan-a is down (the
    // acceptance path: a node that missed a publish lands exactly ONE
    // policy_pulled on its first connected pull of the new generation).
    watcher_a.abort();
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
    let (agent_a_back, watcher_a_back) = start(&pack_dir_a);
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

    watcher_a_back.abort();
    watcher_b2.abort();
    let _ = agent_a_back.shutdown_graceful().await;
    let _ = agent_b2.shutdown_graceful().await;
    shutdown.cancel();
    let _ = hub_task.await;
    for task in backends {
        task.abort();
    }
}
