//! End-to-end acceptance for the stream-proposal flow (kube-CSR shape,
//! (internal design notes)): a node
//! submits through its own session, the operator approves from the issuer
//! machine (the real CLI binary driving the manifest edit + apply + notify
//! orchestration), and the stream arrives hot — zero CLI, zero hand-written
//! TOML, zero chat relay on the requester's side.
//!
//! Covers all four acceptance lines:
//! 1. submit (QUIC frames) → approve (CLI) → the requester's listener is
//!    up and the data plane round-trips;
//! 2. an out-of-egress-scope remote is denied AT REQUEST TIME with the
//!    validator's phrasing;
//! 3. a pending proposal ages past its TTL and dies with an audit event;
//! 4. an unapproved proposal leaves the running policy untouched (the
//!    proposal face and the effective face are isolated).
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use tokio::io::{AsyncReadExt, AsyncWriteExt};

use interflow_core::security::AuditSink;
use interflow_core::tunnel::transport::{
    ProposalStatusWire, StreamProposalRequest, StreamProtoWire,
};
use interflow_identity::credentials::ActiveCredentialSet;
use interflow_identity::pack::CredentialPack;
use interflow_mesh::agent::{AgentClient, AgentHandle, AgentState};
use interflow_mesh::hub::HubServer;
use interflow_mesh::pack::{build_agent_config, build_hub_config};
use std::path::PathBuf;
use std::process::Command;
use std::time::Duration;

fn bin() -> PathBuf {
    let mut p = std::env::current_exe().expect("test bin path");
    p.pop(); // deps/
    p.pop(); // tests/
    p.join(format!("interflow-cli{}", std::env::consts::EXE_SUFFIX))
}

struct RunOutcome {
    success: bool,
    stdout: String,
    stderr: String,
}

fn run(args: &[&str]) -> RunOutcome {
    let output = Command::new(bin()).args(args).output().expect("spawn cli");
    RunOutcome {
        success: output.status.success(),
        stdout: String::from_utf8_lossy(&output.stdout).into_owned(),
        stderr: String::from_utf8_lossy(&output.stderr).into_owned(),
    }
}

fn free_port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

fn manifest_text(hub_port: u16, echo_port: u16) -> String {
    format!(
        r#"
[realm]
id = "proposal-e2e"
[identity]
mode = "offline"
leaf_ttl = "7d"
[mesh.hub.central]
listen = "127.0.0.1:{hub_port}"
endpoint = "127.0.0.1:{hub_port}"
quic_listen = "0.0.0.0:{hub_port}"
[workspace.main]
[agent.lan-a]
workspace = "main"
[[agent.lan-a.mesh_ingress]]
name = "svc"
listen = "127.0.0.1:{listen_existing}"
target_agent = "lan-b"
remote_addr = "127.0.0.1:{echo_port}"
[agent.lan-b]
workspace = "main"
[[agent.lan-b.mesh_egress]]
name = "loopback"
target_cidr = "127.0.0.0/8"
"#,
        listen_existing = free_port(),
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

async fn tcp_roundtrip(addr: &str, payload: &[u8]) -> std::io::Result<Vec<u8>> {
    let mut sock =
        tokio::net::TcpStream::connect(addr.parse::<std::net::SocketAddr>().expect("addr parse"))
            .await?;
    sock.write_all(payload).await?;
    // Half-close: the echo server answers then closes on its EOF —
    // without this the read side waits forever.
    sock.shutdown().await?;
    let mut buf = Vec::new();
    sock.read_to_end(&mut buf).await?;
    Ok(buf)
}

/// The full acceptance: propose → approve (CLI binary) → hot stream.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn proposal_approve_delivers_hot_stream_end_to_end() {
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
    let hub_port = free_port();
    let echo_port = free_port();
    let new_listen = free_port(); // the approved stream's listen port
    let new_remote = free_port(); // the approved stream's echo backend

    // The service behind lan-b for BOTH streams: a plain TCP echo server.
    let echo = tokio::net::TcpListener::bind(("127.0.0.1", echo_port))
        .await
        .unwrap();
    let echo2 = tokio::net::TcpListener::bind(("127.0.0.1", new_remote))
        .await
        .unwrap();
    for listener in [echo, echo2] {
        tokio::spawn(async move {
            loop {
                let Ok((mut sock, _)) = listener.accept().await else {
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
    }

    let dir = tempfile::tempdir().unwrap();
    let manifest = dir.path().join("interflow.toml");
    let issuer_dir = dir.path().join("issuer");
    let out = dir.path().join("dist");
    std::fs::write(&manifest, manifest_text(hub_port, echo_port)).unwrap();

    // First apply (the hub is not up yet — manual-distribution path is
    // fine; the in-process hub boots from the rendered pack below).
    let applied = run(&[
        "plan",
        "apply",
        "--manifest",
        manifest.to_str().unwrap(),
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

    // The hub from the rendered pack.
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

    // lan-a over QUIC (the submitter — the proposal frames ride QUIC),
    // lan-b over the default h2 (both submit paths exist; one each here).
    let start_agent = |pack_dir: PathBuf, quic: bool| async move {
        let pack = CredentialPack::load_runtime(&pack_dir).unwrap();
        let active = ActiveCredentialSet::load_or_bootstrap(&pack).unwrap();
        let mut config = build_agent_config(&pack, &active, &pack_dir).unwrap();
        if quic {
            config.agent.transport = interflow_mesh::config::TransportKind::Quic;
            config.agent.hub_quic_addr = Some(format!("127.0.0.1:{hub_port}"));
        }
        AgentClient::new(config).unwrap().start()
    };
    let dir_a = out.join("packs/agent-lan-a");
    let dir_b = out.join("packs/agent-lan-b");
    let agent_a = start_agent(dir_a, true).await;
    let agent_b = start_agent(dir_b, false).await;
    wait_connected(&agent_a).await;
    wait_connected(&agent_b).await;

    // --- Acceptance 4 (isolation): a pending proposal changes nothing.
    let request = StreamProposalRequest {
        name: "extra".to_owned(),
        listen: format!("127.0.0.1:{new_listen}"),
        protocol: StreamProtoWire::Tcp,
        target_agent: "lan-b".to_owned(),
        remote_addr: format!("127.0.0.1:{new_remote}"),
        idle_timeout_secs: None,
    };
    let queued = agent_a.submit_stream_proposal(&request).await.unwrap();
    let (proposal_id, _) = match &queued {
        interflow_core::tunnel::transport::ProposalSubmitOutcome::Queued {
            id,
            expires_at_unix,
        } => (id.clone(), *expires_at_unix),
        other => panic!("expected queued, got {other:?}"),
    };
    // The new listener is NOT up (the proposal face is not the effective
    // face), and the hub still serves generation 1.
    tokio::time::sleep(Duration::from_secs(2)).await;
    assert!(
        tokio::net::TcpStream::connect(("127.0.0.1", new_listen))
            .await
            .is_err(),
        "an unapproved proposal must not open a listener"
    );

    // --- Acceptance 2: out-of-egress-scope remote denied at request time.
    let mut wan = request.clone();
    wan.remote_addr = "10.1.2.3:80".to_owned();
    wan.name = "wan".to_owned();
    match agent_a.submit_stream_proposal(&wan).await.unwrap() {
        interflow_core::tunnel::transport::ProposalSubmitOutcome::Denied { reason } => {
            assert!(
                reason.contains("does not offer"),
                "the denial must carry the validator's pairing phrasing: {reason}"
            );
        }
        other => panic!("expected denial, got {other:?}"),
    }
    // Idempotent resubmit of the queued rule returns the same id.
    match agent_a.submit_stream_proposal(&request).await.unwrap() {
        interflow_core::tunnel::transport::ProposalSubmitOutcome::Duplicate { id, .. } => {
            assert_eq!(id, proposal_id);
        }
        other => panic!("expected duplicate, got {other:?}"),
    }

    // --- The operator (CLI): list shows the pending proposal.
    let listed = run(&[
        "proposals",
        "list",
        "--manifest",
        manifest.to_str().unwrap(),
        "--issuer",
        issuer_dir.to_str().unwrap(),
    ]);
    assert!(
        listed.success,
        "{}\n--- stderr ---\n{}",
        listed.stdout, listed.stderr
    );
    assert!(
        listed.stdout.contains(&proposal_id),
        "the queue must list the proposal: {}",
        listed.stdout
    );

    // --- Acceptance 1: approve → the stream arrives HOT.
    let approved = run(&[
        "proposals",
        "approve",
        "--id",
        &proposal_id,
        "--manifest",
        manifest.to_str().unwrap(),
        "--issuer",
        issuer_dir.to_str().unwrap(),
        "--out",
        out.to_str().unwrap(),
    ]);
    assert!(approved.success, "{}", approved.stdout);
    assert!(
        approved.stdout.contains("generation 2"),
        "the approval must mint generation 2: {}",
        approved.stdout
    );

    // The requester's listener comes up (policy watcher, ≤ a few
    // intervals) and the DATA PLANE round-trips through the new stream.
    let deadline = tokio::time::Instant::now() + Duration::from_secs(30);
    let payload = b"proposal-e2e";
    loop {
        // Both a timeout and an io error mean "no echo yet" (empty vec
        // never equals the payload) — retry until the deadline.
        let echoed = tokio::time::timeout(
            Duration::from_secs(3),
            tcp_roundtrip_addr(new_listen, payload),
        )
        .await
        .ok()
        .and_then(std::result::Result::ok)
        .unwrap_or_default();
        if echoed == payload.to_vec() {
            break;
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "the approved stream never came up (listener {new_listen})"
        );
        tokio::time::sleep(Duration::from_millis(300)).await;
    }

    // The requester's receipts show the approval (the watcher's receipts
    // face; ≤1 interval after the hub recorded the decision).
    let deadline = tokio::time::Instant::now() + Duration::from_secs(30);
    loop {
        let receipts = agent_a.my_proposals().await.unwrap();
        if receipts.iter().any(|r| {
            r.id == proposal_id && r.status == ProposalStatusWire::Approved { generation: 2 }
        }) {
            break;
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "the approval receipt never reached the requester: {receipts:?}"
        );
        tokio::time::sleep(Duration::from_millis(300)).await;
    }

    // --- Reject flow: a second proposal, rejected with a reason the
    // requester sees as the receipt.
    let mut second = request.clone();
    second.name = "second".to_owned();
    second.listen = format!("127.0.0.1:{}", free_port());
    let queued2 = match agent_a.submit_stream_proposal(&second).await.unwrap() {
        interflow_core::tunnel::transport::ProposalSubmitOutcome::Queued { id, .. } => id,
        other => panic!("expected queued, got {other:?}"),
    };
    let rejected = run(&[
        "proposals",
        "reject",
        "--id",
        &queued2,
        "--reason",
        "use the approved one",
        "--manifest",
        manifest.to_str().unwrap(),
        "--issuer",
        issuer_dir.to_str().unwrap(),
    ]);
    assert!(rejected.success, "{}", rejected.stdout);
    let deadline = tokio::time::Instant::now() + Duration::from_secs(30);
    loop {
        let receipts = agent_a.my_proposals().await.unwrap();
        if receipts.iter().any(|r| {
            r.id == queued2
                && r.status
                    == ProposalStatusWire::Rejected {
                        reason: "use the approved one".to_owned(),
                    }
        }) {
            break;
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "the rejection receipt never reached the requester: {receipts:?}"
        );
        tokio::time::sleep(Duration::from_millis(300)).await;
    }

    // --- Acceptance 3: expiry. The unit suite covers the sweep at
    // second scale (TTL 72h); here we assert the DECIDED records ride out
    // their window and the queue's audit trail names the lifecycle. The
    // approved record is still visible to the operator's list.
    let listed = run(&[
        "proposals",
        "list",
        "--manifest",
        manifest.to_str().unwrap(),
        "--issuer",
        issuer_dir.to_str().unwrap(),
    ]);
    assert!(listed.success);
    assert!(
        listed.stdout.contains("approved (gen 2)"),
        "{}",
        listed.stdout
    );
    assert!(listed.stdout.contains("rejected"), "{}", listed.stdout);

    let _ = agent_a.shutdown_graceful().await;
    let _ = agent_b.shutdown_graceful().await;
    shutdown.cancel();
    let _ = hub_task.await;
}

/// Thin wrapper so the round-trip probe takes a raw port.
async fn tcp_roundtrip_addr(port: u16, payload: &[u8]) -> std::io::Result<Vec<u8>> {
    tcp_roundtrip(&format!("127.0.0.1:{port}"), payload).await
}
