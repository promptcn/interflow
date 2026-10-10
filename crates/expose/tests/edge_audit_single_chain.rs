//! Regression:
//! the fused ingress process (public edge + embedded hub) must run ONE
//! audit writer on the pack ledger. It once ran two — the edge's sink plus
//! a hub-spawned sink on the same path — and on a bare restart (active
//! file present, the standard engine-upgrade step) their startup seals
//! raced: the slower writer appended its fresh chain into the other's
//! just-opened file, interleaving two chains that no replay can verify.
//!
//! This test reproduces the bare-restart condition — a previous process's
//! non-empty ledger in place — starts the full fused edge, provokes one
//! hub-side and one edge-side record, and requires the whole directory to
//! replay: the sealed old chain plus one new active chain, no interleave.
//! It is the automated form of the backlog's on-host verification list.

#![allow(
    clippy::all,
    clippy::pedantic,
    clippy::nursery,
    clippy::panic,
    clippy::unwrap_used,
    clippy::expect_used,
    missing_docs
)]

use interflow_core::config::AuditConfig;
use interflow_core::security::{AuditKind, AuditSink, discover_audit_files, verify_audit_files};
use interflow_expose::edge::{
    ControlEndpointTls, EdgeConfig, IngressPrincipal, Route, WorkspaceTrust,
};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

/// Polls the audit JSONL until it contains `needle` (line-buffered writer
/// thread; a bounded wait beats a fixed sleep).
async fn await_audit_contains(path: &std::path::Path, needle: &str) -> bool {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    while tokio::time::Instant::now() < deadline {
        if let Ok(s) = std::fs::read_to_string(path)
            && s.contains(needle)
        {
            return true;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    false
}

/// Waits for the sealed old segment to settle into its gzip form (the
/// edge's rotation defaults compress in the background; verifying mid-gzip
/// would race a partial archive). Settled = exactly one `.jsonl.gz`
/// segment and no bare segment left.
async fn await_segment_settled(dir: &std::path::Path) -> bool {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
    loop {
        let mut bare = 0usize;
        let mut gz = 0usize;
        if let Ok(entries) = std::fs::read_dir(dir) {
            for entry in entries.flatten() {
                let name = entry.file_name().to_string_lossy().into_owned();
                if name.starts_with("audit-") {
                    if name.ends_with(".jsonl.gz") {
                        gz += 1;
                    } else if name.ends_with(".jsonl") {
                        bare += 1;
                    }
                }
            }
        }
        if gz == 1 && bare == 0 {
            return true;
        }
        if tokio::time::Instant::now() >= deadline {
            return false;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn fused_edge_replays_single_chain_after_bare_restart() {
    let dir = tempfile::tempdir().unwrap();
    let ledger = dir.path().join("audit.jsonl");

    // The previous process's ledger: two records, flushed, handle gone —
    // exactly what a bare `systemctl restart` leaves behind.
    let old = AuditSink::spawn(&AuditConfig {
        enabled: true,
        path: Some(ledger.display().to_string()),
        ..AuditConfig::default()
    });
    old.record(AuditKind::ConfigReloaded, None, None);
    old.record(AuditKind::ConfigReloaded, None, None);
    old.flush().await;
    drop(old);

    // The fused process: edge listener + embedded hub + internal agent,
    // auditing to that same file (the pack-directory convention).
    let certs = interflow_testkit::certs::TestCerts::generate("e2e", "audit-chain-test");
    let (principal_cert, principal_key) = certs.named_client_cert("edge");
    let edge_config = EdgeConfig {
        // :0 = kernel-assigned; spawn_edge hands back the bound addresses
        listen_addr: "127.0.0.1:0".parse().unwrap(),
        control_listen_addr: "127.0.0.1:0".parse().unwrap(),
        control_tls: ControlEndpointTls {
            cert: certs.server_cert_path(),
            key: certs.server_key_path(),
        },
        workspace_trust: vec![WorkspaceTrust {
            workspace: "test".to_string(),
            ca: certs.ca_path(),
        }],
        principals: vec![IngressPrincipal {
            workspace: "test".to_string(),
            cert: principal_cert,
            key: principal_key,
        }],
        routes: vec![Route {
            host: "test.local".to_string(),
            workspace: "test".to_string(),
            agent_id: "audit-chain-test".to_string(),
            service_id: "web".to_string(),
        }],
        audit_path: Some(ledger.clone()),
        agent_recovery_timeout: Duration::from_secs(120),
        ..EdgeConfig::default()
    };
    let edge = interflow_testkit::spawn_edge(edge_config).await;

    // An edge-side denial record: an unroutable Host gets the silent close
    // and an audit line (same trigger as the slow-loris suite).
    let mut sock = tokio::net::TcpStream::connect(edge.public_addr())
        .await
        .expect("connect edge");
    sock.write_all(b"GET / HTTP/1.1\r\nHost: no.such.route\r\nConnection: close\r\n\r\n")
        .await
        .expect("write request");
    let mut sink_buf = vec![0u8; 256];
    let _ = tokio::time::timeout(Duration::from_secs(5), sock.read(&mut sink_buf)).await;

    // Hub-side (internal agent registration) and edge-side (host denial)
    // records must both be in the ONE ledger.
    assert!(
        await_audit_contains(&ledger, "\"kind\":\"agent_registered\"").await,
        "hub-side events must land in the shared ledger"
    );
    assert!(
        await_audit_contains(&ledger, "no.such.route").await,
        "edge-side denial must land in the shared ledger"
    );

    edge.shutdown().await.expect("edge shutdown");

    assert!(
        await_segment_settled(dir.path()).await,
        "sealed old segment must settle into exactly one .gz"
    );

    // The whole directory replays: the previous process's sealed chain +
    // the new process's active chain, and nothing interleaved. Before the
    // fix this failed with a hash/sequence break inside the active file
    // (two chains, two sequence-1 records).
    let files = discover_audit_files(dir.path());
    let report = verify_audit_files(&files)
        .unwrap_or_else(|e| panic!("fused-process ledger must replay: {e}"));
    assert_eq!(
        report.segments, 2,
        "one sealed old segment + the active file"
    );
    assert_eq!(
        report.chains, 2,
        "the previous process's chain + the new one — exactly two, no interleave"
    );
    assert!(
        report.records >= 4,
        "2 pre-seeded + hub/edge records, got {}",
        report.records
    );
    assert!(
        !report.truncated_start,
        "the oldest segment starts the old chain at sequence 1"
    );
}
