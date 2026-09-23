//! e2e: verifies edge slow-loris protection, silent close, and stream idle
//! budget behavior.
//!
//! Scenario 1: client sends 1 byte then hangs; assert the connection is
//! closed within 10s (host_peek_timeout in effect).
//! Scenario 2: unroutable host; assert no response bytes, the connection is
//! closed, and an audit record is written.
//! Scenario 3: backend receives the request then goes silent (< idle budget)
//! before bursting; assert the stream survives and the data is uncorrupted.
//! Scenario 4: bidirectional silence beyond the idle budget tears the stream
//! down (negative control for the configurable budget).

#![allow(
    clippy::all,
    clippy::pedantic,
    clippy::nursery,
    clippy::panic,
    clippy::unwrap_used,
    clippy::expect_used,
    missing_docs,
    dead_code,
    unused_mut
)]
use interflow_expose::client::{ExposeArgs, LocalService};
use interflow_expose::edge::{
    ControlEndpointTls, EdgeConfig, EdgeListenerPolicy, IngressPrincipal, Route, WorkspaceTrust,
};
use interflow_mesh::agent::AgentState;
use interflow_mesh::config::TransportKind;
use std::net::SocketAddr;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

/// Starts edge + expose client + the given backend (all real components) and
/// returns the edge listen address. `stream_idle_timeout_secs` injects the
/// edge stream idle budget (production default 300; tests lower it to control
/// the duration).
async fn spawn_stack(
    audit_path: Option<String>,
    stream_idle_timeout_secs: u64,
    backend_addr: SocketAddr,
) -> SocketAddr {
    let edge_port = interflow_testkit::pick_ephemeral_port();
    let hub_port = interflow_testkit::pick_ephemeral_port();
    let edge_listen: SocketAddr = format!("127.0.0.1:{edge_port}").parse().unwrap();
    let hub_listen: SocketAddr = format!("127.0.0.1:{hub_port}").parse().unwrap();

    let certs = interflow_testkit::certs::TestCerts::generate("e2e", "expose-test");
    let (principal_cert, principal_key) = certs.named_client_cert("edge");
    let edge_config = EdgeConfig {
        listen_addr: edge_listen,
        control_listen_addr: hub_listen,
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
            agent_id: "expose-test".to_string(),
            service_id: "web".to_string(),
        }],
        audit_path: audit_path.map(std::path::PathBuf::from),
        listener: EdgeListenerPolicy {
            stream_idle_timeout: Duration::from_secs(stream_idle_timeout_secs),
            ..EdgeListenerPolicy::default()
        },
        agent_recovery_timeout: Duration::from_secs(120),
        ..EdgeConfig::default()
    };
    tokio::task::spawn(interflow_expose::edge::run(edge_config));

    interflow_testkit::wait_for_tcp(edge_listen, Duration::from_secs(5))
        .await
        .expect("edge listener should start within 5s");
    interflow_testkit::wait_for_tcp(hub_listen, Duration::from_secs(5))
        .await
        .expect("edge hub should start within 5s");

    let (client_cert, client_key) = certs.client_paths();
    let client_args = ExposeArgs {
        log_name: None,
        services: vec![LocalService {
            id: "web".into(),
            target_addr: backend_addr,
            overridden: false,
        }],
        hub_url: format!("https://127.0.0.1:{hub_port}"),
        client_cert: Some(client_cert.display().to_string()),
        client_key: Some(client_key.display().to_string()),
        agent_id: "expose-test".into(),
        ingress_ca_path: Some(certs.ca_path().display().to_string()),
        ca_path: Some(certs.ca_path().display().to_string()),
        transport: TransportKind::H2,
        hub_quic_addr: None,
    };
    let handle = interflow_expose::client::start(&client_args).expect("start expose client");
    let mut state = handle.subscribe_state();
    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    loop {
        match state.borrow_and_update().clone() {
            AgentState::Connected { agent_id } if agent_id == client_args.agent_id => break,
            AgentState::Failed { error } => panic!("expose client failed: {error}"),
            _ => {}
        }
        tokio::time::timeout_at(deadline, state.changed())
            .await
            .expect("expose client should register within 5s")
            .expect("expose client state watch should stay alive");
    }
    tokio::task::spawn(async move { handle.join().await });

    edge_listen
}

/// "Silent-then-burst after receiving the request" backend: accept → read the
/// request once → stay silent for `silence` (no reads or writes, no bytes in
/// either direction) → burst-write `burst` (None = keep staying silent) →
/// switch to echo mode.
async fn spawn_silent_backend(silence: Duration, burst: Option<Vec<u8>>) -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind silent backend");
    let addr = listener.local_addr().expect("silent backend addr");
    tokio::spawn(async move {
        loop {
            let Ok((mut sock, _)) = listener.accept().await else {
                return;
            };
            let burst = burst.clone();
            tokio::spawn(async move {
                // Read once to drain the request bytes (only counts as
                // "silent after receiving the request" once it arrived)
                let mut buf = [0u8; 4096];
                if sock.read(&mut buf).await.is_err() {
                    return;
                }
                tokio::time::sleep(silence).await;
                if let Some(payload) = &burst {
                    if sock.write_all(payload).await.is_err() {
                        return;
                    }
                }
                // Echo mode: round trips after the silent window must still work
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
    addr
}

/// Slow-loris: client sends 1 byte then hangs; assert the connection is
/// closed within 10s.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn edge_slow_loris_timeout() {
    let edge_listen = spawn_stack(None, 300, interflow_testkit::echo_server().await.0).await;

    let mut sock = TcpStream::connect(edge_listen).await.expect("connect edge");
    // Send 1 byte then hang (never send a complete Host header)
    sock.write_all(b"G").await.expect("write 1 byte");
    sock.flush().await.expect("flush");

    // Should be closed shortly after the 10s mark (host_peek_timeout = 10s)
    let start = tokio::time::Instant::now();
    let mut buf = [0u8; 1];
    let result = tokio::time::timeout(Duration::from_secs(15), sock.read(&mut buf)).await;
    let elapsed = start.elapsed();

    assert!(
        elapsed < Duration::from_secs(13),
        "should close after the 10s timeout, actual {:?}",
        elapsed
    );
    // read should return 0 (EOF) or Err (connection closed)
    match result {
        Ok(Ok(0)) | Ok(Err(_)) => {}
        Ok(Ok(n)) => panic!("no response data expected, but read {n} bytes"),
        Err(_) => panic!("read timed out without the connection being closed"),
    }
}

/// Unroutable host: silent close, no response bytes.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn edge_no_route_silent_close() {
    let audit_path = std::env::temp_dir().join(format!(
        "interflow_test_audit_{}.jsonl",
        uuid::Uuid::new_v4()
    ));
    let audit_path_str = audit_path.to_string_lossy().to_string();
    let edge_listen = spawn_stack(
        Some(audit_path_str.clone()),
        300,
        interflow_testkit::echo_server().await.0,
    )
    .await;

    let mut sock = TcpStream::connect(edge_listen).await.expect("connect edge");
    let request = b"GET / HTTP/1.1\r\nHost: no.such.route\r\nConnection: close\r\n\r\n";
    sock.write_all(request).await.expect("write request");
    sock.flush().await.expect("flush");

    // read should return 0 (EOF) shortly, with no HTTP response bytes at all
    let mut buf = vec![0u8; 1024];
    let start = tokio::time::Instant::now();
    let n = tokio::time::timeout(Duration::from_secs(5), sock.read(&mut buf))
        .await
        .expect("read should not timeout")
        .expect("read should succeed");

    assert_eq!(n, 0, "should return EOF (0 bytes), no HTTP response");
    assert!(
        start.elapsed() < Duration::from_secs(2),
        "should close quickly, actual {:?}",
        start.elapsed()
    );

    // Wait for the audit write
    tokio::time::sleep(Duration::from_millis(200)).await;
    let audit_content = std::fs::read_to_string(&audit_path).unwrap_or_default();
    assert!(
        audit_content.contains("no.such.route") || audit_content.contains("no_route"),
        "audit should record the denied host, actual: {audit_content}"
    );
    let _ = std::fs::remove_file(&audit_path);
}

/// Duplicate Host header: the connection should be rejected (extract_host
/// yields no Host → no route match → silent close).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn edge_duplicate_host_rejected() {
    let edge_listen = spawn_stack(None, 300, interflow_testkit::echo_server().await.0).await;

    let mut sock = TcpStream::connect(edge_listen).await.expect("connect edge");
    let request = b"GET / HTTP/1.1\r\nHost: test.local\r\nHost: evil.com\r\n\r\n";
    sock.write_all(request).await.expect("write request");
    sock.flush().await.expect("flush");

    let mut buf = vec![0u8; 1024];
    let n = tokio::time::timeout(Duration::from_secs(5), sock.read(&mut buf))
        .await
        .expect("read should not timeout")
        .expect("read should succeed");

    assert_eq!(n, 0, "duplicate Host header should be silently closed");
}

/// Silent recovery (backing artifact #1): backend receives the request then
/// stays silent for 3s (< idle budget of 5s, no bytes in either direction)
/// before bursting 128KiB; assert the stream survives, the data is
/// byte-for-byte uncorrupted, and later round trips on the same connection
/// still work.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn edge_stream_idle_silence_then_burst_survives() {
    const IDLE_SECS: u64 = 5;
    const SILENCE: Duration = Duration::from_secs(3);

    let payload: Vec<u8> = (0..128 * 1024).map(|i| (i % 251) as u8).collect();
    let backend = spawn_silent_backend(SILENCE, Some(payload.clone())).await;
    let edge_listen = spawn_stack(None, IDLE_SECS, backend).await;

    let mut sock = TcpStream::connect(edge_listen).await.expect("connect edge");
    let request = b"GET / HTTP/1.1\r\nHost: test.local\r\n\r\n";
    sock.write_all(request).await.expect("write request");

    // The silent window (3s < idle 5s) must not tear the stream down: the
    // burst data arrives in full + byte-for-byte uncorrupted
    let mut received = vec![0u8; payload.len()];
    tokio::time::timeout(Duration::from_secs(15), sock.read_exact(&mut received))
        .await
        .expect(
            "burst after silence should arrive within 15s (not torn down within the idle budget)",
        )
        .expect("read_exact");
    assert_eq!(
        received, payload,
        "burst data should be byte-for-byte uncorrupted"
    );

    // One more small round trip on the same connection proves the stream
    // wasn't killed by the silent window and the stack isn't stuck
    let marker = b"still-alive";
    sock.write_all(marker).await.expect("write marker");
    let mut echo = vec![0u8; marker.len()];
    tokio::time::timeout(Duration::from_secs(5), sock.read_exact(&mut echo))
        .await
        .expect("echo round trip after silent recovery should not time out")
        .expect("read_exact");
    assert_eq!(
        echo, marker,
        "stream should still carry round trips after silent recovery"
    );
}

/// Over-budget silence: no bytes in either direction for longer than the idle
/// budget (2s) tears the stream down — verifies that the budget config entry
/// point actually takes effect, as the TCP public-stream counterpart of UDP
/// idle reclamation (being killed by silence is the intended semantics there).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn edge_stream_idle_expired_closes_stream() {
    const IDLE_SECS: u64 = 2;

    let backend = spawn_silent_backend(Duration::from_secs(8), None).await;
    let edge_listen = spawn_stack(None, IDLE_SECS, backend).await;

    let mut sock = TcpStream::connect(edge_listen).await.expect("connect edge");
    let request = b"GET / HTTP/1.1\r\nHost: test.local\r\n\r\n";
    sock.write_all(request).await.expect("write request");

    // Should be closed after exceeding the idle budget: no data bytes at all,
    // and it happens within idle + margin
    let start = tokio::time::Instant::now();
    let mut buf = vec![0u8; 1024];
    let result = tokio::time::timeout(Duration::from_secs(10), sock.read(&mut buf)).await;
    let elapsed = start.elapsed();

    assert!(
        elapsed < Duration::from_secs(6),
        "should close within idle(2s) + margin, actual {elapsed:?}"
    );
    match result {
        Ok(Ok(0)) | Ok(Err(_)) => {}
        Ok(Ok(n)) => panic!("no data bytes expected, but read {n} bytes"),
        Err(_) => panic!("timed out without closing (idle budget not in effect)"),
    }
}
