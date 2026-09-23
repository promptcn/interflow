//! e2e: route-level circuit breaker **recovery** — the acceptance gap the
//! 2026-09-17 incident exposed:
//! the breaker must return to CLOSED after the backend recovers, not merely
//! reject while it is down.
//!
//! Pre-fix root cause: the only recovery evidence was the agent's
//! `backend_closed` close reason, which structurally never arrives under
//! HTTP/1.1 keepalive (the client hangs up first; the hub tears the stream
//! on the edge's request-direction close) — every probe succeeded yet the
//! breaker stayed OPEN forever, surfacing as a 1 req/s "rate-limit-style
//! 502".
//!
//! This test reproduces exactly that client behavior — a fresh connection
//! per request, response read to Content-Length, socket dropped (client
//! closes first, no `backend_closed` ever lands) — and asserts:
//! 1. the dead-route storm still trips the breaker at the edge;
//! 2. after the backend returns and the cooldown elapses, the admitted
//!    recovery probe succeeds AND closes the breaker
//!      (`interflow_edge_route_breaker_transitions_total{state="closed"}`);
//! 3. immediately afterwards a rapid-fire burst is fully served — the
//!    1-req/s stuck-OPEN signature must be gone.
//!
//! Separate test binary from `edge_route_breaker.rs` on purpose: the
//! Prometheus recorder is process-global and the storm test asserts absolute
//! counter values.

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
    ControlEndpointTls, EdgeConfig, EdgeListenerPolicy, IngressPrincipal, Route,
    RouteBreakerPolicy, WorkspaceTrust, run,
};
use interflow_mesh::config::TransportKind;
use interflow_testkit::metrics_harness::{metrics_handle, wait_counter_at_least};
use std::net::SocketAddr;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

/// A dead backend target: hold an ephemeral port, release it — nothing
/// listens there afterwards (connections are refused).
async fn dead_port() -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    drop(listener);
    tokio::time::sleep(Duration::from_millis(50)).await;
    port
}

/// Minimal HTTP/1.1 responder serving `200 OK` with body `ok`, one
/// connection at a time, closing after each response (`Connection: close`).
async fn http_ok_backend(port: u16) -> std::io::Result<()> {
    let listener = TcpListener::bind(("127.0.0.1", port)).await?;
    loop {
        let (mut sock, _) = match listener.accept().await {
            Ok(x) => x,
            Err(_) => continue,
        };
        // Drain the request head (bounded: it is a fixed test request).
        let mut buf = vec![0u8; 4096];
        let _ = tokio::time::timeout(Duration::from_secs(2), async {
            loop {
                let n = sock.read(&mut buf).await.unwrap_or(0);
                if n == 0 || buf[..n].windows(4).any(|w| w == b"\r\n\r\n") {
                    break;
                }
            }
        })
        .await;
        sock.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok")
            .await?;
        let _ = sock.shutdown().await;
    }
}

/// One public request over a fresh connection (the incident's client shape):
/// send the request, read until the fixed-length body (`ok`) has arrived,
/// drop the socket. The client therefore always hangs up first — no
/// `backend_closed` close reason ever lands at the edge. Returns the bytes
/// read (headers + body).
async fn one_request(edge: SocketAddr, host: &str) -> std::io::Result<Vec<u8>> {
    let mut sock = TcpStream::connect(edge).await?;
    sock.write_all(
        format!("GET / HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n").as_bytes(),
    )
    .await?;
    // Read until the body arrived — NOT read_to_end: the agent's
    // backend-EOF drain grace keeps the tunnel stream open for seconds
    // after the response, so EOF is late and irrelevant here.
    let mut got = Vec::new();
    let mut buf = [0u8; 1024];
    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    loop {
        if got.starts_with(b"HTTP/1.1 200") && got.ends_with(b"ok") {
            break;
        }
        let n = tokio::time::timeout_at(deadline, sock.read(&mut buf)).await??;
        if n == 0 {
            break; // EOF before the full response; the caller's shape assert fails
        }
        got.extend_from_slice(&buf[..n]);
    }
    Ok(got)
}

/// Trip the route breaker with a dead-backend storm, bring the backend back,
/// and prove the breaker returns to CLOSED and serves a full rapid burst.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn route_breaker_recovers_after_backend_returns() {
    let _ = metrics_handle();
    let _ = tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "warn".into()),
        )
        .try_init();

    let backend_port = dead_port().await;
    let edge_port = interflow_testkit::pick_ephemeral_port();
    let hub_port = interflow_testkit::pick_ephemeral_port();
    let edge_listen: SocketAddr = format!("127.0.0.1:{edge_port}").parse().unwrap();
    let hub_listen: SocketAddr = format!("127.0.0.1:{hub_port}").parse().unwrap();

    // Route breaker: trip after 3 failing closes, cooldown 2s so the
    // recovery phase is fast.
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
            host: "rev.local".to_string(),
            workspace: "test".to_string(),
            agent_id: "expose-breaker-recovery".to_string(),
            service_id: "web".to_string(),
        }],
        listener: EdgeListenerPolicy {
            route_breaker: RouteBreakerPolicy {
                failure_threshold: 3,
                cooldown_secs: 2,
                ..RouteBreakerPolicy::default()
            },
            ..EdgeListenerPolicy::default()
        },
        agent_recovery_timeout: Duration::from_secs(120),
        ..EdgeConfig::default()
    };
    let edge_handle = tokio::task::spawn(run(edge_config));
    interflow_testkit::wait_for_tcp(hub_listen, Duration::from_secs(5))
        .await
        .expect("hub should start within 5s");
    interflow_testkit::wait_for_tcp(edge_listen, Duration::from_secs(5))
        .await
        .expect("edge listener should start within 5s");

    let (client_cert, client_key) = certs.named_client_cert("expose-breaker-recovery");
    let client_args = ExposeArgs {
        log_name: None,
        services: vec![LocalService {
            id: "web".into(),
            target_addr: format!("127.0.0.1:{backend_port}").parse().unwrap(),
            overridden: false,
        }],
        hub_url: format!("https://127.0.0.1:{hub_port}"),
        client_cert: Some(client_cert.display().to_string()),
        client_key: Some(client_key.display().to_string()),
        agent_id: "expose-breaker-recovery".into(),
        ingress_ca_path: Some(certs.ca_path().display().to_string()),
        ca_path: Some(certs.ca_path().display().to_string()),
        transport: TransportKind::H2,
        hub_quic_addr: None,
    };
    let client = interflow_expose::client::start(&client_args).expect("expose client start");
    assert!(
        interflow_testkit::wait_agent_connected(&client, Duration::from_secs(5)).await,
        "expose client should register within 5s"
    );
    let client_handle = tokio::task::spawn(async move { client.join().await });

    // Phase 1 — the dead-route storm: 8 sequential requests, all fail fast
    // (agent dial refused → zero-byte close). The breaker trips at the edge.
    for _ in 0..8u32 {
        let mut sock = TcpStream::connect(edge_listen).await.expect("connect edge");
        sock.write_all(b"GET / HTTP/1.1\r\nHost: rev.local\r\nConnection: close\r\n\r\n")
            .await
            .expect("write request");
        match tokio::time::timeout(Duration::from_secs(3), sock.read_u8()).await {
            Ok(Err(e))
                if matches!(
                    e.kind(),
                    std::io::ErrorKind::UnexpectedEof | std::io::ErrorKind::ConnectionReset
                ) => {}
            Ok(Ok(b)) => panic!("dead backend must not serve bytes (got {b:#x})"),
            Ok(Err(e)) => panic!("unexpected io error: {e}"),
            Err(_) => panic!("connection did not close out within 3s"),
        }
    }
    wait_counter_at_least(
        "interflow_edge_route_breaker_transitions_total{state=\"open\"}",
        1,
        Duration::from_secs(5),
    )
    .await;
    wait_counter_at_least(
        "interflow_edge_route_breaker_rejected",
        1,
        Duration::from_secs(5),
    )
    .await;

    // Phase 2 — the backend returns on the same port.
    let backend_handle = tokio::task::spawn(http_ok_backend(backend_port));
    interflow_testkit::wait_for_tcp(
        format!("127.0.0.1:{backend_port}").parse().unwrap(),
        Duration::from_secs(5),
    )
    .await
    .expect("backend should come back up");

    // Cooldown (2s) elapses; the next connection is the admitted recovery
    // probe. It succeeds — and because this client hangs up first (fresh
    // connection, response read, socket dropped), the recovery evidence is
    // the pump's locally-observed "response bytes were relayed", exactly the
    // path that was structurally broken before the fix.
    tokio::time::sleep(Duration::from_millis(2600)).await;
    let probe = one_request(edge_listen, "rev.local")
        .await
        .expect("probe request should succeed");
    assert!(
        probe.starts_with(b"HTTP/1.1 200") && probe.ends_with(b"ok"),
        "probe response malformed: {probe:?}"
    );

    // The decisive acceptance (the gap the incident exposed): the breaker
    // actually closed. Pre-fix this never fires — the probe succeeds but its
    // success signal is lost and the route stays OPEN forever.
    wait_counter_at_least(
        "interflow_edge_route_breaker_transitions_total{state=\"closed\"}",
        1,
        Duration::from_secs(5),
    )
    .await;

    // Phase 3 — the stuck-OPEN signature must be gone: a rapid-fire burst
    // (all within one PROBE_INTERVAL) is fully served, not throttled to
    // 1 req/s.
    for i in 0..6u32 {
        let resp = one_request(edge_listen, "rev.local")
            .await
            .unwrap_or_else(|e| panic!("burst request {i} failed after recovery: {e}"));
        assert!(
            resp.starts_with(b"HTTP/1.1 200") && resp.ends_with(b"ok"),
            "burst response {i} malformed: {resp:?}"
        );
    }

    edge_handle.abort();
    client_handle.abort();
    backend_handle.abort();
}
