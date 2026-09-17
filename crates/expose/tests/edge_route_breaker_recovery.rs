//! e2e: route-level circuit breaker **recovery** — the acceptance gap the
//! 2026-09-17 incident exposed (docs/bug/2026-09-17-edge-route-breaker-stuck-open.md):
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
use interflow_expose::client::ExposeArgs;
use interflow_expose::edge::{EdgeArgs, run};
use interflow_mesh::config::TransportKind;
use interflow_testkit::metrics_harness::{metrics_handle, wait_counter_at_least};
use std::net::SocketAddr;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

fn pick_port() -> u16 {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind ephemeral");
    listener.local_addr().expect("addr").port()
}

async fn wait_for_tcp(addr: SocketAddr, timeout: Duration) -> std::io::Result<()> {
    let deadline = tokio::time::Instant::now() + timeout;
    loop {
        match TcpStream::connect(addr).await {
            Ok(_) => return Ok(()),
            Err(e) => {
                if tokio::time::Instant::now() >= deadline {
                    return Err(e);
                }
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
        }
    }
}

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
    let edge_port = pick_port();
    let hub_port = pick_port();
    let edge_listen: SocketAddr = format!("127.0.0.1:{edge_port}").parse().unwrap();
    let hub_listen: SocketAddr = format!("127.0.0.1:{hub_port}").parse().unwrap();

    let routes_path = std::env::temp_dir().join(format!(
        "interflow_test_routes_breaker_recovery_{}.toml",
        uuid::Uuid::new_v4()
    ));
    std::fs::write(
        &routes_path,
        format!(
            r#"
[[routes]]
host = "rev.local"
agent_id = "expose-breaker-recovery"
remote_addr = "127.0.0.1:{backend_port}"
"#
        ),
    )
    .expect("write routes.toml");

    // Route breaker: trip after 3 failing closes, cooldown 2s so the
    // recovery phase is fast.
    let edge_args = EdgeArgs {
        listen_addr: edge_listen,
        hub_listen_addr: hub_listen,
        routes_path: routes_path.to_string_lossy().into_owned(),
        agent_token: "test-token".into(),
        route_breaker_failure_threshold: 3,
        route_breaker_cooldown_secs: 2,
        agent_recovery_timeout_secs: 120,
        ..Default::default()
    };
    let edge_handle = tokio::task::spawn(run(edge_args));
    wait_for_tcp(hub_listen, Duration::from_secs(5))
        .await
        .expect("hub should start within 5s");
    wait_for_tcp(edge_listen, Duration::from_secs(5))
        .await
        .expect("edge listener should start within 5s");

    let client_args = ExposeArgs {
        local_ports: vec![backend_port],
        hub_url: format!("http://127.0.0.1:{hub_port}"),
        auth_token: "test-token".into(),
        agent_id: "expose-breaker-recovery".into(),
        ca_path: None,
        transport: TransportKind::H2,
        hub_quic_addr: None,
    };
    let client_handle =
        tokio::task::spawn(
            async move { interflow_expose::client::start(&client_args)?.join().await },
        );
    tokio::time::sleep(Duration::from_millis(500)).await;

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
    wait_for_tcp(
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
    let _ = std::fs::remove_file(&routes_path);
}
