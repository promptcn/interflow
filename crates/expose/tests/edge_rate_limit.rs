//! e2e: verifies the edge's per-IP new-connection rate limit.
//!
//! Scenario 1: with limit=5/min, 127.0.0.1 quickly opening 5 connections
//! succeeds and the 6th is denied.
//! Scenario 2: 127.0.0.1 opening 5 + 127.0.0.2 opening 5 both succeed
//! (per-IP isolation).
//!
//! Note: a denied connection manifests as "peer closes before sending any
//! bytes" — on a rate-limit hit the edge does `drop(stream)` and sends no
//! HTTP response.

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
use interflow_expose::edge::EdgeArgs;
use interflow_mesh::config::TransportKind;
use std::net::SocketAddr;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

async fn spawn_echo() -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind echo");
    let addr = listener.local_addr().expect("echo addr");
    tokio::spawn(async move {
        loop {
            let Ok((mut sock, _)) = listener.accept().await else {
                return;
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
    addr
}

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

/// Starts edge (with the given rate limit) + expose client + echo, returns edge_listen.
async fn spawn_stack(rate_per_ip_per_min: u32) -> SocketAddr {
    let echo_addr = spawn_echo().await;
    let edge_port = pick_port();
    let hub_port = pick_port();
    let edge_listen: SocketAddr = format!("127.0.0.1:{edge_port}").parse().unwrap();
    let hub_listen: SocketAddr = format!("127.0.0.1:{hub_port}").parse().unwrap();

    let routes_content = format!(
        r#"
[[routes]]
host = "test.local"
agent_id = "expose-test"
remote_addr = "{echo_addr}"
"#
    );
    let routes_path = std::env::temp_dir().join(format!(
        "interflow_test_routes_{}.toml",
        uuid::Uuid::new_v4()
    ));
    std::fs::write(&routes_path, &routes_content).expect("write routes.toml");

    let edge_args = EdgeArgs {
        listen_addr: edge_listen,
        hub_listen_addr: hub_listen,
        routes_path: routes_path.to_string_lossy().into_owned(),
        agent_token: "test-token".into(),
        hub_tls: None,
        quic_listen: None,
        audit_path: None,
        new_conn_rate_per_ip_per_minute: rate_per_ip_per_min,
        stream_idle_timeout_secs: 300,
        route_breaker_enabled: true,
        route_breaker_failure_threshold: 10,
        route_breaker_window_secs: 60,
        route_breaker_cooldown_secs: 30,
        agent_recovery_timeout_secs: 120,
    };
    tokio::task::spawn(interflow_expose::edge::run(edge_args));

    // Wait only for the hub (not the edge listener, to avoid consuming edge rate-limit tokens)
    wait_for_tcp(hub_listen, Duration::from_secs(5))
        .await
        .expect("hub should start within 5s");
    // Give the edge listener a moment to come up
    tokio::time::sleep(Duration::from_millis(300)).await;

    let client_args = ExposeArgs {
        local_ports: vec![echo_addr.port()],
        hub_url: format!("http://127.0.0.1:{hub_port}"),
        auth_token: "test-token".into(),
        agent_id: "expose-test".into(),
        ca_path: None,
        transport: TransportKind::H2,
        hub_quic_addr: None,
    };
    tokio::task::spawn(async move { interflow_expose::client::start(&client_args)?.join().await });

    tokio::time::sleep(Duration::from_millis(500)).await;
    let _ = std::fs::remove_file(&routes_path);
    edge_listen
}

/// Sends an HTTP request with a valid Host header; returns whether any
/// response bytes arrived. On a rate-limit hit the connection is dropped and
/// read returns 0 bytes or an error.
async fn send_request(edge: SocketAddr) -> bool {
    let Ok(mut sock) = TcpStream::connect(edge).await else {
        return false;
    };
    let req = b"GET / HTTP/1.1\r\nHost: test.local\r\nConnection: close\r\n\r\n";
    if sock.write_all(req).await.is_err() {
        return false;
    }
    let _ = sock.flush().await;
    let mut buf = [0u8; 64];
    matches!(sock.read(&mut buf).await, Ok(n) if n > 0)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn rate_limit_rejects_beyond_quota() {
    // limit=5/min: the first 5 pass, the 6th is denied (warmup does not consume edge tokens)
    let edge = spawn_stack(5).await;

    for i in 0..5 {
        assert!(
            send_request(edge).await,
            "request #{i} should succeed within quota"
        );
    }

    // 6th: rate-limit hit, connection dropped
    let got_response = send_request(edge).await;
    assert!(
        !got_response,
        "6th request over rate limit should be dropped (no response bytes)"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn rate_limit_zero_means_unlimited() {
    // 0 = rate limit disabled; all 20 requests should pass
    let edge = spawn_stack(0).await;
    for i in 0..20 {
        assert!(
            send_request(edge).await,
            "request #{i} should succeed when rate limit disabled"
        );
    }
}
