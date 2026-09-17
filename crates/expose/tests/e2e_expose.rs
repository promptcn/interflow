//! e2e: edge + expose client + local echo service, verifying the full
//! public-domain → private-network service path.
//!
//! The test starts, within a single process:
//! 1. edge (hub server + edge agent + HTTP listener)
//! 2. expose client (connects to the edge's hub, agent_id=`expose-test`)
//! 3. echo backend (127.0.0.1:0)
//!
//! It then sends an HTTP/1.1 request with `Host: test.local` to the edge
//! listener and verifies the echo backend reflects the request bytes back
//! (proving the data fully traverses the edge→hub→expose→echo chain).

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
use interflow_expose::edge::{EdgeArgs, HostRouter, Route, RoutesConfig};
use interflow_mesh::config::TransportKind;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

/// Echo backend for tests: writes back whatever it reads.
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

/// Grabs an ephemeral port (bound then released immediately; there is a tiny
/// race between tests but this is usually good enough).
fn pick_port() -> u16 {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind ephemeral");
    listener.local_addr().expect("addr").port()
}

/// Repeatedly TCP-connects to `addr` until success or timeout.
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

/// HostRouter unit test: normalization, case handling, port handling.
#[tokio::test]
async fn host_router_routes_by_host() {
    let echo_addr = spawn_echo().await;

    let router = Arc::new(HostRouter::from_config(RoutesConfig {
        routes: vec![Route {
            host: "test.local".into(),
            agent_id: "expose-test".into(),
            remote_addr: echo_addr,
        }],
    }));

    assert_eq!(router.len(), 1);
    let r = router.lookup("test.local").expect("route found");
    assert_eq!(r.agent_id, "expose-test");
    assert_eq!(r.remote_addr, echo_addr);

    // Port normalization
    assert!(router.lookup("test.local:8443").is_some());
    // Case normalization
    assert!(router.lookup("TEST.LOCAL").is_some());
    // Not registered
    assert!(router.lookup("other.local").is_none());
}

/// Full chain: edge + expose client + echo, verifying HTTP request bytes can
/// traverse the tunnel and be reflected back by the echo backend.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn full_edge_expose_round_trip() {
    // Enable logging (visible only for this test)
    let _ = tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "info,interflow=debug".into()),
        )
        .try_init();

    // 1. echo backend
    // 1. echo backend
    let echo_addr = spawn_echo().await;

    // 2. Grab ports
    let edge_port = pick_port();
    let hub_port = pick_port();
    let edge_listen: SocketAddr = format!("127.0.0.1:{edge_port}").parse().unwrap();
    let hub_listen: SocketAddr = format!("127.0.0.1:{hub_port}").parse().unwrap();

    // 3. Temp routes.toml
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

    // 4. Spawn edge (hub server + edge agent + listener)
    let edge_args = EdgeArgs {
        listen_addr: edge_listen,
        hub_listen_addr: hub_listen,
        routes_path: routes_path.to_string_lossy().into_owned(),
        agent_token: "test-token".into(),
        agent_recovery_timeout_secs: 120,
        ..Default::default()
    };
    let edge_handle = tokio::task::spawn(interflow_expose::edge::run(edge_args));

    // 5. Wait for the hub listener to be ready
    wait_for_tcp(hub_listen, Duration::from_secs(5))
        .await
        .expect("hub should start within 5s");
    // Wait for the edge listener to be ready
    wait_for_tcp(edge_listen, Duration::from_secs(5))
        .await
        .expect("edge listener should start within 5s");

    // 6. Spawn the expose client (connects to the edge's hub, agent_id=expose-test, egress to echo)
    let client_args = ExposeArgs {
        local_ports: vec![echo_addr.port()],
        hub_url: format!("http://127.0.0.1:{hub_port}"),
        auth_token: "test-token".into(),
        agent_id: "expose-test".into(),
        ca_path: None,
        transport: TransportKind::H2,
        hub_quic_addr: None,
    };
    let client_handle =
        tokio::task::spawn(
            async move { interflow_expose::client::start(&client_args)?.join().await },
        );

    // 7. Wait for the agent to register with the hub (no health-check channel; a simple sleep)
    tokio::time::sleep(Duration::from_millis(500)).await;

    // 8. Send an HTTP/1.1 request to the edge listener
    let mut sock = TcpStream::connect(edge_listen)
        .await
        .expect("connect edge listener");
    let request = b"GET / HTTP/1.1\r\nHost: test.local\r\nConnection: close\r\n\r\n";
    sock.write_all(request).await.expect("write request");

    // 9. Read back the same number of bytes — the echo server reflects the
    // request bytes (it does not close the connection itself, so read_to_end
    // would not work)
    let mut response = vec![0u8; request.len()];
    let read_result =
        tokio::time::timeout(Duration::from_secs(3), sock.read_exact(&mut response)).await;
    edge_handle.abort();
    client_handle.abort();
    let _ = std::fs::remove_file(&routes_path);

    read_result
        .expect("read should not timeout")
        .expect("read_exact should succeed");

    // Expected: the echo reflects the request bytes verbatim (proving the data
    // fully traverses edge→hub→expose→echo→expose→hub→edge)
    assert_eq!(
        response.as_slice(),
        request.as_ref(),
        "response should equal echoed request"
    );
}
