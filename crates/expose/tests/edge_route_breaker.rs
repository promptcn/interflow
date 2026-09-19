//! e2e: route-level circuit breaker — a dead backend route's public retry
//! loop must stop at the internet edge (2026-09-16 reason-propagation
//! hardening).
//!
//! Case file: `docs/bug/2026-09-16-egress-global-rate-limit-starvation.md`.
//! The agent now reports its close reason (`connect_failed` /
//! `target_circuit_open`) back through the hub; the edge counts these per
//! host and, once a route trips, closes new public connections right after
//! the Host lookup — **without** an Open through the tunnel — until a
//! recovery probe succeeds. The storm therefore never reaches hub or agent.
//!
//! Discriminating assertions (in-process Prometheus recorder):
//! - the agent's actual dial work is bounded by the route threshold (a
//!   handful of `connect_failed` closes, then silence);
//! - the vast majority of the storm connections are counted as
//!   `interflow_edge_route_breaker_rejected` (closed at the edge);
//! - every connection still closes fast (the public behavior is unchanged:
//!   zero-byte close, nginx surfaces 502).

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
use interflow_expose::edge::{EdgeArgs, EdgeHubTls, run};
use interflow_mesh::config::TransportKind;
use interflow_testkit::metrics_harness::{counter_value, metrics_handle, wait_counter_at_least};
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

/// A route to a dead backend plus a public retry loop: the route breaker
/// trips after `route_breaker_failure_threshold` failing closes; every
/// subsequent connection is closed at the edge without an Open, and the
/// agent's dial work stays bounded.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn dead_route_storm_stops_at_the_edge() {
    let _ = metrics_handle();
    let _ = tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "warn".into()),
        )
        .try_init();

    let dead = dead_port().await;
    let edge_port = pick_port();
    let hub_port = pick_port();
    let edge_listen: SocketAddr = format!("127.0.0.1:{edge_port}").parse().unwrap();
    let hub_listen: SocketAddr = format!("127.0.0.1:{hub_port}").parse().unwrap();

    let routes_path = std::env::temp_dir().join(format!(
        "interflow_test_routes_breaker_{}.toml",
        uuid::Uuid::new_v4()
    ));
    std::fs::write(
        &routes_path,
        format!(
            r#"
[[routes]]
host = "dead.local"
tenant = "test"
agent_id = "expose-breaker"
remote_addr = "127.0.0.1:{dead}"
"#
        ),
    )
    .expect("write routes.toml");

    // Route breaker: trip after 3 failing closes (fast for the test); the
    // agent-side breaker keeps its default threshold of 5, which the edge
    // trip (3) undercuts — the route never lets the agent reach its own
    // threshold, which is exactly the point of stopping at the source.
    let certs = interflow_testkit::certs::TestCerts::generate("e2e", "expose-test");
    let edge_args = EdgeArgs {
        listen_addr: edge_listen,
        hub_listen_addr: hub_listen,
        routes_path: routes_path.to_string_lossy().into_owned(),
        tenant_cas: vec![("test".to_string(), certs.ca_path().display().to_string())],
        proxy_protocol: Default::default(),
        hub_tls: Some(EdgeHubTls {
            cert_path: certs.server_cert_path().display().to_string(),
            key_path: certs.server_key_path().display().to_string(),
        }),
        route_breaker_failure_threshold: 3,
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

    let (client_cert, client_key) = certs.named_client_cert("expose-breaker");
    let client_args = ExposeArgs {
        local_ports: vec![dead],
        hub_url: format!("https://127.0.0.1:{hub_port}"),
        client_cert: Some(client_cert.display().to_string()),
        client_key: Some(client_key.display().to_string()),
        agent_id: "expose-breaker".into(),
        ca_path: Some(certs.ca_path().display().to_string()),
        transport: TransportKind::H2,
        hub_quic_addr: None,
    };
    let client_handle =
        tokio::task::spawn(
            async move { interflow_expose::client::start(&client_args)?.join().await },
        );
    // Wait for the agent to register with the hub.
    tokio::time::sleep(Duration::from_millis(500)).await;

    // The public retry loop: 25 sequential connections, each expecting the
    // fast zero-byte close (EOF/reset), well within the timeout.
    for i in 0..25u32 {
        let mut sock = TcpStream::connect(edge_listen)
            .await
            .expect("connect edge listener");
        sock.write_all(b"GET / HTTP/1.1\r\nHost: dead.local\r\nConnection: close\r\n\r\n")
            .await
            .expect("write request");
        let read = tokio::time::timeout(Duration::from_secs(3), sock.read_u8()).await;
        match read {
            Ok(Err(e))
                if matches!(
                    e.kind(),
                    std::io::ErrorKind::UnexpectedEof | std::io::ErrorKind::ConnectionReset
                ) => {}
            Ok(Ok(b)) => panic!("edge must not write bytes (conn {i}, got {b:#x})"),
            Ok(Err(e)) => panic!("unexpected io error on conn {i}: {e}"),
            Err(_) => panic!("conn {i} did not close out within 3s"),
        }
    }

    // The storm was stopped at the edge: most connections never produced a
    // tunnel Open.
    wait_counter_at_least(
        "interflow_edge_route_breaker_rejected",
        15,
        Duration::from_secs(5),
    )
    .await;

    // The agent's dial work stayed bounded: roughly the route threshold
    // (races may admit a couple more before the trip lands, but the storm's
    // 25 connections must not have become 25 dials).
    let dials = counter_value("interflow_egress_stream_closed_total{reason=\"connect_failed\"}");
    assert!(
        (1..=5).contains(&dials),
        "agent dial work should be bounded by the route threshold, got {dials}"
    );

    edge_handle.abort();
    client_handle.abort();
    let _ = std::fs::remove_file(&routes_path);
}
