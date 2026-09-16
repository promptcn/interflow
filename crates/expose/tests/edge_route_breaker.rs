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
use interflow_expose::edge::{EdgeArgs, run};
use interflow_mesh::config::TransportKind;
use metrics_exporter_prometheus::{PrometheusBuilder, PrometheusHandle};
use std::net::SocketAddr;
use std::sync::OnceLock;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

static METRICS: OnceLock<PrometheusHandle> = OnceLock::new();

fn metrics_handle() -> &'static PrometheusHandle {
    METRICS.get_or_init(|| {
        let recorder = PrometheusBuilder::new().build_recorder();
        let handle = recorder.handle();
        let _ = metrics::set_global_recorder(recorder);
        handle
    })
}

fn counter_value(metric_prefix: &str) -> u64 {
    metrics_handle()
        .render()
        .lines()
        .filter_map(|line| line.split_once(' '))
        .filter(|(k, _)| k.starts_with(metric_prefix))
        .filter_map(|(_, v)| v.trim().parse::<u64>().ok())
        .sum()
}

async fn wait_counter_at_least(metric_prefix: &str, min: u64, timeout: Duration) {
    let deadline = tokio::time::Instant::now() + timeout;
    loop {
        let v = counter_value(metric_prefix);
        if v >= min {
            return;
        }
        if tokio::time::Instant::now() >= deadline {
            panic!(
                "timed out waiting for metric {metric_prefix} >= {min}, current {v} (snapshot:\n{})",
                metrics_handle().render()
            );
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
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
    let edge_args = EdgeArgs {
        listen_addr: edge_listen,
        hub_listen_addr: hub_listen,
        routes_path: routes_path.to_string_lossy().into_owned(),
        agent_token: "test-token".into(),
        hub_tls: None,
        quic_listen: None,
        audit_path: None,
        new_conn_rate_per_ip_per_minute: 0,
        stream_idle_timeout_secs: 300,
        route_breaker_enabled: true,
        route_breaker_failure_threshold: 3,
        route_breaker_window_secs: 60,
        route_breaker_cooldown_secs: 30,
    };
    let edge_handle = tokio::task::spawn(run(edge_args));
    wait_for_tcp(hub_listen, Duration::from_secs(5))
        .await
        .expect("hub should start within 5s");
    wait_for_tcp(edge_listen, Duration::from_secs(5))
        .await
        .expect("edge listener should start within 5s");

    let client_args = ExposeArgs {
        local_ports: vec![dead],
        hub_url: format!("http://127.0.0.1:{hub_port}"),
        auth_token: "test-token".into(),
        agent_id: "expose-breaker".into(),
        ca_path: None,
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
