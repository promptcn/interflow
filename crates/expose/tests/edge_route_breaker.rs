//! e2e: route-level circuit breaker — a dead backend route's public retry
//! loop must stop at the internet edge (2026-09-16 reason-propagation
//! hardening).
//!
//! Case file: `(internal design notes)`.
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
use interflow_expose::client::{ExposeArgs, LocalService};
use interflow_expose::edge::{
    ControlEndpointTls, EdgeConfig, EdgeListenerPolicy, IngressPrincipal, Route,
    RouteBreakerPolicy, WorkspaceTrust,
};
use interflow_mesh::config::TransportKind;
use interflow_testkit::metrics_harness::{counter_value, metrics_handle, wait_counter_at_least};
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

    // Route breaker: trip after 3 failing closes (fast for the test); the
    // agent-side breaker keeps its default threshold of 5, which the edge
    // trip (3) undercuts — the route never lets the agent reach its own
    // threshold, which is exactly the point of stopping at the source.
    let certs = interflow_testkit::certs::TestCerts::generate("e2e", "expose-test");
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
            host: "dead.local".to_string(),
            workspace: "test".to_string(),
            agent_id: "expose-breaker".to_string(),
            service_id: "web".to_string(),
        }],
        listener: EdgeListenerPolicy {
            route_breaker: RouteBreakerPolicy {
                failure_threshold: 3,
                ..RouteBreakerPolicy::default()
            },
            ..EdgeListenerPolicy::default()
        },
        agent_recovery_timeout: Duration::from_secs(120),
        ..EdgeConfig::default()
    };
    let edge = interflow_testkit::spawn_edge(edge_config).await;
    let edge_listen = edge.public_addr();
    let hub_port = edge.control_addr().port();

    let (client_cert, client_key) = certs.named_client_cert("expose-breaker");
    let client_args = ExposeArgs {
        log_name: None,
        services: vec![LocalService {
            id: "web".into(),
            target_addr: format!("127.0.0.1:{dead}").parse().unwrap(),
            overridden: false,
        }],
        hub_url: format!("https://127.0.0.1:{hub_port}"),
        client_cert: Some(client_cert.display().to_string()),
        client_key: Some(client_key.display().to_string()),
        agent_id: "expose-breaker".into(),
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

    edge.shutdown().await.expect("edge shutdown");
    client_handle.abort();
}
