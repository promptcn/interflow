//! e2e: verifies the edge's per-IP new-connection rate limit.
//!
//! Scenario 1: with limit=5/min, 127.0.0.1 quickly opening 5 connections
//! succeeds and the 6th is denied — and since this stack's listener is a
//! plaintext (fronted-shaped) face, the denial is **answered**: a real
//! `429 Too Many Requests` + `Retry-After` instead of the zero-byte close
//! that made fronting proxies synthesize misleading 502s
//!.
//! Scenario 2: limit=0 means unlimited.
//! Scenario 3: the fronted topology default (600/min) admits a
//! browser-shaped burst of 40 requests in one minute — the exact
//! "normal traffic must not be collateral damage" guard the deploy-day
//! validation lacked (only single curls were tried, all 200s).

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
    ControlEndpointTls, DEFAULT_FRONTED_NEW_CONN_RATE_PER_IP_PER_MINUTE, EdgeConfig,
    EdgeListenerPolicy, IngressPrincipal, Route, WorkspaceTrust,
};
use interflow_mesh::config::TransportKind;
use std::net::SocketAddr;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

/// Starts edge (with the given rate limit) + expose client + echo, returns edge_listen.
async fn spawn_stack(rate_per_ip_per_min: u32) -> SocketAddr {
    let echo_addr = interflow_testkit::echo_server().await.0;
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
        listener: EdgeListenerPolicy {
            new_conn_rate_per_ip_per_minute: rate_per_ip_per_min,
            ..EdgeListenerPolicy::default()
        },
        agent_recovery_timeout: Duration::from_secs(120),
        ..EdgeConfig::default()
    };
    tokio::task::spawn(interflow_expose::edge::run(edge_config));

    // Wait only for the hub (not the edge listener, to avoid consuming edge rate-limit tokens)
    interflow_testkit::wait_for_tcp(hub_listen, Duration::from_secs(5))
        .await
        .expect("hub should start within 5s");
    // Give the edge listener a moment to come up
    tokio::time::sleep(Duration::from_millis(300)).await;

    let (client_cert, client_key) = certs.client_paths();
    let client_args = ExposeArgs {
        log_name: None,
        services: vec![LocalService {
            id: "web".into(),
            target_addr: echo_addr,
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
    let client = interflow_expose::client::start(&client_args).expect("expose client start");
    assert!(
        interflow_testkit::wait_agent_connected(&client, Duration::from_secs(5)).await,
        "expose client should register within 5s"
    );
    tokio::task::spawn(async move { client.join().await });
    edge_listen
}

/// Sends an HTTP request with a valid Host header; returns whatever response
/// bytes arrived (the echo backend mirrors the request on success). `None` =
/// zero-byte close; a rate-limit denial on this plaintext face answers
/// `HTTP/1.1 429 …` instead.
async fn send_request(edge: SocketAddr) -> Option<String> {
    let Ok(mut sock) = TcpStream::connect(edge).await else {
        return None;
    };
    let req = b"GET / HTTP/1.1\r\nHost: test.local\r\nConnection: close\r\n\r\n";
    sock.write_all(req).await.ok()?;
    let _ = sock.flush().await;
    let mut buf = [0u8; 512];
    let n = sock.read(&mut buf).await.ok()?;
    if n == 0 {
        return None;
    }
    Some(String::from_utf8_lossy(&buf[..n]).into_owned())
}

/// The denied connection is **answered**, not dropped mid-air: 429 semantics
/// with a Retry-After derived from the quota (ceil(60/5) = 12s until the next
/// token refills).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn rate_limit_rejects_beyond_quota() {
    // limit=5/min: the first 5 pass, the 6th is denied (warmup does not consume edge tokens)
    let edge = spawn_stack(5).await;

    for i in 0..5 {
        let answer = send_request(edge).await;
        assert!(answer.is_some(), "request #{i} should succeed within quota");
        assert!(
            !answer.unwrap().starts_with("HTTP/1.1 429"),
            "request #{i} is within quota and must not be denied"
        );
    }

    // 6th: rate-limit hit — a real 429 answer, not a zero-byte close.
    let answer = send_request(edge)
        .await
        .expect("denial must be answered with bytes, not a bare close");
    assert!(
        answer.starts_with("HTTP/1.1 429 Too Many Requests\r\n"),
        "6th request over quota must be answered 429, got: {answer}"
    );
    assert!(
        answer.to_ascii_lowercase().contains("retry-after: 12"),
        "Retry-After must quote one refill interval (ceil(60/5)=12s): {answer}"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn rate_limit_zero_means_unlimited() {
    // 0 = rate limit disabled; all 20 requests should pass
    let edge = spawn_stack(0).await;
    for i in 0..20 {
        assert!(
            send_request(edge).await.is_some(),
            "request #{i} should succeed when rate limit disabled"
        );
    }
}

/// The fronted-topology default quota admits a browser-shaped burst: one SPA
/// load plus a few page navigations ≈ 30–40 new connections in a minute
/// (the front proxy opens one connection per proxied request). The old 30/min
/// default turned exactly this into random 502s.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn fronted_default_quota_admits_browser_shaped_burst() {
    let edge = spawn_stack(DEFAULT_FRONTED_NEW_CONN_RATE_PER_IP_PER_MINUTE).await;
    for i in 0..40 {
        assert!(
            send_request(edge)
                .await
                .is_some_and(|a| !a.starts_with("HTTP/1.1 429")),
            "browser-shaped request #{i} must pass under the fronted default quota"
        );
    }
}
