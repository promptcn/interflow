//! e2e: verifies X-Forwarded-For real-IP restoration on the edge's public
//! HTTP leg (the standard nginx `proxy_pass` topology).
//!
//! Scenario 1 (`required`): behind a trusted loopback proxy, the per-IP
//! rate limit keys on the right-most XFF entry — one client exhausts its
//! budget (answered with a real `429 Too Many Requests` + `Retry-After`,
//! not the zero-byte close that made the fronting nginx synthesize 502s)
//! while a different client is isolated from it.
//! Scenario 2 (`required`): a trusted proxy that sends no header is
//! rejected fail-closed (zero-byte close — that rejection predates the
//! gate and stays silent).
//! Scenario 3 (untrusted peer): XFF from a non-trusted source is ignored —
//! the TCP peer is the effective IP and the request still routes.
//! The audit log asserts the effective IP (not the proxy's loopback) is
//! what gets recorded on denials.

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
use interflow_core::security::{ProxyProtocolConfig, ProxyProtocolMode, XffMode};
use interflow_expose::client::{ExposeArgs, LocalService};
use interflow_expose::edge::{
    ControlEndpointTls, EdgeConfig, EdgeListenerPolicy, IngressPrincipal, Route, WorkspaceTrust,
};
use interflow_mesh::config::TransportKind;
use std::net::SocketAddr;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

/// Stack configuration knobs shared by the scenarios.
struct StackOpts {
    xff: XffMode,
    trusted_proxies: Vec<String>,
    rate_per_ip_per_min: u32,
}

/// Starts edge + expose client + echo backend; returns (edge_listen,
/// audit_path). Certificates reuse the production test kit (real mTLS).
async fn spawn_stack(opts: StackOpts) -> (SocketAddr, std::path::PathBuf) {
    let echo_addr = interflow_testkit::echo_server().await.0;

    let audit_path = std::env::temp_dir().join(format!(
        "interflow_test_edge_xff_{}.jsonl",
        uuid::Uuid::new_v4()
    ));

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
            host: "test.local".to_string(),
            workspace: "test".to_string(),
            agent_id: "expose-test".to_string(),
            service_id: "web".to_string(),
        }],
        audit_path: Some(audit_path.clone()),
        listener: EdgeListenerPolicy {
            proxy_protocol: ProxyProtocolConfig {
                mode: ProxyProtocolMode::Off,
                trusted_proxies: opts.trusted_proxies.clone(),
            },
            x_forwarded_for: opts.xff,
            new_conn_rate_per_ip_per_minute: opts.rate_per_ip_per_min,
            ..EdgeListenerPolicy::default()
        },
        agent_recovery_timeout: Duration::from_secs(120),
        ..EdgeConfig::default()
    };
    let edge = interflow_testkit::spawn_edge(edge_config).await;
    let edge_listen = edge.public_addr();
    let hub_port = edge.control_addr().port();

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
    (edge_listen, audit_path)
}

/// Sends one HTTP request with an optional X-Forwarded-For header; returns
/// whatever response bytes arrived (the echo backend mirrors the request, so
/// success = the echoed request; a rate-limit denial = a `429 …` answer;
/// `None` = zero-byte close).
async fn send_request(edge: SocketAddr, xff: Option<&str>) -> Option<String> {
    let Ok(mut sock) = TcpStream::connect(edge).await else {
        return None;
    };
    let xff_line = xff.map_or(String::new(), |v| format!("X-Forwarded-For: {v}\r\n"));
    let req = format!("GET / HTTP/1.1\r\nHost: test.local\r\n{xff_line}Connection: close\r\n\r\n");
    sock.write_all(req.as_bytes()).await.ok()?;
    let mut buf = [0u8; 512];
    let n = sock.read(&mut buf).await.ok()?;
    if n == 0 {
        return None;
    }
    Some(String::from_utf8_lossy(&buf[..n]).into_owned())
}

/// Whether the answer bytes are the echo backend's mirror (i.e. the request
/// was routed) — anything else (429 answer, bare close) is a denial.
async fn request_routes(edge: SocketAddr, xff: Option<&str>) -> bool {
    send_request(edge, xff)
        .await
        .is_some_and(|a| !a.starts_with("HTTP/1.1 429"))
}

/// Polls the audit JSONL until it contains `needle` (line-buffered writer
/// thread; a bounded wait beats a fixed sleep).
async fn await_audit_contains(path: &std::path::Path, needle: &str) -> bool {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(3);
    while tokio::time::Instant::now() < deadline {
        if let Ok(s) = std::fs::read_to_string(path) {
            if s.contains(needle) {
                return true;
            }
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    false
}

#[tokio::test]
async fn required_keys_rate_limit_on_rightmost_xff_entry() {
    let (edge, audit) = spawn_stack(StackOpts {
        xff: XffMode::Required,
        trusted_proxies: vec!["127.0.0.1".to_string()],
        rate_per_ip_per_min: 3,
    })
    .await;

    // Three connections from "client 198.51.100.7" (left entry forged by the
    // client, right entry appended by our trusted test "proxy").
    for _ in 0..3 {
        assert!(
            request_routes(edge, Some("6.6.6.6, 198.51.100.7")).await,
            "first three connections should pass"
        );
    }
    // Budget exhausted for that effective IP only — the denial is answered
    // with a real 429 (this is the deferred gate: the request head is fully
    // buffered by the time the XFF key resolves, so a complete HTTP answer
    // is possible), quoting one refill interval (ceil(60/3)=20s).
    let denial = send_request(edge, Some("6.6.6.6, 198.51.100.7"))
        .await
        .expect("rate-limit denial must be answered with bytes, not a bare close");
    assert!(
        denial.starts_with("HTTP/1.1 429 Too Many Requests\r\n"),
        "4th connection over quota must be answered 429, got: {denial}"
    );
    assert!(
        denial.to_ascii_lowercase().contains("retry-after: 20"),
        "Retry-After must quote one refill interval (ceil(60/3)=20s): {denial}"
    );
    // A different client is isolated from the exhausted budget.
    assert!(
        request_routes(edge, Some("203.0.113.9")).await,
        "a different XFF client must not share the budget"
    );

    // The denial names the effective IP, never the proxy's loopback peer.
    assert!(
        await_audit_contains(&audit, "\"source\":\"198.51.100.7\"").await,
        "audit must record the XFF-restored IP on rate-limit denials"
    );
}

#[tokio::test]
async fn required_rejects_trusted_proxy_without_header() {
    let (edge, audit) = spawn_stack(StackOpts {
        xff: XffMode::Required,
        trusted_proxies: vec!["127.0.0.1".to_string()],
        rate_per_ip_per_min: 30,
    })
    .await;

    assert!(
        send_request(edge, None).await.is_none(),
        "trusted proxy without X-Forwarded-For must be rejected fail-closed (silent close)"
    );
    assert!(
        await_audit_contains(&audit, "x_forwarded_for_required").await,
        "the rejection must be audited"
    );
}

#[tokio::test]
async fn untrusted_peer_ignores_the_header_and_still_routes() {
    // 127.0.0.1 is NOT in the trusted set here, so its XFF header is
    // attacker-controlled input and must be ignored wholesale.
    let (edge, _audit) = spawn_stack(StackOpts {
        xff: XffMode::Required,
        trusted_proxies: vec!["10.0.0.0/8".to_string()],
        rate_per_ip_per_min: 30,
    })
    .await;

    assert!(
        request_routes(edge, Some("6.6.6.6, 198.51.100.7")).await,
        "untrusted peer forges XFF: request still routes, keyed on the peer"
    );
}
