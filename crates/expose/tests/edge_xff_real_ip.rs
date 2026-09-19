//! e2e: verifies X-Forwarded-For real-IP restoration on the edge's public
//! HTTP leg (the standard nginx `proxy_pass` topology).
//!
//! Scenario 1 (`required`): behind a trusted loopback proxy, the per-IP
//! rate limit keys on the right-most XFF entry — one client exhausts its
//! budget while a different client is isolated from it.
//! Scenario 2 (`required`): a trusted proxy that sends no header is
//! rejected fail-closed (zero-byte close).
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
use interflow_expose::client::ExposeArgs;
use interflow_expose::edge::{EdgeArgs, EdgeHubTls};
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

/// Stack configuration knobs shared by the scenarios.
struct StackOpts {
    xff: XffMode,
    trusted_proxies: Vec<String>,
    rate_per_ip_per_min: u32,
}

/// Starts edge + expose client + echo backend; returns (edge_listen,
/// audit_path). Certificates reuse the production test kit (real mTLS).
async fn spawn_stack(opts: StackOpts) -> (SocketAddr, std::path::PathBuf) {
    let echo_addr = spawn_echo().await;
    let edge_port = pick_port();
    let hub_port = pick_port();
    let edge_listen: SocketAddr = format!("127.0.0.1:{edge_port}").parse().unwrap();
    let hub_listen: SocketAddr = format!("127.0.0.1:{hub_port}").parse().unwrap();

    let routes_content = r#"
[[routes]]
host = "test.local"
tenant = "test"
agent_id = "expose-test"
remote_addr = "127.0.0.1:9"
"#
    .replace("127.0.0.1:9", &echo_addr.to_string());
    let routes_path = std::env::temp_dir().join(format!(
        "interflow_test_routes_xff_{}.toml",
        uuid::Uuid::new_v4()
    ));
    std::fs::write(&routes_path, routes_content).expect("write routes.toml");

    let audit_path = std::env::temp_dir().join(format!(
        "interflow_test_edge_xff_{}.jsonl",
        uuid::Uuid::new_v4()
    ));

    let certs = interflow_testkit::certs::TestCerts::generate("e2e", "expose-test");
    let edge_args = EdgeArgs {
        listen_addr: edge_listen,
        hub_listen_addr: hub_listen,
        routes_path: routes_path.to_string_lossy().into_owned(),
        tenant_cas: vec![("test".to_string(), certs.ca_path().display().to_string())],
        proxy_protocol: ProxyProtocolConfig {
            mode: ProxyProtocolMode::Off,
            trusted_proxies: opts.trusted_proxies,
        },
        x_forwarded_for: opts.xff,
        hub_tls: Some(EdgeHubTls {
            cert_path: certs.server_cert_path().display().to_string(),
            key_path: certs.server_key_path().display().to_string(),
        }),
        audit_path: Some(audit_path.display().to_string()),
        new_conn_rate_per_ip_per_minute: opts.rate_per_ip_per_min,
        ..Default::default()
    };
    tokio::task::spawn(interflow_expose::edge::run(edge_args));

    // Wait for the hub listener, then let the edge listener come up without
    // consuming any of its rate-limit tokens.
    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    loop {
        if TcpStream::connect(hub_listen).await.is_ok() {
            break;
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "hub should start within 5s"
        );
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    tokio::time::sleep(Duration::from_millis(300)).await;

    let (client_cert, client_key) = certs.client_paths();
    let client_args = ExposeArgs {
        local_ports: vec![echo_addr.port()],
        hub_url: format!("https://127.0.0.1:{hub_port}"),
        client_cert: Some(client_cert.display().to_string()),
        client_key: Some(client_key.display().to_string()),
        agent_id: "expose-test".into(),
        ca_path: Some(certs.ca_path().display().to_string()),
        transport: TransportKind::H2,
        hub_quic_addr: None,
    };
    tokio::task::spawn(async move { interflow_expose::client::start(&client_args)?.join().await });

    tokio::time::sleep(Duration::from_secs(1)).await;
    let _ = std::fs::remove_file(&routes_path);
    (edge_listen, audit_path)
}

/// Sends one HTTP request with an optional X-Forwarded-For header; returns
/// whether any response bytes arrived (echo backend mirrors the request, so
/// success = bytes, denial = zero-byte close).
async fn send_request(edge: SocketAddr, xff: Option<&str>) -> bool {
    let Ok(mut sock) = TcpStream::connect(edge).await else {
        return false;
    };
    let xff_line = xff.map_or(String::new(), |v| format!("X-Forwarded-For: {v}\r\n"));
    let req = format!("GET / HTTP/1.1\r\nHost: test.local\r\n{xff_line}Connection: close\r\n\r\n");
    if sock.write_all(req.as_bytes()).await.is_err() {
        return false;
    }
    let mut buf = [0u8; 128];
    matches!(sock.read(&mut buf).await, Ok(n) if n > 0)
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
            send_request(edge, Some("6.6.6.6, 198.51.100.7")).await,
            "first three connections should pass"
        );
    }
    // Budget exhausted for that effective IP only.
    assert!(
        !send_request(edge, Some("6.6.6.6, 198.51.100.7")).await,
        "4th connection from the same effective IP should be rate limited"
    );
    // A different client is isolated from the exhausted budget.
    assert!(
        send_request(edge, Some("203.0.113.9")).await,
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
        !send_request(edge, None).await,
        "trusted proxy without X-Forwarded-For must be rejected fail-closed"
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
        send_request(edge, Some("6.6.6.6, 198.51.100.7")).await,
        "untrusted peer forges XFF: request still routes, keyed on the peer"
    );
}
