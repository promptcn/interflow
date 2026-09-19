//! e2e: QUIC transport for the expose scenario.
//!
//! Topology (single process): edge (embedded hub with TLS + QUIC listener,
//! edge self-dial over loopback h2) + expose client (`transport = "quic"`,
//! CA-verified) + echo backend.
//!
//! Because the edge's own dial stays on h2, a QUIC round trip here is at the
//! same time a cross-transport proof: h2 edge tunnel ↔ quic expose client,
//! relayed by the embedded hub (the same dual-stack relay the mesh scenario
//! e2e-verifies).

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
use interflow_expose::edge::{EdgeArgs, EdgeHubTls};
use interflow_mesh::agent::AgentEvent;
use interflow_mesh::config::TransportKind;
use interflow_testkit::certs::TestCerts;
use std::net::SocketAddr;
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

/// Grabs an ephemeral port (bound then released immediately).
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

/// Blocks until the expose client's agent session is established (the
/// registration handshake succeeded over QUIC), replacing magic sleeps.
async fn wait_for_session(handle: &mut interflow_mesh::agent::AgentHandle) {
    let mut events = handle.take_events();
    let deadline = tokio::time::Instant::now() + Duration::from_secs(15);
    loop {
        let ev = tokio::time::timeout_at(deadline, events.recv())
            .await
            .expect("session should establish within 15s")
            .expect("event channel should stay open");
        match ev {
            AgentEvent::SessionEstablished { agent_id } => {
                tracing::info!(agent_id, "expose client session established");
                return;
            }
            AgentEvent::StateChanged(s) => tracing::info!(state = ?s, "agent state changed"),
            AgentEvent::SessionEnded { reason } => {
                panic!("session ended before establishing: {reason}")
            }
        }
    }
}

/// Runs the full QUIC round trip.
///
/// `shared_port`: when true, the QUIC listener binds the same port number as
/// the hub TCP listener (the dual-stack default) and the client derives
/// `hub_quic_addr` from its hub URL instead of passing it explicitly.
async fn run_quic_round_trip(derived_addr: bool) {
    let _ = tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "info,interflow=debug".into()),
        )
        .try_init();

    // 1. echo backend + certs (SAN covers localhost + 127.0.0.1 → QUIC SNI ok)
    let echo_addr = spawn_echo().await;
    let _certs = TestCerts::generate("expose-quic-e2e", "unused-client-cn");

    // 2. Ports: with a derived address, QUIC shares the hub TCP port number
    let edge_port = pick_port();
    let hub_port = pick_port();
    let quic_port = if derived_addr { hub_port } else { pick_port() };
    let edge_listen: SocketAddr = format!("127.0.0.1:{edge_port}").parse().unwrap();
    let hub_listen: SocketAddr = format!("127.0.0.1:{hub_port}").parse().unwrap();
    let quic_listen: SocketAddr = format!("127.0.0.1:{quic_port}").parse().unwrap();

    // 3. Temp routes.toml
    let routes_path = std::env::temp_dir().join(format!(
        "interflow_test_routes_quic_{}.toml",
        uuid::Uuid::new_v4()
    ));
    std::fs::write(
        &routes_path,
        format!(
            r#"
[[routes]]
host = "test.local"
tenant = "test"
agent_id = "expose-quic-test"
remote_addr = "{echo_addr}"
"#
        ),
    )
    .expect("write routes.toml");

    // 4. Spawn edge: hub TLS on (QUIC mandates it) + QUIC listener on
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
        quic_listen: Some(quic_listen),
        agent_recovery_timeout_secs: 120,
        ..Default::default()
    };
    let edge_handle = tokio::task::spawn(interflow_expose::edge::run(edge_args));

    wait_for_tcp(edge_listen, Duration::from_secs(5))
        .await
        .expect("edge listener should start within 5s");
    wait_for_tcp(hub_listen, Duration::from_secs(5))
        .await
        .expect("edge hub should start within 5s");

    // 5. Spawn the expose client over QUIC (CA = the test CA; hub URL only
    //    matters for derivation in the derived variant)
    let (client_cert, client_key) = certs.named_client_cert("expose-quic-test");
    let client_args = ExposeArgs {
        local_ports: vec![echo_addr.port()],
        hub_url: format!("https://127.0.0.1:{hub_port}"),
        client_cert: Some(client_cert.display().to_string()),
        client_key: Some(client_key.display().to_string()),
        agent_id: "expose-quic-test".into(),
        ca_path: Some(certs.ca_path().display().to_string()),
        transport: TransportKind::Quic,
        hub_quic_addr: if derived_addr {
            None
        } else {
            Some(format!("127.0.0.1:{quic_port}"))
        },
    };
    let mut client_handle = interflow_expose::client::start(&client_args).expect("client start");
    wait_for_session(&mut client_handle).await;

    // 6. HTTP/1.1 request with the routed Host header → the echo backend
    //    reflects the bytes back through edge(h2) → hub → client(quic) → echo.
    let mut sock = TcpStream::connect(edge_listen)
        .await
        .expect("connect edge listener");
    let request = b"GET / HTTP/1.1\r\nHost: test.local\r\nConnection: close\r\n\r\n";
    sock.write_all(request).await.expect("write request");

    let mut response = vec![0u8; request.len()];
    let read_result =
        tokio::time::timeout(Duration::from_secs(5), sock.read_exact(&mut response)).await;

    client_handle.shutdown_graceful().await.ok();
    edge_handle.abort();
    let _ = std::fs::remove_file(&routes_path);

    read_result
        .expect("read should not timeout")
        .expect("read_exact should succeed");
    assert_eq!(
        response.as_slice(),
        request.as_ref(),
        "response should equal echoed request (full QUIC round trip)"
    );
}

/// Full chain over QUIC with an explicit `hub_quic_addr` (dedicated QUIC
/// port, different from the hub TCP port).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn full_edge_expose_quic_round_trip() {
    run_quic_round_trip(false).await;
}

/// Same chain, but the client derives `hub_quic_addr` from its hub URL —
/// valid because the edge binds QUIC on the hub TCP port number (the
/// dual-stack default).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn full_edge_expose_quic_derived_addr() {
    run_quic_round_trip(true).await;
}

/// `--quic-listen` without hub TLS must fail fast with a pointed config
/// error, before any listener binds.
#[tokio::test]
async fn edge_without_tls_fails_fast() {
    // Since the mTLS-only rework the edge hub requires --hub-cert/--hub-key
    // unconditionally (client certificates are verified at the TLS
    // handshake) — the old QUIC-only prerequisite is subsumed by it.
    let edge_args = EdgeArgs {
        listen_addr: format!("127.0.0.1:{}", pick_port()).parse().unwrap(),
        hub_listen_addr: format!("127.0.0.1:{}", pick_port()).parse().unwrap(),
        routes_path: "nonexistent-routes.toml".into(),
        tenant_cas: Vec::new(),
        proxy_protocol: Default::default(),
        hub_tls: None,
        quic_listen: None,
        agent_recovery_timeout_secs: 120,
        ..Default::default()
    };
    let err = interflow_expose::edge::run(edge_args)
        .await
        .expect_err("edge without hub TLS must fail");
    assert!(
        err.to_string().contains("mTLS requires"),
        "error should name the TLS requirement: {err}"
    );
}
