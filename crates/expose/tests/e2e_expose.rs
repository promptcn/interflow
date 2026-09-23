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
use interflow_expose::client::{ExposeArgs, LocalService};
use interflow_expose::edge::{
    ControlEndpointTls, EdgeConfig, EdgeListenerPolicy, HostRouter, IngressPrincipal, Route,
    WorkspaceTrust,
};
use interflow_mesh::config::TransportKind;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

/// HostRouter unit test: normalization, case handling, port handling.
#[tokio::test]
async fn host_router_routes_by_host() {
    let router = Arc::new(
        HostRouter::from_routes(&[Route {
            host: "test.local".into(),
            workspace: "test".into(),
            agent_id: "expose-test".into(),
            service_id: "web".into(),
        }])
        .unwrap(),
    );

    assert_eq!(router.len(), 1);
    let r = router.lookup("test.local").expect("route found");
    assert_eq!(r.agent_id, "expose-test");
    assert_eq!(r.service_id, "web");

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
    let echo_addr = interflow_testkit::echo_server().await.0;

    // 2. Grab ports
    let edge_port = interflow_testkit::pick_ephemeral_port();
    let hub_port = interflow_testkit::pick_ephemeral_port();
    let edge_listen: SocketAddr = format!("127.0.0.1:{edge_port}").parse().unwrap();
    let hub_listen: SocketAddr = format!("127.0.0.1:{hub_port}").parse().unwrap();

    // 3. Temp routes.toml
    // 4. Spawn edge (hub server + edge agent + listener)
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
            ..EdgeListenerPolicy::default()
        },
        agent_recovery_timeout: Duration::from_secs(120),
        ..EdgeConfig::default()
    };
    let edge_handle = tokio::task::spawn(interflow_expose::edge::run(edge_config));

    // 5. Wait for the hub listener to be ready
    interflow_testkit::wait_for_tcp(hub_listen, Duration::from_secs(5))
        .await
        .expect("hub should start within 5s");
    // Wait for the edge listener to be ready
    interflow_testkit::wait_for_tcp(edge_listen, Duration::from_secs(5))
        .await
        .expect("edge listener should start within 5s");

    // 6. Spawn the expose client (connects to the edge's hub, agent_id=expose-test, egress to echo)
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
    let client_handle = tokio::task::spawn(async move { client.join().await });

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

/// A tiny backend that answers every connection with its own marker —
/// unlike the byte-echo server, this makes *which* backend served a
/// request observable.
async fn marker_backend(marker: &'static str) -> SocketAddr {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        loop {
            let Ok((mut sock, _)) = listener.accept().await else {
                return;
            };
            let _ = sock.write_all(marker.as_bytes()).await;
        }
    });
    addr
}

/// Two services on one agent, selected **by id** across the edge: each
/// host reaches its own service's backend even though the route order and
/// the rule order deliberately disagree — the regression guard for the
/// pre-id era's positional `Vec<u16>` contract (backlog 2026-09-23, pit 1:
/// once per-service addresses exist, positional pairing silently crosses).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn two_services_route_by_id_not_position() {
    let _ = tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "info,interflow=debug".into()),
        )
        .try_init();

    // Two distinguishable backends.
    let alpha_addr = marker_backend("BACKEND-ALPHA\n").await;
    let beta_addr = marker_backend("BACKEND-BETA\n").await;

    let edge_port = interflow_testkit::pick_ephemeral_port();
    let hub_port = interflow_testkit::pick_ephemeral_port();
    let edge_listen: SocketAddr = format!("127.0.0.1:{edge_port}").parse().unwrap();
    let hub_listen: SocketAddr = format!("127.0.0.1:{hub_port}").parse().unwrap();

    // Routes deliberately in the OPPOSITE order of the agent's rules: any
    // positional pairing would cross-wire the hosts.
    let certs = interflow_testkit::certs::TestCerts::generate("e2e2", "expose-test");
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
        routes: vec![
            Route {
                host: "beta.local".to_string(),
                workspace: "test".to_string(),
                agent_id: "expose-test".to_string(),
                service_id: "beta".to_string(),
            },
            Route {
                host: "alpha.local".to_string(),
                workspace: "test".to_string(),
                agent_id: "expose-test".to_string(),
                service_id: "alpha".to_string(),
            },
        ],
        listener: EdgeListenerPolicy::default(),
        agent_recovery_timeout: Duration::from_secs(120),
        ..EdgeConfig::default()
    };
    let edge_handle = tokio::task::spawn(interflow_expose::edge::run(edge_config));
    interflow_testkit::wait_for_tcp(hub_listen, Duration::from_secs(5))
        .await
        .expect("hub should start within 5s");
    interflow_testkit::wait_for_tcp(edge_listen, Duration::from_secs(5))
        .await
        .expect("edge listener should start within 5s");

    // Agent rules declared alpha-first; the routes above are beta-first.
    let (client_cert, client_key) = certs.client_paths();
    let client_args = ExposeArgs {
        log_name: None,
        services: vec![
            LocalService {
                id: "alpha".into(),
                target_addr: alpha_addr,
                overridden: false,
            },
            LocalService {
                id: "beta".into(),
                target_addr: beta_addr,
                overridden: false,
            },
        ],
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
    let client_handle = tokio::task::spawn(async move { client.join().await });

    let fetch = |host: &'static str| async move {
        let mut sock = TcpStream::connect(edge_listen).await.expect("connect edge");
        let request = format!("GET / HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n");
        sock.write_all(request.as_bytes())
            .await
            .expect("write request");
        let mut buf = vec![0u8; 64];
        let n = tokio::time::timeout(Duration::from_secs(3), sock.read(&mut buf))
            .await
            .expect("read should not timeout")
            .expect("read should succeed");
        String::from_utf8_lossy(&buf[..n]).into_owned()
    };

    let alpha_response = fetch("alpha.local").await;
    let beta_response = fetch("beta.local").await;
    edge_handle.abort();
    client_handle.abort();

    assert!(
        alpha_response.contains("BACKEND-ALPHA"),
        "alpha.local must reach the alpha service's backend, got {alpha_response:?}"
    );
    assert!(
        beta_response.contains("BACKEND-BETA"),
        "beta.local must reach the beta service's backend, got {beta_response:?}"
    );
}
