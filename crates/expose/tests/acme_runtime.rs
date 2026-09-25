//! ACME runtime e2e against pebble (Let's Encrypt's test CA).
//!
//! Gated by `INTERFLOW_PEBBLE` (the pebble directory URL, e.g.
//! `https://127.0.0.1:14000/dir`): without it the test skips — a real CA
//! is not a unit-test fixture. Run locally via `scripts/acme-pebble.sh` or
//! in CI where the pebble service container is started.
//!
//! Happy path: order → challenge → issuance → the live certificate serves
//! the public listener → an HTTPS request routes through the tunnel to the
//! echo backend.

use interflow_expose::client::{ExposeArgs, LocalService};
use interflow_expose::edge::{
    AcmeOptions, ControlEndpointTls, EdgeConfig, EdgeListenerPolicy, IngressPrincipal, PublicTls,
    Route, WorkspaceTrust,
};
use interflow_mesh::config::TransportKind;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn acme_issues_serves_and_routes() {
    let Ok(directory) = std::env::var("INTERFLOW_PEBBLE") else {
        eprintln!("skipping: INTERFLOW_PEBBLE (pebble directory URL) not set");
        return;
    };
    let _ = tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info,interflow=debug")),
        )
        .try_init();

    let certs = interflow_testkit::certs::TestCerts::generate("acme", "agent-acme");
    let (echo_addr, _echo_task) = interflow_testkit::echo_server().await;
    let (principal_cert, principal_key) = certs.named_client_cert("edge");
    let cache_dir =
        std::env::temp_dir().join(format!("interflow-acme-cache-{}", uuid::Uuid::new_v4()));

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
            host: "localhost".to_string(),
            workspace: "test".to_string(),
            agent_id: "agent-acme".to_string(),
            service_id: "web".to_string(),
        }],
        public_tls: PublicTls::Acme(AcmeOptions {
            hosts: vec!["localhost".to_string()],
            email: "pebble-test@interflow.invalid".to_string(),
            directory: Some(directory.clone()),
            directory_ca: std::env::var("INTERFLOW_PEBBLE_CA").ok().map(PathBuf::from),
            cache_dir: cache_dir.clone(),
            http_listen: "127.0.0.1:0".parse().unwrap(),
        }),
        listener: EdgeListenerPolicy::default(),
        agent_recovery_timeout: Duration::from_secs(120),
        ..EdgeConfig::default()
    };
    let edge = interflow_testkit::spawn_edge(edge_config).await;
    let edge_listen = edge.public_addr();
    let hub_port = edge.control_addr().port();

    // Egress agent behind the route.
    let (client_cert, client_key) = certs.client_paths();
    let args = ExposeArgs {
        log_name: None,
        services: vec![LocalService {
            id: "web".into(),
            target_addr: echo_addr,
            overridden: false,
        }],
        hub_url: format!("https://127.0.0.1:{hub_port}"),
        client_cert: Some(client_cert.display().to_string()),
        client_key: Some(client_key.display().to_string()),
        agent_id: "agent-acme".to_string(),
        ca_path: Some(certs.ca_path().display().to_string()),
        ingress_ca_path: Some(certs.ca_path().display().to_string()),
        transport: TransportKind::H2,
        hub_quic_addr: None,
    };
    let client = interflow_expose::client::start(&args).expect("agent start");
    assert!(
        interflow_testkit::wait_agent_connected(&client, Duration::from_secs(5)).await,
        "agent should register within 5s"
    );
    tokio::task::spawn(async move {
        let _ = client.join().await;
    });

    // Wait for issuance: the TLS handshake succeeds with the live
    // certificate and an HTTPS request round-trips through the tunnel.
    // Pebble can take a few seconds per order (retry with backoff).
    let request = b"GET / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n";
    let deadline = tokio::time::Instant::now() + Duration::from_secs(60);
    let response = loop {
        assert!(
            tokio::time::Instant::now() < deadline,
            "ACME issuance/serving did not come up within 60s; cache dir: {}",
            cache_dir.display()
        );
        if let Some(got) = try_https_round_trip(edge_listen, request).await {
            break got;
        }
        tokio::time::sleep(Duration::from_millis(500)).await;
    };
    // The echo backend mirrors the request bytes: a full match proves the
    // TLS handshake, Host routing, and tunnel round trip end to end.
    assert_eq!(
        response.as_slice(),
        request,
        "HTTPS request should round-trip through the ACME-served listener"
    );
    assert!(
        cache_dir.read_dir().is_ok_and(|mut d| d.next().is_some()),
        "acme cache should persist issued material"
    );
}

/// One attempt at the TLS round trip; `None` = not ready yet (handshake
/// failed / connection refused).
async fn try_https_round_trip(addr: SocketAddr, request: &[u8]) -> Option<Vec<u8>> {
    let tcp = tokio::net::TcpStream::connect(addr).await.ok()?;
    let config = rustls::ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(NoVerify))
        .with_no_client_auth();
    let connector = tokio_rustls::TlsConnector::from(Arc::new(config));
    let server_name = rustls::pki_types::ServerName::try_from("localhost".to_string()).ok()?;
    let mut tls = connector.connect(server_name, tcp).await.ok()?;
    tls.write_all(request).await.ok()?;
    // The echo backend mirrors the request and keeps the connection open —
    // read exactly the mirrored length, not to EOF.
    let mut buf = vec![0u8; request.len()];
    tokio::time::timeout(Duration::from_secs(5), tls.read_exact(&mut buf))
        .await
        .ok()?
        .ok()?;
    Some(buf)
}

#[derive(Debug)]
struct NoVerify;

impl rustls::client::danger::ServerCertVerifier for NoVerify {
    fn verify_server_cert(
        &self,
        _end_entity: &rustls::pki_types::CertificateDer<'_>,
        _intermediates: &[rustls::pki_types::CertificateDer<'_>],
        _server_name: &rustls::pki_types::ServerName<'_>,
        _ocsp_response: &[u8],
        _now: rustls::pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &rustls::pki_types::CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &rustls::pki_types::CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        vec![
            rustls::SignatureScheme::RSA_PKCS1_SHA256,
            rustls::SignatureScheme::RSA_PKCS1_SHA384,
            rustls::SignatureScheme::RSA_PKCS1_SHA512,
            rustls::SignatureScheme::ECDSA_NISTP256_SHA256,
            rustls::SignatureScheme::ECDSA_NISTP384_SHA384,
            rustls::SignatureScheme::ED25519,
            rustls::SignatureScheme::RSA_PSS_SHA256,
            rustls::SignatureScheme::RSA_PSS_SHA384,
            rustls::SignatureScheme::RSA_PSS_SHA512,
        ]
    }
}
