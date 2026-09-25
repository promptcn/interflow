//! The nginx stream fragment fronts the registrar with a PROXY protocol
//! preamble (v1 on stock nginx) on the SNI-dispatch leg — the accept loop
//! must consume the framing before the TLS acceptor sees the wire. These
//! cases pin both wire versions; the headerless path is covered by the
//! enroll/renew lifecycle in `http.rs`.

use interflow_identity::issuance::{IssuerStore, LeafTtl};
use interflow_registrar::EnrollmentCodes;
use std::net::TcpListener;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio_rustls::rustls::RootCertStore;
use tokio_rustls::rustls::pki_types::ServerName;

/// Spawns the registrar (same setup as `http.rs`) and returns its endpoint
/// plus the realm CA PEM for verification.
fn spawn_registrar() -> (String, String, tempfile::TempDir) {
    let dir = tempfile::tempdir().unwrap();
    let issuer = IssuerStore::open(dir.path().join("issuer"));
    issuer.ensure_realm().unwrap();
    issuer.ensure_policy_key().unwrap();
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    drop(listener);
    let endpoint = format!("https://127.0.0.1:{port}");
    let tls = issuer
        .issue_control_endpoint("test", "registrar", &endpoint)
        .unwrap();
    std::fs::write(dir.path().join("registrar.crt"), &tls.chain_pem).unwrap();
    std::fs::write(dir.path().join("registrar.key"), &tls.key_pem).unwrap();
    EnrollmentCodes::open(dir.path().join("issuer/enrollments.json"))
        .unwrap()
        .create(
            "test",
            interflow_identity::PrincipalKind::Agent,
            None,
            "desktop",
        )
        .unwrap();

    tokio::spawn(interflow_registrar::server::serve(
        dir.path().join("issuer"),
        interflow_registrar::server::ServeOptions {
            listen: format!("127.0.0.1:{port}").parse().unwrap(),
            public_endpoint: endpoint.clone(),
            tls_cert: dir.path().join("registrar.crt"),
            tls_key: dir.path().join("registrar.key"),
            ttl: LeafTtl::default_ttl(),
            control_endpoint: "https://relay.test".to_owned(),
            hub_endpoints: Default::default(),
        },
    ));
    let ca = issuer.realm_issuer().unwrap().cert_pem().to_owned();
    (endpoint, ca, dir)
}

fn v2_preamble(src: [u8; 4]) -> Vec<u8> {
    let mut h = Vec::new();
    h.extend_from_slice(&[
        0x0D, 0x0A, 0x0D, 0x0A, 0x00, 0x0D, 0x0A, 0x51, 0x55, 0x49, 0x54, 0x0A,
    ]);
    h.push(0x21); // ver2 cmd PROXY
    h.push(0x11); // fam TCP4
    h.extend_from_slice(&12u16.to_be_bytes()); // payload length
    h.extend_from_slice(&src); // source address
    h.extend_from_slice(&[10, 0, 0, 1]); // destination address
    h.extend_from_slice(&47115u16.to_be_bytes()); // source port
    h.extend_from_slice(&443u16.to_be_bytes()); // destination port
    h
}

/// Preamble + TLS handshake + `GET /health` over the manual rustls stack
/// (reqwest cannot emit preamble bytes).
async fn health_over_preamble(endpoint: &str, ca: &str, preamble: &[u8]) -> String {
    let mut roots = RootCertStore::empty();
    let mut ca_bytes = ca.as_bytes();
    let certs: Vec<_> = rustls_pemfile::certs(&mut ca_bytes)
        .collect::<Result<_, _>>()
        .unwrap();
    roots.add_parsable_certificates(certs);
    let connector = tokio_rustls::TlsConnector::from(std::sync::Arc::new(
        tokio_rustls::rustls::ClientConfig::builder()
            .with_root_certificates(roots)
            .with_no_client_auth(),
    ));

    let host = endpoint.trim_start_matches("https://");
    let mut tcp = None;
    for _ in 0..100 {
        if let Ok(stream) = tokio::net::TcpStream::connect(host).await {
            tcp = Some(stream);
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    }
    let mut tcp = tcp.expect("registrar did not become ready");
    tcp.write_all(preamble).await.unwrap();
    let addr: std::net::SocketAddr = host.parse().unwrap();
    let server_name = ServerName::from(addr.ip());
    let mut tls = connector.connect(server_name, tcp).await.unwrap();

    tls.write_all(b"GET /health HTTP/1.1\r\n").await.unwrap();
    tls.write_all(format!("Host: {host}\r\n").as_bytes())
        .await
        .unwrap();
    tls.write_all(b"Connection: close\r\n\r\n").await.unwrap();

    let mut response = String::new();
    tls.read_to_string(&mut response).await.unwrap();
    response
}

#[tokio::test]
async fn v1_preamble_then_tls_handshake_serves_health() {
    let _ = tokio_rustls::rustls::crypto::aws_lc_rs::default_provider().install_default();
    let (endpoint, ca, _dir) = spawn_registrar();
    let response = health_over_preamble(
        &endpoint,
        &ca,
        b"PROXY TCP4 198.51.100.7 10.0.0.1 47115 443\r\n",
    )
    .await;
    assert!(response.starts_with("HTTP/1.1 200"), "{response}");
    assert!(response.contains("ok"), "{response}");
}

#[tokio::test]
async fn v2_preamble_then_tls_handshake_serves_health() {
    let _ = tokio_rustls::rustls::crypto::aws_lc_rs::default_provider().install_default();
    let (endpoint, ca, _dir) = spawn_registrar();
    let response = health_over_preamble(&endpoint, &ca, &v2_preamble([198, 51, 100, 7])).await;
    assert!(response.starts_with("HTTP/1.1 200"), "{response}");
    assert!(response.contains("ok"), "{response}");
}

/// A preamble must be consumed exactly: bytes after the framing are the
/// TLS record, not part of the header. The two cases above prove it
/// end-to-end (the handshake would fail on any misframing); this one
/// additionally pins the plain-path invariant — no preamble, plain health.
#[tokio::test]
async fn no_preamble_still_serves_health() {
    let _ = tokio_rustls::rustls::crypto::aws_lc_rs::default_provider().install_default();
    let (endpoint, ca, _dir) = spawn_registrar();
    let response = health_over_preamble(&endpoint, &ca, b"").await;
    assert!(response.starts_with("HTTP/1.1 200"), "{response}");
}
