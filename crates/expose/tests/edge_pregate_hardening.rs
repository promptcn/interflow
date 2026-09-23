//! e2e: verifies the pre-handshake resource governance on the expose public
//! faces.
//!
//! The stack runs in ACME mode against an unreachable local directory, so no
//! certificate is ever issued — every test asserts on the gates that run
//! BEFORE the handshake completes, which is exactly the surface this batch
//! hardens:
//!
//! 1. the per-IP gate runs before the TLS accept (a dribbled or flooding
//!    ClientHello cannot outwait the gate), and the pre-acquired guard is
//!    reused — never double-counted;
//! 2. the ClientHello read and the handshake completion each carry a 10s
//!    deadline (`interflow_edge_tls_handshake_timeout`);
//! 3. an SNI outside the certificate/route host set is closed right after
//!    the acceptor (`interflow_edge_sni_rejected`);
//! 4. the :80 HTTP-01/redirect face runs the same per-IP rate limit and
//!    concurrency caps as :443 (one shared budget).
//!
//! Note: a pre-TLS (:443) denial still manifests as "peer closes before
//! sending any bytes" — no handshake has started, so there is no channel to
//! answer on. A :80 denial is answered with a real HTTP status (plaintext
//! face). Where an exact count matters (single vs double accounting) the
//! oracle is this test's own audit JSONL, which is immune to the
//! process-global metrics recorder being shared by concurrently running
//! tests.

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
use interflow_expose::edge::{
    AcmeOptions, ControlEndpointTls, EdgeConfig, EdgeListenerPolicy, IngressPrincipal, PublicTls,
    Route, WorkspaceTrust,
};
use interflow_testkit::metrics_harness::{counter_value, eventually, init_tracing};
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

/// Starts the edge in ACME mode (no reachable ACME directory → no
/// certificate is ever issued) and returns (edge_listen, http01_listen).
async fn spawn_stack(
    rate_per_ip_per_min: u32,
    audit_path: Option<PathBuf>,
) -> (SocketAddr, SocketAddr) {
    let edge_port = interflow_testkit::pick_ephemeral_port();
    let hub_port = interflow_testkit::pick_ephemeral_port();
    let http_port = interflow_testkit::pick_ephemeral_port();
    let edge_listen: SocketAddr = format!("127.0.0.1:{edge_port}").parse().unwrap();
    let hub_listen: SocketAddr = format!("127.0.0.1:{hub_port}").parse().unwrap();
    let http_listen: SocketAddr = format!("127.0.0.1:{http_port}").parse().unwrap();

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
        audit_path,
        listener: EdgeListenerPolicy {
            new_conn_rate_per_ip_per_minute: rate_per_ip_per_min,
            ..EdgeListenerPolicy::default()
        },
        public_tls: PublicTls::Acme(AcmeOptions {
            hosts: vec!["test.local".to_string()],
            email: "pregate-test@interflow.invalid".to_string(),
            // Unreachable local directory: the order loop warns and backs
            // off forever; nothing here needs issuance (every assertion is
            // about the pre-handshake gates).
            directory: Some("https://127.0.0.1:1/dir".to_string()),
            directory_ca: None,
            cache_dir: std::env::temp_dir()
                .join(format!("interflow-pregate-{}", uuid::Uuid::new_v4())),
            http_listen,
        }),
        agent_recovery_timeout: Duration::from_secs(120),
        ..EdgeConfig::default()
    };
    tokio::task::spawn(interflow_expose::edge::run(edge_config));

    // Wait only for the hub (+ a moment for the public listeners): touching
    // :443 or :80 for readiness would consume rate tokens.
    interflow_testkit::wait_for_tcp(hub_listen, Duration::from_secs(5))
        .await
        .expect("hub should start within 5s");
    tokio::time::sleep(Duration::from_millis(300)).await;
    (edge_listen, http_listen)
}

/// Connects to `addr`, retrying briefly while the listener is still binding
/// (a refused connect never consumed a rate token).
async fn connect_with_retry(addr: SocketAddr) -> TcpStream {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    loop {
        match TcpStream::connect(addr).await {
            Ok(sock) => return sock,
            Err(_e) if tokio::time::Instant::now() < deadline => {
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
            Err(e) => panic!("connect {addr} kept failing: {e}"),
        }
    }
}

/// One raw exchange: connect, write `payload`, return the response bytes that
/// arrive within 2s. Empty = dropped without a response (the gates' silent
/// close). A 2s timeout without bytes AND without a close fails the test —
/// every admitted or denied path here answers or closes well inside it.
async fn attempt(addr: SocketAddr, payload: &[u8]) -> Vec<u8> {
    let mut sock = connect_with_retry(addr).await;
    if sock.write_all(payload).await.is_err() {
        return Vec::new(); // reset before/during the write
    }
    let mut buf = vec![0u8; 256];
    match tokio::time::timeout(Duration::from_secs(2), sock.read(&mut buf)).await {
        Ok(Ok(n)) => {
            buf.truncate(n);
            buf
        }
        Ok(Err(_)) => Vec::new(),
        Err(_) => panic!("no response and no close within 2s: {addr}"),
    }
}

/// Captures a real ClientHello record for `server_name`: a rustls client (no
/// cert verification) is pointed at a local sink that reads exactly one TLS
/// record — the client's first flight — so the bytes can be replayed raw.
async fn capture_client_hello(server_name: &str) -> Vec<u8> {
    let sink = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let sink_addr = sink.local_addr().unwrap();
    let name = server_name.to_string();
    let client_task = tokio::spawn(async move {
        let config = rustls::ClientConfig::builder()
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(NoVerify))
            .with_no_client_auth();
        let connector = tokio_rustls::TlsConnector::from(Arc::new(config));
        let tcp = TcpStream::connect(sink_addr).await.unwrap();
        let server_name = rustls::pki_types::ServerName::try_from(name).unwrap();
        // The handshake fails (the sink never answers); only the bytes on
        // the wire matter.
        let _ = connector.connect(server_name, tcp).await;
    });
    let (mut sock, _) = sink.accept().await.unwrap();
    let mut header = [0u8; 5];
    sock.read_exact(&mut header).await.unwrap();
    let len = u16::from_be_bytes([header[3], header[4]]) as usize;
    let mut hello = vec![0u8; 5 + len];
    hello[..5].copy_from_slice(&header);
    sock.read_exact(&mut hello[5..]).await.unwrap();
    client_task.abort();
    hello
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

/// Polls this test's audit JSONL until `needle` appears `expect` times (the
/// audit writer flushes per line, but asynchronously).
async fn audit_count_reaches(audit_path: &PathBuf, needle: &str, expect: usize) {
    let count = |content: String| content.lines().filter(|l| l.contains(needle)).count();
    let path = audit_path.clone();
    eventually(
        move || {
            std::fs::read_to_string(&path)
                .map(|c| count(c))
                .unwrap_or(0)
                >= expect
        },
        Duration::from_secs(3),
        "audit records to appear",
    )
    .await;
    let got = std::fs::read_to_string(audit_path)
        .map(|c| count(c))
        .unwrap_or(0);
    assert_eq!(
        got, expect,
        "audit should hold exactly {expect} record(s) containing {needle:?}"
    );
}

/// Pre-TLS per-IP gate: with quota 4 the first four connections are admitted
/// (each consumes exactly one token and reaches the TLS acceptor — the
/// handshake then fails, as no certificate is issued against the unreachable
/// directory), the fifth is denied before any handshake byte is read.
///
/// The audit oracle (this test's own JSONL — immune to the process-global
/// metrics recorder shared with concurrently running tests) distinguishes all
/// failure modes: a gate placed after the TLS accept would never fire here
/// (every handshake fails first → zero `rate_limited` records), and
/// double-counting the pre-acquired guard would exhaust the quota at the
/// third connection (→ three records by the fifth attempt). Exactly one
/// record after five attempts is the single-counting, pre-handshake behavior.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn pre_tls_rate_limit_denies_before_handshake() {
    init_tracing();
    let audit_path = std::env::temp_dir().join(format!(
        "interflow_pregate_audit_{}.jsonl",
        uuid::Uuid::new_v4()
    ));
    let (edge, _http) = spawn_stack(4, Some(audit_path.clone())).await;
    let hello = capture_client_hello("test.local").await;

    for _ in 0..4 {
        attempt(edge, &hello).await;
    }
    let fifth = attempt(edge, &hello).await;
    assert!(
        fifth.is_empty(),
        "the over-quota connection must be dropped without any response bytes"
    );
    audit_count_reaches(&audit_path, "rate_limited", 1).await;
    let _ = std::fs::remove_file(&audit_path);
}

/// TLS handshake deadline: a client that dribbles the first 5 bytes of its
/// ClientHello and stalls is closed at the 10s deadline and counted.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn tls_handshake_deadline_closes_slow_clienthello() {
    init_tracing();
    let (edge, _http) = spawn_stack(0, None).await;
    let hello = capture_client_hello("test.local").await;

    let mut sock = connect_with_retry(edge).await;
    sock.write_all(&hello[..5]).await.expect("write 5 bytes");
    let start = tokio::time::Instant::now();
    let mut buf = [0u8; 1];
    let result = tokio::time::timeout(Duration::from_secs(15), sock.read(&mut buf)).await;
    let elapsed = start.elapsed();

    assert!(
        elapsed >= Duration::from_secs(9) && elapsed < Duration::from_secs(13),
        "should close at the 10s handshake deadline, actual {elapsed:?}"
    );
    match result {
        Ok(Ok(0)) | Ok(Err(_)) => {}
        Ok(Ok(n)) => panic!("no response data expected, but read {n} bytes"),
        Err(_) => panic!("read timed out without the connection being closed"),
    }
    let before = counter_value("interflow_edge_tls_handshake_timeout");
    assert!(
        before >= 1,
        "the stalled handshake must be counted (snapshot says {before})"
    );
}

/// SNI allowlist pre-check: an SNI outside the certificate/route host set is
/// closed right after the acceptor, before the handshake; a known SNI is not.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn unknown_sni_closed_before_handshake() {
    init_tracing();
    let (edge, _http) = spawn_stack(0, None).await;
    let known = capture_client_hello("test.local").await;
    let unknown = capture_client_hello("unknown.test").await;

    let before = counter_value("interflow_edge_sni_rejected");
    attempt(edge, &known).await;
    assert_eq!(
        counter_value("interflow_edge_sni_rejected"),
        before,
        "a known SNI must pass the pre-check"
    );

    let resp = attempt(edge, &unknown).await;
    assert!(
        resp.is_empty(),
        "an unknown-SNI connection must be closed without a response"
    );
    assert_eq!(
        counter_value("interflow_edge_sni_rejected"),
        before + 1,
        "the unknown SNI must be counted exactly once"
    );
}

/// :80 rate limit: with quota 5 the first five HTTP requests are answered
/// with the canonical 301 redirect, the sixth is answered `429` (the :80
/// face speaks plaintext HTTP, so a gate denial is a real answer, not a
/// bare close — the shared budget with :443 makes the rejection observable).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn http01_port80_rate_limited() {
    init_tracing();
    let audit_path = std::env::temp_dir().join(format!(
        "interflow_pregate_audit_{}.jsonl",
        uuid::Uuid::new_v4()
    ));
    let (_edge, http) = spawn_stack(5, Some(audit_path.clone())).await;
    let request = b"GET / HTTP/1.1\r\nHost: test.local\r\nConnection: close\r\n\r\n";

    for i in 0..5 {
        let resp = attempt(http, request).await;
        assert!(
            resp.starts_with(b"HTTP/1.1 301"),
            "request #{i} within quota should get the 301 redirect, got {:?}",
            String::from_utf8_lossy(&resp)
        );
    }
    let sixth = attempt(http, request).await;
    let answer = String::from_utf8_lossy(&sixth).into_owned();
    assert!(
        answer.starts_with("HTTP/1.1 429 Too Many Requests\r\n"),
        "the over-quota :80 request must be answered 429, got: {answer}"
    );
    assert!(
        answer.to_ascii_lowercase().contains("retry-after: 12"),
        "Retry-After must quote one refill interval (ceil(60/5)=12s): {answer}"
    );
    audit_count_reaches(&audit_path, "rate_limited", 1).await;
    let _ = std::fs::remove_file(&audit_path);
}

/// :80 per-IP concurrency cap: 64 connections from one IP each holding an
/// incomplete request head (each occupies one slot until the 10s head
/// timeout) fill the per-IP budget; the 65th is denied.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn http01_port80_concurrency_cap() {
    init_tracing();
    let (_edge, http) = spawn_stack(0, None).await;
    let partial_head = b"GET / HTTP/1.1\r\nHost: te"; // no blank line → head never completes

    let mut holders = Vec::new();
    for _ in 0..64 {
        let mut sock = connect_with_retry(http).await;
        sock.write_all(partial_head)
            .await
            .expect("write partial head");
        holders.push(sock);
    }
    // Let the accept loop gate every holder before probing (accepts are
    // processed in order; a moment is amply sufficient).
    tokio::time::sleep(Duration::from_millis(300)).await;

    let before = counter_value("interflow_edge_conn_rejected");
    let probe = attempt(
        http,
        b"GET / HTTP/1.1\r\nHost: test.local\r\nConnection: close\r\n\r\n",
    )
    .await;
    let answer = String::from_utf8_lossy(&probe).into_owned();
    assert!(
        answer.starts_with("HTTP/1.1 503 Service Unavailable\r\n"),
        "the 65th concurrent connection must be answered 503 (concurrency, not rate), got: {answer}"
    );
    let after = counter_value("interflow_edge_conn_rejected");
    assert!(
        after > before,
        "the denied 65th connection must be counted (before {before}, after {after})"
    );
    drop(holders);
}
