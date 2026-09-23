//! Public-port control dispatch: on an ACME ingress, a ClientHello whose
//! SNI is the control endpoint's server name completes its handshake with
//! the control plane's own mTLS configuration
//! and is served by the embedded hub — one public port, two planes.
//!
//! The dispatch is distinguished from the business plane by admission
//! semantics: the control plane REQUIRES client certificates, the business
//! plane does not.

use interflow_core::security::proxy_protocol::ProxyProtocolConfig;
use interflow_core::security::{AuditSink, ProxyProtocolPolicy, XffMode, XffPolicy};
use interflow_core::tls::TlsMinVersion;
use interflow_expose::edge::host_router::HostRouter;
use interflow_expose::edge::ingress_identity::IngressIdentity;
use interflow_expose::edge::listener::{ControlDispatch, EdgeListener, PublicTlsPlanes};
use interflow_mesh::hub::HubServer;
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

const CONTROL_HOST: &str = "tunnel.test";
const BUSINESS_HOST: &str = "app.test";

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn public_port_dispatches_control_sni_to_the_hub_plane() {
    let _ = tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info,interflow=debug")),
        )
        .try_init();
    let certs = interflow_testkit::certs::TestCerts::generate("dispatch", "agent-dispatch");
    let edge_port = interflow_testkit::pick_ephemeral_port();
    let listen: SocketAddr = format!("127.0.0.1:{edge_port}").parse().expect("addr");

    // The embedded control plane: hub state + the mTLS plane built from the
    // test CA (same assembly as the edge, minus its own listener — only the
    // dispatch handle is used).
    let ca_pem = std::fs::read_to_string(certs.ca_path()).expect("ca pem");
    let roots = vec![
        interflow_core::tls::TenantTrustRoot::from_pem_with_crls(
            "test",
            false,
            ca_pem.as_bytes(),
            &[],
        )
        .expect("tenant root"),
    ];
    let plane = interflow_core::tls::build_tls_plane(
        &certs.server_cert_path().display().to_string(),
        &certs.server_key_path().display().to_string(),
        &roots,
        TlsMinVersion::V1_2,
    )
    .expect("hub plane");
    let control_config = plane.config.clone();
    let hub_cfg = interflow_testkit::config::hub_config(0, &certs, vec![]);
    let hub = HubServer::with_tls_plane(hub_cfg, plane).expect("hub server");

    // The business/challenge planes: one-way TLS (no client certs) — the
    // contrast that proves which plane a handshake landed on.
    let mut business_plain = interflow_core::tls::server::build_rustls_server_config_with_roots(
        &certs.server_cert_path().display().to_string(),
        &certs.server_key_path().display().to_string(),
        None,
        TlsMinVersion::V1_2,
    )
    .expect("business config");
    business_plain.alpn_protocols = vec![b"h2".to_vec()];
    let business_config = Arc::new(business_plain);

    let listener = EdgeListener {
        listen_addr: listen,
        node: "test-edge".to_string(),
        tls: Some(PublicTlsPlanes {
            challenge: Arc::clone(&business_config),
            default: business_config,
            host_allowlist: Arc::new(std::iter::once(BUSINESS_HOST.to_string()).collect()),
            control: Some(Arc::new(ControlDispatch {
                host: CONTROL_HOST.to_string(),
                config: control_config,
                hub: hub.dispatch_handle(),
            })),
        }),
        router: Arc::new(HostRouter::from_routes(&[]).expect("empty router")),
        tunnels: HashMap::new(),
        host_peek_timeout: Duration::from_secs(10),
        stream_idle_timeout: Duration::from_secs(300),
        conn_tracker: Arc::new(interflow_core::security::ConnTracker::new(100, 1000)),
        rate_limiter: None,
        audit: AuditSink::disabled(),
        route_breaker: None,
        proxy_policy: Arc::new(
            ProxyProtocolPolicy::from_config(&ProxyProtocolConfig::default()).expect("policy"),
        ),
        xff_policy: Arc::new(
            XffPolicy::new(XffMode::Off, &["127.0.0.1".to_string()]).expect("xff policy"),
        ),
        identity: Arc::new(IngressIdentity::new(vec![], vec![]).expect("identity")),
    };
    tokio::spawn(listener.run());
    interflow_testkit::wait_for_tcp(listen, Duration::from_secs(5))
        .await
        .expect("listener up");

    let (client_cert, client_key) = certs.client_paths();
    let client = Some((client_cert, client_key));

    // NOTE: under TLS 1.3 the client handshake can "complete" before the
    // server has validated the client certificate (the refusal alert lands
    // afterwards), so the discriminator is post-handshake LIVENESS: a
    // refused connection dies on first read, a served one sees the h2
    // server's SETTINGS frame.

    // 1. Control SNI WITHOUT a client certificate → the control plane
    //    refuses (mTLS): proves the dispatch landed on the hub plane, not
    //    the one-way business config.
    let mut refused = tls_handshake(listen, CONTROL_HOST, None)
        .await
        .expect("client-side handshake completes (refusal follows)");
    assert_eq!(
        connection_liveness(&mut refused).await,
        Liveness::Dead,
        "control plane must demand client certificates"
    );

    // 2. Control SNI WITH the agent certificate → dispatched to the hub
    //    plane: served, h2 negotiated, connection alive.
    let mut control_tls = tls_handshake(listen, CONTROL_HOST, client.clone())
        .await
        .expect("dispatched control handshake completes");
    assert_eq!(
        control_tls.get_ref().1.alpn_protocol(),
        Some(&b"h2"[..]),
        "control plane negotiates h2"
    );
    assert_eq!(
        connection_liveness(&mut control_tls).await,
        Liveness::Alive,
        "dispatched control connection is served by the hub plane"
    );

    // 3. Unknown SNI → closed before the handshake (allowlist discipline
    //    still owns everything the dispatch does not claim).
    assert!(
        tls_handshake(listen, "nope.test", client.clone())
            .await
            .is_none(),
        "unknown SNI must be closed pre-handshake"
    );

    // 4. Business SNI on the same port → the one-way business plane accepts
    //    (no client certificate needed) — the two planes coexist on 443.
    let mut business_tls = tls_handshake(listen, BUSINESS_HOST, None)
        .await
        .expect("business handshake completes");
    assert!(
        business_tls.get_ref().1.alpn_protocol().is_some(),
        "business plane negotiated an ALPN protocol"
    );
    assert_eq!(
        connection_liveness(&mut business_tls).await,
        Liveness::Alive,
        "business SNI keeps the normal TLS path"
    );
}

#[derive(Debug, PartialEq, Eq)]
enum Liveness {
    /// The connection delivered bytes (or timed out waiting): served.
    Alive,
    /// EOF or transport error: refused/dead.
    Dead,
}

/// Post-handshake liveness: a served h2 connection sees the server's
/// SETTINGS frame quickly; a refused one dies on first read.
async fn connection_liveness<S>(tls: &mut tokio_rustls::client::TlsStream<S>) -> Liveness
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    use tokio::io::AsyncReadExt;
    let mut buf = [0u8; 64];
    match tokio::time::timeout(Duration::from_secs(3), tls.read(&mut buf)).await {
        Ok(Ok(0) | Err(_)) => Liveness::Dead,
        // Bytes arrived, or nothing did within the budget — both mean the
        // connection is still being served rather than refused.
        Ok(Ok(_)) | Err(_) => Liveness::Alive,
    }
}

/// One TLS attempt; `None` = the handshake was refused. Certificate
/// verification is disabled: the target of every assertion is WHICH plane
/// the dispatch chose (admission semantics), not chain validation.
async fn tls_handshake(
    addr: SocketAddr,
    sni: &str,
    client: Option<(std::path::PathBuf, std::path::PathBuf)>,
) -> Option<tokio_rustls::client::TlsStream<tokio::net::TcpStream>> {
    let tcp = tokio::net::TcpStream::connect(addr).await.ok()?;
    let builder = rustls::ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(NoVerify));
    let mut config = match client {
        Some((cert_path, key_path)) => {
            let cert_pem = std::fs::read(&cert_path).expect("client cert file");
            let key_pem = std::fs::read(&key_path).expect("client key file");
            let cert = rustls_pemfile::certs(&mut cert_pem.as_slice())
                .collect::<Result<Vec<_>, _>>()
                .expect("client cert pem");
            let key = rustls_pemfile::private_key(&mut key_pem.as_slice())
                .expect("client key pem")
                .expect("client key present");
            builder
                .with_client_auth_cert(cert, key)
                .expect("client auth config")
        }
        None => builder.with_no_client_auth(),
    };
    config.alpn_protocols = vec![b"h2".to_vec()];
    let connector = tokio_rustls::TlsConnector::from(Arc::new(config));
    let name = rustls::pki_types::ServerName::try_from(sni.to_owned()).ok()?;
    match tokio::time::timeout(Duration::from_secs(5), connector.connect(name, tcp)).await {
        Ok(Ok(stream)) => Some(stream),
        Ok(Err(e)) => {
            eprintln!("tls_handshake({sni}) failed: {e}");
            None
        }
        Err(_) => {
            eprintln!("tls_handshake({sni}) timed out");
            None
        }
    }
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
        use rustls::SignatureScheme::*;
        vec![
            RSA_PKCS1_SHA256,
            RSA_PKCS1_SHA384,
            RSA_PKCS1_SHA512,
            ECDSA_NISTP256_SHA256,
            ECDSA_NISTP384_SHA384,
            ED25519,
            RSA_PSS_SHA256,
            RSA_PSS_SHA384,
            RSA_PSS_SHA512,
        ]
    }
}
