//! e2e: PROXY protocol negotiation on the control listener (the nginx
//! stream fragment fronts the mTLS-passthrough control leg with a v1
//! preamble; see (internal design notes)).
//!
//! 1. A v1 or v2 preamble + mTLS handshake must succeed and leave a
//!    serving h2 connection (the preamble is consumed before TLS).
//! 2. A headerless direct connection must keep working — mode `On`, not
//!    `Required`: the edge's internal agents self-dial the control
//!    endpoint headerless, and the "new binaries first, nginx conf
//!    second" rollout order relies on the same tolerance.
//! 3. A preamble from an untrusted source is hard-rejected before TLS.
//! 4. With pp off (default / direct topologies) a pp-prefixed TLS
//!    connection fails loudly — pinning the deployment invariant that
//!    pp-tolerant binaries must ship before the nginx conf starts
//!    emitting the preamble.
//! 5. Full-stack: an agent registering through a preamble-injecting
//!    forwarder is audited under the real client IP, not 127.0.0.1.

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
use interflow_core::security::{ProxyProtocolConfig, ProxyProtocolMode};
use interflow_expose::client::{ExposeArgs, LocalService};
use interflow_expose::edge::{
    ControlEndpointTls, EdgeConfig, IngressPrincipal, Route, WorkspaceTrust,
};
use interflow_mesh::config::TransportKind;
use interflow_testkit::certs::{PpVersion, TestCerts, tls_client_connect, tls_client_connect_pp};
use std::net::{IpAddr, SocketAddr};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

/// The fronted-topology control-leg policy: optional-accept, loopback
/// trusted (what `resolve_control_proxy_protocol` derives for
/// `frontend-proxy` / `manual` packs).
fn on_loopback() -> ProxyProtocolConfig {
    ProxyProtocolConfig {
        mode: ProxyProtocolMode::On,
        trusted_proxies: vec!["127.0.0.1".to_string(), "::1".to_string()],
    }
}

/// Spawns the edge (control + public listeners, internal workspace agents
/// self-dialing headerless) with the given control-leg pp policy; returns
/// (control addr, certs, audit path, echo backend).
async fn spawn_edge_with_pp(
    control_pp: ProxyProtocolConfig,
) -> (SocketAddr, TestCerts, std::path::PathBuf, SocketAddr) {
    let echo_addr = interflow_testkit::echo_server().await.0;
    let audit_path = std::env::temp_dir().join(format!(
        "interflow_test_control_pp_{}.jsonl",
        uuid::Uuid::new_v4()
    ));

    let certs = TestCerts::generate("e2e", "control-pp-test");
    let (principal_cert, principal_key) = certs.named_client_cert("edge");
    let edge_config = EdgeConfig {
        // :0 = kernel-assigned; spawn_edge hands back the bound addresses
        listen_addr: "127.0.0.1:0".parse().unwrap(),
        control_listen_addr: "127.0.0.1:0".parse().unwrap(),
        control_tls: ControlEndpointTls {
            cert: certs.server_cert_path(),
            key: certs.server_key_path(),
        },
        control_proxy_protocol: control_pp,
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
            agent_id: "control-pp-test".to_string(),
            service_id: "web".to_string(),
        }],
        audit_path: Some(audit_path.clone()),
        agent_recovery_timeout: Duration::from_secs(120),
        ..EdgeConfig::default()
    };
    let edge = interflow_testkit::spawn_edge(edge_config).await;
    (edge.control_addr(), certs, audit_path, echo_addr)
}

/// h2 connection preface followed by an empty SETTINGS frame (header only).
fn h2_opening() -> Vec<u8> {
    let mut opening = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n".to_vec();
    opening.extend_from_slice(&[0, 0, 0, 4, 0, 0, 0, 0, 0]);
    opening
}

/// Sends the h2 opening and reports whether the server's first frame is
/// its SETTINGS — i.e. the connection survived the pp sniff stage and the
/// hub is serving h2 on it.
async fn server_answers_settings(tls: &mut tokio_rustls::client::TlsStream<TcpStream>) -> bool {
    if tls.write_all(&h2_opening()).await.is_err() {
        return false;
    }
    let mut frame = [0u8; 9];
    matches!(
        tokio::time::timeout(Duration::from_secs(3), tls.read_exact(&mut frame)).await,
        Ok(Ok(n)) if n == frame.len() && frame[3] == 0x04
    )
}

/// Polls the audit JSONL until it contains `needle` (line-buffered writer
/// thread; a bounded wait beats a fixed sleep).
async fn await_audit_contains(path: &std::path::Path, needle: &str) -> bool {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(3);
    while tokio::time::Instant::now() < deadline {
        if let Ok(s) = std::fs::read_to_string(path)
            && s.contains(needle)
        {
            return true;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    false
}

#[tokio::test]
async fn proxy_preamble_plus_mtls_handshake_succeeds() {
    let (control, certs, _audit, _echo) = spawn_edge_with_pp(on_loopback()).await;
    let source: IpAddr = "198.51.100.7".parse().unwrap();
    for version in [PpVersion::V1, PpVersion::V2] {
        let mut tls = tls_client_connect_pp(&certs, "edge", control, source, version)
            .await
            .unwrap_or_else(|e| panic!("{version:?}-preambled mTLS handshake failed: {e}"));
        assert!(
            server_answers_settings(&mut tls).await,
            "hub must serve h2 after consuming the {version:?} preamble"
        );
    }
}

#[tokio::test]
async fn no_header_plus_mtls_still_works() {
    // Migration state / internal self-dial shape: a trusted loopback
    // connection without a preamble is a plain direct connection.
    let (control, certs, _audit, _echo) = spawn_edge_with_pp(on_loopback()).await;
    let mut tls = tls_client_connect(&certs, "edge", control)
        .await
        .expect("headerless mTLS handshake must still work in mode on");
    assert!(server_answers_settings(&mut tls).await);
}

#[tokio::test]
async fn untrusted_peer_preamble_is_rejected() {
    // 127.0.0.1 is NOT in the trusted set here — its preamble bytes are
    // attacker input and must be hard-rejected before TLS.
    let pp = ProxyProtocolConfig {
        mode: ProxyProtocolMode::On,
        trusted_proxies: vec!["10.0.0.0/8".to_string()],
    };
    let (control, certs, _audit, _echo) = spawn_edge_with_pp(pp).await;
    for version in [PpVersion::V1, PpVersion::V2] {
        let res = tls_client_connect_pp(
            &certs,
            "edge",
            control,
            "198.51.100.7".parse().unwrap(),
            version,
        )
        .await;
        assert!(
            res.is_err(),
            "untrusted source speaking {version:?} PROXY must be rejected before TLS"
        );
    }
}

#[tokio::test]
async fn mode_off_rejects_pp_prefixed_tls() {
    // Deployment invariant, as a test: pp-tolerant binaries must be live
    // before the nginx conf starts emitting the preamble. With pp off the
    // preamble reaches the TLS layer as garbage — the handshake fails
    // loudly instead of degrading silently.
    let (control, certs, _audit, _echo) = spawn_edge_with_pp(ProxyProtocolConfig::default()).await;
    let res = tls_client_connect_pp(
        &certs,
        "edge",
        control,
        "198.51.100.7".parse().unwrap(),
        PpVersion::V1,
    )
    .await;
    assert!(
        res.is_err(),
        "pp-prefixed TLS against an off-mode listener must fail"
    );
}

/// A loopback TCP forwarder that prepends a v1 PROXY preamble on every
/// upstream connection — the test stand-in for the nginx stream fragment's
/// control-leg SNI target.
async fn spawn_v1_forwarder(target: SocketAddr, source_ip: IpAddr) -> SocketAddr {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        let preamble = format!("PROXY TCP4 {source_ip} 10.0.0.1 47115 443\r\n").into_bytes();
        loop {
            let Ok((mut inbound, _)) = listener.accept().await else {
                return;
            };
            let Ok(mut upstream) = TcpStream::connect(target).await else {
                continue;
            };
            if upstream.write_all(&preamble).await.is_err() {
                continue;
            }
            tokio::spawn(async move {
                let _ = tokio::io::copy_bidirectional(&mut inbound, &mut upstream).await;
            });
        }
    });
    addr
}

#[tokio::test]
async fn pp_proxied_registration_records_real_ip_in_audit() {
    let (control, certs, audit, echo_addr) = spawn_edge_with_pp(on_loopback()).await;
    let real_ip: IpAddr = "198.51.100.7".parse().unwrap();
    let forwarder = spawn_v1_forwarder(control, real_ip).await;

    let (client_cert, client_key) = certs.client_paths();
    let client_args = ExposeArgs {
        log_name: None,
        services: vec![LocalService {
            id: "web".into(),
            target_addr: echo_addr,
            overridden: false,
        }],
        hub_url: format!("https://127.0.0.1:{}", forwarder.port()),
        client_cert: Some(client_cert.display().to_string()),
        client_key: Some(client_key.display().to_string()),
        agent_id: "control-pp-test".into(),
        ingress_ca_path: Some(certs.ca_path().display().to_string()),
        ca_path: Some(certs.ca_path().display().to_string()),
        transport: TransportKind::H2,
        hub_quic_addr: None,
    };
    let client = interflow_expose::client::start(&client_args).expect("expose client start");
    assert!(
        interflow_testkit::wait_agent_connected(&client, Duration::from_secs(5)).await,
        "agent must register through the preamble-injecting forwarder"
    );
    tokio::task::spawn(async move { client.join().await });
    assert!(
        await_audit_contains(&audit, "\"peer\":\"198.51.100.7\"").await,
        "the registration audit must record the preamble-restored real IP, not the loopback peer"
    );
}
