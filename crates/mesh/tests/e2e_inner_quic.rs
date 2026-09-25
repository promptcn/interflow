//! E2E adversarial coverage for UDP inner QUIC.

#![allow(
    clippy::all,
    clippy::pedantic,
    clippy::panic,
    clippy::unwrap_used,
    clippy::expect_used,
    missing_docs,
    dead_code
)]
use bytes::Bytes;
use interflow_core::protocol::{FLAG_E2E, FrameType, StreamProto};
use interflow_core::tls::{InnerTlsMaterial, inner_quic_client_config, inner_quic_server_name};
use interflow_core::tunnel::inner_udp::{self, CarrierDirection, ControlFrame};
use interflow_core::tunnel::{AgentTunnel, IncomingStream, TunnelData};
use interflow_mesh::agent::AgentClient;
use interflow_mesh::config::AgentConfig;
use interflow_testkit::{
    agent_config, hub_config, spawn_agent_registered, spawn_hub, udp_ingress_rule,
    udp_round_trip_once,
};
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::OnceLock;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;
use tokio::sync::mpsc;

fn certs() -> &'static interflow_testkit::certs::TestCerts {
    static CERTS: OnceLock<interflow_testkit::certs::TestCerts> = OnceLock::new();
    CERTS.get_or_init(|| interflow_testkit::certs::TestCerts::generate("inner-quic", "ingress"))
}

fn foreign_certs() -> &'static interflow_testkit::certs::TestCerts {
    static CERTS: OnceLock<interflow_testkit::certs::TestCerts> = OnceLock::new();
    CERTS.get_or_init(|| {
        interflow_testkit::certs::TestCerts::generate("inner-quic-foreign", "rogue")
    })
}

fn material(
    ca: &std::path::Path,
    cert: &std::path::Path,
    key: &std::path::Path,
) -> InnerTlsMaterial {
    InnerTlsMaterial::from_paths(
        &[ca.display().to_string().as_str()],
        cert.display().to_string().as_str(),
        key.display().to_string().as_str(),
    )
    .expect("inner material")
}

fn named_material(certs: &interflow_testkit::certs::TestCerts, id: &str) -> InnerTlsMaterial {
    let (cert, key) = certs.named_client_cert(id);
    material(&certs.ca_path(), &cert, &key)
}

async fn connect_tunnel(hub_port: u16, agent_id: &str) -> AgentTunnel {
    let client = AgentClient::new(agent_config(agent_id, hub_port, certs())).expect("agent");
    let conn = client.connect_and_register().await.expect("register");
    AgentTunnel::from_sender(
        conn.negotiated.circuit_token,
        &format!("http://127.0.0.1:{hub_port}"),
        conn.send_request,
        &interflow_core::tunnel::session_tasks::SessionTasks::new(
            tokio_util::sync::CancellationToken::new(),
        ),
        interflow_core::tunnel::H2Liveness::HEARTBEAT_DISABLED,
    )
    .expect("raw tunnel")
}

async fn counting_udp_backend() -> (SocketAddr, Arc<AtomicUsize>) {
    let bind_addr: SocketAddr = "127.0.0.1:0".parse().unwrap();
    let socket =
        interflow_mesh::agent::ingress_udp::bind_udp_socket(bind_addr).expect("backend bind");
    let addr = socket.local_addr().unwrap();
    let count = Arc::new(AtomicUsize::new(0));
    let counter = Arc::clone(&count);
    tokio::spawn(async move {
        let mut buf = vec![0u8; 65535];
        while socket.recv_from(&mut buf).await.is_ok() {
            counter.fetch_add(1, Ordering::SeqCst);
        }
    });
    (addr, count)
}

fn egress_config(hub_port: u16, target: SocketAddr) -> AgentConfig {
    let mut cfg = agent_config("egress", hub_port, certs());
    cfg.egress = vec![interflow_testkit::udp_egress_rule("udp", target)];
    cfg.security.allowed_targets = vec![target.to_string()];
    cfg.inner_tls.handshake_timeout_secs = 1;
    cfg
}

fn ingress_config(
    hub_port: u16,
    listen: SocketAddr,
    target_agent: &str,
    remote: SocketAddr,
) -> AgentConfig {
    let mut cfg = agent_config("ingress", hub_port, certs());
    cfg.ingress = vec![udp_ingress_rule("udp", listen, target_agent, Some(remote))];
    cfg.inner_tls.handshake_timeout_secs = 5;
    cfg
}

fn tap_frames(
    frames: mpsc::Receiver<TunnelData>,
) -> (
    mpsc::Receiver<TunnelData>,
    Arc<std::sync::Mutex<Vec<Bytes>>>,
) {
    let (tx, tapped) = mpsc::channel(64);
    let captured = Arc::new(std::sync::Mutex::new(Vec::new()));
    let sink = Arc::clone(&captured);
    tokio::spawn(async move {
        let mut frames = frames;
        while let Some(frame) = frames.recv().await {
            if matches!(frame.stream_type, FrameType::Data) {
                sink.lock().unwrap().push(frame.data.clone());
            }
            if tx.send(frame).await.is_err() {
                break;
            }
        }
    });
    (tapped, captured)
}

async fn read_control(
    carrier: &inner_udp::InnerQuicCarrier,
    stream: quinn::StreamId,
) -> ControlFrame {
    let mut header = [0u8; 2];
    carrier.read_exact(stream, &mut header).await.unwrap();
    let mut body = vec![0u8; u16::from_be_bytes(header) as usize];
    carrier.read_exact(stream, &mut body).await.unwrap();
    let mut encoded = header.to_vec();
    encoded.extend(body);
    ControlFrame::decode(&encoded).unwrap().0
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn udp_inner_quic_hides_target_and_payload_from_hub() {
    let hub = spawn_hub(hub_config(0, certs(), Vec::new())).await;
    let hub_port = hub.local_addr().expect("hub bound").port();
    let target: SocketAddr = "127.0.0.1:53253".parse().unwrap();
    let _ingress = spawn_agent_registered(ingress_config(
        hub_port,
        "127.0.0.1:0".parse().unwrap(),
        "victim",
        target,
    ))
    .await;
    let ingress_addr = _ingress
        .wait_ingress_addr("udp", Duration::from_secs(10))
        .await
        .expect("ingress listener bound");

    let raw = connect_tunnel(hub_port, "victim").await;
    let mut incoming = raw.take_incoming_streams().await.unwrap();
    let responder = tokio::spawn(async move {
        let IncomingStream { open, frames } =
            tokio::time::timeout(Duration::from_secs(10), incoming.recv())
                .await
                .expect("outer Open")
                .expect("raw target alive");
        assert!(open.flags & FLAG_E2E != 0);
        assert_eq!(StreamProto::from_frame_flags(open.flags), StreamProto::Udp);
        let open_text = String::from_utf8_lossy(&open.data).to_string();
        assert!(!open_text.contains(&target.to_string()));
        let (frames, captured) = tap_frames(frames);
        let carrier = inner_udp::accept_inner_quic(
            raw.clone(),
            open.stream_id.clone(),
            frames,
            &named_material(certs(), "victim"),
            CarrierDirection::Egress,
            Duration::from_secs(5),
        )
        .await
        .expect("inner QUIC");
        let mut control = carrier.accept_bi().await.unwrap();
        let opened = loop {
            let frame = read_control(&carrier, control).await;
            if matches!(frame, ControlFrame::Open { .. }) {
                break frame;
            }
            control = carrier.accept_bi().await.unwrap();
        };
        let ControlFrame::Open {
            session, selector, ..
        } = opened
        else {
            panic!("expected OPEN");
        };
        assert_eq!(
            selector,
            interflow_core::tunnel::TargetSelector::Address(target.to_string())
        );
        carrier
            .write_all(control, &ControlFrame::Accept(session).encode().unwrap())
            .await
            .unwrap();
        for fragment in
            inner_udp::encode_datagram_fragments(session, b"INNER-QUIC-TOPSECRET").unwrap()
        {
            carrier.send_datagram(fragment).await.unwrap();
        }
        (captured, session)
    });

    let client = interflow_testkit::udp_client().await;
    let marker = b"INNER-QUIC-TOPSECRET".to_vec();
    let reply = udp_round_trip_once(&client, ingress_addr, &marker, Duration::from_secs(10))
        .await
        .expect("round trip");
    assert_eq!(reply, marker);
    let (captured, _session) = responder.await.unwrap();
    tokio::time::sleep(Duration::from_millis(100)).await;
    let hub_view = captured.lock().unwrap().concat();
    assert!(!windows_contains(&hub_view, &marker));
    assert!(!windows_contains(&hub_view, target.to_string().as_bytes()));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn stripped_udp_e2e_flag_fails_closed_with_zero_dial() {
    let hub = spawn_hub(hub_config(0, certs(), Vec::new())).await;
    let hub_port = hub.local_addr().expect("hub bound").port();
    let (target, dials) = counting_udp_backend().await;
    let _egress = spawn_agent_registered(egress_config(hub_port, target)).await;
    let raw = connect_tunnel(hub_port, "rogue").await;
    let sid = interflow_core::protocol::StreamId::random().unwrap();
    let mut response = raw.register_stream(sid).await;
    raw.send_open(sid, "egress", StreamProto::Udp)
        .await
        .unwrap();
    let closed = tokio::time::timeout(Duration::from_secs(3), async {
        loop {
            let frame = response.recv().await.expect("carrier alive").clone();
            if matches!(frame.stream_type, FrameType::Close) {
                return;
            }
        }
    })
    .await;
    assert!(closed.is_ok(), "egress must close stripped-flag UDP");
    assert_eq!(dials.load(Ordering::SeqCst), 0);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn hub_rejects_udp_e2e_open_with_plaintext_target() {
    let hub = spawn_hub(hub_config(0, certs(), Vec::new())).await;
    let hub_port = hub.local_addr().expect("hub bound").port();
    let raw = connect_tunnel(hub_port, "rogue").await;
    let sid = interflow_core::protocol::StreamId::random().unwrap();
    let mut response = raw.register_stream(sid).await;
    raw.send_open_with(sid, "egress", StreamProto::Udp, true)
        .await
        .unwrap();
    let closed = tokio::time::timeout(Duration::from_secs(3), async {
        loop {
            let frame = response.recv().await.expect("carrier alive").clone();
            if matches!(frame.stream_type, FrameType::Close) {
                return;
            }
        }
    })
    .await;
    assert!(closed.is_ok(), "hub must reject plaintext UDP target_addr");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn wrong_cn_and_foreign_anchor_fail_before_udp_dial() {
    let hub = spawn_hub(hub_config(0, certs(), Vec::new())).await;
    let hub_port = hub.local_addr().expect("hub bound").port();
    let (target, dials) = counting_udp_backend().await;
    let _egress = spawn_agent_registered(egress_config(hub_port, target)).await;

    let wrong_cn = connect_tunnel(hub_port, "rogue").await;
    let foreign = connect_tunnel(hub_port, "foreign-rogue").await;
    let mut cases = Vec::new();
    for (tunnel, _source, ca, cn) in [
        (wrong_cn, "rogue", certs().ca_path(), "other-cn"),
        (
            foreign,
            "foreign-rogue",
            foreign_certs().ca_path(),
            "foreign-rogue",
        ),
    ] {
        let (cert, key) = if cn == "other-cn" {
            certs().named_client_cert(cn)
        } else {
            foreign_certs().named_client_cert(cn)
        };
        let client_material = material(&ca, &cert, &key);
        cases.push(tokio::spawn(async move {
            let sid = interflow_core::protocol::StreamId::random().unwrap();
            let frames = tunnel.register_stream(sid).await;
            tunnel
                .send_open_with(sid, "egress", StreamProto::Udp, true)
                .await
                .unwrap();
            let config = inner_quic_client_config(&client_material, "egress").unwrap();
            let result = inner_udp::connect_inner_quic(
                tunnel.clone(),
                sid,
                frames,
                config,
                inner_quic_server_name("egress"),
                "rogue".to_owned(),
                client_material.leaf_fingerprint(),
                CarrierDirection::Ingress,
                Duration::from_secs(2),
            )
            .await;
            match result {
                Err(_) => true,
                Ok(carrier) => {
                    // TLS 1.3 may let the client reach Connected before the
                    // egress validates its client certificate. A subsequent
                    // read must observe the rejection close.
                    tokio::time::sleep(Duration::from_secs(1)).await;
                    let _ = carrier.open_bi().await;
                    carrier.recv_datagram().await.is_err()
                }
            }
        }));
    }
    for case in cases {
        assert!(case.await.unwrap(), "inner QUIC must reject impersonation");
    }
    assert_eq!(dials.load(Ordering::SeqCst), 0);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn revoked_inner_quic_client_fails_before_udp_dial() {
    let hub = spawn_hub(hub_config(0, certs(), Vec::new())).await;
    let hub_port = hub.local_addr().expect("hub bound").port();
    let (target, dials) = counting_udp_backend().await;
    let mut cfg = egress_config(hub_port, target);
    let (cert, key, crl) = certs().revoked_client_material("rogue");
    cfg.inner_tls.crl_paths = vec![crl.display().to_string()];
    let _egress = spawn_agent_registered(cfg).await;

    let raw = connect_tunnel(hub_port, "rogue").await;
    let client_material = material(&certs().ca_path(), &cert, &key);
    let sid = interflow_core::protocol::StreamId::random().unwrap();
    let frames = raw.register_stream(sid).await;
    raw.send_open_with(sid, "egress", StreamProto::Udp, true)
        .await
        .unwrap();
    let config = inner_quic_client_config(&client_material, "egress").unwrap();
    let result = inner_udp::connect_inner_quic(
        raw.clone(),
        sid,
        frames,
        config,
        inner_quic_server_name("egress"),
        "rogue".to_owned(),
        client_material.leaf_fingerprint(),
        CarrierDirection::Ingress,
        Duration::from_secs(2),
    )
    .await;
    let rejected = match result {
        Err(_) => true,
        Ok(carrier) => {
            tokio::time::sleep(Duration::from_millis(300)).await;
            carrier.open_bi().await.is_err()
        }
    };
    assert!(rejected, "revoked inner QUIC client must fail");
    assert_eq!(dials.load(Ordering::SeqCst), 0);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn silent_and_garbled_udp_quic_handshakes_time_out_without_dial() {
    let hub = spawn_hub(hub_config(0, certs(), Vec::new())).await;
    let hub_port = hub.local_addr().expect("hub bound").port();
    let (target, dials) = counting_udp_backend().await;
    let _egress = spawn_agent_registered(egress_config(hub_port, target)).await;
    let raw = connect_tunnel(hub_port, "rogue").await;
    let sid = interflow_core::protocol::StreamId::random().unwrap();
    let mut response = raw.register_stream(sid).await;
    raw.send_open_with(sid, "egress", StreamProto::Udp, true)
        .await
        .unwrap();
    for byte in [0u8, 1, 2, 3] {
        raw.send_data(sid, Bytes::from(vec![byte])).await.unwrap();
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    let closed = tokio::time::timeout(Duration::from_secs(3), async {
        loop {
            let frame = response.recv().await.expect("carrier alive").clone();
            if matches!(frame.stream_type, FrameType::Close) {
                return;
            }
        }
    })
    .await;
    assert!(closed.is_ok(), "garbled inner QUIC must hit deadline");
    assert_eq!(dials.load(Ordering::SeqCst), 0);
}

fn windows_contains(haystack: &[u8], needle: &[u8]) -> bool {
    haystack
        .windows(needle.len())
        .any(|window| window == needle)
}
