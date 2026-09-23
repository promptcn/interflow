//! E2E: the agent↔agent inner TLS layer (e2e encryption) — adversarial
//! regressions for (internal design notes) §8.1 (A1–A8).
//!
//! Mechanics: a real hub + real agents for the positive
//! paths; for the attack paths a **raw-tunnel endpoint** plays the
//! malicious/compromised party at frame level — exactly the capabilities
//! the threat model grants the hub-position attacker (see Open frames,
//! craft Data payloads, withhold or garble handshakes). The inner TLS
//! machinery itself is driven through the production core entry points
//! (`E2eTunnelIo`, `inner_tls_connect/accept`).
//!
//! "Hub view" ciphertext forensics (A2): a raw endpoint sees exactly the
//! bytes the hub relays — capturing Data payloads at the endpoint IS the
//! hub-position capture, without patching the hub.

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
use bytes::Bytes;
use interflow_core::protocol::{FLAG_E2E, FrameType, StreamProto};
use interflow_core::tls::{InnerTlsMaterial, inner_client_config, inner_server_config};
use interflow_core::tunnel::e2e::{
    E2eHandshakeOutcome, E2eTunnelIo, inner_tls_accept, inner_tls_connect,
};
use interflow_core::tunnel::{AgentTunnel, IncomingStream, TunnelData};
use interflow_mesh::agent::AgentClient;
use interflow_mesh::config::{AgentConfig, InnerTlsConfig};
use interflow_testkit::{
    agent_config, hub_config,
    metrics_harness::{init_tracing, metrics_handle, wait_counter_at_least},
    pick_ephemeral_port, spawn_agent_registered, spawn_hub,
};
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::OnceLock;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::mpsc;

/// Primary test CA (hub tenant `test`).
fn certs() -> &'static interflow_testkit::certs::TestCerts {
    static C: OnceLock<interflow_testkit::certs::TestCerts> = OnceLock::new();
    C.get_or_init(|| interflow_testkit::certs::TestCerts::generate("e2e-in", "agent"))
}

/// A second, foreign CA (never trusted by the hub — only for inner-layer
/// impostor material).
fn foreign_certs() -> &'static interflow_testkit::certs::TestCerts {
    static C: OnceLock<interflow_testkit::certs::TestCerts> = OnceLock::new();
    C.get_or_init(|| interflow_testkit::certs::TestCerts::generate("e2e-foreign", "agent"))
}

static SERIAL: OnceLock<tokio::sync::Mutex<()>> = OnceLock::new();

async fn serial_lock() -> tokio::sync::MutexGuard<'static, ()> {
    SERIAL
        .get_or_init(|| tokio::sync::Mutex::new(()))
        .lock()
        .await
}

const FAILS_INGRESS: &str = "interflow_agent_e2e_handshake_failures_total";
const FAILS_EGRESS: &str = "interflow_agent_e2e_handshake_failures_total";
const OK_INGRESS: &str = "interflow_agent_e2e_handshakes_total";

fn e2e_config(timeout_secs: u64) -> InnerTlsConfig {
    InnerTlsConfig {
        handshake_timeout_secs: timeout_secs,
        ..InnerTlsConfig::default()
    }
}

/// The counting backend from e2e_open_flood (zero-dial assertions).
async fn counting_backend() -> (
    SocketAddr,
    Arc<std::sync::atomic::AtomicUsize>,
    Arc<std::sync::atomic::AtomicUsize>,
) {
    use std::sync::atomic::{AtomicUsize, Ordering};
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let total = Arc::new(AtomicUsize::new(0));
    let active = Arc::new(AtomicUsize::new(0));
    let (t2, a2) = (total.clone(), active.clone());
    tokio::spawn(async move {
        loop {
            let Ok((mut sock, _)) = listener.accept().await else {
                break;
            };
            t2.fetch_add(1, Ordering::SeqCst);
            a2.fetch_add(1, Ordering::SeqCst);
            let a3 = a2.clone();
            tokio::spawn(async move {
                let mut buf = [0u8; 4096];
                while matches!(sock.read(&mut buf).await, Ok(n) if n > 0) {}
                a3.fetch_sub(1, Ordering::SeqCst);
            });
        }
    });
    (addr, total, active)
}

/// A raw-tunnel endpoint registered at the hub (frame-level control).
async fn connect_tunnel(
    hub_port: u16,
    agent_id: &str,
) -> (AgentTunnel, tokio::task::JoinHandle<()>) {
    let client = AgentClient::new(agent_config(agent_id, hub_port, certs())).expect("agent build");
    let conn = client
        .connect_and_register()
        .await
        .expect("connect+register");
    let tunnel = AgentTunnel::from_sender(
        conn.negotiated.circuit_token,
        &format!("http://127.0.0.1:{hub_port}"),
        conn.send_request,
        &interflow_core::tunnel::session_tasks::SessionTasks::new(
            tokio_util::sync::CancellationToken::new(),
        ),
        interflow_core::tunnel::H2Liveness::HEARTBEAT_DISABLED,
    )
    .expect("tunnel");
    (tunnel, conn.conn_handle)
}

/// Inner-TLS material from explicit paths (test-issued pairs).
fn material(ca: &str, cert: &str, key: &str) -> InnerTlsMaterial {
    InnerTlsMaterial::from_paths(&[ca], cert, key).expect("material")
}

/// Same-tenant material for agent `id` (the honest shape).
fn tenant_material(id: &str) -> InnerTlsMaterial {
    let (cert, key) = certs().named_client_cert(id);
    material(
        &certs().ca_path().display().to_string(),
        &cert.display().to_string(),
        &key.display().to_string(),
    )
}

/// Capturing tee: every Data frame the hub delivers for the stream is
/// recorded (the hub-position view) and forwarded to the real consumer.
fn tap_frames(
    frames: mpsc::Receiver<TunnelData>,
) -> (
    mpsc::Receiver<TunnelData>,
    Arc<std::sync::Mutex<Vec<Bytes>>>,
) {
    let (tx, rx) = mpsc::channel(64);
    let captured = Arc::new(std::sync::Mutex::new(Vec::new()));
    let cap2 = captured.clone();
    tokio::spawn(async move {
        let mut frames = frames;
        while let Some(td) = frames.recv().await {
            if matches!(td.stream_type, FrameType::Data) {
                cap2.lock().unwrap().push(td.data.clone());
            }
            if tx.send(td).await.is_err() {
                break;
            }
        }
    });
    (rx, captured)
}

/// A malicious/compromised inner TLS **responder** over a raw endpoint:
/// waits for one Open (asserting the e2e flag shape), then runs the inner
/// server handshake with the given material. On success echoes application
/// data. Returns the captured hub-view Data payloads.
async fn evil_responder(
    tunnel: AgentTunnel,
    server_material: InnerTlsMaterial,
    expected_client_cn: &str,
    echo: bool,
) -> Arc<std::sync::Mutex<Vec<Bytes>>> {
    let mut incoming = tunnel.take_incoming_streams().await.expect("incoming");
    let is = tokio::time::timeout(Duration::from_secs(10), incoming.recv())
        .await
        .expect("open arrived")
        .expect("channel alive");
    spawn_responder_for(tunnel, is, server_material, expected_client_cn, echo).await
}

/// Responder body for an already-received [`IncomingStream`].
async fn spawn_responder_for(
    tunnel: AgentTunnel,
    is: IncomingStream,
    server_material: InnerTlsMaterial,
    expected_client_cn: &str,
    echo: bool,
) -> Arc<std::sync::Mutex<Vec<Bytes>>> {
    let IncomingStream { open, frames } = is;
    assert!(
        open.flags & FLAG_E2E != 0,
        "responder expects the e2e-declared stream"
    );
    let sid = open.stream_id.clone();
    let (tapped, captured) = tap_frames(frames);
    let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(
        inner_server_config(&server_material, expected_client_cn).expect("acceptor"),
    ));
    tokio::spawn(async move {
        let adapter = E2eTunnelIo::egress(tapped, tunnel.clone(), sid);
        match inner_tls_accept(adapter, acceptor, Duration::from_secs(10)).await {
            E2eHandshakeOutcome::Established(mut tls, _) => {
                let mut buf = vec![0u8; 4096];
                if echo {
                    match tls.read(&mut buf).await {
                        Ok(0) | Err(_) => {}
                        Ok(_) if buf.starts_with(b"IFSTREAM") => {
                            // The egress sends the encrypted selector first; echo the
                            // actual application bytes that follow it.
                            if let Ok(m) = tls.read(&mut buf).await {
                                let _ = tls.write_all(&buf[..m]).await;
                                let _ = tls.shutdown().await;
                            }
                        }
                        Ok(n) => {
                            let _ = tls.write_all(&buf[..n]).await;
                            let _ = tls.shutdown().await;
                        }
                    }
                } else {
                    // Hold the stream open silently (silent-peer scenarios).
                    let mut sink = [0u8; 64];
                    let _ = tls.read(&mut sink).await;
                }
            }
            E2eHandshakeOutcome::Failed { .. } => {
                // Keep the malicious peer alive briefly (realistic source);
                // the failed receiver is deliberately not recoverable.
                tokio::time::sleep(Duration::from_secs(2)).await;
            }
        }
    });
    captured
}

/// The egress-role config for a real agent with e2e + a TCP rule.
fn egress_agent_config(
    id: &str,
    hub_port: u16,
    target: SocketAddr,
    e2e: InnerTlsConfig,
) -> AgentConfig {
    let mut cfg = agent_config(id, hub_port, certs());
    cfg.egress = vec![interflow_testkit::tcp_egress_rule("r", target)];
    cfg.security.allowed_targets = vec![target.to_string()];
    cfg.inner_tls = e2e;
    cfg
}

/// The ingress-role config for a real agent with e2e + a TCP listener rule.
fn ingress_agent_config(
    id: &str,
    hub_port: u16,
    listen: SocketAddr,
    target_agent: &str,
    e2e: InnerTlsConfig,
) -> AgentConfig {
    let mut cfg = agent_config(id, hub_port, certs());
    cfg.ingress = vec![interflow_testkit::tcp_ingress_rule(
        "r",
        listen,
        target_agent,
        None,
    )];
    cfg.inner_tls = e2e;
    cfg
}

/// A TCP client connection to an ingress listener.
async fn dial_listener(addr: SocketAddr) -> TcpStream {
    let deadline = std::time::Instant::now() + Duration::from_secs(5);
    loop {
        if let Ok(s) = TcpStream::connect(addr).await {
            return s;
        }
        assert!(
            std::time::Instant::now() < deadline,
            "listener never came up"
        );
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
}

/// Reads until EOF/error or deadline; returns whatever arrived.
async fn read_available(sock: &mut TcpStream, deadline: Duration) -> Vec<u8> {
    let mut out = Vec::new();
    let mut buf = [0u8; 4096];
    let _ = tokio::time::timeout(deadline, async {
        loop {
            match sock.read(&mut buf).await {
                Ok(0) => break,
                Ok(n) => out.extend_from_slice(&buf[..n]),
                Err(_) => break,
            }
        }
    })
    .await;
    out
}

// ---------------------------------------------------------------------------
// Positive path: required ↔ required full chain through a real hub
// ---------------------------------------------------------------------------

/// P1: two real agents, both `required` — an echo round trip through the
/// inner TLS layer works end to end. This transitively pins the hub's
/// FLAG_E2E passthrough (a stripped flag would make the egress close the
/// stream with `not_negotiated`) and both sides' success counters.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn p1_required_full_chain_round_trip() {
    let _serial = serial_lock().await;
    let _ = metrics_handle();
    init_tracing();
    let hub_port = pick_ephemeral_port();
    spawn_hub(hub_config(hub_port, certs(), vec![])).await;
    let (echo_addr, _echo) = interflow_testkit::echo_server().await;

    let eg = spawn_agent_registered(egress_agent_config(
        "eg",
        hub_port,
        echo_addr,
        e2e_config(5),
    ))
    .await;

    let listen: SocketAddr = "127.0.0.1:0".parse().unwrap();
    let listener = TcpListener::bind(listen).await.unwrap();
    let ingress_addr = listener.local_addr().unwrap();
    drop(listener);
    let in_handle = spawn_agent_registered(ingress_agent_config(
        "in",
        hub_port,
        ingress_addr,
        "eg",
        e2e_config(5),
    ))
    .await;

    let mut sock = dial_listener(ingress_addr).await;
    let marker = b"TOPSECRET-MARKER-plaintext";
    sock.write_all(marker).await.unwrap();
    let mut got = vec![0u8; marker.len()];
    tokio::time::timeout(Duration::from_secs(10), sock.read_exact(&mut got))
        .await
        .expect("echo within 10s")
        .expect("read exact");
    assert_eq!(&got, marker, "echo through the inner TLS layer");

    wait_counter_at_least(OK_INGRESS, 1, Duration::from_secs(5)).await;
    drop(sock);
    drop(eg);
    drop(in_handle);
}

/// P2: same chain over the QUIC plane — the inner layer rides frames and
/// must be transport-agnostic.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn p2_quic_plane_smoke() {
    let _serial = serial_lock().await;
    let _ = metrics_handle();
    init_tracing();
    let hub_port = pick_ephemeral_port();
    spawn_hub(interflow_testkit::hub_quic_config(
        hub_port,
        certs(),
        vec![],
    ))
    .await;
    let (echo_addr, _echo) = interflow_testkit::echo_server().await;

    let mut eg_cfg = egress_agent_config("eg", hub_port, echo_addr, e2e_config(5));
    eg_cfg.agent.transport = interflow_mesh::config::TransportKind::Quic;
    eg_cfg.agent.hub_quic_addr = Some(format!("127.0.0.1:{hub_port}"));
    let eg = spawn_agent_registered(eg_cfg).await;

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let ingress_addr = listener.local_addr().unwrap();
    drop(listener);
    let mut in_cfg = ingress_agent_config("in", hub_port, ingress_addr, "eg", e2e_config(5));
    in_cfg.agent.transport = interflow_mesh::config::TransportKind::Quic;
    in_cfg.agent.hub_quic_addr = Some(format!("127.0.0.1:{hub_port}"));
    let in_handle = spawn_agent_registered(in_cfg).await;

    let mut sock = dial_listener(ingress_addr).await;
    sock.write_all(b"quic-plane").await.unwrap();
    let mut got = vec![0u8; b"quic-plane".len()];
    tokio::time::timeout(Duration::from_secs(10), sock.read_exact(&mut got))
        .await
        .expect("echo within 10s")
        .expect("read exact");
    assert_eq!(&got, b"quic-plane");
    drop(sock);
    drop(eg);
    drop(in_handle);
}

// ---------------------------------------------------------------------------
// A1/A2/A4: malicious responder at the hub position
// ---------------------------------------------------------------------------

/// Common scaffolding: hub + a `required` ingress agent targeting the
/// attacker-controlled agent id `victim`. Returns (hub_port, ingress addr).
async fn required_ingress_against(victim: &str, timeout_secs: u64) -> (u16, SocketAddr) {
    let hub_port = pick_ephemeral_port();
    spawn_hub(hub_config(hub_port, certs(), vec![])).await;
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let ingress_addr = listener.local_addr().unwrap();
    drop(listener);
    let in_handle = spawn_agent_registered(ingress_agent_config(
        "in",
        hub_port,
        ingress_addr,
        victim,
        e2e_config(timeout_secs),
    ))
    .await;
    std::mem::forget(in_handle); // lives for the test; cleaned with the process
    (hub_port, ingress_addr)
}

/// A1: the malicious responder presents a self-signed (fresh-CA) inner
/// certificate — the MITM shape. The ingress must fail the handshake and
/// close the visitor connection; the failure counter ticks.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a1_mitm_self_signed_inner_cert_fails_closed() {
    let _serial = serial_lock().await;
    let _ = metrics_handle();
    init_tracing();
    let (hub_port, ingress_addr) = required_ingress_against("victim", 5).await;
    let (attacker, _h) = connect_tunnel(hub_port, "victim").await;

    // Self-signed server material: a fresh CA that the ingress anchors
    // nowhere, cert CN == the declared target (so ONLY the anchoring fails).
    let evil_ca = interflow_testkit::certs::TestCerts::generate("e2e-mitm", "agent");
    let (evil_cert, evil_key) = evil_ca.named_client_cert("victim");
    let evil = material(
        &evil_ca.ca_path().display().to_string(),
        &evil_cert.display().to_string(),
        &evil_key.display().to_string(),
    );

    let responder = tokio::spawn(async move { evil_responder(attacker, evil, "in", false).await });

    let mut sock = dial_listener(ingress_addr).await;
    sock.write_all(b"hello").await.unwrap();
    // Fail-closed: the visitor connection is torn down, no plaintext flows.
    let got = read_available(&mut sock, Duration::from_secs(8)).await;
    assert!(
        !got.windows(b"hello".len()).any(|w| w == b"hello"),
        "no reflected plaintext"
    );
    wait_counter_at_least(FAILS_INGRESS, 1, Duration::from_secs(5)).await;
    responder.abort();
}

/// A2: ciphertext forensics — with an HONEST same-tenant responder, the
/// Data payloads the hub relays (captured at the endpoint) carry no
/// plaintext feature: the marker never appears, everything is TLS records.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a2_hub_view_is_ciphertext() {
    let _serial = serial_lock().await;
    let _ = metrics_handle();
    init_tracing();
    let (hub_port, ingress_addr) = required_ingress_against("victim", 10).await;
    let (attacker, _h) = connect_tunnel(hub_port, "victim").await;

    // Honest responder: tenant material, CN == victim, echoes back.
    let responder = tokio::spawn(async move {
        evil_responder(attacker, tenant_material("victim"), "in", true).await
    });

    let mut sock = dial_listener(ingress_addr).await;
    let marker = b"TOPSECRET-A2-MARKER";
    sock.write_all(marker).await.unwrap();
    let mut got = vec![0u8; marker.len()];
    tokio::time::timeout(Duration::from_secs(10), sock.read_exact(&mut got))
        .await
        .expect("echo")
        .expect("read");
    assert_eq!(&got, marker, "the inner peer decrypted and echoed");

    // The hub-position view (frames delivered to the endpoint) must be
    // pure TLS records: marker absent, payloads non-empty and TLS-shaped.
    let captured = responder
        .await
        .expect("responder finished")
        .lock()
        .unwrap()
        .clone();
    assert!(!captured.is_empty(), "handshake+data frames were relayed");
    for payload in &captured {
        assert!(
            !payload.windows(marker.len()).any(|w| w == marker),
            "plaintext marker leaked into the hub view"
        );
    }
    // TLS record shape on the concatenated byte stream (frames are an
    // arbitrary slicing of the record stream): a handshake record first,
    // then app-data/alert records; no plaintext prefix anywhere.
    let mut joined = Vec::new();
    for payload in &captured {
        joined.extend_from_slice(payload);
    }
    assert!(
        !joined.is_empty() && joined[0] == 0x16 && joined[1] == 0x03,
        "the hub view starts as a TLS handshake record: {:?}",
        &joined[..joined.len().min(8)]
    );
    let mut i = 0usize;
    while i + 5 <= joined.len() {
        let (content_type, len) = (
            joined[i],
            u16::from_be_bytes([joined[i + 3], joined[i + 4]]) as usize,
        );
        assert!(
            matches!(content_type, 0x14 | 0x15 | 0x16 | 0x17),
            "byte {i} is not a TLS record boundary: {:?}",
            &joined[i..(i + 8).min(joined.len())]
        );
        i += 5 + len;
    }
    assert!(i == joined.len(), "no trailing partial garbage");
}

/// A4a: same-tenant redirect — the responder's cert is tenant-anchored but
/// CN != the declared target. And the REAL egress (running `required`
/// toward the same backend) sees zero dials on its counting backend: a
/// redirected stream never reaches any LAN.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a4a_same_tenant_wrong_cn_fails_and_real_egress_zero_dial() {
    let _serial = serial_lock().await;
    let _ = metrics_handle();
    init_tracing();
    let hub_port = pick_ephemeral_port();
    spawn_hub(hub_config(hub_port, certs(), vec![])).await;
    let (backend, total, _active) = counting_backend().await;

    // The real egress: required, would dial the backend if a stream landed.
    let eg =
        spawn_agent_registered(egress_agent_config("eg", hub_port, backend, e2e_config(5))).await;
    std::mem::forget(eg);

    // The ingress targets `victim`; the hub (honestly) routes there — the
    // "redirect" is that the stream never reaches the intended `eg`.
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let ingress_addr = listener.local_addr().unwrap();
    drop(listener);
    let in_handle = spawn_agent_registered(ingress_agent_config(
        "in",
        hub_port,
        ingress_addr,
        "victim",
        e2e_config(5),
    ))
    .await;
    std::mem::forget(in_handle);

    let (attacker, _h) = connect_tunnel(hub_port, "victim").await;
    // Responder with an honest tenant cert but the WRONG CN ("eg").
    let responder =
        tokio::spawn(
            async move { evil_responder(attacker, tenant_material("eg"), "in", false).await },
        );

    let mut sock = dial_listener(ingress_addr).await;
    sock.write_all(b"x").await.unwrap();
    let _ = read_available(&mut sock, Duration::from_secs(8)).await;
    wait_counter_at_least(FAILS_INGRESS, 1, Duration::from_secs(5)).await;
    assert_eq!(
        total.load(std::sync::atomic::Ordering::SeqCst),
        0,
        "zero backend dials anywhere"
    );
    responder.abort();
}

/// A4b: cross-tenant anchor — the responder's cert has the RIGHT CN but is
/// signed by a foreign CA: rejected by the anchor set.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a4b_foreign_tenant_anchor_rejected() {
    let _serial = serial_lock().await;
    let _ = metrics_handle();
    init_tracing();
    let (hub_port, ingress_addr) = required_ingress_against("victim", 5).await;
    let (attacker, _h) = connect_tunnel(hub_port, "victim").await;

    // Foreign-CA material: CN == victim (correct), anchor = foreign root.
    let (fc, fk) = foreign_certs().named_client_cert("victim");
    let impostor = material(
        &foreign_certs().ca_path().display().to_string(),
        &fc.display().to_string(),
        &fk.display().to_string(),
    );
    let responder =
        tokio::spawn(async move { evil_responder(attacker, impostor, "in", false).await });

    let mut sock = dial_listener(ingress_addr).await;
    sock.write_all(b"x").await.unwrap();
    let _ = read_available(&mut sock, Duration::from_secs(8)).await;
    wait_counter_at_least(FAILS_INGRESS, 1, Duration::from_secs(5)).await;
    responder.abort();
}

/// A4c: forged `src_agent` — a registered attacker (CN=rogue) opens a
/// FLAG_E2E stream toward the real `required` egress but presents an inner
/// client certificate with a different CN. The egress rejects + zero dial.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a4c_forged_src_agent_rejected_zero_dial() {
    let _serial = serial_lock().await;
    let _ = metrics_handle();
    init_tracing();
    let hub_port = pick_ephemeral_port();
    spawn_hub(hub_config(hub_port, certs(), vec![])).await;
    let (backend, total, _active) = counting_backend().await;
    let eg =
        spawn_agent_registered(egress_agent_config("eg", hub_port, backend, e2e_config(5))).await;
    std::mem::forget(eg);

    let (attacker, _h) = connect_tunnel(hub_port, "rogue").await;
    let backend_str = backend.to_string();
    tokio::spawn(async move {
        let sid = interflow_testkit::opaque_stream_id("forge-1");
        let rx = attacker.register_stream(sid).await;
        attacker
            .send_open_with(sid, "eg", StreamProto::Tcp, true)
            .await
            .unwrap();
        // Present a valid tenant cert whose CN != the declared source
        // (`test/rogue`): the CN binding must reject it.
        let client_material = tenant_material("someone-else");
        let connector = tokio_rustls::TlsConnector::from(std::sync::Arc::new(
            inner_client_config(&client_material, "eg").unwrap(),
        ));
        let adapter = E2eTunnelIo::ingress(rx, attacker.clone(), sid);
        match inner_tls_connect(adapter, connector, Duration::from_secs(5)).await {
            E2eHandshakeOutcome::Established(mut tls, _) => {
                let hello = interflow_core::tunnel::InnerStreamHello {
                    source_principal: "rogue".to_owned(),
                    source_fingerprint: client_material.leaf_fingerprint(),
                    selector: interflow_core::tunnel::TargetSelector::Address(backend_str),
                    correlation_id: *uuid::Uuid::new_v4().as_bytes(),
                };
                let _ = hello.write(&mut tls).await;
                tokio::time::sleep(Duration::from_millis(500)).await;
            }
            // TLS 1.3 lets the client finish its side first; the egress's
            // rejection arrives as a read error. Either way THIS side could
            // not have smuggled a plaintext dial (asserted below).
            E2eHandshakeOutcome::Failed { .. } => {
                tokio::time::sleep(Duration::from_secs(2)).await;
            }
        }
    });

    wait_counter_at_least(FAILS_EGRESS, 1, Duration::from_secs(8)).await;
    tokio::time::sleep(Duration::from_millis(500)).await;
    assert_eq!(
        total.load(std::sync::atomic::Ordering::SeqCst),
        0,
        "forged-identity stream must not dial the backend"
    );
}

// ---------------------------------------------------------------------------
// A5/A6: downgrade + legacy peers
// ---------------------------------------------------------------------------

/// A5: a flagless Open (the stripped-flag shape) toward a `required`
/// egress is closed fail-closed — no plaintext forward, zero dials,
/// `not_negotiated` counter.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a5_stripped_flag_is_rejected_not_plaintext() {
    let _serial = serial_lock().await;
    let _ = metrics_handle();
    init_tracing();
    let hub_port = pick_ephemeral_port();
    spawn_hub(hub_config(hub_port, certs(), vec![])).await;
    let (backend, total, _active) = counting_backend().await;
    let eg =
        spawn_agent_registered(egress_agent_config("eg", hub_port, backend, e2e_config(5))).await;
    std::mem::forget(eg);

    let (inj, _h) = connect_tunnel(hub_port, "stripper").await;
    let sid = interflow_testkit::opaque_stream_id("strip-1");
    let mut rx = inj.register_stream(sid).await;
    // Deliberately WITHOUT the e2e flag: what the egress sees after a
    // strip-at-the-hub downgrade.
    inj.send_open(sid, "eg", StreamProto::Tcp).await.unwrap();

    let closed = tokio::time::timeout(Duration::from_secs(8), async {
        loop {
            let td = rx.recv().await.expect("channel alive");
            if matches!(td.stream_type, FrameType::Close) {
                break;
            }
        }
    })
    .await;
    assert!(closed.is_ok(), "flagless open must be closed");
    wait_counter_at_least(
        "interflow_agent_e2e_handshake_failures_total{side=\"egress\",reason=\"not_negotiated\"}",
        1,
        Duration::from_secs(5),
    )
    .await;
    assert_eq!(total.load(std::sync::atomic::Ordering::SeqCst), 0);
}

/// A5b: the same flagless open is rejected on every egress; historical
/// migration modes are not deployable.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a5b_legacy_plaintext_is_always_rejected() {
    let _serial = serial_lock().await;
    let _ = metrics_handle();
    init_tracing();
    let hub_port = pick_ephemeral_port();
    spawn_hub(hub_config(hub_port, certs(), vec![])).await;
    let (echo_addr, _echo) = interflow_testkit::echo_server().await;
    let eg = spawn_agent_registered(egress_agent_config(
        "eg",
        hub_port,
        echo_addr,
        e2e_config(5),
    ))
    .await;
    std::mem::forget(eg);

    let (inj, _h) = connect_tunnel(hub_port, "legacy").await;
    let sid = interflow_testkit::opaque_stream_id("legacy-1");
    let mut rx = inj.register_stream(sid).await;
    inj.send_open(sid, "eg", StreamProto::Tcp).await.unwrap();
    inj.send_data(sid, Bytes::from_static(b"plain-old"))
        .await
        .unwrap();

    let closed = tokio::time::timeout(Duration::from_secs(8), async {
        loop {
            let td = rx.recv().await.expect("channel alive");
            assert_ne!(
                td.stream_type,
                FrameType::Data,
                "plaintext leaked: {:?}",
                td.data
            );
            if matches!(td.stream_type, FrameType::Close) {
                break;
            }
        }
    })
    .await;
    assert!(closed.is_ok(), "legacy plaintext stream must close");
    wait_counter_at_least(
        "interflow_agent_e2e_handshake_failures_total{side=\"egress\",reason=\"not_negotiated\"}",
        1,
        Duration::from_secs(5),
    )
    .await;
}

/// A6: `required` ingress vs a silent legacy peer — the handshake deadline
/// closes the visitor connection (availability failure, not plaintext).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a6_required_vs_silent_peer_times_out() {
    let _serial = serial_lock().await;
    let _ = metrics_handle();
    init_tracing();
    let (hub_port, ingress_addr) = required_ingress_against("victim", 2).await;
    let (attacker, _h) = connect_tunnel(hub_port, "victim").await;
    // The peer accepts the Open then stays silent (an old egress that just
    // dialed and waits — nothing ever answers the ClientHello).
    tokio::spawn(async move {
        let mut incoming = attacker.take_incoming_streams().await.unwrap();
        while let Some(IncomingStream { frames, .. }) = incoming.recv().await {
            tokio::spawn(async move {
                let mut frames = frames;
                while frames.recv().await.is_some() {}
            });
        }
    });

    let mut sock = dial_listener(ingress_addr).await;
    sock.write_all(b"anyone?").await.unwrap();
    let started = std::time::Instant::now();
    let _ = read_available(&mut sock, Duration::from_secs(10)).await;
    assert!(
        started.elapsed() < Duration::from_secs(8),
        "the deadline closed the stream"
    );
    wait_counter_at_least(
        "interflow_agent_e2e_handshake_failures_total{side=\"ingress\",reason=\"timeout\"}",
        1,
        Duration::from_secs(5),
    )
    .await;
}

/// A6b: there is no fallback. A plaintext peer closes the visitor connection at
/// the handshake deadline; no banner or visitor payload is served in plaintext.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a6b_plaintext_banner_peer_never_falls_back() {
    let _serial = serial_lock().await;
    let _ = metrics_handle();
    init_tracing();
    let hub_port = pick_ephemeral_port();
    spawn_hub(hub_config(hub_port, certs(), vec![])).await;
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let ingress_addr = listener.local_addr().unwrap();
    drop(listener);
    let in_handle = spawn_agent_registered(ingress_agent_config(
        "in",
        hub_port,
        ingress_addr,
        "victim",
        e2e_config(2),
    ))
    .await;
    std::mem::forget(in_handle);

    let (attacker, _h) = connect_tunnel(hub_port, "victim").await;
    tokio::spawn(async move {
        let mut incoming = attacker.take_incoming_streams().await.unwrap();
        while let Some(IncomingStream { open, frames }) = incoming.recv().await {
            let attacker = attacker.clone();
            tokio::spawn(async move {
                let sid = open.stream_id.clone();
                let mut frames = frames;
                while let Some(td) = frames.recv().await {
                    let tls_shaped = !td.data.is_empty() && matches!(td.data[0], 0x14..=0x17);
                    if matches!(td.stream_type, FrameType::Data)
                        && !td.data.is_empty()
                        && !tls_shaped
                    {
                        let _ = attacker.send_data_response(sid, td.data.clone()).await;
                    }
                }
            });
        }
    });

    let started = std::time::Instant::now();
    let mut sock = dial_listener(ingress_addr).await;
    let probe = b"fallback-probe";
    sock.write_all(probe).await.unwrap();
    let got = read_available(&mut sock, Duration::from_secs(6)).await;
    assert!(
        !got.windows(probe.len()).any(|w| w == probe),
        "plaintext fallback served: {got:?}"
    );
    assert!(started.elapsed() >= Duration::from_secs(2));
    wait_counter_at_least(FAILS_INGRESS, 1, Duration::from_secs(5)).await;
}

// ---------------------------------------------------------------------------
// A7: gateway anchor forms
// ---------------------------------------------------------------------------

/// Registers a gateway-principal raw endpoint (`_edge` tenant anchored at
/// the gateway CA, trusted_gateway) and opens a FLAG_E2E stream toward the
/// real egress with the gateway pair as the inner client.
async fn gateway_stream_against_egress(
    hub_port: u16,
    egress_id: &str,
    target: &str,
    gateway_cert: &str,
    gateway_key: &str,
) -> Option<tokio_rustls::client::TlsStream<tokio::io::DuplexStream>> {
    // The gateway endpoint registers through the hub with the gateway pair
    // (the `_edge` tenant root is the gateway CA).
    let mut cfg = agent_config("edge", hub_port, certs());
    // Hub plane: trust the hub's CA (the test tenant CA), present the
    // gateway pair (the `_edge` principal anchored at the gateway CA).
    cfg.tls = Some(interflow_mesh::config::AgentTlsConfig {
        enabled: true,
        ca_path: Some(certs().ca_path().display().to_string()),
        client_cert_path: Some(gateway_cert.to_string()),
        client_key_path: Some(gateway_key.to_string()),
        hub_cert_fingerprint: None,
    });
    let client = AgentClient::new(cfg).expect("gateway agent build");
    let conn = client.connect_and_register().await.expect("register");
    let tunnel = AgentTunnel::from_sender(
        conn.negotiated.circuit_token,
        &format!("http://127.0.0.1:{hub_port}"),
        conn.send_request,
        &interflow_core::tunnel::session_tasks::SessionTasks::new(
            tokio_util::sync::CancellationToken::new(),
        ),
        interflow_core::tunnel::H2Liveness::HEARTBEAT_DISABLED,
    )
    .expect("tunnel");

    let sid = interflow_testkit::opaque_stream_id(&format!("gw-{egress_id}"));
    let rx = tunnel.register_stream(sid).await;
    // Cross-tenant addressing is the tenant-qualified form (exactly what
    // the edge's listener builds from routes.toml: "{tenant}/{agent}").
    let qualified = format!("test/{egress_id}");
    tunnel
        .send_open_with(sid, &qualified, StreamProto::Tcp, true)
        .await
        .unwrap();
    // Inner client material: present the gateway pair, anchor at the TARGET
    // tenant's CA (the egress's agents — same per-route anchor discipline as
    // the edge's EdgeE2e).
    let tenant_ca = certs().ca_path().display().to_string();
    let gw_material =
        InnerTlsMaterial::from_paths(&[tenant_ca.as_str()], gateway_cert, gateway_key).unwrap();
    let connector = tokio_rustls::TlsConnector::from(Arc::new(
        inner_client_config(&gw_material, egress_id).unwrap(),
    ));
    let adapter = E2eTunnelIo::ingress(rx, tunnel.clone(), sid);
    match inner_tls_connect(adapter, connector, Duration::from_secs(5)).await {
        E2eHandshakeOutcome::Established(mut tls, _) => {
            let hello = interflow_core::tunnel::InnerStreamHello {
                source_principal: "edge".to_owned(),
                source_fingerprint: gw_material.leaf_fingerprint(),
                selector: interflow_core::tunnel::TargetSelector::Address(target.to_owned()),
                correlation_id: *uuid::Uuid::new_v4().as_bytes(),
            };
            hello.write(&mut tls).await.ok()?;
            Some(tls)
        }
        E2eHandshakeOutcome::Failed { .. } => None,
    }
}

/// A7 full chain: egress `required` WITH the gateway anchor — the gateway
/// stream completes the inner handshake (data flows) and the backend dials.
/// A7 anchor-missing: same egress WITHOUT `ingress_ca_path` — rejected,
/// zero dial. Both shapes in one stack (one hub, two egresses).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a7_gateway_anchor_full_chain_and_missing_anchor() {
    let _serial = serial_lock().await;
    let _ = metrics_handle();
    init_tracing();
    let gw_dir = tempfile::tempdir().unwrap();
    interflow_certs::ensure_gateway(gw_dir.path(), false).unwrap();
    let gw_ca = gw_dir
        .path()
        .join("gateway/gateway-ca.crt")
        .display()
        .to_string();
    let gw_cert = gw_dir.path().join("gateway/edge.crt").display().to_string();
    let gw_key = gw_dir.path().join("gateway/edge.key").display().to_string();

    // Hub: the test tenant + the `_edge` gateway principal (trusted).
    let hub_port = pick_ephemeral_port();
    let mut hub_cfg = hub_config(hub_port, certs(), vec![]);
    hub_cfg
        .auth
        .tenants
        .push(interflow_mesh::config::TenantConfig {
            name: "_edge".to_string(),
            ca_path: gw_ca.clone(),
            crl_path: None,
            trusted_gateway: true,
        });
    spawn_hub(hub_cfg).await;

    let (echo_addr, _echo) = interflow_testkit::echo_server().await;
    // Egress WITH the anchor.
    let mut anchored = egress_agent_config("eg-anchored", hub_port, echo_addr, e2e_config(5));
    anchored.inner_tls.ingress_ca_path = Some(gw_ca.clone());
    let eg1 = spawn_agent_registered(anchored).await;
    std::mem::forget(eg1);
    // Egress WITHOUT the anchor.
    let eg2 = spawn_agent_registered(egress_agent_config(
        "eg-bare",
        hub_port,
        echo_addr,
        e2e_config(5),
    ))
    .await;
    std::mem::forget(eg2);

    // Full chain: the gateway stream completes the inner handshake and the
    // application payload round-trips through the backend.
    let mut tls = gateway_stream_against_egress(
        hub_port,
        "eg-anchored",
        &echo_addr.to_string(),
        &gw_cert,
        &gw_key,
    )
    .await
    .expect("anchored egress must accept the gateway stream");
    tls.write_all(b"gw-payload").await.unwrap();
    tls.flush().await.unwrap();
    let mut got = vec![0u8; b"gw-payload".len()];
    tokio::time::timeout(Duration::from_secs(8), tls.read_exact(&mut got))
        .await
        .expect("backend echo through inner TLS")
        .expect("read");
    assert_eq!(&got, b"gw-payload");

    // Missing anchor: the same stream toward `eg-bare` is rejected. TLS 1.3
    // nuance: the client considers its handshake done BEFORE the server
    // verifies the client certificate, so "Established" alone proves
    // nothing — the definitive evidence is that no application bytes ever
    // come back (the egress's rejection alert kills the read).
    let bare_rejected = match gateway_stream_against_egress(
        hub_port,
        "eg-bare",
        &echo_addr.to_string(),
        &gw_cert,
        &gw_key,
    )
    .await
    {
        None => true,
        Some(mut tls) => {
            let mut buf = vec![0u8; 16];
            // No probe is written: the echo backend cannot legitimately
            // answer anything, so any outcome other than an error/close
            // within the bound means the unanchored egress accepted.
            match tokio::time::timeout(Duration::from_secs(3), tls.read(&mut buf)).await {
                Err(_) => true,
                Ok(Err(_)) => true,
                Ok(Ok(0)) => true,
                Ok(Ok(_)) => false,
            }
        }
    };
    assert!(bare_rejected, "unanchored required egress must reject");
    wait_counter_at_least(FAILS_EGRESS, 1, Duration::from_secs(5)).await;
}

// ---------------------------------------------------------------------------
// A8: handshake dribble
// ---------------------------------------------------------------------------

/// A8: a slow-drip responder (tiny garbage Data frames spread over the
/// deadline) cannot hold a `required` ingress stream past its handshake
/// deadline — the visitor connection closes and the timeout counter ticks
/// (anti dribble: the stream-table slot is released with the stream).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a8_handshake_dribble_hits_deadline() {
    let _serial = serial_lock().await;
    let _ = metrics_handle();
    init_tracing();
    let (hub_port, ingress_addr) = required_ingress_against("victim", 2).await;
    let (attacker, _h) = connect_tunnel(hub_port, "victim").await;
    // Dribble: a VALID TLS record header claiming a large body, then the
    // body fed 4 bytes at a time every 300ms — rustls buffers the partial
    // record (no error, no progress), so only the deadline can end it.
    tokio::spawn(async move {
        let mut incoming = attacker.take_incoming_streams().await.unwrap();
        while let Some(IncomingStream { open, frames }) = incoming.recv().await {
            let attacker = attacker.clone();
            tokio::spawn(async move {
                let sid = open.stream_id.clone();
                let _ = frames;
                // Handshake record, legacy version 3.1, 64 KiB body.
                let mut drib = vec![0x16, 0x03, 0x01];
                drib.extend_from_slice(&66u16.to_be_bytes());
                for chunk in drib.chunks(4) {
                    if attacker
                        .send_data_response(sid, Bytes::copy_from_slice(chunk))
                        .await
                        .is_err()
                    {
                        break;
                    }
                    tokio::time::sleep(Duration::from_millis(300)).await;
                }
            });
        }
    });

    let mut sock = dial_listener(ingress_addr).await;
    let started = std::time::Instant::now();
    let _ = read_available(&mut sock, Duration::from_secs(10)).await;
    let elapsed = started.elapsed();
    assert!(
        elapsed >= Duration::from_secs(1) && elapsed < Duration::from_secs(7),
        "closed by the handshake deadline (~2s), took {elapsed:?}"
    );
    wait_counter_at_least(
        "interflow_agent_e2e_handshake_failures_total{side=\"ingress\",reason=\"timeout\"}",
        1,
        Duration::from_secs(5),
    )
    .await;
}
