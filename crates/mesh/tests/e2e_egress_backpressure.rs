//! E2E: egress backpressure and poisoning semantics (regression suite for the
//! 2026-09-12 dispatch channelization final-state refactor).
//!
//! Background: in the
//! old model, egress consumed tunnel frames via a tokio broadcast channel, and
//! consumption lag silently dropped frames as `Lagged(n)` (the TCP stream lost
//! bytes while the connection stayed up); moreover, a single slow backend could
//! stall the entire consumer loop, amplifying into corruption for all streams.
//! After the refactor:
//!
//! - Request-direction frames go through a dedicated per-stream mpsc channel
//!   (with backpressure and structurally no frame loss);
//! - Dispatch waits boundedly for 5s per frame delivery; on timeout it poisons
//!   that stream (`recv() == None` → forwarder self-terminates + Close
//!   notification), without affecting other streams or tearing down the session;
//! - The egress TCP forwarder declares a backend dead on a stalled backend
//!   write timeout; ingress/edge clients close the connection on a stalled
//!   response-write timeout (the consumer-side counterpart of response-
//!   direction poisoning).
//!
//! Scenarios:
//! - T1 a slow backend does not corrupt unrelated streams (main regression for
//!   backlog E1)
//! - T2 poisoning is visible and the agent is not evicted (E2 variant: no
//!   longer needs a fail-loud tunnel teardown)
//! - T3 a targetless stream is rejected + Close, not misrouted to the first
//!   rule (E3)
//! - T4 after a UDP session is recycled on idle, a new session is immediately
//!   usable (E4)
//! - T5 no connection/task leaks after death detection + graceful shutdown (E5)
//! - T6 loopback: a single agent is both ingress and egress (the key path of
//!   direction-split tables)
//! - T7 response-direction poisoning: a client that never reads responses is
//!   closed, other clients are unaffected

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
use interflow_core::protocol::{FrameType, StreamProto};
use interflow_core::tls::{InnerTlsMaterial, inner_client_config};
use interflow_core::tunnel::AgentTunnel;
use interflow_core::tunnel::InnerStreamHello;
use interflow_core::tunnel::TargetSelector;
use interflow_core::tunnel::e2e::{E2eHandshakeOutcome, E2eTunnelIo, inner_tls_connect};
use interflow_mesh::agent::{AgentClient, AgentHandle, AgentState};
use interflow_mesh::config::{EgressRule, EgressTarget, IngressRule};
use interflow_testkit::{
    agent_config, echo_server, hub_config, metrics_harness::eventually,
    metrics_harness::init_tracing, metrics_harness::metrics_handle,
    metrics_harness::wait_counter_at_least, spawn_hub,
};
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

fn certs() -> &'static interflow_testkit::certs::TestCerts {
    static C: std::sync::OnceLock<interflow_testkit::certs::TestCerts> = std::sync::OnceLock::new();
    C.get_or_init(|| interflow_testkit::certs::TestCerts::generate("e2e", "agent"))
}

static SERIAL: std::sync::OnceLock<tokio::sync::Mutex<()>> = std::sync::OnceLock::new();

async fn serial_lock() -> tokio::sync::MutexGuard<'static, ()> {
    SERIAL
        .get_or_init(|| tokio::sync::Mutex::new(()))
        .lock()
        .await
}

/// Adaptive total budget per test (poisoning 5s + backend write timeout 10s +
/// scheduling headroom).
const LONG_DEADLINE: Duration = Duration::from_secs(25);

// ---------------------------------------------------------------------------
// metrics: install an in-process recorder and read snapshots directly
// (installed once, shared by all tests)
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// Test backends and bare-tunnel injection scaffolding
// ---------------------------------------------------------------------------

/// Slow backend: creates a "connection alive but cannot drain" write stall.
///
/// During the hold period (12s) it does **no reads or writes at all** — once
/// the peer's sndbuf/rcvbuf are full, the forwarder's `write_all` stalls,
/// triggering poisoning/write-timeout death detection (in the old
/// implementation, a single `read` would return as soon as the first packet
/// arrived and close the connection early, short-circuiting the write stall
/// into backend_closed). Afterwards it switches to drain mode: while data is
/// not consumed, the FIN sits behind the rcvbuf data, so EOF detection must
/// drain first — draining to EOF/error counts as the connection being closed,
/// decrementing the active count. 12s covers the write-timeout windows of all
/// users (T1/T5 = 3s, T2 = 10s).
async fn slow_backend() -> (SocketAddr, Arc<AtomicUsize>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let active = Arc::new(AtomicUsize::new(0));
    let active2 = active.clone();
    tokio::spawn(async move {
        loop {
            let Ok((mut sock, _)) = listener.accept().await else {
                break;
            };
            active2.fetch_add(1, Ordering::SeqCst);
            let a = active2.clone();
            tokio::spawn(async move {
                // True black hole hold period: no reads → backpressure; drain
                // and close out when it expires
                tokio::time::sleep(Duration::from_secs(12)).await;
                let mut buf = [0u8; 4096];
                loop {
                    if !matches!(sock.read(&mut buf).await, Ok(n) if n > 0) {
                        break;
                    }
                }
                a.fetch_sub(1, Ordering::SeqCst);
            });
        }
    });
    (addr, active)
}

/// Counting backend (T3): counts connections and received bytes; discards
/// whatever it reads.
async fn counting_backend() -> (SocketAddr, Arc<AtomicUsize>, Arc<AtomicUsize>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let conns = Arc::new(AtomicUsize::new(0));
    let bytes = Arc::new(AtomicUsize::new(0));
    let (c2, b2) = (conns.clone(), bytes.clone());
    tokio::spawn(async move {
        loop {
            let Ok((mut sock, _)) = listener.accept().await else {
                break;
            };
            c2.fetch_add(1, Ordering::SeqCst);
            let b3 = b2.clone();
            tokio::spawn(async move {
                let mut buf = [0u8; 4096];
                loop {
                    match sock.read(&mut buf).await {
                        Ok(0) | Err(_) => break,
                        Ok(n) => {
                            b3.fetch_add(n, Ordering::SeqCst);
                        }
                    }
                }
            });
        }
    });
    (addr, conns, bytes)
}

/// Bare-tunnel injection endpoint: connect to the hub + register + AgentTunnel
/// (frame-level direct send, with full control over the frame count).
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

/// Open a production-shaped TCP stream and complete the mandatory inner
/// TLS handshake plus encrypted target selector. Handshake races are retried
/// on the same stream id after an explicit close; successful streams never
/// fall back to plaintext.
async fn open_inner_tls(
    inj: &AgentTunnel,
    sid: interflow_core::protocol::StreamId,
    target: &str,
) -> tokio_rustls::client::TlsStream<tokio::io::DuplexStream> {
    let (cert, key) = certs().named_client_cert("inj");
    let ca = certs().ca_path().display().to_string();
    let material = InnerTlsMaterial::from_paths(
        &[ca.as_str()],
        &cert.display().to_string(),
        &key.display().to_string(),
    )
    .expect("inner material");
    let connector = tokio_rustls::TlsConnector::from(Arc::new(
        inner_client_config(&material, "eg").expect("inner connector"),
    ));

    for attempt in 0..3 {
        let rx = inj.register_stream(sid).await;
        if let Err(e) = inj.send_open_with(sid, "eg", StreamProto::Tcp, true).await {
            let _ = inj.send_close(sid).await;
            inj.unregister_stream(sid).await;
            if attempt == 2 {
                panic!("inner-TLS open: {e}");
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
            continue;
        }
        let adapter = E2eTunnelIo::ingress(rx, inj.clone(), sid);
        let mut tls =
            match inner_tls_connect(adapter, connector.clone(), Duration::from_secs(5)).await {
                E2eHandshakeOutcome::Established(tls, _) => tls,
                E2eHandshakeOutcome::Failed { error } => {
                    let _ = inj.send_close(sid).await;
                    inj.unregister_stream(sid).await;
                    if attempt == 2 {
                        panic!("inner TLS handshake: {error}");
                    }
                    tokio::time::sleep(Duration::from_millis(100)).await;
                    continue;
                }
            };
        let hello = InnerStreamHello {
            source_principal: "inj".to_owned(),
            source_fingerprint: material.leaf_fingerprint(),
            selector: TargetSelector::Address(target.to_owned()),
            correlation_id: *uuid::Uuid::new_v4().as_bytes(),
        };
        if let Err(e) = hello.write(&mut tls).await {
            let _ = inj.send_close(sid).await;
            inj.unregister_stream(sid).await;
            if attempt == 2 {
                panic!("inner hello: {e}");
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
            continue;
        }
        return tls;
    }
    unreachable!("inner-TLS retry loop returns or panics");
}

/// Inner-TLS round trip: send payload and receive the equal-length reply.
async fn tunnel_round_trip(
    inj: &AgentTunnel,
    sid: interflow_core::protocol::StreamId,
    target: SocketAddr,
    payload: &[u8],
    deadline: Duration,
) -> Vec<u8> {
    let mut tls = open_inner_tls(inj, sid, &target.to_string()).await;
    tls.write_all(payload).await.expect("inner send");
    tls.flush().await.expect("inner flush");
    let deadline = tokio::time::Instant::now() + deadline;
    let mut got = Vec::with_capacity(payload.len());
    while got.len() < payload.len() {
        let mut chunk = vec![0u8; payload.len() - got.len()];
        let n = tokio::time::timeout_at(deadline, tls.read(&mut chunk))
            .await
            .expect("reply timed out")
            .expect("inner reply");
        assert_ne!(n, 0, "inner stream closed prematurely");
        got.extend_from_slice(&chunk[..n]);
    }
    got
}

/// Wait until the egress agent is ready (registration complete): probe-stream
/// round trip succeeds or times out.
/// On probe failure (the agent is unregistered and the hub rejects the stream
/// with a Close), retry automatically with a fresh sid.
async fn wait_egress_ready(inj: &AgentTunnel, echo_addr: SocketAddr) {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
    let mut attempt = 0u32;
    loop {
        attempt += 1;
        let sid = interflow_testkit::opaque_stream_id(&format!("probe-{attempt}"));
        // A successful inner-TLS round trip proves both registration and the
        // Data path. Failures retry while the egress is still connecting.
        let result = tokio::time::timeout(
            Duration::from_secs(2),
            tunnel_round_trip(inj, sid, echo_addr, b"ping", Duration::from_secs(2)),
        )
        .await;
        if result.is_ok_and(|resp| resp == b"ping") {
            return;
        }
        if tokio::time::Instant::now() >= deadline {
            panic!("egress agent not ready within 10s");
        }
        tokio::time::sleep(Duration::from_millis(250)).await;
    }
}

/// Start a hub + egress agent (with an echo backend); returns
/// (hub_port, echo_addr, injector).
async fn start_stack(write_timeout: u64) -> (u16, SocketAddr, AgentTunnel) {
    let hub = spawn_hub(hub_config(0, certs(), vec![])).await;
    let hub_port = hub.local_addr().expect("hub bound").port();
    let (echo_addr, _echo) = echo_server().await;

    let mut eg = agent_config("eg", hub_port, certs());
    eg.egress_backend_write_timeout_secs = write_timeout;
    let _eg_handle = interflow_testkit::spawn_agent_registered(eg).await;

    let (inj, _conn) = connect_tunnel(hub_port, "inj").await;
    wait_egress_ready(&inj, echo_addr).await;
    (hub_port, echo_addr, inj)
}

// ---------------------------------------------------------------------------
// T1: a slow backend does not corrupt unrelated streams (main regression for
// backlog E1)
// ---------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn t1_slow_backend_does_not_corrupt_unrelated_streams() {
    let _serial = serial_lock().await;
    let _ = metrics_handle(); // Install the recorder as early as possible: the metrics macros cache per callsite, emissions before installation are invisible
    let (_hub_port, echo_addr, inj) = start_stack(3).await;
    let (slow_addr, slow_active) = slow_backend().await;

    // Keep one backend connection open to the black hole while unrelated
    // streams transfer data. T2/T5 below deliberately fill the stream channel
    // and test poisoning/write-timeout death.
    let slow_sid = interflow_testkit::opaque_stream_id("t1-slow");
    let slow_tls = open_inner_tls(&inj, slow_sid, &slow_addr.to_string()).await;

    // Critical window: while the slow backend occupies a forwarder, unrelated
    // streams must complete round trips with zero corruption. Each stream is
    // used as soon as it is established (the normal client lifecycle); T2/T5
    // cover deliberately stalled bulk writers.
    let mut healthy_results = Vec::new();
    for i in 0..3 {
        let sid = interflow_testkit::opaque_stream_id(&format!("t1-ok-{i}"));
        let payload = vec![0x5a_u8 + i as u8; 64 * 1024];
        let mut tls = open_inner_tls(&inj, sid, &echo_addr.to_string()).await;
        tls.write_all(&payload).await.expect("healthy send");
        tls.flush().await.expect("healthy flush");
        let deadline = tokio::time::Instant::now() + LONG_DEADLINE;
        let mut got = Vec::with_capacity(payload.len());
        while got.len() < payload.len() {
            let mut chunk = vec![0u8; payload.len() - got.len()];
            let n = tokio::time::timeout_at(deadline, tls.read(&mut chunk))
                .await
                .unwrap_or_else(|_| {
                    panic!(
                        "healthy reply timed out (snapshot:\n{})",
                        metrics_handle().render()
                    )
                })
                .expect("healthy reply");
            assert_ne!(n, 0, "healthy inner stream closed");
            got.extend_from_slice(&chunk[..n]);
        }
        healthy_results.push((payload, got));
    }

    for (payload, resp) in healthy_results {
        assert_eq!(
            resp, payload,
            "unrelated-stream data corruption (regression of the slow-backend amplification defect)"
        );
    }
    assert_eq!(
        slow_active.load(Ordering::SeqCst),
        1,
        "slow backend connection should remain open during healthy transfers"
    );

    // Close the slow stream deterministically and verify its backend fd is released.
    drop(slow_tls);
    let _ = inj.send_close(slow_sid).await;
    inj.unregister_stream(slow_sid).await;
    eventually(
        || slow_active.load(Ordering::SeqCst) == 0,
        LONG_DEADLINE,
        "all slow-backend connections closed",
    )
    .await;
    // The session was not torn down: new streams work as usual.
    let resp = tunnel_round_trip(
        &inj,
        interflow_testkit::opaque_stream_id("t1-after"),
        echo_addr,
        b"still-alive",
        LONG_DEADLINE,
    )
    .await;
    assert_eq!(resp, b"still-alive");
}

// ---------------------------------------------------------------------------
// T2: poisoning is visible and the agent is not evicted (a single-stream
// failure does not escalate into a whole-connection reconnect)
// ---------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn t2_poison_is_visible_and_agent_survives() {
    let _serial = serial_lock().await;
    let _ = metrics_handle(); // Install the recorder as early as possible: the metrics macros cache per callsite, emissions before installation are invisible
    let hub = spawn_hub(hub_config(0, certs(), vec![])).await;
    let hub_port = hub.local_addr().expect("hub bound").port();
    let (echo_addr, _echo) = echo_server().await;
    let (slow_addr, _slow_active) = slow_backend().await;

    // Default write timeout 10s: let dispatch poisoning (5s) trigger before the
    // forwarder write timeout.
    let handle: AgentHandle = {
        let mut eg = agent_config("eg", hub_port, certs());
        eg.egress_backend_write_timeout_secs = 10;
        AgentClient::new(eg).expect("agent build").start()
    };

    let (inj, _conn) = connect_tunnel(hub_port, "inj").await;
    wait_egress_ready(&inj, echo_addr).await;

    // Watch the agent state: after the first Connected, no sign of reconnect
    // is allowed.
    let mut state_rx = handle.subscribe_state();
    let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
    loop {
        if matches!(&*state_rx.borrow_and_update(), AgentState::Connected { .. }) {
            break;
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "agent did not become Connected within 10s: {:?}",
            &*state_rx.borrow_and_update()
        );
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    let state_trace = Arc::new(std::sync::Mutex::new(Vec::new()));
    let watcher = {
        let trace = state_trace.clone();
        let mut rx = state_rx.clone();
        tokio::spawn(async move {
            loop {
                if rx.changed().await.is_err() {
                    return;
                }
                trace
                    .lock()
                    .unwrap()
                    .push(format!("{:?}", &*rx.borrow_and_update()));
            }
        })
    };

    // Flood the slow stream with 1500 frames: channel full → dispatch poisons
    // after 5s (visible via the counter).
    let slow_sid = interflow_testkit::opaque_stream_id("t2-slow");
    let slow_tls = open_inner_tls(&inj, slow_sid, &slow_addr.to_string()).await;
    let flood = {
        let mut tls = slow_tls;
        tokio::spawn(async move {
            let chunk = Bytes::from(vec![0xa5u8; 16 * 1024]);
            for _ in 0..1500 {
                if tls.write_all(&chunk).await.is_err() {
                    break;
                }
                if tls.flush().await.is_err() {
                    break;
                }
            }
        })
    };

    // Poisoning counter + egress stream-closed counter appear (visible
    // failure).
    wait_counter_at_least("interflow_dispatch_stream_poisoned_total", 1, LONG_DEADLINE).await;
    wait_counter_at_least("interflow_egress_stream_closed_total", 1, LONG_DEADLINE).await;
    let _ = flood.await;

    // The agent was not evicted/reconnected: a new stream round-trips as
    // usual and the state trace shows no reconnection.
    let resp = tunnel_round_trip(
        &inj,
        interflow_testkit::opaque_stream_id("t2-after"),
        echo_addr,
        b"survivor",
        LONG_DEADLINE,
    )
    .await;
    assert_eq!(resp, b"survivor");
    tokio::time::sleep(Duration::from_millis(300)).await;
    let trace = state_trace.lock().unwrap().clone();
    assert!(
        trace.is_empty(),
        "agent should not change state during poisoning (should not be evicted/reconnected): {trace:?}"
    );
    watcher.abort();
}

// ---------------------------------------------------------------------------
// T3: a targetless stream is rejected + Close, not misrouted to the first
// rule (backlog E3 safety regression)
// ---------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn t3_targetless_udp_stream_rejected_not_misrouted() {
    let _serial = serial_lock().await;
    let _ = metrics_handle(); // Install the recorder as early as possible: the metrics macros cache per callsite, emissions before installation are invisible
    let hub = spawn_hub(hub_config(0, certs(), vec![])).await;
    let hub_port = hub.local_addr().expect("hub bound").port();
    let (tcp_addr, tcp_conns, tcp_bytes) = counting_backend().await;

    // The egress has only one TCP rule: the old code would misroute targetless
    // UDP Data here.
    let mut eg = agent_config("eg", hub_port, certs());
    eg.egress = vec![EgressRule {
        name: "only-tcp".into(),
        target: EgressTarget::Addr(tcp_addr),
        target_protocol: StreamProto::Tcp,
        udp_idle_timeout_secs: None,
    }];
    interflow_testkit::spawn_agent_registered(eg).await;

    let (inj, _conn) = connect_tunnel(hub_port, "inj").await;
    tokio::time::sleep(Duration::from_millis(500)).await;

    // Open with an empty target + UDP protocol: no dynamic target, no UDP rule
    // → must reject + Close.
    let sid = interflow_testkit::opaque_stream_id("t3-stream");
    let mut rx = inj.register_stream(sid.clone()).await;
    inj.send_open(sid, "eg", StreamProto::Udp)
        .await
        .expect("open");
    inj.send_data(sid, Bytes::from_static(b"misroute-me"))
        .await
        .expect("send");

    let frame = tokio::time::timeout(Duration::from_secs(5), rx.recv())
        .await
        .expect("timed out waiting for the rejecting Close")
        .expect("channel alive");
    assert!(
        matches!(frame.stream_type, FrameType::Close),
        "a targetless stream should be rejected with Close, got {frame:?}"
    );

    // Misrouting regression checkpoint: 0 connections and 0 bytes on the TCP
    // backend.
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert_eq!(
        tcp_conns.load(Ordering::SeqCst),
        0,
        "no TCP connection should be mis-created"
    );
    assert_eq!(
        tcp_bytes.load(Ordering::SeqCst),
        0,
        "no bytes should be mis-sent"
    );
    wait_counter_at_least(
        "interflow_egress_stream_closed_total",
        1,
        Duration::from_secs(5),
    )
    .await;
}

// ---------------------------------------------------------------------------
// T4: after a UDP session is recycled on idle, a new session is immediately
// usable (backlog E4)
// ---------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn t4_udp_session_recycles_and_new_session_works() {
    let _serial = serial_lock().await;
    let _ = metrics_handle(); // Install the recorder as early as possible
    init_tracing();
    let hub = spawn_hub(hub_config(0, certs(), vec![])).await;
    let hub_port = hub.local_addr().expect("hub bound").port();
    let (udp_addr, _udp) = interflow_testkit::spawn_udp_echo().await;

    let mut eg = agent_config("eg", hub_port, certs());
    eg.egress = vec![EgressRule {
        name: "udp-out".into(),
        target: EgressTarget::Addr(udp_addr),
        target_protocol: StreamProto::Udp,
        udp_idle_timeout_secs: Some(1),
    }];
    interflow_testkit::spawn_agent_registered(eg).await;

    let mut ing = agent_config("ing", hub_port, certs());
    ing.ingress = vec![IngressRule {
        name: "udp-in".into(),
        listen_addr: "127.0.0.1:0".parse().unwrap(),
        listen_protocol: StreamProto::Udp,
        target_agent: "eg".into(),
        remote_addr: Some(udp_addr.to_string()),
        idle_timeout_secs: Some(1),
        udp_per_ip_pps: 0,
        udp_per_ip_bytes_per_sec: 0,
        udp_egress_bytes_per_sec: 0,
    }];
    let ing_handle = interflow_testkit::spawn_agent_registered(ing).await;
    let listen_addr = ing_handle
        .wait_ingress_addr("udp-in", Duration::from_secs(10))
        .await
        .expect("ingress listener bound");

    // One public source address exercises one inner-QUIC session.
    let sock = interflow_testkit::udp_client().await;
    let mut recv_one = [0u8; 64];
    sock.send_to(b"ping-1", listen_addr)
        .await
        .expect("udp send 1");
    let (n, _) = tokio::time::timeout(Duration::from_secs(5), sock.recv_from(&mut recv_one))
        .await
        .expect("udp reply 1 timed out")
        .expect("udp reply 1");
    assert_eq!(&recv_one[..n], b"ping-1");

    // Idle recycling happens inside the mandatory inner-QUIC association. The
    // same public source must immediately get a fresh session, not hang.
    tokio::time::sleep(Duration::from_millis(1500)).await;
    sock.send_to(b"ping-2", listen_addr)
        .await
        .expect("udp send 2");
    let mut recv_two = [0u8; 64];
    let (n, _) = tokio::time::timeout(Duration::from_secs(5), sock.recv_from(&mut recv_two))
        .await
        .expect("udp reply 2 timed out")
        .expect("udp reply 2");
    assert_eq!(&recv_two[..n], b"ping-2");
}

// ---------------------------------------------------------------------------
// T5: no connection leaks after death detection + graceful shutdown
// (backlog E5)
// ---------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn t5_no_connection_leak_after_kill_and_shutdown() {
    let _serial = serial_lock().await;
    let _ = metrics_handle(); // Install the recorder as early as possible: the metrics macros cache per callsite, emissions before installation are invisible
    let hub = spawn_hub(hub_config(0, certs(), vec![])).await;
    let hub_port = hub.local_addr().expect("hub bound").port();
    let (echo_addr, _echo) = echo_server().await;
    let (slow_addr, slow_active) = slow_backend().await;

    let handle: AgentHandle = {
        let mut eg = agent_config("eg", hub_port, certs());
        eg.egress_backend_write_timeout_secs = 3;
        AgentClient::new(eg).expect("agent build").start()
    };

    let (inj, _conn) = connect_tunnel(hub_port, "inj").await;
    wait_egress_ready(&inj, echo_addr).await;

    // Slow stream declared dead (write stall 3s).
    let slow_sid = interflow_testkit::opaque_stream_id("t5-slow");
    let slow_tls = open_inner_tls(&inj, slow_sid, &slow_addr.to_string()).await;
    let flood = {
        let mut tls = slow_tls;
        tokio::spawn(async move {
            let chunk = Bytes::from(vec![0xa5u8; 16 * 1024]);
            for _ in 0..400 {
                if tls.write_all(&chunk).await.is_err() {
                    break;
                }
                if tls.flush().await.is_err() {
                    break;
                }
            }
        })
    };

    // After the death verdict, the backend connection count must reach zero
    // (forwarder cancel + both halves dropped = actually closed).
    eventually(
        || slow_active.load(Ordering::SeqCst) == 0,
        LONG_DEADLINE,
        "slow-backend connections closed after the death verdict",
    )
    .await;
    let _ = flood.await;

    // Graceful shutdown completes within the time limit (all TaskTracker tasks
    // closed out, no leaked tasks left hanging).
    tokio::time::timeout(Duration::from_secs(10), handle.shutdown_graceful())
        .await
        .expect("graceful shutdown timed out (possible task leak)")
        .expect("shutdown err");
}

// ---------------------------------------------------------------------------
// T6: loopback — a single agent is both ingress and egress (the key path of
// direction-split tables)
// ---------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn t6_loopback_agent_is_both_ingress_and_egress() {
    let _serial = serial_lock().await;
    let _ = metrics_handle(); // Install the recorder as early as possible: the metrics macros cache per callsite, emissions before installation are invisible
    let hub = spawn_hub(hub_config(0, certs(), vec![])).await;
    let hub_port = hub.local_addr().expect("hub bound").port();
    let (echo_addr, _echo) = echo_server().await;

    // Same agent: the ingress rule's target points at itself (hub loopback
    // routing), no egress rules (the dynamic target is carried by the Open
    // frame to this agent's forwarder).
    let mut both = agent_config("both", hub_port, certs());
    both.ingress = vec![IngressRule {
        name: "loop".into(),
        listen_addr: "127.0.0.1:0".parse().unwrap(),
        listen_protocol: StreamProto::Tcp,
        target_agent: "both".into(),
        remote_addr: Some(echo_addr.to_string()),
        idle_timeout_secs: None,
        udp_per_ip_pps: 0,
        udp_per_ip_bytes_per_sec: 0,
        udp_egress_bytes_per_sec: 0,
    }];
    let both_handle = interflow_testkit::spawn_agent_registered(both).await;
    let listen_addr = both_handle
        .wait_ingress_addr("loop", Duration::from_secs(10))
        .await
        .expect("ingress listener bound");

    // Byte-for-byte comparison across two connections: request frames
    // (egress direction) and response frames (ingress direction) for the same
    // sid live in two separate tables without cross-talk.
    for i in 0..2 {
        let payload = vec![0x30_u8 + i as u8; 128 * 1024];
        let resp = interflow_testkit::echo_round_trip(listen_addr, &payload)
            .await
            .expect("loopback echo");
        assert_eq!(resp, payload, "loopback data corruption");
    }
}

// ---------------------------------------------------------------------------
// T7: response-direction poisoning — a client that does not read responses is
// closed, other clients are unaffected
// ---------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn t7_response_poison_closes_stalled_client_only() {
    let _serial = serial_lock().await;
    let _ = metrics_handle(); // Install the recorder as early as possible: the metrics macros cache per callsite, emissions before installation are invisible
    init_tracing();
    let hub = spawn_hub(hub_config(0, certs(), vec![])).await;
    let hub_port = hub.local_addr().expect("hub bound").port();
    let (echo_addr, _echo) = echo_server().await;

    interflow_testkit::spawn_agent_registered(agent_config("eg", hub_port, certs())).await;

    let mut ing = agent_config("ing", hub_port, certs());
    ing.ingress = vec![IngressRule {
        name: "to-eg".into(),
        listen_addr: "127.0.0.1:0".parse().unwrap(),
        listen_protocol: StreamProto::Tcp,
        target_agent: "eg".into(),
        remote_addr: Some(echo_addr.to_string()),
        idle_timeout_secs: None,
        udp_per_ip_pps: 0,
        udp_per_ip_bytes_per_sec: 0,
        udp_egress_bytes_per_sec: 0,
    }];
    let ing_handle = interflow_testkit::spawn_agent_registered(ing).await;
    let listen_addr = ing_handle
        .wait_ingress_addr("to-eg", Duration::from_secs(10))
        .await
        .expect("ingress listener bound");

    // Bad client: writes enough to overrun the response path, then never reads.
    // Periodic one-byte probes detect closure via EPIPE/RST without turning the
    // client into a response consumer or continuously flooding the inner-TLS
    // upload alongside the good stream.
    let bad = TcpStream::connect(listen_addr).await.expect("bad client");
    let (bad_ready, bad_ready_rx) = tokio::sync::oneshot::channel();
    let bad_write = tokio::spawn(async move {
        let mut bad = bad;
        let chunk = vec![0x77u8; 8 * 1024 * 1024];
        if bad.write_all(&chunk).await.is_err() {
            return "closed"; // write failure = the server closed the connection
        }
        let _ = bad_ready.send(());
        let probe = [0x77u8];
        loop {
            tokio::time::sleep(Duration::from_millis(100)).await;
            if bad.write_all(&probe).await.is_err() {
                return "closed";
            }
        }
    });

    // Under a full-suite load the response channel can hit its stall deadline
    // just before the 8 MiB initial write completes. That is still the desired
    // poison outcome; the final task result below asserts closure.
    let _ = bad_ready_rx.await;

    // The good client round-trips concurrently and must finish with zero
    // corruption (being slowed by the poisoning window is allowed).
    let good = {
        let addr = listen_addr;
        tokio::spawn(async move {
            let payload = vec![0x42u8; 256 * 1024];
            let resp = interflow_testkit::echo_round_trip(addr, &payload)
                .await
                .expect("good client echo");
            (payload, resp)
        })
    };
    let (g_payload, g_resp) = good.await.expect("good task");
    assert_eq!(g_resp, g_payload, "unrelated-client data corruption");

    // The bad client is closed within the write-stall upper bound.
    let outcome = tokio::time::timeout(Duration::from_secs(25), bad_write)
        .await
        .expect("timed out detecting bad-client closure")
        .expect("bad write task");
    assert_eq!(
        outcome, "closed",
        "the stalled client should be closed by the server"
    );

    // The poisoning counter is visible (response direction).
    wait_counter_at_least(
        "interflow_dispatch_stream_poisoned_total",
        1,
        Duration::from_secs(5),
    )
    .await;
}
