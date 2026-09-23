//! E2E: eradicating intra-session orphan streams (regression suite for the
//! 2026-09-14 second EMFILE recurrence).
//!
//! Background:
//! 37808dc fixed the **cross-session** leak; three orphan paths remained
//! within the same session — the hub's `_close_` notification silently
//! dropped by try_send, `sweep_agent_streams` clearing the table without
//! notifying the peer, and the egress read task exiting without waking the
//! main loop — enough to exhaust the macOS GUI soft limit of 256 fds within
//! 40 minutes.
//!
//! Scenarios (each maps to one root-cause path; must fail/time out before the
//! fix):
//! - T1 backend EOF + the peer **never replies `_close_`** → the forwarder
//!   closes out after bounded draining, the backend connection is released,
//!   and the `backend_closed` attribution is visible (old code: the main loop
//!   hung on frames.recv() until the session ended);
//! - T2 half-close draining: after the backend's write side FINs it keeps
//!   reading; request tail data arriving within the drain window must reach
//!   the backend (old code: EOF immediately sent back Close, the hub tore the
//!   stream down, and the tail data was rejected);
//! - T4 the source agent re-registering triggers a sweep → all in-flight
//!   streams on the peer egress receive `_close_` and backend connections
//!   reach zero (old code: the table was cleared without notification, and
//!   fds lingered until the egress's own session rebuild);
//! - Normal-close regression: unchanged behavior after the source Close-frame
//!   path moved to the control channel.

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
use interflow_core::protocol::StreamProto;
use interflow_core::tls::{InnerTlsMaterial, inner_client_config};
use interflow_core::tunnel::AgentTunnel;
use interflow_core::tunnel::e2e::{E2eHandshakeOutcome, E2eTunnelIo, inner_tls_connect};
use interflow_core::tunnel::{InnerStreamHello, TargetSelector};
use interflow_mesh::agent::AgentClient;
use interflow_testkit::{
    agent_config, hub_config, metrics_harness::counter_value, metrics_harness::metrics_handle,
    pick_ephemeral_port, spawn_agent_registered, spawn_hub,
};
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

fn certs() -> &'static interflow_testkit::certs::TestCerts {
    static C: std::sync::OnceLock<interflow_testkit::certs::TestCerts> = std::sync::OnceLock::new();
    C.get_or_init(|| interflow_testkit::certs::TestCerts::generate("e2e", "agent"))
}

/// Egress drain window (egress.rs BACKEND_EOF_DRAIN_GRACE) + assertion
/// headroom.
const RELEASE_DEADLINE: Duration = Duration::from_secs(12);

// ---------------------------------------------------------------------------
// metrics: in-process recorder read directly; `eventually` is a local
// variant of testkit's — its timeout panic embeds the metrics snapshot,
// which the generic helper cannot offer.
// ---------------------------------------------------------------------------

async fn eventually<F: Fn() -> bool>(cond: F, timeout: Duration, what: &str) {
    let deadline = tokio::time::Instant::now() + timeout;
    loop {
        if cond() {
            return;
        }
        if tokio::time::Instant::now() >= deadline {
            panic!(
                "timed out waiting for {what} (snapshot:\n{})",
                metrics_handle().render()
            );
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
}

/// Bare-tunnel injection endpoint: connect to the hub + register + AgentTunnel
/// (frame-level direct send, with full control over the frame count).
async fn connect_tunnel(hub_port: u16, agent_id: &str) -> AgentTunnel {
    let client = AgentClient::new(agent_config(agent_id, hub_port, certs())).expect("agent build");
    let conn = client
        .connect_and_register()
        .await
        .expect("connect+register");
    AgentTunnel::from_sender(
        conn.negotiated.circuit_token,
        &format!("http://127.0.0.1:{hub_port}"),
        conn.send_request,
        &interflow_core::tunnel::session_tasks::SessionTasks::new(
            tokio_util::sync::CancellationToken::new(),
        ),
        interflow_core::tunnel::H2Liveness::HEARTBEAT_DISABLED,
    )
    .expect("tunnel")
}

/// Establish an inner-TLS stream and send its encrypted target selector.
async fn open_inner_tls(
    inj: &AgentTunnel,
    agent_id: &str,
    sid: interflow_core::protocol::StreamId,
    target: &str,
) -> tokio_rustls::client::TlsStream<tokio::io::DuplexStream> {
    let rx = inj.register_stream(sid).await;
    inj.send_open_with(sid, "eg", StreamProto::Tcp, true)
        .await
        .expect("inner-TLS open");
    let (cert, key) = certs().named_client_cert(agent_id);
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
    let adapter = E2eTunnelIo::ingress(rx, inj.clone(), sid);
    let mut tls = match inner_tls_connect(adapter, connector, Duration::from_secs(5)).await {
        E2eHandshakeOutcome::Established(tls, _) => tls,
        E2eHandshakeOutcome::Failed { error } => panic!("inner TLS handshake: {error}"),
    };
    InnerStreamHello {
        source_principal: agent_id.to_owned(),
        source_fingerprint: material.leaf_fingerprint(),
        selector: TargetSelector::Address(target.to_owned()),
        correlation_id: *uuid::Uuid::new_v4().as_bytes(),
    }
    .write(&mut tls)
    .await
    .expect("inner hello");
    tls
}

// ---------------------------------------------------------------------------
// Backends
// ---------------------------------------------------------------------------

/// A backend that echoes once it has read `first` and then **closes its write
/// side** (T1: produces a clean EOF for the egress read task).
/// The active count is only decremented when the **egress side** closes the
/// connection (reads EOF/RST) — that is the true signal of the backend fd
/// being released, not the backend dropping its own socket.
async fn close_after_echo_backend(first: &[u8]) -> (SocketAddr, Arc<AtomicUsize>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let active = Arc::new(AtomicUsize::new(0));
    let a2 = active.clone();
    let first = first.to_vec();
    tokio::spawn(async move {
        loop {
            let Ok((mut sock, _)) = listener.accept().await else {
                break;
            };
            a2.fetch_add(1, Ordering::SeqCst);
            let a3 = a2.clone();
            let first = first.clone();
            tokio::spawn(async move {
                let mut buf = Vec::new();
                let mut chunk = [0u8; 256];
                // After reading `first` bytes, echo and close the write side
                // (the egress read task gets a clean EOF)
                while buf.len() < first.len() {
                    match sock.read(&mut chunk).await {
                        Ok(0) | Err(_) => return,
                        Ok(n) => buf.extend_from_slice(&chunk[..n]),
                    }
                }
                let _ = sock.write_all(&buf).await;
                let _ = sock.shutdown().await;
                // Keep reading: only when the egress forwarder releases the
                // connection (both halves dropped → the peer receives
                // FIN/RST) is this connection truly closed
                loop {
                    match sock.read(&mut chunk).await {
                        Ok(0) | Err(_) => break,
                        Ok(_) => {}
                    }
                }
                a3.fetch_sub(1, Ordering::SeqCst);
            });
        }
    });
    (addr, active)
}

/// Half-close backend (T2): read `first` → echo → **close only the write
/// side** (FIN), keep reading and record every subsequent byte into `tail`;
/// the connection ends only at read-side EOF.
async fn half_close_backend(
    first: &[u8],
) -> (SocketAddr, Arc<std::sync::Mutex<Vec<u8>>>, Arc<AtomicUsize>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let active = Arc::new(AtomicUsize::new(0));
    let tail: Arc<std::sync::Mutex<Vec<u8>>> = Arc::new(std::sync::Mutex::new(Vec::new()));
    let (a2, t2) = (active.clone(), tail.clone());
    let first = first.to_vec();
    tokio::spawn(async move {
        loop {
            let Ok((mut sock, _)) = listener.accept().await else {
                break;
            };
            a2.fetch_add(1, Ordering::SeqCst);
            let (a3, t3) = (a2.clone(), t2.clone());
            let first = first.clone();
            tokio::spawn(async move {
                let mut buf = Vec::new();
                let mut chunk = [0u8; 256];
                while buf.len() < first.len() {
                    match sock.read(&mut chunk).await {
                        Ok(0) | Err(_) => return,
                        Ok(n) => buf.extend_from_slice(&chunk[..n]),
                    }
                }
                let _ = sock.write_all(&buf).await;
                // Half close: write-side FIN (egress read task sees EOF), read
                // side stays open
                let _ = sock.shutdown().await;
                loop {
                    match sock.read(&mut chunk).await {
                        Ok(0) | Err(_) => break,
                        Ok(n) => t3.lock().unwrap().extend_from_slice(&chunk[..n]),
                    }
                }
                a3.fetch_sub(1, Ordering::SeqCst);
            });
        }
    });
    (addr, tail, active)
}

/// Silent long-lived backend (T4): after accept, holds the connection
/// silently, only probing for peer closure.
async fn silent_backend() -> (SocketAddr, Arc<AtomicUsize>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let active = Arc::new(AtomicUsize::new(0));
    let a2 = active.clone();
    tokio::spawn(async move {
        loop {
            let Ok((mut sock, _)) = listener.accept().await else {
                break;
            };
            a2.fetch_add(1, Ordering::SeqCst);
            let a3 = a2.clone();
            tokio::spawn(async move {
                let mut buf = [0u8; 256];
                loop {
                    match sock.read(&mut buf).await {
                        Ok(0) | Err(_) => break,
                        Ok(_) => {}
                    }
                }
                a3.fetch_sub(1, Ordering::SeqCst);
            });
        }
    });
    (addr, active)
}

/// Read from the tunnel until `n` bytes are received (skipping non-Data
/// frames; fails on Close).
async fn recv_response_data<R: tokio::io::AsyncRead + Unpin>(rx: &mut R, n: usize, what: &str) {
    let mut got = 0usize;
    let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
    while got < n {
        let mut chunk = vec![0u8; n - got];
        let read = tokio::time::timeout_at(deadline, rx.read(&mut chunk))
            .await
            .unwrap_or_else(|_| panic!("timed out waiting for {what}"))
            .expect("channel alive");
        assert!(read != 0, "{what} closed prematurely");
        got += read;
    }
}

// ---------------------------------------------------------------------------
// T1: backend EOF + the peer never Closes → bounded drain and close out, fd
// released
// ---------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn backend_eof_without_peer_close_releases_fd() {
    let _ = metrics_handle();
    let hub_port = pick_ephemeral_port();
    let hub = spawn_hub(hub_config(hub_port, certs(), vec![])).await;

    let (backend_addr, active) = close_after_echo_backend(b"ping").await;
    // Registration gate: an Open routed to an unregistered target is torn
    // down by the hub with `_close_`, so the egress must be registered
    // before the injector addresses it (startup-race hardening).
    let _agent = spawn_agent_registered(agent_config("eg", hub_port, certs())).await;
    let inj = connect_tunnel(hub_port, "inj-t1").await;

    let closed_before =
        counter_value("interflow_egress_stream_closed_total{reason=\"backend_closed\"}");

    {
        let mut tls = open_inner_tls(
            &inj,
            "inj-t1",
            interflow_testkit::opaque_stream_id("t1"),
            &backend_addr.to_string(),
        )
        .await;
        tls.write_all(b"ping").await.expect("send");
        tls.flush().await.expect("flush");
        tls.flush().await.expect("flush");
        recv_response_data(&mut tls, 4, "T1 echo").await;
        // Keep the source side open: no Close, no connection drop.
        tokio::time::sleep(Duration::from_secs(6)).await;
    }
    // * The peer (injection side) stays silent: no Close, no connection drop —
    // the stream remains "active" on the hub side.
    // Old code: after the read task exited on EOF, the main loop hung on
    // frames.recv() and the backend fd lingered for the whole session.

    // After the drain window (5s) expires the forwarder must close out:
    // backend connection closed + backend_closed attribution
    eventually(
        || active.load(Ordering::SeqCst) == 0,
        RELEASE_DEADLINE,
        "T1 backend connection released (EOF self-healing)",
    )
    .await;
    assert!(
        counter_value("interflow_egress_stream_closed_total{reason=\"backend_closed\"}")
            >= closed_before + 1,
        "backend_closed attribution missing (snapshot:\n{})",
        metrics_handle().render()
    );

    hub.shutdown_graceful().await.expect("hub shutdown");
}

// ---------------------------------------------------------------------------
// T2: half-close draining — request tail data arriving within the window
// after EOF must reach the backend
// ---------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn backend_eof_drain_window_delivers_late_request_tail() {
    let _ = metrics_handle();
    let hub_port = pick_ephemeral_port();
    let hub = spawn_hub(hub_config(hub_port, certs(), vec![])).await;

    let (backend_addr, tail, active) = half_close_backend(b"ping").await;
    // Registration gate: an Open routed to an unregistered target is torn
    // down by the hub with `_close_`, so the egress must be registered
    // before the injector addresses it (startup-race hardening).
    let _agent = spawn_agent_registered(agent_config("eg", hub_port, certs())).await;
    let inj = connect_tunnel(hub_port, "inj-t2").await;

    let mut tls = open_inner_tls(
        &inj,
        "inj-t2",
        interflow_testkit::opaque_stream_id("t2"),
        &backend_addr.to_string(),
    )
    .await;
    tls.write_all(b"ping").await.expect("send");
    tls.flush().await.expect("flush");
    recv_response_data(&mut tls, 4, "T2 echo").await;
    // The backend has half-closed (the egress read task saw EOF). Old code:
    // EOF immediately sent Close back → the hub tore the stream down → the
    // tail data below was rejected with "Stream not found", and no drain
    // semantics existed.
    tokio::time::sleep(Duration::from_secs(1)).await; // within the drain window (5s)
    // The same TLS object owns the half-closed stream; write the late tail
    // through it after the backend FIN.
    tls.write_all(b"late-tail").await.expect(
        "sending tail data within the window (the stream must still be alive on the hub side)",
    );
    tls.flush().await.expect("flush tail data");

    // The tail data reaches the backend through the drain window
    eventually(
        || tail.lock().unwrap().as_slice() == b"late-tail",
        Duration::from_secs(5),
        "T2 tail data delivered to the backend",
    )
    .await;
    // Close out after the window expires: connection closed (read-side EOF
    // triggered by the forwarder drop)
    eventually(
        || active.load(Ordering::SeqCst) == 0,
        RELEASE_DEADLINE,
        "T2 drain finished, connection released",
    )
    .await;

    hub.shutdown_graceful().await.expect("hub shutdown");
}

// ---------------------------------------------------------------------------
// T4: source-agent re-registration (sweep) → all in-flight streams on the
// peer egress receive _close_
// ---------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn source_re_register_sweep_notifies_egress_streams() {
    let _ = metrics_handle();
    let hub_port = pick_ephemeral_port();
    let hub = spawn_hub(hub_config(hub_port, certs(), vec![])).await;

    const K: usize = 3;
    let (backend_addr, active) = silent_backend().await;
    // Registration gate: an Open routed to an unregistered target is torn
    // down by the hub with `_close_`, so the egress must be registered
    // before the injector addresses it (startup-race hardening).
    let _agent = spawn_agent_registered(agent_config("eg", hub_port, certs())).await;
    let inj = connect_tunnel(hub_port, "src-t4").await;

    let mut silent_streams = Vec::new();
    for i in 0..K {
        let sid = interflow_testkit::opaque_stream_id(&format!("t4-s{i}"));
        silent_streams.push(open_inner_tls(&inj, "src-t4", sid, &backend_addr.to_string()).await);
    }
    eventually(
        || active.load(Ordering::SeqCst) == K,
        Duration::from_secs(10),
        "T4 silent streams established",
    )
    .await;

    let closed_before = counter_value("interflow_egress_stream_closed_total");

    // The source agent re-registers (a new session with the same id): the hub
    // clears its orphan streams and notifies the peer egress.
    // Old code: the sweep cleared the table without notifying — the egress
    // forwarder had no frame to wait for, and fds lingered until the egress's
    // own session rebuild (a single edge reconnect could orphan every
    // in-flight stream on a Mac).
    let _inj2 = connect_tunnel(hub_port, "src-t4").await;
    drop(silent_streams);

    eventually(
        || active.load(Ordering::SeqCst) == 0,
        Duration::from_secs(10),
        "T4 egress releases all backend connections after the sweep notice",
    )
    .await;
    assert!(
        counter_value("interflow_egress_stream_closed_total") >= closed_before + K as u64,
        "all K streams must go through the unified close-out"
    );

    hub.shutdown_graceful().await.expect("hub shutdown");
}

// ---------------------------------------------------------------------------
// Regression: a normal source Close (request direction, now via the control
// channel) → the backend connection is still closed as usual
// ---------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn normal_source_close_still_releases_backend() {
    let _ = metrics_handle();
    let hub_port = pick_ephemeral_port();
    let hub = spawn_hub(hub_config(hub_port, certs(), vec![])).await;

    let (backend_addr, active) = silent_backend().await;
    // Registration gate: an Open routed to an unregistered target is torn
    // down by the hub with `_close_`, so the egress must be registered
    // before the injector addresses it (startup-race hardening).
    let _agent = spawn_agent_registered(agent_config("eg", hub_port, certs())).await;
    let inj = connect_tunnel(hub_port, "inj-reg").await;

    let tls = open_inner_tls(
        &inj,
        "inj-reg",
        interflow_testkit::opaque_stream_id("reg"),
        &backend_addr.to_string(),
    )
    .await;
    eventually(
        || active.load(Ordering::SeqCst) == 1,
        Duration::from_secs(10),
        "regression: backend connection established",
    )
    .await;

    drop(tls);
    inj.send_close(interflow_testkit::opaque_stream_id("reg"))
        .await
        .expect("source Close");
    eventually(
        || active.load(Ordering::SeqCst) == 0,
        Duration::from_secs(5),
        "regression: Close (control-channel path) releases the backend connection",
    )
    .await;

    hub.shutdown_graceful().await.expect("hub shutdown");
}
