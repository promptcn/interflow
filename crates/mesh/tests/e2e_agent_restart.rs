//! E2E: restarting an agent immediately after shutdown must not trigger a
//! /poll 409 Conflict.
//!
//! Covers a three-layer fix:
//! 1. The client poll loop is wired to a CancellationToken — after shutdown
//!    the old poll task exits and the connection closes;
//! 2. The server's RxStream Drop returns the rx — once the poll connection
//!    breaks, the same agent's next poll immediately gets 200;
//! 3. The generation mechanism — a stale return from an old connection cannot
//!    overwrite the new channel rebuilt by register;
//! 4. connect_timeout — when the connection hangs (blackhole port), it times
//!    out into Reconnecting instead of staying in Connecting forever.

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
use interflow_mesh::agent::handle::{AgentHandle, AgentState};
use interflow_testkit::{agent_config, hub_config, pick_ephemeral_port, spawn_hub};
use std::time::Duration;

fn certs() -> &'static interflow_testkit::certs::TestCerts {
    static C: std::sync::OnceLock<interflow_testkit::certs::TestCerts> = std::sync::OnceLock::new();
    C.get_or_init(|| interflow_testkit::certs::TestCerts::generate("e2e", "agent"))
}

/// Wait until the agent state reaches Connected or the timeout elapses.
async fn wait_state(handle: &AgentHandle, timeout: Duration) -> AgentState {
    let mut rx = handle.subscribe_state();
    let deadline = tokio::time::Instant::now() + timeout;
    loop {
        let state = rx.borrow_and_update().clone();
        if matches!(state, AgentState::Connected { .. }) {
            return state;
        }
        let change = tokio::time::timeout_at(deadline, rx.changed());
        match change.await {
            Ok(Ok(())) => continue,
            Ok(Err(_)) => panic!("state watch sender dropped"),
            Err(_) => panic!("timed out waiting for Connected, current state: {state:?}"),
        }
    }
}

/// Scenario 1 (GUI bug reproduction): start → graceful shutdown → immediately
/// restart the same agent_id; it should reconnect quickly instead of falling
/// into a 409 retry loop.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn agent_restart_after_graceful_shutdown_reconnects() {
    let hub_port = pick_ephemeral_port();
    let _hub = spawn_hub(hub_config(hub_port, certs(), vec![])).await;
    tokio::time::sleep(Duration::from_millis(300)).await;

    let agent_id = "restart-agent";

    // First start
    let handle1 =
        interflow_mesh::agent::AgentClient::new(agent_config(agent_id, hub_port, certs()))
            .expect("agent build")
            .start();
    wait_state(&handle1, Duration::from_secs(10)).await;

    // Graceful shutdown (the GUI stop path)
    handle1.shutdown_graceful().await.expect("shutdown");

    // Immediately restart (without waiting for any server-side timeout)
    let handle2 =
        interflow_mesh::agent::AgentClient::new(agent_config(agent_id, hub_port, certs()))
            .expect("agent build")
            .start();
    wait_state(&handle2, Duration::from_secs(5)).await;

    // Stay up another 2s to confirm it is stably Connected (before the fix,
    // the old zombie poll fought with the new instance, triggering a 409 loop)
    tokio::time::sleep(Duration::from_secs(2)).await;
    assert!(
        matches!(handle2.state(), AgentState::Connected { .. }),
        "should stay Connected after restart, got: {:?}",
        handle2.state()
    );

    handle2.shutdown_graceful().await.expect("shutdown 2");
}

/// Scenario 2 (server-side return): after the poll connection breaks, the
/// same agent's next /poll should get 200 instead of a 409 waiting for a
/// keepalive timeout. Uses a bare HTTP/2 connection for precise control over
/// the poll lifecycle.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn poll_drop_returns_rx_for_next_poll() {
    use http_body_util::{BodyExt, Empty};
    use hyper::Request;
    use hyper_util::rt::{TokioExecutor, TokioIo};

    let hub_port = pick_ephemeral_port();
    let _hub = spawn_hub(hub_config(hub_port, certs(), vec![])).await;
    tokio::time::sleep(Duration::from_millis(300)).await;

    let (send_request, conn) = hyper::client::conn::http2::Builder::new(TokioExecutor::new())
        .handshake::<_, Empty<bytes::Bytes>>(TokioIo::new(
            interflow_testkit::tls_client_connect(
                certs(),
                "poll-agent",
                format!("127.0.0.1:{hub_port}").parse().unwrap(),
            )
            .await
            .expect("tls"),
        ))
        .await
        .expect("handshake");
    tokio::spawn(async move {
        let _ = conn.await;
    });
    let mut send_request = send_request;

    // register
    let req = Request::builder()
        .method("POST")
        .uri("/register")
        .header("x-agent-id", "poll-agent")
        .body(Empty::new())
        .unwrap();
    let resp = send_request.send_request(req).await.expect("register");
    assert!(resp.status().is_success(), "register: {}", resp.status());

    // First poll: get the streaming body then drop it immediately (simulating
    // a connection break)
    let req = Request::builder()
        .method("GET")
        .uri("/poll")
        .header("x-agent-id", "poll-agent")
        .body(Empty::new())
        .unwrap();
    let resp = send_request.send_request(req).await.expect("poll 1");
    assert_eq!(resp.status(), 200, "poll 1 should succeed");
    drop(resp);

    // Wait for the return task to run (Drop is a spawned async task)
    tokio::time::sleep(Duration::from_millis(200)).await;

    // Second poll: 409 before the fix (rx occupied and tx not closed), 200
    // after
    let req = Request::builder()
        .method("GET")
        .uri("/poll")
        .header("x-agent-id", "poll-agent")
        .body(Empty::new())
        .unwrap();
    let resp = send_request.send_request(req).await.expect("poll 2");
    assert_eq!(
        resp.status(),
        200,
        "polling again immediately after the disconnect should return the rx and succeed, got: {}",
        resp.status()
    );

    // Read one byte to confirm the stream works, then clean up
    let mut body: hyper::body::Incoming = resp.into_body();
    let _ = tokio::time::timeout(Duration::from_millis(100), body.frame()).await;
    drop(body);
    let _ = send_request;
}

/// Scenario 3 (generation guard): while poll A is hanging, the same id
/// re-registers (channel rebuilt); when A disconnects, its stale rx must not
/// overwrite the new channel; the new connection's poll should get 200.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn stale_rx_return_after_reregister_is_discarded() {
    use http_body_util::Empty;
    use hyper::Request;
    use hyper_util::rt::{TokioExecutor, TokioIo};

    let hub_port = pick_ephemeral_port();
    let _hub = spawn_hub(hub_config(hub_port, certs(), vec![])).await;
    tokio::time::sleep(Duration::from_millis(300)).await;

    async fn connect(
        hub_port: u16,
    ) -> hyper::client::conn::http2::SendRequest<Empty<bytes::Bytes>> {
        let (send_request, conn) = hyper::client::conn::http2::Builder::new(TokioExecutor::new())
            .handshake::<_, Empty<bytes::Bytes>>(TokioIo::new(
                interflow_testkit::tls_client_connect(
                    certs(),
                    "gen-agent",
                    format!("127.0.0.1:{hub_port}").parse().unwrap(),
                )
                .await
                .expect("tls"),
            ))
            .await
            .expect("handshake");
        tokio::spawn(async move {
            let _ = conn.await;
        });
        send_request
    }

    // Connection A: register + poll (kept hanging)
    let mut conn_a = connect(hub_port).await;
    let req = Request::builder()
        .method("POST")
        .uri("/register")
        .header("x-agent-id", "gen-agent")
        .body(Empty::new())
        .unwrap();
    let resp = conn_a.send_request(req).await.expect("register A");
    assert!(resp.status().is_success());
    let req = Request::builder()
        .method("GET")
        .uri("/poll")
        .header("x-agent-id", "gen-agent")
        .body(Empty::new())
        .unwrap();
    let poll_a = conn_a.send_request(req).await.expect("poll A");
    assert_eq!(poll_a.status(), 200);

    // Connection B: register with the same id (channel rebuilt in place,
    // generation+1)
    let mut conn_b = connect(hub_port).await;
    let req = Request::builder()
        .method("POST")
        .uri("/register")
        .header("x-agent-id", "gen-agent")
        .body(Empty::new())
        .unwrap();
    let resp = conn_b.send_request(req).await.expect("register B");
    assert!(resp.status().is_success());

    // Disconnect A (triggers the stale return, which the generation mechanism
    // should discard)
    drop(poll_a);
    tokio::time::sleep(Duration::from_millis(200)).await;

    // Connection C: its poll should get the channel rebuilt by B (200), not
    // A's stale receiver
    let mut conn_c = connect(hub_port).await;
    let req = Request::builder()
        .method("GET")
        .uri("/poll")
        .header("x-agent-id", "gen-agent")
        .body(Empty::new())
        .unwrap();
    let resp = conn_c.send_request(req).await.expect("poll C");
    assert_eq!(
        resp.status(),
        200,
        "poll after the channel rebuild should succeed"
    );
}

/// Wait until the agent state satisfies `pred` or the timeout elapses
/// (returns whether it was satisfied).
async fn wait_state_match(
    handle: &AgentHandle,
    timeout: Duration,
    pred: impl Fn(&AgentState) -> bool,
) -> bool {
    let mut rx = handle.subscribe_state();
    let deadline = tokio::time::Instant::now() + timeout;
    loop {
        let state = rx.borrow_and_update().clone();
        if pred(&state) {
            return true;
        }
        let change = tokio::time::timeout_at(deadline, rx.changed()).await;
        match change {
            Ok(Ok(())) => continue,
            Ok(Err(_)) => return false,
            Err(_) => return false,
        }
    }
}

/// Start a black-hole listener that accepts but never sends a byte; returns
/// the port.
/// Simulates a broken network stack after sleep/wake: TCP connects but the
/// subsequent handshake hangs forever.
async fn spawn_black_hole() -> u16 {
    use tokio::net::TcpListener;
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind black hole");
    let port = listener.local_addr().expect("addr").port();
    tokio::spawn(async move {
        // Only accept, holding the connections without reading or writing —
        // after the client sends its HTTP/2 preface, no response ever comes
        while let Ok((_sock, _)) = listener.accept().await {}
    });
    port
}

/// Scenario 4 (connect timeout, GUI sleep/wake bug reproduction): with the
/// hub address pointing at a black-hole port, connect_and_register times out
/// into Reconnecting within connect_timeout_secs instead of staying in
/// Connecting forever (before the fix the supervisor wedged and the GUI showed
/// a fake "started" state).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn connect_timeout_recovers_from_black_hole() {
    let black_port = spawn_black_hole().await;

    let mut cfg = agent_config("blackhole-agent", black_port, certs());
    cfg.agent.connect_timeout_secs = 2;

    let handle = interflow_mesh::agent::AgentClient::new(cfg)
        .expect("agent build")
        .start();

    // The black-hole connection should enter Reconnecting after the timeout
    // (not Connecting forever)
    let reached = wait_state_match(&handle, Duration::from_secs(10), |s| {
        matches!(s, AgentState::Reconnecting { .. })
    })
    .await;
    assert!(
        reached,
        "the black-hole connection should enter Reconnecting after the timeout, got: {:?}",
        handle.state()
    );

    handle.shutdown_graceful().await.expect("shutdown");

    // Restore the link: point at a real hub; the same agent should be
    // Connected normally (timeout → retry → recovery)
    let hub_port = pick_ephemeral_port();
    let _hub = spawn_hub(hub_config(hub_port, certs(), vec![])).await;
    tokio::time::sleep(Duration::from_millis(300)).await;

    let handle2 =
        interflow_mesh::agent::AgentClient::new(agent_config("blackhole-agent", hub_port, certs()))
            .expect("agent build 2")
            .start();
    wait_state(&handle2, Duration::from_secs(10)).await;
    handle2.shutdown_graceful().await.expect("shutdown 2");
}
