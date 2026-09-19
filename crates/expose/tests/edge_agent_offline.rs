//! e2e: route hit but the agent is offline (never registered) — the edge must
//! close out the client connection quickly, and the connection task must
//! **not panic**.
//!
//! Regression background (docs/bug/2026-09-13-select-branch-double-await-joinhandle-panic.md):
//! when the agent is offline the hub answers Open with a CLOSE frame, and the
//! edge write half exiting triggers the select write branch; the old
//! implementation awaited a JoinHandle a second time inside the branch body
//! even though select had already polled it to completion, triggering the
//! "JoinHandle polled after completion" panic — `unregister_stream` was
//! skipped (orphaned stream) and the client got an Empty reply.
//!
//! That panic was swallowed by tokio into a JoinError: the process stayed up
//! and ordinary assertions could not see it — exactly why the bug slipped
//! through for two weeks. So this test installs a **recording panic hook**
//! and asserts on the payload directly.
//!
//! Note: the hub's "target not registered" rejection is carried as a CLOSE
//! frame on `/poll` (144a9b2 removed per-frame HTTP status), and the edge's
//! correct behavior is to close the client connection quickly (the upstream
//! nginx then surfaces 502), not to return a literal 503.

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
use interflow_expose::edge::{EdgeArgs, EdgeHubTls, run};
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

/// Grabs an ephemeral port (bound then released immediately; there is a tiny
/// race between tests but this is usually good enough).
fn pick_port() -> u16 {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind ephemeral");
    listener.local_addr().expect("addr").port()
}

/// Repeatedly TCP-connects to `addr` until success or timeout.
async fn wait_for_tcp(addr: SocketAddr, timeout: Duration) -> std::io::Result<()> {
    let deadline = tokio::time::Instant::now() + timeout;
    loop {
        match TcpStream::connect(addr).await {
            Ok(_) => return Ok(()),
            Err(e) => {
                if tokio::time::Instant::now() >= deadline {
                    return Err(e);
                }
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
        }
    }
}

/// Route hit but the target agent never registered: the connection must close
/// out quickly, with no "JoinHandle polled after completion" panic anywhere
/// along the way.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn agent_offline_closes_fast_without_panic() {
    // 1. Grab ports + a temp routes.toml (route points at a never-registered agent)
    let edge_port = pick_port();
    let hub_port = pick_port();
    let edge_listen: SocketAddr = format!("127.0.0.1:{edge_port}").parse().unwrap();
    let hub_listen: SocketAddr = format!("127.0.0.1:{hub_port}").parse().unwrap();

    let routes_path = std::env::temp_dir().join(format!(
        "interflow_test_routes_offline_{}.toml",
        uuid::Uuid::new_v4()
    ));
    std::fs::write(
        &routes_path,
        r#"
[[routes]]
host = "test.local"
tenant = "test"
agent_id = "ghost-agent"
remote_addr = "127.0.0.1:9"
"#,
    )
    .expect("write routes.toml");

    // 2. Start only the edge (hub server + edge agent + listener); do not start the expose client
    let certs = interflow_testkit::certs::TestCerts::generate("e2e", "expose-test");
    let edge_args = EdgeArgs {
        listen_addr: edge_listen,
        hub_listen_addr: hub_listen,
        routes_path: routes_path.to_string_lossy().into_owned(),
        tenant_cas: vec![("test".to_string(), certs.ca_path().display().to_string())],
        proxy_protocol: Default::default(),
        hub_tls: Some(EdgeHubTls {
            cert_path: certs.server_cert_path().display().to_string(),
            key_path: certs.server_key_path().display().to_string(),
        }),
        agent_recovery_timeout_secs: 120,
        ..Default::default()
    };
    let edge_handle = tokio::task::spawn(run(edge_args));

    wait_for_tcp(hub_listen, Duration::from_secs(5))
        .await
        .expect("hub should start within 5s");
    wait_for_tcp(edge_listen, Duration::from_secs(5))
        .await
        .expect("edge listener should start within 5s");

    // 3. Recording panic hook: capture the payload and forward to the previous hook (keep stderr output)
    let captured: Arc<Mutex<Vec<String>>> = Arc::new(Mutex::new(Vec::new()));
    let cap = captured.clone();
    let prev_hook = Arc::new(std::panic::take_hook());
    let prev_for_hook = prev_hook.clone();
    std::panic::set_hook(Box::new(move |info| {
        let payload = if let Some(p) = info.payload().downcast_ref::<&str>() {
            (*p).to_string()
        } else if let Some(p) = info.payload().downcast_ref::<String>() {
            p.clone()
        } else {
            "<non-string payload>".to_string()
        };
        cap.lock().unwrap().push(payload);
        prev_for_hook(info);
    }));

    // 4. Send request: Open → hub rejects (target not registered) → CLOSE frame → write half exits → close out
    let mut sock = TcpStream::connect(edge_listen)
        .await
        .expect("connect edge listener");
    sock.write_all(b"GET / HTTP/1.1\r\nHost: test.local\r\nConnection: close\r\n\r\n")
        .await
        .expect("write request");

    // 5. Assert: the connection closes out within bounds (the CLOSE-frame path is milliseconds; compare with the hundreds-of-seconds idle timeout)
    let read_result = tokio::time::timeout(Duration::from_secs(10), sock.read_u8()).await;

    // 6. Wait for the hook to settle (any panic would fire before the socket drop), then wrap up
    tokio::time::sleep(Duration::from_millis(300)).await;
    edge_handle.abort();
    let _ = std::fs::remove_file(&routes_path);

    match read_result {
        // Server-side close → EOF / connection reset both count as a fast close-out
        Ok(Err(e))
            if matches!(
                e.kind(),
                std::io::ErrorKind::UnexpectedEof | std::io::ErrorKind::ConnectionReset
            ) => {}
        Ok(Err(e)) => panic!("expected EOF/reset, got IO error: {e}"),
        Ok(Ok(byte)) => panic!("edge should not write any bytes to the client (got {byte:#x})"),
        Err(_) => panic!(
            "connection did not close out within 10s — the CLOSE-frame fast-close path is broken"
        ),
    }

    // 7. Core assertion: no JoinHandle double-poll panic in the connection task
    let panics = captured.lock().unwrap().clone();
    let offenders: Vec<_> = panics
        .iter()
        .filter(|p| p.contains("JoinHandle polled after completion"))
        .collect();
    assert!(
        offenders.is_empty(),
        "captured JoinHandle double-poll panic(s): {offenders:?} (all panics: {panics:?})"
    );
}
