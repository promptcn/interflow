//! E2E: the peer-observability face (2026-10-08 backlog
//! `mesh-peer-observability-gui`) — the first agent-side answer to "is the
//! far end up", previously answerable only by hub-journal forensics.
//!
//! Covered:
//! - The engine's intrinsic peer watcher: an all-QUIC fleet (the promptcn
//!   shape — no h2 PING ever fires) sees each peer online, transitions to
//!   offline within one watch cycle of the peer dying, and back on
//!   restart. No false-dead (the anti-flicker grace) and no false-alive
//!   (the 2026-10-07 stale-green-card mirror image).
//! - The wire contract: `GET /agents` carries the `online` field (the h2
//!   operator face and the QUIC PeerList frame face share the listing
//!   body by construction).
//! - The agent control port's `/agents` proxy rides the session tunnel for
//!   both transports (the former h2-only pass-through answered 501 on
//!   QUIC).

#![allow(
    clippy::all,
    clippy::pedantic,
    clippy::nursery,
    clippy::panic,
    clippy::unwrap_used,
    clippy::expect_used,
    missing_docs
)]
use interflow_core::tunnel::H2RequestBody;
use interflow_mesh::config::ControlConfig;
use interflow_testkit::certs::TestCerts;
use interflow_testkit::{
    agent_config, agent_quic_config, hub_quic_config, list_agents, spawn_agent_registered,
    spawn_hub, tls_client_connect,
};
use std::time::Duration;

fn certs() -> &'static TestCerts {
    static C: std::sync::OnceLock<TestCerts> = std::sync::OnceLock::new();
    C.get_or_init(|| TestCerts::generate("peers", "lan-a"))
}

/// Whether `watcher`'s latest snapshot lists `peer_short` (the qualified
/// id's agent part) with the given online reading — absent peers read as
/// `false` for either argument.
fn sees_peer(handle: &interflow_mesh::agent::AgentHandle, peer_short: &str, online: bool) -> bool {
    let snap = handle.peer_state().snapshot();
    snap.peers
        .iter()
        .any(|p| p.agent.rsplit('/').next() == Some(peer_short) && p.online == online)
}

/// Polls until `cond` or the deadline; panics with `what` on timeout.
async fn eventually<F: Fn() -> bool>(what: &str, budget: Duration, cond: F) {
    let deadline = tokio::time::Instant::now() + budget;
    loop {
        if cond() {
            return;
        }
        if tokio::time::Instant::now() >= deadline {
            panic!("timed out waiting for: {what}");
        }
        tokio::time::sleep(Duration::from_millis(250)).await;
    }
}

/// The full acceptance cycle on an all-QUIC fleet: both peers visible and
/// online; one dies → the survivor's reading flips within one watch cycle
/// (the QUIC connection-lost watcher removes the registration, and the
/// peer watcher samples at the 10s cadence); restart → back online.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn quic_fleet_peer_presence_full_cycle() {
    let _ = tracing_subscriber::fmt()
        .with_env_filter("info,interflow=debug")
        .try_init();
    let hub = spawn_hub(hub_quic_config(0, certs(), Vec::new())).await;
    let port = hub.local_addr().expect("hub bound").port();

    let a = spawn_agent_registered(agent_quic_config("lan-a", port, certs())).await;
    let b = spawn_agent_registered(agent_quic_config("lan-b", port, certs())).await;

    // Both directions see each other online. The peer watcher fetches on
    // session establishment and every 10s; a registered before b, so a's
    // first fetch predates b — one interval is the budget.
    let budget = Duration::from_secs(25);
    eventually("lan-a sees lan-b online", budget, || {
        sees_peer(&a, "lan-b", true)
    })
    .await;
    eventually("lan-b sees lan-a online", budget, || {
        sees_peer(&b, "lan-a", true)
    })
    .await;

    // b dies (a deliberate shutdown — the QUIC connection closes, the hub's
    // connection-lost watcher removes the registration). The survivor's
    // next sample must not show the dead peer as online: ≤1 watch cycle
    // (10s) plus sampling slack, no false-alive.
    b.shutdown_graceful().await.expect("b shuts down");
    eventually(
        "lan-a no longer sees lan-b online",
        Duration::from_secs(20),
        || !sees_peer(&a, "lan-b", true),
    )
    .await;

    // Restart → back online (no false-dead either).
    let b2 = spawn_agent_registered(agent_quic_config("lan-b", port, certs())).await;
    eventually("lan-a sees the restarted lan-b online", budget, || {
        sees_peer(&a, "lan-b", true)
    })
    .await;
    let _ = b2.shutdown_graceful().await;
    let _ = a.shutdown_graceful().await;
}

/// The h2 tunnel path of the peer read (`list_agents_h2` rides the session
/// connection like the policy pull): an all-h2 fleet sees each other too.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn h2_fleet_peer_presence() {
    let _ = tracing_subscriber::fmt()
        .with_env_filter("info,interflow=debug")
        .try_init();
    let hub = spawn_hub(interflow_testkit::hub_config(0, certs(), Vec::new())).await;
    let port = hub.local_addr().expect("hub bound").port();

    let a = spawn_agent_registered(agent_config("lan-a", port, certs())).await;
    let b = spawn_agent_registered(agent_config("lan-b", port, certs())).await;

    eventually(
        "h2 lan-a sees lan-b online",
        Duration::from_secs(25),
        || sees_peer(&a, "lan-b", true),
    )
    .await;
    eventually(
        "h2 lan-b sees lan-a online",
        Duration::from_secs(25),
        || sees_peer(&b, "lan-a", true),
    )
    .await;

    let _ = a.shutdown_graceful().await;
    let _ = b.shutdown_graceful().await;
}

/// The `online` field on the h2 operator face: real agents (poll bodies in
/// place / QUIC relays in place) read `online: true`; the field is part of
/// the pinned wire contract via the testkit mirror.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn agents_listing_carries_online_presence() {
    let _ = tracing_subscriber::fmt()
        .with_env_filter("info,interflow=debug")
        .try_init();
    let hub = spawn_hub(hub_quic_config(0, certs(), Vec::new())).await;
    let port = hub.local_addr().expect("hub bound").port();

    let a = spawn_agent_registered(agent_config("lan-a", port, certs())).await;
    let b = spawn_agent_registered(agent_quic_config("lan-b", port, certs())).await;

    // An mTLS h2 client under the same tenant reads the operator face.
    let (snd, conn) =
        hyper::client::conn::http2::Builder::new(hyper_util::rt::TokioExecutor::new())
            .handshake::<_, H2RequestBody>(hyper_util::rt::TokioIo::new(
                tls_client_connect(
                    certs(),
                    "lan-a",
                    format!("127.0.0.1:{port}").parse().unwrap(),
                )
                .await
                .expect("tls"),
            ))
            .await
            .expect("handshake");
    let mut snd = snd;
    tokio::spawn(async move {
        let _ = conn.await;
    });

    let list = list_agents(&mut snd).await;
    let online: Vec<bool> = list.iter().map(|e| e.online).collect();
    assert!(
        list.len() >= 2,
        "both registered agents should be listed: {list:?}"
    );
    assert!(
        online.iter().all(|&o| o),
        "an h2 poll body in place and a QUIC relay in place must both read online: {list:?}"
    );

    let _ = a.shutdown_graceful().await;
    let _ = b.shutdown_graceful().await;
}

/// The agent control port's `/agents` proxy rides the session tunnel —
/// identical shape for a QUIC agent (the former h2-sender pass-through
/// answered 501 for QUIC agents; the unified trait path serves both).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn control_port_agents_proxy_works_over_quic_session() {
    let _ = tracing_subscriber::fmt()
        .with_env_filter("info,interflow=debug")
        .try_init();
    let hub = spawn_hub(hub_quic_config(0, certs(), Vec::new())).await;
    let port = hub.local_addr().expect("hub bound").port();

    // An explicit ephemeral control port (the config default is a fixed
    // loopback port — parallel tests would collide on it).
    let control_port = std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port();
    let mut cfg = agent_quic_config("lan-a", port, certs());
    cfg.control = ControlConfig {
        enabled: true,
        listen_addr: format!("127.0.0.1:{control_port}").parse().unwrap(),
        auth_token: None,
        allow_remote: false,
    };
    let a = spawn_agent_registered(cfg).await;
    let _b = spawn_agent_registered(agent_quic_config("lan-b", port, certs())).await;

    // Poll the control port until the listing includes the peer — the
    // response body is the same JSON shape the hub face serves.
    #[derive(serde::Deserialize)]
    struct Entry {
        agent: String,
        online: bool,
    }
    let deadline = tokio::time::Instant::now() + Duration::from_secs(25);
    loop {
        let listed = async {
            let stream = tokio::net::TcpStream::connect(("127.0.0.1", control_port))
                .await
                .map_err(|e| format!("{e}"))?;
            let (mut sender, conn) = hyper::client::conn::http1::Builder::new()
                .handshake::<_, http_body_util::Empty<bytes::Bytes>>(hyper_util::rt::TokioIo::new(
                    stream,
                ))
                .await
                .map_err(|e| format!("{e}"))?;
            tokio::spawn(async move {
                let _ = conn.await;
            });
            let req = hyper::Request::builder()
                .uri("/agents")
                .header("host", format!("127.0.0.1:{control_port}"))
                .body(http_body_util::Empty::<bytes::Bytes>::new())
                .map_err(|e| format!("{e}"))?;
            let resp = sender.send_request(req).await.map_err(|e| format!("{e}"))?;
            assert!(resp.status().is_success(), "control port /agents: {resp:?}");
            let body = http_body_util::BodyExt::collect(resp.into_body())
                .await
                .map_err(|e| format!("{e}"))?
                .to_bytes();
            let entries: Vec<Entry> =
                serde_json::from_slice(&body).map_err(|e| format!("not the peer shape: {e}"))?;
            Ok::<_, String>(
                entries
                    .iter()
                    .any(|e| e.agent.ends_with("/lan-b") && e.online),
            )
        }
        .await;
        match listed {
            Ok(true) => break,
            Ok(false) => {}
            Err(_) => {} // control port not accepting yet — retry
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "control port /agents never listed lan-b online via the QUIC session"
        );
        tokio::time::sleep(Duration::from_millis(250)).await;
    }
    let _ = a.shutdown_graceful().await;
}
