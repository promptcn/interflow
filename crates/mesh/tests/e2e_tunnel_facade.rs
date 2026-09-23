//! E2E: the session-slot tunnel facade (regression tests for the 2026-09-16
//! edge self-dial incident).
//!
//! Architecture under test: `AgentHandle::tunnel()` hands embedders an
//! [`AgentTunnel`] backed by a hot-swappable session slot — the supervisor
//! installs each freshly established session's transport into the slot on
//! registration and withdraws it first thing in the session wind-down. A
//! consumer holding that facade across a hub connection death must observe:
//!
//! 1. a working stream round trip before the failure;
//! 2. bounded **fast-fail** sends during the reconnect gap (never a hang,
//!    never a black hole — the gap is served as an immediate error the
//!    consumer's own failure handling can act on);
//! 3. a working stream round trip on the *same* facade after recovery,
//!    without the consumer re-acquiring anything.
//!
//! Must fail before the fix: with the pre-fix shape (a one-shot dial handing
//! the consumer the frozen per-connection tunnel) step 3 never succeeds —
//! the facade stays bound to the dead session forever, which is exactly how
//! the edge process zombied on 2026-09-16.

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
use interflow_core::error::InterflowError;
use interflow_core::protocol::StreamProto;
use interflow_core::tls::{InnerTlsMaterial, inner_client_config};
use interflow_core::tunnel::AgentTunnel;
use interflow_core::tunnel::e2e::{E2eHandshakeOutcome, E2eTunnelIo, inner_tls_connect};
use interflow_core::tunnel::{InnerStreamHello, TargetSelector};
use interflow_mesh::config::EgressRule;
use interflow_testkit::{
    agent_config, echo_server, hub_config, pick_ephemeral_port, spawn_agent_registered, spawn_hub,
    wait_agent_connected,
};
use std::net::SocketAddr;
use std::time::{Duration, Instant};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

fn certs() -> &'static interflow_testkit::certs::TestCerts {
    static C: std::sync::OnceLock<interflow_testkit::certs::TestCerts> = std::sync::OnceLock::new();
    C.get_or_init(|| interflow_testkit::certs::TestCerts::generate("e2e", "agent"))
}

/// One request-direction stream through the facade, edge-listener shape:
/// mandatory inner TLS + encrypted selector, payload, then echoed bytes.
async fn facade_round_trip(
    tunnel: &AgentTunnel,
    target_agent: &str,
    target_addr: SocketAddr,
    payload: &[u8],
) -> interflow_core::error::Result<Vec<u8>> {
    let sid = interflow_core::protocol::StreamId::random().unwrap();
    let data_rx = tunnel.register_stream(sid).await;
    tunnel
        .send_open_with(sid, target_agent, StreamProto::Tcp, true)
        .await?;

    let (cert, key) = certs().named_client_cert("front");
    let ca = certs().ca_path().display().to_string();
    let material = InnerTlsMaterial::from_paths(
        &[ca.as_str()],
        &cert.display().to_string(),
        &key.display().to_string(),
    )
    .map_err(|e| InterflowError::connection(format!("inner material")).with_source(e))?;
    let connector = tokio_rustls::TlsConnector::from(std::sync::Arc::new(
        inner_client_config(&material, target_agent)
            .map_err(|e| InterflowError::connection(format!("inner connector")).with_source(e))?,
    ));
    let adapter = E2eTunnelIo::ingress(data_rx, tunnel.clone(), sid);
    let mut tls = match inner_tls_connect(adapter, connector, Duration::from_secs(5)).await {
        E2eHandshakeOutcome::Established(tls, _) => tls,
        E2eHandshakeOutcome::Failed { error } => {
            tunnel.unregister_stream(sid).await;
            return Err(InterflowError::connection(format!(
                "inner TLS handshake failed: {error}"
            )));
        }
    };
    InnerStreamHello {
        source_principal: "front".to_owned(),
        source_fingerprint: material.leaf_fingerprint(),
        selector: TargetSelector::Address(target_addr.to_string()),
        correlation_id: *uuid::Uuid::new_v4().as_bytes(),
    }
    .write(&mut tls)
    .await?;
    tls.write_all(payload).await?;
    tls.flush().await?;

    let mut got = Vec::with_capacity(payload.len());
    let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
    while got.len() < payload.len() {
        let mut chunk = vec![0u8; payload.len() - got.len()];
        let n = match tokio::time::timeout_at(deadline, tls.read(&mut chunk)).await {
            Ok(Ok(0)) => {
                tunnel.unregister_stream(sid).await;
                return Err(InterflowError::connection(
                    "stream closed by the peer before the echo completed",
                ));
            }
            Ok(Ok(n)) => n,
            Ok(Err(e)) => {
                tunnel.unregister_stream(sid).await;
                return Err(
                    InterflowError::connection(format!("inner stream read failed")).with_source(e),
                );
            }
            Err(_) => {
                tunnel.unregister_stream(sid).await;
                return Err(InterflowError::connection("echo timed out"));
            }
        };
        got.extend_from_slice(&chunk[..n]);
    }
    let _ = tunnel.send_close(sid).await;
    tunnel.unregister_stream(sid).await;
    Ok(got)
}

/// The facade survives a hub connection death: healthy → gap (bounded
/// fast-fail) → recovered, all through one and the same tunnel handle.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn facade_rides_across_session_rebuild() {
    // 1. Backend echo server + hub (front → egress allowed)
    let (echo_addr, _echo_handle) = echo_server().await;
    let hub_port = pick_ephemeral_port();
    let acls = Vec::new();
    let hub = spawn_hub(hub_config(hub_port, certs(), acls.clone())).await;

    // 2. Egress agent serving the echo backend (waited to Connected: the
    //    first round trip must not race its registration)
    let mut egress_cfg = agent_config("egress", hub_port, certs());
    egress_cfg.egress = vec![EgressRule {
        name: "echo".to_string(),
        target_addr: echo_addr,
        target_protocol: StreamProto::Tcp,
        udp_idle_timeout_secs: None,
    }];
    let egress = spawn_agent_registered(egress_cfg).await;

    // 3. Supervised front agent — the embedder shape (what edge does):
    //    start() + the facade from the handle.
    let front = spawn_agent_registered(agent_config("front", hub_port, certs())).await;
    let tunnel = front.tunnel();

    // 4. Healthy round trip through the facade
    let payload = b"facade-before-failure\n".repeat(4);
    let got = facade_round_trip(&tunnel, "egress", echo_addr, &payload)
        .await
        .expect("round trip before the failure");
    assert_eq!(got, payload);

    // 5. Kill the hub: connection-level death (drain: GOAWAY, then forced
    //    close) — the incident's failure form.
    hub.shutdown_graceful().await.expect("hub shutdown");
    // Give the session wind-down a moment to run (it is bounded by design:
    // withdraw → 1s tunnel contract → 5s drain grace); 2s covers the
    // withdraw with margin in the common case.
    tokio::time::sleep(Duration::from_secs(2)).await;

    // 6. Reconnect gap: sends through the facade fail fast — bounded,
    //    actionable errors, never a hang.
    let probe_start = Instant::now();
    let probe = tokio::time::timeout(
        Duration::from_secs(3),
        tunnel.send_open_with(
            interflow_testkit::opaque_stream_id("gap-probe"),
            "egress",
            StreamProto::Tcp,
            true,
        ),
    )
    .await;
    match probe {
        Ok(Err(_)) => {} // fast fail: slot withdrawn / dead session sealed
        Ok(Ok(())) => panic!("send_open must not succeed while the hub is down"),
        Err(_) => panic!("send_open hung during the reconnect gap (black hole)"),
    }
    assert!(
        probe_start.elapsed() < Duration::from_secs(3),
        "gap sends must be fast-fail, took {:?}",
        probe_start.elapsed()
    );

    // 7. Hub back on the same port; BOTH supervisors re-register on their
    //    own — waiting only for the front is not enough: the egress agent
    //    reconnects on its own backoff, and an Open routed to a
    //    not-yet-registered target is (correctly) rejected with a CLOSE
    //    ("Target agent not registered") — the CI flake this wait removes.
    let _hub2 = spawn_hub(hub_config(hub_port, certs(), acls)).await;
    assert!(
        wait_agent_connected(&front, Duration::from_secs(30)).await,
        "front agent should re-register after the hub returns (state: {:?})",
        front.state()
    );
    assert!(
        wait_agent_connected(&egress, Duration::from_secs(30)).await,
        "egress agent should re-register after the hub returns (state: {:?})",
        egress.state()
    );

    // 8. The SAME facade round-trips again — the essence of the fix
    let payload2 = b"facade-after-recovery\n".repeat(4);
    let got2 = facade_round_trip(&tunnel, "egress", echo_addr, &payload2)
        .await
        .expect("round trip after recovery through the same facade");
    assert_eq!(got2, payload2);

    front.shutdown_graceful().await.expect("front shutdown");
    egress.shutdown_graceful().await.expect("egress shutdown");
}

/// During the gap the facade's register path is also bounded (a sealed
/// channel, not a hang) — the consumer sees closure, not silence.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn empty_slot_register_returns_sealed_channel() {
    // A started-but-never-connected agent: the slot stays empty.
    let closed_port = pick_ephemeral_port();
    let mut cfg = agent_config("never-connected", closed_port, certs());
    cfg.agent.connect_timeout_secs = 1;
    let agent = interflow_mesh::agent::AgentClient::new(cfg)
        .unwrap()
        .start();
    let tunnel = agent.tunnel();

    // Give the first (failing) connect attempt a moment; either way the slot
    // is empty until a session registers.
    let mut data_rx = tunnel
        .register_stream(interflow_testkit::opaque_stream_id("sealed-probe"))
        .await;
    let frame = tokio::time::timeout(Duration::from_secs(1), data_rx.recv()).await;
    match frame {
        // Sealed channel: immediate closure (None), or an error out of the
        // slot's fast-fail path — anything but a hang.
        Ok(None) | Ok(Some(_)) => {}
        Err(_) => panic!("register_stream on an empty slot must not hang"),
    }

    agent.shutdown_graceful().await.expect("agent shutdown");
}
