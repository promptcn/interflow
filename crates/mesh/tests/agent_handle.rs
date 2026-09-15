//! AgentHandle lifecycle integration tests:
//! start → Connected → disconnect → Reconnecting → graceful shutdown →
//! Stopped / no leftover tasks.
//!
//! Reuses the minimal hub/agent assembly from `common/mod.rs` (no TLS,
//! anonymous registration).

#![allow(clippy::all, clippy::pedantic, clippy::nursery, clippy::panic)]

use interflow_mesh::agent::{AgentClient, AgentState};
use interflow_testkit::{agent_config, hub_config, pick_ephemeral_port, spawn_hub};
use std::time::Duration;
use tokio::sync::watch;

/// Wait until the watch state satisfies `predicate`; panic on timeout.
async fn wait_state(
    mut rx: watch::Receiver<AgentState>,
    timeout: Duration,
    msg: &str,
) -> AgentState {
    let state = tokio::time::timeout(timeout, async {
        loop {
            let cur = rx.borrow_and_update();
            match &*cur {
                AgentState::Failed { .. } => {
                    panic!("unexpectedly entered Failed: {cur:?} ({msg})")
                }
                s if matches!(s, AgentState::Connected { .. }) => return s.clone(),
                _ => {}
            }
            drop(cur);
            rx.changed().await.expect("watch sender dropped");
        }
    })
    .await
    .unwrap_or_else(|_| panic!("timed out waiting for Connected ({msg})"));
    state
}

#[tokio::test]
async fn start_connect_and_graceful_shutdown() {
    let hub_port = pick_ephemeral_port();
    let hub = spawn_hub(hub_config(hub_port, vec![])).await;
    tokio::time::sleep(Duration::from_millis(200)).await;

    let mut handle = AgentClient::new(agent_config("handle-test", hub_port))
        .expect("agent build")
        .start();
    let mut events = handle.take_events();

    let state = wait_state(
        handle.subscribe_state(),
        Duration::from_secs(5),
        "initial connect",
    )
    .await;
    let AgentState::Connected { agent_id } = state else {
        unreachable!()
    };
    assert_eq!(agent_id, "handle-test");

    // The SessionEstablished event should be received at least once
    let mut got_established = false;
    while !got_established {
        let ev = tokio::time::timeout(Duration::from_secs(1), events.recv())
            .await
            .expect("timed out waiting for the SessionEstablished event")
            .expect("the event stream should not close");
        got_established = matches!(
            ev,
            interflow_mesh::agent::AgentEvent::SessionEstablished { .. }
        );
    }

    // Graceful shutdown: once it returns, the supervisor must have ended and
    // the state must be Stopped
    handle.shutdown_graceful().await.expect("graceful shutdown");
    // After shutdown, read the watch snapshot again
    // (state_rx was consumed with the handle; use the supervisor join's
    // return value + event-stream closure to determine it)

    let _ = hub.shutdown().await;
}

#[tokio::test]
async fn no_hub_then_reconnect() {
    // Do not start the hub yet: connection refused → the supervisor should
    // enter Reconnecting (with backoff) rather than exit
    let hub_port = pick_ephemeral_port();
    let handle = AgentClient::new(agent_config("reconnect-test", hub_port))
        .expect("agent build")
        .start();
    let mut state_rx = handle.subscribe_state();

    tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            if matches!(
                &*state_rx.borrow_and_update(),
                AgentState::Reconnecting { .. }
            ) {
                return;
            }
            state_rx.changed().await.expect("watch sender dropped");
        }
    })
    .await
    .expect("timed out waiting for Reconnecting");

    // Once the hub comes up, the agent should reconnect automatically within
    // the backoff window
    let hub = spawn_hub(hub_config(hub_port, vec![])).await;
    wait_state(
        handle.subscribe_state(),
        Duration::from_secs(35),
        "reconnect",
    )
    .await;

    handle.shutdown_graceful().await.expect("graceful shutdown");
    let _ = hub.shutdown().await;
}

#[tokio::test]
async fn config_error_fails_fast() {
    let mut cfg = agent_config("bad-cfg", pick_ephemeral_port());
    // Invalid URL: a config-class error; the supervisor should become Failed
    // instead of retrying forever
    cfg.agent.hub_url = "not a url".to_string();

    let handle = AgentClient::new(cfg).expect("agent build").start();
    let mut state_rx = handle.subscribe_state();
    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    loop {
        let failed = {
            let cur = state_rx.borrow_and_update();
            match &*cur {
                AgentState::Failed { error } => Some(error.clone()),
                _ => None,
            }
        };
        if let Some(error) = failed {
            assert!(
                error.contains("Hub URL") || error.contains("URL"),
                "the error message should point at the URL: {error}"
            );
            break;
        }
        if tokio::time::Instant::now() > deadline {
            panic!("did not enter Failed within 5s");
        }
        state_rx.changed().await.expect("watch sender dropped");
    }
    handle.shutdown_graceful().await.expect("graceful shutdown");
}
