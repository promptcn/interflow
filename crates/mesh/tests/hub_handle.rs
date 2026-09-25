//! Lifecycle tests for `HubHandle` — the spawn/state-watch/graceful-shutdown
//! vocabulary embedders (GUI, testkit) get for hosting an in-process hub.
//!
//! Lives in `tests/` (not a `#[cfg(test)]` unit module): exercising `spawn`
//! needs a full hub config from the test kit, and mesh's unit-test target
//! builds testkit against a second mesh instance (the supported
//! dev-dependency cycle), so mesh types cannot cross that boundary there.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use interflow_mesh::hub::{HubHandle, HubLifecycle};
use interflow_testkit::hub_config;
use std::time::{Duration, Instant};

/// Wait until the hub reaches a state satisfying `pred`, panicking on
/// timeout.
async fn wait_state(hub: &HubHandle, what: &str) -> HubLifecycle {
    let mut rx = hub.subscribe_state();
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        let state = rx.borrow_and_update().clone();
        let done = match &state {
            HubLifecycle::Running if what == "Running" => true,
            HubLifecycle::Failed { .. } if what == "Failed" => true,
            _ => false,
        };
        if done {
            return state;
        }
        assert!(
            Instant::now() < deadline,
            "hub never reached {what} (state: {state:?})"
        );
        // A closed watch is the only failure (the hub is gone); a poll
        // interval elapsed or a visible change simply re-loops into the
        // deadline check above.
        if let Ok(Err(_)) = tokio::time::timeout(Duration::from_millis(100), rx.changed()).await {
            panic!("state watch closed while waiting for {what}");
        }
    }
}

/// Spawn → Starting → Running → shutdown → Stopped, against a real listener.
#[tokio::test]
async fn spawn_run_stop_round_trip() {
    let certs = interflow_testkit::certs::TestCerts::generate("hub-handle", "hub-agent");
    let hub = HubHandle::spawn(hub_config(0, &certs, Vec::new())).expect("hub spawn");
    assert_eq!(hub.state(), HubLifecycle::Starting);
    wait_state(&hub, "Running").await;

    // shutdown_graceful consumes the handle (same shape as AgentHandle);
    // observe the terminal state through a subscription taken beforehand.
    let mut state = hub.subscribe_state();
    assert!(hub.shutdown_graceful().await.is_ok());
    assert_eq!(*state.borrow_and_update(), HubLifecycle::Stopped);
}

/// A busy listen port fails asynchronously (Starting → Failed), and the
/// failure reason reaches both the state stream and the shutdown result —
/// the embedder's restart decision needs the cause.
#[tokio::test]
async fn busy_port_surfaces_as_failed() {
    // Hold a concrete port the moment it is chosen (bind :0 = kernel-assigned,
    // owned until dropped) so the hub's bind of the same address fails
    // deterministically — no pick-then-hold race window.
    let holder = std::net::TcpListener::bind("127.0.0.1:0").expect("hold port");
    let port = holder.local_addr().expect("held addr").port();
    let certs = interflow_testkit::certs::TestCerts::generate("hub-busy", "hub-agent");
    let hub = HubHandle::spawn(hub_config(port, &certs, Vec::new())).expect("hub spawn");
    let state = wait_state(&hub, "Failed").await;
    let HubLifecycle::Failed { error } = &state else {
        panic!("expected Failed, got {state:?}");
    };
    assert!(!error.is_empty(), "failure must carry a reason");
    assert!(hub.is_finished());
    hub.shutdown_graceful()
        .await
        .expect_err("dead hub resolves with its failure");
    drop(holder);
}
