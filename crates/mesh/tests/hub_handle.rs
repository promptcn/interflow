//! Lifecycle tests for `HubHandle` — the spawn/state-watch/graceful-shutdown
//! vocabulary embedders (GUI, testkit) get for hosting an in-process hub.
//!
//! Lives in `tests/` (not a `#[cfg(test)]` unit module): exercising `spawn`
//! needs a full hub config from the test kit, and mesh's unit-test target
//! builds testkit against a second mesh instance (the supported
//! dev-dependency cycle), so mesh types cannot cross that boundary there.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use interflow_core::config::AuditConfig;
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

/// An in-process respawn after the hub has SERVED agent sessions must not
/// trip the audit ledger's single-writer guard. Every background task
/// holding an `Arc<HubState>` — the poll-grace timer (`RxStream::drop`),
/// the `/stream/up` reader, the QUIC relay reader — is tracked on the
/// run's TaskTracker and exits on shutdown, so the ledger claim releases
/// with the drain and the same path hosts the next generation. This is
/// the GUI rotate / update shape (stop → swap → start inside one
/// process); before the teardown completion fix the second spawn panicked
/// at `AuditSink::spawn`'s claim guard, aborting the whole host process
#[tokio::test]
async fn respawn_after_agent_sessions_reclaims_the_ledger_claim() {
    let certs = interflow_testkit::certs::TestCerts::generate("hub-respawn", "agent");
    let dir = tempfile::tempdir().expect("tempdir");
    let ledger = dir.path().join("audit.jsonl");
    let mut cfg = hub_config(0, &certs, Vec::new());
    cfg.audit = AuditConfig {
        enabled: true,
        path: Some(ledger.display().to_string()),
        ..AuditConfig::default()
    };

    // Generation one serves a real agent session (register + /poll ⇒ an
    // RxStream exists), then drains. `spawn_hub` forgoes its bind retry
    // with an enabled audit sink (a second spawn would collide with the
    // claim); this config is h2-only, so the dual-stack same-port flake
    // the retry exists for does not apply.
    let hub = interflow_testkit::spawn_hub(cfg.clone()).await;
    let port = hub.local_addr().expect("hub bound").port();
    let agent = interflow_testkit::spawn_agent_registered(interflow_testkit::agent_config(
        "respawn-agent",
        port,
        &certs,
    ))
    .await;
    hub.shutdown_graceful()
        .await
        .expect("generation one drains");
    let _ = agent.shutdown_graceful().await;

    // The ledger was really engaged (register audited + flushed by the
    // drain), so the respawn below exercises the claim, not a vacuous
    // disabled sink.
    let served = std::fs::read_to_string(&ledger).expect("ledger readable");
    assert!(
        !served.is_empty(),
        "generation one must have audited events"
    );

    // Generation two, same process, same ledger path. Panics at spawn if
    // any HubState holder outlived the drain.
    let hub2 = interflow_testkit::spawn_hub(cfg).await;
    hub2.shutdown_graceful()
        .await
        .expect("generation two drains");
}
