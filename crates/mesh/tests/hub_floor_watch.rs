//! The floor version clock and its blocking-watch endpoint
//! (`GET /policy/floor/version`) — the change signal the GUI's fleet
//! read model invalidates on
//!
//! The cycle under test, per transport: an external writer acts (agent
//! registers, operator pauses a stream, operator declares maintenance) →
//! the clock bumps → a held watch answers WITHIN the hold, not after it;
//! a watch on an unchanged version runs out its wait and answers the
//! same version. Both transports carry the exchange bumps (h2
//! `POST /streams/intent`, the QUIC frame pair) — the two variants
//! differ ONLY in transport.
#![allow(
    clippy::all,
    clippy::pedantic,
    clippy::nursery,
    clippy::panic,
    clippy::unwrap_used,
    clippy::expect_used,
    missing_docs
)]
use interflow_testkit::control::{
    floor_version, hub_config_with_control, hub_quic_config_with_control, pause_stream,
    set_maintenance, wait_stream_pause_state, watch_floor_version,
};
use interflow_testkit::{agent_config, agent_quic_config, spawn_agent_registered, spawn_hub};
use std::time::{Duration, Instant};

fn certs() -> &'static interflow_testkit::certs::TestCerts {
    static C: std::sync::OnceLock<interflow_testkit::certs::TestCerts> = std::sync::OnceLock::new();
    C.get_or_init(|| interflow_testkit::certs::TestCerts::generate("floorwatch", "src"))
}

fn control_certs() -> &'static interflow_testkit::certs::TestCerts {
    static C: std::sync::OnceLock<interflow_testkit::certs::TestCerts> = std::sync::OnceLock::new();
    C.get_or_init(|| interflow_testkit::certs::TestCerts::generate("floorwatch-ctl", "operator"))
}

/// The watch endpoint's contract, end to end: probe, hold-until-timeout,
/// hold-until-bump (maintenance — immediate, no agent round trip), and
/// the pause face's convergence bump (the agent's exchange reports the
/// paused set). `quic` selects the transport for the agent leg.
async fn watch_cycle(quic: bool) {
    let _ = tracing_subscriber::fmt()
        .with_env_filter("info,interflow_core=debug,interflow_mesh=debug,interflow_expose=debug")
        .try_init();
    let certs = certs();
    let control = control_certs();
    let hub = if quic {
        spawn_hub(hub_quic_config_with_control(0, certs, control, Vec::new())).await
    } else {
        spawn_hub(hub_config_with_control(0, certs, control, Vec::new())).await
    };
    let hub_port = hub.local_addr().expect("hub bound").port();
    let endpoint = format!("127.0.0.1:{hub_port}");

    // A fresh hub has clocked nothing.
    let v0 = floor_version(&endpoint, certs, control).await.unwrap();
    assert_eq!(v0, 0, "nothing has fed the floor read model yet");

    // An external writer: the agent registers (presence is floor-visible).
    let cfg = if quic {
        agent_quic_config("src", hub_port, certs)
    } else {
        agent_config("src", hub_port, certs)
    };
    let _agent = spawn_agent_registered(cfg).await;
    let v1 = floor_version(&endpoint, certs, control).await.unwrap();
    assert!(
        v1 > v0,
        "registration bumps the clock (h2 and QUIC arms alike)"
    );

    // The qualified id the hub reports (tenant from the hub config) — read
    // from the snapshot face rather than guessed.
    let qualified = {
        let doc = interflow_testkit::control::snapshot(&endpoint, certs, control)
            .await
            .unwrap();
        doc.agents
            .iter()
            .find(|row| row.agent.ends_with("/src"))
            .expect("src registered")
            .agent
            .clone()
    };

    // The hold: `since` current, nothing moves — the watch must run out
    // its wait and answer the SAME version.
    let started = Instant::now();
    let held = watch_floor_version(&endpoint, certs, control, v1, 1)
        .await
        .unwrap();
    assert_eq!(held, v1, "no change — the answer is the unchanged version");
    assert!(
        started.elapsed() >= Duration::from_millis(900),
        "the watch held for the wait, not answered instantly (took {:?})",
        started.elapsed()
    );

    // The wake: a held watch answers WITHIN its hold the moment an
    // external writer acts (maintenance needs no agent round trip).
    let watch = tokio::spawn({
        let endpoint = endpoint.clone();
        let (certs, control) = (certs, control);
        async move { watch_floor_version(&endpoint, certs, control, v1, 20).await }
    });
    tokio::time::sleep(Duration::from_millis(300)).await;
    set_maintenance(&endpoint, certs, control, &qualified, true)
        .await
        .unwrap();
    let woken = tokio::time::timeout(Duration::from_secs(5), watch)
        .await
        .expect("the held watch answers within the hold")
        .unwrap()
        .unwrap();
    assert!(woken > v1, "the maintenance declaration woke the watch");

    // The pause face: queue the op, the agent's exchange reports the new
    // paused set, the face change bumps the clock.
    let before_pause = floor_version(&endpoint, certs, control).await.unwrap();
    pause_stream(&endpoint, certs, control, &qualified, "svc")
        .await
        .unwrap();
    wait_stream_pause_state(
        &endpoint,
        certs,
        control,
        &qualified,
        "svc",
        true,
        "face converges",
    )
    .await;
    let after_pause = floor_version(&endpoint, certs, control).await.unwrap();
    assert!(
        after_pause > before_pause,
        "the reported face change bumps the clock (before {before_pause}, after {after_pause})"
    );
}

#[tokio::test]
async fn floor_watch_cycle_h2() {
    watch_cycle(false).await;
}

#[tokio::test]
async fn floor_watch_cycle_quic() {
    watch_cycle(true).await;
}
