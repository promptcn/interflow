//! E2E: the lifecycle migration-event matrix.
//!
//! The bug cluster of 2026-10-06 → 10-12 was not functional logic errors
//! but invariant failures on **lifecycle migration events** (disconnect /
//! reconnect / re-register / refit). Functional e2e existed for each
//! feature; what was missing is coverage organized by the *event*. This
//! file hosts that matrix's new cases and maps every row to its test —
//! including the rows locked by pre-existing cases elsewhere
//!
//! | # | Migration event | Invariant | Locked by |
//! |---|---|---|---|
//! | 1 | Abnormal disconnect (no close frame) → re-register | New session survives; old watchers voided | `e2e_quic::quic_stale_watcher_voids_eviction_after_reregister` (compressed) + `e2e_quic::quic_reregistered_session_survives_stale_watcher_idle_timeout` (real 30s idle, ≥60s window) — the 2026-10-11 anchors, untouched |
//! | 2 | Graceful disconnect (close frame) | Removal honored (not voided), no ghost watcher, streams swept | `matrix_row2_graceful_disconnect_removal_honored_and_cleanup_visible` (below) |
//! | 3 | Hub restart (refit) | Serving lineage continues from persisted state; agents reconnect + re-pull | `pack_site_to_site::hub_restart_serves_persisted_lineage_and_agents_repull` |
//! | 4 | Agent restart / refit | Re-register; old streams drained; new session not killed by old state | `matrix_row4_hard_killed_agent_restart_survives_and_drains` (below, chaos: hard kill → same-identity restart) |
//! | 5 | Policy hot re-apply | Changed listeners stay in place; watermark moves | `pack_site_to_site::policy_param_change_hot_applies_without_listener_restart` |
//! | 6 | Identity change + apply | Generation continues above every local watermark | `cli policy_apply_diff::identity_change_mints_above_node_state_watermarks` |
//! | 7 | no-op gate re-run | Gate is watermark-aware; one re-run converges | `cli policy_apply_hub_reinstall::hub_reinstall_below_bookkeeping_republishes_unchanged_manifest` / `..._floor_absorbed_but_serving_behind_still_republishes` |
//! | 8 | Transport switch h2 ↔ QUIC | The switched leg must pull the new policy generation | `pack_site_to_site::transport_switch_leg_pulls_current_policy_generation` |
//! | 9 | One-way transport blackhole | Liveness roundtrip detection + rebuild | `matrix_row9a_one_way_blackhole_hub_heartbeat_evicts_notifies_and_agent_rebuilds` (hub notice fast path) + `matrix_row9b_blackhole_demanding_probe_backstops_without_hub_notice` (agent-side backstop) |
//! | 10 | Session death (peer unresponsive) | Detection within a deadline, not on the next business stream | Row 9a's `quic_heartbeat_timeout` assertions (QUIC) + `e2e_hub_eviction::heartbeat_evicts_pong_aware_wedge_and_ends_poll` (h2, tuned 1s×1) |
//! | 11 | Old-generation policy pull/reject | Rejection is observable, never silent | `pack_site_to_site::policy_publish_endpoint_verifies_persists_and_rejects` (hub face: 409 + floor). Agent-face observability has no non-log assertion surface (the no-log-grep discipline) — explicit exemption |
//!
//! Fault-injection equipment (shared by rows 1/2/4/9/10):
//! - **Hard kill** (no close frame): soak tier has real SIGKILL
//!   (`kill_and_wait` + churn waves); e2e tier equivalent is
//!   `UdpImpairProxy::shutdown()` — validated by the 2026-10-11 anchors.
//! - **One-way hang**: `UdpImpairProxy::cut/restore(Direction)` (real
//!   per-direction datagram blackhole) + the TCP twin; plus the
//!   `HubQuicSwallowLivenessProbe` fault point (hub swallows liveness
//!   roundtrips while everything else keeps flowing).
//! - **Clock compression**: `hub_quic_config_tuned` /
//!   `agent_quic_config_tuned` + `quic_transport_compressed` (idle 3s /
//!   keepalive 1s, both ends — the idle timeout negotiates as the min) +
//!   `liveness_probe_compressed` (worst-case demanding detection 5s).
//!
//! Budget discipline:
//! every wait below derives from the timers the test itself configures —
//! never from observed timings. Each assertion carries its derivation.

#![allow(
    clippy::all,
    clippy::pedantic,
    clippy::nursery,
    clippy::panic,
    clippy::unwrap_used,
    clippy::expect_used,
    missing_docs
)]
use interflow_core::protocol::StreamProto;
use interflow_mesh::agent::{AgentClient, AgentHandle, AgentState};
use interflow_mesh::config::{EgressRule, EgressTarget, HeartbeatConfig, IngressRule};
use interflow_testkit::impair::{Direction, ImpairConfig, UdpImpairProxy};
use interflow_testkit::metrics_harness::{counter_value, init_tracing, wait_counter_at_least};
use interflow_testkit::{
    agent_quic_config_tuned, echo_server, hub_quic_config, hub_quic_config_tuned,
    liveness_probe_compressed, quic_transport_compressed, spawn_agent, spawn_hub,
    wait_agent_connected,
};
use std::net::SocketAddr;
use std::time::Duration;

fn certs() -> &'static interflow_testkit::certs::TestCerts {
    static C: std::sync::OnceLock<interflow_testkit::certs::TestCerts> = std::sync::OnceLock::new();
    C.get_or_init(|| interflow_testkit::certs::TestCerts::generate("lifecycle", "agent"))
}

/// TCP echo with retries (absorbs registration / session-establishment
/// latency); a single attempt is capped at 2s so overall budgets stay
/// meaningful.
async fn tcp_echo_retry(
    addr: SocketAddr,
    payload: &[u8],
    overall: Duration,
) -> std::io::Result<Vec<u8>> {
    let deadline = tokio::time::Instant::now() + overall;
    loop {
        let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
        if remaining.is_zero() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                "tcp echo retry exhausted",
            ));
        }
        match tokio::time::timeout(
            remaining.min(Duration::from_secs(2)),
            interflow_testkit::echo_round_trip(addr, payload),
        )
        .await
        {
            Ok(Ok(resp)) => return Ok(resp),
            Ok(Err(_)) | Err(_) => tokio::time::sleep(Duration::from_millis(200)).await,
        }
    }
}

/// Assert the client connection is torn down (EOF / error) within `budget`
/// rather than silently hanging.
async fn assert_conn_torn_down(sock: &mut tokio::net::TcpStream, budget: Duration, what: &str) {
    use tokio::io::AsyncReadExt;

    let mut buf = [0u8; 64];
    match tokio::time::timeout(budget, sock.read(&mut buf)).await {
        Ok(Ok(0)) | Ok(Err(_)) => return, // EOF / connection error = torn down
        Ok(Ok(n)) => panic!("{what}: unexpectedly received {n} reply bytes before teardown"),
        Err(_) => panic!("{what}: connection not torn down within {budget:?} (silent hang)"),
    }
}

/// Polls until the handle leaves `Connected` within `budget` (any
/// Reconnecting/Connecting shape passes; Stopped/Failed is a hard failure —
/// death detection must trigger rebuild, not termination).
async fn wait_left_connected(handle: &AgentHandle, budget: Duration) {
    let deadline = tokio::time::Instant::now() + budget;
    loop {
        let state = handle.state();
        if !matches!(state, AgentState::Connected { .. }) {
            assert!(
                !matches!(state, AgentState::Stopped | AgentState::Failed { .. }),
                "death detection should trigger reconnection, not termination (actual: {state:?})"
            );
            return;
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "agent still Connected {budget:?} after the death event (detection broken)"
        );
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
}

/// A QUIC egress rule pointing at `echo_addr`.
fn egress_echo_rules(echo_addr: SocketAddr) -> Vec<EgressRule> {
    vec![EgressRule {
        name: "echo".to_string(),
        target: EgressTarget::Addr(echo_addr),
        target_protocol: StreamProto::Tcp,
        udp_idle_timeout_secs: None,
    }]
}

/// A QUIC ingress rule forwarding to the `egress` agent's echo backend.
fn ingress_to_egress(echo_addr: SocketAddr) -> Vec<IngressRule> {
    vec![IngressRule {
        name: "to-egress".to_string(),
        listen_addr: "127.0.0.1:0".parse().unwrap(),
        listen_protocol: StreamProto::Tcp,
        target_agent: "egress".to_string(),
        remote_addr: Some(echo_addr.to_string()),
        idle_timeout_secs: None,
        udp_per_ip_pps: 0,
        udp_per_ip_bytes_per_sec: 0,
        udp_egress_bytes_per_sec: 0,
    }]
}

// ---------------------------------------------------------------------------
// Matrix row 2 — graceful disconnect (control group of the stale-watcher
// guard)
// ---------------------------------------------------------------------------

/// Row 2: a graceful QUIC close carries a close frame, so the
/// connection-lost watcher wakes within seconds and its removal is
/// **honored** — no re-registration took over, so nothing is voided, the
/// registry entry is removed, orphan streams swept. The same identity's
/// re-registration then starts from a clean slate with no ghost watcher.
///
/// This is the control group of the 2026-10-11 anchors (row 1): identical
/// assembly, but the removal must go through instead of being voided.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn matrix_row2_graceful_disconnect_removal_honored_and_cleanup_visible() {
    init_tracing();
    let (echo_addr, _echo) = echo_server().await;
    let _hub = spawn_hub(hub_quic_config(0, certs(), Vec::new())).await;
    let hub_port = _hub.local_addr().expect("hub bound").port();

    let mut egress_cfg = interflow_testkit::agent_quic_config("egress", hub_port, certs());
    egress_cfg.egress = egress_echo_rules(echo_addr);
    let egress = spawn_agent(egress_cfg.clone());
    assert!(
        wait_agent_connected(&egress, Duration::from_secs(15)).await,
        "egress must register"
    );

    let mut ingress_cfg = interflow_testkit::agent_quic_config("ingress", hub_port, certs());
    ingress_cfg.ingress = ingress_to_egress(echo_addr);
    let _ingress = spawn_agent(ingress_cfg);
    let ingress_addr = _ingress
        .wait_ingress_addr("to-egress", Duration::from_secs(15))
        .await
        .expect("ingress listener bound");

    let payload = b"before-close";
    let resp = tcp_echo_retry(ingress_addr, payload, Duration::from_secs(15))
        .await
        .expect("initial round trip");
    assert_eq!(resp, payload);

    // Graceful close: the close frame reaches the hub, the watcher wakes
    // within seconds (event-driven budget)
    let _ = egress.shutdown_graceful().await;

    // Positive proof: the removal was HONORED (evicted), and — the control
    // group's point — nothing was voided (no rotation ever happened).
    wait_counter_at_least(
        "interflow_hub_agent_evicted{reason=\"quic_connection_closed\"}",
        1,
        Duration::from_secs(15),
    )
    .await;
    assert_eq!(
        counter_value("interflow_hub_agent_eviction_voided{reason=\"quic_connection_closed\"}"),
        0,
        "a graceful close with no re-registration must never be voided"
    );

    // Streams swept: a new stream to the dead agent fails fast instead of
    // black-holing (budget 2s: the fast-fail path is immediate once evicted)
    let denied = tcp_echo_retry(ingress_addr, b"while-down", Duration::from_secs(2)).await;
    assert!(
        denied.is_err(),
        "must fail fast after the graceful-close eviction"
    );

    // Clean slate: the same identity re-registers and serves; no ghost
    // watcher fires on the way (evicted/voided stay at their values).
    let egress2 = {
        let client = AgentClient::new(egress_cfg).expect("build egress restart");
        client.start()
    };
    assert!(
        wait_agent_connected(&egress2, Duration::from_secs(15)).await,
        "re-registration after graceful eviction must succeed"
    );
    let payload = b"after-restart";
    let resp = tcp_echo_retry(ingress_addr, payload, Duration::from_secs(15))
        .await
        .expect("round trip after re-registration");
    assert_eq!(resp, payload);
    assert_eq!(
        counter_value("interflow_hub_agent_evicted{reason=\"quic_connection_closed\"}"),
        1,
        "no ghost watcher may evict the re-registered session"
    );
    assert_eq!(
        counter_value("interflow_hub_agent_eviction_voided{reason=\"quic_connection_closed\"}"),
        0
    );
}

// ---------------------------------------------------------------------------
// Matrix row 4 — agent hard kill + same-identity restart (chaos form
// generalizing the row 1/2 entry events)
// ---------------------------------------------------------------------------

/// Row 4 (chaos): the agent dies WITHOUT a close frame (hard-kill form:
/// path cut under an established connection — the upgrade-killed process
/// shape), then the same identity restarts on a direct connection. The
/// re-registered session must survive the old connection's watcher waking
/// up (compressed idle: 3s), and the dead registration's established
/// streams must drain (the register-path sweep tears the source client
/// down, not leave it hanging).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn matrix_row4_hard_killed_agent_restart_survives_and_drains() {
    init_tracing();
    let (echo_addr, _echo) = echo_server().await;
    // Clock compression: idle 3s / keepalive 1s on BOTH ends (the QUIC idle
    // timeout negotiates as the endpoints' minimum) — the dead connection's
    // watcher wakes at ~3s instead of the production 30s. Heartbeat stays at
    // defaults (this case is about the watcher + register-sweep, not the
    // heartbeat path).
    let (hub_quic, agent_quic) = quic_transport_compressed();
    let _hub = spawn_hub(hub_quic_config_tuned(
        0,
        certs(),
        Vec::new(),
        Default::default(),
        HeartbeatConfig::default(),
        hub_quic,
    ))
    .await;
    let hub_port = _hub.local_addr().expect("hub bound").port();
    let hub_udp: SocketAddr = format!("127.0.0.1:{hub_port}").parse().unwrap();

    // A: the egress behind a pass-through proxy (zero latency, zero loss —
    // until the proxy dies under it, cutting the path without a close
    // frame: the hard-kill form)
    let proxy = UdpImpairProxy::spawn(
        hub_udp,
        ImpairConfig {
            one_way_delay: Duration::ZERO,
            ..ImpairConfig::default()
        },
    )
    .await
    .expect("impair proxy");
    let cfg_a = {
        let mut cfg = agent_quic_config_tuned(
            "egress",
            hub_port,
            certs(),
            agent_quic,
            interflow_mesh::config::LivenessProbeConfig::default(),
        );
        cfg.egress = egress_echo_rules(echo_addr);
        cfg.agent.hub_quic_addr = Some(proxy.local_addr().to_string());
        cfg
    };
    let _a = {
        let client = AgentClient::new(cfg_a).expect("build A");
        client.start()
    };
    wait_counter_at_least(
        "interflow_quic_agents_registered",
        1,
        Duration::from_secs(15),
    )
    .await;

    let mut ingress_cfg = interflow_testkit::agent_quic_config("ingress", hub_port, certs());
    ingress_cfg.ingress = ingress_to_egress(echo_addr);
    let _ingress = spawn_agent(ingress_cfg);
    let ingress_addr = _ingress
        .wait_ingress_addr("to-egress", Duration::from_secs(15))
        .await
        .expect("ingress listener bound");

    // One long-lived stream through A, kept open across the kill (the
    // drain assertion below hangs onto this exact connection).
    let mut old_sock = {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        use tokio::net::TcpStream;
        let payload = b"before-kill";
        loop {
            let attempt = async {
                let mut s = TcpStream::connect(ingress_addr).await?;
                s.write_all(payload).await?;
                let mut buf = vec![0u8; payload.len()];
                tokio::time::timeout(Duration::from_secs(2), s.read_exact(&mut buf)).await??;
                Ok::<_, std::io::Error>(s)
            };
            match attempt.await {
                Ok(s) => break s,
                Err(_) => tokio::time::sleep(Duration::from_millis(200)).await,
            }
        }
    };

    // Hard kill: the proxy dies under the established connection — no close
    // frame in either direction.
    proxy.shutdown().await;

    // The same identity restarts on a direct connection (the "refit"
    // window). The registered counter reaches 3 only with the restart:
    // A + ingress + A'.
    let _a2 = {
        let mut cfg = agent_quic_config_tuned(
            "egress",
            hub_port,
            certs(),
            quic_transport_compressed().1,
            interflow_mesh::config::LivenessProbeConfig::default(),
        );
        cfg.egress = egress_echo_rules(echo_addr);
        let client = AgentClient::new(cfg).expect("build A'");
        client.start()
    };
    wait_counter_at_least(
        "interflow_quic_agents_registered",
        3,
        Duration::from_secs(15),
    )
    .await;

    // The dead registration's established stream must DRAIN: the register
    // sweep removes the orphan stream, the relay writer back-fills Close +
    // FIN, and the held client connection is torn down. Budget: the sweep
    // rides the (already counted) registration; teardown is immediate after
    // it — 15s of headroom over an event that has already happened.
    assert_conn_torn_down(
        &mut old_sock,
        Duration::from_secs(15),
        "the hard-killed registration's stream must drain after the same-identity restart",
    )
    .await;

    // Survival across the old watcher's wake-up: the dead connection's idle
    // timeout (3s compressed) fires the watcher armed with the OLD circuit
    // while A' is live — every round trip across that moment must succeed
    // and no `quic_connection_closed` removal may be honored. Window =
    // idle(3s) + slack(5s) after the restart registered, re-derived from the
    // compressed idle timer, not from observation.
    let window_start = tokio::time::Instant::now();
    let window = Duration::from_secs(8);
    loop {
        let payload = b"across-watcher-wake".to_vec();
        let resp = tcp_echo_retry(ingress_addr, &payload, Duration::from_secs(15))
            .await
            .expect("round trip must keep working across the stale watcher's wake-up");
        assert_eq!(resp, payload);
        assert_eq!(
            counter_value("interflow_hub_agent_evicted{reason=\"quic_connection_closed\"}"),
            0,
            "the stale watcher evicted the restarted session"
        );
        if window_start.elapsed() >= window {
            break;
        }
        tokio::time::sleep(Duration::from_secs(2)).await;
    }

    // Positive proof the watcher DID wake (at the compressed ~3s idle) and
    // was voided by the circuit rotation — not just silence.
    wait_counter_at_least(
        "interflow_hub_agent_eviction_voided{reason=\"quic_connection_closed\"}",
        1,
        Duration::from_secs(15),
    )
    .await;
}

// ---------------------------------------------------------------------------
// Matrix rows 9a + 10 — one-way blackhole: hub-side detection and the
// eviction-notice fast path
// ---------------------------------------------------------------------------

/// Row 9a (and the QUIC half of row 10): the agent→hub direction is cut
/// while hub→agent keeps flowing (the 2026-10-09 one-way form). The hub's
/// heartbeat notices the Pong loss within its dead line (tuned to 1s × 1 →
/// 2s), evicts, and the best-effort eviction notice travels the direction
/// that still works — the agent rebuilds NOW instead of waiting for its own
/// demanding probe. After the cut is restored the agent reconnects and the
/// data plane recovers.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn matrix_row9a_one_way_blackhole_hub_heartbeat_evicts_notifies_and_agent_rebuilds() {
    init_tracing();
    let (echo_addr, _echo) = echo_server().await;
    // Heartbeat compressed to 1s × 1 → dead line = interval × (misses + 1)
    // = 2s. Transport stays at production defaults (30s idle): the
    // connection-lost watcher must stay ASLEEP here so the heartbeat path
    // is the one under test.
    let hb = HeartbeatConfig {
        enabled: true,
        interval_secs: 1,
        max_missed: 1,
    };
    let _hub = spawn_hub(hub_quic_config_tuned(
        0,
        certs(),
        Vec::new(),
        Default::default(),
        hb,
        Default::default(),
    ))
    .await;
    let hub_port = _hub.local_addr().expect("hub bound").port();
    let hub_udp: SocketAddr = format!("127.0.0.1:{hub_port}").parse().unwrap();

    let proxy = UdpImpairProxy::spawn(
        hub_udp,
        ImpairConfig {
            one_way_delay: Duration::ZERO,
            ..ImpairConfig::default()
        },
    )
    .await
    .expect("impair proxy");

    let mut cfg = interflow_testkit::agent_quic_config("egress", hub_port, certs());
    cfg.egress = egress_echo_rules(echo_addr);
    cfg.agent.hub_quic_addr = Some(proxy.local_addr().to_string());
    let egress = spawn_agent(cfg);
    assert!(
        wait_agent_connected(&egress, Duration::from_secs(15)).await,
        "egress must register through the proxy"
    );

    let mut ingress_cfg = interflow_testkit::agent_quic_config("ingress", hub_port, certs());
    ingress_cfg.ingress = ingress_to_egress(echo_addr);
    let _ingress = spawn_agent(ingress_cfg);
    let ingress_addr = _ingress
        .wait_ingress_addr("to-egress", Duration::from_secs(15))
        .await
        .expect("ingress listener bound");

    let payload = b"before-cut";
    let resp = tcp_echo_retry(ingress_addr, payload, Duration::from_secs(15))
        .await
        .expect("round trip before the cut");
    assert_eq!(resp, payload);

    // One-way blackhole: agent→hub dies, hub→agent keeps flowing. The
    // agent's Pongs (and demanding probes) vanish; the hub's Pings still
    // arrive.
    proxy.cut(Direction::AgentToHub);

    // Hub-side detection within the derived budget: dead line 2s + one tick
    // granularity (1s) + headroom for the eviction bookkeeping.
    wait_counter_at_least(
        "interflow_hub_agent_evicted{reason=\"quic_heartbeat_timeout\"}",
        1,
        Duration::from_secs(15),
    )
    .await;

    // The eviction notice rides the direction that still delivers
    // (CONNECTION_CLOSE hub→agent): the agent must leave Connected within
    // notice delivery + session wind-down — seconds, not its own demanding
    // probe budget. 15s = generous headroom over the ~2s detection.
    wait_left_connected(&egress, Duration::from_secs(15)).await;

    // Restore the cut direction: the agent's reconnect backoff tops out at
    // 30s (BACKOFF_CAP, full jitter), so recovery budget = cap + headroom.
    proxy.restore(Direction::AgentToHub);
    assert!(
        wait_agent_connected(&egress, Duration::from_secs(40)).await,
        "agent must reconnect once the direction is restored (backoff cap 30s + headroom)"
    );
    let payload = b"after-restore";
    let resp = tcp_echo_retry(ingress_addr, payload, Duration::from_secs(15))
        .await
        .expect("round trip after recovery");
    assert_eq!(resp, payload);
}

// ---------------------------------------------------------------------------
// Matrix row 9b — one-way blackhole: the agent-side demanding-probe
// backstop, without any hub notice
// ---------------------------------------------------------------------------

/// Row 9b: the guarantee that bounds detection REGARDLESS of the hub's
/// notice. The hub swallows every liveness-probe roundtrip (the
/// `HubQuicSwallowLivenessProbe` fault point: streams dropped unanswered
//  while the connection, the heartbeat Ping/Pong, and everything else keep
/// flowing) — the hub stays content, no eviction, no CONNECTION_CLOSE. The
/// ONLY sensor that can catch this is the agent supervisor's demanding
/// probe, which must fire within its configured budget and force a rebuild.
/// Disarming restores service on the next roundtrip.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn matrix_row9b_blackhole_demanding_probe_backstops_without_hub_notice() {
    use interflow_testkit::fault::{self, FaultPlan};

    init_tracing();
    let (echo_addr, _echo) = echo_server().await;
    // Production heartbeat (the hub must stay content — Ping/Pong flows
    // normally) and production transport. The ONLY compressed timer is the
    // agent's demanding probe: worst-case detection ≈ demand_every +
    // strikes × (tick + demand_deadline) = 1 + 2 × (1 + 1) = 5s.
    let _hub = spawn_hub(hub_quic_config(0, certs(), Vec::new())).await;
    let hub_port = _hub.local_addr().expect("hub bound").port();

    let mut cfg = agent_quic_config_tuned(
        "egress",
        hub_port,
        certs(),
        interflow_mesh::config::AgentQuicConfig::default(),
        liveness_probe_compressed(),
    );
    cfg.egress = egress_echo_rules(echo_addr);
    let egress = spawn_agent(cfg);
    assert!(
        wait_agent_connected(&egress, Duration::from_secs(15)).await,
        "egress must register"
    );

    let mut ingress_cfg = interflow_testkit::agent_quic_config("ingress", hub_port, certs());
    ingress_cfg.ingress = ingress_to_egress(echo_addr);
    let _ingress = spawn_agent(ingress_cfg);
    let ingress_addr = _ingress
        .wait_ingress_addr("to-egress", Duration::from_secs(15))
        .await
        .expect("ingress listener bound");

    let payload = b"before-swallow";
    let resp = tcp_echo_retry(ingress_addr, payload, Duration::from_secs(15))
        .await
        .expect("round trip before the swallow");
    assert_eq!(resp, payload);

    // Arm the one-way form: the hub drops every liveness roundtrip
    // unanswered while everything else keeps flowing.
    let faults = fault::install(
        FaultPlan::new()
            .stall_every_at(interflow_core::fault::FaultPoint::HubQuicSwallowLivenessProbe),
    );

    // The demanding probe is the only sensor that can notice: budget =
    // worst-case detection 5s (derived from the configured probe timers)
    // + headroom for the wind-down = 15s.
    wait_left_connected(&egress, Duration::from_secs(15)).await;

    // The injection actually fired (vacuous-green guard). And the hub's own
    // heartbeat sensor stayed out of it — the 75s default dead line cannot
    // explain a ~2s departure, so the rebuild was driven by the agent-side
    // probe alone ("without hub notice"). The connection-closed removal the
    // hub performs afterwards is the expected post-mortem cleanup of the
    // connection the agent's own wind-down just closed — not asserted here.
    assert!(
        faults
            .wait_fired(
                interflow_core::fault::FaultPoint::HubQuicSwallowLivenessProbe,
                Duration::from_secs(5),
            )
            .await,
        "the swallow fault must have fired for this test to mean anything"
    );
    assert_eq!(
        counter_value("interflow_hub_agent_evicted{reason=\"quic_heartbeat_timeout\"}"),
        0,
        "the hub stayed content (75s default dead line) — only the agent-side probe may detect"
    );

    // Disarm: the hub answers the next roundtrip; the agent's reconnect
    // backoff tops out at 30s → recovery budget = cap + headroom.
    fault::clear();
    assert!(
        wait_agent_connected(&egress, Duration::from_secs(40)).await,
        "agent must reconnect once the hub answers again (backoff cap 30s + headroom)"
    );
    let payload = b"after-disarm";
    let resp = tcp_echo_retry(ingress_addr, payload, Duration::from_secs(15))
        .await
        .expect("round trip after disarm");
    assert_eq!(resp, payload);
}
