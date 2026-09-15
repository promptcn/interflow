//! E2E: UDP forwarding (2026-09-11 backlog §7 T1/T2/T3/T6/T7/T8/T10/T12).
//!
//! Data plane: client → ingress agent (UDP listener, one tunnel stream per
//! source address) → hub → egress agent (connected UDP socket) → UDP echo
//! backend → return along the same path.
//!
//! Note: the in-process harness cannot truly kill the hub process (abort only
//! cancels the run task; the established agent connection tasks live on).
//! Hub-crash scenarios are covered by e2e_hub_eviction's eviction + implicit
//! re-registration path; in this file T3 covers agent restart and T12 covers
//! self-healing after poll-disconnect grace eviction.

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
use interflow_mesh::agent::{AgentClient, AgentHandle, AgentState};
use interflow_mesh::config::{EgressRule, HeartbeatConfig, HubSecurityConfig, IngressRule};
use interflow_testkit::{
    acl, agent_config, hub_config, hub_config_tuned, pick_ephemeral_port, spawn_agent, spawn_hub,
    spawn_udp_echo, spawn_udp_echo_first_delayed, udp_client, udp_echo_round_trip,
    udp_round_trip_once,
};
use std::net::SocketAddr;
use std::time::Duration;

/// Build a UDP egress rule.
fn udp_egress_rule(name: &str, target: SocketAddr) -> EgressRule {
    EgressRule {
        name: name.to_string(),
        target_addr: target,
        target_protocol: StreamProto::Udp,
        udp_idle_timeout_secs: None,
    }
}

/// Build a UDP ingress rule (default rate-limit parameters + optional
/// overrides).
fn udp_ingress_rule(
    name: &str,
    listen: SocketAddr,
    target_agent: &str,
    remote: Option<SocketAddr>,
) -> IngressRule {
    IngressRule {
        name: name.to_string(),
        listen_addr: listen,
        listen_protocol: StreamProto::Udp,
        target_agent: target_agent.to_string(),
        remote_addr: remote.map(|a| a.to_string()),
        idle_timeout_secs: None,
        udp_per_ip_pps: 0,
        udp_per_ip_bytes_per_sec: 0,
        udp_egress_bytes_per_sec: 0,
    }
}

fn random_payload(len: usize) -> Vec<u8> {
    (0..len).map(|i| (i * 31 % 251) as u8).collect()
}

/// T1: basic UDP echo send/receive — random payloads x 3 rounds compared byte
/// for byte (small packets all pass under default rate limits).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn udp_echo_round_trip_basic() {
    let (echo_addr, _echo) = spawn_udp_echo().await;
    let hub_port = pick_ephemeral_port();
    let _hub = spawn_hub(hub_config(hub_port, vec![acl("ingress", "egress")])).await;

    let mut egress_cfg = agent_config("egress", hub_port);
    egress_cfg.egress = vec![udp_egress_rule("echo", echo_addr)];
    let _egress = spawn_agent(egress_cfg);

    let ingress_port = pick_ephemeral_port();
    let mut ingress_cfg = agent_config("ingress", hub_port);
    ingress_cfg.ingress = vec![udp_ingress_rule(
        "to-egress",
        format!("127.0.0.1:{ingress_port}").parse().unwrap(),
        "egress",
        Some(echo_addr),
    )];
    let _ingress = spawn_agent(ingress_cfg);

    let ingress_addr: SocketAddr = format!("127.0.0.1:{ingress_port}").parse().unwrap();

    for round in 0..3 {
        let payload = random_payload(64 + round * 37);
        let resp = udp_echo_round_trip(ingress_addr, &payload, Duration::from_secs(15))
            .await
            .expect("UDP echo round trip");
        assert_eq!(
            resp, payload,
            "round {round}: the reply must match the sent packet byte for byte"
        );
    }
}

/// T2: >= 4 client source addresses concurrently hit the same exposed UDP
/// port.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn udp_multiple_concurrent_clients() {
    let (echo_addr, _echo) = spawn_udp_echo().await;
    let hub_port = pick_ephemeral_port();
    let _hub = spawn_hub(hub_config(hub_port, vec![acl("ingress", "egress")])).await;

    let mut egress_cfg = agent_config("egress", hub_port);
    egress_cfg.egress = vec![udp_egress_rule("echo", echo_addr)];
    let _egress = spawn_agent(egress_cfg);

    let ingress_port = pick_ephemeral_port();
    let mut ingress_cfg = agent_config("ingress", hub_port);
    ingress_cfg.ingress = vec![udp_ingress_rule(
        "to-egress",
        format!("127.0.0.1:{ingress_port}").parse().unwrap(),
        "egress",
        Some(echo_addr),
    )];
    let _ingress = spawn_agent(ingress_cfg);

    let ingress_addr: SocketAddr = format!("127.0.0.1:{ingress_port}").parse().unwrap();

    // First confirm the stack is ready
    let payload = random_payload(32);
    let resp = udp_echo_round_trip(ingress_addr, &payload, Duration::from_secs(15))
        .await
        .expect("stack ready probe");
    assert_eq!(resp, payload);

    // 4 clients (each with its own source port → its own tunnel stream)
    // sending and receiving concurrently
    let mut tasks = Vec::new();
    for client_idx in 0..4 {
        let addr = ingress_addr;
        tasks.push(tokio::spawn(async move {
            let sock = udp_client().await;
            for round in 0..3 {
                let payload = random_payload(48 + client_idx * 16 + round);
                let resp = udp_round_trip_once(&sock, addr, &payload, Duration::from_secs(10))
                    .await
                    .expect("concurrent round trip");
                assert_eq!(resp, payload, "client {client_idx} round {round}");
            }
        }));
    }
    for t in tasks {
        t.await.expect("client task");
    }
}

/// T3: UDP still works after the egress agent gracefully shuts down and
/// restarts (the session is rebuilt automatically).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn udp_agent_restart_recovers() {
    let (echo_addr, _echo) = spawn_udp_echo().await;
    let hub_port = pick_ephemeral_port();
    let _hub = spawn_hub(hub_config(hub_port, vec![acl("ingress", "egress")])).await;

    let mut egress_cfg = agent_config("egress", hub_port);
    egress_cfg.egress = vec![udp_egress_rule("echo", echo_addr)];

    let handle1 = start_agent(egress_cfg.clone());
    wait_state(&handle1, Duration::from_secs(10)).await;

    let ingress_port = pick_ephemeral_port();
    let mut ingress_cfg = agent_config("ingress", hub_port);
    ingress_cfg.ingress = vec![udp_ingress_rule(
        "to-egress",
        format!("127.0.0.1:{ingress_port}").parse().unwrap(),
        "egress",
        Some(echo_addr),
    )];
    let _ingress = spawn_agent(ingress_cfg);

    let ingress_addr: SocketAddr = format!("127.0.0.1:{ingress_port}").parse().unwrap();
    let payload = random_payload(64);
    let resp = udp_echo_round_trip(ingress_addr, &payload, Duration::from_secs(15))
        .await
        .expect("initial round trip");
    assert_eq!(resp, payload);

    // Gracefully shut down the egress (equivalent to rathole's
    // client crash+restart scenario)
    let _ = handle1.shutdown_graceful().await;

    // Restart the agent with the same id
    let handle2 = start_agent(egress_cfg);
    wait_state(&handle2, Duration::from_secs(10)).await;
    tokio::time::sleep(Duration::from_millis(500)).await;

    let payload2 = random_payload(96);
    let resp2 = udp_echo_round_trip(ingress_addr, &payload2, Duration::from_secs(15))
        .await
        .expect("round trip after egress restart");
    assert_eq!(resp2, payload2);
    let _ = handle2;
}

/// T6: 1500 / 2048 / 8192 / 65000-byte datagrams, no truncation, byte-for-byte
/// comparison.
///
/// (A comparison case for frp's default 1500 / rathole's 2048 truncation
/// blind spots; all rate limits disabled to avoid large packets being
/// deterministically rejected by the per-IP byte rate.)
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn udp_large_datagrams_no_truncation() {
    let (echo_addr, _echo) = spawn_udp_echo().await;
    let hub_port = pick_ephemeral_port();
    let _hub = spawn_hub(hub_config(hub_port, vec![acl("ingress", "egress")])).await;

    let mut egress_cfg = agent_config("egress", hub_port);
    egress_cfg.egress = vec![udp_egress_rule("echo", echo_addr)];
    let _egress = spawn_agent(egress_cfg);

    let ingress_port = pick_ephemeral_port();
    let mut ingress_cfg = agent_config("ingress", hub_port);
    ingress_cfg.ingress = vec![udp_ingress_rule(
        "to-egress",
        format!("127.0.0.1:{ingress_port}").parse().unwrap(),
        "egress",
        Some(echo_addr),
    )];
    let _ingress = spawn_agent(ingress_cfg);

    let ingress_addr: SocketAddr = format!("127.0.0.1:{ingress_port}").parse().unwrap();

    for size in [1500usize, 2048, 8192, 65000] {
        let payload = random_payload(size);
        let resp = udp_echo_round_trip(ingress_addr, &payload, Duration::from_secs(15))
            .await
            .unwrap_or_else(|e| panic!("size {size}: {e}"));
        assert_eq!(
            resp.len(),
            size,
            "size {size}: reply length must match (no truncation)"
        );
        assert_eq!(resp, payload, "size {size}: byte-for-byte identical");
    }
}

/// T7: idle-session recycling — the stream table does not leak, and the
/// `max_streams_per_agent` slot is released.
///
/// cap=3: the readiness-probe session takes 1 + two client sessions take 2 →
/// full; while full, a 3rd client must fail, and after idle recycling it must
/// succeed (proving the slot was released, not leaked).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn udp_idle_session_recycled_and_slot_released() {
    let (echo_addr, _echo) = spawn_udp_echo().await;
    let hub_port = pick_ephemeral_port();
    let security = HubSecurityConfig {
        max_streams_per_agent: 3,
        ..HubSecurityConfig::default()
    };
    let _hub = spawn_hub(hub_config_tuned(
        hub_port,
        vec![acl("ingress", "egress")],
        security,
        HeartbeatConfig::default(),
    ))
    .await;

    let mut egress_cfg = agent_config("egress", hub_port);
    egress_cfg.egress = vec![EgressRule {
        udp_idle_timeout_secs: Some(6),
        ..udp_egress_rule("echo", echo_addr)
    }];
    let _egress = spawn_agent(egress_cfg);

    let ingress_port = pick_ephemeral_port();
    let mut ingress_cfg = agent_config("ingress", hub_port);
    ingress_cfg.ingress = vec![IngressRule {
        idle_timeout_secs: Some(6),
        ..udp_ingress_rule(
            "to-egress",
            format!("127.0.0.1:{ingress_port}").parse().unwrap(),
            "egress",
            Some(echo_addr),
        )
    }];
    let _ingress = spawn_agent(ingress_cfg);

    let ingress_addr: SocketAddr = format!("127.0.0.1:{ingress_port}").parse().unwrap();

    // Stack-readiness probe (retries absorb agent registration latency)
    let ready = random_payload(16);
    let resp = udp_echo_round_trip(ingress_addr, &ready, Duration::from_secs(15))
        .await
        .expect("stack ready probe");
    assert_eq!(resp, ready);

    // Fill the per-agent stream quota (cap=2): two clients each establish one
    // session
    let c1 = udp_client().await;
    let c2 = udp_client().await;
    for (i, sock) in [&c1, &c2].iter().enumerate() {
        let payload = random_payload(32);
        let resp = udp_round_trip_once(sock, ingress_addr, &payload, Duration::from_secs(10))
            .await
            .unwrap_or_else(|e| panic!("client {i}: {e}"));
        assert_eq!(resp, payload);
    }

    // Third client: over the cap, stream establishment rejected → no reply
    // (while the sessions are occupied)
    let c3 = udp_client().await;
    let probe = random_payload(16);
    let denied = udp_round_trip_once(&c3, ingress_addr, &probe, Duration::from_millis(1500)).await;
    assert!(
        denied.is_err(),
        "the 3rd session must fail while cap=2 is exhausted"
    );

    // Wait for idle recycling (ingress 6s / egress 6s, independent fallbacks
    // on both sides)
    tokio::time::sleep(Duration::from_secs(9)).await;

    // After recycling the slot is released: the 3rd client re-establishes
    // successfully
    let resp = udp_round_trip_once(&c3, ingress_addr, &probe, Duration::from_secs(10))
        .await
        .expect("the slot must have been released after idle recycling");
    assert_eq!(resp, probe);
}

/// T8: late reply — a response delivered after recycling triggers the cleanup
/// path without panicking or wedging; the stack stays usable.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn udp_late_reply_after_recycle_does_not_wedge() {
    // The echo backend delays its first reply by 3s; both sides idle 1s → the
    // session is recycled before the reply arrives
    let (echo_addr, _echo) = spawn_udp_echo_first_delayed(Duration::from_secs(3)).await;
    let hub_port = pick_ephemeral_port();
    let _hub = spawn_hub(hub_config(hub_port, vec![acl("ingress", "egress")])).await;

    let mut egress_cfg = agent_config("egress", hub_port);
    egress_cfg.egress = vec![EgressRule {
        udp_idle_timeout_secs: Some(1),
        ..udp_egress_rule("echo", echo_addr)
    }];
    let _egress = spawn_agent(egress_cfg);

    let ingress_port = pick_ephemeral_port();
    let mut ingress_cfg = agent_config("ingress", hub_port);
    ingress_cfg.ingress = vec![IngressRule {
        idle_timeout_secs: Some(1),
        ..udp_ingress_rule(
            "to-egress",
            format!("127.0.0.1:{ingress_port}").parse().unwrap(),
            "egress",
            Some(echo_addr),
        )
    }];
    let _ingress = spawn_agent(ingress_cfg);

    let ingress_addr: SocketAddr = format!("127.0.0.1:{ingress_port}").parse().unwrap();
    let client = udp_client().await;

    // A data-plane probe cannot succeed under the delayed reply; use a fixed
    // wait to cover agent registration latency
    tokio::time::sleep(Duration::from_secs(3)).await;

    // First shot: the session is recycled before the reply → the client gets
    // no reply (the late reply went down the cleanup path)
    let payload = random_payload(32);
    let first =
        udp_round_trip_once(&client, ingress_addr, &payload, Duration::from_millis(2500)).await;
    assert!(
        first.is_err(),
        "idle=1s + 3s delay: the first reply is necessarily late"
    );

    // Wait for the late reply to finish going through the cleanup path
    tokio::time::sleep(Duration::from_secs(2)).await;

    // The stack is not wedged: a new datagram opens a new session, and the
    // reply (delayed 3s) arrives normally
    let resp = udp_round_trip_once(&client, ingress_addr, &payload, Duration::from_secs(10))
        .await
        .expect("the stack must remain usable after a late reply");
    assert_eq!(resp, payload);
}

/// T10: inbound per-IP pps rate limit — over-limit drops are observable,
/// within-limit traffic passes fully.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn udp_rate_limit_drops_burst() {
    let (echo_addr, _echo) = spawn_udp_echo().await;
    let hub_port = pick_ephemeral_port();
    let _hub = spawn_hub(hub_config(hub_port, vec![acl("ingress", "egress")])).await;

    let mut egress_cfg = agent_config("egress", hub_port);
    egress_cfg.egress = vec![udp_egress_rule("echo", echo_addr)];
    let _egress = spawn_agent(egress_cfg);

    let ingress_port = pick_ephemeral_port();
    let mut ingress_cfg = agent_config("ingress", hub_port);
    ingress_cfg.ingress = vec![IngressRule {
        udp_per_ip_pps: 5,
        udp_per_ip_bytes_per_sec: 0,
        udp_egress_bytes_per_sec: 0,
        ..udp_ingress_rule(
            "to-egress",
            format!("127.0.0.1:{ingress_port}").parse().unwrap(),
            "egress",
            Some(echo_addr),
        )
    }];
    let _ingress = spawn_agent(ingress_cfg);

    let ingress_addr: SocketAddr = format!("127.0.0.1:{ingress_port}").parse().unwrap();
    let client = udp_client().await;

    // First confirm the stack is ready (consumes 1 burst quota)
    let probe = random_payload(16);
    let resp = udp_echo_round_trip(ingress_addr, &probe, Duration::from_secs(15))
        .await
        .expect("stack ready probe");
    assert_eq!(resp, probe);

    // Burst of 20 datagrams (pps=5 → most are dropped)
    let payload = random_payload(16);
    let mut replies = 0;
    for _ in 0..20 {
        client.send_to(&payload, ingress_addr).await.expect("send");
        if udp_round_trip_once(&client, ingress_addr, &payload, Duration::from_millis(50))
            .await
            .is_ok()
        {
            replies += 1;
        }
        // send-then-recv one at a time, avoiding reply cross-talk
    }
    assert!(
        replies < 20,
        "with pps=5, a burst of 20 must have drops (actual replies {replies})"
    );

    // Within-limit comparison: raising pps lets everything pass
    // (reconfiguring the same stack is not feasible — spin up a fresh stack to
    // verify "the rate-limit parameters take effect" rather than "a network
    // problem")
}

/// T10b: no rate limiting under a high-pps config (a control case proving the
/// drops come from the rate limiter, not a data-plane defect).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn udp_rate_limit_high_pps_all_pass() {
    let (echo_addr, _echo) = spawn_udp_echo().await;
    let hub_port = pick_ephemeral_port();
    let _hub = spawn_hub(hub_config(hub_port, vec![acl("ingress", "egress")])).await;

    let mut egress_cfg = agent_config("egress", hub_port);
    egress_cfg.egress = vec![udp_egress_rule("echo", echo_addr)];
    let _egress = spawn_agent(egress_cfg);

    let ingress_port = pick_ephemeral_port();
    let mut ingress_cfg = agent_config("ingress", hub_port);
    ingress_cfg.ingress = vec![IngressRule {
        udp_per_ip_pps: 1000,
        udp_per_ip_bytes_per_sec: 0,
        udp_egress_bytes_per_sec: 0,
        ..udp_ingress_rule(
            "to-egress",
            format!("127.0.0.1:{ingress_port}").parse().unwrap(),
            "egress",
            Some(echo_addr),
        )
    }];
    let _ingress = spawn_agent(ingress_cfg);

    let ingress_addr: SocketAddr = format!("127.0.0.1:{ingress_port}").parse().unwrap();
    let client = udp_client().await;

    let probe = random_payload(16);
    let resp = udp_echo_round_trip(ingress_addr, &probe, Duration::from_secs(15))
        .await
        .expect("stack ready probe");
    assert_eq!(resp, probe);

    let payload = random_payload(16);
    let mut replies = 0;
    for _ in 0..20 {
        client.send_to(&payload, ingress_addr).await.expect("send");
        if udp_round_trip_once(&client, ingress_addr, &payload, Duration::from_millis(500))
            .await
            .is_ok()
        {
            replies += 1;
        }
    }
    assert_eq!(
        replies, 20,
        "with pps=1000, all 20 in a burst should be replied to"
    );
}

/// T12: after poll-disconnect grace eviction (simulating egress loss of
/// contact), UDP fails fast; once the egress re-registers, it self-heals.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn udp_hub_eviction_then_recovery() {
    let (echo_addr, _echo) = spawn_udp_echo().await;
    let hub_port = pick_ephemeral_port();
    let security = HubSecurityConfig {
        poll_grace_secs: 1,
        ..HubSecurityConfig::default()
    };
    let heartbeat = HeartbeatConfig {
        enabled: true,
        interval_secs: 1,
        max_missed: 2,
    };
    let _hub = spawn_hub(hub_config_tuned(
        hub_port,
        vec![acl("ingress", "egress")],
        security,
        heartbeat,
    ))
    .await;

    let mut egress_cfg = agent_config("egress", hub_port);
    egress_cfg.egress = vec![udp_egress_rule("echo", echo_addr)];

    // Hold the handle manually for a graceful shutdown (triggers poll
    // disconnect → grace 1s → eviction)
    let handle1 = start_agent(egress_cfg.clone());
    wait_state(&handle1, Duration::from_secs(10)).await;

    let ingress_port = pick_ephemeral_port();
    let mut ingress_cfg = agent_config("ingress", hub_port);
    ingress_cfg.ingress = vec![udp_ingress_rule(
        "to-egress",
        format!("127.0.0.1:{ingress_port}").parse().unwrap(),
        "egress",
        Some(echo_addr),
    )];
    let _ingress = spawn_agent(ingress_cfg);

    let ingress_addr: SocketAddr = format!("127.0.0.1:{ingress_port}").parse().unwrap();
    let payload = random_payload(64);
    let resp = udp_echo_round_trip(ingress_addr, &payload, Duration::from_secs(15))
        .await
        .expect("initial round trip");
    assert_eq!(resp, payload);

    // Shut down the egress → poll disconnects → nobody re-polls within the
    // 1s grace → eviction
    let _ = handle1.shutdown_graceful().await;
    tokio::time::sleep(Duration::from_secs(3)).await;

    // After eviction: stream establishment fails fast (503/429 →
    // session_open_failed → datagram dropped)
    let client = udp_client().await;
    let denied =
        udp_round_trip_once(&client, ingress_addr, &payload, Duration::from_millis(1500)).await;
    assert!(
        denied.is_err(),
        "UDP must fail fast after the egress is evicted"
    );

    // Recovery: self-heals once the egress re-registers
    let handle2 = start_agent(egress_cfg);
    wait_state(&handle2, Duration::from_secs(10)).await;
    let resp = udp_echo_round_trip(ingress_addr, &payload, Duration::from_secs(15))
        .await
        .expect("recovery round trip");
    assert_eq!(resp, payload);
    let _ = handle2;
}

// --- Agent-restart helpers (aligned with the e2e_agent_restart pattern) ---

fn start_agent(cfg: interflow_mesh::config::AgentConfig) -> AgentHandle {
    AgentClient::new(cfg).expect("agent build").start()
}

async fn wait_state(handle: &AgentHandle, limit: Duration) {
    let mut rx = handle.subscribe_state();
    let _ = tokio::time::timeout(limit, async {
        loop {
            if matches!(rx.borrow().clone(), AgentState::Connected { .. }) {
                return;
            }
            if rx.changed().await.is_err() {
                return;
            }
        }
    })
    .await;
}
