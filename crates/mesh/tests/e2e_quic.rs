//! E2E: QUIC transport (validation of backlog §7 T4/T5/T12 over the quic
//! transport).
//!
//! - T4 transport matrix: {h2, quic} x {TCP traffic, UDP traffic}
//! - Cross-transport interop: h2 ingress <-> quic egress (hub dual-stack
//!   translation)
//! - T5 mTLS matrix: a valid client certificate passes; a wrong certificate
//!   (CN mismatch) is rejected
//! - T12 disconnect self-healing: QUIC connection drops → eviction → recovery
//!   after re-registration
//! - Regressions (backlog §1.7 regression-coverage audit, 2026-09-14): the
//!   QUIC Close-frame `_close_` sentinel (both paths — synchronous rejection
//!   and teardown back-fill, a59e0a7 — previously covered only by the soak
//!   guard), and hub silent-death detection (the literal e478c4d shape,
//!   previously accepted only on the graceful-shutdown path)
//!
//! Certificates: generated uniformly by the testkit (self-signed CA + a
//! server certificate with SAN(127.0.0.1/localhost) + client certificates
//! with CN = agent id).

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
use interflow_mesh::config::{
    AgentTlsConfig, AuthConfig, AuthMode, EgressRule, IngressRule, MtlsConfig,
};
use interflow_testkit::certs::TestCerts;
use interflow_testkit::{
    acl, agent_config, agent_quic_config, echo_server, hub_quic_config, pick_ephemeral_port,
    spawn_agent, spawn_hub, spawn_udp_echo, tcp_egress_rule, tcp_ingress_rule, udp_echo_round_trip,
    udp_egress_rule, udp_ingress_rule, wait_for_tcp,
};
use std::net::SocketAddr;
use std::time::Duration;

// ---------------------------------------------------------------------------
// T4: transport matrix
// ---------------------------------------------------------------------------

/// TCP echo round trip over quic x quic.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn quic_tcp_round_trip() {
    let certs = TestCerts::generate("quic-e2e", "quic-egress");
    let (echo_addr, _echo) = echo_server().await;
    let hub_port = pick_ephemeral_port();
    let _hub = spawn_hub(hub_quic_config(
        hub_port,
        &certs,
        vec![acl("ingress", "egress")],
    ))
    .await;

    let mut egress_cfg = agent_quic_config("egress", hub_port, &certs);
    egress_cfg.egress = vec![EgressRule {
        name: "echo".to_string(),
        target_addr: echo_addr,
        target_protocol: StreamProto::Tcp,
        udp_idle_timeout_secs: None,
    }];
    let _egress = spawn_agent(egress_cfg);

    let ingress_port = pick_ephemeral_port();
    let mut ingress_cfg = agent_quic_config("ingress", hub_port, &certs);
    ingress_cfg.ingress = vec![IngressRule {
        name: "to-egress".to_string(),
        listen_addr: format!("127.0.0.1:{ingress_port}").parse().unwrap(),
        listen_protocol: StreamProto::Tcp,
        target_agent: "egress".to_string(),
        remote_addr: Some(echo_addr.to_string()),
        idle_timeout_secs: None,
        udp_per_ip_pps: 0,
        udp_per_ip_bytes_per_sec: 0,
        udp_egress_bytes_per_sec: 0,
    }];
    let _ingress = spawn_agent(ingress_cfg);

    let ingress_addr: SocketAddr = format!("127.0.0.1:{ingress_port}").parse().unwrap();
    wait_for_tcp(ingress_addr, Duration::from_secs(15))
        .await
        .expect("ingress ready");

    // wait_for_tcp only proves the ingress is ready; the egress's QUIC
    // registration (including the TLS handshake) may still lag — absorb the
    // readiness latency on both sides with a probing retry
    let payload = b"quic-tcp-roundtrip-payload";
    let resp = tcp_echo_retry(ingress_addr, payload, Duration::from_secs(15))
        .await
        .expect("TCP echo over QUIC transport");
    assert_eq!(resp, payload);
}

/// UDP echo round trip over quic x quic (UDP carried over a QUIC stream).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn quic_udp_round_trip() {
    let certs = TestCerts::generate("quic-e2e", "quic-egress");
    let (echo_addr, _echo) = spawn_udp_echo().await;
    let hub_port = pick_ephemeral_port();
    let _hub = spawn_hub(hub_quic_config(
        hub_port,
        &certs,
        vec![acl("ingress", "egress")],
    ))
    .await;

    let mut egress_cfg = agent_quic_config("egress", hub_port, &certs);
    egress_cfg.egress = vec![udp_egress_rule("echo", echo_addr)];
    let _egress = spawn_agent(egress_cfg);

    let ingress_port = pick_ephemeral_port();
    let mut ingress_cfg = agent_quic_config("ingress", hub_port, &certs);
    ingress_cfg.ingress = vec![udp_ingress_rule(
        "to-egress",
        format!("127.0.0.1:{ingress_port}").parse().unwrap(),
        "egress",
        Some(echo_addr),
    )];
    let _ingress = spawn_agent(ingress_cfg);

    let ingress_addr: SocketAddr = format!("127.0.0.1:{ingress_port}").parse().unwrap();
    let payload = b"quic-udp-roundtrip-datagram";
    let resp = udp_echo_round_trip(ingress_addr, payload, Duration::from_secs(15))
        .await
        .expect("UDP echo over QUIC transport");
    assert_eq!(resp, payload);
}

/// Cross-transport interop: h2 (TLS) ingress <-> quic egress.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn cross_transport_h2_ingress_quic_egress() {
    let certs = TestCerts::generate("quic-e2e", "quic-egress");
    let (echo_addr, _echo) = echo_server().await;
    let hub_port = pick_ephemeral_port();
    let _hub = spawn_hub(hub_quic_config(
        hub_port,
        &certs,
        vec![acl("ingress", "egress")],
    ))
    .await;

    // quic egress
    let mut egress_cfg = agent_quic_config("egress", hub_port, &certs);
    egress_cfg.egress = vec![EgressRule {
        name: "echo".to_string(),
        target_addr: echo_addr,
        target_protocol: StreamProto::Tcp,
        udp_idle_timeout_secs: None,
    }];
    let _egress = spawn_agent(egress_cfg);

    // h2 ingress (TLS over TCP, certificates from the same CA)
    let mut ingress_cfg = agent_config("ingress", hub_port);
    ingress_cfg.agent.hub_url = format!("https://localhost:{hub_port}");
    ingress_cfg.tls = Some(AgentTlsConfig {
        enabled: true,
        ca_path: Some(certs.ca_path().display().to_string()),
        client_cert_path: None,
        client_key_path: None,
        hub_cert_fingerprint: None,
    });
    let ingress_port = pick_ephemeral_port();
    ingress_cfg.ingress = vec![IngressRule {
        name: "to-egress".to_string(),
        listen_addr: format!("127.0.0.1:{ingress_port}").parse().unwrap(),
        listen_protocol: StreamProto::Tcp,
        target_agent: "egress".to_string(),
        remote_addr: Some(echo_addr.to_string()),
        idle_timeout_secs: None,
        udp_per_ip_pps: 0,
        udp_per_ip_bytes_per_sec: 0,
        udp_egress_bytes_per_sec: 0,
    }];
    let _ingress = spawn_agent(ingress_cfg);

    let ingress_addr: SocketAddr = format!("127.0.0.1:{ingress_port}").parse().unwrap();
    wait_for_tcp(ingress_addr, Duration::from_secs(15))
        .await
        .expect("ingress ready");

    let payload = b"cross-transport-payload";
    let resp = tcp_echo_retry(ingress_addr, payload, Duration::from_secs(15))
        .await
        .expect("h2 ingress -> quic egress tunnel");
    assert_eq!(resp, payload);
}

/// DATAGRAM fast path: a size matrix (small packets over QUIC DATAGRAM, over-
/// budget ones falling back to stream carriage).
///
/// The hub defaults to `quic.datagram_enabled = true`; after OpenAck, a quic
/// agent's UDP session sends small packets via `send_datagram` (budget 1023
/// whole frames); under mixed carriage on both sides, the datagram boundary is
/// still preserved by the frame payload_len, byte for byte identical.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn quic_udp_datagram_mixed_sizes() {
    let certs = TestCerts::generate("quic-e2e", "quic-egress");
    let (echo_addr, _echo) = spawn_udp_echo().await;
    let hub_port = pick_ephemeral_port();
    let _hub = spawn_hub(hub_quic_config(
        hub_port,
        &certs,
        vec![acl("ingress", "egress")],
    ))
    .await;

    let mut egress_cfg = agent_quic_config("egress", hub_port, &certs);
    egress_cfg.egress = vec![udp_egress_rule("echo", echo_addr)];
    let _egress = spawn_agent(egress_cfg);

    let ingress_port = pick_ephemeral_port();
    let mut ingress_cfg = agent_quic_config("ingress", hub_port, &certs);
    ingress_cfg.ingress = vec![udp_ingress_rule(
        "to-egress",
        format!("127.0.0.1:{ingress_port}").parse().unwrap(),
        "egress",
        Some(echo_addr),
    )];
    let _ingress = spawn_agent(ingress_cfg);

    let ingress_addr: SocketAddr = format!("127.0.0.1:{ingress_port}").parse().unwrap();

    // Within budget (< 1023 whole frame) goes via DATAGRAM; over budget falls
    // back to stream carriage — the two paths mixed
    for size in [64usize, 512, 900, 1500, 4096, 65000] {
        let payload: Vec<u8> = (0..size).map(|i| (i % 251) as u8).collect();
        let resp = udp_echo_round_trip(ingress_addr, &payload, Duration::from_secs(15))
            .await
            .unwrap_or_else(|e| panic!("size {size}: {e}"));
        assert_eq!(resp.len(), size, "size {size}: no truncation");
        assert_eq!(
            resp, payload,
            "size {size}: byte-for-byte identical (mixed carriage)"
        );
    }
}

// ---------------------------------------------------------------------------
// T5: mTLS matrix
// ---------------------------------------------------------------------------

/// Under mTLS, a client certificate with a matching CN registers successfully
/// and sends/receives normally.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn quic_mtls_valid_client_cert() {
    let certs = TestCerts::generate("quic-e2e", "quic-egress");
    let (echo_addr, _echo) = echo_server().await;
    let hub_port = pick_ephemeral_port();

    let mut hub_cfg = hub_quic_config(hub_port, &certs, vec![acl("ingress", "quic-egress")]);
    hub_cfg.auth = AuthConfig {
        mode: AuthMode::Mtls,
        allow_anonymous: false,
        rate_limit_per_minute: 0,
        static_token: None,
        mtls: Some(MtlsConfig {
            ca_path: certs.ca_path().display().to_string(),
        }),
    };
    let _hub = spawn_hub(hub_cfg).await;

    // quic egress (client certificate with CN = quic-egress)
    let (client_cert, client_key) = certs.client_paths();
    let mut egress_cfg = agent_quic_config("quic-egress", hub_port, &certs);
    egress_cfg.agent.id = "quic-egress".to_string();
    egress_cfg.egress = vec![EgressRule {
        name: "echo".to_string(),
        target_addr: echo_addr,
        target_protocol: StreamProto::Tcp,
        udp_idle_timeout_secs: None,
    }];
    egress_cfg.tls = Some(AgentTlsConfig {
        enabled: true,
        ca_path: Some(certs.ca_path().display().to_string()),
        client_cert_path: Some(client_cert.display().to_string()),
        client_key_path: Some(client_key.display().to_string()),
        hub_cert_fingerprint: None,
    });
    let _egress = spawn_agent(egress_cfg);

    // quic ingress (a client certificate with CN=ingress issued by the same
    // CA)
    let (ingress_cert, ingress_key) = certs.named_client_cert("ingress");
    let ingress_port = pick_ephemeral_port();
    let mut ingress_cfg = agent_quic_config("ingress", hub_port, &certs);
    ingress_cfg.ingress = vec![IngressRule {
        name: "to-egress".to_string(),
        listen_addr: format!("127.0.0.1:{ingress_port}").parse().unwrap(),
        listen_protocol: StreamProto::Tcp,
        target_agent: "quic-egress".to_string(),
        remote_addr: Some(echo_addr.to_string()),
        idle_timeout_secs: None,
        udp_per_ip_pps: 0,
        udp_per_ip_bytes_per_sec: 0,
        udp_egress_bytes_per_sec: 0,
    }];
    ingress_cfg.tls = Some(AgentTlsConfig {
        enabled: true,
        ca_path: Some(certs.ca_path().display().to_string()),
        client_cert_path: Some(ingress_cert.display().to_string()),
        client_key_path: Some(ingress_key.display().to_string()),
        hub_cert_fingerprint: None,
    });
    let _ingress = spawn_agent(ingress_cfg);

    let ingress_addr: SocketAddr = format!("127.0.0.1:{ingress_port}").parse().unwrap();
    wait_for_tcp(ingress_addr, Duration::from_secs(15))
        .await
        .expect("ingress ready");

    let payload = b"mtls-quic-payload";
    let resp = tcp_echo_retry(ingress_addr, payload, Duration::from_secs(15))
        .await
        .expect("mTLS + QUIC round trip");
    assert_eq!(resp, payload);
}

/// Under mTLS, a client certificate with a mismatched CN is rejected: agent
/// registration fails (connection closed).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn quic_mtls_cn_mismatch_rejected() {
    let certs = TestCerts::generate("quic-e2e", "quic-egress");
    let hub_port = pick_ephemeral_port();

    let mut hub_cfg = hub_quic_config(hub_port, &certs, vec![]);
    hub_cfg.auth = AuthConfig {
        mode: AuthMode::Mtls,
        allow_anonymous: false,
        rate_limit_per_minute: 0,
        static_token: None,
        mtls: Some(MtlsConfig {
            ca_path: certs.ca_path().display().to_string(),
        }),
    };
    let _hub = spawn_hub(hub_cfg).await;

    // Certificate with CN = quic-egress, but the agent id claims ingress →
    // must be rejected
    let (client_cert, client_key) = certs.client_paths();
    let mut cfg = agent_quic_config("ingress", hub_port, &certs);
    cfg.tls = Some(AgentTlsConfig {
        enabled: true,
        ca_path: Some(certs.ca_path().display().to_string()),
        client_cert_path: Some(client_cert.display().to_string()),
        client_key_path: Some(client_key.display().to_string()),
        hub_cert_fingerprint: None,
    });

    let client = interflow_mesh::agent::AgentClient::new(cfg).expect("agent build");
    let handle = client.start();
    // Registration rejected → connection closed by the hub → the session
    // fails and loops reconnecting (failing forever)
    tokio::time::sleep(Duration::from_secs(5)).await;
    use interflow_mesh::agent::AgentState;
    let state = handle.state();
    assert!(
        !matches!(state, AgentState::Connected { .. }),
        "QUIC registration with a mismatched CN must fail (actual state: {state:?})"
    );
    let _ = handle.shutdown_graceful().await;
}

// ---------------------------------------------------------------------------
// T12: disconnect eviction and recovery
// ---------------------------------------------------------------------------

/// After a QUIC egress is gracefully shut down (connection drops → watcher
// evicts), re-registration restores forwarding.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn quic_disconnect_evicts_and_recovers() {
    let certs = TestCerts::generate("quic-e2e", "quic-egress");
    let (echo_addr, _echo) = echo_server().await;
    let hub_port = pick_ephemeral_port();
    let _hub = spawn_hub(hub_quic_config(
        hub_port,
        &certs,
        vec![acl("ingress", "egress")],
    ))
    .await;

    let mut egress_cfg = agent_quic_config("egress", hub_port, &certs);
    egress_cfg.egress = vec![EgressRule {
        name: "echo".to_string(),
        target_addr: echo_addr,
        target_protocol: StreamProto::Tcp,
        udp_idle_timeout_secs: None,
    }];

    let handle1 = {
        let client = interflow_mesh::agent::AgentClient::new(egress_cfg.clone()).expect("build");
        client.start()
    };
    // Wait for QUIC registration (no listening port to probe — allow enough
    // time for the handshake)
    tokio::time::sleep(Duration::from_secs(3)).await;

    let ingress_port = pick_ephemeral_port();
    let mut ingress_cfg = agent_quic_config("ingress", hub_port, &certs);
    ingress_cfg.ingress = vec![IngressRule {
        name: "to-egress".to_string(),
        listen_addr: format!("127.0.0.1:{ingress_port}").parse().unwrap(),
        listen_protocol: StreamProto::Tcp,
        target_agent: "egress".to_string(),
        remote_addr: Some(echo_addr.to_string()),
        idle_timeout_secs: None,
        udp_per_ip_pps: 0,
        udp_per_ip_bytes_per_sec: 0,
        udp_egress_bytes_per_sec: 0,
    }];
    let _ingress = spawn_agent(ingress_cfg);

    let ingress_addr: SocketAddr = format!("127.0.0.1:{ingress_port}").parse().unwrap();
    wait_for_tcp(ingress_addr, Duration::from_secs(15))
        .await
        .expect("ingress ready");

    let payload = b"before-disconnect";
    let resp = tcp_echo_retry(ingress_addr, payload, Duration::from_secs(15))
        .await
        .expect("initial round trip");
    assert_eq!(resp, payload);

    // Shut down the egress → QUIC connection drops → watcher evicts (clears
    // the registry + orphan streams)
    let _ = handle1.shutdown_graceful().await;
    tokio::time::sleep(Duration::from_secs(3)).await;

    // After eviction: ingress stream establishment fails fast (no reply /
    // connection refused)
    let denied = tcp_echo_retry(ingress_addr, b"while-down", Duration::from_millis(2000)).await;
    assert!(
        denied.is_err(),
        "must fail fast after the egress is evicted"
    );

    // Restart the egress → recovery
    let handle2 = {
        let client = interflow_mesh::agent::AgentClient::new(egress_cfg).expect("build");
        client.start()
    };
    let payload2 = b"after-recovery";
    let resp2 = tcp_echo_retry(ingress_addr, payload2, Duration::from_secs(15))
        .await
        .expect("recovery round trip");
    assert_eq!(resp2, payload2);
    let _ = handle2;
}

// ---------------------------------------------------------------------------
// Regressions (backlog §1.7 regression-coverage audit, 2026-09-14): Close
// sentinel + silent-death detection
// ---------------------------------------------------------------------------

/// Assert the client connection is torn down by the tunnel side (EOF / error)
/// within `budget`, rather than silently hanging.
///
/// "Must fail before the fix" anchor: when the Close frame's `_close_`
/// sentinel is lost (mislabeled with an agent name), the source agent's
/// dispatch drops it as a late request-direction frame, and the client
/// connection hangs until the idle timeout (on the order of 300s) — the
/// silent-hang shape fixed by a59e0a7.
async fn assert_conn_torn_down(sock: &mut tokio::net::TcpStream, budget: Duration, what: &str) {
    use tokio::io::AsyncReadExt;

    let mut buf = [0u8; 64];
    match tokio::time::timeout(budget, sock.read(&mut buf)).await {
        Ok(Ok(0)) | Ok(Err(_)) => return, // EOF / connection error = torn down
        Ok(Ok(n)) => panic!("{what}: unexpectedly received {n} reply bytes before teardown"),
        Err(_) => panic!(
            "{what}: connection not torn down within {budget:?} (silent hang — the lost-Close-sentinel shape)"
        ),
    }
}

/// Regression (a59e0a7 synchronous-rejection path, reproduced live in the soak
/// on 2026-09-13): the Close frame on the QUIC synchronous-failure path must
/// use the `_close_` sentinel — when the target is unregistered, a Close
/// written back by `write_close_frame` that mislabels the source (e.g. "hub")
/// gets dropped by the source agent's dispatch as a late request-direction
/// frame, and the client connection silently hangs until the idle timeout.
/// This case must fail before the fix; the h2 twin assertion lives in
/// e2e_stream_limits.rs, and the QUIC side was previously covered only by the
/// soak guard.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn quic_open_to_unregistered_target_closes_client_connection() {
    let certs = TestCerts::generate("quic-close-sentinel", "ingress");
    let hub_port = pick_ephemeral_port();
    let _hub = spawn_hub(hub_quic_config(hub_port, &certs, vec![])).await;

    // The ingress's target points at an agent that never registers — the Open
    // must go down the hub's synchronous-rejection path
    let ingress_port = pick_ephemeral_port();
    let mut ingress_cfg = agent_quic_config("ingress", hub_port, &certs);
    ingress_cfg.ingress = vec![tcp_ingress_rule(
        "to-missing",
        format!("127.0.0.1:{ingress_port}").parse().unwrap(),
        "missing",
        None,
    )];
    let _ingress = spawn_agent(ingress_cfg);

    let ingress_addr: SocketAddr = format!("127.0.0.1:{ingress_port}").parse().unwrap();
    wait_for_tcp(ingress_addr, Duration::from_secs(15))
        .await
        .expect("ingress ready");

    let mut sock = tokio::net::TcpStream::connect(ingress_addr)
        .await
        .expect("connect ingress");
    {
        use tokio::io::AsyncWriteExt;
        // Trigger stream establishment; if the Open was already sent at
        // accept time and already rejected, a write failure is the teardown
        // evidence
        let _ = sock.write_all(b"trigger-open").await;
    }
    assert_conn_torn_down(
        &mut sock,
        Duration::from_secs(5),
        "an Open rejected for an unregistered target must tear down the client connection",
    )
    .await;
}

/// Regression (a59e0a7 teardown back-fill path): the Close + FIN back-filled
/// by `relay_stream_writer` when the hub evicts orphan streams must likewise
/// use the `_close_` sentinel — after the target agent disconnects (connection
/// watcher evicts → orphan streams cleared → relay channel dropped), the
/// source-side client connection should be torn down promptly rather than
/// hang. This case must fail before the fix.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn quic_target_agent_disconnect_tears_down_source_client_connections() {
    let certs = TestCerts::generate("quic-close-sentinel", "egress");
    let (echo_addr, _echo) = echo_server().await;
    let hub_port = pick_ephemeral_port();
    let _hub = spawn_hub(hub_quic_config(
        hub_port,
        &certs,
        vec![acl("ingress", "egress")],
    ))
    .await;

    let mut egress_cfg = agent_quic_config("egress", hub_port, &certs);
    egress_cfg.egress = vec![tcp_egress_rule("echo", echo_addr)];
    let egress = spawn_agent(egress_cfg);

    let ingress_port = pick_ephemeral_port();
    let mut ingress_cfg = agent_quic_config("ingress", hub_port, &certs);
    ingress_cfg.ingress = vec![tcp_ingress_rule(
        "to-egress",
        format!("127.0.0.1:{ingress_port}").parse().unwrap(),
        "egress",
        Some(echo_addr),
    )];
    let _ingress = spawn_agent(ingress_cfg);

    let ingress_addr: SocketAddr = format!("127.0.0.1:{ingress_port}").parse().unwrap();
    wait_for_tcp(ingress_addr, Duration::from_secs(15))
        .await
        .expect("ingress ready");

    // Establish one long-lived stream (successful echo round trip = the
    // stream is up); retries absorb the egress registration latency, and the
    // successful connection is kept for the assertions below
    let payload = b"before-target-death";
    let mut sock = {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        use tokio::net::TcpStream;
        let deadline = tokio::time::Instant::now() + Duration::from_secs(15);
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
                Err(e) => {
                    assert!(
                        tokio::time::Instant::now() < deadline,
                        "initial echo round trip failed: {e}"
                    );
                    tokio::time::sleep(Duration::from_millis(200)).await;
                }
            }
        }
    };

    // Kill the target agent: QUIC connection drops → hub watcher evicts and
    // clears orphan streams → the source-side relay write task back-fills
    // `_close_` + FIN → the client connection is torn down
    let _ = egress.shutdown_graceful().await;
    assert_conn_torn_down(
        &mut sock,
        Duration::from_secs(10),
        "the source-side client connection must be torn down after the target agent disconnects",
    )
    .await;
}

/// Regression (the literal e478c4d shape): when the hub dies **silently** (no
/// CONNECTION_CLOSE delivered), an idle QUIC agent must not linger in
/// Connected. The existing acceptance (e2e_hub_shutdown.rs) covers only the
/// graceful-shutdown path; this case uses a UDP black hole to produce a silent
/// death, covering the quinn idle timeout (30s) + keepalive (10s) constant
/// wiring (core quic.rs:43/45) and the independent `closed()` observer.
/// Before the fix (the read loop exiting silently with no observer to end the
/// session), it stayed Connected forever — this case must fail. Runtime
/// ~35-45s: the constants are hardcoded in core and cannot be injected at the
/// integration-test tier.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn quic_hub_silent_death_idle_agent_leaves_connected() {
    use interflow_mesh::agent::AgentState;
    use interflow_testkit::impair::{ImpairConfig, UdpImpairProxy};
    use interflow_testkit::wait_agent_connected;

    let certs = TestCerts::generate("quic-blackhole", "idle-agent");
    let hub_port = pick_ephemeral_port();
    let _hub = spawn_hub(hub_quic_config(hub_port, &certs, vec![])).await;

    // Pass-through impairment proxy: all of the agent's QUIC traffic reaches
    // the hub through it (zero latency, zero loss)
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

    let mut cfg = agent_quic_config("idle-agent", hub_port, &certs);
    cfg.agent.hub_quic_addr = Some(proxy.local_addr().to_string());
    let agent = spawn_agent(cfg);

    assert!(
        wait_agent_connected(&agent, Duration::from_secs(15)).await,
        "the agent must complete registration through the proxy"
    );

    // Black hole: the proxy stops forwarding, so no CONNECTION_CLOSE reaches
    // the hub side — the agent can only detect death via its local idle
    // timeout
    proxy.shutdown().await;

    // Death-detection chain: 30s without inbound packets → quinn idle timeout
    // → closed() observer → session ends → the supervisor leaves Connected.
    // Budget = idle 30s + headroom.
    let deadline = tokio::time::Instant::now() + Duration::from_secs(45);
    loop {
        let state = agent.state();
        if !matches!(state, AgentState::Connected { .. }) {
            // Any state leaving Connected is the death signal; the proxy is
            // dead, so subsequent reconnect attempts necessarily fail and
            // staying in a Reconnecting/Connecting loop is expected
            assert!(
                !matches!(state, AgentState::Stopped | AgentState::Failed { .. }),
                "silent death should trigger reconnection, not termination (actual state: {state:?})"
            );
            break;
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "agent still lingering in Connected 45s after the black hole (idle timeout / closed() observer broken)"
        );
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
}

/// TCP echo with retries (absorbs registration/session-establishment
/// latency).
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
            Ok(Err(e)) => {
                // Transient errors like connection refused: back off and
                // retry
                tokio::time::sleep(Duration::from_millis(200)).await;
                let _ = e;
            }
            Err(_) => {
                tokio::time::sleep(Duration::from_millis(200)).await;
            }
        }
    }
}
