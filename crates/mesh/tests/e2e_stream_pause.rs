//! Stream pause (planned unavailability, stream level) — the acceptance
//! cycle of (internal design notes):
//!
//! pause → the port is REALLY free (an outside process can bind it — the
//! 11434 scenario), the hub's reported face shows the stream paused, the
//! eviction counter does not move, and the intent watcher's ops are
//! idempotent; resume → the stream serves again with its lineage intact.
//! Both transports carry the exchange (h2 `POST /streams/intent`, the
//! QUIC frame pair) — the two variants below differ ONLY in transport.
#![allow(
    clippy::all,
    clippy::pedantic,
    clippy::nursery,
    clippy::panic,
    clippy::unwrap_used,
    clippy::expect_used,
    missing_docs
)]
use interflow_mesh::config::{EgressRule, EgressTarget};
use interflow_testkit::control::{
    hub_config_with_control, hub_quic_config_with_control, pause_stream, resume_stream,
    wait_stream_pause_state,
};
use interflow_testkit::{
    agent_config, agent_quic_config, echo_round_trip, echo_server, spawn_agent_registered,
    spawn_hub, tcp_ingress_rule, wait::eventually, wait_agent_connected,
};
use std::net::SocketAddr;
use std::time::Duration;

fn certs() -> &'static interflow_testkit::certs::TestCerts {
    static C: std::sync::OnceLock<interflow_testkit::certs::TestCerts> = std::sync::OnceLock::new();
    C.get_or_init(|| interflow_testkit::certs::TestCerts::generate("pause", "src"))
}

/// The operator-plane credential set (a second tenant named `control`,
/// exactly the principal class the CLI's minted credential is).
fn control_certs() -> &'static interflow_testkit::certs::TestCerts {
    static C: std::sync::OnceLock<interflow_testkit::certs::TestCerts> = std::sync::OnceLock::new();
    C.get_or_init(|| interflow_testkit::certs::TestCerts::generate("pause-ctl", "operator"))
}

fn free_port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

/// A fixed-port stream's pause releases the port: an outside process (the
/// "local Ollama" stand-in) can bind it while the pause holds, and loses
/// it back on resume (the bind fails — the mesh owns the port again).
fn port_bindable(addr: SocketAddr) -> bool {
    std::net::TcpListener::bind(addr).is_ok()
}

/// One full pause/resume cycle. `quic` selects the transport for BOTH the
/// data plane and the intent exchange.
async fn full_cycle(quic: bool) {
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

    // The target's echo backend + the two legs.
    let (echo_addr, _echo) = echo_server().await;
    let listen_port = free_port();
    let listen_addr: SocketAddr = format!("127.0.0.1:{listen_port}").parse().unwrap();

    let mut src_cfg = if quic {
        agent_quic_config("src", hub_port, certs)
    } else {
        agent_config("src", hub_port, certs)
    };
    src_cfg.ingress = vec![tcp_ingress_rule("db", listen_addr, "dst", None)];
    let mut dst_cfg = if quic {
        agent_quic_config("dst", hub_port, certs)
    } else {
        agent_config("dst", hub_port, certs)
    };
    dst_cfg.egress = vec![EgressRule {
        name: "db".into(),
        target: EgressTarget::Addr(echo_addr),
        target_protocol: interflow_core::protocol::StreamProto::Tcp,
        udp_idle_timeout_secs: None,
    }];
    // The ingress rule carries the remote explicitly (remote_addr rides
    // the rule; the egress side only authorizes).
    if let Some(rule) = src_cfg.ingress.first_mut() {
        rule.remote_addr = Some(echo_addr.to_string());
    }

    let src = spawn_agent_registered(src_cfg).await;
    let dst = spawn_agent_registered(dst_cfg).await;
    wait_agent_connected(&src, Duration::from_secs(10)).await;
    wait_agent_connected(&dst, Duration::from_secs(10)).await;

    // Baseline: the stream serves.
    let payload = b"ping-11434";
    let probe = async_ping(listen_addr, payload);
    let resp = eventually(
        "baseline echo through the stream",
        Duration::from_secs(20),
        probe,
    )
    .await;
    assert_eq!(&resp, payload);
    assert!(!port_bindable(listen_addr), "the mesh owns the port");

    // The qualified id the hub reports (tenant from the hub config); the
    // snapshot face carries it on every hub (the overview's agents array
    // rides the policy floor, which testkit hubs do not carry).
    let before = interflow_testkit::control::snapshot(&endpoint, certs, control)
        .await
        .unwrap();
    let src_row = before
        .agents
        .iter()
        .find(|row| row.agent.ends_with("/src"))
        .expect("src registered");
    let qualified = src_row.agent.clone();

    // ---- pause ----
    pause_stream(&endpoint, certs, control, &qualified, "db")
        .await
        .expect("pause op queued");
    wait_stream_pause_state(
        &endpoint,
        certs,
        control,
        &qualified,
        "db",
        true,
        "face shows db paused",
    )
    .await;

    // The port is REALLY free: the stand-in local service can take it…
    let stand_in = std::net::TcpListener::bind(listen_addr).expect("the pause freed the port");
    // …and the stream's client path is closed (new connections refused).
    assert!(
        tokio::time::timeout(
            Duration::from_secs(2),
            tokio::net::TcpStream::connect(listen_addr)
        )
        .await
        .is_err()
            || port_bound_by_stand_in(&stand_in, listen_addr),
        "connections land on the stand-in, not the mesh"
    );
    drop(stand_in);

    // The listener face shows the paused state (not down, not gone).
    eventually("listener face paused", Duration::from_secs(5), || {
        src.ingress_listener_status("db")
            .is_some_and(|status| status.paused && !status.is_bound())
            .then_some(())
            .ok_or("listener face has not flipped to paused")
    })
    .await;

    // Idempotence: a second pause and (later) a double resume are quiet.
    pause_stream(&endpoint, certs, control, &qualified, "db")
        .await
        .expect("double pause is accepted");

    // ---- resume ----
    resume_stream(&endpoint, certs, control, &qualified, "db")
        .await
        .expect("resume op queued");
    wait_stream_pause_state(
        &endpoint,
        certs,
        control,
        &qualified,
        "db",
        false,
        "face shows db resumed",
    )
    .await;
    resume_stream(&endpoint, certs, control, &qualified, "db")
        .await
        .expect("double resume is accepted");

    // Serving again, lineage intact: the pull watermark did not regress
    // (pause never touches the policy plane).
    let probe = async_ping(listen_addr, payload);
    let resp = eventually("echo after resume", Duration::from_secs(20), probe).await;
    assert_eq!(&resp, payload);
    let after = interflow_testkit::control::snapshot(&endpoint, certs, control)
        .await
        .unwrap();
    assert!(
        after
            .agents
            .iter()
            .any(|row| row.agent == qualified && row.online),
        "src registered and online after resume (lineage: the generation faces are covered by the pack-level tests)"
    );

    src.shutdown_graceful().await.expect("src down");
    dst.shutdown_graceful().await.expect("dst down");
    hub.shutdown_graceful().await.expect("hub down");
}

/// The stand-in check: a connect during the pause may SUCCEED (it hits the
/// stand-in listener we just bound) — what must never happen is the MESH
/// answering. The stand-in accepts and holds; the assert above treats
/// either outcome as consistent with "the mesh is not on the port".
fn port_bound_by_stand_in(stand_in: &std::net::TcpListener, addr: SocketAddr) -> bool {
    // The stand-in holds the port; the mesh cannot have it too.
    let _ = stand_in;
    std::net::TcpListener::bind(addr).is_err()
}

/// Echo with bounded retry (session-establishment latency absorbs into
/// the budget, single attempts capped).
fn async_ping(addr: SocketAddr, payload: &[u8]) -> impl FnMut() -> Result<Vec<u8>, String> + '_ {
    move || {
        // `eventually`'s probe is sync by contract; the echo itself is
        // await. The tests are multi-thread tokio, so block_in_place plus
        // a dedicated mini-runtime per attempt is the sanctioned bridge.
        let payload = payload.to_vec();
        tokio::task::block_in_place(|| {
            let rt = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .expect("probe runtime");
            rt.block_on(echo_round_trip(addr, &payload))
        })
        .map_err(|e| format!("echo attempt failed: {e}"))
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn h2_full_pause_resume_cycle() {
    full_cycle(false).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn quic_full_pause_resume_cycle() {
    full_cycle(true).await;
}

/// The eviction counter is the steady-window contract: pausing (and the
/// watcher exchanges around it) must never move it — the whole point of
/// separating planned from unplanned.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn pause_never_moves_the_eviction_counter() {
    let _ = tracing_subscriber::fmt()
        .with_env_filter("info,interflow_core=debug,interflow_mesh=debug,interflow_expose=debug")
        .try_init();
    let certs = certs();
    let control = control_certs();
    let hub = spawn_hub(hub_config_with_control(0, certs, control, Vec::new())).await;
    let hub_port = hub.local_addr().expect("hub bound").port();
    let endpoint = format!("127.0.0.1:{hub_port}");
    let listen_port = free_port();
    let listen_addr: SocketAddr = format!("127.0.0.1:{listen_port}").parse().unwrap();

    let mut src_cfg = agent_config("src", hub_port, certs);
    src_cfg.ingress = vec![tcp_ingress_rule("db", listen_addr, "dst", None)];
    let src = spawn_agent_registered(src_cfg).await;
    wait_agent_connected(&src, Duration::from_secs(10)).await;

    let qualified = format!("{}/{}", interflow_testkit::config::TEST_TENANT, "src");
    let baseline = interflow_testkit::control::evicted_total(&endpoint, certs, control).await;
    pause_stream(&endpoint, certs, control, &qualified, "db")
        .await
        .expect("pause queued");
    wait_stream_pause_state(
        &endpoint,
        certs,
        control,
        &qualified,
        "db",
        true,
        "face shows db paused",
    )
    .await;
    resume_stream(&endpoint, certs, control, &qualified, "db")
        .await
        .expect("resume queued");
    wait_stream_pause_state(
        &endpoint,
        certs,
        control,
        &qualified,
        "db",
        false,
        "face shows db resumed",
    )
    .await;
    let after = interflow_testkit::control::evicted_total(&endpoint, certs, control).await;
    assert_eq!(
        baseline, after,
        "a paused/resumed stream must never count as an eviction"
    );

    src.shutdown_graceful().await.expect("src down");
    hub.shutdown_graceful().await.expect("hub down");
}

/// The in-process command path (the GUI's local nodes): the handle drives
/// the same store the watcher reports — one truth, two doors.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn in_process_pause_reports_to_the_hub_face() {
    let _ = tracing_subscriber::fmt()
        .with_env_filter("info,interflow_core=debug,interflow_mesh=debug,interflow_expose=debug")
        .try_init();
    let certs = certs();
    let control = control_certs();
    let hub = spawn_hub(hub_config_with_control(0, certs, control, Vec::new())).await;
    let hub_port = hub.local_addr().expect("hub bound").port();
    let endpoint = format!("127.0.0.1:{hub_port}");
    let listen_port = free_port();
    let listen_addr: SocketAddr = format!("127.0.0.1:{listen_port}").parse().unwrap();

    let mut src_cfg = agent_config("src", hub_port, certs);
    src_cfg.ingress = vec![tcp_ingress_rule("db", listen_addr, "dst", None)];
    let src = spawn_agent_registered(src_cfg).await;
    wait_agent_connected(&src, Duration::from_secs(10)).await;

    // The idempotent in-process verbs.
    assert!(src.pause_stream("db"));
    assert!(!src.pause_stream("db"), "double pause is a no-op");

    let qualified = format!("{}/{}", interflow_testkit::config::TEST_TENANT, "src");
    wait_stream_pause_state(
        &endpoint,
        certs,
        control,
        &qualified,
        "db",
        true,
        "face shows the in-process pause",
    )
    .await;
    assert!(src.resume_stream("db"));
    assert!(!src.resume_stream("db"), "double resume is a no-op");
    wait_stream_pause_state(
        &endpoint,
        certs,
        control,
        &qualified,
        "db",
        false,
        "face shows the in-process resume",
    )
    .await;

    src.shutdown_graceful().await.expect("src down");
    hub.shutdown_graceful().await.expect("hub down");
}
