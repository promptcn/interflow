//! e2e: route breaker closed **ahead of its cooldown** by the agent's
//! out-of-band recovery notice — the 2026-10-18 active-recovery root cure
//!
//! The residual window this test pins: an outage SHORTER than the route
//! breaker's cooldown. Both breakers trip while the backend is dead (the
//! agent's target breaker on dial failures, the edge's route breaker on
//! the relayed `connect_failed` evidence); the backend then revives well
//! inside the edge cooldown. Pre-fix, public recovery waited out the full
//! remaining edge cooldown — the "local up, public 502 for tens of
//! seconds" false-failure window (the dev-server-restart picture).
//!
//! The cure under test, end to end: the remote agent's bare-TCP recovery
//! prober notices the backend answering within ~1s, `note_success`-closes
//! its own entry (no stream budget consumed), and pushes the
//! `TargetRecovered` notice over the session control plane; the embedded
//! hub hands it to the edge's recovery sink, which closes the route
//! breaker entry for the sender's matching route. The decisive assertion:
//! `interflow_edge_route_breaker_transitions_total{state="closed"}` fires
//! **while the edge cooldown provably has not elapsed** — with a 30s
//! cooldown and a ~6s observation budget, no cooldown-path recovery can
//! masquerade as this signal, and no probe stream can have been admitted
//! (every public request during OPEN is gate-rejected zero-byte).
//!
//! Separate binary from `edge_route_breaker_recovery.rs` (same recorder
//! discipline: process-global counters, absolute-value assertions).

#![allow(
    clippy::all,
    clippy::pedantic,
    clippy::nursery,
    clippy::panic,
    clippy::unwrap_used,
    clippy::expect_used,
    missing_docs
)]
use interflow_expose::client::ExposeArgs;
use interflow_expose::edge::{
    ControlEndpointTls, EdgeConfig, EdgeListenerPolicy, IngressPrincipal, Route,
    RouteBreakerPolicy, WorkspaceTrust,
};
use interflow_mesh::config::TransportKind;
use interflow_testkit::metrics_harness::{metrics_handle, wait_counter_at_least};
use std::net::SocketAddr;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

/// The edge route breaker's cooldown for this test — deliberately long:
/// it must provably NOT elapse inside the observation budget, so the only
/// possible source of a `state="closed"` transition is the pushed notice.
const EDGE_COOLDOWN: Duration = Duration::from_secs(30);
/// Observation budget from backend revival to route-closed: generous over
/// the prober's ~1-2s lane, far below the cooldown.
const RECOVERY_BUDGET: Duration = Duration::from_secs(8);

async fn dead_port() -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    drop(listener);
    port
}

/// Minimal HTTP/1.1 responder serving `200 OK` with body `ok` (same shape
/// as `edge_route_breaker_recovery.rs`).
async fn http_ok_backend(port: u16) -> std::io::Result<()> {
    let listener = TcpListener::bind(("127.0.0.1", port)).await?;
    loop {
        let (mut sock, _) = match listener.accept().await {
            Ok(x) => x,
            Err(_) => continue,
        };
        let mut buf = vec![0u8; 4096];
        let _ = tokio::time::timeout(Duration::from_secs(2), async {
            loop {
                let n = sock.read(&mut buf).await.unwrap_or(0);
                if n == 0 || buf[..n].windows(4).any(|w| w == b"\r\n\r\n") {
                    break;
                }
            }
        })
        .await;
        sock.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok")
            .await?;
        let _ = sock.shutdown().await;
    }
}

/// One public request; returns the bytes read (headers + body).
async fn one_request(edge: SocketAddr, host: &str) -> std::io::Result<Vec<u8>> {
    let mut sock = TcpStream::connect(edge).await?;
    sock.write_all(
        format!("GET / HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n").as_bytes(),
    )
    .await?;
    let mut got = Vec::new();
    let mut buf = [0u8; 1024];
    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    loop {
        if got.starts_with(b"HTTP/1.1 200") && got.ends_with(b"ok") {
            break;
        }
        let n = tokio::time::timeout_at(deadline, sock.read(&mut buf)).await??;
        if n == 0 {
            break;
        }
        got.extend_from_slice(&buf[..n]);
    }
    Ok(got)
}

/// One bounded control-plane snapshot query (the eventually probes must
/// not hang past their own budgets — an unbounded probe would defeat the
/// deadline).
async fn snapshot_bounded(
    endpoint: &str,
    ca: &std::path::Path,
    cert: &std::path::Path,
    key: &std::path::Path,
) -> Result<interflow_mesh::hub::snapshot::FleetSnapshotDoc, String> {
    tokio::time::timeout(
        Duration::from_secs(5),
        interflow_mesh::hub::snapshot::query_fleet_snapshot(endpoint, ca, cert, key),
    )
    .await
    .map_err(|_| "snapshot query timed out".to_string())?
    .map_err(|e| e.to_string())
}

/// Outage shorter than the cooldown: both breakers trip, the backend
/// revives at once, and the pushed recovery notice closes the route
/// breaker ahead of its cooldown — the public face is back within seconds.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn route_breaker_closes_ahead_of_cooldown_by_pushed_notice() {
    let _ = metrics_handle();
    let _ = tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "warn".into()),
        )
        .try_init();

    let backend_port = dead_port().await;

    let certs = interflow_testkit::certs::TestCerts::generate("e2e", "expose-push-recovery");
    let (principal_cert, principal_key) = certs.named_client_cert("edge");
    // A second CA trusted under the control tenant — the production
    // packs' realm-issuer trust in test shape, so the hub-row assertions
    // below can query `/snapshot` as a control-plane principal (the same
    // CA under two tenants would be ambiguous; the verifier rejects it).
    let ctl_certs = interflow_testkit::certs::TestCerts::generate("e2e-ctl", "doctor");
    let edge_config = EdgeConfig {
        listen_addr: "127.0.0.1:0".parse().unwrap(),
        control_listen_addr: "127.0.0.1:0".parse().unwrap(),
        control_tls: ControlEndpointTls {
            cert: certs.server_cert_path(),
            key: certs.server_key_path(),
        },
        workspace_trust: vec![
            WorkspaceTrust {
                workspace: "test".to_string(),
                ca: certs.ca_path(),
            },
            // The second test CA trusted under the control tenant —
            // the production packs' realm-issuer trust in test shape, so
            // the hub-row assertions below can query `/snapshot` as a
            // control-plane principal.
            WorkspaceTrust {
                workspace: "control".to_string(),
                ca: ctl_certs.ca_path(),
            },
        ],
        principals: vec![IngressPrincipal {
            workspace: "test".to_string(),
            cert: principal_cert,
            key: principal_key,
        }],
        routes: vec![Route {
            host: "push.local".to_string(),
            workspace: "test".to_string(),
            agent_id: "expose-push-recovery".to_string(),
            service_id: "web".to_string(),
        }],
        listener: EdgeListenerPolicy {
            route_breaker: RouteBreakerPolicy {
                // Above the agent-side threshold (5, the egress default):
                // production ordering has the AGENT breaker trip first so
                // the later storm requests arrive as `target_circuit_open`
                // (soft evidence — counts toward tripping, never re-arms),
                // which is the §3.3 interlock shape this scenario needs.
                // (An edge threshold below the agent's would choke the
                // dial-failure evidence flow and the agent entry would
                // never trip — nothing for the prober to recover.)
                failure_threshold: 6,
                cooldown_secs: EDGE_COOLDOWN.as_secs(),
                ..RouteBreakerPolicy::default()
            },
            ..EdgeListenerPolicy::default()
        },
        agent_recovery_timeout: Duration::from_secs(120),
        ..EdgeConfig::default()
    };
    let edge = interflow_testkit::spawn_edge(edge_config).await;
    let edge_listen = edge.public_addr();
    let hub_port = edge.control_addr().port();

    // The remote expose client: its agent engine runs BOTH egress defenses
    // (the target breaker, default 5/10s/30s) and the recovery prober
    // (default on, loopback 1s) — the production shape of a site node.
    let (client_cert, client_key) = certs.named_client_cert("expose-push-recovery");
    let client_args = ExposeArgs {
        log_name: None,
        service_addresses: interflow_mesh::config::ServiceAddresses::of(
            &[("web", format!("127.0.0.1:{backend_port}").parse().unwrap())],
            &[],
        ),
        pack_dir: None,
        hub_url: format!("https://127.0.0.1:{hub_port}"),
        client_cert: Some(client_cert.display().to_string()),
        client_key: Some(client_key.display().to_string()),
        agent_id: "expose-push-recovery".into(),
        ingress_ca_path: Some(certs.ca_path().display().to_string()),
        ca_path: Some(certs.ca_path().display().to_string()),
        transport: TransportKind::H2,
        hub_quic_addr: None,
        identity_offline: false,
        renewal_face: None,
    };
    let client = interflow_expose::client::start(&client_args).expect("expose client start");
    assert!(
        interflow_testkit::wait_agent_connected(&client, Duration::from_secs(5)).await,
        "expose client should register within 5s"
    );
    let client_handle = tokio::task::spawn(async move { client.join().await });

    // Phase 1 — the outage: a dead-backend storm trips both breakers in
    // the production order: the first 5 requests dial at the agent and
    // fail (≥ its default threshold 5 → the agent breaker trips), the
    // remaining 5 are refused pre-dial as `target_circuit_open` (soft
    // evidence at the edge → ≥6 events trips the route breaker).
    for _ in 0..10u32 {
        let mut sock = TcpStream::connect(edge_listen).await.expect("connect edge");
        sock.write_all(b"GET / HTTP/1.1\r\nHost: push.local\r\nConnection: close\r\n\r\n")
            .await
            .expect("write request");
        match tokio::time::timeout(Duration::from_secs(3), sock.read_u8()).await {
            Ok(Err(e))
                if matches!(
                    e.kind(),
                    std::io::ErrorKind::UnexpectedEof | std::io::ErrorKind::ConnectionReset
                ) => {}
            Ok(Ok(b)) => panic!("dead backend must not serve bytes (got {b:#x})"),
            Ok(Err(e)) => panic!("unexpected io error: {e}"),
            Err(_) => panic!("connection did not close out within 3s"),
        }
    }
    wait_counter_at_least(
        "interflow_edge_route_breaker_transitions_total{state=\"open\"}",
        1,
        Duration::from_secs(5),
    )
    .await;
    wait_counter_at_least(
        "interflow_edge_route_breaker_rejected",
        1,
        Duration::from_secs(5),
    )
    .await;

    // The open-set face (2026-10-19): the embedded hub's snapshot hub row
    // carries the OPEN route host with its trip instant — legible without
    // the metrics face.
    let (ca, ctl_cert, ctl_key) = {
        let (cert, key) = ctl_certs.named_client_cert("doctor");
        (certs.ca_path(), cert, key)
    };
    let hub_endpoint = format!("127.0.0.1:{hub_port}");
    let open_row = interflow_testkit::wait::eventually_async(
        "the snapshot hub row reports the OPEN route host",
        Duration::from_secs(10),
        || async {
            let doc = snapshot_bounded(&hub_endpoint, &ca, &ctl_cert, &ctl_key).await?;
            doc.hub
                .route_breakers_open
                .iter()
                .find(|row| row.host == "push.local")
                .cloned()
                .ok_or_else(|| format!("no OPEN row for push.local: {:?}", doc.hub))
        },
    )
    .await;
    assert!(open_row.opened_unix > 0, "the trip instant is populated");

    // Phase 2 — the outage ends immediately (revival lands well inside the
    // edge cooldown; this is exactly the residual window). The agent-side
    // prober closes the agent's entry and pushes the notice; the edge's
    // sink must close the route entry.
    let backend_handle = tokio::task::spawn(http_ok_backend(backend_port));
    interflow_testkit::wait_for_tcp(
        format!("127.0.0.1:{backend_port}").parse().unwrap(),
        Duration::from_secs(5),
    )
    .await
    .expect("backend should come back up");
    let revived_since = std::time::Instant::now();
    wait_counter_at_least(
        "interflow_edge_route_breaker_transitions_total{state=\"closed\"}",
        1,
        RECOVERY_BUDGET,
    )
    .await;
    assert!(
        revived_since.elapsed() < EDGE_COOLDOWN,
        "route closed at {:?} — the {EDGE_COOLDOWN:?} cooldown provably had not elapsed, \
         so the transition's only possible producer is the pushed notice",
        revived_since.elapsed()
    );

    // The open-set face follows the recovery down: the row disappears
    // from the snapshot hub row (the pushed notice's observable twin).
    interflow_testkit::wait::eventually_async(
        "the snapshot hub row drops the recovered route host",
        Duration::from_secs(10),
        || async {
            let doc = snapshot_bounded(&hub_endpoint, &ca, &ctl_cert, &ctl_key).await?;
            if doc
                .hub
                .route_breakers_open
                .iter()
                .any(|row| row.host == "push.local")
            {
                Err("push.local still OPEN in the hub row".to_string())
            } else {
                Ok(())
            }
        },
    )
    .await;

    // Phase 3 — the public face is back: an immediate request round-trips
    // (and would keep doing so; one is enough — the burst shape is the
    // sibling suite's concern).
    let resp = one_request(edge_listen, "push.local")
        .await
        .expect("request after pushed recovery must succeed");
    assert!(
        resp.starts_with(b"HTTP/1.1 200") && resp.ends_with(b"ok"),
        "post-recovery response malformed: {resp:?}"
    );

    // Teardown order: the external client and backend go FIRST — the
    // edge's cooperative shutdown then drains without a live poll
    // connection to wait out (the assertion phases are all complete by
    // here; only cleanup ordering, no semantics).
    client_handle.abort();
    backend_handle.abort();
    edge.shutdown().await.expect("edge shutdown");
}
