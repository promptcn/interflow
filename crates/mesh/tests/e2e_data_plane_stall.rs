//! E2E: data-plane stall self-healing (regression tests for the 2026-09-13
//! incident where the agent data plane stalled for 7.5 hours).
//!
//! Incident shape: the hub heartbeat only proved the h2 connection layer was
//! alive (Pong travels via the /pong endpoint); when the poll/upload data
//! streams stalled, neither side could detect it — the agent did not rebuild
//! and the hub did not evict, a site-wide black hole for 7.5h.
//!
//! Fixed semantics (covered by this file):
//! 1. **Poll receive-side watchdog**: when the poll stream produces no frames
//!    at all for a long time (including heartbeat Pings) → the agent actively
//!    rebuilds the whole session (real hub + forced 2s watchdog; a fake hub
//!    reproduces the incident shape "Ping once then stall" and asserts self-
//!    healing);
//! 2. **Pong travels the upload data stream**: heartbeat replies return via
//!    /stream/up; one heartbeat cycle exercises both data paths;
//! 3. **Paired-deployment strictness**: a register response whose capability
//!    declaration fails to parse is a registration failure — the supervisor
//!    keeps retrying, the agent never reaches Connected;
//! 4. **Metric visibility**: heartbeat Ping/Pong counters grow with traffic
//!    (the direct countermeasure to the journal falling silent for 7.5h in
//!    the incident).

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
use bytes::{Bytes, BytesMut};
use http_body_util::{BodyExt, Full, StreamBody, combinators::BoxBody};
use hyper::body::Frame as HttpFrame;
use hyper::body::Incoming;
use hyper::header::CONTENT_TYPE;
use hyper::server::conn::http2;
use hyper::service::Service;
use hyper::{Request, Response, StatusCode};
use hyper_util::rt::{TokioExecutor, TokioIo};
use interflow_core::error::InterflowError;
use interflow_core::protocol::frame::{DecodeOutcome, FrameType, encode_frame};
use interflow_core::tunnel::PING_SOURCE;
use interflow_mesh::agent::{AgentClient, AgentState};
use interflow_mesh::config::{HeartbeatConfig, HubSecurityConfig};
use interflow_testkit::{
    agent_config, hub_config_tuned, pick_ephemeral_port, spawn_agent_registered, spawn_hub,
    wait_agent_connected,
};
use std::future::Future;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::task::{Context, Poll};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

fn certs() -> &'static interflow_testkit::certs::TestCerts {
    static C: std::sync::OnceLock<interflow_testkit::certs::TestCerts> = std::sync::OnceLock::new();
    C.get_or_init(|| interflow_testkit::certs::TestCerts::generate("e2e", "agent"))
}

// ---------------------------------------------------------------------------
// T1: real hub (heartbeats disabled → a legitimately silent poll stream) +
// forced 2s watchdog → session rebuild
// ---------------------------------------------------------------------------

#[tokio::test]
async fn forced_watchdog_rebuilds_session_on_real_hub() {
    let hub_port = pick_ephemeral_port();
    // Heartbeats disabled: the poll stream stays silent for a long time (no
    // Ping); at that point only the watchdog can distinguish stall from idle
    let hub_cfg = hub_config_tuned(
        hub_port,
        certs(),
        vec![],
        HubSecurityConfig::default(),
        HeartbeatConfig {
            enabled: false,
            ..HeartbeatConfig::default()
        },
    );
    let _hub = spawn_hub(hub_cfg).await;

    let mut cfg = agent_config("stall-real", hub_port, certs());
    cfg.agent.poll_idle_timeout_secs = Some(2);
    let agent = spawn_agent_registered(cfg).await;

    // Observe ~12s: we should see at least one round of
    // "stall → Reconnecting → Connected again"
    let mut rx = agent.subscribe_state();
    let deadline = tokio::time::Instant::now() + Duration::from_secs(12);
    let mut saw_stall_reconnect = false;
    let mut connected_rounds = 0usize;
    let mut was_connected = false;
    while tokio::time::Instant::now() < deadline {
        let st = rx.borrow_and_update().clone();
        match st {
            AgentState::Connected { .. } => {
                if !was_connected {
                    connected_rounds += 1;
                }
                was_connected = true;
            }
            AgentState::Reconnecting { reason, .. } => {
                if reason.contains("stall") {
                    saw_stall_reconnect = true;
                }
                was_connected = false;
            }
            _ => {}
        }
        if saw_stall_reconnect && connected_rounds >= 2 {
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    assert!(
        saw_stall_reconnect,
        "should observe a Reconnecting triggered by the poll data-plane stall"
    );
    assert!(
        connected_rounds >= 2,
        "after the watchdog fires, the session should be rebuilt and Connected again (actual {connected_rounds} rounds)"
    );
    assert!(matches!(agent.state(), AgentState::Connected { .. }));

    agent.shutdown_graceful().await.expect("agent shutdown");
}

// ---------------------------------------------------------------------------
// T2: a fake hub reproducing the incident shape (one Ping then the poll
// stream stalls while the connection layer stays healthy)
// ---------------------------------------------------------------------------

/// Capability mode of the fake hub.
#[derive(Clone, Copy, PartialEq)]
enum FakeMode {
    /// JSON capability declaration: heartbeat cadence.
    Modern,
    /// Plain-text "Registered" — an unparseable declaration.
    PlainText,
}

/// Fake-hub counters.
#[derive(Default)]
struct FakeCounts {
    registers: AtomicUsize,
    /// Pong frames received in the /stream/up frame stream (data-plane Pong).
    pongs_upload: AtomicUsize,
}

struct FakeHub {
    addr: SocketAddr,
    counts: Arc<FakeCounts>,
}

/// Start the fake hub: cleartext h2. `/poll` emits one Ping frame per request
/// then stalls forever (never ends the response, never registers a waker —
/// the connection and other streams are unaffected, precisely reproducing the
/// incident shape of "control plane alive, data plane dead").
async fn spawn_fake_hub(mode: FakeMode) -> FakeHub {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("fake hub bind");
    let addr = listener.local_addr().expect("fake hub addr");
    let counts = Arc::new(FakeCounts::default());

    let svc_counts = counts.clone();
    let svc = FakeHubSvc {
        mode,
        counts: svc_counts,
    };
    tokio::spawn(async move {
        loop {
            let Ok((stream, _)) = listener.accept().await else {
                break;
            };
            let svc = svc.clone();
            tokio::spawn(async move {
                let conn = http2::Builder::new(TokioExecutor::new())
                    .serve_connection(TokioIo::new(stream), svc);
                if let Err(e) = conn.await {
                    eprintln!("fake hub connection error: {e}");
                }
            });
        }
    });
    FakeHub { addr, counts }
}

fn full_body(bytes: impl Into<Bytes>) -> BoxBody<Bytes, InterflowError> {
    Full::new(bytes.into())
        .map_err(|never| match never {})
        .boxed()
}

fn hanging_body() -> BoxBody<Bytes, InterflowError> {
    // Pending forever without registering a waker: the stream stalls (the
    // real hub's death-signal semantics)
    StreamBody::new(futures::stream::poll_fn(|_cx: &mut Context<'_>| {
        Poll::Pending as Poll<Option<std::result::Result<HttpFrame<Bytes>, InterflowError>>>
    }))
    .boxed()
}

#[derive(Clone)]
struct FakeHubSvc {
    mode: FakeMode,
    counts: Arc<FakeCounts>,
}

impl Service<Request<Incoming>> for FakeHubSvc {
    type Response = Response<BoxBody<Bytes, InterflowError>>;
    type Error = std::convert::Infallible;
    type Future =
        Pin<Box<dyn Future<Output = std::result::Result<Self::Response, Self::Error>> + Send>>;

    fn call(&self, req: Request<Incoming>) -> Self::Future {
        let counts = self.counts.clone();
        let mode = self.mode;
        Box::pin(async move {
            let resp = match (req.method().as_str(), req.uri().path()) {
                ("POST", "/register") => {
                    counts.registers.fetch_add(1, Ordering::SeqCst);
                    match mode {
                        FakeMode::Modern => {
                            // Isomorphic with the hub's registration
                            // response (heartbeat 1s/2missed, but the test
                            // overrides the derived value with a fixed 1s
                            // watchdog)
                            let caps = r#"{"heartbeat":{"interval_secs":1,"max_missed":2}}"#;
                            Response::builder()
                                .status(StatusCode::OK)
                                .header(CONTENT_TYPE, "application/json")
                                .body(full_body(caps))
                                .unwrap()
                        }
                        FakeMode::PlainText => Response::builder()
                            .status(StatusCode::OK)
                            .body(full_body("Registered"))
                            .unwrap(),
                    }
                }
                ("GET", "/poll") => {
                    // One Ping frame then stall: the incident shape (the
                    // Ping's arrival proves the connection layer is alive;
                    // the long silence after it = data-plane stall)
                    let fired = std::sync::atomic::AtomicBool::new(false);
                    let body =
                        StreamBody::new(futures::stream::poll_fn(move |_cx: &mut Context<'_>| {
                            if !fired.swap(true, Ordering::SeqCst) {
                                let mut buf = BytesMut::new();
                                encode_frame(FrameType::Ping, 0, "", PING_SOURCE, &[], &mut buf)
                                    .expect("ping encode");
                                Poll::Ready(Some(Ok(HttpFrame::data(buf.freeze()))))
                            } else {
                                Poll::Pending
                            }
                        }))
                        .boxed();
                    Response::builder()
                        .status(StatusCode::OK)
                        .body(body)
                        .unwrap()
                }
                ("POST", "/stream/up") => {
                    // Incrementally decode upload frames and count data-plane
                    // Pongs; the response body hangs (same as the real hub)
                    let up_counts = counts.clone();
                    tokio::spawn(async move {
                        let mut body = req.into_body();
                        let mut buf = BytesMut::new();
                        while let Some(Ok(frame)) = body.frame().await {
                            let Ok(data) = frame.into_data() else {
                                continue;
                            };
                            buf.extend_from_slice(&data);
                            loop {
                                match interflow_core::protocol::frame::decode_frame(&mut buf) {
                                    DecodeOutcome::Ok(f) => {
                                        if f.frame_type == FrameType::Pong {
                                            up_counts.pongs_upload.fetch_add(1, Ordering::SeqCst);
                                        }
                                    }
                                    DecodeOutcome::Pending => break,
                                    DecodeOutcome::UnknownType {
                                        must_understand: false,
                                        ..
                                    } => {}
                                    DecodeOutcome::Error
                                    | DecodeOutcome::UnknownType {
                                        must_understand: true,
                                        ..
                                    } => return,
                                }
                            }
                        }
                    });
                    Response::builder()
                        .status(StatusCode::OK)
                        .body(hanging_body())
                        .unwrap()
                }
                _ => Response::builder()
                    .status(StatusCode::NOT_FOUND)
                    .body(full_body("not found"))
                    .unwrap(),
            };
            Ok(resp)
        })
    }
}

#[tokio::test]
async fn pinged_then_stalled_poll_stream_triggers_session_rebuild() {
    let fake = spawn_fake_hub(FakeMode::Modern).await;
    let port = fake.addr.port();

    let mut cfg = agent_config("stall-wedge", port, certs());
    cfg.agent.hub_url = format!("http://{}", fake.addr);
    // The fake hub speaks plain h2 (no TLS terminator); the mTLS fixture
    // must be stripped for these protocol-level cases.
    cfg.tls = None;
    cfg.agent.poll_idle_timeout_secs = Some(1);
    let agent = spawn_agent_registered(cfg).await;

    // Within the window: Ping received → data-plane Pong (via the upload
    // stream) → after 1s the watchdog → session rebuild → register again.
    // The control plane (connection layer) stays healthy throughout — the
    // exact incident shape.
    //
    // While waiting, record every stall-triggered backoff: each cycle is
    // "established → watchdog → *first* retry after an established session",
    // so under the consecutive-failure contract every backoff must sit at
    // the 1-2s floor. A growing backoff here means the supervisor stopped
    // resetting the counter on established sessions (the pre-fix behavior
    // ramped toward the 30s cap inside this window and blew the final
    // recovery budget below).
    let mut rx = agent.subscribe_state();
    let window_end = tokio::time::Instant::now() + Duration::from_secs(8);
    let mut stall_backoffs: Vec<u64> = Vec::new();
    while tokio::time::Instant::now() < window_end {
        if let AgentState::Reconnecting {
            reason,
            backoff_secs,
        } = rx.borrow_and_update().clone()
        {
            if reason.contains("stall") {
                stall_backoffs.push(backoff_secs);
            }
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }

    let registers = fake.counts.registers.load(Ordering::SeqCst);
    let pongs_upload = fake.counts.pongs_upload.load(Ordering::SeqCst);

    assert!(
        pongs_upload >= 1,
        "heartbeat Pongs should return via the upload data stream (actual {pongs_upload})"
    );
    assert!(
        registers >= 2,
        "the poll stall should trigger a watchdog session rebuild (registrations {registers} < 2)"
    );
    assert!(
        stall_backoffs.iter().all(|&s| s <= 2),
        "after an established session the watchdog rebuild is a first retry: backoff must stay at the 1-2s floor (observed {stall_backoffs:?})"
    );
    // Loop-health proof: against a permanently stalled fake hub the agent
    // keeps cycling "watchdog → rebuild → register". With the backoff
    // bounded at 2s (see above), a full cycle is ~1s watchdog + ≤2s backoff
    // + connect — well inside the 10s budget, so a timeout here means the
    // rebuild loop wedged rather than merely sitting out a long back-off.
    assert!(
        wait_agent_connected(&agent, Duration::from_secs(10)).await,
        "the rebuild loop should keep recovering to Connected (current state {:?})",
        agent.state()
    );

    agent.shutdown_graceful().await.expect("agent shutdown");
}

// ---------------------------------------------------------------------------
// T4: paired-deployment strictness — a register response whose capability
// declaration does not parse is a registration failure (no legacy fallback)
// ---------------------------------------------------------------------------

#[tokio::test]
async fn unparseable_register_body_fails_registration() {
    let fake = spawn_fake_hub(FakeMode::PlainText).await;

    let mut cfg = agent_config("stall-plaintext", fake.addr.port(), certs());
    cfg.agent.hub_url = format!("http://{}", fake.addr);
    // The fake hub speaks plain h2 (no TLS terminator); the mTLS fixture
    // must be stripped for these protocol-level cases.
    cfg.tls = None;
    let agent = AgentClient::new(cfg).expect("client build").start();

    tokio::time::sleep(Duration::from_secs(5)).await;

    let registers = fake.counts.registers.load(Ordering::SeqCst);
    let pongs_upload = fake.counts.pongs_upload.load(Ordering::SeqCst);

    assert!(
        registers >= 2,
        "an unparseable declaration must fail registration and keep the supervisor retrying (registrations {registers} < 2)"
    );
    assert!(
        !matches!(agent.state(), AgentState::Connected { .. }),
        "the agent must never reach Connected against a hub whose declaration does not parse (state {:?})",
        agent.state()
    );
    assert_eq!(
        pongs_upload, 0,
        "no session means no uplink Pong frames (actual {pongs_upload})"
    );

    agent.shutdown_graceful().await.expect("agent shutdown");
}

// ---------------------------------------------------------------------------
// T6: metric visibility — heartbeat Ping / Pong (data-plane path) counters
// grow with traffic
// ---------------------------------------------------------------------------

/// Scrape the Prometheus text (the exporter is a process-level HTTP/1.1
/// listener).
async fn scrape_metrics(addr: SocketAddr) -> String {
    let mut sock = TcpStream::connect(addr).await.expect("metrics tcp");
    sock.write_all(b"GET /metrics HTTP/1.1\r\nHost: metrics\r\nConnection: close\r\n\r\n")
        .await
        .expect("metrics write");
    let mut buf = String::new();
    sock.read_to_string(&mut buf).await.expect("metrics read");
    buf
}

/// Sum a counter (across label lines). `metric` takes the metric name without
/// `_total`.
fn counter_sum(text: &str, metric: &str) -> f64 {
    let mut sum = 0.0;
    for line in text.lines() {
        let Some(rest) = line.strip_prefix(metric) else {
            continue;
        };
        let rest = rest.trim_start_matches("_total");
        let Some((_labels, value)) = rest.rsplit_once(char::is_whitespace) else {
            continue;
        };
        sum += value.trim().parse::<f64>().unwrap_or(0.0);
    }
    sum
}

#[tokio::test]
async fn data_plane_heartbeat_metrics_flow() {
    // Process-level exporter: only this test installs it within this binary
    let metrics_addr: SocketAddr = format!("127.0.0.1:{}", pick_ephemeral_port())
        .parse()
        .expect("metrics addr");
    interflow_core::telemetry::init_metrics(metrics_addr, "/metrics");
    // Wait for the exporter listener to be ready
    let mut ready = false;
    for _ in 0..50 {
        if TcpStream::connect(metrics_addr).await.is_ok() {
            ready = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    assert!(
        ready,
        "the Prometheus exporter should be ready within the test"
    );

    let hub_port = pick_ephemeral_port();
    let hub_cfg = hub_config_tuned(
        hub_port,
        certs(),
        vec![],
        HubSecurityConfig::default(),
        HeartbeatConfig {
            enabled: true,
            interval_secs: 1,
            max_missed: 3,
        },
    );
    let _hub = spawn_hub(hub_cfg).await;

    let agent = spawn_agent_registered(agent_config("metrics-agent", hub_port, certs())).await;

    let before = scrape_metrics(metrics_addr).await;
    tokio::time::sleep(Duration::from_secs(4)).await;
    let after = scrape_metrics(metrics_addr).await;
    assert!(
        matches!(agent.state(), AgentState::Connected { .. }),
        "the agent should stay Connected while heartbeats flow"
    );

    let d_pings = counter_sum(&after, "interflow_hub_heartbeat_pings_sent")
        - counter_sum(&before, "interflow_hub_heartbeat_pings_sent");
    let d_pongs = counter_sum(&after, "interflow_hub_pong_received")
        - counter_sum(&before, "interflow_hub_pong_received");

    assert!(
        d_pings >= 2.0,
        "the global heartbeat supervision loop should keep dispatching Pings (delta-ping={d_pings})"
    );
    assert!(
        d_pongs >= 2.0,
        "data-plane Pongs (via the upload stream) should be counted by the hub (delta-pong={d_pongs})"
    );

    agent.shutdown_graceful().await.expect("agent shutdown");
}
