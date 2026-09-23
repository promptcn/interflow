//! E2E: hub self-healing after the data channel saturates (regression tests
//! for the permanent-502 incident on 2026-09-11).
//!
//! Failure chain: agent dies → hub does not notice → the Open notification's
//! `try_send` failure is silently swallowed while still reporting success,
//! Data frames' `send().await` hang forever, and the registry entry is never
//! evicted.
//!
//! After the 2026-09-12 upload streaming refactor, this file's bare-wire cases
//! use the `POST /stream/up` long upload (same shape as the production agent):
//! - Frame-level rejections (unregistered target / channel full / send
//!   timeout) no longer carry a per-frame HTTP status; instead a `_close_`
//!   frame (`CLOSE:{sid}:{reason}`) returns to the sender via its `/poll`;
//! - Fixed semantics covered (updated after the 2026-09-14 control/data-plane
//!   channel separation):
//!   1. Open failure propagation: unregistered target → reject + roll back
//!      stream state (no more black hole); Open travels on an independent
//!      control channel (delivered while online), so once the target
//!      registers it is no longer constrained by data-channel capacity — the
//!      old "channel full rejects the Open" assertion was retired with the
//!      channel separation and replaced by full flood delivery;
//!   2. Data send timeout: the agent is declared dead and evicted, failing
//!      fast;
//!   3. Poll-disconnect grace: if nobody re-polls within the grace period →
//!      eviction;
//!   4. Poll / upload implicit re-registration: an evicted agent's next
//!      request restores its registration directly;
//!   5. Heartbeat death detection: losing contact after having answered a
//!      Pong → eviction + leftover streams end cleanly via generation
//!      self-checks;
//!   6. Heartbeat contract: the hub's Ping is indeed delivered via the poll
//!      channel; answering Pong as agreed keeps the agent alive long-term;
//!   7. Real AgentClient integration: with heartbeats enabled the agent stays
//!      stably Connected (the tunnel layer answers automatically);
//!   8. h2 empty-DATA-frame budget (2026-09-17 churn bug): the poll body of a
//!      Pong-answering agent must survive far past 100 heartbeat cycles —
//!      h2 ≥0.4.16 GOAWAYs a connection after 100 cumulative empty non-final
//!      DATA frames, and each pre-fix heartbeat Ping carried one.

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
use http_body_util::{BodyExt, StreamBody};
use hyper::StatusCode;
use hyper::body::Frame as HttpFrame;
use hyper::client::conn::http2::SendRequest;
use hyper::{Request, Response};
use hyper_util::rt::{TokioExecutor, TokioIo};
use interflow_core::error::InterflowError;
use interflow_core::protocol::CircuitToken;
use interflow_core::protocol::RouteToken;
use interflow_core::protocol::frame::{
    DecodeOutcome, DecodedFrame, FrameType, decode_frame, encode_frame,
};
use interflow_core::tunnel::H2RequestBody;
use interflow_core::tunnel::negotiation::{RegisterResponse, RouteResponse};
use interflow_mesh::config::{HeartbeatConfig, HubSecurityConfig};
use interflow_mesh::hub::qualified_agent_id;
use interflow_testkit::{hub_config_tuned, pick_ephemeral_port, spawn_hub};
use std::time::Duration;
use tokio::sync::mpsc;

fn certs() -> &'static interflow_testkit::certs::TestCerts {
    static C: std::sync::OnceLock<interflow_testkit::certs::TestCerts> = std::sync::OnceLock::new();
    C.get_or_init(|| interflow_testkit::certs::TestCerts::generate("e2e", "agent"))
}

fn sid(label: &str) -> interflow_core::protocol::StreamId {
    interflow_testkit::opaque_stream_id(label)
}

/// Establish a bare HTTP/2 connection to the hub.
async fn connect(port: u16, cn: &str) -> SendRequest<H2RequestBody> {
    let (send_request, conn) = hyper::client::conn::http2::Builder::new(TokioExecutor::new())
        .handshake::<_, H2RequestBody>(TokioIo::new(
            interflow_testkit::tls_client_connect(
                certs(),
                cn,
                format!("127.0.0.1:{port}").parse().unwrap(),
            )
            .await
            .expect("tls"),
        ))
        .await
        .expect("handshake");
    tokio::spawn(async move {
        let _ = conn.await;
    });
    send_request
}

fn empty_body() -> H2RequestBody {
    interflow_core::tunnel::empty_request_body()
}

async fn register(snd: &mut SendRequest<H2RequestBody>, id: &str) -> CircuitToken {
    snd.ready().await.expect("ready");
    let req = Request::builder()
        .method("POST")
        .uri("/register")
        .header("x-agent-id", id)
        .body(empty_body())
        .unwrap();
    let resp = snd.send_request(req).await.expect("register");
    assert_eq!(resp.status(), StatusCode::OK);
    let body = resp.into_body().collect().await.expect("register body");
    RegisterResponse::parse(&body.to_bytes())
        .expect("register capability")
        .circuit_token
}

async fn route(
    snd: &mut SendRequest<H2RequestBody>,
    circuit: CircuitToken,
    target: &str,
) -> RouteToken {
    snd.ready().await.expect("ready");
    let req = Request::builder()
        .method("POST")
        .uri("/route")
        .header("x-circuit-token", circuit.to_hex())
        .body(
            http_body_util::Full::new(Bytes::copy_from_slice(target.as_bytes()))
                .map_err(|never| match never {})
                .boxed(),
        )
        .unwrap();
    let resp = snd.send_request(req).await.expect("route");
    assert_eq!(resp.status(), StatusCode::OK);
    let body = resp.into_body().collect().await.expect("route body");
    serde_json::from_slice::<RouteResponse>(&body.to_bytes())
        .expect("route capability")
        .route_token
}

/// Open a streaming upload `POST /stream/up`; returns (frame-write channel,
/// pending response).
///
/// The caller must hold the response — dropping it terminates the upload (the
/// same death-signal semantics as on the agent side).
async fn open_upload(
    snd: &mut SendRequest<H2RequestBody>,
    circuit: CircuitToken,
) -> (mpsc::Sender<Bytes>, Response<hyper::body::Incoming>) {
    snd.ready().await.expect("ready");
    let (tx, mut rx) = mpsc::channel::<Bytes>(256);
    let body = StreamBody::new(futures::stream::poll_fn(
        move |cx: &mut std::task::Context<'_>| {
            rx.poll_recv(cx).map(|item| {
                item.map(|b| Ok::<HttpFrame<Bytes>, InterflowError>(HttpFrame::data(b)))
            })
        },
    ))
    .boxed();
    let req = Request::builder()
        .method("POST")
        .uri("/stream/up")
        .header("x-circuit-token", circuit.to_hex())
        .body(body)
        .unwrap();
    let resp = snd.send_request(req).await.expect("upload request");
    assert!(
        resp.status().is_success(),
        "upload should return 200, got {}",
        resp.status()
    );
    (tx, resp)
}

fn encode_up_frame(
    ft: FrameType,
    flags: u8,
    sid: interflow_core::protocol::StreamId,
    src: CircuitToken,
    payload: &[u8],
) -> Bytes {
    let mut buf = BytesMut::new();
    encode_frame(ft, flags, sid, src, payload, &mut buf).expect("frame encode");
    buf.freeze()
}

/// Send an Open frame over the upload channel (payload = "{target}:{addr}",
/// same encoding as QUIC).
async fn up_open(
    tx: &mpsc::Sender<Bytes>,
    sid: interflow_core::protocol::StreamId,
    src: CircuitToken,
    route: RouteToken,
) {
    tx.send(encode_up_frame(
        FrameType::Open,
        0,
        sid,
        src,
        &route.to_bytes(),
    ))
    .await
    .expect("send open frame");
}

/// Send a Data frame over the upload channel.
async fn up_data(
    tx: &mpsc::Sender<Bytes>,
    sid: interflow_core::protocol::StreamId,
    src: CircuitToken,
    data: &[u8],
) {
    tx.send(encode_up_frame(FrameType::Data, 0, sid, src, data))
        .await
        .expect("send data frame");
}

async fn poll(
    snd: &mut SendRequest<H2RequestBody>,
    circuit: CircuitToken,
) -> Response<hyper::body::Incoming> {
    snd.ready().await.expect("ready");
    let req = Request::builder()
        .method("GET")
        .uri("/poll")
        .header("x-circuit-token", circuit.to_hex())
        .body(empty_body())
        .unwrap();
    snd.send_request(req).await.expect("poll")
}

/// Sends one data-plane Pong frame over the upload stream (the heartbeat
/// reply contract — same as the real AgentTunnel).
async fn send_uplink_pong(up_tx: &mpsc::Sender<Bytes>, circuit: CircuitToken) {
    let mut buf = BytesMut::new();
    encode_frame(
        FrameType::Pong,
        0,
        interflow_core::protocol::StreamId::ZERO,
        circuit,
        &[],
        &mut buf,
    )
    .expect("encode pong");
    up_tx.send(buf.freeze()).await.expect("send pong");
}

async fn list_agents(snd: &mut SendRequest<H2RequestBody>) -> Vec<String> {
    snd.ready().await.expect("ready");
    let req = Request::builder()
        .method("GET")
        .uri("/agents")
        .body(empty_body())
        .unwrap();
    let resp = snd.send_request(req).await.expect("agents");
    assert!(resp.status().is_success());
    let body = resp.into_body().collect().await.expect("body").to_bytes();
    serde_json::from_slice(&body).expect("agents json")
}

/// Poll /agents until `pred` holds or the timeout elapses (returns the final
/// list).
async fn wait_agents<F>(
    snd: &mut SendRequest<H2RequestBody>,
    timeout: Duration,
    pred: F,
) -> Vec<String>
where
    F: Fn(&[String]) -> bool,
{
    let deadline = tokio::time::Instant::now() + timeout;
    loop {
        let agents = list_agents(snd).await;
        if pred(&agents) || tokio::time::Instant::now() >= deadline {
            return agents;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
}

/// Continuously read frames from the poll response body and wire-decode them,
/// invoking the callback for each decoded frame; returns true when the body
/// ends.
async fn drain_frames<F>(
    body: &mut hyper::body::Incoming,
    deadline: tokio::time::Instant,
    mut on_frame: F,
) -> bool
where
    F: FnMut(DecodedFrame),
{
    let mut buf = BytesMut::new();
    loop {
        let frame_res = tokio::time::timeout_at(deadline, body.frame()).await;
        match frame_res {
            Err(_) => return false,          // timed out without ending
            Ok(None) => return true, // body ended normally (generation self-check / channel closed)
            Ok(Some(Err(_))) => return true, // a connection error also counts as end of stream
            Ok(Some(Ok(frame))) => {
                let Ok(data) = frame.into_data() else {
                    continue;
                };
                buf.extend_from_slice(&data);
                while let DecodeOutcome::Ok(f) = decode_frame(&mut buf) {
                    on_frame(f);
                }
            }
        }
    }
}

/// Wait for the hub-origin Close frame (the frame-level rejection signal)
/// for `sid` to appear on the poll body; **returns as soon as one is seen**
/// (the reason token). Panics if none arrives within the deadline.
async fn wait_close_notification(
    body: &mut hyper::body::Incoming,
    sid: interflow_core::protocol::StreamId,
    deadline: tokio::time::Instant,
) -> String {
    let mut buf = BytesMut::new();
    loop {
        let frame_res = tokio::time::timeout_at(deadline, body.frame()).await;
        match frame_res {
            Err(_) => panic!("timed out waiting for close note on {sid}"),
            Ok(None) | Ok(Some(Err(_))) => {
                panic!("poll ended early, close note for {sid} never received")
            }
            Ok(Some(Ok(frame))) => {
                let Ok(data) = frame.into_data() else {
                    continue;
                };
                buf.extend_from_slice(&data);
                while let DecodeOutcome::Ok(f) = decode_frame(&mut buf) {
                    if matches!(f.frame_type, FrameType::Close)
                        && f.flags & interflow_core::protocol::FLAG_HUB_ORIGIN != 0
                        && f.stream_id == sid
                    {
                        return interflow_core::protocol::CloseReason::from_payload(&f.payload)
                            .as_str()
                            .to_owned();
                    }
                }
            }
        }
    }
}

/// Security config with no rate limits (max_streams=0); timeout parameters
/// can be overridden.
fn security(send_timeout: u64, grace: u64) -> HubSecurityConfig {
    HubSecurityConfig {
        max_connections_per_ip: 0,
        max_connections_total: 0,
        max_streams_per_agent: 0,
        max_streams_total: 0,
        channel_send_timeout_secs: send_timeout,
        poll_grace_secs: grace,
    }
}

/// Scenario 1: Open toward an unregistered target agent → rejected (a
/// `_close_` frame returns to the sender via poll, payload carries the reason)
/// + no leftover stream state (before the fix it reported success and the
/// stream state fell into a black hole).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn open_to_unregistered_target_replies_close_frame() {
    let port = pick_ephemeral_port();
    let _hub = spawn_hub(hub_config_tuned(
        port,
        certs(),
        vec![],
        security(30, 30),
        HeartbeatConfig::default(),
    ))
    .await;

    let mut src = connect(port, "src").await;
    let src_circuit = register(&mut src, "src").await;
    let ghost_route = route(&mut src, src_circuit, "ghost").await;

    let (up_tx, _up_resp) = open_upload(&mut src, src_circuit).await;
    let poll_resp = poll(&mut src, src_circuit).await;
    assert_eq!(poll_resp.status(), 200);
    let mut poll_body = poll_resp.into_body();

    let s1 = sid("s1");
    up_open(&up_tx, s1, src_circuit, ghost_route).await;

    let note = wait_close_notification(
        &mut poll_body,
        s1,
        tokio::time::Instant::now() + Duration::from_secs(5),
    )
    .await;
    assert_eq!(
        note,
        interflow_core::protocol::CloseReason::NoTarget.as_str(),
        "an unregistered target must map to the no-target code: {note}"
    );
}

/// Scenario 2: after the channel (capacity 256) fills, the 257th Open →
/// rejected + stream state rolled back;
/// Scenario 2 (post 2026-09-14 control-plane channel): flood Opens at a
/// registered target that does not poll — Open travels the independent
/// control channel (unbounded, delivered while online), and data-channel
/// capacity no longer constrains stream establishment: when tgt polls later
/// it should receive **all** 257 Opens, none rolled back/rejected.
/// (The old assertion "the 257th Open is rejected due to data-channel
/// backpressure timeout on a full channel" was retired with the channel
/// separation; the full-data-channel backpressure-eviction semantics are
/// covered by scenario 3's Data frames.)
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn open_flood_to_idle_target_delivers_all_via_control_channel() {
    let port = pick_ephemeral_port();
    let _hub = spawn_hub(hub_config_tuned(
        port,
        certs(),
        vec![],
        security(1, 30),
        HeartbeatConfig::default(),
    ))
    .await;

    let mut src = connect(port, "src").await;
    let src_circuit = register(&mut src, "src").await;
    let mut tgt = connect(port, "tgt").await;
    let tgt_circuit = register(&mut tgt, "tgt").await;
    let tgt_route = route(&mut src, src_circuit, "tgt").await;

    let (up_tx, _up_resp) = open_upload(&mut src, src_circuit).await;
    let poll_resp = poll(&mut src, src_circuit).await;
    let mut poll_body = poll_resp.into_body();

    // All 257 Opens land on a target nobody is draining (under the old
    // semantics the 257th would be rejected and rolled back)
    for i in 0..257 {
        up_open(&up_tx, sid(&format!("s{i}")), src_circuit, tgt_route).await;
    }

    // The sender should not receive any `_close_` rejection (Opens are
    // guaranteed delivery; silent within 1s)
    let rejected = std::sync::Mutex::new(Vec::new());
    let _ended = drain_frames(
        &mut poll_body,
        tokio::time::Instant::now() + Duration::from_secs(1),
        |f| {
            if matches!(f.frame_type, FrameType::Close) {
                if let Ok(mut g) = rejected.lock() {
                    g.push(String::from_utf8_lossy(&f.payload).to_string());
                }
            }
        },
    )
    .await;
    let rejected = rejected.into_inner().unwrap_or_else(|e| e.into_inner());
    assert!(
        rejected.is_empty(),
        "the Open flood should not produce rejection notices: {rejected:?}"
    );

    // tgt starts polling: it should receive all 257 Opens
    let tgt_resp = poll(&mut tgt, tgt_circuit).await;
    assert_eq!(tgt_resp.status(), 200);
    let mut tgt_body = tgt_resp.into_body();
    let opens = std::sync::Mutex::new(std::collections::HashSet::new());
    let ended = drain_frames(
        &mut tgt_body,
        tokio::time::Instant::now() + Duration::from_secs(5),
        |f| {
            if matches!(f.frame_type, FrameType::Open) {
                if let Ok(mut g) = opens.lock() {
                    g.insert(f.stream_id);
                }
            }
        },
    )
    .await;
    let opens = opens.into_inner().unwrap_or_else(|e| e.into_inner());
    assert_eq!(
        opens.len(),
        257,
        "all 257 Opens should be received: {opens:?}"
    );
    assert!(
        opens.contains(&sid("s256")),
        "the 257th Open (s256) must be delivered"
    );
    let _ = ended;

    // Subsequent Opens are dispatched as usual
    up_open(&up_tx, sid("s257"), src_circuit, tgt_route).await;
    let mut got_257 = false;
    let ended = drain_frames(
        &mut tgt_body,
        tokio::time::Instant::now() + Duration::from_secs(3),
        |f| {
            if matches!(f.frame_type, FrameType::Open) && f.stream_id == sid("s257") {
                got_257 = true;
            }
        },
    )
    .await;
    assert!(got_257, "subsequent Opens should be dispatched as usual");
    let _ = ended;
}

/// Scenario 3 (failure reproduction): an agent registers but does not poll;
/// the **data channel** fills with Data frames, and subsequent Data dispatch
/// should evict that agent after the 1s timeout and notify the sender; the
/// agent's /poll then implicitly re-registers it.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn data_send_timeout_evicts_and_poll_recreates() {
    let port = pick_ephemeral_port();
    let _hub = spawn_hub(hub_config_tuned(
        port,
        certs(),
        vec![],
        security(1, 30),
        HeartbeatConfig::default(),
    ))
    .await;

    let mut src = connect(port, "src").await;
    let src_circuit = register(&mut src, "src").await;
    let mut tgt = connect(port, "tgt").await;
    let tgt_circuit = register(&mut tgt, "tgt").await;
    let tgt_route = route(&mut src, src_circuit, "tgt").await;

    let (up_tx, _up_resp) = open_upload(&mut src, src_circuit).await;
    let poll_resp = poll(&mut src, src_circuit).await;
    let mut poll_body = poll_resp.into_body();

    let s0 = sid("s0");
    up_open(&up_tx, s0, src_circuit, tgt_route).await;

    // Fill the **data channel** (after the 2026-09-14 channel separation, Open
    // goes through the control channel and is enqueued immediately; the data
    // channel's capacity is still consumed by the non-polling tgt): flood 256
    // Data frames on one stream
    for i in 0..256 {
        up_data(&up_tx, s0, src_circuit, format!("fill-{i}").as_bytes()).await;
    }

    // The 257th Data frame: full channel + no consumer → 1s backpressure
    // timeout → eviction + sender notified.
    // (Before the fix it hung forever — the root cause of the upstream 502)
    let started = std::time::Instant::now();
    up_data(&up_tx, s0, src_circuit, b"hello").await;
    let note = wait_close_notification(
        &mut poll_body,
        s0,
        tokio::time::Instant::now() + Duration::from_secs(5),
    )
    .await;
    // What arrives first may be the backpressure-timeout notice (stalled) or
    // the eviction sweep's peer notice (agent-evicted — the sweep now also
    // notifies the peer) — both are legitimate termination signals
    assert!(
        matches!(note.as_str(), "dispatch_poison" | "session_closed"),
        "expected a backpressure-timeout or eviction notice: {note}"
    );
    assert!(
        started.elapsed() < Duration::from_secs(4),
        "should fail around send_timeout, not hang"
    );

    // The agent has been evicted
    let agents = wait_agents(&mut src, Duration::from_secs(3), |a| {
        !a.contains(&qualified_agent_id(interflow_testkit::TEST_TENANT, "tgt"))
    })
    .await;
    assert!(
        !agents.contains(&qualified_agent_id(interflow_testkit::TEST_TENANT, "tgt")),
        "tgt should be evicted after the timeout: {agents:?}"
    );

    // tgt polls again → implicit re-registration (before the fix, a 404 loop)
    let resp = poll(&mut tgt, tgt_circuit).await;
    assert_eq!(
        resp.status(),
        200,
        "after eviction, polling should implicitly re-register, not 404"
    );
    let agents = list_agents(&mut src).await;
    assert!(
        agents.contains(&qualified_agent_id(interflow_testkit::TEST_TENANT, "tgt")),
        "after implicit re-registration, tgt should be back in the registry"
    );

    // After re-registration the data plane recovers: a new Open should be
    // dispatched to tgt
    up_open(&up_tx, sid("fresh"), src_circuit, tgt_route).await;
    let mut tgt_body = resp.into_body();
    let mut got_fresh = false;
    let ended = drain_frames(
        &mut tgt_body,
        tokio::time::Instant::now() + Duration::from_secs(3),
        |f| {
            if matches!(f.frame_type, FrameType::Open) && f.stream_id == sid("fresh") {
                got_fresh = true;
            }
        },
    )
    .await;
    assert!(
        got_fresh,
        "after re-registration, a new stream should be dispatched successfully"
    );
    let _ = ended;
}

/// Scenario 4: the poll disconnects and nobody re-polls within the grace
/// period → eviction; polling again implicitly re-registers.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn poll_disconnect_grace_evicts() {
    let port = pick_ephemeral_port();
    let _hub = spawn_hub(hub_config_tuned(
        port,
        certs(),
        vec![],
        security(30, 1),
        HeartbeatConfig::default(),
    ))
    .await;

    let mut tgt = connect(port, "tgt").await;
    let tgt_circuit = register(&mut tgt, "tgt").await;
    let resp = poll(&mut tgt, tgt_circuit).await;
    assert_eq!(resp.status(), 200);
    drop(resp); // simulate agent death: the poll connection breaks

    // Grace 1s + headroom; nobody re-polls during it → eviction
    let agents = wait_agents(&mut tgt, Duration::from_secs(4), |a| {
        !a.contains(&qualified_agent_id(interflow_testkit::TEST_TENANT, "tgt"))
    })
    .await;
    assert!(
        !agents.contains(&qualified_agent_id(interflow_testkit::TEST_TENANT, "tgt")),
        "should be evicted after the grace timeout: {agents:?}"
    );

    // Poll again → implicit re-registration
    let resp = poll(&mut tgt, tgt_circuit).await;
    assert_eq!(resp.status(), 200);
    let agents = list_agents(&mut tgt).await;
    assert!(agents.contains(&qualified_agent_id(interflow_testkit::TEST_TENANT, "tgt")));
}

/// Scenario 5 (wedge reproduction): after answering a Pong once, the agent is
/// "application-layer wedged" — the poll connection stays up but it never
/// answers Pong again → heartbeat death detection evicts it; the leftover poll
/// response ends cleanly via the generation self-check.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn heartbeat_evicts_pong_aware_wedge_and_ends_poll() {
    let port = pick_ephemeral_port();
    let hb = HeartbeatConfig {
        enabled: true,
        interval_secs: 1,
        max_missed: 1,
    };
    let _hub = spawn_hub(hub_config_tuned(
        port,
        certs(),
        vec![],
        security(30, 30),
        hb,
    ))
    .await;

    let mut tgt = connect(port, "wedge").await;
    let wedge_circuit = register(&mut tgt, "wedge").await;
    let resp = poll(&mut tgt, wedge_circuit).await;
    assert_eq!(resp.status(), 200);
    let mut body = resp.into_body();

    // Death detection participates from registration (last_pong initialized
    // there): silence alone ages the session out.

    // Wait for the loss-of-contact verdict (deadline = 1*(1+1) = 2s; generous
    // headroom)
    let agents = wait_agents(&mut tgt, Duration::from_secs(8), |a| {
        !a.contains(&qualified_agent_id(interflow_testkit::TEST_TENANT, "wedge"))
    })
    .await;
    assert!(
        !agents.contains(&qualified_agent_id(interflow_testkit::TEST_TENANT, "wedge")),
        "heartbeat loss of contact should evict: {agents:?}"
    );

    // The leftover poll response should have ended (generation self-check →
    // EOF), not hang forever
    let ended = drain_frames(
        &mut body,
        tokio::time::Instant::now() + Duration::from_secs(5),
        |_| {},
    )
    .await;
    assert!(
        ended,
        "the leftover poll response should end after eviction"
    );
}

/// Scenario 7 (heartbeat contract): an agent that answers Pong as agreed
/// survives long-term.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn pong_replying_agent_survives_heartbeat() {
    let port = pick_ephemeral_port();
    let hb = HeartbeatConfig {
        enabled: true,
        interval_secs: 1,
        max_missed: 1,
    };
    let _hub = spawn_hub(hub_config_tuned(
        port,
        certs(),
        vec![],
        security(30, 30),
        hb,
    ))
    .await;

    let mut tgt = connect(port, "good").await;
    let good_circuit = register(&mut tgt, "good").await;
    let (up_tx, _up_resp) = open_upload(&mut tgt, good_circuit).await;
    let resp = poll(&mut tgt, good_circuit).await;
    assert_eq!(resp.status(), 200);
    let mut body = resp.into_body();

    // Read poll frames: answer Pong on every Ping over the upload stream
    // (the same contract as the real AgentTunnel), for 5s straight
    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    let mut buf = BytesMut::new();
    let mut pings = 0usize;
    let ended = loop {
        if tokio::time::Instant::now() >= deadline {
            break false;
        }
        match tokio::time::timeout_at(deadline, body.frame()).await {
            Err(_) => break false,
            Ok(None) => break true,
            Ok(Some(Err(_))) => break true,
            Ok(Some(Ok(frame))) => {
                let Ok(data) = frame.into_data() else {
                    continue;
                };
                buf.extend_from_slice(&data);
                while let DecodeOutcome::Ok(f) = decode_frame(&mut buf) {
                    if matches!(f.frame_type, FrameType::Ping) {
                        pings += 1;
                        send_uplink_pong(&up_tx, good_circuit).await;
                    }
                }
            }
        }
    };
    assert!(
        !ended,
        "the poll of an agent that keeps answering Pong should not be ended"
    );
    assert!(
        pings >= 3,
        "multiple heartbeat Pings should arrive within 5s, got {pings}"
    );

    let agents = list_agents(&mut tgt).await;
    assert!(
        agents.contains(&qualified_agent_id(interflow_testkit::TEST_TENANT, "good")),
        "an agent that answers as agreed should survive"
    );
}

/// Scenario 8 (real-agent integration): with aggressive heartbeat parameters,
/// a real AgentClient should stay stably Connected (AgentTunnel's poll decode
/// layer answers Pong automatically; after upload streaming, frames go via
/// /stream/up).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn real_agent_survives_aggressive_heartbeat() {
    use interflow_mesh::agent::handle::AgentState;
    use interflow_testkit::agent_config;

    let port = pick_ephemeral_port();
    let hb = HeartbeatConfig {
        enabled: true,
        interval_secs: 1,
        max_missed: 1,
    };
    let _hub = spawn_hub(hub_config_tuned(
        port,
        certs(),
        vec![],
        security(30, 30),
        hb,
    ))
    .await;

    let handle = interflow_mesh::agent::AgentClient::new(agent_config("real-agent", port, certs()))
        .expect("agent build")
        .start();

    // Wait for the connection + observation window (3x the 2s death-detection
    // deadline)
    let mut state_rx = handle.subscribe_state();
    let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
    loop {
        if matches!(*state_rx.borrow_and_update(), AgentState::Connected { .. }) {
            break;
        }
        tokio::time::timeout_at(deadline, state_rx.changed())
            .await
            .expect("timed out waiting for Connected")
            .expect("state sender dropped");
    }
    tokio::time::sleep(Duration::from_secs(6)).await;

    assert!(
        matches!(handle.state(), AgentState::Connected { .. }),
        "with heartbeats enabled the agent should stay Connected, got: {:?}",
        handle.state()
    );
    handle.shutdown_graceful().await.expect("shutdown");
}

/// Scenario 8 (2026-09-17 h2 empty-DATA-frame bomb, compressed in time): the
/// hub's poll response used to split every frame into a header chunk plus a
/// payload chunk; with the heartbeat Ping's empty payload that second chunk
/// became a real (empty, non-final) h2 DATA frame — hyper forwards zero-length
/// chunks straight through. h2 ≥0.4.16 counts cumulative empty non-final DATA
/// frames with a hard cap of 100 and no release path, so the 101st Ping
/// GOAWAY'd the whole connection (`too_many_data_frames`) — in production at
/// 15s cadence this was the deterministic 25:14.1 session churn
///.
///
/// With a 1s heartbeat the same counter trips at ~101s; a Pong-answering
/// poll surviving ~110 cycles proves the bomb is defused (the hub's
/// ChunkHygiene body adapter no longer emits empty chunks). Pre-fix, this
/// test dies with the exact production signature: poll body read error.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn poll_survives_empty_data_frame_budget_past_100_heartbeats() {
    let port = pick_ephemeral_port();
    let hb = HeartbeatConfig {
        enabled: true,
        interval_secs: 1,
        max_missed: 3,
    };
    let _hub = spawn_hub(hub_config_tuned(
        port,
        certs(),
        vec![],
        security(30, 30),
        hb,
    ))
    .await;

    let mut agent = connect(port, "bomb-probe").await;
    let agent_circuit = register(&mut agent, "bomb-probe").await;
    let (up_tx, _up_resp) = open_upload(&mut agent, agent_circuit).await;
    let resp = poll(&mut agent, agent_circuit).await;
    assert_eq!(resp.status(), 200);
    let mut body = resp.into_body();

    // 112s at 1s cadence ≈ 110 cycles: comfortably past the 100-empty-frame
    // cap where the pre-fix connection died.
    let deadline = tokio::time::Instant::now() + Duration::from_secs(112);
    let mut buf = BytesMut::new();
    let mut pings = 0usize;
    let ended = loop {
        if tokio::time::Instant::now() >= deadline {
            break false;
        }
        match tokio::time::timeout_at(deadline, body.frame()).await {
            Err(_) => break false,
            Ok(None) => break true,
            Ok(Some(Err(_))) => break true,
            Ok(Some(Ok(frame))) => {
                let Ok(data) = frame.into_data() else {
                    continue;
                };
                buf.extend_from_slice(&data);
                while let DecodeOutcome::Ok(f) = decode_frame(&mut buf) {
                    if matches!(f.frame_type, FrameType::Ping) {
                        pings += 1;
                        send_uplink_pong(&up_tx, agent_circuit).await;
                    }
                }
            }
        }
    };
    assert!(
        !ended,
        "poll must survive past 100 heartbeat cycles \
         (pre-fix: GOAWAY too_many_data_frames on the 101st empty DATA frame)"
    );
    assert!(
        pings >= 105,
        "expected ≥105 heartbeat Pings within 112s at 1s cadence, got {pings}"
    );

    let agents = list_agents(&mut agent).await;
    assert!(
        agents.contains(&qualified_agent_id(
            interflow_testkit::TEST_TENANT,
            "bomb-probe"
        )),
        "the Pong-answering agent must still be registered after 100+ cycles"
    );
}
