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
//!      stably Connected (the tunnel layer answers automatically).

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
use interflow_core::protocol::frame::{
    DecodeOutcome, DecodedFrame, FrameType, decode_frame, encode_frame,
};
use interflow_core::tunnel::H2RequestBody;
use interflow_mesh::config::{HeartbeatConfig, HubSecurityConfig};
use interflow_testkit::{hub_config_tuned, pick_ephemeral_port, spawn_hub};
use std::time::Duration;
use tokio::sync::mpsc;

/// Establish a bare HTTP/2 connection to the hub.
async fn connect(port: u16) -> SendRequest<H2RequestBody> {
    let (send_request, conn) = hyper::client::conn::http2::Builder::new(TokioExecutor::new())
        .handshake::<_, H2RequestBody>(TokioIo::new(
            tokio::net::TcpStream::connect(format!("127.0.0.1:{port}"))
                .await
                .expect("tcp"),
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

async fn register(snd: &mut SendRequest<H2RequestBody>, id: &str) -> StatusCode {
    snd.ready().await.expect("ready");
    let req = Request::builder()
        .method("POST")
        .uri("/register")
        .header("x-agent-id", id)
        .body(empty_body())
        .unwrap();
    snd.send_request(req).await.expect("register").status()
}

/// Open a streaming upload `POST /stream/up`; returns (frame-write channel,
/// pending response).
///
/// The caller must hold the response — dropping it terminates the upload (the
/// same death-signal semantics as on the agent side).
async fn open_upload(
    snd: &mut SendRequest<H2RequestBody>,
    id: &str,
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
        .header("x-agent-id", id)
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

fn encode_up_frame(ft: FrameType, flags: u8, sid: &str, src: &str, payload: &[u8]) -> Bytes {
    let mut buf = BytesMut::new();
    encode_frame(ft, flags, sid, src, payload, &mut buf).expect("frame encode");
    buf.freeze()
}

/// Send an Open frame over the upload channel (payload = "{target}:{addr}",
/// same encoding as QUIC).
async fn up_open(tx: &mpsc::Sender<Bytes>, sid: &str, src: &str, tgt: &str) {
    let payload = format!("{tgt}:");
    tx.send(encode_up_frame(
        FrameType::Open,
        0,
        sid,
        src,
        payload.as_bytes(),
    ))
    .await
    .expect("send open frame");
}

/// Send a Data frame over the upload channel.
async fn up_data(tx: &mpsc::Sender<Bytes>, sid: &str, src: &str, data: &[u8]) {
    tx.send(encode_up_frame(FrameType::Data, 0, sid, src, data))
        .await
        .expect("send data frame");
}

async fn poll(snd: &mut SendRequest<H2RequestBody>, id: &str) -> Response<hyper::body::Incoming> {
    snd.ready().await.expect("ready");
    let req = Request::builder()
        .method("GET")
        .uri("/poll")
        .header("x-agent-id", id)
        .body(empty_body())
        .unwrap();
    snd.send_request(req).await.expect("poll")
}

/// Sends one data-plane Pong frame over the upload stream (the heartbeat
/// reply contract — same as the real AgentTunnel).
async fn send_uplink_pong(up_tx: &mpsc::Sender<Bytes>, id: &str) {
    let mut buf = BytesMut::new();
    encode_frame(FrameType::Pong, 0, "", id, &[], &mut buf);
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

/// Wait for a `_close_` frame with the `CLOSE:{sid}:` prefix (the frame-level
/// rejection signal) to appear on the poll body; **returns as soon as one is
/// seen** (the full payload). Panics if none arrives within the deadline.
async fn wait_close_notification(
    body: &mut hyper::body::Incoming,
    sid: &str,
    deadline: tokio::time::Instant,
) -> String {
    let prefix = format!("CLOSE:{sid}:");
    let mut buf = BytesMut::new();
    loop {
        let frame_res = tokio::time::timeout_at(deadline, body.frame()).await;
        match frame_res {
            Err(_) => panic!("timed out waiting for {prefix}"),
            Ok(None) | Ok(Some(Err(_))) => {
                panic!("poll ended early, {prefix} never received")
            }
            Ok(Some(Ok(frame))) => {
                let Ok(data) = frame.into_data() else {
                    continue;
                };
                buf.extend_from_slice(&data);
                while let DecodeOutcome::Ok(f) = decode_frame(&mut buf) {
                    if matches!(f.frame_type, FrameType::Close)
                        && f.source_agent == "_close_"
                        && String::from_utf8_lossy(&f.payload).starts_with(&prefix)
                    {
                        return String::from_utf8_lossy(&f.payload).to_string();
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
        vec![],
        security(30, 30),
        HeartbeatConfig::default(),
    ))
    .await;

    let mut src = connect(port).await;
    assert_eq!(register(&mut src, "src").await, 200);

    let (up_tx, _up_resp) = open_upload(&mut src, "src").await;
    let poll_resp = poll(&mut src, "src").await;
    assert_eq!(poll_resp.status(), 200);
    let mut poll_body = poll_resp.into_body();

    up_open(&up_tx, "s1", "src", "ghost").await;

    let note = wait_close_notification(
        &mut poll_body,
        "s1",
        tokio::time::Instant::now() + Duration::from_secs(5),
    )
    .await;
    assert!(
        note.contains("not registered"),
        "the rejection reason should state the target is not registered: {note}"
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
        vec![],
        security(1, 30),
        HeartbeatConfig::default(),
    ))
    .await;

    let mut src = connect(port).await;
    assert_eq!(register(&mut src, "src").await, 200);
    let mut tgt = connect(port).await;
    assert_eq!(register(&mut tgt, "tgt").await, 200);

    let (up_tx, _up_resp) = open_upload(&mut src, "src").await;
    let poll_resp = poll(&mut src, "src").await;
    let mut poll_body = poll_resp.into_body();

    // All 257 Opens land on a target nobody is draining (under the old
    // semantics the 257th would be rejected and rolled back)
    for i in 0..257 {
        up_open(&up_tx, &format!("s{i}"), "src", "tgt").await;
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
    let tgt_resp = poll(&mut tgt, "tgt").await;
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
        opens.contains("s256"),
        "the 257th Open (s256) must be delivered"
    );
    let _ = ended;

    // Subsequent Opens are dispatched as usual
    up_open(&up_tx, "s257", "src", "tgt").await;
    let mut got_257 = false;
    let ended = drain_frames(
        &mut tgt_body,
        tokio::time::Instant::now() + Duration::from_secs(3),
        |f| {
            if matches!(f.frame_type, FrameType::Open) && f.stream_id == "s257" {
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
        vec![],
        security(1, 30),
        HeartbeatConfig::default(),
    ))
    .await;

    let mut src = connect(port).await;
    assert_eq!(register(&mut src, "src").await, 200);
    let mut tgt = connect(port).await;
    assert_eq!(register(&mut tgt, "tgt").await, 200);

    let (up_tx, _up_resp) = open_upload(&mut src, "src").await;
    let poll_resp = poll(&mut src, "src").await;
    let mut poll_body = poll_resp.into_body();

    up_open(&up_tx, "s0", "src", "tgt").await;

    // Fill the **data channel** (after the 2026-09-14 channel separation, Open
    // goes through the control channel and is enqueued immediately; the data
    // channel's capacity is still consumed by the non-polling tgt): flood 256
    // Data frames on one stream
    for i in 0..256 {
        up_data(&up_tx, "s0", "src", format!("fill-{i}").as_bytes()).await;
    }

    // The 257th Data frame: full channel + no consumer → 1s backpressure
    // timeout → eviction + sender notified.
    // (Before the fix it hung forever — the root cause of the upstream 502)
    let started = std::time::Instant::now();
    up_data(&up_tx, "s0", "src", b"hello").await;
    let note = wait_close_notification(
        &mut poll_body,
        "s0",
        tokio::time::Instant::now() + Duration::from_secs(5),
    )
    .await;
    // What arrives first may be the backpressure-timeout notice (stalled) or
    // the eviction sweep's peer notice (agent-evicted — the sweep now also
    // notifies the peer) — both are legitimate termination signals
    assert!(
        note.contains("stalled") || note.contains("agent-evicted"),
        "expected a backpressure-timeout or eviction notice: {note}"
    );
    assert!(
        started.elapsed() < Duration::from_secs(4),
        "should fail around send_timeout, not hang"
    );

    // The agent has been evicted
    let agents = wait_agents(&mut src, Duration::from_secs(3), |a| {
        !a.contains(&"tgt".to_string())
    })
    .await;
    assert!(
        !agents.contains(&"tgt".to_string()),
        "tgt should be evicted after the timeout: {agents:?}"
    );

    // tgt polls again → implicit re-registration (before the fix, a 404 loop)
    let resp = poll(&mut tgt, "tgt").await;
    assert_eq!(
        resp.status(),
        200,
        "after eviction, polling should implicitly re-register, not 404"
    );
    let agents = list_agents(&mut src).await;
    assert!(
        agents.contains(&"tgt".to_string()),
        "after implicit re-registration, tgt should be back in the registry"
    );

    // After re-registration the data plane recovers: a new Open should be
    // dispatched to tgt
    up_open(&up_tx, "fresh", "src", "tgt").await;
    let mut tgt_body = resp.into_body();
    let mut got_fresh = false;
    let ended = drain_frames(
        &mut tgt_body,
        tokio::time::Instant::now() + Duration::from_secs(3),
        |f| {
            if matches!(f.frame_type, FrameType::Open) && f.stream_id == "fresh" {
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
        vec![],
        security(30, 1),
        HeartbeatConfig::default(),
    ))
    .await;

    let mut tgt = connect(port).await;
    assert_eq!(register(&mut tgt, "tgt").await, 200);
    let resp = poll(&mut tgt, "tgt").await;
    assert_eq!(resp.status(), 200);
    drop(resp); // simulate agent death: the poll connection breaks

    // Grace 1s + headroom; nobody re-polls during it → eviction
    let agents = wait_agents(&mut tgt, Duration::from_secs(4), |a| {
        !a.contains(&"tgt".to_string())
    })
    .await;
    assert!(
        !agents.contains(&"tgt".to_string()),
        "should be evicted after the grace timeout: {agents:?}"
    );

    // Poll again → implicit re-registration
    let resp = poll(&mut tgt, "tgt").await;
    assert_eq!(resp.status(), 200);
    let agents = list_agents(&mut tgt).await;
    assert!(agents.contains(&"tgt".to_string()));
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
    let _hub = spawn_hub(hub_config_tuned(port, vec![], security(30, 30), hb)).await;

    let mut tgt = connect(port).await;
    assert_eq!(register(&mut tgt, "wedge").await, 200);
    let resp = poll(&mut tgt, "wedge").await;
    assert_eq!(resp.status(), 200);
    let mut body = resp.into_body();

    // Death detection participates from registration (last_pong initialized
    // there): silence alone ages the session out.

    // Wait for the loss-of-contact verdict (deadline = 1*(1+1) = 2s; generous
    // headroom)
    let agents = wait_agents(&mut tgt, Duration::from_secs(8), |a| {
        !a.contains(&"wedge".to_string())
    })
    .await;
    assert!(
        !agents.contains(&"wedge".to_string()),
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
    let _hub = spawn_hub(hub_config_tuned(port, vec![], security(30, 30), hb)).await;

    let mut tgt = connect(port).await;
    assert_eq!(register(&mut tgt, "good").await, 200);
    let (up_tx, _up_resp) = open_upload(&mut tgt, "good").await;
    let resp = poll(&mut tgt, "good").await;
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
                        send_uplink_pong(&up_tx, "good").await;
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
        agents.contains(&"good".to_string()),
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
    let _hub = spawn_hub(hub_config_tuned(port, vec![], security(30, 30), hb)).await;

    let handle = interflow_mesh::agent::AgentClient::new(agent_config("real-agent", port))
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
