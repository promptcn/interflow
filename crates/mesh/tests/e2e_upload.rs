//! E2E: connection semantics of the `/stream/up` streaming upload (coverage
//! added by the 2026-09-12 upload streaming refactor).
//!
//! Shares the bare-wire shape with `e2e_hub_eviction.rs`, focused on the
//! upload's own lifecycle:
//! - Single-consumer lease: an active upload already exists for the same
//!   agent → 409;
//! - Register preemption: a new connection registering the same identity →
//!   the old upload's response ends (yielding its place);
//! - Frame-level anti-forgery: a source that does not match the connection
//!   identity → rejected with `_close_`, and the upload survives;
//! - Eviction → the upload's death signal → implicit re-registration on
//!   rebuild (fully symmetric with /poll).

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
use hyper::body::Frame as HttpFrame;
use hyper::client::conn::http2::SendRequest;
use hyper::{Request, Response};
use hyper_util::rt::{TokioExecutor, TokioIo};
use interflow_core::error::InterflowError;
use interflow_core::protocol::frame::{DecodeOutcome, FrameType, decode_frame, encode_frame};
use interflow_core::tunnel::H2RequestBody;
use interflow_mesh::config::{HeartbeatConfig, HubSecurityConfig};
use interflow_testkit::{hub_config_tuned, pick_ephemeral_port, spawn_hub};
use std::time::Duration;
use tokio::sync::mpsc;

fn security() -> HubSecurityConfig {
    HubSecurityConfig {
        max_connections_per_ip: 0,
        max_connections_total: 0,
        max_streams_per_agent: 0,
        max_streams_total: 0,
        channel_send_timeout_secs: 30,
        poll_grace_secs: 30,
    }
}

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

async fn register(snd: &mut SendRequest<H2RequestBody>, id: &str) -> hyper::StatusCode {
    snd.ready().await.expect("ready");
    let req = Request::builder()
        .method("POST")
        .uri("/register")
        .header("x-agent-id", id)
        .body(interflow_core::tunnel::empty_request_body())
        .unwrap();
    snd.send_request(req).await.expect("register").status()
}

/// Open a streaming upload; status assertions are made by the caller.
async fn open_upload(
    snd: &mut SendRequest<H2RequestBody>,
    id: &str,
) -> (mpsc::Sender<Bytes>, Response<hyper::body::Incoming>) {
    snd.ready().await.expect("ready");
    let (tx, mut rx) = mpsc::channel::<Bytes>(64);
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
    (tx, resp)
}

async fn open_upload_ok(
    snd: &mut SendRequest<H2RequestBody>,
    id: &str,
) -> (mpsc::Sender<Bytes>, Response<hyper::body::Incoming>) {
    let (tx, resp) = open_upload(snd, id).await;
    assert_eq!(resp.status(), 200, "upload should succeed");
    (tx, resp)
}

async fn poll(snd: &mut SendRequest<H2RequestBody>, id: &str) -> Response<hyper::body::Incoming> {
    snd.ready().await.expect("ready");
    let req = Request::builder()
        .method("GET")
        .uri("/poll")
        .header("x-agent-id", id)
        .body(interflow_core::tunnel::empty_request_body())
        .unwrap();
    snd.send_request(req).await.expect("poll")
}

async fn post_pong(snd: &mut SendRequest<H2RequestBody>, id: &str) -> hyper::StatusCode {
    snd.ready().await.expect("ready");
    let req = Request::builder()
        .method("POST")
        .uri("/pong")
        .header("x-agent-id", id)
        .body(interflow_core::tunnel::empty_request_body())
        .unwrap();
    snd.send_request(req).await.expect("pong").status()
}

async fn list_agents(snd: &mut SendRequest<H2RequestBody>) -> Vec<String> {
    snd.ready().await.expect("ready");
    let req = Request::builder()
        .method("GET")
        .uri("/agents")
        .body(interflow_core::tunnel::empty_request_body())
        .unwrap();
    let resp = snd.send_request(req).await.expect("agents");
    let body = resp.into_body().collect().await.expect("body").to_bytes();
    serde_json::from_slice(&body).expect("agents json")
}

fn encode_up(ft: FrameType, sid: &str, src: &str, payload: &[u8]) -> Bytes {
    let mut buf = BytesMut::new();
    encode_frame(ft, 0, sid, src, payload, &mut buf).expect("encode");
    buf.freeze()
}

/// Read the poll body until a `CLOSE:{sid}:` rejection notice appears
/// (returns the full payload).
async fn wait_close_note(body: &mut hyper::body::Incoming, sid: &str) -> String {
    let prefix = format!("CLOSE:{sid}:");
    let mut buf = BytesMut::new();
    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
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

/// Single-consumer lease: a second upload for the same agent → 409; after the
/// first is dropped, it can be rebuilt.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn second_upload_same_agent_gets_409() {
    let port = pick_ephemeral_port();
    let _hub = spawn_hub(hub_config_tuned(
        port,
        vec![],
        security(),
        HeartbeatConfig::default(),
    ))
    .await;

    let mut a = connect(port).await;
    assert_eq!(register(&mut a, "dup").await, 200);
    let (tx1, resp1) = open_upload_ok(&mut a, "dup").await;

    // Second upload on the same connection: the lease is occupied → 409
    let (_tx2, resp2) = open_upload(&mut a, "dup").await;
    assert_eq!(
        resp2.status(),
        409,
        "the second upload should get 409 while an active upload exists"
    );
    drop(resp2);

    // Terminate the first upload (drop the response + the request-body
    // channel → the stream ends) → the reader exits and returns the lease
    drop(resp1);
    drop(tx1);
    tokio::time::sleep(Duration::from_millis(200)).await;
    let (_tx3, resp3) = open_upload(&mut a, "dup").await;
    assert_eq!(
        resp3.status(),
        200,
        "the upload should be rebuildable once the lease is returned"
    );
}

/// Register preemption: a new connection registers the same identity → the
/// old upload's response ends (the death signal yields its place).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn register_preempts_active_upload() {
    let port = pick_ephemeral_port();
    let _hub = spawn_hub(hub_config_tuned(
        port,
        vec![],
        security(),
        HeartbeatConfig::default(),
    ))
    .await;

    // Connection A: register + active upload
    let mut a = connect(port).await;
    assert_eq!(register(&mut a, "agent-x").await, 200);
    let (_tx_a, resp_a) = open_upload_ok(&mut a, "agent-x").await;
    let mut body_a = resp_a.into_body();

    // Connection B: re-register the same identity (preemption: generation +1,
    // the old lease is cancelled)
    let mut b = connect(port).await;
    assert_eq!(register(&mut b, "agent-x").await, 200);

    // A's upload response should end (lease cancelled → reader exits →
    // END_STREAM)
    let ended = tokio::time::timeout(Duration::from_secs(3), async {
        loop {
            match body_a.frame().await {
                None | Some(Err(_)) => break,
                Some(Ok(_)) => continue,
            }
        }
    })
    .await;
    assert!(
        ended.is_ok(),
        "the old upload response should end within the grace after preemption"
    );

    // B can establish its own upload
    let (_tx_b, resp_b) = open_upload(&mut b, "agent-x").await;
    assert_eq!(
        resp_b.status(),
        200,
        "the preempting side should be able to establish an upload"
    );
}

/// Frame-level anti-forgery: a frame whose source does not match the
/// connection identity → rejected with `_close_` and the upload survives.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn forged_source_frame_rejected_upload_survives() {
    let port = pick_ephemeral_port();
    let _hub = spawn_hub(hub_config_tuned(
        port,
        vec![],
        security(),
        HeartbeatConfig::default(),
    ))
    .await;

    let mut a = connect(port).await;
    assert_eq!(register(&mut a, "real").await, 200);
    let mut other = connect(port).await;
    assert_eq!(register(&mut other, "other").await, 200);

    let (up_tx, _up_resp) = open_upload_ok(&mut a, "real").await;
    let poll_resp = poll(&mut a, "real").await;
    let mut poll_body = poll_resp.into_body();

    // Forged frame: the connection identity is real, the frame claims other
    up_tx
        .send(encode_up(FrameType::Data, "s1", "other", b"evil"))
        .await
        .expect("send forged frame");

    let note = wait_close_note(&mut poll_body, "s1").await;
    assert!(
        note.contains("spoofed"),
        "rejection reason should say spoofed: {note}"
    );

    // The upload is still alive: a legitimate Open (to a registered target) is
    // dispatched normally
    up_tx
        .send(encode_up(FrameType::Open, "s2", "real", b"other:"))
        .await
        .expect("send legit open");
    let other_poll = poll(&mut other, "other").await;
    let mut other_body = other_poll.into_body();
    let mut got_open = false;
    let mut buf = BytesMut::new();
    let deadline = tokio::time::Instant::now() + Duration::from_secs(3);
    loop {
        match tokio::time::timeout_at(deadline, other_body.frame()).await {
            Err(_) => break,
            Ok(None) | Ok(Some(Err(_))) => break,
            Ok(Some(Ok(frame))) => {
                let Ok(data) = frame.into_data() else {
                    continue;
                };
                buf.extend_from_slice(&data);
                while let DecodeOutcome::Ok(f) = decode_frame(&mut buf) {
                    if matches!(f.frame_type, FrameType::Open) && f.stream_id == "s2" {
                        got_open = true;
                        break;
                    }
                }
                if got_open {
                    break;
                }
            }
        }
    }
    assert!(
        got_open,
        "the upload should survive the forged-frame rejection and dispatch legitimate frames normally"
    );
}

/// Eviction (heartbeat loss of contact) → the upload lease is cancelled → the
/// upload response ends; a rebuild self-heals via implicit re-registration.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn evict_ends_upload_and_reupload_implicitly_reregisters() {
    let port = pick_ephemeral_port();
    let hb = HeartbeatConfig {
        enabled: true,
        interval_secs: 1,
        max_missed: 1,
    };
    let _hub = spawn_hub(hub_config_tuned(port, vec![], security(), hb)).await;

    let mut a = connect(port).await;
    assert_eq!(register(&mut a, "wedge").await, 200);
    let (_up_tx, up_resp) = open_upload_ok(&mut a, "wedge").await;
    let mut up_body = up_resp.into_body();

    // Confirm heartbeat capability, then go silent → eviction
    assert_eq!(post_pong(&mut a, "wedge").await, 204);
    let deadline = tokio::time::Instant::now() + Duration::from_secs(8);
    loop {
        if !list_agents(&mut a).await.contains(&"wedge".to_string()) {
            break;
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "heartbeat loss of contact should evict within the grace"
        );
        tokio::time::sleep(Duration::from_millis(100)).await;
    }

    // Eviction cancels the lease → the upload response ends (the death signal
    // on the agent side)
    let ended = tokio::time::timeout(Duration::from_secs(3), async {
        loop {
            match up_body.frame().await {
                None | Some(Err(_)) => break,
                Some(Ok(_)) => continue,
            }
        }
    })
    .await;
    assert!(
        ended.is_ok(),
        "the upload response should end after eviction"
    );

    // Rebuild the upload → implicit re-registration (the same self-healing as
    // /poll)
    let (_up_tx2, up_resp2) = open_upload(&mut a, "wedge").await;
    assert_eq!(
        up_resp2.status(),
        200,
        "rebuilding the upload should implicitly re-register successfully"
    );
    assert!(
        list_agents(&mut a).await.contains(&"wedge".to_string()),
        "should be back in the registry after implicit re-registration"
    );
}
