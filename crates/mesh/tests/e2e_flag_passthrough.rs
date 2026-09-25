//! E2E: frame-level flags integrity across the hub's relay rebuild points.
//!
//! The hub is a frame-aware relay: it decodes Open frames and *rebuilds*
//! them for the target agent (the flag reconstruction lives in
//! `hub/routing.rs` for h2 targets and `hub/quic.rs` for QUIC relay
//! targets). A rebuild that drops `FLAG_E2E` or `FLAG_UDP` silently changes
//! stream semantics — "stripped FLAG_E2E" is exactly the downgrade the
//! e2e-required egress exists to reject. The behavioral suites
//! (`e2e_inner_tls*`, `e2e_quic` transport matrix) cover this indirectly;
//! this test pins the *bits themselves*: every flag combination carried on
//! an Open frame must arrive at the target agent with the identical flags
//! byte.
//!
//! Plane coverage: this file drives the h2 plane end-to-end (upload →
//! routing → poll), pinning the `hub/routing.rs` rebuild. The QUIC relay
//! rebuild points (`hub/quic.rs` `open_relay_stream` / datagram path) are
//! pinned behaviorally by the cross-transport matrix in `e2e_quic.rs` and
//! `e2e_inner_tls.rs`.

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
use interflow_core::protocol::{CircuitToken, RouteToken, StreamId};
use interflow_core::tunnel::H2RequestBody;
use interflow_core::tunnel::negotiation::{RegisterResponse, RouteResponse};
use interflow_mesh::config::{HeartbeatConfig, HubSecurityConfig};
use interflow_testkit::{hub_config_tuned, spawn_hub};
use std::time::Duration;
use tokio::sync::mpsc;

fn certs() -> &'static interflow_testkit::certs::TestCerts {
    static C: std::sync::OnceLock<interflow_testkit::certs::TestCerts> = std::sync::OnceLock::new();
    C.get_or_init(|| interflow_testkit::certs::TestCerts::generate("e2e", "agent"))
}

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

async fn register(snd: &mut SendRequest<H2RequestBody>, id: &str) -> CircuitToken {
    snd.ready().await.expect("ready");
    let req = Request::builder()
        .method("POST")
        .uri("/register")
        .header("x-agent-id", id)
        .body(interflow_core::tunnel::empty_request_body())
        .unwrap();
    let resp = snd.send_request(req).await.expect("register");
    assert_eq!(resp.status(), 200);
    let body = resp.into_body().collect().await.expect("register body");
    RegisterResponse::parse(&body.to_bytes())
        .expect("capability")
        .circuit_token
}

async fn route(
    snd: &mut SendRequest<H2RequestBody>,
    circuit: CircuitToken,
    target: &str,
) -> RouteToken {
    snd.ready().await.expect("ready");
    let body = http_body_util::Full::new(Bytes::copy_from_slice(target.as_bytes()))
        .map_err(|never| match never {})
        .boxed();
    let req = Request::builder()
        .method("POST")
        .uri("/route")
        .header("x-circuit-token", circuit.to_hex())
        .body(body)
        .unwrap();
    let resp = snd.send_request(req).await.expect("route");
    assert_eq!(resp.status(), 200);
    let body = resp.into_body().collect().await.expect("route body");
    serde_json::from_slice::<RouteResponse>(&body.to_bytes())
        .expect("route token")
        .route_token
}

async fn open_upload(
    snd: &mut SendRequest<H2RequestBody>,
    circuit: CircuitToken,
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
        .header("x-circuit-token", circuit.to_hex())
        .body(body)
        .unwrap();
    let resp = snd.send_request(req).await.expect("upload request");
    assert_eq!(resp.status(), 200, "upload should succeed");
    (tx, resp)
}

async fn open_poll(
    snd: &mut SendRequest<H2RequestBody>,
    circuit: CircuitToken,
) -> hyper::body::Incoming {
    snd.ready().await.expect("ready");
    let req = Request::builder()
        .method("GET")
        .uri("/poll")
        .header("x-circuit-token", circuit.to_hex())
        .body(interflow_core::tunnel::empty_request_body())
        .unwrap();
    snd.send_request(req).await.expect("poll").into_body()
}

/// The flag combinations an Open frame may carry (MUST_UNDERSTAND is not an
/// Open semantic; the passthrough contract is about UDP/E2E).
const OPEN_FLAG_COMBOS: [u8; 4] = [0x00, 0x08, 0x10, 0x18];

/// Every Open flag combination must reach the target agent with the exact
/// same bits, the requester circuit as the Open payload, and the `_open_`
/// notification source — the h2 rebuild contract in one table.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn open_flags_survive_hub_relay_rebuild() {
    let port = spawn_hub(hub_config_tuned(
        0,
        certs(),
        vec![],
        security(),
        HeartbeatConfig::default(),
    ))
    .await
    .local_addr()
    .expect("hub bound")
    .port();

    // Target agent first: Open delivery requires a registered target.
    let mut dst = connect(port, "dst").await;
    let dst_circuit = register(&mut dst, "dst").await;
    let mut poll_body = open_poll(&mut dst, dst_circuit).await;

    // Source agent: register, lease a route to dst, open the upload.
    let mut src = connect(port, "src").await;
    let src_circuit = register(&mut src, "src").await;
    let route_token = route(&mut src, src_circuit, "dst").await;
    let (up, _upload_resp) = open_upload(&mut src, src_circuit).await;

    // One Open per flag combination, each on its own stream id.
    let mut expected: Vec<(StreamId, u8)> = Vec::new();
    for flags in OPEN_FLAG_COMBOS {
        let sid = StreamId::random().unwrap();
        let mut buf = BytesMut::new();
        encode_frame(
            FrameType::Open,
            flags,
            sid,
            src_circuit,
            &route_token.to_bytes(),
            &mut buf,
        )
        .expect("encode open");
        up.send(buf.freeze()).await.expect("send open");
        expected.push((sid, flags));
    }

    // Read the poll body: collect the relayed Open frames and assert the
    // bits arrived intact. Skip heartbeat Pings and other noise.
    let mut seen: Vec<(StreamId, u8, CircuitToken)> = Vec::new();
    let mut buf = BytesMut::new();
    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    while seen.len() < expected.len() {
        let frame_res = tokio::time::timeout_at(deadline, poll_body.frame()).await;
        match frame_res {
            Err(_) => panic!(
                "timed out: saw only {}/{} open frames",
                seen.len(),
                expected.len()
            ),
            Ok(None) | Ok(Some(Err(_))) => panic!(
                "poll ended early: saw only {}/{} open frames",
                seen.len(),
                expected.len()
            ),
            Ok(Some(Ok(frame))) => {
                let Ok(data) = frame.into_data() else {
                    continue;
                };
                buf.extend_from_slice(&data);
                while let DecodeOutcome::Ok(f) = decode_frame(&mut buf) {
                    if matches!(f.frame_type, FrameType::Open) {
                        seen.push((f.stream_id, f.flags, f.circuit));
                    }
                }
            }
        }
    }

    for (sid, flags) in &expected {
        let found = seen
            .iter()
            .find(|(seen_sid, _, _)| seen_sid == sid)
            .unwrap_or_else(|| panic!("open frame for stream {sid} never arrived"));
        assert_eq!(
            found.1, *flags,
            "flags must survive the hub rebuild bit-for-bit for stream {sid}"
        );
        assert_eq!(
            found.2, src_circuit,
            "the requester circuit must ride the header field (h2 plane contract; payload empty)"
        );
    }
}
