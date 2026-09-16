//! E2E: tunnel request send-establishment timeout (regression tests for
//! docs/bug/2026-09-16-edge-self-dial-agent-no-reregister.md §4.2).
//!
//! Failure form under test: a `/poll` or `/stream/up` request that never
//! reaches response headers. Before the fix, the request future was raced
//! only against shutdown — no timeout — so this form parked the loop
//! forever. It is *invisible to every existing sensor*:
//!
//! - the poll receive-side watchdog only starts once response headers
//!   arrive, so it never engages;
//! - the connection layer stays healthy (the h2 connection task keeps
//!   running), so the connection-death path never engages;
//! - the hub (here: a fake that simply never answers) does nothing.
//!
//! That is precisely the silent-wedge shape of the 2026-09-16 incident
//! family: the last-words log fires ("reconnecting…"), then nothing — no
//! rebuild, no error, no recovery.
//!
//! Fixed semantics (covered by the two cases below): exceeding the
//! establish bound cancels the session token — identical to the watchdog's
//! move — so the supervisor rebuilds the session and re-registers. Must fail
//! before the fix (registrations stay at 1; no Reconnecting is ever
//! observed).

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
use interflow_mesh::agent::AgentState;
use interflow_testkit::{agent_config, spawn_agent_registered};
use std::future::Future;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::task::{Context, Poll};
use std::time::Duration;
use tokio::net::TcpListener;

/// Which request the fake hub strangles: it accepts the request but never
/// sends response headers (the service future never resolves — hyper holds
/// the stream open, everything else on the connection stays healthy).
#[derive(Clone, Copy)]
struct Hang {
    poll: bool,
    upload: bool,
}

#[derive(Default)]
struct Counts {
    registers: AtomicUsize,
}

struct FakeHub {
    addr: SocketAddr,
    counts: Arc<Counts>,
}

async fn spawn_fake_hub(hang: Hang) -> FakeHub {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("fake hub bind");
    let addr = listener.local_addr().expect("fake hub addr");
    let counts = Arc::new(Counts::default());
    let svc = FakeHubSvc {
        hang,
        counts: counts.clone(),
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
    // Pending forever without registering a waker (the real hub's
    // death-signal semantics on a healthy stream)
    StreamBody::new(futures::stream::poll_fn(|_cx: &mut Context<'_>| {
        Poll::Pending as Poll<Option<std::result::Result<HttpFrame<Bytes>, InterflowError>>>
    }))
    .boxed()
}

/// The request never even gets response headers: the arm pends forever
/// (hyper never sends headers until the service future resolves — everything
/// else on the connection stays healthy).
macro_rules! never_resolves {
    () => {{
        let resp: Response<BoxBody<Bytes, InterflowError>> = std::future::pending().await;
        resp
    }};
}

#[derive(Clone)]
struct FakeHubSvc {
    hang: Hang,
    counts: Arc<Counts>,
}

impl Service<Request<Incoming>> for FakeHubSvc {
    type Response = Response<BoxBody<Bytes, InterflowError>>;
    type Error = std::convert::Infallible;
    type Future =
        Pin<Box<dyn Future<Output = std::result::Result<Self::Response, Self::Error>> + Send>>;

    fn call(&self, req: Request<Incoming>) -> Self::Future {
        let counts = self.counts.clone();
        let hang = self.hang;
        Box::pin(async move {
            let resp = match (req.method().as_str(), req.uri().path()) {
                ("POST", "/register") => {
                    counts.registers.fetch_add(1, Ordering::SeqCst);
                    // Modern caps: pong via upload + 1s heartbeat cadence (the
                    // watchdog override in the test config neutralizes this)
                    let caps = r#"{"pong_via_upload":true,"heartbeat":{"interval_secs":1,"max_missed":2}}"#;
                    Response::builder()
                        .status(StatusCode::OK)
                        .header(CONTENT_TYPE, "application/json")
                        .body(full_body(caps))
                        .unwrap()
                }
                ("GET", "/poll") if hang.poll => {
                    // Strangled poll: headers never arrive
                    never_resolves!()
                }
                ("GET", "/poll") => {
                    // Healthy-shaped poll: one Ping then a legitimately quiet
                    // stream (the establish timeout must fire long before the
                    // watchdog override does)
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
                ("POST", "/stream/up") if hang.upload => {
                    // Strangled upload: headers never arrive
                    never_resolves!()
                }
                ("POST", "/stream/up") => {
                    // Healthy-shaped upload: 200 + hanging body, frames decoded
                    // in the background (drains the client's uplink)
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
                                    DecodeOutcome::Ok(_) => {}
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
                ("POST", "/pong") => Response::builder()
                    .status(StatusCode::NO_CONTENT)
                    .body(full_body(Bytes::new()))
                    .unwrap(),
                _ => Response::builder()
                    .status(StatusCode::NOT_FOUND)
                    .body(full_body("not found"))
                    .unwrap(),
            };
            Ok(resp)
        })
    }
}

/// Shared assertion core: with a 1s establish bound the strangled request
/// must trigger a session rebuild (registers ≥ 2) and the supervisor must
/// stay healthy (keeps cycling back to Connected).
async fn assert_establish_timeout_recovers(
    fake: FakeHub,
    agent: interflow_mesh::agent::AgentHandle,
) {
    let mut rx = agent.subscribe_state();
    let window_end = tokio::time::Instant::now() + Duration::from_secs(10);
    let mut saw_reconnecting = false;
    while tokio::time::Instant::now() < window_end {
        if matches!(&*rx.borrow_and_update(), AgentState::Reconnecting { .. }) {
            saw_reconnecting = true;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    let registers = fake.counts.registers.load(Ordering::SeqCst);
    assert!(
        saw_reconnecting,
        "the strangled request should push the agent through Reconnecting (state: {:?})",
        agent.state()
    );
    assert!(
        registers >= 2,
        "the establish timeout must rebuild the session and re-register (registrations: {registers})"
    );
    // Loop health: against a permanently strangled fake hub the agent keeps
    // cycling "timeout → rebuild → register" and reaches Connected each round.
    assert!(
        interflow_testkit::wait_agent_connected(&agent, Duration::from_secs(10)).await,
        "the rebuild loop should keep recovering to Connected (state: {:?})",
        agent.state()
    );
    agent.shutdown_graceful().await.expect("agent shutdown");
}

/// Case A — the `/stream/up` request never reaches response headers (the
/// incident's upload-side shape: "upload stream" sends hang on a dead-ish
/// connection).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn upload_request_never_answering_rebuilds_session() {
    let fake = spawn_fake_hub(Hang {
        poll: false,
        upload: true,
    })
    .await;

    let mut cfg = agent_config("hang-upload", fake.addr.port());
    cfg.agent.hub_url = format!("http://{}", fake.addr);
    cfg.agent.request_establish_timeout_secs = Some(1);
    // Keep the watchdog far away so the ONLY thing that can fire here is the
    // establish bound.
    cfg.agent.poll_idle_timeout_secs = Some(30);
    let agent = spawn_agent_registered(cfg).await;

    assert_establish_timeout_recovers(fake, agent).await;
}

/// Case B — the `/poll` request never reaches response headers (the watchdog
/// can never start; before the fix this parked the poll loop forever).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn poll_request_never_answering_rebuilds_session() {
    let fake = spawn_fake_hub(Hang {
        poll: true,
        upload: false,
    })
    .await;

    let mut cfg = agent_config("hang-poll", fake.addr.port());
    cfg.agent.hub_url = format!("http://{}", fake.addr);
    cfg.agent.request_establish_timeout_secs = Some(1);
    cfg.agent.poll_idle_timeout_secs = Some(30);
    let agent = spawn_agent_registered(cfg).await;

    assert_establish_timeout_recovers(fake, agent).await;
}
