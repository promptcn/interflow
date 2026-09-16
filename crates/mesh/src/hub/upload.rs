//! `/stream/up` handling: long-lived streamed upload from agent → hub
//! (mirror of `/poll`).
//!
//! Shape (fully symmetric with `/poll`):
//! - The request body is a stream of wire frames (self-describing incremental
//!   decoding via `interflow_core::protocol::frame`); a hub-side reader task
//!   dispatches frame by frame to the frame-level functions in
//!   [`crate::hub::routing`];
//! - The response returns 200 immediately after the placeholder succeeds and
//!   its body stays open — **response body end = this upload terminates**
//!   (eviction / preemption / disconnect); the agent detects this and
//!   rebuilds immediately;
//! - Single-consumer semantics: an agent that already has an active upload
//!   gets 409; register preemption and [`crate::hub::heartbeat::evict_agent`]
//!   eviction cancel the lease (`AgentSession::up_lease`);
//! - An unregistered agent is implicitly re-registered (reusing the
//!   self-healing path of `/poll`).
//!
//! Error signaling: frame-level rejections (ACL / limits / target unreachable /
//! stream not found) go back as `"_close_"` frames (`CLOSE:{sid}:{reason}`) on
//! the sender's `/poll` channel; a single anomalous frame does not tear down
//! the upload; only wire decoding errors (invalid magic / version / fields)
//! end the entire upload stream.

use crate::hub::routing::{Direction, valid_agent_id, valid_stream_id, valid_target_addr};
use crate::hub::service::{HubService, text_response};
use crate::hub::state::{AgentSession, HubResponseBody};
use bytes::{Bytes, BytesMut};
use http_body_util::{BodyExt, StreamBody};
use hyper::body::{Frame as HttpFrame, Incoming};
use hyper::{Request, Response, StatusCode};
use interflow_core::error::{InterflowError, Result};
use interflow_core::protocol::frame as wire;
use interflow_core::protocol::{FrameType, StreamProto};
use interflow_core::tunnel::RESPONSE_SOURCE;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Instant;
use tokio::sync::{RwLock, oneshot};
use tokio_util::sync::CancellationToken;
use tracing::{debug, info, warn};

impl HubService {
    /// Handles a `POST /stream/up` long-lived upload request.
    ///
    /// Authentication and identity binding are the same as `/poll`; after 200
    /// the response body lives as long as the reader task — when the reader
    /// ends (lease cancelled / agent disconnected / protocol error) the
    /// response body ends and the agent rebuilds immediately.
    pub(crate) async fn handle_stream_up(
        &self,
        req: Request<Incoming>,
    ) -> Result<Response<HubResponseBody>> {
        let agent_id = req
            .headers()
            .get("x-agent-id")
            .and_then(|v| v.to_str().ok())
            .ok_or_else(|| InterflowError::config("missing agent-id".to_string()))?
            .to_string();
        let agent_id = agent_id.as_str();

        // Identity binding check (the same gate as /poll)
        {
            let mut identity = self.connection_identity.write().await;
            if let Some(existing_id) = &*identity {
                if existing_id != agent_id {
                    warn!(
                        "identity mismatch: connection is bound to {}, but upload attempt is from {agent_id}",
                        existing_id
                    );
                    return Ok(text_response(StatusCode::FORBIDDEN, "Identity mismatch"));
                }
            } else {
                *identity = Some(agent_id.to_string());
                debug!("Connection bound to identity (upload): {agent_id}");
            }
        }

        // Take the AgentSession (outer read lock is very short-lived);
        // unregistered → implicit rebuild (same self-healing as /poll)
        let state_arc = {
            let agents = self.agents.read().await;
            agents.get(agent_id).cloned()
        };
        let state_arc = match state_arc {
            Some(a) => a,
            None => self.implicit_re_register(agent_id).await,
        };

        // Acquire the upload lease: an active upload in the same generation
        // → 409; a stale cancelled lease is replaced directly
        let lease = {
            let mut state = state_arc.write().await;
            match &state.up_lease {
                Some(l) if !l.is_cancelled() => {
                    warn!("Agent {agent_id} attempted upload but no lease available (in use)");
                    return Ok(text_response(StatusCode::CONFLICT, "Upload busy"));
                }
                _ => {
                    let lease = Arc::new(CancellationToken::new());
                    state.up_lease = Some(lease.clone());
                    lease
                }
            }
        };

        // Reader task: holds the request body, incrementally decoding and
        // dispatching frame by frame
        let (end_tx, end_rx) = oneshot::channel::<()>();
        let reader_svc = self.clone();
        tokio::spawn(upload_reader(
            reader_svc,
            agent_id.to_string(),
            state_arc,
            lease,
            req.into_body(),
            end_tx,
        ));

        // 200 + a body that lives with the reader: reader end (drop end_tx) →
        // body END_STREAM → the agent perceives the death signal. Headers are
        // sent immediately (same shape as the /poll response: body starts
        // empty and Pending, so the status code is not delayed).
        let body = StreamBody::new(upload_end_stream(end_rx)).boxed();
        let response = Response::builder()
            .status(StatusCode::OK)
            .body(body)
            .expect("status+body response is infallible");

        info!("Agent {agent_id} entering streaming upload mode");
        Ok(response)
    }

    /// Dispatches a single uplink frame (called by the reader task).
    ///
    /// Anti-spoofing: the frame's `source_agent` must equal the connection
    /// identity (request direction) or be the `"_response_"` sentinel
    /// (response direction); Open's target and address fields are validated
    /// against the same allowlist as the routing layer. Rejections do not
    /// tear down the upload.
    async fn dispatch_up_frame(&self, agent_id: &str, frame: wire::DecodedFrame) {
        let direction = if frame.source_agent == RESPONSE_SOURCE {
            Direction::Response
        } else if frame.source_agent == agent_id {
            Direction::Request
        } else {
            warn!(
                "upload frame spoofing: connection identity {agent_id}, frame claims {} (stream_id={})",
                frame.source_agent, frame.stream_id
            );
            metrics::counter!("interflow_hub_auth_failures", "reason" => "up_frame_spoofed")
                .increment(1);
            self.notify_sender_close(agent_id, &frame.stream_id, "spoofed source")
                .await;
            return;
        };

        // Data-plane Pong (root fix, 2026-09-13): heartbeat replies travel
        // back on the upload stream, proving the agent→hub data path is
        // alive — together with the Ping dispatched via /poll this forms a
        // complete data-plane heartbeat loop. Control frames carry no stream
        // semantics and are handled before the stream_id validation.
        if frame.frame_type == FrameType::Pong {
            let state_arc = {
                let agents = self.agents.read().await;
                agents.get(agent_id).cloned()
            };
            if let Some(state_arc) = state_arc {
                state_arc.write().await.last_pong = Instant::now();
                metrics::counter!("interflow_hub_pong_received", "path" => "upload").increment(1);
                debug!("agent {agent_id} heartbeat Pong (upload data stream)");
            }
            return;
        }

        if !valid_stream_id(&frame.stream_id) {
            debug!(
                "upload frame stream_id invalid: {:?}, dropping",
                frame.stream_id
            );
            return;
        }

        match frame.frame_type {
            FrameType::Open => {
                // payload = "{target_agent}:{target_addr}" (same encoding as
                // the QUIC backend)
                let payload = String::from_utf8_lossy(&frame.payload).to_string();
                let (target_agent, target_addr) = match payload.split_once(':') {
                    Some((t, a)) => (t.to_string(), (!a.is_empty()).then(|| a.to_string())),
                    None => (payload, None),
                };
                if !valid_agent_id(&target_agent)
                    || target_addr
                        .as_deref()
                        .is_some_and(|a| !valid_target_addr(a))
                {
                    self.notify_sender_close(agent_id, &frame.stream_id, "invalid open payload")
                        .await;
                    return;
                }
                let proto = StreamProto::from_frame_flags(frame.flags);
                if let Err(reason) = self
                    .frame_open(
                        agent_id,
                        &frame.stream_id,
                        &target_agent,
                        target_addr.as_deref(),
                        proto,
                    )
                    .await
                {
                    self.notify_sender_close(agent_id, &frame.stream_id, reason)
                        .await;
                }
            }
            FrameType::Data => {
                if let Err(reason) = self
                    .frame_data(agent_id, &frame.stream_id, direction, frame.payload)
                    .await
                {
                    self.notify_sender_close(agent_id, &frame.stream_id, reason)
                        .await;
                }
            }
            FrameType::Close => {
                let reason = crate::hub::control::close_reason_of(&frame.payload);
                self.frame_close(agent_id, &frame.stream_id, direction, &reason)
                    .await;
            }
            // Other control frames (Hello/Ping/Error etc.) do not travel on
            // the upload stream — the Ping heartbeat is dispatched via /poll
            // (Pong is handled in the data-plane Pong branch above); silently
            // ignored for forward compatibility.
            other => {
                debug!(
                    "upload stream ignored non-traffic frame: type={other:?}, stream_id={}",
                    frame.stream_id
                );
            }
        }
    }
}

/// `/stream/up` reader task: incrementally decodes the request body and
/// dispatches frame by frame.
///
/// Exit paths (mutually exclusive):
/// - lease cancelled (register preemption / eviction);
/// - body EOF (agent half-close) or read error (connection dead);
/// - wire decoding error (protocol violation — ends the entire upload
///   stream, so the agent's rebuild starts from a clean decoding state).
///
/// On exit the lease is returned (only if still its own, judged via ptr_eq)
/// and `end_tx` is dropped → the response body ends → the agent rebuilds
/// the upload.
async fn upload_reader(
    svc: HubService,
    agent_id: String,
    state_arc: Arc<RwLock<AgentSession>>,
    lease: Arc<CancellationToken>,
    mut body: Incoming,
    end_tx: oneshot::Sender<()>,
) {
    let mut buf = BytesMut::with_capacity(16 * 1024);
    let why: &'static str = 'outer: loop {
        tokio::select! {
            () = lease.cancelled() => break 'outer "lease_cancelled",
            r = body.frame() => match r {
                None => break 'outer "eof",
                Some(Err(_)) => break 'outer "read_error",
                Some(Ok(frame)) => {
                    let Ok(data) = frame.into_data() else { continue };
                    buf.extend_from_slice(&data);
                    loop {
                        match wire::decode_frame(&mut buf) {
                            wire::DecodeOutcome::Ok(f) => {
                                svc.dispatch_up_frame(&agent_id, f).await;
                            }
                            wire::DecodeOutcome::Pending => break,
                            wire::DecodeOutcome::Error => {
                                warn!("upload stream protocol frame invalid: agent={agent_id}");
                                break 'outer "protocol_error";
                            }
                            wire::DecodeOutcome::UnknownType { must_understand, .. } => {
                                if must_understand {
                                    break 'outer "unknown_must_understand";
                                }
                                // Skippable unknown frame: keep decoding
                                // subsequent frames
                            }
                        }
                    }
                }
            },
        }
    };

    // Return the lease (only if still its own — register preemption or
    // eviction may have taken it over in the meantime)
    {
        let mut st = state_arc.write().await;
        if st.up_lease.as_ref().is_some_and(|l| Arc::ptr_eq(l, &lease)) {
            st.up_lease = None;
        }
    }
    debug!("agent {agent_id} upload stream ended: {why}");
    drop(end_tx); // → response body END_STREAM → agent rebuilds the upload
}

/// oneshot end signal → http body stream adapter: Pending until the signal
/// arrives (body stays open), then `None` (END_STREAM) once it arrives or the
/// sending end is dropped.
fn upload_end_stream(
    mut end_rx: oneshot::Receiver<()>,
) -> impl futures::Stream<Item = std::result::Result<HttpFrame<Bytes>, InterflowError>> {
    futures::stream::poll_fn(
        move |cx: &mut Context<'_>| -> Poll<Option<std::result::Result<HttpFrame<Bytes>, InterflowError>>> {
            match Pin::new(&mut end_rx).poll(cx) {
                // Ready (signal arrived or sender dropped) → body ends;
                // Pending → stays open
                Poll::Ready(_) => Poll::Ready(None),
                Poll::Pending => Poll::Pending,
            }
        },
    )
}
