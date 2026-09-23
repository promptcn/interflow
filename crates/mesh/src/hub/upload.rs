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
//! stream not found) go back as hub-origin Close frames (stream id in the
//! header, u8 reason code in the payload) on the sender's `/poll` channel; a
//! single anomalous frame does not tear down the upload; only wire decoding
//! errors (invalid magic / version / fields / contract violations) end the
//! entire upload stream.

use crate::hub::routing::Direction;
use crate::hub::service::{HubService, circuit_token_of, text_response};
use crate::hub::state::HubResponseBody;
use bytes::{Bytes, BytesMut};
use http_body_util::{BodyExt, StreamBody};
use hyper::body::{Frame as HttpFrame, Incoming};
use hyper::{Request, Response, StatusCode};
use interflow_core::error::{InterflowError, Result};
use interflow_core::protocol::frame as wire;
use interflow_core::protocol::{CircuitToken, CloseReason, FrameType, RouteToken, StreamProto};
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
        let circuit = circuit_token_of(&req)?;
        let agent_key = self.qualified_id().await;

        if self.circuit().await != Some(circuit) {
            return Ok(text_response(StatusCode::UNAUTHORIZED, "Circuit mismatch"));
        }

        // Take the AgentSession (outer read lock is very short-lived);
        // unregistered → implicit rebuild (same self-healing as /poll)
        let state_arc = {
            let agents = self.state.agents.read().await;
            agents.get(&agent_key).cloned()
        };
        let state_arc = match state_arc {
            Some(a) => a,
            None => self.implicit_re_register(&agent_key).await,
        };
        if state_arc.read().await.circuit != circuit {
            return Ok(text_response(StatusCode::UNAUTHORIZED, "Circuit mismatch"));
        }

        // Acquire the upload lease: an active upload in the same generation
        // → 409; a stale cancelled lease is replaced directly
        let lease = {
            let mut state = state_arc.write().await;
            match &state.up_lease {
                Some(l) if !l.is_cancelled() => {
                    warn!(
                        "Agent circuit={circuit} attempted upload but no lease available (in use)"
                    );
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
            agent_key.clone(),
            circuit,
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

        info!("Agent circuit={circuit} entering streaming upload mode");
        Ok(response)
    }

    /// Dispatches a single uplink frame (called by the reader task).
    ///
    /// Anti-spoofing and anti-impersonation: an agent-origin frame must carry
    /// exactly this TLS connection's registration circuit (request direction)
    /// or the response-direction flag (`FLAG_RESPONSE` + zero circuit);
    /// `FLAG_HUB_ORIGIN` and the hub-only frame types are rejected outright
    /// (the codec already refuses structurally inconsistent shapes — this is
    /// the role check on top). Open payloads must be a route token owned by
    /// that source session.
    ///
    /// Returns `false` when the frame is a protocol violation that must end
    /// the whole upload stream (hub and agent deploy as one paired build —
    /// there is no version-skew case to tolerate).
    async fn dispatch_up_frame(
        &self,
        agent_key: &str,
        state_arc: &Arc<RwLock<crate::hub::state::AgentSession>>,
        circuit: CircuitToken,
        frame: wire::DecodedFrame,
    ) -> bool {
        let hub_origin = frame.flags & interflow_core::protocol::FLAG_HUB_ORIGIN != 0;
        if hub_origin {
            warn!(
                "upload frame spoofing: agent set HUB_ORIGIN (stream_id={})",
                frame.stream_id
            );
            metrics::counter!("interflow_hub_auth_failures", "reason" => "up_frame_hub_origin")
                .increment(1);
            return false;
        }
        if matches!(
            frame.frame_type,
            FrameType::HelloAck
                | FrameType::Ping
                | FrameType::OpenAck
                | FrameType::RouteAck
                | FrameType::Error
        ) {
            warn!(
                "upload frame spoofing: hub-only type {:?} from agent (stream_id={})",
                frame.frame_type, frame.stream_id
            );
            metrics::counter!("interflow_hub_auth_failures", "reason" => "up_frame_hub_only_type")
                .increment(1);
            return false;
        }
        let direction = if frame.flags & interflow_core::protocol::FLAG_RESPONSE != 0 {
            Direction::Response
        } else if frame.circuit == circuit {
            Direction::Request
        } else {
            warn!(
                "upload frame spoofing: circuit mismatch (stream_id={})",
                frame.stream_id
            );
            metrics::counter!("interflow_hub_auth_failures", "reason" => "up_frame_spoofed")
                .increment(1);
            self.notify_sender_close(agent_key, frame.stream_id, "spoofed source")
                .await;
            return true;
        };

        // Data-plane Pong (root fix, 2026-09-13): heartbeat replies travel
        // back on the upload stream, proving the agent→hub data path is
        // alive — together with the Ping dispatched via /poll this forms a
        // complete data-plane heartbeat loop. Control frames carry no stream
        // semantics and are handled before the stream_id validation.
        if frame.frame_type == FrameType::Pong {
            // The Pong's circuit field must re-identify this connection
            // (anti-spoof; the codec guarantees a nonzero circuit on Pong).
            if frame.circuit != circuit {
                warn!("upload Pong circuit mismatch (got {})", frame.circuit);
                metrics::counter!("interflow_hub_auth_failures", "reason" => "pong_circuit_mismatch")
                    .increment(1);
                return false;
            }
            let state_arc = {
                let agents = self.state.agents.read().await;
                agents.get(agent_key).cloned()
            };
            if let Some(state_arc) = state_arc {
                state_arc.write().await.last_pong = Instant::now();
                metrics::counter!("interflow_hub_pong_received", "path" => "upload").increment(1);
                debug!("agent circuit={circuit} heartbeat Pong (upload data stream)");
            }
            return true;
        }

        // The codec's contract table already guarantees a nonzero stream id
        // on the traffic types (a zero id decodes as an error upstream).

        match frame.frame_type {
            FrameType::Open => {
                let route = (frame.payload.len() == 16)
                    .then(|| RouteToken::from_bytes(frame.payload[..16].try_into().expect("16B")))
                    .filter(|t| !t.is_zero());
                let Some(route) = route else {
                    self.notify_sender_close(agent_key, frame.stream_id, "invalid open payload")
                        .await;
                    return true;
                };
                let proto = StreamProto::from_frame_flags(frame.flags);
                let e2e = frame.flags & interflow_core::protocol::FLAG_E2E != 0;
                if let Err(reason) = self
                    .frame_open(
                        state_arc,
                        agent_key,
                        circuit,
                        frame.stream_id,
                        route,
                        proto,
                        e2e,
                    )
                    .await
                {
                    self.notify_sender_close(agent_key, frame.stream_id, reason)
                        .await;
                }
                true
            }
            FrameType::Data => {
                if let Err(reason) = self
                    .frame_data(
                        agent_key,
                        circuit,
                        frame.stream_id,
                        direction,
                        frame.payload,
                    )
                    .await
                {
                    self.notify_sender_close(agent_key, frame.stream_id, reason)
                        .await;
                }
                true
            }
            FrameType::Close => {
                let reason = CloseReason::from_payload(&frame.payload);
                self.frame_close(agent_key, circuit, frame.stream_id, direction, &reason)
                    .await;
                true
            }
            // Control frames (Hello/Ping/Error etc.) do not travel on the
            // upload stream — the Ping heartbeat is dispatched via /poll
            // (Pong is handled in the data-plane Pong branch above). A
            // paired-build agent never sends them here, so their presence is
            // a protocol violation: end the upload stream.
            other => {
                warn!(
                    "upload stream protocol violation: non-traffic frame type={other:?}, stream_id={}",
                    frame.stream_id
                );
                false
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
    agent_key: String,
    circuit: CircuitToken,
    state_arc: Arc<RwLock<crate::hub::state::AgentSession>>,
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
                                if !svc
                                    .dispatch_up_frame(&agent_key, &state_arc, circuit, f)
                                    .await
                                {
                                    break 'outer "non_traffic_frame";
                                }
                            }
                            wire::DecodeOutcome::Pending => break,
                            wire::DecodeOutcome::Error => {
                                warn!("upload stream protocol frame invalid: circuit={circuit}");
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
    debug!("agent circuit={circuit} upload stream ended: {why}");
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
