//! Tunnel transport abstraction: the agent-side tunnel operation trait (2026-09-11 backlog §6.3).
//!
//! `AgentTunnel` is the facade for consumers (mesh ingress/egress, expose edge)
//! and holds a `dyn TunnelTransport` backend. Current backends:
//! - [`crate::tunnel::h2::H2Tunnel`]: HTTP/2 + POST /stream + GET /poll (current semantics)
//! - (P2b) `QuicTunnel`: QUIC native streams carrying custom frames
//!
//! Design constraints:
//! - Direction and origin live in the frame flags (`FLAG_RESPONSE`,
//!   `FLAG_HUB_ORIGIN`) rather than in-band sentinel strings; the dispatch
//!   layer derives them into a [`FrameOrigin`];
//! - Two consumption forms on the inbound side (2026-09-12 refactor; lossy
//!   broadcast was removed):
//!   - **Response direction** (`FLAG_RESPONSE`): a dedicated channel
//!     registered via `register_stream` (ingress return path / expose
//!     edge), end-to-end backpressure;
//!   - **Request direction** (everything else, including loopback): dispatch
//!     creates a dedicated channel on Open and hands it to egress via
//!     `take_incoming_streams` (consumed by the per-stream forwarder).
//!     The channel is **created then handed off while still inside the dispatch
//!     lock** (dispatch is the sole writer of the table), so subsequent
//!     Data/Close frames always hit it — there is no registration race.
//!     Ordering is guaranteed by the transport: h2 has a total order over the
//!     single poll body; QUIC is ordered within each relay stream and Open is
//!     the first frame.
//! - When a single-stream consumer stalls, dispatch performs only a **bounded
//!   wait** ([`DISPATCH_SEND_TIMEOUT`]); on timeout it **poisons that stream**
//!   (remove the table entry → channel closes → consumer exits itself and
//!   sends a Close notification), without affecting other streams or tearing
//!   down the session;
//! - The new-stream event channel is also bounded ([`INCOMING_SEND_TIMEOUT`]):
//!   when the egress main loop is backlogged and dispatch's hand-off wait for
//!   an Open exceeds the limit, it **drops the event and rolls back the table
//!   entry** — flooding Opens no longer propagates a stall into a whole-agent
//!   eviction (already-established healthy streams are unaffected). Data/Close
//!   frames of established streams are still never silently dropped on any
//!   path.

use crate::error::Result;
use crate::protocol::{CloseReason, FrameOrigin, FrameType, StreamId, StreamProto};
use async_trait::async_trait;
use bytes::Bytes;
use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::time::{Duration, Instant};
use tokio::sync::{Notify, RwLock, mpsc};
use tracing::{debug, warn};

/// Tunnel data
#[derive(Debug, Clone)]
pub struct TunnelData {
    /// The stream id.
    pub stream_id: StreamId,
    /// The frame origin: an agent circuit, the response direction, or the hub
    /// (derived from the frame flags — replaces the former sentinel strings).
    pub origin: FrameOrigin,
    /// The payload.
    pub data: Bytes,
    /// The frame type.
    pub stream_type: FrameType,
    /// Wire flags bits (passed through). On Open frames, `FLAG_UDP` set means the stream carries UDP datagrams.
    pub flags: u8,
}

/// A new inbound stream in the request direction: the Open frame itself plus a dedicated channel for the stream's subsequent frames.
///
/// Handed to egress by [`TunnelTransport::take_incoming_streams`]; the channel
/// capacity is [`STREAM_CHANNEL_CAP`], and if the consumer (the per-stream
/// forwarder) stalls, dispatch applies a bounded wait with poisoning as the
/// fallback.
pub struct IncomingStream {
    /// The relayed Open frame (the requester circuit is the frame's circuit
    /// field; the payload is empty).
    pub open: TunnelData,
    /// The dedicated channel for this stream's subsequent Data/Close frames; closure is the poison signal.
    pub frames: mpsc::Receiver<TunnelData>,
}

/// The tunnel transport backend trait.
#[async_trait]
pub trait TunnelTransport: Send + Sync + 'static {
    /// Opens a tunnel stream (request direction).
    ///
    /// `proto` declares the protocol carried by the stream (TCP byte stream /
    /// UDP datagram).
    async fn send_open(
        &self,
        stream_id: StreamId,
        target_agent: &str,
        proto: StreamProto,
    ) -> Result<()> {
        self.send_open_with(stream_id, target_agent, proto, false)
            .await
    }

    /// [`TunnelTransport::send_open`] with the per-stream e2e (inner TLS)
    /// declaration: `true` sets [`crate::protocol::FLAG_E2E`] on the Open
    /// frame, asking the target agent for the agent↔agent TLS layer
    async fn send_open_with(
        &self,
        stream_id: StreamId,
        target_agent: &str,
        proto: StreamProto,
        e2e: bool,
    ) -> Result<()>;

    /// Sends a data frame (request direction, ingress → hub).
    async fn send_data(&self, stream_id: StreamId, data: Bytes) -> Result<()>;

    /// Sends a data frame (response direction, egress → hub).
    async fn send_data_response(&self, stream_id: StreamId, data: Bytes) -> Result<()>;

    /// Closes the stream (request direction).
    async fn send_close(&self, stream_id: StreamId) -> Result<()>;

    /// Closes the stream (response direction). `reason` travels as the u8
    /// Close payload code (the shared
    /// `interflow_contract::close_reason_code` table; [`CloseReason::CLOSE_FRAME`]
    /// = ordinary close) so the far end can distinguish backend failures from
    /// normal teardown (2026-09-16 reason-propagation hardening).
    async fn send_close_response(&self, stream_id: StreamId, reason: CloseReason) -> Result<()>;

    /// Registers the dedicated inbound channel for a response-direction stream (ingress return path / expose edge). Re-registering overwrites the old channel.
    async fn register_stream(&self, stream_id: StreamId) -> mpsc::Receiver<TunnelData>;

    /// Unregisters the dedicated channel for a response-direction stream.
    async fn unregister_stream(&self, stream_id: StreamId);

    /// Takes the receiver end for new request-direction stream events (consumed by egress). May only be taken once per tunnel;
    /// while not yet taken, request-direction Opens that arrive park waiting
    /// for takeover (bounded, see [`ATTACH_GRACE`]) — this covers the
    /// session-establishment timing window where "the hub dispatches an Open
    /// before the egress handler starts"; only after the timeout (abnormal
    /// routing to a pure ingress agent) is the Open dropped.
    async fn take_incoming_streams(&self) -> Option<mpsc::Receiver<IncomingStream>>;

    /// Unregisters the request-direction stream channel (called when a forwarder exits; idempotent).
    async fn unregister_incoming_stream(&self, stream_id: StreamId);

    /// Session-termination contract: releases all stream resources of this tunnel. Idempotent (repeat calls have no side effects).
    ///
    /// Semantics: calling this declares the end of this tunnel's session
    /// (disconnect / watchdog / user shutdown / direct-connection peer exit).
    /// Implementations must:
    /// 1. cancel internal background tasks (poll / upload / read loops);
    /// 2. clear both dispatch tables (drop all senders — leftover consumer
    ///    forwarders/pumps see `recv()` return `None` and exit naturally,
    ///    releasing backend connections and fds with them);
    /// 3. reclaim transport-backend-specific resources (e.g. QUIC closing the
    ///    connection and endpoint).
    ///
    /// This is the transport-side half of the invariant "no stream task may
    /// outlive the session lifecycle": consumers (the client teardown
    /// sequence) call it explicitly, and a background task dying on its own
    /// (e.g. the h2 poll exiting) also triggers the same table cleanup
    /// internally — two paths, so cleanup does not depend on any single call
    /// site remembering it.
    async fn shutdown(&self);
}

/// Capacity (in frames) of the per-stream dedicated channel. A healthy
/// consumer's steady-state backlog stays far below this; a full channel means
/// the consumer has stalled, handled by poisoning via [`DISPATCH_SEND_TIMEOUT`]
/// as the fallback — no unbounded backlog.
const STREAM_CHANNEL_CAP: usize = 256;

// Capacity of the new-stream event channel (control plane) is DERIVED from
// the agent's local concurrent stream limit (`max_incoming_streams`), not
// independently picked: the egress main loop drains instantly at steady
// state, the capacity exists to absorb stream-creation bursts, and a
// legitimate whole-table burst must not get stuck at the channel layer
// (previously the two 256s were unrelated literals that merely happened to
// match). See `config::params::transport::incoming_channel_cap`. Backlog
// beyond capacity is bounded by [`INCOMING_SEND_TIMEOUT`] as the fallback.

/// Bounded wait for dispatch delivering a single frame to a stream channel. On timeout the stream is poisoned (table entry removed, channel closed).
///
/// Must be significantly smaller than the hub-side `channel_send_timeout_secs`
/// (default 30s): a single-stream stall converges in place to that stream
/// closing before the hub evicts the agent, rather than escalating to a
/// whole-connection reconnect.
const DISPATCH_SEND_TIMEOUT: Duration = Duration::from_secs(5);

/// Bounded wait for dispatch handing an event off to the new-stream event channel. On timeout the event is dropped and the table entry rolled back
/// (that stream fails; the Close is finalized by the origin's timeout or the
/// hub's reaping, the same family as "late-frame dropping").
///
/// When an Open flood fills the event channel, the correct action is for the
/// new stream to yield rather than let dispatch hang indefinitely alongside
/// it: the bounded wait keeps progress visible to the poll body / QUIC read
/// loop, so a merely-lagging (still alive) egress main loop does not trigger
/// hub eviction. Must be significantly smaller than
/// [`DISPATCH_SEND_TIMEOUT`] and hub `channel_send_timeout_secs` (30s).
const INCOMING_SEND_TIMEOUT: Duration = Duration::from_secs(2);

/// Upper bound on how long an Open parks before egress takeover.
///
/// Session establishment has an inherent timing window: the hub can dispatch
/// an Open as soon as registration/poll is established, while the agent's
/// egress handler takes over inbound streams a beat later — if an Open
/// arriving within that window were dropped, the stream would hang silently
/// until the idle timeout (reproduced in the soak guardrail on 2026-09-13).
/// The parking wait covers this window (handler startup is on the order of
/// milliseconds); the truly-unclaimed case (abnormal routing) falls into the
/// existing drop path after this bound. The test profile shortens it to keep
/// test cases at second scale.
#[cfg(not(test))]
const ATTACH_GRACE: Duration = Duration::from_secs(10);
#[cfg(test)]
const ATTACH_GRACE: Duration = Duration::from_millis(200);

// The parking-wait concurrency budget mirrors the event-channel capacity
// (same anti-flood family; see `incoming_channel_cap`): an Open flood before
// takeover must not breed parking tasks without bound; over-budget Opens
// yield immediately.

/// Egress takeover latch: set when `take_incoming_streams` runs, waking parked Open hand-offs.
#[derive(Default)]
struct AttachGate {
    attached: AtomicBool,
    notify: Notify,
}

impl AttachGate {
    fn attach(&self) {
        self.attached.store(true, Ordering::Release);
        self.notify.notify_waiters();
    }

    fn is_attached(&self) -> bool {
        self.attached.load(Ordering::Acquire)
    }
}

/// Inbound frame dispatcher: shared by h2 (decoded from /poll) and QUIC (stream read tasks).
///
/// Direction classification replaces the old loopback/Open special-casing:
/// `FLAG_RESPONSE` → response direction; everything else (including loopback,
/// circuit == own) → request direction. The request/response channels for the
/// same sid live in two separate tables, so one agent playing both roles
/// (loopback) does not conflict.
pub(crate) struct TunnelDispatch {
    /// Response-direction stream channels (registered by ingress/edge via register_stream).
    resp_streams: Arc<RwLock<HashMap<StreamId, mpsc::Sender<TunnelData>>>>,
    /// Request-direction stream channels (created by dispatch on Open).
    req_streams: Arc<RwLock<HashMap<StreamId, mpsc::Sender<TunnelData>>>>,
    /// New-stream event sender (delivery only begins after the receiver is taken by egress; see open_request_stream).
    incoming_tx: mpsc::Sender<IncomingStream>,
    /// New-stream event receiver (take-once; still `Some` means egress has not taken over).
    incoming_rx: std::sync::Mutex<Option<mpsc::Receiver<IncomingStream>>>,
    /// Egress takeover latch (set on take; parked Opens wait on it).
    attach_gate: Arc<AttachGate>,
    /// Count of Opens parked in the wait (anti-flood budget).
    pending_attach: Arc<AtomicUsize>,
    /// Parking-wait concurrency budget (mirrors the event-channel capacity).
    pending_attach_cap: usize,
}

impl TunnelDispatch {
    /// Builds with the default event-channel budget (the shared floor) —
    /// for tests and callers without a stream limit.
    pub(crate) fn new() -> Self {
        Self::with_stream_limit(0)
    }

    /// Builds with the event-channel budget derived from the agent's local
    /// concurrent-stream limit: `max_incoming_streams` legitimate Opens must
    /// pass in one go; 0 (unlimited) falls back to the floor.
    pub(crate) fn with_stream_limit(max_incoming_streams: usize) -> Self {
        let cap = crate::config::params::transport::incoming_channel_cap(max_incoming_streams);
        let (incoming_tx, incoming_rx) = mpsc::channel(cap);
        Self {
            resp_streams: Arc::new(RwLock::new(HashMap::new())),
            req_streams: Arc::new(RwLock::new(HashMap::new())),
            incoming_tx,
            incoming_rx: std::sync::Mutex::new(Some(incoming_rx)),
            attach_gate: Arc::new(AttachGate::default()),
            pending_attach: Arc::new(AtomicUsize::new(0)),
            pending_attach_cap: cap,
        }
    }

    /// Registers a dedicated response-direction stream channel (capacity [`STREAM_CHANNEL_CAP`]: under congestion the sender
    /// applies a bounded wait + poisoning fallback, so a single stream's
    /// backlog cannot blow up memory).
    pub(crate) async fn register_stream(&self, stream_id: StreamId) -> mpsc::Receiver<TunnelData> {
        let (tx, rx) = mpsc::channel(STREAM_CHANNEL_CAP);
        let mut map = self.resp_streams.write().await;
        map.insert(stream_id, tx);
        rx
    }

    /// Unregisters the dedicated response-direction stream channel.
    pub(crate) async fn unregister_stream(&self, stream_id: StreamId) {
        let mut map = self.resp_streams.write().await;
        map.remove(&stream_id);
    }

    /// Takes the request-direction new-stream event receiver (take-once) and wakes parked Open hand-offs.
    pub(crate) fn take_incoming_streams(&self) -> Option<mpsc::Receiver<IncomingStream>> {
        let rx = self
            .incoming_rx
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .take();
        if rx.is_some() {
            self.attach_gate.attach();
        }
        rx
    }

    /// Unregisters the request-direction stream channel (called when a forwarder exits; idempotent).
    pub(crate) async fn unregister_incoming_stream(&self, stream_id: StreamId) {
        let mut map = self.req_streams.write().await;
        map.remove(&stream_id);
    }

    /// Session termination: clears the request-direction stream table, returning the number of entries released (idempotent; a second call returns 0).
    ///
    /// Dropping all senders → each stream's forwarder sees `recv()` return
    /// `None` and exits in place → backend connections (TCP fds / UDP
    /// sockets) are released as the tasks exit. This is the root cure for the
    /// retention cycle "forwarder holds tunnel Arc → dispatch holds sender →
    /// channel never closes": after the tunnel dies no new frames arrive, the
    /// poisoning path never triggers, so table entries must be released
    /// uniformly by the termination contract
    /// ([`TunnelTransport::shutdown`])
    pub(crate) async fn close_all_request_streams(&self) -> usize {
        let mut map = self.req_streams.write().await;
        let n = map.len();
        map.clear();
        n
    }

    /// Session termination: clears the response-direction stream table, returning the number of entries released (idempotent).
    ///
    /// Dropping all senders → the write half of the ingress/edge pump sees
    /// `recv()` return `None` and closes out → the client socket is closed
    /// with it (no longer relying on the idle timeout to expire on its own).
    pub(crate) async fn close_all_response_streams(&self) -> usize {
        let mut map = self.resp_streams.write().await;
        let n = map.len();
        map.clear();
        n
    }

    /// Dispatches a `TunnelData` frame to the corresponding stream channel based on direction.
    ///
    /// - Response direction (`FLAG_RESPONSE`): delivered on a resp-table hit,
    ///   dropped on a miss (late frame);
    /// - Close notification (a hub-authored Close, `FLAG_HUB_ORIGIN`, sent by
    ///   the hub when the peer tears down the stream): delivered to the req
    ///   table first (the egress
    ///   forwarder reclaims the slot/connection as soon as it receives it —
    ///   otherwise streams closed by the origin linger indefinitely on the
    ///   agent side); with no req-table entry it goes to the resp table
    ///   (ingress/edge stream teardown);
    /// - Request-direction Open: create the channel + hand off to egress (see
    ///   [`Self::open_request_stream`]);
    /// - Request-direction Data/Close: delivered on a req-table hit, dropped
    ///   on a miss (late frame, or a QUIC DATAGRAM arriving before the Open —
    ///   legitimate loss under UDP semantics).
    pub(crate) async fn dispatch(&self, tunnel_data: TunnelData) {
        let is_response = matches!(tunnel_data.origin, FrameOrigin::Response);
        let is_close_notification = matches!(tunnel_data.origin, FrameOrigin::Hub)
            && tunnel_data.stream_type == FrameType::Close;

        if is_response {
            Self::deliver(tunnel_data, &self.resp_streams, "response").await;
        } else if is_close_notification {
            // Deliver to the req table first (the egress forwarder reclaims
            // the slot/connection as soon as it receives it — otherwise
            // streams closed by the origin linger indefinitely on the agent
            // side); with no req-table entry go to the resp table
            // (ingress/edge stream teardown).
            let has_req = self
                .req_streams
                .read()
                .await
                .contains_key(&tunnel_data.stream_id);
            if has_req {
                Self::deliver(tunnel_data, &self.req_streams, "request").await;
            } else {
                Self::deliver(tunnel_data, &self.resp_streams, "response").await;
            }
        } else if matches!(tunnel_data.stream_type, FrameType::Open) {
            self.open_request_stream(tunnel_data).await;
        } else {
            Self::deliver(tunnel_data, &self.req_streams, "request").await;
        }
    }

    /// Bounded delivery: clone the sender outside the lock, then `timeout(DISPATCH_SEND_TIMEOUT, send())`.
    ///
    /// Timeout = consumer stalled → poison (remove the table entry; once all
    /// senders are dropped the channel closes, and the consumer exits itself
    /// on `recv() == None` and notifies the peer). Channel already closed =
    /// consumer has exited; drop this frame.
    async fn deliver(
        tunnel_data: TunnelData,
        map: &Arc<RwLock<HashMap<StreamId, mpsc::Sender<TunnelData>>>>,
        direction: &'static str,
    ) {
        let stream_id = tunnel_data.stream_id;
        // Release the read lock right after cloning the sender, so send().await does not block register/unregister
        let tx = {
            let map = map.read().await;
            map.get(&stream_id).cloned()
        };
        let Some(tx) = tx else {
            debug!(
                "no channel for stream {} in {direction} direction (late frame), dropping",
                stream_id
            );
            return;
        };
        match tokio::time::timeout(DISPATCH_SEND_TIMEOUT, tx.send(tunnel_data)).await {
            Ok(Ok(())) => {}
            Ok(Err(_)) => {
                debug!(
                    "stream {} channel closed (consumer exited), dropping further frames",
                    stream_id
                );
            }
            Err(_) => {
                metrics::counter!("interflow_dispatch_stream_poisoned_total", "direction" => direction)
                    .increment(1);
                warn!(
                    "stream {} consumer stalled for over {DISPATCH_SEND_TIMEOUT:?}, poisoning the stream (direction={direction})",
                    stream_id
                );
                map.write().await.remove(&stream_id);
            }
        }
    }

    /// Request-direction Open: creates the dedicated channel (inserted into the table inside the lock before hand-off, eliminating the registration race —
    /// subsequent Data/Close frames always hit the channel) and hands
    /// `(Open frame, Receiver)` off to egress.
    async fn open_request_stream(&self, open: TunnelData) {
        let stream_id = open.stream_id;
        let (tx, rx) = mpsc::channel(STREAM_CHANNEL_CAP);
        {
            let mut map = self.req_streams.write().await;
            if map.insert(stream_id, tx.clone()).is_some() {
                warn!(
                    "duplicate Open for request-direction stream {stream_id}, overwriting old channel (old forwarder will exit)"
                );
            }
        }

        // Egress has taken over: direct bounded hand-off.
        if self.attach_gate.is_attached() {
            Self::hand_off_incoming(
                &self.incoming_tx,
                &self.req_streams,
                open,
                rx,
                stream_id,
                &tx,
            )
            .await;
            return;
        }

        // Egress has not taken over (session-establishment timing window: an
        // Open dispatched by the hub before the handler task starts, or
        // abnormal routing to a pure ingress agent): park with a bounded wait
        // for takeover instead of blocking the dispatch loop. If the budget is
        // full, yield immediately (anti-flood semantics, same family as the
        // backlog fallback).
        if self.pending_attach.fetch_add(1, Ordering::Relaxed) >= self.pending_attach_cap {
            self.pending_attach.fetch_sub(1, Ordering::Relaxed);
            metrics::counter!("interflow_agent_open_dropped_total", "reason" => "attach_backlog")
                .increment(1);
            warn!(
                "pending-attach budget full ({}), dropping Open: {stream_id}",
                self.pending_attach_cap
            );
            Self::remove_req_stream(&self.req_streams, stream_id, &tx).await;
            return;
        }
        let gate = Arc::clone(&self.attach_gate);
        let incoming_tx = self.incoming_tx.clone();
        let req_streams = Arc::clone(&self.req_streams);
        let pending = Arc::clone(&self.pending_attach);
        tokio::spawn(async move {
            let deadline = Instant::now() + ATTACH_GRACE;
            loop {
                if gate.is_attached() {
                    break;
                }
                let remaining = deadline.saturating_duration_since(Instant::now());
                if remaining.is_zero() {
                    break;
                }
                // Re-check once after registering the wake point, closing the "between set and register" missed-wakeup window
                let notified = gate.notify.notified();
                if gate.is_attached() {
                    break;
                }
                if tokio::time::timeout(remaining, notified).await.is_err() {
                    break;
                }
            }
            pending.fetch_sub(1, Ordering::Relaxed);
            if !gate.is_attached() {
                metrics::counter!("interflow_agent_open_dropped_total", "reason" => "attach_timeout")
                    .increment(1);
                warn!(
                    "egress did not attach within {ATTACH_GRACE:?} (misrouted or handler not started), dropping Open and rolling back table entry: {stream_id}"
                );
                Self::remove_req_stream(&req_streams, stream_id, &tx).await;
                return;
            }
            Self::hand_off_incoming(&incoming_tx, &req_streams, open, rx, stream_id, &tx).await;
        });
    }

    /// Control-plane hand-off (bounded): the egress main loop only parses + spawns at steady state, draining instantly.
    /// Exceeding the wait = egress backlogged/stalled; the new stream yields —
    /// drop the event and roll back the table entry rather than let dispatch
    /// hang indefinitely alongside it (a flood of Opens no longer propagates
    /// into a hub-side stall and whole-agent eviction loop). A dead egress
    /// task is covered by the channel-closed branch and the client-side
    /// JoinError fallback.
    async fn hand_off_incoming(
        incoming_tx: &mpsc::Sender<IncomingStream>,
        req_streams: &Arc<RwLock<HashMap<StreamId, mpsc::Sender<TunnelData>>>>,
        open: TunnelData,
        frames: mpsc::Receiver<TunnelData>,
        stream_id: StreamId,
        tx: &mpsc::Sender<TunnelData>,
    ) {
        match tokio::time::timeout(
            INCOMING_SEND_TIMEOUT,
            incoming_tx.send(IncomingStream { open, frames }),
        )
        .await
        {
            Ok(Ok(())) => {}
            Ok(Err(_)) => {
                debug!("new-stream event has no consumer (egress exited): {stream_id}");
                Self::remove_req_stream(req_streams, stream_id, tx).await;
            }
            Err(_) => {
                metrics::counter!(
                    "interflow_agent_open_dropped_total",
                    "reason" => "event_backlog"
                )
                .increment(1);
                warn!(
                    "new-stream event channel backlog exceeded {INCOMING_SEND_TIMEOUT:?}, dropping Open and rolling back table entry: {stream_id}"
                );
                Self::remove_req_stream(req_streams, stream_id, tx).await;
            }
        }
    }

    /// Rolls back a request-direction table entry, only if the current entry is still the channel inserted for this stream (`same_channel`).
    ///
    /// Under QUIC, the read tasks of multiple relay streams may dispatch
    /// concurrently: after a duplicate Open for the same sid overwrites the
    /// entry, the old Open's timeout rollback must not delete the new Open's
    /// channel (otherwise the new forwarder would be poisoned for no reason).
    async fn remove_req_stream(
        map: &Arc<RwLock<HashMap<StreamId, mpsc::Sender<TunnelData>>>>,
        stream_id: StreamId,
        tx: &mpsc::Sender<TunnelData>,
    ) {
        let mut map = map.write().await;
        if map.get(&stream_id).is_some_and(|cur| cur.same_channel(tx)) {
            map.remove(&stream_id);
        }
    }

    /// Decodes tunnel data (binary length-prefixed frames, supports fragmentation).
    ///
    /// - the payload shares the original buffer allocation zero-copy via
    ///   `Bytes::slice`
    /// - `decode_frame` automatically consumes the decoded bytes
    /// - unknown frame type → if `MUST_UNDERSTAND` is set, discard the buffer
    ///   and return None to trigger reconnect; otherwise skip this frame and
    ///   continue
    pub(crate) fn decode_tunnel_data(buffer: &mut bytes::BytesMut) -> Option<TunnelData> {
        use crate::protocol::frame as wire;
        let outcome = wire::decode_frame(buffer);
        match outcome {
            wire::DecodeOutcome::Ok(frame) => Some(TunnelData {
                // typed Copy ids — zero allocation on the dispatch path (the
                // former String ×2 + Arc<str> are gone)
                stream_id: frame.stream_id,
                origin: FrameOrigin::from_parts(frame.flags, frame.circuit),
                // payload is a Bytes slice, zero-copy
                data: frame.payload,
                stream_type: frame.frame_type,
                flags: frame.flags,
            }),
            wire::DecodeOutcome::Pending => None,
            wire::DecodeOutcome::Error => {
                tracing::error!(
                    "invalid tunnel frame format (magic/version/field mismatch), discarding and reconnecting"
                );
                buffer.clear();
                None
            }
            wire::DecodeOutcome::UnknownType {
                must_understand,
                total_len: _,
            } => {
                if must_understand {
                    tracing::error!(
                        "received unknown must-understand frame type, disconnecting and reconnecting"
                    );
                    buffer.clear();
                    None
                } else {
                    // decode_frame has already consumed this frame automatically; continue parsing the remaining buffer
                    Self::decode_tunnel_data(buffer)
                }
            }
        }
    }
}

#[cfg(test)]
#[allow(
    clippy::panic,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::missing_docs_in_private_items
)]
mod tests {
    use super::*;
    use std::sync::OnceLock;

    /// In-process Prometheus recorder (same direct-read form as the mesh e2e tests).
    static METRICS: OnceLock<metrics_exporter_prometheus::PrometheusHandle> = OnceLock::new();

    fn metrics_handle() -> &'static metrics_exporter_prometheus::PrometheusHandle {
        METRICS.get_or_init(|| {
            let recorder = metrics_exporter_prometheus::PrometheusBuilder::new().build_recorder();
            let handle = recorder.handle();
            let _ = metrics::set_global_recorder(recorder);
            handle
        })
    }

    /// A deterministic nonzero test circuit (hex `12...30`, same shape as the
    /// negotiation tests).
    fn test_circuit() -> crate::protocol::CircuitToken {
        crate::protocol::CircuitToken::from_hex("12078a05e14f4e2c99b1679be1df7c30").unwrap()
    }

    /// A nonzero StreamId encoding a small integer label.
    fn sid(label: u64) -> StreamId {
        let mut bytes = [0u8; 16];
        bytes[..8].copy_from_slice(&label.to_be_bytes());
        bytes[15] = 1;
        StreamId::from_bytes(bytes)
    }

    fn open_td(label: u64) -> TunnelData {
        TunnelData {
            stream_id: sid(label),
            origin: FrameOrigin::Agent(test_circuit()),
            data: Bytes::new(),
            stream_type: FrameType::Open,
            flags: 0,
        }
    }

    async fn req_stream_count(dispatch: &TunnelDispatch) -> usize {
        dispatch.req_streams.read().await.len()
    }

    /// F1 (main regression, unit form): Open hand-off is bounded when the event channel is backlogged —
    /// past `INCOMING_SEND_TIMEOUT` the event is dropped + the table entry
    /// rolled back + the counter incremented, and dispatch does not block
    /// indefinitely (does not propagate into hub eviction).
    #[tokio::test(start_paused = true)]
    async fn open_event_backlog_drop_is_bounded_and_rolls_back() {
        let _ = metrics_handle();
        let dispatch = TunnelDispatch::new();
        // Egress has taken over (receiver taken) but leaves the backlog unconsumed: fill the event channel
        let _rx = dispatch.take_incoming_streams().unwrap();
        for i in 0..crate::config::params::transport::INCOMING_CHANNEL_CAP_FLOOR {
            dispatch.dispatch(open_td(i as u64 + 1)).await;
        }
        assert_eq!(
            req_stream_count(&dispatch).await,
            crate::config::params::transport::INCOMING_CHANNEL_CAP_FLOOR
        );

        // Over-budget Open: with a paused clock, deterministically reach the timeout branch
        let started = tokio::time::Instant::now();
        dispatch.dispatch(open_td(9_001)).await;
        assert!(started.elapsed() >= INCOMING_SEND_TIMEOUT);

        // Table entry rolled back (dropped stream leaves no channel), counter +1
        assert!(
            dispatch.req_streams.read().await.get(&sid(9_001)).is_none(),
            "the over-budget Open's table entry must be rolled back"
        );
        let dropped = metrics_handle()
            .render()
            .lines()
            .filter(|l| {
                l.starts_with("interflow_agent_open_dropped_total{reason=\"event_backlog\"}")
            })
            .filter_map(|l| l.rsplit(' ').next().and_then(|v| v.parse::<u64>().ok()))
            .sum::<u64>();
        assert!(
            dropped >= 1,
            "event_backlog counter missing: {}",
            metrics_handle().render()
        );
    }

    /// Healthy path: with egress consuming normally, the Open is handed off immediately (bounding introduces no regression).
    #[tokio::test]
    async fn open_delivers_to_egress_consumer() {
        let dispatch = TunnelDispatch::new();
        let mut rx = dispatch.take_incoming_streams().unwrap();
        dispatch.dispatch(open_td(1)).await;
        let ev = rx
            .recv()
            .await
            .expect("Open event should be handed off immediately (channel far from full)");
        assert_eq!(ev.open.stream_id, sid(1));
        assert!(dispatch.req_streams.read().await.contains_key(&sid(1)));
    }

    /// Main regression (the timing race reproduced in the soak guardrail on 2026-09-13; fails before the fix):
    /// an Open arrives **before** egress takeover (the hub dispatched it before
    /// the handler task started); once takeover happens it must still be handed
    /// off — otherwise the stream hangs silently until the idle timeout.
    #[tokio::test]
    async fn open_before_egress_attach_is_delivered_after_attach() {
        let dispatch = TunnelDispatch::new();
        // Not yet taken over: the Open parks (table entry retained, not dropped)
        dispatch.dispatch(open_td(2)).await;
        assert!(
            dispatch.req_streams.read().await.contains_key(&sid(2)),
            "the table entry must be retained while parked (later Data frames must hit the channel)"
        );

        // Egress takes over (handler task starts) — the parked Open should be handed off immediately
        let mut rx = dispatch.take_incoming_streams().unwrap();
        let ev = tokio::time::timeout(Duration::from_secs(1), rx.recv())
            .await
            .expect("the parked Open must be handed off after takeover (this recv times out before the fix)")
            .expect("channel alive");
        assert_eq!(ev.open.stream_id, sid(2));

        // A Data frame arriving during the parking window hits the same channel (zero loss)
        dispatch
            .dispatch(TunnelData {
                stream_id: sid(2),
                origin: FrameOrigin::Agent(test_circuit()),
                data: Bytes::from_static(b"early-data"),
                stream_type: FrameType::Data,
                flags: 0,
            })
            .await;
        let mut frames = ev.frames;
        let td = tokio::time::timeout(Duration::from_secs(1), frames.recv())
            .await
            .expect("the Data frame from the parking window should hit the established channel")
            .expect("channel alive");
        assert_eq!(&td.data[..], b"early-data");
    }

    /// Egress never takes over (abnormal routing / handler not started): after
    /// [`ATTACH_GRACE`] the parked Open is dropped and the table entry rolled
    /// back, with the `attach_timeout` counter.
    #[tokio::test]
    async fn open_without_egress_attachment_drops_after_grace() {
        let _ = metrics_handle();
        let dispatch = TunnelDispatch::new();
        dispatch.dispatch(open_td(3)).await;
        assert_eq!(
            req_stream_count(&dispatch).await,
            1,
            "parked within the grace period"
        );

        // Must converge after the test-profile ATTACH_GRACE (200ms)
        let deadline = Instant::now() + Duration::from_secs(5);
        while req_stream_count(&dispatch).await > 0 {
            assert!(
                Instant::now() < deadline,
                "the table entry must be rolled back after the grace period"
            );
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        let dropped = metrics_handle()
            .render()
            .lines()
            .filter(|l| {
                l.starts_with("interflow_agent_open_dropped_total{reason=\"attach_timeout\"}")
            })
            .filter_map(|l| l.rsplit(' ').next().and_then(|v| v.parse::<u64>().ok()))
            .sum::<u64>();
        assert!(dropped >= 1, "attach_timeout counter missing");
    }

    /// Parking budget full before takeover: over-budget Opens yield immediately (anti-flood does not break due to parking).
    #[tokio::test]
    async fn attach_pending_overflow_drops_immediately() {
        let _ = metrics_handle();
        let dispatch = TunnelDispatch::new();
        for i in 0..crate::config::params::transport::INCOMING_CHANNEL_CAP_FLOOR {
            dispatch.dispatch(open_td(i as u64 + 1)).await;
        }
        assert_eq!(
            req_stream_count(&dispatch).await,
            crate::config::params::transport::INCOMING_CHANNEL_CAP_FLOOR
        );

        dispatch.dispatch(open_td(9_001)).await;
        assert_eq!(
            req_stream_count(&dispatch).await,
            crate::config::params::transport::INCOMING_CHANNEL_CAP_FLOOR,
            "the over-budget Open must not park (entry count unchanged)"
        );
        let dropped = metrics_handle()
            .render()
            .lines()
            .filter(|l| {
                l.starts_with("interflow_agent_open_dropped_total{reason=\"attach_backlog\"}")
            })
            .filter_map(|l| l.rsplit(' ').next().and_then(|v| v.parse::<u64>().ok()))
            .sum::<u64>();
        assert!(dropped >= 1, "attach_backlog counter missing");

        // After takeover, all parked events are handed off (every stream arrives at egress alive)
        let mut rx = dispatch.take_incoming_streams().unwrap();
        let deadline = Instant::now() + Duration::from_secs(5);
        let mut got = 0usize;
        while got < crate::config::params::transport::INCOMING_CHANNEL_CAP_FLOOR {
            assert!(
                Instant::now() < deadline,
                "not all parked events were handed off ({got})"
            );
            if rx.recv().await.is_some() {
                got += 1;
            } else {
                panic!("channel closed early (handed off {got})");
            }
        }
    }

    /// Close-notification (`_close_`) routing: with a req-table entry (egress forwarder in service) → delivered to
    /// the req channel (the forwarder reclaims the slot upon receipt); with no
    /// req-table entry → goes to the resp table (no regression on the
    /// ingress/edge stream-teardown path).
    #[tokio::test]
    async fn close_notification_routes_to_forwarder_first() {
        let dispatch = TunnelDispatch::new();
        let mut rx = dispatch.take_incoming_streams().unwrap();
        dispatch.dispatch(open_td(4)).await;
        let ev = rx.recv().await.expect("Open handed off");
        let mut frames = ev.frames;

        // _close_ notification → req channel (the forwarder side receives the Close frame)
        dispatch
            .dispatch(TunnelData {
                stream_id: sid(4),
                origin: FrameOrigin::Hub,
                data: Bytes::from_static(&[3]),
                stream_type: FrameType::Close,
                flags: 0,
            })
            .await;
        let td = tokio::time::timeout(Duration::from_secs(1), frames.recv())
            .await
            .expect("the notification should be delivered immediately")
            .expect("channel alive");
        assert_eq!(td.stream_type, FrameType::Close);

        // _close_ with no req-table entry → resp table (received by the ingress registrant)
        let mut resp = dispatch.register_stream(sid(5)).await;
        dispatch
            .dispatch(TunnelData {
                stream_id: sid(5),
                origin: FrameOrigin::Hub,
                data: Bytes::from_static(&[0]),
                stream_type: FrameType::Close,
                flags: 0,
            })
            .await;
        let td = tokio::time::timeout(Duration::from_secs(1), resp.recv())
            .await
            .expect("the resp notification should be delivered immediately")
            .expect("channel alive");
        assert_eq!(td.stream_type, FrameType::Close);
    }

    /// Egress receiver already closed (task exited): send fails immediately and the table entry is rolled back.
    #[tokio::test]
    async fn open_fails_fast_when_egress_receiver_closed() {
        let dispatch = TunnelDispatch::new();
        let rx = dispatch.take_incoming_streams().unwrap();
        drop(rx);
        let started = tokio::time::Instant::now();
        dispatch.dispatch(open_td(6)).await;
        assert!(
            started.elapsed() < INCOMING_SEND_TIMEOUT,
            "a closed channel should fail immediately instead of waiting out the full timeout"
        );
        assert_eq!(req_stream_count(&dispatch).await, 0);
    }

    /// Termination contract (main regression, 2026-09-14 fd leak): `close_all_request_streams`
    /// clears the request-direction table and drops all senders — from the
    /// forwarder's perspective the channel is closed (`recv() == None` is the
    /// self-termination signal). Before the fix, senders were pinned in the
    /// table, forwarders hung forever, and the backend TCP fds were never
    /// released.
    #[tokio::test]
    async fn close_all_request_streams_releases_forwarder_channels() {
        let dispatch = TunnelDispatch::new();
        let mut rx = dispatch.take_incoming_streams().unwrap();
        dispatch.dispatch(open_td(7)).await;
        dispatch.dispatch(open_td(8)).await;
        let ev1 = rx.recv().await.expect("Open handed off");
        let ev2 = rx.recv().await.expect("Open handed off");
        assert_eq!(req_stream_count(&dispatch).await, 2);

        let n = dispatch.close_all_request_streams().await;
        assert_eq!(n, 2, "returns the number of cleared entries");
        assert_eq!(req_stream_count(&dispatch).await, 0);

        // From the forwarder's perspective: channel closure is visible immediately, and it is idempotent (a second call returns 0)
        for mut frames in [ev1.frames, ev2.frames] {
            let r = tokio::time::timeout(Duration::from_secs(1), frames.recv()).await;
            assert!(
                matches!(r, Ok(None)),
                "recv must return None immediately after close_all"
            );
        }
        assert_eq!(dispatch.close_all_request_streams().await, 0);
    }

    /// Termination contract (response direction): `close_all_response_streams` clears the resp table —
    /// the write half of the ingress/edge pump closes out on `recv() == None`
    /// (the socket is closed with it).
    #[tokio::test]
    async fn close_all_response_streams_releases_pump_channels() {
        let dispatch = TunnelDispatch::new();
        let mut pump_rx = dispatch.register_stream(sid(9)).await;
        assert_eq!(dispatch.close_all_response_streams().await, 1);

        let r = tokio::time::timeout(Duration::from_secs(1), pump_rx.recv()).await;
        assert!(
            matches!(r, Ok(None)),
            "the pump channel must close immediately after close_all"
        );
        // Table now empty: subsequent frames are dropped as late frames, no hit
        dispatch
            .dispatch(TunnelData {
                stream_id: sid(9),
                origin: FrameOrigin::Response,
                data: Bytes::new(),
                stream_type: FrameType::Data,
                flags: 0,
            })
            .await;
        assert_eq!(dispatch.close_all_response_streams().await, 0);
    }

    /// Duplicate-Open overwrite + timeout-rollback same_channel guard: the old Open's rollback
    /// must not remove the channel installed by the newer duplicate Open
    /// (protection against mis-deletion under concurrent QUIC dispatch).
    #[tokio::test(start_paused = true)]
    async fn timeout_rollback_keeps_newer_duplicate_entry() {
        let dispatch = Arc::new(TunnelDispatch::new());
        let _rx = dispatch.take_incoming_streams().unwrap();
        for i in 0..crate::config::params::transport::INCOMING_CHANNEL_CAP_FLOOR {
            dispatch.dispatch(open_td(i as u64 + 1)).await;
        }
        // The first Open blocks on the timeout; while it is pending, Open the
        // same sid once more (simulating the insertion interleaving of
        // concurrent dispatch: the new channel goes straight into the table).
        let d = Arc::clone(&dispatch);
        let first = tokio::spawn(async move {
            d.dispatch(open_td(10)).await;
        });
        tokio::task::yield_now().await;
        {
            let (tx2, _rx2) = mpsc::channel(STREAM_CHANNEL_CAP);
            dispatch.req_streams.write().await.insert(sid(10), tx2);
        }
        first.await.unwrap();
        // The old Open's timeout rollback is stopped by the same_channel guard: the new channel stays in the table
        assert!(
            dispatch.req_streams.read().await.contains_key(&sid(10)),
            "the timeout rollback must not mis-delete the new channel installed by the duplicate Open"
        );
    }
}
