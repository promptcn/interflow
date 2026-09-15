//! Hub shared state types.
//!
//! These types are shared across handler modules:
//! - [`TunnelData`] (from `interflow-core`) is the minimal data unit passed
//!   around inside the hub (one-to-one with wire protocol frames)
//! - [`AgentSession`] is the runtime state of a single registered agent
//! - [`ActiveStream`] is the metadata of one opened end-to-end TCP stream

use bytes::{Bytes, BytesMut};
use interflow_core::error::InterflowError;
use interflow_core::protocol::StreamProto;
use interflow_core::security::AuditSink;
pub use interflow_core::tunnel::TunnelData;
use std::collections::HashMap;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering as AtomicOrdering};
use std::task::{Context, Poll, Waker};
use std::time::Instant;
use tokio::sync::{RwLock, mpsc};

use crate::config::HubConfig;
use http_body_util::combinators::BoxBody;
use hyper::body::Frame;
use interflow_core::protocol::frame as wire;
use tokio_rustls::TlsAcceptor;

/// Hub HTTP response body type alias.
pub type HubResponseBody = BoxBody<Bytes, InterflowError>;

/// Alias for `Arc<RwLock<HubConfig>>`, supporting hot reload.
pub type SharedHubConfig = Arc<RwLock<HubConfig>>;

/// Alias for `Arc<RwLock<Option<TlsAcceptor>>>`, supporting TLS
/// configuration hot reload.
pub type SharedTlsAcceptor = Arc<RwLock<Option<TlsAcceptor>>>;

/// Registry type: `agent_id -> Arc<RwLock<AgentSession>>`.
pub type SharedAgents = Arc<RwLock<HashMap<String, Arc<RwLock<AgentSession>>>>>;

/// Shared table of `agent_id -> active stream count`.
///
/// Used for `max_streams_per_agent` limiting. The `std::sync::Mutex` is held
/// only briefly during check-and-increment (nanosecond scale), never across
/// an await — avoiding a tokio Mutex serializing the hot path.
pub type SharedStreamCounts = Arc<std::sync::Mutex<HashMap<String, usize>>>;

/// Active stream table type.
pub type SharedActiveStreams = Arc<RwLock<HashMap<String, ActiveStream>>>;

/// Hot-reloadable runtime limits (a lock-free hot-path atomic collection,
/// one struct threaded through the whole hub).
///
/// `HubServer` assembles the initial values from configuration;
/// `HubService` / `AcceptContext` hold clones; the SIGHUP reload task
/// writes new values. Eliminates the pattern of "the same set of atomics
/// passed around one by one as separate parameters across
/// server/service/accept/reload".
#[derive(Clone)]
pub struct HubLimits {
    /// Whether the ACL is enabled (checks are skipped when there are no rules).
    pub acl_enabled: Arc<AtomicBool>,
    /// Maximum concurrent active streams per agent.
    pub max_streams_per_agent: Arc<AtomicUsize>,
    /// Maximum concurrent active streams globally.
    pub max_streams_total: Arc<AtomicUsize>,
    /// Maximum wait in seconds when writing a Data frame into an agent channel.
    pub channel_send_timeout_secs: Arc<AtomicU64>,
    /// Grace period in seconds that an entry survives after a poll disconnect.
    pub poll_grace_secs: Arc<AtomicU64>,
}

impl HubLimits {
    /// Initializes the current values of each limit from the hub
    /// configuration.
    pub fn from_config(cfg: &HubConfig) -> Self {
        Self {
            acl_enabled: Arc::new(AtomicBool::new(!cfg.acl.is_empty())),
            max_streams_per_agent: Arc::new(AtomicUsize::new(cfg.security.max_streams_per_agent)),
            max_streams_total: Arc::new(AtomicUsize::new(cfg.security.max_streams_total)),
            channel_send_timeout_secs: Arc::new(AtomicU64::new(
                cfg.security.channel_send_timeout_secs,
            )),
            poll_grace_secs: Arc::new(AtomicU64::new(cfg.security.poll_grace_secs)),
        }
    }
}

/// Core state for stream routing: the minimal set needed by the
/// dispatch/cleanup primitives shared by the h2 plane and the QUIC plane.
///
/// Derived from [`crate::hub::service::HubService`] or
/// [`crate::hub::accept::AcceptContext`], so that `/stream`, `/poll`, and
/// the QUIC relay operate on the same tables and timeout discipline.
#[derive(Clone)]
pub struct HubCore {
    /// Table of registered agents.
    pub agents: SharedAgents,
    /// Active stream table.
    pub active_streams: SharedActiveStreams,
    /// Per-agent stream counts.
    pub stream_counts: SharedStreamCounts,
    /// Data frame dispatch timeout in seconds (hot-path atomic).
    pub channel_send_timeout_secs: Arc<AtomicU64>,
}

/// Shared handle set needed by agent eviction and heartbeat tasks.
///
/// Assembled by `HubService` and handed to the evict/heartbeat tasks in
/// [`crate::hub::heartbeat`] and held by the poll-grace task of
/// [`RxStream`]; this lets those tasks — which live outside request
/// handling — access the registry and stream tables without depending on
/// `HubService` itself.
#[derive(Clone)]
pub struct HubHandles {
    /// Table of registered agents.
    pub agents: SharedAgents,
    /// Active stream table.
    pub active_streams: SharedActiveStreams,
    /// Per-agent stream counts.
    pub stream_counts: SharedStreamCounts,
    /// Audit sink.
    pub audit: AuditSink,
    /// Hub configuration (read by the heartbeat task every tick).
    pub config: SharedHubConfig,
    /// Poll grace seconds (hot-path atomic, hot-reloadable).
    pub poll_grace_secs: Arc<AtomicU64>,
}

// The data frame type reuses `interflow_core::tunnel::TunnelData`
// (isomorphic with the agent side, eliminating a twin definition); the
// sentinel semantics of the `source_agent` field (`"_open_"`, `"_close_"`,
// `"_response_"`) are documented on the core `TunnelData`.

/// Shared state of a single agent.
///
/// The outer `HashMap` indexes into this `Arc` by `agent_id`; the inner
/// `RwLock` guards the mutable fields (`rx` take/return, channel rebuilds).
/// The hot path (Data frame forwarding) only clones an `mpsc::Sender` under
/// the inner read lock and releases it immediately; the actual
/// `tx.send().await` executes outside all locks.
pub struct AgentSession {
    /// Sender — hub → agent /poll write end (**data plane**: Data / Ping;
    /// when full the sender waits in a bounded fashion, propagating
    /// backpressure upstream).
    pub tx: mpsc::Sender<TunnelData>,
    /// Control-plane sender — Open / `_close_` lifecycle notifications
    /// (unbounded: delivery while online; a full data channel never drops a
    /// close notification, see [`crate::hub::control`]).
    pub ctrl_tx: mpsc::UnboundedSender<TunnelData>,
    /// Control-plane backlog count (sentinel diagnostics): +1 on the send
    /// side ([`crate::hub::control`]), -1 per frame taken by the poll pump
    /// ([`RxStream`]). Reset to zero with the new channel on session
    /// replacement.
    pub ctrl_backlog: Arc<AtomicUsize>,
    /// `Some` means idle, available for the next `/poll` to take; `None`
    /// means currently held by some poll connection.
    pub rx: Option<mpsc::Receiver<TunnelData>>,
    /// Control-plane receiver (same lifetime as `rx`: poll take/return and
    /// generation semantics are fully synchronized).
    pub ctrl_rx: Option<mpsc::UnboundedReceiver<TunnelData>>,
    /// Channel generation: +1 on every channel replacement (register
    /// rebuilding in place / poll detecting closure and rebuilding /
    /// eviction). The poll connection records the generation when taking rx;
    /// on return ([`RxStream`] Drop), a generation mismatch means the stale
    /// receiver is discarded, preventing an old connection from overwriting
    /// a stale receiver onto the new channel.
    pub generation: u64,
    /// Time of the last heartbeat Pong received (reset to now on
    /// registration / re-registration).
    pub last_pong: Instant,
    /// Wake handle of the suspended poll body.
    ///
    /// [`RxStream::poll_next`] registers its waker here before returning
    /// Pending (its mpsc waker only reacts to channel events); after
    /// advancing the generation, eviction/channel rebuilds call
    /// [`AgentSession::wake_poll`] to wake it actively so poll_next
    /// re-runs the generation self-check and ends the response — otherwise
    /// evict cannot reach the rx privately owned by RxStream, and a
    /// residual poll response would hang forever.
    ///
    /// The `Arc` wrapper lets RxStream clone it at construction so
    /// poll_next (a synchronous context) can register without going
    /// through a tokio RwLock, avoiding a "registration failed + wake
    /// lost" race with evict's write lock.
    pub poll_waker: Arc<std::sync::Mutex<Option<Waker>>>,
    /// Upload stream (`POST /stream/up`) lease: `Some` = an active upload
    /// reader task exists.
    ///
    /// Dual to poll's rx single-consumer semantics:
    /// - when an active upload exists in the same generation, a new upload
    ///   gets 409;
    /// - register preemption / [`crate::hub::heartbeat::evict_agent`]
    ///   eviction cancels the lease; the reader task exits → the 200
    ///   response body ends → the agent perceives the death signal and
    ///   rebuilds;
    /// - when the reader itself exits (disconnect / protocol error) it
    ///   returns the lease (only if it is still its own, judged via
    ///   ptr_eq).
    pub up_lease: Option<Arc<tokio_util::sync::CancellationToken>>,
    /// QUIC connection handle: `Some` means this agent registered over QUIC
    /// (traffic streams go through the relay rather than /poll). Set back
    /// to `None` when an h2 re-registration replaces the channel in place.
    pub quic: Option<Arc<QuicAgentConn>>,
}

impl AgentSession {
    /// Wakes the suspended poll body (urging it to self-check and end after
    /// a generation advance). Synchronous, non-blocking.
    pub fn wake_poll(&self) {
        if let Ok(mut guard) = self.poll_waker.lock()
            && let Some(waker) = guard.take()
        {
            waker.wake();
        }
    }
}

/// Dispatch plane of one end of a stream (the transport shape is encoded in
/// the type rather than implicitly expressed via `Option`).
#[derive(Debug, Clone)]
pub enum StreamFace {
    /// h2 agent: frames are dispatched via `lookup_tx` → `/poll`.
    Poll,
    /// QUIC agent: frames are written to this agent's relay stream writer
    /// task.
    Relay(mpsc::Sender<TunnelData>),
}

impl StreamFace {
    /// Relay sender (`None` for an h2 end).
    pub const fn relay_sender(&self) -> Option<&mpsc::Sender<TunnelData>> {
        match self {
            Self::Poll => None,
            Self::Relay(tx) => Some(tx),
        }
    }

    /// Whether this is a QUIC relay plane.
    pub const fn is_relay(&self) -> bool {
        matches!(self, Self::Relay(_))
    }
}

/// Metadata of one active end-to-end stream.
#[derive(Debug, Clone)]
pub struct ActiveStream {
    /// Initiating agent.
    pub source_agent: String,
    /// Target agent.
    pub target_agent: String,
    /// Target address (optional; dynamic addressing).
    pub target_addr: Option<String>,
    /// Stream-carried protocol (recorded at Open); Data frames pass the
    /// corresponding flags through so egress can identify it statelessly.
    pub proto: StreamProto,
    /// Target-end dispatch plane (h2 → /poll; QUIC → relay stream writer
    /// task).
    pub target: StreamFace,
    /// Source-end dispatch plane (return-path frames: h2 → /poll; QUIC →
    /// written back to its bidirectional stream).
    pub source: StreamFace,
    /// Whether the DATAGRAM fast path is in effect for this stream (UDP
    /// stream + QUIC capability on both ends + hub toggle).
    pub datagram_ok: bool,
}

/// QUIC agent connection handle (attached to [`AgentSession`]; `None` for
/// h2-registered agents).
///
/// - `conn`: opens relay streams to this agent (the h2 source → quic target
///   interop path).
/// - `control`: control stream write handle (tokio Mutex: Ping frames are
///   low-frequency, take exclusive write directly).
pub struct QuicAgentConn {
    /// quinn connection.
    pub conn: quinn::Connection,
    /// Control stream sender (Ping).
    pub control: tokio::sync::Mutex<quinn::SendStream>,
    /// Whether this agent negotiated DATAGRAM capability (Hello/HelloAck
    /// caps).
    pub datagram_cap: std::sync::atomic::AtomicBool,
}

/// Adapts an `mpsc::Receiver<TunnelData>` into a `futures::Stream` for a
/// hyper body.
///
/// **Zero-copy path**: each `TunnelData` is split into two `Frame::data`
/// yields:
/// 1. header (magic + ver + type + flags + sid + sa + payload_len)
/// 2. payload (the original `Bytes`, moved rather than copied)
///
/// The HTTP/2 body accumulates in order into a BytesMut at the agent end;
/// the decoder is unaware. This eliminates the per-frame payload memcpy on
/// the hub→agent path.
pub struct RxStream {
    rx: Option<mpsc::Receiver<TunnelData>>,
    ctrl_rx: Option<mpsc::UnboundedReceiver<TunnelData>>,
    /// Control-plane backlog count sharing the session's origin
    /// (decremented by one per frame taken).
    ctrl_backlog: Option<Arc<AtomicUsize>>,
    pending_payload: Option<Bytes>,
    state: Option<Arc<RwLock<AgentSession>>>,
    generation: u64,
    /// Wake slot sharing the origin of `AgentSession::poll_waker` (cloned
    /// at construction; accessed synchronously in poll_next).
    poll_waker: Option<Arc<std::sync::Mutex<Option<Waker>>>>,
    /// Handles needed by the poll-grace task.
    handles: HubHandles,
    /// Owning agent id (only for the grace task's logging and eviction).
    agent_id: String,
}

impl RxStream {
    /// Builds the poll response body stream: returns rx when the connection
    /// drops, and evicts the agent if nobody re-`/poll`s within the grace
    /// period (see [`crate::hub::heartbeat::evict_agent`]).
    #[allow(clippy::too_many_arguments)] // channel/state handles are passed explicitly one by one; the semantics cannot be merged
    pub const fn new(
        rx: mpsc::Receiver<TunnelData>,
        ctrl_rx: mpsc::UnboundedReceiver<TunnelData>,
        ctrl_backlog: Arc<AtomicUsize>,
        state: Arc<RwLock<AgentSession>>,
        generation: u64,
        poll_waker: Arc<std::sync::Mutex<Option<Waker>>>,
        handles: HubHandles,
        agent_id: String,
    ) -> Self {
        Self {
            rx: Some(rx),
            ctrl_rx: Some(ctrl_rx),
            ctrl_backlog: Some(ctrl_backlog),
            pending_payload: None,
            state: Some(state),
            generation,
            poll_waker: Some(poll_waker),
            handles,
            agent_id,
        }
    }
}

/// Converts a usize count to the f64 of a gauge (narrowed through u32 to
/// avoid cast_precision_loss; agent/stream counts are far below u32::MAX in
/// practice).
pub(crate) fn count_as_f64(n: usize) -> f64 {
    f64::from(u32::try_from(n).unwrap_or(u32::MAX))
}

impl Drop for RxStream {
    /// When the poll connection drops, return rx to `AgentSession` so the
    /// same agent's next /poll reuses it immediately instead of being stuck
    /// on 409 waiting for the keepalive timeout. On a generation mismatch
    /// (the channel was replaced by register/rebuild) or when rx is already
    /// occupied, the stale receiver is discarded.
    ///
    /// After returning it, a grace timer starts: if nobody takes rx within
    /// the grace period, the agent is dead (a healthy agent's poll
    /// reconnect backoff tops out at 5s) — evict the registry entry +
    /// orphan streams so subsequent requests take the fast-fail "agent does
    /// not exist" path instead of a black hole.
    fn drop(&mut self) {
        let rx = self.rx.take();
        let ctrl_rx = self.ctrl_rx.take();
        if rx.is_none() && ctrl_rx.is_none() {
            return;
        }
        let Some(state) = self.state.take() else {
            return;
        };
        let handles = self.handles.clone();
        let agent_id = self.agent_id.clone();
        let generation = self.generation;
        // Drop may happen during runtime shutdown (tests / process exit);
        // if try_current fails, discard and degrade to the keepalive-timeout
        // fallback.
        if let Ok(handle) = tokio::runtime::Handle::try_current() {
            handle.spawn(async move {
                {
                    let mut st = state.write().await;
                    if st.generation == generation && st.rx.is_none() {
                        if let Some(rx) = rx {
                            st.rx = Some(rx);
                        }
                        if let Some(ctrl_rx) = ctrl_rx {
                            st.ctrl_rx = Some(ctrl_rx);
                        }
                        tracing::debug!(
                            "poll connection dropped, rx/ctrl_rx returned (generation={generation})"
                        );
                    }
                }
                let grace = std::time::Duration::from_secs(
                    handles.poll_grace_secs.load(AtomicOrdering::Relaxed),
                );
                tokio::time::sleep(grace).await;
                // Re-check: same Arc + same generation + rx still never
                // taken → confirmed dead. Any failure of these conditions
                // (re-registration / rebuild / a fresh poll) means the
                // agent is still active.
                let still_idle = {
                    let st = state.read().await;
                    st.generation == generation && st.rx.is_some()
                };
                if still_idle {
                    crate::hub::heartbeat::evict_agent(
                        &handles,
                        &agent_id,
                        &state,
                        "poll_grace_expired",
                    )
                    .await;
                }
            });
        }
    }
}

impl futures::Stream for RxStream {
    type Item = std::result::Result<Frame<Bytes>, InterflowError>;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        // Flush the payload left over from the previous frame first
        if let Some(payload) = self.pending_payload.take() {
            return Poll::Ready(Some(Ok(Frame::data(payload))));
        }

        // Generation self-check: when the channel has been rebuilt/evicted
        // (generation advanced), end this response stream proactively.
        // This lets residual poll connections after evict/re-registration
        // close out cleanly; the agent re-/polls immediately after its drain
        // returns (implicitly re-registering if necessary) instead of
        // hanging on a zombie poll. try_read is non-blocking; on lock
        // contention, skip this round and check again on the next frame.
        let stale = match self.state.as_ref() {
            Some(state) => match state.try_read() {
                Ok(st) => st.generation != self.generation,
                Err(_) => false,
            },
            None => false,
        };
        if stale {
            self.rx = None;
            self.ctrl_rx = None;
            return Poll::Ready(None);
        }

        // Control plane takes priority: lifecycle notifications (Open /
        // `_close_`) must not be delayed by data-plane backlog. The ordering
        // contract is in the `hub::control` module docs — a stream's Open
        // precedes its Close (same-channel FIFO); `_close_` may overtake
        // request-direction tail data queued in the data channel; a
        // response-direction Close already preserved FIFO through the data
        // channel on the hub side before falling back to this channel.
        if let Some(ctrl_rx) = self.ctrl_rx.as_mut() {
            match ctrl_rx.poll_recv(cx) {
                Poll::Ready(Some(df)) => {
                    if let Some(backlog) = &self.ctrl_backlog {
                        backlog.fetch_sub(1, AtomicOrdering::Relaxed);
                    }
                    return self.begin_frame(df);
                }
                // Control channel closed = the session's channel was
                // replaced/evicted (generation self-check is above); end
                // this response body, and the agent re-/polls.
                Poll::Ready(None) => {
                    self.rx = None;
                    self.ctrl_rx = None;
                    return Poll::Ready(None);
                }
                Poll::Pending => {}
            }
        }

        let Some(rx) = self.rx.as_mut() else {
            return Poll::Ready(None);
        };
        match rx.poll_recv(cx) {
            Poll::Ready(Some(df)) => self.begin_frame(df),
            Poll::Ready(None) => Poll::Ready(None),
            Poll::Pending => {
                // Register the waker before returning Pending: the mpsc
                // waker only reacts to channel events; eviction/generation
                // advances (which send no frame) must go through
                // wake_poll to wake actively and trigger the generation
                // self-check.
                if let Some(slot) = &self.poll_waker
                    && let Ok(mut guard) = slot.lock()
                {
                    *guard = Some(cx.waker().clone());
                }
                Poll::Pending
            }
        }
    }
}

impl RxStream {
    /// First of the two `Frame::data` yields for one `TunnelData` (the
    /// header); the payload waits for the next poll (Bytes moved rather
    /// than copied).
    fn begin_frame(
        &mut self,
        df: TunnelData,
    ) -> Poll<Option<Result<Frame<Bytes>, InterflowError>>> {
        let mut header =
            BytesMut::with_capacity(64 + df.stream_id.len() + df.source.as_str().len());
        if wire::encode_frame_header(
            df.stream_type,
            df.flags,
            &df.stream_id,
            df.source.as_str(),
            df.data.len(),
            &mut header,
        )
        .is_none()
        {
            tracing::error!(
                "Frame encode failed (field too large): stream_id={}",
                df.stream_id
            );
            return Poll::Ready(Some(Ok(Frame::data(Bytes::new()))));
        }
        self.pending_payload = Some(df.data);
        Poll::Ready(Some(Ok(Frame::data(header.freeze()))))
    }
}
