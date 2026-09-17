//! Agent tunnel client (facade).
//!
//! [`AgentTunnel`] keeps a stable method surface for consumers (mesh
//! ingress/egress, expose edge) while internally holding a
//! [`TunnelTransport`] backend. The current backend is HTTP/2
//! ([`crate::tunnel::h2::H2Tunnel`]); the QUIC backend (P2b) is injected via
//! [`AgentTunnel::from_transport`] with zero consumer changes.

use crate::error::{InterflowError, Result};
use crate::protocol::StreamProto;
use crate::tunnel::h2::{H2RequestBody, H2Tunnel};
use crate::tunnel::session_tasks::SessionTasks;
use crate::tunnel::transport::{IncomingStream, TunnelData, TunnelTransport};
use bytes::Bytes;
use hyper::client::conn::http2::SendRequest;
use std::sync::Arc;
use std::time::Duration;

/// Default upper bound for establishing one tunnel request (`/poll` or
/// `/stream/up`: send → response headers). Source of the
/// `request_establish_timeout_secs` default semantics.
///
/// Healthy hubs answer these headers immediately (the body then streams
/// indefinitely), so exceeding the bound means the request path is dead in a
/// form the receive-side watchdog can never see (it only starts once headers
/// arrive) — including hyper SendRequest hang edge states after connection
/// death (docs/bug/2026-09-16-edge-self-dial-agent-no-reregister.md §4.2).
pub const DEFAULT_REQUEST_ESTABLISH_TIMEOUT: Duration = Duration::from_secs(15);

/// h2 session liveness parameters (the product of hub registration capability negotiation; see the `negotiation` module).
///
/// Data-plane heartbeat loop: the hub sends Ping over `/poll` (proving the
/// hub→agent data plane) and the agent returns Pong over `/stream/up`
/// (proving the agent→hub data plane). A stall in either direction is
/// converted into session rebuild / eviction by each end's own liveness
/// detection, eliminating the "control plane alive, data plane dead" blind
/// spot (docs/bug/2026-09-13-data-plane-stall-no-eviction.md).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct H2Liveness {
    /// Poll receive-side watchdog: receiving no frames at all (heartbeat
    /// Ping included) on the `/poll` response for this duration
    /// consecutively is judged a data-plane stall; cancels `shutdown` to
    /// trigger a whole-session rebuild.
    /// [`Duration::ZERO`] disables it.
    pub poll_watchdog: Duration,
    /// Upper bound for establishing one tunnel request (`/poll` or
    /// `/stream/up`: send → response headers). Exceeding it is judged a dead
    /// request path — a form the receive-side watchdog can never observe,
    /// because it only starts once response headers arrive — and cancels
    /// `shutdown` exactly like the watchdog does: the supervisor rebuilds
    /// the session (for direct dialers, fail-fast).
    ///
    /// Healthy hubs answer headers immediately; see
    /// [`DEFAULT_REQUEST_ESTABLISH_TIMEOUT`].
    pub establish_timeout: Duration,
    /// Critical-task stall heartbeat timeout for the h2 loops (upload and
    /// poll): a task that stops beating for this long is judged *wedged*
    /// (alive but not progressing — the failure class the death contract
    /// cannot see, because a wedged task keeps its channels open and sends
    /// buffer as fake successes) and the session is rebuilt.
    /// [`Duration::ZERO`] disables stall supervision (death-only).
    ///
    /// Derived from the negotiated heartbeat cadence
    /// (`interval_secs * (max_missed + 1)` — never tolerate a wedged task
    /// longer than the hub's own aging window) or pinned via the agent
    /// config `task_stall_timeout_secs`.
    pub task_stall_timeout: Duration,
    /// Local concurrent-stream limit the dispatch event channel is sized
    /// from (`max_incoming_streams`): a whole-table stream-creation burst
    /// must pass the channel in one go. Not liveness per se — it rides this
    /// struct because it flows the same negotiated-then-configurable path
    /// into tunnel construction. 0 = the shared floor (see
    /// `config::params::transport::incoming_channel_cap`).
    pub incoming_streams_budget: usize,
}

impl H2Liveness {
    /// Liveness when the hub advertises heartbeat disabled: no poll
    /// watchdog (the poll stream is legitimately silent), the task-stall
    /// fallback, and the default establish timeout.
    pub const HEARTBEAT_DISABLED: Self = Self {
        poll_watchdog: Duration::ZERO,
        establish_timeout: DEFAULT_REQUEST_ESTABLISH_TIMEOUT,
        task_stall_timeout: Duration::from_secs(30),
        incoming_streams_budget: 0,
    };
}

/// Agent tunnel client (transport-backend facade; `Clone` is cheap — `Arc` inside).
#[derive(Clone)]
pub struct AgentTunnel {
    inner: std::sync::Arc<dyn TunnelTransport>,
}

impl AgentTunnel {
    /// Creates a tunnel client from an established HTTP/2 connection (h2 backend).
    ///
    /// Registration is done by the caller (`AgentClient`); when `shutdown`
    /// is cancelled the background poll exits. `liveness` decides the
    /// data-plane heartbeat shape (see [`H2Liveness`]).
    pub fn from_sender(
        agent_id: String,
        hub_url: &str,
        sender: SendRequest<H2RequestBody>,
        auth_token: Option<String>,
        tasks: &SessionTasks,
        liveness: H2Liveness,
    ) -> Result<Self> {
        Ok(Self {
            inner: std::sync::Arc::new(H2Tunnel::new(
                agent_id, hub_url, sender, auth_token, tasks, liveness,
            )),
        })
    }

    /// Constructs from any transport backend (QUIC etc.).
    pub fn from_transport(inner: Arc<dyn TunnelTransport>) -> Self {
        Self { inner }
    }

    /// The raw transport backend behind this facade.
    ///
    /// Used by the agent supervisor to install each fresh per-session
    /// backend into a [`SessionSlot`] (the embedder-facing tunnel then rides
    /// across session rebuilds; see `SessionSlot`).
    pub fn backend(&self) -> Arc<dyn TunnelTransport> {
        self.inner.clone()
    }

    /// Registers the dedicated channel for a response-direction stream
    pub async fn register_stream(
        &self,
        stream_id: String,
    ) -> tokio::sync::mpsc::Receiver<TunnelData> {
        self.inner.register_stream(stream_id).await
    }

    /// Unregisters the dedicated channel for a response-direction stream
    pub async fn unregister_stream(&self, stream_id: &str) {
        self.inner.unregister_stream(stream_id).await;
    }

    /// Takes the request-direction new-stream event receiver (consumed by egress). Take-once per tunnel.
    pub async fn take_incoming_streams(
        &self,
    ) -> Option<tokio::sync::mpsc::Receiver<IncomingStream>> {
        self.inner.take_incoming_streams().await
    }

    /// Unregisters the request-direction stream channel (called when a forwarder exits; idempotent).
    pub async fn unregister_incoming_stream(&self, stream_id: &str) {
        self.inner.unregister_incoming_stream(stream_id).await;
    }

    /// Session-termination contract: releases all stream resources of this tunnel (idempotent).
    ///
    /// Calling it declares this tunnel's session terminated. The
    /// implementation clears both dispatch tables (leftover consumers exit
    /// in place, backend fds released) and reclaims transport-backend
    /// resources (QUIC connection/endpoint etc.), see
    /// [`TunnelTransport::shutdown`].
    pub async fn shutdown(&self) {
        self.inner.shutdown().await;
    }

    /// Sends an open-stream signal to the hub (`proto` declares the stream's carrying protocol).
    pub async fn send_open(
        &self,
        stream_id: &str,
        target_agent: &str,
        target_addr: Option<&str>,
        proto: StreamProto,
    ) -> Result<()> {
        self.inner
            .send_open(stream_id, target_agent, target_addr, proto)
            .await
    }

    /// Sends data to the hub (request direction, ingress → hub).
    pub async fn send_data(&self, stream_id: &str, data: Bytes) -> Result<()> {
        self.inner.send_data(stream_id, data).await
    }

    /// Sends data to the hub (response direction, egress → hub).
    pub async fn send_data_response(&self, stream_id: &str, data: Bytes) -> Result<()> {
        self.inner.send_data_response(stream_id, data).await
    }

    /// Sends a close signal to the hub (request direction).
    pub async fn send_close(&self, stream_id: &str) -> Result<()> {
        self.inner.send_close(stream_id).await
    }

    /// Sends a close signal to the hub (response direction). `reason`
    /// travels in the Close payload (empty = ordinary close); see
    /// [`TunnelTransport::send_close_response`].
    pub async fn send_close_response(&self, stream_id: &str, reason: &str) -> Result<()> {
        self.inner.send_close_response(stream_id, reason).await
    }
}

/// Hot-swappable session slot: the embedder-facing tunnel backend
/// (docs/bug/2026-09-16-edge-self-dial-agent-no-reregister.md).
///
/// Holds the transport of the *current* hub session. The agent supervisor
/// installs a fresh backend on every session establishment and withdraws it
/// first thing in the session wind-down; an embedder (expose edge listener
/// etc.) holds the [`AgentTunnel`] from [`SessionSlot::tunnel`] for its whole
/// lifetime and transparently rides across reconnects — the facade never
/// outlives its usefulness just because one session died.
///
/// Failure discipline during the reconnect gap (slot empty): send operations
/// fail fast with a bounded, actionable error — never hang, never black-hole —
/// mirroring the upstream-channel sealing discipline inside the h2 backend.
/// The consumer's failure handling (fast connection close, circuit breakers)
/// then applies exactly as it does for any other agent-side rejection.
///
/// Registration bookkeeping (`register_stream`/`unregister_stream`)
/// delegates to the backend that is current at call time; ids left over from
/// a dead session landing in the new session's dispatch table are idempotent
/// no-ops (the table is a map remove).
#[derive(Clone, Default)]
pub struct SessionSlot {
    inner: Arc<SlotBackend>,
}

#[derive(Default)]
struct SlotBackend {
    current: std::sync::RwLock<Option<Arc<dyn TunnelTransport>>>,
}

impl SessionSlot {
    pub fn new() -> Self {
        Self::default()
    }

    /// The embedder-facing tunnel: an [`AgentTunnel`] backed by this slot.
    /// Cheap to clone; all clones share the same slot.
    pub fn tunnel(&self) -> AgentTunnel {
        AgentTunnel::from_transport(self.inner.clone())
    }

    /// Installs the backend of a freshly established session, evicting (and
    /// running the termination contract on) any residue a previous session
    /// failed to withdraw — the supervisor normally withdraws in its
    /// wind-down, so eviction here is pure defense in depth.
    pub async fn install(&self, backend: Arc<dyn TunnelTransport>) {
        let evicted = {
            let mut current = self
                .inner
                .current
                .write()
                .expect("session slot lock poisoned");
            current.replace(backend)
        };
        if let Some(old) = evicted {
            old.shutdown().await;
        }
    }

    /// Empties the slot, returning the withdrawn backend (the caller — the
    /// supervisor's wind-down — owns the bounded termination contract on it).
    /// After this, send operations through the facade fail fast until the
    /// next session installs a fresh backend.
    pub fn withdraw(&self) -> Option<Arc<dyn TunnelTransport>> {
        self.inner
            .current
            .write()
            .expect("session slot lock poisoned")
            .take()
    }
}

fn slot_empty_error() -> InterflowError {
    InterflowError::connection(
        "agent session re-establishing (supervisor reconnect in progress); retry later".to_string(),
    )
}

#[async_trait::async_trait]
impl TunnelTransport for SlotBackend {
    async fn send_open(
        &self,
        stream_id: &str,
        target_agent: &str,
        target_addr: Option<&str>,
        proto: StreamProto,
    ) -> Result<()> {
        self.backend()
            .ok_or_else(slot_empty_error)?
            .send_open(stream_id, target_agent, target_addr, proto)
            .await
    }

    async fn send_data(&self, stream_id: &str, data: Bytes) -> Result<()> {
        self.backend()
            .ok_or_else(slot_empty_error)?
            .send_data(stream_id, data)
            .await
    }

    async fn send_data_response(&self, stream_id: &str, data: Bytes) -> Result<()> {
        self.backend()
            .ok_or_else(slot_empty_error)?
            .send_data_response(stream_id, data)
            .await
    }

    async fn send_close(&self, stream_id: &str) -> Result<()> {
        self.backend()
            .ok_or_else(slot_empty_error)?
            .send_close(stream_id)
            .await
    }

    async fn send_close_response(&self, stream_id: &str, reason: &str) -> Result<()> {
        self.backend()
            .ok_or_else(slot_empty_error)?
            .send_close_response(stream_id, reason)
            .await
    }

    async fn register_stream(&self, stream_id: String) -> tokio::sync::mpsc::Receiver<TunnelData> {
        match self.backend() {
            // Empty slot: hand out an already-sealed channel — the consumer's
            // read half sees closure immediately (no stream can be established
            // anyway: send_open fails fast first).
            None => tokio::sync::mpsc::channel(1).1,
            Some(backend) => backend.register_stream(stream_id).await,
        }
    }

    async fn unregister_stream(&self, stream_id: &str) {
        if let Some(backend) = self.backend() {
            backend.unregister_stream(stream_id).await;
        }
    }

    async fn take_incoming_streams(&self) -> Option<tokio::sync::mpsc::Receiver<IncomingStream>> {
        // The request-direction event stream is consumed by the session's own
        // egress handler on the concrete per-session tunnel; through the slot
        // it can only be already-taken (or the slot empty).
        match self.backend() {
            None => None,
            Some(backend) => backend.take_incoming_streams().await,
        }
    }

    async fn unregister_incoming_stream(&self, stream_id: &str) {
        if let Some(backend) = self.backend() {
            backend.unregister_incoming_stream(stream_id).await;
        }
    }

    async fn shutdown(&self) {
        if let Some(backend) = self.withdraw_backend() {
            backend.shutdown().await;
        }
    }
}

impl SlotBackend {
    /// Snapshot of the current backend (Arc clone; the lock is released
    /// before any await — a std RwLockReadGuard must not cross an await
    /// point, the future would not be `Send`).
    fn backend(&self) -> Option<Arc<dyn TunnelTransport>> {
        self.current
            .read()
            .expect("session slot lock poisoned")
            .clone()
    }

    fn withdraw_backend(&self) -> Option<Arc<dyn TunnelTransport>> {
        self.current
            .write()
            .expect("session slot lock poisoned")
            .take()
    }
}
