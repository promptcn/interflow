//! Agent tunnel client (facade).
//!
//! [`AgentTunnel`] keeps a stable method surface for consumers (mesh
//! ingress/egress, expose edge) while internally holding a
//! [`TunnelTransport`] backend. The current backend is HTTP/2
//! ([`crate::tunnel::h2::H2Tunnel`]); the QUIC backend (P2b) is injected via
//! [`AgentTunnel::from_transport`] with zero consumer changes.

use crate::error::Result;
use crate::protocol::StreamProto;
use crate::tunnel::h2::{H2RequestBody, H2Tunnel};
use crate::tunnel::transport::{IncomingStream, TunnelData, TunnelTransport};
use bytes::Bytes;
use hyper::client::conn::http2::SendRequest;
use std::time::Duration;
use tokio_util::sync::CancellationToken;

/// h2 session liveness parameters (the product of hub registration capability negotiation; see the mesh `negotiation` module).
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
    /// Pong returns via `/stream/up` uplink frames (proving the agent→hub
    /// data plane); `false` uses the `POST /pong` endpoint (legacy: only
    /// proves the h2 connection layer is alive).
    pub pong_via_upload: bool,
}

impl H2Liveness {
    /// Pre-negotiation behavior: no watchdog, Pong via the endpoint. The default for direct callers and existing tests.
    pub const LEGACY: Self = Self {
        poll_watchdog: Duration::ZERO,
        pong_via_upload: false,
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
        shutdown: CancellationToken,
        liveness: H2Liveness,
    ) -> Result<Self> {
        Ok(Self {
            inner: std::sync::Arc::new(H2Tunnel::new(
                agent_id, hub_url, sender, auth_token, shutdown, liveness,
            )),
        })
    }

    /// Constructs from any transport backend (QUIC etc.).
    pub fn from_transport(inner: std::sync::Arc<dyn TunnelTransport>) -> Self {
        Self { inner }
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
