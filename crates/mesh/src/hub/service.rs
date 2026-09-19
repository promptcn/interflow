//! `HubService` — hyper `Service` implementation: rate limiting, mTLS
//! identity gating, request routing.
//!
//! Every HTTP/2 request first goes through [`Service::call`]:
//! 1. per-IP token-bucket rate limiting ([`AuthRateLimiter`], keyed on the
//!    PROXY-protocol effective IP); over the limit returns 429
//! 2. mTLS identity gate: the connection must carry a derived
//!    [`PeerIdentity`] (tenant from the chain's anchoring root, agent from
//!    the leaf CN) — the per-handler `x-agent-id` binding then pins every
//!    request to that identity
//! 3. dispatch to the concrete handler (registration / routing / poll / handlers)
//!
//! There is no bearer-token authentication: client certificates are the only
//! credential (RFC docs/design/multi-tenant-mtls-only.md).

use crate::hub::ActiveStream;
use crate::hub::state::{
    HubHandles, HubResponseBody, PeerIdentity, SharedAgents, SharedHubConfig, SharedStreamCounts,
    SharedTlsPlane,
};
use bytes::Bytes;
use http_body_util::{BodyExt, Full};
use hyper::body::Incoming;
use hyper::service::Service;
use hyper::{Method, Request, Response, StatusCode};
use interflow_core::error::InterflowError;
use interflow_core::security::{AuditKind, AuditSink, AuthRateLimiter};
use std::collections::HashMap;
use std::future::Future;
use std::net::{IpAddr, SocketAddr};
use std::pin::Pin;
use std::sync::Arc;
use tracing::warn;

use tokio::sync::RwLock;

/// Per-connection hub service object. Each HTTP/2 connection corresponds to
/// one `HubService` instance.
///
/// `Clone` exists so `/stream/up` reader tasks can hold the same routing /
/// audit handles (all fields are `Arc` / `Copy`, so cloning is cheap).
#[derive(Clone)]
pub struct HubService {
    /// Table of registered agents.
    pub(crate) agents: SharedAgents,
    /// Hub configuration (supports hot reload).
    pub(crate) config: SharedHubConfig,
    /// Peer TCP address.
    pub(crate) peer_addr: SocketAddr,
    /// Effective client IP (the PROXY-protocol address when fronted by a
    /// trusted proxy, else the TCP peer). Rate limiting, connection caps and
    /// audit key on this — never identity or ACL decisions.
    pub(crate) effective_ip: IpAddr,
    /// Table of active streams.
    pub(crate) active_streams: Arc<RwLock<HashMap<String, ActiveStream>>>,
    /// mTLS identity bound to this connection: preset at handshake (tenant
    /// from the chain's anchoring CA, agent from the leaf CN). `None` only
    /// if the acceptor was misassembled — every request then fails closed.
    pub(crate) connection_identity: Arc<RwLock<Option<PeerIdentity>>>,
    /// TLS plane (mTLS acceptor + tenant derivation) — the routing layer
    /// consults it for trusted-gateway status.
    pub(crate) tls_plane: SharedTlsPlane,
    /// Hot-reloadable runtime limits (ACL toggle / stream count caps /
    /// dispatch timeout / poll grace).
    pub(crate) limits: crate::hub::state::HubLimits,
    /// Authentication rate limiter (None means disabled).
    pub(crate) rate_limiter: Option<Arc<AuthRateLimiter>>,
    /// Active stream count per source agent (for `max_streams_per_agent` limiting).
    pub(crate) stream_counts: SharedStreamCounts,
    /// Audit log sink (no-op in disabled mode).
    pub(crate) audit: AuditSink,
}

impl HubService {
    /// Builds the per-connection service object from the accept context
    /// (connection identity is bound per connection).
    pub(crate) fn new(
        ctx: crate::hub::accept::AcceptContext,
        peer_addr: SocketAddr,
        effective_ip: IpAddr,
        connection_identity: Arc<RwLock<Option<PeerIdentity>>>,
    ) -> Self {
        Self {
            agents: ctx.agents,
            config: ctx.config,
            peer_addr,
            effective_ip,
            active_streams: ctx.active_streams,
            connection_identity,
            tls_plane: ctx.tls_plane,
            limits: ctx.limits,
            rate_limiter: ctx.rate_limiter,
            stream_counts: ctx.stream_counts,
            audit: ctx.audit,
        }
    }

    /// The registry key of this connection's identity (`"{tenant}/{agent}"`).
    /// Callers must have passed the identity gate in [`Service::call`] first.
    pub(crate) async fn qualified_id(&self) -> String {
        self.connection_identity
            .read()
            .await
            .as_ref()
            .map_or_else(String::new, PeerIdentity::qualified)
    }

    /// Takes the shared handle set (used by agent eviction / heartbeat /
    /// poll-grace tasks).
    /// Derives the core state for stream routing (h2 routing and QUIC relay
    /// share the same table).
    pub(crate) fn core(&self) -> crate::hub::state::HubCore {
        crate::hub::state::HubCore {
            agents: self.agents.clone(),
            active_streams: self.active_streams.clone(),
            stream_counts: self.stream_counts.clone(),
            channel_send_timeout_secs: self.limits.channel_send_timeout_secs.clone(),
        }
    }

    pub(crate) fn handles(&self) -> HubHandles {
        HubHandles {
            agents: self.agents.clone(),
            active_streams: self.active_streams.clone(),
            stream_counts: self.stream_counts.clone(),
            audit: self.audit.clone(),
            config: self.config.clone(),
            poll_grace_secs: self.limits.poll_grace_secs.clone(),
        }
    }

    /// Takes the peer address as a string (for auditing).
    pub(crate) fn peer_str(&self) -> String {
        self.peer_addr.to_string()
    }

    /// The connection's derived identity, if any (fail-closed gate).
    pub(crate) async fn identity(&self) -> Option<PeerIdentity> {
        self.connection_identity.read().await.clone()
    }
}

/// Boxes a body as a hub response body.
///
/// The error type of `Full<Bytes>` is `Infallible`; `match never {}` is
/// eliminated at compile time, so no fake error branch is needed.
pub(crate) fn boxed_full(body: impl Into<Bytes>) -> HubResponseBody {
    Full::new(body.into())
        .map_err(|never| match never {})
        .boxed()
}

/// Builds a fixed status code + static text response.
pub(crate) fn text_response(status: StatusCode, body: &'static str) -> Response<HubResponseBody> {
    Response::builder()
        .status(status)
        .body(boxed_full(body))
        .expect("static response builder is infallible")
}

/// Builds a JSON response (`application/json`).
pub(crate) fn json_response(status: StatusCode, json: String) -> Response<HubResponseBody> {
    Response::builder()
        .status(status)
        .header("content-type", "application/json")
        .body(boxed_full(json))
        .expect("json response builder is infallible")
}

/// Builds a 429 Too Many Requests response with `Retry-After: 60`
/// (per-minute quota).
fn too_many_requests() -> Response<HubResponseBody> {
    Response::builder()
        .status(StatusCode::TOO_MANY_REQUESTS)
        .header("Retry-After", "60")
        .body(boxed_full("Too Many Requests"))
        .expect("429 builder is infallible")
}

impl Service<Request<Incoming>> for HubService {
    type Response = Response<HubResponseBody>;
    type Error = InterflowError;
    type Future =
        Pin<Box<dyn Future<Output = std::result::Result<Self::Response, Self::Error>> + Send>>;

    fn call(&self, req: Request<Incoming>) -> Self::Future {
        // All fields are Arc / Copy: a single clone transfers every handle
        let svc = self.clone();
        let peer_str = self.peer_addr.to_string();

        Box::pin(async move {
            let path = req.uri().path().to_string();

            // Rate limiting (registration-endpoint churn / DoS suppression;
            // mTLS has no brute-forceable credential)
            if let Some(limiter) = &svc.rate_limiter
                && !limiter.check(svc.effective_ip)
            {
                metrics::counter!("interflow_hub_auth_failures", "reason" => "rate_limited")
                    .increment(1);
                svc.audit.record(
                    AuditKind::AgentRegisterDenied {
                        reason: "rate_limited".into(),
                    },
                    None,
                    Some(peer_str.clone()),
                );
                return Ok(too_many_requests());
            }

            // mTLS identity gate: a connection without a derived identity is
            // a fail-closed reject (only reachable if the acceptor was
            // misassembled — the handshake normally requires client certs).
            if svc.identity().await.is_none() {
                metrics::counter!("interflow_hub_auth_failures", "reason" => "no_client_cert")
                    .increment(1);
                svc.audit.record(
                    AuditKind::AgentRegisterDenied {
                        reason: "no_client_cert".into(),
                    },
                    None,
                    Some(peer_str.clone()),
                );
                return Ok(text_response(
                    StatusCode::UNAUTHORIZED,
                    "Client certificate required",
                ));
            }

            match (req.method(), path.as_str()) {
                (&Method::POST, "/register") => {
                    let agent_id = agent_id_of(&req)?.to_string();
                    svc.handle_register(agent_id).await
                }
                (&Method::POST, "/stream/up") => svc.handle_stream_up(req).await,
                (&Method::GET, "/poll") => svc.handle_poll(req).await,
                (&Method::GET, "/agents") => svc.handle_list_agents().await,
                _ => Ok(text_response(StatusCode::NOT_FOUND, "Not Found")),
            }
        })
    }
}

/// Extracts the `x-agent-id` header — the per-request agent identity on
/// every tunnel endpoint. A missing/garbled header is a protocol violation
/// by the peer, not operator configuration debt.
pub(crate) fn agent_id_of(req: &Request<Incoming>) -> interflow_core::error::Result<&str> {
    req.headers()
        .get("x-agent-id")
        .and_then(|v| v.to_str().ok())
        .ok_or_else(|| InterflowError::protocol("missing agent-id".to_string()))
}

/// Verifies the connection↔agent identity binding shared by the
/// per-connection handlers (`/poll`, `/stream/up`): the claimed bare
/// `x-agent-id` must equal the mTLS-derived identity's agent (CN). The
/// identity itself is preset at handshake and is never claimable.
/// `Ok` = matching; `Err(response)` = the rejection to reply with (boxed:
/// `Response<HubResponseBody>` is large enough to trip
/// `clippy::result_large_err` in the `Result` return position).
pub(crate) async fn bind_connection_identity(
    identity: &RwLock<Option<PeerIdentity>>,
    agent_id: &str,
    op: &str,
) -> std::result::Result<(), Box<Response<HubResponseBody>>> {
    let identity = identity.read().await;
    if let Some(existing) = &*identity {
        if existing.agent != agent_id {
            warn!(
                "identity mismatch: connection is bound to {}/{} (tenant/agent), but {op} attempt is for {agent_id}",
                existing.tenant, existing.agent
            );
            return Err(Box::new(text_response(
                StatusCode::FORBIDDEN,
                "Identity mismatch",
            )));
        }
        Ok(())
    } else {
        // Fail-closed: no derived identity (handshake anomaly).
        warn!("{op} on a connection without a derived identity");
        Err(Box::new(text_response(
            StatusCode::UNAUTHORIZED,
            "Client certificate required",
        )))
    }
}

#[cfg(test)]
#[allow(
    clippy::panic,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::missing_docs_in_private_items
)]
mod tests {}
