//! `HubService` — hyper `Service` implementation: rate limiting, unified
//! authentication, request routing.
//!
//! Every HTTP/2 request first goes through [`Service::call`]:
//! 1. per-IP token-bucket rate limiting ([`AuthRateLimiter`]); over the limit returns 429
//! 2. fetch `auth_token` / `admin_token` and decide the required token level by path
//! 3. validate the `Authorization: Bearer <token>` header with constant-time comparison
//! 4. dispatch to the concrete handler (registration / routing / poll / handlers)

use crate::hub::ActiveStream;
use crate::hub::state::{
    HubHandles, HubResponseBody, SharedAgents, SharedHubConfig, SharedStreamCounts,
};
use bytes::Bytes;
use http::HeaderValue;
use http_body_util::{BodyExt, Full};
use hyper::body::Incoming;
use hyper::service::Service;
use hyper::{Method, Request, Response, StatusCode};
use interflow_core::error::InterflowError;
use interflow_core::security::{AuditKind, AuditSink, AuthRateLimiter};
use std::collections::HashMap;
use std::future::Future;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;
use tracing::{debug, warn};

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
    /// Table of active streams.
    pub(crate) active_streams: Arc<RwLock<HashMap<String, ActiveStream>>>,
    /// Agent identity bound to this connection. `None` means not yet registered.
    pub(crate) connection_identity: Arc<RwLock<Option<String>>>,
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
        connection_identity: Arc<RwLock<Option<String>>>,
    ) -> Self {
        Self {
            agents: ctx.agents,
            config: ctx.config,
            peer_addr,
            active_streams: ctx.active_streams,
            connection_identity,
            limits: ctx.limits,
            rate_limiter: ctx.rate_limiter,
            stream_counts: ctx.stream_counts,
            audit: ctx.audit,
        }
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

            // Rate limiting (before authentication; defends against brute-force
            // token enumeration)
            if let Some(limiter) = &svc.rate_limiter
                && !limiter.check(svc.peer_addr.ip())
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

            // Unified authentication: fetch token levels + validate Bearer
            let (auth_token, admin_token) = {
                let cfg = svc.config.read().await;

                cfg.auth
                    .static_token
                    .as_ref()
                    .map_or((None, None), |s| (s.agent.clone(), s.admin.clone()))
            };

            // `/agents` requires the admin token (if configured); everything
            // else uses the auth token.
            let required_token = if path == "/agents" {
                admin_token.as_ref().or(auth_token.as_ref())
            } else {
                auth_token.as_ref()
            };

            if let Some(token) = required_token
                && !bearer_token_valid(req.headers().get("Authorization"), token)
            {
                metrics::counter!("interflow_hub_auth_failures", "reason" => "bad_token")
                    .increment(1);
                svc.audit.record(
                    AuditKind::AgentRegisterDenied {
                        reason: "bad_token".into(),
                    },
                    None,
                    Some(peer_str.clone()),
                );
                return Ok(text_response(StatusCode::UNAUTHORIZED, "Unauthorized"));
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

/// Verifies (or, on first use, establishes) the connection↔agent identity
/// binding shared by the per-connection handlers (`/poll`, `/stream/up`).
/// `Ok` = bound or matching; `Err(response)` = the rejection to reply with
/// (boxed: `Response<HubResponseBody>` is large enough to trip
/// `clippy::result_large_err` in the `Result` return position).
pub(crate) async fn bind_connection_identity(
    identity: &RwLock<Option<String>>,
    agent_id: &str,
    op: &str,
) -> std::result::Result<(), Box<Response<HubResponseBody>>> {
    let mut identity = identity.write().await;
    if let Some(existing_id) = &*identity {
        if existing_id != agent_id {
            warn!(
                "identity mismatch: connection is bound to {existing_id}, but {op} attempt is for {agent_id}"
            );
            return Err(Box::new(text_response(
                StatusCode::FORBIDDEN,
                "Identity mismatch",
            )));
        }
    } else {
        *identity = Some(agent_id.to_string());
        debug!("Connection bound to identity ({op}): {agent_id}");
    }
    Ok(())
}

/// Validates the `Authorization: Bearer <token>` header with constant-time
/// comparison to prevent timing attacks.
fn bearer_token_valid(header: Option<&HeaderValue>, expected: &str) -> bool {
    let Some(header_val) = header.and_then(|v| v.to_str().ok()) else {
        return false;
    };
    let Some(bearer_token) = header_val.strip_prefix("Bearer ") else {
        return false;
    };
    constant_time_eq(bearer_token.as_bytes(), expected.as_bytes())
}

/// Constant-time byte comparison. Returns false immediately when lengths
/// differ; for equal lengths uses `subtle::ConstantTimeEq`.
fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    use subtle::ConstantTimeEq;
    a.ct_eq(b).unwrap_u8() == 1
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

    #[test]
    fn constant_time_eq_handles_differing_lengths() {
        assert!(!constant_time_eq(b"a", b"ab"));
        assert!(!constant_time_eq(b"ab", b"a"));
        assert!(constant_time_eq(b"abc", b"abc"));
    }

    #[test]
    fn bearer_validation_rejects_missing_and_malformed() {
        assert!(!bearer_token_valid(None, "secret"));
        let bad = HeaderValue::from_static("Basic xyz");
        assert!(!bearer_token_valid(Some(&bad), "secret"));
        let ok = HeaderValue::from_static("Bearer secret");
        assert!(bearer_token_valid(Some(&ok), "secret"));
        let wrong = HeaderValue::from_static("Bearer hunter2");
        assert!(!bearer_token_valid(Some(&wrong), "secret"));
    }
}
