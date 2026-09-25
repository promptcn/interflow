//! `HubService` — hyper `Service` implementation: rate limiting, mTLS
//! identity gating, request routing.
//!
//! Every HTTP/2 request first goes through [`Service::call`]:
//! 1. per-IP token-bucket rate limiting ([`AuthRateLimiter`], keyed on the
//!    PROXY-protocol effective IP); over the limit returns 429
//! 2. mTLS identity gate: the connection must carry a derived
//!    [`PeerIdentity`] (tenant from the chain's anchoring root, agent from
//!    the leaf CN); registration binds the CN while data-plane handlers bind
//!    the connection-scoped opaque circuit
//! 3. dispatch to the concrete handler (registration / route lease / poll /
//!    streaming upload)
//!
//! There is no bearer-token authentication: client certificates are the only
//! credential (RFC (internal design notes)).

use crate::hub::state::{HubResponseBody, HubState, PeerIdentity};
use bytes::Bytes;
use http_body_util::{BodyExt, Full};
use hyper::body::Incoming;
use hyper::service::Service;
use hyper::{Method, Request, Response, StatusCode};
use interflow_core::error::InterflowError;
use interflow_core::protocol::CircuitToken;
use interflow_core::security::AuditKind;
use std::future::Future;
use std::net::IpAddr;
use std::pin::Pin;
use std::sync::Arc;

use tokio::sync::RwLock;

/// Per-connection hub service object. Each HTTP/2 connection corresponds to
/// one `HubService` instance.
///
/// `Clone` exists so `/stream/up` reader tasks can hold the same routing /
/// audit handles (all fields are `Arc` / `Copy`, so cloning is cheap).
#[derive(Clone)]
pub struct HubService {
    /// Long-lived shared hub state (registry/stream tables, limits, audit).
    pub(crate) state: Arc<HubState>,
    /// Effective client IP (the PROXY-protocol address when fronted by a
    /// trusted proxy, else the TCP peer). Rate limiting, connection caps and
    /// audit key on this — never identity or ACL decisions.
    pub(crate) effective_ip: IpAddr,
    /// mTLS identity bound to this connection: preset at handshake (tenant
    /// from the chain's anchoring CA, agent from the leaf CN). `None` only
    /// if the acceptor was misassembled — every request then fails closed.
    pub(crate) connection_identity: Arc<RwLock<Option<PeerIdentity>>>,
    /// The opaque circuit negotiated by this TLS connection's registration.
    /// It is deliberately not derivable from `connection_identity`.
    pub(crate) connection_circuit: Arc<RwLock<Option<CircuitToken>>>,
}

impl HubService {
    /// Builds the per-connection service object from the accept context
    /// (connection identity is bound per connection).
    pub(crate) const fn new(
        state: Arc<crate::hub::state::HubState>,
        effective_ip: IpAddr,
        connection_identity: Arc<RwLock<Option<PeerIdentity>>>,
        connection_circuit: Arc<RwLock<Option<CircuitToken>>>,
    ) -> Self {
        Self {
            state,
            effective_ip,
            connection_identity,
            connection_circuit,
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

    /// Takes the audited peer as a string: the effective client IP (the
    /// PROXY-protocol address when fronted by a trusted proxy), so audit
    /// records carry the real client — fronted legs would otherwise all
    /// log 127.0.0.1. The raw TCP address stays available in accept-path
    /// log lines; identity never reads either (mTLS only).
    pub(crate) fn peer_str(&self) -> String {
        self.effective_ip.to_string()
    }

    /// The connection's derived identity, if any (fail-closed gate).
    pub(crate) async fn identity(&self) -> Option<PeerIdentity> {
        self.connection_identity.read().await.clone()
    }

    /// The opaque circuit bound to this h2 TLS connection, if registered.
    pub(crate) async fn circuit(&self) -> Option<CircuitToken> {
        *self.connection_circuit.read().await
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
        let peer_str = self.peer_str();

        Box::pin(async move {
            let path = req.uri().path().to_string();

            // Rate limiting (registration-endpoint churn / DoS suppression;
            // mTLS has no brute-forceable credential)
            if let Some(limiter) = &svc.state.rate_limiter
                && !limiter.check(svc.effective_ip)
            {
                metrics::counter!("interflow_hub_auth_failures", "reason" => "rate_limited")
                    .increment(1);
                svc.state.audit.record(
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
                svc.state.audit.record(
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
                (&Method::POST, "/route") => svc.handle_route(req).await,
                (&Method::POST, "/stream/up") => svc.handle_stream_up(req).await,
                (&Method::GET, "/poll") => svc.handle_poll(req).await,
                (&Method::GET, "/agents") => svc.handle_list_agents().await,
                (&Method::PUT, "/policy") => svc.handle_policy_publish(req).await,
                (&Method::GET, "/policy") => svc.handle_policy_pull(req).await,
                _ => Ok(text_response(StatusCode::NOT_FOUND, "Not Found")),
            }
        })
    }
}

/// Extracts the registration-only semantic `x-agent-id` header. Data-plane
/// endpoints use the opaque circuit header instead.
pub(crate) fn agent_id_of(req: &Request<Incoming>) -> interflow_core::error::Result<&str> {
    req.headers()
        .get("x-agent-id")
        .and_then(|v| v.to_str().ok())
        .ok_or_else(|| InterflowError::protocol("missing agent-id".to_string()))
}

/// Extracts the opaque h2 data-plane circuit header. Unlike registration's
/// semantic `x-agent-id`, this value is never a tenant/agent name.
pub(crate) fn circuit_token_of(
    req: &Request<Incoming>,
) -> interflow_core::error::Result<CircuitToken> {
    let value = req
        .headers()
        .get("x-circuit-token")
        .and_then(|v| v.to_str().ok())
        .ok_or_else(|| InterflowError::protocol("missing circuit token"))?;
    CircuitToken::from_hex(value).map_err(|_| InterflowError::protocol("invalid circuit token"))
}

#[cfg(test)]
#[allow(
    clippy::panic,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::missing_docs_in_private_items
)]
mod tests {}
