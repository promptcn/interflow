//! Wire contracts of the hub's operator HTTP surface.
//!
//! The typed shapes an operator (or script) consumes via curl. Handlers
//! serialize these; the e2e guards hold their own consumer-side mirror in
//! `interflow-testkit` (`hub_http`), so a shape change here fails the
//! guards unless both sides move in the same commit (the HTTP-surface
//! analog of the GUI bindings drift guard; see
//! (internal design notes)).

use interflow_identity::expiry::LeafHealth;
use serde::{Deserialize, Serialize};

/// One `GET /agents` entry: the agent's qualified id, its reachability
/// reading, and its credential-health reading.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AgentListEntry {
    /// Qualified agent id (`tenant/agent`).
    pub agent: String,
    /// The reachability reading (`registered ≠ reachable`): a QUIC relay
    /// session in place, or an h2 poll body in place / within reconnect
    /// grace. Pong freshness is deliberately not part of it (QUIC agents
    /// never answer an h2 heartbeat).
    pub online: bool,
    /// Parsed from the registration certificate; `None` (serialized as
    /// null) when the leaf certificate did not parse.
    pub leaf_expiry: Option<LeafExpiry>,
}

/// The `leaf_expiry` object: the leaf's `notAfter` plus the single-source
/// phase math ([`LeafHealth`]) flattened to `{remaining_secs, phase}`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LeafExpiry {
    pub not_after_unix: i64,
    #[serde(flatten)]
    pub health: LeafHealth,
}

// ---------------------------------------------------------------------------
// Client (local diagnostics side)
// ---------------------------------------------------------------------------

/// Queries a hub's registered-agents roster (`GET /agents`).
///
/// The authoritative session-presence reading of this connection's tenant —
/// the face `doctor ingress` consults to tell "the agent's leg is gone"
/// from "the leg is up and the backing service is down". The credential is
/// a workspace-tenant agent certificate (the ingress pack's
/// `ingress-<workspace>` principal is exactly that class); server trust is
/// the caller's [`ServerTrust`] — a loopback dial pins the control cert's
/// fingerprint, an operator dial verifies against the realm issuer.
/// One-shot, 3s-bounded (the primary caller dials loopback, where
/// sub-second is the norm — a stuck local control endpoint must not hang a
/// doctor sweep; the remote-client faces keep their own 10s bound).
pub async fn query_agents(
    hub_endpoint: &str,
    trust: crate::hub::policy::ServerTrust<'_>,
    client_cert_path: &std::path::Path,
    client_key_path: &std::path::Path,
) -> interflow_core::error::Result<Vec<AgentListEntry>> {
    use http_body_util::BodyExt;

    let future = async {
        let mut send_request = crate::hub::policy::control_plane_dial(
            hub_endpoint,
            trust,
            client_cert_path,
            client_key_path,
        )
        .await?;
        let request = hyper::Request::builder()
            .method(hyper::Method::GET)
            .uri("/agents")
            .body(
                http_body_util::Full::<bytes::Bytes>::new(bytes::Bytes::new())
                    .map_err(|never| match never {})
                    .boxed(),
            )
            .map_err(|e| {
                interflow_core::error::InterflowError::protocol(
                    "agents-list query build".to_string(),
                )
                .with_source(e)
            })?;
        let response = send_request.send_request(request).await?;
        let status = response.status();
        let collected = response.into_body().collect().await.map_err(|e| {
            interflow_core::error::InterflowError::protocol("agents-list query body".to_string())
                .with_source(e)
        })?;
        let text = String::from_utf8_lossy(&collected.to_bytes()).to_string();
        if status == hyper::StatusCode::FORBIDDEN {
            return Err(interflow_core::error::InterflowError::connection(format!(
                "agents list rejected: {status} — {text} (the credential is not a workspace \
                 tenant principal)"
            )));
        }
        if status != hyper::StatusCode::OK {
            return Err(interflow_core::error::InterflowError::connection(format!(
                "agents list query rejected: {status} — {text}"
            )));
        }
        serde_json::from_str(&text).map_err(|e| {
            interflow_core::error::InterflowError::protocol(format!(
                "agents list 200 with an unparseable body: {e} — {text:?}"
            ))
        })
    };
    tokio::time::timeout(std::time::Duration::from_secs(3), future)
        .await
        .map_err(|_| {
            interflow_core::error::InterflowError::connection(
                "agents list query timed out (>3s) — the control endpoint did not answer"
                    .to_string(),
            )
        })?
}
