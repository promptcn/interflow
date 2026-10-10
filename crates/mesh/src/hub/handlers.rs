//! Administrative HTTP endpoints (`/agents` and the like).

use crate::hub::http::{AgentListEntry, LeafExpiry};
use crate::hub::service::{HubService, boxed_full, text_response};
use crate::hub::state::{HubResponseBody, HubState, PeerIdentity};
use hyper::{Response, StatusCode};
use interflow_core::error::Result;
use std::sync::Arc;

/// Builds the tenant-scoped agent listing — the shared body of the h2
/// `GET /agents` face and the QUIC `PeerListRequest` face (both faces serve
/// the same entries, so their JSON shapes cannot drift). Tenant-scoped
/// observability (THREAT_MODEL §6.5): a cross-tenant list is reconnaissance
/// material.
pub(crate) async fn agent_list(state: &Arc<HubState>, tenant: &str) -> Vec<AgentListEntry> {
    let now_unix = interflow_identity::expiry::now_unix();
    let agents = state.agents.read().await;
    // Lock order matches the registration path (registry, then session) —
    // no inversion deadlock is possible.
    let mut list = Vec::with_capacity(agents.len());
    for (key, session) in agents.iter() {
        if PeerIdentity::split_qualified(key).is_none_or(|(t, _)| *t != *tenant) {
            continue;
        }
        let st = session.read().await;
        let online = st.online();
        let leaf_expiry = st
            .leaf_validity_unix
            .map(|(not_before, not_after)| LeafExpiry {
                not_after_unix: not_after,
                health: interflow_identity::expiry::leaf_phase_from_validity(
                    not_before, not_after, now_unix,
                ),
            });
        list.push(AgentListEntry {
            agent: key.clone(),
            online,
            leaf_expiry,
        });
    }
    list
}

impl HubService {
    /// `GET /agents`: the registered agents of **this connection's
    /// tenant** — a JSON array of [`AgentListEntry`] objects (the
    /// operator's curl-able credential-and-reachability surface;
    /// `leaf_expiry` is null when the registration certificate did not
    /// parse, `online` is the session-presence reading). Tenant-scoped
    /// observability (THREAT_MODEL §6.5): a cross-tenant list is
    /// reconnaissance material.
    pub(crate) async fn handle_list_agents(&self) -> Result<Response<HubResponseBody>> {
        // Fail-closed mirror of the `Service::call` identity gate: routing
        // normally guarantees `Some`, but this endpoint must not become a
        // whole-registry dump if a future refactor moves it ahead of the gate.
        let Some(identity) = self.identity().await else {
            return Ok(text_response(
                StatusCode::FORBIDDEN,
                "Client certificate required",
            ));
        };
        let agent_list = agent_list(&self.state, &identity.tenant).await;
        let json = serde_json::to_string(&agent_list)?;

        let response = Response::builder()
            .status(StatusCode::OK)
            .header("content-type", "application/json")
            .body(boxed_full(json))
            .expect("response with status+header+body is infallible");
        Ok(response)
    }

    /// `GET /ping`: the h2 face of the demanding liveness roundtrip (the
    /// QUIC face is the LivenessPing/LivenessPong arm of
    /// `handle_quic_stream`) — an empty-body answer whose arrival is the
    /// only proof the path carries the agent's questions back. Same mTLS
    /// identity gate as every other session route; deliberately no body,
    /// no registry read.
    #[allow(clippy::unused_async, clippy::unused_async_trait_impl)] // the route table awaits every arm uniformly
    pub(crate) async fn handle_ping(&self) -> Result<Response<HubResponseBody>> {
        Ok(Response::builder()
            .status(StatusCode::OK)
            .body(boxed_full(String::new()))
            .expect("response with status+body is infallible"))
    }
}
