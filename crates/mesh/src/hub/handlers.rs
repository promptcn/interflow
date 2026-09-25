//! Administrative HTTP endpoints (`/agents` and the like).

use crate::hub::http::{AgentListEntry, LeafExpiry};
use crate::hub::service::{HubService, boxed_full, text_response};
use crate::hub::state::{HubResponseBody, PeerIdentity};
use hyper::{Response, StatusCode};
use interflow_core::error::Result;

impl HubService {
    /// `GET /agents`: the registered agents of **this connection's
    /// tenant** — a JSON array of [`AgentListEntry`] objects (the
    /// operator's curl-able credential-health surface; `leaf_expiry` is
    /// null when the registration certificate did not parse). Tenant-scoped
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
        let tenant = identity.tenant.clone();
        let now_unix = interflow_identity::expiry::now_unix();
        let agent_list: Vec<AgentListEntry> = {
            let agents = self.state.agents.read().await;
            // Lock order matches the registration path (registry, then
            // session) — no inversion deadlock is possible.
            let mut list = Vec::with_capacity(agents.len());
            for (key, session) in agents.iter() {
                if PeerIdentity::split_qualified(key).is_none_or(|(t, _)| *t != *tenant) {
                    continue;
                }
                let st = session.read().await;
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
                    leaf_expiry,
                });
            }
            list
        };
        let json = serde_json::to_string(&agent_list)?;

        let response = Response::builder()
            .status(StatusCode::OK)
            .header("content-type", "application/json")
            .body(boxed_full(json))
            .expect("response with status+header+body is infallible");
        Ok(response)
    }
}
