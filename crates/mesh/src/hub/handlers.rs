//! Administrative HTTP endpoints (`/agents` and the like).

use crate::hub::service::{HubService, boxed_full, text_response};
use crate::hub::state::{HubResponseBody, PeerIdentity};
use hyper::{Response, StatusCode};
use interflow_core::error::Result;

impl HubService {
    /// `GET /agents`: the registered agent ids of **this connection's
    /// tenant** (JSON array of qualified keys). Tenant-scoped observability
    /// (THREAT_MODEL §6.5): a cross-tenant list is reconnaissance material.
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
        let agent_list: Vec<String> = {
            let agents = self.state.agents.read().await;
            agents
                .keys()
                .filter(|key| {
                    PeerIdentity::split_qualified(key).is_some_and(|(t, _)| *t == *tenant)
                })
                .cloned()
                .collect()
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
