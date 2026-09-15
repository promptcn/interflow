//! Administrative HTTP endpoints (`/agents` and the like).

use crate::hub::service::{HubService, boxed_full};
use crate::hub::state::HubResponseBody;
use hyper::{Response, StatusCode};
use interflow_core::error::Result;

impl HubService {
    /// `GET /agents`: returns the list of currently registered agent_ids
    /// (JSON array).
    pub(crate) async fn handle_list_agents(&self) -> Result<Response<HubResponseBody>> {
        let agent_list: Vec<String> = {
            let agents = self.agents.read().await;
            agents.keys().cloned().collect()
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
