//! h2 route-lease control endpoint.

use crate::hub::routing::issue_route;
use crate::hub::service::{HubService, circuit_token_of, json_response, text_response};
use http_body_util::BodyExt;
use hyper::body::Incoming;
use hyper::{Request, Response, StatusCode};
use interflow_core::error::Result;
use interflow_core::tunnel::negotiation::RouteResponse;
use tracing::warn;

impl HubService {
    /// `POST /route`: exchange one locally configured semantic target for a
    /// source-session-scoped opaque route token. This is control plane only;
    /// traffic streams carry the returned token and no target semantics.
    pub(crate) async fn handle_route(
        &self,
        req: Request<Incoming>,
    ) -> Result<Response<crate::hub::state::HubResponseBody>> {
        let circuit = circuit_token_of(&req)?;
        if self.circuit().await != Some(circuit) {
            return Ok(text_response(StatusCode::UNAUTHORIZED, "Circuit mismatch"));
        }
        let agent_key = self.qualified_id().await;
        let state_arc = {
            let agents = self.state.agents.read().await;
            agents.get(&agent_key).cloned()
        };
        let Some(state_arc) = state_arc else {
            return Ok(text_response(
                StatusCode::UNAUTHORIZED,
                "Circuit not registered",
            ));
        };
        if state_arc.read().await.circuit != circuit {
            return Ok(text_response(StatusCode::UNAUTHORIZED, "Circuit mismatch"));
        }

        let body = req.into_body();
        let collected = body.collect().await?;
        let bytes = collected.to_bytes();
        if bytes.len() > 256 {
            return Ok(text_response(
                StatusCode::PAYLOAD_TOO_LARGE,
                "Route target too large",
            ));
        }
        let Ok(target) = std::str::from_utf8(&bytes).map(str::to_owned) else {
            return Ok(text_response(
                StatusCode::BAD_REQUEST,
                "Route target invalid",
            ));
        };

        match issue_route(&self.state, &agent_key, circuit, &target).await {
            Ok(route_token) => {
                let body = serde_json::to_string(&RouteResponse { route_token })?;
                Ok(json_response(StatusCode::OK, body))
            }
            Err(reason) => {
                warn!("Route lease denied: circuit={circuit}, reason={reason}");
                Ok(text_response(StatusCode::FORBIDDEN, "Route denied"))
            }
        }
    }
}
