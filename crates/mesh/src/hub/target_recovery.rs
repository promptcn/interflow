//! The hub-side face of the 2026-10-18 active breaker recovery
//!
//! A mesh agent whose egress breaker tripped a backend used to be the only
//! party that could notice the backend coming back — and while tripped, it
//! structurally could not (pre-dial rejection means no dials). The agent
//! now runs a background bare-TCP prober
//! (`mesh::agent::breaker_probe`) and reports each recovery out-of-band
//! over the session control plane (`POST /breakers/recovered` on h2, the
//! `TargetRecoveredRequest` frame on QUIC).
//!
//! Why the hub carries a *sink* instead of the route logic itself: only
//! the expose edge (a hub with a public listener fused into the same
//! process) owns route breakers keyed by host. A plain mesh hub has
//! nothing to close. So [`HubState`](crate::hub::state::HubState) holds an
//! optional edge-registered [`TargetRecoverySink`]; the edge registers one
//! at composition time (reverse-indexing its host table by the sender's
//! identity + the notice's service ids), and every other hub delivers into
//! the `None` arm — acknowledged, closed_routes = 0, no-op. The notice is
//! informational by contract: dropping one (old hub, mid-rebuild session,
//! unregistered sink) only means the receiver keeps its cooldown-based
//! recovery.
//!
//! Security shape: the sender is the connection's registered agent — the
//! sink must only act on routes that resolve to THAT agent, so a
//! compromised agent can at worst prematurely re-admit its own routes
//! (never a peer's).

use std::sync::Arc;

use interflow_core::error::{InterflowError, Result};
use interflow_core::tunnel::transport::{TargetRecoveredAck, TargetRecoveredNotice};

/// The edge-registered receiver of target-recovery notices.
///
/// Registered once at composition time via
/// [`HubState::register_target_recovery_sink`](crate::hub::state::HubState::register_target_recovery_sink);
/// implementations must be cheap (the control-plane handler awaits them).
pub trait TargetRecoverySink: Send + Sync {
    /// Acts on one notice from `agent` (the sender's qualified registry
    /// key, `"{workspace}/{agent_id}"`): close the route-breaker entries
    /// whose route resolves to this agent AND selects one of the notice's
    /// service ids. Returns how many entries were actually closed.
    fn target_recovered(&self, agent: &str, notice: &TargetRecoveredNotice) -> u32;
}

/// The shared sink slot: `None` on every hub without an edge face.
pub type SharedTargetRecoverySink = Arc<std::sync::RwLock<Option<Arc<dyn TargetRecoverySink>>>>;

/// Delivers one notice under the sender's identity. The single entry both
/// transport faces (h2 `POST /breakers/recovered`, the QUIC
/// `TargetRecoveredRequest` arm) call — the identity/registration gate is
/// the callers' (same standing as the stream-intent exchange); this fn is
/// the acting half only.
pub(crate) fn deliver(
    sink: &SharedTargetRecoverySink,
    agent: &str,
    notice: &TargetRecoveredNotice,
) -> TargetRecoveredAck {
    let guard = sink
        .read()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    match guard.as_ref() {
        Some(sink) => TargetRecoveredAck {
            closed_routes: sink.target_recovered(agent, notice),
        },
        // No edge face on this hub (a plain mesh hub): acknowledged no-op.
        None => TargetRecoveredAck::default(),
    }
}

impl crate::hub::service::HubService {
    /// `POST /breakers/recovered` — one agent's out-of-band recovery
    /// notice. Same standing as the stream-intent exchange: the requester
    /// is the connection's identity AND must be a registered agent; the
    /// notice acts under that identity only (never a body-supplied name).
    /// The body is the JSON [`TargetRecoveredNotice`]; the answer is the
    /// JSON [`TargetRecoveredAck`].
    pub(crate) async fn handle_target_recovered(
        &self,
        req: hyper::Request<hyper::body::Incoming>,
    ) -> Result<hyper::Response<crate::hub::state::HubResponseBody>> {
        use http_body_util::BodyExt as _;
        use hyper::StatusCode;
        let Some(identity) = self.identity().await else {
            return Ok(crate::hub::service::text_response(
                StatusCode::UNAUTHORIZED,
                "Client certificate required",
            ));
        };
        if identity.tenant.as_ref() == crate::hub::state::CONTROL_TENANT {
            return Ok(crate::hub::service::text_response(
                StatusCode::FORBIDDEN,
                "control principals do not report target recoveries",
            ));
        }
        let agent = crate::hub::qualified_agent_id(&identity.tenant, &identity.agent);
        {
            let agents = self.state.agents.read().await;
            if !agents.contains_key(&agent) {
                return Ok(crate::hub::service::json_response(
                    StatusCode::FORBIDDEN,
                    serde_json::json!({ "ok": false, "reason": format!("{agent} is not a registered agent") }).to_string(),
                ));
            }
        }
        let collected = http_body_util::Limited::new(req.into_body(), 64 * 1024)
            .collect()
            .await
            .map_err(|e| {
                InterflowError::protocol(
                    "target-recovery notice read failed (or exceeds 64 KiB)".to_string(),
                )
                .with_source(e)
            })?;
        let notice: TargetRecoveredNotice =
            serde_json::from_slice(&collected.to_bytes()).map_err(|e| {
                InterflowError::protocol("target-recovery notice is malformed".to_string())
                    .with_source(e)
            })?;
        let ack = deliver(&self.state.target_recovery, &agent, &notice);
        Ok(crate::hub::service::json_response(
            StatusCode::OK,
            serde_json::to_string(&ack)?,
        ))
    }
}
