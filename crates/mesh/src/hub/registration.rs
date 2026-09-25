//! `/register` handling: identity binding + agent registration.

use crate::hub::service::{HubService, json_response, text_response};
use crate::hub::state::{AgentSession, HubResponseBody, SharedStreamCounts};
use hyper::{Response, StatusCode};
use interflow_core::error::Result;
use interflow_core::protocol::CircuitToken;
use interflow_core::security::AuditKind;
use interflow_core::tunnel::negotiation::{HeartbeatAd, RegisterResponse};
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::{info, warn};

impl HubService {
    /// Handles a `/register` request.
    ///
    /// 1. Identity binding: if the connection is already bound to a different
    ///    agent_id, return 403; otherwise bind it.
    ///    (In mTLS mode connection_identity was preset to the client cert CN
    ///    at handshake time; here the x-agent-id header must equal the CN,
    ///    which prevents impersonation at the root.)
    /// 2. Create an mpsc data channel with capacity 256 (bounds the memory
    ///    peak under multi-stream concurrency for a single agent; when full,
    ///    hyper polling applies backpressure automatically, ultimately
    ///    triggering upstream TCP flow control).
    /// 3. Insert into the agent registry atomically under a single write lock.
    pub(crate) async fn handle_register(
        &self,
        agent_id: String,
    ) -> Result<Response<HubResponseBody>> {
        // Identity binding: the claimed bare id must equal the mTLS-derived
        // identity's agent (CN). The tenant is never claimable — it comes
        // from the certificate chain's anchoring root, so cross-tenant
        // preemption is structurally impossible.
        let identity = {
            let identity = self.connection_identity.read().await;
            match &*identity {
                Some(existing) if existing.agent == agent_id => existing.clone(),
                Some(_) => {
                    warn!("registration identity mismatch on an authenticated connection");
                    metrics::counter!("interflow_hub_auth_failures", "reason" => "identity_mismatch").increment(1);
                    self.state.audit.record(
                        AuditKind::AgentRegisterDenied {
                            reason: "identity_mismatch".to_string(),
                        },
                        None,
                        Some(self.peer_str()),
                    );
                    return Ok(text_response(StatusCode::FORBIDDEN, "Identity mismatch"));
                }
                None => {
                    metrics::counter!("interflow_hub_auth_failures", "reason" => "no_client_cert")
                        .increment(1);
                    self.state.audit.record(
                        AuditKind::AgentRegisterDenied {
                            reason: "no_client_cert".into(),
                        },
                        None,
                        Some(self.peer_str()),
                    );
                    return Ok(text_response(
                        StatusCode::UNAUTHORIZED,
                        "Client certificate required",
                    ));
                }
            }
        };
        let agent_key = identity.qualified();
        // Control-plane principals (the realm root's `control` tenant) never
        // register as data-plane agents — their only authority is policy
        // publication, and registering would hand them a routable circuit.
        if identity.tenant.as_ref() == crate::hub::state::CONTROL_TENANT {
            metrics::counter!("interflow_hub_auth_failures", "reason" => "control_principal_on_data_plane")
                .increment(1);
            self.state.audit.record(
                AuditKind::AgentRegisterDenied {
                    reason: "control_principal_on_data_plane".to_string(),
                },
                None,
                Some(self.peer_str()),
            );
            return Ok(text_response(
                StatusCode::FORBIDDEN,
                "control-plane principals cannot register as agents",
            ));
        }
        let circuit = CircuitToken::random()?;
        *self.connection_circuit.write().await = Some(circuit);
        info!(
            "Agent registered: circuit={circuit} from {}",
            self.effective_ip
        );
        self.state
            .route_leases
            .write()
            .await
            .retain(|_, (_, source, _)| source != &agent_key);

        // The registration certificate's validity window rides the session
        // (refreshed here — a reconnected agent presents its current leaf).
        let leaf_validity = identity.leaf_validity_unix;

        // Single write lock: atomically insert or replace the channel in
        // place (see [`AgentSession::install_channels`] for why in place).
        // The registry key is tenant-qualified: the same bare id under
        // another tenant is a different, non-colliding entry.
        let registered_count = {
            let mut agents = self.state.agents.write().await;
            match agents.get(&agent_key) {
                Some(existing) => {
                    // h2 registration overwrites a QUIC session: the old
                    // relay connection closes itself out via its
                    // connection-lost watcher
                    let mut session = existing.write().await;
                    session.install_channels(circuit, None);
                    session.leaf_validity_unix = leaf_validity;
                }
                None => {
                    agents.insert(
                        agent_key.clone(),
                        Arc::new(RwLock::new(AgentSession::new(circuit, None, leaf_validity))),
                    );
                }
            }
            agents.len()
        };
        self.state
            .route_leases
            .write()
            .await
            .retain(|_, (_, source, _)| source != &agent_key);
        // Absolute value rather than increment: re-registration no longer
        // accumulates drift
        metrics::gauge!("interflow_hub_agents_registered")
            .set(crate::hub::state::count_as_f64(registered_count));

        // Clean up orphan streams left over from the agent's previous
        // connection and reset its counters to prevent drift.
        // Scenario: the agent disconnected abnormally without sending Close,
        // leaving old streams in active_streams; without cleanup on reconnect,
        // the per-agent count stays occupied forever and new streams are
        // rejected.
        Self::sweep_agent_streams(
            &self.state.agents,
            &self.state.active_streams,
            &self.state.stream_counts,
            &agent_key,
        )
        .await;

        self.state.audit.record(
            AuditKind::AgentRegistered {
                circuit: circuit.to_hex(),
            },
            Some(circuit.to_hex()),
            Some(self.peer_str()),
        );

        // Capability negotiation: the response body carries the hub's
        // heartbeat cadence; agents parse it and derive the poll watchdog /
        // task-stall timeouts (see `interflow_core::tunnel::negotiation`).
        let caps = {
            let cfg = self.state.config.read().await;
            RegisterResponse {
                circuit_token: circuit,
                heartbeat: cfg
                    .heartbeat
                    .enabled
                    .then_some(HeartbeatAd::from(&cfg.heartbeat)),
            }
        };
        // Serializing a plain scalar struct cannot fail; if it somehow does,
        // degrade to a minimal capability declaration (heartbeat disabled)
        let body = serde_json::to_string(&caps).unwrap_or_else(|_| "{}".to_string());
        Ok(json_response(StatusCode::OK, body))
    }

    /// Implicit re-registration: when an agent that was evicted (poll grace /
    /// heartbeat loss / send timeout) still holds a healthy connection, its
    /// next `/poll` or `/stream/up` restores registration right here, without
    /// waiting for a disconnect to trigger reconnect and re-registration
    /// (edge processes never re-register and rely on this self-healing path
    /// in particular).
    ///
    /// The identity binding check must be completed before calling; the
    /// authentication level is equivalent to `/register`.
    pub(crate) async fn implicit_re_register(&self, agent_id: &str) -> Arc<RwLock<AgentSession>> {
        let Some(circuit) = self.circuit().await else {
            // A data-plane request cannot implicitly register: it has no
            // response in which to learn the freshly generated circuit.
            unreachable!("implicit re-registration requires a connection circuit");
        };
        info!("Agent circuit={circuit} not registered, implicitly re-registering");
        // The connection certificate's window rides the fresh session.
        let leaf_validity = self.identity().await.and_then(|i| i.leaf_validity_unix);
        let arc = Arc::new(RwLock::new(AgentSession::new(circuit, None, leaf_validity)));
        {
            let mut agents = self.state.agents.write().await;
            agents.insert(agent_id.to_string(), arc.clone());
            metrics::gauge!("interflow_hub_agents_registered")
                .set(crate::hub::state::count_as_f64(agents.len()));
        }
        Self::sweep_agent_streams(
            &self.state.agents,
            &self.state.active_streams,
            &self.state.stream_counts,
            agent_id,
        )
        .await;
        self.state.audit.record(
            AuditKind::AgentRegistered {
                circuit: circuit.to_hex(),
            },
            Some(circuit.to_hex()),
            Some(self.peer_str()),
        );
        // Heartbeats are served by the global supervision loop (see
        // hub/heartbeat.rs); re-registration needs no spawn
        arc
    }
}

impl HubService {
    /// Cleans up all orphan streams where `agent` is the source or target,
    /// resets its per-agent counter, and **produces a termination signal on
    /// the peer's dispatch plane**.
    ///
    /// Called on `/register` (h2 and QUIC) and by the eviction primitive
    /// (`evict_agent`): an agent reconnecting/being evicted means its previous
    /// connection is gone, so old streams are invalid even without receiving
    /// a Close. Not cleaning up leaks `active_streams` and drifts
    /// `stream_counts`; afterwards `max_streams_per_agent` stays occupied
    /// forever by old streams.
    ///
    /// The termination signal is dispatched by the peer's dispatch plane
    /// (2026-09-14 in-session root fix for orphan streams, see `hub::control`):
    /// - **poll plane** (h2 peer): the control channel guarantees delivery of
    ///   `_close_` (reason = `agent-evicted`) — otherwise the peer's
    ///   forwarder waits forever for a Close and the backend fd lingers for
    ///   the whole session (the EMFILE recurrence path);
    /// - **relay plane** (QUIC peer): removing the table entry itself drops
    ///   the relay senders, and the write task writes the outstanding
    ///   Close+FIN — no explicit notification needed.
    pub(crate) async fn sweep_agent_streams(
        agents: &crate::hub::state::SharedAgents,
        active_streams: &crate::hub::state::SharedActiveStreams,
        stream_counts: &SharedStreamCounts,
        agent_id: &str,
    ) {
        let mut removed_as_source = 0usize;
        let mut removed_total = 0usize;
        // Poll-plane peers needing explicit notification (the relay plane is
        // informed by the table-entry drop)
        let mut poll_peers: Vec<(String, interflow_core::protocol::StreamId)> = Vec::new();
        {
            let mut streams = active_streams.write().await;
            streams.retain(|sid, s| {
                if s.source_agent == agent_id {
                    removed_as_source += 1;
                    removed_total += 1;
                    // The evicted party is the source: notify the target end.
                    // For a loopback stream (source == target) the peer is the
                    // evicted agent itself; no notification needed.
                    if !s.target.is_relay() && s.target_agent != agent_id {
                        poll_peers.push((s.target_agent.clone(), *sid));
                    }
                    false
                } else if s.target_agent == agent_id {
                    // Being cleaned up as the target does not count toward
                    // the source count, but the gauge must be decremented
                    // accordingly
                    removed_total += 1;
                    if !s.source.is_relay() && s.source_agent != agent_id {
                        poll_peers.push((s.source_agent.clone(), *sid));
                    }
                    false
                } else {
                    true
                }
            });
            if removed_total > 0 {
                metrics::gauge!("interflow_hub_streams_active")
                    .decrement(u32::try_from(removed_total).unwrap_or(u32::MAX));
                warn!(
                    "agent offline/reconnected: cleaned up {} orphan streams ({} of them needed poll-side peer notification)",
                    removed_total,
                    poll_peers.len()
                );
            }
        }
        // Reset the source count (only slots counted as source_agent)
        {
            let mut map = stream_counts
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            if removed_as_source > 0 {
                map.remove(agent_id);
            }
        }
        // Guaranteed delivery outside the locks (eviction is a failure path;
        // termination takes priority over any tail data still queued)
        for (peer, sid) in poll_peers {
            if crate::hub::control::deliver_close_via_control(
                agents,
                &peer,
                sid,
                interflow_core::protocol::CloseReason::SessionClosed,
            )
            .await
            {
                metrics::counter!("interflow_hub_sweep_peer_notified_total").increment(1);
            }
        }
    }
}
