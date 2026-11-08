//! Agent registration: the transport-neutral core plus the h2 arms.
//!
//! Every registration path funnels through [`HubState::register_agent`] —
//! h2 `/register` (explicit), the implicit re-registration riding `/poll`
//! and `/stream/up`, and the QUIC Hello arm in `hub/quic.rs`. The arms own
//! identity sourcing, denial rendering and ack shaping; the core owns the
//! gates and the full registration side-effect list (session install,
//! floor/gauge, lease hygiene, sweep, audit, the credential-expiry
//! ledger). A registration semantic lands here exactly once: the
//! hand-mirrored per-arm copies this replaced drifted in six places

use crate::hub::crl::revoked_credential_response;
use crate::hub::service::{HubService, json_response, text_response};
use crate::hub::state::{
    AgentSession, HubResponseBody, HubState, PeerIdentity, QuicAgentConn, SharedStreamCounts,
};
use hyper::{Response, StatusCode};
use interflow_core::error::Result;
use interflow_core::protocol::CircuitToken;
use interflow_core::security::AuditKind;
use interflow_core::tunnel::negotiation::{HeartbeatAd, RegisterResponse};
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::info;

/// Why a registration was refused before any state changed. The metric +
/// audit attribution happens once, in the core; each transport arm renders
/// its own denial shape.
#[derive(Debug)]
pub enum RegistrationRefusal {
    /// Control-plane principals (the realm root's `control` tenant) never
    /// register as data-plane agents — their only authority is policy
    /// publication, and registering would hand them a routable circuit.
    ControlPrincipal,
    /// The presented leaf is on the tenant CRL (rotate + re-register).
    CredentialRevoked { serial: String },
}

/// A completed registration, handed back to the transport arm.
pub struct Registered {
    /// The tenant-qualified registry key (`"{tenant}/{agent}"`).
    pub(crate) key: String,
    /// The installed session — the in-place Arc on re-registration.
    pub(crate) session: Arc<RwLock<AgentSession>>,
}

/// A registration keeps only the route leases of the circuit it installs:
/// a fresh circuit (h2 `/register`, QUIC Hello) clears the agent's stale
/// leases; a reused circuit (implicit re-registration) keeps them — the
/// agent's session-scoped route cache survives that path (same
/// connection, same session object) and its tokens must stay valid.
async fn clear_stale_leases(state: &HubState, agent_key: &str, circuit: CircuitToken) {
    state
        .route_leases
        .write()
        .await
        .retain(|_, (lease_circuit, source, _)| source != agent_key || *lease_circuit == circuit);
}

impl HubState {
    /// THE registration core — the single side-effect list every transport
    /// arm calls.
    ///
    /// 1. Gates (control-principal, revocation) — refused before any state
    ///    changes, with the shared metric + audit attribution.
    /// 2. Session install under one write lock: replace-in-place on the
    ///    existing Arc (h2↔QUIC preemption alike) or a fresh row.
    /// 3. The registration implications: lease hygiene, floor/gauge,
    ///    orphan-stream sweep, the `AgentRegistered` audit, and the
    ///    credential-expiry ledger record.
    pub async fn register_agent(
        &self,
        identity: &PeerIdentity,
        circuit: CircuitToken,
        build: Option<String>,
        quic: Option<Arc<QuicAgentConn>>,
        peer: &str,
    ) -> std::result::Result<Registered, RegistrationRefusal> {
        // Control-plane principals (the realm root's `control` tenant)
        // never register as data-plane agents — their only authority is
        // policy publication, and registering would hand them a routable
        // circuit.
        if identity.tenant.as_ref() == crate::hub::state::CONTROL_TENANT {
            metrics::counter!("interflow_hub_auth_failures", "reason" => "control_principal_on_data_plane")
                .increment(1);
            self.audit.record(
                AuditKind::AgentRegisterDenied {
                    reason: "control_principal_on_data_plane".to_string(),
                },
                None,
                Some(peer.to_string()),
            );
            return Err(RegistrationRefusal::ControlPrincipal);
        }
        // The revocation gate: the mTLS handshake may predate the CRL
        // swap that revoked this credential (the h2 acceptor only gates
        // NEW connections; the QUIC handshake never carries CRLs) —
        // registration is the gate every transport shares.
        if let Some(serial) = self.credential_revoked(identity) {
            metrics::counter!("interflow_hub_auth_failures", "reason" => "credential_revoked")
                .increment(1);
            self.audit.record(
                AuditKind::AgentRegisterDenied {
                    reason: format!("credential_revoked (serial {serial})"),
                },
                None,
                Some(peer.to_string()),
            );
            return Err(RegistrationRefusal::CredentialRevoked { serial });
        }
        let agent_key = identity.qualified();
        clear_stale_leases(self, &agent_key, circuit).await;

        // The registration certificate's validity window and revocation
        // serial ride the session (refreshed here — a reconnected agent
        // presents its current leaf).
        let leaf_validity = identity.leaf_validity_unix;
        let leaf_serial = identity
            .leaf_serial_hex
            .clone()
            .map(|serial| (serial, crate::hub::crl::tenant_crl_stem(&identity.tenant)));
        // The expiry face's serial (captured before the session install
        // moves the pair).
        let leaf_serial_hex = leaf_serial.as_ref().map(|(serial, _)| serial.clone());

        // Single write lock: atomically insert or replace the channel in
        // place (see [`AgentSession::install_channels`] for why in place).
        // The registry key is tenant-qualified: the same bare id under
        // another tenant is a different, non-colliding entry.
        let (session, registered_count) = {
            let mut agents = self.agents.write().await;
            if let Some(existing) = agents.get(&agent_key) {
                let mut session = existing.write().await;
                session.install_channels(circuit, quic);
                session.leaf_validity_unix = leaf_validity;
                session.leaf_serial = leaf_serial;
                session.build.clone_from(&build);
                // The flat data-plane projection moves with the registry
                // (same critical section): replace-in-place hands the data
                // plane the new channel, and the old receiver's drop makes
                // every stale sender present as Closed.
                self.install_data_tx(&agent_key, session.tx.clone());
                (existing.clone(), agents.len())
            } else {
                let mut session = AgentSession::new(circuit, quic, leaf_validity, leaf_serial);
                session.build.clone_from(&build);
                self.install_data_tx(&agent_key, session.tx.clone());
                let arc = Arc::new(RwLock::new(session));
                agents.insert(agent_key.clone(), arc.clone());
                // A NEW registry row is floor-visible (presence); a
                // replace-in-place re-registration is not (the row never
                // left).
                self.floor_clock.bump();
                (arc, agents.len())
            }
        };
        // The maintenance auto-lift rides EVERY registration path (a
        // replace-in-place re-registration is a rejoin all the same —
        // (internal design notes)).
        crate::hub::maintenance::auto_lift_on_rejoin(self, &agent_key);
        clear_stale_leases(self, &agent_key, circuit).await;
        // Absolute value rather than increment: re-registration no longer
        // accumulates drift.
        metrics::gauge!("interflow_hub_agents_registered")
            .set(crate::hub::state::count_as_f64(registered_count));

        // Clean up orphan streams left over from the agent's previous
        // connection and reset its counters to prevent drift.
        // Scenario: the agent disconnected abnormally without sending
        // Close, leaving old streams in active_streams; without cleanup
        // on reconnect, the per-agent count stays occupied forever and
        // new streams are rejected.
        HubService::sweep_agent_streams(
            &self.agents,
            &self.active_streams,
            &self.stream_counts,
            &agent_key,
        )
        .await;

        self.audit.record(
            AuditKind::AgentRegistered {
                circuit: circuit.to_hex(),
                agent: agent_key.clone(),
                build,
            },
            Some(circuit.to_hex()),
            Some(peer.to_string()),
        );
        // The credential-expiry face's material: retain the observed
        // window (the chain IS the report — no new reporting channel).
        if let Some((not_before, not_after)) = leaf_validity {
            self.credential_watermarks.record(
                &agent_key,
                not_before,
                not_after,
                leaf_serial_hex,
                u64::try_from(interflow_identity::expiry::now_unix()).unwrap_or(0),
            );
        }
        Ok(Registered {
            key: agent_key,
            session,
        })
    }
}

impl HubService {
    /// Handles a `/register` request.
    ///
    /// 1. Identity binding: if the connection is already bound to a different
    ///    agent_id, return 403; otherwise bind it.
    ///    (In mTLS mode connection_identity was preset to the client cert CN
    ///    at handshake time; here the x-agent-id header must equal the CN,
    ///    which prevents impersonation at the root.)
    /// 2. The registration core: gates, session install, and every
    ///    registration implication (see [`HubState::register_agent`]).
    /// 3. The h2 response carries the circuit + capability declaration.
    pub(crate) async fn handle_register(
        &self,
        agent_id: String,
        build: Option<String>,
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
                    tracing::warn!("registration identity mismatch on an authenticated connection");
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
        let circuit = CircuitToken::random()?;
        match self
            .state
            .register_agent(&identity, circuit, build.clone(), None, &self.peer_str())
            .await
        {
            Ok(_) => {}
            Err(RegistrationRefusal::ControlPrincipal) => {
                return Ok(text_response(
                    StatusCode::FORBIDDEN,
                    "control-plane principals cannot register as agents",
                ));
            }
            Err(RegistrationRefusal::CredentialRevoked { .. }) => {
                return Ok(revoked_credential_response());
            }
        }
        *self.connection_circuit.write().await = Some(circuit);
        info!(
            "Agent registered: circuit={circuit} from {} (build {})",
            self.effective_ip,
            build.as_deref().unwrap_or("unknown")
        );

        // Capability negotiation: the response body carries the hub's
        // heartbeat cadence; agents parse it and derive the poll watchdog /
        // task-stall timeouts (see `interflow_core::tunnel::negotiation`).
        // The egress address is the hub's own observation of the agent —
        // surfaced back so the agent side can show "hub-confirmed"
        // connectivity detail (the NAT truth its own socket cannot see).
        let caps = {
            let cfg = self.state.config.read().await;
            RegisterResponse {
                circuit_token: circuit,
                heartbeat: cfg
                    .heartbeat
                    .enabled
                    .then_some(HeartbeatAd::from(&cfg.heartbeat)),
                egress_ip: Some(self.effective_ip.to_string()),
            }
        };
        // Serializing a plain scalar struct cannot fail in practice; a real
        // failure is a hub bug and fails the request rather than silently
        // degrading to a declaration the agent must reject anyway.
        let body = serde_json::to_string(&caps)?;
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
    /// authentication level is equivalent to `/register`. The connection's
    /// circuit is REUSED (its route leases and the agent's session-scoped
    /// route cache survive the eviction window). `Err` = the registration
    /// core refused; the caller answers with the denial.
    pub(crate) async fn implicit_re_register(
        &self,
        agent_id: &str,
    ) -> std::result::Result<Arc<RwLock<AgentSession>>, Box<Response<HubResponseBody>>> {
        let Some(circuit) = self.circuit().await else {
            // A data-plane request cannot implicitly register: it has no
            // response in which to learn the freshly generated circuit.
            unreachable!("implicit re-registration requires a connection circuit");
        };
        info!("Agent circuit={circuit} not registered, implicitly re-registering");
        // The identity binding check upstream guarantees the mTLS identity;
        // a missing identity here is fail-closed to the same 401 the
        // explicit arm answers with.
        let Some(identity) = self.identity().await else {
            return Err(Box::new(text_response(
                StatusCode::UNAUTHORIZED,
                "Client certificate required",
            )));
        };
        // The caller's key and the identity's key are the same string by
        // construction (`qualified_id`); the core owns the registry key, so
        // pin the agreement — a divergence would fork the caller's view of
        // the row from the row itself.
        debug_assert_eq!(identity.qualified(), agent_id);
        match self
            .state
            .register_agent(&identity, circuit, None, None, &self.peer_str())
            .await
        {
            Ok(registered) => Ok(registered.session),
            Err(RegistrationRefusal::ControlPrincipal) => Err(Box::new(text_response(
                StatusCode::FORBIDDEN,
                "control-plane principals cannot register as agents",
            ))),
            Err(RegistrationRefusal::CredentialRevoked { .. }) => {
                Err(Box::new(revoked_credential_response()))
            }
        }
    }
}

impl HubService {
    /// Cleans up all orphan streams where `agent` is the source or target,
    /// resets its per-agent counter, and **produces a termination signal on
    /// the peer's dispatch plane**.
    ///
    /// Called by the registration core (every transport) and by the eviction
    /// primitive (`remove_agent_if_current`): an agent
    /// reconnecting/being evicted means its previous connection is gone, so
    /// old streams are invalid even without receiving a Close. Not cleaning
    /// up leaks `active_streams` and drifts `stream_counts`; afterwards
    /// `max_streams_per_agent` stays occupied forever by old streams.
    ///
    /// The termination signal is dispatched by the peer's dispatch plane
    /// (2026-09-14 in-session root fix for orphan streams, see `hub::control`):
    /// - **poll plane** (h2 peer): the control channel guarantees delivery of
    ///   Close notification (reason = `agent-evicted`) — otherwise the peer's
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
            // Sharded retain: one shard's write lock at a time; the counts
            // and peer list accumulate across shards.
            active_streams.retain(|sid, s| {
                if &*s.source_agent == agent_id {
                    removed_as_source += 1;
                    removed_total += 1;
                    // The evicted party is the source: notify the target end.
                    // For a loopback stream (source == target) the peer is the
                    // evicted agent itself; no notification needed.
                    if !s.target.is_relay() && &*s.target_agent != agent_id {
                        poll_peers.push((s.target_agent.to_string(), *sid));
                    }
                    false
                } else if &*s.target_agent == agent_id {
                    // Being cleaned up as the target does not count toward
                    // the source count, but the gauge must be decremented
                    // accordingly
                    removed_total += 1;
                    if !s.source.is_relay() && &*s.source_agent != agent_id {
                        poll_peers.push((s.source_agent.to_string(), *sid));
                    }
                    false
                } else {
                    true
                }
            });
            if removed_total > 0 {
                metrics::gauge!("interflow_hub_streams_active")
                    .decrement(u32::try_from(removed_total).unwrap_or(u32::MAX));
                tracing::warn!(
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

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use crate::hub::state::PeerIdentity;
    use crate::hub::test_support::test_state;
    use interflow_core::protocol::RouteToken;

    fn identity(tenant: &str, agent: &str) -> PeerIdentity {
        PeerIdentity {
            tenant: Arc::from(tenant),
            agent: agent.to_string(),
            trusted_gateway: false,
            leaf_validity_unix: Some((100, 200)),
            leaf_serial_hex: Some("00aa01".to_string()),
        }
    }

    fn circuit() -> CircuitToken {
        CircuitToken::random().unwrap()
    }

    /// The expiry face's material is written on BOTH install shapes — the
    /// fresh row and the replace-in-place re-registration (the 2026-10-21
    /// case file: the QUIC arm's hand-mirrored copy dropped the record
    /// entirely; a replace-in-place that dropped it would rot the window
    /// the same way one rotation later).
    #[tokio::test]
    async fn register_records_the_credential_window_on_both_install_shapes() {
        let dir = tempfile::tempdir().unwrap();
        let hub = test_state(dir.path());
        let id = identity("main", "lan-a");
        let first = hub
            .register_agent(&id, circuit(), None, None, "127.0.0.1:1")
            .await
            .unwrap();
        let face = hub.credential_watermarks.face();
        let row = face.get("main/lan-a").unwrap();
        assert_eq!(row.not_before_unix, 100);
        assert_eq!(row.not_after_unix, 200);
        assert_eq!(row.serial_hex.as_deref(), Some("00aa01"));

        // Rotation: a fresh leaf window re-registers in place (same Arc —
        // the replace-in-place contract) and the face follows.
        let mut rotated = identity("main", "lan-a");
        rotated.leaf_validity_unix = Some((150, 250));
        rotated.leaf_serial_hex = Some("00bb02".to_string());
        let second = hub
            .register_agent(&rotated, circuit(), None, None, "127.0.0.1:1")
            .await
            .unwrap();
        assert!(
            Arc::ptr_eq(&first.session, &second.session),
            "re-registration replaces in place (the same Arc)"
        );
        let face = hub.credential_watermarks.face();
        let row = face.get("main/lan-a").unwrap();
        assert_eq!(row.not_before_unix, 150);
        assert_eq!(row.not_after_unix, 250);
        assert_eq!(row.serial_hex.as_deref(), Some("00bb02"));
        assert_eq!(hub.agents.read().await.len(), 1);
    }

    /// The lease rule is circuit-bound: a registration keeps only the
    /// leases of the circuit it installs. A fresh circuit (explicit
    /// re-registration) clears the agent's stale leases; a reused circuit
    /// (implicit re-registration — same connection, same agent session,
    /// session-scoped route cache) keeps them.
    #[tokio::test]
    async fn registration_keeps_only_the_installed_circuits_leases() {
        let dir = tempfile::tempdir().unwrap();
        let hub = test_state(dir.path());
        let id = identity("main", "lan-a");
        let x = circuit();
        hub.register_agent(&id, x, None, None, "127.0.0.1:1")
            .await
            .unwrap();
        let foreign = circuit();
        {
            let mut leases = hub.route_leases.write().await;
            leases.insert(
                RouteToken::from_bytes([1; 16]),
                (x, "main/lan-a".to_string(), "main/lan-b".to_string()),
            );
            leases.insert(
                RouteToken::from_bytes([2; 16]),
                (foreign, "main/lan-a".to_string(), "main/lan-b".to_string()),
            );
        }

        // Implicit shape: the same circuit re-registers → its lease
        // survives, the foreign circuit's goes.
        hub.register_agent(&id, x, None, None, "127.0.0.1:1")
            .await
            .unwrap();
        let leases = hub.route_leases.read().await;
        assert_eq!(leases.len(), 1, "only the installed circuit's lease");
        assert!(leases.contains_key(&RouteToken::from_bytes([1; 16])));
        drop(leases);

        // Explicit shape: a fresh circuit → all of this agent's leases go.
        hub.register_agent(&id, circuit(), None, None, "127.0.0.1:1")
            .await
            .unwrap();
        assert!(
            hub.route_leases.read().await.is_empty(),
            "a fresh circuit clears the agent's stale leases"
        );
    }

    /// Control-plane principals never register as data-plane agents — on
    /// any transport (the QUIC arm historically lacked this gate).
    #[tokio::test]
    async fn register_refuses_control_principals() {
        let dir = tempfile::tempdir().unwrap();
        let hub = test_state(dir.path());
        let Err(refusal) = hub
            .register_agent(
                &identity("control", "plan-apply"),
                circuit(),
                None,
                None,
                "127.0.0.1:1",
            )
            .await
        else {
            panic!("a control principal must not register")
        };
        assert!(matches!(refusal, RegistrationRefusal::ControlPrincipal));
        assert!(hub.agents.read().await.is_empty());
        assert!(hub.credential_watermarks.face().is_empty());
    }

    /// A revoked leaf is refused before any state changes — the gate
    /// every transport shares (the QUIC handshake never carries CRLs; a
    /// plane-rebuild failure must not resurrect a revoked credential
    /// either: the channel, not the plane, is the membership source).
    #[tokio::test]
    async fn register_refuses_revoked_credentials() {
        let dir = tempfile::tempdir().unwrap();
        let mut hub = test_state(dir.path());
        // A real CRL from the fixture's own issuer store, revoking the
        // identity's serial.
        let issuer = interflow_identity::issuance::IssuerStore::open(dir.path().join("issuer"));
        let entry = interflow_identity::revocation::RevocationEntry {
            serial: "00aa01".to_string(),
            issuer: "workspace/main".to_string(),
            reason: "key-compromise".to_string(),
            revoked_at: "2026-10-21T00:00:00Z".to_string(),
            pack_digest: None,
        };
        let crl = interflow_identity::revocation::build_crl(
            &issuer.workspace_issuer("main").unwrap(),
            &[entry],
            1,
        )
        .unwrap();
        let channel = crate::hub::crl::CrlChannel {
            dir: dir.path().join("state/crls"),
            floors: std::sync::Mutex::new(std::collections::BTreeMap::new()),
            current: std::sync::Mutex::new(std::collections::BTreeMap::new()),
            revoked: std::sync::Mutex::new(std::collections::BTreeMap::new()),
            last_reload_unix: std::sync::atomic::AtomicU64::new(0),
        };
        channel.swap_current(std::collections::BTreeMap::from([(
            "workspace-main".to_string(),
            crl,
        )]));
        hub.crl_channel = Some(Arc::new(channel));

        let Err(refusal) = hub
            .register_agent(
                &identity("main", "lan-a"),
                circuit(),
                None,
                None,
                "127.0.0.1:1",
            )
            .await
        else {
            panic!("a revoked credential must not register")
        };
        assert!(matches!(
            refusal,
            RegistrationRefusal::CredentialRevoked { ref serial }
                if serial == "00aa01"
        ));
        assert!(hub.agents.read().await.is_empty());
        assert!(hub.credential_watermarks.face().is_empty());
    }

    /// The maintenance auto-lift rides EVERY registration path — the
    /// fresh row AND the replace-in-place re-registration (the QUIC arm's
    /// hand-mirrored copy only lifted the fresh-row branch; a QUIC
    /// reconnect is a rejoin all the same).
    #[tokio::test]
    async fn register_lifts_maintenance_on_every_path() {
        let dir = tempfile::tempdir().unwrap();
        let hub = test_state(dir.path());
        let id = identity("main", "lan-a");

        hub.maintenance.declare("main/lan-a");
        assert!(hub.maintenance.is_under("main/lan-a"));
        hub.register_agent(&id, circuit(), None, None, "127.0.0.1:1")
            .await
            .unwrap();
        assert!(
            !hub.maintenance.is_under("main/lan-a"),
            "the fresh-row registration lifts the declaration"
        );

        // The replace-in-place arm: declare again, re-register on a fresh
        // circuit — the lift must fire here too.
        hub.maintenance.declare("main/lan-a");
        assert!(hub.maintenance.is_under("main/lan-a"));
        hub.register_agent(&id, circuit(), None, None, "127.0.0.1:1")
            .await
            .unwrap();
        assert!(
            !hub.maintenance.is_under("main/lan-a"),
            "the replace-in-place re-registration lifts the declaration"
        );
    }
}
