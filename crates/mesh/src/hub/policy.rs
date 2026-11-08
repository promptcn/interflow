//! `PUT /policy` — the signed-policy publication endpoint.
//!
//! The operator's control plane (`plan apply`'s policy-only fast path)
//! pushes a freshly signed RuntimePolicy here. The hub is a distributor,
//! not an authority: it verifies the ed25519 signature against the trust
//! bundle's policy key (the same anchor every node verifies with) and
//! enforces the monotonic generation, then persists the bundle into
//! `<pack>/state/policy` — the exact files the reload watcher polls (the
//! hub's own ACL follows within one watch interval) and that agents receive
//! through the update channel. The hub cannot forge a policy (no signing
//! key), only refuse one (availability, the same class as断流).

use crate::hub::service::HubService;
use crate::hub::state::CONTROL_TENANT;
use crate::hub::state::HubResponseBody;
use http::Request;
use http::Response;
use http::StatusCode;
use http_body_util::BodyExt;
use hyper::body::Incoming;
use interflow_contract::generation::floor_epoch;
use interflow_core::error::{InterflowError, Result};
use interflow_core::security::AuditKind;
use interflow_identity::policy::RuntimePolicy;
use std::sync::atomic::Ordering;

/// Body cap: a realm policy is a few KiB of TOML; anything larger is not a
/// policy but an accident (or an attack on memory).
const MAX_POLICY_BODY: usize = 256 * 1024;

impl HubService {
    /// Publishes a signed policy update. Identity contract: the connection
    /// must present a control-plane principal (client certificate anchored
    /// at the realm root — `tenant == "control"`); workspace principals are
    /// rejected (a compromised agent box must not be able to widen its own
    /// authorization).
    pub(crate) async fn handle_policy_publish(
        &self,
        req: Request<Incoming>,
    ) -> Result<Response<HubResponseBody>> {
        let peer = self.peer_str();
        let Some(channel) = self.state.policy_channel.clone() else {
            return Ok(super::service::text_response(
                StatusCode::NOT_FOUND,
                "this hub carries no policy publication face",
            ));
        };
        let Some(identity) = self.identity().await else {
            return Ok(self.publish_denied(
                "no_client_cert",
                StatusCode::UNAUTHORIZED,
                "Client certificate required",
            ));
        };
        if identity.tenant.as_ref() != CONTROL_TENANT {
            return Ok(self.publish_denied(
                "not_control_principal",
                StatusCode::FORBIDDEN,
                "policy publication requires a control-plane principal (realm-anchored)",
            ));
        }

        // Body: canonical policy TOML; signature: hex ed25519 over exactly
        // those bytes, in the header.
        let signature_hex = req
            .headers()
            .get("x-policy-signature")
            .and_then(|v| v.to_str().ok())
            .unwrap_or_default()
            .to_owned();
        let body = req.into_body();
        let collected = http_body_util::Limited::new(body, MAX_POLICY_BODY)
            .collect()
            .await
            .map_err(|e| {
                InterflowError::protocol(format!(
                    "policy body read failed (or exceeds {MAX_POLICY_BODY} bytes)"
                ))
                .with_source(e)
            })?;
        let bytes = collected.to_bytes();
        let signature = hex::decode(signature_hex.trim()).map_err(|e| {
            InterflowError::protocol("x-policy-signature is not hex".to_string()).with_source(e)
        })?;

        // Verify against the trust bundle's policy key — the same anchor
        // every node verifies with. Failure categories are named in the
        // audit trail.
        let Ok(policy) =
            RuntimePolicy::verify_with_hex_key(&bytes, &signature, &channel.verifier_key_hex)
        else {
            return Ok(self.publish_denied(
                "bad_signature",
                StatusCode::BAD_REQUEST,
                "policy signature verification failed",
            ));
        };
        let floor = channel.floor.load(Ordering::Acquire);
        if let Err(e) = policy.check_not_rollback(floor) {
            self.state.audit.record(
                AuditKind::PolicyPublishDenied {
                    reason: format!("rollback (floor={floor}): {e}"),
                },
                Some(identity.qualified()),
                Some(peer),
            );
            // 409 carries the current floor so the publisher can re-sign at
            // floor+1 instead of guessing.
            let body = format!("{{\"error\":\"rollback\",\"current_generation\":{floor}}}");
            return Ok(super::service::json_response(StatusCode::CONFLICT, body));
        }

        // Persist atomically (temp + rename per file): the reload watcher
        // and any restart read a complete pair, never a torn one.
        let dir = &channel.dir;
        std::fs::create_dir_all(dir).map_err(|e| {
            InterflowError::config(format!("policy state dir {}", dir.display())).with_source(e)
        })?;
        write_atomic(&dir.join("policy.toml"), &bytes)?;
        write_atomic(&dir.join("policy.sig"), &signature)?;

        channel.floor.store(policy.generation, Ordering::Release);
        // The floor the version endpoint watches moved with the publish.
        self.state.floor_clock.bump();
        self.state.audit.record(
            AuditKind::PolicyPublished {
                generation: policy.generation,
            },
            Some(identity.qualified()),
            Some(self.peer_str()),
        );
        metrics::counter!("interflow_hub_policy_published_total").increment(1);
        Ok(super::service::json_response(
            StatusCode::OK,
            format!("{{\"generation\":{}}}", policy.generation),
        ))
    }

    /// A publication denial: audited with its category, answered with the
    /// HTTP status + text.
    fn publish_denied(
        &self,
        reason: &str,
        status: StatusCode,
        body: &'static str,
    ) -> Response<HubResponseBody> {
        self.state.audit.record(
            AuditKind::PolicyPublishDenied {
                reason: reason.to_owned(),
            },
            None,
            Some(self.peer_str()),
        );
        super::service::text_response(status, body)
    }
}

/// One file, atomically: write the temp sibling, rename over the target.
pub(crate) fn write_atomic(path: &std::path::Path, bytes: &[u8]) -> Result<()> {
    let tmp = path.with_extension("tmp");
    std::fs::write(&tmp, bytes)
        .and_then(|()| std::fs::rename(&tmp, path))
        .map_err(|e| {
            InterflowError::config(format!("policy state write {}", path.display())).with_source(e)
        })?;
    Ok(())
}

impl HubService {
    /// `GET /policy`: serves the hub's current authoritative bundle (the
    /// published update first, the pack's embedded snapshot otherwise) to
    /// a registered agent, as a conditional request — `x-policy-seen`
    /// carries the generation the caller already holds, and a hub serving
    /// at or below it answers `304 Not Modified` (empty body). The agent —
    /// never the hub — verifies the signature; this face only distributes
    /// bytes the trust chain already anchors.
    ///
    /// The arbitration itself lives in [`serve_policy_conditional`] — the
    /// single code path the h2 and QUIC faces share.
    pub(crate) async fn handle_policy_pull(
        &self,
        req: Request<Incoming>,
    ) -> Result<Response<HubResponseBody>> {
        // Data-plane identity contract: the pulling connection must be a
        // registered agent (workspace principal + bound circuit) — control
        // principals never pull.
        let identity = self.identity().await;
        let Some(identity) = identity else {
            return Ok(super::service::text_response(
                StatusCode::UNAUTHORIZED,
                "Client certificate required",
            ));
        };
        if identity.tenant.as_ref() == CONTROL_TENANT {
            return Ok(super::service::text_response(
                StatusCode::FORBIDDEN,
                "control-plane principals do not pull policy",
            ));
        }
        if self.circuit().await.is_none() {
            return Ok(super::service::text_response(
                StatusCode::UNAUTHORIZED,
                "Register before pulling policy",
            ));
        }
        // The conditional half of the request: the generation the caller
        // already holds. Absent/invalid (an older agent) means 0 — always
        // served, exactly the pre-conditional behavior.
        let seen = req
            .headers()
            .get("x-policy-seen")
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.trim().parse::<u64>().ok())
            .unwrap_or(0);
        drop(req); // request body unused (GET)
        let agent = identity.qualified();
        match serve_policy_conditional(&self.state, &agent, &self.peer_str(), seen) {
            PolicyServe::NoFace => {
                if self.state.policy_channel.is_none() {
                    Ok(super::service::text_response(
                        StatusCode::NOT_FOUND,
                        "this hub carries no policy distribution face",
                    ))
                } else {
                    Ok(super::service::text_response(
                        StatusCode::NOT_FOUND,
                        "no policy bundle is present",
                    ))
                }
            }
            PolicyServe::UpToDate { serving_generation } => {
                let response = Response::builder()
                    .status(StatusCode::NOT_MODIFIED)
                    .header("x-policy-generation", serving_generation.to_string())
                    .body(super::service::boxed_full(bytes::Bytes::new()))
                    .map_err(|e| {
                        InterflowError::protocol("policy pull response build".to_string())
                            .with_source(e)
                    })?;
                Ok(response)
            }
            PolicyServe::Update {
                body,
                signature,
                serving_generation,
            } => {
                let response = Response::builder()
                    .status(StatusCode::OK)
                    .header("x-policy-generation", serving_generation.to_string())
                    .header("x-policy-signature", hex::encode(&signature))
                    .body(super::service::boxed_full(body))
                    .map_err(|e| {
                        InterflowError::protocol("policy pull response build".to_string())
                            .with_source(e)
                    })?;
                Ok(response)
            }
        }
    }

    /// `GET /policy/floor`: the control-plane watermark query — the value
    /// `PUT /policy` arbitrates rollbacks against, so an operator minting
    /// the next generation can align with it BEFORE signing (the identity
    /// contract is the publish face's mirror: a control-plane principal is
    /// required; agents are data-plane identities and never see this).
    /// Carries `serving` (what the hub actually serves right now, from the
    /// same cached arbitration the pull faces use) beside `floor`: the two
    /// diverge exactly in the lineage-loss shape (a hub reinstalled from an
    /// older pack absorbs the fleet's watermarks into `floor` while still
    /// serving the embedded snapshot) — the no-op gate needs both to see
    /// it.
    /// Also carries `agents` — the operator overview primitive: every
    /// registered fleet member (ALL tenants; this is the control-gated
    /// operator face, so a cross-tenant listing is in-bounds here, unlike
    /// the tenant-scoped `GET /agents`) with its presence reading and its
    /// LEVEL policy face from the watermark table (`seen: null` = no
    /// completed pull since this hub process started; `last_pull_unix`
    /// carries the confirmation instant — the two fields together make
    /// "present but silent" legible). `captured_at_unix` anchors every
    /// recency judgment to this hub's clock. The Apply convergence view
    /// renders from exactly this array. Additive fields — older clients
    /// ignore them.
    /// Denials are plain status answers — the audit kind belongs to the
    /// publish face, and a wrong-principal GET leaks nothing to record.
    pub(crate) async fn handle_policy_floor(&self) -> Result<Response<HubResponseBody>> {
        let Some(channel) = self.state.policy_channel.clone() else {
            return Ok(super::service::text_response(
                StatusCode::NOT_FOUND,
                "this hub carries no policy publication face",
            ));
        };
        let Some(identity) = self.identity().await else {
            return Ok(super::service::text_response(
                StatusCode::UNAUTHORIZED,
                "Client certificate required",
            ));
        };
        if identity.tenant.as_ref() != CONTROL_TENANT {
            return Ok(super::service::text_response(
                StatusCode::FORBIDDEN,
                "policy floor query requires a control-plane principal (realm-anchored)",
            ));
        }
        let floor = channel.floor.load(Ordering::Acquire);
        // Registry (presence, all tenants) ∪ watermark table (the level
        // face): an agent that pulled but was since evicted still shows its
        // watermark (offline); an agent that never pulled shows
        // `seen: null`.
        let mut agents: Vec<(String, bool)> = {
            let registry = self.state.agents.read().await;
            let mut rows: Vec<(String, bool)> = Vec::with_capacity(registry.len());
            for (key, session) in registry.iter() {
                let online = session.read().await.online();
                rows.push((key.clone(), online));
            }
            rows.sort();
            rows
        };
        let watermarks = self.state.policy_watermarks.face();
        for agent in watermarks.keys() {
            if !agents.iter().any(|(a, _)| a == agent) {
                agents.push((agent.clone(), false));
            }
        }
        // The credential windows carry their own remembrance rows (a leg
        // that registered but never pulled still counts down).
        for agent in self.state.credential_watermarks.face().keys() {
            if !agents.iter().any(|(a, _)| a == agent) {
                agents.push((agent.clone(), false));
            }
        }
        agents.sort();
        // Planned-unavailability faces (additive, tolerant-parse on the
        // client): the agents' reported paused streams and the maintenance
        // declarations — the GUI's streams/fleet views render them yellow.
        let paused_face: std::collections::HashMap<String, Vec<String>> = {
            let intents = self.state.stream_intents.clone();
            agents
                .iter()
                .filter_map(|(agent, _)| intents.face(agent).map(|paused| (agent.clone(), paused)))
                .collect()
        };
        // The mailbox watermark face (queued ops waiting on each leg):
        // additive per-agent block, present exactly when something is
        // waiting or a drop ever happened.
        let mailbox_face: std::collections::HashMap<
            String,
            crate::hub::stream_intents::MailboxFace,
        > = {
            let intents = &self.state.stream_intents;
            let mut map = std::collections::HashMap::new();
            for (agent, _) in &agents {
                if let Some(face) = intents.mailbox_face(agent) {
                    map.insert(agent.clone(), face);
                }
            }
            map
        };
        let maintenance_face = self.state.maintenance.face();
        // The node-status face (per-stream byte activity) and the
        // admission table (per-leg in-flight counts) — additive per-agent
        // keys, present exactly when a report / a live count exists.
        let node_status_face = self.state.node_status.face();
        // The credential-expiry face's windows (last-seen per leg,
        // retained across eviction).
        let credential_face = self.state.credential_watermarks.face();
        let stream_counts = self
            .state
            .stream_counts
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone();
        // The CRL-poll liveness face (agents + the hub's own self slot):
        // additive fields, present exactly when a level was reported —
        // clients judge `crl_last_success_unix` against
        // `captured_at_unix` (same discipline as `last_pull_unix`).
        let crl_face = self.state.crl_liveness.face();
        let crl_self = self.state.crl_liveness.self_face();
        let agents_json = agents
            .iter()
            .map(|(agent, online)| {
                // `seen` keeps its always-present shape (null = no
                // completed pull this process); `last_pull_unix` is the
                // additive confirmation instant, present exactly when a
                // watermark row exists.
                let seen = watermarks
                    .get(agent)
                    .map_or_else(|| "null".to_string(), |w| w.seen_generation.to_string());
                let last_pull_json = watermarks.get(agent).map_or_else(String::new, |w| {
                    format!(",\"last_pull_unix\":{}", w.last_pull_unix)
                });
                let paused_json = paused_face.get(agent).map_or_else(String::new, |names| {
                    format!(",\"paused_streams\":{}", serde_json::to_string(names).expect("Vec<String> serializes"))
                });
                let maintenance_json = if maintenance_face.contains_key(agent) {
                    ",\"maintenance\":true".to_string()
                } else {
                    String::new()
                };
                let crl_json = crl_face.get(agent).map_or_else(String::new, |row| {
                    format!(
                        ",\"crl_last_success_unix\":{},\"crl_failures_total\":{}",
                        row.last_success_unix, row.failures_total
                    )
                });
                let pending_ops_json = mailbox_face.get(agent).map_or_else(String::new, |face| {
                    format!(
                        ",\"pending_ops\":{}",
                        serde_json::to_string(face).expect("MailboxFace serializes")
                    )
                });
                let streams_json = node_status_face
                    .get(agent)
                    .filter(|status| !status.streams.is_empty())
                    .map_or_else(String::new, |status| {
                        format!(
                            ",\"streams\":{}",
                            serde_json::to_string(&status.streams).expect("activity serializes")
                        )
                    });
                let in_flight_json = stream_counts.get(agent).map_or_else(String::new, |count| {
                    format!(
                        ",\"streams_in_flight\":{}",
                        u64::try_from(*count).unwrap_or(u64::MAX)
                    )
                });
                let connection_json = node_status_face
                    .get(agent)
                    .and_then(|status| status.connection)
                    .map_or_else(String::new, |connection| {
                        format!(
                            ",\"connection\":{}",
                            serde_json::to_string(&connection)
                                .expect("ConnectionQualityWire serializes")
                        )
                    });
                let backoff_json = crl_face.get(agent).map_or_else(String::new, |row| {
                    format!(
                        ",\"renewal_backoff_failures\":{},\"renewal_backoff_max_today\":{}",
                        row.renewal_backoff_failures, row.renewal_backoff_max_today
                    )
                });
                let credential_json = credential_face.get(agent).map_or_else(String::new, |window| {
                    format!(
                        ",\"leaf_not_before_unix\":{},\"leaf_not_after_unix\":{},\"credential_mode\":\"{}\",\"credential_last_seen_unix\":{}",
                        window.not_before_unix,
                        window.not_after_unix,
                        crate::hub::credential_watermarks::tier_from_span(
                            window.not_after_unix - window.not_before_unix
                        ),
                        window.last_seen_unix
                    )
                });
                format!(
                    "{{\"agent\":\"{agent}\",\"online\":{online},\"seen\":{seen}{last_pull_json}{paused_json}{maintenance_json}{crl_json}{pending_ops_json}{streams_json}{in_flight_json}{credential_json}{connection_json}{backoff_json}}}"
                )
            })
            .collect::<Vec<_>>()
            .join(",");
        // The hub self-reports its declared name so clients can attribute
        // presence and generations to the hub that actually answered (the
        // endpoint may be fronted or re-pointed during a migration).
        // `serde_json::to_string` supplies the escaping. Like `serving`
        // below, the key is omitted (not faked) when there is no name.
        let hub_name = self.state.config.read().await.server.hub_name.clone();
        let hub_json = hub_name.map_or_else(String::new, |name| {
            let mut field = serde_json::to_string(&name).expect("a String always serializes");
            field.push(',');
            field
        });
        // The hub's own CRL-poll liveness (self slot) and its plane-reload
        // instant: additive, omitted when this process runs no renewal
        // loop (a missing key reads as unknown, never as zero).
        let crl_self_json = crl_self.map_or_else(String::new, |row| {
            format!(
                ",\"crl_last_success_unix\":{},\"crl_failures_total\":{}",
                row.last_success_unix, row.failures_total
            )
        });
        let crl_reload_json = self
            .state
            .crl_channel
            .as_ref()
            .map(|channel| channel.last_reload_unix())
            .filter(|unix| *unix != 0)
            .map_or_else(String::new, |unix| {
                format!(",\"crl_last_reload_unix\":{unix}")
            });
        // The route-breaker open set (edge gateways): hosts + instants,
        // omitted when this hub carries no edge face.
        let route_breakers_json = {
            let guard = self
                .state
                .route_breaker_face
                .read()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            match guard.as_ref() {
                Some(face) => {
                    let mut rows: Vec<serde_json::Value> = face
                        .snapshot()
                        .into_iter()
                        .map(|row| {
                            serde_json::json!({
                                "host": row.target,
                                "opened_unix": row.opened_unix,
                                "last_probe_unix": row.last_probe_unix,
                            })
                        })
                        .collect();
                    rows.sort_by(|a, b| {
                        a.get("host")
                            .and_then(serde_json::Value::as_str)
                            .cmp(&b.get("host").and_then(serde_json::Value::as_str))
                    });
                    if rows.is_empty() {
                        String::new()
                    } else {
                        format!(
                            ",\"route_breakers_open\":{}",
                            serde_json::to_string(&rows).expect("Value serializes")
                        )
                    }
                }
                None => String::new(),
            }
        };
        // The resident-task watchdog's rows (the armed-assertion face):
        // additive, omitted when this hub reports no resident tasks (a
        // missing key reads as unknown, never as all-armed).
        let watchers_json = {
            let rows = self.state.watchdog.face_rows();
            if rows.is_empty() {
                String::new()
            } else {
                format!(
                    ",\"watchers\":{}",
                    serde_json::to_string(&rows).expect("Vec<WatcherFaceRow> serializes")
                )
            }
        };
        // The proposals queue's watermark (decisions awaiting the
        // operator): additive, omitted when nothing is pending or the hub
        // carries no proposal store.
        let proposals_json = self
            .state
            .proposals
            .as_ref()
            .and_then(|proposals| proposals.pending_face())
            .map_or_else(String::new, |face| {
                format!(
                    ",\"proposals_pending\":{}",
                    serde_json::to_string(&face).expect("ProposalsPendingFace serializes")
                )
            });
        // The session-headroom pair (global count + the admission caps):
        // additive, the denominators of the headroom judgments.
        let headroom_json = format!(
            ",\"streams_in_flight_total\":{},\"stream_limits\":{}",
            u64::try_from(stream_counts.values().sum::<usize>()).unwrap_or(u64::MAX),
            serde_json::to_string(&crate::hub::snapshot::StreamLimitsFace {
                total: self.state.limits.max_streams_total.load(Ordering::Relaxed) as u64,
                per_agent: self
                    .state
                    .limits
                    .max_streams_per_agent
                    .load(Ordering::Relaxed) as u64,
            })
            .expect("StreamLimitsFace serializes")
        );
        // `serving` is omitted (not faked as 0) when nothing servable is on
        // disk — clients treat a missing key as "this hub cannot report
        // it" rather than "it reports zero". `captured_at_unix` anchors
        // recency judgments (`last_pull_unix`) to this hub's clock — the
        // same discipline as the snapshot face's field of that name.
        let captured_at_unix = interflow_identity::expiry::now_unix();
        let body = match serve_cached(&channel) {
            Some((_, _, serving)) => format!(
                "{{\"hub\":{hub_json}\"floor\":{floor},\"serving\":{serving},\"captured_at_unix\":{captured_at_unix}{crl_self_json}{crl_reload_json}{route_breakers_json}{watchers_json}{proposals_json}{headroom_json},\"agents\":[{agents_json}]}}"
            ),
            None => format!(
                "{{\"hub\":{hub_json}\"floor\":{floor},\"captured_at_unix\":{captured_at_unix}{crl_self_json}{crl_reload_json}{route_breakers_json}{watchers_json}{proposals_json}{headroom_json},\"agents\":[{agents_json}]}}"
            ),
        };
        Ok(super::service::json_response(StatusCode::OK, body))
    }

    /// `GET /policy/floor/version[?since=N&wait_secs=S]` — the floor read
    /// model's change signal (the blocking-watch sibling of
    /// [`Self::handle_policy_floor`]).
    ///
    /// Without `since`: an immediate `{"version": N}` probe. With
    /// `since=N`: an immediate answer whenever the current version
    /// diverges from `N` (behind = changes were missed; ahead = this hub
    /// restarted and its in-memory clock reset — either way the caller
    /// owes itself a fresh read), and otherwise the request HOLDS until
    /// the version advances or `wait_secs` (clamped to 30s) elapses,
    /// then answers with the current version either way. The caller
    /// compares the answer against its `since` — equality means "nothing
    /// moved, re-issue the watch".
    ///
    /// Unlike its sibling this answers on EVERY hub (no policy-channel
    /// gate): the clock tracks the fleet face — registry presence, pull
    /// watermarks (advances and fresh↔silent recency transitions — see
    /// `hub::policy_watermarks`), the paused-stream and maintenance faces —
    /// which exists independently of the policy publication channel. The
    /// payload stays with the floor endpoint itself (2026-10-13 ruling:
    /// `/policy/floor`'s contract is watermark arbitration, no field
    /// accretion) — this face pushes the invalidation signal only, under
    /// the same control-principal gate.
    pub(crate) async fn handle_policy_floor_version(
        &self,
        req: hyper::Request<hyper::body::Incoming>,
    ) -> Result<Response<HubResponseBody>> {
        /// The hold ceiling: a held request is re-issued by the caller on
        /// answer, so a modest cap bounds server-held connections while
        /// keeping the wake latency at bump time.
        const MAX_WATCH_WAIT_SECS: u64 = 30;
        let Some(identity) = self.identity().await else {
            return Ok(super::service::text_response(
                StatusCode::UNAUTHORIZED,
                "Client certificate required",
            ));
        };
        if identity.tenant.as_ref() != CONTROL_TENANT {
            return Ok(super::service::text_response(
                StatusCode::FORBIDDEN,
                "policy floor watch requires a control-plane principal (realm-anchored)",
            ));
        }
        let mut since: Option<u64> = None;
        let mut wait_secs: Option<u64> = None;
        if let Some(query) = req.uri().query() {
            for pair in query.split('&') {
                let Some((key, value)) = pair.split_once('=') else {
                    continue;
                };
                match key {
                    "since" => since = value.parse().ok(),
                    "wait_secs" => wait_secs = value.parse().ok(),
                    _ => {}
                }
            }
        }
        let clock = &self.state.floor_clock;
        let answer_now = |version: u64| {
            super::service::json_response(StatusCode::OK, format!("{{\"version\":{version}}}"))
        };
        let current = clock.version();
        let Some(seen) = since.filter(|&value| value == current) else {
            return Ok(answer_now(current));
        };
        let mut rx = clock.subscribe();
        // Close the read→subscribe race: a bump between the version read
        // and the subscription would otherwise wait for the NEXT bump.
        if clock.version() != seen {
            return Ok(answer_now(clock.version()));
        }
        let wait = std::time::Duration::from_secs(wait_secs.unwrap_or(0).min(MAX_WATCH_WAIT_SECS));
        // A timeout is not an error — the answer is the (unchanged)
        // current version and the caller re-issues the watch.
        let _ = tokio::time::timeout(wait, rx.changed()).await;
        Ok(answer_now(clock.version()))
    }
}

/// The distribution-plane arbitration for one conditional policy pull —
/// the single code path both transport faces (h2 `GET /policy` and the
/// QUIC `PolicyPullRequest` frame arm) go through: fingerprint-cached
/// serving, the conditional answer, the `policy_pulled` state-transition
/// audit ledger, the pull/served metrics, and watermark-inversion
/// detection.
///
/// Inversion (the caller's watermark above the serving generation) is the
/// lineage-deadlock signature: every future policy minted below that
/// watermark is dead on arrival at that node. The pull itself keeps its
/// normal not-modified shape (the anti-rollback semantics are the agent's,
/// and correct); the *visibility* is the hub's to provide — one warn per
/// (agent, generation) crossing plus a per-pull metric.
pub(crate) enum PolicyServe {
    /// This hub carries no policy face (no channel) or no servable bundle
    /// on disk. The h2 face maps this to `404`; the QUIC face to the
    /// `unchanged` outcome with generation 0.
    NoFace,
    /// Nothing newer than the caller's watermark (`seen >= generation`);
    /// carries the serving generation so the caller can detect inversion
    /// on its side too.
    UpToDate { serving_generation: u64 },
    /// A bundle newer than the caller's watermark.
    Update {
        body: bytes::Bytes,
        signature: Vec<u8>,
        serving_generation: u64,
    },
}

/// The capture instant for watermark-face rows (unix seconds) — the same
/// clock the snapshot face stamps (`FleetSnapshotHub::captured_at_unix`),
/// so recency judgments across faces share one time base.
fn watermarks_now_unix() -> u64 {
    u64::try_from(interflow_identity::expiry::now_unix()).unwrap_or(0)
}

/// The shared arbitration (see [`PolicyServe`]). `agent` is the puller's
/// qualified name, `peer` the peer address string for the audit trail.
/// Every completed pull — not-modified answers included — also lands in
/// the level-triggered watermark face (`state.policy_watermarks`), the
/// material the fleet faces render from.
pub(crate) fn serve_policy_conditional(
    state: &crate::hub::state::HubState,
    agent: &str,
    peer: &str,
    seen: u64,
) -> PolicyServe {
    let Some(channel) = state.policy_channel.clone() else {
        return PolicyServe::NoFace;
    };
    // The update channel first, the embedded snapshot otherwise. The
    // serve cache keeps steady-state pulls to two stat calls (fingerprint
    // hit ⇒ the verified bytes are what is on disk; an atomic publish
    // changes the fingerprint).
    let Some((body, signature, generation)) = serve_cached(&channel) else {
        return PolicyServe::NoFace;
    };
    metrics::counter!("interflow_hub_policy_pulled_total").increment(1);
    // The puller's watermark vs. the serving generation — watermark-floor
    // semantics through the generational-handle contract (the single
    // compare-before-mutate implementation every rotation guard shares):
    // at-or-above the serving generation means up to date, below it means
    // an update is due.
    if floor_epoch(&seen, &generation).is_current() {
        if seen > generation {
            // Inverted watermark: log once per (agent, generation)
            // crossing; the counter keeps every occurrence.
            metrics::counter!("interflow_hub_policy_stale_watermark_total").increment(1);
            // The reported watermark IS an observable floor: absorb it, so
            // `GET /policy/floor` (and every publisher's rollback
            // arbitration) sees remote node watermarks the issuer machine
            // cannot — "re-publish at a generation above {seen}" becomes
            // machine-observable instead of operator-carried lore. An
            // inflated report only inflates the next minted generation
            // (a monotonic counter); it cannot wedge the channel.
            // An absorbed watermark moves the reported floor — bump only
            // when fetch_max actually raised it.
            let prev_floor = channel.floor.fetch_max(seen, Ordering::AcqRel);
            if prev_floor < seen {
                state.floor_clock.bump();
            }
            if crate::hub::state::should_report_stale_watermark(
                &state.stale_watermark_ledger,
                agent,
                generation,
            ) {
                tracing::warn!(
                    "agent {agent} reports policy watermark {seen} above the serving \
                     generation {generation} — its policy plane is frozen above this hub's \
                     lineage (re-publish at a generation above {seen} to unfreeze it)"
                );
            }
        }
        // The level face: even a not-modified pull is a CONFIRMATION — the
        // agent's watermark and its liveness land in the watermark table
        // (this is the record steady-state pulls never reached when the
        // face read the edge ledger, the "healthy but reads never" defect).
        state
            .policy_watermarks
            .record(agent, seen, watermarks_now_unix());
        return PolicyServe::UpToDate {
            serving_generation: generation,
        };
    }
    // A NEW generation reaching this agent — one `policy_pulled` audit
    // event per (agent, generation); steady-state repeats are
    // authentication activity, not ledger material.
    if crate::hub::state::should_record_policy_pull(&state.policy_pull_ledger, agent, generation) {
        state.audit.record(
            AuditKind::PolicyPulled {
                generation,
                agent: agent.to_owned(),
            },
            Some(agent.to_owned()),
            Some(peer.to_owned()),
        );
    }
    // The level face records the SERVED generation (the pull hands the
    // agent this generation; its next pull will report it back as `seen`).
    // Its advancing watermark is the face-visible change — the bump lives
    // in the watermark table, not here.
    state
        .policy_watermarks
        .record(agent, generation, watermarks_now_unix());
    metrics::counter!("interflow_hub_policy_served_total").increment(1);
    PolicyServe::Update {
        body,
        signature,
        serving_generation: generation,
    }
}

/// Serves the current verified bundle through the channel's fingerprint
/// cache: a hit requires BOTH faces' fingerprints unchanged (the published
/// dir AND the embedded snapshot — see [`CachedPolicy::fingerprint`]);
/// a miss loads + verifies (published dir first, the embedded snapshot
/// otherwise) and refreshes the cache. A publish to either face merely
/// makes the next check a miss again — the cache can never serve bytes
/// that are not the channel's current truth, including the
/// pulled-before-first-publish case where the cached entry came from the
/// embedded fallback.
pub(crate) fn serve_cached(
    channel: &crate::hub::state::PolicyChannel,
) -> Option<(bytes::Bytes, Vec<u8>, u64)> {
    let faces = |channel: &crate::hub::state::PolicyChannel| {
        (
            crate::pack::policy_channel_fingerprint(&channel.dir),
            crate::pack::policy_channel_fingerprint(&channel.embedded_dir),
        )
    };
    {
        let guard = channel
            .cached
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if let Some(cached) = guard.as_ref()
            && faces(channel) == cached.fingerprint
        {
            return Some((
                cached.body.clone(),
                cached.signature.clone(),
                cached.generation,
            ));
        }
    }
    let load = |dir: &std::path::Path| -> Option<(bytes::Bytes, Vec<u8>, u64)> {
        let bytes = std::fs::read(dir.join("policy.toml")).ok()?;
        let signature = std::fs::read(dir.join("policy.sig")).ok()?;
        let policy =
            RuntimePolicy::verify_with_hex_key(&bytes, &signature, &channel.verifier_key_hex)
                .ok()?;
        Some((bytes::Bytes::from(bytes), signature, policy.generation))
    };
    let (dir, (body, signature, generation)) = load(&channel.dir)
        .map(|loaded| (channel.dir.clone(), loaded))
        .or_else(|| {
            load(&channel.embedded_dir).map(|loaded| (channel.embedded_dir.clone(), loaded))
        })?;
    *channel
        .cached
        .write()
        .unwrap_or_else(std::sync::PoisonError::into_inner) =
        Some(crate::hub::state::CachedPolicy {
            dir,
            fingerprint: faces(channel),
            body: body.clone(),
            signature: signature.clone(),
            generation,
        });
    Some((body, signature, generation))
}

// ---------------------------------------------------------------------------
// Publisher (operator CLI side)
// ---------------------------------------------------------------------------

/// How a publication attempt landed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PublishOutcome {
    /// Accepted; the hub now serves this generation.
    Published { generation: u64 },
    /// Rejected as a rollback; carries the hub's current floor
    /// so the caller can re-sign at floor+1 and retry once.
    RollbackConflict { current_generation: u64 },
    /// Rejected outright (bad signature, wrong principal class, …) — the
    /// bundle never landed. Distinct from an unreachable hub: retrying the
    /// same bytes cannot succeed, the reason says why they were refused.
    Rejected { status: u16, detail: String },
}

/// How a control-plane dial verifies the hub's server certificate — the
/// two trust models the product actually uses, typed at the dial instead
/// of re-derived from flags at every caller.
#[derive(Debug, Clone, Copy)]
pub enum ServerTrust<'a> {
    /// Verify the hub against a realm issuer anchor (operator CLI dials:
    /// the hub is a remote peer with a real chain).
    Ca(&'a std::path::Path),
    /// Pin the control cert's SHA256 fingerprint (same-process/loopback
    /// dials: the edge self-dial trust model — no CA chain, no SAN
    /// fabrication, no IP/IPv6 resolution pitfalls).
    Pinned(&'a str),
}

/// Dials one control-plane mTLS h2 connection to a hub (shared by the
/// publish, floor-query, snapshot, and agents-list clients). The caller
/// holds the returned request sender; the connection driver is kept alive
/// by a spawned task for the sender's lifetime.
pub(crate) async fn control_plane_dial(
    hub_endpoint: &str,
    trust: ServerTrust<'_>,
    client_cert_path: &std::path::Path,
    client_key_path: &std::path::Path,
) -> Result<hyper::client::conn::http2::SendRequest<interflow_core::tunnel::H2RequestBody>> {
    use hyper_util::rt::{TokioExecutor, TokioIo};

    let url = if hub_endpoint.contains("://") {
        hub_endpoint.to_owned()
    } else {
        format!("https://{hub_endpoint}")
    };
    let uri: hyper::Uri = url.parse().map_err(|e| {
        InterflowError::config(format!("hub endpoint {hub_endpoint:?}")).with_source(e)
    })?;
    let host = uri
        .host()
        .ok_or_else(|| InterflowError::config("hub endpoint is missing a host".to_string()))?
        .to_owned();
    let port = uri.port_u16().unwrap_or(443);
    let server_name = rustls::pki_types::ServerName::try_from(host.as_str())
        .map_err(|e| InterflowError::config(format!("hub host {host:?}")).with_source(e))?
        .to_owned();

    let (pin, ca) = match trust {
        ServerTrust::Ca(path) => (None, Some(path.display().to_string())),
        ServerTrust::Pinned(hex) => (Some(hex.to_owned()), None),
    };
    let tls_config = interflow_core::tls::client::build_client_config(
        pin.as_deref(),
        ca.as_deref(),
        Some(&client_cert_path.display().to_string()),
        Some(&client_key_path.display().to_string()),
        &["h2"],
    )?;
    let connector = tokio_rustls::TlsConnector::from(std::sync::Arc::new(tls_config));
    let stream = tokio::net::TcpStream::connect((host.as_str(), port)).await?;
    let tls = connector.connect(server_name, stream).await.map_err(|e| {
        InterflowError::connection("hub control-plane TLS handshake failed".to_string())
            .with_source(e)
    })?;
    let mut builder = hyper::client::conn::http2::Builder::new(TokioExecutor::new());
    builder.timer(hyper_util::rt::TokioTimer::new());
    let (send_request, connection) = builder
        .handshake::<_, interflow_core::tunnel::H2RequestBody>(TokioIo::new(tls))
        .await?;
    tokio::spawn(async move {
        if let Err(e) = connection.await {
            tracing::debug!("hub control-plane connection ended: {e}");
        }
    });
    Ok(send_request)
}

/// Publishes a signed policy update to a hub's `PUT /policy`.
///
/// The operator CLI's policy-only fast path. The connection is mTLS: the
/// hub is verified against the realm issuer (the `ca_path` anchor), and the
/// caller presents a realm-anchored control credential (hub member
/// principal) — the only principal class the endpoint accepts. One-shot,
/// bounded (10s overall): a policy publish is a control-plane courtesy
/// call, never something to hang `plan apply` on.
pub async fn publish_policy(
    hub_endpoint: &str,
    ca_path: &std::path::Path,
    client_cert_path: &std::path::Path,
    client_key_path: &std::path::Path,
    policy_bytes: &[u8],
    signature: &[u8],
) -> Result<PublishOutcome> {
    use http_body_util::{BodyExt, Full};

    let future = async {
        let mut send_request = control_plane_dial(
            hub_endpoint,
            ServerTrust::Ca(ca_path),
            client_cert_path,
            client_key_path,
        )
        .await?;
        let body = Full::new(bytes::Bytes::copy_from_slice(policy_bytes))
            .map_err(|never| match never {})
            .boxed();
        let request = hyper::Request::builder()
            .method(hyper::Method::PUT)
            .uri("/policy")
            .header("x-policy-signature", hex::encode(signature))
            .body(body)
            .map_err(|e| {
                InterflowError::protocol("policy publish request build".to_string()).with_source(e)
            })?;
        let response = send_request.send_request(request).await?;
        let status = response.status();
        let body = response.into_body();
        let collected = BodyExt::collect(body).await.map_err(|e| {
            InterflowError::protocol("policy publish response body".to_string()).with_source(e)
        })?;
        let text = String::from_utf8_lossy(&collected.to_bytes()).to_string();
        let json_generation = |key: &str| -> Option<u64> {
            serde_json::from_str::<serde_json::Value>(&text)
                .ok()?
                .get(key)?
                .as_u64()
        };
        match status {
            http::StatusCode::OK => {
                let generation = json_generation("generation").ok_or_else(|| {
                    InterflowError::protocol(format!(
                        "policy publish 200 without a generation: {text:?}"
                    ))
                })?;
                Ok(PublishOutcome::Published { generation })
            }
            http::StatusCode::CONFLICT => Ok(PublishOutcome::RollbackConflict {
                current_generation: json_generation("current_generation").unwrap_or_default(),
            }),
            other => Ok(PublishOutcome::Rejected {
                status: other.as_u16(),
                detail: text,
            }),
        }
    };
    tokio::time::timeout(std::time::Duration::from_secs(10), future)
        .await
        .map_err(|_| {
            InterflowError::connection(
                "policy publish timed out (>10s) — is the mesh hub reachable?".to_string(),
            )
        })?
}

/// The `GET /policy/floor` answer: the anti-rollback floor plus, when the
/// hub can report it, the generation it actually serves right now.
///
/// The two diverge in the lineage-loss shape (reinstall + watermark
/// absorption) — a consumer deciding "is a re-publish needed" must compare
/// BOTH, not the floor alone (the 2026-10-07 no-op-gate blind spot).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PolicyFloorQuery {
    /// The watermark `PUT /policy` arbitrates rollbacks against (includes
    /// absorbed remote-node watermarks).
    pub floor: u64,
    /// What the hub is actually serving (`None` = this hub cannot report
    /// it: no servable bundle on disk, or an older hub without the key).
    pub serving: Option<u64>,
}

/// The operator overview face of `GET /policy/floor` — the same endpoint's
/// richer client view: watermarks PLUS the per-agent convergence array.
///
/// The no-op gate reads [`PolicyFloorQuery`] (floor/serving only, `Copy`);
/// the GUI's Apply-result/convergence card reads this.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HubOverview {
    /// The answering hub's manifest-declared name (`None` = an older hub
    /// that does not self-report, or the 404 no-policy-face fallback).
    pub hub: Option<String>,
    /// Same as [`PolicyFloorQuery::floor`].
    pub floor: u64,
    /// Same as [`PolicyFloorQuery::serving`].
    pub serving: Option<u64>,
    /// The hub-side capture instant (unix seconds) — the anchor every
    /// recency judgment of `last_pull_unix` reads against (`None` = an
    /// older hub that does not self-report it; consumers must then not
    /// judge recency rather than guess).
    pub captured_at_unix: Option<i64>,
    /// Every registered fleet member with presence and last-pulled
    /// watermark. Empty on older hubs that do not report the array.
    pub agents: Vec<PolicyAgentWatermark>,
    /// Unix seconds of THIS hub process's own last successful CRL poll
    /// (the renewal loop's liveness face, self slot; `None` = an older
    /// hub or a process without a renewal loop).
    pub crl_last_success_unix: Option<u64>,
    /// Failed CRL polls since this hub process started.
    pub crl_failures_total: Option<u64>,
    /// The currently-OPEN route breakers (edge gateways; empty on plain
    /// mesh hubs and older hubs).
    pub route_breakers_open: Vec<RouteBreakerOpen>,
    /// The resident-task watchdog's rows (the armed-assertion face; empty
    /// on older hubs — the assertion is then unjudgeable, not passed).
    pub watchers: Vec<crate::hub::watchdog::WatcherFaceRow>,
    /// The proposals queue's watermark face (`None` when nothing is
    /// pending or the hub carries no store).
    pub proposals_pending: Option<crate::hub::proposals::ProposalsPendingFace>,
    /// The hub's currently-admitted streams across all agents (`None` on
    /// older hubs).
    pub streams_in_flight_total: Option<u64>,
    /// The admission caps the headroom judgments read against (`None` on
    /// older hubs).
    pub stream_limits: Option<crate::hub::snapshot::StreamLimitsFace>,
}

/// One OPEN route breaker as the floor payload carries it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RouteBreakerOpen {
    /// The public host whose route breaker is OPEN.
    pub host: String,
    /// Unix seconds of the trip.
    pub opened_unix: u64,
    /// Unix seconds of the last admitted probe/touch.
    pub last_probe_unix: u64,
}

/// One fleet member's row in a [`HubOverview`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PolicyAgentWatermark {
    /// Qualified agent id (`tenant/agent`).
    pub agent: String,
    /// The presence reading (`registered ≠ reachable`; same semantics as
    /// `GET /agents`).
    pub online: bool,
    /// The generation this agent last pulled (`None` = no completed pull
    /// since the hub process started).
    pub seen: Option<u64>,
    /// Unix seconds of the agent's last completed pull (`None` = an older
    /// hub, or no completed pull — a `seen` without this field must not be
    /// judged for recency).
    pub last_pull_unix: Option<u64>,
    /// The stream names this agent last reported paused (planned
    /// unavailability, stream-level). `None` = never reported (or an
    /// older hub without the field).
    pub paused_streams: Option<Vec<String>>,
    /// Whether the node is declared under maintenance (planned
    /// unavailability, node-level).
    pub maintenance: bool,
    /// Unix seconds of the node's last successful CRL poll (its liveness
    /// reporter's level; `None` = never reported or an older hub).
    pub crl_last_success_unix: Option<u64>,
    /// Failed CRL polls since the node's process started.
    pub crl_failures_total: Option<u64>,
    /// The operator's queued stream ops waiting on this leg (the mailbox
    /// watermark face; `None` = nothing waiting and nothing ever
    /// dropped, or an older hub).
    pub pending_ops: Option<crate::hub::stream_intents::MailboxFace>,
    /// This agent's currently-admitted hub streams (`None` on older
    /// hubs / legs with no live count).
    pub streams_in_flight: Option<u64>,
    /// The agent's last-seen leaf validity window (the
    /// credential-expiry face); `None` on older hubs.
    pub leaf_not_before_unix: Option<i64>,
    /// See [`Self::leaf_not_before_unix`].
    pub leaf_not_after_unix: Option<i64>,
    /// The tier the span implies (`registrar` / `offline`).
    pub credential_mode: Option<String>,
    /// Unix seconds of the registration that last presented the window.
    pub credential_last_seen_unix: Option<u64>,
    /// The agent's per-stream byte-activity levels (the fossil face;
    /// empty on older agents / agents without mesh stream rules).
    pub streams: Vec<interflow_core::tunnel::transport::NodeStreamActivity>,
    /// The connection-quality window stats (`None` on older agents).
    pub connection: Option<interflow_core::tunnel::transport::ConnectionQualityWire>,
    /// The renewal backoff ladder's current stage (`None` on older hubs).
    pub renewal_backoff_failures: Option<u32>,
    /// The stage's observed maximum today.
    pub renewal_backoff_max_today: Option<u32>,
}

/// Queries a hub's policy floor (`GET /policy/floor`) — the watermark
/// `PUT /policy` arbitrates against, plus the hub's current serving
/// generation (see [`PolicyFloorQuery`]).
///
/// The same control-plane credential the publisher mints; `floor = 0` when
/// the hub carries no policy face (nothing to align with). One-shot,
/// 10s-bounded, same courtesy-call discipline as [`publish_policy`].
pub async fn query_policy_floor(
    hub_endpoint: &str,
    ca_path: &std::path::Path,
    client_cert_path: &std::path::Path,
    client_key_path: &std::path::Path,
) -> Result<PolicyFloorQuery> {
    use http_body_util::BodyExt;

    let future = async {
        let mut send_request = control_plane_dial(
            hub_endpoint,
            ServerTrust::Ca(ca_path),
            client_cert_path,
            client_key_path,
        )
        .await?;
        let request = hyper::Request::builder()
            .method(hyper::Method::GET)
            .uri("/policy/floor")
            .body(
                http_body_util::Full::<bytes::Bytes>::new(bytes::Bytes::new())
                    .map_err(|never| match never {})
                    .boxed(),
            )
            .map_err(|e| {
                InterflowError::protocol("policy floor query build".to_string()).with_source(e)
            })?;
        let response = send_request.send_request(request).await?;
        let status = response.status();
        let collected = BodyExt::collect(response.into_body()).await.map_err(|e| {
            InterflowError::protocol("policy floor query body".to_string()).with_source(e)
        })?;
        let text = String::from_utf8_lossy(&collected.to_bytes()).to_string();
        if status == http::StatusCode::NOT_FOUND {
            return Ok(PolicyFloorQuery {
                floor: 0,
                serving: None,
            });
        }
        if status != http::StatusCode::OK {
            return Err(InterflowError::connection(format!(
                "policy floor query rejected: {status} — {text}"
            )));
        }
        let value = serde_json::from_str::<serde_json::Value>(&text)
            .ok()
            .ok_or_else(|| {
                InterflowError::protocol(format!(
                    "policy floor query 200 without a floor: {text:?}"
                ))
            })?;
        let floor = value
            .get("floor")
            .and_then(serde_json::Value::as_u64)
            .ok_or_else(|| {
                InterflowError::protocol(format!(
                    "policy floor query 200 without a floor: {text:?}"
                ))
            })?;
        let serving = value.get("serving").and_then(serde_json::Value::as_u64);
        Ok(PolicyFloorQuery { floor, serving })
    };
    tokio::time::timeout(std::time::Duration::from_secs(10), future)
        .await
        .map_err(|_| {
            InterflowError::connection(
                "policy floor query timed out (>10s) — is the mesh hub reachable?".to_string(),
            )
        })?
}

/// One blocking-watch cycle of `GET /policy/floor/version` — the floor
/// read model's change signal.
///
/// Sends `since` (the version the caller's read model was built at) and
/// `wait_secs`; the hub answers immediately on divergence and otherwise
/// holds the request until the version advances or the wait elapses.
/// Returns the hub's CURRENT version either way: the caller decides
/// "changed" by comparison (`answer == since` means nothing moved —
/// re-issue the watch; any other answer, ahead or behind, is a change).
/// The overall budget is `wait_secs + 10s` (dial + hold + answer), NOT
/// the 10s courtesy bound of the one-shot operator calls — a watch that
/// outlived its own timeout would be useless.
pub async fn watch_floor_version(
    hub_endpoint: &str,
    ca_path: &std::path::Path,
    client_cert_path: &std::path::Path,
    client_key_path: &std::path::Path,
    since: u64,
    wait_secs: u64,
) -> Result<u64> {
    use http_body_util::BodyExt;

    let future = async {
        let mut send_request = control_plane_dial(
            hub_endpoint,
            ServerTrust::Ca(ca_path),
            client_cert_path,
            client_key_path,
        )
        .await?;
        let uri = format!("/policy/floor/version?since={since}&wait_secs={wait_secs}");
        let request = hyper::Request::builder()
            .method(hyper::Method::GET)
            .uri(uri)
            .body(
                http_body_util::Full::<bytes::Bytes>::new(bytes::Bytes::new())
                    .map_err(|never| match never {})
                    .boxed(),
            )
            .map_err(|e| {
                InterflowError::protocol("floor version watch build".to_string()).with_source(e)
            })?;
        let response = send_request.send_request(request).await?;
        let status = response.status();
        let collected = BodyExt::collect(response.into_body()).await.map_err(|e| {
            InterflowError::protocol("floor version watch body".to_string()).with_source(e)
        })?;
        let text = String::from_utf8_lossy(&collected.to_bytes()).to_string();
        if status != http::StatusCode::OK {
            return Err(InterflowError::connection(format!(
                "floor version watch rejected: {status} — {text}"
            )));
        }
        serde_json::from_str::<serde_json::Value>(&text)
            .ok()
            .and_then(|value| value.get("version").and_then(serde_json::Value::as_u64))
            .ok_or_else(|| {
                InterflowError::protocol(format!(
                    "floor version watch 200 without a version: {text:?}"
                ))
            })
    };
    let budget = std::time::Duration::from_secs(wait_secs + 10);
    tokio::time::timeout(budget, future).await.map_err(|_| {
        InterflowError::connection(format!(
            "floor version watch timed out (>{wait_secs}s hold + dial) — is the mesh hub reachable?"
        ))
    })?
}

/// Queries the operator overview — the same `GET /policy/floor` endpoint's
/// full client view ([`HubOverview`]).
///
/// Watermarks plus the per-agent convergence array. Same credential
/// discipline, one-shot, 10s-bounded.
pub async fn query_hub_overview(
    hub_endpoint: &str,
    ca_path: &std::path::Path,
    client_cert_path: &std::path::Path,
    client_key_path: &std::path::Path,
) -> Result<HubOverview> {
    use http_body_util::BodyExt;

    let future = async {
        let mut send_request = control_plane_dial(
            hub_endpoint,
            ServerTrust::Ca(ca_path),
            client_cert_path,
            client_key_path,
        )
        .await?;
        let request = hyper::Request::builder()
            .method(hyper::Method::GET)
            .uri("/policy/floor")
            .body(
                http_body_util::Full::<bytes::Bytes>::new(bytes::Bytes::new())
                    .map_err(|never| match never {})
                    .boxed(),
            )
            .map_err(|e| {
                InterflowError::protocol("hub overview query build".to_string()).with_source(e)
            })?;
        let response = send_request.send_request(request).await?;
        let status = response.status();
        let collected = BodyExt::collect(response.into_body()).await.map_err(|e| {
            InterflowError::protocol("hub overview query body".to_string()).with_source(e)
        })?;
        let text = String::from_utf8_lossy(&collected.to_bytes()).to_string();
        if status == http::StatusCode::NOT_FOUND {
            return Ok(HubOverview {
                hub: None,
                floor: 0,
                serving: None,
                captured_at_unix: None,
                crl_last_success_unix: None,
                crl_failures_total: None,
                route_breakers_open: Vec::new(),
                watchers: Vec::new(),
                proposals_pending: None,
                streams_in_flight_total: None,
                stream_limits: None,
                agents: Vec::new(),
            });
        }
        if status != http::StatusCode::OK {
            return Err(InterflowError::connection(format!(
                "hub overview query rejected: {status} — {text}"
            )));
        }
        let value = serde_json::from_str::<serde_json::Value>(&text)
            .ok()
            .ok_or_else(|| {
                InterflowError::protocol(format!("hub overview 200 without a floor: {text:?}"))
            })?;
        let floor = value
            .get("floor")
            .and_then(serde_json::Value::as_u64)
            .ok_or_else(|| {
                InterflowError::protocol(format!("hub overview 200 without a floor: {text:?}"))
            })?;
        let serving = value.get("serving").and_then(serde_json::Value::as_u64);
        // Tolerant parse: `hub` is additive (an older hub self-reports no
        // name — attribution then falls to the caller's honest fallbacks).
        let hub = value
            .get("hub")
            .and_then(serde_json::Value::as_str)
            .map(str::to_owned);
        // Tolerant parse: `captured_at_unix` is additive (an older hub
        // self-reports no capture instant — recency is then unjudgeable,
        // not zero).
        let captured_at_unix = value
            .get("captured_at_unix")
            .and_then(serde_json::Value::as_i64);
        // Tolerant parse: `agents` is additive (an older hub reports no
        // array — the convergence view then shows watermarks only).
        let agents = value
            .get("agents")
            .and_then(serde_json::Value::as_array)
            .map(|rows| {
                rows.iter()
                    .filter_map(|row| {
                        Some(PolicyAgentWatermark {
                            agent: row.get("agent")?.as_str()?.to_owned(),
                            online: row.get("online")?.as_bool()?,
                            seen: row.get("seen").and_then(serde_json::Value::as_u64),
                            last_pull_unix: row
                                .get("last_pull_unix")
                                .and_then(serde_json::Value::as_u64),
                            paused_streams: row.get("paused_streams").and_then(|v| {
                                v.as_array().map(|names| {
                                    names
                                        .iter()
                                        .filter_map(|n| n.as_str().map(str::to_owned))
                                        .collect()
                                })
                            }),
                            maintenance: row
                                .get("maintenance")
                                .and_then(serde_json::Value::as_bool)
                                .unwrap_or(false),
                            crl_last_success_unix: row
                                .get("crl_last_success_unix")
                                .and_then(serde_json::Value::as_u64),
                            crl_failures_total: row
                                .get("crl_failures_total")
                                .and_then(serde_json::Value::as_u64),
                            pending_ops: row
                                .get("pending_ops")
                                .and_then(|v| serde_json::from_value(v.clone()).ok()),
                            streams_in_flight: row
                                .get("streams_in_flight")
                                .and_then(serde_json::Value::as_u64),
                            streams: row
                                .get("streams")
                                .cloned()
                                .and_then(|v| serde_json::from_value(v).ok())
                                .unwrap_or_default(),
                            leaf_not_before_unix: row
                                .get("leaf_not_before_unix")
                                .and_then(serde_json::Value::as_i64),
                            leaf_not_after_unix: row
                                .get("leaf_not_after_unix")
                                .and_then(serde_json::Value::as_i64),
                            credential_mode: row
                                .get("credential_mode")
                                .and_then(serde_json::Value::as_str)
                                .map(str::to_owned),
                            credential_last_seen_unix: row
                                .get("credential_last_seen_unix")
                                .and_then(serde_json::Value::as_u64),
                            connection: row
                                .get("connection")
                                .cloned()
                                .and_then(|v| serde_json::from_value(v).ok()),
                            renewal_backoff_failures: row
                                .get("renewal_backoff_failures")
                                .and_then(serde_json::Value::as_u64)
                                .and_then(|v| u32::try_from(v).ok()),
                            renewal_backoff_max_today: row
                                .get("renewal_backoff_max_today")
                                .and_then(serde_json::Value::as_u64)
                                .and_then(|v| u32::try_from(v).ok()),
                        })
                    })
                    .collect()
            })
            .unwrap_or_default();
        let crl_last_success_unix = value
            .get("crl_last_success_unix")
            .and_then(serde_json::Value::as_u64);
        let crl_failures_total = value
            .get("crl_failures_total")
            .and_then(serde_json::Value::as_u64);
        // Tolerant parse: `route_breakers_open` is additive (edge
        // gateways only; older hubs report nothing).
        let route_breakers_open = value
            .get("route_breakers_open")
            .and_then(serde_json::Value::as_array)
            .map(|rows| {
                rows.iter()
                    .filter_map(|row| {
                        Some(RouteBreakerOpen {
                            host: row.get("host")?.as_str()?.to_owned(),
                            opened_unix: row
                                .get("opened_unix")
                                .and_then(serde_json::Value::as_u64)?,
                            last_probe_unix: row
                                .get("last_probe_unix")
                                .and_then(serde_json::Value::as_u64)?,
                        })
                    })
                    .collect()
            })
            .unwrap_or_default();
        // Tolerant parse: `watchers` is additive (an older hub reports no
        // watchdog face — the assertion is then unjudgeable, not passed).
        // Tolerant parse: `proposals_pending` is additive (an older hub
        // reports no proposals face).
        let proposals_pending = value
            .get("proposals_pending")
            .and_then(|v| serde_json::from_value(v.clone()).ok());
        // Tolerant parse: the headroom pair is additive (an older hub
        // reports neither).
        let streams_in_flight_total = value
            .get("streams_in_flight_total")
            .and_then(serde_json::Value::as_u64);
        let stream_limits = value
            .get("stream_limits")
            .and_then(|v| serde_json::from_value(v.clone()).ok());
        let watchers = value
            .get("watchers")
            .and_then(serde_json::Value::as_array)
            .map(|rows| {
                rows.iter()
                    .filter_map(|row| {
                        Some(crate::hub::watchdog::WatcherFaceRow {
                            name: row.get("name")?.as_str()?.to_owned(),
                            interval_secs: row
                                .get("interval_secs")
                                .and_then(serde_json::Value::as_u64)?,
                            started_unix: row
                                .get("started_unix")
                                .and_then(serde_json::Value::as_u64)?,
                            last_tick_unix: row
                                .get("last_tick_unix")
                                .and_then(serde_json::Value::as_u64)?,
                        })
                    })
                    .collect()
            })
            .unwrap_or_default();
        Ok(HubOverview {
            hub,
            floor,
            serving,
            captured_at_unix,
            agents,
            crl_last_success_unix,
            crl_failures_total,
            route_breakers_open,
            watchers,
            proposals_pending,
            streams_in_flight_total,
            stream_limits,
        })
    };
    tokio::time::timeout(std::time::Duration::from_secs(10), future)
        .await
        .map_err(|_| {
            InterflowError::connection(
                "hub overview query timed out (>10s) — is the mesh hub reachable?".to_string(),
            )
        })?
}
