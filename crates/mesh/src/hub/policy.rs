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
fn write_atomic(path: &std::path::Path, bytes: &[u8]) -> Result<()> {
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
    /// last-pulled watermark from the `policy_pulled` ledger (`seen: null`
    /// = no completed pull since this hub process started). The Apply
    /// convergence view renders from exactly this array. Additive fields —
    /// older clients ignore them.
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
        // Registry (presence, all tenants) ∪ ledger (pulled watermarks):
        // an agent that pulled but was since evicted still shows its
        // watermark (offline); an agent that never pulled shows
        // `seen: null`.
        let mut agents: Vec<(String, bool, Option<u64>)> = {
            let registry = self.state.agents.read().await;
            let mut rows: Vec<(String, bool, Option<u64>)> = Vec::with_capacity(registry.len());
            for (key, session) in registry.iter() {
                let online = session.read().await.online();
                rows.push((key.clone(), online, None));
            }
            rows.sort();
            rows
        };
        {
            let ledger = self
                .state
                .policy_pull_ledger
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            for (agent, seen) in ledger.iter() {
                if let Some(entry) = agents.iter_mut().find(|(a, _, _)| a == agent) {
                    entry.2 = Some(*seen);
                } else {
                    agents.push((agent.clone(), false, Some(*seen)));
                }
            }
            agents.sort();
        }
        let agents_json = agents
            .iter()
            .map(|(agent, online, seen)| {
                let seen = seen.map_or_else(|| "null".to_string(), |s| s.to_string());
                format!("{{\"agent\":\"{agent}\",\"online\":{online},\"seen\":{seen}}}")
            })
            .collect::<Vec<_>>()
            .join(",");
        // `serving` is omitted (not faked as 0) when nothing servable is on
        // disk — clients treat a missing key as "this hub cannot report
        // it" rather than "it reports zero".
        let body = match serve_cached(&channel) {
            Some((_, _, serving)) => {
                format!("{{\"floor\":{floor},\"serving\":{serving},\"agents\":[{agents_json}]}}")
            }
            None => format!("{{\"floor\":{floor},\"agents\":[{agents_json}]}}"),
        };
        Ok(super::service::json_response(StatusCode::OK, body))
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

/// The shared arbitration (see [`PolicyServe`]). `agent` is the puller's
/// qualified name, `peer` the peer address string for the audit trail.
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
    if seen >= generation {
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
            channel.floor.fetch_max(seen, Ordering::AcqRel);
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

/// Dials one control-plane mTLS h2 connection to a hub (shared by the
/// publish and the floor-query clients). The caller holds the returned
/// request sender; the connection driver is kept alive by a spawned task
/// for the sender's lifetime.
pub(crate) async fn control_plane_dial(
    hub_endpoint: &str,
    ca_path: &std::path::Path,
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

    let tls_config = interflow_core::tls::client::build_client_config(
        None,
        Some(&ca_path.display().to_string()),
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
        let mut send_request =
            control_plane_dial(hub_endpoint, ca_path, client_cert_path, client_key_path).await?;
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
    /// Same as [`PolicyFloorQuery::floor`].
    pub floor: u64,
    /// Same as [`PolicyFloorQuery::serving`].
    pub serving: Option<u64>,
    /// Every registered fleet member with presence and last-pulled
    /// watermark. Empty on older hubs that do not report the array.
    pub agents: Vec<PolicyAgentWatermark>,
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
        let mut send_request =
            control_plane_dial(hub_endpoint, ca_path, client_cert_path, client_key_path).await?;
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
        let mut send_request =
            control_plane_dial(hub_endpoint, ca_path, client_cert_path, client_key_path).await?;
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
                floor: 0,
                serving: None,
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
                        })
                    })
                    .collect()
            })
            .unwrap_or_default();
        Ok(HubOverview {
            floor,
            serving,
            agents,
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
