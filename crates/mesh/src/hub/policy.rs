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
    /// Auditing: `policy_pulled` is a state-transition event (a NEW
    /// generation reaching an agent), never a heartbeat — steady-state
    /// 304s and same-generation re-serves do not enter the ledger (see
    /// [`crate::hub::state::SharedPolicyPullLedger`]). The
    /// `interflow_hub_policy_pulled_total` counter still ticks per request
    /// (observability keeps full granularity); `served_total` counts the
    /// 200 bodies actually delivered.
    pub(crate) async fn handle_policy_pull(
        &self,
        req: Request<Incoming>,
    ) -> Result<Response<HubResponseBody>> {
        let Some(channel) = self.state.policy_channel.clone() else {
            return Ok(super::service::text_response(
                StatusCode::NOT_FOUND,
                "this hub carries no policy distribution face",
            ));
        };
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
        // The update channel first, the embedded snapshot otherwise. The
        // serve cache keeps steady-state pulls to two stat calls (fingerprint
        // hit ⇒ the verified bytes are what is on disk; an atomic publish
        // changes the fingerprint).
        let Some((body, signature, generation)) = serve_cached(&channel) else {
            return Ok(super::service::text_response(
                StatusCode::NOT_FOUND,
                "no policy bundle is present",
            ));
        };
        metrics::counter!("interflow_hub_policy_pulled_total").increment(1);
        drop(req); // request body unused (GET)
        if seen >= generation {
            let response = Response::builder()
                .status(StatusCode::NOT_MODIFIED)
                .header("x-policy-generation", generation.to_string())
                .body(super::service::boxed_full(bytes::Bytes::new()))
                .map_err(|e| {
                    InterflowError::protocol("policy pull response build".to_string())
                        .with_source(e)
                })?;
            return Ok(response);
        }
        let agent = identity.qualified();
        if crate::hub::state::should_record_policy_pull(
            &self.state.policy_pull_ledger,
            &agent,
            generation,
        ) {
            self.state.audit.record(
                AuditKind::PolicyPulled {
                    generation,
                    agent: agent.clone(),
                },
                Some(agent),
                Some(self.peer_str()),
            );
        }
        metrics::counter!("interflow_hub_policy_served_total").increment(1);
        let response = Response::builder()
            .status(StatusCode::OK)
            .header("x-policy-generation", generation.to_string())
            .header("x-policy-signature", hex::encode(&signature))
            .body(super::service::boxed_full(body))
            .map_err(|e| {
                InterflowError::protocol("policy pull response build".to_string()).with_source(e)
            })?;
        Ok(response)
    }
}

/// Serves the current verified bundle through the channel's fingerprint
/// cache: a hit returns the cached bytes without touching the disk beyond
/// two `stat`s; a miss loads + verifies (published dir first, the
/// embedded snapshot otherwise) and refreshes the cache. A concurrent
/// publish merely makes the next fingerprint check a miss again — the
/// cache can never serve bytes that are not on disk.
fn serve_cached(
    channel: &crate::hub::state::PolicyChannel,
) -> Option<(bytes::Bytes, Vec<u8>, u64)> {
    let fingerprint_hit = |cached: &crate::hub::state::CachedPolicy| {
        crate::pack::policy_channel_fingerprint(&cached.dir) == cached.fingerprint
    };
    {
        let guard = channel
            .cached
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if let Some(cached) = guard.as_ref()
            && fingerprint_hit(cached)
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
    let fingerprint = crate::pack::policy_channel_fingerprint(&dir);
    *channel
        .cached
        .write()
        .unwrap_or_else(std::sync::PoisonError::into_inner) =
        Some(crate::hub::state::CachedPolicy {
            dir,
            fingerprint,
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
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PublishOutcome {
    /// Accepted; the hub now serves this generation.
    Published { generation: u64 },
    /// Rejected as a rollback; the response carries the hub's current floor
    /// so the caller can re-sign at floor+1 and retry once.
    RollbackConflict { current_generation: u64 },
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
    use hyper_util::rt::{TokioExecutor, TokioIo, TokioTimer};

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

    let future = async {
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
            InterflowError::connection("policy publish TLS handshake failed".to_string())
                .with_source(e)
        })?;
        let mut builder = hyper::client::conn::http2::Builder::new(TokioExecutor::new());
        builder.timer(TokioTimer::new());
        let (mut send_request, connection) = builder
            .handshake::<_, interflow_core::tunnel::H2RequestBody>(TokioIo::new(tls))
            .await?;
        tokio::spawn(async move {
            if let Err(e) = connection.await {
                tracing::debug!("policy publish connection ended: {e}");
            }
        });
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
            other => Err(InterflowError::connection(format!(
                "policy publish rejected: {other} — {text}"
            ))),
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
