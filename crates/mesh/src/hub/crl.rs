//! The CRL hot-distribution channel — revocation's emergency lane onto the
//! hub's verification plane.
//!
//! `PUT /crls` mirrors `PUT /policy`'s shape (control-principal gate,
//! anti-rollback floor, atomic persistence, audit + metric) for the other
//! signed document an issuer produces: CRLs. The publisher is the operator
//! CLI (`revoke`'s finisher, `plan apply`'s render tail), the material is
//! the issuer store's current CRL files. A CRL needs no extra integrity
//! story beyond the mTLS control channel — it is issuer-signed — but the
//! hub still refuses rollbacks: RFC 5280 `crl_number` is the monotonic
//! floor, exactly the counter every issuance site already mints.
//!
//! Enforcement geometry: the handshake acceptor carries CRLs only when
//! every tenant has one (rustls's unknown-status-deny would otherwise
//! break a CRL-less tenant's logins); the per-tenant derivation verifiers
//! always carry their own. The swap is the `SharedTlsPlane` write side —
//! its first writer: h2 accept/derive and the QUIC registration derive all
//! read the live plane, so a swap rejects revoked credentials on NEW
//! connections within seconds, no listener rebuild, no restart. Sessions
//! already established are swept and evicted by leaf serial.

use crate::config::HubConfig;
use crate::hub::service::HubService;
use crate::hub::state::{CONTROL_TENANT, HubResponseBody, HubState};
use http::Request;
use http::Response;
use http::StatusCode;
use http_body_util::BodyExt;
use hyper::body::Incoming;
use interflow_core::error::{InterflowError, Result};
use interflow_core::security::AuditKind;
use std::collections::BTreeMap;
use std::path::Path;
use std::sync::Arc;
use tokio::sync::RwLock;

/// Body cap: a fleet's CRL set is a few KiB of PEM; anything larger is not
/// a CRL push but an accident (or an attack on memory).
const MAX_CRL_BODY: usize = 1024 * 1024;

/// The CRL file stem a tenant's issuer material lives under — the same
/// naming the pack renderer and `revoke` write (`issuer_name` with `/`
/// flattened: `workspace/main` → `workspace-main`, the reserved control
/// tenant → `control`).
pub(crate) fn tenant_crl_stem(tenant: &str) -> String {
    if tenant == CONTROL_TENANT {
        CONTROL_TENANT.to_owned()
    } else {
        format!("workspace-{tenant}")
    }
}

/// One tenant's chosen CRL at (re)build time.
pub(crate) struct TenantCrlChoice {
    /// The issuer stem this CRL belongs to.
    pub stem: String,
    /// The chosen CRL PEM (`None` = this tenant carries no CRL material).
    pub pem: Option<String>,
    /// The chosen CRL's `crl_number` (`None` together with `pem`).
    pub number: Option<u64>,
}

/// A CRL file read + parsed: `None` on any read/parse failure.
fn read_crl_file(path: &Path) -> Option<(String, u64)> {
    let text = std::fs::read_to_string(path).ok()?;
    if text.trim().is_empty() {
        return None;
    }
    let number = interflow_identity::revocation::crl_number(&text).ok()?;
    Some((text, number))
}

/// Chooses every tenant's CRL: the LIVE push lane
/// (`<pack>/state/crls/<stem>.crl.pem`) when it exists and does not sit
/// below the static snapshot's counter, else the static source the config
/// pins (`trust/crls` offline, the same `state/crls` for registrar). A live
/// file that fails to parse falls back to the static source — fail-keep:
/// the plane keeps verifying with what it had, the reject is audible in
/// the log. Non-pack hubs (no `pack_dir`) have no live lane.
pub(crate) fn choose_tenant_crls(cfg: &HubConfig) -> Vec<TenantCrlChoice> {
    cfg.auth
        .tenants
        .iter()
        .map(|tenant| {
            let stem = tenant_crl_stem(&tenant.name);
            let live = cfg.policy.pack_dir.as_deref().and_then(|dir| {
                read_crl_file(
                    &dir.join("state")
                        .join("crls")
                        .join(format!("{stem}.crl.pem")),
                )
            });
            let statc = tenant
                .crl_path
                .as_deref()
                .and_then(|p| read_crl_file(Path::new(p)));
            let chosen = match (live, &statc) {
                (Some((pem, number)), Some((_, static_number))) if number >= *static_number => {
                    Some((pem, number))
                }
                (Some((pem, number)), None) => Some((pem, number)),
                (Some(_), Some((_, static_number))) => {
                    tracing::warn!(
                        "live CRL for {stem} sits below the static snapshot ({static_number}) \
                         — keeping the static source (anti-downgrade)"
                    );
                    statc.clone()
                }
                (None, _) => statc.clone(),
            };
            TenantCrlChoice {
                stem,
                pem: chosen.as_ref().map(|(pem, _)| pem.clone()),
                number: chosen.as_ref().map(|(_, number)| *number),
            }
        })
        .collect()
}

/// Runtime face of the CRL publication channel: where accepted pushes
/// persist and the per-issuer counter floor the endpoint arbitrates
/// rollbacks against. `None` on non-pack hubs (the endpoint then 404s).
pub struct CrlChannel {
    /// Persistence dir (`<pack>/state/crls`) — the same files the renewal
    /// scheduler's pull lane writes and the plane rebuild reads.
    pub dir: std::path::PathBuf,
    /// Highest accepted `crl_number` per issuer stem (monotonic; only
    /// advances). Seeded at assembly from the CRLs the plane would load —
    /// the live lane and the embedded snapshot both count, so a push can
    /// never sneak below the render baseline.
    pub floors: std::sync::Mutex<BTreeMap<String, u64>>,
    /// The CRL PEMs the verification plane currently enforces
    /// (`stem → pem`) — the membership source for the registration gates
    /// (an evicted revoked agent otherwise resurrects itself over a
    /// still-open h2 connection; the acceptor only gates NEW ones).
    pub current: std::sync::Mutex<BTreeMap<String, String>>,
}

impl CrlChannel {
    /// The channel's current counters (the snapshot/verification face).
    pub fn numbers(&self) -> BTreeMap<String, u64> {
        self.floors
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone()
    }

    /// Whether the CRLs currently in force revoke the given serial.
    pub fn revokes(&self, stem: &str, serial: &str) -> bool {
        let current = self
            .current
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        current.get(stem).is_some_and(|pem| {
            matches!(
                interflow_identity::revocation::crl_revokes_serial(pem, serial),
                Ok(Some(true))
            )
        })
    }
}

/// What one plane reload produced: the CRL counters now in force and the
/// live sessions evicted for holding revoked credentials.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ReloadCrlsReport {
    /// `stem → crl_number` the rebuilt plane carries.
    pub numbers: BTreeMap<String, u64>,
    /// Qualified ids evicted by the revocation sweep.
    pub evicted: Vec<String>,
}

/// Rebuilds the TLS plane from the config + the current CRL choice (live
/// lane preferred), swaps it atomically into [`HubState::tls_plane`], and
/// sweeps the registry for sessions whose leaf the new CRLs revoke.
///
/// The `SharedTlsPlane` write side's first resident: fail-keep on any
/// rebuild error (the old plane keeps verifying; the caller narrates). The
/// renewal scheduler's pull lane rides the same fn, so the push and pull
/// distribution paths converge onto one swap semantics.
pub(crate) async fn reload_tls_plane(state: &HubState) -> Result<ReloadCrlsReport> {
    let (cfg, crl_channel) = {
        let cfg = state.config.read().await.clone();
        let channel = state.crl_channel.clone();
        (cfg, channel)
    };
    let Some(channel) = crl_channel else {
        return Err(InterflowError::config(
            "this hub carries no CRL publication face (no pack directory)".to_string(),
        ));
    };
    let plane = crate::hub::server::build_runtime_tls_plane(&cfg)?;
    let choices = choose_tenant_crls(&cfg);
    let pems: BTreeMap<String, String> = choices
        .iter()
        .filter_map(|c| c.pem.clone().map(|pem| (c.stem.clone(), pem)))
        .collect();
    // The floor advances to what the plane now enforces — never regresses.
    {
        let mut floors = channel
            .floors
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        for choice in &choices {
            if let Some(number) = choice.number {
                floors
                    .entry(choice.stem.clone())
                    .and_modify(|e| *e = (*e).max(number))
                    .or_insert(number);
            }
        }
    }
    // The registration gates' membership source tracks the swap.
    {
        let mut current = channel
            .current
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        *current = pems.clone();
    }
    // THE swap: every subsequent accept/derive/registration reads the new
    // plane. Failure before this line leaves the old plane in force.
    *state
        .tls_plane
        .write()
        .unwrap_or_else(std::sync::PoisonError::into_inner) = Arc::new(plane);
    let evicted = evict_revoked_sessions(state, &pems).await;
    Ok(ReloadCrlsReport {
        numbers: channel.numbers(),
        evicted,
    })
}

/// Evicts live agent sessions whose registration leaf the given CRLs
/// revoke — the "already-connected legs" half of the emergency response.
/// Sessions without a retained leaf serial (older hub builds, unparseable
/// leaves) are left to the compensating controls: their next dial is
/// rejected at the swapped plane, and the leaf TTL bounds the residue.
async fn evict_revoked_sessions(state: &HubState, crls: &BTreeMap<String, String>) -> Vec<String> {
    let sessions: Vec<(String, Arc<RwLock<crate::hub::state::AgentSession>>)> = state
        .agents
        .read()
        .await
        .iter()
        .map(|(key, session)| (key.clone(), Arc::clone(session)))
        .collect();
    let mut evicted = Vec::new();
    for (key, session) in sessions {
        let (circuit, leaf) = {
            let s = session.read().await;
            (s.circuit, s.leaf_serial.clone())
        };
        let Some((serial, stem)) = leaf else {
            continue;
        };
        let Some(pem) = crls.get(&stem) else {
            continue;
        };
        if matches!(
            interflow_identity::revocation::crl_revokes_serial(pem, &serial),
            Ok(Some(true))
        ) {
            crate::hub::heartbeat::remove_agent_if_current(
                state,
                &key,
                crate::hub::state::SessionWitness { session, circuit },
                "credential_revoked",
            )
            .await;
            evicted.push(key);
        }
    }
    evicted
}

/// The `PUT /crls` request body: `{"crls": {"<stem>": "<PEM>"}}`. Unknown
/// keys are tolerated (the control-plane additive doctrine).
#[derive(serde::Serialize, serde::Deserialize)]
struct CrlPushBody {
    crls: BTreeMap<String, String>,
}

impl HubService {
    /// Whether THIS connection's credential is revoked by the CRLs the
    /// hub currently enforces — the registration paths' live gate. The
    /// handshake acceptor only gates NEW connections; an evicted revoked
    /// agent otherwise resurrects itself over a still-open h2 connection
    /// via implicit re-registration, exactly the resurrection the
    /// revocation sweep exists to prevent.
    pub(crate) async fn connection_credential_revoked(&self) -> Option<String> {
        let identity = self.identity().await?;
        let serial = identity.leaf_serial_hex.as_ref()?;
        let stem = tenant_crl_stem(&identity.tenant);
        self.state
            .crl_channel
            .as_ref()?
            .revokes(&stem, serial)
            .then(|| serial.clone())
    }

    /// The shared denial shape of the registration gates.
    pub(crate) fn revoked_credential_denied(&self, serial: &str) -> Response<HubResponseBody> {
        metrics::counter!("interflow_hub_auth_failures", "reason" => "credential_revoked")
            .increment(1);
        self.state.audit.record(
            AuditKind::AgentRegisterDenied {
                reason: format!("credential_revoked (serial {serial})"),
            },
            None,
            Some(self.peer_str()),
        );
        super::service::text_response(
            StatusCode::FORBIDDEN,
            "credential revoked — rotate the node and re-register",
        )
    }

    /// Publishes a CRL set. Identity contract mirrors `PUT /policy`: the
    /// connection must present a control-plane principal (realm-anchored).
    ///
    /// Per pushed stem: a number below the floor rejects the WHOLE request
    /// with the current counters (409, the publisher re-pushes per-issuer
    /// state); equal is an idempotent no-op; greater persists atomically.
    /// The plane reload runs for every accepted request — including the
    /// all-equal shape, so a retry heals a previously failed swap.
    pub(crate) async fn handle_crl_publish(
        &self,
        req: Request<Incoming>,
    ) -> Result<Response<HubResponseBody>> {
        let peer = self.peer_str();
        let Some(channel) = self.state.crl_channel.clone() else {
            return Ok(super::service::text_response(
                StatusCode::NOT_FOUND,
                "this hub carries no CRL publication face",
            ));
        };
        let Some(identity) = self.identity().await else {
            return Ok(self.crl_denied(
                "no_client_cert",
                StatusCode::UNAUTHORIZED,
                "Client certificate required",
            ));
        };
        if identity.tenant.as_ref() != CONTROL_TENANT {
            return Ok(self.crl_denied(
                "not_control_principal",
                StatusCode::FORBIDDEN,
                "CRL publication requires a control-plane principal (realm-anchored)",
            ));
        }

        let body = req.into_body();
        let collected = http_body_util::Limited::new(body, MAX_CRL_BODY)
            .collect()
            .await
            .map_err(|e| {
                InterflowError::protocol(format!(
                    "CRL body read failed (or exceeds {MAX_CRL_BODY} bytes)"
                ))
                .with_source(e)
            })?;
        let push: CrlPushBody = serde_json::from_slice(&collected.to_bytes()).map_err(|e| {
            InterflowError::protocol(
                "CRL push body is not {\"crls\": {stem: pem}} JSON".to_string(),
            )
            .with_source(e)
        })?;
        if push.crls.is_empty() {
            return Ok(self.crl_denied(
                "empty",
                StatusCode::BAD_REQUEST,
                "the CRL push carries no issuers",
            ));
        }

        // Validate + classify before touching disk: every PEM must parse
        // with a readable counter, every stem must be path-safe, nothing
        // may sit below the floor.
        let floors = channel.numbers();
        let mut to_write: Vec<(String, String, u64)> = Vec::new();
        for (stem, pem) in &push.crls {
            if stem.is_empty()
                || stem.len() > 128
                || !stem.chars().all(|c| c.is_ascii_alphanumeric() || c == '-')
            {
                return Ok(self.crl_denied(
                    "bad_stem",
                    StatusCode::BAD_REQUEST,
                    "issuer stems are [A-Za-z0-9-] (e.g. control, workspace-main)",
                ));
            }
            let number = interflow_identity::revocation::crl_number(pem).map_err(|e| {
                InterflowError::protocol(format!("CRL for {stem} does not parse")).with_source(e)
            })?;
            if let Some(current) = floors.get(stem)
                && *current > number
            {
                self.state.audit.record(
                    AuditKind::CrlPublishDenied {
                        reason: format!("rollback (floor={current}, pushed={number})"),
                    },
                    Some(identity.qualified()),
                    Some(peer),
                );
                let current_json = floors
                    .iter()
                    .map(|(k, v)| format!("\"{k}\":{v}"))
                    .collect::<Vec<_>>()
                    .join(",");
                return Ok(super::service::json_response(
                    StatusCode::CONFLICT,
                    format!("{{\"error\":\"rollback\",\"current\":{{{current_json}}}}}"),
                ));
            }
            if floors.get(stem) != Some(&number) {
                to_write.push((stem.clone(), pem.clone(), number));
            }
        }

        // Persist atomically (temp + rename per file): the plane rebuild
        // and any restart read a complete CRL, never a torn one.
        std::fs::create_dir_all(&channel.dir).map_err(|e| {
            InterflowError::config(format!("CRL state dir {}", channel.dir.display()))
                .with_source(e)
        })?;
        for (stem, pem, _) in &to_write {
            super::policy::write_atomic(
                &channel.dir.join(format!("{stem}.crl.pem")),
                pem.as_bytes(),
            )?;
        }

        // The reload (plane swap + revocation sweep) runs on every accepted
        // push — a failure keeps the old plane and answers 500; the retry
        // is idempotent (equal numbers) and heals the swap.
        match reload_tls_plane(&self.state).await {
            Ok(report) => {
                let applied: BTreeMap<String, u64> = push
                    .crls
                    .keys()
                    .filter_map(|stem| report.numbers.get(stem).map(|n| (stem.clone(), *n)))
                    .collect();
                self.state.audit.record(
                    AuditKind::CrlPublished {
                        applied: applied.clone(),
                        evicted: report.evicted.clone(),
                    },
                    Some(identity.qualified()),
                    Some(peer),
                );
                metrics::counter!("interflow_hub_crl_published_total").increment(1);
                let applied_json = applied
                    .iter()
                    .map(|(k, v)| format!("\"{k}\":{v}"))
                    .collect::<Vec<_>>()
                    .join(",");
                let evicted_json = report
                    .evicted
                    .iter()
                    .map(|a| format!("\"{a}\""))
                    .collect::<Vec<_>>()
                    .join(",");
                Ok(super::service::json_response(
                    StatusCode::OK,
                    format!("{{\"applied\":{{{applied_json}}},\"evicted\":[{evicted_json}]}}"),
                ))
            }
            Err(e) => {
                self.state.audit.record(
                    AuditKind::CrlPublishDenied {
                        reason: format!("plane reload failed: {e}"),
                    },
                    Some(identity.qualified()),
                    Some(peer),
                );
                Ok(super::service::text_response(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "CRL persisted but the verification plane did not reload — the old \
                     plane keeps verifying; retry the push (idempotent) or restart the hub",
                ))
            }
        }
    }

    /// A CRL publication denial: audited with its category, answered with
    /// the HTTP status + text.
    fn crl_denied(
        &self,
        reason: &str,
        status: StatusCode,
        body: &'static str,
    ) -> Response<HubResponseBody> {
        self.state.audit.record(
            AuditKind::CrlPublishDenied {
                reason: reason.to_owned(),
            },
            None,
            Some(self.peer_str()),
        );
        super::service::text_response(status, body)
    }
}

/// The `PUT /crls` outcome for the publisher.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PublishCrlsOutcome {
    /// Applied (or already in force — idempotent): the hub's verification
    /// plane now rejects the revoked credentials; `evicted` names the live
    /// sessions the sweep removed.
    Applied {
        /// `stem → crl_number` now in force for the pushed issuers.
        numbers: BTreeMap<String, u64>,
        /// Qualified ids of live agent sessions evicted.
        evicted: Vec<String>,
    },
    /// Rejected as a rollback; carries the hub's current counters.
    RollbackConflict {
        /// The hub's `stem → crl_number` floors.
        current: BTreeMap<String, u64>,
    },
    /// Rejected outright (malformed PEM, wrong principal class, an older
    /// hub without the face, …). Retrying the same bytes cannot succeed;
    /// the detail says why.
    Rejected { status: u16, detail: String },
}

/// Pushes a CRL set to a hub's `PUT /crls`.
///
/// The operator CLI's revocation lane (`revoke`'s finisher, `plan apply`'s
/// render tail). Same connection discipline as [`super::policy::publish_policy`]:
/// mTLS with a realm-anchored control credential, one-shot, 10s-bounded —
/// a courtesy call, never something to hang an emergency response on.
pub async fn publish_crls(
    hub_endpoint: &str,
    ca_path: &Path,
    client_cert_path: &Path,
    client_key_path: &Path,
    crls: &BTreeMap<String, String>,
) -> Result<PublishCrlsOutcome> {
    use http_body_util::Full;

    let future = async {
        let mut send_request = super::policy::control_plane_dial(
            hub_endpoint,
            ca_path,
            client_cert_path,
            client_key_path,
        )
        .await?;
        let body = serde_json::to_vec(&CrlPushBody { crls: crls.clone() }).map_err(|e| {
            InterflowError::protocol("CRL push body encode".to_string()).with_source(e)
        })?;
        let request = hyper::Request::builder()
            .method(hyper::Method::PUT)
            .uri("/crls")
            .body(
                Full::new(bytes::Bytes::from(body))
                    .map_err(|never| match never {})
                    .boxed(),
            )
            .map_err(|e| {
                InterflowError::protocol("CRL push request build".to_string()).with_source(e)
            })?;
        let response = send_request.send_request(request).await?;
        let status = response.status();
        let body = response.into_body();
        let collected = BodyExt::collect(body).await.map_err(|e| {
            InterflowError::protocol("CRL push response body".to_string()).with_source(e)
        })?;
        let text = String::from_utf8_lossy(&collected.to_bytes()).to_string();
        let json_map = |key: &str| -> BTreeMap<String, u64> {
            serde_json::from_str::<serde_json::Value>(&text)
                .ok()
                .and_then(|v| v.get(key).cloned())
                .and_then(|v| serde_json::from_value(v).ok())
                .unwrap_or_default()
        };
        match status {
            http::StatusCode::OK => Ok(PublishCrlsOutcome::Applied {
                numbers: json_map("applied"),
                evicted: serde_json::from_str::<serde_json::Value>(&text)
                    .ok()
                    .and_then(|v| v.get("evicted").cloned())
                    .and_then(|v| serde_json::from_value(v).ok())
                    .unwrap_or_default(),
            }),
            http::StatusCode::CONFLICT => Ok(PublishCrlsOutcome::RollbackConflict {
                current: json_map("current"),
            }),
            other => Ok(PublishCrlsOutcome::Rejected {
                status: other.as_u16(),
                detail: text,
            }),
        }
    };
    tokio::time::timeout(std::time::Duration::from_secs(10), future)
        .await
        .map_err(|_| {
            InterflowError::connection(
                "CRL push timed out (>10s) — is the mesh hub reachable?".to_string(),
            )
        })?
}
