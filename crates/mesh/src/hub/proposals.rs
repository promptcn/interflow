//! The hub's stream-proposal queue — the kube-CSR-shaped self-service
//! face.
//!
//! Trust model, one sentence: **nodes can only propose; minting stays
//! with the issuer.** The hub holds the queue (a neutral store-and-
//! forward role exactly like its policy distribution — it never signs
//! anything), operators approve/reject from their issuer machines
//! (GUI Deploy face or CLI), and an approval lands as an ordinary
//! manifest edit + `plan apply` on the SAME single source of truth —
//! no bypass issuance exists.
//!
//! Door discipline:
//! - The requester is the connection's mTLS identity (tenant = workspace,
//!   agent = leaf CN), never a request-body field; it must be a
//!   registered agent.
//! - The submit funnel runs the serving policy's own pairing semantics
//!   (target exists, its egress offers `remote_addr`, listen loopback,
//!   idle bounds, no live rule of the same name) — the errors that today
//!   surface only at apply time surface at REQUEST time, in the
//!   validator's vocabulary.
//! - Queue hygiene: 72h TTL, per-requester and total pending caps,
//!   idempotent resubmit by rule fingerprint, persistence beside the
//!   policy channel (`<pack>/state/proposals.json`, atomic write).
//! - The lifecycle is four audit events (submitted / approved / rejected
//!   / expired), one each per proposal — state-transition accounting.

use crate::hub::state::{CONTROL_TENANT, HubState, PeerIdentity};
use http_body_util::BodyExt;
use hyper::{Request, Response, StatusCode};
use interflow_core::error::{InterflowError, Result};
use interflow_core::security::AuditKind;
use interflow_core::tunnel::transport::{
    ProposalReceipt, ProposalStatusWire, ProposalSubmitOutcome, StreamProposalRequest,
};
use interflow_identity::policy::RuntimePolicy;
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;

/// How long a pending (or decided — the receipt window) proposal lives.
/// Generous enough for an async operator ("approve tomorrow morning"),
/// short enough that an abandoned queue cannot accumulate; expiry is a
/// sweep, not a per-proposal timer.
pub(crate) const PROPOSAL_TTL_SECS: u64 = 72 * 3600;
/// Pending proposals per requester — one agent cannot monopolize the
/// operator's queue.
const MAX_PENDING_PER_REQUESTER: usize = 20;
/// Total pending proposals — the queue's global bound (with the TTL, the
/// two caps are the anti-pile defense in depth).
const MAX_PENDING_TOTAL: usize = 200;
/// Submit/reject body cap.
const MAX_PROPOSAL_BODY: usize = 16 * 1024;

/// One queued proposal (the persisted record).
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct StoredProposal {
    pub id: String,
    /// sha256 over (requester + rule fields) — the idempotency key: a
    /// resubmit of the same rule while its record lives returns the
    /// existing proposal instead of queueing a twin.
    pub fingerprint: String,
    /// The requesting agent's qualified id (`workspace/agent`) — from the
    /// submitter's mTLS chain.
    pub requester: String,
    pub rule: StreamProposalRequest,
    pub submitted_at_unix: u64,
    pub expires_at_unix: u64,
    pub status: StoredStatus,
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum StoredStatus {
    Pending,
    Approved { generation: u64 },
    Rejected { reason: String },
}

/// The queue itself: an in-memory table mirrored to
/// `<pack>/state/proposals.json`.
///
/// Temp+rename, the policy channel's persistence discipline. Rebuilt at
/// hub start (a corrupt file is quarantined, audited, and replaced with an
/// empty queue — see [`quarantine_corrupt_queue`]); records that aged past
/// their TTL are dropped lazily on the access paths and the heartbeat tick,
/// with one `ProposalExpired` audit event each.
pub struct ProposalStore {
    inner: std::sync::Mutex<HashMap<String, StoredProposal>>,
    path: Option<PathBuf>,
}

/// Moves a corrupt queue file aside (`<name>.corrupt-<unix_ts>`) so the
/// proposals face can restart empty without destroying the evidence.
/// Fails (returns `None`) if the move itself fails.
pub(crate) fn quarantine_corrupt_queue(path: &Path) -> Option<PathBuf> {
    let name = path.file_name()?.to_string_lossy().into_owned();
    let ts = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs());
    let aside = path.with_file_name(format!("{name}.corrupt-{ts}"));
    std::fs::rename(path, &aside).ok().map(|()| aside)
}

impl ProposalStore {
    /// Loads the persisted queue. A missing file is an empty queue (first
    /// start); a present-but-unreadable or unparsable file is an error the
    /// assembly turn quarantines — never a silent reset.
    pub(crate) fn load(path: Option<PathBuf>) -> interflow_core::error::Result<Self> {
        let map = if let Some(path) = &path
            && path.exists()
        {
            let bytes = std::fs::read(path)
                .map_err(InterflowError::Io)
                .map_err(|e| {
                    InterflowError::config("proposal queue read failed".to_string()).with_source(e)
                })?;
            let records: Vec<StoredProposal> = serde_json::from_slice(&bytes).map_err(|e| {
                InterflowError::config("proposal queue is not valid JSON".to_string())
                    .with_source(e)
            })?;
            records.into_iter().map(|p| (p.id.clone(), p)).collect()
        } else {
            HashMap::new()
        };
        Ok(Self {
            inner: std::sync::Mutex::new(map),
            path,
        })
    }

    fn persist(&self, map: &HashMap<String, StoredProposal>) {
        let Some(path) = &self.path else { return };
        let mut records: Vec<&StoredProposal> = map.values().collect();
        records.sort_by(|a, b| (&a.submitted_at_unix, &a.id).cmp(&(&b.submitted_at_unix, &b.id)));
        let json = serde_json::to_vec(&records).unwrap_or_else(|_| b"[]".to_vec());
        let tmp = path.with_extension("json.tmp");
        // Best-effort mirror: the queue is re-derivable from audit and the
        // operators' view; a failed write logs and the in-memory table
        // stays authoritative for this process.
        if let Err(e) = std::fs::write(&tmp, &json).and_then(|()| std::fs::rename(&tmp, path)) {
            tracing::warn!("proposal queue persist failed (in-memory table stays live): {e}");
        }
    }

    /// Drops expired records (auditing each) — called lazily on every
    /// access path and from the heartbeat supervisor's tick.
    pub(crate) fn sweep_expired(&self, state: &HubState, now_unix: u64) -> usize {
        let mut map = self
            .inner
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let expired: Vec<StoredProposal> = map
            .values()
            .filter(|p| p.expires_at_unix <= now_unix)
            .cloned()
            .collect();
        if expired.is_empty() {
            return 0;
        }
        for p in &expired {
            map.remove(&p.id);
            state.audit.record(
                AuditKind::ProposalExpired {
                    id: p.id.clone(),
                    requester: p.requester.clone(),
                },
                None,
                None,
            );
        }
        self.persist(&map);
        expired.len()
    }

    /// The submit door: idempotency → caps → the validator funnel →
    /// queue + persist + audit. The funnel checks the SERVING policy (the
    /// hub's own verified view of the desired state).
    pub(crate) fn submit(
        &self,
        state: &HubState,
        requester: &str,
        request: &StreamProposalRequest,
        now_unix: u64,
    ) -> ProposalSubmitOutcome {
        // Idempotency first: a live record with the same fingerprint
        // answers with itself (no new audit event — the resubmit is not
        // news, the original submission already was).
        let fingerprint = fingerprint_of(requester, request);
        {
            let map = self
                .inner
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            if let Some(existing) = map
                .values()
                .find(|p| p.fingerprint == fingerprint && p.expires_at_unix > now_unix)
            {
                return ProposalSubmitOutcome::Duplicate {
                    id: existing.id.clone(),
                    expires_at_unix: existing.expires_at_unix,
                };
            }
        }

        // The funnel: the serving policy's pairing semantics, in the
        // validator's own vocabulary.
        if let Err(reason) = Self::funnel(state, requester, request) {
            state.audit.record(
                AuditKind::ProposalSubmitDenied {
                    requester: requester.to_owned(),
                    reason: reason.clone(),
                },
                None,
                None,
            );
            return ProposalSubmitOutcome::Denied { reason };
        }

        // Caps (pending only — decided records ride out their TTL as
        // receipts).
        {
            let mut map = self
                .inner
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            let pending_total = map
                .values()
                .filter(|p| p.status == StoredStatus::Pending)
                .count();
            if pending_total >= MAX_PENDING_TOTAL {
                let reason =
                    "the proposal queue is full — wait for the operator to work through it"
                        .to_string();
                state.audit.record(
                    AuditKind::ProposalSubmitDenied {
                        requester: requester.to_owned(),
                        reason: reason.clone(),
                    },
                    None,
                    None,
                );
                return ProposalSubmitOutcome::Denied { reason };
            }
            let pending_mine = map
                .values()
                .filter(|p| p.requester == requester && p.status == StoredStatus::Pending)
                .count();
            if pending_mine >= MAX_PENDING_PER_REQUESTER {
                let reason = format!(
                    "this agent already has {pending_mine} pending proposals — wait for decisions before proposing more"
                );
                state.audit.record(
                    AuditKind::ProposalSubmitDenied {
                        requester: requester.to_owned(),
                        reason: reason.clone(),
                    },
                    None,
                    None,
                );
                return ProposalSubmitOutcome::Denied { reason };
            }

            let id = new_proposal_id();
            let record = StoredProposal {
                id: id.clone(),
                fingerprint,
                requester: requester.to_owned(),
                rule: request.clone(),
                submitted_at_unix: now_unix,
                expires_at_unix: now_unix + PROPOSAL_TTL_SECS,
                status: StoredStatus::Pending,
            };
            map.insert(id.clone(), record);
            self.persist(&map);
            state.audit.record(
                AuditKind::ProposalSubmitted {
                    id: id.clone(),
                    requester: requester.to_owned(),
                    target_agent: request.target_agent.clone(),
                    remote_addr: request.remote_addr.clone(),
                },
                Some(requester.to_owned()),
                None,
            );
            ProposalSubmitOutcome::Queued {
                id,
                expires_at_unix: now_unix + PROPOSAL_TTL_SECS,
            }
        }
    }

    /// The validator funnel: the same pairing the apply-time validator
    /// enforces, run against the serving policy so the refusal lands at
    /// request time with the validator's phrasing.
    fn funnel(
        state: &HubState,
        requester: &str,
        request: &StreamProposalRequest,
    ) -> std::result::Result<(), String> {
        let Some(policy) = serving_policy(state) else {
            return Err(
                "this hub carries no serving policy — proposals need a policy face to validate against"
                    .to_string(),
            );
        };
        let (_, requester_agent) =
            PeerIdentity::split_qualified(requester).unwrap_or(("", requester));

        if request.name.trim().is_empty() || request.name.len() > 64 {
            return Err("the stream name must be 1..=64 characters".to_string());
        }
        // Loopback listen: the same shape the engine will bind.
        let listen: std::net::SocketAddr = request.listen.parse().map_err(|_| {
            format!(
                "listen {} is not a valid <ip>:port address (e.g. 127.0.0.1:11434)",
                request.listen
            )
        })?;
        if !listen.ip().is_loopback() {
            return Err(format!(
                "listen {} must be a loopback address — the stream lands on the requester's own machine",
                request.listen
            ));
        }
        if let Some(idle) = request.idle_timeout_secs
            && !(1..=86400).contains(&idle)
        {
            return Err(format!(
                "idle_timeout_secs {idle} is out of bounds (1..=86400, or omit for the default)"
            ));
        }
        // The remote must be a dialable ip:port (the same parse the
        // apply-time validator feeds `offers()`).
        let remote: std::net::SocketAddr = request.remote_addr.parse().map_err(|_| {
            format!(
                "remote_addr {} must be <ip>:port (e.g. 127.0.0.1:11434)",
                request.remote_addr
            )
        })?;
        let protocol = match request.protocol {
            interflow_core::tunnel::transport::StreamProtoWire::Tcp => {
                interflow_identity::manifest::MeshProtocol::Tcp
            }
            interflow_core::tunnel::transport::StreamProtoWire::Udp => {
                interflow_identity::manifest::MeshProtocol::Udp
            }
        };

        // The target must exist in the policy's mesh face and OFFER the
        // remote (exact addr or containing CIDR — the validator's
        // pairing, pre-run).
        let target_egress: Vec<&interflow_identity::policy::PolicyMeshEgress> = policy
            .mesh_egress
            .iter()
            .filter(|e| e.agent == request.target_agent)
            .collect();
        if target_egress.is_empty() {
            return Err(format!(
                "target agent {} declares no mesh egress in the current policy — ask the operator to declare [[agent.{}.mesh_egress]] first",
                request.target_agent, request.target_agent
            ));
        }
        let offered = target_egress.iter().any(|e| {
            e.protocol == protocol
                && (if let Some(addr) = &e.target_addr {
                    addr == &request.remote_addr
                } else if let Some(cidr) = &e.target_cidr {
                    cidr.parse::<ipnetwork::IpNetwork>()
                        .is_ok_and(|net| net.contains(remote.ip()))
                } else {
                    false
                })
        });
        if !offered {
            let offers: Vec<String> = target_egress
                .iter()
                .map(|e| e.authorization().to_string())
                .collect();
            return Err(format!(
                "target agent {} does not offer {} — declare a matching [[agent.{}.mesh_egress]] entry (currently offered: {})",
                request.target_agent,
                request.remote_addr,
                request.target_agent,
                offers.join(", ")
            ));
        }
        // A live stream of the same name on the requester: the rule
        // already exists (an approved-and-applied proposal resubmitted
        // after its record expired lands here).
        if policy
            .mesh
            .iter()
            .any(|s| s.source_agent == requester_agent && s.name == request.name)
        {
            return Err(format!(
                "a stream named {} already exists on {} in the current policy",
                request.name, requester_agent
            ));
        }
        Ok(())
    }

    /// The requester's receipts (pending + decided, until each record's
    /// TTL lapses), newest first.
    pub(crate) fn mine(&self, requester: &str, now_unix: u64) -> Vec<ProposalReceipt> {
        let map = self
            .inner
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let mut receipts: Vec<ProposalReceipt> = map
            .values()
            .filter(|p| p.requester == requester && p.expires_at_unix > now_unix)
            .map(|p| ProposalReceipt {
                id: p.id.clone(),
                rule: p.rule.clone(),
                submitted_at_unix: p.submitted_at_unix,
                expires_at_unix: p.expires_at_unix,
                status: match &p.status {
                    StoredStatus::Pending => ProposalStatusWire::Pending,
                    StoredStatus::Approved { generation } => ProposalStatusWire::Approved {
                        generation: *generation,
                    },
                    StoredStatus::Rejected { reason } => ProposalStatusWire::Rejected {
                        reason: reason.clone(),
                    },
                },
            })
            .collect();
        receipts.sort_by(|a, b| (&b.submitted_at_unix, &a.id).cmp(&(&a.submitted_at_unix, &b.id)));
        receipts
    }

    /// The operator's queue (all live records, newest first).
    pub(crate) fn list_control(&self, now_unix: u64) -> Vec<StoredProposal> {
        let map = self
            .inner
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let mut records: Vec<StoredProposal> = map
            .values()
            .filter(|p| p.expires_at_unix > now_unix)
            .cloned()
            .collect();
        records.sort_by(|a, b| (&b.submitted_at_unix, &a.id).cmp(&(&a.submitted_at_unix, &b.id)));
        records
    }

    /// Records an operator's APPROVAL (the mint happened on the issuer
    /// machine; `generation` is what it minted). Idempotent on the same
    /// decision; a conflicting prior decision refuses.
    pub(crate) fn approve(
        &self,
        state: &HubState,
        id: &str,
        generation: u64,
    ) -> std::result::Result<(), String> {
        let mut map = self
            .inner
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let Some(record) = map.get_mut(id) else {
            return Err(format!(
                "proposal {id} does not exist (expired or already cleared)"
            ));
        };
        match &record.status {
            StoredStatus::Approved { generation: prev } if *prev == generation => return Ok(()),
            StoredStatus::Approved { generation: prev } => {
                return Err(format!(
                    "proposal {id} is already approved at generation {prev} (refusing to re-record {generation})"
                ));
            }
            StoredStatus::Rejected { reason } => {
                return Err(format!("proposal {id} is already rejected: {reason}"));
            }
            StoredStatus::Pending => {}
        }
        record.status = StoredStatus::Approved { generation };
        self.persist(&map);
        state.audit.record(
            AuditKind::ProposalApproved {
                id: id.to_owned(),
                generation,
            },
            Some(CONTROL_TENANT.to_owned()),
            None,
        );
        Ok(())
    }

    /// Records an operator's REJECTION (with the requester-visible
    /// reason). Same idempotency contract as [`Self::approve`].
    pub(crate) fn reject(
        &self,
        state: &HubState,
        id: &str,
        reason: &str,
    ) -> std::result::Result<(), String> {
        let mut map = self
            .inner
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let Some(record) = map.get_mut(id) else {
            return Err(format!(
                "proposal {id} does not exist (expired or already cleared)"
            ));
        };
        match &record.status {
            StoredStatus::Rejected { reason: prev } if prev == reason => return Ok(()),
            StoredStatus::Rejected { reason: prev } => {
                return Err(format!("proposal {id} is already rejected: {prev}"));
            }
            StoredStatus::Approved { generation } => {
                return Err(format!(
                    "proposal {id} is already approved (generation {generation}) — cannot reject"
                ));
            }
            StoredStatus::Pending => {}
        }
        let reason = reason.trim().chars().take(512).collect::<String>();
        record.status = StoredStatus::Rejected {
            reason: reason.clone(),
        };
        self.persist(&map);
        state.audit.record(
            AuditKind::ProposalRejected {
                id: id.to_owned(),
                reason,
            },
            Some(CONTROL_TENANT.to_owned()),
            None,
        );
        Ok(())
    }
}

/// The hub's verified view of the serving policy (the same cached bytes
/// the pull faces serve).
pub(crate) fn serving_policy(state: &HubState) -> Option<RuntimePolicy> {
    let channel = state.policy_channel.clone()?;
    let (bytes, signature, _) = crate::hub::policy::serve_cached(&channel)?;
    let key = interflow_identity::policy::RuntimePolicy::verifying_key_from_hex(
        &channel.verifier_key_hex,
    )
    .ok()?;
    interflow_identity::policy::RuntimePolicy::verify(&bytes, &signature, &key).ok()
}

/// sha256 over the requester + the complete rule — the idempotency key.
fn fingerprint_of(requester: &str, request: &StreamProposalRequest) -> String {
    let material = format!(
        "{}|{}|{}|{}|{}|{}|{}",
        requester,
        request.name,
        request.listen,
        match request.protocol {
            interflow_core::tunnel::transport::StreamProtoWire::Tcp => "tcp",
            interflow_core::tunnel::transport::StreamProtoWire::Udp => "udp",
        },
        request.target_agent,
        request.remote_addr,
        request
            .idle_timeout_secs
            .map_or_else(|| "-".to_string(), |s| s.to_string()),
    );
    interflow_util::sha256_hex(material.as_bytes())
}

/// A fresh proposal id (32 hex chars of randomness).
fn new_proposal_id() -> String {
    let sid = interflow_core::protocol::StreamId::random()
        .unwrap_or_else(|_| interflow_core::protocol::StreamId::from_bytes([7u8; 16]));
    hex::encode(sid.to_bytes())
}

fn now_unix() -> u64 {
    interflow_identity::expiry::now_unix()
        .max(0)
        .cast_unsigned()
}

// ---------------------------------------------------------------------------
// h2 handlers
// ---------------------------------------------------------------------------

use crate::hub::service::{HubService, json_response, text_response};
use crate::hub::state::HubResponseBody;

impl HubService {
    fn proposals(&self) -> Result<Arc<ProposalStore>> {
        self.state
            .proposals
            .clone()
            .ok_or_else(|| InterflowError::config("no proposals face".to_string()))
    }

    /// `POST /proposals` — an agent's self-service submission. The
    /// requester is the connection's identity AND must be a registered
    /// agent (proposals ride the session's control plane; a certified but
    /// unregistered identity has no standing to queue work).
    pub(crate) async fn handle_proposal_submit(
        &self,
        req: Request<hyper::body::Incoming>,
    ) -> Result<Response<HubResponseBody>> {
        let Some(identity) = self.identity().await else {
            return Ok(text_response(
                StatusCode::UNAUTHORIZED,
                "Client certificate required",
            ));
        };
        if identity.tenant.as_ref() == CONTROL_TENANT {
            return Ok(text_response(
                StatusCode::FORBIDDEN,
                "control principals do not submit stream proposals",
            ));
        }
        let store = self.proposals()?;
        let requester = crate::hub::qualified_agent_id(&identity.tenant, &identity.agent);
        {
            // Registered check (fail-closed: the registry is the roster).
            let agents = self.state.agents.read().await;
            if !agents.contains_key(&requester) {
                return Ok(json_response(
                    StatusCode::FORBIDDEN,
                    serde_json::json!({ "outcome": "denied", "reason": format!(
                        "{requester} is not a registered agent — register before proposing streams"
                    ) })
                    .to_string(),
                ));
            }
        }
        let body = req.into_body();
        let collected = http_body_util::Limited::new(body, MAX_PROPOSAL_BODY)
            .collect()
            .await
            .map_err(|e| {
                InterflowError::protocol(format!(
                    "proposal body read failed (or exceeds {MAX_PROPOSAL_BODY} bytes)"
                ))
                .with_source(e)
            })?;
        let request: StreamProposalRequest = serde_json::from_slice(&collected.to_bytes())
            .map_err(|e| {
                InterflowError::protocol("proposal body is not a stream request".to_string())
                    .with_source(e)
            })?;
        let now = now_unix();
        store.sweep_expired(&self.state, now);
        let outcome = store.submit(&self.state, &requester, &request, now);
        Ok(json_response(
            StatusCode::OK,
            serde_json::to_string(&outcome)?,
        ))
    }

    /// `GET /proposals/mine` — the requester's own receipts.
    pub(crate) async fn handle_proposals_mine(&self) -> Result<Response<HubResponseBody>> {
        let Some(identity) = self.identity().await else {
            return Ok(text_response(
                StatusCode::UNAUTHORIZED,
                "Client certificate required",
            ));
        };
        let store = self.proposals()?;
        let requester = crate::hub::qualified_agent_id(&identity.tenant, &identity.agent);
        let now = now_unix();
        store.sweep_expired(&self.state, now);
        let receipts = store.mine(&requester, now);
        Ok(json_response(
            StatusCode::OK,
            serde_json::to_string(&receipts)?,
        ))
    }

    /// `GET /proposals` — the operator's queue (control principal only).
    pub(crate) async fn handle_proposals_list(&self) -> Result<Response<HubResponseBody>> {
        let Some(identity) = self.identity().await else {
            return Ok(text_response(
                StatusCode::UNAUTHORIZED,
                "Client certificate required",
            ));
        };
        if identity.tenant.as_ref() != CONTROL_TENANT {
            return Ok(text_response(
                StatusCode::FORBIDDEN,
                "the proposal queue is a control-plane face",
            ));
        }
        let store = self.proposals()?;
        let now = now_unix();
        store.sweep_expired(&self.state, now);
        let records = store.list_control(now);
        Ok(json_response(
            StatusCode::OK,
            serde_json::to_string(&records)?,
        ))
    }

    /// `POST /proposals/{id}/approve` — records the operator's approval
    /// (body: `{"generation": N}` — what the issuer machine minted).
    pub(crate) async fn handle_proposal_approve(
        &self,
        req: Request<hyper::body::Incoming>,
        id: &str,
    ) -> Result<Response<HubResponseBody>> {
        if let Err(message) = self.require_control("approve proposals").await {
            return Ok(json_response(
                StatusCode::FORBIDDEN,
                serde_json::json!({ "error": message }).to_string(),
            ));
        }
        let store = self.proposals()?;
        let body = req.into_body();
        let collected = http_body_util::Limited::new(body, MAX_PROPOSAL_BODY)
            .collect()
            .await
            .map_err(|e| {
                InterflowError::protocol("approve body read failed".to_string()).with_source(e)
            })?;
        #[derive(serde::Deserialize)]
        struct ApproveBody {
            generation: u64,
        }
        let parsed: ApproveBody = serde_json::from_slice(&collected.to_bytes()).map_err(|e| {
            InterflowError::protocol("approve body must be {\"generation\": N}".to_string())
                .with_source(e)
        })?;
        match store.approve(&self.state, id, parsed.generation) {
            Ok(()) => Ok(json_response(StatusCode::OK, r#"{"ok":true}"#.to_string())),
            Err(reason) => Ok(json_response(
                StatusCode::CONFLICT,
                serde_json::json!({ "ok": false, "reason": reason }).to_string(),
            )),
        }
    }

    /// `POST /proposals/{id}/reject` — records the operator's rejection
    /// (body: `{"reason": "..."}`).
    pub(crate) async fn handle_proposal_reject(
        &self,
        req: Request<hyper::body::Incoming>,
        id: &str,
    ) -> Result<Response<HubResponseBody>> {
        if let Err(message) = self.require_control("reject proposals").await {
            return Ok(json_response(
                StatusCode::FORBIDDEN,
                serde_json::json!({ "error": message }).to_string(),
            ));
        }
        let store = self.proposals()?;
        let body = req.into_body();
        let collected = http_body_util::Limited::new(body, MAX_PROPOSAL_BODY)
            .collect()
            .await
            .map_err(|e| {
                InterflowError::protocol("reject body read failed".to_string()).with_source(e)
            })?;
        #[derive(serde::Deserialize)]
        struct RejectBody {
            reason: String,
        }
        let parsed: RejectBody = serde_json::from_slice(&collected.to_bytes()).map_err(|e| {
            InterflowError::protocol("reject body must be {\"reason\": \"...\"}".to_string())
                .with_source(e)
        })?;
        match store.reject(&self.state, id, &parsed.reason) {
            Ok(()) => Ok(json_response(StatusCode::OK, r#"{"ok":true}"#.to_string())),
            Err(reason) => Ok(json_response(
                StatusCode::CONFLICT,
                serde_json::json!({ "ok": false, "reason": reason }).to_string(),
            )),
        }
    }

    /// The control-principal gate shared by the decision endpoints.
    async fn require_control(&self, what: &str) -> std::result::Result<(), String> {
        let Some(identity) = self.identity().await else {
            return Err("Client certificate required".to_string());
        };
        if identity.tenant.as_ref() != CONTROL_TENANT {
            return Err(format!(
                "only a control-plane principal may {what} (realm-anchored)"
            ));
        }
        Ok(())
    }
}

/// The QUIC arms' submit (the session IS the registered agent — its
/// qualified key is the requester).
pub(crate) fn submit_via_state(
    state: &HubState,
    requester: &str,
    request: &StreamProposalRequest,
) -> ProposalSubmitOutcome {
    let Some(store) = state.proposals.clone() else {
        return ProposalSubmitOutcome::Denied {
            reason: "this hub carries no proposals face".to_string(),
        };
    };
    let now = now_unix();
    store.sweep_expired(state, now);
    store.submit(state, requester, request, now)
}

/// The QUIC arm's receipts query.
pub(crate) fn mine_via_state(state: &HubState, requester: &str) -> Vec<ProposalReceipt> {
    let Some(store) = state.proposals.clone() else {
        return Vec::new();
    };
    let now = now_unix();
    store.sweep_expired(state, now);
    store.mine(requester, now)
}

// ---------------------------------------------------------------------------
// Operator-side clients (the GUI Deploy face and the CLI drive these with
// a minted control credential — same dial and courtesy-call discipline as
// the policy publication client).
// ---------------------------------------------------------------------------

/// One queue entry as the operator's client reads it (`GET /proposals`).
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ControlProposal {
    pub id: String,
    /// The requesting agent's qualified id.
    pub requester: String,
    pub rule: StreamProposalRequest,
    pub submitted_at_unix: u64,
    pub expires_at_unix: u64,
    pub status: StoredStatus,
}

/// Lists the hub's proposal queue (pending and decided records still in
/// their TTL window).
pub async fn list_proposals(
    hub_endpoint: &str,
    ca_path: &std::path::Path,
    client_cert_path: &std::path::Path,
    client_key_path: &std::path::Path,
) -> Result<Vec<ControlProposal>> {
    let future = async {
        let mut send_request = crate::hub::policy::control_plane_dial(
            hub_endpoint,
            ca_path,
            client_cert_path,
            client_key_path,
        )
        .await?;
        let request = hyper::Request::builder()
            .method(hyper::Method::GET)
            .uri("/proposals")
            .body(
                http_body_util::Full::<bytes::Bytes>::new(bytes::Bytes::new())
                    .map_err(|never| match never {})
                    .boxed(),
            )
            .map_err(|e| {
                InterflowError::protocol("proposal list request build".to_string()).with_source(e)
            })?;
        let response = send_request.send_request(request).await?;
        let status = response.status();
        let collected = BodyExt::collect(response.into_body()).await.map_err(|e| {
            InterflowError::protocol("proposal list body".to_string()).with_source(e)
        })?;
        let text = String::from_utf8_lossy(&collected.to_bytes()).to_string();
        if status == StatusCode::NOT_FOUND {
            return Ok(Vec::new());
        }
        if status != StatusCode::OK {
            return Err(InterflowError::connection(format!(
                "proposal list rejected: {status} — {text}"
            )));
        }
        serde_json::from_str(&text).map_err(|e| {
            InterflowError::protocol("proposal list payload is malformed".to_string())
                .with_source(e)
        })
    };
    tokio::time::timeout(std::time::Duration::from_secs(10), future)
        .await
        .map_err(|_| {
            InterflowError::connection(
                "proposal list timed out (>10s) — is the mesh hub reachable?".to_string(),
            )
        })?
}

/// Records an approval (body: the generation the issuer machine minted).
/// A conflicting prior decision surfaces as the hub's readable reason.
pub async fn approve_proposal(
    hub_endpoint: &str,
    ca_path: &std::path::Path,
    client_cert_path: &std::path::Path,
    client_key_path: &std::path::Path,
    id: &str,
    generation: u64,
) -> Result<()> {
    let future = async {
        let mut send_request = crate::hub::policy::control_plane_dial(
            hub_endpoint,
            ca_path,
            client_cert_path,
            client_key_path,
        )
        .await?;
        let body = serde_json::json!({ "generation": generation }).to_string();
        let request = hyper::Request::builder()
            .method(hyper::Method::POST)
            .uri(format!("/proposals/{id}/approve"))
            .header("content-type", "application/json")
            .body(
                http_body_util::Full::new(bytes::Bytes::from(body))
                    .map_err(|never| match never {})
                    .boxed(),
            )
            .map_err(|e| {
                InterflowError::protocol("proposal approve request build".to_string())
                    .with_source(e)
            })?;
        let response = send_request.send_request(request).await?;
        let status = response.status();
        let collected = BodyExt::collect(response.into_body()).await.map_err(|e| {
            InterflowError::protocol("proposal approve body".to_string()).with_source(e)
        })?;
        let text = String::from_utf8_lossy(&collected.to_bytes()).to_string();
        if status == StatusCode::OK {
            return Ok(());
        }
        #[derive(serde::Deserialize)]
        struct Reason {
            #[serde(default)]
            reason: String,
        }
        let reason = serde_json::from_str::<Reason>(&text)
            .map(|r| r.reason)
            .unwrap_or(text);
        Err(InterflowError::connection(format!(
            "proposal approve refused: {status} — {reason}"
        )))
    };
    tokio::time::timeout(std::time::Duration::from_secs(10), future)
        .await
        .map_err(|_| {
            InterflowError::connection(
                "proposal approve timed out (>10s) — is the mesh hub reachable?".to_string(),
            )
        })?
}

/// Records a rejection (with the requester-visible reason).
pub async fn reject_proposal(
    hub_endpoint: &str,
    ca_path: &std::path::Path,
    client_cert_path: &std::path::Path,
    client_key_path: &std::path::Path,
    id: &str,
    reason: &str,
) -> Result<()> {
    let future = async {
        let mut send_request = crate::hub::policy::control_plane_dial(
            hub_endpoint,
            ca_path,
            client_cert_path,
            client_key_path,
        )
        .await?;
        let body = serde_json::json!({ "reason": reason }).to_string();
        let request = hyper::Request::builder()
            .method(hyper::Method::POST)
            .uri(format!("/proposals/{id}/reject"))
            .header("content-type", "application/json")
            .body(
                http_body_util::Full::new(bytes::Bytes::from(body))
                    .map_err(|never| match never {})
                    .boxed(),
            )
            .map_err(|e| {
                InterflowError::protocol("proposal reject request build".to_string()).with_source(e)
            })?;
        let response = send_request.send_request(request).await?;
        let status = response.status();
        let collected = BodyExt::collect(response.into_body()).await.map_err(|e| {
            InterflowError::protocol("proposal reject body".to_string()).with_source(e)
        })?;
        let text = String::from_utf8_lossy(&collected.to_bytes()).to_string();
        if status == StatusCode::OK {
            return Ok(());
        }
        #[derive(serde::Deserialize)]
        struct Reason {
            #[serde(default)]
            reason: String,
        }
        let reason = serde_json::from_str::<Reason>(&text)
            .map(|r| r.reason)
            .unwrap_or(text);
        Err(InterflowError::connection(format!(
            "proposal reject refused: {status} — {reason}"
        )))
    };
    tokio::time::timeout(std::time::Duration::from_secs(10), future)
        .await
        .map_err(|_| {
            InterflowError::connection(
                "proposal reject timed out (>10s) — is the mesh hub reachable?".to_string(),
            )
        })?
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use crate::hub::state::{HubLimits, HubState, PolicyChannel};

    fn empty_server_config() -> crate::config::ServerConfig {
        crate::config::ServerConfig {
            listen_addr: "127.0.0.1:0".parse().unwrap(),
            node_name: None,
            hub_name: None,
            proxy_protocol: interflow_core::security::ProxyProtocolConfig::default(),
        }
    }

    /// Enough of a HubConfig for the store paths (they never read it —
    /// the field just must exist). Field-by-field because HubConfig has
    /// no Default (assembly requires real values in production).
    fn empty_hub_config() -> crate::config::HubConfig {
        crate::config::HubConfig {
            server: empty_server_config(),
            auth: crate::config::AuthConfig {
                rate_limit_per_minute: 0,
                tenants: vec![],
            },
            tls: None,
            acl: crate::config::AclConfig {
                rules: std::collections::HashSet::new(),
            },
            security: crate::config::HubSecurityConfig::default(),
            heartbeat: crate::config::HeartbeatConfig::default(),
            metrics: crate::config::MetricsConfig::default(),
            policy: crate::config::PolicyAdminConfig::default(),
            audit: interflow_core::config::AuditConfig::default(),
            logging: crate::config::LoggingConfig::default(),
            transport: crate::config::HubTransportConfig::default(),
        }
    }
    use interflow_core::tunnel::transport::{StreamProposalRequest, StreamProtoWire};
    use std::sync::Arc;

    fn request(name: &str, remote: &str) -> StreamProposalRequest {
        StreamProposalRequest {
            name: name.to_owned(),
            listen: "127.0.0.1:25000".to_owned(),
            protocol: StreamProtoWire::Tcp,
            target_agent: "lan-b".to_owned(),
            remote_addr: remote.to_owned(),
            idle_timeout_secs: None,
        }
    }

    /// A minimal live HubState: disabled audit, no rate limiter, and a
    /// REAL policy channel (an issuer-signed policy on disk — the funnel
    /// validates against the verified serving bytes). The policy declares
    /// lan-b offering 127.0.0.0/8 egress.
    fn test_state(dir: &std::path::Path) -> HubState {
        let issuer = interflow_identity::issuance::IssuerStore::open(dir.join("issuer"));
        issuer.ensure_realm().unwrap();
        issuer.ensure_workspace("main").unwrap();
        issuer.ensure_policy_key().unwrap();
        let verifier_key_hex = hex::encode(issuer.policy_verifier().unwrap().as_bytes());
        let manifest = interflow_identity::manifest::Manifest::parse(
            r#"
[realm]
id = "unit"
[identity]
mode = "offline"
leaf_ttl = "7d"
[mesh.hub.h]
listen = "127.0.0.1:16666"
endpoint = "127.0.0.1:16666"
[workspace.main]
[agent.lan-a]
workspace = "main"
[[agent.lan-a.mesh_ingress]]
name = "svc"
listen = "127.0.0.1:24001"
target_agent = "lan-b"
remote_addr = "127.0.0.1:12345"
[agent.lan-b]
workspace = "main"
[[agent.lan-b.mesh_egress]]
name = "loopback"
target_cidr = "127.0.0.0/8"
"#,
        )
        .unwrap();
        let policy = interflow_identity::policy::RuntimePolicy::from_manifest(&manifest, 1);
        let (bytes, sig) = policy.signed(&issuer.policy_signer().unwrap()).unwrap();
        let policy_dir = dir.join("state/policy");
        std::fs::create_dir_all(&policy_dir).unwrap();
        std::fs::write(policy_dir.join("policy.toml"), &bytes).unwrap();
        std::fs::write(policy_dir.join("policy.sig"), &sig).unwrap();
        let channel = PolicyChannel {
            verifier_key_hex,
            dir: policy_dir.clone(),
            embedded_dir: policy_dir,
            floor: std::sync::atomic::AtomicU64::new(1),
            cached: std::sync::RwLock::new(None),
        };
        // The TLS plane: built directly from the shared test kit's
        // certificate files (the store paths never touch it — the field
        // just must exist).
        let certs = interflow_testkit::certs::TestCerts::generate("unit", "lan-a");
        let ca_pem = std::fs::read(certs.ca_path()).unwrap();
        let root =
            interflow_core::tls::TenantTrustRoot::from_pem_with_crls("main", false, &ca_pem, &[])
                .unwrap();
        let plane = interflow_core::tls::build_tls_plane(
            &certs.server_cert_path().display().to_string(),
            &certs.server_key_path().display().to_string(),
            &[root],
            interflow_core::tls::TlsMinVersion::V1_2,
        )
        .unwrap();
        let proposals_path = dir.join("state/proposals.json");
        HubState {
            agents: Arc::new(tokio::sync::RwLock::new(HashMap::new())),
            route_leases: Arc::new(tokio::sync::RwLock::new(HashMap::new())),
            config: Arc::new(tokio::sync::RwLock::new(empty_hub_config())),
            active_streams: Arc::new(tokio::sync::RwLock::new(HashMap::new())),
            tls_plane: Arc::new(std::sync::RwLock::new(Arc::new(plane))),
            crl_channel: None,
            limits: HubLimits {
                max_streams_per_agent: Arc::new(std::sync::atomic::AtomicUsize::new(0)),
                max_streams_total: Arc::new(std::sync::atomic::AtomicUsize::new(0)),
                channel_send_timeout_secs: Arc::new(std::sync::atomic::AtomicU64::new(30)),
                poll_grace_secs: Arc::new(std::sync::atomic::AtomicU64::new(30)),
            },
            rate_limiter: None,
            stream_counts: Arc::new(std::sync::Mutex::new(HashMap::new())),
            audit: interflow_core::security::AuditSink::spawn(&Default::default()),
            policy_channel: Some(Arc::new(channel)),
            policy_pull_ledger: Arc::new(std::sync::Mutex::new(HashMap::new())),
            proposals: Some(Arc::new(ProposalStore::load(Some(proposals_path)).unwrap())),
            stale_watermark_ledger: Arc::new(std::sync::Mutex::new(HashMap::new())),
            expiry_ledger: Arc::new(std::sync::Mutex::new(HashMap::new())),
            evicted_total: Arc::new(std::sync::atomic::AtomicU64::new(0)),
            conn_tracker: Arc::new(interflow_core::security::ConnTracker::new(0, 0)),
            tasks: tokio_util::task::TaskTracker::new(),
            shutdown: tokio_util::sync::CancellationToken::new(),
        }
    }

    /// Queue discipline through the public door: queued → idempotent
    /// duplicate (same id) → per-requester cap → TTL sweep clears →
    /// resubmit queues fresh.
    #[test]
    fn store_idempotency_caps_and_ttl() {
        let dir = tempfile::tempdir().unwrap();
        let state = test_state(dir.path());
        let store = state.proposals.clone().unwrap();
        let now = 1_000u64;

        let first = store.submit(
            &state,
            "main/lan-a",
            &request("extra", "127.0.0.1:20001"),
            now,
        );
        let ProposalSubmitOutcome::Queued { id, .. } = first else {
            panic!("expected queued, got {first:?}")
        };
        // Same rule again: the existing record answers (no twin).
        let dup = store.submit(
            &state,
            "main/lan-a",
            &request("extra", "127.0.0.1:20001"),
            now + 5,
        );
        match dup {
            ProposalSubmitOutcome::Duplicate { id: dup_id, .. } => assert_eq!(dup_id, id),
            other => panic!("expected duplicate, got {other:?}"),
        }
        // Distinct rules fill the requester's queue up to the cap.
        for i in 1..MAX_PENDING_PER_REQUESTER {
            let outcome = store.submit(
                &state,
                "main/lan-a",
                &request(&format!("r{i}"), &format!("127.0.0.1:{i}")),
                now + 6,
            );
            assert!(
                matches!(outcome, ProposalSubmitOutcome::Queued { .. }),
                "rule {i} should queue: {outcome:?}"
            );
        }
        let over = store.submit(
            &state,
            "main/lan-a",
            &request("overflow", "127.0.0.1:29999"),
            now + 7,
        );
        match over {
            ProposalSubmitOutcome::Denied { reason } => {
                assert!(reason.contains("pending proposals"), "{reason}");
            }
            other => panic!("expected cap denial, got {other:?}"),
        }
        // TTL lapse sweeps everything (audit records each expiry; the
        // disabled sink drops them silently — the count is the check).
        assert_eq!(
            store.sweep_expired(&state, now + PROPOSAL_TTL_SECS + 10),
            MAX_PENDING_PER_REQUESTER
        );
        assert!(store.list_control(now + PROPOSAL_TTL_SECS + 10).is_empty());
        // After expiry the same rule queues fresh (new id).
        let fresh = store.submit(
            &state,
            "main/lan-a",
            &request("extra", "127.0.0.1:20001"),
            now + PROPOSAL_TTL_SECS + 20,
        );
        match fresh {
            ProposalSubmitOutcome::Queued { id: fresh_id, .. } => assert_ne!(fresh_id, id),
            other => panic!("expected fresh queue, got {other:?}"),
        }
        // Persistence round-trip: a new store over the same file sees the record.
        let path = dir.path().join("state/proposals.json");
        let reloaded = ProposalStore::load(Some(path)).unwrap();
        assert!(
            reloaded
                .list_control(now + PROPOSAL_TTL_SECS + 30)
                .iter()
                .any(|p| p.requester == "main/lan-a" && p.rule.name == "extra")
        );
    }

    /// The funnel's pairing semantics (the apply-time validator's checks,
    /// pre-run): unoffered remote, non-loopback listen, bad idle, unknown
    /// target, live-rule name collision.
    #[test]
    fn funnel_pairs_like_the_apply_time_validator() {
        let dir = tempfile::tempdir().unwrap();
        let state = test_state(dir.path());
        let store = state.proposals.clone().unwrap();
        let now = 1_000u64;

        let denied =
            |req: StreamProposalRequest| match store.submit(&state, "main/lan-a", &req, now) {
                ProposalSubmitOutcome::Denied { reason } => reason,
                other => panic!("expected denial, got {other:?}"),
            };
        // Outside the offered CIDR.
        assert!(
            denied(request("x", "10.1.2.3:80")).contains("does not offer"),
            "unoffered remote must name the pairing"
        );
        // Non-loopback listen.
        let mut wan = request("x", "127.0.0.1:20002");
        wan.listen = "0.0.0.0:25000".to_owned();
        assert!(denied(wan).contains("loopback"));
        // Out-of-bounds idle.
        let mut idle = request("x", "127.0.0.1:20003");
        idle.idle_timeout_secs = Some(100_000);
        assert!(denied(idle).contains("out of bounds"));
        // Unknown target.
        let mut ghost = request("x", "127.0.0.1:20004");
        ghost.target_agent = "ghost".to_owned();
        assert!(denied(ghost).contains("no mesh egress"));
        // A name that is already live on the requester.
        let mut clash = request("svc", "127.0.0.1:20005");
        clash.name = "svc".to_owned();
        assert!(denied(clash).contains("already exists"));
    }

    /// Decision recording: approve is idempotent per generation and
    /// refuses conflicts; reject carries the reason; decided records ride
    /// out their TTL as receipts.
    #[test]
    fn decisions_are_idempotent_and_conflict_refusing() {
        let dir = tempfile::tempdir().unwrap();
        let state = test_state(dir.path());
        let store = state.proposals.clone().unwrap();
        let now = 1_000u64;
        let ProposalSubmitOutcome::Queued { id, .. } = store.submit(
            &state,
            "main/lan-a",
            &request("extra", "127.0.0.1:20006"),
            now,
        ) else {
            panic!("queue")
        };
        store.approve(&state, &id, 2).unwrap();
        store.approve(&state, &id, 2).unwrap(); // idempotent
        assert!(store.approve(&state, &id, 3).is_err()); // conflicting re-record
        assert!(store.reject(&state, &id, "nope").is_err()); // already approved

        let mine = store.mine("main/lan-a", now);
        assert_eq!(mine.len(), 1);
        assert_eq!(
            mine[0].status,
            interflow_core::tunnel::transport::ProposalStatusWire::Approved { generation: 2 }
        );
    }
}
