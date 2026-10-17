//! `GET /snapshot` — the fleet's steady-state picture, one versioned
//! document.
//!
//! The upgrade-acceptance discipline (deployment handbook §8) used to live
//! as a hand-run ritual: same-build-string across five surfaces, serving
//! lineage survived, evictions flat over the steady window — each one a
//! separate ssh + journal grep. This face turns that picture into a single
//! machine-readable document the operator CLI persists (`status snapshot`)
//! and diffs (`status diff`); `doctor link --upgrade-check` renders its
//! verdicts from the same bytes.
//!
//! Why a dedicated endpoint instead of accreting fields on
//! `GET /policy/floor`: the floor query's contract is watermark
//! negotiation (what `PUT /policy` arbitrates against); the snapshot's
//! contract is the fleet's *state* at capture time. Different consumers,
//! different evolution — the snapshot carries an explicit
//! [`FLEET_SNAPSHOT_SCHEMA_VERSION`] and its shape is locked by golden
//! tests, while the floor face stays untouched for the GUI.
//!
//! Identity contract: same as the floor query — a realm-anchored
//! control-plane principal. Agents are data-plane identities and never see
//! another tenant's rows; the operator sees all of them (that is the point
//! of this face).

use crate::hub::state::PolicyChannel;
use crate::hub::state::{CONTROL_TENANT, HubResponseBody, HubState};
use http::{Response, StatusCode};
use interflow_core::error::{InterflowError, Result};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::atomic::Ordering;

/// The format epoch of [`FleetSnapshotDoc`].
///
/// The SHARED compatibility epoch every Interflow-owned machine format
/// rides ([`interflow_contract::FORMAT_VERSION`]) — never a snapshot-local
/// counter (the version contract's whole point).
///
/// Additive fields (new optional keys) never bump the epoch — serde ignores
/// unknown keys on the client side, so an older CLI reading a newer hub
/// degrades gracefully. A bump means a breaking format change and moves
/// every peer together per the coordinated-upgrade runbook; the client
/// then rejects the document instead of rendering a wrong verdict.
pub const FLEET_SNAPSHOT_FORMAT_VERSION: u8 = interflow_contract::FORMAT_VERSION;

/// Which channel face the currently served policy bundle was loaded from.
///
/// The runtime truth behind the startup line `serving policy gen N (from …)`,
/// kept current (a lineage wipe mid-run flips the origin on the next serve,
/// not just at boot).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ServingSource {
    /// The node-local state channel survived (`<pack>/state/policy`) — the
    /// upgrade contract held.
    StateLineage,
    /// Serving the pack's embedded render — a fresh install, or a lineage
    /// loss (check whether `state/` was expected to survive; a gen ABOVE
    /// the old lineage is a forward move, the warning targets the
    /// low-gen-deadlock shape).
    PackSnapshot,
}

/// One agent's transport on the hub-facing control plane.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SnapshotTransport {
    /// Registered over QUIC (relay streams; skips the h2 heartbeat path —
    /// an all-QUIC fleet legitimately reports `ping=0`).
    Quic,
    /// Registered over h2 (poll long-poll body).
    H2,
}

/// The fleet snapshot document — the wire contract's single authoritative
/// definition (hub and CLI both use this type; golden tests lock the JSON
/// shape).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FleetSnapshotDoc {
    /// See [`FLEET_SNAPSHOT_FORMAT_VERSION`].
    pub format_version: u8,
    /// The hub's own steady state.
    pub hub: FleetSnapshotHub,
    /// Every fleet member (all tenants — operator face), sorted by
    /// qualified agent id: deterministic byte order, so two captures of an
    /// unchanged fleet diff clean.
    pub agents: Vec<FleetSnapshotAgent>,
}

/// The hub half of a [`FleetSnapshotDoc`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FleetSnapshotHub {
    /// The hub's configured node name, when it has one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub node: Option<String>,
    /// The generation the hub actually serves right now (`None` = nothing
    /// servable on disk — the floor handler's `serving` discipline: a
    /// missing key never reads as zero).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub serving_generation: Option<u64>,
    /// The lineage origin of the served bundle (`None` when nothing is
    /// servable). The acceptance question "did the state lineage survive
    /// the upgrade?" reads this, not the boot-time journal line.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub serving_source: Option<ServingSource>,
    /// The anti-rollback floor (includes absorbed remote watermarks).
    #[serde(default)]
    pub floor_generation: u64,
    /// Cumulative evictions that actually landed (voided removals do not
    /// count) — monotonic for the hub process's lifetime. The steady-window
    /// acceptance is "this did not move between two captures".
    pub evicted_total: u64,
    /// The CRL counters the hub's verification plane enforces (`stem →
    /// crl_number`) — the push face's floors. The acceptance question
    /// "did the emergency revocation reach this hub?" reads this, not the
    /// issuer store. Empty on older hubs and non-pack hubs (the additive
    /// tolerance doctrine: a missing key reads as unknown, never as zero).
    #[serde(default, skip_serializing_if = "std::collections::BTreeMap::is_empty")]
    pub crl_numbers: std::collections::BTreeMap<String, u64>,
    /// Hub-side capture time (unix seconds) — the instant this picture was
    /// true, independent of when the operator persisted it.
    pub captured_at_unix: i64,
}

/// One fleet member's row in a [`FleetSnapshotDoc`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FleetSnapshotAgent {
    /// Qualified agent id (`tenant/agent`).
    pub agent: String,
    /// The presence reading (`registered ≠ reachable`, same semantics as
    /// `GET /agents`).
    pub online: bool,
    /// The last policy generation this agent pulled (`None` = no completed
    /// pull since the hub process started).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub seen_generation: Option<u64>,
    /// The registering binary's self-declared build tag (`None` = an older
    /// agent that does not declare one). Upgrade acceptance: every leg the
    /// same string, zero `-dirty`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub build: Option<String>,
    /// The registration's transport (`None` = no live session row; a
    /// ledger-only remembrance of an agent that pulled and was since
    /// evicted).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub transport: Option<SnapshotTransport>,
    /// The current registration's opaque circuit, canonical 32-hex — the
    /// same form as the journal's `circuit=…` lines and the audit ledger,
    /// so a snapshot correlates with both without translation. A changed
    /// circuit across two snapshots = re-registration, not an offline
    /// blip.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub circuit: Option<String>,
}

/// What the registry walk reads per live session (extracted under the
/// session read lock; the merge itself is pure).
pub(crate) struct SessionRow {
    /// Qualified agent id.
    pub agent: String,
    /// The presence reading at capture.
    pub online: bool,
    /// The session's self-declared build tag.
    pub build: Option<String>,
    /// The session's transport.
    pub transport: SnapshotTransport,
    /// The session's circuit (32-hex).
    pub circuit: String,
}

/// Merges the registry walk with the policy-pull ledger: a registry row
/// carries its session fields; a ledger-only agent (pulled, then evicted
/// without re-registering) survives as a row with no session fields — its
/// watermark is still fleet history, and its absence from the registry is
/// itself a diffable fact. Sorted by qualified id for stable output.
pub(crate) fn merge_agent_rows(
    sessions: Vec<SessionRow>,
    ledger: &HashMap<String, u64>,
) -> Vec<FleetSnapshotAgent> {
    let mut rows: Vec<FleetSnapshotAgent> = sessions
        .into_iter()
        .map(|s| FleetSnapshotAgent {
            agent: s.agent,
            online: s.online,
            seen_generation: None,
            build: s.build,
            transport: Some(s.transport),
            circuit: Some(s.circuit),
        })
        .collect();
    for (agent, seen) in ledger {
        match rows.iter_mut().find(|r| &r.agent == agent) {
            Some(row) => row.seen_generation = Some(*seen),
            None => rows.push(FleetSnapshotAgent {
                agent: agent.clone(),
                online: false,
                seen_generation: Some(*seen),
                build: None,
                transport: None,
                circuit: None,
            }),
        }
    }
    rows.sort_by(|a, b| a.agent.cmp(&b.agent));
    rows
}

/// Maps the serve cache's loaded-from directory onto the lineage origin.
/// Pure so the classification is unit-testable without a live channel.
pub(crate) fn classify_serving_origin(
    state_dir: &std::path::Path,
    embedded_dir: &std::path::Path,
    loaded_from: &std::path::Path,
) -> ServingSource {
    if loaded_from == embedded_dir && embedded_dir != state_dir {
        ServingSource::PackSnapshot
    } else {
        ServingSource::StateLineage
    }
}

/// The serving generation plus its lineage origin, straight from the
/// channel's serve cache (warmed if no pull has populated it yet — one
/// fingerprint check, the same two stats a steady-state pull pays).
pub(crate) fn serving_generation_and_origin(
    channel: &PolicyChannel,
) -> Option<(u64, ServingSource)> {
    crate::hub::policy::serve_cached(channel)?;
    let guard = channel
        .cached
        .read()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let cached = guard.as_ref()?;
    Some((
        cached.generation,
        classify_serving_origin(&channel.dir, &channel.embedded_dir, &cached.dir),
    ))
}

/// Assembles the document from live hub state. Deterministic: same state,
/// same bytes (modulo the capture timestamp).
pub(crate) async fn assemble_fleet_snapshot(state: &HubState) -> FleetSnapshotDoc {
    let node = state.config.read().await.server.node_name.clone();
    let (floor_generation, serving) = match &state.policy_channel {
        Some(channel) => (
            channel.floor.load(Ordering::Acquire),
            serving_generation_and_origin(channel),
        ),
        None => (0, None),
    };
    let (serving_generation, serving_source) = match serving {
        Some((generation, source)) => (Some(generation), Some(source)),
        None => (None, None),
    };
    let sessions = {
        let registry = state.agents.read().await;
        let mut rows = Vec::with_capacity(registry.len());
        for (key, session) in registry.iter() {
            let st = session.read().await;
            rows.push(SessionRow {
                agent: key.clone(),
                online: st.online(),
                build: st.build.clone(),
                transport: if st.quic.is_some() {
                    SnapshotTransport::Quic
                } else {
                    SnapshotTransport::H2
                },
                circuit: st.circuit.to_hex(),
            });
        }
        rows
    };
    let ledger = state
        .policy_pull_ledger
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .clone();
    FleetSnapshotDoc {
        format_version: FLEET_SNAPSHOT_FORMAT_VERSION,
        hub: FleetSnapshotHub {
            node,
            serving_generation,
            serving_source,
            floor_generation,
            evicted_total: state.evicted_total.load(Ordering::Acquire),
            crl_numbers: state
                .crl_channel
                .as_ref()
                .map_or_else(std::collections::BTreeMap::new, |channel| channel.numbers()),
            captured_at_unix: interflow_identity::expiry::now_unix(),
        },
        agents: merge_agent_rows(sessions, &ledger),
    }
}

impl crate::hub::service::HubService {
    /// `GET /snapshot` — see the module docs. Control-principal gated
    /// (the floor query's mirror); denials are plain status answers.
    pub(crate) async fn handle_fleet_snapshot(&self) -> Result<Response<HubResponseBody>> {
        let Some(identity) = self.identity().await else {
            return Ok(super::service::text_response(
                StatusCode::UNAUTHORIZED,
                "Client certificate required",
            ));
        };
        if identity.tenant.as_ref() != CONTROL_TENANT {
            return Ok(super::service::text_response(
                StatusCode::FORBIDDEN,
                "fleet snapshot requires a control-plane principal (realm-anchored)",
            ));
        }
        let doc = assemble_fleet_snapshot(&self.state).await;
        let body = serde_json::to_string(&doc).map_err(|e| {
            InterflowError::protocol("fleet snapshot serialization failed".to_string())
                .with_source(e)
        })?;
        Ok(super::service::json_response(StatusCode::OK, body))
    }
}

// ---------------------------------------------------------------------------
// Client (operator CLI side)
// ---------------------------------------------------------------------------

/// Queries a hub's fleet snapshot (`GET /snapshot`) — the steady-state
/// document [`status snapshot`](interflow_cli) persists and diffs.
///
/// Same credential discipline as the floor query (a freshly minted
/// control credential), one-shot, 10s-bounded. A 404 is reported as an
/// explicit "this hub predates the face" error — the caller should not
/// fall back to guessing the picture from journal lines.
pub async fn query_fleet_snapshot(
    hub_endpoint: &str,
    ca_path: &std::path::Path,
    client_cert_path: &std::path::Path,
    client_key_path: &std::path::Path,
) -> Result<FleetSnapshotDoc> {
    use http_body_util::BodyExt;

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
            .uri("/snapshot")
            .body(
                http_body_util::Full::<bytes::Bytes>::new(bytes::Bytes::new())
                    .map_err(|never| match never {})
                    .boxed(),
            )
            .map_err(|e| {
                InterflowError::protocol("fleet snapshot query build".to_string()).with_source(e)
            })?;
        let response = send_request.send_request(request).await?;
        let status = response.status();
        let collected = BodyExt::collect(response.into_body()).await.map_err(|e| {
            InterflowError::protocol("fleet snapshot query body".to_string()).with_source(e)
        })?;
        let text = String::from_utf8_lossy(&collected.to_bytes()).to_string();
        if status == StatusCode::NOT_FOUND {
            return Err(InterflowError::connection(format!(
                "hub {hub_endpoint} does not carry the fleet-snapshot face — upgrade the hub \
                 before using snapshot-based tooling"
            )));
        }
        if status != StatusCode::OK {
            return Err(InterflowError::connection(format!(
                "fleet snapshot query rejected: {status} — {text}"
            )));
        }
        let doc: FleetSnapshotDoc = serde_json::from_str(&text).map_err(|e| {
            InterflowError::protocol(format!(
                "fleet snapshot 200 with an unparseable body: {e} — {text:?}"
            ))
        })?;
        if doc.format_version != FLEET_SNAPSHOT_FORMAT_VERSION {
            return Err(InterflowError::protocol(format!(
                "fleet snapshot format epoch {} is not the supported {} — this CLI and the \
                 hub come from different format epochs; align the two before trusting the diff",
                doc.format_version, FLEET_SNAPSHOT_FORMAT_VERSION
            )));
        }
        Ok(doc)
    };
    tokio::time::timeout(std::time::Duration::from_secs(10), future)
        .await
        .map_err(|_| {
            InterflowError::connection(
                "fleet snapshot query timed out (>10s) — is the mesh hub reachable?".to_string(),
            )
        })?
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    /// A registry row keeps its session fields and picks up its watermark
    /// from the ledger; a ledger-only agent survives without session
    /// fields; output is sorted by qualified id.
    #[test]
    fn merge_registry_with_ledger() {
        let sessions = vec![
            SessionRow {
                agent: "main/lan-b".to_owned(),
                online: true,
                build: Some("2026-10-12_bf11cd8".to_owned()),
                transport: SnapshotTransport::Quic,
                circuit: "b".repeat(32),
            },
            SessionRow {
                agent: "main/lan-a".to_owned(),
                online: false,
                build: None,
                transport: SnapshotTransport::H2,
                circuit: "a".repeat(32),
            },
        ];
        let mut ledger = HashMap::new();
        ledger.insert("main/lan-a".to_owned(), 15u64);
        ledger.insert("main/lan-gone".to_owned(), 14u64);
        let rows = merge_agent_rows(sessions, &ledger);

        assert_eq!(
            rows.iter().map(|r| r.agent.as_str()).collect::<Vec<_>>(),
            vec!["main/lan-a", "main/lan-b", "main/lan-gone"],
            "sorted, registry ∪ ledger"
        );
        let lan_a = &rows[0];
        assert_eq!(
            (lan_a.online, lan_a.seen_generation, lan_a.transport),
            (false, Some(15), Some(SnapshotTransport::H2))
        );
        let lan_b = &rows[1];
        assert_eq!(lan_b.seen_generation, None, "never pulled: no watermark");
        let gone = &rows[2];
        assert_eq!(
            (
                gone.online,
                gone.seen_generation,
                gone.circuit.as_deref(),
                gone.transport
            ),
            (false, Some(14), None, None),
            "ledger-only remembrance: no session fields"
        );
    }

    /// The origin classification: loaded from the embedded dir = pack
    /// snapshot; anything else (including a shared-dir config, where the
    /// two faces coincide) = state lineage.
    #[test]
    fn serving_origin_classification() {
        let state_dir = std::path::Path::new("/pack/state/policy");
        let embedded_dir = std::path::Path::new("/pack/policy");
        assert_eq!(
            classify_serving_origin(state_dir, embedded_dir, state_dir),
            ServingSource::StateLineage
        );
        assert_eq!(
            classify_serving_origin(state_dir, embedded_dir, embedded_dir),
            ServingSource::PackSnapshot
        );
        let same = std::path::Path::new("/pack/policy");
        assert_eq!(
            classify_serving_origin(same, same, same),
            ServingSource::StateLineage,
            "coincident faces cannot be a lineage loss"
        );
    }

    /// The wire shape is a contract: lock it byte-for-byte so an accidental
    /// rename or reordering surfaces here, not in a downstream verdict.
    #[test]
    fn wire_shape_is_locked() {
        let doc = FleetSnapshotDoc {
            format_version: 1,
            hub: FleetSnapshotHub {
                node: Some("promptcn".to_owned()),
                serving_generation: Some(15),
                serving_source: Some(ServingSource::StateLineage),
                floor_generation: 15,
                evicted_total: 0,
                crl_numbers: std::collections::BTreeMap::from([
                    ("control".to_owned(), 4u64),
                    ("workspace-main".to_owned(), 4u64),
                ]),
                captured_at_unix: 1_760_000_000,
            },
            agents: vec![FleetSnapshotAgent {
                agent: "main/lan-a".to_owned(),
                online: true,
                seen_generation: Some(15),
                build: Some("2026-10-12_bf11cd8".to_owned()),
                transport: Some(SnapshotTransport::Quic),
                circuit: Some("ab".repeat(16)),
            }],
        };
        let json = serde_json::to_string_pretty(&doc).unwrap();
        let golden = r#"{
  "format_version": 1,
  "hub": {
    "node": "promptcn",
    "serving_generation": 15,
    "serving_source": "state_lineage",
    "floor_generation": 15,
    "evicted_total": 0,
    "crl_numbers": {
      "control": 4,
      "workspace-main": 4
    },
    "captured_at_unix": 1760000000
  },
  "agents": [
    {
      "agent": "main/lan-a",
      "online": true,
      "seen_generation": 15,
      "build": "2026-10-12_bf11cd8",
      "transport": "quic",
      "circuit": "abababababababababababababababab"
    }
  ]
}"#;
        assert_eq!(json, golden, "the wire shape is a contract");
        // And the round trip is lossless.
        let back: FleetSnapshotDoc = serde_json::from_str(&json).unwrap();
        assert_eq!(back, doc);
    }

    /// Additive evolution: unknown keys from a newer hub are ignored, and
    /// omitted optional fields default — an older-hub document (no node,
    /// no serving face, a ledger-only row) still parses.
    #[test]
    fn parse_tolerates_newer_and_older_shapes() {
        let newer = r#"{
            "format_version": 1,
            "hub": {"floor_generation": 7, "evicted_total": 2, "captured_at_unix": 5, "some_future_field": true},
            "agents": [{"agent": "main/x", "online": false, "yet_another_future_field": []}]
        }"#;
        let doc: FleetSnapshotDoc = serde_json::from_str(newer).unwrap();
        assert_eq!(doc.hub.floor_generation, 7);
        assert_eq!(doc.hub.serving_generation, None);
        assert!(
            doc.hub.crl_numbers.is_empty(),
            "an older hub reports no CRL face"
        );
        assert_eq!(doc.agents[0].circuit, None);
    }
}
