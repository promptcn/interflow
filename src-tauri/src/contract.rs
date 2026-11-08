//! GUI boundary contract: the single source of truth for the IPC schema.
//!
//! These DTOs mirror the domain types (`node::NodeKind` / `NodeState` /
//! `PackInfo`, mesh `TransportKind`) so the domain modules stay free of IPC
//! concerns; the mappings are compiler-checked via `From` impls. TS types and
//! typed invoke/event wrappers are generated from this module into
//! `src/bindings.ts` (tauri-specta) — the frontend must never hand-write a
//! copy again. The 2026-09-18 incident (GUI still sending `auth_token` after
//! the mTLS-only migration, Start/Save both failing serde) was exactly this
//! class of drift.
//!
//! v2 (2026-09-22, the unified node manager): the single-tunnel commands
//! (`start_tunnel`/`stop_tunnel`/`get_state`, bare `TunnelState` events) are
//! replaced by node-addressed commands and `{ id, state }` events; the
//! profile commands are gone (add/remove/prefs commands persist
//! incrementally).

use crate::node::{NodeKind, NodeSnapshot, NodeState, PackInfo};
use interflow_identity::manifest::{AgentTransport, MeshEgressRule, MeshIngressRule, MeshProtocol};
use interflow_mesh::config::TransportKind;
use serde::{Deserialize, Serialize};
use std::path::Path;

/// One service an agent node declares, with the address the agent will
/// actually dial (pack default unless a machine-local preference overrides
/// it — what is shown is what runs).
#[derive(Debug, Clone, Serialize, Deserialize, specta::Type)]
pub struct ServiceAddressDto {
    pub id: String,
    /// Manifest-issued default from the pack.
    pub default_address: String,
    /// Effective dial target (override if set, else the default).
    pub effective_address: String,
    /// A machine-local preference overrides the default.
    pub overridden: bool,
}

/// Transport toward the hub/control endpoint (wire form mirrors mesh
/// `TransportKind`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize, specta::Type)]
#[serde(rename_all = "lowercase")]
pub enum Transport {
    #[default]
    H2,
    Quic,
}

impl From<TransportKind> for Transport {
    fn from(kind: TransportKind) -> Self {
        match kind {
            TransportKind::H2 => Self::H2,
            TransportKind::Quic => Self::Quic,
        }
    }
}

impl From<AgentTransport> for Transport {
    fn from(transport: AgentTransport) -> Self {
        match transport {
            AgentTransport::H2 => Self::H2,
            AgentTransport::Quic => Self::Quic,
        }
    }
}

impl From<Transport> for TransportKind {
    fn from(transport: Transport) -> Self {
        match transport {
            Transport::H2 => Self::H2,
            Transport::Quic => Self::Quic,
        }
    }
}

/// What a node is — derived from its Credential Pack (wire form of
/// `node::NodeKind`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, specta::Type)]
#[serde(rename_all = "snake_case")]
pub enum NodeKindDto {
    ExposeAgent,
    MeshAgent,
    Hub,
    Ingress,
}

impl From<NodeKind> for NodeKindDto {
    fn from(kind: NodeKind) -> Self {
        match kind {
            NodeKind::ExposeAgent => Self::ExposeAgent,
            NodeKind::MeshAgent => Self::MeshAgent,
            NodeKind::Hub => Self::Hub,
            NodeKind::Ingress => Self::Ingress,
        }
    }
}

/// Node lifecycle (wire form of `node::NodeState`; `backoff_secs` narrows
/// u64 → u32: specta forbids BigInt-style exports, and a backoff beyond
/// u32::MAX seconds is meaningless).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, specta::Type)]
pub enum NodeStateDto {
    Starting,
    Connecting,
    Connected {
        agent_id: String,
        /// The hub's registration receipt (wire form of mesh `HubReceipt`):
        /// the egress address the hub observed plus the registration moment
        /// — the "hub-confirmed" evidence the UI surfaces. Absent keeps the
        /// pre-receipt wire shape.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        hub_receipt: Option<HubReceiptDto>,
    },
    Reconnecting {
        reason: String,
        backoff_secs: u32,
    },
    Running,
    Stopping,
    Stopped,
    Failed {
        error: String,
    },
}

/// The hub's registration receipt, carried with [`NodeStateDto::Connected`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, specta::Type)]
pub struct HubReceiptDto {
    /// The egress address the hub observed for this registration.
    pub egress_ip: Option<String>,
    /// When the registration exchange completed (unix seconds; u32 on the
    /// wire — specta forbids BigInt-style types, and unix seconds beyond
    /// 2106 are meaningless here).
    pub registered_at_unix: u32,
}

impl From<interflow_mesh::agent::HubReceipt> for HubReceiptDto {
    fn from(receipt: interflow_mesh::agent::HubReceipt) -> Self {
        Self {
            egress_ip: receipt.egress_ip,
            registered_at_unix: u32::try_from(receipt.registered_at_unix).unwrap_or(u32::MAX),
        }
    }
}

impl From<NodeState> for NodeStateDto {
    fn from(state: NodeState) -> Self {
        match state {
            NodeState::Starting => Self::Starting,
            NodeState::Connecting => Self::Connecting,
            NodeState::Connected {
                agent_id,
                hub_receipt,
            } => Self::Connected {
                agent_id,
                hub_receipt: hub_receipt.map(Into::into),
            },
            NodeState::Reconnecting {
                reason,
                backoff_secs,
            } => Self::Reconnecting {
                reason,
                backoff_secs,
            },
            NodeState::Running => Self::Running,
            NodeState::Stopping => Self::Stopping,
            NodeState::Stopped => Self::Stopped,
            NodeState::Failed { error } => Self::Failed { error },
        }
    }
}

/// Wire protocol of a mesh rule (wire form of manifest `MeshProtocol`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, specta::Type)]
#[serde(rename_all = "lowercase")]
pub enum MeshProtocolDto {
    Tcp,
    Udp,
}

impl From<MeshProtocol> for MeshProtocolDto {
    fn from(protocol: MeshProtocol) -> Self {
        match protocol {
            MeshProtocol::Tcp => Self::Tcp,
            MeshProtocol::Udp => Self::Udp,
        }
    }
}

/// A listen-side mesh rule (pack-signed; the GUI shows it read-only).
#[derive(Debug, Clone, Serialize, Deserialize, specta::Type)]
pub struct MeshIngressRuleDto {
    pub name: String,
    /// Local listen address (loopback).
    pub listen: String,
    pub protocol: MeshProtocolDto,
    /// The peer agent that dials `remote_addr` on its own network.
    pub target_agent: String,
    pub remote_addr: String,
}

impl From<MeshIngressRule> for MeshIngressRuleDto {
    fn from(rule: MeshIngressRule) -> Self {
        Self {
            name: rule.name,
            listen: rule.listen,
            protocol: rule.protocol.into(),
            target_agent: rule.target_agent,
            remote_addr: rule.remote_addr,
        }
    }
}

/// A serve-side mesh rule (pack-signed; the GUI shows it read-only). `target`
/// is one concrete `host:port`, or an authorized `ip/prefix` range.
#[derive(Debug, Clone, Serialize, Deserialize, specta::Type)]
pub struct MeshEgressRuleDto {
    pub name: String,
    pub protocol: MeshProtocolDto,
    pub target: String,
}

impl From<MeshEgressRule> for MeshEgressRuleDto {
    fn from(rule: MeshEgressRule) -> Self {
        Self {
            target: rule.authorization().to_owned(),
            name: rule.name,
            protocol: rule.protocol.into(),
        }
    }
}

/// Leaf-credential health of one pack (the "when do this node's
/// credentials stop working" surface). Phase thresholds are the
/// workspace-wide 20% / 10% of the leaf TTL (identity's `expiry` module).
#[derive(Debug, Clone, Serialize, Deserialize, specta::Type)]
pub struct CredentialHealthDto {
    /// Earliest active leaf `notAfter` (RFC 3339, UTC).
    pub not_after: String,
    /// Remaining seconds of that leaf (negative once expired; i32 on the
    /// wire — specta forbids BigInt-style types, and ±68 years of
    /// remaining-seconds headroom is beyond generous).
    pub remaining_secs: i32,
    /// `healthy` / `warn` (<20% of the TTL remains, amber) / `critical`
    /// (<10%, red). Surfaces color-code on this string.
    pub phase: String,
}

impl From<crate::node::CredentialHealth> for CredentialHealthDto {
    fn from(h: crate::node::CredentialHealth) -> Self {
        Self {
            not_after: h.not_after,
            remaining_secs: i32::try_from(h.remaining_secs).unwrap_or(i32::MAX),
            phase: h.phase.as_str().to_string(),
        }
    }
}

/// The policy plane's live face for one mesh agent node — "which policy
/// generation is this node actually running, from which channel, and is
/// the hub ahead or behind it" (the policy-health surface; a
/// `hub_generation` below `generation` is the lineage-deadlock signature
/// and surfaces color-code it amber).
#[derive(Debug, Clone, Serialize, Deserialize, specta::Type)]
pub struct PolicyPlaneDto {
    /// The generation this node currently runs.
    pub generation: u32,
    /// Which face the live policy came from.
    pub source: PolicySourceDto,
    /// The hub's serving generation as of the watcher's last poll;
    /// `None` = never polled / the hub did not report / node not running.
    pub hub_generation: Option<u32>,
    /// The control-plane pull channel's own health while the node runs;
    /// `None` = the node is stopped.
    pub pull: Option<PullHealthDto>,
}

/// The distribution plane's liveness face — distinct from whichever
/// generation it delivered: `last_ok_unix == 0` on a connected agent is a
/// channel that has never completed a pull (the 2026-10-07 frozen-mesh
/// signature), and `last_tick_unix` frozen in the past is a dead watcher
/// task.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, specta::Type)]
pub struct PullHealthDto {
    /// Unix seconds of the last completed pull; `0` = never.
    pub last_ok_unix: u32,
    /// Total failed pull attempts since the node started.
    pub failures_total: u32,
    /// Unix seconds of the watcher's most recent wake.
    pub last_tick_unix: u32,
}

/// Which distribution face a node's live policy came from.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, specta::Type)]
#[serde(rename_all = "snake_case")]
pub enum PolicySourceDto {
    /// The pack's embedded snapshot.
    Pack,
    /// The node-local update channel (`state/policy`) — hub pulls and
    /// manual injections land here.
    StatePolicy,
}

impl From<crate::node::PolicyPlane> for PolicyPlaneDto {
    fn from(p: crate::node::PolicyPlane) -> Self {
        Self {
            generation: u32::try_from(p.generation).unwrap_or(u32::MAX),
            source: match p.source {
                crate::node::PolicySource::Pack => PolicySourceDto::Pack,
                crate::node::PolicySource::StatePolicy => PolicySourceDto::StatePolicy,
            },
            hub_generation: p.hub_generation.and_then(|g| u32::try_from(g).ok()),
            pull: p.pull.map(|h| PullHealthDto {
                last_ok_unix: u32::try_from(h.last_ok_unix).unwrap_or(u32::MAX),
                failures_total: u32::try_from(h.failures_total).unwrap_or(u32::MAX),
                last_tick_unix: u32::try_from(h.last_tick_unix).unwrap_or(u32::MAX),
            }),
        }
    }
}

/// The peer plane's live face for one mesh agent node — the tenant's other
/// agents with presence and leaf health (the 2026-10-08
/// peer-observability surface; the first local answer to "is the far end
/// up"). Information-minimal: name, presence, leaf phase.
#[derive(Debug, Clone, Serialize, Deserialize, specta::Type)]
pub struct PeersPlaneDto {
    /// The tenant's registered agents, self excluded.
    pub peers: Vec<PeerStatusDto>,
    /// Unix seconds of the last successful fetch; `0` = never.
    pub last_ok_unix: u32,
    /// Failed fetches since the node started.
    pub failures_total: u32,
}

/// The CRL-poll liveness plane for one running node — the renewal loop's
/// level (value + confirmation instant), the local half of the 2026-10-19
/// liveness face. The panel judges `last_success_unix` against its own
/// clock: a level that stopped advancing is a wedged poll loop, exactly
/// the reading this face exists to make visible.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, specta::Type)]
pub struct CrlPollPlaneDto {
    /// Unix seconds of the last successful CRL poll; `0` = never.
    pub last_success_unix: u32,
    /// Failed polls since the node's process started.
    pub failures_total: u32,
}

impl From<crate::node::CrlPollPlane> for CrlPollPlaneDto {
    fn from(p: crate::node::CrlPollPlane) -> Self {
        Self {
            last_success_unix: u32::try_from(p.last_success_unix).unwrap_or(u32::MAX),
            failures_total: u32::try_from(p.failures_total).unwrap_or(u32::MAX),
        }
    }
}

/// One OPEN breaker entry (agent egress dial keys locally, route hosts
/// on the hub face) — the open-set face's row material (2026-10-19).
#[derive(Debug, Clone, Serialize, Deserialize, specta::Type)]
pub struct BreakerOpenRowDto {
    /// The breaker key: `tcp:host:port` / `udp:host:port` (agent egress)
    /// or the bare public host (edge routes).
    pub target: String,
    /// Unix seconds of the trip.
    pub opened_unix: u32,
    /// Unix seconds of the last admitted recovery probe; `0` = never.
    pub last_probe_unix: u32,
}

impl From<crate::node::BreakerOpenFace> for BreakerOpenRowDto {
    fn from(r: crate::node::BreakerOpenFace) -> Self {
        Self {
            target: r.target,
            opened_unix: u32::try_from(r.opened_unix).unwrap_or(u32::MAX),
            last_probe_unix: u32::try_from(r.last_probe_unix).unwrap_or(u32::MAX),
        }
    }
}

/// One OPEN route breaker on the answering hub, as the overview parses
/// it off the floor payload.
#[derive(Debug, Clone, Serialize, Deserialize, specta::Type)]
pub struct RouteBreakerOpenRowDto {
    /// The public host whose route breaker is OPEN.
    pub host: String,
    /// Unix seconds of the trip.
    pub opened_unix: u32,
    /// Unix seconds of the last admitted probe/touch.
    pub last_probe_unix: u32,
}

/// The proposals queue's watermark face: pending count plus the oldest
/// submission's instant (ages are consumer-side, judged against the
/// overview's `captured_at_unix`).
#[derive(Debug, Clone, Serialize, Deserialize, specta::Type)]
pub struct ProposalsPendingDto {
    /// Proposals awaiting an operator decision.
    pub pending_count: u32,
    /// Unix seconds of the oldest pending submission.
    pub oldest_submitted_unix: u32,
}

/// One resident hub task as the watchdog face carries it (the
/// armed-assertion face): a row whose `last_tick_unix` went quiet past
/// `watcher_silent_factor` multiples of its OWN `interval_secs` (judged
/// against the overview's `captured_at_unix`) is a task wedged while the
/// hub keeps serving.
#[derive(Debug, Clone, Serialize, Deserialize, specta::Type)]
pub struct WatcherFaceRowDto {
    /// The task's registry name (stable across restarts).
    pub name: String,
    /// The task's own loop cadence, seconds — the silence judgment's
    /// anchor.
    pub interval_secs: u32,
    /// Unix seconds of this row's (re-)registration.
    pub started_unix: u32,
    /// Unix seconds of the last loop pass.
    pub last_tick_unix: u32,
}

/// One peer as the node's peer watcher reads it.
#[derive(Debug, Clone, Serialize, Deserialize, specta::Type)]
pub struct PeerStatusDto {
    /// Qualified peer id (`tenant/agent`).
    pub agent: String,
    /// Presence (`registered ≠ reachable`): a QUIC relay session in place,
    /// or an h2 poll body in place / within reconnect grace.
    pub online: bool,
    /// The peer's leaf-health phase (`None` = its leaf did not parse).
    /// Color-code like the node's own credential face: warn = amber,
    /// critical = red.
    pub leaf_phase: Option<LeafPhaseDto>,
    /// Seconds of leaf validity remaining (`0` with phase `None`).
    pub leaf_remaining_secs: i32,
    /// The leaf's `notAfter` unix seconds (`0` with phase `None`; capped
    /// at u32 — unix seconds stay inside it until 2106).
    pub leaf_not_after_unix: u32,
}

/// The leaf-health phase spelling (snake_case on the wire).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, specta::Type)]
#[serde(rename_all = "snake_case")]
pub enum LeafPhaseDto {
    Healthy,
    Warn,
    Critical,
}

/// One ingress rule's listener actual state — where it is really serving,
/// or why it is not (the actual-state counterpart of the rule store; the
/// 2026-10-09 honesty axis: a green session card plus a gone listener
/// surfaces as exactly that).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, specta::Type)]
pub struct ListenerStatusDto {
    /// The ingress rule the listener serves.
    pub rule: String,
    /// The actually-bound address, port materialized (`:0` picks show the
    /// real port) — `null` = no listener is up for the rule.
    pub bound_addr: Option<String>,
    /// The last bind failure (`null` = healthy).
    pub last_error: Option<String>,
    /// The stream is paused by intent (planned unavailability): no
    /// listener should be up and the port is deliberately free — its own
    /// face, not a bind failure.
    pub paused: bool,
}

impl From<crate::node::ListenerStatusFace> for ListenerStatusDto {
    fn from(f: crate::node::ListenerStatusFace) -> Self {
        Self {
            rule: f.rule,
            bound_addr: f.bound_addr,
            last_error: f.last_error,
            paused: f.paused,
        }
    }
}

impl From<crate::node::PeersPlane> for PeersPlaneDto {
    fn from(p: crate::node::PeersPlane) -> Self {
        Self {
            peers: p
                .peers
                .into_iter()
                .map(|s| PeerStatusDto {
                    agent: s.agent,
                    online: s.online,
                    leaf_phase: s.leaf_phase.map(|phase| match phase {
                        interflow_core::tunnel::transport::PeerLeafPhase::Healthy => {
                            LeafPhaseDto::Healthy
                        }
                        interflow_core::tunnel::transport::PeerLeafPhase::Warn => {
                            LeafPhaseDto::Warn
                        }
                        interflow_core::tunnel::transport::PeerLeafPhase::Critical => {
                            LeafPhaseDto::Critical
                        }
                    }),
                    leaf_remaining_secs: i32::try_from(s.leaf_remaining_secs).unwrap_or(i32::MAX),
                    leaf_not_after_unix: u32::try_from(s.leaf_not_after_unix.max(0))
                        .unwrap_or(u32::MAX),
                })
                .collect(),
            last_ok_unix: u32::try_from(p.last_ok_unix).unwrap_or(u32::MAX),
            failures_total: u32::try_from(p.failures_total).unwrap_or(u32::MAX),
        }
    }
}

/// One managed node (list rows, detail panes).
#[derive(Debug, Clone, Serialize, Deserialize, specta::Type)]
pub struct NodeInfo {
    pub id: String,
    pub kind: NodeKindDto,
    /// Display name (the pack's node name).
    pub name: String,
    /// The identity the pack carries (`realm/workspace/kind/node`);
    /// `None` = the pack was unreadable at restore (placeholder).
    pub principal: Option<String>,
    /// Unique log attribution value (name + id prefix) — the `node` field
    /// this node's captured log lines carry and the "This node" filter
    /// matches on.
    pub attribution: String,
    /// Directory of the installed Credential Pack.
    pub pack_dir: String,
    pub state: NodeStateDto,
    /// Start intent: the node should be (and, on launch, will be) running.
    pub desired_running: bool,
    /// Agent nodes only.
    pub transport: Option<Transport>,
    /// Dial transport the pack declares as its signed default (agent
    /// nodes; `None` = the h2 default). The effective transport the node
    /// runs with is `transport ?? pack_transport ?? h2` — shown so the
    /// UI never claims h2 while an unset preference inherits a `quic`
    /// pack default.
    pub pack_transport: Option<Transport>,
    /// Agent nodes only; `None` derives from the control endpoint.
    pub hub_quic_addr: Option<String>,
    /// The QUIC dial address the pack implies (mesh agents: derived from
    /// the signed hub endpoint; `None` when it carries no explicit port).
    /// The fallback a blank [`Self::hub_quic_addr`] preference resolves
    /// to — shown so the UI states what a quic dial will actually touch.
    pub pack_hub_quic_addr: Option<String>,
    /// Services the pack declares, with the effective dial address (expose
    /// agents; empty for other kinds).
    pub services: Vec<ServiceAddressDto>,
    /// Site-to-site rules the pack declares (mesh agents; empty for other
    /// kinds). Pack-signed truth, shown read-only.
    pub mesh_ingress_rules: Vec<MeshIngressRuleDto>,
    /// Serve-side mesh rules (mesh agents; empty for other kinds).
    pub mesh_egress_rules: Vec<MeshEgressRuleDto>,
    /// Public/control listener the pack declares (hub/ingress).
    pub listen: Option<String>,
    /// Rotation generation of the pack (display cache for update hints).
    pub generation: u32,
    /// Leaf-credential health (earliest active expiry, phased). `None`
    /// when the pack has no active credential set. Color-code `phase`:
    /// warn = amber, critical = red (the dirty-build visual language).
    pub credential: Option<CredentialHealthDto>,
    /// The policy plane's live face (mesh agents only). `None` for other
    /// kinds or an unreadable pack.
    pub policy: Option<PolicyPlaneDto>,
    /// The peer plane's live face (mesh agents only, running). `None` for
    /// other kinds or a stopped node — presence has no meaningful stale
    /// display.
    pub peers: Option<PeersPlaneDto>,
    /// The renewal loop's CRL-poll liveness plane (agent/edge kinds,
    /// running). `None` for other kinds or a stopped node — a stale
    /// reading must come from a running loop or not at all.
    pub crl: Option<CrlPollPlaneDto>,
    /// The egress-breaker open set (mesh agents, running, breaker
    /// enabled). `None` for other kinds or a stopped node.
    pub breakers: Option<Vec<BreakerOpenRowDto>>,
    /// This node's stream-proposal receipts (mesh agents only, running) —
    /// `None` for other kinds or a stopped node.
    pub proposals: Option<Vec<ProposalReceiptDto>>,
    /// Every ingress rule's listener actual state (mesh agents only,
    /// running) — `None` for other kinds or a stopped node. This is what
    /// is REALLY listening, not what the policy wants.
    pub listeners: Option<Vec<ListenerStatusDto>>,
    /// The deployment this node's pack belongs to (`<root>/dist/packs/…`
    /// reverse-resolved); `None` for sealed imports and packs outside any
    /// deployment tree — the cross-link the new IA's fleet/machine views
    /// navigate by.
    pub deployment: Option<DeploymentRefDto>,
}

impl From<NodeSnapshot> for NodeInfo {
    fn from(snapshot: NodeSnapshot) -> Self {
        let attribution = crate::node::log_attribution(&snapshot.spec);
        // Before the rules extraction consumes `pack_mesh` by value.
        let pack_hub_quic_addr = snapshot
            .spec
            .pack_mesh
            .as_ref()
            .and_then(|mesh| interflow_mesh::pack::derive_quic_addr(&mesh.hub_endpoint));
        let services = snapshot
            .spec
            .pack_services
            .iter()
            .map(|service| {
                let override_addr = snapshot.spec.service_addresses.get(&service.id);
                ServiceAddressDto {
                    id: service.id.clone(),
                    default_address: service.default_address.clone(),
                    effective_address: override_addr
                        .cloned()
                        .unwrap_or_else(|| service.default_address.clone()),
                    overridden: override_addr.is_some(),
                }
            })
            .collect();
        let (mesh_ingress_rules, mesh_egress_rules) = snapshot
            .spec
            .pack_mesh
            .map(|mesh| {
                (
                    mesh.ingress.into_iter().map(Into::into).collect(),
                    mesh.egress.into_iter().map(Into::into).collect(),
                )
            })
            .unwrap_or_default();
        Self {
            id: snapshot.spec.id.clone(),
            kind: snapshot.spec.kind.into(),
            name: snapshot.spec.name,
            attribution,
            principal: snapshot.spec.principal,
            pack_dir: snapshot.spec.pack_dir.display().to_string(),
            state: snapshot.state.into(),
            desired_running: snapshot.desired_running,
            transport: snapshot.spec.transport.map(Transport::from),
            pack_transport: match snapshot.spec.pack_transport.as_deref() {
                // "h2" and anything unexpected both display as the default
                // (None); an unexpected string fails loud at start instead.
                Some("quic") => Some(Transport::Quic),
                _ => None,
            },
            hub_quic_addr: snapshot.spec.hub_quic_addr,
            pack_hub_quic_addr,
            services,
            mesh_ingress_rules,
            mesh_egress_rules,
            listen: snapshot.spec.pack_listen,
            generation: u32::try_from(snapshot.spec.generation).unwrap_or(u32::MAX),
            // Merged by the command layer from the manager's health cache
            // (the snapshot is pure node state).
            credential: None,
            // Merged by the command layer from the manager's policy-plane
            // view (live watcher state or the authoritative pack load).
            policy: None,
            // Merged by the command layer from the manager's peers-plane
            // view (live watcher state; stopped nodes carry no reading).
            peers: None,
            crl: None,
            breakers: None,
            // Merged by the command layer from the manager's proposal
            // receipts view (same contract).
            proposals: None,
            // Merged by the command layer from the manager's
            // listeners-plane view (live reconciler table; stopped nodes
            // carry no reading).
            listeners: None,
            // Pure filesystem probe on the pack directory — the deployment
            // the pack was rendered into, for the fleet/machine cross-links.
            deployment: crate::deployment::deployment_of_pack(Path::new(&snapshot.spec.pack_dir))
                .map(|d| DeploymentRefDto {
                    name: d.name,
                    root: d.root.display().to_string(),
                }),
        }
    }
}

/// The deployment a node/pack belongs to — the new IA's navigation anchor.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, specta::Type)]
pub struct DeploymentRefDto {
    /// The deployment folder's name (the realm id, by convention).
    pub name: String,
    /// The deployment folder's absolute path.
    pub root: String,
}

/// One discovered deployment folder (`deployment_list`) — the switcher's
/// row and the open-deployment flow's unit.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, specta::Type)]
pub struct DeploymentDto {
    pub name: String,
    pub root: String,
    pub manifest_path: String,
    /// The issuer store (`<root>/issuer`); present once an apply has run.
    pub issuer_path: String,
    /// The dist tree (`<root>/dist`) packs render into.
    pub out_path: String,
    pub has_issuer: bool,
    pub has_dist: bool,
}

impl From<crate::deployment::DeploymentDir> for DeploymentDto {
    fn from(d: crate::deployment::DeploymentDir) -> Self {
        Self {
            name: d.name,
            root: d.root.display().to_string(),
            manifest_path: d.manifest.display().to_string(),
            issuer_path: d.issuer.display().to_string(),
            out_path: d.out.display().to_string(),
            has_issuer: d.has_issuer,
            has_dist: d.has_dist,
        }
    }
}

/// What the add-node flow shows after a pack directory is picked (validated
/// through the same funnel the start path uses).
#[derive(Debug, Clone, Serialize, Deserialize, specta::Type)]
pub struct PackInspection {
    pub kind: NodeKindDto,
    pub name: String,
    /// The identity the pack carries (`realm/workspace/kind/node`) — a node
    /// is an identity, not a machine; one identity runs at most once here.
    pub principal: String,
    /// Agents dial it; hubs/ingress show their listen address.
    pub control_endpoint: String,
    /// Expose services the pack declares (ids; the pack's manifest-issued
    /// default addresses show up in the node detail after adding).
    pub services: Vec<String>,
    /// Mesh rule counts (mesh agents). u32 on the wire — specta forbids
    /// BigInt-style types, and rule counts beyond u32 are meaningless.
    pub mesh_ingress: u32,
    pub mesh_egress: u32,
    /// Listen address (hub/ingress).
    pub listen: Option<String>,
    /// Dial transport the pack declares as its signed default (agent packs;
    /// `None` = the h2 default). The add dialog starts its transport control
    /// here, so a pack signed `quic` never gets silently re-defaulted to h2
    pub transport: Option<Transport>,
    /// Leaf-credential health (earliest active expiry, phased).
    pub credential: Option<CredentialHealthDto>,
}

impl From<PackInfo> for PackInspection {
    fn from(info: PackInfo) -> Self {
        let (mesh_ingress, mesh_egress) = info
            .mesh
            .as_ref()
            .map_or((0, 0), |mesh| (mesh.ingress.len(), mesh.egress.len()));
        Self {
            kind: info.kind.into(),
            name: info.name,
            principal: info.principal,
            control_endpoint: info.control_endpoint,
            services: info.services.into_iter().map(|s| s.id).collect(),
            mesh_ingress: u32::try_from(mesh_ingress).unwrap_or(u32::MAX),
            mesh_egress: u32::try_from(mesh_egress).unwrap_or(u32::MAX),
            listen: info.listen,
            // Same mapping as `NodeInfo::pack_transport`: "h2" and anything
            // unexpected both display as the default (None); an unexpected
            // string fails loud at start instead.
            transport: match info.transport.as_deref() {
                Some("quic") => Some(Transport::Quic),
                _ => None,
            },
            credential: info.credential.map(Into::into),
        }
    }
}

/// Parameters for adding a node (frontend add flow → Rust).
#[derive(Debug, Clone, Deserialize, specta::Type)]
#[serde(deny_unknown_fields)]
pub struct AddNodeParams {
    /// Directory of the installed Credential Pack.
    pub pack_dir: String,
    /// Transport toward the hub; absent = h2 (agent nodes only).
    pub transport: Option<Transport>,
    /// Hub QUIC address; absent = derived (agent nodes only).
    pub hub_quic_addr: Option<String>,
}

/// One machine-local service-address preference (expose agents).
#[derive(Debug, Clone, Serialize, Deserialize, specta::Type)]
pub struct ServiceAddressPrefDto {
    pub id: String,
    pub address: String,
}

/// Agent runtime preferences (updatable while the node is stopped).
#[derive(Debug, Clone, Deserialize, specta::Type)]
#[serde(deny_unknown_fields)]
pub struct NodePrefs {
    pub transport: Option<Transport>,
    pub hub_quic_addr: Option<String>,
    /// The **complete** preference set for service addresses (full-state
    /// replacement, same semantics as `transport`): each entry overrides
    /// the pack default for that service id; an empty list reverts every
    /// service to its default.
    pub service_addresses: Vec<ServiceAddressPrefDto>,
}

/// One apply's structured outcome — the report lines (what the CLI prints
/// verbatim) plus the generation it landed on. The Deploy overview's
/// Apply-result card renders both.
#[derive(Debug, Clone, Serialize, Deserialize, specta::Type)]
pub struct ApplyReportDto {
    pub lines: Vec<String>,
    /// The policy generation this apply minted — or, on a no-op, the live
    /// generation it confirmed.
    pub generation: u32,
}

/// The bookkeeping-level "would apply do anything" pre-check (no minting,
/// no hub dial): the "unapplied changes" badge and the next-steps face.
#[derive(Debug, Clone, Serialize, Deserialize, specta::Type)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum ChangeStateDto {
    /// No applied state in this issuer store — the first apply performs a
    /// full render.
    NeverApplied,
    /// The manifest matches the applied state exactly.
    Applied { generation: u32 },
    /// Only the policy face moved (mesh rules, services, routes, idle
    /// budgets) — the next apply takes the policy-only fast path (hot,
    /// ≤10s to the fleet, every node kind).
    PolicyEditsPending,
    /// The identity/trust/dial face changed — the next apply re-renders
    /// every pack.
    IdentityEditsPending,
    /// The declaration is unchanged but the rendered pack tree is not
    /// "applied" — a retired pack format, or an embedded CRL snapshot
    /// predating the issuer's deny list. The next apply re-renders every
    /// pack and publishes a new generation above the watermarks; local
    /// nodes restart per their captured intent.
    PackTreeStale,
    /// The declaration is unchanged but the dist tree's signed artifacts
    /// sit above the issuer bookkeeping — the next apply re-publishes the
    /// same policy above the watermarks (hot, like policy edits; no pack
    /// re-renders).
    WatermarksDiverged,
}

/// The running hub's operator overview: watermarks plus the fleet's
/// presence and pull convergence (from the control-credential
/// `GET /policy/floor` — all facts the hub already holds).
#[derive(Debug, Clone, Serialize, Deserialize, specta::Type)]
pub struct HubOverviewDto {
    /// The answering hub's manifest-declared name (`None` = an older hub
    /// that does not self-report).
    pub hub: Option<String>,
    /// The anti-rollback floor (includes absorbed node watermarks).
    pub floor: u32,
    /// What the hub actually serves; `None` = this hub cannot report it.
    pub serving: Option<u32>,
    /// The hub-side capture instant (unix seconds) — the anchor every
    /// per-leg recency judgment reads against; `None` = an older hub
    /// (recency then stays unjudgeable, never guessed).
    #[serde(default)]
    pub captured_at_unix: Option<u32>,
    /// The policy-watch silent threshold in seconds (3× the engine's
    /// watch interval), self-reported so clients never hardcode a
    /// cadence they do not own.
    #[serde(default)]
    pub policy_silent_after_secs: u32,
    /// The CRL-poll silent threshold in seconds (3× the renewal loop's
    /// poll cadence), self-reported so clients never hardcode a cadence
    /// they do not own (same discipline as
    /// [`Self::policy_silent_after_secs`]).
    #[serde(default)]
    pub crl_silent_after_secs: u32,
    /// Unix seconds of THIS hub's own last successful CRL poll (its
    /// renewal loop's liveness face, self slot); `None` = an older hub
    /// or no renewal loop.
    #[serde(default)]
    pub crl_last_success_unix: Option<u32>,
    /// Failed CRL polls since this hub process started.
    #[serde(default)]
    pub crl_failures_total: Option<u32>,
    /// The currently-OPEN route breakers (edge gateways; empty on plain
    /// mesh hubs) — the hub card's ⚠ chips and the doctor line read this.
    #[serde(default)]
    pub route_breakers_open: Vec<RouteBreakerOpenRowDto>,
    /// The resident-task watchdog's rows (the armed-assertion face): every
    /// long-lived hub task with its cadence anchor and last tick. Empty on
    /// older hubs — the assertion is then unjudgeable, never passed.
    #[serde(default)]
    pub watchers: Vec<WatcherFaceRowDto>,
    /// The silence judgment factor (a row is silent strictly past this
    /// multiple of its own interval), self-reported so clients never
    /// hardcode a threshold they do not own.
    #[serde(default)]
    pub watcher_silent_factor: u32,
    /// The proposals queue's watermark face (`None` when nothing is
    /// pending or the hub carries no store).
    #[serde(default)]
    pub proposals_pending: Option<ProposalsPendingDto>,
    /// The hub's currently-admitted streams across all agents (`None` on
    /// older hubs).
    #[serde(default)]
    pub streams_in_flight_total: Option<u32>,
    /// The admission caps the headroom judgments read against (`None` on
    /// older hubs).
    #[serde(default)]
    pub stream_limits: Option<StreamLimitsDto>,
    /// The fossil-judgment anchors, self-reported so clients never
    /// hardcode thresholds they do not own: a budgeted stream reads
    /// fossil quiet past this multiple of its own budget.
    #[serde(default)]
    pub fossil_idle_multiple: u32,
    /// The fossil line for streams with NO idle budget (days).
    #[serde(default)]
    pub fossil_unbudgeted_days: u32,
    /// The headroom warn ratio (percent; a scope under this remaining
    /// capacity reads tight).
    #[serde(default)]
    pub headroom_warn_pct: u32,
    /// The credential-expiry face's thresholds, self-reported so clients
    /// never hardcode lines they do not own: the offline tier's yellow
    /// line (days remaining).
    #[serde(default)]
    pub offline_warn_days: i32,
    /// The offline tier's red line (days).
    #[serde(default)]
    pub offline_critical_days: i32,
    /// The registrar tier's yellow line (percent of the span remaining).
    #[serde(default)]
    pub registrar_warn_pct: u32,
    /// The registrar tier's red line (percent of the span).
    #[serde(default)]
    pub registrar_critical_pct: u32,
    /// Every registered fleet member with presence and last-pulled
    /// watermark.
    pub agents: Vec<HubAgentRowDto>,
}

/// The deployment-scoped composed read model (2026-10-10 IA) — ONE command
/// backing the 总览/流/服务 views: the declared desired state (manifest
/// summary), the bookkeeping change classification, the hub's fleet face
/// (optional — never let hub latency hold the local view hostage), and the
/// joins that make each declared node answer "is it here, is it running,
/// is it converged".
#[derive(Debug, Clone, Serialize, specta::Type)]
pub struct FleetDto {
    pub summary: ManifestSummaryDto,
    pub change_state: ChangeStateDto,
    /// The hub's operator overview; `None` = not requested or unreachable
    /// (the caller decides whether to dial — `include_hub`).
    pub hub: Option<HubOverviewDto>,
    /// One row per DECLARED node (manifest truth): agents, hubs,
    /// ingresses.
    pub nodes: Vec<FleetNodeDto>,
    /// The 流 view's rows: every declared mesh ingress stream, joined with
    /// its live listener state and convergence.
    pub streams: Vec<StreamDto>,
    /// The 服务 view's rows: every declared expose service, joined with
    /// this machine's effective address.
    pub services: Vec<ServiceFaceDto>,
    /// Local nodes whose packs do NOT belong to this deployment (sealed
    /// imports, other deployments) — the 节点 view completes from these.
    pub local_only: Vec<NodeInfo>,
}

/// One declared node as the fleet table shows it.
#[derive(Debug, Clone, Serialize, specta::Type)]
pub struct FleetNodeDto {
    /// The declared kind (manifest face): agent / hub / ingress.
    pub kind: NodeKindDto,
    pub name: String,
    /// The workspace (agents); `None` for hubs and ingresses.
    pub workspace: Option<String>,
    /// This machine's face (`None` = the node does not run here).
    pub local: Option<LocalFaceDto>,
    /// The hub's face (`None` = no hub overview / the node is not an
    /// agent registered there).
    pub remote: Option<RemoteFaceDto>,
}

/// The local-machine face of a declared node: what the NodeManager knows.
#[derive(Debug, Clone, Serialize, specta::Type)]
pub struct LocalFaceDto {
    /// The NodeManager id (the 节点 view's navigation target).
    pub id: String,
    pub state: NodeStateDto,
    pub desired_running: bool,
    /// The installed pack's generation (display cache).
    pub generation: u32,
    /// The policy plane's applied generation (mesh/expose agents;
    /// `None` = no watcher face, e.g. a stopped node or a hub).
    pub policy_generation: Option<u32>,
    /// Live listener states (mesh agents, running; else empty).
    pub listeners: Vec<ListenerStatusDto>,
}

/// The hub's face of a declared agent.
#[derive(Debug, Clone, Serialize, specta::Type)]
pub struct RemoteFaceDto {
    /// `registered ≠ reachable` — presence as the hub answers it.
    pub online: bool,
    /// The generation this agent last pulled; `None` = no completed pull.
    pub seen_generation: Option<u32>,
    /// Unix seconds of the agent's last completed pull; `None` = no
    /// completed pull, or an older hub without the field (recency then
    /// stays unjudgeable, never guessed).
    pub policy_last_pull_unix: Option<u32>,
    /// The overview's hub-side capture instant — the recency anchor (a
    /// face older than the silent threshold cannot support a per-leg
    /// silent verdict; the view degrades to "data age", not a guess).
    pub face_captured_at_unix: Option<u32>,
    /// The stream names this member last reported paused (planned
    /// unavailability, stream-level); `None` = never reported.
    #[serde(default)]
    pub paused_streams: Option<Vec<String>>,
    /// The member is declared under maintenance (planned unavailability,
    /// node-level — its absence is expected, not an accident).
    #[serde(default)]
    pub maintenance: bool,
    /// Unix seconds of the member's last successful CRL poll (its
    /// renewal reporter's level); `None` = never reported / an older
    /// hub.
    #[serde(default)]
    pub crl_last_success_unix: Option<u32>,
    /// Failed CRL polls since the member's process started.
    #[serde(default)]
    pub crl_failures_total: Option<u32>,
    /// The operator's queued stream ops waiting on this leg (the mailbox
    /// watermark face); `None` = nothing waiting / an older hub.
    #[serde(default)]
    pub pending_ops: Option<MailboxFaceDto>,
    /// This agent's currently-admitted hub streams (`None` on older
    /// hubs / legs with no live count).
    #[serde(default)]
    pub streams_in_flight: Option<u32>,
    /// The agent's per-stream byte-activity levels (the fossil face).
    #[serde(default)]
    pub streams: Vec<NodeStreamActivityDto>,
    /// The last-seen leaf validity window (the credential-expiry face).
    #[serde(default)]
    pub leaf_not_before_unix: Option<u32>,
    /// See [`Self::leaf_not_before_unix`].
    #[serde(default)]
    pub leaf_not_after_unix: Option<u32>,
    /// The tier the span implies (`registrar` / `offline`).
    #[serde(default)]
    pub credential_mode: Option<String>,
    /// Unix seconds of the registration that last presented the window.
    #[serde(default)]
    pub credential_last_seen_unix: Option<u32>,
    /// The connection-quality window stats (`None` on older agents).
    #[serde(default)]
    pub connection: Option<ConnectionQualityDto>,
    /// The renewal backoff ladder's current stage.
    #[serde(default)]
    pub renewal_backoff_failures: Option<u32>,
    /// The stage's observed maximum today.
    #[serde(default)]
    pub renewal_backoff_max_today: Option<u32>,
}

/// A stream row's live status. Local bind state is definitive when the
/// source node runs here; convergence answers "has the fleet taken the
/// current policy"; `Unknown` is honest (a remote source's bind state is
/// not observable from here — the row then leans on its remote face).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, specta::Type)]
#[serde(rename_all = "snake_case")]
pub enum StreamStatusDto {
    /// A local listener is bound and serving this rule.
    Serving,
    /// The local listener exists but its bind failed (down; the error
    /// rides the listener face).
    Down,
    /// The stream is paused by intent (planned unavailability): no
    /// listener should be up, the port is deliberately free (e.g. lent
    /// to a local process). Yellow, not red — and resumable in one
    /// action.
    Paused,
    /// The policy generation is still propagating (hub serving above the
    /// source node's seen/applied generation).
    CatchingUp,
    /// No local face and no convergence answer — render from the remote
    /// face instead of guessing.
    Unknown,
}

/// One mesh stream (the 流 view's row): a cross-machine pairing object —
/// the source agent's listen rule AND the target's remote, joined with
/// everything live about it.
#[derive(Debug, Clone, Serialize, specta::Type)]
pub struct StreamDto {
    /// The source agent (where the loopback listener runs).
    pub agent: String,
    /// The stream's name (rule identity on the source agent).
    pub name: String,
    pub listen: String,
    pub protocol: MeshProtocolDto,
    pub target_agent: String,
    pub remote_addr: String,
    pub idle_timeout_secs: Option<u32>,
    pub status: StreamStatusDto,
    /// The actually-bound address, port materialized (`:0` picks show the
    /// real port) — `None` = not bound, or no local face to observe it.
    pub bound_addr: Option<String>,
    /// The last bind failure verbatim (`None` = healthy or unobservable) —
    /// the 流 row's down reason (gui.md's "挂了看原因").
    pub last_error: Option<String>,
    /// The local NodeManager id of the source agent (`None` = it does not
    /// run on this machine) — the 节点 view cross-link.
    pub source_node_id: Option<String>,
}

/// One expose service (the 服务 view's row): the declared id + default
/// address, joined with this machine's effective dial target.
#[derive(Debug, Clone, Serialize, specta::Type)]
pub struct ServiceFaceDto {
    pub agent: String,
    pub workspace: String,
    pub id: String,
    /// The manifest-declared default — the signed default since the hot
    /// channel (what a machine without a local preference dials).
    pub default_address: String,
    /// This machine's effective address (`None` = the agent does not run
    /// here).
    pub effective_address: Option<String>,
    /// The effective address came from a machine-local preference.
    pub overridden: bool,
    /// The local NodeManager id of the serving agent.
    pub local_node_id: Option<String>,
}

/// What a publish did (the 发布 button's single backend entry).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, specta::Type)]
#[serde(rename_all = "snake_case")]
pub enum PublishKindDto {
    /// Only the policy face moved — every node hot-applies within a
    /// watcher period; no pack was touched.
    PolicyOnly,
    /// The identity/dial face moved — packs re-rendered; local stale
    /// packs were swapped in place (running nodes restarted).
    FullRender,
    /// Nothing to do (the idempotent gate).
    NoOp,
}

/// `deployment_publish`'s result: the apply report plus the orchestration
/// the old flow left to the operator (which local nodes were converged,
/// which were swapped, what needs manual attention).
#[derive(Debug, Clone, Serialize, specta::Type)]
pub struct PublishResultDto {
    pub kind: PublishKindDto,
    pub apply: ApplyReportDto,
    /// Node names this publish converged WITHOUT touching (policy-only:
    /// every local node of the deployment is hot).
    pub hot_nodes: Vec<String>,
    /// Node names whose local packs were swapped in place (full render;
    /// running ones restarted per their start intent).
    pub updated_nodes: Vec<String>,
    /// `(node name, error)` — a failed pack swap never fails the publish
    /// itself; the row stays stale and the operator re-runs update.
    pub failed_updates: Vec<NodeUpdateFailureDto>,
}

/// One pack-swap failure, phrased for the fleet table's row.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, specta::Type)]
pub struct NodeUpdateFailureDto {
    pub node: String,
    pub error: String,
}

/// One fleet member's row in a [`HubOverviewDto`].
#[derive(Debug, Clone, Serialize, Deserialize, specta::Type)]
pub struct HubAgentRowDto {
    /// Qualified agent id (`tenant/agent`).
    pub agent: String,
    /// Presence (`registered ≠ reachable`).
    pub online: bool,
    /// The generation this agent last pulled; `None` = no completed pull
    /// since the hub process started.
    pub seen: Option<u32>,
    /// Unix seconds of the agent's last completed pull (`None` = an older
    /// hub, or no completed pull) — the LEVEL face's confirmation instant.
    #[serde(default)]
    pub policy_last_pull_unix: Option<u32>,
    /// The stream names this member last reported paused (planned
    /// unavailability, stream-level); `None` = never reported.
    #[serde(default)]
    pub paused_streams: Option<Vec<String>>,
    /// The member is declared under maintenance (planned unavailability,
    /// node-level — its absence is expected, not an accident).
    #[serde(default)]
    pub maintenance: bool,
    /// Unix seconds of the member's last successful CRL poll (its renewal
    /// reporter's level); `None` = never reported / an older hub.
    #[serde(default)]
    pub crl_last_success_unix: Option<u32>,
    /// Failed CRL polls since the member's process started.
    #[serde(default)]
    pub crl_failures_total: Option<u32>,
    /// The operator's queued stream ops waiting on this leg (the mailbox
    /// watermark face); `None` = nothing waiting and nothing ever
    /// dropped, or an older hub.
    #[serde(default)]
    pub pending_ops: Option<MailboxFaceDto>,
    /// This agent's currently-admitted hub streams (`None` on older
    /// hubs / legs with no live count).
    #[serde(default)]
    pub streams_in_flight: Option<u32>,
    /// The agent's per-stream byte-activity levels (the fossil face;
    /// empty on older agents / agents without mesh stream rules).
    #[serde(default)]
    pub streams: Vec<NodeStreamActivityDto>,
    /// The last-seen leaf validity window (the credential-expiry face).
    #[serde(default)]
    pub leaf_not_before_unix: Option<u32>,
    /// See [`Self::leaf_not_before_unix`].
    #[serde(default)]
    pub leaf_not_after_unix: Option<u32>,
    /// The tier the span implies (`registrar` / `offline`).
    #[serde(default)]
    pub credential_mode: Option<String>,
    /// Unix seconds of the registration that last presented the window.
    #[serde(default)]
    pub credential_last_seen_unix: Option<u32>,
    /// The connection-quality window stats (`None` on older agents).
    #[serde(default)]
    pub connection: Option<ConnectionQualityDto>,
    /// The renewal backoff ladder's current stage.
    #[serde(default)]
    pub renewal_backoff_failures: Option<u32>,
    /// The stage's observed maximum today.
    #[serde(default)]
    pub renewal_backoff_max_today: Option<u32>,
}

/// One stream's byte-activity level (the fossil face's row material).
#[derive(Debug, Clone, Serialize, Deserialize, specta::Type)]
pub struct NodeStreamActivityDto {
    /// The stream rule's name (policy vocabulary).
    pub name: String,
    /// Unix seconds of the last byte (arm-time baseline before the
    /// first byte ever crosses).
    pub last_byte_unix: u32,
    /// The rule's own idle budget, when it sets one — the fossil
    /// judgment's per-row anchor.
    #[serde(default)]
    pub idle_budget_secs: Option<u32>,
}

/// The connection-quality window stats (the supervisor domain's
/// levels): reconnect rate, liveness RTT percentiles, probe timeouts.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, specta::Type)]
pub struct ConnectionQualityDto {
    /// Session establishments inside the reconnect window (one hour).
    pub reconnects_last_hour: u32,
    /// Median answered roundtrip, millis (`None` = no answered sample).
    #[serde(default)]
    pub rtt_p50_ms: Option<u32>,
    /// 99th-percentile answered roundtrip, millis.
    #[serde(default)]
    pub rtt_p99_ms: Option<u32>,
    /// Unanswered demanding roundtrips in the window.
    pub rtt_timeouts: u32,
    /// Total roundtrip samples in the window.
    pub rtt_samples: u32,
}

/// The admission caps the headroom judgments read against.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, specta::Type)]
pub struct StreamLimitsDto {
    /// `max_streams_total` (0 = unlimited).
    pub total: u32,
    /// `max_streams_per_agent` (0 = unlimited).
    pub per_agent: u32,
}

/// The mailbox watermark face for one member: queued stream ops waiting
/// on the leg, plus the capacity-drop history
///. Ages judge
/// against the overview's `captured_at_unix`.
#[derive(Debug, Clone, Serialize, Deserialize, specta::Type)]
pub struct MailboxFaceDto {
    /// Ops occupying the mailbox (undelivered AND delivered-unacked).
    pub pending_count: u32,
    /// Unix seconds of the oldest queued op.
    #[serde(default)]
    pub oldest_queued_unix: Option<u32>,
    /// The oldest op, rendered (`"pause ollama"`).
    #[serde(default)]
    pub oldest_op: Option<String>,
    /// Ops dropped by the capacity guard, cumulative for this hub
    /// process.
    pub dropped_total: u32,
}

/// One stream-proposal request (the requester's form = the validator's
/// fields, verbatim).
#[derive(Debug, Clone, Serialize, Deserialize, specta::Type)]
pub struct StreamProposalRequestDto {
    pub name: String,
    pub listen: String,
    /// tcp / udp.
    pub protocol: MeshProtocolDto,
    pub target_agent: String,
    pub remote_addr: String,
    pub idle_timeout_secs: Option<u32>,
}

/// A proposal's decision state (wire shape mirrors the hub record's).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, specta::Type)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum ProposalStatusDto {
    Pending,
    Approved { generation: u32 },
    Rejected { reason: String },
}

/// One queue entry as the operator's Deploy face shows it.
#[derive(Debug, Clone, Serialize, Deserialize, specta::Type)]
pub struct ControlProposalDto {
    pub id: String,
    /// The requesting agent's qualified id.
    pub requester: String,
    pub rule: StreamProposalRequestDto,
    pub submitted_at_unix: u32,
    pub expires_at_unix: u32,
    pub status: ProposalStatusDto,
}

/// The hub's answer to one submission (queued / idempotent duplicate /
/// denied with the funnel's readable reason).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, specta::Type)]
#[serde(tag = "outcome", rename_all = "snake_case")]
pub enum ProposalSubmitOutcomeDto {
    Queued { id: String, expires_at_unix: u32 },
    Duplicate { id: String, expires_at_unix: u32 },
    Denied { reason: String },
}

/// One of this node's own proposals (the receipts face).
#[derive(Debug, Clone, Serialize, Deserialize, specta::Type)]
pub struct ProposalReceiptDto {
    pub id: String,
    pub rule: StreamProposalRequestDto,
    pub submitted_at_unix: u32,
    pub expires_at_unix: u32,
    pub status: ProposalStatusDto,
}

impl From<interflow_mesh::hub::proposals::ControlProposal> for ControlProposalDto {
    fn from(p: interflow_mesh::hub::proposals::ControlProposal) -> Self {
        Self {
            id: p.id,
            requester: p.requester,
            rule: proposal_rule_dto(p.rule),
            submitted_at_unix: u32::try_from(p.submitted_at_unix).unwrap_or(u32::MAX),
            expires_at_unix: u32::try_from(p.expires_at_unix).unwrap_or(u32::MAX),
            status: proposal_status_dto(p.status),
        }
    }
}

impl From<interflow_core::tunnel::transport::ProposalReceipt> for ProposalReceiptDto {
    fn from(r: interflow_core::tunnel::transport::ProposalReceipt) -> Self {
        Self {
            id: r.id,
            rule: proposal_rule_dto(r.rule),
            submitted_at_unix: u32::try_from(r.submitted_at_unix).unwrap_or(u32::MAX),
            expires_at_unix: u32::try_from(r.expires_at_unix).unwrap_or(u32::MAX),
            status: match r.status {
                interflow_core::tunnel::transport::ProposalStatusWire::Pending => {
                    ProposalStatusDto::Pending
                }
                interflow_core::tunnel::transport::ProposalStatusWire::Approved { generation } => {
                    ProposalStatusDto::Approved {
                        generation: u32::try_from(generation).unwrap_or(u32::MAX),
                    }
                }
                interflow_core::tunnel::transport::ProposalStatusWire::Rejected { reason } => {
                    ProposalStatusDto::Rejected { reason }
                }
            },
        }
    }
}

fn proposal_rule_dto(
    rule: interflow_core::tunnel::transport::StreamProposalRequest,
) -> StreamProposalRequestDto {
    StreamProposalRequestDto {
        name: rule.name,
        listen: rule.listen,
        protocol: match rule.protocol {
            interflow_core::tunnel::transport::StreamProtoWire::Tcp => MeshProtocolDto::Tcp,
            interflow_core::tunnel::transport::StreamProtoWire::Udp => MeshProtocolDto::Udp,
        },
        target_agent: rule.target_agent,
        remote_addr: rule.remote_addr,
        idle_timeout_secs: rule.idle_timeout_secs.and_then(|s| u32::try_from(s).ok()),
    }
}

fn proposal_status_dto(status: interflow_mesh::hub::proposals::StoredStatus) -> ProposalStatusDto {
    match status {
        interflow_mesh::hub::proposals::StoredStatus::Pending => ProposalStatusDto::Pending,
        interflow_mesh::hub::proposals::StoredStatus::Approved { generation } => {
            ProposalStatusDto::Approved {
                generation: u32::try_from(generation).unwrap_or(u32::MAX),
            }
        }
        interflow_mesh::hub::proposals::StoredStatus::Rejected { reason } => {
            ProposalStatusDto::Rejected { reason }
        }
    }
}

impl From<interflow_core::tunnel::transport::ProposalSubmitOutcome> for ProposalSubmitOutcomeDto {
    fn from(o: interflow_core::tunnel::transport::ProposalSubmitOutcome) -> Self {
        match o {
            interflow_core::tunnel::transport::ProposalSubmitOutcome::Queued {
                id,
                expires_at_unix,
            } => Self::Queued {
                id,
                expires_at_unix: u32::try_from(expires_at_unix).unwrap_or(u32::MAX),
            },
            interflow_core::tunnel::transport::ProposalSubmitOutcome::Duplicate {
                id,
                expires_at_unix,
            } => Self::Duplicate {
                id,
                expires_at_unix: u32::try_from(expires_at_unix).unwrap_or(u32::MAX),
            },
            interflow_core::tunnel::transport::ProposalSubmitOutcome::Denied { reason } => {
                Self::Denied { reason }
            }
        }
    }
}

impl From<StreamProposalRequestDto> for interflow_core::tunnel::transport::StreamProposalRequest {
    fn from(r: StreamProposalRequestDto) -> Self {
        Self {
            name: r.name,
            listen: r.listen,
            protocol: match r.protocol {
                MeshProtocolDto::Tcp => interflow_core::tunnel::transport::StreamProtoWire::Tcp,
                MeshProtocolDto::Udp => interflow_core::tunnel::transport::StreamProtoWire::Udp,
            },
            target_agent: r.target_agent,
            remote_addr: r.remote_addr,
            idle_timeout_secs: r.idle_timeout_secs.map(u64::from),
        }
    }
}

impl From<interflow_cli::plan::ApplyReport> for ApplyReportDto {
    fn from(r: interflow_cli::plan::ApplyReport) -> Self {
        Self {
            lines: r.lines,
            generation: u32::try_from(r.generation).unwrap_or(u32::MAX),
        }
    }
}

impl From<interflow_cli::plan::ChangeState> for ChangeStateDto {
    fn from(s: interflow_cli::plan::ChangeState) -> Self {
        match s {
            interflow_cli::plan::ChangeState::NeverApplied => Self::NeverApplied,
            interflow_cli::plan::ChangeState::Applied { generation } => Self::Applied {
                generation: u32::try_from(generation).unwrap_or(u32::MAX),
            },
            interflow_cli::plan::ChangeState::PolicyEditsPending => Self::PolicyEditsPending,
            interflow_cli::plan::ChangeState::IdentityEditsPending => Self::IdentityEditsPending,
            interflow_cli::plan::ChangeState::PackTreeStale => Self::PackTreeStale,
            interflow_cli::plan::ChangeState::WatermarksDiverged => Self::WatermarksDiverged,
        }
    }
}

impl From<interflow_mesh::hub::policy::HubOverview> for HubOverviewDto {
    fn from(o: interflow_mesh::hub::policy::HubOverview) -> Self {
        Self {
            hub: o.hub,
            floor: u32::try_from(o.floor).unwrap_or(u32::MAX),
            serving: o.serving.and_then(|g| u32::try_from(g).ok()),
            captured_at_unix: o.captured_at_unix.and_then(|t| u32::try_from(t).ok()),
            policy_silent_after_secs: u32::try_from(
                interflow_mesh::agent::policy_watch::POLICY_SILENT_AFTER_SECS,
            )
            .unwrap_or(u32::MAX),
            crl_silent_after_secs: u32::try_from(interflow_renewal::CRL_SILENT_AFTER_SECS)
                .unwrap_or(u32::MAX),
            crl_last_success_unix: o.crl_last_success_unix.and_then(|t| u32::try_from(t).ok()),
            crl_failures_total: o.crl_failures_total.and_then(|t| u32::try_from(t).ok()),
            route_breakers_open: o
                .route_breakers_open
                .into_iter()
                .map(|row| RouteBreakerOpenRowDto {
                    host: row.host,
                    opened_unix: u32::try_from(row.opened_unix).unwrap_or(u32::MAX),
                    last_probe_unix: u32::try_from(row.last_probe_unix).unwrap_or(u32::MAX),
                })
                .collect(),
            watchers: o
                .watchers
                .into_iter()
                .map(|row| WatcherFaceRowDto {
                    name: row.name,
                    interval_secs: u32::try_from(row.interval_secs).unwrap_or(u32::MAX),
                    started_unix: u32::try_from(row.started_unix).unwrap_or(u32::MAX),
                    last_tick_unix: u32::try_from(row.last_tick_unix).unwrap_or(u32::MAX),
                })
                .collect(),
            watcher_silent_factor: u32::try_from(
                interflow_mesh::hub::watchdog::WATCHER_SILENT_FACTOR,
            )
            .unwrap_or(u32::MAX),
            proposals_pending: o.proposals_pending.map(|face| ProposalsPendingDto {
                pending_count: face.pending_count,
                oldest_submitted_unix: u32::try_from(face.oldest_submitted_unix)
                    .unwrap_or(u32::MAX),
            }),
            streams_in_flight_total: o
                .streams_in_flight_total
                .and_then(|v| u32::try_from(v).ok()),
            stream_limits: o.stream_limits.map(|limits| StreamLimitsDto {
                total: u32::try_from(limits.total).unwrap_or(u32::MAX),
                per_agent: u32::try_from(limits.per_agent).unwrap_or(u32::MAX),
            }),
            fossil_idle_multiple: u32::try_from(
                interflow_mesh::agent::stream_activity::FOSSIL_IDLE_MULTIPLE,
            )
            .unwrap_or(u32::MAX),
            fossil_unbudgeted_days: u32::try_from(
                interflow_mesh::agent::stream_activity::FOSSIL_UNBUDGETED_DAYS_SECS / 86_400,
            )
            .unwrap_or(u32::MAX),
            headroom_warn_pct: ratio_as_pct(interflow_mesh::hub::routing::HEADROOM_WARN_RATIO),
            offline_warn_days: i32::try_from(interflow_identity::expiry::OFFLINE_WARN_DAYS)
                .unwrap_or(i32::MAX),
            offline_critical_days: i32::try_from(interflow_identity::expiry::OFFLINE_CRITICAL_DAYS)
                .unwrap_or(i32::MAX),
            registrar_warn_pct: ratio_as_pct(interflow_identity::expiry::WARN_RATIO),
            registrar_critical_pct: ratio_as_pct(interflow_identity::expiry::CRITICAL_RATIO),
            agents: o
                .agents
                .into_iter()
                .map(|row| HubAgentRowDto {
                    agent: row.agent,
                    online: row.online,
                    seen: row.seen.and_then(|g| u32::try_from(g).ok()),
                    policy_last_pull_unix: row.last_pull_unix.and_then(|t| u32::try_from(t).ok()),
                    paused_streams: row.paused_streams,
                    maintenance: row.maintenance,
                    crl_last_success_unix: row
                        .crl_last_success_unix
                        .and_then(|t| u32::try_from(t).ok()),
                    crl_failures_total: row.crl_failures_total.and_then(|t| u32::try_from(t).ok()),
                    pending_ops: row.pending_ops.map(|face| MailboxFaceDto {
                        pending_count: face.pending_count,
                        oldest_queued_unix: face
                            .oldest_queued_unix
                            .and_then(|t| u32::try_from(t).ok()),
                        oldest_op: face.oldest_op,
                        dropped_total: u32::try_from(face.dropped_total).unwrap_or(u32::MAX),
                    }),
                    streams_in_flight: row.streams_in_flight.and_then(|t| u32::try_from(t).ok()),
                    streams: row
                        .streams
                        .into_iter()
                        .map(|s| NodeStreamActivityDto {
                            name: s.name,
                            last_byte_unix: u32::try_from(s.last_byte_unix).unwrap_or(u32::MAX),
                            idle_budget_secs: s.idle_budget_secs,
                        })
                        .collect(),
                    leaf_not_before_unix: row
                        .leaf_not_before_unix
                        .and_then(|t| u32::try_from(t).ok()),
                    leaf_not_after_unix: row
                        .leaf_not_after_unix
                        .and_then(|t| u32::try_from(t).ok()),
                    credential_mode: row.credential_mode,
                    credential_last_seen_unix: row
                        .credential_last_seen_unix
                        .and_then(|t| u32::try_from(t).ok()),
                    connection: row.connection.map(|c| ConnectionQualityDto {
                        reconnects_last_hour: c.reconnects_last_hour,
                        rtt_p50_ms: c.rtt_p50_ms.and_then(|v| u32::try_from(v).ok()),
                        rtt_p99_ms: c.rtt_p99_ms.and_then(|v| u32::try_from(v).ok()),
                        rtt_timeouts: c.rtt_timeouts,
                        rtt_samples: c.rtt_samples,
                    }),
                    renewal_backoff_failures: row.renewal_backoff_failures,
                    renewal_backoff_max_today: row.renewal_backoff_max_today,
                })
                .collect(),
        }
    }
}

/// A threshold ratio in `[0, 1]` as the whole percent the chips print.
// Nothing to truncate, no sign to lose on a const ratio in [0, 1] — the
// cast lints cannot see the range.
#[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
fn ratio_as_pct(ratio: f64) -> u32 {
    (ratio * 100.0).round() as u32
}

/// One rendered pack in a `plan apply` output tree (deploy page cards).
#[derive(Debug, Clone, Serialize, Deserialize, specta::Type)]
pub struct DeployPackDto {
    /// Directory name under `<out>/packs/` (e.g. `ingress-edge`) — the
    /// display name.
    pub dir_name: String,
    /// The pack directory's absolute path. The single source of truth for
    /// locating the pack (update/seal/rotate/revoke all take it); the old
    /// `<out>/packs/<dir_name>` frontend join assumed the dist-tree layout
    /// and broke on a bare pack directory or an unpacked zip.
    pub path: String,
    pub kind: NodeKindDto,
    pub node: String,
    /// Rotation generation (u32 on the wire — specta forbids BigInt).
    pub generation: u32,
    /// Content digest (`sha256:…`): differs across same-generation renders,
    /// which is how "update available" catches a re-applied manifest.
    pub digest: String,
    pub expires: String,
    pub principal: String,
    /// One of rotate's `-gen<N>` staging outputs (named by `plan::rotate`
    /// for distribution; kept after the local node consumes it) — the UI
    /// badges these instead of letting them sit visually equal to the
    /// identity's base pack.
    pub is_staging: bool,
    /// The local node added from this pack's identity, if any — the
    /// "update this local node to this generation" hook (P1-2).
    pub local_node: Option<LocalNodeRefDto>,
}

/// A local node matching a dist pack's identity (Deploy page cards).
#[derive(Debug, Clone, Serialize, Deserialize, specta::Type)]
pub struct LocalNodeRefDto {
    pub id: String,
    pub name: String,
    /// Generation of the pack currently in place.
    pub generation: u32,
    /// Content digest of the pack currently in place (display cache from
    /// the node spec, refreshed at every GUI start and every update).
    pub digest: String,
}

/// `deploy_update_node` result: what the swap did plus the refreshed node.
#[derive(Debug, Clone, Serialize, specta::Type)]
pub struct UpdatedNodeDto {
    pub node: NodeInfo,
    pub generation_from: u32,
    pub generation_to: u32,
    /// The node had a running intent and was restarted onto the new pack.
    pub restarted: bool,
}

impl From<crate::deploy::DeployPack> for DeployPackDto {
    fn from(pack: crate::deploy::DeployPack) -> Self {
        Self {
            is_staging: pack.is_staging,
            dir_name: pack.dir_name,
            path: pack.path.display().to_string(),
            kind: pack.kind.into(),
            node: pack.node,
            generation: u32::try_from(pack.generation).unwrap_or(u32::MAX),
            digest: pack.digest,
            expires: pack.expires,
            principal: pack.principal,
            local_node: None,
        }
    }
}

/// Parameters of the manifest template builder (mirrors `interflow-cli setup`).
#[derive(Debug, Clone, Deserialize, specta::Type)]
#[serde(deny_unknown_fields)]
pub struct ManifestTemplateParams {
    pub realm: String,
    pub control_endpoint: String,
    pub registrar_endpoint: String,
    pub host: String,
    pub agent: String,
    pub service: String,
    pub service_address: String,
}

/// Which known retirement a startup notice narrates. The wire tags are the
/// contract (the shell maps them to localized text).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, specta::Type)]
#[serde(rename_all = "snake_case")]
pub enum StartupNoticeKindDto {
    /// Stored preferences exist but this build cannot read them — they were
    /// retired by the upgrade; removing prefs.db starts fresh.
    PrefsRetired,
    /// The remembered deployment folder no longer opens as a deployment —
    /// retired by an upgrade or moved; open a current one or import a node
    /// pack.
    DeploymentGone,
}

/// One startup notice: a known retirement this build narrates instead of
/// silently absorbing. `id` is the stable dismissal key — tied to the
/// format epoch whose retirement produced the notice, so each era
/// notifies exactly once per machine.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, specta::Type)]
pub struct StartupNoticeDto {
    pub id: String,
    pub kind: StartupNoticeKindDto,
}

/// `deploy_install_sealed` result: ready to "add as node".
#[derive(Debug, Clone, Serialize, specta::Type)]
pub struct ImportedPackDto {
    pub pack_dir: String,
    pub inspection: PackInspection,
}

/// Which node kind the issue wizard appends (the agent role split is the
/// wizard's concern; the CLI core only knows agent/ingress/hub).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, specta::Type)]
#[serde(rename_all = "snake_case")]
pub enum IssueNodeKindDto {
    AgentExpose,
    AgentMesh,
    Hub,
    Ingress,
}

/// One service an expose agent dials locally (issue wizard).
#[derive(Debug, Clone, Serialize, Deserialize, specta::Type)]
#[serde(deny_unknown_fields)]
pub struct IssueServiceSpecDto {
    pub id: String,
    pub address: String,
}

/// A listen-side mesh rule (issue wizard).
#[derive(Debug, Clone, Serialize, Deserialize, specta::Type)]
#[serde(deny_unknown_fields)]
pub struct IssueMeshIngressDto {
    pub name: String,
    pub listen: String,
    pub protocol: MeshProtocolDto,
    pub target_agent: String,
    pub remote_addr: String,
}

/// A serve-side mesh rule (issue wizard): exactly one of `target` /
/// `target_cidr`.
#[derive(Debug, Clone, Serialize, Deserialize, specta::Type)]
#[serde(deny_unknown_fields)]
pub struct IssueMeshEgressDto {
    pub name: String,
    pub protocol: MeshProtocolDto,
    pub target: Option<String>,
    pub target_cidr: Option<String>,
}

/// `deploy_add_node` parameters — the GUI twin of `interflow-cli node add`
/// (structured, non-destructive manifest append).
#[derive(Debug, Clone, Deserialize, specta::Type)]
#[serde(deny_unknown_fields)]
pub struct IssueNodeParams {
    pub kind: IssueNodeKindDto,
    pub node: String,
    pub manifest: String,
    pub workspace: Option<String>,
    pub services: Vec<IssueServiceSpecDto>,
    pub mesh_ingress: Vec<IssueMeshIngressDto>,
    pub mesh_egress: Vec<IssueMeshEgressDto>,
    pub ingress_workspaces: Vec<String>,
    pub hub_endpoint: Option<String>,
}

/// `deploy_add_node` result: the rewritten manifest text (feeds the editor
/// so both surfaces stay on the same file) and the pack directory name
/// `plan apply` will render.
#[derive(Debug, Clone, Serialize, specta::Type)]
pub struct AddedNodeDto {
    pub manifest_text: String,
    pub pack_dir_name: String,
}

/// `deploy_seal_to_downloads` result: where the sealed pack landed plus the
/// passphrase it was sealed with (the wizard shows it exactly once).
#[derive(Debug, Clone, Serialize, specta::Type)]
pub struct SealedPackDto {
    pub path: String,
    pub passphrase: String,
}

// ---------------------------------------------------------------------------
// Manifest form editor — the read model (a projection of the document) and
// the edit vocabulary (complete desired states; see interflow_cli::
// manifest_edit for the document model). One document, two views: these
// DTOs carry what the Form view renders and what it submits — never a
// second copy of the document itself.
// ---------------------------------------------------------------------------

/// How the ingress terminates public HTTPS (wire form of manifest
/// `PublicTlsMode`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, specta::Type)]
#[serde(rename_all = "kebab-case")]
pub enum PublicTlsModeDto {
    Acme,
    FrontendProxy,
    Manual,
}

impl From<interflow_identity::manifest::PublicTlsMode> for PublicTlsModeDto {
    fn from(mode: interflow_identity::manifest::PublicTlsMode) -> Self {
        use interflow_identity::manifest::PublicTlsMode;
        match mode {
            PublicTlsMode::Acme => Self::Acme,
            PublicTlsMode::FrontendProxy => Self::FrontendProxy,
            PublicTlsMode::Manual => Self::Manual,
        }
    }
}

impl From<PublicTlsModeDto> for interflow_identity::manifest::PublicTlsMode {
    fn from(mode: PublicTlsModeDto) -> Self {
        match mode {
            PublicTlsModeDto::Acme => Self::Acme,
            PublicTlsModeDto::FrontendProxy => Self::FrontendProxy,
            PublicTlsModeDto::Manual => Self::Manual,
        }
    }
}

/// Which identity tier a deployment runs (wire form of manifest
/// `IdentityMode`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, specta::Type)]
#[serde(rename_all = "lowercase")]
pub enum IdentityModeDto {
    Registrar,
    Offline,
}

impl From<interflow_identity::manifest::IdentityMode> for IdentityModeDto {
    fn from(mode: interflow_identity::manifest::IdentityMode) -> Self {
        use interflow_identity::manifest::IdentityMode;
        match mode {
            IdentityMode::Registrar => Self::Registrar,
            IdentityMode::Offline => Self::Offline,
        }
    }
}

impl From<IdentityModeDto> for interflow_identity::manifest::IdentityMode {
    fn from(mode: IdentityModeDto) -> Self {
        match mode {
            IdentityModeDto::Registrar => Self::Registrar,
            IdentityModeDto::Offline => Self::Offline,
        }
    }
}

impl From<MeshProtocolDto> for MeshProtocol {
    fn from(protocol: MeshProtocolDto) -> Self {
        match protocol {
            MeshProtocolDto::Tcp => Self::Tcp,
            MeshProtocolDto::Udp => Self::Udp,
        }
    }
}

/// The identity tier's `leaf_ttl` bounds and default as display text —
/// computed from the issuance constants, so the form's hint and the
/// validator's裁决 can never disagree.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, specta::Type)]
pub struct LeafTtlBoundsDto {
    pub min: String,
    pub max: String,
    pub default: String,
}

impl From<interflow_cli::manifest_edit::LeafTtlBounds> for LeafTtlBoundsDto {
    fn from(bounds: interflow_cli::manifest_edit::LeafTtlBounds) -> Self {
        Self {
            min: bounds.min,
            max: bounds.max,
            default: bounds.default,
        }
    }
}

/// Which pack role an agent plays (`Mixed`/`Empty` occur only in documents
/// the validation funnel rejects).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, specta::Type)]
#[serde(rename_all = "lowercase")]
pub enum AgentRoleDto {
    Expose,
    Mesh,
    Mixed,
    Empty,
}

impl From<interflow_cli::manifest_edit::AgentRole> for AgentRoleDto {
    fn from(role: interflow_cli::manifest_edit::AgentRole) -> Self {
        use interflow_cli::manifest_edit::AgentRole;
        match role {
            AgentRole::Expose => Self::Expose,
            AgentRole::Mesh => Self::Mesh,
            AgentRole::Mixed => Self::Mixed,
            AgentRole::Empty => Self::Empty,
        }
    }
}

/// `[realm]` as the form sees it (empty `control_endpoint` = site-to-site
/// only).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, specta::Type)]
pub struct RealmDto {
    pub id: String,
    pub control_endpoint: String,
}

/// `[public_tls]` as the form sees it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, specta::Type)]
pub struct PublicTlsDto {
    pub mode: PublicTlsModeDto,
    pub email: Option<String>,
    pub directory: Option<String>,
}

/// The identity tier as the form sees it — mode, leaf TTL, and the tier's
/// bounds in one place (the bounds re-derive with the mode).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, specta::Type)]
pub struct IdentityDto {
    pub mode: IdentityModeDto,
    pub leaf_ttl: Option<String>,
    pub leaf_ttl_bounds: LeafTtlBoundsDto,
    /// The registrar endpoint when the tier has one (registrar mode).
    pub registrar_endpoint: String,
}

/// One `[[agent.<node>.services]]` entry.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, specta::Type)]
pub struct ManifestServiceDto {
    pub id: String,
    pub address: String,
}

/// One `[[agent.<node>.mesh_ingress]]` rule with every field (u32 on the
/// wire — specta forbids BigInt, and the timeout ceiling is 86400).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, specta::Type)]
pub struct ManifestIngressRuleDto {
    pub name: String,
    pub listen: String,
    pub protocol: MeshProtocolDto,
    pub target_agent: String,
    pub remote_addr: String,
    pub idle_timeout_secs: Option<u32>,
}

/// One `[[agent.<node>.mesh_egress]]` rule; exactly one of `target_addr` /
/// `target_cidr` is set.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, specta::Type)]
pub struct ManifestEgressRuleDto {
    pub name: String,
    pub protocol: MeshProtocolDto,
    pub target_addr: Option<String>,
    pub target_cidr: Option<String>,
    pub udp_idle_timeout_secs: Option<u32>,
}

/// One agent node as the form sees it — identity (name, workspace), role,
/// and the role's content.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, specta::Type)]
pub struct AgentSummaryDto {
    pub node: String,
    pub workspace: String,
    pub role: AgentRoleDto,
    /// Dial transport the manifest pins for this agent (expose agents;
    /// `None` = the h2 default). The node's signed pack default.
    pub transport: Option<Transport>,
    pub services: Vec<ManifestServiceDto>,
    pub mesh_ingress: Vec<ManifestIngressRuleDto>,
    pub mesh_egress: Vec<ManifestEgressRuleDto>,
}

/// One `[ingress.<node>]` (public entry point); `edge_rate` `None` = no
/// `[edge]` overrides.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, specta::Type)]
pub struct IngressNodeDto {
    pub node: String,
    pub workspaces: Vec<String>,
    pub listen: String,
    pub control_listen: String,
    /// Control endpoint's QUIC (UDP) listen address; `None` = the QUIC
    /// transport is off.
    pub quic_listen: Option<String>,
    pub edge_rate_per_ip_per_minute: Option<u32>,
}

/// One `[[route]]`: public host → service identity.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, specta::Type)]
pub struct RouteDto {
    pub host: String,
    pub service: String,
}

/// One `[mesh.hub.<name>]`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, specta::Type)]
pub struct HubDto {
    pub name: String,
    pub listen: String,
    /// The hub's QUIC (UDP) face; `None` = the QUIC transport stays off.
    pub quic_listen: Option<String>,
    pub endpoint: String,
}

/// The whole manifest as the Form view renders it — a projection of the
/// parsed document (every schema field, by construction), with validation
/// issues attached. `issues` empty ⇔ applyable.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, specta::Type)]
pub struct ManifestSummaryDto {
    pub realm: RealmDto,
    pub public_tls: PublicTlsDto,
    pub identity: IdentityDto,
    pub workspaces: Vec<String>,
    pub agents: Vec<AgentSummaryDto>,
    pub ingress: Vec<IngressNodeDto>,
    pub routes: Vec<RouteDto>,
    pub hubs: Vec<HubDto>,
    pub issues: Vec<String>,
}

impl From<interflow_cli::manifest_edit::ManifestSummary> for ManifestSummaryDto {
    fn from(summary: interflow_cli::manifest_edit::ManifestSummary) -> Self {
        // u32 on the wire (specta forbids BigInt); the timeout ceiling is
        // 86400, so the clamp never engages on real values.
        fn narrow(value: u64) -> u32 {
            u32::try_from(value).unwrap_or(u32::MAX)
        }
        let manifest = summary.manifest;
        let agents = manifest
            .agent
            .iter()
            .map(|(node, agent)| AgentSummaryDto {
                node: node.clone(),
                workspace: agent.workspace.clone(),
                role: summary
                    .agent_roles
                    .get(node)
                    .copied()
                    .map_or(AgentRoleDto::Empty, Into::into),
                transport: agent.transport.map(Into::into),
                services: agent
                    .services
                    .iter()
                    .map(|s| ManifestServiceDto {
                        id: s.id.clone(),
                        address: s.address.clone(),
                    })
                    .collect(),
                mesh_ingress: agent
                    .mesh_ingress
                    .iter()
                    .map(|r| ManifestIngressRuleDto {
                        name: r.name.clone(),
                        listen: r.listen.clone(),
                        protocol: r.protocol.into(),
                        target_agent: r.target_agent.clone(),
                        remote_addr: r.remote_addr.clone(),
                        idle_timeout_secs: r.idle_timeout_secs.map(narrow),
                    })
                    .collect(),
                mesh_egress: agent
                    .mesh_egress
                    .iter()
                    .map(|r| ManifestEgressRuleDto {
                        name: r.name.clone(),
                        protocol: r.protocol.into(),
                        target_addr: r.target_addr.clone(),
                        target_cidr: r.target_cidr.clone(),
                        udp_idle_timeout_secs: r.udp_idle_timeout_secs.map(narrow),
                    })
                    .collect(),
            })
            .collect();
        Self {
            realm: RealmDto {
                id: manifest.realm.id.clone(),
                control_endpoint: manifest.realm.control_endpoint.clone(),
            },
            public_tls: PublicTlsDto {
                mode: manifest.public_tls.mode.into(),
                email: manifest.public_tls.email.clone(),
                directory: manifest.public_tls.directory.clone(),
            },
            identity: IdentityDto {
                mode: manifest.identity.mode.into(),
                leaf_ttl: manifest.identity.leaf_ttl.clone(),
                leaf_ttl_bounds: summary.leaf_ttl.into(),
                registrar_endpoint: manifest.registrar.endpoint.clone(),
            },
            workspaces: manifest.workspace.keys().cloned().collect(),
            agents,
            ingress: manifest
                .ingress
                .iter()
                .map(|(node, ingress)| IngressNodeDto {
                    node: node.clone(),
                    workspaces: ingress.workspaces.clone(),
                    listen: ingress.listen.clone(),
                    control_listen: ingress.control_listen.clone(),
                    quic_listen: ingress.quic_listen.clone(),
                    edge_rate_per_ip_per_minute: ingress
                        .edge
                        .as_ref()
                        .and_then(|edge| edge.new_conn_rate_per_ip_per_minute),
                })
                .collect(),
            routes: manifest
                .route
                .iter()
                .map(|route| RouteDto {
                    host: route.host.clone(),
                    service: route.service.clone(),
                })
                .collect(),
            hubs: manifest
                .mesh
                .hub
                .iter()
                .map(|(name, hub)| HubDto {
                    name: name.clone(),
                    listen: hub.listen.clone(),
                    quic_listen: hub.quic_listen.clone(),
                    endpoint: hub.endpoint.clone(),
                })
                .collect(),
            issues: summary.issues,
        }
    }
}

// --- Edits: what the form submits (complete desired states) ---------------

/// `[realm]`.
#[derive(Debug, Clone, Deserialize, specta::Type)]
#[serde(deny_unknown_fields)]
pub struct RealmEditDto {
    pub id: String,
    /// Empty = absent (site-to-site-only realm).
    pub control_endpoint: String,
}

/// `[public_tls]`.
#[derive(Debug, Clone, Deserialize, specta::Type)]
#[serde(deny_unknown_fields)]
pub struct PublicTlsEditDto {
    pub mode: PublicTlsModeDto,
    pub email: Option<String>,
    pub directory: Option<String>,
}

/// The identity tier — one atomic decision (mode + leaf TTL + the
/// registrar endpoint that registrar mode demands and offline mode
/// forbids).
#[derive(Debug, Clone, Deserialize, specta::Type)]
#[serde(deny_unknown_fields)]
pub struct IdentityEditDto {
    pub mode: IdentityModeDto,
    pub leaf_ttl: Option<String>,
    pub registrar_endpoint: Option<String>,
}

/// `[mesh.hub.<name>]`.
#[derive(Debug, Clone, Deserialize, specta::Type)]
#[serde(deny_unknown_fields)]
pub struct HubEditDto {
    pub name: String,
    pub endpoint: String,
    /// Empty/`None` = the default listen (`0.0.0.0:6666`).
    pub listen: Option<String>,
    /// The hub's QUIC (UDP) listen address; blank/`None` keeps the QUIC
    /// transport off.
    pub quic_listen: Option<String>,
}

/// `[ingress.<node>]`.
#[derive(Debug, Clone, Deserialize, specta::Type)]
#[serde(deny_unknown_fields)]
pub struct IngressEditDto {
    pub node: String,
    pub workspaces: Vec<String>,
    pub listen: Option<String>,
    pub control_listen: Option<String>,
    /// Blank/`None` keeps the QUIC transport off.
    pub quic_listen: Option<String>,
    pub edge_rate_per_ip_per_minute: Option<u32>,
}

/// One service entry on an agent.
#[derive(Debug, Clone, Deserialize, specta::Type)]
#[serde(deny_unknown_fields)]
pub struct ServiceEditDto {
    pub agent: String,
    pub id: String,
    pub address: String,
}

/// One listen-side mesh rule.
#[derive(Debug, Clone, Deserialize, specta::Type)]
#[serde(deny_unknown_fields)]
pub struct MeshIngressEditDto {
    pub agent: String,
    pub name: String,
    pub listen: String,
    pub protocol: MeshProtocolDto,
    pub target_agent: String,
    pub remote_addr: String,
    pub idle_timeout_secs: Option<u32>,
}

/// One serve-side mesh rule.
#[derive(Debug, Clone, Deserialize, specta::Type)]
#[serde(deny_unknown_fields)]
pub struct MeshEgressEditDto {
    pub agent: String,
    pub name: String,
    pub protocol: MeshProtocolDto,
    pub target_addr: Option<String>,
    pub target_cidr: Option<String>,
    pub udp_idle_timeout_secs: Option<u32>,
}

/// One public route.
#[derive(Debug, Clone, Deserialize, specta::Type)]
#[serde(deny_unknown_fields)]
pub struct RouteEditDto {
    pub host: String,
    pub service: String,
}

/// Whole-node creation with role content — the same append the issue
/// wizard performs, minus the wizard's paths (the document being edited is
/// the target). Shape mirrors [`IssueNodeParams`].
#[derive(Debug, Clone, Deserialize, specta::Type)]
#[serde(deny_unknown_fields)]
pub struct CreateNodeDto {
    pub kind: IssueNodeKindDto,
    pub node: String,
    pub workspace: Option<String>,
    pub services: Vec<IssueServiceSpecDto>,
    pub mesh_ingress: Vec<IssueMeshIngressDto>,
    pub mesh_egress: Vec<IssueMeshEgressDto>,
    pub ingress_workspaces: Vec<String>,
    pub hub_endpoint: Option<String>,
}

/// One structured manifest edit — the Form view's whole submission
/// vocabulary (wire form of `manifest_edit::ManifestEdit`).
#[derive(Debug, Clone, Deserialize, specta::Type)]
pub enum EditActionDto {
    SetRealm(RealmEditDto),
    SetPublicTls(PublicTlsEditDto),
    SetIdentity(IdentityEditDto),
    UpsertWorkspace(String),
    RemoveWorkspace(String),
    UpsertHub(HubEditDto),
    RemoveHub(String),
    UpsertIngress(IngressEditDto),
    RemoveIngress(String),
    CreateNode(CreateNodeDto),
    SetAgentWorkspace {
        agent: String,
        workspace: String,
    },
    /// `transport: None` returns the agent to the h2 default.
    SetAgentTransport {
        agent: String,
        transport: Option<Transport>,
    },
    RemoveAgent(String),
    UpsertService(ServiceEditDto),
    RemoveService {
        agent: String,
        id: String,
    },
    UpsertMeshIngress(MeshIngressEditDto),
    RemoveMeshIngress {
        agent: String,
        name: String,
    },
    /// In-place rename (position, decor, comments preserved); the taken /
    /// missing / blank-name rejections ride the valid→valid funnel.
    RenameMeshIngress {
        agent: String,
        from: String,
        to: String,
    },
    UpsertMeshEgress(MeshEgressEditDto),
    RemoveMeshEgress {
        agent: String,
        name: String,
    },
    RenameMeshEgress {
        agent: String,
        from: String,
        to: String,
    },
    /// Service rename with the `[[route]]` cascade (refs follow the id).
    RenameService {
        agent: String,
        from: String,
        to: String,
    },
    UpsertRoute(RouteEditDto),
    RemoveRoute {
        host: String,
    },
}

impl From<EditActionDto> for interflow_cli::manifest_edit::ManifestEdit {
    fn from(action: EditActionDto) -> Self {
        use interflow_cli::manifest_edit::{
            AddMeshEgressSpec, AddMeshIngressSpec, AddNodeKind, AddNodeSpec, AddServiceSpec,
            HubEdit, IdentityEdit, IngressEdit, MeshEgressEdit, MeshIngressEdit, PublicTlsEdit,
            RealmEdit, RouteEdit, ServiceEdit,
        };
        match action {
            EditActionDto::SetRealm(edit) => Self::SetRealm(RealmEdit {
                id: edit.id,
                control_endpoint: edit.control_endpoint,
            }),
            EditActionDto::SetPublicTls(edit) => Self::SetPublicTls(PublicTlsEdit {
                mode: edit.mode.into(),
                email: edit.email,
                directory: edit.directory,
            }),
            EditActionDto::SetIdentity(edit) => Self::SetIdentity(IdentityEdit {
                mode: edit.mode.into(),
                leaf_ttl: edit.leaf_ttl,
                registrar_endpoint: edit.registrar_endpoint,
            }),
            EditActionDto::UpsertWorkspace(name) => Self::UpsertWorkspace(name),
            EditActionDto::RemoveWorkspace(name) => Self::RemoveWorkspace(name),
            EditActionDto::UpsertHub(edit) => Self::UpsertHub(HubEdit {
                name: edit.name,
                endpoint: edit.endpoint,
                listen: edit.listen,
                quic_listen: edit.quic_listen,
            }),
            EditActionDto::RemoveHub(name) => Self::RemoveHub(name),
            EditActionDto::UpsertIngress(edit) => Self::UpsertIngress(IngressEdit {
                node: edit.node,
                workspaces: edit.workspaces,
                listen: edit.listen,
                control_listen: edit.control_listen,
                quic_listen: edit.quic_listen,
                edge_rate_per_ip_per_minute: edit.edge_rate_per_ip_per_minute,
            }),
            EditActionDto::RemoveIngress(node) => Self::RemoveIngress(node),
            EditActionDto::CreateNode(spec) => Self::AddNode(AddNodeSpec {
                kind: match spec.kind {
                    IssueNodeKindDto::AgentExpose | IssueNodeKindDto::AgentMesh => {
                        AddNodeKind::Agent
                    }
                    IssueNodeKindDto::Hub => AddNodeKind::Hub,
                    IssueNodeKindDto::Ingress => AddNodeKind::Ingress,
                },
                node: spec.node,
                workspace: spec.workspace,
                services: spec
                    .services
                    .into_iter()
                    .map(|s| AddServiceSpec {
                        id: s.id,
                        address: s.address,
                    })
                    .collect(),
                mesh_ingress: spec
                    .mesh_ingress
                    .into_iter()
                    .map(|r| AddMeshIngressSpec {
                        name: r.name,
                        listen: r.listen,
                        udp: matches!(r.protocol, MeshProtocolDto::Udp),
                        target_agent: r.target_agent,
                        remote_addr: r.remote_addr,
                        idle_timeout_secs: None,
                    })
                    .collect(),
                mesh_egress: spec
                    .mesh_egress
                    .into_iter()
                    .map(|r| AddMeshEgressSpec {
                        name: r.name,
                        udp: matches!(r.protocol, MeshProtocolDto::Udp),
                        target_addr: r.target.filter(|s| !s.trim().is_empty()),
                        target_cidr: r.target_cidr.filter(|s| !s.trim().is_empty()),
                    })
                    .collect(),
                ingress_workspaces: spec.ingress_workspaces,
                hub_endpoint: spec.hub_endpoint,
            }),
            EditActionDto::SetAgentWorkspace { agent, workspace } => {
                Self::SetAgentWorkspace { agent, workspace }
            }
            EditActionDto::SetAgentTransport { agent, transport } => Self::SetAgentTransport {
                agent,
                transport: transport.map(|t| {
                    use interflow_identity::manifest::AgentTransport;
                    match t {
                        Transport::H2 => AgentTransport::H2,
                        Transport::Quic => AgentTransport::Quic,
                    }
                }),
            },
            EditActionDto::RemoveAgent(node) => Self::RemoveAgent(node),
            EditActionDto::UpsertService(edit) => Self::UpsertService(ServiceEdit {
                agent: edit.agent,
                id: edit.id,
                address: edit.address,
            }),
            EditActionDto::RemoveService { agent, id } => Self::RemoveService { agent, id },
            EditActionDto::UpsertMeshIngress(edit) => Self::UpsertMeshIngress(MeshIngressEdit {
                agent: edit.agent,
                name: edit.name,
                listen: edit.listen,
                protocol: edit.protocol.into(),
                target_agent: edit.target_agent,
                remote_addr: edit.remote_addr,
                idle_timeout_secs: edit.idle_timeout_secs.map(u64::from),
            }),
            EditActionDto::RemoveMeshIngress { agent, name } => {
                Self::RemoveMeshIngress { agent, name }
            }
            EditActionDto::RenameMeshIngress { agent, from, to } => {
                Self::RenameMeshIngress { agent, from, to }
            }
            EditActionDto::UpsertMeshEgress(edit) => Self::UpsertMeshEgress(MeshEgressEdit {
                agent: edit.agent,
                name: edit.name,
                protocol: edit.protocol.into(),
                target_addr: edit.target_addr,
                target_cidr: edit.target_cidr,
                udp_idle_timeout_secs: edit.udp_idle_timeout_secs.map(u64::from),
            }),
            EditActionDto::RemoveMeshEgress { agent, name } => {
                Self::RemoveMeshEgress { agent, name }
            }
            EditActionDto::RenameMeshEgress { agent, from, to } => {
                Self::RenameMeshEgress { agent, from, to }
            }
            EditActionDto::RenameService { agent, from, to } => {
                Self::RenameService { agent, from, to }
            }
            EditActionDto::UpsertRoute(edit) => Self::UpsertRoute(RouteEdit {
                host: edit.host,
                service: edit.service,
            }),
            EditActionDto::RemoveRoute { host } => Self::RemoveRoute { host },
        }
    }
}

/// `deploy_edit_manifest` result: the rewritten document text (the editor's
/// new state) and its read model in one round trip — the form re-renders
/// from what the edit actually produced, never from a client-side guess.
#[derive(Debug, Clone, Serialize, specta::Type)]
pub struct EditedManifestDto {
    pub text: String,
    pub summary: ManifestSummaryDto,
}

/// Parameters of the site-to-site (mesh) starter template (mirrors
/// `interflow-cli setup --face mesh`).
#[derive(Debug, Clone, Deserialize, specta::Type)]
#[serde(deny_unknown_fields)]
pub struct MeshTemplateParams {
    pub realm: String,
    pub hub_name: String,
    pub hub_endpoint: String,
}

/// One remembered deployment context (manifest/issuer/out travel as a
/// triple — mixing faces' paths is the confusion this kills).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, specta::Type)]
pub struct DeployContextDto {
    pub manifest: String,
    pub issuer: String,
    pub out: String,
}

/// `deploy_defaults` payload: the deployments root — one deployment = one
/// realm-named folder under it, with the fixed inner layout
/// `interflow.toml` / `issuer/` / `dist/`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, specta::Type)]
pub struct DeployDefaultsDto {
    /// Absolute deployments root (home-based, e.g. `~/interflow-deployments`).
    pub root: String,
}

/// `deploy_read_text` payload: the document text plus its freshness token
/// (sha256 of the bytes on disk). Saving hands the token back; a mismatch
/// is a conflict, never a silent overwrite.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, specta::Type)]
pub struct DeployTextDto {
    pub text: String,
    pub digest: String,
}

/// `deploy_write_text` outcome. `Conflict` carries the CURRENT on-disk
/// document so the editor's reload-or-keep choice needs no second round
/// trip — the other writer's edit is already in the payload.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, specta::Type)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum SaveManifestOutcomeDto {
    Saved {
        /// The freshness token of what was just written — the next save's
        /// expected digest.
        digest: String,
    },
    Conflict {
        /// What the disk holds now (the winning writer's version).
        text: String,
        /// Its freshness token — adopting the disk version adopts this.
        digest: String,
    },
}

/// `deploy_prefs_load/save` payload: the recent deployment contexts, most
/// recent first.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize, specta::Type)]
pub struct DeployPrefsDto {
    pub recent: Vec<DeployContextDto>,
}

/// This build's identity (machine header): crate version plus the
/// compile-time build tag the engine binaries also log at startup —
/// what the GUI shows is what a log line prints, so the two name the
/// same build without translation.
#[derive(Debug, Clone, Serialize, specta::Type)]
pub struct VersionInfo {
    /// Workspace crate version (e.g. `0.4.0`).
    pub version: String,
    /// `<commit-date>_<git-short-hash>[-dirty]` — the one build tag every
    /// Interflow surface prints.
    pub build_tag: String,
    /// The working tree had uncommitted changes when this binary was
    /// built: the tag names a commit the binary only partially matches.
    /// Surfaced visually (amber), not just as a suffix — a dirty build on
    /// a remote machine must not be mistaken for the named commit.
    pub dirty: bool,
}

/// The GUI's interface language (wire form of `gui_prefs::Lang`; English
/// is the default, Chinese is opt-in from the header switch).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, specta::Type)]
#[serde(rename_all = "lowercase")]
pub enum GuiLanguageDto {
    En,
    Zh,
}

impl From<crate::gui_prefs::Lang> for GuiLanguageDto {
    fn from(lang: crate::gui_prefs::Lang) -> Self {
        match lang {
            crate::gui_prefs::Lang::En => Self::En,
            crate::gui_prefs::Lang::Zh => Self::Zh,
        }
    }
}

impl From<GuiLanguageDto> for crate::gui_prefs::Lang {
    fn from(lang: GuiLanguageDto) -> Self {
        match lang {
            GuiLanguageDto::En => Self::En,
            GuiLanguageDto::Zh => Self::Zh,
        }
    }
}

/// `gui_prefs_load` payload: GUI-wide preferences. The language is shared
/// with the Rust-rendered surfaces (tray, user-facing command errors), so
/// one switch flips every surface at once.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, specta::Type)]
pub struct GuiPrefsDto {
    pub language: GuiLanguageDto,
    /// The deployment the app opens into (root folder path); `None` on
    /// first run. Round-trips whole so a language switch never drops it.
    pub current_deployment: Option<String>,
}

/// `node-state` event payload: which node transitioned to what.
#[derive(Debug, Clone, Serialize, Deserialize, specta::Type, tauri_specta::Event)]
#[tauri_specta(event_name = "node-state")]
pub struct NodeStateEvent {
    pub id: String,
    pub state: NodeStateDto,
}

/// `policy-plane` event payload: a running mesh agent's policy telemetry
/// moved (engine watcher → manager forwarder → here). The health panel
/// patches its node's `policy` field from these, so it tracks the engine's
/// live watermark and pull health instead of freezing on whatever
/// `list_nodes` happened to return at node start
#[derive(Debug, Clone, Serialize, Deserialize, specta::Type, tauri_specta::Event)]
#[tauri_specta(event_name = "policy-plane")]
pub struct PolicyPlaneEvent {
    pub id: String,
    pub plane: PolicyPlaneDto,
}

/// `mesh-peers` event payload: a running mesh agent's peer telemetry moved
/// (engine peer watcher → manager forwarder → here). The node detail's
/// Peers section patches its node's `peers` field from these — same
/// push-not-poll contract as [`PolicyPlaneEvent`].
#[derive(Debug, Clone, Serialize, Deserialize, specta::Type, tauri_specta::Event)]
#[tauri_specta(event_name = "mesh-peers")]
pub struct MeshPeersEvent {
    pub id: String,
    pub peers: PeersPlaneDto,
}

/// `mesh-proposals` event payload: a running mesh agent's proposal
/// receipts moved (engine watcher → manager forwarder → here). The node
/// detail's "Requested streams" section patches its node's `proposals`
/// from these.
#[derive(Debug, Clone, Serialize, Deserialize, specta::Type, tauri_specta::Event)]
#[tauri_specta(event_name = "mesh-proposals")]
pub struct MeshProposalsEvent {
    pub id: String,
    pub proposals: Vec<ProposalReceiptDto>,
}

/// `mesh-crl` event payload: a running node's CRL-poll liveness level
/// moved (renewal loop atomics → ticking forwarder → here). The node
/// detail's "CRL polling" panel patches its node's `crl` field from
/// these — same push-not-poll contract as [`MeshPeersEvent`]; the local
/// half of the 2026-10-19 liveness face (fleet rows come from the hub's
/// floor face instead).
#[derive(Debug, Clone, Serialize, Deserialize, specta::Type, tauri_specta::Event)]
#[tauri_specta(event_name = "mesh-crl")]
pub struct MeshCrlEvent {
    pub id: String,
    pub crl: CrlPollPlaneDto,
}

/// `mesh-breakers` event payload: a running mesh agent's egress-breaker
/// open set moved (table publish → manager forwarder → here). The node
/// detail's "Egress breakers" panel patches its node's `breakers` from
/// these.
#[derive(Debug, Clone, Serialize, Deserialize, specta::Type, tauri_specta::Event)]
#[tauri_specta(event_name = "mesh-breakers")]
pub struct MeshBreakersEvent {
    pub id: String,
    pub breakers: Vec<BreakerOpenRowDto>,
}

/// `mesh-listeners` event payload: a running mesh agent's ingress-listener
/// actual state moved (engine reconciler → manager forwarder → here). The
/// node card's listener badge and the detail's Health section patch their
/// node's `listeners` from these — a bind failure mid-flight surfaces
/// immediately, not at the next `list_nodes` (same push-not-poll contract
/// as [`MeshPeersEvent`]; the 2026-10-09 honesty axis).
#[derive(Debug, Clone, Serialize, Deserialize, specta::Type, tauri_specta::Event)]
#[tauri_specta(event_name = "mesh-listeners")]
pub struct MeshListenersEvent {
    pub id: String,
    pub listeners: Vec<ListenerStatusDto>,
}

/// `hub-floor` event payload: the deployment's hub floor version advanced
/// (hub floor watcher → here). The composed fleet read model is a pull
/// over `/policy/floor`; this event is its invalidation signal — the
/// deployment scope re-pulls on receipt, so external writers (a CLI
/// pause/resume, a maintenance declaration, another operator's publish,
/// an agent's re-report) reach every fleet-reading view the moment the
/// hub's face moves, not at the next manual refresh
#[derive(Debug, Clone, Serialize, Deserialize, specta::Type, tauri_specta::Event)]
#[tauri_specta(event_name = "hub-floor")]
pub struct HubFloorEvent {
    /// The hub's floor version at the advance (diagnostics; the payload
    /// stays with the floor endpoint — narrowed u64 → u32 per the
    /// BigInt-ban contract rule).
    pub version: u32,
}

/// `log` event payload (tracing capture pump → frontend log panel).
#[derive(Debug, Clone, Serialize, Deserialize, specta::Type, tauri_specta::Event)]
#[tauri_specta(event_name = "log")]
pub struct LogEvent(pub crate::tracing_capture::LogLine);

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    /// The DTO's serde form must stay identical to the domain enum's — the
    /// TS contract and the runtime JSON are both derived from it.
    #[test]
    fn transport_wire_form_matches_mesh() {
        assert_eq!(serde_json::to_string(&Transport::H2).unwrap(), r#""h2""#);
        assert_eq!(
            serde_json::to_string(&Transport::Quic).unwrap(),
            r#""quic""#
        );
        assert_eq!(
            serde_json::to_string(&TransportKind::H2).unwrap(),
            serde_json::to_string(&Transport::H2).unwrap()
        );
    }

    /// The inspection carries the pack's signed transport default through to
    /// the wire (the add dialog's transport control starts from it — the
    /// 2026-09-29 bug was exactly this field not existing).
    #[test]
    fn pack_inspection_carries_the_signed_transport_default() {
        let inspection = |transport: Option<&str>| {
            PackInspection::from(crate::node::PackInfo {
                kind: crate::node::NodeKind::MeshAgent,
                name: "lan-a".into(),
                principal: "promptcn/-/agent/lan-a".into(),
                generation: 1,
                digest: "sha256:abc".into(),
                control_endpoint: "hub.invalid:443".into(),
                services: Vec::new(),
                mesh: None,
                listen: None,
                transport: transport.map(str::to_string),
                credential: None,
            })
        };
        assert_eq!(inspection(Some("quic")).transport, Some(Transport::Quic));
        assert_eq!(inspection(None).transport, None);
        // "h2" and anything unexpected both map to the default (None), the
        // same fold as NodeInfo::pack_transport.
        assert_eq!(inspection(Some("h2")).transport, None);
        assert_eq!(inspection(Some("bogus")).transport, None);
    }

    /// Node states serialize to the externally-tagged wire form the
    /// frontend matches on.
    #[test]
    fn node_state_wire_form() {
        assert_eq!(
            serde_json::to_string(&NodeStateDto::Running).unwrap(),
            r#""Running""#
        );
        assert_eq!(
            serde_json::to_string(&NodeStateDto::Connected {
                agent_id: "expose-mac".into(),
                hub_receipt: None,
            })
            .unwrap(),
            r#"{"Connected":{"agent_id":"expose-mac"}}"#
        );
        // The hub receipt rides along when present (skip-when-none keeps the
        // old consumers' shape).
        assert_eq!(
            serde_json::to_string(&NodeStateDto::Connected {
                agent_id: "expose-mac".into(),
                hub_receipt: Some(HubReceiptDto {
                    egress_ip: Some("203.0.113.7".into()),
                    registered_at_unix: 1_759_171_200,
                }),
            })
            .unwrap(),
            r#"{"Connected":{"agent_id":"expose-mac","hub_receipt":{"egress_ip":"203.0.113.7","registered_at_unix":1759171200}}}"#
        );
    }

    /// Every `ChangeState` variant maps through the `From` layer to its
    /// exact wire tag — the three faces' anchor: the CLI enum
    /// (`interflow_cli::plan::ChangeState`, classified by the SAME fork
    /// decision apply executes), this DTO's wire form (what the frontend
    /// receives), and the TS union (held fresh by `bindings_ts_is_fresh`,
    /// exhaustively switched by `changeStateLabel`). A new CLI variant
    /// fails to compile here until the whole chain carries it.
    #[test]
    fn change_state_dto_wire_tags_are_exhaustive_and_stable() {
        let wire = |s: interflow_cli::plan::ChangeState| {
            serde_json::to_string(&ChangeStateDto::from(s)).unwrap()
        };
        assert_eq!(
            wire(interflow_cli::plan::ChangeState::NeverApplied),
            r#"{"kind":"never_applied"}"#
        );
        assert_eq!(
            wire(interflow_cli::plan::ChangeState::Applied { generation: 7 }),
            r#"{"kind":"applied","generation":7}"#
        );
        assert_eq!(
            wire(interflow_cli::plan::ChangeState::PolicyEditsPending),
            r#"{"kind":"policy_edits_pending"}"#
        );
        assert_eq!(
            wire(interflow_cli::plan::ChangeState::IdentityEditsPending),
            r#"{"kind":"identity_edits_pending"}"#
        );
        assert_eq!(
            wire(interflow_cli::plan::ChangeState::PackTreeStale),
            r#"{"kind":"pack_tree_stale"}"#
        );
        assert_eq!(
            wire(interflow_cli::plan::ChangeState::WatermarksDiverged),
            r#"{"kind":"watermarks_diverged"}"#
        );
    }

    /// The startup-notice wire shape is the shell's dismissal contract: the
    /// `kind` tags are stable spellings, and the epoch-suffixed `id` is
    /// what the localStorage dismissal keys on — a re-spelled tag or a
    /// missing field would silently re-notify (or never notify) every
    /// machine that lived through a retirement.
    #[test]
    fn startup_notice_wire_tags_are_exhaustive_and_stable() {
        let prefs_retired = StartupNoticeDto {
            id: "prefs-retired@3".to_owned(),
            kind: StartupNoticeKindDto::PrefsRetired,
        };
        assert_eq!(
            serde_json::to_string(&prefs_retired).unwrap(),
            r#"{"id":"prefs-retired@3","kind":"prefs_retired"}"#
        );
        let deployment_gone = StartupNoticeDto {
            id: "deployment-gone@3".to_owned(),
            kind: StartupNoticeKindDto::DeploymentGone,
        };
        assert_eq!(
            serde_json::to_string(&deployment_gone).unwrap(),
            r#"{"id":"deployment-gone@3","kind":"deployment_gone"}"#
        );
    }

    /// The GUI face classifies the SHARED corpus (the same bytes the CLI's
    /// released-binary contract test drives) and lands on the same forks:
    /// a retired pack format is a full re-render, a node state mirror above
    /// the bookkeeping is a re-publish.
    #[test]
    fn gui_face_classifies_the_shared_corpus() {
        use interflow_testkit::plan_corpus;

        let dir = tempfile::tempdir().unwrap();
        let manifest_path = dir.path().join("interflow.toml");
        let issuer = dir.path().join("issuer");
        let out = dir.path().join("dist");
        let classify = || {
            serde_json::to_string(&ChangeStateDto::from(
                interflow_cli::plan::change_state(&manifest_path, &issuer, &out).unwrap(),
            ))
            .unwrap()
        };

        std::fs::write(
            &manifest_path,
            plan_corpus::mesh_manifest_text("gui-corpus", 11434, 8080),
        )
        .unwrap();
        interflow_cli::plan::apply(
            &manifest_path,
            &issuer,
            &out,
            false,
            &interflow_cli::plan::BackupInitOptions::default(),
            false,
        )
        .unwrap();
        assert_eq!(classify(), r#"{"kind":"applied","generation":1}"#);

        plan_corpus::deprecate_pack_format(&out.join("packs/agent-svc-host"));
        assert_eq!(classify(), r#"{"kind":"pack_tree_stale"}"#);

        // Restore a current-format pack.toml by re-rendering, then plant a
        // node state mirror above the bookkeeping.
        interflow_cli::plan::apply(
            &manifest_path,
            &issuer,
            &out,
            false,
            &interflow_cli::plan::BackupInitOptions::default(),
            false,
        )
        .unwrap();
        plan_corpus::write_state_policy_mirror(&out, "home-win", 6);
        assert_eq!(classify(), r#"{"kind":"watermarks_diverged"}"#);
    }
}
