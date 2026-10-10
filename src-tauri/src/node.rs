//! NodeManager: the unified multi-node supervisor behind the GUI.
//!
//! One node = one Credential Pack directory + a couple of runtime
//! preferences. What a node IS comes entirely from the pack
//! ([`NodeKind::classify`]): expose agent, mesh agent, mesh hub, or ingress
//! — there is no mode switch anywhere in the product, and any number of
//! nodes run side by side.
//!
//! This module continues the discipline of the tunnel manager it replaces
//!: it is
//! GUI-framework-free domain logic — UI side effects (frontend events, tray
//! refresh, profile persistence) are injected as sinks — and every critical
//! section is synchronous and sub-millisecond. No lock is ever held across
//! an `.await` (compile-time rejected workspace-wide via
//! `clippy::await_holding_lock` = deny). The two things that are slow —
//! loading/validating a pack and shutting an engine down — happen outside
//! the lock ([`prepare`] and the `stop`/rotation paths).
//!
//! Sinks are never called from mutation code: state/persist effects are
//! queued as [`ManagerEvent`]s inside the critical section (so FIFO
//! delivery order equals application order) and drained by a single
//! consumer task that holds no lock — sinks may read the manager back,
//! which the GUI's tray refresh does. Before this split, sinks ran under
//! the manager lock and that read-back self-deadlocked Start
//!
//! Lifecycle per node:
//! - **start** (user): `prepare` from the pack (outside the lock), build the
//!   engine (spawn, returns immediately), wire a state listener, and spawn
//!   the renewal scheduler beside it. Start intent (`desired_running`) is
//!   persisted — Start means "keep it on", Stop "keep it off"; the GUI
//!   restores the desired set on launch.
//! - **renewal** (parity with the CLI/mesh binaries): one
//!   `renewal_scheduler(pack_dir)` per node. Its `Ok` completion means "new
//!   credential generation is active — restart onto it" (the in-process
//!   equivalent of the binaries' exit-for-systemd-restart); its `Err` means
//!   the credential is unsalvageable (expired / CRL stale beyond bound) —
//!   the node is stopped and surfaced as `Failed`.
//! - **death**: an engine that ends without a user stop enters the bounded
//!   auto-restart loop (`SupervisorRestartPolicy`, shared with the agent
//!   engine); exhaustion surfaces as `Failed`.
//!
//! Log attribution: engine-level events carry a `node` field (see the
//! engine crates); this manager logs its own transitions with the node's
//! pack name in the same field so the GUI log view can filter per node.

use interflow_identity::credentials::ActiveCredentialSet;
use interflow_identity::manifest::{MeshEgressRule, MeshIngressRule};
use interflow_identity::pack::{CredentialPack, PackKind};
use interflow_mesh::agent::{
    AgentClient, AgentHandle, AgentState, RestartDecision, SupervisorRestartPolicy,
};
use interflow_mesh::config::{AgentConfig, HubConfig, TransportKind};
use interflow_mesh::hub::{HubHandle, HubLifecycle};
use std::collections::HashMap;
use std::future::Future;
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::time::{Duration, Instant};
use tokio_util::sync::CancellationToken;

/// Stable node identity (UUID minted at add time; survives credential
/// rotations, which rewrite pack contents but not the profile).
pub type NodeId = String;

/// What a node is — derived from the pack, never chosen in the UI.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
pub enum NodeKind {
    /// Public-domain tunnel agent (the `interflow-cli agent` engine).
    ExposeAgent,
    /// Site-to-site mesh agent (the `interflow-mesh agent` engine).
    MeshAgent,
    /// Site-to-site mesh hub (the `interflow-mesh hub` engine).
    Hub,
    /// Public-domain ingress edge (the `interflow-cli ingress` engine).
    Ingress,
}

impl NodeKind {
    /// Pack → node kind. Agent packs split by mesh role (`node_config.mesh`
    /// present = mesh); hub/ingress are role-bound by `PackKind`.
    pub const fn classify(pack: &CredentialPack) -> Self {
        match pack.metadata.kind {
            PackKind::Hub => Self::Hub,
            PackKind::Ingress => Self::Ingress,
            PackKind::Agent => {
                if pack.node_config.mesh.is_some() {
                    Self::MeshAgent
                } else {
                    Self::ExposeAgent
                }
            }
        }
    }

    /// Short human label (list rows, tray).
    pub const fn label(self) -> &'static str {
        match self {
            Self::ExposeAgent => "expose agent",
            Self::MeshAgent => "mesh agent",
            Self::Hub => "mesh hub",
            Self::Ingress => "ingress",
        }
    }
}

/// What the UI shows when a pack is picked, before anything starts.
/// One service an expose pack declares: its id and the manifest-issued
/// default dial target (a machine-local preference may override the address
/// at run time; the id and the service *set* are pack-signed).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PackService {
    pub id: String,
    pub default_address: String,
}

#[derive(Debug, Clone)]
pub struct PackInfo {
    /// Node kind (from [`NodeKind::classify`]).
    pub kind: NodeKind,
    /// Pack node name (the display name).
    pub name: String,
    /// The identity the pack carries ([`pack_principal`]) — shown in the
    /// add preview and used as the add-time uniqueness key.
    pub principal: String,
    /// Rotation generation (display cache; the pack is the source).
    pub generation: u64,
    /// Content digest of the pack as loaded (`sha256:…` over the digest
    /// manifest). Two packs with the same generation but different content
    /// differ here — the "update available" truth that a generation-only
    /// comparison misses (a re-applied manifest renders generation 1 again).
    pub digest: String,
    /// Control endpoint (agents dial it; hubs/ingress show their listen).
    pub control_endpoint: String,
    /// Expose services declared in the pack (id + default address).
    pub services: Vec<PackService>,
    /// Site-to-site face of the pack (mesh agents; the rule counts derive
    /// from its vecs).
    pub mesh: Option<PackMeshRules>,
    /// Listen address (hub/ingress).
    pub listen: Option<String>,
    /// Dial transport the pack declares as its signed default (expose
    /// agents; `None` = the h2 default).
    pub transport: Option<String>,
    /// Leaf-credential health (earliest active expiry, phased). `None`
    /// when the pack has no active credential set yet.
    pub credential: Option<CredentialHealth>,
}

/// Leaf-credential health of one pack — the GUI/tray/doctor surface of
/// "how long until this node's credentials stop working". Phase math and
/// text come from identity's `expiry` module (the workspace-wide single
/// source, shared with the hub's per-agent observations).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CredentialHealth {
    /// Earliest active leaf `notAfter` (RFC 3339, UTC).
    pub not_after: String,
    /// Remaining seconds of that leaf (negative once expired).
    pub remaining_secs: i64,
    /// Phase: healthy / warn (<20% of the TTL) / critical (<10%).
    pub phase: interflow_identity::expiry::LeafPhase,
}

/// The policy plane's live face for one mesh agent node — "which policy
/// generation is this node actually running, from which channel, and is
/// the hub ahead or behind it" (2026-10-06 policy-health surface).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PolicyPlane {
    /// The generation this node currently runs (the state/policy override
    /// when present, the pack's embedded snapshot otherwise).
    pub generation: u64,
    /// Which face the live policy came from.
    pub source: PolicySource,
    /// The hub's serving generation as of the watcher's last control-plane
    /// poll; `None` = never polled / the hub did not report / node not
    /// running. A value BELOW `generation` is the lineage-deadlock
    /// signature.
    pub hub_generation: Option<u64>,
    /// The control-plane pull's own health while the node runs; `None` =
    /// the node is stopped (the watcher is not alive to report).
    pub pull: Option<PullHealth>,
}

impl PolicyPlane {
    /// Assembles the live face from a watcher snapshot — the one
    /// construction both consumption paths share (the `policy_plane` query
    /// and the event forwarder), so a value shown on demand and a value
    /// pushed as an event can never disagree.
    fn live(snap: interflow_mesh::agent::PolicyWatchSnapshot) -> Self {
        Self {
            generation: snap.seen,
            source: if snap.state_channel {
                PolicySource::StatePolicy
            } else {
                PolicySource::Pack
            },
            // 0 = the hub did not report one (never polled / no tunnel).
            hub_generation: (snap.hub_generation > 0).then_some(snap.hub_generation),
            // The control-plane pull's own health — the 2026-10-07
            // lesson: "never completed a pull" on a connected agent is
            // a dead distribution plane, and it must be readable as
            // such, not as an absent field.
            pull: Some(PullHealth {
                last_ok_unix: snap.pull_last_ok_unix,
                failures_total: snap.pull_failures_total,
                last_tick_unix: snap.last_tick_unix,
            }),
        }
    }
}

/// The hub control-plane pull channel's liveness face — the distribution
/// plane's own health, separate from whichever generation it delivered
/// (2026-10-07: a channel that never completes a pull looked identical to
/// a hub with nothing to say, and the distinction is the difference
/// between a working mesh and an 8-day-frozen one).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PullHealth {
    /// Unix seconds of the last completed pull (`UpToDate` or `Update`
    /// alike). `0` = never completed one — on a connected agent this is a
    /// dead distribution plane, not an idle one.
    pub last_ok_unix: u64,
    /// Total failed pull attempts since the node started (each is also a
    /// warn-once log line at the engine level).
    pub failures_total: u64,
    /// Unix seconds of the watcher's most recent wake. Frozen in the past
    /// while the node runs = the watcher task itself is dead.
    pub last_tick_unix: u64,
}

/// Which distribution face a node's live policy came from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PolicySource {
    /// The pack's embedded snapshot.
    Pack,
    /// The node-local update channel (`state/policy`) — hub pulls and
    /// manual injections land here.
    StatePolicy,
}

/// The peer plane's live face for one mesh agent node — "who else is in
/// the tenant's fleet, is each peer reachable right now, and how is each
/// peer's leaf credential doing" (the 2026-10-08 peer-observability
/// surface: the first local answer to "is the far end up", which used to
/// require hub-journal forensics). Information-minimal by design: name,
/// presence, leaf phase — nothing else.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PeersPlane {
    /// The tenant's registered agents, self excluded (sorted by id).
    pub peers: Vec<PeerStatus>,
    /// Unix seconds of the last successful fetch; `0` = never fetched.
    pub last_ok_unix: u64,
    /// Failed fetches since the node started (each also a warn-once log
    /// line at the engine level).
    pub failures_total: u64,
}

impl PeersPlane {
    /// Assembles the live face from a watcher snapshot — the one
    /// construction the query path and the event forwarder share (same
    /// contract as [`PolicyPlane::live`]).
    fn live(snap: interflow_mesh::agent::PeerWatchSnapshot) -> Self {
        Self {
            peers: snap
                .peers
                .into_iter()
                .map(|p| PeerStatus {
                    agent: p.agent,
                    online: p.online,
                    leaf_phase: p.leaf_expiry.as_ref().map(|l| l.phase),
                    leaf_remaining_secs: p.leaf_expiry.as_ref().map_or(0, |l| l.remaining_secs),
                    leaf_not_after_unix: p.leaf_expiry.as_ref().map_or(0, |l| l.not_after_unix),
                })
                .collect(),
            last_ok_unix: snap.last_ok_unix,
            failures_total: snap.failures_total,
        }
    }
}

/// One peer of the tenant's fleet as the node's peer watcher reads it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PeerStatus {
    /// Qualified peer id (`tenant/agent`).
    pub agent: String,
    /// Presence: a QUIC relay session in place, or an h2 poll body in
    /// place / within reconnect grace. `registered ≠ reachable`.
    pub online: bool,
    /// The peer's leaf-health phase (`None` = its leaf did not parse).
    /// Same warn/critical tiering the node's own credential face uses —
    /// the colors match across self and peers.
    pub leaf_phase: Option<interflow_core::tunnel::transport::PeerLeafPhase>,
    /// Seconds of leaf validity remaining (`0` with phase `None`).
    pub leaf_remaining_secs: i64,
    /// The leaf's `notAfter` unix seconds (`0` with phase `None`).
    pub leaf_not_after_unix: i64,
}

/// The listeners plane's live face for one mesh agent node — every ingress
/// rule's actual listener state (the actual-state counterpart of the rule
/// store: the policy face can say "generation green" while a listener is
/// gone; this answers what is really listening). The honesty axis the
/// 2026-10-09 one-way-blackhole case demanded at the GUI layer: a green
/// session card plus a dead listener must be visible as exactly that.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ListenerStatusFace {
    /// The ingress rule the listener serves.
    pub rule: String,
    /// The actually-bound address (`None` = no listener is up for the rule).
    pub bound_addr: Option<String>,
    /// The last bind failure (`None` = healthy).
    pub last_error: Option<String>,
}

impl ListenerStatusFace {
    /// Assembles the live face from the engine table — the one construction
    /// the query path and the event forwarder share (same contract as
    /// [`PeersPlane::live`]).
    fn live(
        snap: std::collections::HashMap<String, interflow_mesh::agent::ListenerStatus>,
    ) -> Vec<Self> {
        let mut faces: Vec<Self> = snap
            .into_iter()
            .map(|(rule, status)| Self {
                rule,
                bound_addr: status.bound_addr.map(|a| a.to_string()),
                last_error: status.last_error,
            })
            .collect();
        faces.sort_by(|a, b| a.rule.cmp(&b.rule));
        faces
    }
}

/// Computes a pack's credential health: from its ACTIVE credential set
/// when one exists (the renewal plane's output — `load_existing`, never
/// bootstrap: a view must not mint credential state), falling back to the
/// pack's bootstrap identities for a never-started node (the credentials
/// its first start will actually use). `None` when neither carries any
/// expiry.
pub fn pack_credential_health(pack: &CredentialPack) -> Option<CredentialHealth> {
    let not_after_unix =
        match interflow_identity::credentials::ActiveCredentialSet::load_existing(pack)
            .ok()
            .flatten()
        {
            Some(active) => active.earliest_expiry().ok()?.unix_timestamp(),
            None => pack
                .identities
                .values()
                .flat_map(|buckets| buckets.values())
                .map(|entry| entry.not_after_unix)
                .min()?,
        };
    let health = interflow_identity::expiry::leaf_phase_from_ttl(
        not_after_unix,
        pack.metadata.leaf_ttl_secs,
        interflow_identity::expiry::now_unix(),
    );
    Some(CredentialHealth {
        not_after: interflow_identity::expiry::format_rfc3339(not_after_unix),
        remaining_secs: health.remaining_secs,
        phase: health.phase,
    })
}

/// Mesh display model for one node: the hub dial target (from `node.toml`,
/// which carries dial info only) plus the rules this node runs. The rules
/// come from the AUTHORITATIVE policy face (state/policy override included
/// — what the engine actually runs, same as `build_agent_config`), never
/// from node.toml.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct PackMeshRules {
    pub hub_endpoint: String,
    pub ingress: Vec<MeshIngressRule>,
    pub egress: Vec<MeshEgressRule>,
}

/// The mesh display model of a loaded pack (`None` for non-mesh packs).
fn mesh_rules_from_pack(pack: &CredentialPack) -> Option<PackMeshRules> {
    pack.node_config.mesh.as_ref().map(|mesh| PackMeshRules {
        hub_endpoint: mesh.hub_endpoint.clone(),
        ingress: pack
            .policy
            .mesh
            .iter()
            .filter(|s| s.source_agent == pack.metadata.node)
            .map(|s| MeshIngressRule {
                name: s.name.clone(),
                listen: s.listen.clone(),
                protocol: s.protocol,
                target_agent: s.target_agent.clone(),
                remote_addr: s.remote_addr.clone(),
                idle_timeout_secs: s.idle_timeout_secs,
            })
            .collect(),
        egress: pack
            .policy
            .mesh_egress
            .iter()
            .filter(|o| o.agent == pack.metadata.node)
            .map(|o| MeshEgressRule {
                name: o.name.clone(),
                protocol: o.protocol,
                target_addr: o.target_addr.clone(),
                target_cidr: o.target_cidr.clone(),
                udp_idle_timeout_secs: o.udp_idle_timeout_secs,
            })
            .collect(),
    })
}

/// Inspects a pack directory through the shared validation funnel — the same
/// `CredentialPack::load_runtime` the start path uses, so a pack that
/// inspects clean also starts clean (the 2026-09-18 papercuts lesson:
/// validation lives in the shared layer, not the GUI).
pub fn inspect_pack(pack_dir: &Path) -> Result<PackInfo, String> {
    let pack = CredentialPack::load_runtime(pack_dir)
        .map_err(|e| format!("Credential Pack rejected: {e}"))?;
    let mesh = mesh_rules_from_pack(&pack);
    Ok(PackInfo {
        kind: NodeKind::classify(&pack),
        name: pack.metadata.node.clone(),
        principal: pack_principal(&pack),
        generation: pack.metadata.generation,
        digest: pack.pack_digest.clone(),
        control_endpoint: pack.metadata.control_endpoint.clone(),
        services: pack
            .node_config
            .services
            .iter()
            .map(|s| PackService {
                id: s.id.clone(),
                default_address: s.address.clone(),
            })
            .collect(),
        mesh,
        listen: pack.node_config.listen.clone(),
        transport: (!pack.node_config.transport.is_empty())
            .then(|| pack.node_config.transport.clone()),
        credential: pack_credential_health(&pack),
    })
}

/// A node's persisted identity + preferences (mirrors `profile::NodeEntry`).
#[derive(Debug, Clone)]
pub struct NodeSpec {
    pub id: NodeId,
    pub kind: NodeKind,
    pub name: String,
    /// The identity the pack carries — `realm/workspace/kind/node` from
    /// `pack.toml` ([`pack_principal`]). The add-time uniqueness key: one
    /// identity runs at most once on this machine (duplicate registrations
    /// would kick each other at the hub). `None` = the pack was unreadable
    /// at restore (placeholder entry; `prepare` fails with the real error
    /// at start).
    pub principal: Option<String>,
    pub pack_dir: PathBuf,
    /// Agent nodes only: h2 (default) or quic.
    pub transport: Option<TransportKind>,
    /// Agent nodes only: explicit hub QUIC address; `None` derives it.
    pub hub_quic_addr: Option<String>,
    /// Rotation generation of the pack last seen (display cache for
    /// "update available" hints; the pack is the source).
    pub generation: u64,
    /// Content digest of the pack last installed here (display cache in the
    /// same spirit as `generation`: re-read from the pack at every restore,
    /// refreshed by `update_pack`). "Update available" compares BOTH — a
    /// re-applied manifest re-renders the same generation with different
    /// content, which only the digest catches.
    pub pack_digest: String,
    /// Services the pack declares (id + manifest-issued default address).
    /// Display-and-validation cache: `prepare` re-reads the pack for the
    /// dial targets, so a swapped pack cannot lie about defaults for long.
    pub pack_services: Vec<PackService>,
    /// Site-to-site rules the pack declares (mesh agents). Display cache in
    /// the same spirit as `pack_services`: the pack is the signed truth, the
    /// GUI shows it read-only — `prepare` re-reads the pack to run.
    pub pack_mesh: Option<PackMeshRules>,
    /// Public/control listener the pack declares (hub/ingress). Display
    /// cache, same lifecycle as `pack_services`.
    pub pack_listen: Option<String>,
    /// Dial transport the pack declares as its signed manifest default
    /// (expose agents; `None` = h2). Display cache in the same spirit:
    /// `prepare` re-reads the pack, so the effective transport always
    /// comes from the pack, never this cache.
    pub pack_transport: Option<String>,
    /// Expose nodes only: per-service dial-address preferences (id →
    /// effective address), overriding the pack defaults. Empty = defaults.
    pub service_addresses: std::collections::BTreeMap<String, String>,
}

/// The identity a pack carries, as a stable printable key — the
/// (realm, workspace, pack kind, node name) tuple from `pack.toml`. Two
/// packs with the same principal are the same member of the same mesh; two
/// packs that merely share a node name are not.
fn pack_principal(pack: &CredentialPack) -> String {
    format!(
        "{}/{}/{}/{}",
        pack.metadata.realm,
        pack.metadata.workspace.as_deref().unwrap_or("-"),
        pack.metadata.kind.as_str(),
        pack.metadata.node
    )
}

/// The value engine/manager log lines attribute this node's events to:
/// the display name plus the id's short prefix, unique per node even when
/// two nodes share a name across realms/workspaces. The same value is
/// injected into every engine config at start (`AgentInfo::log_name`,
/// `ServerConfig::node_name`) and keys the "This node" log filter.
pub fn log_attribution(spec: &NodeSpec) -> String {
    format!("{}·{}", spec.name, spec.id.get(..8).unwrap_or(&spec.id))
}

/// Unified runtime state across the four engines (wire-adjacent; the IPC
/// contract maps it 1:1).
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub enum NodeState {
    /// Hub/ingress: spawned, listeners not yet up.
    Starting,
    /// Agent: connecting + registering at the hub.
    Connecting,
    /// Agent: registered and serving. The hub receipt (observed egress +
    /// registration moment) rides along — the hub-confirmed evidence the UI
    /// surfaces instead of making operators grep the hub journal.
    Connected {
        agent_id: String,
        hub_receipt: Option<interflow_mesh::agent::HubReceipt>,
    },
    /// Reconnect backoff (agent) or restart backoff (any engine).
    Reconnecting {
        reason: String,
        backoff_secs: u32,
    },
    /// Hub/ingress: listeners up and serving.
    Running,
    /// Shutdown requested; draining.
    Stopping,
    Stopped,
    Failed {
        error: String,
    },
}

impl From<AgentState> for NodeState {
    fn from(state: AgentState) -> Self {
        match state {
            AgentState::Connecting => Self::Connecting,
            AgentState::Connected {
                agent_id,
                hub_receipt,
            } => Self::Connected {
                agent_id,
                hub_receipt,
            },
            AgentState::Reconnecting {
                reason,
                backoff_secs,
            } => Self::Reconnecting {
                reason,
                backoff_secs: u32::try_from(backoff_secs).unwrap_or(u32::MAX),
            },
            AgentState::Stopped => Self::Stopped,
            AgentState::Failed { error } => Self::Failed { error },
        }
    }
}

impl From<HubLifecycle> for NodeState {
    fn from(state: HubLifecycle) -> Self {
        match state {
            HubLifecycle::Starting => Self::Starting,
            HubLifecycle::Running => Self::Running,
            HubLifecycle::Stopping => Self::Stopping,
            HubLifecycle::Stopped => Self::Stopped,
            HubLifecycle::Failed { error } => Self::Failed { error },
        }
    }
}

/// A fully validated, ready-to-build engine input. Built outside the manager
/// lock (pack loading is file IO + digest verification).
#[allow(clippy::large_enum_variant)]
enum Prepared {
    Expose(interflow_expose::client::ExposeArgs),
    /// The mesh agent config. The signed-policy plane (and the pack dir it
    /// reads) rides the config itself — the engine spawns its own watcher
    /// at start.
    Mesh {
        config: AgentConfig,
    },
    /// The hub config — the signed-policy ACL watcher rides the engine's
    /// run future via the config's policy plane (pack_dir embedded by
    /// `build_hub_config`); the GUI spawns nothing itself.
    Hub {
        config: HubConfig,
    },
    Ingress(interflow_expose::edge::EdgeConfig),
}

/// Loads the pack and derives the engine input for `spec`'s kind. Role
/// binding is re-checked here — a pack whose kind does not match the node's
/// recorded kind (e.g. the directory was replaced) fails with a pointed
/// message instead of starting the wrong engine.
fn prepare(spec: &NodeSpec) -> Result<Prepared, String> {
    let dir = spec.pack_dir.clone();
    let pack =
        CredentialPack::load_runtime(&dir).map_err(|e| format!("Credential Pack rejected: {e}"))?;
    let active = ActiveCredentialSet::load_or_bootstrap(&pack)
        .map_err(|e| format!("Credential Pack rejected: {e}"))?;
    match spec.kind {
        NodeKind::ExposeAgent => {
            if pack.metadata.kind != PackKind::Agent || pack.node_config.mesh.is_some() {
                return Err(
                    "this pack is not an expose agent pack — it cannot start as this node \
                     (role-bound)"
                        .into(),
                );
            }
            // Effective transport = local preference over the pack's signed
            // manifest default (h2 floor); headless parity comes from the
            // same resolver `agent run --pack` uses.
            let transport = interflow_cli::runtime::resolve_effective_transport(
                spec.transport,
                pack.node_config.transport.as_str(),
            )
            .map_err(|e| format!("cannot start from this Credential Pack: {e}"))?;
            let mut args = interflow_cli::runtime::build_agent_args(
                &pack,
                &active,
                &dir,
                transport,
                spec.hub_quic_addr.clone().filter(|s| !s.trim().is_empty()),
                &spec.service_addresses,
            )
            .map_err(|e| format!("cannot start from this Credential Pack: {e}"))?;
            args.log_name = Some(log_attribution(spec));
            Ok(Prepared::Expose(args))
        }
        NodeKind::MeshAgent => {
            if pack.metadata.kind != PackKind::Agent {
                return Err(
                    "this pack is not an agent pack — it cannot start as this node (role-bound)"
                        .into(),
                );
            }
            if pack.node_config.mesh.is_none() {
                return Err(
                    "this is an expose agent pack — it cannot start as a mesh agent \
                     (add it as an expose node instead)"
                        .into(),
                );
            }
            let mut config = interflow_mesh::pack::build_agent_config(&pack, &active, &dir)
                .map_err(|e| format!("cannot start from this Credential Pack: {e}"))?;
            // Same resolution as expose agents: local preference over the
            // pack's signed dial default, h2 the floor (one fold for both
            // agent faces). The pack path already carried (or derived) the
            // QUIC dial address for a quic default; the local address only
            // overrides when the operator typed one, and a local quic
            // preference over an h2 pack derives from the signed hub
            // endpoint — same single-source helper the pack path uses.
            config.agent.transport = interflow_cli::runtime::resolve_effective_transport(
                spec.transport,
                pack.node_config.transport.as_str(),
            )
            .map_err(|e| format!("cannot start from this Credential Pack: {e}"))?;
            let quic_addr = spec
                .hub_quic_addr
                .clone()
                .filter(|s| !s.trim().is_empty())
                .or_else(|| config.agent.hub_quic_addr.clone())
                .or_else(|| {
                    (config.agent.transport == interflow_mesh::config::TransportKind::Quic)
                        .then(|| interflow_mesh::pack::derive_quic_addr(&config.agent.hub_url))
                        .flatten()
                });
            config.agent.hub_quic_addr = quic_addr;
            config.agent.log_name = Some(log_attribution(spec));
            Ok(Prepared::Mesh { config })
        }
        NodeKind::Hub => {
            if pack.metadata.kind != PackKind::Hub {
                return Err(
                    "this pack is not a hub pack — it cannot start as this node (role-bound)"
                        .into(),
                );
            }
            let mut config = interflow_mesh::pack::build_hub_config(&pack, &active, &dir)
                .map_err(|e| format!("cannot start from this Credential Pack: {e}"))?;
            config.server.node_name = Some(log_attribution(spec));
            Ok(Prepared::Hub { config })
        }
        NodeKind::Ingress => {
            if pack.metadata.kind != PackKind::Ingress {
                return Err(
                    "this pack is not an ingress pack — it cannot start as this node (role-bound)"
                        .into(),
                );
            }
            let mut config = interflow_cli::runtime::build_edge_config(&pack, &active, &dir)
                .map_err(|e| format!("cannot start from this Credential Pack: {e}"))?;
            config.log_name = Some(log_attribution(spec));
            Ok(Prepared::Ingress(config))
        }
    }
}

/// `https://host:port` → `host:port` (mesh agents have no expose-style
/// derivation helper; the control endpoint carries the hub dial address).
/// Returns `None` when no explicit port is present — engine config
/// validation then fails with its own pointed message.
/// A running engine, normalized.
enum Engine {
    Agent { handle: AgentHandle },
    Hub { handle: HubHandle },
    Ingress(FutureEngine),
}

impl Engine {
    fn is_alive(&self) -> bool {
        match self {
            Self::Agent { handle, .. } => {
                !matches!(
                    handle.state(),
                    AgentState::Stopped | AgentState::Failed { .. }
                ) && !handle.is_finished()
            }
            // The hub monitor reaches a terminal lifecycle when (and only
            // when) the run future ended.
            Self::Hub { handle, .. } => !handle.is_finished(),
            Self::Ingress(e) => !matches!(e.state(), NodeState::Stopped | NodeState::Failed { .. }),
        }
    }

    async fn shutdown_graceful(self) -> Result<(), String> {
        match self {
            // The policy watchers ride the handles' own task groups (the
            // engines run them intrinsically) — no per-surface abort left
            // to forget.
            Self::Agent { handle } => handle.shutdown_graceful().await.map_err(|e| e.to_string()),
            Self::Hub { handle } => handle.shutdown_graceful().await.map_err(|e| e.to_string()),
            Self::Ingress(e) => e.shutdown_graceful().await,
        }
    }
}

/// Wraps `edge::run_until_signalled` into a hub-handle-shaped lifecycle.
/// The edge signals its own readiness (public listener + control endpoint
/// bound); never-ready within the startup budget cancels the run (the
/// monitor then records the failure). No synthetic connections — the same
/// signal systemd's `Type=notify` start jobs gate on.
struct FutureEngine {
    state: tokio::sync::watch::Receiver<NodeState>,
    token: CancellationToken,
    result: tokio::sync::oneshot::Receiver<interflow_core::error::Result<()>>,
}

impl FutureEngine {
    fn spawn_ingress(
        config: interflow_expose::edge::EdgeConfig,
        rt: &tokio::runtime::Handle,
    ) -> Self {
        const READY_TIMEOUT: Duration = Duration::from_secs(30);
        let token = CancellationToken::new();
        let (state_tx, state_rx) = tokio::sync::watch::channel(NodeState::Starting);
        let (result_tx, result_rx) = tokio::sync::oneshot::channel();
        let listen_addr = config.listen_addr;

        let run_token = token.clone();
        let (ready_tx, ready_rx) = tokio::sync::oneshot::channel();
        let mut task = rt.spawn(async move {
            interflow_expose::edge::run_until_signalled(config, run_token, ready_tx).await
        });

        // Readiness: the edge's own signal; never-ready cancels the run.
        {
            let token = token.clone();
            let state_tx = state_tx.clone();
            rt.spawn(async move {
                let readied = tokio::select! {
                    ready = ready_rx => match ready {
                    // EdgeReady carries the bound addresses; the GUI only
                    // gates on readiness itself.
                    Ok(_edge_ready) => true,
                        // The run ended before signalling readiness (its
                        // sender is gone): the real error surfaces through
                        // the monitor — don't race it with a generic
                        // timeout message.
                        Err(_) => return,
                    },
                    () = tokio::time::sleep(READY_TIMEOUT) => false,
                };
                if token.is_cancelled() {
                    return;
                }
                if readied {
                    let _ = state_tx.send(NodeState::Running);
                } else {
                    let _ = state_tx.send(NodeState::Failed {
                        error: format!(
                            "ingress did not become ready within {READY_TIMEOUT:?} \
                             (public listener {listen_addr})",
                        ),
                    });
                    token.cancel();
                }
            });
        }

        // Monitor: token → Stopping; run end → Stopped/Failed. A run that
        // ends via cancellation without ever reaching Running is a startup
        // failure (the probe's Failed must not be overwritten by Stopped).
        let monitor_token = token.clone();
        rt.spawn(async move {
            let joined = tokio::select! {
                () = monitor_token.cancelled() => {
                    let _ = state_tx.send(NodeState::Stopping);
                    task.await
                }
                joined = &mut task => joined,
            };
            if let Err(ref join_err) = joined {
                // Task-level death (panic/abort): synthesize the engine
                // error — there is no run result to hand out.
                let error = format!("ingress task join failed: {join_err}");
                let _ = state_tx.send(NodeState::Failed {
                    error: error.clone(),
                });
                let _ = result_tx.send(Err(interflow_core::error::InterflowError::connection(
                    error,
                )));
                return;
            }
            match &joined {
                Ok(Ok(())) => {
                    if matches!(*state_tx.borrow(), NodeState::Failed { .. }) {
                        // keep the probe's never-ready verdict
                    } else {
                        let _ = state_tx.send(NodeState::Stopped);
                    }
                }
                Ok(Err(e)) => {
                    let _ = state_tx.send(NodeState::Failed {
                        error: e.to_string(),
                    });
                }
                Err(_) => unreachable!("handled above"),
            }
            let Ok(outcome) = joined else {
                unreachable!("join errors handled above");
            };
            let _ = result_tx.send(outcome);
        });

        Self {
            state: state_rx,
            token,
            result: result_rx,
        }
    }

    fn state(&self) -> NodeState {
        self.state.borrow().clone()
    }

    async fn shutdown_graceful(self) -> Result<(), String> {
        self.token.cancel();
        match self.result.await {
            Ok(res) => res.map_err(|e| e.to_string()),
            Err(_) => Err("ingress monitor ended without delivering a result".into()),
        }
    }
}

/// Everything mutable per node, under the manager's single lock.
struct NodeEntry {
    spec: NodeSpec,
    /// Persisted start intent (Start = keep on, Stop = keep off).
    desired_running: bool,
    /// A stop the manager itself initiated (user stop or credential
    /// rotation) — silences the death-restart path for the dying engine.
    expected_stop: bool,
    /// Latest observed state (authoritative for queries).
    state: NodeState,
    engine: Option<Engine>,
    renewal: Option<tokio::task::AbortHandle>,
    restart: SupervisorRestartPolicy,
    /// Bumped on every start and stop; listener/restart tasks carry the
    /// generation they were spawned for and go quiet once it advances.
    generation: u64,
}

/// UI side-effect sinks. Both are invoked exclusively by the manager's
/// event-consumer task: never with the manager lock held, so a sink MAY
/// read manager state back synchronously — the GUI's tray does exactly
/// that (`emit_node_state` → `tray::refresh` → `snapshots()`). A sink
/// must return promptly, though: events are drained one at a time, so one
/// slow sink delays every later event.
pub type StateSink = Arc<dyn Fn(&str, &NodeState) + Send + Sync>;
/// Persists the node list + intent bits (wired to `profile::save`). The
/// manager hands over the already-serialized profile data. Same consumer
/// contract as [`StateSink`]; single-consumer delivery also serializes
/// profile writes (no concurrent `save` interleaving from parallel
/// start/stop paths).
pub type PersistSink = Arc<dyn Fn(&[crate::profile::NodeEntry]) + Send + Sync>;
/// Delivers a running mesh agent's policy-plane telemetry to the UI (wired
/// to the frontend `policy-plane` event). Fired by the forwarder task each
/// time the engine's watcher publishes a changed snapshot — the 2026-10-07
/// stale-panel bug was exactly this face missing: the panel sampled the
/// watcher's atomics once at node start and nothing ever told it the values
/// had moved. Same consumer contract as [`StateSink`].
pub type PolicySink = Arc<dyn Fn(&str, &PolicyPlane) + Send + Sync>;
/// Delivers a running mesh agent's peer-plane telemetry to the UI (wired
/// to the frontend `mesh-peers` event). Fired by the forwarder task each
/// time the engine's peer watcher publishes a changed snapshot — same
/// push-not-poll contract as [`PolicySink`], so the Peers section can
/// never freeze on its start-time reading.
pub type PeersSink = Arc<dyn Fn(&str, &PeersPlane) + Send + Sync>;
/// Delivers a running mesh agent's proposal receipts to the UI (wired to
/// the frontend `mesh-proposals` event). Same push-not-poll contract as
/// [`PeersSink`].
pub type ProposalsSink =
    Arc<dyn Fn(&str, &[interflow_core::tunnel::transport::ProposalReceipt]) + Send + Sync>;
/// Delivers a running mesh agent's ingress-listener actual state to the UI
/// (wired to the frontend `mesh-listeners` event). Fired by the forwarder
/// task each time the engine's reconciler records a bind or a failure —
/// the honesty axis of the 2026-10-09 case: a green card plus a gone
/// listener must surface as exactly that, not as nothing.
pub type ListenersSink = Arc<dyn Fn(&str, &[ListenerStatusFace]) + Send + Sync>;

/// What the manager tells its sinks, in order. Mutation code only ever
/// *sends* these — inside the critical section, right where the state is
/// applied, so FIFO delivery order equals application order — and the
/// consumer task alone turns them into sink calls, lock-free. Before this
/// split, sinks were called directly under the manager lock and the GUI's
/// read-back tray refresh self-deadlocked Start
enum ManagerEvent {
    State {
        id: NodeId,
        state: NodeState,
    },
    Persist {
        entries: Vec<crate::profile::NodeEntry>,
    },
    /// A running mesh agent's policy telemetry moved (forwarder task →
    /// [`PolicySink`]). Sent outside the critical section — unlike
    /// State/Persist it mirrors engine-side atomics, not manager state.
    PolicyPlane {
        id: NodeId,
        plane: PolicyPlane,
    },
    /// A running mesh agent's peer telemetry moved (forwarder task →
    /// [`PeersSink`]). Mirrors engine-side watcher state, not manager
    /// state — same outside-the-lock contract as [`ManagerEvent::PolicyPlane`].
    PeersPlane {
        id: NodeId,
        plane: PeersPlane,
    },
    /// A running mesh agent's proposal receipts moved (forwarder task →
    /// [`ProposalsSink`]).
    Proposals {
        id: NodeId,
        receipts: Vec<interflow_core::tunnel::transport::ProposalReceipt>,
    },
    /// A running mesh agent's ingress-listener actual state moved
    /// (forwarder task → [`ListenersSink`]). Mirrors the engine's
    /// reconciler table, not manager state — same outside-the-lock
    /// contract as [`ManagerEvent::PeersPlane`].
    Listeners {
        id: NodeId,
        faces: Vec<ListenerStatusFace>,
    },
    /// Round-trip marker behind [`NodeManager::settle`].
    Settled {
        ack: tokio::sync::oneshot::Sender<()>,
    },
}
/// Renewal future factory — injectable for tests; the default is the real
/// `renewal_scheduler` bound to the node's pack directory and log
/// attribution name.
pub type RenewalFactory = Arc<
    dyn Fn(
            PathBuf,
            String,
        ) -> Pin<Box<dyn Future<Output = interflow_core::error::Result<()>> + Send>>
        + Send
        + Sync,
>;

/// What one in-place pack update did (P1-2 UI feedback).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UpdateReport {
    /// Generation of the pack that was in place before the swap.
    pub generation_from: u64,
    /// Generation of the pack now in place.
    pub generation_to: u64,
    /// The node had a running intent and was restarted onto the new pack.
    pub restarted: bool,
}

struct Inner {
    nodes: HashMap<NodeId, NodeEntry>,
}

impl Inner {
    /// The persisted shape of the current node set (profile order).
    fn profile_entries(&self) -> Vec<crate::profile::NodeEntry> {
        let mut entries: Vec<_> = self
            .nodes
            .values()
            .map(|e| crate::profile::NodeEntry {
                id: e.spec.id.clone(),
                pack_dir: e.spec.pack_dir.display().to_string(),
                transport: e.spec.transport,
                hub_quic_addr: e.spec.hub_quic_addr.clone(),
                service_addresses: e
                    .spec
                    .service_addresses
                    .iter()
                    .map(|(id, address)| crate::profile::ServiceAddressPref {
                        id: id.clone(),
                        address: address.clone(),
                    })
                    .collect(),
                desired_running: e.desired_running,
            })
            .collect();
        entries.sort_by(|a, b| a.pack_dir.cmp(&b.pack_dir));
        entries
    }
}

/// The multi-node manager. Clone-safe (all state behind one shared mutex).
///
/// `rt` is the runtime the engines and supervisor tasks are spawned onto.
/// It is injected (not ambient) because the manager must be startable from
/// threads without a Tokio context — Tauri runs sync commands on such a
/// pool.
///
/// Sinks are NOT part of the manager: they are captured by the consumer
/// task spawned at construction (see [`ManagerEvent`]). Mutation code can
/// only queue events — firing a sink with the lock held is unrepresentable.
#[derive(Clone)]
pub struct NodeManager {
    inner: Arc<Mutex<Inner>>,
    rt: tokio::runtime::Handle,
    events: tokio::sync::mpsc::UnboundedSender<ManagerEvent>,
    renewal: RenewalFactory,
    /// Per-node leaf-credential health cache (node id -> health). Fed by
    /// the 5-minute refresher and the add/update paths; `list_nodes`
    /// lazily computes missing entries (first sighting). Credential
    /// expiry is a slow variable — a 5-minute granularity is far finer
    /// than the decision it feeds (rotate within days).
    credential_health: Arc<Mutex<HashMap<String, CredentialHealth>>>,
}

/// How often the credential-health cache is recomputed from the packs.
const CREDENTIAL_HEALTH_REFRESH: std::time::Duration = std::time::Duration::from_secs(300);

/// Recomputes the whole credential-health cache: snapshot (id, pack_dir)
/// under the manager lock, then read + phase OUTSIDE it (pack loads are
/// file IO; the lock must not wait on disks). Nodes whose pack no longer
/// loads simply drop out of the cache.
fn refresh_health_cache(
    inner: &Arc<Mutex<Inner>>,
    cache: &Arc<Mutex<HashMap<String, CredentialHealth>>>,
) {
    let dirs: Vec<(String, std::path::PathBuf)> = {
        let guard = inner.lock().unwrap_or_else(PoisonError::into_inner);
        guard
            .nodes
            .iter()
            .map(|(id, e)| (id.clone(), e.spec.pack_dir.clone()))
            .collect()
    };
    let mut fresh = HashMap::new();
    for (id, dir) in dirs {
        if let Some(pack) = CredentialPack::load_runtime(&dir).ok()
            && let Some(health) = pack_credential_health(&pack)
        {
            fresh.insert(id, health);
        }
    }
    *cache.lock().unwrap_or_else(PoisonError::into_inner) = fresh;
}

/// Snapshot for `list_nodes` (commands layer maps it to the IPC DTO).
#[derive(Debug, Clone)]
pub struct NodeSnapshot {
    pub spec: NodeSpec,
    pub desired_running: bool,
    pub state: NodeState,
}

impl NodeManager {
    pub fn new(
        rt: tokio::runtime::Handle,
        on_state: impl Fn(&str, &NodeState) + Send + Sync + 'static,
        on_persist: impl Fn(&[crate::profile::NodeEntry]) + Send + Sync + 'static,
        on_policy_plane: impl Fn(&str, &PolicyPlane) + Send + Sync + 'static,
        on_peers_plane: impl Fn(&str, &PeersPlane) + Send + Sync + 'static,
        on_proposals: impl Fn(&str, &[interflow_core::tunnel::transport::ProposalReceipt])
        + Send
        + Sync
        + 'static,
        on_listeners: impl Fn(&str, &[ListenerStatusFace]) + Send + Sync + 'static,
    ) -> Self {
        Self::with_renewal(
            rt,
            on_state,
            on_persist,
            on_policy_plane,
            on_peers_plane,
            on_proposals,
            on_listeners,
            Arc::new(|pack_dir, log_name| {
                // The future owns the path (it outlives the closure call).
                Box::pin(async move {
                    interflow_renewal::renewal_scheduler_with_log_name(&pack_dir, Some(log_name))
                        .await
                }) as Pin<Box<dyn Future<Output = _> + Send>>
            }),
        )
    }

    /// Test seam: injectable renewal future.
    pub fn with_renewal(
        rt: tokio::runtime::Handle,
        on_state: impl Fn(&str, &NodeState) + Send + Sync + 'static,
        on_persist: impl Fn(&[crate::profile::NodeEntry]) + Send + Sync + 'static,
        on_policy_plane: impl Fn(&str, &PolicyPlane) + Send + Sync + 'static,
        on_peers_plane: impl Fn(&str, &PeersPlane) + Send + Sync + 'static,
        on_proposals: impl Fn(&str, &[interflow_core::tunnel::transport::ProposalReceipt])
        + Send
        + Sync
        + 'static,
        on_listeners: impl Fn(&str, &[ListenerStatusFace]) + Send + Sync + 'static,
        renewal: RenewalFactory,
    ) -> Self {
        let (events, mut rx) = tokio::sync::mpsc::unbounded_channel();
        // The sinks belong to the consumer alone — mutation code only ever
        // holds the sender, so "call a sink under the lock" has no path.
        let on_state: StateSink = Arc::new(on_state);
        let on_persist: PersistSink = Arc::new(on_persist);
        let on_policy_plane: PolicySink = Arc::new(on_policy_plane);
        let on_peers_plane: PeersSink = Arc::new(on_peers_plane);
        let on_proposals: ProposalsSink = Arc::new(on_proposals);
        let on_listeners: ListenersSink = Arc::new(on_listeners);
        rt.spawn(async move {
            while let Some(event) = rx.recv().await {
                match event {
                    ManagerEvent::State { id, state } => on_state(&id, &state),
                    ManagerEvent::Persist { entries } => on_persist(&entries),
                    ManagerEvent::PolicyPlane { id, plane } => on_policy_plane(&id, &plane),
                    ManagerEvent::PeersPlane { id, plane } => on_peers_plane(&id, &plane),
                    ManagerEvent::Proposals { id, receipts } => on_proposals(&id, &receipts),
                    ManagerEvent::Listeners { id, faces } => on_listeners(&id, &faces),
                    ManagerEvent::Settled { ack } => {
                        let _ = ack.send(());
                    }
                }
            }
        });
        let inner: Arc<Mutex<Inner>> = Arc::new(Mutex::new(Inner {
            nodes: HashMap::new(),
        }));
        let credential_health: Arc<Mutex<HashMap<String, CredentialHealth>>> =
            Arc::new(Mutex::new(HashMap::new()));
        // Low-frequency refresher: expiry is a slow variable (days), the
        // recompute is a handful of pack reads (ms-scale) — a plain tick on
        // the shared runtime, blocked-worker cost is one blink per 5 min.
        {
            let inner = Arc::clone(&inner);
            let cache = Arc::clone(&credential_health);
            rt.spawn(async move {
                let mut ticker = tokio::time::interval(CREDENTIAL_HEALTH_REFRESH);
                ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
                ticker.tick().await; // the interval's immediate first tick
                loop {
                    ticker.tick().await;
                    refresh_health_cache(&inner, &cache);
                }
            });
        }
        Self {
            inner,
            rt,
            events,
            renewal,
            credential_health,
        }
    }

    /// Poison-tolerant lock (same rationale as the tunnel manager before
    /// it: a contained panic must not wedge Start/Stop forever).
    fn lock(&self) -> MutexGuard<'_, Inner> {
        self.inner.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Queues a state event for the consumer. Called inside the critical
    /// section, next to the state write it mirrors — channel FIFO order is
    /// the sink delivery order. The channel is unbounded on purpose:
    /// events are tiny (state transitions only), while a bounded channel
    /// would either block a lock holder or (try_send) silently drop
    /// persistence — both re-create the hazards this queue exists to kill.
    fn record_state(&self, id: &str, state: &NodeState) {
        let _ = self.events.send(ManagerEvent::State {
            id: id.to_string(),
            state: state.clone(),
        });
    }

    /// Queues a profile persist event for the consumer (same ordering
    /// contract as [`Self::record_state`]).
    fn record_persist(&self, entries: Vec<crate::profile::NodeEntry>) {
        let _ = self.events.send(ManagerEvent::Persist { entries });
    }

    /// Barrier: resolves once every event queued before this call has been
    /// consumed and its sink has returned. Tests assert on recorded sink
    /// effects behind it; the quit path flushes the final persist before
    /// the runtime goes away with the app.
    pub async fn settle(&self) {
        let (ack_tx, ack_rx) = tokio::sync::oneshot::channel();
        if self
            .events
            .send(ManagerEvent::Settled { ack: ack_tx })
            .is_ok()
        {
            let _ = ack_rx.await;
        }
        // A closed channel means the consumer is gone (runtime shutdown);
        // everything queued before it is gone too — nothing to wait for.
    }

    // ------------------------------------------------------------------
    // Node list management
    // ------------------------------------------------------------------

    /// Replaces the node list from the persisted profile (GUI startup).
    /// Entries are all `Stopped`; [`NodeManager::start_desired`] brings the
    /// desired set up. Kind and display name re-derive from the pack (one
    /// load per node — the pack is the single source of truth); an
    /// unreadable pack keeps a placeholder that fails with a pointed
    /// message at start.
    pub fn restore(&self, nodes: Vec<crate::profile::NodeEntry>) {
        let mut inner = self.lock();
        inner.nodes.clear();
        for persisted in nodes {
            let id = persisted.id.clone();
            let spec = spec_from_profile(persisted);
            inner.nodes.insert(
                id,
                NodeEntry {
                    desired_running: spec.desired_running,
                    expected_stop: false,
                    state: NodeState::Stopped,
                    engine: None,
                    renewal: None,
                    restart: SupervisorRestartPolicy::new(),
                    generation: 0,
                    spec: spec.spec,
                },
            );
        }
    }

    /// Adds a node (fresh id minted here and returned). Rejects an identity
    /// that is already managed — one identity runs at most once on this
    /// machine, because the same identity registered twice fights itself at
    /// the hub (each registration kicks the previous). A re-added pack
    /// directory is the same check one level down; a different directory
    /// carrying the same identity (e.g. a copied pack) is caught the same
    /// way.
    pub fn add(&self, mut spec: NodeSpec) -> Result<NodeId, String> {
        if spec.id.is_empty() {
            spec.id = uuid::Uuid::new_v4().to_string();
        }
        let mut inner = self.lock();
        let canonical = spec
            .pack_dir
            .canonicalize()
            .unwrap_or_else(|_| spec.pack_dir.clone());
        for entry in inner.nodes.values() {
            if let (Some(new_principal), Some(existing_principal)) =
                (&spec.principal, &entry.spec.principal)
                && new_principal == existing_principal
            {
                let existing_dir = entry
                    .spec
                    .pack_dir
                    .canonicalize()
                    .unwrap_or_else(|_| entry.spec.pack_dir.clone());
                return Err(if existing_dir == canonical {
                    format!(
                        "this Credential Pack is already added as “{}” ({existing_principal})",
                        entry.spec.name
                    )
                } else {
                    format!(
                        "this identity ({existing_principal}) is already added from \
                         “{}” — one identity can run only once here, because duplicate \
                         registrations kick each other at the hub",
                        entry.spec.pack_dir.display()
                    )
                });
            }
            let existing = entry
                .spec
                .pack_dir
                .canonicalize()
                .unwrap_or_else(|_| entry.spec.pack_dir.clone());
            if existing == canonical {
                return Err(format!(
                    "this Credential Pack is already added as node “{}”",
                    entry.spec.name
                ));
            }
        }
        let id = spec.id.clone();
        inner.nodes.insert(
            id.clone(),
            NodeEntry {
                desired_running: false,
                expected_stop: false,
                state: NodeState::Stopped,
                engine: None,
                renewal: None,
                restart: SupervisorRestartPolicy::new(),
                generation: 0,
                spec,
            },
        );
        self.record_persist(inner.profile_entries());
        Ok(id)
    }

    /// Removes a node; refuses while it is running (stop it first).
    pub fn remove(&self, id: &str) -> Result<(), String> {
        let mut inner = self.lock();
        let entry = inner
            .nodes
            .get(id)
            .ok_or_else(|| "unknown node".to_string())?;
        if entry.engine.as_ref().is_some_and(Engine::is_alive) {
            return Err("stop the node before removing it".into());
        }
        inner.nodes.remove(id);
        self.record_persist(inner.profile_entries());
        Ok(())
    }

    /// Updates an agent node's runtime preferences (applied at next
    /// start; refused while running so what is shown is what runs).
    ///
    /// Service-address preferences are strictly validated here — strict
    /// `SocketAddr`, loopback-only — matching exactly what the engine's
    /// default-deny security policy will dial for expose agents; failing
    /// at save time beats a `SecurityDenied` buried in the logs.
    pub fn set_prefs(
        &self,
        id: &str,
        transport: Option<TransportKind>,
        hub_quic_addr: Option<String>,
        service_addresses: &[crate::profile::ServiceAddressPref],
    ) -> Result<(), String> {
        let mut inner = self.lock();
        let entry = inner
            .nodes
            .get_mut(id)
            .ok_or_else(|| "unknown node".to_string())?;
        if entry.engine.as_ref().is_some_and(Engine::is_alive) {
            return Err("stop the node before changing its preferences".into());
        }
        let mut overrides = std::collections::BTreeMap::new();
        for pref in service_addresses {
            if !entry.spec.pack_services.iter().any(|s| s.id == pref.id) {
                let valid = entry
                    .spec
                    .pack_services
                    .iter()
                    .map(|s| s.id.as_str())
                    .collect::<Vec<_>>()
                    .join(", ");
                return Err(format!(
                    "service {:?} is not declared by this pack (declared: [{valid}])",
                    pref.id
                ));
            }
            let addr: std::net::SocketAddr = pref.address.trim().parse().map_err(|_| {
                format!(
                    "address for service {:?} must be <ip>:<port> (e.g. 127.0.0.1:3000), \
                     got {:?}",
                    pref.id, pref.address
                )
            })?;
            if !addr.ip().is_loopback() {
                return Err(format!(
                    "address for service {:?} must be loopback (127.0.0.1:port or \
                     [::1]:port) — an expose agent dials its own machine, got {addr}",
                    pref.id
                ));
            }
            overrides.insert(pref.id.clone(), addr.to_string());
        }
        entry.spec.transport = transport;
        entry.spec.hub_quic_addr = hub_quic_addr;
        entry.spec.service_addresses = overrides;
        self.record_persist(inner.profile_entries());
        Ok(())
    }
    /// Updates a node's pack contents in place from `source` — the GUI side
    /// of `node install` (deploy_apply's "update this local node" action):
    /// stop → verify the identity matches → swap the pack (node-local
    /// `state/` carried over; the previous pack kept as
    /// `<pack_dir>.previous`) → refresh the display caches → restore the
    /// start intent. The profile entry (node id, preferences) survives:
    /// same identity, same node. A generation *downgrade* fails loudly at
    /// the next start via the anti-rollback check.
    pub async fn update_pack(&self, id: &str, source: &Path) -> Result<UpdateReport, String> {
        // Snapshot what we need; nothing holds the lock across an await.
        let (pack_dir, principal, desired_running, cached_generation) = {
            let inner = self.lock();
            let entry = inner
                .nodes
                .get(id)
                .ok_or_else(|| "unknown node".to_string())?;
            (
                entry.spec.pack_dir.clone(),
                entry.spec.principal.clone(),
                entry.desired_running,
                entry.spec.generation,
            )
        };
        // Identity must match — an update refreshes a node's pack, never
        // changes who the node is. Both sides go through the shared
        // validation funnel before anything on disk is touched.
        let installed_source = CredentialPack::load_runtime(source)
            .map_err(|e| format!("source pack rejected: {e}"))?;
        let source_principal = pack_principal(&installed_source);
        match principal {
            Some(ref current) if *current != source_principal => {
                return Err(format!(
                    "identity mismatch: this node is {current} but the source pack is \
                     {source_principal} — an update keeps the identity, never changes it"
                ));
            }
            None => {
                return Err(
                    "this node's pack is unreadable, so its identity cannot be verified — \
                     remove the node and add the new pack instead"
                        .into(),
                );
            }
            _ => {}
        }
        // The current pack's generation feeds only the report's "from"
        // display; it must never gate the swap. An unreadable current pack
        // (directory moved aside or emptied — e.g. while re-organizing the
        // dist tree) is exactly what this swap repairs, so fall back to the
        // cached generation and proceed — Update IS the recovery path
        let generation_from = CredentialPack::load_runtime(&pack_dir).map_or_else(
            |e| {
                tracing::warn!(
                    "current pack unreadable ({e}); updating anyway from the \
                         cached generation {cached_generation}"
                );
                cached_generation
            },
            |pack| pack.metadata.generation,
        );

        // Stop unconditionally: it also aborts the renewal supervisor and
        // cancels death-restart retries that could race the swap. The
        // captured intent is restored by `start` below.
        self.stop(id).await?;

        let installed = interflow_cli::node_install::swap_pack_into(source, &pack_dir, None, true)
            .map_err(|e| format!("pack swap failed: {e}"))?;
        let generation_to = installed.metadata.generation;

        // Refresh the display caches from the new content: kind, name, and
        // the declared service set may legitimately change across
        // generations; the node id and every preference survive.
        {
            let mut inner = self.lock();
            let entry = inner
                .nodes
                .get_mut(id)
                .ok_or_else(|| "unknown node".to_string())?;
            entry.spec.kind = NodeKind::classify(&installed);
            let pack_mesh = mesh_rules_from_pack(&installed);
            entry.spec.name = installed.metadata.node;
            entry.spec.principal = Some(source_principal);
            entry.spec.generation = generation_to;
            entry.spec.pack_digest = installed.pack_digest.clone();
            entry.spec.pack_services = installed
                .node_config
                .services
                .iter()
                .map(|s| PackService {
                    id: s.id.clone(),
                    default_address: s.address.clone(),
                })
                .collect();
            entry.spec.pack_mesh = pack_mesh;
            entry
                .spec
                .pack_listen
                .clone_from(&installed.node_config.listen);
        }

        if desired_running {
            self.start(id)?;
        }
        // The pack's leaf changed under the update — refresh the health
        // cache so the next view shows the new expiry, not the old one.
        self.refresh_credential_health();
        Ok(UpdateReport {
            generation_from,
            generation_to,
            restarted: desired_running,
        })
    }

    /// Current list snapshot (profile order is maintained by insertion;
    /// commands sort by name for display).
    pub fn snapshots(&self) -> Vec<NodeSnapshot> {
        let inner = self.lock();
        let mut nodes: Vec<_> = inner
            .nodes
            .values()
            .map(|e| NodeSnapshot {
                spec: e.spec.clone(),
                desired_running: e.desired_running,
                state: e.state.clone(),
            })
            .collect();
        nodes.sort_by(|a, b| a.spec.name.cmp(&b.spec.name));
        nodes
    }

    /// The node's credential health, from the cache when present (the
    /// 5-minute refresher / add-update paths feed it), computed on first
    /// sighting otherwise. `None` = no node, or no active credential set.
    pub fn credential_health(&self, id: &str) -> Option<CredentialHealth> {
        {
            let cache = self
                .credential_health
                .lock()
                .unwrap_or_else(PoisonError::into_inner);
            if let Some(h) = cache.get(id) {
                return Some(h.clone());
            }
        }
        let pack_dir = self.lock().nodes.get(id)?.spec.pack_dir.clone();
        let pack = CredentialPack::load_runtime(&pack_dir).ok()?;
        let health = pack_credential_health(&pack)?;
        self.credential_health
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .insert(id.to_string(), health.clone());
        Some(health)
    }

    /// Drops and recomputes every cached credential health (add / update /
    /// rotate paths call this so the next view reads the fresh pack).
    pub fn refresh_credential_health(&self) {
        refresh_health_cache(&self.inner, &self.credential_health);
    }

    /// The policy-plane face for one node (mesh agents only — the surface
    /// is "policy health", and only mesh agents carry a policy watcher). A
    /// running agent reports its watcher's live values (no disk IO); a
    /// stopped agent falls back to the same authoritative pack load the
    /// start path uses, so the stopped view equals what a restart would
    /// run. `None` = no node / not a mesh agent / pack unreadable.
    pub fn policy_plane(&self, id: &str) -> Option<PolicyPlane> {
        let (kind, pack_dir, live) = {
            let inner = self.lock();
            let entry = inner.nodes.get(id)?;
            let live = match entry.engine.as_ref() {
                Some(Engine::Agent { handle }) => {
                    handle.policy_state().map(|state| state.snapshot())
                }
                _ => None,
            };
            (entry.spec.kind, entry.spec.pack_dir.clone(), live)
        };
        if kind != NodeKind::MeshAgent {
            return None;
        }
        if let Some(snapshot) = live {
            return Some(PolicyPlane::live(snapshot));
        }
        let pack = CredentialPack::load_runtime(&pack_dir).ok()?;
        Some(PolicyPlane {
            generation: pack.policy.generation,
            source: if pack.policy_from_state_channel {
                PolicySource::StatePolicy
            } else {
                PolicySource::Pack
            },
            hub_generation: None,
            pull: None,
        })
    }

    /// The peer-plane face for one node (mesh agents only). A running
    /// agent reports its watcher's live reading; a stopped agent has no
    /// live presence reading to show — `None` (deliberately no stale
    /// last-known display: presence is meaningless without the session
    /// that observed it).
    pub fn peers_plane(&self, id: &str) -> Option<PeersPlane> {
        let inner = self.lock();
        let entry = inner.nodes.get(id)?;
        if entry.spec.kind != NodeKind::MeshAgent {
            return None;
        }
        match entry.engine.as_ref() {
            Some(Engine::Agent { handle }) => {
                Some(PeersPlane::live(handle.peer_state().snapshot()))
            }
            _ => None,
        }
    }

    /// Submits one self-service stream proposal through the running
    /// agent's current session (the kube-CSR face). Requires the node to
    /// be a RUNNING mesh agent.
    pub async fn submit_stream_proposal(
        &self,
        id: &str,
        request: &interflow_core::tunnel::transport::StreamProposalRequest,
    ) -> Result<interflow_core::tunnel::transport::ProposalSubmitOutcome, String> {
        let tunnel = {
            let inner = self.lock();
            let entry = inner
                .nodes
                .get(id)
                .ok_or_else(|| "unknown node".to_string())?;
            match entry.engine.as_ref() {
                Some(Engine::Agent { handle }) if entry.spec.kind == NodeKind::MeshAgent => {
                    handle.control_tunnel()
                }
                _ => return Err("node is not a running mesh agent".to_string()),
            }
        };
        tunnel
            .submit_stream_proposal(request)
            .await
            .map_err(|e| e.to_string())
    }

    /// The proposal receipts face for one node (running mesh agents only).
    pub fn proposals_plane(
        &self,
        id: &str,
    ) -> Option<Vec<interflow_core::tunnel::transport::ProposalReceipt>> {
        let inner = self.lock();
        let entry = inner.nodes.get(id)?;
        if entry.spec.kind != NodeKind::MeshAgent {
            return None;
        }
        match entry.engine.as_ref() {
            Some(Engine::Agent { handle }) => Some(handle.proposal_state().snapshot()),
            _ => None,
        }
    }

    /// The ingress-listeners actual-state face for one node (running mesh
    /// agents only). A stopped agent has no listeners serving — `None`
    /// (same no-stale-display discipline as [`Self::peers_plane`]).
    pub fn listeners_plane(&self, id: &str) -> Option<Vec<ListenerStatusFace>> {
        let inner = self.lock();
        let entry = inner.nodes.get(id)?;
        if entry.spec.kind != NodeKind::MeshAgent {
            return None;
        }
        match entry.engine.as_ref() {
            Some(Engine::Agent { handle }) => Some(ListenerStatusFace::live(
                handle.ingress_listeners_snapshot(),
            )),
            _ => None,
        }
    }

    pub fn state(&self, id: &str) -> Option<NodeState> {
        self.lock().nodes.get(id).map(|e| e.state.clone())
    }

    // ------------------------------------------------------------------
    // Lifecycle
    // ------------------------------------------------------------------

    /// User start. `prepare` runs outside the lock (pack loading is file
    /// IO); the aliveness check and the engine store are one atomic
    /// critical section, so concurrent double-starts cannot exist.
    pub fn start(&self, id: &str) -> Result<(), String> {
        let spec = {
            let inner = self.lock();
            inner
                .nodes
                .get(id)
                .map(|e| e.spec.clone())
                .ok_or_else(|| "unknown node".to_string())?
        };
        let prepared = prepare(&spec)?;
        let mut inner = self.lock();
        let entry = inner
            .nodes
            .get_mut(id)
            .ok_or_else(|| "unknown node".to_string())?;
        if entry.engine.as_ref().is_some_and(Engine::is_alive) {
            return Err("node is already running".into());
        }
        entry.engine = None; // drop any dead handle
        entry.expected_stop = false;
        entry.desired_running = true;
        entry.restart = SupervisorRestartPolicy::new();
        entry.generation += 1;
        // Effective service list on the start line (expose agents): dial
        // targets from the freshly resolved `prepare` output — the pack was
        // just re-read — each tagged with its origin via the shared
        // `id=addr(override|default)` vocabulary. This is the log-view
        // answer to "did my local preference take effect" (2026-09-23
        // backlog); the expose engine's own startup line repeats it as a
        // second, engine-side source.
        let services = match &prepared {
            Prepared::Expose(args) => interflow_expose::client::service_log_summary(&args.services),
            _ => String::new(),
        };
        tracing::info!(
            node = %log_attribution(&entry.spec),
            "node starting ({}){}",
            entry.spec.kind.label(),
            if services.is_empty() {
                String::new()
            } else {
                format!(": services {services}")
            }
        );
        self.start_locked(id, entry, prepared)?;
        self.record_persist(inner.profile_entries());
        Ok(())
    }

    /// Build the engine, wire listeners + renewal. Called with the lock
    /// held; everything here is spawn-and-return (the same property that
    /// made the tunnel manager's critical sections safe).
    ///
    /// The `enter` guard makes this — and the engine crates' spawn-and-return
    /// constructors it calls, several layers down — safe from threads
    /// without an ambient Tokio runtime (Tauri's sync-command pool). It is
    /// idempotent on threads that are already inside `rt`. The guard is
    /// synchronous and lock-free, so holding it across the critical section
    /// cannot deadlock.
    fn start_locked(
        &self,
        id: &str,
        entry: &mut NodeEntry,
        prepared: Prepared,
    ) -> Result<(), String> {
        let _rt = self.rt.enter();
        let generation = entry.generation;
        match prepared {
            Prepared::Expose(args) => {
                let handle = interflow_expose::client::start(&args)
                    .map_err(|e| format!("cannot start: {e}"))?;
                self.clone()
                    .spawn_agent_listener(id, generation, handle.subscribe_state());
                entry.state = handle.state().into();
                entry.engine = Some(Engine::Agent { handle });
            }
            Prepared::Mesh { config, .. } => {
                let handle = AgentClient::new(config)
                    .map_err(|e| format!("cannot start: {e}"))?
                    .start();
                // The signed-policy watcher is the engine's own (the config
                // carries the policy plane) — same path the CLI binary and
                // every e2e take; there is no GUI-side wiring to drift. The
                // subscription is taken while the Arc is still borrowed and
                // dropped immediately after: the forwarder must hold only
                // the receiver, or it would keep the watch sender (and the
                // watcher's state) alive past the engine's shutdown.
                let policy_rx = handle.policy_state().map(|state| state.subscribe());
                if let Some(rx) = policy_rx {
                    self.clone().spawn_policy_forwarder(id, rx);
                }
                // The peer watcher is likewise the engine's own (every mesh
                // agent has one — the agents control plane needs no pack).
                // Same subscription-taken-early contract as the policy
                // forwarder above.
                let peers_rx = handle.peer_state().subscribe();
                self.clone().spawn_peers_forwarder(id, peers_rx);
                // The proposal receipts face rides the same task; its
                // forwarder mirrors the peers one.
                let proposals_rx = handle.proposal_state().subscribe();
                self.clone().spawn_proposals_forwarder(id, proposals_rx);
                // The ingress-listener actual-state face (what is really
                // listening) — the 2026-10-09 honesty axis. Same
                // hold-only-the-subscription contract.
                let listeners_rx = handle.subscribe_ingress_listeners();
                self.clone().spawn_listeners_forwarder(id, listeners_rx);
                self.clone()
                    .spawn_agent_listener(id, generation, handle.subscribe_state());
                entry.state = handle.state().into();
                entry.engine = Some(Engine::Agent { handle });
            }
            Prepared::Hub { config } => {
                // The ACL hot-swap watcher rides the hub's run future (the
                // config's policy plane names the pack) — same path the hub
                // binary takes.
                let handle = HubHandle::spawn(config).map_err(|e| format!("cannot start: {e}"))?;
                self.clone()
                    .spawn_hub_listener(id, generation, handle.subscribe_state());
                entry.state = handle.state().into();
                entry.engine = Some(Engine::Hub { handle });
            }
            Prepared::Ingress(config) => {
                let engine = FutureEngine::spawn_ingress(config, &self.rt);
                self.clone()
                    .spawn_lifecycle_listener(id, generation, engine.state.clone());
                entry.state = engine.state();
                entry.engine = Some(Engine::Ingress(engine));
            }
        }
        entry.renewal = Some(self.spawn_renewal(
            id,
            generation,
            entry.spec.pack_dir.clone(),
            log_attribution(&entry.spec),
        ));
        self.record_state(id, &entry.state);
        Ok(())
    }

    /// User stop: clears the start intent, cancels renewal, shuts the
    /// engine down gracefully. Also the escape hatch from any restart loop
    /// (the generation bump silences in-flight listeners).
    pub async fn stop(&self, id: &str) -> Result<(), String> {
        let (engine, name) = {
            let mut inner = self.lock();
            let Some(entry) = inner.nodes.get_mut(id) else {
                return Err("unknown node".into());
            };
            entry.expected_stop = true;
            entry.desired_running = false;
            if let Some(renewal) = entry.renewal.take() {
                renewal.abort();
            }
            let engine = entry.engine.take();
            let name = engine.as_ref().map(|_| log_attribution(&entry.spec));
            entry.generation += 1;
            self.record_persist(inner.profile_entries());
            (engine, name)
        };
        if let Some(engine) = engine {
            engine.shutdown_graceful().await?;
            // Logged only for an actual shutdown — a stop of an
            // already-stopped node is a no-op with nothing to attribute.
            // Hoisted out of the critical section (the `renewal_completed`
            // pattern) so the line lands after the engine is down, before
            // the terminal state write.
            if let Some(name) = name {
                tracing::info!(node = %name, "node stopped (user request)");
            }
        }
        let mut inner = self.lock();
        if let Some(entry) = inner.nodes.get_mut(id) {
            entry.state = NodeState::Stopped;
            let state = entry.state.clone();
            self.record_state(id, &state);
        }
        Ok(())
    }

    /// Stops every running node concurrently (app quit).
    pub async fn stop_all(&self) {
        let engines: Vec<(NodeId, Engine)> = {
            let mut inner = self.lock();
            let engines = inner
                .nodes
                .iter_mut()
                .filter_map(|(id, entry)| {
                    entry.expected_stop = true;
                    entry.desired_running = false;
                    if let Some(renewal) = entry.renewal.take() {
                        renewal.abort();
                    }
                    entry
                        .engine
                        .take()
                        .filter(Engine::is_alive)
                        .map(|e| (id.clone(), e))
                })
                .collect();
            self.record_persist(inner.profile_entries());
            engines
        };
        let mut set = tokio::task::JoinSet::new();
        for (id, engine) in engines {
            let manager = self.clone();
            set.spawn(async move {
                let _ = engine.shutdown_graceful().await;
                let mut inner = manager.lock();
                if let Some(entry) = inner.nodes.get_mut(&id) {
                    entry.state = NodeState::Stopped;
                    // Terminal attribution line, logged only for engines
                    // this stop_all actually shut down (the final sink loop
                    // below also touches long-stopped nodes — those must
                    // not produce lines).
                    tracing::info!(
                        node = %log_attribution(&entry.spec),
                        "node stopped (stop-all)"
                    );
                }
            });
        }
        while set.join_next().await.is_some() {}
        // One final sink per node so the UI/tray see the terminal state.
        let inner = self.lock();
        for (id, entry) in &inner.nodes {
            if matches!(entry.state, NodeState::Stopped) {
                self.record_state(id, &NodeState::Stopped);
            }
        }
    }

    /// Starts every node whose persisted intent says on (GUI launch).
    pub fn start_desired(&self) {
        let ids: Vec<NodeId> = {
            let inner = self.lock();
            inner
                .nodes
                .iter()
                .filter(|(_, e)| e.desired_running)
                .map(|(id, _)| id.clone())
                .collect()
        };
        for id in ids {
            if let Err(e) = self.start(&id) {
                let mut inner = self.lock();
                if let Some(entry) = inner.nodes.get_mut(&id) {
                    tracing::error!(node = %log_attribution(&entry.spec), "desired-start failed: {e}");
                    entry.state = NodeState::Failed { error: e.clone() };
                    let state = entry.state.clone();
                    self.record_state(&id, &state);
                }
            }
        }
    }

    // ------------------------------------------------------------------
    // Observation + recovery (spawned tasks)
    // ------------------------------------------------------------------

    /// Records an observed state for a node (generation-checked) and fans
    /// it out to the sinks. Runs from listener tasks.
    #[allow(clippy::needless_pass_by_value)] // ownership flows into the entry
    fn observe(&self, id: &str, generation: u64, state: NodeState) {
        let mut inner = self.lock();
        let Some(entry) = inner.nodes.get_mut(id) else {
            return;
        };
        if entry.generation != generation {
            return; // stale listener (a newer start/stop happened)
        }
        entry.state = state.clone();
        self.record_state(id, &state);
    }

    /// Mesh agents: forwards the engine watcher's policy telemetry into
    /// the event queue (→ [`PolicySink`] → the GUI's policy health panel,
    /// which otherwise only samples at `list_nodes` time and reads a
    /// converged system as frozen). The task holds only the subscription:
    /// when the engine shuts down and the watcher's state — and with it the
    /// watch sender — is dropped, `changed()` errors and the forwarder
    /// rides out with the engine it mirrors, no separate token involved.
    fn spawn_policy_forwarder(
        self,
        id: &str,
        mut rx: tokio::sync::watch::Receiver<interflow_mesh::agent::PolicyWatchSnapshot>,
    ) {
        let rt = self.rt.clone();
        let manager = self;
        let id = id.to_string();
        rt.spawn(async move {
            while rx.changed().await.is_ok() {
                let plane = PolicyPlane::live(*rx.borrow_and_update());
                let _ = manager.events.send(ManagerEvent::PolicyPlane {
                    id: id.clone(),
                    plane,
                });
            }
        });
    }

    /// Mesh agents: forwards the engine peer watcher's telemetry into the
    /// event queue (→ [`PeersSink`] → the GUI's Peers section). Same
    /// hold-only-the-subscription contract as
    /// [`Self::spawn_policy_forwarder`].
    fn spawn_peers_forwarder(
        self,
        id: &str,
        mut rx: tokio::sync::watch::Receiver<interflow_mesh::agent::PeerWatchSnapshot>,
    ) {
        let rt = self.rt.clone();
        let manager = self;
        let id = id.to_string();
        rt.spawn(async move {
            while rx.changed().await.is_ok() {
                let plane = PeersPlane::live(rx.borrow_and_update().clone());
                let _ = manager.events.send(ManagerEvent::PeersPlane {
                    id: id.clone(),
                    plane,
                });
            }
        });
    }

    /// Mesh agents: forwards the engine's proposal receipts into the event
    /// queue (→ [`ProposalsSink`] → the GUI's "Requested streams" face).
    /// Same hold-only-the-subscription contract as
    /// [`Self::spawn_policy_forwarder`].
    fn spawn_proposals_forwarder(
        self,
        id: &str,
        mut rx: tokio::sync::watch::Receiver<
            Vec<interflow_core::tunnel::transport::ProposalReceipt>,
        >,
    ) {
        let rt = self.rt.clone();
        let manager = self;
        let id = id.to_string();
        rt.spawn(async move {
            while rx.changed().await.is_ok() {
                let receipts = rx.borrow_and_update().clone();
                let _ = manager.events.send(ManagerEvent::Proposals {
                    id: id.clone(),
                    receipts,
                });
            }
        });
    }

    /// Mesh agents: forwards the engine's ingress-listener actual state
    /// into the event queue (→ [`ListenersSink`] → the GUI's listeners
    /// face). The watch carries the full table on every mutation, so this
    /// is exactly the peers/policy forwarder shape — hold only the
    /// subscription; when the agent handle drops, the sender goes with it,
    /// `changed()` errors, and the task rides down with the engine.
    fn spawn_listeners_forwarder(
        self,
        id: &str,
        mut rx: tokio::sync::watch::Receiver<
            std::sync::Arc<HashMap<String, interflow_mesh::agent::ListenerStatus>>,
        >,
    ) {
        let rt = self.rt.clone();
        let manager = self;
        let id = id.to_string();
        rt.spawn(async move {
            while rx.changed().await.is_ok() {
                let faces = ListenerStatusFace::live((**rx.borrow_and_update()).clone());
                let _ = manager.events.send(ManagerEvent::Listeners {
                    id: id.clone(),
                    faces,
                });
            }
        });
    }

    /// Agent engines: rich state stream + healthy-streak accounting + dead
    /// supervisor detection (the watch stream ends when the supervisor
    /// task is gone).
    fn spawn_agent_listener(
        self,
        id: &str,
        generation: u64,
        mut rx: tokio::sync::watch::Receiver<AgentState>,
    ) {
        let rt = self.rt.clone();
        let manager = self;
        let id = id.to_string();
        rt.spawn(async move {
            let mut connected_since: Option<Instant> = None;
            loop {
                let state = rx.borrow_and_update().clone();
                if matches!(state, AgentState::Connected { .. }) {
                    connected_since.get_or_insert_with(Instant::now);
                    if let Some(since) = connected_since {
                        let streak = since.elapsed();
                        let mut inner = manager.lock();
                        if let Some(entry) = inner.nodes.get_mut(&id)
                            && entry.generation == generation
                        {
                            entry.restart.note_healthy_streak(streak);
                        }
                    }
                } else {
                    connected_since = None;
                }
                manager.observe(&id, generation, state.into());
                if rx.changed().await.is_err() {
                    let final_state = rx.borrow().clone();
                    let proceed = {
                        let mut inner = manager.lock();
                        matches!(
                            inner.nodes.get_mut(&id),
                            Some(entry)
                                if entry.generation == generation
                                    && !entry.expected_stop
                                    && !matches!(
                                        final_state,
                                        AgentState::Stopped | AgentState::Failed { .. }
                                    )
                        )
                    };
                    manager.observe(&id, generation, final_state.into());
                    if proceed {
                        let manager2 = manager.clone();
                        manager.rt.clone().spawn(async move {
                            manager2.restart_after_death(id, generation).await;
                        });
                    }
                    return;
                }
            }
        });
    }

    /// Hub engines: lifecycle watch; a terminal state without an expected
    /// stop is a death.
    fn spawn_hub_listener(
        self,
        id: &str,
        generation: u64,
        mut rx: tokio::sync::watch::Receiver<HubLifecycle>,
    ) {
        let rt = self.rt.clone();
        let manager = self;
        let id = id.to_string();
        rt.spawn(async move {
            loop {
                let state = rx.borrow_and_update().clone();
                let terminal = matches!(state, HubLifecycle::Stopped | HubLifecycle::Failed { .. });
                let failed = matches!(state, HubLifecycle::Failed { .. });
                manager.observe(&id, generation, state.into());
                if terminal {
                    let proceed = {
                        let mut inner = manager.lock();
                        matches!(
                            inner.nodes.get_mut(&id),
                            Some(entry)
                                if entry.generation == generation
                                    && !entry.expected_stop
                                    && failed
                        )
                    };
                    if proceed {
                        let manager2 = manager.clone();
                        manager.rt.clone().spawn(async move {
                            manager2.restart_after_death(id, generation).await;
                        });
                    }
                    return;
                }
                if rx.changed().await.is_err() {
                    return; // monitor closed after the terminal send
                }
            }
        });
    }

    /// Ingress engines: already-normalized lifecycle watch.
    fn spawn_lifecycle_listener(
        self,
        id: &str,
        generation: u64,
        mut rx: tokio::sync::watch::Receiver<NodeState>,
    ) {
        let rt = self.rt.clone();
        let manager = self;
        let id = id.to_string();
        rt.spawn(async move {
            loop {
                let state = rx.borrow_and_update().clone();
                let terminal = matches!(state, NodeState::Stopped | NodeState::Failed { .. });
                let failed = matches!(state, NodeState::Failed { .. });
                manager.observe(&id, generation, state);
                if terminal {
                    let proceed = {
                        let mut inner = manager.lock();
                        matches!(
                            inner.nodes.get_mut(&id),
                            Some(entry)
                                if entry.generation == generation
                                    && !entry.expected_stop
                                    && failed
                        )
                    };
                    if proceed {
                        let manager2 = manager.clone();
                        manager.rt.clone().spawn(async move {
                            manager2.restart_after_death(id, generation).await;
                        });
                    }
                    return;
                }
                if rx.changed().await.is_err() {
                    return;
                }
            }
        });
    }

    /// Bounded auto-restart after an engine death: backoff → prepare from
    /// the pack → rebuild. Boxed: the call graph is recursive (restart →
    /// start_locked → listener → restart), same shape as the tunnel
    /// manager's loop before it.
    fn restart_after_death(
        self,
        id: String,
        generation: u64,
    ) -> Pin<Box<dyn Future<Output = ()> + Send>> {
        Box::pin(async move {
            loop {
                let decision = {
                    let mut inner = self.lock();
                    let Some(entry) = inner.nodes.get_mut(&id) else {
                        return;
                    };
                    if entry.generation != generation {
                        return; // a newer start/stop owns this node now
                    }
                    entry.restart.on_supervisor_death()
                };
                match decision {
                    RestartDecision::GiveUp => {
                        let mut inner = self.lock();
                        if let Some(entry) = inner.nodes.get_mut(&id)
                            && entry.generation == generation
                        {
                            entry.engine = None;
                            entry.state = NodeState::Failed {
                                error: "engine exited unexpectedly; automatic restart \
                                        attempts exhausted"
                                    .into(),
                            };
                            let attribution = log_attribution(&entry.spec);
                            let state = entry.state.clone();
                            tracing::error!(node = %attribution, "{state:?}");
                            self.record_state(&id, &state);
                        }
                        return;
                    }
                    RestartDecision::RestartIn(backoff) => {
                        let backoff_secs = backoff.as_secs();
                        self.observe(
                            &id,
                            generation,
                            NodeState::Reconnecting {
                                reason: "engine exited unexpectedly; restarting".into(),
                                backoff_secs: u32::try_from(backoff_secs).unwrap_or(u32::MAX),
                            },
                        );
                        tokio::time::sleep(backoff).await;
                        // Re-read under the same lock the stop path clears
                        // intent with: a stop that ran while we slept wins.
                        let spec = {
                            let inner = self.lock();
                            match inner.nodes.get(&id) {
                                Some(entry)
                                    if entry.generation == generation && !entry.expected_stop =>
                                {
                                    entry.spec.clone()
                                }
                                _ => return,
                            }
                        };
                        let prepared = match prepare(&spec) {
                            Ok(p) => p,
                            // Config/pack gone: burn an attempt and retry.
                            Err(e) => {
                                tracing::warn!(node = %log_attribution(&spec), "restart prepare failed: {e}");
                                continue;
                            }
                        };
                        let mut inner = self.lock();
                        let Some(entry) = inner.nodes.get_mut(&id) else {
                            return;
                        };
                        if entry.generation != generation || entry.expected_stop {
                            return;
                        }
                        entry.engine = None; // clear the dead engine
                        tracing::info!(node = %log_attribution(&entry.spec), "restarting after unexpected exit");
                        if self.start_locked(&id, entry, prepared).is_ok() {
                            return; // fresh listener + renewal own it now
                        }
                        // Build itself failed: loop for the next budgeted
                        // attempt or GiveUp.
                    }
                }
            }
        })
    }

    /// One renewal future beside the engine (parity with every binary entry
    /// point). Aborted by stop; its completion drives the rotation/renewal
    /// failure paths below. Returns the abort handle for the caller to
    /// store in the node entry.
    fn spawn_renewal(
        &self,
        id: &str,
        generation: u64,
        pack_dir: PathBuf,
        log_name: String,
    ) -> tokio::task::AbortHandle {
        let renewal = self.renewal.clone();
        let manager = self.clone();
        let id = id.to_string();
        self.rt
            .spawn(async move {
                match (renewal)(pack_dir, log_name).await {
                    Ok(()) => manager.renewal_completed(&id, generation).await,
                    Err(e) => manager.renewal_failed(&id, generation, e),
                }
            })
            .abort_handle()
    }

    /// Rotation completed: gracefully stop, rebuild from the pack (the
    /// freshly written credential generation), start again. The in-process
    /// equivalent of the binaries' "return Ok so systemd restarts us".
    async fn renewal_completed(&self, id: &str, generation: u64) {
        let name = {
            let mut inner = self.lock();
            let Some(entry) = inner.nodes.get_mut(id) else {
                return;
            };
            if entry.generation != generation {
                return;
            }
            entry.renewal = None;
            entry.expected_stop = true; // silence the dying engine's listeners
            log_attribution(&entry.spec)
        };
        tracing::info!(node = %name, "credentials renewed — restarting onto the new generation");
        self.observe(
            id,
            generation,
            NodeState::Reconnecting {
                reason: "credentials renewed — restarting".into(),
                backoff_secs: 0,
            },
        );
        let engine = {
            let mut inner = self.lock();
            inner
                .nodes
                .get_mut(id)
                .and_then(|entry| entry.engine.take())
        };
        if let Some(engine) = engine {
            let _ = engine.shutdown_graceful().await;
        }
        let spec = {
            let inner = self.lock();
            match inner.nodes.get(id) {
                Some(entry) if entry.generation == generation => entry.spec.clone(),
                _ => return,
            }
        };
        let prepared = match prepare(&spec) {
            Ok(p) => p,
            Err(e) => {
                tracing::error!(node = %name, "rebuild after renewal failed: {e}");
                let mut inner = self.lock();
                if let Some(entry) = inner.nodes.get_mut(id)
                    && entry.generation == generation
                {
                    entry.state = NodeState::Failed { error: e };
                    let state = entry.state.clone();
                    self.record_state(id, &state);
                }
                return;
            }
        };
        let mut inner = self.lock();
        let Some(entry) = inner.nodes.get_mut(id) else {
            return;
        };
        if entry.generation != generation {
            return;
        }
        // Fresh budget + generation: this is a planned restart, not a crash.
        entry.expected_stop = false;
        entry.restart = SupervisorRestartPolicy::new();
        entry.generation += 1;
        entry.engine = None;
        if let Err(e) = self.start_locked(id, entry, prepared) {
            entry.state = NodeState::Failed { error: e };
            let state = entry.state.clone();
            self.record_state(id, &state);
        }
    }

    /// Renewal failed (credential expired / CRL stale beyond the bound):
    /// the engine cannot stay up — stop it and surface the reason.
    fn renewal_failed(
        &self,
        id: &str,
        generation: u64,
        error: interflow_core::error::InterflowError,
    ) {
        let (engine, name) = {
            let mut inner = self.lock();
            let Some(entry) = inner.nodes.get_mut(id) else {
                return;
            };
            if entry.generation != generation {
                return;
            }
            entry.renewal = None;
            entry.expected_stop = true;
            entry.state = NodeState::Failed {
                error: error.to_string(),
            };
            let state = entry.state.clone();
            self.record_state(id, &state);
            (entry.engine.take(), log_attribution(&entry.spec))
        };
        tracing::error!(node = %name, "credential renewal failed: {error}");
        let manager = self.clone();
        let id = id.to_string();
        self.rt.spawn(async move {
            if let Some(engine) = engine {
                let _ = engine.shutdown_graceful().await;
            }
            // Confirm the terminal state after the shutdown settles (the
            // dying engine's listeners are silenced by expected_stop).
            manager.observe(
                &id,
                generation,
                NodeState::Failed {
                    error: error.to_string(),
                },
            );
        });
    }
}

/// Profile entry → node spec (restore path). `desired_running` rides along
/// so the caller can persist it back verbatim.
struct SpecWithIntent {
    spec: NodeSpec,
    desired_running: bool,
}

fn spec_from_profile(persisted: crate::profile::NodeEntry) -> SpecWithIntent {
    let pack_dir = PathBuf::from(&persisted.pack_dir);
    let (
        kind,
        name,
        principal,
        pack_services,
        pack_mesh,
        pack_listen,
        pack_transport,
        generation,
        pack_digest,
    ) = match CredentialPack::load_runtime(&pack_dir) {
        Ok(pack) => {
            let principal = Some(pack_principal(&pack));
            let services = pack
                .node_config
                .services
                .iter()
                .map(|s| PackService {
                    id: s.id.clone(),
                    default_address: s.address.clone(),
                })
                .collect();
            let mesh = mesh_rules_from_pack(&pack);
            let listen = pack.node_config.listen.clone();
            let transport = (!pack.node_config.transport.is_empty())
                .then(|| pack.node_config.transport.clone());
            (
                NodeKind::classify(&pack),
                pack.metadata.node,
                principal,
                services,
                mesh,
                listen,
                transport,
                pack.metadata.generation,
                pack.pack_digest,
            )
        }
        Err(_) => (
            // Placeholder for display only: `prepare` re-validates and
            // fails with the pack's real error at start. No principal —
            // add-time identity dedup skips unreadable placeholders.
            NodeKind::ExposeAgent,
            pack_dir.file_name().map_or_else(
                || persisted.pack_dir.clone(),
                |n| n.to_string_lossy().into_owned(),
            ),
            None,
            Vec::new(),
            None,
            None,
            None,
            0,
            String::new(),
        ),
    };
    let service_addresses = persisted
        .service_addresses
        .into_iter()
        .map(|p| (p.id, p.address))
        .collect();
    SpecWithIntent {
        spec: NodeSpec {
            id: persisted.id,
            kind,
            name,
            principal,
            pack_dir,
            transport: persisted.transport,
            hub_quic_addr: persisted.hub_quic_addr,
            generation,
            pack_digest,
            pack_services,
            pack_mesh,
            pack_listen,
            pack_transport,
            service_addresses,
        },
        desired_running: persisted.desired_running,
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn node_state_maps_agent_and_hub_lifecycles() {
        let receipt = interflow_mesh::agent::HubReceipt {
            egress_ip: Some("203.0.113.7".into()),
            registered_at_unix: 1_759_171_200,
        };
        assert_eq!(
            NodeState::from(AgentState::Connected {
                agent_id: "lan-a".into(),
                hub_receipt: Some(receipt.clone()),
            }),
            NodeState::Connected {
                agent_id: "lan-a".into(),
                hub_receipt: Some(receipt),
            }
        );
        assert_eq!(NodeState::from(HubLifecycle::Running), NodeState::Running);
        assert_eq!(
            NodeState::from(HubLifecycle::Failed {
                error: "bind".into()
            }),
            NodeState::Failed {
                error: "bind".into()
            }
        );
    }

    // ------------------------------------------------------------------
    // Lifecycle tests against real Credential Packs (manifest → issuer →
    // rendered packs — the same funnel as crates/mesh's
    // pack_site_to_site.rs acceptance test, driven through the manager).
    // ------------------------------------------------------------------

    /// A never-started pack reports its bootstrap identities' health (the
    /// credentials its first start will use): healthy, essentially the
    /// full leaf TTL remaining, RFC 3339 not_after. (The phase MATH —
    /// 20%/10% boundaries, expired, both entries agreeing — is unit-locked
    /// in identity's expiry module; this locks the GUI plumbing.)
    #[test]
    fn fresh_pack_reports_bootstrap_leaf_health() {
        let dir = tempfile::tempdir().unwrap();
        let issuer = IssuerStore::open(dir.path().join("issuer"));
        issuer.ensure_realm().unwrap();
        issuer.ensure_workspace("alpha").unwrap();
        issuer.ensure_policy_key().unwrap();
        let manifest = Manifest::parse(
            r#"
[realm]
id = "gui-test"
[registrar]
endpoint = "https://registrar.example.com"
[mesh.hub.central]
listen = "127.0.0.1:1"
endpoint = "127.0.0.1:1"
[workspace.alpha]
[agent.lan-a]
workspace = "alpha"
[[agent.lan-a.mesh_egress]]
name = "svc"
target_addr = "127.0.0.1:1"
"#,
        )
        .unwrap();
        let pack_dir = dir.path().join("packs/agent-lan-a");
        AgentCredentialPack::render(&issuer, &manifest, "lan-a", 1, &pack_dir).unwrap();
        let pack = CredentialPack::load_runtime(&pack_dir).unwrap();
        let health = pack_credential_health(&pack)
            .expect("a rendered pack carries bootstrap identities with expiries");
        assert_eq!(
            health.phase,
            interflow_identity::expiry::LeafPhase::Healthy,
            "a freshly rendered pack is inside its window with room"
        );
        // Registrar tier: 24h leaf, rendered moments ago.
        assert!(
            health.remaining_secs > 23 * 3600,
            "remaining: {}",
            health.remaining_secs
        );
        assert!(
            health.not_after.ends_with('Z'),
            "RFC 3339 UTC: {}",
            health.not_after
        );
    }

    use interflow_identity::issuance::IssuerStore;
    use interflow_identity::manifest::Manifest;
    use interflow_identity::pack::render::{
        AgentCredentialPack, HubCredentialPack, IngressCredentialPack,
    };
    use std::sync::Mutex as StdMutex;
    use std::sync::OnceLock;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    struct TestStack {
        manager: NodeManager,
        events: Arc<StdMutex<Vec<(NodeId, NodeState)>>>,
        persisted: Arc<StdMutex<Vec<crate::profile::NodeEntry>>>,
        /// Every policy-plane event the sink delivered — the GUI event
        /// face's recording (what `emit_policy_plane` would push to the
        /// panel).
        policy_events: Arc<StdMutex<Vec<(NodeId, PolicyPlane)>>>,
        /// Every peers-plane event the sink delivered — the recording for
        /// the `mesh-peers` event face. No assertion reads it yet (the
        /// face is wired through the sink seam above); the expectation
        /// un-fulfills the moment one does.
        #[expect(dead_code)]
        peers_events: Arc<StdMutex<Vec<(NodeId, PeersPlane)>>>,
        hub_id: NodeId,
        lan_a_id: NodeId,
        lan_b_id: NodeId,
        listen_port: u16,
        /// The signed-policy test needs re-signing authority: the stack's
        /// issuer (policy key + realm root) plus the ports a gen-2
        /// manifest re-signs.
        issuer: IssuerStore,
        hub_port: u16,
        echo_port: u16,
        lan_a_pack: std::path::PathBuf,
    }

    /// Never-completes renewal (the scheduler's steady state between 50%-TTL
    /// rotations).
    fn pending_renewal() -> RenewalFactory {
        Arc::new(|_pack_dir, _log_name| {
            Box::pin(std::future::pending::<interflow_core::error::Result<()>>())
        })
    }

    /// Renders hub-central + lan-a + lan-b packs and registers them with a
    /// fresh manager. The echo service behind lan-b round-trips TCP bytes.
    async fn stack_with_mesh_site(renewal: RenewalFactory) -> TestStack {
        let hub_port = crate::test_util::free_port();
        let echo_port = crate::test_util::free_port();
        let listen_port = crate::test_util::free_port();

        // The service behind lan-b: a plain TCP echo server.
        let echo = tokio::net::TcpListener::bind(("127.0.0.1", echo_port))
            .await
            .unwrap();
        tokio::spawn(async move {
            loop {
                let Ok((mut sock, _)) = echo.accept().await else {
                    break;
                };
                tokio::spawn(async move {
                    let mut buf = [0u8; 1024];
                    loop {
                        match sock.read(&mut buf).await {
                            Ok(0) | Err(_) => break,
                            Ok(n) => {
                                if sock.write_all(&buf[..n]).await.is_err() {
                                    break;
                                }
                            }
                        }
                    }
                });
            }
        });

        let dir = tempfile::tempdir().unwrap();
        let issuer = IssuerStore::open(dir.path().join("issuer"));
        issuer.ensure_realm().unwrap();
        issuer.ensure_workspace("alpha").unwrap();
        issuer.ensure_workspace("beta").unwrap();
        issuer.ensure_policy_key().unwrap();

        let manifest = Manifest::parse(&format!(
            r#"
[realm]
id = "gui-test"
[registrar]
endpoint = "https://registrar.example.com"
[mesh.hub.central]
listen = "127.0.0.1:{hub_port}"
endpoint = "127.0.0.1:{hub_port}"
[workspace.alpha]
[workspace.beta]
[agent.lan-a]
workspace = "alpha"
[[agent.lan-a.mesh_ingress]]
name = "svc"
listen = "127.0.0.1:{listen_port}"
target_agent = "lan-b"
remote_addr = "127.0.0.1:{echo_port}"
[agent.lan-b]
workspace = "beta"
[[agent.lan-b.mesh_egress]]
name = "svc"
target_addr = "127.0.0.1:{echo_port}"
"#
        ))
        .unwrap();

        let hub_dir = dir.path().join("packs/hub-central");
        HubCredentialPack::render(&issuer, &manifest, "central", 1, &hub_dir).unwrap();
        let dir_a = dir.path().join("packs/agent-lan-a");
        AgentCredentialPack::render(&issuer, &manifest, "lan-a", 1, &dir_a).unwrap();
        let dir_b = dir.path().join("packs/agent-lan-b");
        AgentCredentialPack::render(&issuer, &manifest, "lan-b", 1, &dir_b).unwrap();
        // Packs must outlive `dir` (the manager reads them at every start).
        std::mem::forget(dir);

        let events: Arc<StdMutex<Vec<(NodeId, NodeState)>>> = Arc::new(StdMutex::new(Vec::new()));
        let persisted: Arc<StdMutex<Vec<crate::profile::NodeEntry>>> =
            Arc::new(StdMutex::new(Vec::new()));
        let policy_events: Arc<StdMutex<Vec<(NodeId, PolicyPlane)>>> =
            Arc::new(StdMutex::new(Vec::new()));
        let peers_events: Arc<StdMutex<Vec<(NodeId, PeersPlane)>>> =
            Arc::new(StdMutex::new(Vec::new()));
        type ProposalSinkEvents = Vec<(
            NodeId,
            Vec<interflow_core::tunnel::transport::ProposalReceipt>,
        )>;
        let proposal_events: Arc<StdMutex<ProposalSinkEvents>> =
            Arc::new(StdMutex::new(Vec::new()));
        // Hostile-sink seam: the GUI's sinks read the manager back
        // (emit_node_state → tray::refresh → snapshots), so these do too —
        // every lifecycle test below is a sentinel for any regression
        // that invokes sinks with the manager lock held. The slot is filled
        // after construction (the sinks outlive the manager's binding).
        let manager_slot: Arc<StdMutex<Option<NodeManager>>> = Arc::new(StdMutex::new(None));
        let sink_events = events.clone();
        let slot_events = manager_slot.clone();
        let sink_persist = persisted.clone();
        let slot_persist = manager_slot.clone();
        let sink_policy = policy_events.clone();
        let sink_peers = peers_events.clone();
        let sink_proposals = proposal_events;
        let manager = NodeManager::with_renewal(
            tokio::runtime::Handle::current(),
            move |id, state| {
                sink_events
                    .lock()
                    .unwrap_or_else(PoisonError::into_inner)
                    .push((id.to_string(), state.clone()));
                if let Some(manager) = slot_events
                    .lock()
                    .unwrap_or_else(PoisonError::into_inner)
                    .as_ref()
                {
                    let _ = manager.snapshots();
                }
            },
            move |entries| {
                *sink_persist.lock().unwrap_or_else(PoisonError::into_inner) = entries.to_vec();
                if let Some(manager) = slot_persist
                    .lock()
                    .unwrap_or_else(PoisonError::into_inner)
                    .as_ref()
                {
                    let _ = manager.snapshots();
                }
            },
            move |id, plane| {
                sink_policy
                    .lock()
                    .unwrap_or_else(PoisonError::into_inner)
                    .push((id.to_string(), plane.clone()));
            },
            move |id, plane| {
                sink_peers
                    .lock()
                    .unwrap_or_else(PoisonError::into_inner)
                    .push((id.to_string(), plane.clone()));
            },
            move |id, receipts| {
                sink_proposals
                    .lock()
                    .unwrap_or_else(PoisonError::into_inner)
                    .push((id.to_string(), receipts.to_vec()));
            },
            |_, _| {}, // no listeners assertion in this stack
            renewal,
        );
        *manager_slot.lock().unwrap_or_else(PoisonError::into_inner) = Some(manager.clone());

        let add = |manager: &NodeManager, dir: std::path::PathBuf| {
            let info = inspect_pack(&dir).expect("pack inspects clean");
            manager
                .add(NodeSpec {
                    generation: info.generation,
                    pack_digest: info.digest.clone(),
                    id: String::new(),
                    kind: info.kind,
                    name: info.name,
                    principal: Some(info.principal),
                    pack_dir: dir,
                    transport: None,
                    hub_quic_addr: None,
                    pack_services: info.services,
                    pack_mesh: info.mesh,
                    pack_listen: info.listen,
                    pack_transport: info.transport,
                    service_addresses: Default::default(),
                })
                .expect("add node")
        };
        let node_hub = add(&manager, hub_dir);
        let node_a = add(&manager, dir_a.clone());
        let node_b = add(&manager, dir_b);

        TestStack {
            manager,
            events,
            persisted,
            policy_events,
            peers_events,
            hub_id: node_hub,
            lan_a_id: node_a,
            lan_b_id: node_b,
            listen_port,
            issuer,
            hub_port,
            echo_port,
            lan_a_pack: dir_a,
        }
    }

    /// Polls until the node reaches a state satisfying `pred`.
    async fn wait_for(
        manager: &NodeManager,
        id: &str,
        pred: impl Fn(&NodeState) -> bool,
        what: &str,
    ) {
        let deadline = Instant::now() + Duration::from_secs(30);
        loop {
            let state = manager
                .state(id)
                .unwrap_or_else(|| panic!("node {id} gone"));
            if pred(&state) {
                return;
            }
            assert!(
                Instant::now() < deadline,
                "node {id} never reached {what} (state: {state:?})"
            );
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    }

    async fn connected(manager: &NodeManager, id: &str) {
        wait_for(
            manager,
            id,
            |s| matches!(s, NodeState::Connected { .. }),
            "Connected",
        )
        .await;
    }

    /// The 2026-09-23 crash, machine-reproduced: `start` must work from a
    /// thread with NO ambient Tokio runtime — Tauri's sync-command pool is
    /// exactly such a thread (the Start button's path). Before the runtime
    /// handle was injected into the manager, the engine crates' bare
    /// `tokio::spawn` panicked ("there is no reactor running"), aborting
    /// the whole app in release builds. A plain `#[tokio::test]` can never
    /// catch this class (its own thread always has a reactor), hence the
    /// dedicated bare thread below.
    #[tokio::test]
    async fn start_off_runtime_thread_still_connects() {
        let stack = stack_with_mesh_site(pending_renewal()).await;
        let manager = stack.manager.clone();

        // Hub first from this (runtime) thread — the GUI's startup-restore
        // path — then the agent from a bare thread — the Start button's.
        manager.start(&stack.hub_id).expect("hub start");
        wait_for(
            &manager,
            &stack.hub_id,
            |s| matches!(s, NodeState::Running),
            "Running",
        )
        .await;

        let id = stack.lan_a_id.clone();
        let off_runtime = std::thread::spawn(move || {
            assert!(
                tokio::runtime::Handle::try_current().is_err(),
                "the bare thread must not carry an ambient runtime"
            );
            manager.start(&id).expect("agent start off the runtime");
        });
        off_runtime
            .join()
            .expect("start must not panic off the runtime");

        connected(&stack.manager, &stack.lan_a_id).await;
        stack.manager.stop_all().await;
    }

    /// The 2026-09-23 Start hang: the GUI's state sink reads the manager
    /// back (frontend event → tray::refresh → snapshots). Invoked with the
    /// manager lock held — as every fire site did before the event-queue
    /// rework — that re-entry self-deadlocks and the whole app beachballs.
    /// The harness sinks above read back too, which makes every lifecycle
    /// test a sentinel; this one additionally bounds the failure so a
    /// regression fails in seconds instead of hanging the suite: `start`
    /// runs on a bare thread (the sync-command shape, as in
    /// [`start_off_runtime_thread_still_connects`]) and the test times out
    /// waiting for it.
    #[tokio::test]
    async fn sink_reading_manager_back_does_not_deadlock() {
        let stack = stack_with_mesh_site(pending_renewal()).await;
        let manager = stack.manager.clone();
        let id = stack.hub_id.clone();
        let (done_tx, done_rx) = std::sync::mpsc::channel::<()>();
        std::thread::spawn(move || {
            manager.start(&id).expect("hub start on a bare thread");
            done_tx.send(()).expect("test still waiting");
        });
        match done_rx.recv_timeout(Duration::from_secs(10)) {
            Ok(()) => {}
            Err(std::sync::mpsc::RecvTimeoutError::Timeout) => panic!(
                "start never returned — a sink invoked with the manager lock \
                 held self-deadlocks exactly here \
                "
            ),
            Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => {
                panic!("start thread died before signalling completion")
            }
        }
        // Consumer-side guard: settle must drain within the bound — a sink
        // invoked while any manager lock is held starves the consumer
        // exactly here (the mutation-side shape is caught above).
        tokio::time::timeout(Duration::from_secs(10), stack.manager.settle())
            .await
            .expect("event consumer drained — a lock held across a sink call starves it");
        let delivered = {
            let events = stack.events.lock().unwrap_or_else(PoisonError::into_inner);
            events.iter().any(|(id, _)| id == &stack.hub_id)
        };
        assert!(
            delivered,
            "state events for the hub must have been delivered"
        );
        wait_for(
            &stack.manager,
            &stack.hub_id,
            |s| matches!(s, NodeState::Running),
            "Running",
        )
        .await;
        stack.manager.stop(&stack.hub_id).await.expect("hub stop");
        wait_for(
            &stack.manager,
            &stack.hub_id,
            |s| *s == NodeState::Stopped,
            "Stopped",
        )
        .await;
    }

    /// Process-wide tracing recorder for attribution assertions — the
    /// test-side stand-in for the GUI's log capture (same
    /// [`crate::tracing_capture::MessageVisitor`], so the field shapes
    /// match what the frontend's strict "This node" filter sees).
    ///
    /// Installed once per test binary via `set_global_default`: manager
    /// and engine events fire from runtime/task threads of every
    /// concurrently-running test, so a thread-local `set_default` misses
    /// most of them. Assertions filter by node attribution, which is
    /// unique per stack, so cross-test events in the shared sink are
    /// inert.
    type RecordedEvents = Arc<StdMutex<Vec<(Option<String>, String)>>>;
    /// Class-level attribution guard sink: (target, node, message). The
    /// (node, message) shape above cannot answer "which module emitted a
    /// bare line", so the mesh-agent zero-bare-lines invariant asserts
    /// against this triple sink instead.
    type AttributionEvents = Arc<StdMutex<Vec<(&'static str, Option<String>, String)>>>;
    /// Shared home of the attribution sink handle: filled by the same
    /// OnceLock init that installs the global test registry (one install,
    /// two recorders).
    static ATTRIBUTED_SINK: OnceLock<AttributionEvents> = OnceLock::new();

    struct RecordingLayer(RecordedEvents);

    impl<S: tracing::Subscriber> tracing_subscriber::Layer<S> for RecordingLayer {
        fn on_event(
            &self,
            event: &tracing::Event<'_>,
            _ctx: tracing_subscriber::layer::Context<'_, S>,
        ) {
            let mut visitor = crate::tracing_capture::MessageVisitor::new();
            event.record(&mut visitor);
            if visitor.message.is_empty() {
                return;
            }
            self.0
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .push((visitor.node, visitor.message));
        }
    }

    struct AttributionLayer(AttributionEvents);

    impl<S: tracing::Subscriber> tracing_subscriber::Layer<S> for AttributionLayer {
        fn on_event(
            &self,
            event: &tracing::Event<'_>,
            _ctx: tracing_subscriber::layer::Context<'_, S>,
        ) {
            let mut visitor = crate::tracing_capture::MessageVisitor::new();
            event.record(&mut visitor);
            if visitor.message.is_empty() {
                return;
            }
            self.0.lock().unwrap_or_else(PoisonError::into_inner).push((
                event.metadata().target(),
                visitor.node,
                visitor.message,
            ));
        }
    }

    fn tracing_recorder() -> RecordedEvents {
        use tracing_subscriber::layer::SubscriberExt as _;
        static RECORDER: OnceLock<RecordedEvents> = OnceLock::new();
        RECORDER
            .get_or_init(|| {
                let sink: RecordedEvents = Arc::new(StdMutex::new(Vec::new()));
                let attributed: AttributionEvents = Arc::new(StdMutex::new(Vec::new()));
                // Process-lifetime global (set_global_default never resets);
                // a second call would Err, but the OnceLock guarantees one.
                // Both layers install in the one registry this OnceLock
                // guards, so either recorder implies the other.
                tracing::subscriber::set_global_default(
                    tracing_subscriber::registry()
                        .with(AttributionLayer(attributed.clone()))
                        .with(RecordingLayer(sink.clone())),
                )
                .expect("no other global subscriber in this test binary");
                ATTRIBUTED_SINK
                    .set(attributed)
                    .expect("set once beside RECORDER");
                sink
            })
            .clone()
    }

    /// The (target, node, message) sink — installed together with
    /// [`tracing_recorder`]'s registry (see above).
    fn attribution_recorder() -> AttributionEvents {
        let _ = tracing_recorder();
        ATTRIBUTED_SINK
            .get()
            .expect("attribution sink installs with the tracing recorder")
            .clone()
    }

    /// Spins until a line with this exact node attribution + message lands
    /// in the recorder: engine-side lines fire from spawned tasks, so
    /// observing the state change does not yet prove the line flushed.
    async fn wait_for_line(recorded: &RecordedEvents, node: &str, message: &str) -> bool {
        let deadline = std::time::Instant::now() + Duration::from_secs(5);
        loop {
            let hit = recorded
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .iter()
                .any(|(n, m)| n.as_deref() == Some(node) && m == message);
            if hit || std::time::Instant::now() > deadline {
                return hit;
            }
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
    }

    /// Same polling shape as [`wait_for_line`], for messages whose dynamic
    /// parts (peer ports, stream ids) rule out an exact match.
    async fn wait_for_line_starting(recorded: &RecordedEvents, node: &str, prefix: &str) -> bool {
        let deadline = std::time::Instant::now() + Duration::from_secs(5);
        loop {
            let hit = recorded
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .iter()
                .any(|(n, m)| n.as_deref() == Some(node) && m.starts_with(prefix));
            if hit || std::time::Instant::now() > deadline {
                return hit;
            }
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
    }

    /// Terminal lifecycle attribution lines (2026-09-23 backlog): a user
    /// Stop must land a `node stopped (user request)` line, stop_all a
    /// `node stopped (stop-all)` line per node it actually shut down — both
    /// with the `node` field in the Display (`%`) shape the "This node"
    /// filter matches, and silent for nodes that were already stopped.
    #[tokio::test]
    async fn stop_and_stop_all_emit_terminal_log_lines() {
        let recorded = tracing_recorder();

        let stack = stack_with_mesh_site(pending_renewal()).await;
        let manager = &stack.manager;
        manager.start(&stack.hub_id).expect("hub start");
        wait_for(
            manager,
            &stack.hub_id,
            |s| matches!(s, NodeState::Running),
            "Running",
        )
        .await;
        manager.start(&stack.lan_b_id).expect("lan-b start");
        manager.start(&stack.lan_a_id).expect("lan-a start");
        connected(manager, &stack.lan_b_id).await;
        connected(manager, &stack.lan_a_id).await;

        let attribution = |id: &str| {
            manager
                .snapshots()
                .into_iter()
                .find(|n| n.spec.id == id)
                .map(|n| log_attribution(&n.spec))
                .expect("node snapshot")
        };
        let has_line = |node: &str, message: &str| {
            recorded
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .iter()
                .any(|(n, m)| n.as_deref() == Some(node) && m == message)
        };

        // User stop → its own terminal line, attribution matching the
        // filter value byte-for-byte.
        let lan_a_attr = attribution(&stack.lan_a_id);
        manager.stop(&stack.lan_a_id).await.expect("lan-a stop");
        wait_for(
            manager,
            &stack.lan_a_id,
            |s| *s == NodeState::Stopped,
            "Stopped",
        )
        .await;
        assert!(
            has_line(&lan_a_attr, "node stopped (user request)"),
            "user stop must log its terminal line with the node attribution; captured: {:?}",
            recorded.lock().unwrap_or_else(PoisonError::into_inner)
        );

        // stop_all → one line per node it actually shut down; the
        // already-stopped lan-a must stay silent.
        manager.stop_all().await;
        wait_for(
            manager,
            &stack.hub_id,
            |s| *s == NodeState::Stopped,
            "Stopped",
        )
        .await;
        wait_for(
            manager,
            &stack.lan_b_id,
            |s| *s == NodeState::Stopped,
            "Stopped",
        )
        .await;
        assert!(
            has_line(&attribution(&stack.hub_id), "node stopped (stop-all)"),
            "stop_all must log the hub's terminal line"
        );
        assert!(
            has_line(&attribution(&stack.lan_b_id), "node stopped (stop-all)"),
            "stop_all must log lan-b's terminal line"
        );
        assert!(
            !has_line(&lan_a_attr, "node stopped (stop-all)"),
            "an already-stopped node must not log a second stop line"
        );
    }

    /// Start-line service visibility (2026-09-23 backlog): the user-facing
    /// start line carries the effective service list — dial targets from
    /// the freshly resolved prepare output, origin-tagged via the shared
    /// `id=addr(override|default)` vocabulary — under the node attribution
    /// the "This node" filter matches, in both the pack-default and the
    /// local-preference forms; the expose engine's own startup line repeats
    /// the list as the second, engine-side source (proposal 1 + 2 as
    /// mutual redundancy).
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn start_emits_effective_services_line() {
        let recorded = tracing_recorder();
        let stack = stack_with_expose_site();
        let manager = &stack.manager;

        manager.start(&stack.ingress_id).expect("ingress start");
        wait_for(
            manager,
            &stack.ingress_id,
            |s| matches!(s, NodeState::Running),
            "Running",
        )
        .await;
        manager.start(&stack.agent_id).expect("agent start");
        connected(manager, &stack.agent_id).await;

        let agent_attr = manager
            .snapshots()
            .into_iter()
            .find(|n| n.spec.id == stack.agent_id)
            .map(|n| log_attribution(&n.spec))
            .expect("agent snapshot");
        // The pack default (a dead port on purpose — stack fixture) is what
        // resolves without preferences.
        let default_addr = manager
            .snapshots()
            .into_iter()
            .find(|n| n.spec.id == stack.agent_id)
            .unwrap()
            .spec
            .pack_services
            .iter()
            .find(|s| s.id == "web")
            .unwrap()
            .default_address
            .clone();

        // Default form: the start line names the pack default.
        assert!(
            wait_for_line(
                &recorded,
                &agent_attr,
                &format!("node starting (expose agent): services web={default_addr}(default)")
            )
            .await,
            "start line must name the pack default; captured: {:?}",
            recorded.lock().unwrap_or_else(PoisonError::into_inner)
        );
        // Engine-side redundancy: the expose client's own startup line
        // carries the attribution (previously the invisible ground truth).
        {
            let deadline = std::time::Instant::now() + Duration::from_secs(5);
            let hit = loop {
                let hit = recorded
                    .lock()
                    .unwrap_or_else(PoisonError::into_inner)
                    .iter()
                    .any(|(n, m)| {
                        n.as_deref() == Some(agent_attr.as_str())
                            && m.starts_with("expose client starting")
                    });
                if hit || std::time::Instant::now() > deadline {
                    break hit;
                }
                tokio::time::sleep(Duration::from_millis(25)).await;
            };
            assert!(
                hit,
                "the expose engine's startup line must be attributed; captured: {:?}",
                recorded.lock().unwrap_or_else(PoisonError::into_inner)
            );
        }

        // Override form: stop → preference → restart; the fresh dial target
        // and the (override) tag replace the default on the same line.
        manager.stop(&stack.agent_id).await.expect("agent stop");
        wait_for(
            manager,
            &stack.agent_id,
            |s| *s == NodeState::Stopped,
            "Stopped",
        )
        .await;
        let pref_port = crate::test_util::free_port();
        manager
            .set_prefs(
                &stack.agent_id,
                None,
                None,
                &[pref("web", &format!("127.0.0.1:{pref_port}"))],
            )
            .expect("set address preference");
        manager.start(&stack.agent_id).expect("agent restart");
        connected(manager, &stack.agent_id).await;
        assert!(
            wait_for_line(
                &recorded,
                &agent_attr,
                &format!(
                    "node starting (expose agent): services web=127.0.0.1:{pref_port}(override)"
                )
            )
            .await,
            "restart after a preference must show the new dial target tagged override; \
             captured: {:?}",
            recorded.lock().unwrap_or_else(PoisonError::into_inner)
        );
    }

    /// Ingress attribution (same backlog, class-level fix): the edge
    /// engine's own lines — including the effective public listener line —
    /// carry the attribution injected at prepare, so the ingress node's
    /// log view answers "which address is the public face on" without
    /// leaving the GUI.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn ingress_engine_lines_carry_node_attribution() {
        let recorded = tracing_recorder();
        let stack = stack_with_expose_site();
        let manager = &stack.manager;

        manager.start(&stack.ingress_id).expect("ingress start");
        wait_for(
            manager,
            &stack.ingress_id,
            |s| matches!(s, NodeState::Running),
            "Running",
        )
        .await;

        let ingress_attr = manager
            .snapshots()
            .into_iter()
            .find(|n| n.spec.id == stack.ingress_id)
            .map(|n| log_attribution(&n.spec))
            .expect("ingress snapshot");
        assert!(
            wait_for_line(
                &recorded,
                &ingress_attr,
                &format!(
                    "Edge public listener started: 127.0.0.1:{} (1 routes)",
                    stack.edge_port
                )
            )
            .await,
            "the effective public listener line must be attributed to the ingress node; \
             captured: {:?}",
            recorded.lock().unwrap_or_else(PoisonError::into_inner)
        );
    }

    /// Mesh-agent attribution (2026-10-09 bug, class-level fix): the
    /// steady-state lines — the 15s `Ingress reconciled` heartbeat,
    /// per-connection `Connection accepted` / `Backend connection
    /// established` — must carry the node attribution injected at prepare,
    /// and NO line from any `interflow_mesh::agent::*` module may go bare
    /// (the gap this test machine-locks: a new bare log line anywhere in
    /// the agent modules fails here, in CI).
    ///
    /// Dual-path redundancy per the bug file: the recorded `node` value is
    /// compared byte-for-byte against `node_infos`' `NodeInfo.attribution`
    /// — the exact input the frontend "This node" filter matches on — and
    /// the sink reuses the GUI production `MessageVisitor`, so the field
    /// shapes match what the filter sees.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    #[allow(clippy::similar_names)] // lan_a_attr / lan_b_attr: the two agents under assertion
    async fn mesh_agent_lines_carry_node_attribution() {
        let recorded = tracing_recorder();
        let attributed = attribution_recorder();

        let stack = stack_with_mesh_site(pending_renewal()).await;
        let manager = &stack.manager;
        manager.start(&stack.hub_id).expect("hub start");
        wait_for(
            manager,
            &stack.hub_id,
            |s| matches!(s, NodeState::Running),
            "Running",
        )
        .await;
        manager.start(&stack.lan_b_id).expect("lan-b start");
        manager.start(&stack.lan_a_id).expect("lan-a start");
        connected(manager, &stack.lan_b_id).await;
        connected(manager, &stack.lan_a_id).await;

        let attribution = |id: &str| {
            manager
                .snapshots()
                .into_iter()
                .find(|n| n.spec.id == id)
                .map(|n| log_attribution(&n.spec))
                .expect("node snapshot")
        };
        let lan_a_attr = attribution(&stack.lan_a_id);
        let lan_b_attr = attribution(&stack.lan_b_id);

        // Dual-path lock: the GUI's own attribution face (`node_infos`) and
        // the snapshot-derived value must agree byte-for-byte — they are
        // the two sources of the frontend filter input.
        {
            let infos = crate::commands::node_infos(manager);
            let find = |id: &str| {
                infos
                    .iter()
                    .find(|i| i.id == id)
                    .map(|i| i.attribution.clone())
                    .unwrap_or_default()
            };
            assert_eq!(find(&stack.lan_a_id), lan_a_attr);
            assert_eq!(find(&stack.lan_b_id), lan_b_attr);
        }

        // Business flow through the tunnel: produces the per-connection
        // steady-state lines the bug file lists (§6.4).
        let payload = b"ping-into-the-node-view";
        let mut sock = tokio::net::TcpStream::connect(("127.0.0.1", stack.listen_port))
            .await
            .expect("dial lan-a listener");
        sock.write_all(payload).await.unwrap();
        let mut buf = [0u8; 64];
        let n = tokio::time::timeout(Duration::from_secs(10), sock.read(&mut buf))
            .await
            .expect("echo within 10s")
            .expect("read");
        assert_eq!(&buf[..n], payload);
        drop(sock);

        // Deterministic steady-state lines, exact-match (the report's §6.2
        // checklist, distilled): the heartbeat summary and both handler
        // starts land in the right node's view.
        assert!(
            wait_for_line(&recorded, &lan_a_attr, "Ingress reconciled: +1 ~0 -0 !0").await,
            "the reconcile heartbeat line must be attributed to lan-a; captured: {:?}",
            recorded.lock().unwrap_or_else(PoisonError::into_inner)
        );
        assert!(
            wait_for_line(
                &recorded,
                &lan_b_attr,
                "Egress handler started, agent_id=lan-b"
            )
            .await,
            "the egress start line must be attributed to lan-b; captured: {:?}",
            recorded.lock().unwrap_or_else(PoisonError::into_inner)
        );

        // Business lines with dynamic parts (peer port / stream id),
        // prefix-matched: the flow must be traceable inside each node's
        // own view, without leaving for the machine-wide view.
        assert!(
            wait_for_line_starting(&recorded, &lan_a_attr, "Connection accepted: ").await,
            "the accepted-connection line must be attributed to lan-a; captured: {:?}",
            recorded.lock().unwrap_or_else(PoisonError::into_inner)
        );
        assert!(
            wait_for_line_starting(&recorded, &lan_b_attr, "Backend connection established: ")
                .await,
            "the backend-connection line must be attributed to lan-b; captured: {:?}",
            recorded.lock().unwrap_or_else(PoisonError::into_inner)
        );

        // The class-level lock: every line from every mesh-agent module
        // carries one of the stack's node attributions — a bare (or
        // foreign-valued) `node` field anywhere fails here. This is the
        // machine-enforced half of the fix: per-line annotation discipline
        // is no longer a convention but an invariant under test.
        let offenders = attributed
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .iter()
            .filter(|(target, ..)| target.starts_with("interflow_mesh::agent"))
            .filter(|(_, node, _)| {
                node.as_deref() != Some(lan_a_attr.as_str())
                    && node.as_deref() != Some(lan_b_attr.as_str())
            })
            .map(|(target, node, message)| (*target, node.clone(), message.clone()))
            .collect::<Vec<_>>();
        // Non-vacuity: the assertion below only means something if the
        // sink actually observed mesh-agent lines (startup + the driven
        // business flow must have produced dozens).
        let agent_lines = attributed
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .iter()
            .filter(|(target, ..)| target.starts_with("interflow_mesh::agent"))
            .count();
        assert!(
            agent_lines >= 10,
            "the attribution sink must have observed mesh-agent lines (got {agent_lines}); \
             otherwise the class-level assertion below is vacuous"
        );
        assert!(
            offenders.is_empty(),
            "every interflow_mesh::agent::* line must carry one of the node attributions \
             ({lan_a_attr} / {lan_b_attr}); bare or misattributed lines: {offenders:?}"
        );
    }

    /// The full-stack acceptance: hub + two mesh agents run side by side
    /// under the manager, TCP traffic flows through the tunnel, and
    /// stop_all lands every node in Stopped.
    #[tokio::test]
    async fn hub_and_two_agents_run_side_by_side_and_forward_traffic() {
        let stack = stack_with_mesh_site(pending_renewal()).await;
        let manager = &stack.manager;

        manager.start(&stack.hub_id).expect("hub start");
        wait_for(
            manager,
            &stack.hub_id,
            |s| matches!(s, NodeState::Running),
            "Running",
        )
        .await;
        manager.start(&stack.lan_b_id).expect("lan-b start");
        manager.start(&stack.lan_a_id).expect("lan-a start");
        connected(manager, &stack.lan_b_id).await;
        connected(manager, &stack.lan_a_id).await;

        // Traffic: connect to lan-a's ingress listener, echo round-trips
        // through hub → lan-b → the echo service.
        let mut sock = tokio::net::TcpStream::connect(("127.0.0.1", stack.listen_port))
            .await
            .expect("dial lan-a listener");
        sock.write_all(b"ping-through-the-manager").await.unwrap();
        let mut buf = [0u8; 64];
        let n = tokio::time::timeout(Duration::from_secs(10), sock.read(&mut buf))
            .await
            .expect("echo within 10s")
            .expect("read");
        assert_eq!(&buf[..n], b"ping-through-the-manager");

        // Intent bits: everything started → persisted desired=true.
        manager.settle().await;
        {
            let persisted = stack
                .persisted
                .lock()
                .unwrap_or_else(PoisonError::into_inner);
            assert!(persisted.iter().all(|e| e.desired_running));
        }

        // Stop one node (per-node independence), then stop the rest.
        manager.stop(&stack.lan_a_id).await.expect("lan-a stop");
        wait_for(
            manager,
            &stack.lan_a_id,
            |s| *s == NodeState::Stopped,
            "Stopped",
        )
        .await;
        assert!(
            matches!(
                manager.state(&stack.lan_b_id),
                Some(NodeState::Connected { .. })
            ),
            "lan-b must keep running while lan-a stops"
        );

        manager.stop_all().await;
        for id in [&stack.hub_id, &stack.lan_b_id] {
            wait_for(
                manager,
                id,
                |s| *s == NodeState::Stopped,
                "Stopped after stop_all",
            )
            .await;
        }

        // Stop cleared the intent for every node.
        manager.settle().await;
        {
            let persisted = stack
                .persisted
                .lock()
                .unwrap_or_else(PoisonError::into_inner);
            assert!(persisted.iter().all(|e| !e.desired_running));
        }
    }

    /// The 2026-10-07 bug, machine-locked: a policy PUBLISHED at the hub
    /// reaches a GUI-managed agent with zero touches — no restart, no
    /// Stop→Start, no manual state injection. The whole distribution plane
    /// (hub serve cache → agent pull → verify → persist → apply) rides
    /// paths `NodeManager::start` actually builds; before the engine
    /// absorbed the watcher, the e2e suites wired it by hand and the GUI
    /// wiring had no test at all
    #[tokio::test]
    async fn published_policy_reaches_gui_managed_agents_without_restart() {
        let stack = stack_with_mesh_site(pending_renewal()).await;
        let manager = &stack.manager;
        manager.start(&stack.hub_id).expect("hub start");
        wait_for(
            manager,
            &stack.hub_id,
            |s| matches!(s, NodeState::Running),
            "Running",
        )
        .await;
        manager.start(&stack.lan_b_id).expect("lan-b start");
        manager.start(&stack.lan_a_id).expect("lan-a start");
        connected(manager, &stack.lan_b_id).await;
        connected(manager, &stack.lan_a_id).await;

        // The policy face is live before any publish: the watcher exists
        // (this is the assertion the old wiring could never make from the
        // GUI side) and its pull channel has completed at least one poll.
        let deadline = tokio::time::Instant::now() + Duration::from_secs(30);
        loop {
            let plane = manager.policy_plane(&stack.lan_a_id).expect("policy plane");
            if plane.pull.is_some_and(|h| h.last_ok_unix > 0) {
                break;
            }
            assert!(
                tokio::time::Instant::now() < deadline,
                "GUI agent's policy watcher never completed a control-plane pull"
            );
            tokio::time::sleep(Duration::from_millis(500)).await;
        }

        // Publish generation 2: same mesh, one NEW listener port on lan-a.
        let listen_v2 = crate::test_util::free_port();
        let manifest_v2 = Manifest::parse(&format!(
            r#"
[realm]
id = "gui-test"
[registrar]
endpoint = "https://registrar.example.com"
[mesh.hub.central]
listen = "127.0.0.1:{hub_port}"
endpoint = "127.0.0.1:{hub_port}"
[workspace.alpha]
[workspace.beta]
[agent.lan-a]
workspace = "alpha"
[[agent.lan-a.mesh_ingress]]
name = "svc"
listen = "127.0.0.1:{listen_v2}"
target_agent = "lan-b"
remote_addr = "127.0.0.1:{echo_port}"
[agent.lan-b]
workspace = "beta"
[[agent.lan-b.mesh_egress]]
name = "svc"
target_addr = "127.0.0.1:{echo_port}"
"#,
            hub_port = stack.hub_port,
            echo_port = stack.echo_port,
        ))
        .unwrap();
        let policy_v2 = interflow_identity::policy::RuntimePolicy::from_manifest(&manifest_v2, 2);
        let (bytes_v2, sig_v2) = policy_v2
            .signed(&stack.issuer.policy_signer().unwrap())
            .unwrap();
        let creds = tempfile::tempdir().unwrap();
        let material = stack
            .issuer
            .issue_hub_member_with_ttl(
                "gui-test",
                "publish",
                interflow_identity::issuance::LeafTtl::default_ttl(),
            )
            .unwrap();
        let (ca, cert, key) = (
            creds.path().join("ca.crt"),
            creds.path().join("client.crt"),
            creds.path().join("client.key"),
        );
        std::fs::write(&ca, stack.issuer.realm_issuer().unwrap().cert_pem()).unwrap();
        std::fs::write(&cert, &material.chain_pem).unwrap();
        std::fs::write(&key, &material.key_pem).unwrap();
        let outcome = interflow_mesh::hub::policy::publish_policy(
            &format!("127.0.0.1:{}", stack.hub_port),
            &ca,
            &cert,
            &key,
            &bytes_v2,
            &sig_v2,
        )
        .await
        .unwrap();
        assert_eq!(
            outcome,
            interflow_mesh::hub::policy::PublishOutcome::Published { generation: 2 }
        );

        // The EXACT frozen-state observable from the incident: the agent's
        // state/policy files advance (mtime moves, generation lands) — plus
        // the live faces: the new listener answers and the policy plane
        // reports the converged watermark with a healthy pull channel.
        let deadline = tokio::time::Instant::now() + Duration::from_secs(45);
        let state_toml = stack.lan_a_pack.join("state/policy/policy.toml");
        loop {
            let converged = std::fs::read_to_string(&state_toml)
                .is_ok_and(|body| body.contains("generation = 2"))
                && tokio::net::TcpStream::connect(("127.0.0.1", listen_v2))
                    .await
                    .is_ok();
            if converged {
                break;
            }
            assert!(
                tokio::time::Instant::now() < deadline,
                "published gen 2 never reached the GUI-managed agent (state file: {:?})",
                std::fs::read_to_string(&state_toml).ok()
            );
            tokio::time::sleep(Duration::from_millis(500)).await;
        }
        let plane = manager.policy_plane(&stack.lan_a_id).expect("policy plane");
        assert_eq!(plane.generation, 2, "applied watermark converges");
        assert_eq!(plane.hub_generation, Some(2), "hub generation converges");
        let pull = plane.pull.expect("running watcher reports pull health");
        assert!(pull.last_ok_unix > 0, "pull channel completed polls");

        // The 2026-10-07 stale-panel bug lived past this point: the domain
        // query converged here while the GUI's own two legs never heard
        // about it. Leg 1 — the event face: the forwarder must have pushed
        // the converged plane through the sink (what `emit_policy_plane`
        // delivers to the panel).
        {
            let deadline = tokio::time::Instant::now() + Duration::from_secs(30);
            loop {
                let converged = stack.policy_events.lock().unwrap().iter().any(|(id, p)| {
                    id == &stack.lan_a_id
                        && p.generation == 2
                        && p.pull.is_some_and(|h| h.last_ok_unix > 0)
                });
                if converged {
                    break;
                }
                assert!(
                    tokio::time::Instant::now() < deadline,
                    "policy-plane events never carried the converged watermark to the GUI face"
                );
                tokio::time::sleep(Duration::from_millis(500)).await;
            }
        }
        // Leg 2 — the command face: what `list_nodes` composes for the GUI
        // (the on-demand twin of the event stream; same composition either
        // way). The DTO must carry the live values, not the start-time seed.
        let gui = crate::commands::node_infos(manager)
            .into_iter()
            .find(|n| n.id == stack.lan_a_id)
            .expect("lan-a in the GUI node list");
        let policy = gui.policy.expect("policy face present");
        assert_eq!(policy.generation, 2, "GUI DTO carries the live watermark");
        assert_eq!(
            policy.source,
            crate::contract::PolicySourceDto::StatePolicy,
            "GUI DTO names the state/policy channel"
        );
        assert_eq!(policy.hub_generation, Some(2));
        assert!(
            policy.pull.expect("pull health in DTO").last_ok_unix > 0,
            "GUI DTO reports a completed pull, not the never-pulled seed"
        );

        manager.stop_all().await;
        for id in [&stack.hub_id, &stack.lan_a_id, &stack.lan_b_id] {
            wait_for(manager, id, |s| *s == NodeState::Stopped, "Stopped").await;
        }
    }

    /// The 2026-10-08 peer-observability face, machine-locked from the GUI
    /// side: a running mesh agent's peer watcher must surface the fleet
    /// through BOTH consumption legs (the `mesh-peers` event stream and
    /// the `list_nodes` composition). Tenant semantics ride along: the
    /// listing is workspace-tenant scoped (THREAT_MODEL §6.5 — one root
    /// per workspace anchors the client chains), so same-workspace lan-b
    /// is visible to lan-a and other-workspace lan-x is not. Stopping the
    /// node drops the face (presence has no meaningful stale display).
    ///
    /// Own minimal fixture rather than `stack_with_mesh_site`: the shared
    /// stack splits lan-a/lan-b across the alpha/beta workspaces (two
    /// tenants), which would make the POSITIVE visibility leg untestable —
    /// here lan-a and lan-b share one workspace and lan-x sits in another.
    #[tokio::test]
    async fn peer_plane_flows_to_gui_events_and_node_infos() {
        let hub_port = crate::test_util::free_port();
        let dead_port = crate::test_util::free_port(); // rules point here; no traffic flows

        let dir = tempfile::tempdir().unwrap();
        let issuer = IssuerStore::open(dir.path().join("issuer"));
        issuer.ensure_realm().unwrap();
        issuer.ensure_workspace("main").unwrap();
        issuer.ensure_workspace("other").unwrap();
        issuer.ensure_policy_key().unwrap();

        let manifest = Manifest::parse(&format!(
            r#"
[realm]
id = "gui-peers"
[registrar]
endpoint = "https://registrar.example.com"
[mesh.hub.central]
listen = "127.0.0.1:{hub_port}"
endpoint = "127.0.0.1:{hub_port}"
[workspace.main]
[workspace.other]
[agent.lan-a]
workspace = "main"
[[agent.lan-a.mesh_ingress]]
name = "svc"
listen = "127.0.0.1:{dead_port}"
target_agent = "lan-b"
remote_addr = "127.0.0.1:{dead_port}"
[agent.lan-b]
workspace = "main"
[[agent.lan-b.mesh_egress]]
name = "svc"
target_addr = "127.0.0.1:{dead_port}"
[agent.lan-x]
workspace = "other"
[[agent.lan-x.mesh_egress]]
name = "svc"
target_addr = "127.0.0.1:{dead_port}"
"#
        ))
        .unwrap();

        let hub_dir = dir.path().join("packs/hub-central");
        HubCredentialPack::render(&issuer, &manifest, "central", 1, &hub_dir).unwrap();
        let dir_a = dir.path().join("packs/agent-lan-a");
        AgentCredentialPack::render(&issuer, &manifest, "lan-a", 1, &dir_a).unwrap();
        let dir_b = dir.path().join("packs/agent-lan-b");
        AgentCredentialPack::render(&issuer, &manifest, "lan-b", 1, &dir_b).unwrap();
        let dir_x = dir.path().join("packs/agent-lan-x");
        AgentCredentialPack::render(&issuer, &manifest, "lan-x", 1, &dir_x).unwrap();
        // Packs must outlive `dir` (the manager reads them at every start).
        std::mem::forget(dir);

        let peers_events: Arc<StdMutex<Vec<(NodeId, PeersPlane)>>> =
            Arc::new(StdMutex::new(Vec::new()));
        let sink_peers = peers_events.clone();
        let manager = NodeManager::with_renewal(
            tokio::runtime::Handle::current(),
            |_, _| {},
            |_| {},
            |_, _| {},
            move |id, plane| {
                sink_peers
                    .lock()
                    .unwrap_or_else(PoisonError::into_inner)
                    .push((id.to_string(), plane.clone()));
            },
            |_, _| {},
            |_, _| {},
            pending_renewal(),
        );

        let add = |dir: std::path::PathBuf| {
            let info = inspect_pack(&dir).expect("pack inspects clean");
            manager
                .add(NodeSpec {
                    generation: info.generation,
                    pack_digest: info.digest.clone(),
                    id: String::new(),
                    kind: info.kind,
                    name: info.name,
                    principal: Some(info.principal),
                    pack_dir: dir,
                    transport: None,
                    hub_quic_addr: None,
                    pack_services: info.services,
                    pack_mesh: info.mesh,
                    pack_listen: info.listen,
                    pack_transport: info.transport,
                    service_addresses: Default::default(),
                })
                .expect("add node")
        };
        let hub_id = add(hub_dir);
        let lan_a = add(dir_a);
        let lan_b = add(dir_b);
        let lan_x = add(dir_x);

        manager.start(&hub_id).expect("hub start");
        wait_for(
            &manager,
            &hub_id,
            |s| matches!(s, NodeState::Running),
            "Running",
        )
        .await;
        manager.start(&lan_b).expect("lan-b start");
        manager.start(&lan_a).expect("lan-a start");
        manager.start(&lan_x).expect("lan-x start");
        connected(&manager, &lan_b).await;
        connected(&manager, &lan_a).await;
        connected(&manager, &lan_x).await;

        // Leg 1 — the event face: the forwarder pushed a snapshot naming
        // lan-b as a peer of lan-a (online, self excluded, the
        // other-workspace agent never present).
        let deadline = tokio::time::Instant::now() + Duration::from_secs(45);
        loop {
            let converged = peers_events.lock().unwrap().iter().any(|(id, p)| {
                *id == lan_a
                    && p.peers.len() == 1
                    && p.peers[0].agent.ends_with("/lan-b")
                    && p.peers[0].online
                    && p.last_ok_unix > 0
            });
            if converged {
                break;
            }
            assert!(
                tokio::time::Instant::now() < deadline,
                "mesh-peers events never carried lan-b to lan-a's GUI face"
            );
            tokio::time::sleep(Duration::from_millis(500)).await;
        }

        // Leg 2 — the command face: `list_nodes` composes the same live
        // reading; the hub carries no peer face; the other-workspace agent
        // sees an empty fleet from its side (tenant isolation, §6.5).
        let infos = crate::commands::node_infos(&manager);
        let gui_a = infos
            .iter()
            .find(|n| n.id == lan_a)
            .expect("lan-a in the GUI node list");
        let peers = gui_a
            .peers
            .clone()
            .expect("peers face present while running");
        assert_eq!(peers.peers.len(), 1, "self excluded, one peer: {peers:?}");
        assert!(peers.peers[0].agent.ends_with("/lan-b"));
        assert!(peers.peers[0].online, "lan-b reads online: {peers:?}");
        assert!(
            infos
                .iter()
                .find(|n| n.id == hub_id)
                .is_none_or(|n| n.peers.is_none()),
            "the hub is not a mesh agent"
        );
        let gui_x = infos
            .iter()
            .find(|n| n.id == lan_x)
            .expect("lan-x in the GUI node list");
        let peers_x = gui_x.peers.clone().expect("lan-x peers face present");
        assert!(
            peers_x.peers.is_empty(),
            "other-workspace agents must not observe the main tenant: {peers_x:?}"
        );

        // Stopping the agent drops the face — presence without the session
        // that observed it must not linger as stale display.
        manager.stop(&lan_a).await.expect("lan-a stop");
        wait_for(&manager, &lan_a, |s| *s == NodeState::Stopped, "Stopped").await;
        assert!(
            manager.peers_plane(&lan_a).is_none(),
            "a stopped node carries no peer reading"
        );

        manager.stop_all().await;
        for id in [&hub_id, &lan_a, &lan_b, &lan_x] {
            wait_for(&manager, id, |s| *s == NodeState::Stopped, "Stopped").await;
        }
    }

    /// The 2026-10-07 hot-reapply incident, machine-locked from the GUI
    /// face: a policy PUBLISHED at the hub that only touches a
    /// connection-level knob of an EXISTING stream (same name, SAME listen
    /// port, only `idle_timeout_secs` added) must reach the GUI-managed
    /// agent with the listener never moving — the incident's shape lost
    /// 9091 silently while state said gen 8 and the health panel stayed
    /// green.
    /// The sibling test above covers the add-stream shape; this one locks
    /// modify-stream.
    #[tokio::test]
    async fn published_policy_param_change_keeps_listener_alive_without_restart() {
        let stack = stack_with_mesh_site(pending_renewal()).await;
        let manager = &stack.manager;
        manager.start(&stack.hub_id).expect("hub start");
        wait_for(
            manager,
            &stack.hub_id,
            |s| matches!(s, NodeState::Running),
            "Running",
        )
        .await;
        manager.start(&stack.lan_b_id).expect("lan-b start");
        manager.start(&stack.lan_a_id).expect("lan-a start");
        connected(manager, &stack.lan_b_id).await;
        connected(manager, &stack.lan_a_id).await;

        // The incident's own observable, strengthened: not just "the port
        // accepts a TCP connect" but a full round-trip through the tunnel
        // (lan-a ingress → hub → lan-b egress → echo), on the SAME port,
        // before AND after the change.
        let round_trip = |payload: &'static [u8]| async move {
            let mut client =
                tokio::net::TcpStream::connect(("127.0.0.1", stack.listen_port)).await?;
            client.write_all(payload).await?;
            let mut echoed = vec![0u8; payload.len()];
            client.read_exact(&mut echoed).await?;
            Ok::<Vec<u8>, std::io::Error>(echoed)
        };
        let (baseline, after) = (b"via-v1".to_vec(), b"via-v2".to_vec());

        let deadline = tokio::time::Instant::now() + Duration::from_secs(30);
        loop {
            if let Ok(Ok(got)) =
                tokio::time::timeout(Duration::from_secs(5), round_trip(b"via-v1")).await
                && got == b"via-v1".to_vec()
            {
                break;
            }
            assert!(
                tokio::time::Instant::now() < deadline,
                "v1 listener never came up on {}",
                stack.listen_port
            );
            tokio::time::sleep(Duration::from_millis(500)).await;
        }

        // Publish generation 2: the SAME stream, only the idle knob added.
        let manifest_v2 = Manifest::parse(&format!(
            r#"
[realm]
id = "gui-test"
[registrar]
endpoint = "https://registrar.example.com"
[mesh.hub.central]
listen = "127.0.0.1:{hub_port}"
endpoint = "127.0.0.1:{hub_port}"
[workspace.alpha]
[workspace.beta]
[agent.lan-a]
workspace = "alpha"
[[agent.lan-a.mesh_ingress]]
name = "svc"
listen = "127.0.0.1:{listen_port}"
target_agent = "lan-b"
remote_addr = "127.0.0.1:{echo_port}"
idle_timeout_secs = 1800
[agent.lan-b]
workspace = "beta"
[[agent.lan-b.mesh_egress]]
name = "svc"
target_addr = "127.0.0.1:{echo_port}"
"#,
            hub_port = stack.hub_port,
            echo_port = stack.echo_port,
            listen_port = stack.listen_port,
        ))
        .unwrap();
        let policy_v2 = interflow_identity::policy::RuntimePolicy::from_manifest(&manifest_v2, 2);
        let (bytes_v2, sig_v2) = policy_v2
            .signed(&stack.issuer.policy_signer().unwrap())
            .unwrap();
        let creds = tempfile::tempdir().unwrap();
        let material = stack
            .issuer
            .issue_hub_member_with_ttl(
                "gui-test",
                "publish",
                interflow_identity::issuance::LeafTtl::default_ttl(),
            )
            .unwrap();
        let (ca, cert, key) = (
            creds.path().join("ca.crt"),
            creds.path().join("client.crt"),
            creds.path().join("client.key"),
        );
        std::fs::write(&ca, stack.issuer.realm_issuer().unwrap().cert_pem()).unwrap();
        std::fs::write(&cert, &material.chain_pem).unwrap();
        std::fs::write(&key, &material.key_pem).unwrap();
        let outcome = interflow_mesh::hub::policy::publish_policy(
            &format!("127.0.0.1:{}", stack.hub_port),
            &ca,
            &cert,
            &key,
            &bytes_v2,
            &sig_v2,
        )
        .await
        .unwrap();
        assert_eq!(
            outcome,
            interflow_mesh::hub::policy::PublishOutcome::Published { generation: 2 }
        );

        // Convergence, incident-shaped: the state file advances AND the
        // very same listener keeps round-tripping — state face and
        // listener face must NOT split (the incident had gen 8 in state
        // with 9091 gone).
        let deadline = tokio::time::Instant::now() + Duration::from_secs(45);
        let state_toml = stack.lan_a_pack.join("state/policy/policy.toml");
        loop {
            let converged = std::fs::read_to_string(&state_toml)
                .is_ok_and(|body| body.contains("generation = 2"))
                && matches!(
                    tokio::time::timeout(Duration::from_secs(5), round_trip(b"via-v2")).await,
                    Ok(Ok(got)) if got == after
                );
            if converged {
                break;
            }
            assert!(
                tokio::time::Instant::now() < deadline,
                "param-only gen 2 never reached the GUI-managed agent with the listener alive \
                 (state file: {:?})",
                std::fs::read_to_string(&state_toml).ok()
            );
            tokio::time::sleep(Duration::from_millis(500)).await;
        }
        let plane = manager.policy_plane(&stack.lan_a_id).expect("policy plane");
        assert_eq!(plane.generation, 2, "applied watermark converges");
        assert_eq!(plane.hub_generation, Some(2), "hub generation converges");
        assert!(
            plane.pull.is_some_and(|h| h.last_ok_unix > 0),
            "pull channel completed polls"
        );
        // The baseline proof too: the port that served v1 is the port that
        // serves v2 (no restart, no rebind hole).
        assert_eq!(baseline, b"via-v1".to_vec());

        manager.stop_all().await;
        for id in [&stack.hub_id, &stack.lan_a_id, &stack.lan_b_id] {
            wait_for(manager, id, |s| *s == NodeState::Stopped, "Stopped").await;
        }
    }

    /// A hub node whose port is held by someone else surfaces Failed (and
    /// the bounded restart policy eventually exhausts — asserted only via
    /// the first Failed transition; exhaustion takes minutes by design).
    #[tokio::test]
    async fn busy_hub_port_surfaces_failed() {
        let stack = stack_with_mesh_site(pending_renewal()).await;
        // Occupying the hub port requires knowing it; re-derive from the
        // pack's inspection.
        let inspection = stack
            .manager
            .snapshots()
            .into_iter()
            .find(|s| s.spec.id == stack.hub_id)
            .map(|s| inspect_pack(&s.spec.pack_dir).unwrap())
            .unwrap();
        let listen: std::net::SocketAddr = inspection.listen.unwrap().parse().unwrap();
        let holder = std::net::TcpListener::bind(listen).unwrap();
        // Start succeeds (the bind failure is asynchronous, engine-side).
        stack.manager.start(&stack.hub_id).expect("start spawns");
        // The engine fails asynchronously: Starting → Failed.
        wait_for(
            &stack.manager,
            &stack.hub_id,
            |s| matches!(s, NodeState::Failed { .. }),
            "Failed (busy port)",
        )
        .await;
        drop(holder);
    }

    /// Adding the same pack directory twice is rejected — the same identity
    /// registered twice fights itself at the hub.
    #[tokio::test]
    async fn duplicate_pack_rejected() {
        let stack = stack_with_mesh_site(pending_renewal()).await;
        let hub_dir = stack
            .manager
            .snapshots()
            .into_iter()
            .find(|s| s.spec.id == stack.hub_id)
            .unwrap()
            .spec
            .pack_dir;
        let info = inspect_pack(&hub_dir).unwrap();
        let err = stack
            .manager
            .add(NodeSpec {
                generation: info.generation,
                pack_digest: info.digest.clone(),
                id: String::new(),
                kind: info.kind,
                name: info.name.clone(),
                principal: Some(info.principal),
                pack_dir: hub_dir,
                transport: None,
                hub_quic_addr: None,
                pack_services: info.services,
                pack_mesh: info.mesh,
                pack_listen: info.listen,
                pack_transport: info.transport,
                service_addresses: Default::default(),
            })
            .expect_err("duplicate must be rejected");
        assert!(err.contains("already added"), "wrong message: {err}");
    }

    /// Identity dedup, one level up from the directory check: a *different*
    /// directory carrying the *same* identity (a copied pack) is rejected
    /// with the identity-causal reason; a same-name node in a different
    /// realm is a different identity and passes.
    #[tokio::test]
    async fn same_identity_from_another_directory_rejected() {
        let stack = stack_with_mesh_site(pending_renewal()).await;
        let hub_dir = stack
            .manager
            .snapshots()
            .into_iter()
            .find(|s| s.spec.id == stack.hub_id)
            .unwrap()
            .spec
            .pack_dir;
        let info = inspect_pack(&hub_dir).unwrap();

        let copied = std::path::PathBuf::from("/definitely/elsewhere/hub-copy");
        let err = stack
            .manager
            .add(NodeSpec {
                generation: info.generation,
                pack_digest: info.digest.clone(),
                id: String::new(),
                kind: info.kind,
                name: info.name.clone(),
                principal: Some(info.principal.clone()),
                pack_dir: copied,
                transport: None,
                hub_quic_addr: None,
                pack_services: info.services.clone(),
                pack_mesh: info.mesh.clone(),
                pack_listen: info.listen.clone(),
                pack_transport: info.transport.clone(),
                service_addresses: Default::default(),
            })
            .expect_err("same identity must be rejected");
        assert!(
            err.contains("this identity") && err.contains("kick each other"),
            "wrong message: {err}"
        );

        // Same node name, different realm → different identity → accepted.
        let other = stack
            .manager
            .add(NodeSpec {
                generation: info.generation,
                pack_digest: info.digest.clone(),
                id: String::new(),
                kind: info.kind,
                name: info.name.clone(),
                principal: Some(format!("other-realm/-/hub/{}", info.name)),
                pack_dir: std::path::PathBuf::from("/elsewhere/other-realm-hub"),
                transport: None,
                hub_quic_addr: None,
                pack_services: info.services,
                pack_mesh: info.mesh,
                pack_listen: info.listen,
                pack_transport: info.transport,
                service_addresses: Default::default(),
            })
            .expect("a different identity sharing the node name must pass");
        assert!(!other.is_empty());
    }

    /// Renewal rotation: the scheduler's Ok completion (new credential
    /// generation active) gracefully restarts the node in-process — the
    /// engine comes back up and the intent stays on.
    #[tokio::test]
    async fn renewal_rotation_restarts_the_node() {
        // Script: the first renewal future (spawned by the first start)
        // completes Ok when fired; any later one (after the restart) parks.
        let gate: Arc<StdMutex<Option<tokio::sync::oneshot::Receiver<()>>>> =
            Arc::new(StdMutex::new(None));
        let (fire_tx, fire_rx) = tokio::sync::oneshot::channel::<()>();
        *gate.lock().unwrap() = Some(fire_rx);
        let gate_for_factory = gate.clone();
        let renewal: RenewalFactory = Arc::new(move |_dir, _log_name| {
            let rx = gate_for_factory.lock().unwrap().take();
            Box::pin(async move {
                match rx {
                    Some(rx) => {
                        let _ = rx.await;
                        Ok(())
                    }
                    None => std::future::pending().await,
                }
            })
        });

        let stack = stack_with_mesh_site(renewal).await;
        let manager = &stack.manager;
        manager.start(&stack.hub_id).expect("hub start");
        wait_for(
            manager,
            &stack.hub_id,
            |s| matches!(s, NodeState::Running),
            "Running",
        )
        .await;

        // Fire the rotation: the hub restarts onto the new generation. The
        // intermediate Reconnecting (renewed) state can be sub-poll-duration
        // wide (an idle hub drains instantly), so the transition is
        // asserted on the recorded event sequence, not on live polls.
        fire_tx.send(()).unwrap();
        wait_for(
            manager,
            &stack.hub_id,
            |s| matches!(s, NodeState::Running),
            "Running again",
        )
        .await;
        let deadline = Instant::now() + Duration::from_secs(5);
        loop {
            // Scoped guard: nothing is held across the sleep below.
            let saw_rotation_notice = {
                let events = stack.events.lock().unwrap_or_else(PoisonError::into_inner);
                events.iter().any(|(id, state)| {
                    id == &stack.hub_id
                        && matches!(state,
                            NodeState::Reconnecting { reason, .. } if reason.contains("renewed"))
                })
            };
            if saw_rotation_notice {
                break;
            }
            assert!(Instant::now() < deadline, "rotation notice never observed");
            tokio::time::sleep(Duration::from_millis(20)).await;
        }

        // The intent survived the rotation.
        manager.settle().await;
        assert!(
            stack
                .persisted
                .lock()
                .unwrap()
                .iter()
                .find(|e| e.id == stack.hub_id)
                .is_some_and(|e| e.desired_running)
        );
        manager.stop(&stack.hub_id).await.expect("stop");
        wait_for(
            manager,
            &stack.hub_id,
            |s| *s == NodeState::Stopped,
            "Stopped",
        )
        .await;
    }
    // ------------------------------------------------------------------
    // Service-address preferences + in-place pack update (backlog
    // 2026-09-23: address as a machine-local preference, P1-1/P1-2).
    // ------------------------------------------------------------------

    struct ExposeStack {
        manager: NodeManager,
        ingress_id: NodeId,
        agent_id: NodeId,
        edge_port: u16,
        persisted: Arc<StdMutex<Vec<crate::profile::NodeEntry>>>,
    }

    /// Renders ingress-edge + agent-desktop expose packs and registers them
    /// with a fresh manager. The service's pack default points at a dead
    /// port on purpose: only a preference (or a changed default) can make
    /// traffic land.
    fn stack_with_expose_site() -> ExposeStack {
        let control_port = crate::test_util::free_port();
        let edge_port = crate::test_util::free_port();
        let dead_port = crate::test_util::free_port(); // nothing listens here

        let dir = tempfile::tempdir().unwrap();
        let issuer = IssuerStore::open(dir.path().join("issuer"));
        issuer.ensure_realm().unwrap();
        issuer.ensure_workspace("default").unwrap();
        issuer.ensure_policy_key().unwrap();

        let manifest = Manifest::parse(&format!(
            r#"
[realm]
id = "gui-expose"
control_endpoint = "127.0.0.1:{control_port}"
[public_tls]
mode = "frontend-proxy"
[registrar]
endpoint = "https://registrar.invalid"
[ingress.edge]
workspaces = ["default"]
listen = "127.0.0.1:{edge_port}"
control_listen = "127.0.0.1:{control_port}"
[workspace.default]
[agent.desktop]
workspace = "default"
[[agent.desktop.services]]
id = "web"
address = "127.0.0.1:{dead_port}"
[[route]]
host = "test.local"
service = "default/desktop/web"
"#
        ))
        .unwrap();

        let ingress_dir = dir.path().join("packs/ingress-edge");
        IngressCredentialPack::render(&issuer, &manifest, "edge", 1, &ingress_dir).unwrap();
        let agent_dir = dir.path().join("packs/agent-desktop");
        AgentCredentialPack::render(&issuer, &manifest, "desktop", 1, &agent_dir).unwrap();
        // Packs must outlive `dir` (the manager reads them at every start).
        std::mem::forget(dir);

        let events: Arc<StdMutex<Vec<(NodeId, NodeState)>>> = Arc::new(StdMutex::new(Vec::new()));
        let persisted: Arc<StdMutex<Vec<crate::profile::NodeEntry>>> =
            Arc::new(StdMutex::new(Vec::new()));
        let manager = NodeManager::with_renewal(
            tokio::runtime::Handle::current(),
            move |id, state| {
                events
                    .lock()
                    .unwrap_or_else(PoisonError::into_inner)
                    .push((id.to_string(), state.clone()));
            },
            {
                let persisted = persisted.clone();
                move |entries| {
                    *persisted.lock().unwrap_or_else(PoisonError::into_inner) = entries.to_vec();
                }
            },
            |_, _| {}, // this stack has no mesh agent; the policy face stays quiet
            |_, _| {}, // ...and neither does the peers face
            |_, _| {}, // ...nor the proposal receipts face
            |_, _| {}, // ...nor the listeners face
            pending_renewal(),
        );

        let add = |manager: &NodeManager, dir: PathBuf| {
            let info = inspect_pack(&dir).expect("pack inspects clean");
            manager
                .add(NodeSpec {
                    id: String::new(),
                    kind: info.kind,
                    name: info.name,
                    principal: Some(info.principal),
                    pack_dir: dir,
                    transport: None,
                    hub_quic_addr: None,
                    generation: info.generation,
                    pack_digest: info.digest.clone(),
                    pack_services: info.services,
                    pack_mesh: info.mesh,
                    pack_listen: info.listen,
                    pack_transport: info.transport,
                    service_addresses: Default::default(),
                })
                .expect("add node")
        };
        let ingress_id = add(&manager, ingress_dir);
        let agent_id = add(&manager, agent_dir);

        ExposeStack {
            manager,
            ingress_id,
            agent_id,
            edge_port,
            persisted,
        }
    }

    fn pref(id: &str, address: &str) -> crate::profile::ServiceAddressPref {
        crate::profile::ServiceAddressPref {
            id: id.into(),
            address: address.into(),
        }
    }

    /// set_prefs strictly validates address preferences: strict SocketAddr
    /// (no string surgery on `:`), loopback-only (what the engine's
    /// default-deny policy will dial), and known service ids only.
    #[tokio::test]
    async fn set_prefs_validates_service_addresses() {
        let stack = stack_with_expose_site();
        let manager = &stack.manager;
        let id = &stack.agent_id;

        // Hostnames are not dialable on the engine path.
        let err = manager
            .set_prefs(id, None, None, &[pref("web", "localhost:3000")])
            .unwrap_err();
        assert!(err.contains("<ip>:<port>"), "wrong error: {err}");

        // The default-deny policy only dials loopback for expose agents.
        let err = manager
            .set_prefs(id, None, None, &[pref("web", "10.0.0.5:80")])
            .unwrap_err();
        assert!(err.contains("loopback"), "wrong error: {err}");

        // The pack is the source of truth for the service set.
        let err = manager
            .set_prefs(id, None, None, &[pref("nope", "127.0.0.1:3000")])
            .unwrap_err();
        assert!(err.contains("not declared"), "wrong error: {err}");

        // Valid preference: normalized, persisted, and visible in the
        // snapshot as the effective address.
        manager
            .set_prefs(id, None, None, &[pref("web", "127.0.0.1:5173")])
            .expect("valid preference accepted");
        manager.settle().await;
        {
            let persisted = stack
                .persisted
                .lock()
                .unwrap_or_else(PoisonError::into_inner);
            let entry = persisted.iter().find(|e| &e.id == id).unwrap();
            assert_eq!(entry.service_addresses.len(), 1);
            assert_eq!(entry.service_addresses[0].address, "127.0.0.1:5173");
        }
        let snapshot = manager
            .snapshots()
            .into_iter()
            .find(|s| &s.spec.id == id)
            .unwrap();
        assert_eq!(
            snapshot.spec.service_addresses.get("web").unwrap(),
            "127.0.0.1:5173"
        );

        // Clearing (empty set) reverts to the pack default.
        manager
            .set_prefs(id, None, None, &[])
            .expect("empty set reverts to defaults");
        manager.settle().await;
        let snapshot = manager
            .snapshots()
            .into_iter()
            .find(|s| &s.spec.id == id)
            .unwrap();
        assert!(snapshot.spec.service_addresses.is_empty());
    }

    /// The proposal's acceptance sentence, end to end: a machine-local
    /// preference changes where the traffic lands; clearing it falls back
    /// to the pack default (a dead port — the request must fail).
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn service_address_preference_changes_where_traffic_lands() {
        let stack = stack_with_expose_site();
        let manager = &stack.manager;

        // The real service: an echo on its own port.
        let echo_port = crate::test_util::free_port();
        let echo = tokio::net::TcpListener::bind(("127.0.0.1", echo_port))
            .await
            .unwrap();
        tokio::spawn(async move {
            loop {
                let Ok((mut sock, _)) = echo.accept().await else {
                    break;
                };
                tokio::spawn(async move {
                    let mut buf = [0u8; 1024];
                    loop {
                        match sock.read(&mut buf).await {
                            Ok(0) | Err(_) => break,
                            Ok(n) => {
                                if sock.write_all(&buf[..n]).await.is_err() {
                                    break;
                                }
                            }
                        }
                    }
                });
            }
        });

        // Preference before first start (stopped-only rule).
        manager
            .set_prefs(
                &stack.agent_id,
                None,
                None,
                &[pref("web", &format!("127.0.0.1:{echo_port}"))],
            )
            .expect("set address preference");

        manager.start(&stack.ingress_id).expect("ingress start");
        wait_for(
            manager,
            &stack.ingress_id,
            |s| matches!(s, NodeState::Running),
            "Running",
        )
        .await;
        manager.start(&stack.agent_id).expect("agent start");
        connected(manager, &stack.agent_id).await;

        let request_via_edge = |expect: &'static str| async move {
            let mut sock = tokio::net::TcpStream::connect(("127.0.0.1", stack.edge_port))
                .await
                .expect("dial edge listener");
            // frontend-proxy mode: the edge requires X-Forwarded-For (a
            // fronting nginx always adds it).
            sock.write_all(
                b"GET / HTTP/1.1\r\nHost: test.local\r\nX-Forwarded-For: 127.0.0.1\r\nConnection: close\r\n\r\n",
            )
            .await
            .unwrap();
            let mut buf = [0u8; 64];
            match tokio::time::timeout(Duration::from_secs(5), sock.read(&mut buf)).await {
                Ok(Ok(n)) => (String::from_utf8_lossy(&buf[..n]).into_owned(), expect),
                Ok(Err(e)) => panic!("read failed: {e}"),
                Err(_) => ("timeout".to_owned(), expect),
            }
        };

        // With the preference in force, the request echoes back through the
        // preference's port.
        let (response, _) = request_via_edge("echo").await;
        assert!(
            response.starts_with("GET / HTTP/1.1"),
            "traffic must land on the preference's target, got {response:?}"
        );

        // Clear the preference while stopped → the pack default (a dead
        // port) takes over → the request must NOT round-trip.
        manager.stop(&stack.agent_id).await.expect("agent stop");
        wait_for(
            manager,
            &stack.agent_id,
            |s| *s == NodeState::Stopped,
            "Stopped",
        )
        .await;
        manager
            .set_prefs(&stack.agent_id, None, None, &[])
            .expect("clear preference");
        manager.start(&stack.agent_id).expect("agent restart");
        connected(manager, &stack.agent_id).await;
        let (response, _) = request_via_edge("dead").await;
        assert!(
            !response.contains("GET /"),
            "the dead default must not answer, got {response:?}"
        );

        manager.stop_all().await;
    }

    /// P1-2: update_pack swaps a new generation in place — identity-checked,
    /// state carried over, previous kept, start intent restored.
    #[tokio::test]
    async fn update_pack_swaps_generation_and_restores_intent() {
        let stack = stack_with_expose_site();
        let manager = &stack.manager;
        let agent_dir = manager
            .snapshots()
            .into_iter()
            .find(|s| s.spec.id == stack.agent_id)
            .unwrap()
            .spec
            .pack_dir
            .clone();

        // Node-local state (what a running node writes) must survive.
        let state_dir = agent_dir.join("state/credentials");
        std::fs::create_dir_all(&state_dir).unwrap();
        std::fs::write(state_dir.join("active.pem"), b"node-local material").unwrap();

        // Generation 2 of the same identity, rendered beside the install.
        // (Render from the same issuer + manifest shape: a fresh issuer
        // would change the identity and prove nothing about generations.)
        let dir = tempfile::tempdir().unwrap();
        let issuer = IssuerStore::open(dir.path().join("issuer"));
        issuer.ensure_realm().unwrap();
        issuer.ensure_workspace("default").unwrap();
        issuer.ensure_policy_key().unwrap();
        let manifest = Manifest::parse(&format!(
            r#"
[realm]
id = "gui-expose"
control_endpoint = "127.0.0.1:{}"
[public_tls]
mode = "frontend-proxy"
[registrar]
endpoint = "https://registrar.invalid"
[ingress.edge]
workspaces = ["default"]
[workspace.default]
[agent.desktop]
workspace = "default"
[[agent.desktop.services]]
id = "web"
address = "127.0.0.1:59999"
[[route]]
host = "test.local"
service = "default/desktop/web"
"#,
            crate::test_util::free_port()
        ))
        .unwrap();
        let gen2 = dir.path().join("gen2");
        AgentCredentialPack::render(&issuer, &manifest, "desktop", 2, &gen2).unwrap();
        std::mem::forget(dir);

        // A different identity refuses the swap outright.
        let hub_stack = stack_with_mesh_site(pending_renewal()).await;
        let hub_dir = hub_stack
            .manager
            .snapshots()
            .into_iter()
            .find(|s| s.spec.id == hub_stack.hub_id)
            .unwrap()
            .spec
            .pack_dir
            .clone();
        let err = manager
            .update_pack(&stack.agent_id, &hub_dir)
            .await
            .unwrap_err();
        assert!(err.contains("identity mismatch"), "wrong error: {err}");

        let report = manager
            .update_pack(&stack.agent_id, &gen2)
            .await
            .expect("update in place");
        assert_eq!(report.generation_from, 1);
        assert_eq!(report.generation_to, 2);
        assert!(!report.restarted, "the node was never started");

        // The install now runs generation 2; state survived; previous kept.
        let installed = CredentialPack::load_runtime(&agent_dir).unwrap();
        assert_eq!(installed.metadata.generation, 2);
        assert_eq!(
            std::fs::read(agent_dir.join("state/credentials/active.pem")).unwrap(),
            b"node-local material",
            "node-local state must survive the swap"
        );
        assert!(
            agent_dir
                .with_extension("previous")
                .join("pack.toml")
                .exists()
                || agent_dir
                    .parent()
                    .unwrap()
                    .join(format!(
                        "{}.previous",
                        agent_dir.file_name().unwrap().to_string_lossy()
                    ))
                    .join("pack.toml")
                    .exists(),
            "the previous pack is kept as .previous"
        );
        // Display caches refreshed from the new content.
        let snapshot = manager
            .snapshots()
            .into_iter()
            .find(|s| s.spec.id == stack.agent_id)
            .unwrap();
        assert_eq!(snapshot.spec.generation, 2);
        assert_eq!(
            snapshot.spec.pack_services[0].default_address,
            "127.0.0.1:59999"
        );
    }

    /// ④ of the QUIC-switch GUI consolidation: a pack directory that was
    /// cleared or moved aside (e.g. while re-organizing the dist tree) must
    /// not block the update — the swap IS the repair, and the report falls
    /// back to the cached generation.
    #[tokio::test]
    async fn update_pack_recovers_from_a_cleared_pack_dir() {
        let stack = stack_with_expose_site();
        let manager = &stack.manager;
        let agent_dir = manager
            .snapshots()
            .into_iter()
            .find(|s| s.spec.id == stack.agent_id)
            .unwrap()
            .spec
            .pack_dir
            .clone();

        // Generation 2 of the same identity (same issuer discipline as the
        // swap test above: a fresh issuer would change the identity).
        let dir = tempfile::tempdir().unwrap();
        let issuer = IssuerStore::open(dir.path().join("issuer"));
        issuer.ensure_realm().unwrap();
        issuer.ensure_workspace("default").unwrap();
        issuer.ensure_policy_key().unwrap();
        let manifest = Manifest::parse(&format!(
            r#"
[realm]
id = "gui-expose"
control_endpoint = "127.0.0.1:{}"
[public_tls]
mode = "frontend-proxy"
[registrar]
endpoint = "https://registrar.invalid"
[ingress.edge]
workspaces = ["default"]
[workspace.default]
[agent.desktop]
workspace = "default"
[[agent.desktop.services]]
id = "web"
address = "127.0.0.1:59999"
[[route]]
host = "test.local"
service = "default/desktop/web"
"#,
            crate::test_util::free_port()
        ))
        .unwrap();
        let gen2 = dir.path().join("gen2");
        AgentCredentialPack::render(&issuer, &manifest, "desktop", 2, &gen2).unwrap();
        std::mem::forget(dir);

        // The current install's directory content is gone (moved away while
        // re-organizing; the old code died here with "current pack
        // rejected: io error").
        std::fs::remove_dir_all(&agent_dir).unwrap();

        let report = manager
            .update_pack(&stack.agent_id, &gen2)
            .await
            .expect("the swap repairs a cleared install");
        assert_eq!(
            report.generation_from, 1,
            "fell back to the cached generation"
        );
        assert_eq!(report.generation_to, 2);

        // The install is whole again and the digest cache follows.
        let installed = CredentialPack::load_runtime(&agent_dir).unwrap();
        assert_eq!(installed.metadata.generation, 2);
        let snapshot = manager
            .snapshots()
            .into_iter()
            .find(|s| s.spec.id == stack.agent_id)
            .unwrap();
        assert_eq!(snapshot.spec.pack_digest, installed.pack_digest);
    }
}
