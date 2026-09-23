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
//!.
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
use interflow_identity::pack::{CredentialPack, NodeMeshConfig, PackKind};
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
    /// Public-domain tunnel agent (the `interflow agent` engine).
    ExposeAgent,
    /// Site-to-site mesh agent (the `interflow-mesh agent` engine).
    MeshAgent,
    /// Site-to-site mesh hub (the `interflow-mesh hub` engine).
    Hub,
    /// Public-domain ingress edge (the `interflow ingress` engine).
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
    /// Control endpoint (agents dial it; hubs/ingress show their listen).
    pub control_endpoint: String,
    /// Expose services declared in the pack (id + default address).
    pub services: Vec<PackService>,
    /// Site-to-site rules the pack carries (mesh agents; the rule counts
    /// derive from its vecs).
    pub mesh: Option<NodeMeshConfig>,
    /// Listen address (hub/ingress).
    pub listen: Option<String>,
}

/// Inspects a pack directory through the shared validation funnel — the same
/// `CredentialPack::load_runtime` the start path uses, so a pack that
/// inspects clean also starts clean (the 2026-09-18 papercuts lesson:
/// validation lives in the shared layer, not the GUI).
pub fn inspect_pack(pack_dir: &Path) -> Result<PackInfo, String> {
    let pack = CredentialPack::load_runtime(pack_dir)
        .map_err(|e| format!("Credential Pack rejected: {e}"))?;
    Ok(PackInfo {
        kind: NodeKind::classify(&pack),
        name: pack.metadata.node.clone(),
        principal: pack_principal(&pack),
        generation: pack.metadata.generation,
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
        mesh: pack.node_config.mesh.clone(),
        listen: pack.node_config.listen.clone(),
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
    /// Services the pack declares (id + manifest-issued default address).
    /// Display-and-validation cache: `prepare` re-reads the pack for the
    /// dial targets, so a swapped pack cannot lie about defaults for long.
    pub pack_services: Vec<PackService>,
    /// Site-to-site rules the pack declares (mesh agents). Display cache in
    /// the same spirit as `pack_services`: the pack is the signed truth, the
    /// GUI shows it read-only — `prepare` re-reads the pack to run.
    pub pack_mesh: Option<NodeMeshConfig>,
    /// Public/control listener the pack declares (hub/ingress). Display
    /// cache, same lifecycle as `pack_services`.
    pub pack_listen: Option<String>,
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
    /// Agent: registered and serving.
    Connected {
        agent_id: String,
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
            AgentState::Connected { agent_id } => Self::Connected { agent_id },
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
    Mesh(AgentConfig),
    Hub(HubConfig),
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
            let mut args = interflow_cli::runtime::build_agent_args(
                &pack,
                &active,
                &dir,
                spec.transport.unwrap_or_default(),
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
            // The pack path pins h2 defaults; the node preference (the same
            // h2/QUIC choice expose agents expose) overrides the two plain
            // fields.
            if let Some(transport) = spec.transport {
                config.agent.transport = transport;
            }
            let quic_addr = spec
                .hub_quic_addr
                .clone()
                .filter(|s| !s.trim().is_empty())
                .or_else(|| derive_quic_addr(&config.agent.hub_url));
            config.agent.hub_quic_addr = quic_addr;
            config.agent.log_name = Some(log_attribution(spec));
            Ok(Prepared::Mesh(config))
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
            Ok(Prepared::Hub(config))
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
fn derive_quic_addr(hub_url: &str) -> Option<String> {
    let no_scheme = hub_url
        .trim()
        .trim_start_matches("https://")
        .trim_start_matches("http://");
    if let Some((host, tail)) = no_scheme
        .strip_prefix('[')
        .and_then(|rest| rest.split_once(']'))
    {
        // IPv6: [::1]:port
        let port = tail.trim_start_matches(':');
        return (!port.is_empty()).then(|| format!("[{host}]:{port}"));
    }
    match no_scheme.rsplit_once(':') {
        Some((_, port)) if !port.is_empty() && port.bytes().all(|b| b.is_ascii_digit()) => {
            Some(no_scheme.to_string())
        }
        _ => None,
    }
}

/// A running engine, normalized.
enum Engine {
    Agent(AgentHandle),
    Hub(HubHandle),
    Ingress(FutureEngine),
}

impl Engine {
    fn is_alive(&self) -> bool {
        match self {
            Self::Agent(h) => {
                !matches!(h.state(), AgentState::Stopped | AgentState::Failed { .. })
                    && !h.is_finished()
            }
            // The hub monitor reaches a terminal lifecycle when (and only
            // when) the run future ended.
            Self::Hub(h) => !h.is_finished(),
            Self::Ingress(e) => !matches!(e.state(), NodeState::Stopped | NodeState::Failed { .. }),
        }
    }

    async fn shutdown_graceful(self) -> Result<(), String> {
        match self {
            Self::Agent(h) => h.shutdown_graceful().await.map_err(|e| e.to_string()),
            Self::Hub(h) => h.shutdown_graceful().await.map_err(|e| e.to_string()),
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
                        Ok(()) => true,
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

/// What the manager tells its sinks, in order. Mutation code only ever
/// *sends* these — inside the critical section, right where the state is
/// applied, so FIFO delivery order equals application order — and the
/// consumer task alone turns them into sink calls, lock-free. Before this
/// split, sinks were called directly under the manager lock and the GUI's
/// read-back tray refresh self-deadlocked Start
///.
enum ManagerEvent {
    State {
        id: NodeId,
        state: NodeState,
    },
    Persist {
        entries: Vec<crate::profile::NodeEntry>,
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
    ) -> Self {
        Self::with_renewal(
            rt,
            on_state,
            on_persist,
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
        renewal: RenewalFactory,
    ) -> Self {
        let (events, mut rx) = tokio::sync::mpsc::unbounded_channel();
        // The sinks belong to the consumer alone — mutation code only ever
        // holds the sender, so "call a sink under the lock" has no path.
        let on_state: StateSink = Arc::new(on_state);
        let on_persist: PersistSink = Arc::new(on_persist);
        rt.spawn(async move {
            while let Some(event) = rx.recv().await {
                match event {
                    ManagerEvent::State { id, state } => on_state(&id, &state),
                    ManagerEvent::Persist { entries } => on_persist(&entries),
                    ManagerEvent::Settled { ack } => {
                        let _ = ack.send(());
                    }
                }
            }
        });
        Self {
            inner: Arc::new(Mutex::new(Inner {
                nodes: HashMap::new(),
            })),
            rt,
            events,
            renewal,
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
        let (pack_dir, principal, desired_running) = {
            let inner = self.lock();
            let entry = inner
                .nodes
                .get(id)
                .ok_or_else(|| "unknown node".to_string())?;
            (
                entry.spec.pack_dir.clone(),
                entry.spec.principal.clone(),
                entry.desired_running,
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
        let generation_from = CredentialPack::load_runtime(&pack_dir)
            .map_err(|e| format!("current pack rejected: {e}"))?
            .metadata
            .generation;

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
            entry.spec.name = installed.metadata.node;
            entry.spec.principal = Some(source_principal);
            entry.spec.generation = generation_to;
            entry.spec.pack_services = installed
                .node_config
                .services
                .iter()
                .map(|s| PackService {
                    id: s.id.clone(),
                    default_address: s.address.clone(),
                })
                .collect();
            entry.spec.pack_mesh.clone_from(&installed.node_config.mesh);
            entry
                .spec
                .pack_listen
                .clone_from(&installed.node_config.listen);
        }

        if desired_running {
            self.start(id)?;
        }
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
                entry.engine = Some(Engine::Agent(handle));
            }
            Prepared::Mesh(config) => {
                let handle = AgentClient::new(config)
                    .map_err(|e| format!("cannot start: {e}"))?
                    .start();
                self.clone()
                    .spawn_agent_listener(id, generation, handle.subscribe_state());
                entry.state = handle.state().into();
                entry.engine = Some(Engine::Agent(handle));
            }
            Prepared::Hub(config) => {
                let handle = HubHandle::spawn(config).map_err(|e| format!("cannot start: {e}"))?;
                self.clone()
                    .spawn_hub_listener(id, generation, handle.subscribe_state());
                entry.state = handle.state().into();
                entry.engine = Some(Engine::Hub(handle));
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
    let (kind, name, principal, pack_services, pack_mesh, pack_listen, generation) =
        match CredentialPack::load_runtime(&pack_dir) {
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
                let mesh = pack.node_config.mesh.clone();
                let listen = pack.node_config.listen.clone();
                (
                    NodeKind::classify(&pack),
                    pack.metadata.node,
                    principal,
                    services,
                    mesh,
                    listen,
                    pack.metadata.generation,
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
                0,
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
            pack_services,
            pack_mesh,
            pack_listen,
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
    fn quic_addr_derivation() {
        assert_eq!(
            derive_quic_addr("https://127.0.0.1:6666"),
            Some("127.0.0.1:6666".into())
        );
        assert_eq!(
            derive_quic_addr("https://[2001:db8::1]:6666"),
            Some("[2001:db8::1]:6666".into())
        );
        // No port: None (engine validation produces the pointed error).
        assert_eq!(derive_quic_addr("https://hub.example.com"), None);
        assert_eq!(
            derive_quic_addr("127.0.0.1:6666"),
            Some("127.0.0.1:6666".into())
        );
    }

    #[test]
    fn node_state_maps_agent_and_hub_lifecycles() {
        assert_eq!(
            NodeState::from(AgentState::Connected {
                agent_id: "lan-a".into()
            }),
            NodeState::Connected {
                agent_id: "lan-a".into()
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
        hub_id: NodeId,
        lan_a_id: NodeId,
        lan_b_id: NodeId,
        listen_port: u16,
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
            renewal,
        );
        *manager_slot.lock().unwrap_or_else(PoisonError::into_inner) = Some(manager.clone());

        let add = |manager: &NodeManager, dir: std::path::PathBuf| {
            let info = inspect_pack(&dir).expect("pack inspects clean");
            manager
                .add(NodeSpec {
                    generation: info.generation,
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
                    service_addresses: Default::default(),
                })
                .expect("add node")
        };
        let node_hub = add(&manager, hub_dir);
        let node_a = add(&manager, dir_a);
        let node_b = add(&manager, dir_b);

        TestStack {
            manager,
            events,
            persisted,
            hub_id: node_hub,
            lan_a_id: node_a,
            lan_b_id: node_b,
            listen_port,
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

    fn tracing_recorder() -> RecordedEvents {
        use tracing_subscriber::layer::SubscriberExt as _;
        static RECORDER: OnceLock<RecordedEvents> = OnceLock::new();
        RECORDER
            .get_or_init(|| {
                let sink: RecordedEvents = Arc::new(StdMutex::new(Vec::new()));
                // Process-lifetime global (set_global_default never resets);
                // a second call would Err, but the OnceLock guarantees one.
                tracing::subscriber::set_global_default(
                    tracing_subscriber::registry().with(RecordingLayer(sink.clone())),
                )
                .expect("no other global subscriber in this test binary");
                sink
            })
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
                    pack_services: info.services,
                    pack_mesh: info.mesh,
                    pack_listen: info.listen,
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
}
