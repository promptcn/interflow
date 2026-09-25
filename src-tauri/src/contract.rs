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
use interflow_identity::manifest::{MeshEgressRule, MeshIngressRule, MeshProtocol};
use interflow_mesh::config::TransportKind;
use serde::{Deserialize, Serialize};

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
    Connected { agent_id: String },
    Reconnecting { reason: String, backoff_secs: u32 },
    Running,
    Stopping,
    Stopped,
    Failed { error: String },
}

impl From<NodeState> for NodeStateDto {
    fn from(state: NodeState) -> Self {
        match state {
            NodeState::Starting => Self::Starting,
            NodeState::Connecting => Self::Connecting,
            NodeState::Connected { agent_id } => Self::Connected { agent_id },
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
    /// Agent nodes only; `None` derives from the control endpoint.
    pub hub_quic_addr: Option<String>,
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
}

impl From<NodeSnapshot> for NodeInfo {
    fn from(snapshot: NodeSnapshot) -> Self {
        let attribution = crate::node::log_attribution(&snapshot.spec);
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
            hub_quic_addr: snapshot.spec.hub_quic_addr,
            services,
            mesh_ingress_rules,
            mesh_egress_rules,
            listen: snapshot.spec.pack_listen,
            generation: u32::try_from(snapshot.spec.generation).unwrap_or(u32::MAX),
            // Merged by the command layer from the manager's health cache
            // (the snapshot is pure node state).
            credential: None,
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

/// One rendered pack in a `plan apply` output tree (deploy page cards).
#[derive(Debug, Clone, Serialize, Deserialize, specta::Type)]
pub struct DeployPackDto {
    /// Directory name under `<out>/packs/` (e.g. `ingress-edge`).
    pub dir_name: String,
    pub kind: NodeKindDto,
    pub node: String,
    /// Rotation generation (u32 on the wire — specta forbids BigInt).
    pub generation: u32,
    pub expires: String,
    pub principal: String,
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
            dir_name: pack.dir_name,
            kind: pack.kind.into(),
            node: pack.node,
            generation: u32::try_from(pack.generation).unwrap_or(u32::MAX),
            expires: pack.expires,
            principal: pack.principal,
            local_node: None,
        }
    }
}

/// Parameters of the manifest template builder (mirrors `interflow setup`).
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

/// `deploy_add_node` parameters — the GUI twin of `interflow node add`
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
}

/// `[ingress.<node>]`.
#[derive(Debug, Clone, Deserialize, specta::Type)]
#[serde(deny_unknown_fields)]
pub struct IngressEditDto {
    pub node: String,
    pub workspaces: Vec<String>,
    pub listen: Option<String>,
    pub control_listen: Option<String>,
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
    SetAgentWorkspace { agent: String, workspace: String },
    RemoveAgent(String),
    UpsertService(ServiceEditDto),
    RemoveService { agent: String, id: String },
    UpsertMeshIngress(MeshIngressEditDto),
    RemoveMeshIngress { agent: String, name: String },
    UpsertMeshEgress(MeshEgressEditDto),
    RemoveMeshEgress { agent: String, name: String },
    UpsertRoute(RouteEditDto),
    RemoveRoute { host: String },
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
            }),
            EditActionDto::RemoveHub(name) => Self::RemoveHub(name),
            EditActionDto::UpsertIngress(edit) => Self::UpsertIngress(IngressEdit {
                node: edit.node,
                workspaces: edit.workspaces,
                listen: edit.listen,
                control_listen: edit.control_listen,
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
/// `interflow setup --face mesh`).
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

/// `node-state` event payload: which node transitioned to what.
#[derive(Debug, Clone, Serialize, Deserialize, specta::Type, tauri_specta::Event)]
#[tauri_specta(event_name = "node-state")]
pub struct NodeStateEvent {
    pub id: String,
    pub state: NodeStateDto,
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
                agent_id: "expose-mac".into()
            })
            .unwrap(),
            r#"{"Connected":{"agent_id":"expose-mac"}}"#
        );
    }
}
