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

/// A serve-side mesh rule (pack-signed; the GUI shows it read-only).
#[derive(Debug, Clone, Serialize, Deserialize, specta::Type)]
pub struct MeshEgressRuleDto {
    pub name: String,
    pub protocol: MeshProtocolDto,
    pub target_addr: String,
}

impl From<MeshEgressRule> for MeshEgressRuleDto {
    fn from(rule: MeshEgressRule) -> Self {
        Self {
            name: rule.name,
            protocol: rule.protocol.into(),
            target_addr: rule.target_addr,
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
