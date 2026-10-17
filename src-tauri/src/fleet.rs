//! The fleet composed read model (2026-10-10 IA): ONE join backing the
//! 总览/流/服务 views — the manifest's declared truth, the bookkeeping
//! change classification, the hub's fleet face, and the local NodeManager's
//! live faces, resolved against each other.
//!
//! Framework-free on purpose (the `node.rs` discipline): everything here is
//! a pure function of its inputs, so the composition is testable without a
//! Tauri app and the command layer stays a thin wrapper.
//!
//! Resolution key: the pack principal (`realm/workspace/kind/node`). A
//! declared manifest node matches a local node by principal (agents) or by
//! realm+kind+name (hubs/ingresses, whose workspace segment is `-`).

use crate::contract::{
    ChangeStateDto, FleetDto, FleetNodeDto, LocalFaceDto, NodeInfo, NodeKindDto, RemoteFaceDto,
    ServiceFaceDto, StreamDto, StreamStatusDto,
};

/// The principal segments of one local node, when it parses: `(realm,
/// workspace, kind, name)`; `None` for placeholder nodes (unreadable pack
/// at restore).
type Principal<'a> = Option<(&'a str, &'a str, &'a str, &'a str)>;

fn split_principal(principal: &str) -> Principal<'_> {
    let mut parts = principal.split('/');
    match (parts.next(), parts.next(), parts.next(), parts.next()) {
        (Some(realm), Some(workspace), Some(kind), Some(name)) if parts.next().is_none() => {
            Some((realm, workspace, kind, name))
        }
        _ => None,
    }
}

/// Whether one local node is the manifest-declared agent `agent` of realm
/// `realm` (workspace is part of the key — an agent IS its workspace).
fn is_agent(info: &NodeInfo, realm: &str, agent: &crate::contract::AgentSummaryDto) -> bool {
    split_principal(info.principal.as_deref().unwrap_or("")).is_some_and(
        |(p_realm, p_ws, p_kind, p_name)| {
            p_realm == realm && p_ws == agent.workspace && p_kind == "agent" && p_name == agent.node
        },
    )
}

/// Whether one local node is the manifest-declared hub/ingress `name` (the
/// workspace segment is `-` on those packs — match realm+kind+name).
fn is_hub_or_ingress(info: &NodeInfo, realm: &str, kind: &str, name: &str) -> bool {
    split_principal(info.principal.as_deref().unwrap_or("")).is_some_and(
        |(p_realm, _p_ws, p_kind, p_name)| p_realm == realm && p_kind == kind && p_name == name,
    )
}

fn local_face(info: &NodeInfo) -> LocalFaceDto {
    LocalFaceDto {
        id: info.id.clone(),
        state: info.state.clone(),
        desired_running: info.desired_running,
        generation: info.generation,
        policy_generation: info.policy.as_ref().map(|p| p.generation),
        listeners: info.listeners.clone().unwrap_or_default(),
    }
}

/// The hub's row for one agent, matched by the qualified id's agent segment
/// (`tenant/agent` — the manifest's workspace + node).
fn remote_face(
    hub: &crate::contract::HubOverviewDto,
    workspace: &str,
    node: &str,
) -> Option<RemoteFaceDto> {
    hub.agents
        .iter()
        .find(|row| row.agent == format!("{workspace}/{node}"))
        .map(|row| RemoteFaceDto {
            online: row.online,
            seen_generation: row.seen,
        })
}

/// Whether the policy face has converged on a node: the hub's serving
/// generation (floor as the fallback) is at or below what the node applied.
fn converged(hub: &crate::contract::HubOverviewDto, applied: Option<u32>) -> Option<bool> {
    let serving = hub.serving.or(Some(hub.floor))?;
    Some(applied.is_some_and(|seen| seen >= serving))
}

/// Composes the fleet view. `nodes` are the ALREADY-composed `NodeInfo`s
/// (the `list_nodes` composition — snapshot + health faces); everything
/// else arrives as its final DTO.
pub fn compose(
    summary: crate::contract::ManifestSummaryDto,
    change_state: ChangeStateDto,
    hub: Option<crate::contract::HubOverviewDto>,
    nodes: Vec<NodeInfo>,
) -> FleetDto {
    let realm = summary.realm.id.clone();

    // Declare→local resolution, computed once: every declared node that has
    // a face on this machine. The owned local-only list is what remains.
    let mut local_only: Vec<NodeInfo> = nodes;
    fn take_local(
        local_only: &mut Vec<NodeInfo>,
        matches: impl Fn(&NodeInfo) -> bool,
    ) -> Option<NodeInfo> {
        let index = local_only.iter().position(matches);
        index.map(|i| local_only.remove(i))
    }

    // ---- nodes (fleet table) ----
    let mut fleet_nodes = Vec::new();
    let mut agent_locals = Vec::new();
    for agent in &summary.agents {
        let local = take_local(&mut local_only, |n| is_agent(n, &realm, agent));
        let remote = hub
            .as_ref()
            .and_then(|h| remote_face(h, &agent.workspace, &agent.node));
        let kind = match agent.role {
            crate::contract::AgentRoleDto::Expose => NodeKindDto::ExposeAgent,
            _ => NodeKindDto::MeshAgent,
        };
        fleet_nodes.push(FleetNodeDto {
            kind,
            name: agent.node.clone(),
            workspace: Some(agent.workspace.clone()),
            local: local.as_ref().map(local_face),
            remote,
        });
        agent_locals.push((agent, local));
    }
    for hub_decl in &summary.hubs {
        let local = take_local(&mut local_only, |n| {
            is_hub_or_ingress(n, &realm, "hub", &hub_decl.name)
        });
        fleet_nodes.push(FleetNodeDto {
            kind: NodeKindDto::Hub,
            name: hub_decl.name.clone(),
            workspace: None,
            local: local.as_ref().map(local_face),
            remote: None,
        });
    }
    for ingress in &summary.ingress {
        let local = take_local(&mut local_only, |n| {
            is_hub_or_ingress(n, &realm, "ingress", &ingress.node)
        });
        fleet_nodes.push(FleetNodeDto {
            kind: NodeKindDto::Ingress,
            name: ingress.node.clone(),
            workspace: None,
            local: local.as_ref().map(local_face),
            remote: None,
        });
    }

    // ---- streams (the 流 view) ----
    let mut streams = Vec::new();
    for (agent, local) in &agent_locals {
        for rule in &agent.mesh_ingress {
            // The listener face, when the source runs here: its facts
            // (bound address, last bind failure) ride the row whatever the
            // convergence verdict says — a catching-up row still honestly
            // reports the old-policy listener it is running.
            let listener = local.as_ref().and_then(|info| {
                info.listeners
                    .as_ref()
                    .and_then(|ls| ls.iter().find(|l| l.rule == rule.name))
            });
            let bound_addr = listener.and_then(|l| l.bound_addr.clone());
            let last_error = listener.and_then(|l| l.last_error.clone());
            let status = match (local, hub.as_ref()) {
                (Some(info), maybe_hub) => {
                    let applied = info.policy.as_ref().map(|p| p.generation);
                    let behind = maybe_hub
                        .and_then(|h| converged(h, applied))
                        .is_some_and(|caught_up| !caught_up);
                    if behind {
                        StreamStatusDto::CatchingUp
                    } else {
                        match listener.map(|l| l.bound_addr.is_some()) {
                            Some(true) => StreamStatusDto::Serving,
                            Some(false) => StreamStatusDto::Down,
                            // Running with no listener face (not yet
                            // reconciled, or the node just started).
                            None => StreamStatusDto::Unknown,
                        }
                    }
                }
                (None, Some(h)) => {
                    // Remote source: only convergence is observable. A
                    // converged remote still cannot prove its bind state —
                    // stay honest and lean on the remote face.
                    let row = remote_face(h, &agent.workspace, &agent.node);
                    match row.and_then(|r| converged(h, r.seen_generation)) {
                        Some(true) | None => StreamStatusDto::Unknown,
                        Some(false) => StreamStatusDto::CatchingUp,
                    }
                }
                (None, None) => StreamStatusDto::Unknown,
            };
            streams.push(StreamDto {
                agent: agent.node.clone(),
                name: rule.name.clone(),
                listen: rule.listen.clone(),
                protocol: rule.protocol,
                target_agent: rule.target_agent.clone(),
                remote_addr: rule.remote_addr.clone(),
                idle_timeout_secs: rule.idle_timeout_secs,
                status,
                bound_addr,
                last_error,
                source_node_id: local.as_ref().map(|i| i.id.clone()),
            });
        }
    }

    // ---- services (the 服务 view) ----
    let mut services = Vec::new();
    for (agent, local) in &agent_locals {
        for service in &agent.services {
            let local_service = local
                .as_ref()
                .and_then(|info| info.services.iter().find(|s| s.id == service.id).cloned());
            services.push(ServiceFaceDto {
                agent: agent.node.clone(),
                workspace: agent.workspace.clone(),
                id: service.id.clone(),
                default_address: service.address.clone(),
                effective_address: local_service.as_ref().map(|s| s.effective_address.clone()),
                overridden: local_service.as_ref().is_some_and(|s| s.overridden),
                local_node_id: local.as_ref().map(|i| i.id.clone()),
            });
        }
    }

    FleetDto {
        summary,
        change_state,
        hub,
        nodes: fleet_nodes,
        streams,
        services,
        local_only,
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use crate::contract::{
        AgentSummaryDto, ChangeStateDto, HubAgentRowDto, HubOverviewDto, ListenerStatusDto,
        ManifestSummaryDto, MeshProtocolDto, NodeStateDto, PolicyPlaneDto, RealmDto,
    };

    fn agent_summary(node: &str) -> AgentSummaryDto {
        AgentSummaryDto {
            node: node.into(),
            workspace: "main".into(),
            role: crate::contract::AgentRoleDto::Mesh,
            transport: None,
            services: vec![],
            mesh_ingress: vec![crate::contract::ManifestIngressRuleDto {
                name: "db".into(),
                listen: "127.0.0.1:15432".into(),
                protocol: MeshProtocolDto::Tcp,
                target_agent: "srv".into(),
                remote_addr: "127.0.0.1:5432".into(),
                idle_timeout_secs: None,
            }],
            mesh_egress: vec![],
        }
    }

    fn summary() -> ManifestSummaryDto {
        ManifestSummaryDto {
            realm: RealmDto {
                id: "test".into(),
                control_endpoint: String::new(),
            },
            public_tls: crate::contract::PublicTlsDto {
                mode: crate::contract::PublicTlsModeDto::FrontendProxy,
                email: None,
                directory: None,
            },
            identity: crate::contract::IdentityDto {
                mode: crate::contract::IdentityModeDto::Registrar,
                leaf_ttl: None,
                leaf_ttl_bounds: crate::contract::LeafTtlBoundsDto {
                    min: "1h".into(),
                    max: "24h".into(),
                    default: "24h".into(),
                },
                registrar_endpoint: String::new(),
            },
            workspaces: vec!["main".into()],
            agents: vec![agent_summary("laptop"), agent_summary("srv")],
            ingress: vec![],
            routes: vec![],
            hubs: vec![],
            issues: vec![],
        }
    }

    type Extras = fn() -> (Option<PolicyPlaneDto>, Option<Vec<ListenerStatusDto>>);

    fn local_node(id: &str, name: &str, extras: Extras) -> NodeInfo {
        let (policy, listeners) = extras();
        NodeInfo {
            id: id.into(),
            kind: NodeKindDto::MeshAgent,
            name: name.into(),
            principal: Some(format!("test/main/agent/{name}")),
            attribution: format!("{name}#ab12"),
            pack_dir: format!("/packs/agent-{name}"),
            state: NodeStateDto::Running,
            desired_running: true,
            transport: None,
            pack_transport: None,
            hub_quic_addr: None,
            pack_hub_quic_addr: None,
            services: vec![],
            mesh_ingress_rules: vec![],
            mesh_egress_rules: vec![],
            listen: None,
            generation: 3,
            credential: None,
            policy,
            peers: None,
            proposals: None,
            listeners,
            deployment: None,
        }
    }

    fn none_extras() -> (Option<PolicyPlaneDto>, Option<Vec<ListenerStatusDto>>) {
        (None, None)
    }

    /// The join's contract: a local running agent with a bound listener is
    /// Serving; one behind the hub's serving generation is CatchingUp (even
    /// while still serving the old table); a remote agent answers only via
    /// convergence; unrelated local nodes land in `local_only`.
    #[test]
    fn stream_status_joins_local_listeners_and_hub_convergence() {
        let hub = HubOverviewDto {
            hub: None,
            floor: 5,
            serving: Some(5),
            agents: vec![
                HubAgentRowDto {
                    agent: "main/laptop".into(),
                    online: true,
                    seen: Some(5),
                },
                HubAgentRowDto {
                    agent: "main/srv".into(),
                    online: true,
                    seen: Some(4),
                },
            ],
        };
        let nodes = vec![local_node("id-laptop", "laptop", || {
            (
                Some(PolicyPlaneDto {
                    generation: 5,
                    source: crate::contract::PolicySourceDto::Pack,
                    hub_generation: Some(5),
                    pull: None,
                }),
                Some(vec![ListenerStatusDto {
                    rule: "db".into(),
                    bound_addr: Some("127.0.0.1:15432".into()),
                    last_error: None,
                }]),
            )
        })];
        let fleet = compose(
            summary(),
            ChangeStateDto::Applied { generation: 5 },
            Some(hub),
            nodes,
        );

        let laptop = fleet.streams.iter().find(|s| s.agent == "laptop").unwrap();
        assert_eq!(laptop.status, StreamStatusDto::Serving);
        assert_eq!(laptop.source_node_id.as_deref(), Some("id-laptop"));
        assert_eq!(laptop.bound_addr.as_deref(), Some("127.0.0.1:15432"));
        assert_eq!(laptop.last_error, None);

        // srv is remote: hub says seen 4 < serving 5 → catching up, and the
        // row honestly refuses to claim a bind state it cannot see.
        let srv = fleet.streams.iter().find(|s| s.agent == "srv").unwrap();
        assert_eq!(srv.status, StreamStatusDto::CatchingUp);
        assert_eq!(srv.source_node_id, None);
        assert_eq!(srv.bound_addr, None);
        assert_eq!(srv.last_error, None);

        // The laptop fleet row carries both faces; the hub row is matched by
        // qualified id, not by name alone.
        let row = fleet.nodes.iter().find(|n| n.name == "laptop").unwrap();
        assert!(row.local.is_some());
        assert_eq!(row.remote.as_ref().unwrap().seen_generation, Some(5));
    }

    /// A local agent serving an OLD policy (applied 4 < hub 5) is
    /// CatchingUp even though its listener is bound — the row must not say
    /// "serving" while the current generation has not landed.
    #[test]
    fn behind_policy_downgrades_to_catching_up() {
        let hub = HubOverviewDto {
            hub: None,
            floor: 5,
            serving: Some(5),
            agents: vec![],
        };
        let nodes = vec![local_node("id-a", "laptop", || {
            (
                Some(PolicyPlaneDto {
                    generation: 4,
                    source: crate::contract::PolicySourceDto::Pack,
                    hub_generation: Some(5),
                    pull: None,
                }),
                Some(vec![ListenerStatusDto {
                    rule: "db".into(),
                    bound_addr: Some("127.0.0.1:15432".into()),
                    last_error: None,
                }]),
            )
        })];
        let fleet = compose(
            summary(),
            ChangeStateDto::Applied { generation: 5 },
            Some(hub),
            nodes,
        );
        assert_eq!(fleet.streams[0].status, StreamStatusDto::CatchingUp);
        // The old-policy listener's bound fact still rides the row — the
        // status word steps down, the observable truth does not.
        assert_eq!(
            fleet.streams[0].bound_addr.as_deref(),
            Some("127.0.0.1:15432")
        );

        // No hub overview at all: the local bind state stands on its own.
        let fleet = compose(
            summary(),
            ChangeStateDto::Applied { generation: 5 },
            None,
            vec![local_node("id-a", "laptop", none_extras)],
        );
        assert_eq!(fleet.streams[0].status, StreamStatusDto::Unknown);
    }

    /// A failed bind is Down and the failure rides the row verbatim — the
    /// 流 view's "挂了看原因" contract (gui.md).
    #[test]
    fn down_streams_carry_the_bind_error() {
        let nodes = vec![local_node("id-a", "laptop", || {
            (
                Some(PolicyPlaneDto {
                    generation: 5,
                    source: crate::contract::PolicySourceDto::Pack,
                    hub_generation: Some(5),
                    pull: None,
                }),
                Some(vec![ListenerStatusDto {
                    rule: "db".into(),
                    bound_addr: None,
                    last_error: Some("bind 127.0.0.1:15432: address in use".into()),
                }]),
            )
        })];
        let fleet = compose(
            summary(),
            ChangeStateDto::Applied { generation: 5 },
            None,
            nodes,
        );
        assert_eq!(fleet.streams[0].status, StreamStatusDto::Down);
        assert_eq!(fleet.streams[0].bound_addr, None);
        assert_eq!(
            fleet.streams[0].last_error.as_deref(),
            Some("bind 127.0.0.1:15432: address in use")
        );
    }

    /// A node of another realm/workspace never matches the declaration and
    /// stays in `local_only` (sealed imports and foreign deployments).
    #[test]
    fn foreign_locals_stay_local_only() {
        let mut foreign = local_node("id-x", "laptop", none_extras);
        foreign.principal = Some("other/main/agent/laptop".into());
        let fleet = compose(summary(), ChangeStateDto::NeverApplied, None, vec![foreign]);
        assert!(fleet.nodes.iter().all(|n| n.local.is_none()));
        assert_eq!(fleet.local_only.len(), 1);
        assert_eq!(fleet.local_only[0].id, "id-x");
    }
}
