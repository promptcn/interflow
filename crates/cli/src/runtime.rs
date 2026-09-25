//! `interflow ingress run --pack` / `interflow agent run --pack` —
//! Credential-Pack → runtime-engine bootstrap.
//!
//! The user-facing model never sees certificate paths: the pack supplies
//! the identity, trust, and signed policy; this module maps it onto the
//! relay engine **in memory** — no intermediate config files are rendered,
//! so the bytes the issuer signed are the bytes the engine runs.

use interflow_core::error::{InterflowError, Result};
use interflow_core::security::{ProxyProtocolConfig, ProxyProtocolMode};
use interflow_expose::edge::{
    AcmeOptions, ControlEndpointTls, DEFAULT_FRONTED_NEW_CONN_RATE_PER_IP_PER_MINUTE,
    DEFAULT_NEW_CONN_RATE_PER_IP_PER_MINUTE, EdgeConfig, EdgeListenerPolicy, IngressPrincipal,
    PublicTls, Route, WorkspaceTrust,
};
use interflow_identity::credentials::ActiveCredentialSet;
use interflow_identity::pack::{CredentialPack, NodeEdgeConfig, PackKind};
use std::net::SocketAddr;
use std::path::Path;

/// Resolves the edge per-IP new-connection rate for an ingress pack.
///
/// An explicit `[edge]` override wins (0 = unlimited); otherwise the
/// topology default — fronted 600 (a front proxy opens one new connection
/// per proxied request, so the budget must scale with request rate, and
/// 600/min matches the reference nginx `limit_req 10r/s`), direct 30
/// (browser keepalive keeps new connections rare and no front shields the
/// listener). The 30/min default behind a front broke normal single-user
/// browsing into 502s once already — this split is the fix's load-bearing
/// part.
pub fn resolve_new_conn_rate(public_tls: &str, edge: Option<&NodeEdgeConfig>) -> u32 {
    if let Some(rate) = edge.and_then(|config| config.new_conn_rate_per_ip_per_minute) {
        return rate;
    }
    match public_tls {
        "frontend-proxy" | "manual" => DEFAULT_FRONTED_NEW_CONN_RATE_PER_IP_PER_MINUTE,
        _ => DEFAULT_NEW_CONN_RATE_PER_IP_PER_MINUTE,
    }
}

/// Resolves the control listener's PROXY protocol negotiation for an
/// ingress pack.
///
/// Topology-derived, same discipline as [`resolve_new_conn_rate`]: no
/// manifest field, no pack re-signing. Fronted topologies sit behind the
/// nginx stream fragment, which emits PROXY protocol (v1 on stock nginx)
/// on every SNI-map target — including the mTLS-passthrough control leg —
/// so the embedded hub must consume the preamble and re-key its per-IP
/// admission on the real client IP. Mode `On` (not `Required`): the edge's
/// internal workspace agents self-dial the control endpoint headerless
/// over loopback, and `On` is also what makes the zero-downtime rollout
/// order (new binaries first, nginx conf switch second) work — a headerless
/// leg is a plain direct connection. Direct topologies (`acme`) keep the
/// default (off): nothing fronts the control listener.
pub fn resolve_control_proxy_protocol(public_tls: &str) -> ProxyProtocolConfig {
    match public_tls {
        "frontend-proxy" | "manual" => ProxyProtocolConfig {
            mode: ProxyProtocolMode::On,
            trusted_proxies: vec!["127.0.0.1".to_owned(), "::1".to_owned()],
        },
        _ => ProxyProtocolConfig::default(),
    }
}

/// Pack load/validation failures are configuration-class (unrecoverable at
/// boot); keep the identity error as the source-chain root.
pub fn pack_error(e: interflow_identity::Error) -> InterflowError {
    InterflowError::config("credential pack error").with_source(e)
}

pub fn init_node_logging() {
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
    let _ = tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .with_target(false)
        .try_init();
}

pub async fn run_ingress(pack_dir: &Path) -> Result<()> {
    init_node_logging();
    let pack = CredentialPack::load_runtime(pack_dir).map_err(pack_error)?;
    let active = ActiveCredentialSet::load_or_bootstrap(&pack).map_err(pack_error)?;
    let config = build_edge_config(&pack, &active, pack_dir)?;
    tokio::select! {
        result = interflow_expose::edge::run(config) => result,
        result = interflow_renewal::renewal_scheduler(pack_dir) => result,
    }
}

pub async fn run_agent(pack_dir: &Path) -> Result<()> {
    init_node_logging();
    let pack = CredentialPack::load_runtime(pack_dir).map_err(pack_error)?;
    if pack.metadata.kind != PackKind::Agent {
        return Err(InterflowError::config(format!(
            "this is an {} pack — it cannot start as an agent (role-bound)",
            pack.metadata.kind.as_str()
        )));
    }
    pack.primary_identity().map_err(pack_error)?;
    let args = build_agent_args(
        &pack,
        &ActiveCredentialSet::load_or_bootstrap(&pack).map_err(pack_error)?,
        pack_dir,
        interflow_mesh::config::TransportKind::default(),
        None,
        // Headless run: no profile, so no machine-local preferences — every
        // service dials its pack default.
        &std::collections::BTreeMap::new(),
    )?;
    let mut handle = interflow_expose::client::start(&args)?;
    println!(
        "agent {} started: {} service(s) → {}",
        pack.metadata.node,
        pack.node_config.services.len(),
        args.hub_url
    );
    // Expose agents are pure dial-out (no listener to bind): the supervised
    // client itself is the service — the same nothing-to-probe condition the
    // old install probes treated as ready. READY releases a Type=notify
    // start job; hub connectivity is supervised reconnect, never a gate.
    interflow_util::systemd::notify_ready();
    let mut events = handle.take_events();
    let pump = tokio::spawn(async move {
        use interflow_mesh::agent::AgentEvent;
        while let Some(ev) = events.recv().await {
            match ev {
                AgentEvent::StateChanged(state) => {
                    eprintln!("agent state: {state:?}");
                }
                AgentEvent::SessionEstablished { agent_id } => {
                    eprintln!("control session established: {agent_id}");
                }
                AgentEvent::SessionEnded { reason } => {
                    eprintln!("control session ended: {reason}");
                }
            }
        }
    });
    tokio::select! {
        () = wait_for_shutdown() => {},
        result = interflow_renewal::renewal_scheduler(pack_dir) => result?,
    }
    pump.abort();
    handle.shutdown_graceful().await?;
    Ok(())
}

/// Builds the typed edge engine configuration from a fully validated
/// Credential Pack.
///
/// Routes resolve in memory from the **signed** runtime policy (public
/// host → workspace/agent/service). The policy carries service ids only:
/// where the target agent dials is node-side (pack default + machine-local
/// preference), selected by id over the inner stream — never authored on
/// the public side, never round-tripped through a file an operator or
/// attacker could edit without signature coverage.
pub fn build_edge_config(
    pack: &CredentialPack,
    active: &ActiveCredentialSet,
    pack_dir: &Path,
) -> Result<EdgeConfig> {
    if pack.metadata.kind != PackKind::Ingress {
        return Err(InterflowError::config(format!(
            "this is an {} pack — it cannot start as an ingress (role-bound)",
            pack.metadata.kind.as_str()
        )));
    }
    let authorized = pack.ingress_identities().map_err(pack_error)?;
    if authorized.is_empty() {
        return Err(InterflowError::config(
            "ingress pack carries no workspace principal",
        ));
    }

    // Trust: one issuer CA per workspace carried in the pack's trust
    // bundle (workspace/<name> issuers land as trust/workspace-<name>.crt).
    let trust_dir = pack_dir.join("trust");
    let mut workspace_trust = Vec::with_capacity(pack.trust.metadata.issuers.len());
    for name in pack.trust.metadata.issuers.keys() {
        if let Some(workspace) = name.strip_prefix("workspace/") {
            workspace_trust.push(WorkspaceTrust {
                workspace: workspace.to_owned(),
                ca: trust_dir.join(format!("{}.crt", name.replace('/', "-"))),
            });
        }
    }

    // Principals: one workspace-scoped ingress credential per authorization.
    let principals = authorized
        .keys()
        .filter_map(|workspace| {
            let stem = format!("ingress-{workspace}");
            active
                .material_paths(&stem)
                .ok()
                .map(|(cert, key)| IngressPrincipal {
                    workspace: workspace.clone(),
                    cert,
                    key,
                })
        })
        .collect::<Vec<_>>();

    // Routes: resolved from the signed policy, in memory. The edge learns
    // only the service **id** — where the agent dials is node-side (pack
    // default + machine-local preference), so no address ever crosses this
    // boundary in either direction.
    let mut routes = Vec::with_capacity(pack.policy.routes.len());
    for route in &pack.policy.routes {
        let Some(service) = pack.policy.find_service(&route.service) else {
            return Err(InterflowError::config(format!(
                "signed policy route {host:?} references unknown service {service:?}",
                host = route.host,
                service = route.service
            )));
        };
        routes.push(Route {
            host: route.host.clone(),
            workspace: service.workspace.clone(),
            agent_id: service.agent.clone(),
            service_id: service.id.clone(),
        });
    }

    let listen: SocketAddr = pack
        .node_config
        .listen
        .as_deref()
        .unwrap_or("0.0.0.0:8443")
        .parse()
        .map_err(|e| {
            InterflowError::config(format!(
                "ingress listen address {:?} is invalid",
                pack.node_config.listen
            ))
            .with_source(e)
        })?;
    let control_listen: SocketAddr = pack
        .node_config
        .control_listen
        .as_deref()
        .unwrap_or("127.0.0.1:16666")
        .parse()
        .map_err(|e| {
            InterflowError::config(format!(
                "control endpoint listen address {:?} is invalid",
                pack.node_config.control_listen
            ))
            .with_source(e)
        })?;

    // Public-HTTPS termination: `acme` terminates TLS on the ingress itself
    // (HTTP-01 + TLS-ALPN-01 + renewal, state under the pack directory);
    // the fronted topologies keep the plain-TCP listener behind the proxy.
    let fronted = matches!(
        pack.node_config.public_tls.as_str(),
        "frontend-proxy" | "manual"
    );
    let public_tls = if pack.node_config.public_tls == "acme" {
        let email = pack.node_config.public_tls_email.clone().ok_or_else(|| {
            InterflowError::config(
                "acme mode requires a contact email ([public_tls] email in the manifest)",
            )
        })?;
        PublicTls::Acme(AcmeOptions {
            hosts: Vec::new(), // filled from the resolved routes by the engine
            email,
            directory: pack.node_config.public_tls_directory.clone(),
            directory_ca: None,
            cache_dir: pack_dir.join("state").join("acme"),
            http_listen: "0.0.0.0:80".parse().expect("static addr"),
        })
    } else {
        PublicTls::Fronted
    };

    Ok(EdgeConfig {
        listen_addr: listen,
        control_listen_addr: control_listen,
        control_tls: ControlEndpointTls {
            cert: active
                .material_paths("control-endpoint")
                .map_err(pack_error)?
                .0,
            key: active
                .material_paths("control-endpoint")
                .map_err(pack_error)?
                .1,
        },
        control_proxy_protocol: resolve_control_proxy_protocol(&pack.node_config.public_tls),
        workspace_trust,
        principals,
        routes,
        quic_listen: None,
        audit_path: Some(pack_dir.join("audit.jsonl")),
        listener: EdgeListenerPolicy {
            x_forwarded_for: if fronted {
                interflow_core::security::XffMode::Required
            } else {
                interflow_core::security::XffMode::Off
            },
            new_conn_rate_per_ip_per_minute: resolve_new_conn_rate(
                &pack.node_config.public_tls,
                pack.node_config.edge.as_ref(),
            ),
            ..EdgeListenerPolicy::default()
        },
        public_tls,
        control_dispatch_host: pack.node_config.control_dispatch_host.clone(),
        ..EdgeConfig::default()
    })
}

/// Builds the agent engine arguments from a fully validated Credential Pack.
///
/// The pack is the single source of node material: identity, trust anchors,
/// control endpoint, and the service **set** all derive from it — callers
/// only contribute machine-local preferences (transport, hub QUIC address,
/// and per-service dial-address overrides). Effective address = override ?
/// ? pack default (`node.toml`); an empty override map is the headless
/// `agent run --pack` behavior (defaults only).
pub fn build_agent_args(
    pack: &CredentialPack,
    active: &ActiveCredentialSet,
    pack_dir: &Path,
    transport: interflow_mesh::config::TransportKind,
    hub_quic_addr: Option<String>,
    service_overrides: &std::collections::BTreeMap<String, String>,
) -> Result<interflow_expose::client::ExposeArgs> {
    let workspace =
        pack.metadata.workspace.as_deref().ok_or_else(|| {
            InterflowError::config("agent pack is missing its workspace".to_owned())
        })?;
    if pack.metadata.kind != PackKind::Agent {
        return Err(InterflowError::config(format!(
            "this is an {} pack — it cannot start as an agent (role-bound)",
            pack.metadata.kind.as_str()
        )));
    }
    let trust_dir = pack_dir.join("trust");
    let (cert, key) = active
        .material_paths(&format!("agent-{workspace}"))
        .map_err(pack_error)?;
    let control_anchor = trust_dir.join("control.crt");
    let ingress_anchor = trust_dir.join(format!("workspace-{workspace}.crt"));
    let services = resolve_local_services(&pack.node_config.services, service_overrides)?;
    Ok(interflow_expose::client::ExposeArgs {
        log_name: None,
        services,
        hub_url: normalize_endpoint(&pack.metadata.control_endpoint),
        agent_id: pack.metadata.node.clone(),
        client_cert: Some(cert.display().to_string()),
        client_key: Some(key.display().to_string()),
        ca_path: Some(control_anchor.display().to_string()),
        ingress_ca_path: Some(ingress_anchor.display().to_string()),
        transport,
        hub_quic_addr,
    })
}

/// Resolves each declared service to its effective dial target: a
/// machine-local preference wins, the pack default (`node.toml`) fills the
/// rest. Strict `SocketAddr` parsing — never string surgery on `:` — with
/// the service id and the value's origin in the error. Overrides for ids
/// the pack no longer declares are ignored with a warning (the pack is the
/// source of truth for the service set; rotate may drop services).
fn resolve_local_services(
    declared: &[interflow_identity::pack::NodeService],
    overrides: &std::collections::BTreeMap<String, String>,
) -> Result<Vec<interflow_expose::client::LocalService>> {
    for id in overrides.keys() {
        if !declared.iter().any(|s| &s.id == id) {
            tracing::warn!(
                "ignoring address preference for service {id:?} — the pack does not \
                 declare it (a rotation may have removed it)"
            );
        }
    }
    declared
        .iter()
        .map(|service| {
            let (raw, origin, overridden) = match overrides.get(&service.id) {
                Some(address) => (address.as_str(), "local preference", true),
                None => (service.address.as_str(), "pack default", false),
            };
            let target_addr: SocketAddr = raw.parse().map_err(|e| {
                InterflowError::config(format!(
                    "service {:?} has an invalid address {raw:?} ({origin}) — expected \
                     <ip>:<port> (e.g. 127.0.0.1:3000)",
                    service.id
                ))
                .with_source(e)
            })?;
            Ok(interflow_expose::client::LocalService {
                id: service.id.clone(),
                target_addr,
                overridden,
            })
        })
        .collect()
}

/// Unix/Windows shutdown signal with the conventional exit code.
async fn wait_for_shutdown() {
    #[cfg(unix)]
    {
        use tokio::signal::unix::{SignalKind, signal};
        let mut sigint = signal(SignalKind::interrupt()).expect("SIGINT handler");
        let mut sigterm = signal(SignalKind::terminate()).expect("SIGTERM handler");
        tokio::select! {
            _ = sigint.recv() => {},
            _ = sigterm.recv() => {},
        }
    }
    #[cfg(not(unix))]
    {
        let _ = tokio::signal::ctrl_c().await;
    }
}

pub fn normalize_endpoint(endpoint: &str) -> String {
    if endpoint.contains("://") {
        endpoint.to_owned()
    } else {
        format!("https://{endpoint}")
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::{
        NodeEdgeConfig, resolve_control_proxy_protocol, resolve_local_services,
        resolve_new_conn_rate,
    };
    use interflow_core::security::ProxyProtocolMode;
    use interflow_identity::pack::NodeService;
    use std::collections::BTreeMap;

    fn declared() -> Vec<NodeService> {
        vec![
            NodeService {
                id: "web".into(),
                address: "127.0.0.1:3000".into(),
            },
            NodeService {
                id: "api".into(),
                address: "127.0.0.1:9000".into(),
            },
        ]
    }

    fn overrides(pairs: &[(&str, &str)]) -> BTreeMap<String, String> {
        pairs
            .iter()
            .map(|(id, address)| ((*id).to_owned(), (*address).to_owned()))
            .collect()
    }

    /// Empty overrides = the headless `agent run --pack` behavior: every
    /// service dials its pack default.
    #[test]
    fn no_overrides_use_pack_defaults() {
        let services = resolve_local_services(&declared(), &BTreeMap::new()).unwrap();
        assert_eq!(services[0].id, "web");
        assert_eq!(services[0].target_addr.port(), 3000);
        assert_eq!(services[1].id, "api");
        assert_eq!(services[1].target_addr.port(), 9000);
        assert!(
            !services.iter().any(|s| s.overridden),
            "pack defaults are not overrides"
        );
    }

    /// A preference replaces only its own service's target — the one-step
    /// port change this whole feature exists for.
    #[test]
    fn override_replaces_only_its_service() {
        let services =
            resolve_local_services(&declared(), &overrides(&[("web", "127.0.0.1:5173")])).unwrap();
        assert_eq!(services[0].target_addr.port(), 5173);
        assert!(
            services[0].overridden,
            "the origin tag travels with the resolved service"
        );
        assert_eq!(
            services[1].target_addr.port(),
            9000,
            "api keeps its default"
        );
        assert!(!services[1].overridden);
    }

    /// A garbage default now fails loudly naming the service — the old
    /// `rsplit_once(':')` path silently dropped the port instead.
    #[test]
    fn invalid_address_fails_naming_the_service_and_origin() {
        let mut services = declared();
        services[0].address = "localhost:3000".into();
        let err = resolve_local_services(&services, &BTreeMap::new()).unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("web") && msg.contains("pack default"),
            "wrong error: {msg}"
        );

        let err =
            resolve_local_services(&declared(), &overrides(&[("web", "::1:443")])).unwrap_err();
        assert!(err.to_string().contains("local preference"), "{err}");
    }

    /// Overrides for ids the pack no longer declares are inert (a rotation
    /// may have removed them); the declared ones still resolve.
    #[test]
    fn unknown_override_ids_are_ignored() {
        let services = resolve_local_services(
            &declared(),
            &overrides(&[("gone", "127.0.0.1:1"), ("api", "127.0.0.1:8443")]),
        )
        .unwrap();
        assert_eq!(services.len(), 2);
        assert_eq!(services[1].target_addr.port(), 8443);
    }

    fn edge(rate: Option<u32>) -> NodeEdgeConfig {
        NodeEdgeConfig {
            new_conn_rate_per_ip_per_minute: rate,
        }
    }

    /// Fronted topologies default to 600/min: the front proxy opens one new
    /// connection per proxied request, so the direct-topology 30/min breaks
    /// normal browsing. Direct (ACME) keeps 30.
    #[test]
    fn topology_defaults_fronted_600_direct_30() {
        assert_eq!(resolve_new_conn_rate("frontend-proxy", None), 600);
        assert_eq!(resolve_new_conn_rate("manual", None), 600);
        assert_eq!(resolve_new_conn_rate("acme", None), 30);
    }

    /// An explicit `[edge]` override wins on every topology, including the
    /// 0 = unlimited escape hatch.
    #[test]
    fn explicit_override_wins() {
        assert_eq!(
            resolve_new_conn_rate("frontend-proxy", Some(&edge(Some(120)))),
            120
        );
        assert_eq!(resolve_new_conn_rate("acme", Some(&edge(Some(120)))), 120);
        assert_eq!(resolve_new_conn_rate("acme", Some(&edge(Some(0)))), 0);
    }

    /// An `[edge]` section present but with the rate unset still means
    /// "engine default for the topology" — the field is optional, not
    /// required-once-present.
    #[test]
    fn empty_edge_section_falls_back_to_topology_default() {
        assert_eq!(
            resolve_new_conn_rate("frontend-proxy", Some(&edge(None))),
            600
        );
        assert_eq!(resolve_new_conn_rate("acme", Some(&edge(None))), 30);
    }

    /// Fronted topologies derive control-listener pp `On` with loopback
    /// trust (the nginx stream fragment emits the preamble on the control
    /// leg); direct topologies stay off — nothing fronts the listener.
    #[test]
    fn control_proxy_protocol_topology_defaults() {
        for fronted in ["frontend-proxy", "manual"] {
            let cfg = resolve_control_proxy_protocol(fronted);
            assert_eq!(cfg.mode, ProxyProtocolMode::On, "topology {fronted}");
            assert_eq!(cfg.trusted_proxies, vec!["127.0.0.1", "::1"]);
        }
        let direct = resolve_control_proxy_protocol("acme");
        assert_eq!(direct.mode, ProxyProtocolMode::Off);
    }
}
