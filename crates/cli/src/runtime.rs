//! `interflow-cli ingress run --pack` / `interflow-cli agent run --pack` —
//! Credential-Pack → runtime-engine bootstrap.
//!
//! The user-facing model never sees certificate paths: the pack supplies the
//! identity, trust, and signed policy; this module maps it onto the relay
//! engine **in memory** — no intermediate config files are rendered,
//! so the bytes the issuer signed are the bytes the engine runs.
//!
//! The pack's node.toml is canonical (2026-10-10): every knob arrives
//! concrete, resolved at render time. The resolvers below only parse those
//! concrete values into engine types — the topology-default resolution that
//! used to live here moved into the renderer.

use interflow_core::error::{InterflowError, Result};
use interflow_core::security::{ProxyProtocolConfig, ProxyProtocolMode, XffMode};
use interflow_expose::edge::{
    AcmeOptions, ControlEndpointTls, EdgeConfig, EdgeListenerPolicy, IngressPrincipal, PublicTls,
    Route, WorkspaceTrust,
};
use interflow_identity::credentials::ActiveCredentialSet;
use interflow_identity::manifest::IdentityMode;
use interflow_identity::pack::{CredentialPack, NodeEdgeConfig, PackKind};
use std::net::SocketAddr;
use std::path::Path;

/// Parses the public listener's `X-Forwarded-For` mode from the pack's
/// canonical `[edge]` section.
///
/// `"off"` / `"on"` / `"required"` — the renderer already resolved the
/// topology default; an unrecognized value is a version-skew tripwire, not
/// a user-facing path: node.toml rides the pack's SHA256SUMS digest.
pub fn resolve_xff_mode(edge: &NodeEdgeConfig) -> Result<XffMode> {
    match edge.x_forwarded_for.as_str() {
        "off" => Ok(XffMode::Off),
        "on" => Ok(XffMode::On),
        "required" => Ok(XffMode::Required),
        other => Err(InterflowError::config(format!(
            "[edge] x_forwarded_for = {other:?} is not one of \"off\" | \"on\" | \"required\""
        ))),
    }
}

/// Parses the control listener's PROXY protocol negotiation from the pack's
/// canonical `[edge]` section (`"on"` / `"off"`).
///
/// Mode `On` (not `Required`):
/// the edge's internal workspace agents self-dial the control endpoint
/// headerless over loopback, and `On` is also what makes the zero-downtime
/// rollout order (new binaries first, nginx conf switch second) work — a
/// headerless leg is a plain direct connection. Trusted proxies stay
/// engine-fixed (loopback) — the front runs beside the edge.
pub fn resolve_control_proxy_protocol(edge: &NodeEdgeConfig) -> Result<ProxyProtocolConfig> {
    match edge.control_proxy_protocol.as_str() {
        "on" => Ok(ProxyProtocolConfig {
            mode: ProxyProtocolMode::On,
            trusted_proxies: vec!["127.0.0.1".to_owned(), "::1".to_owned()],
        }),
        "off" => Ok(ProxyProtocolConfig::default()),
        other => Err(InterflowError::config(format!(
            "[edge] control_proxy_protocol = {other:?} is not one of \"on\" | \"off\""
        ))),
    }
}

/// Parses the ACME HTTP-01 challenge listener from the pack's canonical
/// `[edge]` section.
///
/// The renderer pinned the port-80 default the ACME protocol practically
/// requires; an explicit value moves the challenge listener behind a
/// forward or onto another interface.
pub fn resolve_acme_http_listen(edge: &NodeEdgeConfig) -> Result<SocketAddr> {
    edge.acme_http_listen.parse().map_err(|e| {
        InterflowError::config(format!(
            "acme http_listen address {:?} is invalid",
            edge.acme_http_listen
        ))
        .with_source(e)
    })
}

/// Resolves the control endpoint's QUIC (UDP) listen address for an
/// ingress pack: `None` keeps the QUIC transport off, a concrete address
/// opens the QUIC face beside the control TCP listener.
///
/// The manifest already validation-checked the value (public, concrete
/// port — `Manifest::validate`); node.toml rides the pack's SHA256SUMS
/// digest, so it cannot drift from what was validated. This resolver
/// only does the String→SocketAddr parse, failing before any listener
/// bind exactly like the `listen`/`control_listen` parses beside it.
/// The `Some(:0)` derived-ephemeral state stays testkit-only: a manifest
/// cannot express it (`validate` rejects port 0), so it never reaches
/// this leg through a pack.
pub fn resolve_quic_listen(raw: Option<&str>) -> Result<Option<SocketAddr>> {
    match raw {
        None => Ok(None),
        Some(raw) => raw.parse().map(Some).map_err(|e| {
            InterflowError::config(format!(
                "control endpoint QUIC listen address {raw:?} is invalid"
            ))
            .with_source(e)
        }),
    }
}

/// Resolves the dial transport an agent runs with: the machine-local
/// preference wins, the pack's render-time-resolved default is the fallback
/// (`"h2"` / `"quic"`, never absent — canonical node.toml).
///
/// Single resolution point for every caller — the headless
/// `agent run --pack` path (no profile: local is `None`, the pack default
/// *is* the config) and the GUI (profile preference over the pack
/// default), mirroring how service dial targets resolve (pack default +
/// machine-local override). An unexpected pack string fails loud instead of
/// silently degrading to h2 — node.toml is digest-covered, so this is
/// a version-skew tripwire, not a user-facing path. The string semantics
/// live on [`TransportKind::parse_dial`] (shared with the mesh pack
/// path).
pub fn resolve_effective_transport(
    local: Option<interflow_mesh::config::TransportKind>,
    pack_default: &str,
) -> Result<interflow_mesh::config::TransportKind> {
    if let Some(local) = local {
        return Ok(local);
    }
    interflow_mesh::config::TransportKind::parse_dial(Some(pack_default))
        .map_err(InterflowError::config)
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
        // Headless run: no profile, so no machine-local preferences — the
        // pack's manifest-issued defaults are the whole config (every
        // service dials its pack default; the dial transport is the pack's
        // render-time-resolved `transport`).
        resolve_effective_transport(None, pack.node_config.transport.as_str())?,
        None,
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

    // The renderer always writes both listen addresses on an ingress pack;
    // missing values are pre-2026-10 packs — fail loudly with the recovery
    // action instead of silently binding default addresses.
    let listen: SocketAddr = pack
        .node_config
        .listen
        .as_deref()
        .ok_or_else(|| {
            InterflowError::config(
                "ingress pack node.toml carries no listen address — re-render the pack \
                 (interflow-cli plan apply); the silent 0.0.0.0:8443 fallback is retired",
            )
        })?
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
        .ok_or_else(|| {
            InterflowError::config(
                "ingress pack node.toml carries no control_listen address — re-render the \
                 pack (interflow-cli plan apply); the silent 127.0.0.1:16666 fallback is \
                 retired",
            )
        })?
        .parse()
        .map_err(|e| {
            InterflowError::config(format!(
                "control endpoint listen address {:?} is invalid",
                pack.node_config.control_listen
            ))
            .with_source(e)
        })?;
    let quic_listen = resolve_quic_listen(pack.node_config.quic_listen.as_deref())?;

    // Public-HTTPS termination: `acme` terminates TLS on the ingress itself
    // (HTTP-01 + TLS-ALPN-01 + renewal, state under the pack directory);
    // the fronted topologies keep the plain-TCP listener behind the proxy.
    // The [edge] section is canonical and always present on an ingress pack
    // (the load path enforces it; the guard here is the same fail-loud for
    // hand-loaded packs).
    let edge = pack.node_config.edge.as_ref().ok_or_else(|| {
        InterflowError::config(
            "ingress pack node.toml carries no [edge] section — re-render the pack \
             (interflow-cli plan apply); boot-time topology defaults are retired",
        )
    })?;
    let public_tls = if pack.node_config.public_tls == "acme" {
        let email = pack.node_config.public_tls_email.clone().ok_or_else(|| {
            InterflowError::config(
                "acme mode requires a contact email ([public_tls] email in the manifest)",
            )
        })?;
        PublicTls::Acme(AcmeOptions {
            hosts: Vec::new(), // filled from the resolved routes by the engine
            email,
            // Canonical node.toml always names the concrete directory (the
            // renderer resolved an unset manifest to LE production); ""
            // can only mean "no public-TLS face", impossible on this leg.
            directory: Some(pack.node_config.public_tls_directory.clone()),
            directory_ca: None,
            cache_dir: pack_dir.join("state").join("acme"),
            http_listen: resolve_acme_http_listen(edge)?,
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
        control_proxy_protocol: resolve_control_proxy_protocol(edge)?,
        workspace_trust,
        principals,
        routes,
        quic_listen,
        audit_path: Some(pack_dir.join("audit.jsonl")),
        listener: EdgeListenerPolicy {
            x_forwarded_for: resolve_xff_mode(edge)?,
            // Canonical node.toml carries the render-time-resolved rate
            // (fronted 600 / direct 30)
            new_conn_rate_per_ip_per_minute: edge.new_conn_rate_per_ip_per_minute,
            ..EdgeListenerPolicy::default()
        },
        public_tls,
        control_dispatch_host: pack.node_config.control_dispatch_host.clone(),
        identity_offline: pack.metadata.identity_mode == IdentityMode::Offline,
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
        identity_offline: pack.metadata.identity_mode == IdentityMode::Offline,
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
        NodeEdgeConfig, resolve_acme_http_listen, resolve_control_proxy_protocol,
        resolve_effective_transport, resolve_local_services, resolve_quic_listen, resolve_xff_mode,
    };
    use interflow_core::security::{ProxyProtocolMode, XffMode};
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

    /// A canonical [edge] section: the render-time-resolved values the
    /// resolvers parse. Topology-default resolution moved into the renderer
    /// (identity's resolve_edge) — these tests cover the parse-only leg.
    fn edge_with(rate: u32, xff: &str, proxy: &str, acme_http_listen: &str) -> NodeEdgeConfig {
        NodeEdgeConfig {
            new_conn_rate_per_ip_per_minute: rate,
            x_forwarded_for: xff.to_owned(),
            control_proxy_protocol: proxy.to_owned(),
            acme_http_listen: acme_http_listen.to_owned(),
        }
    }

    /// PROXY protocol parses from the canonical value; a bad value fails
    /// naming the field (node.toml is digest-covered — a version-skew
    /// tripwire, not a user-facing path).
    #[test]
    fn control_proxy_protocol_parses_or_fails_loud() {
        let on = resolve_control_proxy_protocol(&edge_with(600, "required", "on", "0.0.0.0:80"))
            .unwrap();
        assert_eq!(on.mode, ProxyProtocolMode::On);
        assert_eq!(on.trusted_proxies, vec!["127.0.0.1", "::1"]);
        let off =
            resolve_control_proxy_protocol(&edge_with(30, "off", "off", "0.0.0.0:80")).unwrap();
        assert_eq!(off.mode, ProxyProtocolMode::Off);
        let err = resolve_control_proxy_protocol(&edge_with(30, "off", "maybe", "0.0.0.0:80"))
            .unwrap_err();
        assert!(
            err.to_string().contains("control_proxy_protocol"),
            "wrong error: {err}"
        );
    }

    /// XFF mode parses from the canonical value; a bad value fails naming
    /// the field.
    #[test]
    fn xff_mode_parses_or_fails_loud() {
        assert_eq!(
            resolve_xff_mode(&edge_with(600, "required", "on", "0.0.0.0:80")).unwrap(),
            XffMode::Required
        );
        assert_eq!(
            resolve_xff_mode(&edge_with(30, "off", "off", "0.0.0.0:80")).unwrap(),
            XffMode::Off
        );
        assert_eq!(
            resolve_xff_mode(&edge_with(30, "on", "off", "0.0.0.0:80")).unwrap(),
            XffMode::On
        );
        let err = resolve_xff_mode(&edge_with(30, "sometimes", "off", "0.0.0.0:80")).unwrap_err();
        assert!(
            err.to_string().contains("x_forwarded_for"),
            "wrong error: {err}"
        );
    }

    /// The ACME HTTP-01 listener parses from the canonical value (the
    /// renderer pinned the port-80 default); garbage fails before any bind.
    #[test]
    fn acme_http_listen_parses_or_fails_loud() {
        assert_eq!(
            resolve_acme_http_listen(&edge_with(30, "off", "off", "0.0.0.0:80")).unwrap(),
            "0.0.0.0:80".parse().unwrap()
        );
        assert_eq!(
            resolve_acme_http_listen(&edge_with(30, "off", "off", "127.0.0.1:8080")).unwrap(),
            "127.0.0.1:8080".parse().unwrap()
        );
        let err =
            resolve_acme_http_listen(&edge_with(30, "off", "off", "not-an-addr")).unwrap_err();
        assert!(
            err.to_string().contains("acme http_listen"),
            "wrong error: {err}"
        );
    }

    /// `None` keeps the QUIC face off (the h2-only status quo); a concrete
    /// address parses; garbage fails naming the field before any bind —
    /// the same fail-fast the `listen`/`control_listen` parses give.
    #[test]
    fn quic_listen_resolves_none_concrete_or_fails() {
        assert_eq!(super::resolve_quic_listen(None).unwrap(), None);
        assert_eq!(
            resolve_quic_listen(Some("0.0.0.0:16666")).unwrap(),
            Some("0.0.0.0:16666".parse().unwrap())
        );
        let err = resolve_quic_listen(Some("udp://16666")).unwrap_err();
        assert!(
            err.to_string().contains("QUIC listen address"),
            "wrong error: {err}"
        );
    }

    /// Transport resolution: a machine-local preference beats the pack's
    /// render-time-resolved default, no preference inherits it, h2 is the
    /// floor (an ingress/hub pack's "" no-dial value parses as h2 too), and
    /// an unexpected pack string fails loud (digest-covered node.toml — a
    /// version-skew tripwire, not a user-facing path).
    #[test]
    fn effective_transport_pref_over_pack_default_over_h2() {
        use interflow_mesh::config::TransportKind;

        assert_eq!(
            resolve_effective_transport(Some(TransportKind::H2), "quic").unwrap(),
            TransportKind::H2,
            "a machine-local preference beats the pack default"
        );
        assert_eq!(
            resolve_effective_transport(None, "quic").unwrap(),
            TransportKind::Quic,
            "no preference inherits the pack's resolved default"
        );
        assert_eq!(
            resolve_effective_transport(None, "h2").unwrap(),
            TransportKind::default()
        );
        assert_eq!(
            resolve_effective_transport(None, "").unwrap(),
            TransportKind::default(),
            "the no-dial-face empty value parses as the h2 floor"
        );
        let err = resolve_effective_transport(None, "quic3").unwrap_err();
        assert!(
            err.to_string().contains("not recognized"),
            "version-skew tripwire fails loud: {err}"
        );
    }
}
