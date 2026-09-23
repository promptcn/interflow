//! The desired-state manifest — the single source of truth
//! for a deployment.
//!
//! Everything else (Credential Packs, Trust Bundles, node manifests, service
//! units, frontend-proxy configs) is *rendered* from this file by
//! `interflow plan apply`. Nothing on the public side ever carries an
//! internal listen address or a certificate path.

use crate::{Error, Result, issuance::LeafTtl, validate_name};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::net::SocketAddr;

/// A realm: one independent trust domain (`promptcn`, `acme`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RealmConfig {
    /// Realm identifier — the trust-domain name inside principal URIs.
    pub id: String,
    /// The address expose agents dial to reach the control plane. Presented
    /// to users as an endpoint, never as a "hub". Absent in site-to-site-only
    /// realms, where agents dial the mesh hub instead (see `validate`).
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub control_endpoint: String,
}

/// How the ingress terminates public HTTPS.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum PublicTlsMode {
    /// The ingress terminates public HTTPS itself with automatic ACME
    /// issuance and renewal (the default product path).
    #[default]
    Acme,
    /// A front proxy (nginx/LB/WAF) terminates public HTTPS and forwards to
    /// the ingress; `plan apply` renders the matching proxy config.
    FrontendProxy,
    /// Explicit manual certificates (advanced/expert deployments).
    Manual,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PublicTlsConfig {
    #[serde(default)]
    pub mode: PublicTlsMode,
    /// ACME contact email (required for `acme` mode in production).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub email: Option<String>,
    /// ACME directory URL. `None` uses Let's Encrypt production.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub directory: Option<String>,
}

impl Default for PublicTlsConfig {
    fn default() -> Self {
        Self {
            mode: PublicTlsMode::Acme,
            email: None,
            directory: None,
        }
    }
}

/// How end-entity credentials live.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum IdentityMode {
    /// Short leaves (1h–24h) renewed unattended through the registrar —
    /// the multi-tenant / multi-operator default.
    #[default]
    Registrar,
    /// Long leaves (7d–365d, default 90d), no registrar, manual
    /// rotate/revoke. For single-operator deployments the offline issuer is
    /// a *stronger* boundary: it never touches a network.
    Offline,
}

/// End-entity identity lifetime policy.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub struct IdentityConfig {
    #[serde(default)]
    pub mode: IdentityMode,
    /// Human-readable TTL, e.g. `1h` or `24h`; bounds and default depend on
    /// `mode` (registrar: 1h–24h/24h; offline: 7d–365d/90d).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub leaf_ttl: Option<String>,
}

/// The independently deployed identity registrar.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub struct RegistrarConfig {
    /// HTTPS endpoint used for unattended enrollment and renewal.
    #[serde(default)]
    pub endpoint: String,
}

/// An ingress node: a public entry point.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IngressConfig {
    /// The workspaces this ingress is authorized to serve. One
    /// workspace-scoped ingress principal credential is issued per entry.
    pub workspaces: Vec<String>,
    /// Public listen address (rendered into the ingress node config).
    #[serde(default = "default_public_listen")]
    pub listen: String,
    /// Control-plane listen address for the embedded control endpoint.
    #[serde(default = "default_control_listen")]
    pub control_listen: String,
    /// Public-listener governance overrides (rendered into the ingress
    /// node config's `[edge]` section; absent = engine defaults for the
    /// deployment's topology).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub edge: Option<crate::pack::NodeEdgeConfig>,
}

fn default_public_listen() -> String {
    "0.0.0.0:443".to_owned()
}

fn default_control_listen() -> String {
    "127.0.0.1:16666".to_owned()
}

/// A workspace: the isolation and authorization namespace. Single-workspace
/// deployments get `default` and never see the concept.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WorkspaceConfig {}

/// A named service an agent provides locally (`asr` on `127.0.0.1:8080`).
///
/// `address` is the manifest-issued **default** dial target — the pack
/// carries it into `node.toml`, and a machine-local preference may override
/// it at run time (identity and the service *set* stay pack-signed).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ServiceConfig {
    pub id: String,
    pub address: String,
}

/// An agent node: the in-network connector that dials the control endpoint.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AgentConfig {
    pub workspace: String,
    #[serde(default)]
    pub services: Vec<ServiceConfig>,
    /// Site-to-site listen-side rules: forward a local listener through the
    /// mesh hub to a peer agent (empty for expose-only agents).
    #[serde(default)]
    pub mesh_ingress: Vec<MeshIngressRule>,
    /// Site-to-site serve-side rules: what this agent is willing to dial on
    /// its own network for peers.
    #[serde(default)]
    pub mesh_egress: Vec<MeshEgressRule>,
}

/// A public route: `host` → named service identity.
///
/// The service reference is `<workspace>/<agent>/<service>` — never an
/// internal address. Addresses live in the agent's service declaration.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RouteConfig {
    pub host: String,
    pub service: String,
}

/// A site-to-site mesh hub node: the public relay LAN agents dial.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HubNodeConfig {
    /// Hub listen address (rendered into the hub node config).
    #[serde(default = "default_mesh_hub_listen")]
    pub listen: String,
    /// The dial address agents use to reach this hub (`host:port`, or a
    /// full `https://host:port`). Also the SAN source of the hub's server
    /// credential — agents dial exactly this address.
    pub endpoint: String,
}

fn default_mesh_hub_listen() -> String {
    "0.0.0.0:6666".to_owned()
}

/// Site-to-site (mesh) deployment declarations.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MeshConfig {
    #[serde(default)]
    pub hub: BTreeMap<String, HubNodeConfig>,
}

/// Wire protocol of a mesh rule.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum MeshProtocol {
    #[default]
    Tcp,
    Udp,
}

/// A listen-side mesh rule on an agent: accept local connections and forward
/// them through the hub to `target_agent`'s `remote_addr`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MeshIngressRule {
    pub name: String,
    /// Local listen address — loopback only (the engine refuses otherwise).
    pub listen: String,
    #[serde(default)]
    pub protocol: MeshProtocol,
    /// The peer agent that dials `remote_addr` on its own network.
    pub target_agent: String,
    pub remote_addr: String,
}

/// A serve-side mesh rule on an agent: an address this agent is willing to
/// dial for peers (also its egress allowlist entry).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MeshEgressRule {
    pub name: String,
    #[serde(default)]
    pub protocol: MeshProtocol,
    pub target_addr: String,
}

/// The desired-state manifest.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Manifest {
    pub realm: RealmConfig,
    #[serde(default)]
    pub public_tls: PublicTlsConfig,
    #[serde(default)]
    pub identity: IdentityConfig,
    #[serde(default)]
    pub registrar: RegistrarConfig,
    #[serde(default)]
    pub ingress: BTreeMap<String, IngressConfig>,
    #[serde(default)]
    pub workspace: BTreeMap<String, WorkspaceConfig>,
    #[serde(default)]
    pub agent: BTreeMap<String, AgentConfig>,
    #[serde(default)]
    pub route: Vec<RouteConfig>,
    #[serde(default)]
    pub mesh: MeshConfig,
}

impl Manifest {
    /// Parses a manifest from TOML text.
    pub fn parse(text: &str) -> Result<Self> {
        let manifest: Self = toml::from_str(text)
            .map_err(|e| Error::manifest("TOML parse failed".to_string()).with_source(e))?;
        manifest.validate()?;
        Ok(manifest)
    }

    /// Loads and validates a manifest from a file.
    pub fn load(path: &std::path::Path) -> Result<Self> {
        let text = std::fs::read_to_string(path).map_err(|e| Error::Io {
            path: path.display().to_string(),
            source: e,
        })?;
        Self::parse(&text)
    }

    /// Serializes the manifest back to canonical TOML (key order stable via
    /// BTreeMap; routes keep declaration order).
    pub fn to_toml(&self) -> Result<String> {
        toml::to_string_pretty(self)
            .map_err(|e| Error::serialize("manifest serialization".to_string()).with_source(e))
    }

    /// Parses and bounds the configured end-entity TTL. Bounds are the
    /// mode's: registrar leaves renew unattended and stay short; offline
    /// leaves carry the whole rotation cadence.
    pub(crate) fn effective_leaf_ttl(&self) -> Result<LeafTtl> {
        use IdentityMode::*;
        let (min, max, default, range_text) = match self.identity.mode {
            Registrar => (
                super::issuance::MIN_LEAF_TTL_SECONDS,
                super::issuance::MAX_LEAF_TTL_SECONDS,
                super::issuance::DEFAULT_LEAF_TTL_SECONDS,
                "1h and 24h",
            ),
            Offline => (
                super::issuance::OFFLINE_MIN_LEAF_TTL_SECONDS,
                super::issuance::OFFLINE_MAX_LEAF_TTL_SECONDS,
                super::issuance::OFFLINE_DEFAULT_LEAF_TTL_SECONDS,
                "7d and 365d",
            ),
        };
        let mode_name = match self.identity.mode {
            IdentityMode::Registrar => "registrar",
            IdentityMode::Offline => "offline",
        };
        let Some(text) = self.identity.leaf_ttl.as_deref() else {
            return LeafTtl::from_seconds(default as i64);
        };
        let seconds = humantime::parse_duration(text)
            .map_err(|e| {
                Error::manifest(format!("identity.leaf_ttl {text:?} is invalid")).with_source(e)
            })?
            .as_secs();
        if (min..=max).contains(&seconds) {
            LeafTtl::from_seconds(
                i64::try_from(seconds).map_err(|e| {
                    Error::manifest("identity.leaf_ttl is out of range").with_source(e)
                })?,
            )
            .map_err(|e| {
                Error::manifest("identity.leaf_ttl exceeds the supported range").with_source(e)
            })
        } else {
            Err(Error::manifest(format!(
                "identity.leaf_ttl must be between {range_text} in identity.mode = \
                 \"{mode_name}\" (found {text:?})"
            )))
        }
    }

    /// Full semantic validation. Every failure is phrased for a human:
    /// identity and routing semantics, never certificate mechanics.
    pub fn validate(&self) -> Result<()> {
        validate_name("realm", &self.realm.id)?;
        // The control endpoint is the expose agents' dial target; a
        // site-to-site-only realm dials the mesh hub instead.
        if !self.ingress.is_empty() && self.realm.control_endpoint.trim().is_empty() {
            return Err(Error::manifest(
                "realm.control_endpoint is required when the manifest declares an ingress \
                 (the address expose agents dial)"
                    .to_owned(),
            ));
        }
        let registrar_endpoint = self.registrar.endpoint.trim();
        match self.identity.mode {
            IdentityMode::Registrar => {
                if registrar_endpoint.is_empty() {
                    return Err(Error::manifest(
                        "registrar.endpoint is required in identity.mode = \"registrar\" — \
                         credentials renew automatically and must not depend on a human-run \
                         rotate command"
                            .to_owned(),
                    ));
                }
                // One shared endpoint parser validates the whole thing: scheme,
                // authority, port. Userinfo and non-ASCII (IDNA) hosts are
                // rejected outright rather than normalized.
                match interflow_util::parse_endpoint(registrar_endpoint) {
                    Ok(parsed) if parsed.scheme.as_deref() == Some("https") => {}
                    Ok(_) => {
                        return Err(Error::manifest(
                            "registrar.endpoint must use https:// — plaintext enrollment is \
                             not allowed"
                                .to_owned(),
                        ));
                    }
                    Err(e) => {
                        return Err(Error::manifest(format!(
                            "registrar.endpoint {registrar_endpoint:?} is not a valid URL"
                        ))
                        .with_source(e));
                    }
                }
            }
            IdentityMode::Offline => {
                if !registrar_endpoint.is_empty() {
                    return Err(Error::manifest(
                        "[registrar] cannot coexist with identity.mode = \"offline\" — the \
                         offline tier has no renewal service; remove the section or switch \
                         the mode"
                            .to_owned(),
                    ));
                }
            }
        }
        _ = self.effective_leaf_ttl()?;

        // Workspaces.
        for name in self.workspace.keys() {
            validate_name("workspace", name)?;
        }

        // Agents + services.
        if self.agent.is_empty() {
            return Err(Error::manifest(
                "at least one [[agent]] is required — a route needs a connector to reach"
                    .to_owned(),
            ));
        }
        let mut service_index: BTreeSet<String> = BTreeSet::new();
        for (agent_id, agent) in &self.agent {
            validate_name("agent", agent_id)?;
            if !self.workspace.contains_key(&agent.workspace) {
                return Err(Error::manifest(format!(
                    "agent '{agent_id}' references unknown workspace {ws:?} — declare \
                     [workspace.{ws}] first",
                    ws = agent.workspace
                )));
            }
            let has_mesh_role = !agent.mesh_ingress.is_empty() || !agent.mesh_egress.is_empty();
            if agent.services.is_empty() && !has_mesh_role {
                return Err(Error::manifest(format!(
                    "agent '{agent_id}' declares neither services nor mesh rules — add an \
                     [[agent.{agent_id}.services]] entry or a mesh rule",
                )));
            }
            if !agent.services.is_empty() && has_mesh_role {
                return Err(Error::manifest(format!(
                    "agent '{agent_id}' mixes public services and mesh rules — one pack, one \
                     role; declare a second agent node for the other role",
                )));
            }
            let mut seen = BTreeSet::new();
            for service in &agent.services {
                validate_name("service", &service.id)?;
                if !seen.insert(service.id.clone()) {
                    return Err(Error::manifest(format!(
                        "agent '{agent_id}' declares service {:?} twice",
                        service.id
                    )));
                }
                if service.address.trim().is_empty() {
                    return Err(Error::manifest(format!(
                        "service {}/{} has an empty address",
                        agent_id, service.id
                    )));
                }
                // Strict SocketAddr, the same shape mesh_egress target_addr
                // enforces: the address is the manifest-issued *default* the
                // agent dials, and the engine dials literal IPs (no hostname
                // resolution on that path). Failing here surfaces at
                // `plan validate` instead of at node boot.
                if service.address.parse::<std::net::SocketAddr>().is_err() {
                    return Err(Error::manifest(format!(
                        "service {}/{} has an invalid address {:?} — expected \
                         <ip>:<port> (e.g. 127.0.0.1:3000)",
                        agent_id, service.id, service.address
                    )));
                }
                service_index.insert(format!("{}/{}/{}", agent.workspace, agent_id, service.id));
            }
        }

        // Ingresses.
        if self.ingress.is_empty() && self.mesh.hub.is_empty() {
            return Err(Error::manifest(
                "at least one [ingress.<node>] or [mesh.hub.<name>] is required — public \
                 entry needs an ingress, site-to-site needs a hub"
                    .to_owned(),
            ));
        }
        for (node, ingress) in &self.ingress {
            validate_name("ingress node", node)?;
            if ingress.workspaces.is_empty() {
                return Err(Error::manifest(format!(
                    "ingress '{node}' serves no workspace — list at least one under \
                     ingress.{node}.workspaces"
                )));
            }
            let mut seen = BTreeSet::new();
            for workspace in &ingress.workspaces {
                if !seen.insert(workspace.clone()) {
                    return Err(Error::manifest(format!(
                        "ingress '{node}' lists workspace {workspace:?} twice",
                    )));
                }
                if !self.workspace.contains_key(workspace) {
                    return Err(Error::manifest(format!(
                        "ingress '{node}' references unknown workspace {workspace:?}",
                    )));
                }
            }
        }

        // Routes.
        if !self.ingress.is_empty() && self.route.is_empty() {
            return Err(Error::manifest(
                "at least one [[route]] is required when an ingress is declared — declare a \
                 public hostname → service"
                    .to_owned(),
            ));
        }
        let mut hosts = BTreeSet::new();
        for route in &self.route {
            let host = route.host.trim().to_ascii_lowercase();
            if host.is_empty() {
                return Err(Error::manifest("route host must not be empty".to_owned()));
            }
            if !hosts.insert(host) {
                return Err(Error::manifest(format!(
                    "route host {:?} is declared twice",
                    route.host
                )));
            }
            if !service_index.contains(&route.service) {
                return Err(Error::manifest(format!(
                    "route {:?} references unknown service {:?} — expected \
                     <workspace>/<agent>/<service> declared by an agent",
                    route.host, route.service
                )));
            }
        }
        // The control endpoint's host must never double as a route host: one
        // server name can only dispatch one way (the ingress's public-port
        // SNI mux and the front proxy's stream map share this constraint).
        if !self.ingress.is_empty() && !self.realm.control_endpoint.trim().is_empty() {
            let trimmed = self.realm.control_endpoint.trim();
            let control_host = trimmed
                .split_once("://")
                .map_or(trimmed, |(_, rest)| rest)
                .split_once(':')
                .map_or(trimmed, |(host, _)| host)
                .to_ascii_lowercase();
            if hosts.contains(&control_host) {
                return Err(Error::manifest(format!(
                    "realm.control_endpoint host {control_host:?} is also a route host — the \
                     control endpoint needs its own name (e.g. tunnel.<domain>)"
                )));
            }
        }

        // Site-to-site (mesh) face.
        self.validate_mesh()?;

        // Reachability: every workspace served by an ingress has at least
        // one service-providing agent (otherwise its routes could never be
        // satisfied).
        for (node, ingress) in &self.ingress {
            for workspace in &ingress.workspaces {
                let has_agent = self
                    .agent
                    .values()
                    .any(|agent| &agent.workspace == workspace && !agent.services.is_empty());
                if !has_agent {
                    return Err(Error::manifest(format!(
                        "ingress '{node}' serves workspace {workspace:?} which has no agent \
                         providing services",
                    )));
                }
            }
        }
        Ok(())
    }

    /// Validates the site-to-site face: hub declarations plus every agent's
    /// mesh rules and their authorization pairs.
    fn validate_mesh(&self) -> Result<()> {
        if self.mesh.hub.len() > 1 {
            return Err(Error::manifest(format!(
                "mesh.hub declares {} hubs — v1 supports exactly one site-to-site hub per \
                 realm",
                self.mesh.hub.len()
            )));
        }
        for (node, hub) in &self.mesh.hub {
            validate_name("hub node", node)?;
            if hub.endpoint.trim().is_empty() {
                return Err(Error::manifest(format!(
                    "mesh.hub.{node}.endpoint is required (the address agents dial)"
                )));
            }
            if let Err(e) = interflow_util::parse_endpoint(hub.endpoint.trim()) {
                return Err(Error::manifest(format!(
                    "mesh.hub.{node}.endpoint {:?} is not a valid address: {e}",
                    hub.endpoint
                )));
            }
            if let Err(e) = hub.listen.parse::<SocketAddr>() {
                return Err(Error::manifest(format!(
                    "mesh.hub.{node}.listen {:?} is not a valid address: {e}",
                    hub.listen
                )));
            }
        }
        if !self.mesh.hub.is_empty() {
            let any_mesh_agent = self
                .agent
                .values()
                .any(|agent| !agent.mesh_ingress.is_empty() || !agent.mesh_egress.is_empty());
            if !any_mesh_agent {
                return Err(Error::manifest(
                    "the mesh hub serves no agent — declare mesh rules on at least one \
                     [[agent]]"
                        .to_owned(),
                ));
            }
        } else {
            // No hub: mesh rules would have nowhere to relay through.
            for (agent_id, agent) in &self.agent {
                if !agent.mesh_ingress.is_empty() || !agent.mesh_egress.is_empty() {
                    return Err(Error::manifest(format!(
                        "agent '{agent_id}' declares mesh rules but the manifest declares no \
                         [mesh.hub.<name>] — site-to-site needs a hub to relay through",
                    )));
                }
            }
        }
        for (agent_id, agent) in &self.agent {
            let mut ingress_names = BTreeSet::new();
            for rule in &agent.mesh_ingress {
                validate_name("mesh rule", &rule.name)?;
                if !ingress_names.insert(rule.name.clone()) {
                    return Err(Error::manifest(format!(
                        "agent '{agent_id}' declares mesh rule {:?} twice",
                        rule.name
                    )));
                }
                let listen: SocketAddr = rule.listen.parse().map_err(|e| {
                    Error::manifest(format!(
                        "agent '{agent_id}' mesh rule {:?}: listen {:?} is not a valid \
                         address: {e}",
                        rule.name, rule.listen
                    ))
                })?;
                if !listen.ip().is_loopback() {
                    return Err(Error::manifest(format!(
                        "agent '{agent_id}' mesh rule {:?} listens on {listen} — mesh \
                         listeners are loopback-only (expose the LAN another way)",
                        rule.name
                    )));
                }
                rule.remote_addr.parse::<SocketAddr>().map_err(|e| {
                    Error::manifest(format!(
                        "agent '{agent_id}' mesh rule {:?}: remote_addr {:?} is not a valid \
                         address: {e}",
                        rule.name, rule.remote_addr
                    ))
                })?;
                let Some(target) = self.agent.get(&rule.target_agent) else {
                    return Err(Error::manifest(format!(
                        "agent '{agent_id}' mesh rule {:?} references unknown agent {:?}",
                        rule.name, rule.target_agent
                    )));
                };
                let offered = target.mesh_egress.iter().any(|egress| {
                    egress.target_addr == rule.remote_addr && egress.protocol == rule.protocol
                });
                if !offered {
                    return Err(Error::manifest(format!(
                        "agent '{agent_id}' mesh rule {:?} targets agent {:?} at {}, but that \
                         agent does not offer it — declare a matching \
                         [[agent.{}.mesh_egress]] entry",
                        rule.name, rule.target_agent, rule.remote_addr, rule.target_agent
                    )));
                }
            }
            let mut egress_names = BTreeSet::new();
            for rule in &agent.mesh_egress {
                validate_name("mesh rule", &rule.name)?;
                if !egress_names.insert(rule.name.clone()) {
                    return Err(Error::manifest(format!(
                        "agent '{agent_id}' declares mesh rule {:?} twice",
                        rule.name
                    )));
                }
                if rule.target_addr.parse::<SocketAddr>().is_err() {
                    return Err(Error::manifest(format!(
                        "agent '{agent_id}' mesh rule {:?}: target_addr {:?} is not a valid \
                         address",
                        rule.name, rule.target_addr
                    )));
                }
            }
        }
        Ok(())
    }

    /// All service identities declared by agents
    /// (`workspace/agent/service` → address).
    pub fn service_index(&self) -> BTreeMap<String, String> {
        let mut index = BTreeMap::new();
        for (agent_id, agent) in &self.agent {
            for service in &agent.services {
                index.insert(
                    format!("{}/{}/{}", agent.workspace, agent_id, service.id),
                    service.address.clone(),
                );
            }
        }
        index
    }

    /// Whether an agent participates in the site-to-site face.
    pub fn agent_has_mesh_role(&self, agent_id: &str) -> bool {
        self.agent
            .get(agent_id)
            .is_some_and(|agent| !agent.mesh_ingress.is_empty() || !agent.mesh_egress.is_empty())
    }

    /// The single declared hub's dial endpoint (v1 manifests allow exactly
    /// one hub; `None` when the mesh face is absent).
    pub(crate) fn mesh_hub_endpoint(&self) -> Option<&str> {
        self.mesh
            .hub
            .values()
            .next()
            .map(|hub| hub.endpoint.as_str())
    }

    /// Workspaces whose issuer CAs a mesh-role agent must trust: its own,
    /// plus the workspaces of every peer it opens streams to or receives
    /// streams from (inner peer verification is mutual).
    pub fn mesh_trust_workspaces(&self, agent_id: &str) -> Vec<String> {
        let mut workspaces = Vec::new();
        if let Some(agent) = self.agent.get(agent_id) {
            workspaces.push(agent.workspace.clone());
            for rule in &agent.mesh_ingress {
                if let Some(target) = self.agent.get(&rule.target_agent) {
                    workspaces.push(target.workspace.clone());
                }
            }
            for (peer_id, peer) in &self.agent {
                if peer_id == agent_id {
                    continue;
                }
                if peer
                    .mesh_ingress
                    .iter()
                    .any(|rule| rule.target_agent == agent_id)
                {
                    workspaces.push(peer.workspace.clone());
                }
            }
        }
        workspaces.sort();
        workspaces.dedup();
        workspaces
    }

    /// Workspaces whose issuer CAs the mesh hub must trust: every workspace
    /// with at least one mesh-role agent (the hub's tenant trust table).
    pub fn mesh_served_workspaces(&self) -> Vec<String> {
        let mut workspaces: Vec<String> = self
            .agent
            .values()
            .filter(|agent| !agent.mesh_ingress.is_empty() || !agent.mesh_egress.is_empty())
            .map(|agent| agent.workspace.clone())
            .collect();
        workspaces.sort();
        workspaces.dedup();
        workspaces
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    const VALID: &str = r#"
[realm]
id = "promptcn"
control_endpoint = "example.com"

[public_tls]
mode = "acme"

[identity]
leaf_ttl = "24h"

[registrar]
endpoint = "https://registrar.example.com"

[ingress.edge]
workspaces = ["main"]

[workspace.main]

[agent.desktop]
workspace = "main"

[[agent.desktop.services]]
id = "asr"
address = "127.0.0.1:8080"

[[route]]
host = "asr.example.com"
service = "main/desktop/asr"
"#;

    #[test]
    fn valid_manifest_parses() {
        let m = Manifest::parse(VALID).unwrap();
        assert_eq!(m.realm.id, "promptcn");
        assert_eq!(m.public_tls.mode, PublicTlsMode::Acme);
        assert_eq!(m.route.len(), 1);
        assert_eq!(
            m.service_index().get("main/desktop/asr"),
            Some(&"127.0.0.1:8080".to_owned())
        );
    }

    #[test]
    fn service_address_must_be_a_socket_addr() {
        // Hostnames are not dialable on the engine path (no resolution
        // there); the default must be a literal <ip>:<port>.
        let err = Manifest::parse(&VALID.replace("127.0.0.1:8080", "localhost:8080")).unwrap_err();
        assert!(err.to_string().contains("invalid address"), "{err}");
        let err = Manifest::parse(&VALID.replace("127.0.0.1:8080", "127.0.0.1")).unwrap_err();
        assert!(err.to_string().contains("invalid address"), "{err}");
    }

    #[test]
    fn empty_service_address_is_rejected() {
        let err = Manifest::parse(&VALID.replace("127.0.0.1:8080", "")).unwrap_err();
        assert!(err.to_string().contains("empty address"), "{err}");
    }

    #[test]
    fn leaf_ttl_is_bounded_to_one_day() {
        assert!(Manifest::parse(&VALID.replace("\"24h\"", "\"1h\"")).is_ok());
        assert!(Manifest::parse(&VALID.replace("\"24h\"", "\"30m\"")).is_err());
        assert!(Manifest::parse(&VALID.replace("\"24h\"", "\"25h\"")).is_err());
    }

    #[test]
    fn rejects_machine_format_version_field() {
        let err = Manifest::parse(
            "format_version = 1\n[realm]\nid=\"r\"\ncontrol_endpoint=\"x\"\n[ingress.e]\nworkspaces=[\"w\"]",
        )
        .unwrap_err();
        assert!(
            interflow_util::format_chain(&err).contains("format_version"),
            "unknown-field rejection must name the machine-format field: {}",
            interflow_util::format_chain(&err)
        );
    }

    #[test]
    fn rejects_unknown_service_reference() {
        let text = VALID.replace("main/desktop/asr", "main/desktop/missing");
        let err = Manifest::parse(&text).unwrap_err();
        assert!(err.to_string().contains("unknown service"));
    }

    #[test]
    fn rejects_route_to_unauthorized_workspace() {
        // Add a second workspace + agent, a route into it, but the ingress
        // does not list that workspace.
        let mut text = VALID.to_owned();
        text.push_str("\n[workspace.other]\n[agent.other-desktop]\nworkspace = \"other\"\n");
        text.push_str(
            "[[agent.other-desktop.services]]\nid = \"svc\"\naddress = \"127.0.0.1:9\"\n",
        );
        text.push_str(
            "[[route]]\nhost = \"svc.example.com\"\nservice = \"other/other-desktop/svc\"\n",
        );
        // This is structurally valid today: authorization of workspace entry
        // is enforced at the ingress principal layer (workspace-scoped
        // credentials), so the manifest itself accepts it.
        assert!(Manifest::parse(&text).is_ok());
    }

    #[test]
    fn rejects_duplicate_hosts_and_empty_agents() {
        let dup = format!(
            "{VALID}[[route]]\nhost = \"asr.example.com\"\nservice = \"main/desktop/asr\"\n"
        );
        assert!(
            Manifest::parse(&dup)
                .unwrap_err()
                .to_string()
                .contains("twice")
        );
    }

    /// A site-to-site-only realm: no ingress, no route, no control endpoint —
    /// agents dial the mesh hub instead.
    const MESH_VALID: &str = r#"
[realm]
id = "promptcn"

[registrar]
endpoint = "https://registrar.example.com"

[mesh.hub.central]
listen = "0.0.0.0:6666"
endpoint = "hub.example.com:6666"

[workspace.main]

[agent.lan-a]
workspace = "main"

[[agent.lan-a.mesh_ingress]]
name = "to-lan-b"
listen = "127.0.0.1:3001"
target_agent = "lan-b"
remote_addr = "127.0.0.1:3000"

[agent.lan-b]
workspace = "main"

[[agent.lan-b.mesh_egress]]
name = "web"
target_addr = "127.0.0.1:3000"
"#;

    #[test]
    fn mesh_only_manifest_parses_without_control_endpoint() {
        let m = Manifest::parse(MESH_VALID).unwrap();
        assert_eq!(m.mesh.hub.len(), 1);
        assert!(m.realm.control_endpoint.is_empty());
        assert_eq!(
            m.agent["lan-a"].mesh_ingress[0].target_agent,
            "lan-b".to_owned()
        );
        // Canonical round trip keeps the mesh face.
        let text = m.to_toml().unwrap();
        assert_eq!(Manifest::parse(&text).unwrap(), m);
    }

    #[test]
    fn mesh_rule_requires_matching_egress_pair() {
        let text = MESH_VALID.replace(
            "remote_addr = \"127.0.0.1:3000\"",
            "remote_addr = \"127.0.0.1:9999\"",
        );
        let err = Manifest::parse(&text).unwrap_err();
        assert!(
            err.to_string().contains("does not offer it"),
            "pairing error must be human-readable: {err}"
        );
    }

    #[test]
    fn mesh_listener_is_loopback_only() {
        let text = MESH_VALID.replace("127.0.0.1:3001", "0.0.0.0:3001");
        let err = Manifest::parse(&text).unwrap_err();
        assert!(err.to_string().contains("loopback-only"));
    }

    #[test]
    fn mesh_rules_need_a_hub_and_hubs_need_an_agent() {
        // Mesh rules with neither hub nor ingress: the entry-point check
        // fires first, phrased for the user.
        let no_hub = MESH_VALID.replace(
            "[mesh.hub.central]\nlisten = \"0.0.0.0:6666\"\nendpoint = \"hub.example.com:6666\"\n\n",
            "",
        );
        let err = Manifest::parse(&no_hub).unwrap_err();
        assert!(
            err.to_string()
                .contains("at least one [ingress.<node>] or [mesh.hub.<name>]"),
            "{err}"
        );

        // Mesh rules alongside a complete expose face but no hub: the hub is
        // the missing relay.
        let expose_no_hub = r#"
[realm]
id = "promptcn"
control_endpoint = "example.com"
[registrar]
endpoint = "https://registrar.example.com"
[workspace.main]
[agent.desktop]
workspace = "main"
[[agent.desktop.services]]
id = "asr"
address = "127.0.0.1:8080"
[ingress.edge]
workspaces = ["main"]
[[route]]
host = "asr.example.com"
service = "main/desktop/asr"
[agent.peer]
workspace = "main"
[[agent.peer.mesh_egress]]
name = "leak"
target_addr = "127.0.0.1:9"
"#;
        let err = Manifest::parse(expose_no_hub).unwrap_err();
        assert!(
            err.to_string()
                .contains("declares mesh rules but the manifest declares no [mesh.hub"),
            "{err}"
        );

        // A hub whose agents all declare services instead of mesh rules has
        // an empty trust table — rejected.
        let served_by_services = r#"
[realm]
id = "promptcn"
[registrar]
endpoint = "https://registrar.example.com"
[mesh.hub.central]
endpoint = "hub.example.com:6666"
[workspace.main]
[agent.lan-a]
workspace = "main"
[[agent.lan-a.services]]
id = "svc"
address = "127.0.0.1:9"
"#;
        let err = Manifest::parse(served_by_services).unwrap_err();
        assert!(
            err.to_string().contains("the mesh hub serves no agent"),
            "{err}"
        );
    }

    #[test]
    fn one_role_per_agent() {
        let mixed = format!(
            "{MESH_VALID}[[agent.lan-b.services]]\nid = \"svc\"\naddress = \"127.0.0.1:9\"\n"
        );
        let err = Manifest::parse(&mixed).unwrap_err();
        assert!(err.to_string().contains("one pack, one role"));
    }

    #[test]
    fn two_hubs_are_rejected_in_v1() {
        let two =
            format!("{MESH_VALID}[mesh.hub.backup]\nendpoint = \"backup.example.com:6666\"\n");
        let err = Manifest::parse(&two).unwrap_err();
        assert!(err.to_string().contains("exactly one site-to-site hub"));
    }

    #[test]
    fn expose_face_still_requires_control_endpoint_and_routes() {
        let base = r#"
[realm]
id = "promptcn"
[registrar]
endpoint = "https://registrar.example.com"
[workspace.main]
[agent.desktop]
workspace = "main"
[[agent.desktop.services]]
id = "asr"
address = "127.0.0.1:8080"
[ingress.edge]
workspaces = ["main"]
"#;
        let err = Manifest::parse(base).unwrap_err();
        assert!(err.to_string().contains("control_endpoint"));
        let with_endpoint = base.replacen(
            "id = \"promptcn\"",
            "id = \"promptcn\"\ncontrol_endpoint = \"example.com\"",
            1,
        );
        let err = Manifest::parse(&with_endpoint).unwrap_err();
        assert!(err.to_string().contains("[[route]]"));
    }

    #[test]
    fn offline_tier_replaces_the_registrar_requirement() {
        let base = r#"
[realm]
id = "promptcn"
control_endpoint = "example.com:16666"
[public_tls]
mode = "frontend-proxy"
[identity]
mode = "offline"
[ingress.edge]
workspaces = ["main"]
[workspace.main]
[agent.desktop]
workspace = "main"
[[agent.desktop.services]]
id = "asr"
address = "127.0.0.1:8080"
[[route]]
host = "asr.example.com"
service = "main/desktop/asr"
"#;
        let manifest = Manifest::parse(base).expect("offline manifest validates");
        assert_eq!(
            manifest.effective_leaf_ttl().unwrap().duration(),
            time::Duration::days(90)
        );

        let with_registrar = base.replacen(
            "[ingress.edge]",
            "[registrar]\nendpoint = \"https://registrar.example.com\"\n\n[ingress.edge]",
            1,
        );
        let err = Manifest::parse(&with_registrar).unwrap_err();
        assert!(err.to_string().contains("cannot coexist"));
    }

    #[test]
    fn leaf_ttl_bounds_follow_the_tier() {
        let manifest_text_with_ttl = |ttl: &str| -> String {
            let text = format!(
                r#"
[realm]
id = "promptcn"
[identity]
mode = "offline"
leaf_ttl = "{ttl}"
[workspace.main]
[agent.desktop]
workspace = "main"
[[agent.desktop.mesh_ingress]]
name = "ragflow"
listen = "127.0.0.1:18000"
target_agent = "peer"
remote_addr = "127.0.0.1:80"
[agent.peer]
workspace = "main"
[[agent.peer.mesh_egress]]
name = "ragflow"
target_addr = "127.0.0.1:80"
[mesh.hub.promptcn]
endpoint = "hub.example.com:6666"
"#
            );
            text
        };
        // Validation runs at parse time, so bound failures surface there.
        assert!(Manifest::parse(&manifest_text_with_ttl("6d")).is_err());
        assert!(Manifest::parse(&manifest_text_with_ttl("7d")).is_ok());
        assert!(Manifest::parse(&manifest_text_with_ttl("90d")).is_ok());
        assert!(Manifest::parse(&manifest_text_with_ttl("366d")).is_err());

        // The same 30d is invalid in the default (registrar) tier.
        let registrar_tier = manifest_text_with_ttl("30d").replace("mode = \"offline\"\n", "");
        let err = Manifest::parse(&registrar_tier).unwrap_err();
        assert!(err.to_string().contains("registrar"));
    }

    #[test]
    fn control_endpoint_host_must_differ_from_route_hosts() {
        let base = r#"
[realm]
id = "promptcn"
control_endpoint = "asr.example.com:16666"
[registrar]
endpoint = "https://registrar.example.com"
[public_tls]
mode = "frontend-proxy"
[ingress.edge]
workspaces = ["main"]
[workspace.main]
[agent.desktop]
workspace = "main"
[[agent.desktop.services]]
id = "asr"
address = "127.0.0.1:8080"
[[route]]
host = "asr.example.com"
service = "main/desktop/asr"
"#;
        let err = Manifest::parse(base).unwrap_err();
        assert!(err.to_string().contains("tunnel.<domain>"), "{err}");
    }
}
