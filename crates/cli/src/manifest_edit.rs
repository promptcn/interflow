//! Structured, format-preserving manifest editing — the document model the
//! GUI's Form view, the issue wizard's `node add`, and any future CLI edit
//! surface share.
//!
//! Every operation here is a **pure text transform**: `text → text`. toml_edit
//! carries every comment and the operator's layout across the edit, and
//! purity is the rollback — a rejected edit never returns half-applied text.
//! Nothing in this module touches the filesystem; persistence is the
//! [`save_manifest`] shell (one-generation `.bak` + atomic write) — the
//! write discipline `node add` has always had, now shared by the GUI
//! editor's Save.
//!
//! Validation is the **valid→valid invariant**: when the input document is
//! already valid, the edit must keep it valid — the full
//! `Manifest::parse → validate` funnel runs and a rejection lands at the
//! moment of the bad change, not at Apply time. When the input is an
//! under-construction document (a fresh mesh skeleton is deliberately
//! invalid until its first agent; a hub waits for the agents it will serve),
//! only the shape funnel runs: construction must be able to pass *through*
//! intermediate states, with the semantic problems surfacing as live
//! `issues` in the read model — Apply re-runs the full funnel regardless.
//! [`add_node_in_text`] keeps its unconditional full funnel: one append
//! carries its own validity (the skeleton crosses the line in one step).
//!
//! The read model is [`ManifestSummary`]: a shape-level parse (no
//! `validate`) with validation diagnostics attached, plus the derived facts
//! the form should never re-derive client-side (identity-tier TTL bounds,
//! agent roles).

use interflow_core::error::{InterflowError, Result};
use interflow_identity::issuance::{
    DEFAULT_LEAF_TTL_SECONDS, MAX_LEAF_TTL_SECONDS, MIN_LEAF_TTL_SECONDS,
    OFFLINE_DEFAULT_LEAF_TTL_SECONDS, OFFLINE_MAX_LEAF_TTL_SECONDS, OFFLINE_MIN_LEAF_TTL_SECONDS,
};
use interflow_identity::manifest::{
    AgentConfig, IdentityMode, Manifest, MeshProtocol, PublicTlsMode,
};
use std::collections::BTreeMap;
use std::path::Path;
use toml_edit::{ArrayOfTables, Item, Table, Value};

// ---------------------------------------------------------------------------
// Read model — what the GUI form renders
// ---------------------------------------------------------------------------

/// One whole manifest as the form sees it.
///
/// The parsed shape (every schema field, by construction — the manifest
/// type is the single source), the identity tier's TTL bounds, per-agent
/// roles, and the validation diagnostics (`issues` empty ⇔ applyable).
#[derive(Debug, Clone)]
pub struct ManifestSummary {
    pub manifest: Manifest,
    pub leaf_ttl: LeafTtlBounds,
    pub agent_roles: BTreeMap<String, AgentRole>,
    /// Full `validate()` diagnostics, human-readable (the same phrasing
    /// `plan validate` prints). Empty when the document is valid.
    pub issues: Vec<String>,
}

/// The identity tier's `leaf_ttl` bounds and default as display text.
///
/// `1h`–`24h`, default `24h` / `7d`–`365d`, default `90d` — computed from
/// the issuance constants, so the form's hint and the validator's裁决 can
/// never disagree.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LeafTtlBounds {
    pub min: String,
    pub max: String,
    pub default: String,
}

impl LeafTtlBounds {
    fn for_mode(mode: IdentityMode) -> Self {
        let (min, max, default) = match mode {
            IdentityMode::Registrar => (
                MIN_LEAF_TTL_SECONDS,
                MAX_LEAF_TTL_SECONDS,
                DEFAULT_LEAF_TTL_SECONDS,
            ),
            IdentityMode::Offline => (
                OFFLINE_MIN_LEAF_TTL_SECONDS,
                OFFLINE_MAX_LEAF_TTL_SECONDS,
                OFFLINE_DEFAULT_LEAF_TTL_SECONDS,
            ),
        };
        Self {
            min: secs_text(min),
            max: secs_text(max),
            default: secs_text(default),
        }
    }
}

/// Seconds as the compact human form the docs use — hours under two days
/// (`1h`, `24h`, matching the registrar tier's phrasing), days from a week
/// up (`7d`, `90d`, `365d`, the offline tier's).
fn secs_text(secs: u64) -> String {
    const HOUR: u64 = 3_600;
    const DAY: u64 = 24 * HOUR;
    if secs.is_multiple_of(DAY) && secs >= 7 * DAY {
        format!("{}d", secs / DAY)
    } else if secs.is_multiple_of(HOUR) {
        format!("{}h", secs / HOUR)
    } else {
        format!("{secs}s")
    }
}

/// Which pack role an agent plays.
///
/// Presentation of the one-pack-one-role split (`services` vs mesh
/// rules), derived once here so the form never re-derives it.
/// `Mixed`/`Empty` occur only in documents the funnel (or the
/// valid→valid invariant) will reject.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AgentRole {
    Expose,
    Mesh,
    Mixed,
    Empty,
}

impl AgentRole {
    const fn of(agent: &AgentConfig) -> Self {
        match (
            agent.services.is_empty(),
            agent.mesh_ingress.is_empty() && agent.mesh_egress.is_empty(),
        ) {
            (false, false) => Self::Mixed,
            (false, true) => Self::Expose,
            (true, false) => Self::Mesh,
            (true, true) => Self::Empty,
        }
    }
}

/// Shape-parses a manifest into the form's read model — shape-level only.
///
/// Semantic problems (a realm without agents, an unpaired mesh rule…)
/// land in `issues` instead of failing — the form renders them beside the
/// fields, and Apply re-runs the full funnel anyway. A syntax or type
/// error (or an unknown field) is a hard `Err`: there is no document to
/// render, only text to fix.
pub fn summarize(text: &str) -> Result<ManifestSummary> {
    let manifest: Manifest = toml::from_str(text)
        .map_err(|e| InterflowError::config("manifest parse".to_string()).with_source(e))?;
    let leaf_ttl = LeafTtlBounds::for_mode(manifest.identity.mode);
    let agent_roles = manifest
        .agent
        .iter()
        .map(|(node, cfg)| (node.clone(), AgentRole::of(cfg)))
        .collect();
    let issues = match manifest.validate() {
        Ok(()) => Vec::new(),
        Err(e) => vec![error_chain(&e)],
    };
    Ok(ManifestSummary {
        manifest,
        leaf_ttl,
        agent_roles,
        issues,
    })
}

/// An error plus its full source chain, `": "`-joined — the manifest
/// validator puts the decisive facts (positions, rule names) in the chain.
pub fn error_chain(error: &dyn std::error::Error) -> String {
    let mut text = error.to_string();
    let mut source = error.source();
    while let Some(next) = source {
        text.push_str(": ");
        text.push_str(&next.to_string());
        source = next.source();
    }
    text
}

// ---------------------------------------------------------------------------
// Edits — pure text transforms
// ---------------------------------------------------------------------------

/// One structured edit — the GUI Form view's whole vocabulary.
///
/// Each variant carries the **complete desired state** of its target
/// (section fields, rule fields), so an edit never depends on what the
/// document looked like before the form rendered it — the form resubmits
/// what it shows.
#[derive(Debug, Clone)]
pub enum ManifestEdit {
    /// `[realm]`: empty/blank `control_endpoint` = absent
    /// (site-to-site-only realm).
    SetRealm(RealmEdit),
    /// `[public_tls]`: `email`/`directory` absent when `None`/blank.
    SetPublicTls(PublicTlsEdit),
    /// The identity tier is **one decision**: `[identity].mode` and
    /// `[registrar]` cross-validate (registrar mode demands the endpoint,
    /// offline mode forbids the section), so they can only be written
    /// atomically. `leaf_ttl` absent when `None`/blank (tier default).
    SetIdentity(IdentityEdit),
    UpsertWorkspace(String),
    RemoveWorkspace(String),
    /// `[mesh.hub.<name>]` upsert: `listen` absent when `None`/blank
    /// (default `0.0.0.0:6666`). Renaming a hub is remove + add — the name
    /// is the pack's identity, not a display label.
    UpsertHub(HubEdit),
    RemoveHub(String),
    /// `[ingress.<node>]` upsert: `None`/blank = engine default,
    /// `edge_rate` `None` = no `[edge]` section.
    UpsertIngress(IngressEdit),
    RemoveIngress(String),
    /// Whole-node creation with role content — the same append `node add`
    /// and the issue wizard perform (one pack, one role enforced inside).
    /// Bare agents cannot exist (the funnel demands a role), so creation
    /// always carries its services or mesh rules in the same breath.
    AddNode(AddNodeSpec),
    /// Retargets an existing agent's workspace.
    SetAgentWorkspace {
        agent: String,
        workspace: String,
    },
    RemoveAgent(String),
    /// One `[[agent.<agent>.services]]` entry, keyed by `id`.
    UpsertService(ServiceEdit),
    RemoveService {
        agent: String,
        id: String,
    },
    /// One `[[agent.<agent>.mesh_ingress]]` rule, keyed by `name` — unique
    /// per agent per kind, the validator enforces it and the editor relies
    /// on it as the stable address of a rule.
    UpsertMeshIngress(MeshIngressEdit),
    RemoveMeshIngress {
        agent: String,
        name: String,
    },
    /// One `[[agent.<agent>.mesh_egress]]` rule, keyed by `name`; exactly
    /// one of `target_addr` / `target_cidr` non-blank.
    UpsertMeshEgress(MeshEgressEdit),
    RemoveMeshEgress {
        agent: String,
        name: String,
    },
    /// One `[[route]]`, keyed by `host`.
    UpsertRoute(RouteEdit),
    RemoveRoute {
        host: String,
    },
}

#[derive(Debug, Clone)]
pub struct RealmEdit {
    pub id: String,
    pub control_endpoint: String,
}

#[derive(Debug, Clone)]
pub struct PublicTlsEdit {
    pub mode: PublicTlsMode,
    pub email: Option<String>,
    pub directory: Option<String>,
}

#[derive(Debug, Clone)]
pub struct IdentityEdit {
    pub mode: IdentityMode,
    pub leaf_ttl: Option<String>,
    /// Required (https) in registrar mode; must be `None`/blank in offline
    /// mode — the arm removes the `[registrar]` section when blank.
    pub registrar_endpoint: Option<String>,
}

#[derive(Debug, Clone)]
pub struct HubEdit {
    pub name: String,
    pub endpoint: String,
    pub listen: Option<String>,
}

#[derive(Debug, Clone)]
pub struct IngressEdit {
    pub node: String,
    pub workspaces: Vec<String>,
    pub listen: Option<String>,
    pub control_listen: Option<String>,
    pub edge_rate_per_ip_per_minute: Option<u32>,
}

#[derive(Debug, Clone)]
pub struct ServiceEdit {
    pub agent: String,
    pub id: String,
    pub address: String,
}

#[derive(Debug, Clone)]
pub struct MeshIngressEdit {
    pub agent: String,
    pub name: String,
    pub listen: String,
    pub protocol: MeshProtocol,
    pub target_agent: String,
    pub remote_addr: String,
    pub idle_timeout_secs: Option<u64>,
}

#[derive(Debug, Clone)]
pub struct MeshEgressEdit {
    pub agent: String,
    pub name: String,
    pub protocol: MeshProtocol,
    pub target_addr: Option<String>,
    pub target_cidr: Option<String>,
    pub udp_idle_timeout_secs: Option<u64>,
}

#[derive(Debug, Clone)]
pub struct RouteEdit {
    pub host: String,
    pub service: String,
}

/// Applies one edit to the manifest text and returns the rewritten text.
///
/// The valid→valid invariant is the contract: a valid input either stays
/// valid or the edit fails; an under-construction input only needs to stay
/// shape-parseable (its issues surface in the read model, Apply re-checks
/// everything). The function never writes, so failure leaves nothing
/// behind.
pub fn apply_edit(text: &str, edit: &ManifestEdit) -> Result<String> {
    // `AddNode` is its own well-tested transform with an unconditional full
    // funnel — delegate rather than re-express it.
    if let ManifestEdit::AddNode(spec) = edit {
        return add_node_in_text(text, spec);
    }
    // Shape-level parse of the current state: edits address real things
    // (agents, workspaces) and "unknown agent" should be phrased by the
    // schema, not by tomlEdit key lookups. A fresh mesh skeleton passes
    // (shape ≠ valid); only malformed text cannot be edited at all.
    let current: Manifest = toml::from_str(text)
        .map_err(|e| InterflowError::config("manifest parse".to_string()).with_source(e))?;
    let input_was_valid = current.validate().is_ok();
    let mut doc: toml_edit::DocumentMut = text
        .parse()
        .map_err(|e| InterflowError::config("manifest TOML syntax".to_string()).with_source(e))?;
    let root = doc.as_table_mut();
    match edit {
        ManifestEdit::AddNode { .. } => unreachable!("delegated above"),
        ManifestEdit::SetRealm(edit) => {
            let realm = section_table(root, "realm")?;
            set_str(realm, "id", Some(edit.id.trim()));
            set_str(
                realm,
                "control_endpoint",
                non_blank_str(&edit.control_endpoint),
            );
        }
        ManifestEdit::SetPublicTls(edit) => {
            let carries_something = edit.mode != PublicTlsMode::Acme
                || non_blank(edit.email.as_deref()).is_some()
                || non_blank(edit.directory.as_deref()).is_some();
            if root.contains_key("public_tls") || carries_something {
                let tls = section_table(root, "public_tls")?;
                set_enum(tls, "mode", tls_mode_text(edit.mode), "acme");
                set_str(tls, "email", non_blank(edit.email.as_deref()));
                set_str(tls, "directory", non_blank(edit.directory.as_deref()));
            }
        }
        ManifestEdit::SetIdentity(edit) => {
            let carries_something = edit.mode != IdentityMode::Registrar
                || non_blank(edit.leaf_ttl.as_deref()).is_some()
                || non_blank(edit.registrar_endpoint.as_deref()).is_some();
            if root.contains_key("identity") || carries_something {
                let identity = section_table(root, "identity")?;
                set_enum(identity, "mode", identity_mode_text(edit.mode), "registrar");
                set_str(identity, "leaf_ttl", non_blank(edit.leaf_ttl.as_deref()));
            }
            match non_blank(edit.registrar_endpoint.as_deref()) {
                Some(endpoint) => {
                    let registrar = section_table(root, "registrar")?;
                    set_str(registrar, "endpoint", Some(endpoint));
                }
                None => {
                    root.remove("registrar");
                }
            }
        }
        ManifestEdit::UpsertWorkspace(name) => {
            declare_workspace(root, &current, name.trim())?;
        }
        ManifestEdit::RemoveWorkspace(name) => {
            let workspaces = parent_table(root, "workspace")?;
            if workspaces.remove(name).is_none() {
                return Err(unknown("workspace", name));
            }
        }
        ManifestEdit::UpsertHub(edit) => {
            let mesh = parent_table(root, "mesh")?;
            let hubs = parent_table(mesh, "hub")?;
            let name = edit.name.trim();
            if !hubs.contains_key(name) {
                hubs.insert(name, Item::Table(Table::new()));
            }
            let hub = hubs
                .get_mut(name)
                .and_then(Item::as_table_mut)
                .ok_or_else(|| unknown("hub", name))?;
            set_str(hub, "endpoint", Some(edit.endpoint.trim()));
            set_str(hub, "listen", non_blank(edit.listen.as_deref()));
        }
        ManifestEdit::RemoveHub(name) => {
            let mesh = parent_table(root, "mesh")?;
            let hubs = parent_table(mesh, "hub")?;
            if hubs.remove(name).is_none() {
                return Err(unknown("hub", name));
            }
        }
        ManifestEdit::UpsertIngress(edit) => {
            let node = edit.node.trim();
            let workspaces: Vec<String> = edit
                .workspaces
                .iter()
                .map(|ws| ws.trim().to_owned())
                .filter(|ws| !ws.is_empty())
                .collect();
            if workspaces.is_empty() {
                return Err(InterflowError::config(format!(
                    "ingress '{node}' serves no workspace — list at least one"
                )));
            }
            for workspace in &workspaces {
                declare_workspace(root, &current, workspace)?;
            }
            let ingresses = parent_table(root, "ingress")?;
            if !ingresses.contains_key(node) {
                ingresses.insert(node, Item::Table(Table::new()));
            }
            let ingress = ingresses
                .get_mut(node)
                .and_then(Item::as_table_mut)
                .ok_or_else(|| unknown("ingress", node))?;
            set_str_array(ingress, "workspaces", &workspaces);
            set_str(ingress, "listen", non_blank(edit.listen.as_deref()));
            set_str(
                ingress,
                "control_listen",
                non_blank(edit.control_listen.as_deref()),
            );
            match edit.edge_rate_per_ip_per_minute {
                Some(rate) => {
                    let edge = section_table(ingress, "edge")?;
                    set_u64(
                        edge,
                        "new_conn_rate_per_ip_per_minute",
                        Some(u64::from(rate)),
                    );
                }
                None => {
                    ingress.remove("edge");
                }
            }
        }
        ManifestEdit::RemoveIngress(node) => {
            let ingresses = parent_table(root, "ingress")?;
            if ingresses.remove(node).is_none() {
                return Err(unknown("ingress", node));
            }
        }
        ManifestEdit::SetAgentWorkspace { agent, workspace } => {
            declare_workspace(root, &current, workspace.trim())?;
            let agent_table = agent_table_mut(root, agent)?;
            set_str(agent_table, "workspace", Some(workspace.trim()));
        }
        ManifestEdit::RemoveAgent(node) => {
            let agents = parent_table(root, "agent")?;
            if agents.remove(node).is_none() {
                return Err(unknown("agent", node));
            }
        }
        ManifestEdit::UpsertService(edit) => {
            let agent_table = agent_table_mut(root, edit.agent.trim())?;
            let services = array_of_tables_mut(agent_table, "services")?;
            upsert_entry(services, "id", edit.id.trim(), |entry| {
                set_str(entry, "id", Some(edit.id.trim()));
                set_str(entry, "address", Some(edit.address.trim()));
            });
        }
        ManifestEdit::RemoveService { agent, id } => {
            let agent_table = agent_table_mut(root, agent)?;
            let services = array_of_tables_mut(agent_table, "services")?;
            remove_entry(services, "service", "id", id)?;
            drop_empty(agent_table, "services");
        }
        ManifestEdit::UpsertMeshIngress(edit) => {
            let agent_table = agent_table_mut(root, edit.agent.trim())?;
            let rules = array_of_tables_mut(agent_table, "mesh_ingress")?;
            upsert_entry(rules, "name", edit.name.trim(), |entry| {
                set_str(entry, "name", Some(edit.name.trim()));
                set_str(entry, "listen", Some(edit.listen.trim()));
                set_enum(entry, "protocol", protocol_text(edit.protocol), "tcp");
                set_str(entry, "target_agent", Some(edit.target_agent.trim()));
                set_str(entry, "remote_addr", Some(edit.remote_addr.trim()));
                set_u64(entry, "idle_timeout_secs", edit.idle_timeout_secs);
            });
        }
        ManifestEdit::RemoveMeshIngress { agent, name } => {
            let agent_table = agent_table_mut(root, agent)?;
            let rules = array_of_tables_mut(agent_table, "mesh_ingress")?;
            remove_entry(rules, "mesh ingress rule", "name", name)?;
            drop_empty(agent_table, "mesh_ingress");
        }
        ManifestEdit::UpsertMeshEgress(edit) => {
            let agent_table = agent_table_mut(root, edit.agent.trim())?;
            let rules = array_of_tables_mut(agent_table, "mesh_egress")?;
            upsert_entry(rules, "name", edit.name.trim(), |entry| {
                set_str(entry, "name", Some(edit.name.trim()));
                set_enum(entry, "protocol", protocol_text(edit.protocol), "tcp");
                set_str(entry, "target_addr", non_blank(edit.target_addr.as_deref()));
                set_str(entry, "target_cidr", non_blank(edit.target_cidr.as_deref()));
                set_u64(entry, "udp_idle_timeout_secs", edit.udp_idle_timeout_secs);
            });
        }
        ManifestEdit::RemoveMeshEgress { agent, name } => {
            let agent_table = agent_table_mut(root, agent)?;
            let rules = array_of_tables_mut(agent_table, "mesh_egress")?;
            remove_entry(rules, "mesh egress rule", "name", name)?;
            drop_empty(agent_table, "mesh_egress");
        }
        ManifestEdit::UpsertRoute(edit) => {
            let routes = array_of_tables_mut(root, "route")?;
            upsert_entry(routes, "host", edit.host.trim(), |entry| {
                set_str(entry, "host", Some(edit.host.trim()));
                set_str(entry, "service", Some(edit.service.trim()));
            });
        }
        ManifestEdit::RemoveRoute { host } => {
            let routes = root
                .get_mut("route")
                .and_then(Item::as_array_of_tables_mut)
                .ok_or_else(|| {
                    InterflowError::config("the manifest declares no [[route]] entries")
                })?;
            remove_entry(routes, "route", "host", host)?;
            if routes.is_empty() {
                root.remove("route");
            }
        }
    }
    let edited = doc.to_string();
    let edited_manifest: Manifest = toml::from_str(&edited)
        .map_err(|e| InterflowError::config("manifest parse".to_string()).with_source(e))?;
    if input_was_valid {
        edited_manifest
            .validate()
            .map_err(crate::runtime::pack_error)?;
    }
    Ok(edited)
}

const fn tls_mode_text(mode: PublicTlsMode) -> &'static str {
    match mode {
        PublicTlsMode::Acme => "acme",
        PublicTlsMode::FrontendProxy => "frontend-proxy",
        PublicTlsMode::Manual => "manual",
    }
}

const fn identity_mode_text(mode: IdentityMode) -> &'static str {
    match mode {
        IdentityMode::Registrar => "registrar",
        IdentityMode::Offline => "offline",
    }
}

const fn protocol_text(protocol: MeshProtocol) -> &'static str {
    match protocol {
        MeshProtocol::Tcp => "tcp",
        MeshProtocol::Udp => "udp",
    }
}

fn unknown(kind: &str, name: &str) -> InterflowError {
    InterflowError::config(format!("the manifest declares no {kind} {name:?}"))
}

/// `Some(trimmed)` for a non-blank optional string, else `None`.
fn non_blank(value: Option<&str>) -> Option<&str> {
    value.and_then(non_blank_str)
}

/// `Some(trimmed)` for a non-blank string, else `None` (empty = absent).
fn non_blank_str(value: &str) -> Option<&str> {
    let trimmed = value.trim();
    (!trimmed.is_empty()).then_some(trimmed)
}

// ---------------------------------------------------------------------------
// toml_edit micro-helpers — minimal-diff, comment-preserving writes
// ---------------------------------------------------------------------------

/// Assigns a string key: an existing value is replaced **in place** (its
/// decor — surrounding whitespace, inline comment — survives), an absent
/// key is appended, `None` removes the key. A no-op assignment (same
/// string) rewrites nothing, which is what keeps round-trips byte-stable.
fn set_str(table: &mut Table, key: &str, desired: Option<&str>) {
    match desired {
        None => {
            table.remove(key);
        }
        Some(desired) => match table.get_mut(key) {
            Some(item) => match item.as_value_mut() {
                Some(value) if value.as_str() != Some(desired) => {
                    let decor = value.decor().clone();
                    *value = desired.into();
                    *value.decor_mut() = decor;
                }
                Some(_) => {}
                None => {
                    table.insert(key, toml_edit::value(desired));
                }
            },
            None => {
                table.insert(key, toml_edit::value(desired));
            }
        },
    }
}

/// Integer twin of [`set_str`] (the timeout knobs; bounded 1..=86400 by
/// the validator, so the i64 narrowing is exact).
fn set_u64(table: &mut Table, key: &str, desired: Option<u64>) {
    let Some(desired) = desired else {
        table.remove(key);
        return;
    };
    let desired = i64::try_from(desired).unwrap_or(i64::MAX);
    let same = table
        .get(key)
        .and_then(Item::as_value)
        .and_then(Value::as_integer)
        .is_some_and(|current| current == desired);
    if same {
        return;
    }
    match table.get_mut(key) {
        Some(item) => match item.as_value_mut() {
            Some(value) => {
                let decor = value.decor().clone();
                *value = Value::from(desired);
                *value.decor_mut() = decor;
            }
            None => {
                table.insert(key, toml_edit::value(desired));
            }
        },
        None => {
            table.insert(key, toml_edit::value(desired));
        }
    }
}

/// Inline string array (ingress `workspaces`): replaced in place when the
/// key exists, appended when absent; order-sensitive equality short-circuits
/// the no-op case.
fn set_str_array(table: &mut Table, key: &str, desired: &[String]) {
    let current: Option<Vec<String>> = table
        .get(key)
        .and_then(Item::as_value)
        .and_then(Value::as_array)
        .map(|array| {
            array
                .iter()
                .filter_map(|value| value.as_str().map(str::to_owned))
                .collect()
        });
    if current.as_deref() == Some(desired) {
        return;
    }
    let mut array = toml_edit::Array::new();
    for value in desired {
        array.push(value.as_str());
    }
    match table.get_mut(key) {
        Some(item) => match item.as_value_mut() {
            Some(value) => {
                let decor = value.decor().clone();
                *value = Value::from(array);
                *value.decor_mut() = decor;
            }
            None => {
                table.insert(key, toml_edit::value(array));
            }
        },
        None => {
            table.insert(key, toml_edit::value(array));
        }
    }
}

/// Enum key with a serde default (`mode = "acme"`, `protocol = "tcp"`):
/// the canonical form for the default value is *absence*, so a desired
/// default removes an off-default key and leaves an already-absent one
/// alone — while an explicitly written default stays explicit (the
/// operator wrote it; minimal diff beats canonicalization).
fn set_enum(table: &mut Table, key: &str, desired: &str, default: &str) {
    if desired != default {
        set_str(table, key, Some(desired));
        return;
    }
    let present = table
        .get(key)
        .and_then(Item::as_value)
        .and_then(Value::as_str);
    if present.is_some_and(|current| current != desired) {
        table.remove(key);
    }
}

/// The (possibly created) sub-table `key` of `root`, explicit — for
/// sections that carry keys directly (`[realm]`, `[identity]`), unlike
/// [`parent_table`]'s implicit `[agent]`-style namespaces.
fn section_table<'a>(root: &'a mut Table, key: &str) -> Result<&'a mut Table> {
    let item = root.entry(key).or_insert_with(|| Item::Table(Table::new()));
    let table = item
        .as_table_mut()
        .ok_or_else(|| InterflowError::config(format!("manifest key {key:?} is not a table")))?;
    table.set_implicit(false);
    Ok(table)
}

/// The (possibly created) sub-table `key` of `root`, as an implicit parent
/// — `[agent]`-style bare headers are never emitted for tables that only
/// carry subtables.
fn parent_table<'a>(root: &'a mut Table, key: &str) -> Result<&'a mut Table> {
    let item = root.entry(key).or_insert_with(|| {
        let mut table = Table::new();
        table.set_implicit(true);
        Item::Table(table)
    });
    item.as_table_mut().ok_or_else(|| {
        InterflowError::config(format!(
            "manifest key {key:?} is not a table — cannot append to it"
        ))
    })
}

/// `[agent.<name>]` as a mutable table, with the schema (not the raw keys)
/// deciding existence.
fn agent_table_mut<'a>(root: &'a mut Table, agent: &str) -> Result<&'a mut Table> {
    parent_table(root, "agent")?
        .get_mut(agent)
        .and_then(Item::as_table_mut)
        .ok_or_else(|| unknown("agent", agent))
}

/// The (possibly created) `[[…key]]` array-of-tables under `table`. An
/// inline array (`mesh_ingress = [{…}]`) parses fine but is not a shape
/// this editor writes — refuse it with a pointer to the TOML view rather
/// than half-migrating the layout.
fn array_of_tables_mut<'a>(table: &'a mut Table, key: &str) -> Result<&'a mut ArrayOfTables> {
    let item = table
        .entry(key)
        .or_insert_with(|| Item::ArrayOfTables(ArrayOfTables::new()));
    item.as_array_of_tables_mut().ok_or_else(|| {
        InterflowError::config(format!(
            "{key} is written as an inline array — the structured editor edits \
             [[…{key}]] entries; convert the section in the TOML view first"
        ))
    })
}

/// Removes the array key entirely once its last entry is gone: an empty
/// array-of-tables and an absent key serialize identically, and absent is
/// the canonical form.
fn drop_empty(table: &mut Table, key: &str) {
    if table
        .get(key)
        .and_then(Item::as_array_of_tables)
        .is_some_and(ArrayOfTables::is_empty)
    {
        table.remove(key);
    }
}

/// Finds the entry whose `key_field` equals `key`.
fn find_entry_index(array: &ArrayOfTables, key_field: &str, key: &str) -> Option<usize> {
    array.iter().position(|entry| {
        entry
            .get(key_field)
            .and_then(Item::as_value)
            .and_then(Value::as_str)
            == Some(key)
    })
}

/// Adds the entry `key` identifies, or patches the existing one in place —
/// entry-level comments survive an edit because only the entry's keys are
/// touched, never the entry table itself.
fn upsert_entry(
    array: &mut ArrayOfTables,
    key_field: &str,
    key: &str,
    write: impl FnOnce(&mut Table),
) {
    if let Some(index) = find_entry_index(array, key_field, key) {
        if let Some(entry) = array.get_mut(index) {
            write(entry);
        }
    } else {
        let mut entry = Table::new();
        write(&mut entry);
        array.push(entry);
    }
}

fn remove_entry(array: &mut ArrayOfTables, label: &str, key_field: &str, key: &str) -> Result<()> {
    match find_entry_index(array, key_field, key) {
        Some(index) => {
            array.remove(index);
            Ok(())
        }
        None => Err(InterflowError::config(format!(
            "the manifest declares no {label} {key:?}"
        ))),
    }
}

/// Declares `[workspace.<name>]` when the manifest does not have it yet —
/// appended nodes may introduce a new isolation namespace in the same
/// breath as referencing it.
fn declare_workspace(root: &mut Table, current: &Manifest, workspace: &str) -> Result<()> {
    if current.workspace.contains_key(workspace) {
        return Ok(());
    }
    parent_table(root, "workspace")?.insert(workspace, Item::Table(Table::new()));
    Ok(())
}

// ---------------------------------------------------------------------------
// `node add` — the structured append: a pure core + a file shell
// ---------------------------------------------------------------------------

/// Which node table [`add_node`] appends to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AddNodeKind {
    Agent,
    Ingress,
    Hub,
}

impl AddNodeKind {
    /// The dist directory prefix of the rendered pack (`<kind>-<node>`).
    pub const fn dir_prefix(self) -> &'static str {
        match self {
            Self::Agent => "agent",
            Self::Ingress => "ingress",
            Self::Hub => "hub",
        }
    }

    /// Parses `agent/<name>` / `ingress/<name>` / `hub/<name>`.
    pub fn parse(text: &str) -> Result<(Self, String)> {
        let Some((kind, node)) = text.split_once('/') else {
            return Err(InterflowError::config(format!(
                "node {text:?} must look like agent/<name>, ingress/<name> or hub/<name>"
            )));
        };
        let kind = match kind {
            "agent" => Self::Agent,
            "ingress" => Self::Ingress,
            "hub" => Self::Hub,
            other => {
                return Err(InterflowError::config(format!(
                    "unknown node kind {other:?} — expected agent, ingress or hub"
                )));
            }
        };
        if node.is_empty() {
            return Err(InterflowError::config(format!(
                "node {text:?} has an empty name"
            )));
        }
        Ok((kind, node.to_owned()))
    }
}

/// A service an expose agent dials locally.
#[derive(Debug, Clone)]
pub struct AddServiceSpec {
    pub id: String,
    pub address: String,
}

/// A listen-side mesh rule (`mesh_ingress`).
#[derive(Debug, Clone)]
pub struct AddMeshIngressSpec {
    pub name: String,
    pub listen: String,
    pub udp: bool,
    pub target_agent: String,
    pub remote_addr: String,
    /// Stream idle budget (seconds, 1..=86400); `None` = protocol default
    /// (tcp 300 / udp 60). The CLI flag shorthand leaves it unset — the GUI
    /// form editor is the surface that tunes it.
    pub idle_timeout_secs: Option<u64>,
}

/// A serve-side mesh rule (`mesh_egress`): exactly one of `target_addr` /
/// `target_cidr` (mirrors the manifest type).
#[derive(Debug, Clone)]
pub struct AddMeshEgressSpec {
    pub name: String,
    pub udp: bool,
    pub target_addr: Option<String>,
    pub target_cidr: Option<String>,
}

/// One structured node append — the shared core behind CLI `node add`, the
/// GUI issue wizard, and the form's node-creation dialogs.
///
/// Only the authorization-relevant facts: everything else (validation,
/// rendering, sealing) stays where it already lives.
#[derive(Debug, Clone)]
pub struct AddNodeSpec {
    pub kind: AddNodeKind,
    pub node: String,
    /// Agent only; `None` = the manifest's sole workspace, else `default`.
    pub workspace: Option<String>,
    /// Agent (expose role).
    pub services: Vec<AddServiceSpec>,
    /// Agent (mesh role).
    pub mesh_ingress: Vec<AddMeshIngressSpec>,
    pub mesh_egress: Vec<AddMeshEgressSpec>,
    /// Ingress only: the workspaces it serves.
    pub ingress_workspaces: Vec<String>,
    /// Hub only: the dial endpoint agents use.
    pub hub_endpoint: Option<String>,
}

/// What [`add_node`] produced: the rewritten manifest text (the GUI feeds
/// it back into its editor so both surfaces stay on the same file) and the
/// pack directory name `plan apply` will render.
#[derive(Debug)]
pub struct AddNodeOutcome {
    pub manifest_text: String,
    pub pack_dir_name: String,
}

/// Appends one node to the manifest file — non-destructively and
/// fail-closed (see [`add_node_in_text`]); writes through
/// [`save_manifest`].
pub fn add_node(manifest_path: &Path, spec: &AddNodeSpec) -> Result<AddNodeOutcome> {
    let original = std::fs::read_to_string(manifest_path)?;
    let edited = add_node_in_text(&original, spec)?;
    save_manifest(manifest_path, &edited)?;
    Ok(AddNodeOutcome {
        manifest_text: edited,
        pack_dir_name: format!("{}-{}", spec.kind.dir_prefix(), spec.node),
    })
}

/// The pure core of `node add`: appends one node to the manifest text.
///
/// Runs under an **unconditional** full funnel — one append carries its
/// own validity, so whatever comes back parses and validates, whatever
/// fails leaves the input untouched. toml_edit keeps every comment and
/// the operator's layout.
pub fn add_node_in_text(original: &str, spec: &AddNodeSpec) -> Result<String> {
    // Shape-only parse of the current state: a fresh `setup --face mesh`
    // skeleton has no agent yet and is deliberately invalid until the first
    // append — the *edited* manifest below carries the full validation
    // duty, so the current one only has to be well-formed.
    let current: Manifest = toml::from_str(original)
        .map_err(|e| InterflowError::config("manifest parse".to_string()).with_source(e))?;
    if current.agent.contains_key(&spec.node)
        || current.ingress.contains_key(&spec.node)
        || current.mesh.hub.contains_key(&spec.node)
    {
        return Err(InterflowError::config(format!(
            "node '{}' already exists in the manifest",
            spec.node
        )));
    }
    let mut doc: toml_edit::DocumentMut = original
        .parse()
        .map_err(|e| InterflowError::config("manifest TOML syntax".to_string()).with_source(e))?;
    let root = doc.as_table_mut();
    match spec.kind {
        AddNodeKind::Agent => {
            // One pack, one role — refuse here with validate's phrasing so
            // the failure happens before anything is written.
            let has_services = !spec.services.is_empty();
            let has_mesh = !spec.mesh_ingress.is_empty() || !spec.mesh_egress.is_empty();
            if has_services && has_mesh {
                return Err(InterflowError::config(format!(
                    "agent '{}' mixes public services and mesh rules — one pack, one role; \
                     declare a second agent node for the other role",
                    spec.node
                )));
            }
            if !has_services && !has_mesh {
                return Err(InterflowError::config(format!(
                    "agent '{}' declares neither services nor mesh rules",
                    spec.node
                )));
            }
            let workspace = spec
                .workspace
                .clone()
                .unwrap_or_else(|| default_workspace(&current));
            let mut node = Table::new();
            node["workspace"] = toml_edit::value(workspace.as_str());
            if !spec.services.is_empty() {
                let mut list = ArrayOfTables::new();
                for service in &spec.services {
                    let mut entry = Table::new();
                    entry["id"] = toml_edit::value(service.id.as_str());
                    entry["address"] = toml_edit::value(service.address.as_str());
                    list.push(entry);
                }
                node["services"] = Item::ArrayOfTables(list);
            }
            if !spec.mesh_ingress.is_empty() {
                let mut list = ArrayOfTables::new();
                for rule in &spec.mesh_ingress {
                    let mut entry = Table::new();
                    entry["name"] = toml_edit::value(rule.name.as_str());
                    entry["listen"] = toml_edit::value(rule.listen.as_str());
                    if rule.udp {
                        entry["protocol"] = toml_edit::value("udp");
                    }
                    entry["target_agent"] = toml_edit::value(rule.target_agent.as_str());
                    entry["remote_addr"] = toml_edit::value(rule.remote_addr.as_str());
                    if let Some(secs) = rule.idle_timeout_secs {
                        entry["idle_timeout_secs"] =
                            toml_edit::value(i64::try_from(secs).unwrap_or(i64::MAX));
                    }
                    list.push(entry);
                }
                node["mesh_ingress"] = Item::ArrayOfTables(list);
            }
            if !spec.mesh_egress.is_empty() {
                let mut list = ArrayOfTables::new();
                for rule in &spec.mesh_egress {
                    let mut entry = Table::new();
                    entry["name"] = toml_edit::value(rule.name.as_str());
                    if rule.udp {
                        entry["protocol"] = toml_edit::value("udp");
                    }
                    if let Some(addr) = &rule.target_addr {
                        entry["target_addr"] = toml_edit::value(addr.as_str());
                    }
                    if let Some(cidr) = &rule.target_cidr {
                        entry["target_cidr"] = toml_edit::value(cidr.as_str());
                    }
                    list.push(entry);
                }
                node["mesh_egress"] = Item::ArrayOfTables(list);
            }
            declare_workspace(root, &current, &workspace)?;
            parent_table(root, "agent")?.insert(spec.node.as_str(), Item::Table(node));
        }
        AddNodeKind::Ingress => {
            if spec.ingress_workspaces.is_empty() {
                return Err(InterflowError::config(format!(
                    "ingress '{}' needs the workspaces it serves (one or more)",
                    spec.node
                )));
            }
            let mut node = Table::new();
            let mut list = toml_edit::Array::new();
            for workspace in &spec.ingress_workspaces {
                list.push(workspace.as_str());
                declare_workspace(root, &current, workspace)?;
            }
            node["workspaces"] = toml_edit::value(list);
            parent_table(root, "ingress")?.insert(spec.node.as_str(), Item::Table(node));
        }
        AddNodeKind::Hub => {
            let Some(endpoint) = spec.hub_endpoint.as_deref() else {
                return Err(InterflowError::config(format!(
                    "hub '{}' needs its dial endpoint (host:port)",
                    spec.node
                )));
            };
            let mut node = Table::new();
            node["endpoint"] = toml_edit::value(endpoint);
            // `listen` stays omitted → the manifest default (0.0.0.0:6666).
            let mesh = parent_table(root, "mesh")?;
            parent_table(mesh, "hub")?.insert(spec.node.as_str(), Item::Table(node));
        }
    }
    let edited = doc.to_string();
    // Full validation on the edited manifest — nothing reaches the caller
    // unless the whole file (not just the appended node) passes the same
    // funnel `plan validate` runs.
    Manifest::parse(&edited).map_err(crate::runtime::pack_error)?;
    Ok(edited)
}

/// The manifest's sole workspace, else `default` — single-workspace
/// deployments never see the concept.
fn default_workspace(current: &Manifest) -> String {
    let mut keys = current.workspace.keys();
    if let (Some(only), None) = (keys.next(), keys.next()) {
        only.clone()
    } else {
        "default".to_owned()
    }
}

// ---------------------------------------------------------------------------
// Persistence — the one write shell
// ---------------------------------------------------------------------------

/// Persists manifest text with the editor's write discipline.
///
/// A silent one-generation `.bak` (best effort — the atomic replace below
/// is the write safety; validation upstream is the content safety), then
/// the atomic write. This is the only function in the module that touches
/// a file, and the only write path its callers share.
pub fn save_manifest(path: &Path, text: &str) -> Result<()> {
    if path.exists() {
        let mut backup = path.as_os_str().to_os_string();
        backup.push(".bak");
        let _ = std::fs::copy(path, std::path::PathBuf::from(backup));
    }
    interflow_util::atomic_write(
        path,
        text.as_bytes(),
        interflow_util::WriteMode::PreserveOr(0o644),
    )
    .map_err(InterflowError::Io)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    /// The blueprint subset of the real promptcn site-to-site deployment:
    /// comments in load-bearing positions (section headers, inside entries,
    /// trailing keys), the fields the editor must round-trip, and nothing
    /// else. Every comment line below is asserted to survive every edit.
    const MESH_MANIFEST: &str = r#"# top comment — the whole file's contract
[realm]
id = "promptcn-mesh"     # realm comment

# offline tier comment
[identity]
mode = "offline"
leaf_ttl = "90d"

# hub comment
[mesh.hub.promptcn]
listen = "0.0.0.0:6666"
endpoint = "mesh.example.com:6666"

[workspace.main]

# ingress side
[agent.leo-mesh]
workspace = "main"

# first rule comment
[[agent.leo-mesh.mesh_ingress]]
name = "ollama"
listen = "127.0.0.1:11434"
target_agent = "home-win"
remote_addr = "127.0.0.1:11434"

# asr needs a raised idle budget
[[agent.leo-mesh.mesh_ingress]]
name = "asr"
listen = "127.0.0.1:8056"
target_agent = "home-win"
remote_addr = "127.0.0.1:8056"
idle_timeout_secs = 1800

# egress side
[agent.home-win]
workspace = "main"

[[agent.home-win.mesh_egress]]
name = "loopback-services"
target_cidr = "127.0.0.0/8"
"#;

    /// Every comment line of the fixture, in order — the invariant under
    /// test is "still present, verbatim" after each edit.
    fn comment_lines(text: &str) -> Vec<String> {
        text.lines()
            .filter(|line| line.trim_start().starts_with('#'))
            .map(str::to_owned)
            .collect()
    }

    fn comments_survive(original: &str, edited: &str) {
        assert_eq!(
            comment_lines(original),
            comment_lines(edited),
            "every comment must survive, verbatim and in order"
        );
    }

    /// A full error chain as the issues display would render it.
    fn chain_of(error: &InterflowError) -> String {
        let mut chain = error.to_string();
        let mut source: &dyn std::error::Error = error;
        while let Some(next) = source.source() {
            chain.push_str(&next.to_string());
            source = next;
        }
        chain
    }

    /// TTL bounds track the issuance constants — the form hint can never
    /// disagree with the validator's裁决.
    #[test]
    fn leaf_ttl_bounds_match_tiers() {
        assert_eq!(
            LeafTtlBounds::for_mode(IdentityMode::Registrar),
            LeafTtlBounds {
                min: "1h".into(),
                max: "24h".into(),
                default: "24h".into(),
            }
        );
        assert_eq!(
            LeafTtlBounds::for_mode(IdentityMode::Offline),
            LeafTtlBounds {
                min: "7d".into(),
                max: "365d".into(),
                default: "90d".into(),
            }
        );
    }

    /// A valid document summarizes with zero issues and the derived facts
    /// the form needs; a shape-parse failure is a hard error (there is no
    /// document to render); a skeleton summarizes with its issues.
    #[test]
    fn summarize_reports_issues_without_inventing_a_document() {
        let summary = summarize(MESH_MANIFEST).unwrap();
        assert!(summary.issues.is_empty(), "{:?}", summary.issues);
        assert_eq!(summary.agent_roles["leo-mesh"], AgentRole::Mesh);
        assert_eq!(summary.agent_roles["home-win"], AgentRole::Mesh);
        assert_eq!(
            summary.manifest.agent["leo-mesh"].mesh_ingress[1].idle_timeout_secs,
            Some(1800),
            "the summary carries every schema field"
        );

        assert!(
            summarize("[realm\nid = \"x\"").is_err(),
            "unparseable text has no read model"
        );

        let skeleton = crate::plan::setup_mesh_template("t", "hub", "mesh.example.com:6666");
        let summary = summarize(&skeleton).unwrap();
        assert!(
            !summary.issues.is_empty(),
            "the skeleton's missing agent surfaces as an issue, not an error"
        );
    }

    /// The identity tier is one atomic decision: offline→registrar and
    /// back lands with `[identity]` and `[registrar]` crossing the line
    /// together, comments intact, and every intermediate state valid.
    #[test]
    fn identity_tier_switches_atomically() {
        let registrar = apply_edit(
            MESH_MANIFEST,
            &ManifestEdit::SetIdentity(IdentityEdit {
                mode: IdentityMode::Registrar,
                leaf_ttl: Some("12h".into()),
                registrar_endpoint: Some("https://reg.example.com".into()),
            }),
        )
        .unwrap();
        comments_survive(MESH_MANIFEST, &registrar);
        let manifest = Manifest::parse(&registrar).unwrap();
        assert_eq!(manifest.registrar.endpoint, "https://reg.example.com");
        assert_eq!(manifest.identity.leaf_ttl.as_deref(), Some("12h"));

        let offline = apply_edit(
            &registrar,
            &ManifestEdit::SetIdentity(IdentityEdit {
                mode: IdentityMode::Offline,
                leaf_ttl: Some("90d".into()),
                registrar_endpoint: None,
            }),
        )
        .unwrap();
        assert!(
            !offline.contains("[registrar]"),
            "offline tier drops the section: {offline}"
        );
        Manifest::parse(&offline).unwrap();
    }

    /// The full round-trip invariant: re-applying the document's own values
    /// through every edit variant is byte-stable — explicit defaults stay
    /// explicit, absent defaults stay absent, nothing reflows. A kitchen
    /// sink exercises every field the form can write.
    #[test]
    fn reapplying_a_summary_is_byte_stable() {
        const KITCHEN_SINK: &str = r#"# sink comment
[realm]
id = "kitchen"
control_endpoint = "tunnel.example.com:443"

[public_tls]
mode = "frontend-proxy" # explicit non-default
email = "ops@example.com"

[identity]
mode = "offline"
leaf_ttl = "45d"

[workspace.default]

[ingress.edge]
workspaces = ["default"]
listen = "0.0.0.0:443"
control_listen = "127.0.0.1:16666"

[ingress.edge.edge]
new_conn_rate_per_ip_per_minute = 30

[agent.desktop]
workspace = "default"

[[agent.desktop.services]]
id = "asr"
address = "127.0.0.1:8080"

[[route]]
host = "app.example.com"
service = "default/desktop/asr"
"#;
        let summary = summarize(KITCHEN_SINK).unwrap();
        assert!(summary.issues.is_empty(), "{:?}", summary.issues);
        let manifest = summary.manifest;
        let edits = [
            ManifestEdit::SetRealm(RealmEdit {
                id: manifest.realm.id.clone(),
                control_endpoint: manifest.realm.control_endpoint.clone(),
            }),
            ManifestEdit::SetPublicTls(PublicTlsEdit {
                mode: manifest.public_tls.mode,
                email: manifest.public_tls.email.clone(),
                directory: manifest.public_tls.directory.clone(),
            }),
            ManifestEdit::SetIdentity(IdentityEdit {
                mode: manifest.identity.mode,
                leaf_ttl: manifest.identity.leaf_ttl.clone(),
                registrar_endpoint: None,
            }),
            ManifestEdit::UpsertIngress(IngressEdit {
                node: "edge".into(),
                workspaces: manifest.ingress["edge"].workspaces.clone(),
                listen: Some(manifest.ingress["edge"].listen.clone()),
                control_listen: Some(manifest.ingress["edge"].control_listen.clone()),
                edge_rate_per_ip_per_minute: manifest.ingress["edge"]
                    .edge
                    .as_ref()
                    .and_then(|edge| edge.new_conn_rate_per_ip_per_minute),
            }),
            ManifestEdit::SetAgentWorkspace {
                agent: "desktop".into(),
                workspace: manifest.agent["desktop"].workspace.clone(),
            },
            ManifestEdit::UpsertService(ServiceEdit {
                agent: "desktop".into(),
                id: manifest.agent["desktop"].services[0].id.clone(),
                address: manifest.agent["desktop"].services[0].address.clone(),
            }),
            ManifestEdit::UpsertRoute(RouteEdit {
                host: manifest.route[0].host.clone(),
                service: manifest.route[0].service.clone(),
            }),
            ManifestEdit::UpsertWorkspace("default".into()),
        ];
        let mut text = KITCHEN_SINK.to_owned();
        for edit in &edits {
            text = apply_edit(&text, edit).unwrap();
        }
        assert_eq!(text, KITCHEN_SINK, "full round-trip must be byte-stable");
    }

    /// Upsert-by-name patches the matching entry in place (entry comments
    /// survive) and appends a new entry when the name is new; removing the
    /// idle key and dropping the last rule both behave canonically.
    #[test]
    fn mesh_rule_upsert_addresses_entries_by_name() {
        let edited = apply_edit(
            MESH_MANIFEST,
            &ManifestEdit::UpsertMeshIngress(MeshIngressEdit {
                agent: "leo-mesh".into(),
                name: "asr".into(),
                listen: "127.0.0.1:8056".into(),
                protocol: MeshProtocol::Tcp,
                target_agent: "home-win".into(),
                remote_addr: "127.0.0.1:8056".into(),
                idle_timeout_secs: Some(3600),
            }),
        )
        .unwrap();
        comments_survive(MESH_MANIFEST, &edited);
        assert!(edited.contains("idle_timeout_secs = 3600"), "{edited}");
        assert_eq!(
            Manifest::parse(&edited).unwrap().agent["leo-mesh"]
                .mesh_ingress
                .len(),
            2,
            "upsert of an existing name patches, not appends"
        );

        // Clearing the idle budget removes the key (absent = default).
        let edited = apply_edit(
            &edited,
            &ManifestEdit::UpsertMeshIngress(MeshIngressEdit {
                agent: "leo-mesh".into(),
                name: "asr".into(),
                listen: "127.0.0.1:8056".into(),
                protocol: MeshProtocol::Tcp,
                target_agent: "home-win".into(),
                remote_addr: "127.0.0.1:8056".into(),
                idle_timeout_secs: None,
            }),
        )
        .unwrap();
        assert!(!edited.contains("idle_timeout_secs"), "{edited}");

        // New names append: one more rule, funnel satisfied by the peer's
        // loopback-range egress.
        let edited = apply_edit(
            &edited,
            &ManifestEdit::UpsertMeshIngress(MeshIngressEdit {
                agent: "leo-mesh".into(),
                name: "tts".into(),
                listen: "127.0.0.1:8055".into(),
                protocol: MeshProtocol::Tcp,
                target_agent: "home-win".into(),
                remote_addr: "127.0.0.1:8055".into(),
                idle_timeout_secs: None,
            }),
        )
        .unwrap();
        comments_survive(MESH_MANIFEST, &edited);
        assert_eq!(
            Manifest::parse(&edited).unwrap().agent["leo-mesh"]
                .mesh_ingress
                .len(),
            3
        );
    }

    /// Removing a rule by name drops exactly that entry; removing the last
    /// rule of the only role an agent has is refused by the valid→valid
    /// invariant (the agent would declare neither services nor mesh rules
    /// — the operator's move is RemoveAgent).
    #[test]
    fn remove_rule_is_targeted_and_role_aware() {
        let err = apply_edit(
            MESH_MANIFEST,
            &ManifestEdit::RemoveMeshEgress {
                agent: "home-win".into(),
                name: "loopback-services".into(),
            },
        )
        .unwrap_err();
        assert!(
            chain_of(&err).contains("declares neither services nor mesh rules"),
            "dropping the agent's only role is rejected on a valid document: {err}"
        );

        let edited = apply_edit(
            MESH_MANIFEST,
            &ManifestEdit::RemoveMeshIngress {
                agent: "leo-mesh".into(),
                name: "ollama".into(),
            },
        )
        .unwrap();
        // The removed entry's own comment goes with it (there is nowhere
        // for it to live); everything else survives verbatim.
        let expected: Vec<String> = comment_lines(MESH_MANIFEST)
            .into_iter()
            .filter(|line| line != "# first rule comment")
            .collect();
        assert_eq!(comment_lines(&edited), expected);
        let manifest = Manifest::parse(&edited).unwrap();
        let rules = &manifest.agent["leo-mesh"].mesh_ingress;
        assert_eq!(rules.len(), 1);
        assert_eq!(rules[0].name, "asr");

        let err = apply_edit(
            &edited,
            &ManifestEdit::RemoveMeshIngress {
                agent: "leo-mesh".into(),
                name: "no-such-rule".into(),
            },
        )
        .unwrap_err();
        assert!(err.to_string().contains("no mesh ingress rule"), "{err}");
    }

    /// The valid→valid invariant at work: on a valid document, an edit
    /// that would break mesh pairing is rejected outright (purity is the
    /// rollback — there is no returned text to inspect); on an
    /// under-construction skeleton the same shape of edit succeeds,
    /// because construction must pass through intermediate states whose
    /// issues surface in the read model instead.
    #[test]
    fn valid_documents_only_transition_to_valid_documents() {
        let err = apply_edit(
            MESH_MANIFEST,
            &ManifestEdit::UpsertMeshIngress(MeshIngressEdit {
                agent: "leo-mesh".into(),
                name: "unpaired".into(),
                listen: "127.0.0.1:9".into(),
                protocol: MeshProtocol::Tcp,
                target_agent: "home-win".into(),
                remote_addr: "10.0.0.5:9".into(),
                idle_timeout_secs: None,
            }),
        )
        .unwrap_err();
        assert!(
            chain_of(&err).contains("does not offer it"),
            "unpaired rule rejected at edit time: {err}"
        );

        let skeleton = crate::plan::setup_mesh_template("t", "central", "mesh.example.com:6666");
        assert!(!summarize(&skeleton).unwrap().issues.is_empty());
        // The skeleton's hub is already declared; editing the realm on the
        // invalid skeleton proceeds — shape funnel only.
        let edited = apply_edit(
            &skeleton,
            &ManifestEdit::SetRealm(RealmEdit {
                id: "renamed".into(),
                control_endpoint: String::new(),
            }),
        )
        .unwrap();
        assert!(
            edited.contains("id = \"renamed\""),
            "edits proceed on under-construction documents: {edited}"
        );
        assert!(
            !summarize(&edited).unwrap().issues.is_empty(),
            "the missing agent is still a live issue, not a silent pass"
        );
    }

    /// Sections with a serde default stay absent when the desired state is
    /// the default and the document never declared them — a form "Apply"
    /// with unchanged defaults must not spray empty tables.
    #[test]
    fn default_sections_are_not_invented() {
        let edited = apply_edit(
            MESH_MANIFEST,
            &ManifestEdit::SetPublicTls(PublicTlsEdit {
                mode: PublicTlsMode::Acme,
                email: None,
                directory: None,
            }),
        )
        .unwrap();
        assert!(
            !edited.contains("[public_tls]"),
            "all-default state must not create the section: {edited}"
        );
        assert_eq!(edited, MESH_MANIFEST, "a no-op edit is byte-stable");
    }

    /// Node creation rides the same transform `node add` uses (one pack,
    /// one role, unconditional funnel) and lands valid from a skeleton in
    /// one step — the GUI's create dialogs get identical semantics.
    #[test]
    fn add_node_edits_create_nodes_with_roles() {
        let skeleton = crate::plan::setup_mesh_template("t", "central", "mesh.example.com:6666");
        let with_egress = apply_edit(
            &skeleton,
            &ManifestEdit::AddNode(AddNodeSpec {
                kind: AddNodeKind::Agent,
                node: "home-win".into(),
                workspace: None,
                services: vec![],
                mesh_ingress: vec![],
                mesh_egress: vec![AddMeshEgressSpec {
                    name: "loopback".into(),
                    udp: false,
                    target_addr: None,
                    target_cidr: Some("127.0.0.0/8".into()),
                }],
                ingress_workspaces: vec![],
                hub_endpoint: None,
            }),
        )
        .unwrap();
        let with_ingress = apply_edit(
            &with_egress,
            &ManifestEdit::AddNode(AddNodeSpec {
                kind: AddNodeKind::Agent,
                node: "leo".into(),
                workspace: None,
                services: vec![],
                mesh_ingress: vec![AddMeshIngressSpec {
                    name: "asr".into(),
                    listen: "127.0.0.1:8056".into(),
                    udp: false,
                    target_agent: "home-win".into(),
                    remote_addr: "127.0.0.1:8056".into(),
                    idle_timeout_secs: Some(1800),
                }],
                mesh_egress: vec![],
                ingress_workspaces: vec![],
                hub_endpoint: None,
            }),
        )
        .unwrap();
        let manifest = Manifest::parse(&with_ingress).unwrap();
        assert_eq!(
            manifest.agent["leo"].mesh_ingress[0].idle_timeout_secs,
            Some(1800),
            "node creation carries the idle budget"
        );
        assert!(
            with_ingress.contains("# The manifest needs at least one agent"),
            "the skeleton's guidance comments survive the appends"
        );
    }

    /// save_manifest keeps a one-generation backup and writes the new text
    /// atomically; a nonexistent target gets created (first Save).
    #[test]
    fn save_manifest_leaves_one_generation_backup() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("interflow.toml");
        save_manifest(&path, MESH_MANIFEST).unwrap();
        assert_eq!(std::fs::read_to_string(&path).unwrap(), MESH_MANIFEST);
        assert!(!path.with_extension("toml.bak").exists());

        save_manifest(&path, "# replaced\n").unwrap();
        assert_eq!(std::fs::read_to_string(&path).unwrap(), "# replaced\n");
        let mut backup = path.as_os_str().to_os_string();
        backup.push(".bak");
        assert_eq!(
            std::fs::read_to_string(std::path::PathBuf::from(backup)).unwrap(),
            MESH_MANIFEST,
            "the previous generation is the backup"
        );
    }
}
