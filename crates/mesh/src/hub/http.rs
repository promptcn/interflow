//! Wire contracts of the hub's operator HTTP surface.
//!
//! The typed shapes an operator (or script) consumes via curl. Handlers
//! serialize these; the e2e guards hold their own consumer-side mirror in
//! `interflow-testkit` (`hub_http`), so a shape change here fails the
//! guards unless both sides move in the same commit (the HTTP-surface
//! analog of the GUI bindings drift guard; see
//! (internal design notes)).

use interflow_identity::expiry::LeafHealth;
use serde::{Deserialize, Serialize};

/// One `GET /agents` entry: the agent's qualified id plus its
/// credential-health reading.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AgentListEntry {
    /// Qualified agent id (`tenant/agent`).
    pub agent: String,
    /// Parsed from the registration certificate; `None` (serialized as
    /// null) when the leaf certificate did not parse.
    pub leaf_expiry: Option<LeafExpiry>,
}

/// The `leaf_expiry` object: the leaf's `notAfter` plus the single-source
/// phase math ([`LeafHealth`]) flattened to `{remaining_secs, phase}`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LeafExpiry {
    pub not_after_unix: i64,
    #[serde(flatten)]
    pub health: LeafHealth,
}
