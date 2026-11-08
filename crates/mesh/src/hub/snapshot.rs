//! `GET /snapshot` — the fleet's steady-state picture, one versioned
//! document.
//!
//! The upgrade-acceptance discipline (deployment handbook §8) used to live
//! as a hand-run ritual: same-build-string across five surfaces, serving
//! lineage survived, evictions flat over the steady window — each one a
//! separate ssh + journal grep. This face turns that picture into a single
//! machine-readable document the operator CLI persists (`status snapshot`)
//! and diffs (`status diff`); `doctor link --upgrade-check` renders its
//! verdicts from the same bytes.
//!
//! Why a dedicated endpoint instead of accreting fields on
//! `GET /policy/floor`: the floor query's contract is watermark
//! negotiation (what `PUT /policy` arbitrates against); the snapshot's
//! contract is the fleet's *state* at capture time. Different consumers,
//! different evolution — the snapshot carries an explicit
//! [`FLEET_SNAPSHOT_SCHEMA_VERSION`] and its shape is locked by golden
//! tests, while the floor face stays untouched for the GUI.
//!
//! Identity contract: same as the floor query — a realm-anchored
//! control-plane principal. Agents are data-plane identities and never see
//! another tenant's rows; the operator sees all of them (that is the point
//! of this face).

use crate::hub::state::PolicyChannel;
use crate::hub::state::{CONTROL_TENANT, HubResponseBody, HubState};
use http::{Response, StatusCode};
use interflow_core::error::{InterflowError, Result};
use serde::{Deserialize, Serialize};
use std::sync::atomic::Ordering;

/// The format epoch of [`FleetSnapshotDoc`].
///
/// The SHARED compatibility epoch every Interflow-owned machine format
/// rides ([`interflow_contract::FORMAT_VERSION`]) — never a snapshot-local
/// counter (the version contract's whole point).
///
/// Additive fields (new optional keys) never bump the epoch — serde ignores
/// unknown keys on the client side, so an older CLI reading a newer hub
/// degrades gracefully. A bump means a breaking format change and moves
/// every peer together per the coordinated-upgrade runbook; the client
/// then rejects the document instead of rendering a wrong verdict.
pub const FLEET_SNAPSHOT_FORMAT_VERSION: u8 = interflow_contract::FORMAT_VERSION;

/// Which channel face the currently served policy bundle was loaded from.
///
/// The runtime truth behind the startup line `serving policy gen N (from …)`,
/// kept current (a lineage wipe mid-run flips the origin on the next serve,
/// not just at boot).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ServingSource {
    /// The node-local state channel survived (`<pack>/state/policy`) — the
    /// upgrade contract held.
    StateLineage,
    /// Serving the pack's embedded render — a fresh install, or a lineage
    /// loss (check whether `state/` was expected to survive; a gen ABOVE
    /// the old lineage is a forward move, the warning targets the
    /// low-gen-deadlock shape).
    PackSnapshot,
}

/// One agent's transport on the hub-facing control plane.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SnapshotTransport {
    /// Registered over QUIC (relay streams; skips the h2 heartbeat path —
    /// an all-QUIC fleet legitimately reports `ping=0`).
    Quic,
    /// Registered over h2 (poll long-poll body).
    H2,
}

/// The fleet snapshot document — the wire contract's single authoritative
/// definition (hub and CLI both use this type; golden tests lock the JSON
/// shape).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FleetSnapshotDoc {
    /// See [`FLEET_SNAPSHOT_FORMAT_VERSION`].
    pub format_version: u8,
    /// The hub's own steady state.
    pub hub: FleetSnapshotHub,
    /// Every fleet member (all tenants — operator face), sorted by
    /// qualified agent id: deterministic byte order, so two captures of an
    /// unchanged fleet diff clean.
    pub agents: Vec<FleetSnapshotAgent>,
}

/// The hub half of a [`FleetSnapshotDoc`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FleetSnapshotHub {
    /// The hub's configured node name, when it has one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub node: Option<String>,
    /// The generation the hub actually serves right now (`None` = nothing
    /// servable on disk — the floor handler's `serving` discipline: a
    /// missing key never reads as zero).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub serving_generation: Option<u64>,
    /// The lineage origin of the served bundle (`None` when nothing is
    /// servable). The acceptance question "did the state lineage survive
    /// the upgrade?" reads this, not the boot-time journal line.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub serving_source: Option<ServingSource>,
    /// The anti-rollback floor (includes absorbed remote watermarks).
    #[serde(default)]
    pub floor_generation: u64,
    /// Cumulative evictions that actually landed (voided removals do not
    /// count) — monotonic for the hub process's lifetime. The steady-window
    /// acceptance is "this did not move between two captures".
    pub evicted_total: u64,
    /// The CRL counters the hub's verification plane enforces (`stem →
    /// crl_number`) — the push face's floors. The acceptance question
    /// "did the emergency revocation reach this hub?" reads this, not the
    /// issuer store. Empty on older hubs and non-pack hubs (the additive
    /// tolerance doctrine: a missing key reads as unknown, never as zero).
    #[serde(default, skip_serializing_if = "std::collections::BTreeMap::is_empty")]
    pub crl_numbers: std::collections::BTreeMap<String, u64>,
    /// Unix seconds of THIS hub process's own last successful CRL poll
    /// (the renewal loop's liveness face, self slot) — the local half of
    /// "is the hub's poll loop alive"; the agents' halves ride their rows.
    /// `None` on older hubs and processes without a renewal loop
    /// (non-pack hubs, offline-identity nodes). Additive, no
    /// format-version bump.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub crl_last_success_unix: Option<u64>,
    /// Failed CRL polls since this hub process started (self slot).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub crl_failures_total: Option<u64>,
    /// Unix seconds of the last accepted plane reload (push or pull lane
    /// — their convergence point) — "when did the counters above last
    /// move". `None` on older hubs / before the first reload.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub crl_last_reload_unix: Option<u64>,
    /// The currently-OPEN route breakers (edge gateways only; empty on
    /// plain mesh hubs). A stuck-OPEN entry or a dead recovery loop is
    /// legible from the row instants without any context beyond the doc.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub route_breakers_open: Vec<RouteBreakerOpenRow>,
    /// The resident-task watchdog's rows (the armed-assertion face): every
    /// long-lived hub task with its cadence anchor and last tick. A row
    /// whose `last_tick_unix` is quiet past
    /// [`crate::hub::watchdog::WATCHER_SILENT_FACTOR`] multiples of its
    /// own `interval_secs` (judged against `captured_at_unix`) is a task
    /// wedged while the process keeps serving. Empty on older hubs.
    /// Additive, no format-version bump.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub watchers: Vec<crate::hub::watchdog::WatcherFaceRow>,
    /// The proposals queue's watermark face (decisions awaiting the
    /// operator + the oldest submission's instant). `None` when nothing
    /// is pending or the hub carries no proposal store. Additive, no
    /// format-version bump.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub proposals_pending: Option<crate::hub::proposals::ProposalsPendingFace>,
    /// The hub's currently-admitted streams across all agents (the
    /// session-headroom face's global half). `None` on older hubs.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub streams_in_flight_total: Option<u64>,
    /// The admission caps the headroom face judges against (`0` = the
    /// scope is unlimited). `None` on older hubs. Additive, no
    /// format-version bump.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub stream_limits: Option<StreamLimitsFace>,
    /// The hub-side capture anchor (unix seconds) — the instant this
    /// picture was true, independent of when the operator persisted it.
    /// (Field order keeps the wire shape's historical tail.)
    pub captured_at_unix: i64,
}

/// The admission caps as the snapshot hub row carries them (the
/// headroom judgments' denominators).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct StreamLimitsFace {
    /// `max_streams_total` (0 = unlimited).
    pub total: u64,
    /// `max_streams_per_agent` (0 = unlimited).
    pub per_agent: u64,
}

/// One currently-OPEN route breaker on the answering hub (edge gateways
/// only).
///
/// The host, when it tripped — the open-set face's row material
/// (2026-10-19). An empty list on plain mesh hubs reads "no edge face",
/// the additive-tolerance doctrine as ever.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RouteBreakerOpenRow {
    /// The public host whose route breaker is OPEN.
    pub host: String,
    /// Unix seconds of the trip (the closed→open transition).
    pub opened_unix: u64,
    /// Unix seconds of the last admitted probe/touch — the
    /// dead-recovery-machinery signature when it stops advancing on a
    /// still-open entry.
    pub last_probe_unix: u64,
}

/// One fleet member's row in a [`FleetSnapshotDoc`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FleetSnapshotAgent {
    /// Qualified agent id (`tenant/agent`).
    pub agent: String,
    /// The presence reading (`registered ≠ reachable`, same semantics as
    /// `GET /agents`).
    pub online: bool,
    /// The last policy generation this agent pulled (`None` = no completed
    /// pull since the hub process started). Sourced from the LEVEL
    /// watermark table (every completed pull, not-modified included,
    /// refreshes it) — not the edge audit ledger.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub seen_generation: Option<u64>,
    /// Unix seconds of the agent's last completed pull (`None` = no
    /// completed pull, or an older hub without the field). Together with
    /// [`Self::seen_generation`] this is the level face: "present but
    /// silent" (a watermark that stopped confirming) is legible against
    /// `FleetSnapshotHub::captured_at_unix`. Additive, optional, no
    /// format-version bump.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_pull_unix: Option<u64>,
    /// The registering binary's self-declared build tag (`None` = an older
    /// agent that does not declare one). Upgrade acceptance: every leg the
    /// same string, zero `-dirty`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub build: Option<String>,
    /// The registration's transport (`None` = no live session row; a
    /// ledger-only remembrance of an agent that pulled and was since
    /// evicted).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub transport: Option<SnapshotTransport>,
    /// The current registration's opaque circuit, canonical 32-hex — the
    /// same form as the journal's `circuit=…` lines and the audit ledger,
    /// so a snapshot correlates with both without translation. A changed
    /// circuit across two snapshots = re-registration, not an offline
    /// blip.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub circuit: Option<String>,
    /// The stream names this agent last REPORTED as paused (planned
    /// unavailability, stream-level). `None` = the agent has never
    /// reported; an offline agent keeps its last report (the paused
    /// state matters most exactly while the node is down). Additive,
    /// optional, no format-version bump.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub paused_streams: Option<Vec<String>>,
    /// Whether the node is declared under maintenance (planned
    /// unavailability, node-level: its absence is expected, not an
    /// accident). Additive, optional, no format-version bump.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub maintenance: Option<bool>,
    /// Unix seconds of the node's renewal loop's last successful CRL poll
    /// (its liveness reporter's level). Together with
    /// [`FleetSnapshotHub::captured_at_unix`] this is the level face:
    /// "polling, nothing changed" keeps this advancing; a wedged poll
    /// loop freezes it — legible without any context beyond the doc.
    /// `None` = never reported (or an older hub without the field).
    /// Additive, no format-version bump.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub crl_last_success_unix: Option<u64>,
    /// Failed CRL polls since the node's process started (its reporter's
    /// failure counter — diagnostic material, not the recency trigger).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub crl_failures_total: Option<u64>,
    /// The operator's queued stream ops waiting on this leg (the mailbox
    /// watermark face): count, oldest queued instant + label, and the
    /// cumulative capacity-drop counter. `None` = nothing waiting and
    /// nothing ever dropped. Ages judge against
    /// [`FleetSnapshotHub::captured_at_unix`]. Additive, no
    /// format-version bump.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pending_ops: Option<crate::hub::stream_intents::MailboxFace>,
    /// This agent's currently-admitted hub streams (the session-headroom
    /// face's per-leg half). `None` on older hubs and legs with no
    /// live count. Additive, no format-version bump.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub streams_in_flight: Option<u64>,
    /// The agent's per-stream byte-activity levels (the fossil face:
    /// name, last-byte instant, the rule's own idle budget as the
    /// silence-judgment anchor). Empty on older agents and agents
    /// without mesh stream rules. Additive, no format-version bump.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub streams: Vec<interflow_core::tunnel::transport::NodeStreamActivity>,
    /// The agent's last-seen leaf validity window (the
    /// credential-expiry face): the notBefore/notAfter parsed from the
    /// mTLS chain at registration, retained across eviction — the
    /// countdown's target is absolute, offline legs keep counting.
    /// Additive, no format-version bump.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub leaf_not_before_unix: Option<i64>,
    /// See [`Self::leaf_not_before_unix`].
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub leaf_not_after_unix: Option<i64>,
    /// The tier the window's span implies (`registrar` / `offline` —
    /// the legal TTL bands are disjoint). Additive.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub credential_mode: Option<String>,
    /// Unix seconds of the registration that last presented this window
    /// (staleness material; the window itself never goes stale).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub credential_last_seen_unix: Option<u64>,
    /// The connection-quality window stats (reconnects per hour, liveness
    /// RTT p50/p99, probe timeouts) — the engine's supervisor domain,
    /// shipped on the node-status report. `None` on older agents.
    /// Additive, no format-version bump.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub connection: Option<interflow_core::tunnel::transport::ConnectionQualityWire>,
    /// The renewal backoff ladder's current stage (consecutive failed
    /// renewal attempts, 0 = none) — rides the CRL-liveness report.
    /// Additive.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub renewal_backoff_failures: Option<u32>,
    /// The stage's observed maximum today (UTC day rollover).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub renewal_backoff_max_today: Option<u32>,
}

/// What the registry walk reads per live session (extracted under the
/// session read lock; the merge itself is pure).
pub(crate) struct SessionRow {
    /// Qualified agent id.
    pub agent: String,
    /// The presence reading at capture.
    pub online: bool,
    /// The session's self-declared build tag.
    pub build: Option<String>,
    /// The session's transport.
    pub transport: SnapshotTransport,
    /// The session's circuit (32-hex).
    pub circuit: String,
}

/// Merges the registry walk with the level watermark table: a registry row
/// carries its session fields; a watermark-only agent (pulled, then evicted
/// without re-registering) survives as a row with no session fields — its
/// watermark is still fleet history, and its absence from the registry is
/// itself a diffable fact. Sorted by qualified id for stable output.
pub(crate) fn merge_agent_rows(
    sessions: Vec<SessionRow>,
    watermarks: &std::collections::BTreeMap<String, crate::hub::policy_watermarks::PolicyWatermark>,
    paused_face: &crate::hub::stream_intents::StreamIntents,
    maintenance: &crate::hub::maintenance::MaintenanceLedger,
    crl_face: &std::collections::BTreeMap<String, crate::hub::crl_liveness::CrlLivenessRow>,
    stream_counts: &std::collections::HashMap<String, usize>,
    node_status: &std::collections::BTreeMap<String, crate::hub::node_status::NodeStatusRow>,
    credentials: &std::collections::BTreeMap<
        String,
        crate::hub::credential_watermarks::CredentialWatermark,
    >,
) -> Vec<FleetSnapshotAgent> {
    let maintenance_face = maintenance.face();
    let mut rows: Vec<FleetSnapshotAgent> = sessions
        .into_iter()
        .map(|s| FleetSnapshotAgent {
            paused_streams: paused_face.face(&s.agent),
            maintenance: maintenance_face.get(&s.agent).map(|_| true),
            pending_ops: paused_face.mailbox_face(&s.agent),
            agent: s.agent,
            online: s.online,
            seen_generation: None,
            last_pull_unix: None,
            build: s.build,
            transport: Some(s.transport),
            circuit: Some(s.circuit),
            crl_last_success_unix: None,
            crl_failures_total: None,
            streams_in_flight: None,
            streams: Vec::new(),
            leaf_not_before_unix: None,
            leaf_not_after_unix: None,
            credential_mode: None,
            credential_last_seen_unix: None,
            connection: None,
            renewal_backoff_failures: None,
            renewal_backoff_max_today: None,
        })
        .collect();
    for (agent, watermark) in watermarks {
        match rows.iter_mut().find(|r| &r.agent == agent) {
            Some(row) => {
                row.seen_generation = Some(watermark.seen_generation);
                row.last_pull_unix = Some(watermark.last_pull_unix);
            }
            None => rows.push(FleetSnapshotAgent {
                agent: agent.clone(),
                online: false,
                seen_generation: Some(watermark.seen_generation),
                last_pull_unix: Some(watermark.last_pull_unix),
                build: None,
                transport: None,
                circuit: None,
                // Watermark-only remembrance: an agent absent from the
                // registry keeps its last reported faces (the planned
                // unavailability is the story exactly then).
                paused_streams: paused_face.face(agent),
                maintenance: maintenance_face.get(agent).map(|_| true),
                crl_last_success_unix: None,
                crl_failures_total: None,
                pending_ops: paused_face.mailbox_face(agent),
                streams_in_flight: None,
                streams: Vec::new(),
                leaf_not_before_unix: None,
                leaf_not_after_unix: None,
                credential_mode: None,
                credential_last_seen_unix: None,
                connection: None,
                renewal_backoff_failures: None,
                renewal_backoff_max_today: None,
            }),
        }
    }
    // The liveness face merges over whatever rows exist (registry,
    // watermark-only) and a CRL-only reporter — an agent whose reporter
    // landed before its first completed policy pull — keeps its own
    // remembrance row, same doctrine as the watermark-only one.
    for (agent, crl) in crl_face {
        match rows.iter_mut().find(|r| &r.agent == agent) {
            Some(row) => {
                row.crl_last_success_unix = Some(crl.last_success_unix);
                row.crl_failures_total = Some(crl.failures_total);
                row.pending_ops = paused_face.mailbox_face(agent);
                row.renewal_backoff_failures = Some(crl.renewal_backoff_failures);
                row.renewal_backoff_max_today = Some(crl.renewal_backoff_max_today);
            }
            None => rows.push(FleetSnapshotAgent {
                agent: agent.clone(),
                online: false,
                seen_generation: None,
                last_pull_unix: None,
                build: None,
                transport: None,
                circuit: None,
                paused_streams: paused_face.face(agent),
                maintenance: maintenance_face.get(agent).map(|_| true),
                crl_last_success_unix: Some(crl.last_success_unix),
                crl_failures_total: Some(crl.failures_total),
                renewal_backoff_failures: Some(crl.renewal_backoff_failures),
                renewal_backoff_max_today: Some(crl.renewal_backoff_max_today),
                pending_ops: paused_face.mailbox_face(agent),
                streams_in_flight: None,
                streams: Vec::new(),
                leaf_not_before_unix: None,
                leaf_not_after_unix: None,
                credential_mode: None,
                credential_last_seen_unix: None,
                connection: None,
            }),
        }
    }
    // The node-status face merges the same way (a reporter that landed
    // before any completed pull keeps its own remembrance row) — and the
    // per-row fills (in-flight count from the hub's admission table,
    // stream-activity levels from the latest report) apply to every row
    // that exists by now.
    for (agent, status) in node_status {
        if !rows.iter().any(|r| &r.agent == agent) {
            rows.push(FleetSnapshotAgent {
                agent: agent.clone(),
                online: false,
                seen_generation: None,
                last_pull_unix: None,
                build: None,
                transport: None,
                circuit: None,
                paused_streams: paused_face.face(agent),
                maintenance: maintenance_face.get(agent).map(|_| true),
                crl_last_success_unix: None,
                crl_failures_total: None,
                pending_ops: paused_face.mailbox_face(agent),
                streams_in_flight: None,
                streams: status.streams.clone(),
                leaf_not_before_unix: None,
                leaf_not_after_unix: None,
                credential_mode: None,
                credential_last_seen_unix: None,
                connection: None,
                renewal_backoff_failures: None,
                renewal_backoff_max_today: None,
            });
        }
    }
    for row in &mut rows {
        row.streams_in_flight = stream_counts
            .get(&row.agent)
            .map(|count| u64::try_from(*count).unwrap_or(u64::MAX));
        if let Some(status) = node_status.get(&row.agent) {
            row.streams = status.streams.clone();
            row.connection = status.connection;
        }
        if let Some(window) = credentials.get(&row.agent) {
            row.leaf_not_before_unix = Some(window.not_before_unix);
            row.leaf_not_after_unix = Some(window.not_after_unix);
            row.credential_mode = Some(
                crate::hub::credential_watermarks::tier_from_span(
                    window.not_after_unix - window.not_before_unix,
                )
                .to_owned(),
            );
            row.credential_last_seen_unix = Some(window.last_seen_unix);
        }
    }
    // A credential-only remembrance row: an agent evicted before any
    // pull/report still carries its countdown (the expiry question is
    // most urgent exactly for legs that went dark).
    for (agent, window) in credentials {
        if !rows.iter().any(|r| &r.agent == agent) {
            rows.push(FleetSnapshotAgent {
                agent: agent.clone(),
                online: false,
                seen_generation: None,
                last_pull_unix: None,
                build: None,
                transport: None,
                circuit: None,
                paused_streams: paused_face.face(agent),
                maintenance: maintenance_face.get(agent).map(|_| true),
                crl_last_success_unix: None,
                crl_failures_total: None,
                pending_ops: paused_face.mailbox_face(agent),
                streams_in_flight: None,
                streams: Vec::new(),
                leaf_not_before_unix: Some(window.not_before_unix),
                leaf_not_after_unix: Some(window.not_after_unix),
                credential_mode: Some(
                    crate::hub::credential_watermarks::tier_from_span(
                        window.not_after_unix - window.not_before_unix,
                    )
                    .to_owned(),
                ),
                credential_last_seen_unix: Some(window.last_seen_unix),
                connection: None,
                renewal_backoff_failures: None,
                renewal_backoff_max_today: None,
            });
        }
    }
    rows.sort_by(|a, b| a.agent.cmp(&b.agent));
    rows
}

/// Maps the serve cache's loaded-from directory onto the lineage origin.
/// Pure so the classification is unit-testable without a live channel.
pub(crate) fn classify_serving_origin(
    state_dir: &std::path::Path,
    embedded_dir: &std::path::Path,
    loaded_from: &std::path::Path,
) -> ServingSource {
    if loaded_from == embedded_dir && embedded_dir != state_dir {
        ServingSource::PackSnapshot
    } else {
        ServingSource::StateLineage
    }
}

/// The serving generation plus its lineage origin, straight from the
/// channel's serve cache (warmed if no pull has populated it yet — one
/// fingerprint check, the same two stats a steady-state pull pays).
pub(crate) fn serving_generation_and_origin(
    channel: &PolicyChannel,
) -> Option<(u64, ServingSource)> {
    crate::hub::policy::serve_cached(channel)?;
    let guard = channel
        .cached
        .read()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let cached = guard.as_ref()?;
    Some((
        cached.generation,
        classify_serving_origin(&channel.dir, &channel.embedded_dir, &cached.dir),
    ))
}

/// The registered route-breaker face's open rows (empty on plain mesh
/// hubs and edges with the breaker disabled) — the snapshot hub row's
/// source, sorted by host for stable output.
fn route_breaker_face_rows(state: &HubState) -> Vec<RouteBreakerOpenRow> {
    let guard = state
        .route_breaker_face
        .read()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    match guard.as_ref() {
        Some(face) => {
            let mut rows: Vec<RouteBreakerOpenRow> = face
                .snapshot()
                .into_iter()
                .map(|row| RouteBreakerOpenRow {
                    host: row.target,
                    opened_unix: row.opened_unix,
                    last_probe_unix: row.last_probe_unix,
                })
                .collect();
            rows.sort_by(|a, b| a.host.cmp(&b.host));
            rows
        }
        None => Vec::new(),
    }
}

/// Assembles the document from live hub state. Deterministic: same state,
/// same bytes (modulo the capture timestamp).
pub(crate) async fn assemble_fleet_snapshot(state: &HubState) -> FleetSnapshotDoc {
    let node = state.config.read().await.server.node_name.clone();
    let (floor_generation, serving) = match &state.policy_channel {
        Some(channel) => (
            channel.floor.load(Ordering::Acquire),
            serving_generation_and_origin(channel),
        ),
        None => (0, None),
    };
    let (serving_generation, serving_source) = match serving {
        Some((generation, source)) => (Some(generation), Some(source)),
        None => (None, None),
    };
    let sessions = {
        let registry = state.agents.read().await;
        let mut rows = Vec::with_capacity(registry.len());
        for (key, session) in registry.iter() {
            let st = session.read().await;
            rows.push(SessionRow {
                agent: key.clone(),
                online: st.online(),
                build: st.build.clone(),
                transport: if st.quic.is_some() {
                    SnapshotTransport::Quic
                } else {
                    SnapshotTransport::H2
                },
                circuit: st.circuit.to_hex(),
            });
        }
        rows
    };
    let watermarks = state.policy_watermarks.face();
    let crl_liveness = state.crl_liveness.face();
    let crl_self = state.crl_liveness.self_face();
    let node_status = state.node_status.face();
    let credentials = state.credential_watermarks.face();
    let stream_counts = state
        .stream_counts
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .clone();
    // Planned-unavailability faces ride the snapshot even for agents the
    // registry lost (watermark-only rows below keep their last report).
    let intents_face = state.stream_intents.clone();
    let maintenance = state.maintenance.clone();
    FleetSnapshotDoc {
        format_version: FLEET_SNAPSHOT_FORMAT_VERSION,
        hub: FleetSnapshotHub {
            node,
            serving_generation,
            serving_source,
            floor_generation,
            evicted_total: state.evicted_total.load(Ordering::Acquire),
            crl_numbers: state
                .crl_channel
                .as_ref()
                .map_or_else(std::collections::BTreeMap::new, |channel| channel.numbers()),
            crl_last_success_unix: crl_self.map(|row| row.last_success_unix),
            crl_failures_total: crl_self.map(|row| row.failures_total),
            crl_last_reload_unix: state
                .crl_channel
                .as_ref()
                .map(|channel| channel.last_reload_unix())
                .filter(|unix| *unix != 0),
            route_breakers_open: route_breaker_face_rows(state),
            watchers: state.watchdog.face_rows(),
            proposals_pending: state.proposals.as_ref().and_then(|p| p.pending_face()),
            streams_in_flight_total: Some(
                u64::try_from(stream_counts.values().sum::<usize>()).unwrap_or(u64::MAX),
            ),
            stream_limits: Some(StreamLimitsFace {
                total: state
                    .limits
                    .max_streams_total
                    .load(std::sync::atomic::Ordering::Relaxed) as u64,
                per_agent: state
                    .limits
                    .max_streams_per_agent
                    .load(std::sync::atomic::Ordering::Relaxed) as u64,
            }),
            captured_at_unix: interflow_identity::expiry::now_unix(),
        },
        agents: merge_agent_rows(
            sessions,
            &watermarks,
            &intents_face,
            &maintenance,
            &crl_liveness,
            &stream_counts,
            &node_status,
            &credentials,
        ),
    }
}

impl crate::hub::service::HubService {
    /// `GET /snapshot` — see the module docs. Control-principal gated
    /// (the floor query's mirror); denials are plain status answers.
    pub(crate) async fn handle_fleet_snapshot(&self) -> Result<Response<HubResponseBody>> {
        let Some(identity) = self.identity().await else {
            return Ok(super::service::text_response(
                StatusCode::UNAUTHORIZED,
                "Client certificate required",
            ));
        };
        if identity.tenant.as_ref() != CONTROL_TENANT {
            return Ok(super::service::text_response(
                StatusCode::FORBIDDEN,
                "fleet snapshot requires a control-plane principal (realm-anchored)",
            ));
        }
        let doc = assemble_fleet_snapshot(&self.state).await;
        let body = serde_json::to_string(&doc).map_err(|e| {
            InterflowError::protocol("fleet snapshot serialization failed".to_string())
                .with_source(e)
        })?;
        Ok(super::service::json_response(StatusCode::OK, body))
    }
}

// ---------------------------------------------------------------------------
// Client (operator CLI side)
// ---------------------------------------------------------------------------

/// Queries a hub's fleet snapshot (`GET /snapshot`) — the steady-state
/// document [`status snapshot`](interflow_cli) persists and diffs.
///
/// Same credential discipline as the floor query (a freshly minted
/// control credential), one-shot, 10s-bounded. A 404 is reported as an
/// explicit "this hub predates the face" error — the caller should not
/// fall back to guessing the picture from journal lines.
pub async fn query_fleet_snapshot(
    hub_endpoint: &str,
    ca_path: &std::path::Path,
    client_cert_path: &std::path::Path,
    client_key_path: &std::path::Path,
) -> Result<FleetSnapshotDoc> {
    use http_body_util::BodyExt;

    let future = async {
        let mut send_request = crate::hub::policy::control_plane_dial(
            hub_endpoint,
            crate::hub::policy::ServerTrust::Ca(ca_path),
            client_cert_path,
            client_key_path,
        )
        .await?;
        let request = hyper::Request::builder()
            .method(hyper::Method::GET)
            .uri("/snapshot")
            .body(
                http_body_util::Full::<bytes::Bytes>::new(bytes::Bytes::new())
                    .map_err(|never| match never {})
                    .boxed(),
            )
            .map_err(|e| {
                InterflowError::protocol("fleet snapshot query build".to_string()).with_source(e)
            })?;
        let response = send_request.send_request(request).await?;
        let status = response.status();
        let collected = BodyExt::collect(response.into_body()).await.map_err(|e| {
            InterflowError::protocol("fleet snapshot query body".to_string()).with_source(e)
        })?;
        let text = String::from_utf8_lossy(&collected.to_bytes()).to_string();
        if status == StatusCode::NOT_FOUND {
            return Err(InterflowError::connection(format!(
                "hub {hub_endpoint} does not carry the fleet-snapshot face — upgrade the hub \
                 before using snapshot-based tooling"
            )));
        }
        if status != StatusCode::OK {
            return Err(InterflowError::connection(format!(
                "fleet snapshot query rejected: {status} — {text}"
            )));
        }
        let doc: FleetSnapshotDoc = serde_json::from_str(&text).map_err(|e| {
            InterflowError::protocol(format!(
                "fleet snapshot 200 with an unparseable body: {e} — {text:?}"
            ))
        })?;
        if doc.format_version != FLEET_SNAPSHOT_FORMAT_VERSION {
            return Err(InterflowError::protocol(format!(
                "fleet snapshot format epoch {} is not the supported {} — this CLI and the \
                 hub come from different format epochs; align the two before trusting the diff",
                doc.format_version, FLEET_SNAPSHOT_FORMAT_VERSION
            )));
        }
        Ok(doc)
    };
    tokio::time::timeout(std::time::Duration::from_secs(10), future)
        .await
        .map_err(|_| {
            InterflowError::connection(
                "fleet snapshot query timed out (>10s) — is the mesh hub reachable?".to_string(),
            )
        })?
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    /// A registry row keeps its session fields and picks up its level
    /// watermark; a watermark-only agent survives without session fields;
    /// output is sorted by qualified id.
    #[test]
    fn merge_registry_with_watermarks() {
        let sessions = vec![
            SessionRow {
                agent: "main/lan-b".to_owned(),
                online: true,
                build: Some("2026-10-12_bf11cd8".to_owned()),
                transport: SnapshotTransport::Quic,
                circuit: "b".repeat(32),
            },
            SessionRow {
                agent: "main/lan-a".to_owned(),
                online: false,
                build: None,
                transport: SnapshotTransport::H2,
                circuit: "a".repeat(32),
            },
        ];
        let watermarks = std::collections::BTreeMap::from([
            (
                "main/lan-a".to_owned(),
                crate::hub::policy_watermarks::PolicyWatermark {
                    seen_generation: 15,
                    last_pull_unix: 1_760_000_000,
                },
            ),
            (
                "main/lan-gone".to_owned(),
                crate::hub::policy_watermarks::PolicyWatermark {
                    seen_generation: 14,
                    last_pull_unix: 1_759_999_000,
                },
            ),
        ]);
        let rows = merge_agent_rows(
            sessions,
            &watermarks,
            &crate::hub::stream_intents::StreamIntents::new(
                crate::hub::floor_clock::FloorClock::new(),
            ),
            &crate::hub::maintenance::MaintenanceLedger::load(
                None,
                crate::hub::floor_clock::FloorClock::new(),
            ),
            &std::collections::BTreeMap::new(),
            &std::collections::HashMap::new(),
            &std::collections::BTreeMap::new(),
            &std::collections::BTreeMap::new(),
        );

        assert_eq!(
            rows.iter().map(|r| r.agent.as_str()).collect::<Vec<_>>(),
            vec!["main/lan-a", "main/lan-b", "main/lan-gone"],
            "sorted, registry ∪ watermarks"
        );
        let lan_a = &rows[0];
        assert_eq!(
            (
                lan_a.online,
                lan_a.seen_generation,
                lan_a.last_pull_unix,
                lan_a.transport
            ),
            (
                false,
                Some(15),
                Some(1_760_000_000),
                Some(SnapshotTransport::H2)
            )
        );
        let lan_b = &rows[1];
        assert_eq!(
            (lan_b.seen_generation, lan_b.last_pull_unix),
            (None, None),
            "never pulled: no watermark, no confirmation instant"
        );
        let gone = &rows[2];
        assert_eq!(
            (
                gone.online,
                gone.seen_generation,
                gone.last_pull_unix,
                gone.circuit.as_deref(),
                gone.transport
            ),
            (false, Some(14), Some(1_759_999_000), None, None),
            "watermark-only remembrance: no session fields"
        );
    }

    /// The origin classification: loaded from the embedded dir = pack
    /// snapshot; anything else (including a shared-dir config, where the
    /// two faces coincide) = state lineage.
    #[test]
    fn serving_origin_classification() {
        let state_dir = std::path::Path::new("/pack/state/policy");
        let embedded_dir = std::path::Path::new("/pack/policy");
        assert_eq!(
            classify_serving_origin(state_dir, embedded_dir, state_dir),
            ServingSource::StateLineage
        );
        assert_eq!(
            classify_serving_origin(state_dir, embedded_dir, embedded_dir),
            ServingSource::PackSnapshot
        );
        let same = std::path::Path::new("/pack/policy");
        assert_eq!(
            classify_serving_origin(same, same, same),
            ServingSource::StateLineage,
            "coincident faces cannot be a lineage loss"
        );
    }

    /// The wire shape is a contract: lock it byte-for-byte so an accidental
    /// rename or reordering surfaces here, not in a downstream verdict.
    #[test]
    fn wire_shape_is_locked() {
        let doc = FleetSnapshotDoc {
            format_version: 1,
            hub: FleetSnapshotHub {
                node: Some("promptcn".to_owned()),
                serving_generation: Some(15),
                serving_source: Some(ServingSource::StateLineage),
                floor_generation: 15,
                evicted_total: 0,
                crl_numbers: std::collections::BTreeMap::from([
                    ("control".to_owned(), 4u64),
                    ("workspace-main".to_owned(), 4u64),
                ]),
                crl_last_success_unix: Some(1_760_000_020),
                crl_failures_total: Some(2),
                crl_last_reload_unix: Some(1_760_000_005),
                route_breakers_open: vec![RouteBreakerOpenRow {
                    host: "web.test".to_owned(),
                    opened_unix: 1_760_000_007,
                    last_probe_unix: 1_760_000_012,
                }],
                watchers: vec![
                    crate::hub::watchdog::WatcherFaceRow {
                        name: "heartbeat".to_owned(),
                        interval_secs: 15,
                        started_unix: 1_760_000_000,
                        last_tick_unix: 1_760_000_010,
                    },
                    crate::hub::watchdog::WatcherFaceRow {
                        name: "renewal".to_owned(),
                        interval_secs: 60,
                        started_unix: 1_760_000_000,
                        last_tick_unix: 1_760_000_005,
                    },
                ],
                proposals_pending: Some(crate::hub::proposals::ProposalsPendingFace {
                    pending_count: 2,
                    oldest_submitted_unix: 1_760_000_003,
                }),
                streams_in_flight_total: Some(47),
                stream_limits: Some(StreamLimitsFace {
                    total: 100_000,
                    per_agent: 256,
                }),
                captured_at_unix: 1_760_000_000,
            },
            agents: vec![FleetSnapshotAgent {
                agent: "main/lan-a".to_owned(),
                online: true,
                seen_generation: Some(15),
                last_pull_unix: Some(1_760_000_010),
                build: Some("2026-10-12_bf11cd8".to_owned()),
                transport: Some(SnapshotTransport::Quic),
                circuit: Some("ab".repeat(16)),
                paused_streams: Some(vec!["ollama-compat".to_owned()]),
                maintenance: None,
                crl_last_success_unix: Some(1_760_000_030),
                crl_failures_total: Some(0),
                pending_ops: Some(crate::hub::stream_intents::MailboxFace {
                    pending_count: 1,
                    oldest_queued_unix: Some(1_760_000_008),
                    oldest_op: Some("pause ollama-compat".to_owned()),
                    dropped_total: 0,
                }),
                streams_in_flight: Some(3),
                streams: vec![interflow_core::tunnel::transport::NodeStreamActivity {
                    name: "ollama-compat".to_owned(),
                    last_byte_unix: 1_760_000_020,
                    idle_budget_secs: Some(300),
                }],
                leaf_not_before_unix: Some(1_759_100_000),
                leaf_not_after_unix: Some(1_760_100_000),
                credential_mode: Some("offline".to_owned()),
                credential_last_seen_unix: Some(1_760_000_005),
                connection: Some(interflow_core::tunnel::transport::ConnectionQualityWire {
                    reconnects_last_hour: 0,
                    rtt_p50_ms: Some(105),
                    rtt_p99_ms: Some(190),
                    rtt_timeouts: 0,
                    rtt_samples: 12,
                }),
                renewal_backoff_failures: Some(0),
                renewal_backoff_max_today: Some(0),
            }],
        };
        let json = serde_json::to_string_pretty(&doc).unwrap();
        let golden = r#"{
  "format_version": 1,
  "hub": {
    "node": "promptcn",
    "serving_generation": 15,
    "serving_source": "state_lineage",
    "floor_generation": 15,
    "evicted_total": 0,
    "crl_numbers": {
      "control": 4,
      "workspace-main": 4
    },
    "crl_last_success_unix": 1760000020,
    "crl_failures_total": 2,
    "crl_last_reload_unix": 1760000005,
    "route_breakers_open": [
      {
        "host": "web.test",
        "opened_unix": 1760000007,
        "last_probe_unix": 1760000012
      }
    ],
    "watchers": [
      {
        "name": "heartbeat",
        "interval_secs": 15,
        "started_unix": 1760000000,
        "last_tick_unix": 1760000010
      },
      {
        "name": "renewal",
        "interval_secs": 60,
        "started_unix": 1760000000,
        "last_tick_unix": 1760000005
      }
    ],
    "proposals_pending": {
      "pending_count": 2,
      "oldest_submitted_unix": 1760000003
    },
    "streams_in_flight_total": 47,
    "stream_limits": {
      "total": 100000,
      "per_agent": 256
    },
    "captured_at_unix": 1760000000
  },
  "agents": [
    {
      "agent": "main/lan-a",
      "online": true,
      "seen_generation": 15,
      "last_pull_unix": 1760000010,
      "build": "2026-10-12_bf11cd8",
      "transport": "quic",
      "circuit": "abababababababababababababababab",
      "paused_streams": [
        "ollama-compat"
      ],
      "crl_last_success_unix": 1760000030,
      "crl_failures_total": 0,
      "pending_ops": {
        "pending_count": 1,
        "oldest_queued_unix": 1760000008,
        "oldest_op": "pause ollama-compat",
        "dropped_total": 0
      },
      "streams_in_flight": 3,
      "streams": [
        {
          "name": "ollama-compat",
          "last_byte_unix": 1760000020,
          "idle_budget_secs": 300
        }
      ],
      "leaf_not_before_unix": 1759100000,
      "leaf_not_after_unix": 1760100000,
      "credential_mode": "offline",
      "credential_last_seen_unix": 1760000005,
      "connection": {
        "reconnects_last_hour": 0,
        "rtt_p50_ms": 105,
        "rtt_p99_ms": 190,
        "rtt_timeouts": 0,
        "rtt_samples": 12
      },
      "renewal_backoff_failures": 0,
      "renewal_backoff_max_today": 0
    }
  ]
}"#;
        assert_eq!(json, golden, "the wire shape is a contract");
        // And the round trip is lossless.
        let back: FleetSnapshotDoc = serde_json::from_str(&json).unwrap();
        assert_eq!(back, doc);
    }

    /// Additive evolution: unknown keys from a newer hub are ignored, and
    /// omitted optional fields default — an older-hub document (no node,
    /// no serving face, a ledger-only row) still parses.
    #[test]
    fn parse_tolerates_newer_and_older_shapes() {
        let newer = r#"{
            "format_version": 1,
            "hub": {"floor_generation": 7, "evicted_total": 2, "captured_at_unix": 5, "some_future_field": true},
            "agents": [{"agent": "main/x", "online": false, "yet_another_future_field": []}]
        }"#;
        let doc: FleetSnapshotDoc = serde_json::from_str(newer).unwrap();
        assert_eq!(doc.hub.floor_generation, 7);
        assert_eq!(doc.hub.serving_generation, None);
        assert!(
            doc.hub.crl_numbers.is_empty(),
            "an older hub reports no CRL face"
        );
        assert_eq!(doc.agents[0].circuit, None);
        assert_eq!(
            doc.agents[0].last_pull_unix, None,
            "an older hub reports no confirmation instant — recency unjudgeable, not zero"
        );
        assert!(
            doc.hub.watchers.is_empty(),
            "an older hub reports no watchdog face — unjudgeable, not all-armed"
        );
    }
}
