//! `interflow-cli status` — the fleet's steady-state picture: capture it,
//! persist it, diff it
//!
//! Every upgrade's acceptance used to be a hand-run ritual — per-leg ssh +
//! journal grep for build strings, serving lineage, evictions. The
//! capture/diff pair here turns that ritual into two files and one
//! command:
//!
//! - `status snapshot` fetches the hub's `GET /snapshot` document and
//!   persists it (an envelope: the wire document + the capturing CLI's
//!   own build + the hub endpoint — the upgrade log's machine-readable
//!   attachment);
//! - `status diff <old> <new>` renders what moved between two captures:
//!   per-leg build changes, generation continuity and lineage origin,
//!   presence/transport moves, re-registrations (circuit rotation, not
//!   offline blips), evictions.
//!
//! `doctor link --upgrade-check` renders its verdicts from the same
//! comparison core ([`compare`]).

use clap::Subcommand;
use interflow_cli::outln;
use interflow_mesh::hub::snapshot::{
    FLEET_SNAPSHOT_FORMAT_VERSION, FleetSnapshotDoc, ServingSource, SnapshotTransport,
};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

#[derive(Subcommand)]
pub enum StatusCommand {
    /// Capture the fleet's steady state from the running hub and persist
    /// it (upgrade acceptance starts with a picture from BEFORE).
    Snapshot {
        /// Manifest describing the deployment (names the hub endpoint).
        #[arg(long, default_value = "interflow.toml")]
        manifest: PathBuf,
        /// Issuer store directory (operator machine only).
        #[arg(long, default_value = "issuer")]
        issuer: PathBuf,
        /// Write the snapshot here (pretty JSON); omit to print it to
        /// stdout instead.
        #[arg(long)]
        out: Option<PathBuf>,
    },
    /// Render what moved between two captured snapshots — the upgrade
    /// acceptance reading (build changes, generation continuity, presence,
    /// re-registrations, evictions).
    Diff {
        /// The earlier snapshot file (`status snapshot --out …`).
        old: PathBuf,
        /// The later snapshot file.
        new: PathBuf,
        /// Emit the structured diff as JSON instead of the human reading.
        #[arg(long)]
        json: bool,
    },
}

/// The persisted capture: the wire document plus the local context of the
/// machine that took it. `cli_build` is one of the fleet's build surfaces
/// in its own right — a snapshot taken ON a leg machine records that leg's
/// running binary alongside the hub-side picture.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SnapshotFile {
    /// The captured document (schema-versioned wire contract).
    pub snapshot: FleetSnapshotDoc,
    /// The capturing CLI's own build tag (`<semver> (<date>_<hash>…)`).
    pub cli_build: String,
    /// The hub endpoint the document was captured from.
    pub hub_endpoint: String,
}

impl StatusCommand {
    pub fn run(self) -> interflow_core::error::Result<()> {
        match self {
            Self::Snapshot {
                manifest,
                issuer,
                out,
            } => run_snapshot(&manifest, &issuer, out.as_deref()),
            Self::Diff { old, new, json } => run_diff(&old, &new, json),
        }
    }
}

fn run_snapshot(
    manifest: &Path,
    issuer: &Path,
    out: Option<&Path>,
) -> interflow_core::error::Result<()> {
    let Some((endpoint, doc)) = interflow_cli::plan::with_hub_control_credential(
        manifest,
        issuer,
        |ep, ca, cert, key| async move {
            interflow_mesh::hub::snapshot::query_fleet_snapshot(&ep, &ca, &cert, &key).await
        },
    )?
    else {
        return Err(interflow_core::error::InterflowError::config(format!(
            "manifest {} names no hub endpoint — nothing to capture",
            manifest.display()
        )));
    };
    let file = SnapshotFile {
        cli_build: interflow_buildinfo::VERSION_WITH_TAG.to_owned(),
        hub_endpoint: endpoint,
        snapshot: doc,
    };
    let json = serde_json::to_string_pretty(&file).map_err(|e| {
        interflow_core::error::InterflowError::protocol("snapshot serialization".to_string())
            .with_source(e)
    })?;
    match out {
        Some(path) => {
            std::fs::write(path, format!("{json}\n"))?;
            outln!("✔ snapshot written: {}", path.display());
            outln!(
                "  format epoch {} · {} leg(s)",
                file.snapshot.format_version,
                file.snapshot.agents.len()
            );
        }
        None => println!("{json}"),
    }
    Ok(())
}

fn run_diff(old: &Path, new: &Path, json: bool) -> interflow_core::error::Result<()> {
    let old = load_snapshot_file(old)?;
    let new = load_snapshot_file(new)?;
    let diff = compare(&old.snapshot, &new.snapshot);
    if json {
        let text = serde_json::to_string_pretty(&diff).map_err(|e| {
            interflow_core::error::InterflowError::protocol("diff serialization".to_string())
                .with_source(e)
        })?;
        println!("{text}");
    } else {
        print!("{}", render_diff_text(&diff));
    }
    Ok(())
}

fn load_snapshot_file(path: &Path) -> interflow_core::error::Result<SnapshotFile> {
    let text = std::fs::read_to_string(path).map_err(|e| {
        interflow_core::error::InterflowError::config(format!(
            "read snapshot {}: {}",
            path.display(),
            e
        ))
    })?;
    let file: SnapshotFile = serde_json::from_str(&text).map_err(|e| {
        interflow_core::error::InterflowError::config(format!(
            "parse snapshot {} as a status-snapshot file: {e} — capture it with \
             `interflow-cli status snapshot`",
            path.display()
        ))
    })?;
    if file.snapshot.format_version != FLEET_SNAPSHOT_FORMAT_VERSION {
        return Err(interflow_core::error::InterflowError::config(format!(
            "snapshot {} carries format epoch {} — this CLI reads {}; the file and the CLI \
             come from different format epochs",
            path.display(),
            file.snapshot.format_version,
            FLEET_SNAPSHOT_FORMAT_VERSION
        )));
    }
    Ok(file)
}

// ---------------------------------------------------------------------------
// The comparison core — pure facts, shared with `doctor link
// --upgrade-check` (which layers verdicts on top).
// ---------------------------------------------------------------------------

/// How one leg's presence changed between the captures.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PresenceChange {
    /// In both, online throughout.
    Online,
    /// In both, offline throughout.
    Offline,
    /// Was online, reads offline now.
    WentOffline,
    /// Was offline, reads online now.
    CameOnline,
    /// Only in the new capture (joined the fleet / first registration).
    Joined,
    /// Only in the old capture (evicted without re-registering).
    Departed,
}

/// One leg's row in a [`SnapshotDiff`]: only the MOVES are populated —
/// unchanged fields stay `None`/false so a diff reads at a glance.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AgentDiff {
    /// Qualified agent id.
    pub agent: String,
    /// Presence move between the captures.
    pub presence: PresenceChange,
    /// Build-string change (`None` = unchanged or unknown on both sides).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub build_change: Option<BuildChange>,
    /// The leg's build string in the NEWER capture (`None` = not present
    /// there, or an older agent that does not declare) — the summary's
    /// same-string reading works off this, not off the changes.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub build_now: Option<String>,
    /// Transport move (`None` = unchanged).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub transport_change: Option<TransportChange>,
    /// The circuit token rotated while the leg stayed — the
    /// re-registration signature (NOT an offline blip: a leg that dropped
    /// and returned as a new circuit is fleet churn the acceptance must
    /// name, per the §10.8 re-registration case).
    pub circuit_rotated: bool,
    /// Pulled-watermark move (`None` = unchanged).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub seen_change: Option<SeenChange>,
    /// Whether the leg reads online in the newer capture.
    pub online_now: bool,
}

/// A build-string move; either side may be `None` (an older agent that
/// does not declare, or a leg that lost its live session row).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BuildChange {
    /// The old capture's build string.
    pub from: Option<String>,
    /// The new capture's build string.
    pub to: Option<String>,
}

/// A transport move (an h2 leg that re-registered over QUIC, or back).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct TransportChange {
    /// The old capture's transport.
    pub from: SnapshotTransport,
    /// The new capture's transport.
    pub to: SnapshotTransport,
}

/// A pulled-watermark move.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct SeenChange {
    /// The old capture's watermark (None = never pulled at that time).
    pub from: Option<u64>,
    /// The new capture's watermark.
    pub to: Option<u64>,
}

/// The hub half of a [`SnapshotDiff`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct HubDiff {
    /// Serving generation in the old capture (`None` = the hub could not
    /// report it then).
    pub serving_from: Option<u64>,
    /// Serving generation in the new capture.
    pub serving_to: Option<u64>,
    /// Lineage origin in the old capture.
    pub source_from: Option<ServingSource>,
    /// Lineage origin in the new capture.
    pub source_to: Option<ServingSource>,
    /// Anti-rollback floor in the old capture.
    pub floor_from: u64,
    /// Anti-rollback floor in the new capture.
    pub floor_to: u64,
    /// Cumulative evictions in the old capture.
    pub evicted_from: u64,
    /// Cumulative evictions in the new capture.
    pub evicted_to: u64,
}

impl HubDiff {
    /// Whether the serving generation moved backwards or the hub lost its
    /// lineage between the captures — the acceptance's generation
    /// continuity question.
    pub const fn gen_regression(&self) -> bool {
        match (self.serving_from, self.serving_to) {
            (Some(from), Some(to)) => to < from,
            // Losing the report entirely (a hub that went from serving to
            // nothing) is a regression in everything but the number.
            (Some(_), None) => true,
            _ => false,
        }
    }

    /// Whether the lineage origin flipped to the pack's embedded snapshot.
    pub const fn lineage_lost(&self) -> bool {
        matches!(
            (self.source_from, self.source_to),
            (
                Some(ServingSource::StateLineage),
                Some(ServingSource::PackSnapshot)
            )
        )
    }

    /// Evictions that landed between the captures (the steady-window
    /// acceptance: zero).
    pub const fn evicted_delta(&self) -> u64 {
        self.evicted_to.saturating_sub(self.evicted_from)
    }
}

/// The full comparison of two captures — pure facts, no verdicts (those
/// live with the doctor face; `status diff` renders these as text).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SnapshotDiff {
    /// The hub's own moves.
    pub hub: HubDiff,
    /// Every leg in either capture, sorted by qualified id.
    pub agents: Vec<AgentDiff>,
}

impl SnapshotDiff {
    /// The distinct build strings among ONLINE legs in the newer capture,
    /// sorted. Acceptance wants exactly one entry — every leg on the same
    /// string.
    pub fn online_builds(&self) -> Vec<String> {
        let mut builds: Vec<String> = self
            .agents
            .iter()
            .filter(|a| a.online_now)
            .filter_map(|a| a.build_now.clone())
            .collect();
        builds.sort();
        builds.dedup();
        builds
    }

    /// Online-leg counts (before, after).
    pub fn online_leg_counts(&self) -> (usize, usize) {
        let before = self
            .agents
            .iter()
            .filter(|a| {
                matches!(
                    a.presence,
                    PresenceChange::Online | PresenceChange::WentOffline
                )
            })
            .count();
        let after = self.agents.iter().filter(|a| a.online_now).count();
        (before, after)
    }
}

/// Compares two captures into pure facts. Deterministic: rows sorted by
/// qualified agent id.
pub fn compare(old: &FleetSnapshotDoc, new: &FleetSnapshotDoc) -> SnapshotDiff {
    let hub = HubDiff {
        serving_from: old.hub.serving_generation,
        serving_to: new.hub.serving_generation,
        source_from: old.hub.serving_source,
        source_to: new.hub.serving_source,
        floor_from: old.hub.floor_generation,
        floor_to: new.hub.floor_generation,
        evicted_from: old.hub.evicted_total,
        evicted_to: new.hub.evicted_total,
    };
    let mut agents: Vec<AgentDiff> = Vec::new();
    for row_old in &old.agents {
        match new.agents.iter().find(|a| a.agent == row_old.agent) {
            Some(row_new) => {
                let presence = match (row_old.online, row_new.online) {
                    (true, true) => PresenceChange::Online,
                    (false, false) => PresenceChange::Offline,
                    (true, false) => PresenceChange::WentOffline,
                    (false, true) => PresenceChange::CameOnline,
                };
                agents.push(AgentDiff {
                    agent: row_old.agent.clone(),
                    presence,
                    build_change: (row_old.build != row_new.build).then(|| BuildChange {
                        from: row_old.build.clone(),
                        to: row_new.build.clone(),
                    }),
                    build_now: row_new.build.clone(),
                    transport_change: (row_old.transport != row_new.transport).then(|| {
                        TransportChange {
                            from: row_old.transport.unwrap_or(SnapshotTransport::H2),
                            to: row_new.transport.unwrap_or(SnapshotTransport::H2),
                        }
                    }),
                    circuit_rotated: row_old.circuit.is_some()
                        && row_new.circuit.is_some()
                        && row_old.circuit != row_new.circuit,
                    seen_change: (row_old.seen_generation != row_new.seen_generation).then_some(
                        SeenChange {
                            from: row_old.seen_generation,
                            to: row_new.seen_generation,
                        },
                    ),
                    online_now: row_new.online,
                });
            }
            None => agents.push(AgentDiff {
                agent: row_old.agent.clone(),
                presence: PresenceChange::Departed,
                build_change: None,
                build_now: None,
                transport_change: None,
                circuit_rotated: false,
                seen_change: None,
                online_now: false,
            }),
        }
    }
    for row_new in &new.agents {
        if !old.agents.iter().any(|a| a.agent == row_new.agent) {
            agents.push(AgentDiff {
                agent: row_new.agent.clone(),
                presence: PresenceChange::Joined,
                build_change: None,
                build_now: row_new.build.clone(),
                transport_change: None,
                circuit_rotated: false,
                seen_change: None,
                online_now: row_new.online,
            });
        }
    }
    agents.sort_by(|a, b| a.agent.cmp(&b.agent));
    SnapshotDiff { hub, agents }
}

// ---------------------------------------------------------------------------
// The human reading.
// ---------------------------------------------------------------------------

const fn transport_str(transport: SnapshotTransport) -> &'static str {
    match transport {
        SnapshotTransport::Quic => "quic",
        SnapshotTransport::H2 => "h2",
    }
}

const fn source_str(source: ServingSource) -> &'static str {
    match source {
        ServingSource::StateLineage => "state lineage",
        ServingSource::PackSnapshot => "pack snapshot",
    }
}

/// The upgrade-acceptance reading of a [`SnapshotDiff`]: generation
/// continuity (with the lineage-loss warning AND its direction caveat —
/// the warning targets the low-generation deadlock shape; a hub serving
/// ABOVE the old lineage re-converges), per-leg moves, evictions, and the
/// same-build-string summary.
pub fn render_diff_text(diff: &SnapshotDiff) -> String {
    let mut out = String::new();
    let hub = &diff.hub;
    let from = hub
        .serving_from
        .map_or_else(|| "unreported".to_owned(), |g| g.to_string());
    let to = hub
        .serving_to
        .map_or_else(|| "unreported".to_owned(), |g| g.to_string());
    use std::fmt::Write as _;
    let _ = writeln!(out, "hub:");
    let _ = writeln!(out, "  serving gen {from} → {to}");
    if hub.lineage_lost() {
        let forward = matches!((hub.serving_from, hub.serving_to), (Some(a), Some(b)) if b >= a);
        let caveat = if forward {
            " — forward move: re-publishing above the old lineage re-converges, the \
             warning targets a LOW-generation deadlock"
        } else {
            " — check whether state/ was expected to survive the upgrade"
        };
        let _ = writeln!(
            out,
            "  ⚠ lineage origin state lineage → pack snapshot{caveat}"
        );
    } else if let Some(source) = hub.source_to {
        let _ = writeln!(out, "  lineage origin: {} (held)", source_str(source));
    }
    if hub.gen_regression() {
        let _ = writeln!(out, "  ⚠ serving generation moved BACKWARDS");
    }
    let _ = writeln!(out, "  floor {} → {}", hub.floor_from, hub.floor_to);
    let delta = hub.evicted_delta();
    match delta {
        0 => {
            let _ = writeln!(
                out,
                "  evictions {} → {} (steady window)",
                hub.evicted_from, hub.evicted_to
            );
        }
        n => {
            let _ = writeln!(
                out,
                "  ⚠ evictions {} → {} (+{n} landed between the captures — find the \
                 eviction reason in the hub journal: journalctl -u <hub> | grep evicted)",
                hub.evicted_from, hub.evicted_to
            );
        }
    }

    let _ = writeln!(out, "legs:");
    for leg in &diff.agents {
        let marker = match leg.presence {
            PresenceChange::Online | PresenceChange::Offline => " ",
            PresenceChange::WentOffline => "↓",
            PresenceChange::CameOnline => "↑",
            PresenceChange::Joined => "+",
            PresenceChange::Departed => "-",
        };
        let mut line = format!("{marker} {}", leg.agent);
        // (std::fmt::Write is imported at fn top; reuse it for the appends.)
        if let Some(build) = &leg.build_change {
            let from = build.from.as_deref().unwrap_or("unknown");
            let to = build.to.as_deref().unwrap_or("unknown");
            let _ = write!(line, ": build {from} → {to}");
            if to.contains("-dirty") {
                line.push_str(" ⚠ DIRTY build — an amber string voids the leg for acceptance");
            }
        }
        if let Some(transport) = &leg.transport_change {
            let _ = write!(
                line,
                "; transport {} → {}",
                transport_str(transport.from),
                transport_str(transport.to)
            );
        }
        if leg.circuit_rotated {
            line.push_str("; re-registered (circuit rotated — fleet churn, not an offline blip)");
        }
        match leg.presence {
            PresenceChange::WentOffline => line.push_str(": went OFFLINE"),
            PresenceChange::CameOnline => line.push_str(": back ONLINE"),
            PresenceChange::Joined => line.push_str(": joined the fleet"),
            PresenceChange::Departed => line.push_str(": departed (no live registration)"),
            _ => {}
        }
        let _ = writeln!(out, "{line}");
    }

    let (before, after) = diff.online_leg_counts();
    let builds = diff.online_builds();
    let builds_text = if builds.is_empty() {
        "none reported".to_owned()
    } else {
        builds.join(", ")
    };
    let dirty = builds.iter().filter(|b| b.contains("-dirty")).count();
    let uniform = if builds.len() <= 1 {
        "uniform"
    } else {
        "⚠ MIXED build strings"
    };
    let dirty_text = if dirty == 0 {
        "zero dirty".to_owned()
    } else {
        format!("⚠ {dirty} dirty string(s)")
    };
    let _ = writeln!(
        out,
        "summary: online {before} → {after} · builds [{builds_text}] ({uniform}, {dirty_text})"
    );
    out
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    fn doc(
        generation: u64,
        agents: Vec<interflow_mesh::hub::snapshot::FleetSnapshotAgent>,
    ) -> FleetSnapshotDoc {
        FleetSnapshotDoc {
            format_version: 1,
            hub: interflow_mesh::hub::snapshot::FleetSnapshotHub {
                node: Some("promptcn".into()),
                serving_generation: Some(generation),
                serving_source: Some(ServingSource::StateLineage),
                floor_generation: generation,
                evicted_total: 0,
                crl_numbers: std::collections::BTreeMap::new(),
                captured_at_unix: 0,
            },
            agents,
        }
    }

    fn leg(
        agent: &str,
        online: bool,
        build: Option<&str>,
        circuit: &str,
    ) -> interflow_mesh::hub::snapshot::FleetSnapshotAgent {
        interflow_mesh::hub::snapshot::FleetSnapshotAgent {
            agent: agent.to_owned(),
            online,
            seen_generation: Some(15),
            build: build.map(str::to_owned),
            transport: Some(SnapshotTransport::Quic),
            circuit: Some(circuit.repeat(16)),
        }
    }

    /// The §10.8 acceptance reading, end to end: build upgrades per leg,
    /// generation continuity, a re-registration named as circuit rotation
    /// (not an offline blip), a departed leg, eviction movement, and the
    /// same-build summary.
    #[test]
    fn upgrade_diff_full_reading() {
        let old = doc(
            15,
            vec![
                leg("main/lan-a", true, Some("2026-10-11_b9aab4a"), "aa"),
                leg("main/lan-b", true, Some("2026-10-11_b9aab4a"), "bb"),
                leg("main/lan-gone", false, Some("2026-10-10_0000000"), "cc"),
            ],
        );
        let mut new = doc(
            15,
            vec![
                leg("main/lan-a", true, Some("2026-10-12_bf11cd8"), "aa"),
                // lan-b re-registered: new circuit, same identity.
                leg("main/lan-b", true, Some("2026-10-12_bf11cd8"), "dd"),
                leg("main/lan-new", true, Some("2026-10-12_bf11cd8"), "ee"),
            ],
        );
        new.hub.evicted_total = 2;

        let diff = compare(&old, &new);
        assert!(!diff.hub.gen_regression(), "15 → 15 is continuity");
        assert_eq!(diff.hub.evicted_delta(), 2);
        assert!(!diff.hub.lineage_lost());

        let by = |agent: &str| diff.agents.iter().find(|a| a.agent == agent).unwrap();
        assert_eq!(by("main/lan-a").presence, PresenceChange::Online);
        assert_eq!(
            by("main/lan-a")
                .build_change
                .as_ref()
                .unwrap()
                .to
                .as_deref(),
            Some("2026-10-12_bf11cd8")
        );
        let lan_b = by("main/lan-b");
        assert!(
            lan_b.circuit_rotated,
            "a new circuit on the same leg is churn"
        );
        assert_eq!(by("main/lan-gone").presence, PresenceChange::Departed);
        assert_eq!(by("main/lan-new").presence, PresenceChange::Joined);

        let text = render_diff_text(&diff);
        assert!(text.contains("15 → 15"), "generation continuity: {text}");
        assert!(
            text.contains("+2 landed"),
            "eviction movement named: {text}"
        );
        assert!(text.contains("re-registered (circuit rotated"), "{text}");
        assert!(text.contains("main/lan-new: joined"), "{text}");
        assert!(text.contains("main/lan-gone: departed"), "{text}");
    }

    /// The lineage-loss warning fires on the origin flip, and the §10.7
    /// direction caveat distinguishes a forward move from the deadlock
    /// shape.
    #[test]
    fn lineage_loss_direction_caveat() {
        let mut old = doc(12, vec![]);
        old.hub.serving_source = Some(ServingSource::StateLineage);
        // The deadlock shape: serving BELOW the old lineage.
        let mut low = doc(10, vec![]);
        low.hub.serving_source = Some(ServingSource::PackSnapshot);
        let low_diff = compare(&old, &low);
        assert!(low_diff.hub.lineage_lost() && low_diff.hub.gen_regression());
        let low_text = render_diff_text(&low_diff);
        assert!(
            low_text.contains("state/ was expected to survive"),
            "{low_text}"
        );

        // The forward move: pack snapshot ABOVE the old lineage.
        let mut high = doc(14, vec![]);
        high.hub.serving_source = Some(ServingSource::PackSnapshot);
        let high_diff = compare(&old, &high);
        assert!(high_diff.hub.lineage_lost() && !high_diff.hub.gen_regression());
        let high_text = render_diff_text(&high_diff);
        assert!(high_text.contains("forward move"), "{high_text}");
    }

    /// Snapshot files round-trip through the envelope (the wire document
    /// stays pristine inside it).
    #[test]
    fn snapshot_file_round_trip() {
        let file = SnapshotFile {
            cli_build: "0.9.0 (2026-10-13_abcdef1)".to_owned(),
            hub_endpoint: "mesh.example.com:6666".to_owned(),
            snapshot: doc(15, vec![leg("main/lan-a", true, None, "aa")]),
        };
        let json = serde_json::to_string(&file).unwrap();
        let back: SnapshotFile = serde_json::from_str(&json).unwrap();
        assert_eq!(back, file);
    }
}
