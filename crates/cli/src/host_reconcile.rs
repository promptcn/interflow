//! Host-level reconciliation: units and packs against the signed roster.
//!
//! Retirement used to live in the runbook — "remember to disable the old
//! unit" — and a forgotten step armed a port race that only detonated on the
//! next reboot. This module names the leftovers; it never removes anything
//! (`node retire` is the one explicit action).
//!
//! Three structural judgments, no heuristics:
//!
//! 1. **unit ↔ pack cross-reference** — a unit whose `(kind, node)` has no
//!    installed pack (or a pack with no unit on a unit-managed layout) is a
//!    half-finished change either way;
//! 2. **the signed roster** (format epoch 3) — a pack absent from its
//!    realm's newest roster on this machine is a retired or renamed node's
//!    leftovers; membership is a signed fact, not a guess;
//! 3. **archive/staging exemption** — `*.previous`, `*.retired-<date>` and
//!    `.staging-*` siblings are deliberate history, never findings.

use interflow_identity::pack::PackKind;
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

/// One installed pack as the scan sees it.
struct InstalledPack {
    kind: PackKind,
    node: String,
    realm: String,
    dir: PathBuf,
    /// The embedded policy's `(generation, roster)` when it carries one
    /// (format epoch 3+); `None` = no roster authority for its realm.
    roster: Option<(u64, Vec<(String, String)>)>,
}

/// A unit file name that names a node (`interflow-<kind>-<node>.service`).
struct UnitSlot {
    kind: PackKind,
    node: String,
    path: PathBuf,
}

/// One reconciliation finding. `describe()` carries the operator-facing
/// line (glyph included); severity decides ⚠ (act before the next boot)
/// vs · (hygiene).
pub struct ReconcileFinding {
    kind: PackKind,
    node: String,
    detail: FindingDetail,
}

enum FindingDetail {
    /// A unit with no installed pack — at boot systemd starts it against a
    /// missing tree, or worse, against whatever replaced it.
    UnitWithoutPack,
    /// A pack (with its unit, when one is present) that the realm's newest
    /// signed roster does not list — a retired or renamed node's leftovers.
    OffRoster { unit: Option<PathBuf> },
    /// A pack with no unit on a unit-managed layout — half-configured or
    /// half-retired; `node install` finishes it, `node retire` closes it.
    PackWithoutUnit,
}

impl ReconcileFinding {
    /// The operator-facing line, glyph first — the caller indents it.
    pub fn describe(&self) -> String {
        let slot = format!("{}-{}", self.kind.as_str(), self.node);
        match &self.detail {
            FindingDetail::UnitWithoutPack => format!(
                "⚠ unit interflow-{slot}.service has no installed pack — disable and remove \
                 it (interflow-cli node retire --pack packs/{slot}), or it races for ports \
                 on the next boot",
            ),
            FindingDetail::OffRoster { unit } => match unit {
                Some(unit_path) => format!(
                    "⚠ {slot} (pack packs/{slot} + unit {}) is NOT in the realm's current \
                     signed roster — retired or renamed; retire it: interflow-cli node \
                     retire --pack packs/{slot}",
                    unit_path.display()
                ),
                None => format!(
                    "⚠ pack packs/{slot} is NOT in the realm's current signed roster — \
                     retired or renamed; retire it: interflow-cli node retire --pack \
                     packs/{slot}",
                ),
            },
            FindingDetail::PackWithoutUnit => format!(
                "· pack packs/{slot} has no unit on this layout — run node install for it \
                 or retire it (interflow-cli node retire --pack packs/{slot})",
            ),
        }
    }

    /// Whether the finding is a ⚠ (act) rather than a · (hygiene).
    pub const fn is_warning(&self) -> bool {
        !matches!(self.detail, FindingDetail::PackWithoutUnit)
    }
}

/// A directory name that is deliberate history, not a live install:
/// rollback (`<name>.previous`), retirement archives
/// (`<name>.retired-<date>`), and install staging (`.staging-*`).
fn is_history(name: &str) -> bool {
    name.starts_with('.') || name.ends_with(".previous") || name.contains(".retired-")
}

/// Parses `interflow-<kind>-<node>.service` into its node slot. Any other
/// name (the registrar unit, operator files) is not a node unit → `None`.
fn parse_unit_name(path: &Path) -> Option<(PackKind, String)> {
    let name = path.file_name()?.to_str()?;
    let rest = name.strip_prefix("interflow-")?.strip_suffix(".service")?;
    let (kind_str, node) = rest.split_once('-')?;
    let kind = match kind_str {
        "ingress" => PackKind::Ingress,
        "agent" => PackKind::Agent,
        "hub" => PackKind::Hub,
        _ => return None,
    };
    Some((kind, node.to_owned()))
}

fn scan_packs(packs_root: &Path) -> Vec<InstalledPack> {
    let Ok(entries) = std::fs::read_dir(packs_root) else {
        return Vec::new();
    };
    let mut packs = Vec::new();
    for entry in entries.flatten() {
        let name = entry.file_name();
        let Some(name) = name.to_str() else { continue };
        if is_history(name) || !entry.path().is_dir() {
            continue;
        }
        let Ok((kind, node, realm)) = interflow_identity::pack_kind_node_realm_of(&entry.path())
        else {
            continue;
        };
        let roster =
            interflow_identity::pack_roster_of(&entry.path()).map(|(generation, nodes)| {
                (
                    generation,
                    nodes.into_iter().map(|n| (n.kind, n.node)).collect(),
                )
            });
        packs.push(InstalledPack {
            kind,
            node,
            realm,
            dir: entry.path(),
            roster,
        });
    }
    packs
}

fn scan_units(unit_dir: &Path) -> Vec<UnitSlot> {
    let Ok(entries) = std::fs::read_dir(unit_dir) else {
        return Vec::new();
    };
    entries
        .flatten()
        .map(|entry| entry.path())
        .filter_map(|path| parse_unit_name(&path).map(|(kind, node)| UnitSlot { kind, node, path }))
        .collect()
}

/// The newest roster per realm among the installed packs. A realm whose
/// packs all predate the roster face (or whose policies are unreadable)
/// simply has no entry — roster judgment is skipped for it, never guessed.
/// Same-generation ties (two deployments minted independently) break on the
/// directory name purely for determinism — a real rename/redeploy rides the
/// same issuer lineage and lands strictly above the watermark.
/// One realm's newest roster authority, with the directory name that won
/// the same-generation tie-break (determinism only).
type RealmRoster = (u64, String, Vec<(String, String)>);

fn newest_rosters(packs: &[InstalledPack]) -> BTreeMap<String, (u64, Vec<(String, String)>)> {
    let mut by_realm: BTreeMap<String, RealmRoster> = BTreeMap::new();
    for pack in packs {
        let Some((generation, roster)) = &pack.roster else {
            continue;
        };
        let dir_name = pack
            .dir
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_default();
        let better = by_realm
            .get(&pack.realm)
            .is_none_or(|(current_gen, current_dir, _)| {
                (*generation, &dir_name) > (*current_gen, current_dir)
            });
        if better {
            by_realm.insert(pack.realm.clone(), (*generation, dir_name, roster.clone()));
        }
    }
    by_realm
        .into_iter()
        .map(|(realm, (generation, _, roster))| (realm, (generation, roster)))
        .collect()
}

/// Scans one host's footprint: `unit_dir` (system layout: the systemd unit
/// directory; self-contained layouts: `<root>/systemd`) and `packs_root`.
/// Purely read-only; findings are named, never acted on.
pub fn scan(unit_dir: &Path, packs_root: &Path) -> Vec<ReconcileFinding> {
    let packs = scan_packs(packs_root);
    let units = scan_units(unit_dir);
    let rosters = newest_rosters(&packs);
    let unit_dir_exists = unit_dir.is_dir();

    let mut findings = Vec::new();
    // 1. Units with no installed pack.
    for unit in &units {
        if !packs
            .iter()
            .any(|p| p.kind == unit.kind && p.node == unit.node)
        {
            findings.push(ReconcileFinding {
                kind: unit.kind,
                node: unit.node.clone(),
                detail: FindingDetail::UnitWithoutPack,
            });
        }
    }
    for pack in &packs {
        // 2. The signed roster: absent membership names retired/renamed
        //    leftovers, pack AND unit together.
        let roster_knows_it = rosters.get(&pack.realm).is_none_or(|(_, roster)| {
            roster
                .iter()
                .any(|(kind, node)| *kind == pack.kind.as_str() && node == &pack.node)
        });
        if !roster_knows_it {
            let unit = units
                .iter()
                .find(|u| u.kind == pack.kind && u.node == pack.node)
                .map(|u| u.path.clone());
            findings.push(ReconcileFinding {
                kind: pack.kind,
                node: pack.node.clone(),
                detail: FindingDetail::OffRoster { unit },
            });
            continue;
        }
        // 3. A rostered pack with no unit on a unit-managed layout.
        if unit_dir_exists
            && !units
                .iter()
                .any(|u| u.kind == pack.kind && u.node == pack.node)
        {
            findings.push(ReconcileFinding {
                kind: pack.kind,
                node: pack.node.clone(),
                detail: FindingDetail::PackWithoutUnit,
            });
        }
    }
    findings
}

/// The ingress node names installed under a packs root (history siblings
/// excluded) — the nginx fragment reconciliation's expected-vhost source.
///
/// A machine's nginx carries vhosts for the ingress nodes installed ON it,
/// and the packs root is the host's own record of that set.
pub fn installed_ingress_nodes(packs_root: &Path) -> Vec<String> {
    let mut nodes: Vec<String> = scan_packs(packs_root)
        .into_iter()
        .filter(|pack| pack.kind == PackKind::Ingress)
        .map(|pack| pack.node)
        .collect();
    nodes.sort();
    nodes.dedup();
    nodes
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Writes a minimal installable pack: pack.toml carrying the identity
    /// face plus (optionally) an embedded policy with a roster.
    fn write_pack(
        packs_root: &Path,
        kind: &str,
        node: &str,
        realm: &str,
        generation: u64,
        roster: Option<&[(&str, &str)]>,
    ) -> PathBuf {
        let dir = packs_root.join(format!("{kind}-{node}"));
        std::fs::create_dir_all(dir.join("policy")).unwrap();
        std::fs::write(
            dir.join("pack.toml"),
            format!(
                "format_version = 3\nkind = \"{kind}\"\nrealm = \"{realm}\"\nworkspace = \
                 \"\"\nnode = \"{node}\"\ngeneration = {generation}\ncreated = \
                 \"2026-11-04T00:00:00Z\"\nexpires = \"2026-12-04T00:00:00Z\"\ncontrol_endpoint \
                 = \"hub.example.com:6666\"\nleaf_ttl_secs = 7776000\nidentity_mode = \
                 \"offline\"\n"
            ),
        )
        .unwrap();
        if let Some(roster) = roster {
            let mut policy = format!(
                "generation = {generation}\nroutes = []\nservices = \
                 []\ningress_authorizations = []\nmesh = []\nmesh_egress = []\n"
            );
            for (kind, node) in roster {
                policy.push_str("\n[[nodes]]\nkind = \"");
                policy.push_str(kind);
                policy.push_str("\"\nnode = \"");
                policy.push_str(node);
                policy.push_str("\"\n");
            }
            std::fs::write(dir.join("policy").join("policy.toml"), policy).unwrap();
        }
        dir
    }

    fn write_unit(unit_dir: &Path, kind: &str, node: &str) {
        std::fs::create_dir_all(unit_dir).unwrap();
        std::fs::write(
            unit_dir.join(format!("interflow-{kind}-{node}.service")),
            "# unit\n",
        )
        .unwrap();
    }

    fn temp_layout() -> (tempfile::TempDir, PathBuf, PathBuf) {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path().to_path_buf();
        let units = root.join("systemd");
        let packs = root.join("packs");
        std::fs::create_dir_all(&packs).unwrap();
        (tmp, units, packs)
    }

    fn described(findings: &[ReconcileFinding]) -> Vec<String> {
        findings.iter().map(ReconcileFinding::describe).collect()
    }

    /// The in-service shape: every pack rostered, every pack with its unit —
    /// zero findings, multi-realm included.
    #[test]
    fn in_service_multi_realm_layout_is_silent() {
        let (_tmp, units, packs) = temp_layout();
        let roster = &[
            ("ingress", "ecs-edge"),
            ("agent", "worker"),
            ("hub", "ecs-hub"),
        ];
        write_pack(&packs, "ingress", "ecs-edge", "expose", 8, Some(roster));
        write_pack(&packs, "hub", "ecs-hub", "mesh", 5, Some(roster));
        write_pack(&packs, "agent", "worker", "mesh", 5, Some(roster));
        write_unit(&units, "ingress", "ecs-edge");
        write_unit(&units, "hub", "ecs-hub");
        write_unit(&units, "agent", "worker");
        assert!(
            scan(&units, &packs).is_empty(),
            "an in-service multi-realm host must produce zero findings"
        );
    }

    /// The rename shape from the epoch-2 redeploy: the old unit AND the old
    /// pack both remain (mutually consistent, invisible to cross-reference)
    /// — the newest roster names BOTH, with the retire instruction.
    #[test]
    fn renamed_pair_is_named_by_the_roster() {
        let (_tmp, units, packs) = temp_layout();
        let old_roster = &[("hub", "promptcn"), ("ingress", "edge")];
        let new_roster = &[("hub", "ecs-hub"), ("ingress", "ecs-edge")];
        write_pack(&packs, "hub", "promptcn", "mesh", 4, Some(old_roster));
        write_pack(&packs, "ingress", "edge", "expose", 4, Some(old_roster));
        write_pack(&packs, "hub", "ecs-hub", "mesh", 9, Some(new_roster));
        write_pack(&packs, "ingress", "ecs-edge", "expose", 9, Some(new_roster));
        write_unit(&units, "hub", "promptcn");
        write_unit(&units, "ingress", "edge");
        write_unit(&units, "hub", "ecs-hub");
        write_unit(&units, "ingress", "ecs-edge");
        let lines = described(&scan(&units, &packs));
        assert_eq!(lines.len(), 2, "exactly the two stale pairs: {lines:?}");
        for line in &lines {
            assert!(
                line.contains("NOT in the realm's current signed roster"),
                "{line}"
            );
            assert!(
                line.contains("node retire"),
                "the executable remedy: {line}"
            );
        }
        assert!(
            lines.iter().any(|l| l.contains("hub-promptcn")
                && l.contains("interflow-hub-promptcn.service")),
            "the finding names the pack AND the unit: {lines:?}"
        );
        assert!(
            lines[0].starts_with("⚠") && lines[1].starts_with("⚠"),
            "roster findings are warnings: {lines:?}"
        );
    }

    /// Half-finished changes: a unit whose pack is gone (the boot-race
    /// trap), and a rostered pack with no unit.
    #[test]
    fn cross_reference_names_both_half_states() {
        let (_tmp, units, packs) = temp_layout();
        let roster = &[("hub", "ecs-hub"), ("ingress", "ecs-edge")];
        write_pack(&packs, "hub", "ecs-hub", "mesh", 9, Some(roster));
        write_pack(&packs, "ingress", "ecs-edge", "expose", 9, Some(roster));
        // The old ingress's unit survived its pack's removal.
        write_unit(&units, "ingress", "edge");
        // The hub pack never got its unit.
        write_unit(&units, "ingress", "ecs-edge");
        let lines = described(&scan(&units, &packs));
        assert_eq!(lines.len(), 2, "{lines:?}");
        assert!(
            lines.iter().any(|l| l.contains(
                "unit interflow-ingress-edge.service has no \
                 installed pack"
            ) && l.starts_with("⚠")),
            "the unit-without-pack danger is named: {lines:?}"
        );
        assert!(
            lines
                .iter()
                .any(|l| l.contains("packs/hub-ecs-hub has no unit") && l.starts_with("·")),
            "the pack-without-unit hygiene note is named: {lines:?}"
        );
    }

    /// Deliberate history is never a finding; pre-roster policies are never
    /// guessed at (graceful degradation to cross-reference only).
    #[test]
    fn history_dirs_and_pre_roster_packs_are_exempt() {
        let (_tmp, units, packs) = temp_layout();
        // Rollback + retirement archives + staging siblings.
        write_pack(&packs, "hub", "ecs-hub", "mesh", 9, None);
        std::fs::rename(
            packs.join("hub-ecs-hub"),
            packs.join("hub-ecs-hub.previous"),
        )
        .unwrap();
        write_pack(&packs, "ingress", "edge", "expose", 4, None);
        std::fs::rename(
            packs.join("ingress-edge"),
            packs.join("ingress-edge.retired-2026-11-04"),
        )
        .unwrap();
        std::fs::create_dir_all(packs.join(".staging-install-999")).unwrap();
        write_unit(&units, "hub", "ecs-hub");
        // A pre-epoch-3 pack (policy without the nodes face): roster judgment
        // is skipped — its unit exists, its pack parses, zero findings.
        write_pack(&packs, "agent", "laptop", "mesh", 2, None);
        write_pack(&packs, "hub", "ecs-hub", "mesh", 9, None);
        write_unit(&units, "agent", "laptop");
        assert!(
            scan(&units, &packs).is_empty(),
            "history and pre-roster shapes must stay silent"
        );
    }

    /// The registrar unit is not a node unit; foreign files in the packs
    /// root are not packs.
    #[test]
    fn non_node_surfaces_are_ignored() {
        let (_tmp, units, packs) = temp_layout();
        write_unit(&units, "hub", "ecs-hub");
        write_pack(&packs, "hub", "ecs-hub", "mesh", 9, None);
        std::fs::create_dir_all(&units).unwrap();
        std::fs::write(units.join("interflow-registrar.service"), "# unit\n").unwrap();
        std::fs::create_dir_all(packs.join("not-a-pack")).unwrap();
        std::fs::write(packs.join("README.md"), "hi\n").unwrap();
        assert!(scan(&units, &packs).is_empty());
    }

    /// A missing unit directory (GUI-style pack roots) skips the unit face;
    /// roster judgment still runs.
    #[test]
    fn missing_unit_dir_degrades_to_roster_only() {
        let (_tmp, units, packs) = temp_layout();
        let new_roster = &[("agent", "laptop")];
        write_pack(&packs, "agent", "laptop", "mesh", 5, Some(new_roster));
        write_pack(&packs, "agent", "old-laptop", "mesh", 2, Some(new_roster));
        // No unit dir at all.
        let lines = described(&scan(&units, &packs));
        assert_eq!(lines.len(), 1, "{lines:?}");
        assert!(lines[0].contains("agent-old-laptop"), "{lines:?}");
    }
}
