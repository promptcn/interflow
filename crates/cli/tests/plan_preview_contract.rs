//! Preview honorability — the cross-face contract test class.
//!
//! The plan face's family of defects (three same-day incidents, 2026-11-02)
//! all leaked through the same seam: the matrix was VERTICAL — each face
//! asserted its own output against a state it had built for itself, and no
//! test ever put `plan diff` and `plan apply` on the SAME store and tree
//! and checked that the promises were kept. The family's definition is
//! "face A's statement about state S ≠ face B's behavior on state S", so
//! the only guard that holds it is horizontal: for every corpus state,
//! parse what diff promises, run apply, and require every action to be
//! covered by a promise — an unpromised action is the family, red.
//!
//! The promise/action vocabulary comes from the tested crate itself
//! (`interflow_cli::plan::narration`): diff and apply compose their lines
//! from those constants, and this test parses with the SAME constants —
//! rewording a line reflows the test with it, so the test can never drift
//! from the faces it polices.
//!
//! The corpus (the family's known members; a new seam adds a cell — the
//! shared state builders live in interflow-testkit's `plan_corpus`):
//! - healthy tree × zero drift / policy edits / identity edits
//! - stale baseline cache (digest disagrees, snapshot proves unchanged)
//!   × zero drift / policy edits / identity edits
//! - stale tree, trust (a real revoke past the embedded CRLs) × zero drift,
//!   and the incident's exact order: policy-only apply THEN revoke
//! - stale tree, format (a retired pack.toml vintage) × zero drift / policy edits
//! - watermark divergence (a node state mirror above the bookkeeping)
//! - a damaged baseline fails loudly on BOTH faces
//!
//! The hub endpoint is a closed loopback port: publication degrades to the
//! manual-drop artifact — fast, deterministic, no network. Every cell is
//! re-runnable locally with
//! `cargo nextest run -p interflow-cli --test plan_preview_contract`.
//!
//! Backlog: (internal design notes)
//! and (internal design notes).

mod common;

use common::{RunOutcome, run};
use interflow_cli::plan::narration::{action, promise};
use interflow_identity::issuance::IssuerStore;
use interflow_testkit::plan_corpus;
use std::path::PathBuf;

// ---------------------------------------------------------------------------
// The scene: one temp directory, one manifest, one issuer store, one dist
// tree — both faces act on the exact same bytes.
// ---------------------------------------------------------------------------

struct Scene {
    dir: PathBuf,
}

impl Scene {
    fn new() -> Self {
        let scene = Self {
            dir: tempfile::tempdir().expect("tempdir").keep(),
        };
        scene.manifest_at(11434, 8080);
        scene
    }

    /// Writes a corpus declaration with `remote_port`/`service_port` at
    /// their canonical values and returns its path.
    fn manifest_at(&self, remote_port: u16, service_port: u16) -> String {
        let text = plan_corpus::mesh_manifest_text("preview-contract", remote_port, service_port);
        self.write_manifest(&text)
    }

    fn write_manifest(&self, text: &str) -> String {
        let path = self.dir.join("interflow.toml");
        std::fs::write(&path, text).unwrap();
        path.display().to_string()
    }

    fn issuer_dir(&self) -> PathBuf {
        self.dir.join("issuer")
    }

    fn issuer(&self) -> String {
        self.issuer_dir().display().to_string()
    }

    fn out_dir(&self) -> PathBuf {
        self.dir.join("dist")
    }

    fn out(&self) -> String {
        self.out_dir().display().to_string()
    }

    fn diff(&self, manifest: &str) -> RunOutcome {
        let issuer = self.issuer();
        let out = self.out();
        run(&[
            "plan",
            "diff",
            "--manifest",
            manifest,
            "--issuer",
            &issuer,
            "--out",
            &out,
        ])
    }

    fn apply(&self, manifest: &str) -> RunOutcome {
        let issuer = self.issuer();
        let out = self.out();
        run(&[
            "plan",
            "apply",
            "--manifest",
            manifest,
            "--issuer",
            &issuer,
            "--out",
            &out,
        ])
    }

    /// A real revoke against one pack, no `--manifest`: the deny list moves,
    /// the tree's embedded CRLs do not — the trust-staleness corpus cell.
    fn revoke_home_win(&self) -> RunOutcome {
        let issuer = self.issuer();
        let pack = self.out_dir().join("packs/agent-home-win");
        run(&[
            "revoke",
            "--issuer",
            &issuer,
            "--pack",
            &pack.display().to_string(),
            "--reason",
            "superseded",
        ])
    }

    /// The render fingerprint the "no render" promises are checked against:
    /// every pack directory's SHA256SUMS, byte for byte.
    fn pack_digests(&self) -> Vec<(String, String)> {
        let packs = self.out_dir().join("packs");
        let mut entries = std::fs::read_dir(&packs)
            .expect("dist/packs exists after an apply")
            .map(|e| {
                e.expect("readable")
                    .file_name()
                    .to_string_lossy()
                    .into_owned()
            })
            .collect::<Vec<_>>();
        entries.sort();
        entries
            .into_iter()
            .map(|dir| {
                let sums = std::fs::read_to_string(packs.join(&dir).join("SHA256SUMS"))
                    .expect("a rendered pack carries SHA256SUMS (the no-render evidence)");
                (dir, sums)
            })
            .collect()
    }

    /// The issuer bookkeeping's live generation.
    fn generation(&self) -> u64 {
        IssuerStore::open(self.issuer_dir())
            .applied_state()
            .unwrap()
            .expect("a state is recorded")
            .policy_generation
    }

    /// The dist policy mirror's generation (the manual-drop artifact).
    fn mirror_generation(&self) -> u64 {
        let text = std::fs::read_to_string(self.out_dir().join("policy/policy.toml"))
            .expect("dist/policy/policy.toml");
        text.lines()
            .find_map(|l| l.trim().strip_prefix("generation = ").map(str::to_owned))
            .map(|g| g.parse().expect("generation parses"))
            .expect("the mirror names its generation")
    }

    /// Rewrites the recorded digest into a stale cache while the record
    /// keeps the live declaration's text as its snapshot — a digest that
    /// disagrees with a snapshot that is still the truth (the shape a
    /// serialized-representation drift, or any cache desync, leaves).
    fn age_the_cache(&self, manifest: &str) {
        let store = IssuerStore::open(self.issuer_dir());
        let mut applied = store
            .applied_state()
            .unwrap()
            .expect("apply recorded a state");
        let snapshot = std::fs::read_to_string(manifest).unwrap();
        applied.stripped_manifest_digest = String::from("sha256:a-stale-cache");
        store
            .record_applied(
                &applied,
                Some(&snapshot),
                interflow_identity::issuance::AppliedKind::FullRender,
            )
            .unwrap();
    }
}

// ---------------------------------------------------------------------------
// The promise parser — driven by the SAME constants diff composes from.
// ---------------------------------------------------------------------------

/// What the diff face promised about the next apply. One bool per promise
/// marker; zero promises on a successful diff is the parser going blind
/// (fail-closed, the `check_version_surface.py` "zero roots is a failure"
/// discipline).
#[allow(clippy::struct_excessive_bools)] // one bool per promise marker — the vocabulary's parsed shape
#[derive(Default, Debug, Clone, Copy, PartialEq, Eq)]
struct Promises {
    never_applied: bool,
    nothing_to_apply: bool,
    baseline_cache_refresh: bool,
    policy_only_fast_path: bool,
    rerenders_every_pack: bool,
    pack_tree_stale: bool,
    publishes_above_watermarks: bool,
    watermarks_diverge: bool,
    republishes_above_watermarks: bool,
    fast_path_superseded: bool,
}

impl Promises {
    fn parse(diff: &RunOutcome) -> Self {
        assert!(diff.success, "diff failed: {}", diff.stderr);
        let stdout = &diff.stdout;
        let p = Self {
            never_applied: stdout.contains(promise::FULL_FIRST_RENDER),
            nothing_to_apply: stdout.contains(promise::NOTHING_TO_APPLY),
            baseline_cache_refresh: stdout.contains(promise::BASELINE_CACHE_REFRESH),
            policy_only_fast_path: stdout.contains(promise::POLICY_ONLY_FAST_PATH),
            rerenders_every_pack: stdout.contains(promise::RERENDERS_EVERY_PACK),
            pack_tree_stale: stdout.contains(promise::PACK_TREE_IS_STALE),
            publishes_above_watermarks: stdout.contains(promise::PUBLISHES_ABOVE_THE_WATERMARKS),
            watermarks_diverge: stdout.contains(promise::WATERMARKS_DIVERGE),
            republishes_above_watermarks: stdout
                .contains(promise::REPUBLISHES_ABOVE_THE_WATERMARKS),
            fast_path_superseded: stdout.contains(promise::FAST_PATH_SUPERSEDED),
        };
        assert!(
            p.any(),
            "the promise parser matched NOTHING — it is blind, not the contract \
             satisfied:\n{}",
            diff.stdout
        );
        p
    }

    const fn any(self) -> bool {
        self.never_applied
            || self.nothing_to_apply
            || self.baseline_cache_refresh
            || self.policy_only_fast_path
            || self.rerenders_every_pack
            || self.pack_tree_stale
            || self.publishes_above_watermarks
            || self.watermarks_diverge
            || self.republishes_above_watermarks
            || self.fast_path_superseded
    }

    /// May apply do this, given what diff promised? This table IS the
    /// family's invariant: an action with no covering promise is the seam.
    fn allows(self, marker: &str) -> bool {
        if marker == action::APPLIED {
            return self.never_applied || self.rerenders_every_pack || self.pack_tree_stale;
        }
        if marker == action::POLICY_ONLY_CHANGE {
            return self.policy_only_fast_path || self.watermarks_diverge;
        }
        if marker == action::ALREADY_APPLIED {
            return self.nothing_to_apply;
        }
        if marker == action::MANIFEST_UNCHANGED_BUT {
            return self.pack_tree_stale || self.watermarks_diverge;
        }
        if marker == action::REPUBLISHING_ABOVE_THE_WATERMARKS {
            return self.watermarks_diverge;
        }
        if marker == action::RERENDERING_AND_PUBLISHING {
            return self.pack_tree_stale;
        }
        if marker == action::PUBLISHED_TO_HUB || marker == action::MANUAL_DISTRIBUTION {
            // A publish happens whenever a generation is minted — never on
            // the no-op fork (the one place diff may say "no publish").
            return self.never_applied
                || self.rerenders_every_pack
                || self.pack_tree_stale
                || self.publishes_above_watermarks
                || self.watermarks_diverge
                || self.republishes_above_watermarks
                || self.policy_only_fast_path;
        }
        if marker == action::EMBEDDED_REVOCATION_SNAPSHOT {
            return self.never_applied || self.rerenders_every_pack || self.pack_tree_stale;
        }
        if marker == action::RESTAMPED {
            return self.baseline_cache_refresh;
        }
        if marker == action::NOTHING_TO_DO {
            return self.nothing_to_apply;
        }
        false
    }
}

/// The honor check: apply ran on the state diff just read — every action
/// marker in its output must be covered by a promise, and every ✔ line
/// must be one of the known action heads (a new ✔ the vocabulary does not
/// know is red here, not silently passed).
fn assert_honored(p: Promises, diff_out: &str, applied: &RunOutcome) {
    assert!(applied.success, "apply failed: {}", applied.stderr);
    for marker in [
        action::APPLIED,
        action::POLICY_ONLY_CHANGE,
        action::ALREADY_APPLIED,
        action::MANIFEST_UNCHANGED_BUT,
        action::REPUBLISHING_ABOVE_THE_WATERMARKS,
        action::RERENDERING_AND_PUBLISHING,
        action::PUBLISHED_TO_HUB,
        action::MANUAL_DISTRIBUTION,
        action::EMBEDDED_REVOCATION_SNAPSHOT,
        action::RESTAMPED,
        action::NOTHING_TO_DO,
    ] {
        if applied.stdout.contains(marker) {
            assert!(
                p.allows(marker),
                "apply did \"{marker}\" — diff never promised it.\n— diff:\n{diff_out}— \
                 apply:\n{}",
                applied.stdout
            );
        }
    }
    for line in applied.stdout.lines().filter(|l| l.starts_with('✔')) {
        let known = [
            action::APPLIED,
            action::POLICY_ONLY_CHANGE,
            action::ALREADY_APPLIED,
            action::MANIFEST_UNCHANGED_BUT,
            // A one-time infrastructure side effect, not a deployment
            // action — known on purpose so the scanner stays strict about
            // every other ✔ line.
            action::BACKUP_CONFIGURED,
        ]
        .iter()
        .any(|marker| line.contains(marker));
        assert!(
            known,
            "an action line the vocabulary does not know (a new seam?): {line}"
        );
    }
}

/// Runs the read face on the current scene state: its stdout (for failure
/// messages) plus the parsed promises.
fn preview(scene: &Scene, manifest: &str) -> (String, Promises) {
    let diff = scene.diff(manifest);
    let p = Promises::parse(&diff);
    (diff.stdout, p)
}

// ---------------------------------------------------------------------------
// The corpus — healthy tree first.
// ---------------------------------------------------------------------------

/// Never applied → the full first render. Then zero drift → nothing to
/// apply, and apply keeps every byte of the promise: no render (every
/// pack's SHA256SUMS unchanged), no publish (bookkeeping generation and
/// the dist mirror unchanged).
#[test]
fn healthy_tree_zero_drift_honors_nothing_to_apply() {
    let scene = Scene::new();
    let manifest = scene.manifest_at(11434, 8080);

    let (first_diff, p) = preview(&scene, &manifest);
    assert!(p.never_applied, "a fresh store promises the first render");
    let first = scene.apply(&manifest);
    assert_honored(p, &first_diff, &first);
    assert!(first.stdout.contains(action::APPLIED));
    assert_eq!(scene.generation(), 1, "the first render mints generation 1");
    let packs = scene.pack_digests();
    let mirror = scene.mirror_generation();

    let (drift, p) = preview(&scene, &manifest);
    assert!(
        p.nothing_to_apply && !p.baseline_cache_refresh,
        "a fresh cache needs no refresh: {drift}"
    );
    let second = scene.apply(&manifest);
    assert_honored(p, &drift, &second);
    assert!(second.stdout.contains(action::NOTHING_TO_DO));
    assert_eq!(scene.pack_digests(), packs, "no render");
    assert_eq!(
        scene.generation(),
        1,
        "no publish: the bookkeeping never moved"
    );
    assert_eq!(
        scene.mirror_generation(),
        mirror,
        "no mint: the mirror never moved"
    );
}

/// Policy edits → the policy-only fast path: a generation publishes, no
/// pack re-renders (SHA256SUMS untouched), the bookkeeping advances by
/// exactly one.
#[test]
fn healthy_tree_policy_edits_honor_the_fast_path() {
    let scene = Scene::new();
    let base = scene.manifest_at(11434, 8080);
    assert!(scene.apply(&base).success);
    let packs = scene.pack_digests();

    let manifest = scene.manifest_at(11435, 8080);
    let (drift, p) = preview(&scene, &manifest);
    assert!(p.policy_only_fast_path, "{drift}");
    let applied = scene.apply(&manifest);
    assert_honored(p, &drift, &applied);
    assert!(applied.stdout.contains(action::POLICY_ONLY_CHANGE));
    assert_eq!(scene.pack_digests(), packs, "no pack re-rendered");
    assert_eq!(scene.generation(), 2, "exactly one generation minted");
    assert_eq!(scene.mirror_generation(), 2);
}

/// Identity edits → every pack re-renders (SHA256SUMS move) and a
/// generation publishes above the watermarks. The hub's dial listener is
/// the edit: an identity-face move that keeps the realm (one store still
/// signs one realm).
#[test]
fn healthy_tree_identity_edits_honor_the_full_render() {
    let scene = Scene::new();
    let base = scene.manifest_at(11434, 8080);
    assert!(scene.apply(&base).success);
    let packs = scene.pack_digests();

    let manifest = scene.write_manifest(&plan_corpus::with_hub_listen(
        &plan_corpus::mesh_manifest_text("preview-contract", 11434, 8080),
        16677,
    ));
    let (drift, p) = preview(&scene, &manifest);
    assert!(p.rerenders_every_pack, "{drift}");
    let applied = scene.apply(&manifest);
    assert_honored(p, &drift, &applied);
    assert!(applied.stdout.contains(action::APPLIED));
    assert_ne!(scene.pack_digests(), packs, "every pack re-rendered");
    assert_eq!(scene.generation(), 2);
}

// ---------------------------------------------------------------------------
// The corpus — a stale baseline cache (the digest disagrees, the snapshot
// proves the face unchanged).
// ---------------------------------------------------------------------------

/// Stale cache, zero drift: applied + the refresh promise, whose "no render
/// and no publish" tail apply keeps byte for byte (packs, bookkeeping and
/// mirror all unchanged).
#[test]
fn stale_cache_zero_drift_honors_the_refresh_promise() {
    let scene = Scene::new();
    let manifest = scene.manifest_at(11434, 8080);
    assert!(scene.apply(&manifest).success);
    scene.age_the_cache(&manifest);
    let packs = scene.pack_digests();

    let (drift, p) = preview(&scene, &manifest);
    assert!(p.nothing_to_apply && p.baseline_cache_refresh, "{drift}");
    let applied = scene.apply(&manifest);
    assert_honored(p, &drift, &applied);
    assert!(applied.stdout.contains(action::RESTAMPED));
    assert_eq!(scene.pack_digests(), packs, "no render");
    assert_eq!(scene.generation(), 1, "no publish");
    assert_eq!(scene.mirror_generation(), 1, "no mint");

    // The refresh bought a fresh cache: the next diff promises nothing but
    // the no-op.
    let (drift, p) = preview(&scene, &manifest);
    assert!(p.nothing_to_apply && !p.baseline_cache_refresh, "{drift}");
}

/// Stale cache, policy edits: the fast path carries them (one generation,
/// no pack re-rendered); the refresh rides the fast path's own record.
#[test]
fn stale_cache_policy_edits_ride_the_policy_only_record() {
    let scene = Scene::new();
    let base = scene.manifest_at(11434, 8080);
    assert!(scene.apply(&base).success);
    scene.age_the_cache(&base);
    let packs = scene.pack_digests();

    let manifest = scene.manifest_at(11435, 8080);
    let (drift, p) = preview(&scene, &manifest);
    assert!(p.policy_only_fast_path, "{drift}");
    assert!(
        p.baseline_cache_refresh,
        "the refresh is part of the prediction: {drift}"
    );
    let applied = scene.apply(&manifest);
    assert_honored(p, &drift, &applied);
    assert!(applied.stdout.contains(action::POLICY_ONLY_CHANGE));
    assert_eq!(scene.pack_digests(), packs, "no pack re-rendered");
    assert_eq!(scene.generation(), 2);
}

/// Stale cache, identity edits: the snapshot settles the disagreement as a
/// real identity edit — the honest full-render promise, never an
/// unverifiable hedge and never a silent policy-only pass.
#[test]
fn stale_cache_identity_edits_are_settled_by_the_snapshot() {
    let scene = Scene::new();
    let base = scene.manifest_at(11434, 8080);
    assert!(scene.apply(&base).success);
    scene.age_the_cache(&base);
    let packs = scene.pack_digests();

    let manifest = scene.write_manifest(&plan_corpus::with_hub_listen(
        &plan_corpus::mesh_manifest_text("preview-contract", 11434, 8080),
        16677,
    ));
    let (drift, p) = preview(&scene, &manifest);
    assert!(
        p.rerenders_every_pack,
        "the snapshot proves the edit: {drift}"
    );
    let applied = scene.apply(&manifest);
    assert_honored(p, &drift, &applied);
    assert!(applied.stdout.contains(action::APPLIED));
    assert_ne!(scene.pack_digests(), packs);
    assert_eq!(scene.generation(), 2);
    let (drift, p) = preview(&scene, &manifest);
    assert!(
        p.nothing_to_apply,
        "the render recorded a fresh cache: {drift}"
    );
}

// ---------------------------------------------------------------------------
// The corpus — stale trees. The 2026-11-02 incident's own shape.
// ---------------------------------------------------------------------------

/// The incident's exact order, through the shipped binary: apply → a
/// policy-only apply (the fast path does not touch packs) → a real revoke
/// moves the deny list past the tree's embedded CRLs. diff must name the
/// stale tree, promise the re-render AND the publish above the watermarks,
/// and must not promise the no-op or the fast path; apply then does
/// exactly that (full render, fresh embedded snapshots, generation minted
/// above the watermark) and the scene converges back to matches.
#[test]
fn revoke_after_a_policy_only_apply_diff_names_the_stale_tree_and_the_mint() {
    let scene = Scene::new();
    let base = scene.manifest_at(11434, 8080);
    assert!(scene.apply(&base).success);

    let manifest = scene.manifest_at(11435, 8080);
    let applied = scene.apply(&manifest);
    assert!(
        applied.stdout.contains(action::POLICY_ONLY_CHANGE),
        "the fast path ran first: {}",
        applied.stdout
    );
    assert_eq!(scene.generation(), 2);

    let revoked = scene.revoke_home_win();
    assert!(revoked.success, "{}", revoked.stderr);

    let (drift, p) = preview(&scene, &manifest);
    assert!(p.pack_tree_stale, "{drift}");
    assert!(
        p.rerenders_every_pack && p.publishes_above_watermarks,
        "the mint-and-publish is part of the prediction: {drift}"
    );
    assert!(
        !p.baseline_cache_refresh && !p.nothing_to_apply,
        "a stale tree is not a no-op: {drift}"
    );
    let packs = scene.pack_digests();
    let applied = scene.apply(&manifest);
    assert_honored(p, &drift, &applied);
    assert!(applied.stdout.contains(action::APPLIED));
    assert!(
        applied
            .stdout
            .contains(action::EMBEDDED_REVOCATION_SNAPSHOT),
        "the re-render embeds the fresh deny list: {}",
        applied.stdout
    );
    assert_ne!(scene.pack_digests(), packs, "every pack re-rendered");
    assert_eq!(scene.generation(), 3, "minted above the watermark");

    let (drift, p) = preview(&scene, &manifest);
    assert!(p.nothing_to_apply, "converged: {drift}");
}

/// A retired pack.toml vintage, zero drift: diff names the format fact and
/// the publish; apply re-renders and the pack loads under the current
/// format again.
#[test]
fn stale_format_zero_drift_diff_names_the_retired_vintage() {
    let scene = Scene::new();
    let manifest = scene.manifest_at(11434, 8080);
    assert!(scene.apply(&manifest).success);
    plan_corpus::deprecate_pack_format(&scene.out_dir().join("packs/agent-svc-host"));

    let (drift, p) = preview(&scene, &manifest);
    assert!(p.pack_tree_stale, "{drift}");
    assert!(
        drift.contains("pack.toml does not parse as the current pack format"),
        "{drift}"
    );
    assert!(p.publishes_above_watermarks, "{drift}");
    assert!(!p.baseline_cache_refresh, "{drift}");
    let applied = scene.apply(&manifest);
    assert_honored(p, &drift, &applied);
    assert!(applied.stdout.contains(action::APPLIED));
    assert_eq!(scene.generation(), 2);
}

/// A retired vintage with policy edits pending: the full render carries
/// them — diff says the fast path is superseded, and apply never takes it.
#[test]
fn stale_format_policy_edits_are_carried_by_the_full_render() {
    let scene = Scene::new();
    let base = scene.manifest_at(11434, 8080);
    assert!(scene.apply(&base).success);
    plan_corpus::deprecate_pack_format(&scene.out_dir().join("packs/agent-svc-host"));

    let manifest = scene.manifest_at(11435, 8080);
    let (drift, p) = preview(&scene, &manifest);
    assert!(p.pack_tree_stale && p.fast_path_superseded, "{drift}");
    assert!(!p.policy_only_fast_path, "{drift}");
    let applied = scene.apply(&manifest);
    assert_honored(p, &drift, &applied);
    assert!(!applied.stdout.contains(action::POLICY_ONLY_CHANGE));
    assert!(applied.stdout.contains(action::APPLIED));
    assert_eq!(scene.generation(), 2);
}

// ---------------------------------------------------------------------------
// The corpus — watermark divergence (the locally observable shape).
// ---------------------------------------------------------------------------

/// A node state mirror above the bookkeeping: diff promises the re-publish
/// above the watermarks; apply re-publishes the same policy — minting at
/// the DIST floor + 1, not the bookkeeping + 1 — and no pack moves.
#[test]
fn watermark_divergence_honors_the_republish_above_the_dist_floor() {
    let scene = Scene::new();
    let manifest = scene.manifest_at(11434, 8080);
    assert!(scene.apply(&manifest).success);
    plan_corpus::write_state_policy_mirror(&scene.out_dir(), "home-win", 6);
    let packs = scene.pack_digests();

    let (drift, p) = preview(&scene, &manifest);
    assert!(
        p.watermarks_diverge && p.republishes_above_watermarks,
        "{drift}"
    );
    assert!(!p.nothing_to_apply, "{drift}");
    let applied = scene.apply(&manifest);
    assert_honored(p, &drift, &applied);
    assert!(
        applied
            .stdout
            .contains(action::REPUBLISHING_ABOVE_THE_WATERMARKS),
        "{}",
        applied.stdout
    );
    assert!(applied.stdout.contains(action::POLICY_ONLY_CHANGE));
    assert_eq!(scene.pack_digests(), packs, "no pack re-rendered");
    assert_eq!(
        scene.generation(),
        7,
        "minted above the dist floor, not the bookkeeping"
    );
    assert_eq!(scene.mirror_generation(), 7);

    let (drift, p) = preview(&scene, &manifest);
    assert!(p.nothing_to_apply, "converged: {drift}");
}

// ---------------------------------------------------------------------------
// The corpus — damaged input fails loudly on BOTH faces.
// ---------------------------------------------------------------------------

/// A damaged bookkeeping db is an error on both faces — never a quiet
/// downgrade to never-applied on one and a full render on the other.
#[test]
fn a_damaged_baseline_fails_loudly_on_both_faces() {
    let scene = Scene::new();
    let manifest = scene.manifest_at(11434, 8080);
    assert!(scene.apply(&manifest).success);
    let db = scene.issuer_dir().join("store.db");
    let healthy = std::fs::read(&db).unwrap();
    std::fs::write(&db, &healthy[..healthy.len() / 2]).unwrap();

    let diff = scene.diff(&manifest);
    assert!(!diff.success, "a damaged baseline is not a quiet read");
    assert!(diff.stderr.contains("issuer store db"), "{}", diff.stderr);
    let applied = scene.apply(&manifest);
    assert!(!applied.success, "and not a quiet write either");
    assert!(
        applied.stderr.contains("issuer store db"),
        "{}",
        applied.stderr
    );
}
