# Version and rotation model

Interflow deliberately separates four user-visible ideas:

| Concept | Example | Purpose |
|---|---:|---|
| Product version | `0.9.0` | Identifies a source release or binary, and tells the operator what the upgrade asks of them (SemVer scopes below). It never decides wire compatibility. |
| Format epoch | `FORMAT_VERSION = 1` | The single compatibility epoch for Interflow-owned frames, inner hello, and Credential Packs. |
| Generation | `1, 2, 3, …` | The single signed-object rotation counter used for anti-rollback. |
| Local migration counter | `backup.json` v1 → v2 | Versions an operator-machine-local file with a single writer; legacy shapes migrate on read instead of failing closed (below). |

## Product version — SemVer with explicit scopes

The product version follows Semantic Versioning 2.0.0 with the compatibility
scopes defined below. Nothing in the toolchain consumes it mechanically —
release artifacts are binaries and images, never crate publishes — so the
number's entire job is the signal it sends to an operator.

- **PATCH** (`0.9.0 → 0.9.1`): a drop-in batch. Bug fixes and internal work
  only — no new config keys, no CLI surface change, no pack re-render, wire
  changes additive-only per the epoch contract. Upgrading requires nothing
  beyond the usual binary swap.
- **MINOR** (`0.9.0 → 0.10.0`): a feature batch — new capabilities, new
  config keys (optional, with defaults), new CLI commands. While the project
  is in `0.x`, MINOR is also the compatibility axis (SemVer rule 4): breaking
  changes ride a MINOR and must follow the epoch procedure below.
- **MAJOR** (`1.0.0`): reserved for the stability declaration (the 1.0 gate
  below); afterwards MAJOR is what carries breaking changes.

Downgrades are never supported. The rollback path is the `.previous`
installation kept by `node install` and the issuer store's automatic
backups; machine-owned stores migrate forward only (below), so an older
binary refuses a newer store rather than guessing at it.

A fix-only sync that should not release simply lands on `main` untagged (the
default — see release cutting). The PATCH slot exists so that a fixes-only
batch that *should* release has an honest number to wear.

The version is defined once by the Cargo workspace (`[workspace.package]`)
and mirrored in the GUI package manifest; `check_version_contract.py` pins
every mirror, including the CHANGELOG's newest versioned section. Internal
crate dependencies carry no mirror at all: each is declared once in
`[workspace.dependencies]` as a bare path spec (nothing is published to
crates.io — the source export is the distribution) and inherited by members
with `interflow-x.workspace = true`, so no version literal exists to drift
on a bump; the checker holds that structure. If publishing ever starts,
versions go into the root declarations — one file — and the checker's rule
flips to value-matching the workspace version.

## Format epoch

Every Interflow-owned machine format — data-plane frames, the inner-stream
hello, and Credential Pack metadata — shares `FORMAT_VERSION`, declared only
by `interflow-contract`. The value is a **monotonic epoch**: a breaking
change to any of those formats bumps it, and endpoints or packs carrying any
other value are rejected fail-closed rather than migrated.

During the current `0.x` protocol-churn phase the check is strict equality
on both sides: a mixed-version realm fails closed at the first frame, and
upgrades follow the coordinated-upgrade runbook. When the protocol
stabilizes, the
1.0 gate requires the rolling window — the hub accepting epoch `N-1` for one
release cycle — so a realm can roll binaries without a paired stop.

A breaking change must carry all of (deliberately lean; this phase is
expected to repeat):

1. `FORMAT_VERSION` +1 in `interflow-contract`;
2. a MINOR bump — breaking changes never ship in a PATCH;
3. a `Migration` section in that release's CHANGELOG entry;
4. a pass over the coordinated-upgrade runbook (ordering, window behavior).

The 2026-10-10 frame-type renumbering and signed-policy strictening happened
under the old "redefine in place" doctrine and is archived as the last
in-place change of epoch 1; the first breaking change after it opens epoch 2.

### Additive changes never bump the epoch

Additive evolution is a load-bearing compatibility guarantee, not an accident
— receivers keep tolerating:

- unknown frame types (skipped unless `FLAG_MUST_UNDERSTAND`);
- unknown flag bits (ignored on receive);
- unknown keys in JSON control-plane payloads;
- unknown capability bits.

The compatibility-contract tests in `interflow-core` pin each of these. A
sender may use a new wire feature only once the peer advertised support —
capability bits in the Hello/HelloAck handshake (`interflow_contract::caps`).
A change that cannot be expressed as an addition is breaking and bumps the
epoch instead; there is no third kind.

## Local migration counters

The format epoch above versions everything that more than one process must
agree on at the same time, and its discipline is strict equality — nothing
migrates. A second, narrower kind of version exists: a **local migration
counter** versions a file that lives on a single operator machine, has one
writer (this binary), and whose old bytes on real disks must keep loading.
Fail-closed would strand every legacy file at upgrade time, so these
formats migrate instead: read the old shape, normalize it in memory, stamp
the new value on the next write.

Discriminating criterion — who has to agree, and what happens to legacy
bytes. Cross-process agreement (frames, the inner-stream hello, Credential
Pack metadata) is the epoch: a peer carrying any other value is rejected,
never migrated. A file only this binary reads and writes on one machine,
where an operator's existing older file must keep working, is a local
migration counter: it migrates on read.

Current membership:

- `backup.json`'s `version` field (`crates/identity/src/backup.rs`): v1
  stored the configure-time `backup_dir` exactly as passed — CWD-relative
  when the operator ran from the deployment tree; v2 pins it absolute.
  Reads normalize the v1 shape in memory; the next mutation persists it.
- The SQLite `user_version` stores in "State and rotation planes" below
  are the same doctrine in engine form: machine-owned, forward-only, a
  store written by a newer build refused rather than guessed at.

Declaration form — the guard. A local migration counter whose constant name
would otherwise hit `check_version_contract.py`'s forbidden legacy terms is
*declared*, and the declaration has two halves that must both hold (the
`LOCAL_MIGRATION_COUNTERS` list in that script is the single source of who
is registered):

1. registered there: named file + named term + this section;
2. the counter's declaration site cites this section by anchor —
   `documentation/versioning.md#local-migration-counters`.

Registration without the anchor citation, the citation without
registration, or an entry pointing at a section that no longer exists all
fail the scan. The forbidden terms stay forbidden everywhere else, and
renaming a counter to dodge the word list is the anti-pattern this
mechanism exists to make unnecessary — and to expose.

## State and rotation planes

- Human-authored desired-state and node configuration files carry no
  machine-format field.
- Machine-owned state stores migrate by SQLite's `user_version` (the issuer
  store's `store.db`, the GUI's `prefs.db`): the shape lives in code, bumps
  forward only, and a store written by a newer build is refused rather than
  guessed at. This is not a counter in a human document — the
  no-machine-fields rule above governs what people edit, and these stores
  are never hand-edited.
- A Credential Pack and the Trust Bundle and Runtime Policy embedded in it
  must carry the same generation. Loading rejects any mismatch.
- `interflow-cli rotate` issues generation `N + 1`. Runtime policy older than
  the highest generation accepted by a node is rejected.
- Local registrar-driven leaf renewals may switch active credential files
  atomically, but they do not change the signed-object generation.
- TLS, HTTP/2, QUIC, and PROXY-protocol version selection belongs to those
  external protocol implementations. Their versions are not Interflow
  internal format versions.

## The 1.0 gate

The project declares 1.0 only when all of these hold:

- the rolling epoch window is implemented and has survived one real breaking
  change on the live fleet (hub accepting `N-1` across a full cycle);
- a run of consecutive MINOR releases shipped without an epoch bump;
- the coordinated-upgrade runbook has been exercised end-to-end at least
  twice on real machines;
- the identity and security model has been stable across that same window.

At 1.0 the SemVer axes take their standard meanings: PATCH = compatible
fixes, MINOR = compatible features, MAJOR = breaking.

## Release cutting

A product version "ships" when `vX.Y.Z` is tagged on the public repo —
`release.yml` runs only on `v*` tag pushes (five CLI targets + four GUI
bundles + the docker image; the Release page is created automatically with
the tag annotation as its body). The export script only syncs the `main`
branch and never tags: cutting the release is a separate, explicitly
deliberate step, because not every export is a release — post-release fix
syncs (CI fixes, doc touch-ups) land on `main` untagged by design. Four
steps:

1. Private version-bump commit — `scripts/bump_version.py X.Y.Z`: refuses a
   dirty tree and refuses an empty `[Unreleased]` (bookkeeping debt is paid
   before the version moves), mirrors the version (workspace `Cargo.toml`,
   GUI `package.json` + `package-lock.json` via `npm version`, Cargo.lock's
   workspace members via `cargo update -w`), promotes `[Unreleased]` to
   `[X.Y.Z] - date` and re-opens a fresh empty `[Unreleased]`, re-runs the
   version-contract check, and lands as a dedicated 🔖 commit.
2. `./scripts/export_public.sh <target> --update "Release vX.Y.Z: <milestone
   summary>"` — syncs `main` (the public-CI parity run included) and, when
   the tree's version has no matching tag yet, closes with a reminder
   printing step 3's exact command.
3. Cut: `./scripts/release_public.sh <target> vX.Y.Z` — after its contracts
   hold (tag == the target tree's workspace version; the CHANGELOG carries a
   `## [X.Y.Z]` section; every already-released section still matches its
   tag annotation verbatim; tag unused locally and on the remote; target
   HEAD == origin/main; clean tree), it creates an annotated tag whose body
   is that CHANGELOG section and pushes it. Any failed contract leaves
   nothing behind.
4. Wait for `release.yml`; the Release page then shows the CLI archives,
   GUI bundles, checksums and the docker image (22 assets), with the
   CHANGELOG section as the body — identical to the tag annotation by
   construction.

Only tag commits produced by the export flow — its local parity run already
proved that tree passes its own CI. Never tag a commit that reached `main`
by any other path.

## CHANGELOG

`CHANGELOG.md` (repo root, exported) is the single user-facing record of
what changed. Keep-a-Changelog 1.1 format, English, `Added / Changed /
Fixed / Security` sections — plus a `Migration` section in any release that
bumps the epoch or requires pack re-renders.

Bookkeeping is enforced, not remembered:

- The file always opens with `## [Unreleased]` — entries accumulate there
  as work lands, and the bump promotes the whole section in one move
  (enforced by `scripts/check_version_contract.py`).
- Entries are written with the change, never reconstructed at release
  time: once commits after a bump have touched product surfaces
  (everything tracked except the private trees, repo infrastructure and
  CI/build configuration), the changelog must have gained at least one
  entry line since that same bump (`scripts/check_changelog_debt.py`, in
  `just ci`, the export preflight and the public CI). Where the entry
  lives is style — `[Unreleased]` is the documented home; folding into
  the still-unreleased current section counts as visible. There is no
  marker or opt-out syntax: a batch with nothing user-facing to say pays
  with one honest line.
- Entries never reference private paths and stand alone — the file ships
  verbatim with the export, so a pointer into the private archive tree
  would publish as a dead link (`check_version_contract.py` fails it at
  commit time; the exporter's reference gates catch any survivor).
- A released section is immutable: the tag annotation is the published
  Release body, so post-release facts go under `[Unreleased]` for the
  next version, never into a shipped section. `release_public.sh` refuses
  a cut while any existing tag no longer matches its section verbatim,
  and `bump_version.py` refuses to promote an empty `[Unreleased]`.

The release flow above makes the tag annotation, and therefore the Release
body, a verbatim copy of the versioned section — and the contracts above
keep it that way after the cut.
