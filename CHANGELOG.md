# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog 1.1], and this project adheres to
[Semantic Versioning 2.0.0]. Releases before 0.9.0 predate this changelog;
their curated summaries live in the annotated release tags (and the GitHub
Releases pages cut from them). Sections 0.9.0 and 0.10.0 were internal
milestones, never separately released: their content ships with v0.11.0,
the first public release carrying this changelog.

[Keep a Changelog 1.1]: https://keepachangelog.com/en/1.1.0/
[Semantic Versioning 2.0.0]: https://semver.org/

## [Unreleased]

## [0.11.1] - 2026-10-17

### Fixed

- Ambient proxy environments no longer break renewal: the renewal client now
  dials the registrar directly (`no_proxy()`). On any host exporting
  `http(s)_proxy` (Docker Desktop injects one into every container; corporate
  shells export one), every renewal request — mTLS identity-plane traffic to a
  pinned, usually loopback endpoint — was silently rerouted to a proxy that
  cannot reach it and failed with a fast opaque connection error. Discovered
  as the real root cause behind the "registrar fixture never becomes ready on
  Linux" backlog (the server never saw a single connection; the requests
  never entered the container's network namespace at all). Test-built clients
  gained the same immunity through a single direct-dial constructor. CI now
  enforces the immunity structurally: a dedicated test stage re-runs the
  identity-plane crates (registrar and renewal wholesale, plus the CLI
  renewal e2e) under injected unreachable proxies — every spelling reqwest
  reads, with an empty `no_proxy` so loopback is not exempt — and carries
  fail-closed self-checks (the injection asserted in the shell and again at
  the child-process layer; a proxy-honoring probe client must fail under the
  environment) that redden the stage itself if its injection or its teeth
  are ever lost. A regression to proxy-honoring dials is now caught on any
  runner, not only in a proxy-laden local container.
- Half-closing TCP clients now get their response on every platform. A client
  that shuts down its write side and awaits the answer (curl's shape) raced
  the whole teardown chain through the hub: the ingress pump's local-EOF
  drain window was zero, so the FIN became an immediate raw stream Close and
  the hub tore the stream down before the response could traverse it — macOS
  passed only by winning that race within ~3ms, Linux lost it
  deterministically. The tunnel now performs a proper directional close: the
  FIN propagates as the inner-TLS close_notify, the response drains within
  the same five-second window the egress side already used, the relay shuttle
  keeps serving the response leg after the TLS write half ends, and the raw
  Close goes out only after the answer has drained. The proposal-approval
  e2e (the only half-closing probe in the suite) and an ingress-side
  half-close regression test pass identically on macOS and Linux — the pin
  covers both hub transports, since h2 and QUIC share no stream-close code
  beneath the pump and each needed its own.

### Changed

- The registrar server's lifecycle is now injectable and observable:
  `serve` splits into bind + `serve_on(listener, token)`, so callers own the
  listening socket from its first moment (the ephemeral-port TOCTOU doctrine
  — no probe/drop/rebind window) and a `CancellationToken` performs graceful
  shutdown with connection drain; the stand-alone entry wires SIGTERM/Ctrl-C.
  Accept, PROXY-framing and TLS-handshake failures now log their full errors
  instead of closing silently, and the testkit grows a shared registrar
  fixture plus a global test logging sink (stderr + ring buffer, embedded
  into readiness panics) — the two Linux backlogs of 2026-10-17 were
  prolonged exactly by that blind spot. The eleven `#[ignore]`s they had
  pinned are removed; the suite is green on macOS (`just ci`) and in a
  proxy-laden Linux container (`scripts/linux-test.sh`).

## [0.11.0] - 2026-10-17

### Added

- Quitting the GUI no longer clears start intent: tray Quit now takes the
  engines down gracefully while `desired_running` stays persisted, so the
  next launch (post-upgrade reopen, shell:startup reboot) restores the
  running set instead of landing every node Stopped until a human clicks
  Start — the two-days-two-hits "forgot to Start" of the Windows upgrade
  runbook. Stop and stop-all keep their meaning (intent off, stays off).
  A one-shot amber notice on the nodes face ("all stopped — start them?")
  covers the residue the intent restore cannot decide: prefs written by the
  old quit-wipes-intent builds. The install-time launch itself needs no new
  mechanism — the NSIS finish page's run checkbox is default-checked.
- Installing moves forward only, everywhere: `update_pack` (the GUI's
  swap-in-place) refuses a pack older than the installed generation before
  the stop/swap touch anything; `plan apply`'s convergence picks the
  newest pack per identity instead of the first match; `node install`
  refuses downgrades unless the new `--allow-downgrade` flag names the
  deliberate rollback; the GUI's sealed-pack import refuses too. One
  mental model: updates advance, rollbacks are typed.
- The staging-window lifecycle closes at three standing enforcement points,
  not just the next rotate: the janitor (strictly-scoped name match +
  lenient pack-metadata agreement, best-effort) is shared by rotate, by the
  full-render apply (which re-renders the bases above every staging
  watermark and previously forgot the staging family entirely — the exact
  gap that left same-generation staging beside an advanced base), and by
  the GUI's `update_pack` (a locally-consumed staging has no possible
  offline receiver — an identity is one machine — so the swap's success
  removes it; the CLI `node install` keeps receiver-side semantics and
  never touches the operator's source copy).
- The Packs view renders one card per IDENTITY, not per directory
  (NodeCard grammar): principal + generation state + at most one primary
  action, with an open rotate window riding the card as an accent badge
  ("gen N to install" locally / "gen N to distribute" for remote
  identities). Consumed or superseded staging directories and archives no
  longer appear anywhere in the view — the filesystem stays their archive;
  the detail page resolves every action to its right source (update/distribute
  from the open window, rotate/revoke on the base, so revoke can no longer
  target a leftover shell).
- The hub's overview answer now self-reports its configuration name, so the
  fleet page attributes presence and generation by respondent — a row
  answers for the hub the deployment actually points at. A second, stale
  hub still answering from an old address shows as a stray row instead of
  silently merging into the live one.
- The streams page's rows are a language now: status is a dot plus a word
  (an unknown state renders a hollow circle — never a guessed color — and a
  down stream shows the bind-failure reason on hover), path weight rides a
  single layered arrow with the protocol as a badge pill, and clicking a
  row opens the stream's full story — the semantic sentence with live
  truth, declared-versus-actual binding, the idle-timeout default, the
  catch-up generation, and jump links to both endpoints. Row actions are
  an inline 调整 plus a ⋯ menu with labeled rename and delete, and
  structural edits in the streams and services tables refresh the list
  immediately instead of waiting for the next publish. `StreamDto` carries
  `bound_addr` and `last_error`, so a catch-up row honestly reports the
  old-generation binding it still serves.
- The agents picker is a master-detail: a statistics bar over the agent
  list, per-agent counts in the dropdown, and a newly created agent lands
  selected instead of requiring a second click.
- The services and streams views appear only when the deployment's shape
  has them (a hub-less source deployment carries neither), with the
  navigation bounce guard generalized to any hidden face; the services
  page's agent picker filters candidates by role.
- InfoHint — a shared ⓘ that carries a one-sentence concept. SectionPanel's
  permanent hint lines migrated to it (the full text is the aria-label;
  keyboard focus reveals it), and fourteen call sites inherited the
  density win without touching their props.
- The overview page projects by deployment shape: NEXT STEPS branches on
  what the deployment actually is, every issue step is a real action, the
  fleet table names members by their role, and the online column is gated
  on the hub actually answering rather than on any traffic.

### Changed

- The GUI sidebar's axis is the realm. The deployment switcher is the
  group's header — the open realm's name, or 打开部署… when none — with
  总览 / 流 / 服务 / 高级 expanding only while a realm is open; read-only
  realms join the switcher instead of hiding it, Peers lives under the
  deployment group, and the local group shrinks to a bottom entry (节点).
  "Switch deployment" structurally cannot land on the nodes face — the
  silent no-op of switching while on 节点 is gone.
- The local group's 机器/Machines entry is renamed 节点/Nodes, and the
  vocabulary now follows the engine model wherever it names a node or
  this view: the group title 本机 already carries the scope, so a plural
  "Machines" under it read as "this machine contains many machines."
  The rename is thorough, not cosmetic — i18n keys and values together
  (`dep.nav.nodes`, `dep.node.*`), MachinesView → NodesView, the
  internal view id, and the Rust doc comments that name the view.
  Deployment-face strings that refer to nodes also say 节点 now (添加
  节点, 打开节点 / 打开枢纽节点 / 打开源节点, publish counts in 个节点,
  the services table's first column matching the fleet table it shares
  data with) — the engine fields behind them (FleetNodeDto,
  target_agent, updated_nodes) were nodes all along. Machine wording
  survives only where the semantics are physical: the 本机 group title,
  the This machine log scope, and the 这台机器拨哪里 service dials.
- Explanatory copy settled into three layers: dialog-footer paragraphs
  collapsed into title ⓘ hints (the long-form reasons stay a hover away),
  nine over-long tooltips were compressed to a sentence each, and 51 dead
  i18n keys were removed with en/zh symmetry kept.
- The fleet page's status language converged: online drops the word (the
  label survives as screen-reader-only text), the PeerDot renders three
  honest states, and online rows pin to the top of their segment while
  keeping their order.

### Fixed

- Pack cards no longer offer "Update" for older-generation packs. The
  update check's digest clause (built for same-generation re-renders with
  different content) had no generation guard, so a rotate staging remnant
  or an archived pack lit up an Update button whose click silently
  downgraded the node — possibly reinstalling revoked material. The rule
  now lives in one place (`packUpdateAction`) and generations move forward
  only; the detail page's reinstall branch no longer serves as a second
  downgrade door.
- Restarting a hub in-process after it has served agent sessions no longer
  trips the audit ledger's single-writer guard: the poll-grace timer, the
  upload reader, and the QUIC relay reader all held an `Arc<HubState>`
  past the graceful drain (the grace timer alone slept a fixed 30 s), so
  the ledger path stayed claimed and the next `HubHandle::spawn` on the
  same path — the GUI's Rotate / Update of a live hub — panicked, taking
  the whole GUI process down. Every engine-state-holding background task
  is now tracked on the run's TaskTracker and exits on shutdown, so the
  claim releases with the drain. A side effect is a cleanup: a stopping
  hub no longer writes a late `AgentEvicted` record ~30 s after its audit
  flush.
- CRL change detection keys on `crl_number`, not bytes: an issuer
  re-issuing an equivalent CRL no longer reads as a rotation every poll
  (~60 s) — the phantom change had agents and edges exit gracefully and
  systemd restart-loop them at minute cadence.
- The renewal scheduler's retry backoff is a real ladder — 60 s → 2 m →
  4 m → 8 m → 15 m — instead of being flattened to a constant 60 s, and
  the scheduler now runs on an injected clock, so its timing is testable.
- The fleet page's hub row counts an overview answer as presence: the
  hub's own row no longer reads 未知 while the header it anchors already
  reports the hub reachable.

### Security

- Dependencies: quinn-proto 0.11.17 → 0.11.19 and rustls 0.23.45 →
  0.23.46, picking up seven October transport advisories — three
  remote-panic vectors in quinn-proto (zero-length STREAM frames during
  unordered reads, ACK_FREQUENCY minimum-delay handling, outgoing-datagram
  buffer accounting) and four in rustls (TLS secrets exposed by client-
  session `Debug` output, application data sent to the outer server after
  ECH rejection, a 1 GiB certificate-decompression allocation before
  authentication, and a classical-key-exchange downgrade persisting across
  later connections). For a tunnel whose peers are exactly the remote
  attackers, the panic vectors are release-blocking.
- The doctor's UDP probe pads its version-negotiation trigger to the QUIC
  minimum datagram size (1200 bytes): RFC 9000 §5.2.2 lets servers drop
  smaller unsupported-version packets, and quinn-proto 0.11.18+ does —
  the old 15-byte probe would read silence off a healthy QUIC listener
  and diagnose a broken link.

## [0.10.0] - 2026-10-13

### Added

- The CRL hot-distribution channel — revocation is delivered, not just
  recorded: `PUT /crls` (control-principal gated, RFC 5280 `crl_number`
  anti-rollback floor) accepts the issuer's current CRLs and hot-swaps the
  hub's verification plane onto them — revoked credentials are rejected at
  the NEXT mTLS handshake with no restart, live sessions holding a revoked
  leaf are evicted by serial, and the registration paths gate on the same
  live CRLs (no resurrection over a still-open connection). The hub's
  registrar pull lane rides the same swap instead of exiting for a
  supervisor restart.
- `revoke --manifest <interflow.toml>` — the finisher pushes the fresh
  CRLs to the hub's control plane (seconds-level enforcement; the outcome
  — applied / idempotent / unreachable / older hub — is narrated
  honestly). `plan apply`'s offline render tail pushes the same set.
- `GET /snapshot` now reports `hub.crl_numbers` (issuer stem → counter) —
  the "did the emergency revocation reach this hub?" verification face.

- The versioning and rotation policy now ships with the public repo at
  `documentation/versioning.md` — a new born-public documentation directory —
  and the version contract recognizes a second kind of version: local
  migration counters (operator-machine-local files whose legacy shapes
  migrate on read, e.g. `backup.json`'s v1 → v2).
- `issuer backup relocate` — the sanctioned way to move the backup target
  to a second medium: keeps the encryption identity and retention,
  checkpoints into the new directory immediately, and leaves prior
  versions in the old directory readable by the same recovery identity
  (the doctor hint and `issuer backup status` warning now point at it).
- `plan apply --force-rerender` — the explicit exit for pack-format
  retirements: skips the no-op gate and re-renders every pack with the
  policy generation still minted above every watermark (no reset).

### Fixed

- Issuer restore no longer carries the old machine's `backup.json` across:
  the restored store is unconfigured by design (same shape as a freshly
  created one), so the first checkpoint on new hardware can never land in
  — or silently create — the old machine's absolute backup directory.
  The restore output prints the derived `--recipient` so backups can be
  re-armed with the recovery identity the operator already holds.
- `plan apply` now senses a stale pack tree: when the manifest is
  unchanged but a rendered pack directory carries no current-format
  `pack.toml` (retired vintage, damaged file, or a wiped dist), the gate
  no longer reports "already applied" — every pack re-renders above the
  watermarks and the next run converges back to a no-op.
- `revoke` and `rotate` no longer depend on the strict pack loader.
  Revocation reads the certificates directly (serial and issuer
  attribution come from the certs themselves, including renewed
  state-channel credentials), so a pack whose format the loader refuses —
  a retired vintage, a damaged `pack.toml`, a leaked legacy copy — can
  still be revoked; rotate reads the generation number leniently. The
  dummy-node two-pass re-render ritual is retired.
- Backup directory nesting check: the store root and the candidate
  directory are now anchored through their deepest existing ancestor
  before comparison — a symlinked temp root (macOS `/var` →
  `/private/var`) could previously split one tree across two spellings
  and let a nested backup dir slip past the refusal.
- Issuer backups: the stored `backup.json` now pins the backup directory
  as an absolute path (format v2). Legacy configs carrying a CWD-relative
  directory are resolved against the store's parent on read and persisted
  by the next checkpoint, so `status`/`rekey`/`backup now` no longer
  depend on the working directory they are invoked from — the version
  history can no longer split across two directories.
- Issuer backups: version ordering keys on the timestamp embedded in the
  file name, with mtime demoted to a same-second tiebreak. A copied or
  synced backup directory (mtimes reset) no longer misidentifies the
  newest version, prunes the wrong file, or reports a false "store changed
  since the last successful backup".
- CLI: a stdout pipe closed early (`… | head`) now silences further
  output instead of panicking on the next write. Commands run to
  completion through their normal exit path — every side effect (files
  written, checkpoints taken) still lands — via a new fault-tolerant
  output layer that all CLI stdout goes through.
- Build: the issuer store's `mint_uuid` adapts to getrandom 0.3.4 (`Error`
  no longer implements `std::error::Error`), same shape as the other
  entropy call sites.

## [0.9.0] - 2026-10-12

### Added

- `plan diff` — a drift view of the declared manifest versus the applied
  snapshot.
- Expose hot channel: services and routes now apply without a process
  restart, and listen addresses can be changed online.
- GUI: deployment-centric redesign — five views (overview, streams,
  services, machines, peers), visual language v2, the local-node view as an
  unconditional first-class surface, and a version popover in the sidebar.
- `[liveness_probe]` configuration section — the mesh liveness probe's
  timing parameters are now operator-configurable.
- Atomic renames in the declared manifest editor: renaming an item lands in
  one step, with no stale-name residue.
- Mesh end-to-end lifecycle matrix with fault injection, run as a dedicated
  CI job.

### Changed

- Declared documents now carry a digest compare-and-set: a manifest changed
  on disk since it was last applied is surfaced as a conflict instead of
  being silently overwritten.
- GUI preferences moved into a `prefs.db` SQLite store, and the issuer's
  binding/applied accounting moved into the issuer `store.db`. Both migrate
  forward only; the legacy files are absorbed once on first open.
- Session handles are generation-typed, so a stale handle can no longer
  evict a re-registered session.
- Versioning policy v2: explicit SemVer scopes (PATCH = drop-in batches,
  MINOR = feature batches), a monotonic format epoch with a lean
  breaking-change procedure, a coordinated-upgrade runbook, and this
  changelog as the single source of release notes.

### Fixed

- Mesh: the eviction guard now carries circuit credentials — a dead watcher
  can no longer take down a session that re-registered in the meantime.
- Mesh: ingress reconcile no longer floods the log with steady-state
  heartbeat lines; reconciliation results collapse into a per-class report.
- GUI: table columns with CJK text wrapped mid-word in all views (cells are
  now nowrap with horizontal scroll); Fleet badges use product vocabulary;
  the packs listing no longer treats a `.previous` backup as a pack.
- Build: unbounded incremental-session growth under `target/` is now
  contained at the source.

### Migration

- No format-epoch change: the wire format and Credential Pack layouts are
  unchanged, and existing packs remain loadable without re-rendering.
- State migration is automatic on first run — GUI preferences into
  `prefs.db`, issuer binding/applied accounting into `store.db`; legacy
  files are absorbed once and renamed `.migrated`.
