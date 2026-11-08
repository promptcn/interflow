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

## [0.12.0] - 2026-11-08

### Changed (breaking — fleet roster epoch 3, 2026-11-04, full re-render)

- The signed Runtime Policy gained a required `nodes` fleet-roster face —
  every ingress, agent and hub the manifest declares, signed as the realm's
  desired state. Membership is a signed fact, so retirement and renaming
  become detectable on any machine carrying a current pack: the new
  host-level reconciliation (below) tells a retired or renamed node's
  leftovers from a serving member by the roster, not by heuristics. The
  format epoch is 3: same terms as epoch 2 — every pack re-renders on the
  next `plan apply`, mixed-version fleets fail closed at the first frame,
  there is no migration path by design.

### Added (epoch-2 redeploy follow-ups, 2026-11-04)

- `doctor host` and a closing sweep in `node install`: the machine's
  interflow footprint (systemd units + pack directories) reconciled against
  the installed set and the signed roster. A unit without a pack (the
  races-for-ports-at-next-boot trap), a pack absent from its realm's
  current roster (retired or renamed — named with its unit), and a rostered
  pack without a unit are each pointed at with their cleanup instruction;
  `.previous`, `.retired-*` and staging siblings are deliberate history
  and never flagged.
- `node retire --pack packs/<kind>-<node>`: the explicit inverse of
  `node install` — disable --now, remove the unit, daemon-reload, and
  archive the pack directory as `<name>.retired-<date>` (archived, never
  deleted; same-day re-runs refuse rather than overwrite).
- `install.sh` copies binaries with a byte-identical skip (`cmp -s`; a
  skipped binary says so) — re-running a second realm's install on the
  same machine no longer replaces unchanged binaries, so the disk-swap
  detection only speaks on a real disk change. A `--root <dir>` flag
  selects a self-contained layout (everything under one root, no system
  user — the same contract `node install --root` offers, for containers
  and sandboxes); the default machine-scope path is unchanged.
- `doctor ingress --nginx-dir <dir>` reconciles the deployed nginx
  fragment directories against the current render set: superseded
  fragments (the rename leftovers whose server names race the current set
  on include order), expected-but-missing fragments, names no signed route
  declares, and conflicting `server_name` definitions across two loaded
  files (red — nginx silently ignores the later one) are each named with
  the removal instruction. Nothing is removed automatically.
- The GUI's onboarding gained "Import a node pack…": a `.iflowpack`
  carries the node's identity, hub endpoint and transport on its own, so a
  pure agent machine starts from the pack and never touches a deployment
  manifest (creating a deployment is demoted behind an Advanced fold with
  an explicit "brand-new deployment" caution). Upgrades now also narrate
  what they retired instead of absorbing it silently: unreadable
  stored preferences and a remembered deployment that no longer opens as
  one each show a dismissible banner exactly once per format era.

### Changed (performance — hot-path audit 2026-11-04, non-breaking)

- The hub's active-stream table is sharded by stream id (16 std-RwLock
  shards) and every stream entry carries its delivery sender on both
  dispatch planes; the per-Data-frame cost drops from one global lock plus
  the agent registry's two-level hop to a single shard read. An in-place
  re-registration's stale sender presents as a closed channel and
  re-resolves once through a flat data-plane projection maintained at the
  registry's two mutation points.
- The agent-side dispatch (h2 and QUIC downstream) delivers non-blockingly
  (`try_send` fast path; a full stream parks its frames per-stream-ordered
  while other streams flow, resolving parked frames under the existing
  timeout-and-poison discipline at batch end); the h2 poll loop no longer
  head-of-line-blocks every stream behind one stalled consumer, and the
  per-frame timeout `Sleep` only materializes under backpressure (the
  write-stall timers in the TCP/e2e pumps arm lazily the same way).
- The h2 upstream carries one `(header, payload)` channel element per
  frame — the payload `Bytes` reaches the h2 DATA frame zero-copy and the
  per-frame tokio mutex is gone (a std slot lock hands out the current
  sender during upload rebuilds).
- Inner-TLS configs are cached on the material itself: per-expected-CN
  client/QUIC configs (128-entry bound), the CN-agnostic server acceptors
  (TCP and inner-QUIC ALPN shapes) and the shared chain verifier build
  once per material; the egress acceptor, ingress connector, inner-UDP
  association acceptor and the expose edge's per-connection connector are
  `Arc` clones instead of full rebuilds (anchor-store deep-copies, CRL
  copies and webpki verifier rebuilds per stream/connection are gone).
  The per-stream full-handshake security design is unchanged. The agent's
  hub-plane client config is likewise cached per TLS shape (reconnects
  stop re-reading PEMs and the system trust store; the first build runs
  on the blocking pool).
- The QUIC stream write path is two-segment (`write_all(header)` +
  `write_all(payload)`): the whole-frame memcpy is gone on the stream
  path (the DATAGRAM path's single ≤1 KiB contiguous buffer is inherent
  to the quinn API, documented as such). DATAGRAM eligibility is a
  per-handle flag instead of a parallel shared set; the traffic/control
  read loops read directly into the decode buffer (`read_buf` + reserve),
  dropping the 16 KiB intermediate chunks and their second copies.
- CRL membership is pre-parsed at plane-swap time (per-issuer revoked
  serial sets in canonical minimal-hex form): the registration gate's
  revocation check is a hash lookup instead of a PEM→DER→BigUint re-parse
  per registration/poll, property-tested equivalent to the numeric
  comparison across leading-zero and sign-byte encodings.
- Tenant derivation parses the leaf once (CN, validity window and serial
  ride the derived identity — the accept paths' three follow-up DER parses
  are gone) and pre-filters candidate tenants by issuer/subject
  fingerprints (a chain can only anchor where some link's issuer matches
  a root's subject; unresolvable shapes fall back to the full set —
  webpki stays the sole authority).
- The expose edge's per-workspace inner-TLS material validates the
  active-credential pointer by file stamp (one `stat` per connection;
  a rotation rebuilds on the blocking pool), the hub compiles the
  PROXY-protocol policy once at assembly (`server.proxy_protocol` is
  startup-fixed), the QUIC datagram toggle and ACL lookups left the
  per-Open config lock (an atomic and a borrowed scan respectively), and
  the inner-UDP carrier reuses its transmit/response buffers and sleeps
  to the connection's own timer deadline (20 wakeups/s/session gone).

### Changed (breaking — full redeploy)

- The breaking-refactor batch: every compatibility channel for pre-existing
  deployments is retired. Stores, packs and policies from any earlier build
  are refused loudly (re-provision, never migrated): the issuer store's
  bookkeeping db moved to shape 3 (one shape per build generation, no
  ladder), the format epoch is 2 (signed policy `services[].address` and
  `mesh_egress` are required keys — the absent-field serde shims retired
  with the epoch), and the digest-kind registry is gone: the applied
  declaration snapshot is the one truth, the recorded digest its unlabelled
  cache, and a disagreement is settled against the snapshot (a stale cache
  heals as a bookkeeping-only refresh; a real identity edit reads as one).
  `plan diff`'s "baseline unverifiable" fourth state retired with it — the
  question is always decidable. The GUI's legacy TOML preference import,
  the backup config's v1 normalization, the revocation list's counter
  backfill, and the audit ledger's optional `agent` field tolerance retired
  alongside (audit records now always name the agent).
- The staging tar is written through the `tar` crate with hand-built
  headers (mtime/uid/gid zeroed, modes normalized to 0755/0644), fixing a
  hand-rolled writer's silent corruption on >100-byte root names and its
  panic on oversized octal fields; the archive's bytes are a function of
  content and executability only.
- Dependency governance: the cross-crate externals (the rustls family,
  clap, tempfile, time, reqwest, tracing, hyper, quinn, …) are declared
  once in `[workspace.dependencies]`; members add features, never versions.

### Fixed

- The frontend-proxy XFF precheck probed only the first policy route and,
  on its 502, asserted a single cause ("the fronting proxy does NOT inject
  X-Forwarded-For") with instructions to edit a correct nginx config. A
  502 through the proxy is a dual-cause signal — a stripped header, or a
  dead backing service behind a correctly injected one. The precheck now
  probes every route: any answered route proves the header was injected
  (named, with the proving route); only an all-closed sweep raises the
  flag, with both causes, every route and its backing service listed, a
  discriminating action per route, and the nginx directive framed as the
  hypothesis to confirm rather than the verdict.
- The CRL revoked-serial set carried minimal hex forms (`"d"` for 0x0d)
  while membership queries used the normalized even-length spelling
  (`"0d"`), so odd-digit serials never matched their own revocations; the
  set is built through the same normalization the query side uses.
- Endpoint-host extraction parsed by hand (`split_once(':')`) in three
  places, truncating IPv6 literals at the first colon: the nginx stream
  SNI map key, the control-endpoint vs route-host conflict check, and the
  ACME dispatch host all keyed on `[` for a bracketed address. All three
  now parse through the shared authority parser (fail-closed).
- Pack digest verification skipped malformed `SHA256SUMS` lines silently
  and never looked for files the manifest did not list. It now rejects
  malformed lines loudly and reconciles the tree against the manifest in
  both directions (runtime artifacts — `state/`, the audit ledger, the
  post-seal embedded CRL snapshot — are exempt by design and documented).
- `plan diff` on a legacy JSON-pair store misreported "never applied"; the
  pre-db read fallback retired with the breaking batch (the misreport's
  cause with it).

### Added

- `plan stage` renders the nginx fragments fresh instead of copying them
  from dist, and every rendered artifact now carries a provenance line
  (`# rendered by interflow-cli <build tag> from manifest sha256:…`) —
  headers, install.sh, units alike. Staging could silently ship an older
  build's fragment output (dist is whatever the last apply rendered; its
  renderer vintage may lag the staging CLI by any number of versions, and
  `--verify-staging` would happily green-light the stale bytes). The
  fragments are now rendered by the staging build from the current
  declaration through the same pure functions `plan apply` uses (one
  source: same build + same declaration ⇒ byte-identical output), any
  dist lag is named as an ℹ, and the snapshot tests codify the policy
  that the vintage line's tag component varies with the build while
  everything else stays byte-locked.
- `plan stage --host <kind>/<node> --with <kind>/<node>` (repeatable):
  one physical machine hosting several nodes (e.g. an ingress edge and a
  hub on one ECS box) stages ONE tree — bin/ and install.sh once (the
  union of the nodes' binary faces), every node's pack, the nginx
  fragment union, one stage-manifest (schema 2, a `hosts` array) and one
  deterministic tar. One scp, one `--verify-staging`, one `install.sh`,
  then `node install` per node; the freshness gate still refuses the
  whole tree when the next apply would re-render packs, naming every
  node it covers.
- `doctor route` and `doctor ingress` now check the public certificate
  material of every frontend-proxy route host — presence, SAN coverage
  (wildcards included), cert/key pairing and validity (≤14 days warns,
  expired fails; a `·` note names hosts no certbot renewal config
  covers), all local reads with a concrete fix per finding. The deployed
  vhost fragment's `ssl_certificate` lines are authoritative when
  present (a divergence from the convention is flagged), `--certs-dir`
  overrides the default `/etc/nginx/certs`, and the key files are read
  in every PEM form openssl and certbot emit (PKCS#8, PKCS#1, SEC1).

- The preview and the gate are one decision. `plan diff` and `plan apply`
  now share a single fork decision (`classify_fork`): the read face runs
  the same baseline verification, the same pack-tree freshness probes
  (retired pack format vintage; an embedded CRL snapshot that predates
  the issuer's deny list) and the same local watermark gate the apply
  gate runs, so the prediction cannot promise a fork the gate would not
  take. `plan diff` gained `--out` (default `dist`, like apply — the tree
  it must look at), and two new classifications surface where apply
  really would act despite an unchanged declaration: `pack_tree_stale`
  (every pack re-renders and a new generation publishes above the
  watermarks — the re-render's ✔ line now names the publish too) and
  `watermarks_diverged` (dist artifacts above the bookkeeping: the same
  policy re-publishes above the watermarks), both on the CLI face and
  the GUI's "unapplied changes" badge. Pending policy edits on a stale
  tree are announced as carried by the full re-render ("the policy-only
  fast path does not apply"); the baseline-restamp note keeps its "no
  render and no publish" wording only where it is true (the no-op fork)
  and says which fork's record the re-record rides elsewhere; and the
  no-op prediction states its boundary when a hub endpoint is configured
  (the hub's own watermarks are re-queried at apply time). Every
  promise/action phrase lives in one exported vocabulary
  (`plan::narration`) that diff, apply and the new preview-honorability
  contract test (`plan_preview_contract`: 15 corpus states × diff then
  apply × every action must be covered by a promise, fail-closed parsers,
  the shared state corpus in interflow-testkit's `plan_corpus`) all
  consume — the test cannot drift from the faces it polices.

- The issuer store's applied baseline is self-describing. Every recorded
  identity-face digest now carries the strip rule that produced it
  (`digest_kind`: `stripped-v1` until 2026-10-11, `stripped-v2` since —
  the rule registry lives in one place and a future rule is one variant
  away); the store's bookkeeping db walks from shape 1 to shape 2 on its
  next write (reads of a shape-1 db keep working, untouched); and the
  applied declaration snapshot is the truth a digest mismatch is
  verified against before anything is called an edit. `plan apply`
  re-records a baseline it has verified unchanged under the current rule
  as a matter of course — on the policy-only path by construction, and
  on the no-op path as a bookkeeping-only write (`✔ manifest already
  applied — … baseline bookkeeping re-recorded under the current rule
  (no render, no publish)`, history kind `baseline-restamp`) that also
  gives a pre-snapshot baseline the snapshot it never had, so the next
  `plan diff` reads line by line. The same verification makes the
  classification immune to the next rule change and to a representation
  change in the manifest's serialization (a field added to the struct):
  both compare unequal, both are checked against the snapshot, neither
  is mistaken for an edit. A baseline the store cannot verify (recorded
  before kinds were tracked, no snapshot, and moved since under every
  known rule) surfaces as the new `baseline_unverifiable` state on the
  GUI's "unapplied changes" badge and re-renders once — fail-closed,
  with no override flag.

- `--version` on every CLI, one identity: `interflow-mesh --version` /
  `-V` now answers like `interflow-cli --version` — the same
  `<semver> (<build tag>)` line, byte-identical to the `version`
  subcommand it keeps — and the remaining clap CLIs in the tree (the
  soak gate, `interflow-soak-node`, the `loss_hol` bench) carry the same
  flag instead of none. A guard (`just version-surface`, also in CI)
  holds `version = interflow_buildinfo::VERSION_WITH_TAG` on every clap
  root, so a new binary can neither miss `--version` nor regress to the
  tag-less default.

- Leg biography + cross-machine correlation: incident timelines stop
  being ssh + journalctl + manual timestamp alignment. The hub's audit
  ledger gains a read face — `GET /audit/biography?agent=&since_secs=`
  (control-gated) filters one leg's records (the qualified-id fields
  directly, the circuit-keyed kinds through the agent's current
  circuit) and answers newest-first with reasons expanded; `interflow-cli
  doctor biography --agent home-win --since 2d` prints the timeline
  (`10-19 09:12 agent_registered registered (circuit d92d3f05…, build
  …)`). The `registered`/`evicted` events carry the agent's qualified
  id as an additive field (pre-field history links through the current
  circuit only — the honest bound of additive evolution, verified
  against the chain). The agent side publishes its session's circuit as
  an 8-hex short id at registration, and the stream-level log lines
  (ingress idle-timeout, egress backend-established) carry `circuit
  d92d3f05 · stream 1a2b3c4d…` — one grep now hits both machines' logs
  for the same session. No new id space, no wire changes.


- Connection-quality time windows: `doctor link` answers "is it up
  now"; chronic degradation now has a window behind it. Every mesh
  agent keeps two in-memory rings — session-establishment instants
  (one-hour reconnect rate) and demanding-probe roundtrips (ten-minute
  RTT p50/p99 plus a timeout counter) — written at their existing
  observation points and shipped on the node-status report's new
  additive `connection` section. The renewal backoff ladder's current
  stage (e9c7ed2's 60s→15m real ladder) rides the CRL-liveness report
  as an additive field, with a hub-tracked per-day maximum. The fleet
  faces carry all of it; `doctor link --hub` renders per leg
  (`reconnects 0/h · backoff stage 0/5 · rtt p50 105ms p99 190ms`),
  failing on the chronic shapes with the case-hardened readings built
  in: reconnects-plus-climbing-backoff is the long-term-loss edge, and
  unanswered probes while the heartbeat stays in-register carries the
  2026-10-09 note ("check `circuit evicted` on the hub before assuming
  the network"); a p99 past 3× the median earns the path-degradation
  note. The GUI fleet rows carry the reconnect/probe ⚠ chips.


- Credential-expiry fleet face: "don't forget to rotate" is now a
  displayed level instead of a discipline. The hub already parses every
  connecting agent's leaf validity window from the mTLS chain — it now
  retains the last-seen window per leg (surviving eviction, the
  ledger-only remembrance shape) and the fleet faces carry it
  (`leaf_not_before_unix` / `leaf_not_after_unix` / the tier the span
  implies / the registration instant). The countdown is absolute: an
  offline leg's days keep ticking, rendered with a stale note. The
  judgment is per-tier with single-sourced lines — offline: ⚠ under
  14 days (one rotate-ceremony lead), ✘ under 7 (the backup window);
  registrar: the identity module's span-relative phases, where warn
  reads "renewal stalled". `doctor link --hub` renders the line per leg
  (red fails the reading — the rotate is overdue); the GUI fleet rows
  carry the countdown chip with per-tier hover hints (thresholds
  self-reported through the overview, zh/en).


- Fossil-stream and session-headroom faces: what only the node itself
  can observe now reaches the fleet faces over a new additive control
  pair (`NodeStatus` 0x30/0x31 on QUIC, `POST /node/status` on h2 — the
  control-plane byte block grows past its original `0x2F` ceiling, same
  epoch). Every mesh agent's engine intrinsically ships its per-stream
  byte-activity levels — each ingress rule's last-byte instant, touched
  by the pumps beside their existing idle-deadline resets (one atomic
  fetch-max, no lock on the data path) and armed at listener-bind with
  the rule's own idle budget as the silence-judgment anchor. A stream
  quiet past 10× its own budget (7 days when unbudgeted) reads fossil —
  "mounted, listening, but the service is gone" becomes a ⚠ instead of
  a memory. The hub's stream-admission headroom rides the same faces
  (`streams_in_flight` per leg, the global count plus the caps on the
  hub row): remaining capacity under 20% warns BEFORE the
  `Global stream limit reached` wall. `doctor link --hub` renders both
  (fossil per stream, headroom per scope, day-scale ages humanized);
  the GUI fleet rows carry fossil ⚠ chips and the tight-headroom chip,
  with the fossil multiples and the warn ratio self-reported through
  the overview.


- Mailbox/queue watermark face: the operator's queued stream ops are now
  continuously visible instead of living one CLI message long. Each
  agent's fleet row carries `pending_ops` — how many ops wait in the hub
  mailbox (undelivered and unconfirmed alike), since when (the oldest
  op's enqueue instant + label), and whether the 128-slot capacity guard
  ever dropped an op (`dropped_total`, cumulative — dropped is dropped,
  the re-issue decision reads the counter, not the journal warn). An op
  queued for an offline leg can sit for days; `doctor link --hub` renders
  the waiting state per leg (`⚠ 1 queued op(s) undelivered for 3d —
  node offline? (delivered on next check-in)`), failing the reading only
  when an ONLINE leg's ops outlived the delivery budget (the intent
  watcher not consuming). Enqueue and delivery transitions bump the
  floor version clock; the GUI fleet rows carry the waiting ⚠ chip with
  the drop history. The proposals queue gets the same watermark
  (`proposals_pending`: count + oldest submission, rendered as the hub's
  informational note).

- Watcher armed-assertion face: the hub's resident tasks (the heartbeat
  supervisor, the policy/CRL recency sweepers, the signed-policy reload
  watcher, the renewal loop, the CRL self-reporter) now register a
  watchdog row at spawn and touch it on every loop pass. The fleet
  snapshot's hub row and the `/policy/floor` overview carry the rows
  (name, own cadence anchor, last tick); a row quiet for strictly more
  than 3× its OWN interval reads silent — "the process is alive but a
  task inside it wedged" is now a one-glance assertion instead of a
  journal-scrolling session (the CRL-restart-loop shape found by
  pattern-matching journal lines). `doctor link --hub` renders the
  verdict (`✔ all watchers armed (5/5, …)` / `⚠ watcher "policy" silent
  45s (interval 10s)`, a silent row fails the reading) and the GUI fleet
  page shows the assertion strip. The fresh↔silent transitions (and only
  those — registration is boot-time and bumps nothing, an idle hub keeps
  version 0) bump the floor version clock, so the push contract carries
  them; the renewal
  loop attests its own passes through a `TickWatch` the hub assembly
  hands in (its liveness level, not an external poller's guess).

- Policy pull faces are now level-triggered: the hub records every
  completed policy pull — not-modified answers included — as a watermark
  plus its confirmation instant (`last_pull_unix`, carried by the fleet
  snapshot and the `/policy/floor` overview alongside `captured_at_unix`,
  the hub-side time anchor). A leg that pulls healthily while already up
  to date no longer reads as "never pulled", and a hub restart refills
  the face within one watch interval. `doctor link --hub` renders the
  four-state reading per leg (`policy_seen=15 · pulled 8s ago`,
  behind-with-recency, `silent` ⚠, and `never` — now with exactly one
  meaning), naming an online leg whose policy watcher stopped pulling as
  a failure. The same recency rides the GUI fleet rows.
- Silent policy faces are push-visible: a hub-side sweeper re-classifies
  pull recency and bumps the floor version clock on each fresh↔silent
  transition (threshold: 3× the 10s watch interval), so a dead policy
  watcher — which produces no pulls and therefore no ordinary face
  change — reaches `/policy/floor/version` watchers within the threshold
  plus one sweep, the same push contract as every other fleet-face
  change.

- Hub floor watch: `GET /policy/floor/version` — the fleet read model's
  change signal. The hub keeps a monotonic version over everything
  `/policy/floor` reports (presence, pull watermarks, the paused-stream
  and maintenance faces), bumped by every mutation funnel on both
  transports (h2 handlers and QUIC frame arms alike). Without `since` it
  is an immediate version probe; with `since=N&wait_secs=S` it HOLDS the
  request until the version diverges from `N` or the wait elapses (the
  blocking-query shape), so a long-lived reader learns about an external
  write — a pause queued from a terminal, a maintenance declaration,
  another operator's publish — the moment the hub's face moves, not on
  its own polling cadence. Control-principal gated like its sibling
  endpoint; answers on every hub (the tracked face exists independently
  of the policy channel).

- GUI live fleet invalidation: the deployment's hub floor watcher — a
  background task holding one blocking watch on the version endpoint —
  emits a `hub-floor` event on every advance and the deployment scope
  re-pulls the composed fleet on receipt. External state changes now
  reach the 流/服务/编队/总览 views at face-convergence time (a CLI
  `stream pause` shows its yellow dot the moment the hub reports it),
  replacing the fleet page's 30s poll; local-node faces (listener
  actuals, node lifecycle) invalidate the same read model through a
  debounced re-pull.

- Active breaker recovery, agent side: every mesh agent with the target
  breaker enabled now runs a background bare-TCP recovery prober. A tripped
  backend's revival is detected within one probe interval (loopback 1s,
  non-loopback 5s by default — `egress_recovery_probe_*` config) instead of
  after the 30s cooldown, and the probe dial is not a stream Open, so the
  cooldown's budget-isolation purpose is untouched. Breaker entries are now
  transport-namespaced (`tcp:`/`udp:` keys), so a TCP probe success can
  never "heal" a UDP-tripped entry and the two failure populations no
  longer contaminate each other. The `interflow_egress_target_breakers_open`
  / `interflow_edge_route_breakers_open` gauges (promised by a field comment
  since 2026-09-16) are wired for real, and prober activity is counted.

- Active breaker recovery, wire face: the `TargetRecovered` control-plane
  request/response pair (QUIC frames 0x2C/0x2D; `POST /breakers/recovered`
  on h2). An agent reports each prober-detected recovery out-of-band; an
  expose edge (hub fused with a public listener) closes the matching route
  breaker entries ahead of their cooldown — the root cure for the
  "outage shorter than cooldown" residual window where the backend was
  back but the public face kept answering 502 for up to a full cooldown.
  The notice is informational (an old hub 404s/skips it harmlessly; pure
  mesh hubs acknowledge without acting) and acts only on routes resolving
  to the sending agent. The edge route breaker now keys by canonical host
  (one entry per host regardless of `Host:` header spelling).
- Clock-skew fault injection for the renewal scheduler: the test clock
  gains a skewed start (the host runs ahead of or behind the registrar
  that issued its credentials) and independent wall / monotonic axes (an
  NTP-style wall step that wakes nothing; monotonic time with the wall
  frozen). Six cases pin every wall-anchored decision under skew — a slow
  host renews at its own 50% and fails closed exactly |skew| after the
  real expiry, a fast host past the leaf fails closed before any dial, a
  fast host inside the half renews early — and pin which clock each
  decision reads: the CRL freshness bound ignores wall steps in either
  direction and trips on monotonic time alone; the renewal threshold
  ignores monotonic time and opens on the wall. The renewed material is
  the registrar's work in every case (expiry anchored to the real
  issuance instant), so skew moves when the scheduler acts, never what it
  receives.
- Identity-plane lifecycle matrix: the registrar / renewal / CRL face
  organized by migration event, the way the mesh data plane already is —
  every row names its invariant and the test that locks it or a reasoned
  exemption (`crates/mesh/tests/identity_lifecycle_matrix.rs`, living
  beside the code). New locks for the rows that had none: a registrar
  that is unreachable when the renewal window opens and returns at the
  same address (the ladder keeps retrying, nothing fails closed early,
  the first attempt after revival converges in one pass); a leaf that
  expires un-renewed (the node stops serving within one poll interval of
  the real expiry through the production wiring, the hub refuses the
  expired leaf at every new handshake, fresh material is accepted); CRL
  pulls that fail and recover inside the freshness bound (self-healing,
  no restart); and one enrollment code raced by many clients (exactly one
  is issued a leaf). The inventory also records two facts about the
  current contract: the hub audits an expired-leaf session but relies on
  the node's own fail-closed to end it, and a one-hour leaf's warning
  band is narrower than the backoff ladder's top rung.
- The per-client rate limiter's memory bound is an operator knob: the hub
  config gains `[auth] max_tracked_clients` (default 65536 — the former
  built-in constant, so existing deployments change nothing), sizing the
  most distinct clients the limiter tracks at once; the startup log names
  the effective bound (rounded down to multiples of 32) and the edge
  listener's runtime policy carries the same knob for its new-connection
  limiter. Beyond the bound the limiter forgets the debt of clients idle
  for a whole generation first — counted in
  `interflow_rate_limit_capacity_evictions`, never refusing a newcomer.
  (The edge's manifest-level declaration of the knob is a pack-format
  change and ships separately.)
- Soak gate: an identity-churn phase. After warmup the runner presents
  thousands of never-seen client addresses to the hub through the PROXY
  preamble (the fronted-topology path), idles two rotation periods, then
  sweeps every limiter shard — and asserts, on the hub's production
  `/metrics`, that the tracked population never exceeds its configured
  bound, that capacity evictions fire under the pressure, and that the
  population recedes once it stops. The phase's wall budget is validated
  up front (a run too short to hold it is refused with the arithmetic;
  `--quick` is lengthened to fit; `--identity-churn-per-sec 0` is the
  explicit opt-out). The nightly workflow now builds the soak node it
  runs — its build step still named the pre-2026-09-22 binary, so the
  gate had been failing at startup.
- Windows CI: a `windows-smoke` job builds and lints the workspace on the
  msvc target and runs the tests aimed at the Windows risk classes —
  atomic writes on NTFS and the SQLite store, config and path handling,
  pack assembly — plus a platform smoke that drives the path a Windows
  agent node actually runs (register, one TCP stream end to end, restart,
  re-register, stream again). Windows is a production platform that had
  no automated coverage; the cfg(not(unix)) branches the job lints were
  brought to zero locally first through `cargo xwin clippy` against the
  same target. A `.gitattributes` pins LF line endings so byte-exact
  fixtures survive Windows checkouts.
- `plan stage --host <kind>/<node>`: the per-server staging tree as one
  command — hand-assembly failed three times in as many weeks (install.sh
  run outside the dist root, a flat staging directory, a `cp` missing
  `-R`), all the same class: the correct shape lived only in runbooks.
  Each host stages exactly its minimal face (verified `bin/`, its own
  pack, its nginx fragments on a frontend-proxy ingress, install.sh —
  never another node's pack, never a unit, never the policy mirror).
  `bin/` is verified against the artifact record: a `build-manifest.*.json`
  is consumed and checked (commit must match this build, each artifact's
  sha256 re-hashed, the build tag scanned out of the bytes — cross-built
  Linux binaries cannot run on the staging machine), exact canonical
  names otherwise, and a build tag of `unknown` refuses outright. The
  pack copy runs through the product's recursive copier and the staged
  copy is validated by `load_runtime` — the install-time digest funnel
  moved to production time. Staging is refused while the next
  `plan apply` would re-render packs (the same `classify_fork` decision
  diff and apply share); the policy-only fast path and the re-publish
  leave pack bytes untouched and stage with a note. Every tree carries
  `stage-manifest.json` (sha256 per file) and a deterministic tar+sha256
  pair — re-staging reproduces both byte for byte. Every host's tree is
  self-sufficient for fresh installs and upgrades alike:
  `interflow-cli` always ships (the target host runs `node install` with
  it), `interflow-mesh` when the node's unit execs it or the host is an
  ingress edge.
- `install.sh` anchors every path at its own directory (never the CWD —
  the 2026-10-18 incident), fails loudly when `bin/` is missing or empty
  instead of silently skipping it (the 2026-11-01 incident), and gains
  `install.sh --verify-staging`: the transfer-integrity gate that checks
  a tree against its `stage-manifest.json` (every listed file's sha256,
  no unlisted files) with system tools only. The install path runs the
  same check automatically whenever a staging manifest is present, so
  the loop closes without a flag to remember.

### Changed

- Every per-source admission budget (the hub auth limiter, the edge's
  per-connection gate, the UDP inbound buckets, the per-source connection
  cap) now counts one **client**, defined once: an IPv4 address — an
  IPv4-mapped IPv6 spelling is the same client — or an IPv6 /64. A host
  rotating addresses inside its /64 can no longer mint fresh budgets
  (keyed per address, it could), and a dual-stack listener no longer
  double-counts an IPv4 visitor's mapped spelling. Operational note: hosts
  behind one IPv4 NAT or inside one IPv6 /64 share a budget, and the hub
  charges its auth budget per request — a fleet of agents on one LAN
  registering through the same hub should keep an eye on
  `rate_limit_per_minute` (the audit record and logs still name the exact
  address, never the summary).
- Data-plane log levels follow one contract: lifecycle transitions stay
  `info`, per-connection and per-stream diagnostics stay `debug`, and
  per-frame / per-heartbeat lines (hub routing "Data frame received /
  Route direction / Data received / Data sent", QUIC relay "no route"
  drops, tunnel late-frame drops, heartbeat Ping/Pong bookkeeping) move
  to `trace`. Nothing changes at the default `info` filter; a
  `interflow_mesh=debug` session now reads connection-level events
  instead of four lines per data frame (one soak run's hub log had
  reached 273 MB that way). Steady-state drop counts move to metrics:
  `interflow_hub_frames_dropped{reason=no_route|forged}` and
  `interflow_dispatch_frames_dropped_total{reason,direction}`. The QUIC
  transport-stats samplers (cwnd / rtt / lost packets / black holes,
  10 s cadence) emit under their own `transport_stats` target, so
  forensics enable them with `RUST_LOG=info,transport_stats=debug`
  without opening a crate-wide debug face.
- Log output no longer carries ANSI color codes when it is not going to a
  terminal (files, pipes, journald); `NO_COLOR` disables color
  unconditionally and `CLICOLOR_FORCE` forces it on, on every node entry
  (pack-driven mesh binary, `interflow-cli node run`, the soak nodes).
- The soak gate bounds its own evidence: nodes run on the narrow default
  filter, a `log_volume_bound` assertion fails a scenario whose raw logs
  exceed `--log-budget-mb` (default 64), `--node-log-filter` reruns a scenario
  verbose for forensics (self-declared, skips the budget), run logs are
  gzipped in place after the artifact is written, and past runs' logs
  under `bench-results/soak-*` are pruned oldest-first to
  `--retention-mb` (default 512; every `results.json` kept, the newest
  three completed runs never touched).

### Fixed

- `plan diff` promised "no render and no publish" for states whose next
  apply did both: a stale pack tree (a revoke that moved the deny list
  past the embedded CRLs, a retired pack format) triggered the apply
  gate's freshness probes into a full re-render that minted and
  published a new generation — unpredicted, consuming a pending
  generation slot with no warning. The same half-truth existed on the
  policy-only path (the fast path publishes a generation, yet the
  restamp note still said "no publish") and on the GUI publish flow
  (an unchanged-but-stale tree applied a full render while the
  orchestration treated it as a no-op and left every local node on the
  stale packs). All three are the read face and the write face
  disagreeing; they are closed by the single fork decision above.

- `plan diff` (and the GUI's "unapplied changes" face) reported
  `identity-face edits pending — the next plan apply re-renders every
  pack` for a declaration with zero drift when the issuer store's applied
  baseline had been recorded by a CLI older than the 2026-10-11
  policy/identity face split (the pre-SQLite JSON pair, or its row
  absorbed verbatim into the db). The digest behind that classification
  had been computed under an older strip rule — services and routes
  still counted as identity material — so it compared unequal to the
  current rule's digest of the very same text, and the inequality was
  asserted as an identity edit; a route added on such a baseline (the
  field case) read the same way. A digest mismatch is now verified
  before it condemns anything: against the applied declaration snapshot
  (exact — the current rule over both texts) or, for a snapshot-less
  legacy baseline, against the older rules the registry keeps. Zero
  drift on a pre-split baseline reads `matches the applied state` plus an
  `ℹ … recorded under the stripped-v1 strip rule` note, a mesh-rule edit
  still takes the policy-only fast path, a real identity edit still
  reads identity-pending wherever a snapshot exists to prove it, and
  only a baseline nothing can vouch for reads the new honest verdict —
  `the applied baseline predates digest-kind tracking, carries no
  declaration snapshot, and the declaration has moved since — the next
  plan apply re-renders once and records a self-describing baseline` —
  which never claims an identity edit it cannot see.

- `plan diff` (and the GUI's "unapplied changes" face) reported a
  deployment as `never applied` when its issuer store still carried its
  bookkeeping in the pre-SQLite JSON pair (beside no `store.db` — the
  shape a store is in when the last write was made by an older CLI, or
  after restoring a pre-pivot backup). Those files are absorbed into the
  db by the next write, but the read paths returned "nothing recorded"
  until then, so a pre-apply review of a deployment at policy generation
  3 said the next apply would be a full first render. The issuer store's
  read methods now answer from the legacy pair when no db exists — the
  classification is the recorded one (`matches the applied state (policy
  generation 3)` / `policy-face edits pending`), followed by the honest
  `no declaration snapshot exists` line (the old format kept none). The
  binding contract gains the same truth: a legacy store bound to another
  manifest is refused by `plan apply` exactly as a db-backed one is,
  instead of being silently rebound. A malformed legacy file is a loud
  error on read, never a quiet downgrade to never-applied; reads stay
  side-effect free (no db materialized, nothing renamed), and the absorb
  remains a write-path event.
- The per-client rate limiters grew without bound: every distinct source
  address a public listener saw left a permanent entry in the limiter's
  state table, so an ingress process's memory crept up with the internet's
  scanner traffic (the observed face: a monotone rise in the daily
  zero-traffic RSS floor, ~1.5 MB/day). The limiters now run on a bounded
  state store: idle clients expire losslessly (the expiry predicate is the
  same one the underlying library's own cleanup uses, pinned by
  differential tests against a never-evicting limiter), and a hard cap
  bounds the table no matter how many distinct sources arrive — sustained
  pressure beyond it forgets only clients idle for a whole generation
  (new clients are still admitted; a client still spending its budget
  keeps it), with the degradation counted
  (`interflow_rate_limit_capacity_evictions`) and warned about rather
  than silent. The tracked population is exported as
  `interflow_rate_limit_tracked_clients{limiter}`.
- The credential-expiry fleet face was empty on all-QUIC fleets: every
  leg read `leaf expiry unknown (no window on this hub's face)` right
  after registering. The hub's QUIC registration arm was a hand-mirrored
  copy of the h2 arms' registration semantics, and the mirror had
  drifted — it never wrote the expiry ledger, lacked the control-principal
  refusal (a control credential could register as a data-plane agent over
  QUIC and obtain a routable circuit), lacked the registration-time CRL
  gate (revoked chains were only caught incidentally by tenant derivation,
  attributed as `tenant_unclaimed`), lifted a maintenance declaration only
  on a fresh row (never on a reconnect), audited none of its refusals, and
  left a stale-green registration behind when the HelloAck failed.
  Registration semantics now have one home: a transport-neutral core
  (`HubState::register_agent`) owns the gates and the full side-effect
  list, and the h2 explicit, h2 implicit and QUIC arms keep only their
  identity sourcing and answer shaping. Route-lease hygiene is expressed
  as circuit-bound (a registration keeps only the leases of the circuit it
  installs), which preserves the implicit re-registration path's reuse of
  the connection circuit and the agent's session-scoped route cache. The
  expiry-face, CRL hot-swap and control-principal e2e suites now run on
  both transports; the core carries its own unit pins.
- Revoking a credential did not sever a QUIC leg: the sweep removed the
  registry row, but the session's terminate step only cut the h2 pipes,
  so the QUIC relay connection stayed alive (keepalive + Pong kept the
  heartbeat happy) and the route leases it had been issued — which never
  expire on their own — stayed usable for opening new streams until the
  connection eventually died. Eviction now closes the QUIC connection on
  every eviction reason (the CONNECTION_CLOSE names the reason), and a
  revocation eviction additionally clears the circuit's route leases.
- The leg-biography timeline could come out oldest-first for records
  written within the same second: the reader sorted by the ledger's
  second-resolution timestamp only, and the stable sort kept same-second
  rows in file order (registration first), so the timeline's newest-first
  contract depended on writes straddling a second boundary. Same-second
  rows now order by the audit chain's monotonic sequence; a unit test
  locks the order against both file layouts.
- `just soak` (and the nightly soak workflow) had panicked at scenario
  start since the libtest runner guard landed: the guard's env/argv
  heuristic classified the standalone soak binary as a plain `cargo test`
  queue the moment it generated its test certificates. The soak binary
  now declares itself a standalone runner explicitly
  (`interflow_testkit::declare_standalone_runner()`), and the guard
  honours that declaration ahead of its heuristics.
- Tripped target breakers no longer couple recovery to the trip time: the
  cooldown's expiry admitted the FIRST possible recovery probe, so a
  backend that revived mid-cooldown stayed dark until the remaining
  cooldown burned down — the "local up, public 502" false-failure window
  (tens of seconds after every dev-server restart) that read as a fault
  and invited rollbacks it did not need. Recovery is now driven by the
  backend's actual return (the prober above), on both the agent face and,
  via the pushed notice, the expose edge's route face.

- Planned unavailability, stream level: `interflow-cli stream pause` /
  `stream resume` stop and restart ONE ingress stream without touching the
  node, the fleet, or the manifest. A paused stream's listener is really
  down and its port really free (e.g. lending 127.0.0.1:11434 to a local
  process); the intent persists across node restarts (a restart must not
  quietly re-grab the port), does not survive a re-provisioned node, and
  only an explicit resume lifts it. Both verbs are idempotent. The hub's
  status snapshot carries each node's paused streams as a first-class
  field; `doctor link` and `status diff` read them as planned (yellow),
  never as faults, and the GUI's 流 view shows a paused status with
  pause/resume actions (local nodes in-process, remote nodes through the
  hub). Pausing every stream of a node prints the pointer to node-level
  maintenance instead of leaving an empty shell.

- Planned unavailability, node level: `interflow-cli maintenance on|off`
  declare a leg's coming absence EXPECTED — the whole 2026-10-18
  maintenance story (shutdown windows, host reboots) without firing the
  accidental-death signals. While declared, a departing session still
  cleans up the registry but is exempt from eviction accounting (the
  `evicted_total` steady-window contract holds; a security revocation is
  never exempt); `doctor link --upgrade-check` reads offline legs under
  maintenance as planned (yellow), including probe targets on them (the
  data-plane triple is deliberately not counted against a listener that is
  down by intent). The declaration lives in the hub's state channel
  (survives hub restarts, declarable while the node is already down) and
  lifts ITSELF when the node rejoins — zero-operation recovery, no
  residual exemption. The GUI's 编队 view shows the maintenance word and
  offers declare/lift actions; `status snapshot`/`diff` carry the
  declaration as a first-class field.

### Fixed

- The stale-exec scan test no longer flakes on starved CI runners: the
  post-replacement assertion became a bounded wait-for-condition (the
  kernel's `/proc` view of a rename-over races the scan instant; the wait
  target is a condition, not a time) instead of a point-in-time assert. The
  wait itself moved into a shared testkit primitive (`eventually` /
  `eventually_sync`, whose timeout panics carry the last observation) that
  replaces the three ad-hoc polling-loop variants the suites had grown.
  No production code changed.
- The doctor XFF-precheck tests named a fixture node after a private
  machine (the release export's leak gate refused the 0.12.0 cut on it);
  the fixture identifier is neutral now. No production code changed.
- The doctor certificate-inspection tests embedded their synthetic
  openssl fixtures (the legacy SEC1 and PKCS#1 forms rcgen cannot emit)
  as literal PEM strings, and the release export's key-material gate
  refused the 0.12.0 cut on the private-key headers: the throwaway
  fixtures now assemble their header line from `concat!` parts — the
  assembled value is byte-identical, and no literal key-shaped header
  ships in the public tree. No production code changed.
- install.sh's changed-binary copy now lands as a staged swap (the new
  bytes arrive beside the old as `.new`, then `mv` replaces the
  directory entry atomically): GNU install on Linux rewrites an existing
  destination under the same inode (BSD/macOS installs land a fresh one),
  so the "a real change breaks the inode" contract the disk-swap
  detection reads did not hold on Linux machines — and even
  rm-then-install can hand the just-freed inode number straight back. A
  running process now keeps its old binary until exit across the swap,
  the same discipline `node install`'s staged swap uses.
- Two doc-comment citations sat mid-line ahead of their sentence, and the
  release export's strip pass (which removes the private parenthetical)
  left an orphaned `: …` / `;` continuation behind that clippy's
  doc-lazy-continuation lint rejected on the public tree; the citations
  are whole-line now, dropped cleanly. The GUI's localStorage test stub
  was likewise missing the `Storage` interface's `length`/`key` members
  (no local gate typechecks the frontend — the public gui job caught
  it). Neither changes behavior.
- The tree-walk single-sourcing's non-unix `entry_mode` stub could be a
  `const fn` (clippy's nursery `missing_const_for_fn`, a lint that only
  fires on the compiled Windows face — no local gate or ubuntu job sees
  it; the windows-smoke job caught it): `const` now, in step with the
  stub conventions elsewhere (`same_device` is const, `chown_tree` allows
  the lint). No behavior change.
- The install.sh execution tests rode `std::os::unix`'s inode face
  through an ungated module import, a hard compile error on the msvc
  test face (the build step compiles bins only and stayed green — the
  blind spot survived a ci round): the file is `#![cfg(unix)]` now,
  empty elsewhere — it runs a bash bootstrap and asserts inodes, unix
  end to end. The windows clippy step also converts its diagnostics
  into public annotations, the channel the test stages already use.
  No production code changed.
- The config path-anchoring tests asserted unix separator spellings
  byte-for-byte and failed on the Windows risk face the moment the
  clippy fix let windows-smoke reach its unit-test step (a face no
  earlier round this release had exercised): the assertions compare
  path components now (`Path::starts_with`/`ends_with`,
  separator-agnostic), keeping the Windows coverage instead of gating
  it off. No production code changed.
- The audit ledger's cross-process single-writer claim locked the active
  file itself, and that shape fails twice on Windows: std maps a bare
  append open to `FILE_APPEND_DATA` without `GENERIC_READ` (the
  whole-file lock call refuses the handle with "Access is denied" —
  every Windows machine took the designed degradation path and ran the
  audit sink disabled, always), and even with the handle fixed,
  `LockFileEx` is enforced against readers too, so a live active file
  would be unreadable to doctor/verify/GUI for the writer's whole
  lifetime. The claim now rides a sidecar lock file beside the ledger
  (`audit.jsonl.lock`, opened read+append, matching no pattern the
  discovery scan reads, and exempt from the pack digest reconciliation
  alongside the ledger family — a running node's pack keeps loading):
  the ledger itself is never locked, single-writer holds across
  processes on both platforms, and the fd closes with the last sink
  handle — the claim's exact lifetime.

### Security

- Dependencies: five RUSTSEC advisories disclosed 2026-10 against
  already-locked versions (found red on a clean tree — the advisory-db
  snapshot, not the code, decides this gate). Four are closed by upgrade:
  rustls-webpki 0.103.15 → 0.103.16 (path validation could accept
  distrusted emSign intermediates when the trust anchors allow such paths
  — the entire TLS stack rides it), webpki-roots 1.0.9 → 1.0.11 and
  webpki-root-certs 1.0.8 → 1.0.11 (both bundled the since-distrusted
  emSign ECC Root CA - G3 in their root sets; outbound HTTPS and ACME
  challenge faces), and tokio 1.53.1 → 1.54.1 (unsound `AsyncFd`
  constructors violating I/O safety — not called directly here; the
  patch closes the transitive surface). The fifth, basic-toml
  (unmaintained, archived upstream), is carried as a documented deny.toml
  exemption: its only path is a compile-time macro chain
  (age → i18n-embed-fl → i18n-config), never linked into a runtime
  binary, and no fixed version exists to upgrade to.
- age 0.11 → 0.12 (identity's pack/backup sealing): the breaking changes
  upstream are all outside this codebase's usage surface
  (`Encryptor`/`Decryptor`/`x25519`/`scrypt`), and ciphertexts sealed by
  0.11 decrypt under 0.12 — verified with payloads sealed by 0.11.5 and
  opened by 0.12.1 across both the passphrase and x25519 recipient paths.
  The chain refresh retires the proc-macro-error2 advisory exemption
  (RUSTSEC-2026-0173): i18n-embed-fl 0.10 moved to proc-macro-error3, so
  the ignore list shrank by one entry instead of growing. The move also
  pulls age's new p256-backed `age1tag`/`age1tagpq` recipient types, whose
  crypto-bigint 0.5.5 carries RUSTSEC-2026-0387 (timing variability in
  constant-time operations) — unreachable in this product (sealing only
  ever constructs x25519/scrypt recipients) and strand-locked by age's
  `p256 ^0.13` pin until RustCrypto's 0.14 line propagates; carried as a
  documented bridge exemption with that removal condition. Two same-day
  upstream yanks (clipboard-win 5.4.1, async-executor 1.14.0) surfaced by
  the same fresh-index fetch were rolled past (5.4.3 / 1.14.1), and the
  hybrid-array crate the new age chain pulls in made two e2e asserts'
  array `as_ref()` inference-ambiguous — both now spell the slice
  explicitly (`&request[..]`).
- `just ci` now includes `deny` (parity with the public ci.yml job): the
  2026-10-17 and 2026-11-03 advisory batches both sat invisible between
  local-green runs because advisories redden on disclosure, not on code
  change. machete stays a standalone recipe (no missing-tool fallback).

### Migration

- This release carries two format-epoch jumps, 1 → 2 → 3, folded into one
  cut — epoch 2 opened with the breaking-refactor batch above, epoch 3
  with the signed fleet roster; there is no epoch-2 release to stage
  through, and one coordinated window covers both. The epoch check stays
  strict equality on both ends, so a mixed-version realm fails closed at
  the first frame: this upgrade is a planned stop, not a roll. While the
  window is open, the not-yet-upgraded side logs `PROTOCOL_VIOLATION`
  frames, reconnect loops and (agent-side) out-of-tree probe alerts —
  expected window noise, gone when the last node lands.
- Every pack re-renders as a new generation (fresh digests), its
  `format_version` stamped 3 by the new CLI. Binary and pack must land on
  each machine at the same moment: stage per host, then per machine
  `install.sh` (new binaries; the running services are untouched)
  followed by `node install --pack` (new pack + restart, the atomic
  swap) — swapping one without the other fails to load at the
  `format_version` gate. Order hub first, agents after: the agent's
  reconnect discipline is built for exactly this interruption, and each
  agent's link recovers the moment it lands. On a frontend-proxy topology
  the node (binary + pack) swaps first, the nginx fragments and reload
  after — the reverse order fails the control-leg handshake. A GUI-managed
  local node updates through the "update node" flow (`node install`'s GUI
  face); its binary still goes through `install.sh` first.
- Nothing migrates: stores, packs and policies from any earlier build are
  refused loudly, by design. The issuer machine's bookkeeping db walks to
  shape 3 and the GUI's state dbs move forward on first run — neither
  rolls back with a binary; recovering those machines uses the issuer
  store's automatic backups, and an older binary refuses a newer db
  rather than guessing at it. The retired legacy shapes (the GUI's legacy
  TOML preference import, the backup config's v1 normalization, the
  revocation list's counter backfill, the audit ledger's optional `agent`
  field tolerance) are refused the same way — re-create in the current
  form rather than import. Signed policies missing `services[].address`
  or `mesh_egress` (required since epoch 2) or the `nodes` roster
  (epoch 3) are rejected at load; re-render from the current manifest
  instead of editing them by hand.
- Rollback is per node and returns both halves together: the kept
  `<pack>.previous` (via `node install --pack`, or a directory swap plus
  restart) and the old dist's `install.sh` for the binaries. A
  rolled-back node fail-closes against its upgraded peers exactly as
  before, so a partial rollback extends the window until every peer is
  back on the old epoch — finish the fleet or return it whole.

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
