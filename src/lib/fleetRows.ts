/// The 编队 page's row model (2026-10-15 nav re-axis): one pure merge of
/// the realm's three truth sources — the hub's report (authoritative
/// presence + generations while reachable), the local mesh agents' peers
/// planes (leaf countdowns, and the whole truth when the hub is not
/// reachable or the machine carries no control credential), and the
/// manifest declaration (which rows are members at all). Pure on purpose
/// (the `shellFace` discipline): testable without a Tauri app, rendered
/// as-is by `FleetView`.

import {
  isRunning,
  type FleetDto,
  type NodeInfo,
  type NodeKindDto,
  type PeerStatusDto,
  type PeersPlaneDto,
} from "../api";
import { principalRealm } from "./shellFace";

/// A peer watcher's hub read is "fresh" for this long — the poll cadence
/// is tens of seconds, so a last_ok older than this means the observer
/// itself has lost the hub (its presence rows are stale, and its own
/// online answer flips to false).
export const HUB_FRESH_SECS = 120;

/// The CRL-poll silent threshold for the LOCAL panel's judgment — the
/// TS mirror of the Rust single source
/// (`interflow_renewal::CRL_SILENT_AFTER_SECS`, 3× the 60s poll cadence
/// + sweep slack). The hub faces carry the threshold self-reported; the
/// local face (plain atomics, no hub round trip) has no carrier for it,
/// so this mirror is the one place the frontend owns a cadence number.
export const CRL_SILENT_AFTER_SECS = 200;

/// The policy face's recency reading (the LEVEL face the hub reports per
/// leg: watermark + confirmation instant). `null` on rows without a hub
/// face (hubs, expose agents, the degraded local view).
export type PolicyFaceReading =
  /// No completed pull since the hub process started — the one honest
  /// meaning of "never" now that steady-state pulls land in the face.
  | { state: "never" }
  /// Confirming within the silent threshold, judged at the face's own
  /// capture instant (hub truth, not the render clock).
  | { state: "current"; ageSecs: number }
  /// The watermark holds but its confirmation instant is older than the
  /// threshold — present but fossilized (a dead policy watcher); the
  /// hub-side sweeper pushes exactly this transition.
  | { state: "silent"; ageSecs: number }
  /// No verdict: an older hub without the field, or a face too stale to
  /// support a judgment (degrade, never guess).
  | { state: "unknown" };

/// Classifies one leg's policy recency. Pure on purpose (the injected
/// `nowUnix` is the render clock; the judgment itself anchors on the
/// hub-side `faceCapturedAtUnix`). Inputs arrive as the bindings' optional
/// properties — `null` and `undefined` both read "absent" (an older hub),
/// never a zero that would fabricate a verdict. A face older than the
/// silent threshold cannot support a per-leg verdict — between its
/// capture and now a crossing could have happened unseen — so it reads
/// unknown, not a possibly-stale current.
export function policyFaceReading(
  seenGeneration: number | null | undefined,
  lastPullUnix: number | null | undefined,
  faceCapturedAtUnix: number | null | undefined,
  silentAfterSecs: number | undefined,
  nowUnix: number,
): PolicyFaceReading {
  if (seenGeneration == null && lastPullUnix == null) return { state: "never" };
  if (silentAfterSecs == null || !(silentAfterSecs > 0)) return { state: "unknown" };
  if (lastPullUnix == null || faceCapturedAtUnix == null) return { state: "unknown" };
  if (nowUnix - faceCapturedAtUnix > silentAfterSecs) return { state: "unknown" };
  const ageSecs = Math.max(0, faceCapturedAtUnix - lastPullUnix);
  return ageSecs > silentAfterSecs
    ? { state: "silent", ageSecs }
    : { state: "current", ageSecs };
}

/// The CRL-poll liveness reading (the 2026-10-19 face: the renewal loop's
/// level = confirmation instant + failure counter). `null` on rows
/// without a hub face.
export type CrlFaceReading =
  /// No report ever landed — an older node, or one without a renewal
  /// loop. Unknown, not silent.
  | { state: "never" }
  /// Polling (no-change polls included — "polled, nothing moved").
  | { state: "current"; ageSecs: number; failures: number }
  /// The confirmation instant froze past the threshold — the poll loop
  /// wedged without erroring (the 1h fail-closed bound never fires: the
  /// loop itself is the thing that checks it).
  | { state: "silent"; ageSecs: number; failures: number }
  /// No verdict: an older hub without the field, or a face too stale to
  /// support a judgment (degrade, never guess).
  | { state: "unknown" };

/// Classifies one member's CRL-poll liveness. Same discipline as
/// [`policyFaceReading`]: pure, anchored on the hub-side capture instant,
/// absent inputs read unknown — never a zero that would fabricate a
/// verdict.
export function crlFaceReading(
  lastSuccessUnix: number | null | undefined,
  faceCapturedAtUnix: number | null | undefined,
  silentAfterSecs: number | undefined,
  nowUnix: number,
  failuresTotal: number | null | undefined,
): CrlFaceReading {
  const failures = failuresTotal ?? 0;
  if (lastSuccessUnix == null) return { state: "never" };
  if (silentAfterSecs == null || !(silentAfterSecs > 0)) return { state: "unknown" };
  if (faceCapturedAtUnix == null) return { state: "unknown" };
  if (nowUnix - faceCapturedAtUnix > silentAfterSecs) return { state: "unknown" };
  const ageSecs = Math.max(0, faceCapturedAtUnix - lastSuccessUnix);
  return ageSecs > silentAfterSecs
    ? { state: "silent", ageSecs, failures }
    : { state: "current", ageSecs, failures };
}


/// One resident hub task's silence, pre-aged for rendering (the
/// armed-assertion face's failure row).
export interface WatcherSilentRow {
  name: string;
  intervalSecs: number;
  quietSecs: number;
}

/// The hub's resident-task armed assertion (the 2026-10-20 watchdog
/// face): every long-lived task judged against its OWN cadence — a row
/// quiet past `silentFactor` multiples of its interval is a task wedged
/// while the hub keeps serving.
export type WatchersFaceReading =
  /// No rows / older hub without the field — unjudgeable, never "passed".
  | { state: "unknown" }
  /// Every registered task ticked within its own threshold.
  | { state: "allArmed"; count: number }
  /// At least one row went quiet past its own threshold.
  | { state: "silent"; armed: number; silent: WatcherSilentRow[] };

/// Classifies the watchdog face. Same discipline as the per-leg faces:
/// pure, anchored on the hub-side capture instant, absent inputs read
/// unknown — never a zero that would fabricate a verdict. The face-stale
/// guard uses the LARGEST row threshold (beyond it every row's verdict
/// could have changed unseen since capture).
export function watchersFaceReading(
  rows: { name: string; interval_secs: number; last_tick_unix: number }[] | null | undefined,
  faceCapturedAtUnix: number | null | undefined,
  silentFactor: number | undefined,
  nowUnix: number,
): WatchersFaceReading {
  if (rows == null || rows.length === 0) return { state: "unknown" };
  if (silentFactor == null || !(silentFactor > 0) || faceCapturedAtUnix == null) {
    return { state: "unknown" };
  }
  const maxThreshold = Math.max(...rows.map((r) => silentFactor * r.interval_secs));
  if (nowUnix - faceCapturedAtUnix > maxThreshold) return { state: "unknown" };
  const silent: WatcherSilentRow[] = [];
  for (const row of rows) {
    const quietSecs = Math.max(0, faceCapturedAtUnix - row.last_tick_unix);
    if (quietSecs > silentFactor * row.interval_secs) {
      silent.push({ name: row.name, intervalSecs: row.interval_secs, quietSecs });
    }
  }
  return silent.length === 0
    ? { state: "allArmed", count: rows.length }
    : { state: "silent", armed: rows.length - silent.length, silent };
}


/// The mailbox watermark's reading for one leg
/// — the
/// "queued, applies on next check-in" instant made continuous: what is
/// waiting, since when, and whether anything was ever dropped.
export type QueuedOpsFaceReading =
  /// Nothing waiting (or an older hub without the field).
  | { state: "clear" }
  /// Ops waiting; `stuck` = the leg is ONLINE and the ops outlived the
  /// delivery budget (a working intent watcher delivers within one watch
  /// interval — waiting past that is a loop not consuming).
  | { state: "waiting"; count: number; ageSecs: number; oldestOp: string | null; stuck: boolean }
  /// Only drops on record (nothing waiting now, an op was dropped).
  | { state: "dropped"; droppedTotal: number };

/// Classifies one leg's mailbox watermark. Same discipline as the sibling
/// faces: pure, anchored on the hub-side capture instant, absent inputs
/// read clear — never a zero that would fabricate a verdict.
export function queuedOpsFaceReading(
  pendingCount: number | null | undefined,
  oldestQueuedUnix: number | null | undefined,
  faceCapturedAtUnix: number | null | undefined,
  oldestOp: string | null | undefined,
  droppedTotal: number | null | undefined,
  online: boolean,
  deliveryBudgetSecs: number | undefined,
): QueuedOpsFaceReading {
  const dropped = droppedTotal ?? 0;
  if (pendingCount == null || !(pendingCount > 0)) {
    return dropped > 0
      ? { state: "dropped", droppedTotal: dropped }
      : { state: "clear" };
  }
  const budgetKnown =
    deliveryBudgetSecs != null &&
    deliveryBudgetSecs > 0 &&
    faceCapturedAtUnix != null &&
    oldestQueuedUnix != null;
  const ageSecs = budgetKnown
    ? Math.max(0, (faceCapturedAtUnix as number) - (oldestQueuedUnix as number))
    : 0;
  const stuck =
    online && budgetKnown && ageSecs > (deliveryBudgetSecs as number);
  return {
    state: "waiting",
    count: pendingCount,
    ageSecs,
    oldestOp: oldestOp ?? null,
    stuck,
  };
}

/// One stream the fossil face flags: quiet past a multiple of its own
/// idle budget (or the unbudgeted default), pre-aged for rendering.
export interface FossilStreamRow {
  name: string;
  idleSecs: number;
}

/// The fossil reading for one leg's streams. Pure, anchored on the
/// hub-side capture instant, per-row budget anchors — never a global
/// threshold.
export function fossilStreamsFaceReading(
  streams: { name: string; last_byte_unix: number; idle_budget_secs?: number | null }[] | null | undefined,
  faceCapturedAtUnix: number | null | undefined,
  idleMultiple: number | undefined,
  unbudgetedDays: number | undefined,
): FossilStreamRow[] {
  if (
    streams == null ||
    streams.length === 0 ||
    faceCapturedAtUnix == null ||
    idleMultiple == null ||
    unbudgetedDays == null
  ) {
    return [];
  }
  const fossils: FossilStreamRow[] = [];
  for (const stream of streams) {
    const idleSecs = Math.max(0, faceCapturedAtUnix - stream.last_byte_unix);
    const line =
      stream.idle_budget_secs != null && stream.idle_budget_secs > 0
        ? stream.idle_budget_secs * idleMultiple
        : unbudgetedDays * 86_400;
    if (idleSecs > line) {
      fossils.push({ name: stream.name, idleSecs });
    }
  }
  return fossils;
}

/// The headroom reading for one admission scope: remaining capacity in
/// percent, tight when under the self-reported warn ratio. `null` when
/// the scope is unlimited or the inputs are absent (no wall, no
/// reading).
export interface HeadroomReading {
  inFlight: number;
  cap: number;
  remainingPct: number;
  tight: boolean;
}

export function headroomFaceReading(
  inFlight: number | null | undefined,
  cap: number | null | undefined,
  warnPct: number | undefined,
): HeadroomReading | null {
  if (inFlight == null || cap == null || cap <= 0 || warnPct == null) return null;
  const remainingPct = Math.max(0, Math.round(((cap - inFlight) / cap) * 100));
  return { inFlight, cap, remainingPct, tight: remainingPct < warnPct };
}

/// The credential-expiry reading for one leg
/// the
/// countdown as a level, judged per-tier against the self-reported
/// thresholds. "Don't forget to rotate" as a display, not a discipline.
export type CredentialFaceReading =
  | { state: "green"; mode: "registrar" | "offline"; remainingSecs: number }
  | { state: "yellow"; mode: "registrar" | "offline"; remainingSecs: number }
  | { state: "red"; mode: "registrar" | "offline"; remainingSecs: number }
  /// No window on the face (an older hub) — unjudgeable, never green.
  | { state: "unknown" };

/// Classifies one leg's credential window. Same discipline as the
/// sibling faces: pure, anchored on the hub-side capture instant,
/// absent inputs read unknown.
export function credentialFaceReading(
  notBeforeUnix: number | null | undefined,
  notAfterUnix: number | null | undefined,
  faceCapturedAtUnix: number | null | undefined,
  offlineWarnDays: number | undefined,
  offlineCriticalDays: number | undefined,
  registrarWarnPct: number | undefined,
  registrarCriticalPct: number | undefined,
): CredentialFaceReading {
  if (
    notBeforeUnix == null ||
    notAfterUnix == null ||
    faceCapturedAtUnix == null ||
    offlineWarnDays == null ||
    offlineCriticalDays == null ||
    registrarWarnPct == null ||
    registrarCriticalPct == null
  ) {
    return { state: "unknown" };
  }
  const remaining = notAfterUnix - faceCapturedAtUnix;
  const span = notAfterUnix - notBeforeUnix;
  const mode: "registrar" | "offline" = span < 3 * 86_400 ? "registrar" : "offline";
  if (remaining < 0) return { state: "red", mode, remainingSecs: remaining };
  if (mode === "offline") {
    const days = Math.floor(remaining / 86_400);
    if (days < offlineCriticalDays) return { state: "red", mode, remainingSecs: remaining };
    if (days < offlineWarnDays) return { state: "yellow", mode, remainingSecs: remaining };
    return { state: "green", mode, remainingSecs: remaining };
  }
  const pct = (remaining / Math.max(1, span)) * 100;
  if (pct < registrarCriticalPct) return { state: "red", mode, remainingSecs: remaining };
  if (pct < registrarWarnPct) return { state: "yellow", mode, remainingSecs: remaining };
  return { state: "green", mode, remainingSecs: remaining };
}

/// The connection-quality reading for one leg
/// the
/// window stats a point reading can never show — reconnect rate, the
/// backoff ladder's stage, liveness RTT percentiles.
export type ConnectionFaceReading =
  | { state: "unknown" }
  | {
      state: "healthy" | "reconnecting" | "probesUnanswered";
      reconnects: number;
      backoffStage: number;
      timeouts: number;
      p50Ms: number | null;
      p99Ms: number | null;
    };

/// Classifies one leg's connection window. Pure; the countable signals
/// drive the state (timeouts outrank reconnects — the blackhole's
/// leading signal fires while the session object stays alive), the
/// percentiles ride as diagnostic material.
export function connectionFaceReading(
  connection: {
    reconnects_last_hour: number;
    rtt_p50_ms?: number | null;
    rtt_p99_ms?: number | null;
    rtt_timeouts: number;
  } | null | undefined,
  backoffFailures: number | null | undefined,
): ConnectionFaceReading {
  if (connection == null) return { state: "unknown" };
  const backoffStage = Math.min(backoffFailures ?? 0, 5);
  const base = {
    reconnects: connection.reconnects_last_hour,
    backoffStage,
    timeouts: connection.rtt_timeouts,
    p50Ms: connection.rtt_p50_ms ?? null,
    p99Ms: connection.rtt_p99_ms ?? null,
  };
  if (connection.rtt_timeouts > 0) return { state: "probesUnanswered", ...base };
  if (connection.reconnects_last_hour > 0) return { state: "reconnecting", ...base };
  return { state: "healthy", ...base };
}

export interface LeafHealth {
  phase: string | null;
  remaining_secs: number;
}

/// One row of the 编队 table. `online === null` means no source can see
/// this member (an off-machine hub or expose agent) — rendered as
/// unknown, never guessed.
export interface FleetRow {
  /// Agents: the qualified id (`tenant/agent`); hubs/ingresses: a
  /// kind-prefixed name — unique within the merge either way.
  key: string;
  /// Display name: the agent part for agents, the declared name
  /// otherwise (the full qualified id stays one hover away).
  name: string;
  kind: NodeKindDto;
  online: boolean | null;
  /// The generation the hub last saw this agent pull (the floor
  /// watermark for hubs — the lineage anchor).
  gen: number | null;
  /// The policy face's recency reading (mesh agent rows with a hub face;
  /// `null` elsewhere — hubs, expose agents, the degraded local view).
  policy: PolicyFaceReading | null;
  /// The CRL-poll liveness reading (rows with a hub face); `null`
  /// elsewhere — same shape as `policy`.
  crl: CrlFaceReading | null;
  leaf: LeafHealth | null;
  /// The NodeManager id when the member runs on this machine — the 本机
  /// badge and the cross-link into the 本机 entry.
  localNodeId: string | null;
  /// Whether the manifest declares this member (false = a stray the hub
  /// registered or a local pack without a declaration).
  declared: boolean;
  /// The member is declared under maintenance (planned unavailability,
  /// node level): its absence is expected, not an accident. Reads from
  /// the hub's face; `false` when there is no face to read.
  maintenance: boolean;
  /// How many of the member's streams the hub face reports paused
  /// (planned unavailability, stream level) — the row's hover note.
  pausedStreams: number;
  /// The mailbox watermark reading (queued ops waiting on this leg);
  /// `null` on rows without a hub face.
  queuedOps: QueuedOpsFaceReading | null;
  /// The mailbox's cumulative drop counter (rendered apart from the
  /// waiting reading; 0 when no face).
  queuedDropped: number;
  /// The leg's fossil streams (pre-aged rows); empty on rows without
  /// the face.
  fossils: FossilStreamRow[];
  /// The per-leg session headroom; `null` when unjudgeable.
  headroom: HeadroomReading | null;
  /// The credential-expiry reading; `null` on rows without a hub face.
  credential: CredentialFaceReading | null;
  /// The connection-quality reading; `null` on rows without a hub face.
  connection: ConnectionFaceReading | null;
}

/// The qualified id of a signed principal's agent face
/// (`workspace/node`); null when the principal does not parse.
function agentId(principal: string | null): string | null {
  const parts = principal?.split("/") ?? [];
  return parts.length === 4 ? `${parts[1]}/${parts[3]}` : null;
}

/// Whether a deployment has a mesh fleet at all — the 编队 nav item's
/// visibility rule (the 2026-10-15 ruling): an expose deployment (no
/// hub, no mesh/mixed agent) shows no 编队 item; the nav's shape follows
/// the deployment's content.
export function hasFleetFace(summary: {
  hubs: unknown[];
  agents: { role: string }[];
}): boolean {
  return (
    summary.hubs.length > 0 ||
    summary.agents.some((a) => a.role === "mesh" || a.role === "mixed")
  );
}

/// The same principle's remaining two faces (the 2026-10-16 ruling,
/// completing 2026-10-15): services can only be declared on expose/mixed
/// agents and streams only flow from mesh ingress (mesh/mixed agents) —
/// so each face's nav item appears only where its content can exist,
/// and a mixed deployment shows all three.
export function hasServicesFace(summary: {
  agents: { role: string }[];
}): boolean {
  return summary.agents.some((a) => a.role === "expose" || a.role === "mixed");
}

export function hasStreamsFace(summary: {
  agents: { role: string }[];
}): boolean {
  return summary.agents.some((a) => a.role === "mesh" || a.role === "mixed");
}

interface Observer {
  node: NodeInfo;
  plane: PeersPlaneDto;
  lastOk: number;
}

/// The local observers this merge can draw on: running mesh agents with
/// a peers plane, optionally narrowed to one realm (the 🔒 realm page
/// and the deployment page's degraded form both stay realm-honest).
export function realmObservers(nodes: NodeInfo[], realm: string | null): Observer[] {
  return nodes.flatMap((n) =>
    n.kind === "mesh_agent" &&
    isRunning(n.state) &&
    n.peers &&
    (realm === null || principalRealm(n.principal) === realm)
      ? [{ node: n, plane: n.peers, lastOk: n.peers.last_ok_unix }]
      : [],
  );
}

/// Leaf health of one member by qualified id, from any local observer's
/// peers plane (each plane is tenant-scoped, so the freshest plane that
/// carries the id wins — different tenants never collide on one id).
function peersLeaf(obs: Observer[], id: string): LeafHealth | null {
  let best: LeafHealth | null = null;
  let bestOk = -1;
  for (const o of obs) {
    const row: PeerStatusDto | undefined = o.plane.peers.find((p) => p.agent === id);
    if (row && o.lastOk > bestOk) {
      best = { phase: row.leaf_phase, remaining_secs: row.leaf_remaining_secs };
      bestOk = o.lastOk;
    }
  }
  return best;
}

function localLeaf(node: NodeInfo | undefined): LeafHealth | null {
  return node?.credential
    ? { phase: node.credential.phase, remaining_secs: node.credential.remaining_secs }
    : null;
}

/// Whether a unix-seconds timestamp is inside the freshness window
/// (`nowUnix` injected — the pure-function discipline).
export function fresh(lastOkUnix: number, nowUnix: number): boolean {
  return lastOkUnix > 0 && nowUnix - lastOkUnix <= HUB_FRESH_SECS;
}

function hubRow(
  name: string,
  online: boolean | null,
  gen: number | null,
  local: NodeInfo | undefined,
  declared: boolean,
): FleetRow {
  return {
    key: `hub:${name}`,
    name,
    kind: "hub",
    online,
    gen,
    policy: null,
    crl: null,
    leaf: localLeaf(local),
    localNodeId: local?.id ?? null,
    declared,
    maintenance: false,
    pausedStreams: 0,
    queuedOps: null,
    queuedDropped: 0,
    fossils: [],
    headroom: null,
    credential: null,
    connection: null,
  };
}

function agentRow(
  id: string,
  name: string,
  kind: NodeKindDto,
  online: boolean | null,
  gen: number | null,
  leaf: LeafHealth | null,
  localNodeId: string | null,
  declared: boolean,
  maintenance = false,
  pausedStreams = 0,
  policy: PolicyFaceReading | null = null,
  crl: CrlFaceReading | null = null,
  queuedOps: QueuedOpsFaceReading | null = null,
  queuedDropped = 0,
  fossils: FossilStreamRow[] = [],
  headroom: HeadroomReading | null = null,
  credential: CredentialFaceReading | null = null,
  connection: ConnectionFaceReading | null = null,
): FleetRow {
  return {
    key: id,
    name,
    kind,
    online,
    gen,
    policy,
    crl,
    leaf,
    localNodeId,
    declared,
    maintenance,
    pausedStreams,
    queuedOps,
    queuedDropped,
    fossils,
    headroom,
    credential,
    connection,
  };
}

/// One OPEN route breaker on the answering hub, pre-aged for rendering.
export interface RouteBreakerRow {
  host: string;
  openSecs: number;
  probeAgoSecs: number;
}

/// The deployment scope's rows: the manifest's declared members with the
/// hub's faces joined (authoritative online/gen while the hub answers),
/// plus two honest tails — hub-registered agents the manifest does not
/// declare, and this realm's local packs without a declaration. Absent
/// evidence is never guessed into a boolean: unknown stays unknown.
export function buildDeploymentRows(
  fleet: FleetDto,
  nodes: NodeInfo[],
  nowUnix: number,
): {
  rows: FleetRow[];
  floorServing: { floor: number; serving: number | null } | null;
  routeBreakers: RouteBreakerRow[];
  watchers: WatchersFaceReading;
} {
  const realm = fleet.summary.realm.id;
  const obs = realmObservers(nodes, realm);
  // The hub's route-breaker open set (edge gateways), aged against the
  // hub's own capture anchor — same never-guess discipline as the faces.
  const routeBreakers: RouteBreakerRow[] = (fleet.hub?.route_breakers_open ?? []).map((row) => ({
    host: row.host,
    openSecs: Math.max(0, (fleet.hub?.captured_at_unix ?? 0) - row.opened_unix),
    probeAgoSecs: Math.max(0, (fleet.hub?.captured_at_unix ?? 0) - row.last_probe_unix),
  }));
  const byId = new Map(nodes.map((n) => [n.id, n]));
  const seen = new Set<string>();
  const hubReachable = fleet.hub !== null;
  const rows: FleetRow[] = [];

  // Declared hubs first — the realm's control-plane anchor. The hub
  // never appears in its own agents listing; presence and the floor
  // generation attribute to exactly the row whose name the answer
  // self-reports (`fleet.hub.hub`). An UNNAMED answer (an older hub, or
  // the no-policy-face 404 fallback) attributes only when exactly one
  // hub is declared — whatever endpoint was dialed belongs to it. Every
  // other declared hub falls back to its local face, unknown
  // off-machine.
  const responder = fleet.hub?.hub ?? null;
  const answer = fleet.hub;
  for (const h of fleet.summary.hubs) {
    const declared = fleet.nodes.find((n) => n.kind === "hub" && n.name === h.name);
    const localNode = declared?.local ? byId.get(declared.local.id) : undefined;
    seen.add(`hub:${h.name}`);
    const attributed =
      fleet.hub !== null &&
      (responder === h.name ||
        (responder === null && fleet.summary.hubs.length === 1));
    rows.push(
      hubRow(
        h.name,
        attributed
          ? true
          : declared?.local
            ? isRunning(declared.local.state)
            : null,
        attributed && fleet.hub ? fleet.hub.floor : null,
        localNode,
        true,
      ),
    );
  }

  // A named answer no declared row matches — the endpoint was answered
  // by a hub outside the manifest (a migration overlap: DNS still on the
  // old hub, or a balancer fronting two). The stranger stays visible as
  // an undeclared row carrying its own facts, like a stray agent: the
  // overlap is what the operator is watching for, not noise to hide.
  if (
    answer !== null &&
    responder !== null &&
    !fleet.summary.hubs.some((h) => h.name === responder)
  ) {
    seen.add(`hub:${responder}`);
    const localNode = fleet.local_only.find(
      (n) =>
        n.kind === "hub" &&
        n.name === responder &&
        principalRealm(n.principal) === realm,
    );
    rows.push(hubRow(responder, true, answer.floor, localNode, false));
  }

  // Declared agents: hub rows are authoritative while the hub answers
  // (a declared agent with no hub row is honestly offline); expose
  // agents never had a hub face — their truth is the local dial, and
  // off-machine they read unknown.
  for (const row of fleet.nodes) {
    if (row.kind === "mesh_agent" || row.kind === "expose_agent") {
      const id = row.workspace !== null ? `${row.workspace}/${row.name}` : row.name;
      seen.add(id);
      const localNode = row.local ? byId.get(row.local.id) : undefined;
      const online =
        row.kind === "expose_agent"
          ? row.local
            ? isRunning(row.local.state)
            : null
          : hubReachable
            ? row.remote !== null && row.remote.online
            : null;
      rows.push(
        agentRow(
          id,
          row.name,
          row.kind,
          online,
          row.remote ? row.remote.seen_generation : null,
          peersLeaf(obs, id) ?? localLeaf(localNode),
          row.local?.id ?? null,
          true,
          row.remote?.maintenance ?? false,
          row.remote?.paused_streams?.length ?? 0,
          row.kind === "mesh_agent" && row.remote !== null && fleet.hub !== null
            ? policyFaceReading(
                row.remote.seen_generation,
                row.remote.policy_last_pull_unix,
                row.remote.face_captured_at_unix,
                fleet.hub.policy_silent_after_secs,
                nowUnix,
              )
            : null,
          row.kind === "mesh_agent" && row.remote !== null && fleet.hub !== null
            ? crlFaceReading(
                row.remote.crl_last_success_unix,
                row.remote.face_captured_at_unix,
                fleet.hub.crl_silent_after_secs,
                nowUnix,
                row.remote.crl_failures_total,
              )
            : null,
          row.kind === "mesh_agent" && row.remote !== null && fleet.hub !== null
            ? queuedOpsFaceReading(
                row.remote.pending_ops?.pending_count ?? null,
                row.remote.pending_ops?.oldest_queued_unix ?? null,
                row.remote.face_captured_at_unix,
                row.remote.pending_ops?.oldest_op ?? null,
                row.remote.pending_ops?.dropped_total ?? null,
                online === true,
                fleet.hub.policy_silent_after_secs,
              )
            : null,
          row.remote?.pending_ops?.dropped_total ?? 0,
          fossilStreamsFaceReading(
            row.remote?.streams ?? null,
            row.remote?.face_captured_at_unix ?? null,
            fleet.hub?.fossil_idle_multiple,
            fleet.hub?.fossil_unbudgeted_days,
          ),
          headroomFaceReading(
            row.remote?.streams_in_flight ?? null,
            fleet.hub?.stream_limits?.per_agent ?? null,
            fleet.hub?.headroom_warn_pct,
          ),
          row.kind === "mesh_agent" && row.remote !== null && fleet.hub !== null
            ? credentialFaceReading(
                row.remote.leaf_not_before_unix ?? null,
                row.remote.leaf_not_after_unix ?? null,
                row.remote.face_captured_at_unix,
                fleet.hub.offline_warn_days,
                fleet.hub.offline_critical_days,
                fleet.hub.registrar_warn_pct,
                fleet.hub.registrar_critical_pct,
              )
            : null,
          row.kind === "mesh_agent" && row.remote !== null
            ? connectionFaceReading(
                row.remote.connection ?? null,
                row.remote.renewal_backoff_failures ?? null,
              )
            : null,
        ),
      );
    } else if (row.kind === "ingress") {
      seen.add(`ingress:${row.name}`);
      const localNode = row.local ? byId.get(row.local.id) : undefined;
      rows.push({
        key: `ingress:${row.name}`,
        name: row.name,
        kind: "ingress",
        online: row.local ? isRunning(row.local.state) : null,
        gen: null,
        policy: null,
        crl: null,
        leaf: localLeaf(localNode),
        localNodeId: row.local?.id ?? null,
        declared: true,
        maintenance: false,
        pausedStreams: 0,
        queuedOps: null,
        queuedDropped: 0,
        fossils: [],
        headroom: null,
        credential: null,
        connection: null,
      });
    }
  }

  // Tail 1: hub-registered agents the manifest does not declare — the
  // hub's registry is the realm's live truth; a stray stays visible.
  if (fleet.hub) {
    const overview = fleet.hub;
    for (const row of overview.agents) {
      if (seen.has(row.agent)) continue;
      seen.add(row.agent);
      const localNode = nodes.find((n) => agentId(n.principal) === row.agent);
      rows.push(
        agentRow(
          row.agent,
          row.agent.split("/").pop() ?? row.agent,
          "mesh_agent",
          row.online,
          row.seen,
          peersLeaf(obs, row.agent) ?? localLeaf(localNode),
          localNode?.id ?? null,
          false,
          row.maintenance,
          row.paused_streams?.length ?? 0,
          policyFaceReading(
            row.seen,
            row.policy_last_pull_unix,
            overview.captured_at_unix,
            overview.policy_silent_after_secs,
            nowUnix,
          ),
          crlFaceReading(
            row.crl_last_success_unix,
            overview.captured_at_unix,
            overview.crl_silent_after_secs,
            nowUnix,
            row.crl_failures_total,
          ),
          queuedOpsFaceReading(
            row.pending_ops?.pending_count ?? null,
            row.pending_ops?.oldest_queued_unix ?? null,
            overview.captured_at_unix,
            row.pending_ops?.oldest_op ?? null,
            row.pending_ops?.dropped_total ?? null,
            row.online,
            overview.policy_silent_after_secs,
          ),
          row.pending_ops?.dropped_total ?? 0,
          fossilStreamsFaceReading(
            row.pending_ops === null && row.streams === undefined
              ? null
              : (row.streams ?? null),
            overview.captured_at_unix,
            overview.fossil_idle_multiple,
            overview.fossil_unbudgeted_days,
          ),
          headroomFaceReading(
            row.streams_in_flight ?? null,
            overview.stream_limits?.per_agent ?? null,
            overview.headroom_warn_pct,
          ),
          credentialFaceReading(
            row.leaf_not_before_unix ?? null,
            row.leaf_not_after_unix ?? null,
            overview.captured_at_unix,
            overview.offline_warn_days,
            overview.offline_critical_days,
            overview.registrar_warn_pct,
            overview.registrar_critical_pct,
          ),
          connectionFaceReading(
            row.connection ?? null,
            row.renewal_backoff_failures ?? null,
          ),
        ),
      );
    }
  }

  // Tail 2: this realm's local packs without a declaration (sealed
  // imports, machine-local applies) — members by identity even though no
  // manifest names them.
  for (const node of fleet.local_only) {
    if (principalRealm(node.principal) !== realm) continue;
    if (node.kind === "hub") {
      const key = `hub:${node.name}`;
      if (seen.has(key)) continue;
      seen.add(key);
      rows.push(hubRow(node.name, isRunning(node.state), null, node, false));
    } else if (node.kind === "ingress") {
      const key = `ingress:${node.name}`;
      if (seen.has(key)) continue;
      seen.add(key);
      rows.push({
        key,
        name: node.name,
        kind: "ingress",
        online: isRunning(node.state),
        gen: null,
        policy: null,
        crl: null,
        leaf: localLeaf(node),
        localNodeId: node.id,
        declared: false,
        maintenance: false,
        pausedStreams: 0,
        queuedOps: null,
        queuedDropped: 0,
        fossils: [],
        headroom: null,
        credential: null,
        connection: null,
      });
    } else {
      const id = agentId(node.principal) ?? node.name;
      if (seen.has(id)) continue;
      seen.add(id);
      rows.push(
        agentRow(
          id,
          node.name,
          node.kind,
          node.kind === "expose_agent"
            ? isRunning(node.state)
            : node.peers
              ? fresh(node.peers.last_ok_unix, nowUnix)
              : false,
          null,
          peersLeaf(obs, id) ?? localLeaf(node),
          node.id,
          false,
        ),
      );
    }
  }

  return {
    rows,
    floorServing: fleet.hub
      ? { floor: fleet.hub.floor, serving: fleet.hub.serving }
      : null,
    routeBreakers,
    watchers:
      fleet.hub !== null
        ? watchersFaceReading(
            fleet.hub.watchers,
            fleet.hub.captured_at_unix,
            fleet.hub.watcher_silent_factor,
            nowUnix,
          )
        : { state: "unknown" },
  };
}

/// The 🔒 realm scope's rows: this machine's own agents (presence from
/// their hub connection's freshness — no control credential exists to
/// ask the hub directly) plus the union of their peers planes, deduped
/// by qualified id with the freshest observation winning, plus a
/// synthesized hub row (reachable exactly while some observer's hub
/// read is fresh).
export function buildRealmRows(realm: string, nodes: NodeInfo[], nowUnix: number): FleetRow[] {
  const obs = realmObservers(nodes, realm);
  const seen = new Set<string>();
  const rows: FleetRow[] = [];

  const hubNode = nodes.find(
    (n) => n.kind === "hub" && principalRealm(n.principal) === realm,
  );
  if (hubNode !== undefined || obs.length > 0) {
    rows.push(
      hubRow(hubNode?.name ?? "hub", obs.some((o) => fresh(o.lastOk, nowUnix)), null, hubNode, false),
    );
  }

  // The machine's own agents first (self is excluded from its own peers
  // plane): online exactly while its hub read is fresh; the policy plane
  // supplies the generation it runs.
  for (const { node } of obs) {
    const id = agentId(node.principal);
    if (id === null || seen.has(id)) continue;
    seen.add(id);
    rows.push(
      agentRow(
        id,
        node.name,
        "mesh_agent",
        node.peers !== null ? fresh(node.peers.last_ok_unix, nowUnix) : false,
        node.policy?.generation ?? null,
        localLeaf(node),
        node.id,
        false,
      ),
    );
  }

  // The peers planes' union, freshest observation per id.
  for (const o of [...obs].sort((a, b) => b.lastOk - a.lastOk)) {
    for (const peer of o.plane.peers) {
      if (seen.has(peer.agent)) continue;
      seen.add(peer.agent);
      rows.push(
        agentRow(
          peer.agent,
          peer.agent.split("/").pop() ?? peer.agent,
          "mesh_agent",
          peer.online,
          null,
          { phase: peer.leaf_phase, remaining_secs: peer.leaf_remaining_secs },
          nodes.find((n) => agentId(n.principal) === peer.agent)?.id ?? null,
          false,
        ),
      );
    }
  }

  return rows;
}
