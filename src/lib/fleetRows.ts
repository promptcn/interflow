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

/// Leaf health, normalized across the two carriers: a peer row's
/// `leaf_phase` and a local node's own credential face say the same thing
/// in slightly different shapes.
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
  leaf: LeafHealth | null;
  /// The NodeManager id when the member runs on this machine — the 本机
  /// badge and the cross-link into the 本机 entry.
  localNodeId: string | null;
  /// Whether the manifest declares this member (false = a stray the hub
  /// registered or a local pack without a declaration).
  declared: boolean;
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
    leaf: localLeaf(local),
    localNodeId: local?.id ?? null,
    declared,
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
): FleetRow {
  return { key: id, name, kind, online, gen, leaf, localNodeId, declared };
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
} {
  const realm = fleet.summary.realm.id;
  const obs = realmObservers(nodes, realm);
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
        leaf: localLeaf(localNode),
        localNodeId: row.local?.id ?? null,
        declared: true,
      });
    }
  }

  // Tail 1: hub-registered agents the manifest does not declare — the
  // hub's registry is the realm's live truth; a stray stays visible.
  if (fleet.hub) {
    for (const row of fleet.hub.agents) {
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
        leaf: localLeaf(node),
        localNodeId: node.id,
        declared: false,
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
