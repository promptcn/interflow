import { describe, expect, it } from "vitest";
import {
  buildDeploymentRows,
  buildRealmRows,
  hasFleetFace,
  hasServicesFace,
  hasStreamsFace,
  crlFaceReading,
  policyFaceReading,
  queuedOpsFaceReading,
  connectionFaceReading,
  credentialFaceReading,
  fossilStreamsFaceReading,
  headroomFaceReading,
  realmObservers,
  watchersFaceReading,
} from "./fleetRows";
import type {
  FleetDto,
  ManifestSummaryDto,
  NodeInfo,
  PeersPlaneDto,
} from "../api";

const NOW = 1_000_000;

function node(over: Partial<NodeInfo> & Pick<NodeInfo, "id" | "name" | "principal">): NodeInfo {
  return {
    kind: "mesh_agent",
    attribution: `${over.name}#ab12`,
    pack_dir: `/packs/${over.name}`,
    state: "Running",
    desired_running: true,
    crl: null,
    breakers: null,
    transport: null,
    pack_transport: null,
    hub_quic_addr: null,
    pack_hub_quic_addr: null,
    services: [],
    mesh_ingress_rules: [],
    mesh_egress_rules: [],
    listen: null,
    generation: 3,
    credential: null,
    policy: null,
    peers: null,
    proposals: null,
    listeners: null,
    deployment: null,
    ...over,
  };
}

function plane(peers: PeersPlaneDto["peers"], lastOk = NOW - 30): PeersPlaneDto {
  return { peers, last_ok_unix: lastOk, failures_total: 0 };
}

function summary(over: Partial<ManifestSummaryDto> = {}): ManifestSummaryDto {
  return {
    realm: { id: "mesh", control_endpoint: "https://hub" },
    public_tls: { mode: "frontend-proxy", email: null, directory: null },
    identity: {
      mode: "registrar",
      leaf_ttl: null,
      leaf_ttl_bounds: { min: "1h", max: "24h", default: "24h" },
      registrar_endpoint: "",
    },
    workspaces: ["main"],
    agents: [
      { node: "leo", workspace: "main", role: "mesh", transport: null, services: [], mesh_ingress: [], mesh_egress: [] },
    ],
    ingress: [],
    routes: [],
    hubs: [{ name: "hub", listen: "0.0.0.0:6666", quic_listen: null, endpoint: "https://hub" }],
    issues: [],
    ...over,
  };
}

function fleet(over: Partial<FleetDto> = {}): FleetDto {
  return {
    summary: summary(),
    change_state: { kind: "applied", generation: 15 },
    hub: {
      hub: "hub",
      floor: 15,
      serving: 15,
      agents: [
        { agent: "main/leo", online: true, seen: 15 },
        { agent: "main/home-win", online: false, seen: 14 },
      ],
    },
    nodes: [
      {
        kind: "mesh_agent",
        name: "leo",
        workspace: "main",
        local: { id: "n-leo", state: "Running", desired_running: true, generation: 3, policy_generation: 15, listeners: [] },
        remote: { online: true, seen_generation: 15, policy_last_pull_unix: null, face_captured_at_unix: null, crl_last_success_unix: null, crl_failures_total: null },
      },
      {
        kind: "hub",
        name: "hub",
        workspace: null,
        local: { id: "n-hub", state: "Running", desired_running: true, generation: 3, policy_generation: null, listeners: [] },
        remote: null,
      },
    ],
    streams: [],
    services: [],
    local_only: [],
    ...over,
  };
}

describe("hasFleetFace — the 编队 nav item follows the deployment's content", () => {
  it("a hub or any mesh/mixed agent makes a fleet", () => {
    expect(hasFleetFace(summary())).toBe(true);
    expect(
      hasFleetFace(summary({ hubs: [], agents: [{ node: "web", workspace: "main", role: "mixed", transport: null, services: [], mesh_ingress: [], mesh_egress: [] }] })),
    ).toBe(true);
  });

  it("an expose deployment (no hub, expose-only agents) has no fleet face", () => {
    expect(
      hasFleetFace(
        summary({
          hubs: [],
          agents: [{ node: "web", workspace: "main", role: "expose", transport: null, services: [], mesh_ingress: [], mesh_egress: [] }],
        }),
      ),
    ).toBe(false);
  });
});

describe("hasServicesFace — the 服务 nav item follows the deployment's content", () => {
  it("any expose/mixed agent makes a services face", () => {
    expect(
      hasServicesFace(
        summary({
          hubs: [],
          agents: [{ node: "web", workspace: "main", role: "expose", transport: null, services: [], mesh_ingress: [], mesh_egress: [] }],
        }),
      ),
    ).toBe(true);
    expect(
      hasServicesFace(
        summary({
          agents: [{ node: "api", workspace: "main", role: "mixed", transport: null, services: [], mesh_ingress: [], mesh_egress: [] }],
        }),
      ),
    ).toBe(true);
  });

  it("a mesh deployment (hub and mesh-only agents, services undeclarable) has no services face", () => {
    expect(hasServicesFace(summary())).toBe(false);
  });
});

describe("hasStreamsFace — the 流 nav item follows the deployment's content", () => {
  it("any mesh/mixed agent makes a streams face", () => {
    expect(hasStreamsFace(summary())).toBe(true);
    expect(
      hasStreamsFace(
        summary({
          agents: [{ node: "api", workspace: "main", role: "mixed", transport: null, services: [], mesh_ingress: [], mesh_egress: [] }],
        }),
      ),
    ).toBe(true);
  });

  it("an expose deployment (expose-only agents, no mesh ingress) has no streams face", () => {
    expect(
      hasStreamsFace(
        summary({
          hubs: [],
          agents: [{ node: "web", workspace: "main", role: "expose", transport: null, services: [], mesh_ingress: [], mesh_egress: [] }],
        }),
      ),
    ).toBe(false);
  });

  it("a mixed deployment shows all three faces", () => {
    const mixed = summary({
      agents: [{ node: "api", workspace: "main", role: "mixed", transport: null, services: [], mesh_ingress: [], mesh_egress: [] }],
    });
    expect(hasFleetFace(mixed)).toBe(true);
    expect(hasServicesFace(mixed)).toBe(true);
    expect(hasStreamsFace(mixed)).toBe(true);
  });
});

describe("buildDeploymentRows — the hub's report is authoritative", () => {
  const localLeo = node({
    id: "n-leo",
    name: "leo",
    principal: "mesh/main/agent/leo",
    credential: { not_after: "2030-01-01T00:00:00Z", remaining_secs: 500_000, phase: "healthy" },
    peers: plane([{ agent: "main/home-win", online: false, leaf_phase: "warn", leaf_remaining_secs: 250_000, leaf_not_after_unix: 1_250_000 }]),
    policy: { generation: 15, source: "pack", hub_generation: 15, pull: null },
  });
  const localHub = node({ id: "n-hub", name: "hub", kind: "hub", principal: "mesh/-/hub/hub" });

  it("declared hub first with the floor watermark, agents joined to hub rows", () => {
    const { rows, floorServing } = buildDeploymentRows(fleet(), [localLeo, localHub], NOW);
    expect(floorServing).toEqual({ floor: 15, serving: 15 });
    expect(rows[0]).toMatchObject({ key: "hub:hub", online: true, gen: 15, localNodeId: "n-hub", declared: true });
    const leo = rows.find((r) => r.key === "main/leo");
    expect(leo).toMatchObject({ online: true, gen: 15, localNodeId: "n-leo", declared: true });
    // The observer never sees itself in its own plane — the leaf falls
    // back to its own credential face.
    expect(leo?.leaf).toEqual({ phase: "healthy", remaining_secs: 500_000 });
  });

  it("hub-registered undeclared agents stay visible, leaf from the peers plane", () => {
    const { rows } = buildDeploymentRows(fleet(), [localLeo, localHub], NOW);
    expect(rows.find((r) => r.key === "main/home-win")).toMatchObject({
      online: false,
      gen: 14,
      declared: false,
      leaf: { phase: "warn", remaining_secs: 250_000 },
    });
  });

  it("a declared agent with no hub row is honestly offline, never unknown", () => {
    const f = fleet({
      hub: { hub: "hub", floor: 15, serving: 15, agents: [] },
      nodes: fleet().nodes.map((n) => (n.kind === "mesh_agent" ? { ...n, remote: null } : n)),
    });
    const { rows } = buildDeploymentRows(f, [localHub], NOW);
    expect(rows.find((r) => r.key === "main/leo")?.online).toBe(false);
  });

  it("a sealed import of this realm joins as an undeclared local member; foreign realms do not", () => {
    const sealed = node({
      id: "n-sealed",
      name: "spare",
      principal: "mesh/main/agent/spare",
      peers: plane([], NOW - 10),
    });
    const foreign = node({ id: "n-x", name: "other", principal: "other/main/agent/other" });
    const { rows } = buildDeploymentRows(fleet({ local_only: [sealed, foreign] }), [localHub], NOW);
    expect(rows.find((r) => r.key === "main/spare")).toMatchObject({
      online: true,
      declared: false,
      localNodeId: "n-sealed",
    });
    expect(rows.find((r) => r.key === "main/other" || r.key === "other/main/agent/other")).toBeUndefined();
  });

  it("a delivered overview is the hub answering — presence proven even off-machine", () => {
    // The hub never appears in its own agents listing; the merged table
    // renders only when the overview arrived, which IS the hub's answer.
    const f = fleet({
      nodes: fleet().nodes.map((n) => (n.kind === "hub" ? { ...n, local: null } : n)),
    });
    const { rows } = buildDeploymentRows(f, [], NOW);
    expect(rows.find((r) => r.key === "hub:hub")).toMatchObject({
      online: true,
      gen: 15,
      localNodeId: null,
    });
  });

  it("hub unreachable: no floor strip, agent presence unknown (the degraded form owns the page)", () => {
    const { rows, floorServing } = buildDeploymentRows(fleet({ hub: null }), [localHub], NOW);
    expect(floorServing).toBeNull();
    expect(rows.find((r) => r.key === "main/leo")?.online).toBeNull();
    // No hub answer to prove presence — the local face is the only witness.
    expect(rows.find((r) => r.key === "hub:hub")?.online).toBe(true);
  });
});

describe("buildDeploymentRows — attribution keys on the answer's self-reported name", () => {
  const hubRowDto = (name: string, local: boolean) => ({
    kind: "hub" as const,
    name,
    workspace: null,
    local: local
      ? { id: `n-${name}`, state: "Running" as const, desired_running: true, generation: 3, policy_generation: null, listeners: [] }
      : null,
    remote: null,
  });
  const multiHubFleet = (responder: string | null): FleetDto =>
    fleet({
      summary: summary({
        hubs: [
          { name: "hub-a", listen: "0.0.0.0:6666", quic_listen: null, endpoint: "https://a" },
          { name: "hub-b", listen: "0.0.0.0:6667", quic_listen: null, endpoint: "https://b" },
        ],
      }),
      hub: { hub: responder, floor: 21, serving: 21, agents: [] },
      nodes: [hubRowDto("hub-a", true), hubRowDto("hub-b", false)],
    });

  it("a named answer attributes exactly its row; other declared hubs keep only their local face", () => {
    const { rows, floorServing } = buildDeploymentRows(multiHubFleet("hub-b"), [], NOW);
    expect(floorServing).toEqual({ floor: 21, serving: 21 });
    expect(rows.find((r) => r.key === "hub:hub-b")).toMatchObject({
      online: true,
      gen: 21,
      declared: true,
    });
    // The non-responder stays online only via its local face — the
    // answer proves nothing about it, and it borrows no generation.
    expect(rows.find((r) => r.key === "hub:hub-a")).toMatchObject({
      online: true,
      gen: null,
      declared: true,
    });
  });

  it("a named stranger surfaces as an undeclared row; the declared hub borrows nothing", () => {
    // Migration overlap: the endpoint still resolves to the old hub, whose
    // self-reported name the manifest no longer declares.
    const f = fleet({
      summary: summary({
        hubs: [{ name: "hub-new", listen: "0.0.0.0:6666", quic_listen: null, endpoint: "https://hub" }],
      }),
      hub: { hub: "hub-old", floor: 9, serving: 9, agents: [] },
      nodes: [hubRowDto("hub-new", false)],
    });
    const { rows, floorServing } = buildDeploymentRows(f, [], NOW);
    expect(floorServing).toEqual({ floor: 9, serving: 9 });
    expect(rows.find((r) => r.key === "hub:hub-new")).toMatchObject({
      online: null,
      gen: null,
      declared: true,
    });
    // The hub that actually answered stays visible with its own facts —
    // the overlap the operator is watching for.
    expect(rows.find((r) => r.key === "hub:hub-old")).toMatchObject({
      online: true,
      gen: 9,
      declared: false,
    });
  });

  it("an unnamed answer (older hub / no-policy-face fallback) still attributes the sole declared hub", () => {
    const f = fleet({ hub: { hub: null, floor: 15, serving: 15, agents: [] } });
    const { rows } = buildDeploymentRows(f, [], NOW);
    expect(rows.find((r) => r.key === "hub:hub")).toMatchObject({ online: true, gen: 15 });
  });

  it("an unnamed answer across several declared hubs attributes none of them", () => {
    const { rows } = buildDeploymentRows(multiHubFleet(null), [], NOW);
    expect(rows.find((r) => r.key === "hub:hub-a")).toMatchObject({ gen: null });
    expect(rows.find((r) => r.key === "hub:hub-b")).toMatchObject({ online: null, gen: null });
  });
});

describe("buildRealmRows — the 🔒 realm page from local observation", () => {
  const leg = node({
    id: "n-home",
    name: "home-win",
    principal: "mesh/main/agent/home-win",
    credential: { not_after: "2030-01-01T00:00:00Z", remaining_secs: 500_000, phase: "healthy" },
    policy: { generation: 15, source: "pack", hub_generation: 15, pull: null },
    peers: plane([
      { agent: "main/leo-mesh", online: true, leaf_phase: null, leaf_remaining_secs: 900_000, leaf_not_after_unix: 1_900_000 },
      { agent: "main/pzy", online: false, leaf_phase: "critical", leaf_remaining_secs: 250_000, leaf_not_after_unix: 1_250_000 },
    ]),
  });

  it("synthesized hub row + the machine's own agent + the peers union", () => {
    const rows = buildRealmRows("mesh", [leg], NOW);
    expect(rows[0]).toMatchObject({ key: "hub:hub", name: "hub", online: true });
    expect(rows.find((r) => r.key === "main/home-win")).toMatchObject({
      online: true,
      gen: 15,
      localNodeId: "n-home",
      leaf: { phase: "healthy", remaining_secs: 500_000 },
    });
    expect(rows.find((r) => r.key === "main/leo-mesh")).toMatchObject({ online: true, declared: false });
    expect(rows.find((r) => r.key === "main/pzy")).toMatchObject({ online: false, leaf: { phase: "critical" } });
  });

  it("a stale hub read flips the observer and the synthesized hub row offline", () => {
    const stale = { ...leg, peers: plane(leg.peers!.peers, NOW - 10_000) };
    const rows = buildRealmRows("mesh", [stale], NOW);
    expect(rows.find((r) => r.key === "hub:hub")?.online).toBe(false);
    expect(rows.find((r) => r.key === "main/home-win")?.online).toBe(false);
  });

  it("a local hub names the hub row; other realms' agents never leak in", () => {
    const localHub = node({ id: "n-hub", name: "hub-1", kind: "hub", principal: "mesh/-/hub/hub-1" });
    const foreign = node({ id: "n-f", name: "f", principal: "other/main/agent/f", peers: plane([]) });
    const rows = buildRealmRows("mesh", [leg, localHub, foreign], NOW);
    expect(rows[0]).toMatchObject({ key: "hub:hub-1", name: "hub-1", localNodeId: "n-hub" });
    expect(rows.find((r) => r.key === "main/f")).toBeUndefined();
  });
});

describe("realmObservers — running mesh agents with a peers plane, realm-honest", () => {
  it("stops at stopped agents, other realms, and non-agent kinds", () => {
    const running = node({ id: "a", name: "a", principal: "mesh/main/agent/a", peers: plane([]) });
    const stopped = node({ id: "b", name: "b", principal: "mesh/main/agent/b", state: "Stopped", peers: plane([]) });
    const foreign = node({ id: "c", name: "c", principal: "other/main/agent/c", peers: plane([]) });
    const hub = node({ id: "d", name: "d", kind: "hub", principal: "mesh/-/hub/d" });
    expect(realmObservers([running, stopped, foreign, hub], "mesh").map((o) => o.node.id)).toEqual(["a"]);
    // `null` is the unfiltered form (the deployment scope's degraded page).
    expect(realmObservers([running, foreign], null).map((o) => o.node.id)).toEqual(["a", "c"]);
  });
});

describe("watchersFaceReading — the resident-task armed assertion", () => {
  const CAPTURED = NOW;
  const FACTOR = 3;
  const row = (name: string, intervalSecs: number, tickAge: number) => ({
    name,
    interval_secs: intervalSecs,
    last_tick_unix: CAPTURED - tickAge,
  });

  it("allArmed: every row inside its own threshold", () => {
    expect(
      watchersFaceReading([row("heartbeat", 15, 8), row("renewal", 60, 45)], CAPTURED, FACTOR, NOW),
    ).toEqual({ state: "allArmed", count: 2 });
  });

  it("the boundary is per-row: exactly 3× its own interval is a slow pass, one past is silent", () => {
    expect(watchersFaceReading([row("policy", 10, 30)], CAPTURED, FACTOR, NOW)).toEqual({
      state: "allArmed",
      count: 1,
    });
    // The SAME tick age on a slower task stays armed — the anchor is the
    // row's own cadence, never a global threshold.
    expect(watchersFaceReading([row("renewal", 60, 31)], CAPTURED, FACTOR, NOW)).toEqual({
      state: "allArmed",
      count: 1,
    });
    expect(watchersFaceReading([row("policy", 10, 31)], CAPTURED, FACTOR, NOW)).toEqual({
      state: "silent",
      armed: 0,
      silent: [{ name: "policy", intervalSecs: 10, quietSecs: 31 }],
    });
  });

  it("mixed: the silent row is named, the armed count keeps the rest", () => {
    expect(
      watchersFaceReading([row("heartbeat", 15, 3), row("policy", 10, 45)], CAPTURED, FACTOR, NOW),
    ).toEqual({
      state: "silent",
      armed: 1,
      silent: [{ name: "policy", intervalSecs: 10, quietSecs: 45 }],
    });
  });

  it("unknown: no rows (an older hub) or missing anchor/factor never reads as passed", () => {
    expect(watchersFaceReading([], CAPTURED, FACTOR, NOW)).toEqual({ state: "unknown" });
    expect(watchersFaceReading([row("policy", 10, 5)], null, FACTOR, NOW)).toEqual({
      state: "unknown",
    });
    expect(watchersFaceReading([row("policy", 10, 5)], CAPTURED, undefined, NOW)).toEqual({
      state: "unknown",
    });
  });

  it("unknown: a face staler than the largest row threshold cannot support a verdict", () => {
    // Largest threshold here is 3×60 = 180s; the render clock 400s past
    // capture means every verdict could have changed unseen.
    expect(
      watchersFaceReading([row("heartbeat", 15, 5), row("renewal", 60, 5)], CAPTURED, FACTOR, NOW + 400),
    ).toEqual({ state: "unknown" });
  });
});

describe("queuedOpsFaceReading — the mailbox watermark classification", () => {
  const CAPTURED = NOW;
  const BUDGET = 30;

  it("clear: no face / nothing waiting — never a fabricated verdict", () => {
    expect(queuedOpsFaceReading(null, null, CAPTURED, null, null, false, BUDGET)).toEqual({
      state: "clear",
    });
    expect(queuedOpsFaceReading(0, null, CAPTURED, null, 0, false, BUDGET)).toEqual({
      state: "clear",
    });
  });

  it("waiting on an offline leg reads expected (rides the next check-in)", () => {
    expect(
      queuedOpsFaceReading(1, CAPTURED - 259_200, CAPTURED, "pause ollama", 0, false, BUDGET),
    ).toEqual({
      state: "waiting",
      count: 1,
      ageSecs: 259_200,
      oldestOp: "pause ollama",
      stuck: false,
    });
  });

  it("the stuck boundary is online-only: exactly the budget is slow, one past is stuck", () => {
    expect(
      queuedOpsFaceReading(2, CAPTURED - BUDGET, CAPTURED, null, 0, true, BUDGET),
    ).toEqual({ state: "waiting", count: 2, ageSecs: BUDGET, oldestOp: null, stuck: false });
    expect(
      queuedOpsFaceReading(2, CAPTURED - (BUDGET + 1), CAPTURED, null, 0, true, BUDGET),
    ).toEqual({ state: "waiting", count: 2, ageSecs: BUDGET + 1, oldestOp: null, stuck: true });
    // The same age on an OFFLINE leg never reads stuck.
    expect(
      queuedOpsFaceReading(2, CAPTURED - (BUDGET + 1), CAPTURED, null, 0, false, BUDGET),
    ).toEqual({ state: "waiting", count: 2, ageSecs: BUDGET + 1, oldestOp: null, stuck: false });
  });

  it("dropped: nothing waiting now, but the drop history renders apart", () => {
    expect(queuedOpsFaceReading(0, null, CAPTURED, null, 3, false, BUDGET)).toEqual({
      state: "dropped",
      droppedTotal: 3,
    });
  });

  it("missing anchors degrade: no budget or capture anchor → age unknown, never stuck", () => {
    expect(
      queuedOpsFaceReading(1, CAPTURED - 1000, null, null, 0, true, BUDGET),
    ).toEqual({ state: "waiting", count: 1, ageSecs: 0, oldestOp: null, stuck: false });
    expect(
      queuedOpsFaceReading(1, null, CAPTURED, null, 0, true, undefined),
    ).toEqual({ state: "waiting", count: 1, ageSecs: 0, oldestOp: null, stuck: false });
  });
});

describe("connectionFaceReading — the window-stats classification", () => {
  const conn = (reconnects: number, timeouts: number) => ({
    reconnects_last_hour: reconnects,
    rtt_p50_ms: 100,
    rtt_p99_ms: 190,
    rtt_timeouts: timeouts,
  });

  it("unknown on absent inputs; healthy when everything countable is quiet", () => {
    expect(connectionFaceReading(null, null)).toEqual({ state: "unknown" });
    expect(connectionFaceReading(conn(0, 0), null)).toEqual({
      state: "healthy",
      reconnects: 0,
      backoffStage: 0,
      timeouts: 0,
      p50Ms: 100,
      p99Ms: 190,
    });
  });

  it("timeouts outrank reconnects; the backoff stage clamps to the ladder depth", () => {
    expect(connectionFaceReading(conn(6, 0), 3)).toMatchObject({
      state: "reconnecting",
      reconnects: 6,
      backoffStage: 3,
    });
    expect(connectionFaceReading(conn(6, 3), 9)).toMatchObject({
      state: "probesUnanswered",
      timeouts: 3,
      backoffStage: 5,
    });
  });
});

describe("credentialFaceReading — the per-tier countdown judgment", () => {
  const CAPTURED = NOW;

  it("offline tier: green at 45d, yellow strictly under 14d, red strictly under 7d", () => {
    const offline = (remainingDays: number) => {
      const notAfter = CAPTURED + remainingDays * 86_400;
      const notBefore = notAfter - 90 * 86_400;
      return credentialFaceReading(
        notBefore,
        notAfter,
        CAPTURED,
        14,
        7,
        20,
        10,
      );
    };
    expect(offline(45)).toEqual({ state: "green", mode: "offline", remainingSecs: 45 * 86_400 });
    expect(offline(14)).toEqual({ state: "green", mode: "offline", remainingSecs: 14 * 86_400 });
    expect(offline(13)).toMatchObject({ state: "yellow", mode: "offline" });
    expect(offline(7)).toMatchObject({ state: "yellow", mode: "offline" });
    expect(offline(6)).toMatchObject({ state: "red", mode: "offline" });
  });

  it("registrar tier: span-relative phases, and expired is the deepest red", () => {
    const registrar = (spanSecs: number, remainingSecs: number) =>
      credentialFaceReading(
        CAPTURED - (spanSecs - remainingSecs),
        CAPTURED + remainingSecs,
        CAPTURED,
        14,
        7,
        20,
        10,
      );
    expect(registrar(24 * 3600, 12 * 3600)).toMatchObject({ state: "green", mode: "registrar" });
    // 1h of 24h is 4% — already past the critical line; yellow lives in [10%, 20%).
    expect(registrar(24 * 3600, 12_000)).toMatchObject({ state: "yellow", mode: "registrar" });
    expect(registrar(24 * 3600, 600)).toMatchObject({ state: "red", mode: "registrar" });
    expect(registrar(24 * 3600, -1)).toMatchObject({ state: "red", mode: "registrar" });
  });

  it("absent window or thresholds read unknown — never a fabricated green", () => {
    expect(credentialFaceReading(null, null, CAPTURED, 14, 7, 20, 10)).toEqual({
      state: "unknown",
    });
    expect(
      credentialFaceReading(CAPTURED, CAPTURED + 86_400, null, 14, 7, 20, 10),
    ).toEqual({ state: "unknown" });
    expect(
      credentialFaceReading(CAPTURED, CAPTURED + 86_400, CAPTURED, undefined, 7, 20, 10),
    ).toEqual({ state: "unknown" });
  });
});

describe("fossilStreamsFaceReading — the fossil face's per-row judgment", () => {
  const CAPTURED = NOW;
  const stream = (name: string, byteAge: number, budget?: number | null) => ({
    name,
    last_byte_unix: CAPTURED - byteAge,
    idle_budget_secs: budget ?? null,
  });

  it("per-row anchors: a 300s-budget stream is fossil past 10×300, a sibling with the same age and a 3600s budget is not", () => {
    const fossils = fossilStreamsFaceReading(
      [stream("svc", 2_900, 300), stream("db", 2_900, 3600)],
      CAPTURED,
      10,
      7,
    );
    // 2_900 < 3_000: neither yet.
    expect(fossils).toEqual([]);
    const crossed = fossilStreamsFaceReading(
      [stream("svc", 3_001, 300), stream("db", 3_001, 3600)],
      CAPTURED,
      10,
      7,
    );
    expect(crossed).toEqual([{ name: "svc", idleSecs: 3_001 }]);
  });

  it("unbudgeted streams use the absolute default (7d)", () => {
    expect(
      fossilStreamsFaceReading([stream("svc", 7 * 86_400, null)], CAPTURED, 10, 7),
    ).toEqual([]);
    expect(
      fossilStreamsFaceReading([stream("svc", 7 * 86_400 + 1, undefined)], CAPTURED, 10, 7),
    ).toEqual([{ name: "svc", idleSecs: 7 * 86_400 + 1 }]);
  });

  it("absent inputs read no fossils, never a guess", () => {
    expect(fossilStreamsFaceReading(null, CAPTURED, 10, 7)).toEqual([]);
    expect(fossilStreamsFaceReading([stream("svc", 9_999_999, 300)], null, 10, 7)).toEqual([]);
    expect(fossilStreamsFaceReading([stream("svc", 9_999_999, 300)], CAPTURED, undefined, 7)).toEqual([]);
  });
});

describe("headroomFaceReading — the admission-scope headroom", () => {
  it("unlimited or absent scopes read null (no wall, no reading)", () => {
    expect(headroomFaceReading(47, 0, 20)).toBeNull();
    expect(headroomFaceReading(null, 256, 20)).toBeNull();
    expect(headroomFaceReading(47, 256, undefined)).toBeNull();
  });

  it("tight strictly under the warn pct: 20% remaining is not yet tight, 19% is", () => {
    expect(headroomFaceReading(200, 250, 20)).toEqual({
      inFlight: 200,
      cap: 250,
      remainingPct: 20,
      tight: false,
    });
    expect(headroomFaceReading(202, 250, 20)?.tight).toBe(true);
    expect(headroomFaceReading(256, 256, 20)).toEqual({
      inFlight: 256,
      cap: 256,
      remainingPct: 0,
      tight: true,
    });
  });
});

describe("crlFaceReading — the CRL-poll liveness classification", () => {
  const CAPTURED = NOW;
  const SILENT_AFTER = 200;

  it("current: polling, nothing moved (no-change polls count)", () => {
    expect(crlFaceReading(CAPTURED - 45, CAPTURED, SILENT_AFTER, NOW, 0)).toEqual({
      state: "current",
      ageSecs: 45,
      failures: 0,
    });
    // The failure counter rides along as diagnostic material, never as
    // the trigger: a failing-but-polling loop still reads current.
    expect(crlFaceReading(CAPTURED - 45, CAPTURED, SILENT_AFTER, NOW, 7)).toEqual({
      state: "current",
      ageSecs: 45,
      failures: 7,
    });
  });

  it("the boundary: exactly the threshold is still current, one past it is the wedged-loop class", () => {
    expect(crlFaceReading(CAPTURED - SILENT_AFTER, CAPTURED, SILENT_AFTER, NOW, 0)).toEqual({
      state: "current",
      ageSecs: SILENT_AFTER,
      failures: 0,
    });
    expect(crlFaceReading(CAPTURED - (SILENT_AFTER + 1), CAPTURED, SILENT_AFTER, NOW, 9)).toEqual({
      state: "silent",
      ageSecs: SILENT_AFTER + 1,
      failures: 9,
    });
  });

  it("never: no report landed — unknown, not silent", () => {
    expect(crlFaceReading(null, CAPTURED, SILENT_AFTER, NOW, null)).toEqual({ state: "never" });
  });

  it("unknown: an older hub (no capture anchor / no threshold) never guesses", () => {
    expect(crlFaceReading(CAPTURED - 8, null, SILENT_AFTER, NOW, 0)).toEqual({ state: "unknown" });
    expect(crlFaceReading(CAPTURED - 8, CAPTURED, undefined, NOW, 0)).toEqual({ state: "unknown" });
  });

  it("unknown: a face staler than the threshold degrades, never renders a stale verdict", () => {
    expect(crlFaceReading(CAPTURED - 8, CAPTURED, SILENT_AFTER, NOW + 400, 0)).toEqual({
      state: "unknown",
    });
  });
});

describe("policyFaceReading — the level face's recency classification", () => {
  const CAPTURED = NOW;
  const SILENT_AFTER = 30;

  it("current: a fresh confirmation instant, judged at the capture anchor", () => {
    expect(policyFaceReading(15, CAPTURED - 8, CAPTURED, SILENT_AFTER, NOW)).toEqual({
      state: "current",
      ageSecs: 8,
    });
  });

  it("the boundary: exactly the threshold is still current, one past it is silent", () => {
    expect(policyFaceReading(15, CAPTURED - SILENT_AFTER, CAPTURED, SILENT_AFTER, NOW)).toEqual({
      state: "current",
      ageSecs: SILENT_AFTER,
    });
    expect(policyFaceReading(15, CAPTURED - (SILENT_AFTER + 1), CAPTURED, SILENT_AFTER, NOW)).toEqual({
      state: "silent",
      ageSecs: SILENT_AFTER + 1,
    });
  });

  it("never: no watermark and no confirmation — the one honest meaning left", () => {
    expect(policyFaceReading(null, null, CAPTURED, SILENT_AFTER, NOW)).toEqual({ state: "never" });
  });

  it("unknown: an older hub (a watermark without the instant) never guesses", () => {
    expect(policyFaceReading(15, null, CAPTURED, SILENT_AFTER, NOW)).toEqual({ state: "unknown" });
    expect(policyFaceReading(15, CAPTURED - 8, null, SILENT_AFTER, NOW)).toEqual({ state: "unknown" });
  });

  it("unknown: a face staler than the threshold cannot support a per-leg verdict", () => {
    // The face was captured 45s ago (missed pushes, a sleeping machine):
    // between then and now a crossing could have happened unseen —
    // degrade, never render a possibly-stale "current".
    expect(policyFaceReading(15, CAPTURED - 8, CAPTURED, SILENT_AFTER, NOW + 45)).toEqual({
      state: "unknown",
    });
    // "never" is a value fact, not a recency one — it survives a stale face.
    expect(policyFaceReading(null, null, CAPTURED, SILENT_AFTER, NOW + 45)).toEqual({
      state: "never",
    });
  });

  it("rides the composed rows: a declared mesh agent's remote face carries the reading", () => {
    const f = fleet({
      hub: {
        hub: "hub",
        floor: 15,
        serving: 15,
        captured_at_unix: NOW,
        policy_silent_after_secs: 30,
        agents: [
          { agent: "main/leo", online: true, seen: 15, policy_last_pull_unix: NOW - 8 },
          { agent: "main/gone", online: false, seen: 14, policy_last_pull_unix: NOW - 400 },
        ],
      },
      nodes: [
        {
          kind: "mesh_agent",
          name: "leo",
          workspace: "main",
          local: null,
          remote: {
            online: true,
            seen_generation: 15,
            policy_last_pull_unix: NOW - 8,
            face_captured_at_unix: NOW,
          },
        },
      ],
    });
    const { rows } = buildDeploymentRows(f, [], NOW);
    expect(rows.find((r) => r.key === "main/leo")?.policy).toEqual({ state: "current", ageSecs: 8 });
    // Tail 1 (the hub-registered stray) classifies from the overview's
    // own anchor + threshold.
    expect(rows.find((r) => r.key === "main/gone")?.policy).toEqual({
      state: "silent",
      ageSecs: 400,
    });
    // The stock fixture (no confirmation instants — an older hub's shape)
    // never guesses: the reading reads unknown, not a fabricated current.
    const { rows: plainRows } = buildDeploymentRows(fleet(), [], NOW);
    expect(plainRows.find((r) => r.key === "main/leo")?.policy).toEqual({ state: "unknown" });
  });
});
