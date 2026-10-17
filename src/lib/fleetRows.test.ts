import { describe, expect, it } from "vitest";
import {
  buildDeploymentRows,
  buildRealmRows,
  hasFleetFace,
  hasServicesFace,
  hasStreamsFace,
  realmObservers,
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
        remote: { online: true, seen_generation: 15 },
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
