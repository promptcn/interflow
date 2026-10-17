import { describe, expect, it } from "vitest";
import { createEntryVisible, meshRealms, principalRealm, shellFace } from "./shellFace";

describe("principalRealm — identity, not the filesystem, names a node", () => {
  it("takes the realm segment of a signed agent principal", () => {
    expect(principalRealm("acme-mesh/main/mesh_agent/home-win")).toBe("acme-mesh");
  });

  it("hubs and ingresses carry the '-' workspace — the realm is still first", () => {
    expect(principalRealm("acme-mesh/-/hub/hub-1")).toBe("acme-mesh");
  });

  it("placeholder nodes (unreadable pack) show no realm, not a broken one", () => {
    expect(principalRealm(null)).toBeNull();
    expect(principalRealm(undefined)).toBeNull();
    expect(principalRealm("")).toBeNull();
  });
});

describe("meshRealms — the leg machine's realm inference from packs", () => {
  it("collects the realms of mesh agents, deduped and sorted", () => {
    expect(
      meshRealms([
        { kind: "mesh_agent", principal: "promptcn-mesh/main/agent/leo-mesh" },
        { kind: "mesh_agent", principal: "promptcn-mesh/main/agent/spare" },
        { kind: "mesh_agent", principal: "acme-mesh/ops/agent/home-win" },
      ]),
    ).toEqual(["acme-mesh", "promptcn-mesh"]);
  });

  it("expose agents and hubs name no realm — no fleet face to observe", () => {
    expect(
      meshRealms([
        { kind: "expose_agent", principal: "promptcn/main/agent/web" },
        { kind: "hub", principal: "promptcn-mesh/-/hub/hub" },
      ]),
    ).toEqual([]);
  });

  it("placeholder nodes (unreadable pack) stay silent", () => {
    expect(meshRealms([{ kind: "mesh_agent", principal: null }])).toEqual([]);
  });
});

describe("createEntryVisible — onboarding guidance by existence", () => {
  it("the true new operator (zero deployments, zero nodes) sees it", () => {
    expect(createEntryVisible(false, false)).toBe(true);
  });

  it("an operator machine (deployments found) keeps it — zero regression", () => {
    expect(createEntryVisible(true, true)).toBe(true);
    expect(createEntryVisible(true, false)).toBe(true);
  });

  it("a deployed-end machine (nodes, no deployments) never gets deployment-pushing guidance", () => {
    expect(createEntryVisible(false, true)).toBe(false);
  });
});

describe("shellFace — the 本机 view is unconditionally first-class", () => {
  it("an open scope (deployment or 🔒 realm) owns the shell: its views", () => {
    expect(
      shellFace({ depLoading: false, nodesLoaded: true, scopeOpen: true, nodeCount: 2 }),
    ).toBe("scopeViews");
    expect(
      shellFace({ depLoading: true, nodesLoaded: false, scopeOpen: true, nodeCount: 0 }),
    ).toBe("scopeViews");
  });

  it("nodes without a scope are a complete view, not a degraded state", () => {
    expect(
      shellFace({ depLoading: false, nodesLoaded: true, scopeOpen: false, nodeCount: 1 }),
    ).toBe("localView");
  });

  it("zero deployments and zero nodes is the only onboarding form", () => {
    expect(
      shellFace({ depLoading: false, nodesLoaded: true, scopeOpen: false, nodeCount: 0 }),
    ).toBe("onboarding");
  });

  it("the node list gates the no-scope branch — no onboarding flash while nodes load", () => {
    expect(
      shellFace({ depLoading: false, nodesLoaded: false, scopeOpen: false, nodeCount: 0 }),
    ).toBe("loading");
    expect(
      shellFace({ depLoading: true, nodesLoaded: true, scopeOpen: false, nodeCount: 3 }),
    ).toBe("loading");
  });
});
