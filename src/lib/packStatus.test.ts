import { describe, expect, it } from "vitest";
import type { DeployPackDto } from "../api";
import { packDistributeSource, packIdentities, packUpdateAction, packUpdateSource } from "./packStatus";

const pack = (over: Partial<DeployPackDto>): DeployPackDto =>
  ({
    dir_name: "agent-leo-mesh",
    path: "/dist/packs/agent-leo-mesh",
    kind: "mesh_agent",
    node: "leo-mesh",
    generation: 16,
    digest: "sha256:current",
    expires: "2027-01-01",
    principal: "gui/mesh/agent/leo-mesh",
    is_staging: false,
    local_node: null,
    ...over,
  }) as DeployPackDto;

const local = (generation: number, digest = "sha256:current") =>
  ({ id: "n1", name: "leo-mesh", generation, digest }) as DeployPackDto["local_node"];

describe("packUpdateAction — generations move forward only", () => {
  it("the 2026-10-14 bug: a lower-generation pack with a different digest is a downgrade, not an update", () => {
    // rotate staging remnant: node on gen16, card holds gen15 content.
    expect(
      packUpdateAction(pack({ generation: 15, digest: "sha256:gen15", local_node: local(16) })),
    ).toBe("downgrade");
  });

  it("a lower-generation pack with the SAME digest is still a downgrade", () => {
    expect(packUpdateAction(pack({ generation: 15, local_node: local(16) }))).toBe("downgrade");
  });

  it("a higher generation is the forward update", () => {
    expect(packUpdateAction(pack({ local_node: local(15, "sha256:old") }))).toBe("upgrade");
  });

  it("same generation, different digest stays actionable — the content refresh must not regress", () => {
    expect(
      packUpdateAction(pack({ digest: "sha256:reapplied", local_node: local(16, "sha256:old") })),
    ).toBe("content");
  });

  it("same generation, same digest is the reinstall recovery path", () => {
    expect(packUpdateAction(pack({ local_node: local(16) }))).toBe("reinstall");
  });

  it("no local node means no action at all", () => {
    expect(packUpdateAction(pack({ local_node: null }))).toBe("none");
  });
});

describe("packIdentities — one card per identity, history never surfaces", () => {
  const identity = "gui/mesh/agent/leo-mesh";

  it("the 2026-10-14 field shape: base at gen16 beside consumed gen16/gen15 stagings collapses to one card, no window", () => {
    const identities = packIdentities([
      pack({ principal: identity, local_node: local(16) }),
      pack({
        dir_name: "agent-leo-mesh-gen16",
        path: "/dist/packs/agent-leo-mesh-gen16",
        is_staging: true,
        principal: identity,
        local_node: local(16),
      }),
      pack({
        dir_name: "agent-leo-mesh-gen15",
        path: "/dist/packs/agent-leo-mesh-gen15",
        generation: 15,
        digest: "sha256:gen15",
        is_staging: true,
        principal: identity,
        local_node: local(16),
      }),
    ]);
    expect(identities).toHaveLength(1);
    expect(identities[0].current.dir_name).toBe("agent-leo-mesh");
    expect(identities[0].window).toBeNull();
  });

  it("an ahead-of-base staging the local node has not reached IS the window", () => {
    const identities = packIdentities([
      pack({ generation: 14, principal: identity, local_node: local(14, "sha256:old") }),
      pack({
        dir_name: "agent-leo-mesh-gen15",
        path: "/dist/packs/agent-leo-mesh-gen15",
        generation: 15,
        digest: "sha256:gen15",
        is_staging: true,
        principal: identity,
        local_node: local(14, "sha256:old"),
      }),
    ]);
    expect(identities[0].window?.dir_name).toBe("agent-leo-mesh-gen15");
  });

  it("a remote identity (no local node) keeps its window open — the offline receiver may still be waiting", () => {
    const remote = "gui/mesh/agent/home-win";
    const identities = packIdentities([
      pack({
        dir_name: "agent-home-win",
        path: "/dist/packs/agent-home-win",
        node: "home-win",
        generation: 3,
        principal: remote,
      }),
      pack({
        dir_name: "agent-home-win-gen4",
        path: "/dist/packs/agent-home-win-gen4",
        node: "home-win",
        generation: 4,
        is_staging: true,
        principal: remote,
      }),
    ]);
    expect(identities[0].window?.generation).toBe(4);
  });

  it("a consumed staging ahead of a stale base is history, not a window", () => {
    // Node installed outside the dist tree: base still gen14, node already
    // runs the gen15 staging — nothing left to distribute or install.
    const identities = packIdentities([
      pack({ generation: 14, principal: identity, local_node: local(15, "sha256:gen15") }),
      pack({
        dir_name: "agent-leo-mesh-gen15",
        path: "/dist/packs/agent-leo-mesh-gen15",
        generation: 15,
        digest: "sha256:gen15",
        is_staging: true,
        principal: identity,
        local_node: local(15, "sha256:gen15"),
      }),
    ]);
    expect(identities[0].window).toBeNull();
    expect(identities[0].current.generation).toBe(14);
  });

  it("with several live stagings the newest wins; superseded ones stay invisible", () => {
    const identities = packIdentities([
      pack({ generation: 14, principal: identity }),
      pack({
        dir_name: "agent-leo-mesh-gen15",
        path: "/dist/packs/agent-leo-mesh-gen15",
        generation: 15,
        is_staging: true,
        principal: identity,
      }),
      pack({
        dir_name: "agent-leo-mesh-gen16",
        path: "/dist/packs/agent-leo-mesh-gen16",
        is_staging: true,
        principal: identity,
      }),
    ]);
    expect(identities[0].window?.dir_name).toBe("agent-leo-mesh-gen16");
  });

  it("a staging-only tree (base hand-moved) still gets a card, carried by the newest staging", () => {
    const identities = packIdentities([
      pack({
        dir_name: "agent-leo-mesh-gen16",
        path: "/dist/packs/agent-leo-mesh-gen16",
        is_staging: true,
        principal: identity,
      }),
    ]);
    expect(identities).toHaveLength(1);
    expect(identities[0].current.dir_name).toBe("agent-leo-mesh-gen16");
    expect(identities[0].window).toBeNull();
  });

  it("identities are ordered by node name", () => {
    const identities = packIdentities([
      pack({ node: "z-last", principal: "gui/mesh/agent/z-last" }),
      pack({ node: "a-first", principal: "gui/mesh/agent/a-first" }),
    ]);
    expect(identities.map((i) => i.current.node)).toEqual(["a-first", "z-last"]);
  });
});

describe("action sources — one identity, one resolved directory per intent", () => {
  it("update and distribute prefer the window; both fall back to current", () => {
    const withWindow = {
      principal: "p",
      current: pack({ generation: 14 }),
      window: pack({
        dir_name: "agent-leo-mesh-gen15",
        generation: 15,
        is_staging: true,
      }),
    };
    expect(packUpdateSource(withWindow).dir_name).toBe("agent-leo-mesh-gen15");
    expect(packDistributeSource(withWindow).dir_name).toBe("agent-leo-mesh-gen15");

    const closed = { principal: "p", current: pack({}), window: null };
    expect(packUpdateSource(closed).dir_name).toBe("agent-leo-mesh");
    expect(packDistributeSource(closed).dir_name).toBe("agent-leo-mesh");
  });
});
