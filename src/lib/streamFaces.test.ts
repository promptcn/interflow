/// The 流 face-derivations' contract: the four statuses land in the
/// shared vocabulary with unknown staying honestly uncolored, the idle
/// defaults follow the protocol, and the target join only ever links an
/// agent row that runs on this machine.

import { describe, expect, it } from "vitest";
import { idleTimeoutDefault, streamStatusKey, targetLocalNodeId } from "./streamFaces";

describe("streamStatusKey", () => {
  it("maps the four states onto the shared status vocabulary", () => {
    expect(streamStatusKey("serving")).toBe("success");
    expect(streamStatusKey("down")).toBe("critical");
    expect(streamStatusKey("catching_up")).toBe("warn");
  });

  it("unknown maps to null — the hollow dot, never a guessed color", () => {
    expect(streamStatusKey("unknown")).toBeNull();
  });
});

describe("idleTimeoutDefault", () => {
  it("carries the engine's per-protocol defaults", () => {
    expect(idleTimeoutDefault("tcp")).toBe(300);
    expect(idleTimeoutDefault("udp")).toBe(60);
  });
});

describe("targetLocalNodeId", () => {
  const fleet = {
    nodes: [
      { kind: "mesh_agent" as const, name: "srv", local: { id: "id-srv" } },
      { kind: "expose_agent" as const, name: "web", local: null },
      { kind: "hub" as const, name: "hub1", local: { id: "id-hub" } },
      { kind: "ingress" as const, name: "in1", local: { id: "id-in" } },
    ],
  };

  it("links a target agent that runs on this machine", () => {
    expect(targetLocalNodeId(fleet, "srv")).toBe("id-srv");
  });

  it("stays a word (null) for a remote target, a stranger, or a non-agent row", () => {
    expect(targetLocalNodeId(fleet, "web")).toBeNull();
    expect(targetLocalNodeId(fleet, "nope")).toBeNull();
    // A hub/ingress sharing the name is not the target agent — the join
    // is kind-honest, never name-greedy.
    expect(targetLocalNodeId(fleet, "hub1")).toBeNull();
    expect(targetLocalNodeId(fleet, "in1")).toBeNull();
  });
});
