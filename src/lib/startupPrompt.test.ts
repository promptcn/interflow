import { describe, expect, it } from "vitest";
import type { NodeInfo } from "../api";
import { shouldPromptStartAll } from "./startupPrompt";

const node = (over: Partial<NodeInfo>): NodeInfo =>
  ({
    id: "n1",
    kind: "mesh_agent",
    name: "lan-a",
    principal: "gui/mesh/agent/lan-a",
    attribution: "lan-a#n1",
    pack_dir: "/packs/agent-lan-a",
    state: "Stopped",
    desired_running: false,
    transport: null,
    pack_transport: null,
    hub_quic_addr: null,
    pack_hub_quic_addr: null,
    services: [],
    mesh_ingress_rules: [],
    mesh_egress_rules: [],
    listen: null,
    generation: 1,
    credential: null,
    policy: null,
    ...over,
  }) as NodeInfo;

describe("shouldPromptStartAll — the startup all-stopped prompt rule", () => {
  it("an empty node list never prompts", () => {
    expect(shouldPromptStartAll([])).toBe(false);
  });

  it("all stopped, no intent — the residue the intent restore cannot decide", () => {
    expect(shouldPromptStartAll([node({}), node({ id: "n2" })])).toBe(true);
  });

  it("Failed counts as not running — the offer covers a failed restore too", () => {
    expect(shouldPromptStartAll([node({ state: { Failed: { error: "pack unreadable" } } })])).toBe(
      true,
    );
  });

  it("any node with start intent stays silent — the auto-restore is on it", () => {
    // The mount-time race guard: a desired node may still read Stopped.
    expect(shouldPromptStartAll([node({}), node({ id: "n2", desired_running: true })])).toBe(
      false,
    );
  });

  it("anything running stays silent", () => {
    expect(shouldPromptStartAll([node({ state: "Running" }), node({ id: "n2" })])).toBe(false);
  });

  it("a node mid-start (Starting) counts as running — no prompt during restore", () => {
    expect(shouldPromptStartAll([node({ state: "Starting" })])).toBe(false);
  });
});
