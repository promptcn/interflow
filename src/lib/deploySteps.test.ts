import { describe, expect, it, vi } from "vitest";
import type { ChangeStateDto, ManifestSummaryDto } from "../api";
import { buildNextSteps, rememberContext, withBlankSiblingsFilled } from "./deploySteps";

/// A key-returning t: assertions stay copy-independent while interpolated
/// values ({error} etc.) stay visible in the returned text.
const t = (key: string, params?: Record<string, string | number>) =>
  params === undefined ? key : `${key} ${JSON.stringify(params)}`;

const agents = (n: number) =>
  Array.from({ length: n }, (_, i) => ({ node: `agent-${i}` })) as ManifestSummaryDto["agents"];

const baseInput = () => ({
  t,
  readError: null,
  loaded: true,
  parseError: null,
  issues: [] as string[],
  agents: agents(1),
  meshAgents: agents(1),
  dirty: false,
  changeState: { kind: "applied", generation: 3 } as ChangeStateDto,
  onChooseManifest: vi.fn(),
  onOpenManifest: vi.fn(),
  onIssueNode: vi.fn(),
  onAddStream: vi.fn(),
  onSave: vi.fn(),
  onApply: vi.fn(),
});

describe("buildNextSteps — the two no-document failure classes", () => {
  it("a read failure is the file-missing step with the pick action, even alongside a parse error", () => {
    const input = baseInput();
    const steps = buildNextSteps({ ...input, readError: "File not found: /x/interflow.toml", parseError: "bad toml" });
    expect(steps).toHaveLength(1);
    expect(steps[0].text).toContain("overview.stepFileMissing");
    expect(steps[0].text).toContain("/x/interflow.toml");
    expect(steps[0].action).toBe(input.onChooseManifest);
    // The 2026-10-09 bug: this state rendered as "fix the TOML syntax".
    expect(steps[0].text).not.toContain("overview.stepFixSyntax");
  });

  it("a parse failure (file read fine) stays the syntax step with the editor action", () => {
    const input = baseInput();
    const steps = buildNextSteps({ ...input, parseError: "TOML parse error at line 3" });
    expect(steps).toHaveLength(1);
    expect(steps[0].text).toContain("overview.stepFixSyntax");
    expect(steps[0].action).toBe(input.onOpenManifest);
  });

  it("a blank first run (nothing read, nothing parsed) is the load step, now with the pick action", () => {
    const input = baseInput();
    const steps = buildNextSteps({
      ...input,
      loaded: false,
      agents: agents(0),
      meshAgents: agents(0),
    });
    expect(steps).toHaveLength(1);
    expect(steps[0].text).toContain("overview.stepLoad");
    expect(steps[0].action).toBe(input.onChooseManifest);
  });
});

describe("buildNextSteps — the loaded ladder", () => {
  it("walks issues → first node → first stream → save → apply in order, wiring each action", () => {
    const input = baseInput();
    const steps = buildNextSteps({
      ...input,
      issues: ["no hub", "no route"],
      agents: agents(0),
      meshAgents: agents(0),
      dirty: true,
      changeState: null,
    });
    expect(steps.map((s) => s.done)).toEqual([false, false, false, false, false]);
    expect(steps[0].action).toBe(input.onOpenManifest);
    expect(steps[1].action).toBe(input.onIssueNode);
    expect(steps[2].action).toBe(input.onAddStream);
    expect(steps[3].action).toBe(input.onSave);
    expect(steps[4].action).toBe(input.onApply);
  });

  it("marks everything done for a valid, applied deployment (no actions left)", () => {
    const steps = buildNextSteps(baseInput());
    expect(steps.map((s) => s.done)).toEqual([true, true, true, true, true]);
    expect(steps.every((s) => s.action === undefined)).toBe(true);
    expect(steps[4].text).toContain("overview.stepApplied");
  });
});

describe("withBlankSiblingsFilled", () => {
  it("fills blank issuer/out from the manifest's own directory (the one-folder convention)", () => {
    expect(
      withBlankSiblingsFilled({
        manifest: "/home/x/interflow-deployments/promptcn-mesh/interflow.toml",
        issuer: "",
        out: "  ",
      }),
    ).toEqual({
      manifest: "/home/x/interflow-deployments/promptcn-mesh/interflow.toml",
      issuer: "/home/x/interflow-deployments/promptcn-mesh/issuer",
      out: "/home/x/interflow-deployments/promptcn-mesh/dist",
    });
  });

  it("keeps the manifest's separator style for Windows paths", () => {
    expect(
      withBlankSiblingsFilled({ manifest: "C:\\deployments\\mesh\\interflow.toml", issuer: "", out: "" }),
    ).toEqual({
      manifest: "C:\\deployments\\mesh\\interflow.toml",
      issuer: "C:\\deployments\\mesh\\issuer",
      out: "C:\\deployments\\mesh\\dist",
    });
  });

  it("a bare manifest filename fills with CWD-relative siblings (CLI parity)", () => {
    expect(withBlankSiblingsFilled({ manifest: "interflow.toml", issuer: "", out: "" })).toEqual({
      manifest: "interflow.toml",
      issuer: "issuer",
      out: "dist",
    });
  });

  it("never overwrites typed sibling values", () => {
    expect(
      withBlankSiblingsFilled({ manifest: "/m/interflow.toml", issuer: "/mine/issuer", out: "/mine/dist" }),
    ).toEqual({ manifest: "/m/interflow.toml", issuer: "/mine/issuer", out: "/mine/dist" });
  });
});

describe("rememberContext", () => {
  const ctx = (n: number) => ({ manifest: `/m${n}`, issuer: `/i${n}`, out: `/o${n}` });

  it("rejects incomplete triples — placeholder paths never persist themselves", () => {
    const list = [ctx(1)];
    expect(rememberContext(list, { manifest: "/m", issuer: "", out: "/o" })).toBe(list);
    expect(rememberContext(list, { manifest: "", issuer: "/i", out: "/o" })).toBe(list);
  });

  it("promotes the current context to the front and drops its duplicate", () => {
    const list = [ctx(1), ctx(2), ctx(3)];
    expect(rememberContext(list, ctx(2))).toEqual([ctx(2), ctx(1), ctx(3)]);
  });

  it("caps the remembered list at five", () => {
    const list = [ctx(1), ctx(2), ctx(3), ctx(4), ctx(5)];
    expect(rememberContext(list, ctx(6))).toEqual([ctx(6), ctx(1), ctx(2), ctx(3), ctx(4)]);
  });
});
