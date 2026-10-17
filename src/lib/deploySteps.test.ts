import { describe, expect, it, vi } from "vitest";
import type { AgentRoleDto, ChangeStateDto, ManifestSummaryDto } from "../api";
import { buildNextSteps, rememberContext, withBlankSiblingsFilled } from "./deploySteps";

/// A key-returning t: assertions stay copy-independent while interpolated
/// values ({error} etc.) stay visible in the returned text.
const t = (key: string, params?: Record<string, string | number>) =>
  params === undefined ? key : `${key} ${JSON.stringify(params)}`;

/// One declared agent — the role the faces read plus the two content
/// counts the ladder reads (declared services, mesh rules).
const agent = (
  role: AgentRoleDto,
  opts: { services?: number; rules?: number } = {},
): ManifestSummaryDto["agents"][number] => ({
  node: "web",
  workspace: "main",
  role,
  transport: null,
  services: Array.from({ length: opts.services ?? 0 }, (_, i) => ({
    id: `svc-${i}`,
    address: "127.0.0.1:9000",
  })),
  mesh_ingress: Array.from({ length: opts.rules ?? 0 }, (_, i) => ({
    name: `in-${i}`,
    listen: "127.0.0.1:9001",
    protocol: "tcp" as const,
    target_agent: "web",
    remote_addr: "10.0.0.1:9002",
    idle_timeout_secs: null,
  })),
  mesh_egress: [],
});

const baseInput = () => ({
  t,
  readError: null,
  loaded: true,
  parseError: null,
  issues: [] as string[],
  agents: [agent("mesh", { rules: 1 })],
  dirty: false,
  changeState: { kind: "applied", generation: 3 } as ChangeStateDto,
  onChooseManifest: vi.fn(),
  onOpenManifest: vi.fn(),
  onIssueNode: vi.fn(),
  onAddStream: vi.fn(),
  onDeclareService: vi.fn(),
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
      agents: [],
    });
    expect(steps).toHaveLength(1);
    expect(steps[0].text).toContain("overview.stepLoad");
    expect(steps[0].action).toBe(input.onChooseManifest);
  });
});

describe("buildNextSteps — the loaded ladder", () => {
  it("walks issues → first node → first stream → save → apply in order, wiring each action with its label", () => {
    const input = baseInput();
    const steps = buildNextSteps({
      ...input,
      issues: ["no hub", "no route"],
      agents: [agent("mixed")],
      dirty: true,
      changeState: null,
    });
    // The declared mixed agent completes the first-node step and lights
    // both content faces; the content itself is still missing.
    expect(steps.map((s) => s.done)).toEqual([false, true, false, false, false, false]);
    expect(steps[0].action).toBe(input.onOpenManifest);
    expect(steps[1].action).toBeUndefined();
    expect(steps[2].action).toBe(input.onAddStream);
    expect(steps[3].action).toBe(input.onDeclareService);
    expect(steps[4].action).toBe(input.onSave);
    expect(steps[5].action).toBe(input.onApply);
    expect(steps.map((s) => s.actionLabel)).toEqual([
      "overview.editManifestAction",
      undefined,
      "overview.go",
      "overview.go",
      "manifest.save",
      "dep.publish",
    ]);
  });

  it("marks everything done for a valid, applied deployment (no actions left)", () => {
    const steps = buildNextSteps(baseInput());
    expect(steps.map((s) => s.done)).toEqual([true, true, true, true, true]);
    expect(steps.every((s) => s.action === undefined)).toBe(true);
    expect(steps[4].text).toContain("overview.stepApplied");
  });

  it("a loaded document with semantic issues walks the ISSUES step — never the syntax branch (the OverviewView masquerade regression)", () => {
    const input = baseInput();
    const steps = buildNextSteps({ ...input, issues: ["no hub declared"] });
    expect(steps[0].text).toContain("overview.stepIssues");
    expect(steps[0].text).toContain("no hub declared");
    expect(steps[0].text).not.toContain("overview.stepFixSyntax");
    expect(steps[0].action).toBe(input.onOpenManifest);
    expect(steps).toHaveLength(5); // the ladder continues past issues
  });
});

describe("buildNextSteps — the content steps follow the deployment's shape", () => {
  it("a mesh deployment keeps the stream step and shows no service step", () => {
    const input = baseInput();
    const steps = buildNextSteps({ ...input, agents: [agent("mesh")] });
    const texts = steps.map((s) => s.text);
    expect(texts).toContain(t("overview.stepFirstStream"));
    expect(texts).not.toContain(t("overview.stepFirstService"));
    const stream = steps.find((s) => s.text === t("overview.stepFirstStream"))!;
    expect(stream.done).toBe(false);
    expect(stream.action).toBe(input.onAddStream);
  });

  it("an expose deployment swaps the stream step for the service step — the un-completable step never hangs", () => {
    const input = baseInput();
    const steps = buildNextSteps({ ...input, agents: [agent("expose")] });
    const texts = steps.map((s) => s.text);
    expect(texts).not.toContain(t("overview.stepFirstStream"));
    expect(texts).toContain(t("overview.stepFirstService"));
    const service = steps.find((s) => s.text === t("overview.stepFirstService"))!;
    expect(service.done).toBe(false);
    expect(service.action).toBe(input.onDeclareService);
  });

  it("the steps complete on their own declared content (services; mesh rules)", () => {
    const steps = buildNextSteps({
      ...baseInput(),
      agents: [agent("expose", { services: 1 }), agent("mesh", { rules: 1 })],
    });
    const byText = (key: string) => steps.find((s) => s.text === t(key))!;
    expect(byText("overview.stepFirstService").done).toBe(true);
    expect(byText("overview.stepFirstStream").done).toBe(true);
  });

  it("a mixed deployment shows both content steps, stream first (the nav's order)", () => {
    const steps = buildNextSteps({ ...baseInput(), agents: [agent("mixed")] });
    const texts = steps.map((s) => s.text);
    expect(texts).toHaveLength(6);
    expect(texts.indexOf(t("overview.stepFirstNode"))).toBeLessThan(texts.indexOf(t("overview.stepFirstStream")));
    expect(texts.indexOf(t("overview.stepFirstStream"))).toBeLessThan(texts.indexOf(t("overview.stepFirstService")));
    expect(texts.indexOf(t("overview.stepFirstService"))).toBeLessThan(texts.indexOf(t("overview.stepSave")));
  });

  it("zero agents leave the face undetermined — only the first-node step shows, claiming nothing else", () => {
    const input = baseInput();
    const steps = buildNextSteps({ ...input, agents: [] });
    const texts = steps.map((s) => s.text);
    expect(texts).not.toContain(t("overview.stepFirstStream"));
    expect(texts).not.toContain(t("overview.stepFirstService"));
    expect(texts).toHaveLength(4); // issues → first node → save → apply
    expect(steps[1].action).toBe(input.onIssueNode);
    expect(steps[1].actionLabel).toBe("dep.overview.issueNode");
  });
});

describe("buildNextSteps — the ghost-button invariant", () => {
  it("every not-done step with an action carries its label — an empty-label pill never renders", () => {
    const steps = buildNextSteps({
      ...baseInput(),
      issues: ["no hub"],
      agents: [agent("mixed")],
      dirty: true,
      changeState: null,
    });
    const acting = steps.filter((s) => s.action !== undefined && !s.done);
    expect(acting.length).toBeGreaterThan(0);
    for (const step of acting) {
      expect(step.actionLabel, `step "${step.text}" has an action but no label`).toBeTruthy();
    }
  });

  it("an omitted callback renders no action at all", () => {
    const steps = buildNextSteps({
      ...baseInput(),
      onChooseManifest: undefined,
      onOpenManifest: undefined,
      onIssueNode: undefined,
      onAddStream: undefined,
      onDeclareService: undefined,
      onSave: undefined,
      onApply: undefined,
      issues: ["no hub"],
      agents: [agent("mixed")],
      dirty: true,
      changeState: null,
    });
    expect(steps.every((s) => s.action === undefined)).toBe(true);
  });

  it("busy disables exactly the save/apply actions (the in-flight no-go is stated, not swallowed)", () => {
    const steps = buildNextSteps({ ...baseInput(), dirty: true, changeState: null, busy: true });
    const disabled = steps.filter((s) => s.disabled === true);
    expect(disabled.map((s) => s.text)).toEqual([t("overview.stepSave"), t("overview.changeUnknown")]);
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
