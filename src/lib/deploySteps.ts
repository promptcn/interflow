import type { useT } from "../i18n";
import type { ChangeStateDto, DeployContextDto, ManifestSummaryDto } from "../api";

export type Translate = ReturnType<typeof useT>["t"];

export interface NextStep {
  text: string;
  done: boolean;
  action?: () => void;
  actionLabel?: string;
}

/// The next-steps checklist: the FIRST not-done item is the current legal
/// action, in a fixed priority order (fix document → add first node → add
/// first stream → save → apply). Everything above it renders as done.
///
/// The two no-document states are honest about what failed: a read failure
/// (`readError`) is a missing/unreadable FILE — its remedy is picking or
/// creating one, never editing TOML; a parse failure (`parseError`) means
/// the text loaded but does not parse — that one is the editor's. The
/// 2026-10-09 first-run bug lived in collapsing the two: a missing
/// `~/interflow.toml` surfaced as "fix the manifest's TOML syntax".
export function buildNextSteps(input: {
  t: Translate;
  /// The file could not be read (missing/unreadable) — the load-class
  /// failure; takes priority over everything.
  readError: string | null;
  /// A document exists in some form (parsed, or loaded-but-unparseable).
  loaded: boolean;
  /// The loaded text failed to parse — the syntax-class failure.
  parseError: string | null;
  issues: string[];
  agents: ManifestSummaryDto["agents"];
  meshAgents: ManifestSummaryDto["agents"];
  dirty: boolean;
  changeState: ChangeStateDto | null;
  onChooseManifest: () => void;
  onOpenManifest: () => void;
  onIssueNode: () => void;
  onAddStream: () => void;
  onSave: () => void;
  onApply: () => void;
}): NextStep[] {
  const { t } = input;
  const steps: NextStep[] = [];
  if (input.readError !== null) {
    steps.push({
      text: t("overview.stepFileMissing", { error: input.readError }),
      done: false,
      action: input.onChooseManifest,
      actionLabel: t("overview.chooseAction"),
    });
    return steps;
  }
  if (input.parseError !== null) {
    steps.push({
      text: t("overview.stepFixSyntax", { error: input.parseError }),
      done: false,
      action: input.onOpenManifest,
    });
    return steps;
  }
  if (!input.loaded) {
    return [
      {
        text: t("overview.stepLoad"),
        done: false,
        action: input.onChooseManifest,
        actionLabel: t("overview.chooseAction"),
      },
    ];
  }
  steps.push({
    text:
      input.issues.length > 0
        ? t("overview.stepIssues", {
            n: String(input.issues.length),
            first: input.issues[0] ?? "",
          })
        : t("overview.stepValid"),
    done: input.issues.length === 0,
    action: input.issues.length > 0 ? input.onOpenManifest : undefined,
  });
  const hasAgents = input.agents.length > 0;
  steps.push({
    text: t("overview.stepFirstNode"),
    done: hasAgents,
    action: hasAgents ? undefined : input.onIssueNode,
  });
  const hasStreams = input.meshAgents.length > 0;
  steps.push({
    text: t("overview.stepFirstStream"),
    done: hasStreams,
    action: hasStreams ? undefined : input.onAddStream,
  });
  steps.push({
    text: t("overview.stepSave"),
    done: !input.dirty,
    action: input.dirty ? input.onSave : undefined,
  });
  const applied = input.changeState?.kind === "applied";
  steps.push({
    text: applied
      ? t("overview.stepApplied", {
          gen: input.changeState?.kind === "applied" ? String(input.changeState.generation) : "",
        })
      : changeStateLabel(input.changeState, t),
    done: applied,
    action: applied ? undefined : input.onApply,
  });
  return steps;
}

export function changeStateLabel(state: ChangeStateDto | null, t: Translate): string {
  if (state === null) return t("overview.changeUnknown");
  switch (state.kind) {
    case "never_applied":
      return t("overview.changeNever");
    case "applied":
      return t("overview.changeApplied", { gen: String(state.generation) });
    case "policy_edits_pending":
      return t("overview.changePolicy");
    case "identity_edits_pending":
      return t("overview.changeIdentity");
  }
}

/// Issuer/out blank-fill: a context whose siblings were never given values
/// (first run, or a fresh manifest pick) takes them from the manifest's own
/// directory — `<dir>/issuer` and `<dir>/dist`, the one-deployment-one-
/// folder convention the CLI's CWD-relative defaults already encode. A
/// bare manifest filename fills with bare `issuer`/`dist` (CLI parity);
/// a typed value is never overwritten.
export function withBlankSiblingsFilled(current: DeployContextDto): DeployContextDto {
  return {
    manifest: current.manifest,
    issuer: current.issuer.trim() === "" ? siblingOf(current.manifest, "issuer") : current.issuer,
    out: current.out.trim() === "" ? siblingOf(current.manifest, "dist") : current.out,
  };
}

/// The manifest's sibling path for `name`, keeping the manifest's own
/// separator style (Windows dialogs emit backslashes; hand-typed paths
/// are usually forward slashes — either works, echoing is nicer).
function siblingOf(manifestPath: string, name: string): string {
  const trimmed = manifestPath.trim();
  const cut = Math.max(trimmed.lastIndexOf("/"), trimmed.lastIndexOf("\\"));
  if (cut <= 0) return name; // bare filename → CWD-relative sibling
  const sep = trimmed.includes("\\") && !trimmed.includes("/") ? "\\" : "/";
  return trimmed.slice(0, cut).replace(/[\\/]+$/, "") + sep + name;
}

/// Remembers a deployment context: current first, duplicates dropped,
/// capped at five. An incomplete triple (any blank path) is not a context
/// yet — placeholder values must never persist themselves into the list
/// (the 2026-10-09 sticky-`~/interflow.toml` bug).
export function rememberContext(
  list: DeployContextDto[],
  ctx: DeployContextDto,
): DeployContextDto[] {
  if (ctx.manifest.trim() === "" || ctx.issuer.trim() === "" || ctx.out.trim() === "") {
    return list;
  }
  const rest = list.filter(
    (c) => c.manifest !== ctx.manifest || c.issuer !== ctx.issuer || c.out !== ctx.out,
  );
  return [ctx, ...rest].slice(0, 5);
}
