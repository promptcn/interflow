import type { useT } from "../i18n";
import type { ChangeStateDto, DeployContextDto, ManifestSummaryDto } from "../api";
import { hasServicesFace, hasStreamsFace } from "./fleetRows";

export type Translate = ReturnType<typeof useT>["t"];

export interface NextStep {
  text: string;
  done: boolean;
  action?: () => void;
  actionLabel?: string;
  /// The action exists but is currently a no-go (a publish in flight) —
  /// the button renders disabled instead of swallowing the click.
  disabled?: boolean;
}

/// The next-steps checklist: the FIRST not-done item is the current legal
/// action, in a priority order that follows the deployment's SHAPE (the
/// 2026-10-15/16 ruling, here as everywhere): fix document → add first
/// node → the content steps the declared agents can carry (first stream
/// under a streams face, first service under a services face, both for
/// mixed, neither while zero agents leave the face undetermined) → save
/// → apply. Everything above the current item renders as done.
///
/// The two no-document states are honest about what failed: a read failure
/// (`readError`) is a missing/unreadable FILE — its remedy is picking or
/// creating one, never editing TOML; a parse failure (`parseError`) means
/// the text loaded but does not parse — that one is the editor's. The
/// 2026-10-09 first-run bug lived in collapsing the two: a missing
/// `~/interflow.toml` surfaced as "fix the manifest's TOML syntax".
///
/// Every action callback is optional: a step without its callback renders
/// no button (a real action with a real label, or no button at all — an
/// empty-label pill that does nothing is never an option).
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
  dirty: boolean;
  changeState: ChangeStateDto | null;
  onChooseManifest?: () => void;
  onOpenManifest?: () => void;
  onIssueNode?: () => void;
  onAddStream?: () => void;
  onDeclareService?: () => void;
  onSave?: () => void;
  onApply?: () => void;
  /// An orchestration is in flight — the save/apply actions render
  /// disabled (their buttons state the no-go instead of swallowing it).
  busy?: boolean;
}): NextStep[] {
  const { t } = input;
  const steps: NextStep[] = [];
  if (input.readError !== null) {
    steps.push({
      text: t("overview.stepFileMissing", { error: input.readError }),
      done: false,
      ...act(input.onChooseManifest, t("overview.chooseAction")),
    });
    return steps;
  }
  if (input.parseError !== null) {
    steps.push({
      text: t("overview.stepFixSyntax", { error: input.parseError }),
      done: false,
      ...act(input.onOpenManifest, t("overview.editManifestAction")),
    });
    return steps;
  }
  if (!input.loaded) {
    return [
      {
        text: t("overview.stepLoad"),
        done: false,
        ...act(input.onChooseManifest, t("overview.chooseAction")),
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
    ...act(
      input.issues.length > 0 ? input.onOpenManifest : undefined,
      t("overview.editManifestAction"),
    ),
  });
  const hasAgents = input.agents.length > 0;
  steps.push({
    text: t("overview.stepFirstNode"),
    done: hasAgents,
    ...act(hasAgents ? undefined : input.onIssueNode, t("dep.overview.issueNode")),
  });
  // The content steps follow the deployment's shape — the SAME predicates
  // the nav items live by (10-15/10-16): a first-stream step only where a
  // mesh/mixed agent can carry mesh rules, a first-service step only where
  // an expose/mixed agent can declare services. Mixed shows both, streams
  // first (the nav's order); zero agents leave the face undetermined, so
  // neither step claims work the first node hasn't made possible yet — it
  // appears the moment the issued node's kind lands.
  if (hasStreamsFace({ agents: input.agents })) {
    const hasStreams = input.agents.some(
      (a) => a.mesh_ingress.length + a.mesh_egress.length > 0,
    );
    steps.push({
      text: t("overview.stepFirstStream"),
      done: hasStreams,
      ...act(hasStreams ? undefined : input.onAddStream, t("overview.go")),
    });
  }
  if (hasServicesFace({ agents: input.agents })) {
    const hasServices = input.agents.some((a) => a.services.length > 0);
    steps.push({
      text: t("overview.stepFirstService"),
      done: hasServices,
      ...act(hasServices ? undefined : input.onDeclareService, t("overview.go")),
    });
  }
  steps.push({
    text: t("overview.stepSave"),
    done: !input.dirty,
    disabled: input.busy,
    ...act(input.dirty ? input.onSave : undefined, t("manifest.save")),
  });
  const applied = input.changeState?.kind === "applied";
  steps.push({
    text: applied
      ? t("overview.stepApplied", {
          gen: input.changeState?.kind === "applied" ? String(input.changeState.generation) : "",
        })
      : changeStateLabel(input.changeState, t),
    done: applied,
    disabled: input.busy,
    ...act(applied ? undefined : input.onApply, t("dep.publish")),
  });
  return steps;
}

/// An action and its label travel together, or neither does — the
/// ghost-button invariant (a rendered button must have something to do
/// and something to say) encoded in one place.
function act(
  action: (() => void) | undefined,
  label: string,
): { action?: () => void; actionLabel?: string } {
  return action === undefined ? {} : { action, actionLabel: label };
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
