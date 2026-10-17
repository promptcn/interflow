import { useT } from "../i18n";
import { Badge, Button, Hint } from "../components/ui";
import { changeStateLabel } from "../lib/deploySteps";
import { useDeployment } from "./DeploymentContext";

/// The top bar's status cluster: the change-loop's state made permanently
/// visible — unsaved edits, unpublished changes (with the consequence
/// stated: hot or restart), pending requests, and the 发布 button. All
/// clear shows just the quiet converged dot (默认安静，异常才说话).
export default function StatusCluster({ onJumpProposals }: { onJumpProposals: () => void }) {
  const { t } = useT();
  const { busy, text, savedText, changeState, proposals, publish, deployment } = useDeployment();

  if (deployment === null) return null;

  const dirty = text !== null && text !== savedText;
  const pending = (proposals ?? []).filter((p) => p.status.status === "pending").length;

  // The classification states the publish consequence: policy-only edits
  // land hot across the fleet; identity-face edits re-render packs and
  // restart the local nodes. That difference is the button's tooltip.
  const unpublished =
    changeState !== null && changeState.kind !== "applied" && changeState.kind !== "never_applied";

  return (
    <div className="flex items-center gap-2">
      {dirty && (
        <Badge tone="warn" title={t("dep.status.dirty")}>
          {t("dep.status.dirty")}
        </Badge>
      )}
      {unpublished ? (
        <Hint
          text={
            changeState?.kind === "policy_edits_pending"
              ? t("dep.status.unpublishedHot")
              : t("dep.status.unpublishedRestart")
          }
        >
          <Badge tone="warn">{changeStateLabel(changeState, t)}</Badge>
        </Hint>
      ) : (
        !dirty && (
          <span className="inline-flex items-center gap-1.5 text-small text-fg-3">
            <span className="inline-block size-2 rounded-full bg-success" />
            {t("dep.status.saved")}
          </span>
        )
      )}
      {pending > 0 && (
        <button
          onClick={onJumpProposals}
          className="inline-flex min-h-control-sm cursor-pointer items-center rounded-full border border-warn/55 bg-warn/10 px-2.5 text-small font-medium text-warn transition-colors duration-150 outline-none hover:bg-warn/15 focus-visible:ring-[3px] focus-visible:ring-accent-tint"
        >
          {t("dep.status.pending", { n: String(pending) })}
        </button>
      )}
      <Button disabled={busy} onClick={() => void publish()}>
        {busy ? t("dep.publishing") : t("dep.publish")}
      </Button>
    </div>
  );
}
