import { useState } from "react";
import { Plus } from "lucide-react";
import { api, isRunning, policyInverted, type NodeInfo } from "../api";
import { useT } from "../i18n";
import AddNodeDialog from "./AddNodeDialog";
import NodeCard from "./NodeCard";
import { Hint } from "./ui";

/// The Nodes face landing view: every node on this machine as one card, a
/// one-glance aggregate line above, the add flow at the end. This layer
/// answers "what runs here and where does it point"; anything heavier
/// (editing, logs, removal) is the detail page's job. GUI errors surface in
/// the app-level banner (default-quiet, interrupt-on-error).
export default function NodeOverview({
  nodes,
  loaded,
  onChanged,
  onError,
  onOpen,
}: {
  nodes: NodeInfo[];
  loaded: boolean;
  onChanged: () => Promise<void>;
  onError: (message: string) => void;
  onOpen: (id: string) => void;
}) {
  const [adding, setAdding] = useState(false);
  const { t } = useT();

  const quickAction = async (node: NodeInfo) => {
    try {
      if (isRunning(node.state)) {
        await api.stopNode(node.id);
      } else {
        await api.startNode(node.id);
      }
      await onChanged();
    } catch (e) {
      onError(
        t("overview.actionFailed", {
          action: isRunning(node.state) ? t("common.stop") : t("common.start"),
          name: node.name,
          error: String(e),
        }),
      );
    }
  };

  // Aggregate line parts, non-zero only — silence when everything is fine.
  const runningCount = nodes.filter((n) => isRunning(n.state)).length;
  const failedCount = nodes.filter(
    (n) => typeof n.state === "object" && n.state !== null && "Failed" in n.state,
  ).length;
  const stoppedCount = nodes.length - runningCount - failedCount;
  const aggregate = [
    runningCount > 0 && t("overview.runningCount", { n: runningCount }),
    stoppedCount > 0 && t("overview.stoppedCount", { n: stoppedCount }),
    failedCount > 0 && t("overview.failedCount", { n: failedCount }),
  ]
    .filter(Boolean)
    .join(" · ");
  // Worst-of exception bits (2026-10-09 frequency layering): policy
  // inversion and pending approvals are push-mode signals — the overview
  // must speak them even when nobody opens a card. Users don't visit a
  // detail page to discover a deadlock.
  const staleCount = nodes.filter((n) => policyInverted(n.policy)).length;
  const pendingCount = nodes.reduce(
    (acc, n) =>
      acc + (n.proposals?.filter((p) => p.status.status === "pending").length ?? 0),
    0,
  );

  return (
    <div className="flex min-h-0 flex-1 flex-col gap-2 overflow-y-auto">
      {nodes.length > 0 ? (
        <div className="px-0.5 text-small text-fg-3">
          {aggregate}
          {staleCount > 0 && (
            <>
              {" · "}
              <Hint text={t("nodeDetail.policyStaleTitle")}>
                <span className="text-warn">
                  {t("overview.policyStaleCount", { n: String(staleCount) })}
                </span>
              </Hint>
            </>
          )}
          {pendingCount > 0 && (
            <>
              {" · "}
              <span className="text-accent">
                {t("overview.pendingCount", { n: String(pendingCount) })}
              </span>
            </>
          )}
        </div>
      ) : (
        loaded && <div className="px-0.5 text-small text-fg-3">{t("overview.none")}</div>
      )}

      <div className="grid grid-cols-[repeat(auto-fill,minmax(300px,1fr))] content-start gap-3">
        {nodes.map((node) => (
          <NodeCard
            key={node.id}
            node={node}
            onOpen={() => onOpen(node.id)}
            onQuickAction={() => void quickAction(node)}
          />
        ))}
        <button
          onClick={() => setAdding(true)}
          className="flex min-h-[118px] cursor-pointer flex-col items-center justify-center gap-1.5 rounded-xl border border-dashed border-line-strong p-3 text-fg-3 outline-none transition-colors duration-150 hover:border-accent hover:text-accent focus-visible:border-accent focus-visible:ring-[3px] focus-visible:ring-accent-tint"
        >
          <Plus className="size-5" />
          {t("overview.addNode")}
        </button>
      </div>

      {adding && (
        <AddNodeDialog
          onClose={() => setAdding(false)}
          onAdded={async (createdId) => {
            setAdding(false);
            await onChanged();
            onOpen(createdId);
          }}
        />
      )}
    </div>
  );
}
