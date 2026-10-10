import { useState } from "react";
import { ArrowLeft } from "lucide-react";
import {
  formatRemainingSecs,
  leafPhase,
  policyInverted,
  type LogLine,
  type NodeInfo,
} from "../api";
import { useT } from "../i18n";
import LogView from "./LogView";
import NodeConfigView from "./NodeConfigView";
import NodeStatusView from "./NodeStatusView";
import ProposalDialog from "./ProposalDialog";
import {
  Badge,
  Button,
  Hint,
  Kbd,
  KindBadge,
  SectionPanel,
  SegmentedControl,
  StateDot,
} from "./ui";

export type DetailView = "status" | "config" | "logs";

interface Props {
  node: NodeInfo;
  // View state lives in App (the DeployFace precedent): Esc climbs
  // view → overview, and opening a node always lands on Status — the
  // monitoring view is never polluted by the previous browse path.
  view: DetailView;
  onViewChange: (view: DetailView) => void;
  onBack: () => void;
  onChanged: () => Promise<void>;
  onError: (message: string) => void;
  // Log pane: the detail page owns its placement, App still owns the
  // buffer and the scope preference.
  logs: LogLine[];
  logScope: "node" | "machine";
  onLogScopeChange: (scope: "node" | "machine") => void;
  onClearLogs: () => void;
}

/// A badge that jumps to the view owning its exception — the cross-view
/// rule made clickable (quiet by default; when it speaks, it navigates).
function ViewBadge({
  view,
  tone,
  text,
  title,
  onViewChange,
}: {
  view: DetailView;
  tone: "warn" | "critical" | "accent";
  text: string;
  title?: string;
  onViewChange: (view: DetailView) => void;
}) {
  const badge = (
    <Badge
      tone={tone}
      className="cursor-pointer"
      role="button"
      tabIndex={0}
      onClick={() => onViewChange(view)}
      onKeyDown={(e) => {
        if (e.key === "Enter" || e.key === " ") {
          e.preventDefault();
          onViewChange(view);
        }
      }}
    >
      {text}
    </Badge>
  );
  return title ? <Hint text={title}>{badge}</Hint> : badge;
}

/// The detail page shell: a shared header (back, state dot, name, kind)
/// over three in-page views — Status (default) / Config / Logs
/// (2026-10-09 frequency layering). The monitoring glance, the reference
/// truth, and the incident pane each get their own scroll axis instead of
/// sharing one; Logs finally owns the full page height. Section budget:
/// a new surface must first answer "which view, and does it need a
/// badge" — appending sections to a shared scroll axis is how this page
/// rotted twice before. Exceptions are never buried in a view: policy
/// inversion, credential tiers, reconnecting, and pending proposals hang
/// as badges on the view chrome and jump to the owning view.
export default function NodeDetail({
  node,
  view,
  onViewChange,
  onBack,
  onChanged,
  onError,
  logs,
  logScope,
  onLogScopeChange,
  onClearLogs,
}: Props) {
  const { t } = useT();
  // The requester's stream-proposal dialog (mesh agent, running) — opened
  // from the Status view, lives above all views.
  const [proposalOpen, setProposalOpen] = useState(false);

  // Cross-view exception badges, non-zero/abnormal only — silence when
  // everything is fine.
  const stale = policyInverted(node.policy);
  const leaf = leafPhase(node.credential);
  const reconnecting =
    typeof node.state === "object" && node.state !== null && "Reconnecting" in node.state;
  const pendingCount =
    node.proposals?.filter((p) => p.status.status === "pending").length ?? 0;

  return (
    <div className="flex min-h-0 flex-1 flex-col gap-3">
      <div className="flex flex-wrap items-center gap-2.5">
        <Button variant="link" size="sm" onClick={onBack}>
          <ArrowLeft className="size-4" />
          {t("nodeDetail.allNodes")}
          <Kbd>Esc</Kbd>
        </Button>
        <StateDot state={node.state} size="md" />
        <h2 className="m-0 text-xl font-semibold">{node.name}</h2>
        <KindBadge kind={node.kind} />
      </div>

      <div className="flex flex-wrap items-center gap-2.5">
        <SegmentedControl
          value={view}
          options={[
            { value: "status", label: t("nodeDetail.status") },
            { value: "config", label: t("nodeDetail.viewConfig") },
            { value: "logs", label: t("nodeDetail.logs") },
          ]}
          onChange={onViewChange}
        />
        {stale && (
          <ViewBadge
            view="status"
            tone="warn"
            text={t("nodeCard.policyStale")}
            title={t("nodeDetail.policyStaleTitle")}
            onViewChange={onViewChange}
          />
        )}
        {leaf && node.credential && (
          <ViewBadge
            view="status"
            tone={leaf}
            text={`leaf ${formatRemainingSecs(node.credential.remaining_secs)}`}
            title={t("nodeDetail.credentialsExpireTitle")}
            onViewChange={onViewChange}
          />
        )}
        {reconnecting && (
          <ViewBadge
            view="status"
            tone="warn"
            text={t("nodeCard.reconnecting")}
            onViewChange={onViewChange}
          />
        )}
        {pendingCount > 0 && (
          <ViewBadge
            view="config"
            tone="accent"
            text={t("proposal.pendingCount", { n: String(pendingCount) })}
            onViewChange={onViewChange}
          />
        )}
      </div>

      {/* All three views stay mounted and merely hide (the App face-switch
          precedent): switching preserves the preferences form state and
          each view's scroll position, and the engine-pushed
          peers/proposals planes keep rendering into their view. Each
          view owns its scroll container — Logs instead lets LogView's
          internal pane own the full page height. */}
      <div
        className={
          view === "status" ? "flex min-h-0 flex-1 flex-col gap-3 overflow-y-auto" : "hidden"
        }
      >
        <NodeStatusView
          node={node}
          onChanged={onChanged}
          onError={onError}
          onRemoved={onBack}
          onRequestStream={() => setProposalOpen(true)}
        />
      </div>
      <div
        className={
          view === "config" ? "flex min-h-0 flex-1 flex-col gap-3 overflow-y-auto" : "hidden"
        }
      >
        <NodeConfigView node={node} onChanged={onChanged} onError={onError} />
      </div>
      <div className={view === "logs" ? "flex min-h-0 flex-1 flex-col gap-3" : "hidden"}>
        <SectionPanel
          title={t("nodeDetail.logs")}
          grow
          actions={
            <SegmentedControl
              value={logScope}
              options={[
                { value: "node", label: t("nodeDetail.thisNode") },
                { value: "machine", label: t("nodeDetail.thisMachine") },
              ]}
              onChange={onLogScopeChange}
            />
          }
        >
          <LogView logs={logs} showNodeColumn={logScope === "machine"} onClear={onClearLogs} />
        </SectionPanel>
      </div>

      {proposalOpen && (
        <ProposalDialog node={node} onClose={() => setProposalOpen(false)} onError={onError} />
      )}
    </div>
  );
}
