import { Asterisk } from "lucide-react";
import {
  effectiveTransport,
  formatRemainingSecs,
  isRunning,
  leafPhase,
  listenerDown,
  policyInverted,
  stateText,
  type NodeInfo,
} from "../api";
import { useT, type TFn } from "../i18n";
import { principalRealm } from "../lib/shellFace";
import { cn } from "../lib/utils";
import { Badge, Button, Hint, KindBadge, StateDot } from "./ui";

/// Short state label for the card footer — `stateText` in full (Failed
/// carries the whole error) belongs in the detail page; the card shows the
/// word, the tooltip carries the rest. A connected agent also names its
/// transport: the dial form is the node's own static choice, so Connected
/// plus this value is the hub-confirmed form — the QUIC-switch acceptance
/// signal that used to require grepping the hub journal.
function shortState(node: NodeInfo, t: TFn): string {
  const state = node.state;
  if (typeof state === "object" && state !== null) {
    if (state.Connected) {
      const isAgent = node.kind === "expose_agent" || node.kind === "mesh_agent";
      if (isAgent) {
        return effectiveTransport(node) === "quic"
          ? t("nodeCard.quicConfirmed")
          : t("nodeCard.h2Confirmed");
      }
      return t("nodeCard.connected");
    }
    if (state.Reconnecting) return t("nodeCard.reconnecting");
    if (state.Failed) return t("nodeCard.failed");
  }
  return stateText(state, t).replace(/…$/, "");
}

/// The one-line "what this node points at" summary — the card's reason to
/// exist. Kind-specific because the four roles answer different questions:
/// expose → where each service is reached, mesh → how many rules it carries,
/// hub/ingress → where it listens. Everything shown is effective truth
/// (override applied), matching the start log's vocabulary.
function summaryLines(
  node: NodeInfo,
  t: TFn,
): { text: string; title?: string; overridden?: boolean }[] {
  switch (node.kind) {
    case "expose_agent":
      return (node.services ?? []).map((service) => ({
        text: `${service.id} → ${service.effective_address}`,
        // Data, not explanation: the ✱ marker is the override flag, the
        // tooltip carries the pack default it overrides.
        overridden: service.overridden,
        title: service.overridden
          ? t("common.packDefaultTitle", { addr: service.default_address })
          : undefined,
      }));
    case "mesh_agent": {
      const inCount = node.mesh_ingress_rules.length;
      const outCount = node.mesh_egress_rules.length;
      return [{ text: t("nodeCard.meshRules", { in: inCount, out: outCount }) }];
    }
    case "hub":
    case "ingress":
      return [{ text: t("nodeCard.listens", { addr: node.listen ?? "—" }) }];
  }
}

/// One node as an overview card. The card body navigates to the detail
/// page; the single quick action (Start/Stop — the day-to-day operation)
/// stays on the card and never enters the detail page. Everything else
/// (Remove, preferences, logs) lives one level down.
export default function NodeCard({
  node,
  onOpen,
  onQuickAction,
}: {
  node: NodeInfo;
  onOpen: () => void;
  onQuickAction: () => void;
}) {
  const running = isRunning(node.state);
  const failed = typeof node.state === "object" && node.state !== null && "Failed" in node.state;
  const leaf = leafPhase(node.credential);
  const { t } = useT();
  const summary = summaryLines(node, t);
  // Identity from the signed principal — a sealed import always carries a
  // realm, so the card never needs a deployment tree to be nameable.
  const realm = principalRealm(node.principal);

  return (
    <Hint text={node.principal ?? node.pack_dir}>
      <div
        role="button"
        tabIndex={0}
        onClick={onOpen}
        onKeyDown={(e) => {
          if (e.key === "Enter") onOpen();
        }}
        className={cn(
          "flex w-full cursor-pointer flex-col gap-2 rounded-xl border bg-bg-2 p-3.5 text-left text-fg-1 outline-none",
          "transition-[border-color,box-shadow] duration-150 hover:border-line-strong hover:shadow-elevate-1",
          "focus-visible:border-accent focus-visible:ring-[3px] focus-visible:ring-accent-tint",
          failed ? "border-critical/50 hover:border-critical/70" : "border-line",
        )}
      >
        <div className="flex items-center gap-2">
          <StateDot state={node.state} />
          <strong className="min-w-0 flex-1 truncate text-base font-semibold">{node.name}</strong>
          {realm && <span className="shrink-0 font-mono text-micro text-fg-3">{realm}</span>}
          <KindBadge kind={node.kind} />
        </div>
        <div className="flex min-h-[18px] flex-col gap-0.5 font-mono text-small text-fg-2">
          {summary.length === 0 && <span className="text-fg-3">—</span>}
          {summary.map((line) => (
            <div key={line.text} className="flex min-w-0 items-center gap-1 overflow-hidden">
              {line.overridden && (
                <Asterisk aria-label={t("common.overriddenTitle")} className="size-3 shrink-0 text-warn" />
              )}
              <Hint text={line.title ?? line.text}>
                <span className="truncate">{line.text}</span>
              </Hint>
            </div>
          ))}
        </div>
        {(node.desired_running ||
          node.generation > 0 ||
          node.credential ||
          policyInverted(node.policy) ||
          listenerDown(node.listeners)) && (
          <div className="flex flex-wrap gap-1.5">
            {node.desired_running && <Badge>{t("nodeCard.autoStart")}</Badge>}
            {node.generation > 0 && <Badge>gen {node.generation}</Badge>}
            {/* Deadlock on the card (2026-10-09): users don't visit a
                detail page to discover a lineage deadlock — the inversion
                badge rides with the other always-on tier badges. */}
            {policyInverted(node.policy) && (
              <Hint text={t("nodeDetail.policyStaleTitle")}>
                <Badge tone="warn">{t("nodeCard.policyStale")}</Badge>
              </Hint>
            )}
            {/* Listener honesty on the card (2026-10-09): a green session
                card plus a gone listener must surface as exactly that —
                the rule is declared but nothing is serving it. */}
            {listenerDown(node.listeners) && (
              <Hint text={t("nodeDetail.listenerDownTitle")}>
                <Badge tone="critical">{t("nodeCard.listenerDown")}</Badge>
              </Hint>
            )}
            {node.credential && (
              <Hint text={t("nodeCard.credentialsExpireTitle", { time: node.credential.not_after })}>
                <Badge tone={leaf ?? "neutral"}>leaf {formatRemainingSecs(node.credential.remaining_secs)}</Badge>
              </Hint>
            )}
          </div>
        )}
        <div className="mt-auto flex min-h-control items-center gap-2">
          <Hint text={stateText(node.state, t)}>
            <span className="min-w-0 flex-1 truncate text-start text-small text-fg-3">
              {shortState(node, t)}
            </span>
          </Hint>
          <Button
            size="sm"
            variant={running ? "secondary" : "primary"}
            disabled={node.state === "Starting" || node.state === "Stopping"}
            onClick={(e) => {
              e.stopPropagation();
              onQuickAction();
            }}
          >
            {running ? t("common.stop") : t("common.start")}
          </Button>
        </div>
      </div>
    </Hint>
  );
}
