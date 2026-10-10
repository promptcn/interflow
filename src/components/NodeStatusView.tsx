import { Plus } from "lucide-react";
import {
  api,
  effectiveTransport,
  formatAgoSecs,
  formatRemainingSecs,
  isRunning,
  leafPhase,
  peerLeafPhase,
  policyInverted,
  stateText,
  type NodeInfo,
} from "../api";
import { localeOf, useT } from "../i18n";
import { cn } from "../lib/utils";
import { Button, Hint, InfoRow, PeerDot, SectionPanel } from "./ui";

/// The detail page's default view: what gets a glance every day — state
/// and operations, health signals, peers — one screen, no scrolling
/// (2026-10-09 frequency layering). The health rows moved here from the
/// old Identity section: warn/critical phases are push-mode exceptions,
/// and exceptions live where the user lands, not one click away.
export default function NodeStatusView({
  node,
  onChanged,
  onError,
  onRemoved,
  onRequestStream,
}: {
  node: NodeInfo;
  onChanged: () => Promise<void>;
  onError: (message: string) => void;
  onRemoved: () => void;
  onRequestStream: () => void;
}) {
  const { t, lang } = useT();
  const running = isRunning(node.state);
  // The hub's registration receipt rides with the Connected state — the
  // egress address the hub observed plus the registration moment.
  const receipt =
    typeof node.state === "object" && node.state !== null && node.state.Connected
      ? node.state.Connected.hub_receipt
      : null;
  // The agent's own QUIC-timeout reason carries the "switch to h2" hint in
  // its text; surface the actionable short form instead of burying it in
  // the state line (the full reason still shows there).
  const quicDialTimeout =
    typeof node.state === "object" &&
    node.state !== null &&
    node.state.Reconnecting?.reason.includes("QUIC connect") === true;
  const reconnecting =
    typeof node.state === "object" && node.state !== null && "Reconnecting" in node.state;
  const stale = policyInverted(node.policy);

  const start = async () => {
    try {
      await api.startNode(node.id);
      await onChanged();
    } catch (e) {
      onError(t("nodeDetail.startFailed", { error: String(e) }));
    }
  };

  const stop = async () => {
    try {
      await api.stopNode(node.id);
      await onChanged();
    } catch (e) {
      onError(t("nodeDetail.stopFailed", { error: String(e) }));
    }
  };

  const remove = async () => {
    try {
      await api.removeNode(node.id);
      onRemoved();
      await onChanged();
    } catch (e) {
      onError(t("nodeDetail.removeFailed", { error: String(e) }));
    }
  };

  return (
    <>
      <SectionPanel
        title={t("nodeDetail.status")}
        actions={
          <>
            <Button variant="primary" disabled={running} onClick={start}>
              {t("common.start")}
            </Button>
            <Button disabled={!running} onClick={stop}>
              {t("common.stop")}
            </Button>
            <Hint text={t("nodeDetail.removeTitle")}>
              <Button variant="danger" disabled={running} onClick={remove}>
                {t("common.remove")}
              </Button>
            </Hint>
            {node.kind === "mesh_agent" && running && (
              <Button onClick={onRequestStream}>
                <Plus className="size-4" />
                {t("proposal.requestStream")}
              </Button>
            )}
          </>
        }
      >
        <span className="text-base">{stateText(node.state, t)}</span>
        {receipt && (
          <span className="text-small text-fg-3">
            {t("nodeDetail.receiptBase", {
              transport: effectiveTransport(node) === "quic" ? "QUIC" : "h2",
            })}
            {receipt.egress_ip ? t("nodeDetail.receiptEgress", { ip: receipt.egress_ip }) : ""}
            {t("nodeDetail.receiptRegistered", {
              time: new Date(receipt.registered_at_unix * 1000).toLocaleTimeString(
                localeOf(lang),
              ),
            })}
          </span>
        )}
        {quicDialTimeout && (
          <span className="text-small text-warn">{t("nodeDetail.quicTimeout")}</span>
        )}
        {reconnecting && !quicDialTimeout && (
          <span className="text-small text-fg-3">{t("nodeDetail.willReconnect")}</span>
        )}
      </SectionPanel>

      {(node.policy || node.credential) && (
        <SectionPanel title={t("nodeDetail.health")}>
          {node.policy && (
            <InfoRow label={t("nodeDetail.policyGeneration")}>
              {(() => {
                const text = `gen ${node.policy.generation} · ${
                  node.policy.source === "state_policy"
                    ? t("nodeDetail.policySourceState")
                    : t("nodeDetail.policySourcePack")
                }${
                  node.policy.hub_generation != null
                    ? t("nodeDetail.policyHubGen", { gen: String(node.policy.hub_generation) })
                    : ""
                }`;
                return (
                  <Hint text={stale ? t("nodeDetail.policyStaleTitle") : t("nodeDetail.policyTitle")}>
                    <span className={cn("text-small", stale ? "text-warn" : "text-fg-3")}>
                      {text}
                    </span>
                  </Hint>
                );
              })()}
            </InfoRow>
          )}
          {node.policy?.pull && (
            <InfoRow label={t("nodeDetail.policyPull")}>
              <Hint text={t("nodeDetail.policyPullTitle")}>
                <span
                  className={cn(
                    "text-small",
                    node.policy.pull.last_ok_unix === 0 ? "text-warn" : "text-fg-3",
                  )}
                >
                  {node.policy.pull.last_ok_unix === 0
                    ? t("nodeDetail.policyPullNever")
                    : t("nodeDetail.policyPullOk", {
                        ago: formatAgoSecs(node.policy.pull.last_ok_unix),
                        fails: String(node.policy.pull.failures_total),
                      })}
                </span>
              </Hint>
            </InfoRow>
          )}
          {node.credential && (
            <InfoRow label={t("nodeDetail.credentialsExpire")}>
              <Hint text={t("nodeDetail.credentialsExpireTitle")}>
                <span
                  className={cn(
                    "text-small",
                    leafPhase(node.credential) === "warn" && "text-warn",
                    leafPhase(node.credential) === "critical" && "text-critical",
                    leafPhase(node.credential) === null && "text-fg-3",
                  )}
                >
                  {node.credential.not_after} ·{" "}
                  {t("addNode.timeLeft", { time: formatRemainingSecs(node.credential.remaining_secs) })}
                </span>
              </Hint>
            </InfoRow>
          )}
        </SectionPanel>
      )}

      {/* What is REALLY listening (mesh agents, running) — the actual-state
          counterpart of the rules: per-rule bound address (port picks
          materialized) or the bind failure. A green card plus a gone
          listener shows as exactly that (the 2026-10-09 honesty axis). */}
      {node.kind === "mesh_agent" && running && node.listeners != null && (
        <SectionPanel title={t("nodeDetail.listeners")}>
          {node.listeners.length === 0 ? (
            <span className="text-small text-fg-3">{t("nodeDetail.listenersNone")}</span>
          ) : (
            node.listeners.map((l) => (
              <InfoRow key={l.rule} label={l.rule}>
                {l.bound_addr != null ? (
                  <Hint text={t("nodeDetail.listenerBoundTitle")}>
                    <span className="font-mono text-small text-fg-3">{l.bound_addr}</span>
                  </Hint>
                ) : (
                  <Hint text={l.last_error ?? t("nodeDetail.listenerDownTitle")}>
                    <span className="text-small text-critical">
                      {t("nodeDetail.listenerNotServing")}
                    </span>
                  </Hint>
                )}
                {/* A bound listener with a recorded error = a replace retry
                    pending (the old listener keeps serving) — warn, not
                    critical. */}
                {l.bound_addr != null && l.last_error != null && (
                  <Hint text={l.last_error}>
                    <span className="text-small text-warn">{t("nodeDetail.listenerRetry")}</span>
                  </Hint>
                )}
              </InfoRow>
            ))
          )}
        </SectionPanel>
      )}

      {node.kind === "mesh_agent" && running && node.peers && (
        <SectionPanel
          title={t("nodeDetail.peers")}
          hint={
            node.peers.last_ok_unix > 0
              ? t("nodeDetail.peersUpdated", { ago: formatAgoSecs(node.peers.last_ok_unix) })
              : undefined
          }
        >
          {node.peers.peers.length === 0 ? (
            <span className="text-small text-fg-3">{t("nodeDetail.peersNone")}</span>
          ) : (
            node.peers.peers.map((peer) => {
              // Display name: the qualified id's agent part (the listing
              // is already tenant-scoped, so it is unique in here); the
              // full id stays one hover away.
              const shortName = peer.agent.split("/").pop() ?? peer.agent;
              const leaf = peerLeafPhase(peer);
              return (
                <div key={peer.agent} className="flex flex-wrap items-center gap-2.5 text-base">
                  <PeerDot online={peer.online} />
                  <Hint text={peer.agent}>
                    <span className="font-mono text-small">{shortName}</span>
                  </Hint>
                  <span className={peer.online ? "text-base" : "text-small text-fg-3"}>
                    {peer.online ? t("nodeDetail.peerOnline") : t("nodeDetail.peerOffline")}
                  </span>
                  {peer.leaf_phase && (
                    <Hint text={t("nodeDetail.peerLeafTitle")}>
                      <span
                        className={cn(
                          "ml-auto text-small",
                          leaf === "warn" && "text-warn",
                          leaf === "critical" && "text-critical",
                          leaf === null && "text-fg-3",
                        )}
                      >
                        leaf {formatRemainingSecs(peer.leaf_remaining_secs)}
                      </span>
                    </Hint>
                  )}
                </div>
              );
            })
          )}
        </SectionPanel>
      )}
    </>
  );
}
