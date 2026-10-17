import { useEffect } from "react";
import {
  formatAgoSecs,
  formatRemainingSecs,
  leafPhase,
  type NodeInfo,
} from "../api";
import { useT } from "../i18n";
import { cn } from "../lib/utils";
import { Button, EmptyState, Hint, PeerDot, SectionPanel } from "../components/ui";
import { useDeployment } from "./DeploymentContext";
import {
  buildDeploymentRows,
  buildRealmRows,
  realmObservers,
  type FleetRow,
} from "../lib/fleetRows";

/// 编队 (ex-Peers, 2026-10-15 re-axis): the realm's whole fleet — who is
/// online, at which generation, how long their leaves last. Presence is
/// a property of the REALM, not of this machine's eyes: under a
/// deployment the hub's report is authoritative (one merged table; the
/// local peers planes only donate leaf countdowns), and when the hub is
/// unreachable the page degrades WHOLE to this machine's observation
/// with the source and freshness stated. Under a 🔒 realm (no control
/// credential exists) local observation IS the source, labeled as such.
/// The 2026-10-12 ruling stands: still its own page, never buried in a
/// node detail.
export default function FleetView({
  realm,
  nodes,
  onOpenNode,
}: {
  /// null = the deployment scope (the hub's report via the composed
  /// fleet); a realm name = the 🔒 read-only scope (local observation).
  realm: string | null;
  nodes: NodeInfo[];
  onOpenNode: (id: string) => void;
}) {
  const { t } = useT();
  const dep = useDeployment();

  // The hub's overview is pull-only (no push event) — keep it fresh
  // while the page is open under a deployment.
  useEffect(() => {
    if (realm !== null || dep.deployment === null) return;
    const timer = setInterval(() => void dep.refresh(true), 30_000);
    return () => clearInterval(timer);
  }, [realm, dep.deployment, dep.refresh]);

  if (realm !== null) {
    return <RealmFleet realm={realm} nodes={nodes} onOpenNode={onOpenNode} />;
  }

  if (dep.fleet === null) {
    // Still opening (busy) vs failed to compose (the shell's error banner
    // carries the reason) — two different silences.
    return dep.busy ? (
      <div className="flex flex-1 items-center justify-center text-small text-fg-3">…</div>
    ) : (
      <EmptyState>{t("fleet.unavailable")}</EmptyState>
    );
  }

  if (dep.fleet.hub === null) {
    // Degraded: the hub did not answer — the page says so and falls
    // back to this machine's observation, freshness stated per observer.
    const obs = realmObservers(nodes, dep.fleet.summary.realm.id);
    return (
      <div className="flex min-h-0 flex-1 flex-col gap-3 overflow-y-auto">
        <div className="flex items-center gap-2 rounded-lg border border-warn/45 bg-warn/10 px-3 py-2 text-small text-warn">
          {t("fleet.degraded")}
        </div>
        {obs.length === 0 ? (
          <EmptyState>{t("fleet.none")}</EmptyState>
        ) : (
          obs.map(({ node, plane }) => (
            <ObserverPanel key={node.id} node={node} plane={plane} onOpenNode={onOpenNode} t={t} />
          ))
        )}
      </div>
    );
  }

  const { rows, floorServing } = buildDeploymentRows(dep.fleet, nodes, Date.now() / 1000);
  return (
    <div className="flex min-h-0 flex-1 flex-col gap-3 overflow-y-auto">
      {floorServing !== null && <LineageStrip floor={floorServing.floor} serving={floorServing.serving} t={t} />}
      <SectionPanel title={dep.fleet.summary.realm.id} hint={t("fleet.hubReported")} grow>
        <div className="flex flex-col gap-1.5">
          {byPresence(rows).map((row) => (
            <FleetRowLine key={row.key} row={row} onOpenNode={onOpenNode} t={t} />
          ))}
        </div>
      </SectionPanel>
    </div>
  );
}

/// The 🔒 realm scope: local observation is the source (no control
/// credential exists to ask the hub directly) — stated once at the top,
/// freshness of the freshest observer beside it.
function RealmFleet({
  realm,
  nodes,
  onOpenNode,
}: {
  realm: string;
  nodes: NodeInfo[];
  onOpenNode: (id: string) => void;
}) {
  const { t } = useT();
  const rows = buildRealmRows(realm, nodes, Date.now() / 1000);
  if (rows.length === 0) {
    return <EmptyState>{t("fleet.none")}</EmptyState>;
  }
  const freshest = Math.max(
    0,
    ...realmObservers(nodes, realm).map((o) => o.plane.last_ok_unix),
  );
  return (
    <div className="flex min-h-0 flex-1 flex-col gap-3 overflow-y-auto">
      <SectionPanel
        title={realm}
        hint={
          freshest > 0
            ? t("fleet.observedAt", { ago: formatAgoSecs(freshest) })
            : t("fleet.observed")
        }
        grow
      >
        <div className="flex flex-col gap-1.5">
          {byPresence(rows).map((row) => (
            <FleetRowLine key={row.key} row={row} onOpenNode={onOpenNode} t={t} />
          ))}
        </div>
      </SectionPanel>
    </div>
  );
}

/// The 2026-10-16 ruling: online rows lead, offline and unknown follow
/// ("不在线的在下") — a stable two-segment partition ONLY, so the merge
/// order's structure (hub anchors first, declared before strays) stays
/// intact inside each segment. Render-layer concern on purpose: the row
/// model stays a pure merge.
function byPresence<T extends { online: boolean | null }>(rows: T[]): T[] {
  return [
    ...rows.filter((r) => r.online === true),
    ...rows.filter((r) => r.online !== true),
  ];
}

/// The hub's floor/serving strip — the generation the fleet converges
/// toward; a serving behind the floor is the lineage-stale signature.
function LineageStrip({
  floor,
  serving,
  t,
}: {
  floor: number;
  serving: number | null;
  t: ReturnType<typeof useT>["t"];
}) {
  const stale = serving !== null && serving < floor;
  return (
    <div className="flex items-center gap-2 px-1 text-small text-fg-3">
      <span className="font-mono">floor {floor}</span>
      <span>·</span>
      <span className="font-mono">serving {serving ?? "—"}</span>
      {stale && (
        <Hint text={t("fleet.lineageStaleHint")}>
          <span className="text-warn">⚠ {t("fleet.lineageStale")}</span>
        </Hint>
      )}
    </div>
  );
}

/// The degraded form's per-observer panel — the pre-re-axis Peers page's
/// rendering, unchanged in shape (one panel per running mesh agent, its
/// own tenant view), now scoped to the realm and stated as a fallback.
/// The 2026-10-16 status language applies here too: the online word
/// drops to sr-only, offline names dim, online rows lead.
function ObserverPanel({
  node,
  plane,
  onOpenNode,
  t,
}: {
  node: NodeInfo;
  plane: NonNullable<NodeInfo["peers"]>;
  onOpenNode: (id: string) => void;
  t: ReturnType<typeof useT>["t"];
}) {
  return (
    <SectionPanel
      title={node.name}
      hint={
        plane.last_ok_unix > 0
          ? t("nodeDetail.peersUpdated", { ago: formatAgoSecs(plane.last_ok_unix) })
          : undefined
      }
      actions={
        <Button variant="link" size="sm" onClick={() => onOpenNode(node.id)}>
          {t("fleet.openNode")}
        </Button>
      }
    >
      {plane.peers.length === 0 ? (
        <span className="text-small text-fg-3">{t("nodeDetail.peersNone")}</span>
      ) : (
        byPresence(plane.peers).map((peer) => {
          const shortName = peer.agent.split("/").pop() ?? peer.agent;
          const leaf = peer.leaf_phase ? leafPhase({ phase: peer.leaf_phase }) : null;
          return (
            <div key={peer.agent} className="flex flex-wrap items-center gap-2.5 text-base">
              <PeerDot online={peer.online} />
              <Hint text={peer.agent}>
                <span className={cn("font-mono text-small", !peer.online && "text-fg-3")}>
                  {shortName}
                </span>
              </Hint>
              {peer.online ? (
                <span className="sr-only">{t("nodeDetail.peerOnline")}</span>
              ) : (
                <span className="text-small text-fg-3">{t("nodeDetail.peerOffline")}</span>
              )}
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
  );
}

/// One merged row. The 2026-10-16 status language: the green dot alone
/// says online (the word drops to sr-only — color is never the only
/// signal, but the word was redundant next to it), offline and unknown
/// keep their words (the hollow and gray dots sit close; text is their
/// second channel), and an offline row dims its name — row-level
/// light/dark as the second channel.
function FleetRowLine({
  row,
  onOpenNode,
  t,
}: {
  row: FleetRow;
  onOpenNode: (id: string) => void;
  t: ReturnType<typeof useT>["t"];
}) {
  const leaf = row.leaf?.phase ? leafPhase({ phase: row.leaf.phase }) : null;
  return (
    <div className="flex flex-wrap items-center gap-2.5 text-base">
      <PeerDot online={row.online} />
      <Hint text={row.key}>
        <span
          className={cn("font-mono text-small font-medium", row.online === false && "text-fg-3")}
        >
          {row.name}
        </span>
      </Hint>
      {row.online === true ? (
        <span className="sr-only">{t("nodeDetail.peerOnline")}</span>
      ) : (
        <span className="text-small text-fg-3">
          {row.online === null ? t("fleet.unknown") : t("nodeDetail.peerOffline")}
        </span>
      )}
      {row.gen !== null && (
        <span className="font-mono text-small text-fg-3">gen {row.gen}</span>
      )}
      {row.leaf?.phase && (
        <Hint text={t("nodeDetail.peerLeafTitle")}>
          <span
            className={cn(
              "text-small",
              leaf === "warn" && "text-warn",
              leaf === "critical" && "text-critical",
              leaf === null && "text-fg-3",
            )}
          >
            leaf {formatRemainingSecs(row.leaf.remaining_secs)}
          </span>
        </Hint>
      )}
      {!row.declared && (
        <Hint text={t("fleet.undeclaredHint")}>
          <span className="rounded border border-line px-1.5 py-0.5 text-micro text-fg-3">
            {t("fleet.undeclared")}
          </span>
        </Hint>
      )}
      {row.localNodeId !== null && (
        <Button
          variant="link"
          size="sm"
          className="ml-auto"
          onClick={() => onOpenNode(row.localNodeId as string)}
        >
          {t("fleet.localNode")}
        </Button>
      )}
    </div>
  );
}
