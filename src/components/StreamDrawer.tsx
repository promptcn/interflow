import { useT } from "../i18n";
import type { FleetDto, StreamDto } from "../api";
import {
  idleTimeoutDefault,
  streamStatusKey,
  streamStatusWordKey,
  targetLocalNodeId,
} from "../lib/streamFaces";
import { cn } from "../lib/utils";
import { Badge, Button, DialogFooter, Drawer, InfoRow, StatusKeyDot, statusTextClass } from "./ui";
import { DialogTitle } from "./ui/dialog";

/// The stream's whole story (2026-10-16 streams row language): the table
/// row carries the scan-level truth — status, identity, one weighted
/// route line — and everything the row cannot afford lives here, one
/// click away: the semantics sentence with real values, declared vs
/// actually-bound listen, the idle budget and its default, the down
/// reason, the catching-up generations, and BOTH endpoint cross-links
/// (dead-end #10's "jump to both machines"). The wizard (StreamDialog)
/// is this sheet's editing twin; the two share the Drawer form.
export default function StreamDrawer({
  stream,
  fleet,
  busy,
  onAdjust,
  onRename,
  onDelete,
  onOpenNode,
  onClose,
}: {
  stream: StreamDto;
  fleet: FleetDto;
  busy: boolean;
  onAdjust: () => void;
  onRename: () => void;
  onDelete: () => void;
  onOpenNode: (id: string) => void;
  onClose: () => void;
}) {
  const { t } = useT();
  const key = streamStatusKey(stream.status);
  const targetId = targetLocalNodeId(fleet, stream.target_agent);
  const idle = stream.idle_timeout_secs ?? idleTimeoutDefault(stream.protocol);
  // The status line's generation context: serving (with floor as the
  // fallback) is exactly the watermark the CatchingUp verdict compared.
  const hub = fleet.hub;
  const serving = hub !== null ? (hub.serving ?? hub.floor) : null;

  return (
    <Drawer onClose={onClose}>
      <DialogTitle>
        <span className="font-mono">{stream.name}</span>
      </DialogTitle>
      <p className="m-0 flex flex-wrap items-center gap-1.5">
        <StatusKeyDot status={key} />
        <span
          className={cn(
            "text-small font-medium transition-colors duration-200",
            key === null ? "text-fg-3" : statusTextClass[key],
          )}
        >
          {t(streamStatusWordKey[stream.status])}
        </span>
        {stream.status === "catching_up" && hub !== null && serving !== null && (
          <span className="font-mono text-small text-fg-3">
            {t("dep.streams.drawer.gen", { floor: hub.floor, serving })}
          </span>
        )}
      </p>
      <p className="m-0 text-small text-fg-3">
        {t("dep.streams.drawer.semantics", {
          agent: stream.agent,
          listen: stream.listen,
          target: stream.target_agent,
          remote: stream.remote_addr,
        })}
      </p>
      <div className="flex flex-col gap-2">
        <InfoRow label={t("dep.streams.drawer.source")}>
          {stream.source_node_id ? (
            <Button
              size="sm"
              variant="link"
              title={t("dep.streams.openSourceNode")}
              onClick={() => onOpenNode(stream.source_node_id!)}
            >
              {stream.agent}
            </Button>
          ) : (
            <span className="font-mono text-small text-fg-2">{stream.agent}</span>
          )}
        </InfoRow>
        <InfoRow label={t("dep.streams.drawer.listen")}>
          <span className="flex min-w-0 flex-col">
            <span className="font-mono text-small text-fg-1">{stream.listen}</span>
            {stream.bound_addr !== null && stream.bound_addr !== stream.listen && (
              <span className="font-mono text-small text-fg-2">
                {t("dep.streams.drawer.bound")}: {stream.bound_addr}
              </span>
            )}
          </span>
        </InfoRow>
        <InfoRow label={t("dep.streams.drawer.target")}>
          {targetId !== null ? (
            <Button
              size="sm"
              variant="link"
              title={t("dep.streams.openTargetNode")}
              onClick={() => onOpenNode(targetId)}
            >
              {stream.target_agent}
            </Button>
          ) : (
            <span className="font-mono text-small text-fg-2">{stream.target_agent}</span>
          )}
        </InfoRow>
        <InfoRow label={t("stream.remote")}>
          <span className="font-mono text-small text-fg-1">{stream.remote_addr}</span>
        </InfoRow>
        <InfoRow label={t("stream.protocol")}>
          <Badge tone="neutral" className="uppercase">
            {stream.protocol}
          </Badge>
        </InfoRow>
        <InfoRow label={t("dep.streams.drawer.idle")}>
          <span className="min-w-0 flex-1">
            <span className="font-mono text-small text-fg-1">{idle}s</span>
            {stream.idle_timeout_secs === null && (
              <span className="ml-1.5 text-small text-fg-3">
                {t("dep.streams.drawer.idleDefault")}
              </span>
            )}
          </span>
        </InfoRow>
        {stream.last_error !== null && (
          <InfoRow label={t("dep.streams.drawer.error")}>
            <span className="whitespace-pre-wrap font-mono text-small text-critical">
              {stream.last_error}
            </span>
          </InfoRow>
        )}
      </div>
      <DialogFooter>
        <Button size="sm" disabled={busy} onClick={onAdjust}>
          {t("dep.streams.adjust")}
        </Button>
        <Button variant="secondary" size="sm" disabled={busy} onClick={onRename}>
          {t("dep.streams.rename")}
        </Button>
        <Button variant="danger" size="sm" disabled={busy} onClick={onDelete}>
          {t("dep.streams.delete")}
        </Button>
      </DialogFooter>
    </Drawer>
  );
}
