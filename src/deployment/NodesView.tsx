import type { LogLine, NodeInfo } from "../api";
import NodeDetail, { type DetailView } from "../components/NodeDetail";
import NodeOverview from "../components/NodeOverview";

/// 节点 (Nodes): the old Nodes face's whole operational value, embedded
/// unchanged — the card grid (start/stop intent, worst-of exception
/// badges) and the three-view detail page (status/config/logs). The
/// deployment context adds the cross-links (fleet rows and stream rows
/// open the node detail); the node cards themselves carry the per-node
/// truth they always did.
export default function NodesView({
  nodes,
  nodesLoaded,
  selectedNodeId,
  detailView,
  onDetailViewChange,
  onOpenNode,
  onBack,
  onChanged,
  onError,
  logs,
  logScope,
  onLogScopeChange,
  onClearLogs,
}: {
  nodes: NodeInfo[];
  nodesLoaded: boolean;
  selectedNodeId: string | null;
  detailView: DetailView;
  onDetailViewChange: (view: DetailView) => void;
  onOpenNode: (id: string) => void;
  onBack: () => void;
  onChanged: () => Promise<void>;
  onError: (message: string) => void;
  logs: LogLine[];
  logScope: "node" | "machine";
  onLogScopeChange: (scope: "node" | "machine") => void;
  onClearLogs: () => void;
}) {
  const selected = nodes.find((n) => n.id === selectedNodeId) ?? null;
  return selected ? (
    <NodeDetail
      node={selected}
      view={detailView}
      onViewChange={onDetailViewChange}
      onBack={onBack}
      onChanged={onChanged}
      onError={onError}
      logs={logs}
      logScope={logScope}
      onLogScopeChange={onLogScopeChange}
      onClearLogs={onClearLogs}
    />
  ) : (
    <NodeOverview
      nodes={nodes}
      loaded={nodesLoaded}
      onChanged={onChanged}
      onError={onError}
      onOpen={onOpenNode}
    />
  );
}
