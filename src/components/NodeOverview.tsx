import { useState } from "react";
import { api, isRunning, type NodeInfo } from "../api";
import AddNodeDialog from "./AddNodeDialog";
import NodeCard from "./NodeCard";

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

  const quickAction = async (node: NodeInfo) => {
    try {
      if (isRunning(node.state)) {
        await api.stopNode(node.id);
      } else {
        await api.startNode(node.id);
      }
      await onChanged();
    } catch (e) {
      onError(`${isRunning(node.state) ? "Stop" : "Start"} ${node.name} failed: ${e}`);
    }
  };

  // Aggregate line parts, non-zero only — silence when everything is fine.
  const runningCount = nodes.filter((n) => isRunning(n.state)).length;
  const failedCount = nodes.filter(
    (n) => typeof n.state === "object" && n.state !== null && "Failed" in n.state,
  ).length;
  const stoppedCount = nodes.length - runningCount - failedCount;
  const aggregate = [
    runningCount > 0 && `${runningCount} running`,
    stoppedCount > 0 && `${stoppedCount} stopped`,
    failedCount > 0 && `${failedCount} failed`,
  ]
    .filter(Boolean)
    .join(" · ");

  return (
    <div className="overview">
      {nodes.length > 0 ? (
        <div className="overview-status hint">{aggregate}</div>
      ) : (
        loaded && <div className="overview-status hint">no nodes yet</div>
      )}

      <div className="card-grid">
        {nodes.map((node) => (
          <NodeCard
            key={node.id}
            node={node}
            onOpen={() => onOpen(node.id)}
            onQuickAction={() => void quickAction(node)}
          />
        ))}
        <button className="add-card" onClick={() => setAdding(true)}>
          + Add node
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
