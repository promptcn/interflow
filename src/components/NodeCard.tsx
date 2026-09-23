import { isRunning, stateText, type NodeInfo } from "../api";
import { KindBadge, StateDot } from "./ui";

/// Short state label for the card footer — `stateText` in full (Failed
/// carries the whole error) belongs in the detail page; the card shows the
/// word, the tooltip carries the rest.
function shortState(node: NodeInfo): string {
  const state = node.state;
  if (typeof state === "object" && state !== null) {
    if (state.Connected) return "Connected";
    if (state.Reconnecting) return "Reconnecting";
    if (state.Failed) return "Failed";
  }
  return stateText(state).replace(/…$/, "");
}

/// The one-line "what this node points at" summary — the card's reason to
/// exist. Kind-specific because the four roles answer different questions:
/// expose → where each service is reached, mesh → how many rules it carries,
/// hub/ingress → where it listens. Everything shown is effective truth
/// (override applied), matching the start log's vocabulary.
function summaryLines(node: NodeInfo): { text: string; title?: string }[] {
  switch (node.kind) {
    case "expose_agent":
      return (node.services ?? []).map((service) => ({
        text: `${service.id} → ${service.effective_address}${service.overridden ? " ✱" : ""}`,
        // Data, not explanation: the pack default the ✱ line overrides.
        title: service.overridden ? `Pack default: ${service.default_address}` : undefined,
      }));
    case "mesh_agent": {
      const inCount = node.mesh_ingress_rules.length;
      const outCount = node.mesh_egress_rules.length;
      return [{ text: `${inCount} ingress · ${outCount} egress` }];
    }
    case "hub":
    case "ingress":
      return [{ text: `Listens on ${node.listen ?? "—"}` }];
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
  const summary = summaryLines(node);

  return (
    <div
      className={`node-card ${failed ? "failed" : ""}`}
      role="button"
      tabIndex={0}
      title={node.principal ?? node.pack_dir}
      onClick={onOpen}
      onKeyDown={(e) => {
        if (e.key === "Enter") onOpen();
      }}
    >
      <div className="node-card-head">
        <StateDot state={node.state} />
        <strong className="node-card-name">{node.name}</strong>
        <KindBadge kind={node.kind} />
      </div>
      <div className="node-card-summary">
        {summary.length === 0 && <span className="hint">—</span>}
        {summary.map((line) => (
          <div className="node-card-line" key={line.text} title={line.title}>
            {line.text}
          </div>
        ))}
      </div>
      <div className="node-card-foot">
        <span className="node-card-state" title={stateText(node.state)}>
          {shortState(node)}
        </span>
        {node.desired_running && <span className="node-card-tag">auto-start</span>}
        {node.generation > 0 && <span className="node-card-tag">gen {node.generation}</span>}
        <button
          className={running ? "" : "primary"}
          disabled={node.state === "Starting" || node.state === "Stopping"}
          onClick={(e) => {
            e.stopPropagation();
            onQuickAction();
          }}
        >
          {running ? "Stop" : "Start"}
        </button>
      </div>
    </div>
  );
}
