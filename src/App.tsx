import { useEffect, useMemo, useState } from "react";
import { writeText } from "@tauri-apps/plugin-clipboard-manager";
import {
  api,
  onLogLine,
  onNodeState,
  type LogLine,
  type NodeInfo,
  type NodeStateDto,
  type VersionInfo,
} from "./api";
import DeployFace, { type DeployView } from "./components/DeployFace";
import NodeDetail from "./components/NodeDetail";
import NodeOverview from "./components/NodeOverview";

const MAX_LOG_LINES = 2000;

/// Two-layer information architecture: each face lands on an overview (the
/// cards — "what exists and how is it"), and one level down a full-width
/// detail page carries editing, pack-signed truth, and logs. `null` means
/// overview; Esc climbs one level back up (never while typing).
export default function App() {
  const [nodes, setNodes] = useState<NodeInfo[]>([]);
  const [selectedNodeId, setSelectedNodeId] = useState<string | null>(null);
  const [logs, setLogs] = useState<LogLine[]>([]);
  // In the node detail page: show its logs only, or everything on this
  // machine (the GUI itself included).
  const [allLogs, setAllLogs] = useState(false);
  const [nodesLoaded, setNodesLoaded] = useState(false);
  const [hostName, setHostName] = useState<string | null>(null);
  // Compile-time build identity — fetched once; never changes at runtime.
  const [versionInfo, setVersionInfo] = useState<VersionInfo | null>(null);
  // Transient "copied ✓" feedback on the header identity chip.
  const [versionCopied, setVersionCopied] = useState(false);
  // Operator face: deploy (issue packs) vs nodes (run them). Both faces
  // stay mounted and merely hide — switching faces preserves editor and
  // navigation state.
  const [face, setFace] = useState<"nodes" | "deploy">("nodes");
  const [deployView, setDeployView] = useState<DeployView>("packs");
  const [selectedPackDir, setSelectedPackDir] = useState<string | null>(null);
  // The one interruption channel: GUI errors surface here (dismissable)
  // instead of as permanent furniture. The log buffer keeps the history.
  const [guiError, setGuiError] = useState<string | null>(null);

  const reportError = (message: string) => {
    setGuiError(message);
    setLogs((prev) => [
      ...prev,
      { ts: new Date().toISOString(), level: "ERROR", target: "gui", message, node: null },
    ]);
  };

  const refreshNodes = async () => {
    try {
      setNodes(await api.listNodes());
    } catch (e) {
      console.error("Failed to list nodes:", e);
    }
  };

  useEffect(() => {
    (async () => {
      try {
        setNodes(await api.listNodes());
      } finally {
        setNodesLoaded(true);
      }
      setLogs(await api.getRecentLogs());
      try {
        setHostName(await api.getHostName());
      } catch (e) {
        console.error("Failed to get hostname:", e);
      }
      try {
        setVersionInfo(await api.getVersionInfo());
      } catch (e) {
        console.error("Failed to get version info:", e);
      }
    })();

    const unsubs = [
      // State events patch the matching card; anything else (e.g. an add in
      // another window) is covered by the refresh calls after mutations.
      onNodeState((id, state) => {
        setNodes((prev) =>
          prev.map((n) => (n.id === id ? { ...n, state: state as NodeStateDto } : n))
        );
      }),
      onLogLine((line) =>
        setLogs((prev) => {
          const next = [...prev, line];
          return next.length > MAX_LOG_LINES ? next.slice(next.length - MAX_LOG_LINES) : next;
        })
      ),
    ];
    return () => {
      unsubs.forEach((u) => u.then((f) => f()));
    };
  }, []);

  // "Which build is that machine running" rounds end in a pasted string:
  // one click copies the canonical identity (same form the CLI prints).
  const copyVersion = async () => {
    if (!versionInfo) return;
    try {
      await writeText(`Interflow v${versionInfo.version} (${versionInfo.build_tag})`);
      setVersionCopied(true);
      setTimeout(() => setVersionCopied(false), 1500);
    } catch {
      // Clipboard denied — the chip text stays selectable for manual copy.
    }
  };

  // Esc climbs one level (detail → overview, pack detail → grid, manifest →
  // packs) — but never steals the key from a text field.
  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if (e.key !== "Escape") return;
      const target = e.target as HTMLElement | null;
      if (
        target &&
        (target.tagName === "INPUT" || target.tagName === "TEXTAREA" || target.isContentEditable)
      ) {
        return;
      }
      if (face === "nodes" && selectedNodeId !== null) setSelectedNodeId(null);
      else if (face === "deploy") {
        if (selectedPackDir !== null) setSelectedPackDir(null);
        else if (deployView === "manifest") setDeployView("packs");
      }
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [face, selectedNodeId, selectedPackDir, deployView]);

  const selected = nodes.find((n) => n.id === selectedNodeId) ?? null;

  // Per-node log attribution: lines carry the engine's `node` field, which
  // the backend sets to the node's unique attribution value (name + id
  // prefix) — same-name nodes in different realms stay separable. "This
  // machine" shows everything.
  const visibleLogs = useMemo(() => {
    if (!selected || allLogs) return logs;
    return logs.filter((l) => l.node === selected.attribution);
  }, [logs, selected, allLogs]);

  return (
    <div className="app-frame">
      <header className="machine-header">
        <span className="machine-title">Interflow</span>
        {hostName && <span className="machine-host">— {hostName}</span>}
        <span className="face-toggle">
          <button
            className={face === "nodes" ? "selected" : ""}
            onClick={() => setFace("nodes")}
          >
            Nodes
          </button>
          <button
            className={face === "deploy" ? "selected" : ""}
            onClick={() => setFace("deploy")}
          >
            Deploy
          </button>
        </span>
        {versionInfo && (
          <button
            className={`machine-version${versionInfo.dirty ? " dirty" : ""}`}
            title={
              versionInfo.dirty
                ? "Built from uncommitted local changes — treat as the builder's, not the commit's. Click to copy the build identity"
                : "Click to copy the build identity"
            }
            onClick={copyVersion}
          >
            {versionCopied
              ? "copied ✓"
              : `v${versionInfo.version} · ${versionInfo.build_tag}`}
          </button>
        )}
      </header>

      {guiError && (
        <div className="error-banner" role="alert">
          <span>{guiError}</span>
          <button className="link" onClick={() => setGuiError(null)}>
            dismiss
          </button>
        </div>
      )}

      <div className="app">
        <div className={`face${face === "nodes" ? "" : " hidden"}`}>
          {selected ? (
            <NodeDetail
              node={selected}
              onBack={() => setSelectedNodeId(null)}
              onChanged={refreshNodes}
              onError={reportError}
              logs={visibleLogs}
              logScope={allLogs ? "machine" : "node"}
              onLogScopeChange={(scope) => setAllLogs(scope === "machine")}
              onClearLogs={async () => {
                // View first (instant feedback), then the backend buffer it
                // replays from on reload — the other order would let cleared
                // lines reappear after a webview reload.
                setLogs([]);
                try {
                  await api.clearLogs();
                } catch (e) {
                  console.error("Failed to clear logs:", e);
                }
              }}
            />
          ) : (
            <NodeOverview
              nodes={nodes}
              loaded={nodesLoaded}
              onChanged={refreshNodes}
              onError={reportError}
              onOpen={setSelectedNodeId}
            />
          )}
        </div>
        <div className={`face${face === "deploy" ? "" : " hidden"}`}>
          <DeployFace
            view={deployView}
            selectedPack={selectedPackDir}
            onViewChange={setDeployView}
            onSelectPack={setSelectedPackDir}
            onError={reportError}
            onNodesChanged={refreshNodes}
          />
        </div>
      </div>
    </div>
  );
}
