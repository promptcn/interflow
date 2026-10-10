import { useEffect, useMemo, useState } from "react";
import { writeText } from "@tauri-apps/plugin-clipboard-manager";
import {
  api,
  onLogLine,
  onMeshListeners,
  onMeshPeers,
  onMeshProposals,
  onNodeState,
  onPolicyPlane,
  type LogLine,
  type NodeInfo,
  type NodeStateDto,
  type VersionInfo,
} from "./api";
import DeployFace, { type DeployView } from "./components/DeployFace";
import NodeDetail, { type DetailView } from "./components/NodeDetail";
import NodeOverview from "./components/NodeOverview";
import { Button, SegmentedControl, ToastProvider, TooltipProvider, useToast } from "./components/ui";
import { useT } from "./i18n";

const MAX_LOG_LINES = 2000;

/// Two-layer information architecture: each face lands on an overview (the
/// cards — "what exists and how is it"), and one level down a full-width
/// detail page carries editing, pack-signed truth, and logs. `null` means
/// overview; Esc climbs one level back up — inside the detail page first
/// to the Status view, then to the overview (never while typing, never
/// while a dialog owns the Escape key).
export default function App() {
  return (
    <ToastProvider>
      <TooltipProvider>
        <AppShell />
      </TooltipProvider>
    </ToastProvider>
  );
}

function AppShell() {
  const [nodes, setNodes] = useState<NodeInfo[]>([]);
  const [selectedNodeId, setSelectedNodeId] = useState<string | null>(null);
  // Detail-page view (status/config/logs) — like deployView, navigation
  // state lives in App so Esc climbs coherently and face switches stay
  // consistent.
  const [detailView, setDetailView] = useState<DetailView>("status");
  const [logs, setLogs] = useState<LogLine[]>([]);
  // In the node detail page: show its logs only, or everything on this
  // machine (the GUI itself included).
  const [allLogs, setAllLogs] = useState(false);
  const [nodesLoaded, setNodesLoaded] = useState(false);
  const [hostName, setHostName] = useState<string | null>(null);
  // Compile-time build identity — fetched once; never changes at runtime.
  const [versionInfo, setVersionInfo] = useState<VersionInfo | null>(null);
  // Operator face: deploy (issue packs) vs nodes (run them). Both faces
  // stay mounted and merely hide — switching faces preserves editor and
  // navigation state.
  const [face, setFace] = useState<"nodes" | "deploy">("nodes");
  const [deployView, setDeployView] = useState<DeployView>("overview");
  const [selectedPackDir, setSelectedPackDir] = useState<string | null>(null);
  // The one interruption channel: GUI errors surface here (dismissable)
  // instead of as permanent furniture. The log buffer keeps the history.
  const [guiError, setGuiError] = useState<string | null>(null);
  const toast = useToast();
  const { lang, setLang, t } = useT();

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
      // Policy telemetry advances inside a running mesh agent with no user
      // action near it — the engine pushes each changed snapshot, so the
      // health panel tracks the live watermark and pull health instead of
      // freezing on whatever listNodes returned at node start
      onPolicyPlane((id, plane) => {
        setNodes((prev) => prev.map((n) => (n.id === id ? { ...n, policy: plane } : n)));
      }),
      // Peer telemetry advances the same way (the engine's peer watcher
      // publishes each changed snapshot) — the Peers section tracks live
      // presence instead of freezing on its start-time reading.
      onMeshPeers((id, peers) => {
        setNodes((prev) => prev.map((n) => (n.id === id ? { ...n, peers } : n)));
      }),
      // Proposal receipts advance the same way (the engine's receipts
      // watcher publishes each changed list).
      onMeshProposals((id, proposals) => {
        setNodes((prev) => prev.map((n) => (n.id === id ? { ...n, proposals } : n)));
      }),
      // Ingress-listener actual state advances the same way (the engine's
      // reconciler records every bind/failure) — a mid-flight bind failure
      // surfaces on the card immediately, not at the next listNodes (the
      // 2026-10-09 honesty axis).
      onMeshListeners((id, listeners) => {
        setNodes((prev) => prev.map((n) => (n.id === id ? { ...n, listeners } : n)));
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
      toast.push(t("common.copied"));
    } catch {
      // Clipboard denied — the chip text stays selectable for manual copy.
    }
  };

  // Esc climbs one level (detail view → status, detail → overview, pack
  // detail → grid, manifest → packs) — but never steals the key from a
  // text field, and defers to an open dialog (Radix closes the dialog
  // itself).
  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if (e.key !== "Escape") return;
      if (document.querySelector('[role="dialog"]')) return;
      const target = e.target as HTMLElement | null;
      if (
        target &&
        (target.tagName === "INPUT" || target.tagName === "TEXTAREA" || target.isContentEditable)
      ) {
        return;
      }
      if (face === "nodes" && selectedNodeId !== null) {
        if (detailView !== "status") setDetailView("status");
        else setSelectedNodeId(null);
      } else if (face === "deploy") {
        if (selectedPackDir !== null) setSelectedPackDir(null);
        else if (deployView !== "overview") setDeployView("overview");
      }
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [face, selectedNodeId, detailView, selectedPackDir, deployView]);

  const selected = nodes.find((n) => n.id === selectedNodeId) ?? null;

  // Opening a node always lands on the Status view — the monitoring view
  // is never polluted by where the previous visit ended up.
  const openNode = (id: string) => {
    setDetailView("status");
    setSelectedNodeId(id);
  };

  // Per-node log attribution: lines carry the engine's `node` field, which
  // the backend sets to the node's unique attribution value (name + id
  // prefix) — same-name nodes in different realms stay separable. "This
  // machine" shows everything.
  const visibleLogs = useMemo(() => {
    if (!selected || allLogs) return logs;
    return logs.filter((l) => l.node === selected.attribution);
  }, [logs, selected, allLogs]);

  return (
    <div className="flex h-screen flex-col bg-bg-1 text-fg-1">
      <header className="flex items-baseline gap-2 px-4 pt-2.5 text-base">
        <span className="font-semibold tracking-tight">Interflow</span>
        {hostName && <span className="font-mono text-small text-fg-3">— {hostName}</span>}
        <SegmentedControl
          className="ml-auto"
          value={face}
          options={[
            { value: "nodes", label: t("app.nodes") },
            { value: "deploy", label: t("app.deploy") },
          ]}
          onChange={setFace}
        />
        {versionInfo && (
          <Button
            variant="link"
            title={versionInfo.dirty ? t("app.versionDirtyTitle") : t("app.versionTitle")}
            onClick={copyVersion}
            className={
              versionInfo.dirty
                ? "font-mono text-small text-warn opacity-100"
                : "font-mono text-small text-fg-3"
            }
          >
            {`v${versionInfo.version} · ${versionInfo.build_tag}`}
          </Button>
        )}
        {/* Self-naming options: each label in its own language, so the
            switch reads the same in either UI language. */}
        <SegmentedControl
          className="ml-2.5"
          value={lang}
          options={[
            { value: "en", label: "EN" },
            { value: "zh", label: "中文" },
          ]}
          onChange={setLang}
        />
      </header>

      {guiError && (
        <div
          role="alert"
          className="mx-4 mt-2 flex items-baseline gap-3 rounded-lg border border-critical/45 bg-critical/10 px-3 py-2 text-base text-critical"
        >
          <span className="min-w-0 flex-1 break-words">{guiError}</span>
          <Button variant="link" size="sm" onClick={() => setGuiError(null)}>
            {t("app.dismiss")}
          </Button>
        </div>
      )}

      <main className="flex min-h-0 flex-1 px-4 pt-3 pb-4">
        <div className="flex min-h-0 min-w-0 flex-1 flex-col gap-3">
          <div className={face === "nodes" ? "flex min-h-0 min-w-0 flex-1 flex-col gap-3" : "hidden"}>
            {selected ? (
              <NodeDetail
                node={selected}
                view={detailView}
                onViewChange={setDetailView}
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
                onOpen={openNode}
              />
            )}
          </div>
          <div className={face === "deploy" ? "flex min-h-0 min-w-0 flex-1 flex-col gap-3" : "hidden"}>
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
      </main>
    </div>
  );
}
