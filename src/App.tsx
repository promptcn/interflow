import { useEffect, useMemo, useRef, useState } from "react";
import { writeText } from "@tauri-apps/plugin-clipboard-manager";
import {
  ArrowLeftRight,
  ChevronsLeft,
  ChevronsRight,
  FileCog,
  Globe,
  LayoutDashboard,
  Server,
  Users,
} from "lucide-react";
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
import { type DetailView } from "./components/NodeDetail";
import {
  Button,
  Popover,
  PopoverContent,
  PopoverTrigger,
  SegmentedControl,
  ToastProvider,
  TooltipProvider,
  useToast,
} from "./components/ui";
import { useT } from "./i18n";
import { meshRealms, shellFace } from "./lib/shellFace";
import { hasFleetFace, hasServicesFace, hasStreamsFace } from "./lib/fleetRows";
import {
  DeploymentProvider,
  useDeployment,
} from "./deployment/DeploymentContext";
import ConflictDialog from "./deployment/ConflictDialog";
import DeploymentSwitcher from "./deployment/DeploymentSwitcher";
import StatusCluster from "./deployment/StatusCluster";
import Onboarding from "./deployment/Onboarding";
import OverviewView from "./deployment/OverviewView";
import StreamsView from "./deployment/StreamsView";
import ServicesView from "./deployment/ServicesView";
import NodesView from "./deployment/NodesView";
import AdvancedView from "./deployment/AdvancedView";
import FleetView from "./deployment/FleetView";

const MAX_LOG_LINES = 2000;

/// The sidebar's icons — one glyph each, stable across the
/// collapsed/expanded states.
const NAV_ICONS = {
  overview: LayoutDashboard,
  fleet: Users,
  streams: ArrowLeftRight,
  services: Globe,
  advanced: FileCog,
  local: Server,
} as const satisfies Record<View, typeof LayoutDashboard>;

/// The realm-axis shell (2026-10-15 nav re-axis): the deployment (realm)
/// is the OBJECT the sidebar is organized by — the switcher at the top
/// governs the whole nav, its body the scope's views (总览/编队/流/服务/
/// 高级 under a deployment, 编队 alone under a 🔒 realm inferred from
/// local packs). This machine is only the observation position, demoted
/// to a bottom entry (本机: every managed node on this machine,
/// cross-deployment, + machine-level logs) — always present, never
/// touched by the scope above it. Machines are not two classes: a
/// node-carrying machine without deployments gets the 本机 view as a
/// complete view, and the onboarding speaks only where there is nothing
/// else — zero deployments AND zero nodes. Node state, the event
/// bridges, and the log buffer live here exactly as before — the 本机
/// view and every cross-link consume them.
type View = "overview" | "fleet" | "streams" | "services" | "advanced" | "local";

/// Whether `view`'s nav item survives the opened deployment's shape —
/// the three face views check their predicate; the always-present views
/// (总览/高级/本机) are faceless and never bounce. The rebound guard's
/// one lookup, shared by all three faces (2026-10-15 for 编队,
/// 2026-10-16 for 服务/流).
function viewHasFace(
  view: View,
  summary: Parameters<typeof hasFleetFace>[0],
): boolean {
  switch (view) {
    case "fleet":
      return hasFleetFace(summary);
    case "streams":
      return hasStreamsFace(summary);
    case "services":
      return hasServicesFace(summary);
    default:
      return true;
  }
}

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
  return (
    <DeploymentProvider onError={(m) => console.error("deployment:", m)}>
      <Shell />
    </DeploymentProvider>
  );
}

function Shell() {
  const [nodes, setNodes] = useState<NodeInfo[]>([]);
  const [selectedNodeId, setSelectedNodeId] = useState<string | null>(null);
  const [detailView, setDetailView] = useState<DetailView>("status");
  const [logs, setLogs] = useState<LogLine[]>([]);
  const [allLogs, setAllLogs] = useState(false);
  const [nodesLoaded, setNodesLoaded] = useState(false);
  const [hostName, setHostName] = useState<string | null>(null);
  const [versionInfo, setVersionInfo] = useState<VersionInfo | null>(null);
  const [view, setView] = useState<View>("overview");
  const [sidebarCollapsed, setSidebarCollapsed] = useState(
    () => localStorage.getItem("interflow.sidebar-collapsed") === "1",
  );
  /// The 🔒 realm scope (mutually exclusive with an open deployment):
  /// read-only presence context for a machine whose packs name realms it
  /// has no deployment tree for. Remembered across restarts like the
  /// sidebar state — a leg machine relaunches into its realm.
  const [realmScope, setRealmScope] = useState<string | null>(null);
  const toggleSidebar = () =>
    setSidebarCollapsed((v) => {
      localStorage.setItem("interflow.sidebar-collapsed", v ? "0" : "1");
      return !v;
    });
  const [selectedPackPrincipal, setSelectedPackPrincipal] = useState<string | null>(null);
  const [guiError, setGuiError] = useState<string | null>(null);
  const toast = useToast();
  const { lang, setLang, t } = useT();
  const dep = useDeployment();

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
      onNodeState((id, state) => {
        setNodes((prev) =>
          prev.map((n) => (n.id === id ? { ...n, state: state as NodeStateDto } : n))
        );
      }),
      onPolicyPlane((id, plane) => {
        setNodes((prev) => prev.map((n) => (n.id === id ? { ...n, policy: plane } : n)));
      }),
      onMeshPeers((id, peers) => {
        setNodes((prev) => prev.map((n) => (n.id === id ? { ...n, peers } : n)));
      }),
      onMeshProposals((id, proposals) => {
        setNodes((prev) => prev.map((n) => (n.id === id ? { ...n, proposals } : n)));
      }),
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

  // Esc climbs one level: machine detail view → status, detail → grid,
  // pack detail → packs — never while typing, never past an open dialog.
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
      if (view === "local" && selectedNodeId !== null) {
        if (detailView !== "status") setDetailView("status");
        else setSelectedNodeId(null);
      } else if (view === "advanced" && selectedPackPrincipal !== null) {
        setSelectedPackPrincipal(null);
      }
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [view, selectedNodeId, detailView, selectedPackPrincipal]);

  /// The scope: an open deployment (writable) or a 🔒 realm (read-only)
  /// — the axis the whole sidebar hangs on. The 本机 entry lives outside
  /// it and stays reachable under any scope.
  const depOpen = dep.deployment !== null;
  const scopeOpen = depOpen || realmScope !== null;

  /// Launch restore, once: a remembered deployment wins (guiPrefs is the
  /// operator's authoritative memory); otherwise the remembered 🔒 realm
  /// comes back if this machine still carries its packs, and a machine
  /// with exactly ONE inferred realm selects it outright — a leg machine
  /// relaunches straight into its fleet, never a waiting room. Zero or
  /// several realms land on 本机 (no silent choice among many).
  const restoreTriedRef = useRef(false);
  useEffect(() => {
    if (restoreTriedRef.current || dep.loading || !nodesLoaded) return;
    restoreTriedRef.current = true;
    if (dep.deployment !== null) return;
    const realms = meshRealms(nodes);
    const remembered = localStorage.getItem("interflow.realm-scope");
    const pick =
      remembered !== null && realms.includes(remembered)
        ? remembered
        : realms.length === 1
          ? realms[0]
          : null;
    if (pick !== null) setRealmScope(pick);
  }, [dep.loading, dep.deployment, nodesLoaded, nodes]);

  /// The deployment-scope nav's shape follows the deployment's content
  /// — one visibility predicate per face: 编队 exists under a 🔒 realm
  /// always, under a deployment only when the manifest declares a hub
  /// or a mesh/mixed agent (the 2026-10-15 ruling); 服务 needs an
  /// expose/mixed agent (services can't be declared elsewhere) and 流
  /// needs a mesh/mixed agent (streams flow from mesh ingress) — the
  /// 2026-10-16 ruling completing the principle: a permanently-empty
  /// page only makes the user ask why it's there. A mixed deployment
  /// shows all three.
  const fleetNavVisible = realmScope !== null || (dep.fleet !== null && hasFleetFace(dep.fleet.summary));
  const streamsNavVisible = dep.fleet !== null && hasStreamsFace(dep.fleet.summary);
  const servicesNavVisible = dep.fleet !== null && hasServicesFace(dep.fleet.summary);

  const scopeNav: { value: View; label: string }[] =
    realmScope !== null
      ? [{ value: "fleet", label: t("dep.nav.fleet") }]
      : [
          { value: "overview", label: t("dep.nav.overview") },
          ...(fleetNavVisible ? [{ value: "fleet" as View, label: t("dep.nav.fleet") }] : []),
          ...(streamsNavVisible ? [{ value: "streams" as View, label: t("dep.nav.streams") }] : []),
          ...(servicesNavVisible ? [{ value: "services" as View, label: t("dep.nav.services") }] : []),
          { value: "advanced", label: t("dep.nav.advanced") },
        ];
  const nav = [...scopeNav, { value: "local" as View, label: t("dep.nav.local") }];

  /// A remembered view can't outlive its scope's shape: no scope → 本机;
  /// a 🔒 realm offers 编队 (and 本机); a deployment offers its views —
  /// each face view bounces to 总览 when the opened deployment turns
  /// out to lack that face (the items appear only after the summary
  /// loads, and this guard catches views remembered from the previous
  /// scope).
  useEffect(() => {
    if (!dep.loading && !scopeOpen && view !== "local") {
      setView("local");
    } else if (realmScope !== null && view !== "fleet" && view !== "local") {
      setView("fleet");
    } else if (
      depOpen &&
      !dep.busy &&
      dep.fleet !== null &&
      !viewHasFace(view, dep.fleet.summary)
    ) {
      setView("overview");
    }
  }, [dep.loading, dep.busy, dep.fleet, depOpen, realmScope, scopeOpen, view]);

  const copyVersion = async () => {
    if (!versionInfo) return;
    try {
      await writeText(`Interflow v${versionInfo.version} (${versionInfo.build_tag})`);
      toast.push(t("common.copied"));
    } catch {
      // Clipboard denied — the chip text stays selectable.
    }
  };

  /// Every cross-link lands here: fleet rows, stream rows, and the hub
  /// hint all open the node's detail page in place — inside the 本机
  /// entry, whatever scope is open above it.
  const openNode = (id: string) => {
    setDetailView("status");
    setSelectedNodeId(id);
    setView("local");
  };

  const selected = nodes.find((n) => n.id === selectedNodeId) ?? null;
  const visibleLogs = useMemo(() => {
    if (!selected || allLogs) return logs;
    return logs.filter((l) => l.node === selected.attribution);
  }, [logs, selected, allLogs]);

  const renderNavItem = (item: { value: View; label: string }) => {
    const Icon = NAV_ICONS[item.value];
    return (
      <button
        key={item.value}
        onClick={() => setView(item.value)}
        title={item.label}
        className={`flex min-h-control cursor-pointer items-center rounded-lg text-left text-base outline-none transition-colors duration-150 focus-visible:ring-[3px] focus-visible:ring-accent-tint ${
          sidebarCollapsed ? "justify-center px-0" : "px-2.5"
        } ${
          view === item.value
            ? "bg-accent-tint font-medium text-accent"
            : "text-fg-2 hover:bg-bg-hover"
        }`}
      >
        <Icon className="size-4 shrink-0" />
        {!sidebarCollapsed && <span className="ml-2 truncate">{item.label}</span>}
      </button>
    );
  };

  /// The 本机 entry: the host view (this machine's every managed node,
  /// cross-deployment, + machine-level logs) — an entry, not a nav
  /// group; the hostname names the observation position.
  const renderLocalEntry = () => {
    const Icon = NAV_ICONS.local;
    const label =
      hostName !== null
        ? t("dep.nav.localEntry", { host: hostName, count: nodes.length })
        : t("dep.nav.local");
    return (
      <button
        onClick={() => setView("local")}
        title={label}
        className={`flex min-h-control cursor-pointer items-center rounded-lg text-left text-base outline-none transition-colors duration-150 focus-visible:ring-[3px] focus-visible:ring-accent-tint ${
          sidebarCollapsed ? "justify-center px-0" : "px-2.5"
        } ${
          view === "local"
            ? "bg-accent-tint font-medium text-accent"
            : "text-fg-2 hover:bg-bg-hover"
        }`}
      >
        <Icon className="size-4 shrink-0" />
        {!sidebarCollapsed && <span className="ml-2 truncate text-small">{label}</span>}
      </button>
    );
  };

  /// Scope picks (from the switcher): a deployment opens the writable
  /// scope and clears any 🔒 realm; a realm does the reverse (closing
  /// the deployment quietly — its state is mutually exclusive); closing
  /// the scope returns the shell to 本机.
  const pickDeployment = async (root: string) => {
    localStorage.removeItem("interflow.realm-scope");
    setRealmScope(null);
    return dep.openDeployment(root);
  };
  const pickRealm = (name: string) => {
    localStorage.setItem("interflow.realm-scope", name);
    setRealmScope(name);
    setView("fleet");
    void dep.closeDeployment();
  };
  const closeScope = async () => {
    if (realmScope !== null) {
      localStorage.removeItem("interflow.realm-scope");
      setRealmScope(null);
    } else {
      await dep.closeDeployment();
    }
  };

  const face = shellFace({
    depLoading: dep.loading,
    nodesLoaded,
    scopeOpen,
    nodeCount: nodes.length,
  });

  /// The 本机 view is face-independent (machine-local truth only) — the
  /// same element serves the scoped shell and the scope-less form.
  const nodesView = (
    <NodesView
      nodes={nodes}
      nodesLoaded={nodesLoaded}
      selectedNodeId={selectedNodeId}
      detailView={detailView}
      onDetailViewChange={setDetailView}
      onOpenNode={openNode}
      onBack={() => setSelectedNodeId(null)}
      onChanged={refreshNodes}
      onError={reportError}
      logs={visibleLogs}
      logScope={allLogs ? "machine" : "node"}
      onLogScopeChange={(scope) => setAllLogs(scope === "machine")}
      onClearLogs={() => {
        setLogs([]);
        void api.clearLogs().catch(() => {});
      }}
    />
  );

  /// The 编队 view: hub-reported presence under a deployment, local
  /// observation under a 🔒 realm — `FleetView` owns the merge.
  const fleetView = <FleetView realm={realmScope} nodes={nodes} onOpenNode={openNode} />;

  const title =
    view === "local" && selected
      ? `${t("dep.nav.local")} — ${selected.name}`
      : nav.find((n) => n.value === view)?.label ?? "";

  return (
    <div className="flex h-screen bg-bg-1 text-fg-1">
      {/* ---- sidebar: the realm axis + the 本机 entry + build identity ---- */}
      <aside
        className={`flex shrink-0 flex-col gap-2 border-r border-line bg-bg-2 py-2.5 transition-[width] duration-150 ${
          sidebarCollapsed ? "w-[56px] px-1.5" : "w-[210px] px-2.5"
        }`}
      >
        {/* The scope group — the switcher IS its header (the open
            deployment's or 🔒 realm's name, 打开部署… when none); its
            body, the scope's views, expands only while a scope is open.
            The switcher governs the whole sidebar now — the 本机 entry
            below is the observation position, structurally outside every
            scope. */}
        <DeploymentSwitcher
          collapsed={sidebarCollapsed}
          hasNodes={nodes.length > 0}
          realms={meshRealms(nodes)}
          realmScope={realmScope}
          onPickDeployment={pickDeployment}
          onPickRealm={pickRealm}
          onCloseScope={closeScope}
        />
        <nav className="mt-1 flex flex-col gap-0.5">
          {scopeOpen && scopeNav.map(renderNavItem)}
          {/* The 本机 entry — machine-local truth, always present, never
              filtered by the scope above. */}
          {!sidebarCollapsed && (
            <span className="mt-3 px-2.5 text-small font-semibold uppercase tracking-[0.05em] text-fg-3">
              {t("dep.nav.localGroup")}
            </span>
          )}
          {renderLocalEntry()}
        </nav>
        <div className="mt-auto flex flex-col gap-1">
          {!sidebarCollapsed && versionInfo && (
            <Popover>
              <PopoverTrigger asChild>
                <Button
                  variant="link"
                  title={t("app.versionTitle")}
                  className={
                    versionInfo.dirty
                      ? "justify-start font-mono text-micro text-warn opacity-100"
                      : "justify-start font-mono text-micro text-fg-3"
                  }
                >
                  {`v${versionInfo.version}`}
                </Button>
              </PopoverTrigger>
              <PopoverContent side="right" align="end" className="w-[280px]">
                <div className="flex flex-col gap-1">
                  <span className="text-small text-fg-3">{t("app.version")}</span>
                  <span className="font-mono text-small">{`v${versionInfo.version}`}</span>
                  <span className="mt-1.5 text-small text-fg-3">{t("app.buildTag")}</span>
                  <span className="break-all font-mono text-small">
                    {versionInfo.build_tag}
                  </span>
                  {versionInfo.dirty && (
                    <p className="m-0 mt-1 text-small text-warn">{t("app.versionDirtyTitle")}</p>
                  )}
                  <Button
                    variant="secondary"
                    size="sm"
                    className="mt-2 self-start"
                    onClick={copyVersion}
                  >
                    {t("app.copyBuildIdentity")}
                  </Button>
                </div>
              </PopoverContent>
            </Popover>
          )}
          <button
            onClick={toggleSidebar}
            title={sidebarCollapsed ? t("dep.sidebar.expand") : t("dep.sidebar.collapse")}
            className="flex min-h-control-sm cursor-pointer items-center justify-center rounded-lg text-fg-3 outline-none transition-colors duration-150 hover:bg-bg-hover hover:text-fg-1 focus-visible:ring-[3px] focus-visible:ring-accent-tint"
          >
            {sidebarCollapsed ? (
              <ChevronsRight className="size-4" />
            ) : (
              <ChevronsLeft className="size-4" />
            )}
          </button>
        </div>
      </aside>

      {/* ---- content: top bar (view title + status cluster) + the view ---- */}
      <div className="flex min-w-0 flex-1 flex-col">
        <header className="flex items-center gap-3 px-4 pt-2.5 pb-1">
          <h1 className="m-0 text-base font-semibold tracking-tight">{title}</h1>
          <div className="ml-auto flex items-center gap-2.5">
            <StatusCluster onJumpProposals={() => setView("overview")} />
            <SegmentedControl
              value={lang}
              options={[
                { value: "en", label: "EN" },
                { value: "zh", label: "中文" },
              ]}
              onChange={setLang}
            />
          </div>
        </header>

        {guiError && (
          <div
            role="alert"
            className="mx-4 mt-1 flex items-baseline gap-3 rounded-lg border border-critical/45 bg-critical/10 px-3 py-2 text-base text-critical"
          >
            <span className="min-w-0 flex-1 break-words">{guiError}</span>
            <Button variant="link" size="sm" onClick={() => setGuiError(null)}>
              {t("app.dismiss")}
            </Button>
          </div>
        )}

        <ConflictDialog />

        <main className="flex min-h-0 flex-1 flex-col px-4 pt-2 pb-4">
          {face === "loading" ? (
            <div className="flex flex-1 items-center justify-center text-small text-fg-3">…</div>
          ) : face === "onboarding" ? (
            <Onboarding />
          ) : (
            <>
              {view === "overview" && depOpen && (
                <OverviewView
                  onOpenNode={openNode}
                  onOpenAdvanced={() => setView("advanced")}
                  onOpenStreams={() => setView("streams")}
                  onOpenServices={() => setView("services")}
                />
              )}
              {view === "fleet" && scopeOpen && fleetView}
              {view === "streams" && depOpen && <StreamsView onOpenNode={openNode} />}
              {view === "services" && depOpen && <ServicesView onOpenNode={openNode} />}
              {view === "local" && nodesView}
              {view === "advanced" && depOpen && (
                <AdvancedView selectedPack={selectedPackPrincipal} onSelectPack={setSelectedPackPrincipal} />
              )}
            </>
          )}
        </main>

        {dep.deployment !== null && dep.output.length > 0 && (
          <pre className="mx-4 mb-3 max-h-[160px] shrink-0 overflow-auto rounded-lg border border-line bg-bg-3 p-2.5 font-mono text-micro whitespace-pre-wrap text-fg-2">
            {dep.output.join("\n")}
          </pre>
        )}
      </div>
    </div>
  );
}
