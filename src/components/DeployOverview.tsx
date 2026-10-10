import { useCallback, useEffect, useState } from "react";
import {
  api,
  type ApplyReportDto,
  type ChangeStateDto,
  type ControlProposalDto,
  type DeployContextDto,
  type HubOverviewDto,
  type ManifestSummaryDto,
} from "../api";
import {
  ArrowDownLeft,
  ArrowUpRight,
  Check,
  Plus,
  RefreshCw,
  SlidersHorizontal,
  Upload,
} from "lucide-react";
import { useT } from "../i18n";
import { buildNextSteps, changeStateLabel } from "../lib/deploySteps";
import RecentContextSelect from "./RecentContextSelect";
import {
  Badge,
  Button,
  Hint,
  Input,
  PeerDot,
  SectionPanel,
  TBody,
  Table,
  Td,
  Th,
  THead,
  Tr,
} from "./ui";

/// The Deploy face's landing view (2026-10-08 deploy-legibility backlog):
/// task-first, not schema-first. Three answers on one screen —
///   ① "what does this deployment look like" (the fleet table: agents and
///      their stream counts, presence when the hub answers),
///   ② "what should I do next" (the next-steps checklist, derived from the
///      live document state and the issuer bookkeeping — never a guess),
///   ③ "what did my last apply do" (the generation card with per-node
///      convergence, refreshable until the whole fleet caught up).
/// The full manifest editor remains the escape hatch one nav-click away.
export default function DeployOverview({
  manifest,
  issuer,
  out,
  summary,
  parseError,
  readError,
  dirty,
  lastApply,
  busy,
  recentContexts,
  onPickContext,
  onChooseManifest,
  onCreateDeployment,
  onAddStream,
  onAdjustStream,
  onApply,
  onOpenManifest,
  onOpenPacks,
  onIssueNode,
  onSave,
  proposals,
  proposalsBusy,
  onApproveProposal,
  onRejectProposal,
}: {
  manifest: string;
  issuer: string;
  out: string;
  /// The manifest document's current read model (from the editor's parse);
  /// `null` = not loaded yet.
  summary: ManifestSummaryDto | null;
  /// The loaded text failed to parse — the syntax class; the editor's.
  parseError: string | null;
  /// The file could not be read (missing/unreadable) — the load class;
  /// the remedy is picking or creating a manifest, never editing TOML.
  readError: string | null;
  /// Unsaved editor edits exist — Save before they ride an Apply.
  dirty: boolean;
  lastApply: ApplyReportDto | null;
  busy: boolean;
  recentContexts: DeployContextDto[];
  onPickContext: (ctx: DeployContextDto) => void;
  /// Native open dialog for an existing manifest (empty/missing-file
  /// states' primary action).
  onChooseManifest: () => void;
  /// Opens the create-deployment dialog (template → save → load).
  onCreateDeployment: () => void;
  onAddStream: () => void;
  onAdjustStream: (agent: string, ruleName: string) => void;
  onApply: () => void;
  onOpenManifest: () => void;
  onOpenPacks: () => void;
  onIssueNode: () => void;
  onSave: () => void;
  /// The hub's proposal queue (pending + recently decided); `null` = not
  /// fetched / no endpoint.
  proposals: ControlProposalDto[] | null;
  proposalsBusy: boolean;
  onApproveProposal: (id: string) => void;
  onRejectProposal: (id: string, reason: string) => void;
}) {
  const { t } = useT();
  const [changeState, setChangeState] = useState<ChangeStateDto | null>(null);
  const [hub, setHub] = useState<HubOverviewDto | null>(null);
  const [hubState, setHubState] = useState<"idle" | "loading" | "unreachable">("idle");
  const [rejecting, setRejecting] = useState<string | null>(null);
  const [rejectReason, setRejectReason] = useState("");

  const refreshHub = useCallback(async () => {
    if (manifest.trim() === "" || issuer.trim() === "") return;
    setHubState("loading");
    try {
      const overview = await api.deployHubOverview(manifest.trim(), issuer.trim());
      setHub(overview ?? null);
      setHubState("idle");
    } catch {
      setHub(null);
      setHubState("unreachable");
    }
  }, [manifest, issuer]);

  // The bookkeeping-level pre-check + the hub overview: re-read whenever
  // the paths move, the document changes shape (a save/apply cycles
  // `summary`), or an apply lands (`lastApply`).
  useEffect(() => {
    let cancelled = false;
    void (async () => {
      if (manifest.trim() === "" || issuer.trim() === "") {
        if (!cancelled) setChangeState(null);
        return;
      }
      try {
        const state = await api.deployChangeState(manifest.trim(), issuer.trim());
        if (!cancelled) setChangeState(state);
      } catch {
        if (!cancelled) setChangeState(null);
      }
    })();
    return () => {
      cancelled = true;
    };
  }, [manifest, issuer, summary, lastApply]);

  useEffect(() => {
    void refreshHub();
    // refreshHub closes over the paths; re-run when they move or an apply
    // may have moved the fleet.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [manifest, issuer, lastApply]);

  const meshAgents = (summary?.agents ?? []).filter(
    (a) => a.mesh_ingress.length > 0 || a.mesh_egress.length > 0 || a.role === "mesh",
  );
  // Fleet rows: every agent (streams live on any of them); presence joins
  // by the qualified id's agent part when the hub answered.
  const agents = summary?.agents ?? [];
  const presenceOf = (node: string): boolean | null => {
    if (!hub) return null;
    const row = hub.agents.find((a) => a.agent.endsWith(`/${node}`));
    return row ? row.online : null;
  };

  const nextSteps = buildNextSteps({
    t,
    readError,
    loaded: summary !== null || parseError !== null,
    parseError,
    issues: summary?.issues ?? [],
    agents,
    meshAgents,
    dirty,
    changeState,
    onChooseManifest,
    onOpenManifest,
    onIssueNode,
    onAddStream,
    onSave,
    onApply,
  });

  const converged =
    lastApply !== null &&
    hub !== null &&
    (hub.agents.length === 0 ||
      hub.agents.every((a) => a.seen != null && a.seen >= lastApply.generation));

  return (
    <div className="flex min-h-0 flex-1 flex-col gap-2.5 overflow-y-auto">
      <div className="grid grid-cols-[minmax(0,1.6fr)_minmax(280px,1fr)] items-start gap-2.5">
        <SectionPanel
          title={t("overview.fleet")}
          hint={hub ? t("overview.fleetHub", { gen: String(hub.serving ?? hub.floor) }) : undefined}
          actions={
            <Button size="sm" disabled={hubState === "loading"} onClick={() => void refreshHub()}>
              {hubState === "loading" ? "…" : t("overview.refresh")}
            </Button>
          }
          grow
        >
          {readError !== null ? (
            <div className="flex flex-1 flex-col items-center justify-center gap-2.5 p-6 text-center">
              <p className="m-0 max-w-[60ch] text-base text-critical whitespace-pre-wrap">
                {t("overview.stepFileMissing", { error: readError })}
              </p>
              <div className="flex gap-2">
                <Button variant="primary" disabled={busy} onClick={onChooseManifest}>
                  {t("overview.chooseAction")}
                </Button>
                <Button disabled={busy} onClick={onCreateDeployment}>
                  {t("overview.createAction")}
                </Button>
              </div>
            </div>
          ) : summary === null && parseError === null ? (
            <div className="flex flex-1 flex-col items-center justify-center gap-2.5 p-6 text-center">
              <p className="m-0 max-w-[60ch] text-base text-fg-2">{t("overview.emptyBody")}</p>
              <div className="flex gap-2">
                <Button variant="primary" disabled={busy} onClick={onChooseManifest}>
                  {t("overview.chooseAction")}
                </Button>
                <Button disabled={busy} onClick={onCreateDeployment}>
                  {t("overview.createAction")}
                </Button>
              </div>
            </div>
          ) : agents.length === 0 ? (
            <p className="text-small text-fg-3">
              {summary === null
                ? t("overview.notLoaded")
                : t("overview.noAgents", { name: manifest })}
            </p>
          ) : (
            <Table>
              <THead>
                <Tr>
                  <Th scope="col">{t("overview.agent")}</Th>
                  <Th scope="col">{t("overview.workspace")}</Th>
                  <Th scope="col">{t("overview.streams")}</Th>
                  <Th scope="col">{t("overview.transport")}</Th>
                  <Th scope="col">{t("overview.online")}</Th>
                </Tr>
              </THead>
              <TBody>
                {agents.map((agent) => (
                  <Tr key={agent.node}>
                    <Td className="font-mono text-small">{agent.node}</Td>
                    <Td>{agent.workspace}</Td>
                    <Td>
                      {agent.mesh_ingress.length > 0 && (
                        <Hint
                          text={agent.mesh_ingress
                            .map((r) => `${r.name}: ${r.listen} → ${r.remote_addr} @ ${r.target_agent}`)
                            .join("\n")}
                        >
                          <span className="mr-2.5 inline-flex items-baseline gap-1.5">
                            <ArrowUpRight className="size-3.5 self-center text-fg-3" />
                            {agent.mesh_ingress.length}
                            {agent.mesh_ingress.map((rule) => (
                              <Button
                                key={rule.name}
                                variant="link"
                                size="sm"
                                disabled={busy}
                                title={t("overview.adjustStreamTitle", { name: rule.name })}
                                onClick={() => onAdjustStream(agent.node, rule.name)}
                                className="px-1"
                              >
                                {rule.name}
                              </Button>
                            ))}
                          </span>
                        </Hint>
                      )}
                      {agent.mesh_egress.length > 0 && (
                        <Hint
                          text={agent.mesh_egress
                            .map((r) => `${r.name}: ${r.target_addr ?? r.target_cidr ?? ""}`)
                            .join("\n")}
                        >
                          <span className="mr-2.5 inline-flex items-baseline gap-1.5">
                            <ArrowDownLeft className="size-3.5 self-center text-fg-3" />
                            {agent.mesh_egress.length}
                            {agent.mesh_egress.map((rule) => (
                              <Badge key={rule.name}>{rule.name}</Badge>
                            ))}
                          </span>
                        </Hint>
                      )}
                      {agent.mesh_ingress.length === 0 && agent.mesh_egress.length === 0 && (
                        <span className="text-small text-fg-3">—</span>
                      )}
                    </Td>
                    <Td>{agent.transport ?? "h2"}</Td>
                    <Td>
                      {presenceOf(agent.node) == null ? (
                        <span className="text-small text-fg-3">—</span>
                      ) : presenceOf(agent.node) ? (
                        <span className="inline-flex items-center gap-1.5">
                          <PeerDot online />
                          <span className="sr-only">{t("overview.onlineShort")}</span>
                        </span>
                      ) : (
                        <span className="inline-flex items-center gap-1.5">
                          <PeerDot online={false} />
                          <span className="sr-only">{t("overview.offlineShort")}</span>
                        </span>
                      )}
                    </Td>
                  </Tr>
                ))}
              </TBody>
            </Table>
          )}
          {hubState === "unreachable" && (
            <p className="text-small text-fg-3">{t("overview.hubUnreachable")}</p>
          )}
        </SectionPanel>

        <div className="flex flex-col gap-2.5">
          <SectionPanel title={t("overview.tasks")}>
            <div className="grid grid-cols-2 gap-2">
              <TaskCard icon={<Plus className="size-4" />} title={t("overview.addStream")} hint={t("overview.addStreamHint")} disabled={busy || summary === null} onClick={onAddStream} />
              <TaskCard icon={<SlidersHorizontal className="size-4" />} title={t("overview.adjustStream")} hint={t("overview.adjustStreamHint")} disabled={busy || (meshAgents.length === 0 && agents.length === 0)} onClick={onAddStream} tooltip={t("overview.adjustStreamTitle", { name: "" })} />
              <TaskCard icon={<Upload className="size-4" />} title={t("overview.apply")} hint={changeStateLabel(changeState, t)} primary disabled={busy || summary === null} onClick={onApply} />
              <TaskCard icon={<RefreshCw className="size-4" />} title={t("overview.rotate")} hint={t("overview.rotateHint")} onClick={onOpenPacks} />
            </div>
          </SectionPanel>

          <SectionPanel title={t("overview.nextSteps")}>
            <ol className="m-0 flex list-decimal flex-col gap-1 pl-4">
              {nextSteps.map((step, i) => (
                <li key={i} className={step.done ? "text-fg-3" : "text-fg-1"}>
                  <span className="flex items-center gap-1.5 text-small">
                    {step.done && <Check className="size-3.5 shrink-0 text-success" />}
                    {step.text}
                    {step.action && !step.done && (
                      <Button variant="link" size="sm" disabled={busy} onClick={step.action} className="ml-1 px-1">
                        {step.actionLabel ?? t("overview.go")}
                      </Button>
                    )}
                  </span>
                </li>
              ))}
            </ol>
          </SectionPanel>

          {lastApply && (
            <SectionPanel
              title={t("overview.lastApply")}
              actions={
                <Button size="sm" disabled={hubState === "loading"} onClick={() => void refreshHub()}>
                  {t("overview.refresh")}
                </Button>
              }
            >
              <p className="m-0 text-base">
                <span className="text-small text-fg-3">{t("overview.generation")}</span>{" "}
                <span className="font-mono text-small">gen {lastApply.generation}</span>{" "}
                {hub && (
                  <span className="text-small text-fg-3">
                    · hub {hub.serving != null ? `serving ${hub.serving}` : `floor ${hub.floor}`}
                  </span>
                )}
                {converged && <span className="text-small text-success"> · {t("overview.converged")}</span>}
              </p>
              {hub && hub.agents.length > 0 && (
                <Table className="text-small">
                  <TBody>
                    {hub.agents.map((row) => {
                      const short = row.agent.split("/").pop() ?? row.agent;
                      const caught = row.seen != null && row.seen >= lastApply.generation;
                      return (
                        <Tr key={row.agent}>
                          <Td className="py-1 font-mono">{short}</Td>
                          <Td className="py-1">
                            <span className="inline-flex items-center gap-1.5">
                              <PeerDot online={row.online} />
                              {row.online ? t("overview.onlineShort") : t("overview.offlineShort")}
                            </span>
                          </Td>
                          <Td className="py-1">
                            {row.seen == null ? (
                              <span className="text-fg-3">—</span>
                            ) : caught ? (
                              <span className="inline-flex items-center gap-1 text-success">
                                <Check className="size-3.5" />
                                gen {row.seen}
                              </span>
                            ) : (
                              <span className="text-warn">
                                {t("overview.pendingGen", { gen: String(row.seen) })}
                              </span>
                            )}
                          </Td>
                        </Tr>
                      );
                    })}
                  </TBody>
                </Table>
              )}
              <details className="mt-1">
                <summary className="cursor-pointer text-small text-fg-3">
                  {t("overview.reportLines")}
                </summary>
                <pre className="mt-1.5 m-0 max-h-[200px] overflow-auto rounded-lg border border-line bg-bg-3 p-2.5 font-mono text-micro whitespace-pre-wrap text-fg-2">
                  {lastApply.lines.join("\n")}
                </pre>
              </details>
            </SectionPanel>
          )}
        </div>
      </div>

      {proposals !== null && proposals.length > 0 && (
        <SectionPanel title={t("overview.proposals")} hint={t("overview.proposalsHint")}>
          {proposals.map((p) => {
            const pending = p.status.status === "pending";
            const shortRequester = p.requester.split("/").pop() ?? p.requester;
            return (
              <div
                key={p.id}
                className="flex flex-wrap items-center gap-2.5 border-b border-line/40 py-1.5 text-base last:border-b-0"
              >
                <Hint text={p.requester}>
                  <span className="font-mono text-small">{shortRequester}</span>
                </Hint>
                <span className="text-small text-fg-3">wants</span>
                <span className="font-mono text-small">{p.rule.listen}</span>
                <Badge className="uppercase">{p.rule.protocol}</Badge>
                <span>
                  → {p.rule.remote_addr}{" "}
                  <span className="text-small text-fg-3">
                    {t("nodeDetail.atAgent", { agent: p.rule.target_agent })}
                  </span>
                </span>
                <Hint text={p.id}>
                  <span className="text-small text-fg-3">{p.rule.name}</span>
                </Hint>
                <span className="text-small text-fg-3">
                  {p.status.status === "pending" && t("proposal.statusPending")}
                  {p.status.status === "approved" &&
                    t("proposal.statusApproved", { gen: String(p.status.generation) })}
                  {p.status.status === "rejected" && t("proposal.statusRejected")}
                </span>
                {pending && (
                  <>
                    <Hint text={t("overview.approveTitle")}>
                      <Button
                        size="sm"
                        variant="primary"
                        disabled={proposalsBusy}
                        onClick={() => onApproveProposal(p.id)}
                      >
                        {t("overview.approve")}
                      </Button>
                    </Hint>
                    <Button
                      size="sm"
                      disabled={proposalsBusy}
                      onClick={() => {
                        setRejecting(rejecting === p.id ? null : p.id);
                        setRejectReason("");
                      }}
                    >
                      {t("overview.reject")}
                    </Button>
                    {rejecting === p.id && (
                      <span className="inline-flex items-center gap-1.5">
                        <Input
                          aria-label={t("overview.rejectReasonPlaceholder")}
                          value={rejectReason}
                          onChange={(e) => setRejectReason(e.target.value)}
                          placeholder={t("overview.rejectReasonPlaceholder")}
                          autoCapitalize="none"
                          autoCorrect="off"
                          spellCheck={false}
                          className="max-w-[280px]"
                        />
                        <Button
                          size="sm"
                          variant="danger"
                          disabled={proposalsBusy || rejectReason.trim() === ""}
                          onClick={() => {
                            onRejectProposal(p.id, rejectReason.trim());
                            setRejecting(null);
                          }}
                        >
                          {t("overview.rejectConfirm")}
                        </Button>
                      </span>
                    )}
                  </>
                )}
              </div>
            );
          })}
        </SectionPanel>
      )}

      <div className="flex items-center gap-2">
        <span className="w-[140px] shrink-0 text-base text-fg-2">{t("manifest.recent")}</span>
        <RecentContextSelect
          contexts={recentContexts}
          current={{ manifest, issuer, out }}
          onPick={onPickContext}
        />
      </div>
    </div>
  );
}

/// One task entry (the Overview's front door): icon + title + one-line
/// hint. The apply entry is the primary path — accent-tinted.
function TaskCard({
  icon,
  title,
  hint,
  primary = false,
  disabled = false,
  tooltip,
  onClick,
}: {
  icon: React.ReactNode;
  title: string;
  hint: string;
  primary?: boolean;
  disabled?: boolean;
  tooltip?: string;
  onClick: () => void;
}) {
  return (
    <button
      disabled={disabled}
      onClick={onClick}
      title={tooltip}
      className={
        "flex cursor-pointer flex-col items-start gap-0.5 rounded-lg border p-2.5 text-left outline-none transition-colors duration-150 focus-visible:border-accent focus-visible:ring-[3px] focus-visible:ring-accent-tint disabled:pointer-events-none disabled:opacity-50 " +
        (primary
          ? "border-accent/50 bg-accent-tint text-accent hover:border-accent"
          : "border-line bg-bg-2 text-fg-1 hover:border-line-strong hover:bg-bg-hover")
      }
    >
      <span className="flex items-center gap-1.5 text-base font-medium">
        {icon}
        {title}
      </span>
      <span className={primary ? "text-small text-accent/80" : "text-small text-fg-3"}>{hint}</span>
    </button>
  );
}

/// The next-steps checklist and its helpers live in `src/lib/deploySteps.ts`
/// (pure, unit-tested — the read/parse error classification lives there).
