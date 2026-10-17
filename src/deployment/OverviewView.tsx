import { useState } from "react";
import { api, isRunning, type FleetNodeDto } from "../api";
import { useT } from "../i18n";
import { buildNextSteps } from "../lib/deploySteps";
import IssuePackDialog from "../components/IssuePackDialog";
import {
  Button,
  EmptyState,
  KindBadge,
  PeerDot,
  SectionPanel,
  StateDot,
  Table,
  TBody,
  Td,
  Th,
  THead,
  Tr,
} from "../components/ui";
import { useDeployment } from "./DeploymentContext";
import { principalRealm } from "../lib/shellFace";

interface Props {
  onOpenNode: (id: string) => void;
  onOpenAdvanced: () => void;
  /// The ladder's content-step destinations — the streams/services views.
  /// The step buttons only render while their face predicate holds (the
  /// same rule the nav items live by), so neither navigation can ever
  /// meet the rebound guard.
  onOpenStreams: () => void;
  onOpenServices: () => void;
}

/// 总览: the deployment's whole truth in one screen — the members table
/// (declared nodes, local faces, remote presence, convergence), the
/// derived next steps for a fresh deployment, the last publish's result
/// with its consequences stated, and the stream-request queue. Every row
/// cross-links: local nodes open the machine detail; the unreachable-hub
/// hint opens the hub's machine (dead-end kill list #8/#9).
export default function OverviewView({
  onOpenNode,
  onOpenAdvanced,
  onOpenStreams,
  onOpenServices,
}: Props) {
  const { t } = useT();
  const {
    deployment,
    fleet,
    text,
    savedText,
    proposals,
    lastPublish,
    busy,
    save,
    publish,
    say,
    nodesChanged,
  } = useDeployment();
  const [issueOpen, setIssueOpen] = useState(false);

  if (deployment === null || fleet === null) return null;

  const dirty = text !== null && text !== savedText;
  const summary = fleet.summary;

  const nextSteps = buildNextSteps({
    t,
    readError: null,
    loaded: true,
    // A summary only exists for a parsed document (an unreadable or
    // unparseable manifest fails the whole composed read and this view
    // renders nothing) — so `issues` here is always the semantic class
    // and walks the issues step, never the syntax branch it was once
    // folded into.
    parseError: null,
    issues: summary.issues,
    agents: summary.agents,
    dirty,
    changeState: fleet.change_state,
    onOpenManifest: onOpenAdvanced,
    onIssueNode: () => setIssueOpen(true),
    onAddStream: onOpenStreams,
    onDeclareService: onOpenServices,
    onSave: () => void save(),
    onApply: () => void publish(),
    busy,
  });

  // The convergence picture from the hub's face: every agent at the
  // serving generation, or the count that still trails.
  const hub = fleet.hub;
  const serving = hub?.serving ?? null;
  const catchingUp =
    hub === null
      ? null
      : hub.agents.filter((a) => a.seen === null || a.seen < (serving ?? hub.floor)).length;

  // The 在线 column exists only where an overview exists to ask: the
  // column's remote face comes solely from the hub's report, and an
  // expose agent (dialing ingress, never the hub) is structurally absent
  // from it — a declared-hub-less deployment would show a column of
  // placeholders forever (the permanently-empty face, column edition).
  // A DECLARED but unreachable hub keeps the column (honest "—" rows plus
  // the unreachable hint); the 版本 column stays regardless — the local
  // node's policy generation is this machine's own truth.
  const hubDeclared = fleet.summary.hubs.length > 0;

  const hubLocal = fleet.nodes.find((n) => n.kind === "hub" && n.local !== null);

  const openProposalRow = async (id: string, approve: boolean) => {
    if (deployment === null) return;
    try {
      if (approve) {
        const report = await api.deployApproveProposal(
          deployment.manifest_path,
          deployment.issuer_path,
          deployment.out_path,
          id,
        );
        say(report.lines);
      } else {
        await api.deployRejectProposal(
          deployment.manifest_path,
          deployment.issuer_path,
          id,
          "",
        );
      }
      nodesChanged();
    } catch (e) {
      say([`✘ ${String(e)}`]);
    }
  };

  const pending = (proposals ?? []).filter((p) => p.status.status === "pending");

  return (
    <div className="flex min-h-0 flex-1 flex-col gap-3 overflow-auto">
      {nextSteps.length > 0 && (
        <SectionPanel title={t("dep.overview.nextSteps")}>
          <ol className="m-0 flex list-none flex-col gap-1 p-0">
            {nextSteps.map((step, i) => (
              <li
                key={i}
                className={`flex items-center gap-2 text-base ${step.done ? "text-fg-3 line-through" : ""}`}
              >
                <span className="font-mono text-small text-fg-3">{i + 1}.</span>
                {step.text}
                {step.action && step.actionLabel && !step.done && (
                  <Button
                    size="sm"
                    variant="secondary"
                    disabled={step.disabled}
                    onClick={step.action}
                  >
                    {step.actionLabel}
                  </Button>
                )}
              </li>
            ))}
          </ol>
        </SectionPanel>
      )}

      <SectionPanel
        title={t("dep.overview.fleet")}
        actions={
          <Button size="sm" variant="secondary" onClick={() => setIssueOpen(true)}>
            {t("dep.overview.issueNode")}
          </Button>
        }
      >
        {fleet.nodes.length === 0 ? (
          <EmptyState>{t("dep.overview.emptyAgents")}</EmptyState>
        ) : (
          <div className="overflow-x-auto">
          <Table>
            <THead>
              <Tr>
                <Th>{t("dep.overview.col.node")}</Th>
                <Th>{t("dep.overview.col.here")}</Th>
                {hubDeclared && <Th>{t("dep.overview.col.online")}</Th>}
                <Th>{t("dep.overview.col.version")}</Th>
              </Tr>
            </THead>
            <TBody>
              {fleet.nodes.map((row) => (
                <FleetRow
                  key={`${row.kind}/${row.name}`}
                  row={row}
                  serving={serving}
                  showOnline={hubDeclared}
                  onOpenNode={onOpenNode}
                />
              ))}
            </TBody>
          </Table>
          </div>
        )}
        {fleet.local_only.length > 0 && (
          <div className="mt-2 flex flex-col gap-px text-micro text-fg-3">
            {fleet.local_only.map((n) => {
              const realm = principalRealm(n.principal);
              return (
                <p key={n.name} className="m-0">
                  {realm
                    ? t("dep.overview.localOtherRealm", { name: n.name, realm })
                    : t("dep.overview.localOther", { name: n.name })}
                </p>
              );
            })}
          </div>
        )}
        {hub === null && hubLocal && (
          <p className="m-0 mt-2 text-small text-warn">
            {t("dep.overview.hubUnreachable")}{" "}
            <Button size="sm" variant="link" onClick={() => onOpenNode(hubLocal.local!.id)}>
              {t("dep.overview.hubOpen")}
            </Button>
          </p>
        )}
      </SectionPanel>

      {lastPublish !== null && (
        <SectionPanel title={t("dep.overview.lastPublish")}>
          <p className="m-0 text-base">
            {lastPublish.kind === "policy_only"
              ? t("dep.publish.policyOnly", {
                  gen: String(lastPublish.apply.generation),
                })
              : lastPublish.kind === "full_render"
                ? t("dep.publish.fullRender", {
                    gen: String(lastPublish.apply.generation),
                  })
                : t("dep.publish.noOp")}
          </p>
          <div className="mt-1 flex flex-wrap items-baseline gap-x-4 gap-y-1 text-small text-fg-2">
            {lastPublish.updated_nodes.length > 0 && (
              <span className="text-success">
                {t("dep.publish.updated", { n: String(lastPublish.updated_nodes.length) })}
              </span>
            )}
            {lastPublish.failed_updates.length > 0 && (
              <span className="text-critical">
                {t("dep.publish.failed", { n: String(lastPublish.failed_updates.length) })}{" "}
                ({lastPublish.failed_updates.map((f) => f.node).join(", ")})
              </span>
            )}
            {hub !== null &&
              (catchingUp === 0 ? (
                <span className="text-success">{t("dep.overview.converged")}</span>
              ) : (
                <span className="text-warn">
                  {t("dep.overview.catchingUp", { n: String(catchingUp) })}
                </span>
              ))}
          </div>
        </SectionPanel>
      )}

      {pending.length > 0 && (
        <SectionPanel title={t("dep.overview.proposals")}>
          <div className="flex flex-col gap-1">
            {pending.map((p) => (
              <div
                key={p.id}
                className="flex flex-wrap items-baseline gap-x-3 gap-y-1 rounded-lg border border-line bg-bg-2 px-2.5 py-1.5 text-small"
              >
                <span className="font-medium">{p.rule.name}</span>
                <span className="font-mono text-fg-2">
                  {p.rule.listen} → {p.rule.target_agent} · {p.rule.remote_addr}
                </span>
                <span className="text-fg-3">{p.requester}</span>
                <span className="ml-auto flex gap-1.5">
                  <Button size="sm" disabled={busy} onClick={() => void openProposalRow(p.id, true)}>
                    {t("common.apply")}
                  </Button>
                  <Button
                    size="sm"
                    variant="secondary"
                    onClick={() => void openProposalRow(p.id, false)}
                  >
                    {t("overview.reject")}
                  </Button>
                </span>
              </div>
            ))}
          </div>
        </SectionPanel>
      )}

      {issueOpen && deployment !== null && (
        <IssuePackDialog
          manifest={deployment.manifest_path}
          issuer={deployment.issuer_path}
          out={deployment.out_path}
          busy={busy}
          recentContexts={[]}
          onPickContext={() => {}}
          onSay={say}
          onIssued={() => nodesChanged()}
          onComplete={() => nodesChanged()}
          onAddHere={(packDir) => {
            void (async () => {
              try {
                await api.addNode({ pack_dir: packDir, transport: null, hub_quic_addr: null });
                say([t("dep.node.addedHere")]);
              } catch (e) {
                say([`✘ ${String(e)}`]);
              }
            })();
          }}
          onClose={() => setIssueOpen(false)}
        />
      )}
    </div>
  );
}

/// One members row: declared identity (the kind badge inline with the
/// name carries the role) + the local face (openable) + the hub-reported
/// presence (only while a hub is declared) + the convergence arithmetic
/// (applied/seen vs serving).
function FleetRow({
  row,
  serving,
  showOnline,
  onOpenNode,
}: {
  row: FleetNodeDto;
  serving: number | null;
  showOnline: boolean;
  onOpenNode: (id: string) => void;
}) {
  const { t } = useT();
  const applied = row.local?.policy_generation ?? row.remote?.seen_generation ?? null;
  const behind = serving !== null && applied !== null && applied < serving;
  return (
    <Tr>
      <Td>
        <span className="flex items-center gap-2">
          <KindBadge kind={row.kind} />
          <span className="font-medium">{row.name}</span>
          {row.workspace && <span className="text-small text-fg-3">{row.workspace}</span>}
        </span>
      </Td>
      <Td className="whitespace-nowrap">
        {row.local ? (
          <button
            onClick={() => onOpenNode(row.local!.id)}
            className="inline-flex cursor-pointer items-center gap-1.5 text-base text-accent outline-none hover:underline focus-visible:ring-[3px] focus-visible:ring-accent-tint"
            title={t("dep.overview.here.open")}
          >
            <StateDot state={row.local.state} />
            {isRunning(row.local.state)
              ? t("dep.overview.here.running")
              : t("dep.overview.here.stopped")}
          </button>
        ) : (
          <span className="text-fg-3">{t("dep.overview.here.absent")}</span>
        )}
      </Td>
      {showOnline && (
        <Td className="whitespace-nowrap">
          {row.remote ? (
            <span className="inline-flex items-center gap-1.5">
              <PeerDot online={row.remote.online} />
              <span className="text-small text-fg-2">
                {row.remote.online ? t("nodeDetail.peerOnline") : t("nodeDetail.peerOffline")}
              </span>
            </span>
          ) : (
            <span className="text-fg-3">{t("dep.overview.here.absent")}</span>
          )}
        </Td>
      )}
      <Td className="whitespace-nowrap">
        <span
          className={`font-mono text-small transition-colors duration-200 ${
            behind ? "text-warn" : "text-fg-2"
          }`}
          title={behind ? t("dep.streams.status.catchingUp") : undefined}
        >
          {applied === null ? "—" : `v${applied}`}
        </span>
      </Td>
    </Tr>
  );
}
