// Tauri API wrapper over the generated IPC contract.
//
// `./bindings` is generated from src-tauri/src/contract.rs via tauri-specta
// (`npm run gen:bindings`) — the single source of truth. Never hand-write a
// type in this file that mirrors a Rust struct; extend the Rust contract and
// regenerate instead (the 2026-09-18 auth_token drift is why this exists).

import { commands, events } from "./bindings";
import type { Event } from "@tauri-apps/api/event";
import type { TFn } from "./i18n";
import type {
  AddNodeParams,
  DeployContextDto,
  EditActionDto,
  GuiPrefsDto,
  IssueNodeParams,
  ListenerStatusDto,
  LogLine,
  ManifestTemplateParams,
  MeshTemplateParams,
  NodeKindDto,
  NodePrefs,
  NodeStateDto,
  PeersPlaneDto,
  PolicyPlaneDto,
  ProposalReceiptDto,
  StreamProposalRequestDto,
  Transport,
} from "./bindings";

export type {
  AddNodeParams,
  AddedNodeDto,
  AgentRoleDto,
  AgentSummaryDto,
  ApplyReportDto,
  ChangeStateDto,
  CreateNodeDto,
  CredentialHealthDto,
  DeploymentDto,
  DeployContextDto,
  DeployPackDto,
  EditActionDto,
  EditedManifestDto,
  FleetDto,
  FleetNodeDto,
  LocalFaceDto,
  PublishKindDto,
  PublishResultDto,
  ServiceFaceDto,
  StreamDto,
  StreamStatusDto,
  GuiLanguageDto,
  GuiPrefsDto,
  HubAgentRowDto,
  HubDto,
  HubOverviewDto,
  IdentityModeDto,
  ImportedPackDto,
  IngressNodeDto,
  IssueMeshEgressDto,
  IssueMeshIngressDto,
  IssueNodeKindDto,
  IssueNodeParams,
  IssueServiceSpecDto,
  LeafTtlBoundsDto,
  ListenerStatusDto,
  LogLine,
  ManifestEgressRuleDto,
  ManifestIngressRuleDto,
  ManifestServiceDto,
  ManifestSummaryDto,
  ManifestTemplateParams,
  MeshEgressRuleDto,
  MeshIngressRuleDto,
  MeshProtocolDto,
  MeshTemplateParams,
  ControlProposalDto,
  NodeInfo,
  NodeKindDto,
  NodePrefs,
  NodeStateDto,
  PackInspection,
  ProposalReceiptDto,
  ProposalStatusDto,
  ProposalSubmitOutcomeDto,
  StreamProposalRequestDto,
  PeerStatusDto,
  PeersPlaneDto,
  PolicyPlaneDto,
  PublicTlsModeDto,
  RealmDto,
  RouteDto,
  SealedPackDto,
  Transport,
  VersionInfo,
} from "./bindings";

/// Result commands return a typed `{status: ok|error}` envelope instead of
/// throwing; unwrap back to exceptions so callers keep try/catch semantics.
async function unwrap<T>(
  result: Promise<{ status: "ok"; data: T } | { status: "error"; error: string }>
): Promise<T> {
  const res = await result;
  if (res.status === "error") throw new Error(res.error);
  return res.data;
}

export const api = {
  listNodes: () => unwrap(commands.listNodes()),
  inspectPack: (packDir: string) => unwrap(commands.inspectPack(packDir)),
  addNode: (params: AddNodeParams) => unwrap(commands.addNode(params)),
  removeNode: (id: string) => unwrap(commands.removeNode(id)),
  startNode: (id: string) => unwrap(commands.startNode(id)),
  stopNode: (id: string) => unwrap(commands.stopNode(id)),
  updateNodePrefs: (id: string, prefs: NodePrefs) =>
    unwrap(commands.updateNodePrefs(id, prefs)),
  getRecentLogs: () => unwrap(commands.getRecentLogs()),
  clearLogs: () => unwrap(commands.clearLogs()),
  getHostName: () => unwrap(commands.getHostName()),
  getVersionInfo: () => unwrap(commands.getVersionInfo()),
  // Deploy (operator) surface — the plan/rotate/revoke/pack twins.
  deployManifestTemplate: (params: ManifestTemplateParams) =>
    unwrap(commands.deployManifestTemplate(params)),
  deployMeshTemplate: (params: MeshTemplateParams) =>
    unwrap(commands.deployMeshTemplate(params)),
  deployReadText: (path: string) => unwrap(commands.deployReadText(path)),
  deployWriteText: (path: string, text: string, expectedDigest: string | null) =>
    unwrap(commands.deployWriteText(path, text, expectedDigest)),
  // The deployments root (one deployment = one realm-named folder under
  // it, fixed inner layout interflow.toml/issuer/dist) — placeholders and
  // the create flow's starting folder.
  deployDefaults: () => unwrap(commands.deployDefaults()),
  // Creates a NEW manifest file (refuses an existing one — the CLI setup
  // semantic); the create-deployment dialog's write half.
  deployCreateManifest: (path: string, text: string) =>
    unwrap(commands.deployCreateManifest(path, text)),
  // Manifest form editor — the document model's read/transform pair (pure;
  // the file write stays with Save).
  deployParseManifest: (text: string) => unwrap(commands.deployParseManifest(text)),
  deployEditManifest: (text: string, action: EditActionDto) =>
    unwrap(commands.deployEditManifest(text, action)),
  deployValidate: (manifest: string) => unwrap(commands.deployValidate(manifest)),
  deployApply: (manifest: string, issuer: string, out: string) =>
    unwrap(commands.deployApply(manifest, issuer, out)),
  // The bookkeeping-level "would apply do anything" pre-check — the
  // overview's unapplied-changes badge and next-steps face.
  deployChangeState: (manifest: string, issuer: string) =>
    unwrap(commands.deployChangeState(manifest, issuer)),
  // The running hub's operator overview — Apply-result/convergence card
  // and the fleet table's online column.
  deployHubOverview: (manifest: string, issuer: string) =>
    unwrap(commands.deployHubOverview(manifest, issuer)),
  // The stream-proposal queue (the operator's approve/reject face).
  deployListProposals: (manifest: string, issuer: string) =>
    unwrap(commands.deployListProposals(manifest, issuer)),
  deployApproveProposal: (manifest: string, issuer: string, out: string, id: string) =>
    unwrap(commands.deployApproveProposal(manifest, issuer, out, id)),
  deployRejectProposal: (manifest: string, issuer: string, id: string, reason: string) =>
    unwrap(commands.deployRejectProposal(manifest, issuer, id, reason)),
  // The requester's face: submit one proposal through a running agent.
  meshSubmitProposal: (nodeId: string, request: StreamProposalRequestDto) =>
    unwrap(commands.meshSubmitProposal(nodeId, request)),
  deployListPacks: (outRoot: string) => unwrap(commands.deployListPacks(outRoot)),
  deployUpdateNode: (nodeId: string, sourceDir: string) =>
    unwrap(commands.deployUpdateNode(nodeId, sourceDir)),
  deploySealPack: (packDir: string, outFile: string, passphrase: string) =>
    unwrap(commands.deploySealPack(packDir, outFile, passphrase)),
  deployInstallSealed: (sealed: string, passphrase: string) =>
    unwrap(commands.deployInstallSealed(sealed, passphrase)),
  deployRotate: (manifest: string, issuer: string, node: string, pack: string | null) =>
    unwrap(commands.deployRotate(manifest, issuer, node, pack)),
  deployRevoke: (issuer: string, pack: string, reason: string) =>
    unwrap(commands.deployRevoke(issuer, pack, reason)),
  // Issue wizard — the `node add` + seal-with-generated-passphrase twin.
  deployAddNode: (params: IssueNodeParams) => unwrap(commands.deployAddNode(params)),
  deployGeneratePassphrase: () => unwrap(commands.deployGeneratePassphrase()),
  deploySealToDownloads: (packDir: string, passphrase: string) =>
    unwrap(commands.deploySealToDownloads(packDir, passphrase)),
  deployPrefsLoad: () => unwrap(commands.deployPrefsLoad()),
  deployPrefsSave: (recent: DeployContextDto[]) => unwrap(commands.deployPrefsSave(recent)),
  // GUI-wide preferences (interface language + the current deployment —
  // shared with the tray). The prefs object round-trips whole so a
  // language switch never drops the remembered deployment.
  guiPrefsLoad: () => unwrap(commands.guiPrefsLoad()),
  guiPrefsSave: (prefs: GuiPrefsDto) => unwrap(commands.guiPrefsSave(prefs)),
  // Deployment-as-root-object (2026-10-11 IA): discovery, the composed
  // fleet read model, and the one-click publish orchestration.
  deploymentList: () => unwrap(commands.deploymentList()),
  deploymentCurrent: () => unwrap(commands.deploymentCurrent()),
  deploymentSetCurrent: (root: string) => unwrap(commands.deploymentSetCurrent(root)),
  fleetOverview: (manifest: string, issuer: string, includeHub: boolean) =>
    unwrap(commands.fleetOverview(manifest, issuer, includeHub)),
  deploymentPublish: (
    manifest: string,
    issuer: string,
    out: string,
    manifestText: string | null,
  ) => unwrap(commands.deploymentPublish(manifestText, manifest, issuer, out)),
};

/// Listeners resolve to an unlisten fn (App keeps them for cleanup).
export function onNodeState(handler: (id: string, state: NodeStateDto) => void): Promise<() => void> {
  return events.nodeState.listen((e: Event<{ id: string; state: NodeStateDto }>) =>
    handler(e.payload.id, e.payload.state)
  );
}

/// Policy telemetry moved on a running mesh agent (engine watcher →
/// manager forwarder). The health panel patches its node's `policy` from
/// these pushes — `listNodes` stays the baseline read of the same values
export function onPolicyPlane(
  handler: (id: string, plane: PolicyPlaneDto) => void
): Promise<() => void> {
  return events.policyPlane.listen((e: Event<{ id: string; plane: PolicyPlaneDto }>) =>
    handler(e.payload.id, e.payload.plane)
  );
}

/// Peer telemetry moved on a running mesh agent (engine peer watcher →
/// manager forwarder). The Peers section patches its node's `peers` from
/// these pushes — same push-not-poll contract as `onPolicyPlane`.
export function onMeshPeers(
  handler: (id: string, peers: PeersPlaneDto) => void
): Promise<() => void> {
  return events.meshPeers.listen((e: Event<{ id: string; peers: PeersPlaneDto }>) =>
    handler(e.payload.id, e.payload.peers)
  );
}

/// Proposal receipts moved on a running mesh agent (engine watcher →
/// manager forwarder). The node detail's "Requested streams" section
/// patches its node's `proposals` from these.
export function onMeshProposals(
  handler: (id: string, proposals: ProposalReceiptDto[]) => void,
): Promise<() => void> {
  return events.meshProposals.listen(
    (e: Event<{ id: string; proposals: ProposalReceiptDto[] }>) =>
      handler(e.payload.id, e.payload.proposals),
  );
}

/// Ingress-listener actual state moved on a running mesh agent (engine
/// reconciler → manager forwarder). The node card's listener badge and the
/// detail's Health section patch their node's `listeners` from these —
/// same push-not-poll contract (the 2026-10-09 honesty axis).
export function onMeshListeners(
  handler: (id: string, listeners: ListenerStatusDto[]) => void,
): Promise<() => void> {
  return events.meshListeners.listen(
    (e: Event<{ id: string; listeners: ListenerStatusDto[] }>) =>
      handler(e.payload.id, e.payload.listeners),
  );
}

export function onLogLine(handler: (line: LogLine) => void): Promise<() => void> {
  return events.log.listen((e: Event<LogLine>) => handler(e.payload));
}

/// State wording is UI chrome — localized. The `Failed`/`Reconnecting`
/// payloads stay verbatim (engine diagnostics, shared with the logs).
export function stateText(state: NodeStateDto | null, t: TFn): string {
  if (!state) return t("state.unknown");
  if (state === "Starting") return t("state.starting");
  if (state === "Connecting") return t("state.connecting");
  if (state === "Running") return t("state.running");
  if (state === "Stopping") return t("state.stopping");
  if (state === "Stopped") return t("state.stopped");
  if (typeof state === "object") {
    if (state.Connected) return t("state.connected", { id: state.Connected.agent_id });
    if (state.Reconnecting)
      return t("state.reconnecting", {
        reason: state.Reconnecting.reason,
        secs: state.Reconnecting.backoff_secs,
      });
    if (state.Failed) return t("state.failed", { error: state.Failed.error });
  }
  return t("state.unknown");
}

/// The transport an agent node actually dials with: local preference over
/// the pack's signed default, h2 the floor — the same fold the backend's
/// `resolve_effective_transport` applies at start. An agent picks its
/// transport statically (nothing is negotiated on the wire), so once the
/// state is Connected this value IS the hub-confirmed transport form.
export function effectiveTransport(node: {
  transport: Transport | null;
  pack_transport: Transport | null;
}): Transport {
  return node.transport ?? node.pack_transport ?? "h2";
}

/// Remaining-lifetime text (mirrors identity::expiry::format_remaining —
/// one vocabulary across GUI, hub log, and doctor; deliberately NOT
/// localized, so the window, tray, and doctor agree).
export function formatRemainingSecs(secs: number): string {
  if (secs <= 0) return "expired";
  if (secs < 86400) return "<1d";
  return `${Math.floor(secs / 86400)}d`;
}

/// How long ago a unix-seconds timestamp was, for liveness faces ("42s
/// 前" / "5m 前"); 0 passes through as 0 (the caller renders "never").
export function formatAgoSecs(unix: number): string {
  if (unix <= 0) return "0s";
  const ago = Math.max(0, Math.floor(Date.now() / 1000) - unix);
  if (ago < 60) return `${ago}s`;
  if (ago < 3600) return `${Math.floor(ago / 60)}m`;
  if (ago < 86400) return `${Math.floor(ago / 3600)}h`;
  return `${Math.floor(ago / 86400)}d`;
}

/// 语义状态键——颜色的唯一词汇:success=运行/已连接,warn=过渡态与凭据
/// leaf <20%,critical=Failed 与 leaf <10%/过期,neutral=停止。hex 全部
/// 退到 theme.css 的 status 令牌(2026-10-08 视觉系统重建)。
export type StatusKey = "success" | "warn" | "critical" | "neutral";

/// The phase key for credential surfaces: warn = amber, critical = red
/// (the dirty-build visual language), null = healthy/muted. Tier thresholds
/// live engine-side (identity::expiry) — the GUI only renders the phase.
export function leafPhase(
  credential: { phase: string } | null | undefined,
): "warn" | "critical" | null {
  if (!credential) return null;
  return credential.phase === "warn" || credential.phase === "critical"
    ? credential.phase
    : null;
}

/// Same tiering for a peer's leaf phase — the colors match the node's own
/// credential face across self and peers (the same vocabulary, one source).
export function peerLeafPhase(peer: { leaf_phase: string | null }): "warn" | "critical" | null {
  return peer.leaf_phase ? leafPhase({ phase: peer.leaf_phase }) : null;
}

/// Policy inversion — the lineage-deadlock signature (contract.rs:260 is
/// the contract; `hub_generation` below the local `generation` means the
/// hub serves stale policy and every hub-published update gets rejected
/// as rollback until the watermark catches up). One predicate behind the
/// detail-page health row, the header badge, and the card/overview
/// worst-of bits — users don't visit a detail page to discover a deadlock.
export function policyInverted(policy: PolicyPlaneDto | null | undefined): boolean {
  return policy != null && policy.hub_generation != null && policy.hub_generation < policy.generation;
}

/// Listener degradation — any declared ingress rule whose listener is not
/// currently serving (`bound_addr == null`: bind failed and no previous
/// listener survived). The card-level "green card, gone listener" honesty
/// bit (the 2026-10-09 axis); the detail Health section renders the
/// per-rule faces behind it.
export function listenerDown(listeners: ListenerStatusDto[] | null | undefined): boolean {
  return listeners != null && listeners.some((l) => l.bound_addr == null);
}

export function stateStatus(state: NodeStateDto | null): StatusKey {
  if (!state || state === "Stopped") return "neutral";
  if (state === "Starting" || state === "Connecting" || state === "Stopping") return "warn";
  if (state === "Running") return "success";
  if (typeof state === "object") {
    if (state.Connected) return "success";
    if (state.Reconnecting) return "warn";
    if (state.Failed) return "critical";
  }
  return "neutral";
}

/// Anything between "user asked for start" and "user asked for stop".
export function isRunning(state: NodeStateDto | null): boolean {
  if (!state) return false;
  if (state === "Stopped") return false;
  if (state === "Starting" || state === "Connecting" || state === "Running") return true;
  return typeof state === "object" && (!!state.Connected || !!state.Reconnecting);
}

/// Short kind badge — product vocabulary, shared with the tray (never
/// localized).
export function kindLabel(kind: NodeKindDto): string {
  switch (kind) {
    case "expose_agent":
      return "Expose";
    case "mesh_agent":
      return "Mesh";
    case "hub":
      return "Hub";
    case "ingress":
      return "Ingress";
  }
}

export function kindBlurb(kind: NodeKindDto, t: TFn): string {
  switch (kind) {
    case "expose_agent":
      return t("kindBlurb.expose");
    case "mesh_agent":
      return t("kindBlurb.mesh");
    case "hub":
      return t("kindBlurb.hub");
    case "ingress":
      return t("kindBlurb.ingress");
  }
}
