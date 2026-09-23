// Tauri API wrapper over the generated IPC contract.
//
// `./bindings` is generated from src-tauri/src/contract.rs via tauri-specta
// (`npm run gen:bindings`) — the single source of truth. Never hand-write a
// type in this file that mirrors a Rust struct; extend the Rust contract and
// regenerate instead (the 2026-09-18 auth_token drift is why this exists).

import { commands, events } from "./bindings";
import type { Event } from "@tauri-apps/api/event";
import type {
  AddNodeParams,
  LogLine,
  ManifestTemplateParams,
  NodeKindDto,
  NodePrefs,
  NodeStateDto,
} from "./bindings";

export type {
  AddNodeParams,
  DeployPackDto,
  ImportedPackDto,
  LogLine,
  ManifestTemplateParams,
  MeshEgressRuleDto,
  MeshIngressRuleDto,
  MeshProtocolDto,
  NodeInfo,
  NodeKindDto,
  NodePrefs,
  NodeStateDto,
  PackInspection,
  Transport,
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
  // Deploy (operator) surface — the plan/rotate/revoke/pack twins.
  deployManifestTemplate: (params: ManifestTemplateParams) =>
    unwrap(commands.deployManifestTemplate(params)),
  deployReadText: (path: string) => unwrap(commands.deployReadText(path)),
  deployWriteText: (path: string, text: string) =>
    unwrap(commands.deployWriteText(path, text)),
  deployValidate: (manifest: string) => unwrap(commands.deployValidate(manifest)),
  deployApply: (manifest: string, issuer: string, out: string) =>
    unwrap(commands.deployApply(manifest, issuer, out)),
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
};

/// Both listeners resolve to an unlisten fn (App keeps them for cleanup).
export function onNodeState(handler: (id: string, state: NodeStateDto) => void): Promise<() => void> {
  return events.nodeState.listen((e: Event<{ id: string; state: NodeStateDto }>) =>
    handler(e.payload.id, e.payload.state)
  );
}

export function onLogLine(handler: (line: LogLine) => void): Promise<() => void> {
  return events.log.listen((e: Event<LogLine>) => handler(e.payload));
}

export function stateText(state: NodeStateDto | null): string {
  if (!state) return "Unknown";
  if (state === "Starting") return "Starting…";
  if (state === "Connecting") return "Connecting…";
  if (state === "Running") return "Running";
  if (state === "Stopping") return "Stopping…";
  if (state === "Stopped") return "Stopped";
  if (typeof state === "object") {
    if (state.Connected) return `Connected (${state.Connected.agent_id})`;
    if (state.Reconnecting)
      return `Reconnecting (${state.Reconnecting.reason}, retrying in ${state.Reconnecting.backoff_secs}s)`;
    if (state.Failed) return `Failed: ${state.Failed.error}`;
  }
  return "Unknown";
}

export function stateColor(state: NodeStateDto | null): string {
  if (!state || state === "Stopped") return "#787878";
  if (state === "Starting" || state === "Connecting" || state === "Stopping") return "#ffcc00";
  if (state === "Running") return "#34c759";
  if (typeof state === "object") {
    if (state.Connected) return "#34c759";
    if (state.Reconnecting) return "#ffcc00";
    if (state.Failed) return "#ff453a";
  }
  return "#787878";
}

/// Anything between "user asked for start" and "user asked for stop".
export function isRunning(state: NodeStateDto | null): boolean {
  if (!state) return false;
  if (state === "Stopped") return false;
  if (state === "Starting" || state === "Connecting" || state === "Running") return true;
  return typeof state === "object" && (!!state.Connected || !!state.Reconnecting);
}

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

export function kindBlurb(kind: NodeKindDto): string {
  switch (kind) {
    case "expose_agent":
      return "exposes local services under a public domain";
    case "mesh_agent":
      return "site-to-site mesh endpoint";
    case "hub":
      return "site-to-site relay between networks";
    case "ingress":
      return "public entry point for expose routes";
  }
}
