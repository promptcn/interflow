// Tauri API wrapper over the generated IPC contract.
//
// `./bindings` is generated from src-tauri/src/contract.rs via tauri-specta
// (`npm run gen:bindings`) — the single source of truth. Never hand-write a
// type in this file that mirrors a Rust struct; extend the Rust contract and
// regenerate instead (the 2026-09-18 auth_token drift is why this exists).

import { commands, events } from "./bindings";
import type { Event } from "@tauri-apps/api/event";
import type { LogLine, Profile, TunnelConfig, TunnelState } from "./bindings";

export type { LogLine, Profile, Transport, TunnelConfig, TunnelState } from "./bindings";

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
  loadProfile: () => unwrap(commands.loadProfile()),
  saveProfile: (profile: Profile) => unwrap(commands.saveProfile(profile)),
  generateAgentId: () => commands.generateAgentId(),
  startTunnel: (config: TunnelConfig) => unwrap(commands.startTunnel(config)),
  stopTunnel: () => unwrap(commands.stopTunnel()),
  getState: () => unwrap(commands.getState()),
  getRecentLogs: () => unwrap(commands.getRecentLogs()),
  clearLogs: () => unwrap(commands.clearLogs()),
};

/// Both listeners resolve to an unlisten fn (App keeps them for cleanup).
export function onTunnelState(handler: (state: TunnelState) => void): Promise<() => void> {
  return events.tunnelState.listen((e: Event<TunnelState>) => handler(e.payload));
}

export function onLogLine(handler: (line: LogLine) => void): Promise<() => void> {
  return events.log.listen((e: Event<LogLine>) => handler(e.payload));
}

export function stateText(state: TunnelState | null): string {
  if (!state) return "Unknown";
  if (state === "Connecting") return "Connecting…";
  if (state === "Stopped") return "Stopped";
  if (typeof state === "object") {
    if (state.Connected) return `Connected (${state.Connected.agent_id})`;
    if (state.Reconnecting) return `Reconnecting (${state.Reconnecting.reason}, retrying in ${state.Reconnecting.backoff_secs}s)`;
    if (state.Failed) return `Failed: ${state.Failed.error}`;
  }
  return "Unknown";
}

export function stateColor(state: TunnelState | null): string {
  if (!state || state === "Stopped") return "#787878";
  if (state === "Connecting") return "#ffcc00";
  if (typeof state === "object") {
    if (state.Connected) return "#34c759";
    if (state.Reconnecting) return "#ffcc00";
    if (state.Failed) return "#ff453a";
  }
  return "#787878";
}

export function isRunning(state: TunnelState | null): boolean {
  return state === "Connecting" || (typeof state === "object" && state !== null && (!!state.Connected || !!state.Reconnecting));
}
