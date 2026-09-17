// Tauri API wrapper: types aligned with the Rust-side serde definitions.

/// Transport toward the hub (serialized form of the Rust `TransportKind`).
export type Transport = "h2" | "quic";

export interface Profile {
  hub_url: string | null;
  auth_token: string | null;
  agent_id: string | null;
  ca_path: string | null;
  local_ports?: number[] | null;
  transport?: Transport | null;
  hub_quic_addr?: string | null;
}

export interface TunnelConfig {
  local_ports: number[];
  hub_url: string;
  auth_token: string;
  agent_id: string;
  ca_path: string | null;
  transport?: Transport | null;
  hub_quic_addr?: string | null;
}

export type TunnelState =
  | "Connecting"
  | { Connected: { agent_id: string } }
  | { Reconnecting: { reason: string; backoff_secs: number } }
  | "Stopped"
  | { Failed: { error: string } };

export interface LogLine {
  ts: string;
  level: string;
  target: string;
  message: string;
}

const invoker = async <T>(cmd: string, args?: Record<string, unknown>): Promise<T> => {
  const { invoke } = await import("@tauri-apps/api/core");
  return invoke<T>(cmd, args);
};

export const api = {
  loadProfile: () => invoker<Profile>("load_profile"),
  saveProfile: (profile: Profile) => invoker<void>("save_profile", { profile }),
  generateAgentId: () => invoker<string>("generate_agent_id"),
  startTunnel: (config: TunnelConfig) => invoker<void>("start_tunnel", { config }),
  stopTunnel: () => invoker<void>("stop_tunnel"),
  getState: () => invoker<TunnelState>("get_state"),
  getRecentLogs: () => invoker<LogLine[]>("get_recent_logs"),
};

export async function listenEvent<T>(event: string, handler: (payload: T) => void): Promise<() => void> {
  const { listen } = await import("@tauri-apps/api/event");
  const unlisten = await listen<T>(event, (e) => handler(e.payload));
  return unlisten;
}

export function stateText(state: TunnelState | null): string {
  if (!state) return "Unknown";
  if (state === "Connecting") return "Connecting…";
  if (state === "Stopped") return "Stopped";
  if (typeof state === "object") {
    if ("Connected" in state) return `Connected (${state.Connected.agent_id})`;
    if ("Reconnecting" in state) return `Reconnecting (${state.Reconnecting.reason}, retrying in ${state.Reconnecting.backoff_secs}s)`;
    if ("Failed" in state) return `Failed: ${state.Failed.error}`;
  }
  return "Unknown";
}

export function stateColor(state: TunnelState | null): string {
  if (!state || state === "Stopped") return "#787878";
  if (state === "Connecting") return "#ffcc00";
  if (typeof state === "object") {
    if ("Connected" in state) return "#34c759";
    if ("Reconnecting" in state) return "#ffcc00";
    if ("Failed" in state) return "#ff453a";
  }
  return "#787878";
}

export function isRunning(state: TunnelState | null): boolean {
  return state === "Connecting" || (typeof state === "object" && state !== null && ("Connected" in state || "Reconnecting" in state));
}
