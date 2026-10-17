/// The 流 row's pure face-derivations (the fleetRows discipline): the
/// status word's dot/text vocabulary, the idle-timeout default the
/// engine applies when the manifest leaves the key out, and the drawer's
/// target-end cross-link join. Pure on purpose — testable without a
/// Tauri app, rendered as-is by StreamsView and StreamDrawer
/// (the 2026-10-16 streams row language).

import type { MeshProtocolDto, NodeKindDto, StreamStatusDto, StatusKey } from "../api";

/// A stream status → the shared status vocabulary. `unknown` maps to
/// null — StatusKeyDot's hollow circle, "no source can observe this": a
/// statement, never a guessed color.
export function streamStatusKey(status: StreamStatusDto): StatusKey | null {
  switch (status) {
    case "serving":
      return "success";
    case "down":
      return "critical";
    case "catching_up":
      return "warn";
    default:
      return null;
  }
}

/// The status word's i18n key — one mapping shared by the row and the
/// drawer, so the two surfaces can never call one status different
/// names.
export const streamStatusWordKey = {
  serving: "dep.streams.status.serving",
  down: "dep.streams.status.down",
  catching_up: "dep.streams.status.catchingUp",
  unknown: "dep.streams.status.unknown",
} as const;

/// The idle timeout the engine applies when the manifest leaves the key
/// out — the per-protocol runtime defaults (mesh's agent config: tcp
/// 5 min, udp 1 min). The drawer shows it as the 默认 value; a declared
/// value always wins.
export function idleTimeoutDefault(protocol: MeshProtocolDto): number {
  return protocol === "tcp" ? 300 : 60;
}

/// The local NodeManager id of the TARGET agent, when it runs on this
/// machine — the drawer's 对端 cross-link (dead-end #10's "both ends":
/// the source link lives in the row, the target link here). Structural
/// on purpose so tests need no full FleetDto.
export function targetLocalNodeId(
  fleet: { nodes: { kind: NodeKindDto; name: string; local?: { id: string } | null }[] },
  targetAgent: string,
): string | null {
  const row = fleet.nodes.find(
    (n) => (n.kind === "mesh_agent" || n.kind === "expose_agent") && n.name === targetAgent,
  );
  return row?.local?.id ?? null;
}
