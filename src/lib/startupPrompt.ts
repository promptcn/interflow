import { isRunning, type NodeInfo } from "../api";

/// The startup "all stopped" prompt rule (the B fallback of
/// (internal design notes)): offer one
/// non-blocking "start them?" when the GUI comes up and every node entry
/// sits stopped with NO start intent anywhere — the residue the intent
/// restore (shutdown_all preserving desired_running) cannot decide: prefs
/// written by the old quit-wipes-intent builds, or deliberate stops that
/// outlived a reinstall.
///
/// The `desired_running` guard is what makes the check race-free at mount:
/// a node about to be auto-started may still read Stopped for a moment,
/// but its intent flag is already true, so the prompt stays silent — the
/// restore is on it.
export function shouldPromptStartAll(nodes: NodeInfo[]): boolean {
  if (nodes.length === 0) return false;
  if (nodes.some((n) => n.desired_running)) return false;
  return nodes.every((n) => !isRunning(n.state));
}
