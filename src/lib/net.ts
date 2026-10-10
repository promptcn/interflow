/// Strict loopback `<ip>:<port>` parse (127.x.x.x:port or [::1]:port) —
/// the same shape the engine's default-deny policy will dial; the backend
/// re-validates, this is the fail-fast hint. (Was three verbatim copies in
/// NodeDetail / ProposalDialog / StreamDialog.)
export function parseLoopbackAddr(value: string): string | null {
  const trimmed = value.trim();
  let m = /^\[([0-9a-fA-F:]+)\]:(\d+)$/.exec(trimmed);
  if (m) {
    if (m[1].toLowerCase() !== "::1") return null;
    const port = Number(m[2]);
    return port >= 1 && port <= 65535 ? `[::1]:${port}` : null;
  }
  m = /^(127\.\d{1,3}\.\d{1,3}\.\d{1,3}):(\d+)$/.exec(trimmed);
  if (m) {
    const port = Number(m[2]);
    return port >= 1 && port <= 65535 ? `${m[1]}:${port}` : null;
  }
  return null;
}
