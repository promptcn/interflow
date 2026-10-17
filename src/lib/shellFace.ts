/// The realm-axis shell (2026-10-15 nav re-axis): the deployment (realm)
/// is the OBJECT the sidebar is organized by; this machine is only the
/// observation position, demoted to a bottom entry. A scope is either an
/// open deployment (writable: 总览/编队/流/服务/高级) or a 🔒 realm
/// inferred from local packs (read-only: 编队 only). The 本机 entry is
/// unconditional — local nodes are a fact, deployment or none, and the
/// onboarding speaks only where there is nothing else.

/// The realm segment of a signed principal (`realm/workspace/kind/node`).
/// Sealed imports always carry one — identity is the pack's own truth, so
/// a node never needs a deployment tree to be nameable. `null` for
/// placeholder nodes (unreadable pack at restore) — they show no realm.
export function principalRealm(
  principal: string | null | undefined,
): string | null {
  const realm = principal?.split("/")[0];
  return realm ? realm : null;
}

/// The realms this machine carries mesh identities in: the pack
/// principals of its mesh agents, deduped and name-sorted. This is the
/// leg machine's realm inference — a machine without any deployment tree
/// still names the realms it belongs to, because identity is the pack's
/// own truth. Only mesh agents qualify: expose agents have no fleet face,
/// and a local hub's presence says nothing about which realm's fleet this
/// machine may observe.
export function meshRealms(
  nodes: { kind: string; principal: string | null }[],
): string[] {
  const realms = new Set<string>();
  for (const n of nodes) {
    if (n.kind !== "mesh_agent") continue;
    const realm = principalRealm(n.principal);
    if (realm !== null) realms.add(realm);
  }
  return [...realms].sort();
}

/// The create-deployment entry is onboarding guidance: it belongs to the
/// true new operator (zero deployments, zero nodes) and to machines that
/// already operate deployments. The one form that must never see it is a
/// deployed-end machine — nodes on board, no deployment tree; popping
/// "create a deployment" there is exactly the wrong-direction guidance.
export function createEntryVisible(
  deploymentsFound: boolean,
  hasNodes: boolean,
): boolean {
  return deploymentsFound || !hasNodes;
}

export type ShellFace =
  | "loading"
  /// Zero deployments, zero nodes, no scope — the only form the
  /// onboarding owns.
  | "onboarding"
  /// No scope open, nodes on board — the 本机 entry's view (a complete
  /// view, not a waiting room).
  | "localView"
  /// A scope is open (deployment or 🔒 realm) — the scope's views, the
  /// 本机 entry still reachable in the sidebar.
  | "scopeViews";

/// What the shell's content area shows. The node list gates the
/// no-scope branch, so `nodesLoaded` must be true before the onboarding
/// may claim the shell — a deployed-end machine flashing onboarding while
/// its nodes load is the bug this ordering prevents.
export function shellFace(opts: {
  depLoading: boolean;
  nodesLoaded: boolean;
  scopeOpen: boolean;
  nodeCount: number;
}): ShellFace {
  if (opts.scopeOpen) return "scopeViews";
  if (opts.depLoading || !opts.nodesLoaded) return "loading";
  return opts.nodeCount === 0 ? "onboarding" : "localView";
}
