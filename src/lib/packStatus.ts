import { type DeployPackDto } from "../api";

/// How a pack relates to the pack the local node actually runs — the
/// single rule behind every update button. Generations move forward
/// only: a lower generation is a downgrade no matter what the digest
/// says (superseded staging and historical archives would otherwise
/// light up "Update" and one click would install older — possibly
/// revoked — material; (internal design notes)).
/// A same-generation digest difference stays actionable: a re-applied
/// manifest re-renders the SAME generation with different content
/// (e.g. an h2→QUIC transport switch), which only the digest catches.
export type PackUpdateAction =
  /// No local node for this pack's identity — nothing to update.
  | "none"
  /// The pack's generation is higher: the forward update.
  | "upgrade"
  /// Same generation, different digest: the content refresh.
  | "content"
  /// Same generation, same digest: a reinstall is the recovery path
  /// for a damaged install.
  | "reinstall"
  /// The pack's generation is LOWER than what the node runs: no button
  /// ever installs it. Deliberate rollbacks go through the CLI.
  | "downgrade";

export function packUpdateAction(pack: DeployPackDto): PackUpdateAction {
  const local = pack.local_node;
  if (!local) return "none";
  if (local.generation < pack.generation) return "upgrade";
  if (local.generation === pack.generation) {
    return local.digest === pack.digest ? "reinstall" : "content";
  }
  return "downgrade";
}

/// One identity's live truth for the Packs overview: the card IS the
/// identity, not the directory. `current` is the canonical base pack; the
/// `window` is the one live distribution surface — rotate's newest staging
/// that is strictly ahead of the base AND not yet consumed by the local
/// node. Everything else (consumed or superseded staging, `.previous`
/// archives) is history and never surfaces here; the filesystem stays its
/// archive. This is the view-side half of the staging-window lifecycle the
/// engine closes at rotate, full-render apply and local consumption.
export interface PackIdentity {
  principal: string;
  /// The identity's canonical directory — the base pack; the newest
  /// staging stands in when the base is absent (a hand-moved tree still
  /// deserves a card).
  current: DeployPackDto;
  /// The open distribution window, newest first: null when every staging is
  /// consumed or superseded — the steady state of a healthy identity.
  window: DeployPackDto | null;
}

export function packIdentities(packs: DeployPackDto[]): PackIdentity[] {
  const byPrincipal = new Map<string, DeployPackDto[]>();
  for (const pack of packs) {
    const list = byPrincipal.get(pack.principal) ?? [];
    list.push(pack);
    byPrincipal.set(pack.principal, list);
  }
  return [...byPrincipal.entries()]
    .map(([principal, list]) => {
      const stagings = list
        .filter((p) => p.is_staging)
        .sort((a, b) => b.generation - a.generation);
      const current = list.find((p) => !p.is_staging) ?? stagings[0];
      // The window predicate absorbs the old ready/consumed split: a
      // staging surfaces only while it carries material the base lacks AND
      // the local node has not installed yet. `local_node` is joined by the
      // backend on principal, so every member agrees.
      const local = current.local_node;
      const window =
        stagings.find(
          (s) =>
            s.generation > current.generation &&
            (!local || local.generation < s.generation),
        ) ?? null;
      return { principal, current, window };
    })
    .sort((a, b) => a.current.node.localeCompare(b.current.node));
}

/// The pack an identity's "update local node" action installs: the window
/// when open (its generation is the actionable one), else the current pack
/// (same-generation content refresh or reinstall recovery).
export function packUpdateSource(identity: PackIdentity): DeployPackDto {
  return identity.window ?? identity.current;
}

/// The pack the distribution actions (seal / copy install command) ship:
/// the open window's fresh generation when there is one, else the current
/// material.
export function packDistributeSource(identity: PackIdentity): DeployPackDto {
  return identity.window ?? identity.current;
}
