import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { dismissedNotices, dismissNotice, visibleNotices } from "./startupNotices";

/// The suite runs in the node environment (no jsdom) — a Map-backed
/// localStorage stub exercises the module's real storage path.
beforeEach(() => {
  const store = new Map<string, string>();
  vi.stubGlobal(
    "localStorage",
    {
      getItem: (key: string) => (store.has(key) ? (store.get(key) as string) : null),
      setItem: (key: string, value: string) => void store.set(key, value),
      removeItem: (key: string) => void store.delete(key),
      clear: () => store.clear(),
    } satisfies Storage,
  );
});
afterEach(() => {
  vi.unstubAllGlobals();
});

/// The notice ledger: an id dismissed once stays hidden; a NEW era's id
/// (the epoch suffix changed) shows again — each retirement notifies
/// exactly once per machine.
describe("startup notice dismissal", () => {
  it("hides dismissed ids and keeps undismissed ones visible", () => {
    const notices = [
      { id: "prefs-retired@3", kind: "prefs_retired" as const },
      { id: "deployment-gone@3", kind: "deployment_gone" as const },
    ];
    const visible = visibleNotices(notices, ["prefs-retired@3"]);
    expect(visible.map((n) => n.id)).toEqual(["deployment-gone@3"]);
  });

  it("a new era re-arms the narrative even for the same kind", () => {
    const dismissed = ["prefs-retired@3"];
    const nextEra = [{ id: "prefs-retired@4", kind: "prefs_retired" as const }];
    expect(visibleNotices(nextEra, dismissed)).toHaveLength(1);
  });
});

describe("startup notice storage", () => {
  it("round-trips a dismissal and tolerates a corrupt store", () => {
    localStorage.clear();
    expect(dismissedNotices()).toEqual([]);
    dismissNotice("prefs-retired@3");
    dismissNotice("prefs-retired@3"); // idempotent
    expect(dismissedNotices()).toEqual(["prefs-retired@3"]);

    localStorage.setItem("interflow.startup-notices-dismissed", "{not json");
    expect(dismissedNotices()).toEqual([]);
    dismissNotice("deployment-gone@3"); // recovers by rewriting
    expect(dismissedNotices()).toEqual(["deployment-gone@3"]);
  });
});
