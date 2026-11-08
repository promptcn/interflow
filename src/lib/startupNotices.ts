/// Startup-notice dismissal — the "narrate once" half of the retirement
/// narrative.
/// Notice ids are stable and epoch-suffixed (produced backend-side), so a
/// dismissal keyed on the id shows each era's retirement exactly once and
/// automatically re-arms when a FUTURE era retires something else.
/// localStorage is the store (the same side-car the sidebar collapse and
/// the 🔒 realm scope use): a prefs db this build cannot read cannot be
/// asked to remember that it was scolded about being unreadable.

const STORE_KEY = "interflow.startup-notices-dismissed";

export function dismissedNotices(): string[] {
  try {
    const raw = localStorage.getItem(STORE_KEY);
    const parsed = raw === null ? [] : (JSON.parse(raw) as unknown);
    return Array.isArray(parsed) ? parsed.filter((id): id is string => typeof id === "string") : [];
  } catch {
    return [];
  }
}

/// The notices still owed to this machine: not yet dismissed.
export function visibleNotices<T extends { id: string }>(all: T[], dismissed: string[]): T[] {
  return all.filter((notice) => !dismissed.includes(notice.id));
}

export function dismissNotice(id: string): void {
  const next = [...new Set([...dismissedNotices(), id])];
  try {
    localStorage.setItem(STORE_KEY, JSON.stringify(next));
  } catch {
    // A full or blocked store only means the banner shows again next
    // launch — never worth failing the shell over.
  }
}
