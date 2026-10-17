import { stateStatus, type NodeStateDto, type StatusKey } from "../../api";
import { cn } from "../../lib/utils";

/// Semantic status → utility class maps. Static strings so Tailwind's
/// scanner sees every class — dynamic class names are forbidden.
export const statusDotClass: Record<StatusKey, string> = {
  success: "bg-success",
  warn: "bg-warn",
  critical: "bg-critical",
  neutral: "bg-neutral",
};

export const statusTextClass: Record<StatusKey, string> = {
  success: "text-success",
  warn: "text-warn",
  critical: "text-critical",
  neutral: "text-neutral",
};

/// The presence/status dot. Transitional states (warn) breathe with a
/// subtle pulse; settled states are steady. Color is never the only
/// signal — call sites pair it with text (or sr-only text).
export function StateDot({
  state,
  size = "sm",
  className,
}: {
  state: NodeStateDto;
  size?: "sm" | "md";
  className?: string;
}) {
  const key = stateStatus(state);
  return (
    <span
      aria-hidden
      className={cn(
        "inline-block shrink-0 rounded-full",
        size === "sm" ? "size-2.5" : "size-3",
        statusDotClass[key],
        key === "warn" && "animate-pulse",
        className,
      )}
    />
  );
}

/// Same dot language for presence: online = the green a connected node
/// speaks, offline = the gray of a stopped one, unknown (null) = a
/// hollow circle — no source can see the member, a statement rather
/// than a failure to color.
export function PeerDot({ online }: { online: boolean | null }) {
  return (
    <span
      aria-hidden
      className={cn(
        "inline-block size-2.5 shrink-0 self-center rounded-full",
        online === null ? "border-2 border-fg-3" : online ? "bg-success" : "bg-neutral",
      )}
    />
  );
}

/// The dot for statuses already normalized to a `StatusKey` — the same
/// vocabulary `StateDot` speaks, for faces that carry no NodeStateDto (a
/// stream's four states). `null` = the honest-unknown hollow circle
/// (PeerDot's "a statement, not a failure to color"): no source can
/// observe the thing, so no color is claimed.
export function StatusKeyDot({ status, className }: { status: StatusKey | null; className?: string }) {
  return (
    <span
      aria-hidden
      className={cn(
        "inline-block size-2.5 shrink-0 self-center rounded-full",
        status === null ? "border-2 border-fg-3" : statusDotClass[status],
        status === "warn" && "animate-pulse",
        className,
      )}
    />
  );
}
