import { clsx, type ClassValue } from "clsx";
import { twMerge } from "tailwind-merge";

/// The one class combiner: clsx semantics + Tailwind conflict resolution
/// (later utilities win). Every primitive and call site composes through
/// this — no ad-hoc template strings.
export function cn(...inputs: ClassValue[]): string {
  return twMerge(clsx(inputs));
}
