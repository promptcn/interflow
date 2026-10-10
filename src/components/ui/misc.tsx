import type { HTMLAttributes, ReactNode } from "react";
import * as SeparatorPrimitive from "@radix-ui/react-separator";
import { cn } from "../../lib/utils";

/// The nothing-to-see surface: centered, quiet, never a dead end (call
/// sites pair it with the add-card or a task entry).
export function EmptyState({ className, children }: { className?: string; children: ReactNode }) {
  return (
    <div
      className={cn(
        "flex flex-1 items-center justify-center p-6 text-center text-base text-fg-3",
        className,
      )}
    >
      {children}
    </div>
  );
}

/// Keyboard affordance (the "Esc" chips on back buttons).
export function Kbd({ className, ...props }: HTMLAttributes<HTMLElement>) {
  return (
    <kbd
      className={cn(
        "inline-flex h-5 min-w-5 items-center justify-center rounded border border-line bg-bg-3 px-1 font-mono text-micro text-fg-2",
        className,
      )}
      {...props}
    />
  );
}

export function Separator({
  className,
  orientation = "horizontal",
}: {
  className?: string;
  orientation?: "horizontal" | "vertical";
}) {
  return (
    <SeparatorPrimitive.Root
      orientation={orientation}
      className={cn(
        "shrink-0 bg-line",
        orientation === "horizontal" ? "h-px w-full" : "h-full w-px",
        className,
      )}
    />
  );
}
