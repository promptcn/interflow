import type { ReactElement } from "react";
import * as TooltipPrimitive from "@radix-ui/react-tooltip";
import { Info } from "lucide-react";
import { cn } from "../../lib/utils";

/// One TooltipProvider at the app root; Hint wraps any single trigger
/// element and replaces the load-bearing native `title` tooltips (they
/// carried pack defaults, state text, the Esc hint). Focus shows it too,
/// which native titles never did.
export function TooltipProvider({ children }: { children: ReactElement }) {
  return (
    <TooltipPrimitive.Provider delayDuration={250} skipDelayDuration={120}>
      {children}
    </TooltipPrimitive.Provider>
  );
}

export function Hint({
  text,
  children,
  side = "top",
}: {
  text: string;
  children: ReactElement;
  side?: "top" | "bottom" | "left" | "right";
}) {
  return (
    <TooltipPrimitive.Root>
      <TooltipPrimitive.Trigger asChild>{children}</TooltipPrimitive.Trigger>
      <TooltipPrimitive.Portal>
        <TooltipPrimitive.Content
          side={side}
          sideOffset={6}
          className={cn(
            "z-50 max-w-[340px] rounded-lg border border-line bg-bg-2 px-2.5 py-1.5 text-small text-fg-1 shadow-elevate-3",
            "data-[state=delayed-open]:animate-in data-[state=delayed-open]:fade-in-0 data-[state=delayed-open]:zoom-in-95 duration-100",
          )}
        >
          {text}
        </TooltipPrimitive.Content>
      </TooltipPrimitive.Portal>
    </TooltipPrimitive.Root>
  );
}

/// The ⓘ affordance: one-line concept explanations ride its hover/focus
/// instead of being permanent chrome — shared by SectionPanel heads and
/// dialog titles (the density pass's rule for explanatory copy).
export function InfoHint({
  text,
  className,
}: {
  text: string;
  className?: string;
}) {
  return (
    <Hint text={text}>
      <button
        type="button"
        aria-label={text}
        className={cn(
          "inline-flex shrink-0 items-center rounded-sm p-0.5 text-fg-3 transition-colors hover:text-fg-2",
          className,
        )}
      >
        <Info size={13} />
      </button>
    </Hint>
  );
}
