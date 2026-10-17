import type { ComponentPropsWithoutRef } from "react";
import * as PopoverPrimitive from "@radix-ui/react-popover";
import { cn } from "../../lib/utils";

/// Anchored popup for chrome-adjacent details (the sidebar's build
/// identity): opens next to its trigger and dismisses on outside click
/// or Esc. Dialog owns the modal path; this owns the "something small
/// beside where you clicked" path.
export const Popover = PopoverPrimitive.Root;
export const PopoverTrigger = PopoverPrimitive.Trigger;

export function PopoverContent({
  className,
  side = "right",
  align = "center",
  sideOffset = 6,
  children,
  ...props
}: ComponentPropsWithoutRef<typeof PopoverPrimitive.Content>) {
  return (
    <PopoverPrimitive.Portal>
      <PopoverPrimitive.Content
        side={side}
        align={align}
        sideOffset={sideOffset}
        className={cn(
          "z-50 rounded-lg border border-line bg-bg-2 p-3 text-base text-fg-1 shadow-elevate-3",
          "data-[state=open]:animate-in data-[state=open]:fade-in-0 data-[state=open]:zoom-in-95 duration-100",
          className,
        )}
        {...props}
      >
        {children}
      </PopoverPrimitive.Content>
    </PopoverPrimitive.Portal>
  );
}
