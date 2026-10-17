import type { ComponentPropsWithoutRef } from "react";
import * as MenuPrimitive from "@radix-ui/react-dropdown-menu";
import { cn } from "../../lib/utils";

/// The overflow menu — the row-actions idiom's "the rest" home (the
/// 2026-10-16 streams row language ruling): one primary action stays
/// inline per row; low-frequency and destructive operations live here
/// with TEXT labels — more discoverable than an icon that only a title
/// explains. Typeahead, arrow keys, focus trap and Esc are Radix's, the
/// same contract every other primitive here gets from it.
export const Menu = MenuPrimitive.Root;
export const MenuTrigger = MenuPrimitive.Trigger;

export function MenuContent({
  className,
  side = "bottom",
  align = "end",
  sideOffset = 4,
  children,
  ...props
}: ComponentPropsWithoutRef<typeof MenuPrimitive.Content>) {
  return (
    <MenuPrimitive.Portal>
      <MenuPrimitive.Content
        side={side}
        align={align}
        sideOffset={sideOffset}
        className={cn(
          "z-50 min-w-[10rem] rounded-lg border border-line bg-bg-2 p-1 text-base text-fg-1 shadow-elevate-3",
          "data-[state=open]:animate-in data-[state=open]:fade-in-0 data-[state=open]:zoom-in-95 duration-100",
          className,
        )}
        {...props}
      >
        {children}
      </MenuPrimitive.Content>
    </MenuPrimitive.Portal>
  );
}

/// One action. `danger` = destructive — the critical word with a tinted
/// highlight instead of the neutral hover gray.
export function MenuItem({
  className,
  danger = false,
  ...props
}: ComponentPropsWithoutRef<typeof MenuPrimitive.Item> & { danger?: boolean }) {
  return (
    <MenuPrimitive.Item
      className={cn(
        "flex min-h-control-sm cursor-pointer select-none items-center gap-2 rounded-md px-2.5 text-small outline-none",
        danger
          ? "text-critical data-[highlighted]:bg-critical/10"
          : "text-fg-1 data-[highlighted]:bg-bg-hover",
        "data-[disabled]:pointer-events-none data-[disabled]:opacity-50",
        className,
      )}
      {...props}
    />
  );
}

export function MenuSeparator({
  className,
  ...props
}: ComponentPropsWithoutRef<typeof MenuPrimitive.Separator>) {
  return (
    <MenuPrimitive.Separator className={cn("-mx-1 my-1 h-px bg-line", className)} {...props} />
  );
}
