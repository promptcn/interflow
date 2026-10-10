import * as SelectPrimitive from "@radix-ui/react-select";
import { Check, ChevronDown } from "lucide-react";
import { cn } from "../../lib/utils";

export type SelectOption = { value: string; label: string };

/// The one select — replaces every native <select> (protocol pickers,
/// workspace/transport pickers, recent contexts). Popover menu on
/// elevate-3, check column left, trigger width respected. Radix rejects
/// empty-string item values, so guard them at the boundary.
export function Select({
  value,
  onValueChange,
  options,
  placeholder,
  ariaLabel,
  title,
  id,
  disabled = false,
  className,
}: {
  value: string;
  onValueChange: (value: string) => void;
  options: SelectOption[];
  placeholder?: string;
  ariaLabel?: string;
  title?: string;
  id?: string;
  disabled?: boolean;
  className?: string;
}) {
  return (
    <SelectPrimitive.Root value={value} onValueChange={onValueChange} disabled={disabled}>
      <SelectPrimitive.Trigger
        id={id}
        aria-label={ariaLabel}
        title={title}
        className={cn(
          "inline-flex min-h-control w-full min-w-0 items-center justify-between gap-2 rounded-lg border border-line bg-bg-2 px-3 text-base text-fg-1",
          "transition-colors duration-150 outline-none hover:border-line-strong",
          "focus-visible:border-accent focus-visible:ring-[3px] focus-visible:ring-accent-tint",
          "data-[placeholder]:text-fg-3 disabled:opacity-50",
          className,
        )}
      >
        <SelectPrimitive.Value placeholder={placeholder ?? ""} />
        <SelectPrimitive.Icon>
          <ChevronDown className="size-4 shrink-0 text-fg-3" />
        </SelectPrimitive.Icon>
      </SelectPrimitive.Trigger>
      <SelectPrimitive.Portal>
        <SelectPrimitive.Content
          position="popper"
          sideOffset={4}
          className={cn(
            "z-50 max-h-[320px] min-w-[var(--radix-select-trigger-width)] overflow-hidden rounded-lg border border-line bg-bg-2 shadow-elevate-3",
            "data-[state=open]:animate-in data-[state=open]:fade-in-0 data-[state=open]:zoom-in-95 data-[state=closed]:animate-out data-[state=closed]:fade-out-0 duration-150",
          )}
        >
          <SelectPrimitive.Viewport className="p-1">
            {options
              .filter((o) => o.value !== "")
              .map((o) => (
                <SelectPrimitive.Item
                  key={o.value}
                  value={o.value}
                  className={cn(
                    "flex min-h-control-sm cursor-pointer select-none items-center gap-2 rounded-md px-2 text-base text-fg-1 outline-none",
                    "transition-colors duration-100 data-[highlighted]:bg-bg-hover data-[state=checked]:text-accent",
                  )}
                >
                  <span className="flex w-4 shrink-0 items-center">
                    <SelectPrimitive.ItemIndicator>
                      <Check className="size-4 text-accent" />
                    </SelectPrimitive.ItemIndicator>
                  </span>
                  <SelectPrimitive.ItemText>{o.label}</SelectPrimitive.ItemText>
                </SelectPrimitive.Item>
              ))}
          </SelectPrimitive.Viewport>
        </SelectPrimitive.Content>
      </SelectPrimitive.Portal>
    </SelectPrimitive.Root>
  );
}
