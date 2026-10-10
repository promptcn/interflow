import * as ToggleGroupPrimitive from "@radix-ui/react-toggle-group";
import { cn } from "../../lib/utils";

/// One mutually-exclusive picker — the single widget behind the face
/// switch, deploy nav, manifest views, log scope, transport and kind
/// pickers. Radix ToggleGroup brings the radiogroup-adjacent semantics
/// (roving focus, arrow keys) the hand-rolled version lacked.
///
/// Selection language: accent-tinted chip on the elevated bg-2 — "选中 =
/// 蓝" belongs to the accent vocabulary; solid accent stays for actions.
export function SegmentedControl<T extends string>({
  value,
  options,
  onChange,
  disabled = false,
  className = "",
}: {
  value: T;
  options: { value: T; label: string; title?: string }[];
  onChange: (value: T) => void;
  disabled?: boolean;
  className?: string;
}) {
  return (
    <ToggleGroupPrimitive.Root
      type="single"
      value={value}
      onValueChange={(next) => {
        // Clicking the selected item reports "" — stay put (mutual
        // exclusion means one is always selected).
        if (next !== "") onChange(next as T);
      }}
      disabled={disabled}
      className={cn(
        "inline-flex flex-wrap items-center gap-0.5 rounded-lg bg-bg-3 p-0.5",
        className,
      )}
    >
      {options.map((option) => (
        <ToggleGroupPrimitive.Item
          key={option.value}
          value={option.value}
          title={option.title}
          disabled={disabled}
          className={cn(
            "min-h-[22px] cursor-pointer rounded-md px-3 text-small text-fg-2 outline-none",
            "transition-colors duration-150 hover:text-fg-1",
            "focus-visible:ring-[3px] focus-visible:ring-accent-tint",
            "data-[state=on]:bg-bg-2 data-[state=on]:font-medium data-[state=on]:text-accent data-[state=on]:shadow-elevate-1",
            "data-[disabled]:pointer-events-none data-[disabled]:opacity-50",
          )}
        >
          {option.label}
        </ToggleGroupPrimitive.Item>
      ))}
    </ToggleGroupPrimitive.Root>
  );
}
