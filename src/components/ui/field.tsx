import { useId, type ReactNode } from "react";
import * as LabelPrimitive from "@radix-ui/react-label";
import { cn } from "../../lib/utils";

export const Label = LabelPrimitive.Root;

/// One label + control row with a REAL id association — the old `.row`
/// labels were purely visual (zero htmlFor in the whole app). The render
/// prop hands the generated id to whatever control the row hosts:
/// `<Field label="Name">{(id) => <Input id={id} …/>}</Field>`.
export function Field({
  label,
  className,
  children,
}: {
  label: ReactNode;
  className?: string;
  children: (id: string) => ReactNode;
}) {
  const id = useId();
  return (
    <div className={cn("flex items-center gap-2", className)}>
      <Label htmlFor={id} className="w-[140px] shrink-0 text-base text-fg-2">
        {label}
      </Label>
      {children(id)}
    </div>
  );
}

/// The display twin of Field: label + read-only value (no control, no id).
/// Carries the signed-pack truth rows and summary lines.
export function InfoRow({
  label,
  className,
  children,
}: {
  label: ReactNode;
  className?: string;
  children: ReactNode;
}) {
  return (
    <div className={cn("flex items-center gap-2", className)}>
      <span className="w-[140px] shrink-0 text-base text-fg-2">{label}</span>
      <span className="min-w-0 flex-1">{children}</span>
    </div>
  );
}
