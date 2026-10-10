import type { ButtonHTMLAttributes } from "react";
import { cva, type VariantProps } from "class-variance-authority";
import { cn } from "../../lib/utils";

/// The control baseline: heights floored by the control tokens
/// (min-h-control / min-h-control-sm), one variant vocabulary.
/// primary = the single blue accent (actions); green is NOT a button color
/// anymore — it only speaks state (2026-10-08 visual-system rebuild).
const buttonVariants = cva(
  "inline-flex cursor-pointer select-none items-center justify-center gap-1.5 whitespace-nowrap rounded-lg border transition-[background-color,border-color,color,opacity,transform] duration-150 outline-none focus-visible:border-accent focus-visible:ring-[3px] focus-visible:ring-accent-tint disabled:pointer-events-none disabled:opacity-50",
  {
    variants: {
      variant: {
        primary: "border-transparent bg-accent font-medium text-accent-fg hover:bg-accent-hover",
        secondary:
          "border-line bg-bg-2 text-fg-1 hover:border-line-strong hover:bg-bg-hover",
        danger:
          "border-critical/40 text-critical hover:border-critical/70 hover:bg-critical/10",
        link: "border-transparent bg-transparent px-2 text-accent underline-offset-4 hover:underline",
      },
      size: {
        md: "min-h-control px-3.5 text-base",
        sm: "min-h-control-sm px-3 text-small",
        icon: "size-control shrink-0 p-0",
        "icon-sm": "size-control-sm shrink-0 p-0",
      },
    },
    defaultVariants: { variant: "secondary", size: "md" },
  },
);

export function Button({
  className,
  variant,
  size,
  type = "button",
  ...props
}: ButtonHTMLAttributes<HTMLButtonElement> & VariantProps<typeof buttonVariants>) {
  return (
    <button type={type} className={cn(buttonVariants({ variant, size }), className)} {...props} />
  );
}
