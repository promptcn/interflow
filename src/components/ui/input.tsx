import { forwardRef, type InputHTMLAttributes } from "react";
import { cn } from "../../lib/utils";

/// Text input on the control baseline. Call sites pass aria-invalid (the
/// red ring is driven by it); read-only renders as inset truth (bg-3,
/// fg-2) — the "signed pack value" look.
export const Input = forwardRef<HTMLInputElement, InputHTMLAttributes<HTMLInputElement>>(
  function Input({ className, ...props }, ref) {
    return (
      <input
        ref={ref}
        className={cn(
          "min-h-control w-full min-w-0 rounded-lg border border-line bg-bg-2 px-3 text-base text-fg-1 transition-colors duration-150 outline-none",
          "placeholder:text-fg-3 hover:border-line-strong focus-visible:border-accent focus-visible:ring-[3px] focus-visible:ring-accent-tint",
          "read-only:border-line/70 read-only:bg-bg-3 read-only:text-fg-2",
          "disabled:opacity-50 aria-invalid:border-critical aria-invalid:focus-visible:border-critical aria-invalid:focus-visible:ring-critical/15",
          className,
        )}
        {...props}
      />
    );
  },
);
