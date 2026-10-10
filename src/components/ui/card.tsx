import type { ReactNode } from "react";
import { cn } from "../../lib/utils";

/// One titled block of a detail page: the unit that replaced the old
/// everything-in-one-form pane. Elevated surface (bg-2) over the page
/// (bg-1); the head carries the one-line rule of the section; `grow`
/// lets a section take the page's leftover height (the logs).
export function SectionPanel({
  title,
  hint,
  actions,
  grow = false,
  className,
  children,
}: {
  title: string;
  hint?: string;
  actions?: ReactNode;
  grow?: boolean;
  className?: string;
  children: ReactNode;
}) {
  return (
    <section
      className={cn(
        "flex min-w-0 flex-col rounded-xl border border-line bg-bg-2",
        grow && "min-h-[260px] flex-1",
        className,
      )}
    >
      <div className="flex flex-wrap items-baseline gap-x-2.5 gap-y-1 border-b border-line px-4 py-2.5">
        <h3 className="text-small font-semibold uppercase tracking-[0.05em] text-fg-3">
          {title}
        </h3>
        {hint && <span className="text-small text-fg-3">{hint}</span>}
        {actions && <span className="ml-auto flex items-center gap-2">{actions}</span>}
      </div>
      <div className={cn("flex min-w-0 flex-col gap-2 p-4", grow && "min-h-0 flex-1")}>
        {children}
      </div>
    </section>
  );
}
