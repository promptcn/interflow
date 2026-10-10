import type {
  TableHTMLAttributes,
  TdHTMLAttributes,
  ThHTMLAttributes,
  HTMLAttributes,
} from "react";
import { cn } from "../../lib/utils";

/// Dense data tables (the fleet/convergence tables): uppercase column
/// heads in the section-head vocabulary, hairline row separators. All
/// wrappers pass through native table semantics — call sites add
/// scope="col" on Th.

export function Table({ className, ...props }: TableHTMLAttributes<HTMLTableElement>) {
  return <table className={cn("w-full border-collapse text-base", className)} {...props} />;
}

export function THead({ className, ...props }: HTMLAttributes<HTMLTableSectionElement>) {
  return <thead className={cn(className)} {...props} />;
}

export function TBody({ className, ...props }: HTMLAttributes<HTMLTableSectionElement>) {
  return <tbody className={cn(className)} {...props} />;
}

export function Tr({ className, ...props }: HTMLAttributes<HTMLTableRowElement>) {
  return <tr className={cn("border-b border-line/60 last:border-b-0", className)} {...props} />;
}

export function Th({ className, ...props }: ThHTMLAttributes<HTMLTableCellElement>) {
  return (
    <th
      className={cn(
        "border-b border-line px-0 pr-2 pb-1.5 text-left align-bottom text-small font-semibold uppercase tracking-[0.05em] text-fg-3",
        className,
      )}
      {...props}
    />
  );
}

export function Td({ className, ...props }: TdHTMLAttributes<HTMLTableCellElement>) {
  return <td className={cn("px-0 py-1.5 pr-2 align-baseline", className)} {...props} />;
}
