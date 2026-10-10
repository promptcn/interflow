import type { HTMLAttributes } from "react";
import { cva, type VariantProps } from "class-variance-authority";
import { kindLabel, type NodeKindDto } from "../../api";
import { cn } from "../../lib/utils";

/// Pills/tags/chips — one shape, tones carry semantics. Kind hues keep the
/// legacy identity (hub blue / ingress purple / mesh orange / expose green).
const badgeVariants = cva(
  "inline-flex shrink-0 items-center gap-1 whitespace-nowrap rounded-full border px-2 py-px text-micro leading-[1.5]",
  {
    variants: {
      tone: {
        neutral: "border-line text-fg-2",
        accent: "border-accent/50 text-accent",
        success: "border-success/50 text-success",
        warn: "border-warn/55 text-warn",
        critical: "border-critical/55 text-critical",
        hub: "border-kind-hub/50 text-kind-hub",
        ingress: "border-kind-ingress/50 text-kind-ingress",
        mesh: "border-kind-mesh/55 text-kind-mesh",
        expose: "border-kind-expose/50 text-kind-expose",
      },
    },
    defaultVariants: { tone: "neutral" },
  },
);

export function Badge({
  className,
  tone,
  ...props
}: HTMLAttributes<HTMLSpanElement> & VariantProps<typeof badgeVariants>) {
  return <span className={cn(badgeVariants({ tone }), className)} {...props} />;
}

const KIND_TONE = {
  hub: "hub",
  ingress: "ingress",
  mesh_agent: "mesh",
  expose_agent: "expose",
} as const satisfies Record<NodeKindDto, NonNullable<VariantProps<typeof badgeVariants>["tone"]>>;

/// Short kind badge — product vocabulary, shared with the tray (never
/// localized). Same API as the old ui.tsx primitive.
export function KindBadge({ kind }: { kind: NodeKindDto }) {
  return <Badge tone={KIND_TONE[kind]}>{kindLabel(kind)}</Badge>;
}
