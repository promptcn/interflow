import type { HTMLAttributes } from "react";
import { cva, type VariantProps } from "class-variance-authority";
import { kindBlurb, kindLabel, type NodeKindDto } from "../../api";
import { useT } from "../../i18n";
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

/// Short kind badge — the text is the product vocabulary (kindLabel,
/// shared with the tray, the binaries and the ops docs; never localized,
/// never overridable), and the hover title defaults to the localized
/// blurb, so "term + explanation" is a component invariant rather than
/// per-call-site discipline. `title` overrides the blurb only where a
/// surface needs a context-specific explanation.
export function KindBadge({ kind, title }: { kind: NodeKindDto; title?: string }) {
  const { t } = useT();
  return (
    <Badge tone={KIND_TONE[kind]} title={title ?? kindBlurb(kind, t)}>
      {kindLabel(kind)}
    </Badge>
  );
}
