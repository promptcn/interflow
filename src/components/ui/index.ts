/// Shared visual primitives — the one vocabulary every face speaks.
/// Rebuilt 2026-10-08 on Tailwind + Radix
/// — new surfaces reuse these instead of growing local variants.

export { Button } from "./button";
export { Badge, KindBadge } from "./badge";
export { PeerDot, StateDot, statusDotClass, statusTextClass } from "./state-dot";
export { SectionPanel } from "./card";
export {
  ConfirmDialog,
  Dialog,
  DialogClose,
  DialogContent,
  DialogFooter,
  DialogTitle,
  DialogTrigger,
  Modal,
  PassphraseDialog,
} from "./dialog";
export { SegmentedControl } from "./segmented";
export { Select, type SelectOption } from "./select";
export { Hint, TooltipProvider } from "./tooltip";
export { Field, InfoRow, Label } from "./field";
export { Input } from "./input";
export { ToastProvider, useToast } from "./toast";
export { Table, TBody, THead, Td, Th, Tr } from "./table";
export { EmptyState, Kbd, Separator } from "./misc";
