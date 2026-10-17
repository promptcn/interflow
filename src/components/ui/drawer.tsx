import type { ReactNode } from "react";
import * as DialogPrimitive from "@radix-ui/react-dialog";
import { cn } from "../../lib/utils";

/// Side sheet — the editing surface for first-class objects (streams,
/// services): slides in from the right, 420px (full-width under 480px of
/// room), 160ms ease-out. `guard` keeps the backdrop click from closing
/// while there is unsaved state in the sheet (Esc stays available — the
/// user's explicit way out). Dialog semantics (role, focus trap, Esc) are
/// the Radix Dialog's, same contract as Modal.
///
/// Motion is deliberately minimal: one slide+fade on entry, none on exit
/// (the sheet is gone when the state says so); the global
/// prefers-reduced-motion rule zeroes it. No loops, no view transitions —
/// 默认安静.
export function Drawer({
  children,
  onClose,
  guard = false,
  className,
}: {
  children: ReactNode;
  onClose: () => void;
  /// While true, a backdrop click does NOT close (dirty edits); Esc and
  /// the explicit buttons still do.
  guard?: boolean;
  className?: string;
}) {
  return (
    <DialogPrimitive.Root open onOpenChange={(open) => !open && !guard && onClose()}>
      <DialogPrimitive.Portal>
        <DialogPrimitive.Overlay className="fixed inset-0 z-40 bg-black/25 animate-[drawer-fade_160ms_ease-out]" />
        <DialogPrimitive.Content
          className={cn(
            "fixed inset-y-0 right-0 z-50 flex w-[420px] max-w-full flex-col gap-3 overflow-y-auto",
            "border-l border-line bg-bg-2 p-4 shadow-elevate-3 outline-none",
            "animate-[drawer-in_160ms_ease-out]",
            className,
          )}
        >
          {children}
        </DialogPrimitive.Content>
      </DialogPrimitive.Portal>
    </DialogPrimitive.Root>
  );
}
