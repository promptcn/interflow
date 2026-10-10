import { useId, useState, type ReactNode } from "react";
import * as DialogPrimitive from "@radix-ui/react-dialog";
import { X } from "lucide-react";
import { api } from "../../api";
import { useT } from "../../i18n";
import { cn } from "../../lib/utils";
import { Button } from "./button";
import { Input } from "./input";
import { Label } from "./field";

/// Radix-backed modal frame: focus trap + restore, aria-modal, labelled
/// semantics, Esc closes THE DIALOG (the app-level Esc climber defers to
/// an open dialog — see App's global handler). Backdrop click closes, as
/// the old hand-rolled Modal did.
///
/// Migration note: content should open with <DialogTitle> (h2 semantics
/// + aria-labelledby wiring for free). DialogFooter right-anchors the
/// action row.

export const Dialog = DialogPrimitive.Root;
export const DialogTrigger = DialogPrimitive.Trigger;
export const DialogClose = DialogPrimitive.Close;

export function DialogContent({
  children,
  wide = false,
  className,
}: {
  children: ReactNode;
  wide?: boolean;
  className?: string;
}) {
  const { t } = useT();
  return (
    <DialogPrimitive.Portal>
      <DialogPrimitive.Overlay
        className={cn(
          "fixed inset-0 z-50 bg-black/40 backdrop-blur-[1px]",
          "data-[state=open]:animate-in data-[state=open]:fade-in-0 data-[state=closed]:animate-out data-[state=closed]:fade-out-0 duration-150",
        )}
      />
      <DialogPrimitive.Content
        aria-describedby={undefined}
        className={cn(
          "fixed left-1/2 top-1/2 z-50 flex max-h-[calc(100vh-64px)] w-[calc(100vw-48px)] -translate-x-1/2 -translate-y-1/2 flex-col gap-3 overflow-y-auto rounded-xl border border-line bg-bg-2 p-5 shadow-elevate-2",
          wide ? "max-w-[760px]" : "max-w-[560px]",
          "data-[state=open]:animate-in data-[state=open]:fade-in-0 data-[state=open]:zoom-in-95 data-[state=closed]:animate-out data-[state=closed]:fade-out-0 data-[state=closed]:zoom-out-95 duration-150",
          className,
        )}
      >
        {children}
        <DialogPrimitive.Close asChild>
          <Button
            variant="link"
            size="icon-sm"
            aria-label={t("common.close")}
            className="absolute right-2.5 top-2.5 text-fg-3 hover:text-fg-1"
          >
            <X className="size-4" />
          </Button>
        </DialogPrimitive.Close>
      </DialogPrimitive.Content>
    </DialogPrimitive.Portal>
  );
}

export function DialogTitle({ children }: { children: ReactNode }) {
  return (
    <DialogPrimitive.Title className="pr-8 text-lg font-semibold text-fg-1">
      {children}
    </DialogPrimitive.Title>
  );
}

export function DialogFooter({ children }: { children: ReactNode }) {
  return <div className="flex justify-end gap-2">{children}</div>;
}

/// Compat frame: always-open dialog that closes through `onClose` — the
/// exact contract the old ui.tsx Modal had, so imperative call sites
/// (`open && <Modal>…`) migrate one-to-one.
export function Modal({
  children,
  onClose,
  wide = false,
}: {
  children: ReactNode;
  onClose: () => void;
  wide?: boolean;
}) {
  return (
    <DialogPrimitive.Root open onOpenChange={(open) => !open && onClose()}>
      <DialogContent wide={wide}>{children}</DialogContent>
    </DialogPrimitive.Root>
  );
}

export function ConfirmDialog({
  title,
  message,
  confirmLabel,
  danger = false,
  busy = false,
  onConfirm,
  onClose,
}: {
  title: string;
  message: string;
  confirmLabel: string;
  danger?: boolean;
  busy?: boolean;
  onConfirm: () => void;
  onClose: () => void;
}) {
  const { t } = useT();
  return (
    <Modal onClose={onClose}>
      <DialogTitle>{title}</DialogTitle>
      <p className="text-base whitespace-pre-wrap text-fg-1">{message}</p>
      <DialogFooter>
        <Button onClick={onClose}>{t("common.cancel")}</Button>
        <Button
          variant={danger ? "danger" : "primary"}
          disabled={busy}
          onClick={onConfirm}
        >
          {busy ? "…" : confirmLabel}
        </Button>
      </DialogFooter>
    </Modal>
  );
}

export function PassphraseDialog({
  title,
  description,
  confirmLabel,
  generate = false,
  onConfirm,
  onClose,
}: {
  title: string;
  description: string;
  confirmLabel: string;
  /// Offer a Generate button (sealing flows): a 144-bit passphrase from
  /// the same source the CLI uses, revealed in the clear because its whole
  /// job is to travel to the target machine. Import flows must NOT offer
  /// it — the passphrase has to match the existing file.
  generate?: boolean;
  onConfirm: (passphrase: string) => void;
  onClose: () => void;
}) {
  const [passphrase, setPassphrase] = useState("");
  const [revealed, setRevealed] = useState(false);
  const id = useId();
  const { t } = useT();
  return (
    <Modal onClose={onClose}>
      <DialogTitle>{title}</DialogTitle>
      <p className="text-base whitespace-pre-wrap text-fg-1">{description}</p>
      <div className="flex items-center gap-2">
        <Label htmlFor={id}>{t("common.passphrase")}</Label>
        <Input
          id={id}
          type={revealed ? "text" : "password"}
          autoFocus
          value={passphrase}
          onChange={(e) => setPassphrase(e.target.value)}
          onKeyDown={(e) => {
            if (e.key === "Enter" && passphrase !== "") onConfirm(passphrase);
          }}
          autoComplete="off"
        />
        {generate && (
          <Button
            title={t("common.generatePassphraseTitle")}
            onClick={async () => {
              try {
                setPassphrase(await api.deployGeneratePassphrase());
                setRevealed(true);
              } catch {
                // Generation is best-effort convenience; typing still works.
              }
            }}
          >
            {t("common.generate")}
          </Button>
        )}
      </div>
      <DialogFooter>
        <Button onClick={onClose}>{t("common.cancel")}</Button>
        <Button
          variant="primary"
          disabled={passphrase === ""}
          onClick={() => onConfirm(passphrase)}
        >
          {confirmLabel}
        </Button>
      </DialogFooter>
    </Modal>
  );
}
