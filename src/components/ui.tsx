import { useState, type ReactNode } from "react";
import { kindLabel, stateColor, type NodeKindDto, type NodeStateDto } from "../api";

/// Shared visual primitives — the one vocabulary every face speaks (cards,
/// sections, badges, dots, dialogs). New surfaces reuse these instead of
/// growing local variants; the card-overview redesign
/// made them the
/// single source of visual truth.

export function StateDot({ state, size = 10 }: { state: NodeStateDto; size?: number }) {
  return (
    <span
      className="dot"
      style={{ background: stateColor(state), width: size, height: size }}
      aria-hidden
    />
  );
}

export function KindBadge({ kind }: { kind: NodeKindDto }) {
  return <span className={`kind-badge kind-${kind}`}>{kindLabel(kind)}</span>;
}

/// One titled block of a detail page: the unit that replaced the old
/// everything-in-one-form pane. `hint` carries the one-line rule of the
/// section (what is editable when, what is pack-signed); `grow` lets a
/// section take the page's leftover height (the logs).
export function SectionPanel({
  title,
  hint,
  actions,
  grow = false,
  children,
}: {
  title: string;
  hint?: string;
  actions?: ReactNode;
  grow?: boolean;
  children: ReactNode;
}) {
  return (
    <section className={`section${grow ? " grow" : ""}`}>
      <div className="section-head">
        <h3>{title}</h3>
        {hint && <span className="hint">{hint}</span>}
        {actions && <span className="section-actions">{actions}</span>}
      </div>
      <div className="section-body">{children}</div>
    </section>
  );
}

/// Backdrop-click-to-close modal frame (the AddNodeDialog pattern,
/// extracted so confirm/passphrase prompts stop living in window.prompt).
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
    <div className="dialog-backdrop" onClick={(e) => e.target === e.currentTarget && onClose()}>
      <div className={`dialog ${wide ? "dialog-wide" : ""}`}>{children}</div>
    </div>
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
  return (
    <Modal onClose={onClose}>
      <h2>{title}</h2>
      <p className="confirm-message">{message}</p>
      <div className="dialog-actions">
        <button onClick={onClose}>Cancel</button>
        <button className={danger ? "danger" : "primary"} disabled={busy} onClick={onConfirm}>
          {busy ? "…" : confirmLabel}
        </button>
      </div>
    </Modal>
  );
}

export function PassphraseDialog({
  title,
  description,
  confirmLabel,
  onConfirm,
  onClose,
}: {
  title: string;
  description: string;
  confirmLabel: string;
  onConfirm: (passphrase: string) => void;
  onClose: () => void;
}) {
  const [passphrase, setPassphrase] = useState("");
  return (
    <Modal onClose={onClose}>
      <h2>{title}</h2>
      <p className="confirm-message">{description}</p>
      <div className="row">
        <label>Passphrase</label>
        <input
          type="password"
          autoFocus
          value={passphrase}
          onChange={(e) => setPassphrase(e.target.value)}
          onKeyDown={(e) => {
            if (e.key === "Enter" && passphrase !== "") onConfirm(passphrase);
          }}
          autoComplete="off"
        />
      </div>
      <div className="dialog-actions">
        <button onClick={onClose}>Cancel</button>
        <button
          className="primary"
          disabled={passphrase === ""}
          onClick={() => onConfirm(passphrase)}
        >
          {confirmLabel}
        </button>
      </div>
    </Modal>
  );
}
