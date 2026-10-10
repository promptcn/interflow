import {
  createContext,
  useCallback,
  useContext,
  useRef,
  useState,
  type ReactNode,
} from "react";

type ToastEntry = { id: number; text: string };

const ToastCtx = createContext<{ push: (text: string) => void } | null>(null);

export function useToast(): { push: (text: string) => void } {
  const ctx = useContext(ToastCtx);
  if (!ctx) throw new Error("useToast requires <ToastProvider> at the app root");
  return ctx;
}

/// Ephemeral confirmations ("Copied", "Saved") — the replacement for the
/// four label-swap flashes. NOT an error channel: GUI errors stay on the
/// app-level error banner (the one interruption channel, unchanged).
export function ToastProvider({ children }: { children: ReactNode }) {
  const [toasts, setToasts] = useState<ToastEntry[]>([]);
  const nextId = useRef(0);
  const push = useCallback((text: string) => {
    const id = ++nextId.current;
    setToasts((prev) => [...prev.slice(-3), { id, text }]);
    setTimeout(() => setToasts((prev) => prev.filter((t) => t.id !== id)), 1800);
  }, []);
  return (
    <ToastCtx.Provider value={{ push }}>
      {children}
      <div
        aria-live="polite"
        className="pointer-events-none fixed right-4 bottom-4 z-[60] flex flex-col items-end gap-2"
      >
        {toasts.map((toast) => (
          <div
            key={toast.id}
            className="toast-item rounded-lg border border-line bg-bg-2 px-3.5 py-2 text-small text-fg-1 shadow-elevate-3"
          >
            {toast.text}
          </div>
        ))}
      </div>
    </ToastCtx.Provider>
  );
}
