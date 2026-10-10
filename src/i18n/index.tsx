// Hand-rolled i18n: two typed dictionaries + one context. The frontend
// keeps a zero-extra-dependency shape (no router, no state library, no UI
// kit), and compile-time key parity — `zh` must carry every `en` key — is
// worth more here than a runtime i18n framework: a missing translation is
// a typecheck failure, not a raw key leaking to the user.
//
// The language lives in `gui.toml` next to the other prefs: main.tsx
// awaits it before first paint (no flash of the wrong language), and every
// switch persists through `gui_prefs_save`, which also rebuilds the
// Rust-rendered tray — one switch flips every surface at once.

import {
  createContext,
  useCallback,
  useContext,
  useEffect,
  useMemo,
  useState,
  type ReactNode,
} from "react";
import { EN } from "./en";
import { ZH } from "./zh";

export type Lang = "en" | "zh";
export type TParams = Record<string, string | number>;

/// The translator every surface shares: dictionary lookup + `{name}`
/// interpolation — the same placeholder convention the Rust i18n module
/// uses, one vocabulary across the IPC boundary.
export type TFn = (key: keyof typeof EN, params?: TParams) => string;

function interpolate(template: string, params?: TParams): string {
  if (!params) return template;
  // An unknown placeholder stays verbatim — a template/args drift must be
  // visible, not silently eaten.
  return template.replace(/\{(\w+)\}/g, (match, name: string) =>
    name in params ? String(params[name]) : match
  );
}

type I18nContextValue = { lang: Lang; setLang: (lang: Lang) => void; t: TFn };

const I18nContext = createContext<I18nContextValue | null>(null);

/// `initialLang` comes from gui.toml (main.tsx awaits it before render);
/// `persist` runs on every switch — main wires it to `gui_prefs_save`.
/// A persist failure is the caller's to report; the session's choice
/// stays live either way.
export function I18nProvider({
  initialLang,
  persist,
  children,
}: {
  initialLang: Lang;
  persist?: (lang: Lang) => void;
  children: ReactNode;
}) {
  const [lang, setLangState] = useState<Lang>(initialLang);
  const setLang = useCallback(
    (next: Lang) => {
      setLangState(next);
      // A synchronous persist failure (e.g. running outside the Tauri
      // shell) must not take the in-session switch down with it.
      try {
        persist?.(next);
      } catch {
        // The caller's persist wiring reports; the session stays switched.
      }
    },
    [persist]
  );
  // <html lang> follows the choice — accessibility and CJK font hints.
  useEffect(() => {
    document.documentElement.lang = lang;
  }, [lang]);
  const t = useCallback<TFn>(
    (key, params) => interpolate(lang === "en" ? EN[key] : ZH[key], params),
    [lang]
  );
  const value = useMemo(() => ({ lang, setLang, t }), [lang, setLang, t]);
  return <I18nContext.Provider value={value}>{children}</I18nContext.Provider>;
}

export function useT(): I18nContextValue {
  const ctx = useContext(I18nContext);
  if (!ctx) throw new Error("useT outside I18nProvider");
  return ctx;
}

/// Locale for Intl formatting (log timestamps): keeps the translated clock
/// and the translated text agreeing.
export function localeOf(lang: Lang): string {
  return lang === "zh" ? "zh-CN" : "en-US";
}
