import React from "react";
import ReactDOM from "react-dom/client";
import App from "./App";
import { api, type GuiPrefsDto } from "./api";
import { I18nProvider, type Lang } from "./i18n";
import { initTheme } from "./theme";
import "./theme.css";

/// Boot: resolve the persisted language BEFORE first paint (a local TOML
/// read, milliseconds) so the window never flashes the wrong language.
/// Outside the Tauri shell (vite dev in a plain browser) the invoke
/// rejects — English, the default, stands.
async function boot() {
  initTheme();
  let initialLang: Lang = "en";
  let loadedPrefs: GuiPrefsDto | null = null;
  try {
    loadedPrefs = await api.guiPrefsLoad();
    initialLang = loadedPrefs.language;
  } catch {
    // Default stands.
  }

  ReactDOM.createRoot(document.getElementById("root")!).render(
    <React.StrictMode>
      <I18nProvider
        initialLang={initialLang}
        // Also rebuilds the Rust-rendered tray; a persist failure keeps
        // the session's choice live.
        persist={(lang) => {
          const prefs = loadedPrefs ?? { language: lang, current_deployment: null };
          api
            .guiPrefsSave({ ...prefs, language: lang })
            .catch((e) => console.error("failed to persist language:", e));
        }}
      >
        <App />
      </I18nProvider>
    </React.StrictMode>
  );
}

void boot();
