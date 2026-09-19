//! Interflow expose GUI: Tauri 2.0 backend.
//!
//! Components:
//! - `contract` —— the IPC boundary DTOs + events; `src/bindings.ts` is
//!   generated from them (tauri-specta), the frontend never hand-writes types
//! - `tracing_capture` —— captures library-level tracing events and pushes them to the frontend log panel
//! - `tunnel` —— TunnelManager, wrapping AgentHandle for start/stop and state broadcasting
//! - `commands` —— Tauri invoke API
//! - `tray` —— tray icon/menu + hide on window close

mod commands;
mod contract;
mod tracing_capture;
mod tray;
mod tunnel;

use contract::TunnelStateEvent;
use interflow_mesh::agent::AgentState;
use std::sync::Mutex;
use tauri::{AppHandle, Manager};
use tunnel::TunnelManager;

pub struct AppState {
    pub tunnel: TunnelManager,
    pub logs: tracing_capture::LogBuffer,
}

pub type SharedState = Mutex<AppState>;

/// The tauri-specta command/event registry: the Rust side of the generated
/// `src/bindings.ts` contract.
fn specta_builder() -> tauri_specta::Builder<tauri::Wry> {
    tauri_specta::Builder::<tauri::Wry>::new()
        .commands(tauri_specta::collect_commands![
            commands::load_profile,
            commands::save_profile,
            commands::generate_agent_id,
            commands::start_tunnel,
            commands::stop_tunnel,
            commands::get_state,
            commands::get_recent_logs,
            commands::clear_logs,
        ])
        .events(tauri_specta::collect_events![
            contract::TunnelStateEvent,
            contract::LogEvent
        ])
}

/// Regenerates the TypeScript IPC contract (npm script `gen:bindings`).
pub fn export_bindings(path: &str) -> Result<(), String> {
    specta_builder()
        .export(specta_typescript::Typescript::default(), path)
        .map_err(|e| format!("failed to export bindings to {path}: {e}"))
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    let builder = specta_builder();

    #[cfg(debug_assertions)]
    export_bindings("../src/bindings.ts").expect("failed to export src/bindings.ts");

    tauri::Builder::default()
        .plugin(tauri_plugin_clipboard_manager::init())
        .plugin(tauri_plugin_dialog::init())
        .plugin(tauri_plugin_single_instance::init(|app, _args, _cwd| {
            // Second launch: focus the existing main window
            use tauri::Manager;
            if let Some(win) = app.get_webview_window("main") {
                let _ = win.show();
                let _ = win.set_focus();
            }
        }))
        .invoke_handler(builder.invoke_handler())
        .setup(move |app| {
            builder.mount_events(app);

            let (log_tx, log_rx) = tokio::sync::mpsc::channel(256);
            tracing_capture::init(log_tx);

            // The tunnel manager is GUI-framework-free domain logic; its UI
            // side effects (frontend event + tray refresh) are injected here
            // as the StateSink.
            let tunnel_app = app.handle().clone();
            app.manage(Mutex::new(AppState {
                tunnel: TunnelManager::new(move |state| emit_tunnel_state(&tunnel_app, state)),
                logs: tracing_capture::LogBuffer::new(),
            }));

            // Log pump: tracing capture layer → ring buffer + frontend events
            {
                let app_handle = app.handle().clone();
                tauri::async_runtime::spawn(async move {
                    tracing_capture::pump(app_handle, log_rx).await;
                });
            }

            tray::setup(app.handle())?;
            Ok(())
        })
        .on_window_event(|window, event| {
            if let tauri::WindowEvent::CloseRequested { api, .. } = event {
                // Window close = hide to tray; the tunnel keeps running
                api.prevent_close();
                let _ = window.hide();
            }
        })
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}

/// Tunnel state → frontend `tunnel-state` event + tray refresh. Runs inside
/// the TunnelManager's critical section — must not call back into the
/// manager (see `tunnel::StateSink`).
fn emit_tunnel_state(app: &AppHandle, state: &AgentState) {
    use tauri_specta::Event;
    let _ = TunnelStateEvent(state.clone().into()).emit(app);
    if let Some(tray) = app.tray_by_id("main") {
        tray::refresh(&tray, state);
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    /// Contract drift guard: the committed `src/bindings.ts` must be exactly
    /// what the current Rust contract generates. The 2026-09-18 incident
    /// (GUI sent `auth_token` after the mTLS-only migration) was this class
    /// of drift; this test turns it into a build failure instead of a
    /// runtime serde error.
    #[test]
    fn bindings_ts_is_fresh() {
        let tmp = tempfile::NamedTempFile::new().unwrap();
        let path = tmp.path().to_str().unwrap();
        super::export_bindings(path).unwrap();
        let generated = std::fs::read_to_string(path).unwrap();
        let committed =
            std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/../src/bindings.ts"))
                .unwrap_or_default();
        assert_eq!(
            generated, committed,
            "src/bindings.ts is stale — run `npm run gen:bindings` and commit the result"
        );
    }
}
