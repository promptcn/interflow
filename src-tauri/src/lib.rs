//! Interflow expose GUI: Tauri 2.0 backend.
//!
//! Components:
//! - `tracing_capture` —— captures library-level tracing events and pushes them to the frontend log panel
//! - `tunnel` —— TunnelManager, wrapping AgentHandle for start/stop and state broadcasting
//! - `commands` —— Tauri invoke API
//! - `tray` —— tray icon/menu + hide on window close

mod commands;
mod tracing_capture;
mod tray;
mod tunnel;

use std::sync::Mutex;
use tauri::Manager;
use tunnel::TunnelManager;

pub struct AppState {
    pub tunnel: TunnelManager,
    pub logs: tracing_capture::LogBuffer,
}

pub type SharedState = Mutex<AppState>;

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
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
        .setup(|app| {
            let (log_tx, log_rx) = tokio::sync::mpsc::channel(256);
            tracing_capture::init(log_tx);

            app.manage(Mutex::new(AppState {
                tunnel: TunnelManager::new(),
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
        .invoke_handler(tauri::generate_handler![
            commands::load_profile,
            commands::save_profile,
            commands::generate_agent_id,
            commands::start_tunnel,
            commands::stop_tunnel,
            commands::get_state,
            commands::get_recent_logs,
        ])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
