//! System tray: status icon + menu (show/start/stop/quit).

use interflow_mesh::agent::AgentState;
use tauri::AppHandle;
use tauri::Manager as _;
use tauri::menu::{Menu, MenuItem};
use tauri::tray::TrayIconBuilder;

pub fn setup(app: &AppHandle) -> tauri::Result<()> {
    let show = MenuItem::with_id(app, "show", "Show main window", true, None::<&str>)?;
    let start = MenuItem::with_id(app, "start", "Start tunnel", true, None::<&str>)?;
    let stop = MenuItem::with_id(app, "stop", "Stop tunnel", true, None::<&str>)?;
    let quit = MenuItem::with_id(app, "quit", "Quit", true, None::<&str>)?;

    let menu = Menu::with_items(app, &[&show, &start, &stop, &quit])?;

    let mut builder = TrayIconBuilder::with_id("main")
        .menu(&menu)
        .show_menu_on_left_click(false)
        .on_menu_event(|app, event| match event.id().as_ref() {
            "show" => show_main_window(app),
            "start" => {
                let app = app.clone();
                tauri::async_runtime::spawn(async move {
                    emit_requested(&app, "start");
                });
            }
            "stop" => {
                let app = app.clone();
                tauri::async_runtime::spawn(async move {
                    if let Err(e) = do_stop(&app).await {
                        eprintln!("Stop failed: {e}");
                    }
                });
            }
            "quit" => {
                let app = app.clone();
                tauri::async_runtime::spawn(async move {
                    if let Err(e) = do_stop(&app).await {
                        eprintln!("Failed to stop the tunnel before exit: {e}");
                    }
                    app.exit(0);
                });
            }
            _ => {}
        });

    // Initial icon (grey for Stopped) — embedded into the binary via include_bytes to avoid resource path issues.
    builder = builder.icon(tauri::image::Image::from_bytes(include_bytes!(
        "../icons/tray-grey.png"
    ))?);

    builder.build(app)?;
    Ok(())
}

fn emit_requested(app: &AppHandle, action: &str) {
    use tauri::Emitter;
    let _ = app.emit("tray-action", action);
}

fn show_main_window(app: &AppHandle) {
    if let Some(win) = app.get_webview_window("main") {
        let _ = win.show();
        let _ = win.set_focus();
    }
}

async fn do_stop(app: &AppHandle) -> Result<(), String> {
    let state = app.state::<crate::SharedState>();
    let manager = {
        let guard = state
            .lock()
            .map_err(|_| "state lock poisoned".to_string())?;
        guard.tunnel.clone()
    };
    manager.stop().await
}

/// State → tray icon/menu refresh.
pub fn refresh(tray: &tauri::tray::TrayIcon, state: &AgentState) {
    let icon_bytes: &[u8] = match state {
        AgentState::Connected { .. } => include_bytes!("../icons/tray-green.png"),
        AgentState::Connecting | AgentState::Reconnecting { .. } => {
            include_bytes!("../icons/tray-yellow.png")
        }
        AgentState::Failed { .. } => include_bytes!("../icons/tray-red.png"),
        AgentState::Stopped => include_bytes!("../icons/tray-grey.png"),
    };
    if let Ok(img) = tauri::image::Image::from_bytes(icon_bytes) {
        tray.set_icon(Some(img)).ok();
    }
}
