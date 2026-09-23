//! System tray: per-node start/stop, aggregate status icon, show/stop-all/
//! quit.
//!
//! Menu actions act on the NodeManager **directly in Rust** — no webview
//! round-trip (the pre-v2 tray emitted a `tray-action` event nothing
//! listened to). The menu is rebuilt on node-list/state changes; the icon is
//! the worst-of aggregate over all nodes (failed > reconnecting > running >
//! idle).

use crate::node::{NodeManager, NodeState};
use tauri::AppHandle;
use tauri::Manager as _;
use tauri::menu::{Menu, MenuItem};
use tauri::tray::{TrayIcon, TrayIconBuilder};

/// Menu item id prefix for per-node entries.
const NODE_ITEM_PREFIX: &str = "node:";

pub fn setup(app: &AppHandle) -> tauri::Result<()> {
    let menu = build_menu(app)?;
    // Machine anchor: the tray aggregates this machine's nodes, so the
    // tooltip names the machine (a node is an identity, not a machine).
    let tooltip = format!(
        "Interflow — {}",
        gethostname::gethostname().to_string_lossy()
    );
    let builder = TrayIconBuilder::with_id("main")
        .menu(&menu)
        .tooltip(tooltip)
        .show_menu_on_left_click(false)
        .on_menu_event(|app, event| match event.id().as_ref() {
            "show" => show_main_window(app),
            "stop-all" => {
                let app = app.clone();
                tauri::async_runtime::spawn(async move {
                    manager(&app).stop_all().await;
                });
            }
            "quit" => {
                let app = app.clone();
                tauri::async_runtime::spawn(async move {
                    let manager = manager(&app);
                    manager.stop_all().await;
                    // Flush the final persist + Stopped events before the
                    // runtime dies with the app (settle = drain barrier).
                    manager.settle().await;
                    app.exit(0);
                });
            }
            id => {
                let Some(node_id) = id.strip_prefix(NODE_ITEM_PREFIX) else {
                    return;
                };
                let node_id = node_id.to_string();
                let app = app.clone();
                tauri::async_runtime::spawn(async move {
                    toggle_node(&app, &node_id).await;
                });
            }
        });

    // Initial icon (grey = everything idle) — embedded into the binary via
    // include_bytes to avoid resource path issues.
    let builder = builder.icon(tauri::image::Image::from_bytes(include_bytes!(
        "../icons/tray-grey.png"
    ))?);

    builder.build(app)?;
    Ok(())
}

fn manager(app: &AppHandle) -> NodeManager {
    let state = app.state::<crate::SharedState>();
    state
        .lock()
        .map(|guard| guard.nodes.clone())
        .expect("state lock poisoned")
}

/// A per-node menu item toggles start/stop based on liveness.
async fn toggle_node(app: &AppHandle, id: &str) {
    let manager = manager(app);
    let snapshot = manager.snapshots().into_iter().find(|s| s.spec.id == id);
    let Some(snapshot) = snapshot else {
        return;
    };
    let outcome = if matches!(
        snapshot.state,
        NodeState::Stopped | NodeState::Failed { .. }
    ) {
        manager.start(id)
    } else {
        manager.stop(id).await
    };
    if let Err(e) = outcome {
        tracing::warn!(node = %crate::node::log_attribution(&snapshot.spec), "tray toggle failed: {e}");
    }
}

fn show_main_window(app: &AppHandle) {
    if let Some(win) = app.get_webview_window("main") {
        let _ = win.show();
        let _ = win.set_focus();
    }
}

/// Builds the full menu from the current node set (callers hold no manager
/// lock; the menu read is a snapshot).
fn build_menu(app: &AppHandle) -> tauri::Result<Menu<tauri::Wry>> {
    let mut items: Vec<tauri::menu::MenuItem<tauri::Wry>> = Vec::new();
    for snapshot in manager(app).snapshots() {
        let glyph = state_glyph(&snapshot.state);
        let title = format!(
            "{glyph} {} — {}",
            snapshot.spec.name,
            snapshot.spec.kind.label()
        );
        items.push(MenuItem::with_id(
            app,
            format!("{NODE_ITEM_PREFIX}{}", snapshot.spec.id),
            title,
            true,
            None::<&str>,
        )?);
    }
    if !items.is_empty() {
        items.push(MenuItem::with_id(
            app,
            "stop-all",
            "Stop all",
            true,
            None::<&str>,
        )?);
    }
    items.push(MenuItem::with_id(
        app,
        "show",
        "Show main window",
        true,
        None::<&str>,
    )?);
    items.push(MenuItem::with_id(app, "quit", "Quit", true, None::<&str>)?);
    let refs: Vec<&dyn tauri::menu::IsMenuItem<tauri::Wry>> = items
        .iter()
        .map(|item| item as &dyn tauri::menu::IsMenuItem<tauri::Wry>)
        .collect();
    Menu::with_items(app, &refs)
}

/// Stable state glyph for menu rows (● running, ◐ busy, ○ stopped, ✕ failed).
const fn state_glyph(state: &NodeState) -> &'static str {
    match state {
        NodeState::Connected { .. } | NodeState::Running => "●",
        NodeState::Starting
        | NodeState::Connecting
        | NodeState::Reconnecting { .. }
        | NodeState::Stopping => "◐",
        NodeState::Stopped => "○",
        NodeState::Failed { .. } => "✕",
    }
}

/// Menu/icon refresh on any node state change. Rebuilds the menu (cheap,
/// happens on state transitions only — the busy states settle within
/// seconds) and sets the worst-of aggregate icon.
pub fn refresh(app: &AppHandle, tray: &TrayIcon) {
    let snapshots = manager(app).snapshots();
    let worst = snapshots
        .iter()
        .map(|s| severity(&s.state))
        .max()
        .unwrap_or(0);
    let icon_bytes: &[u8] = match worst {
        3 => include_bytes!("../icons/tray-red.png"),
        2 => include_bytes!("../icons/tray-yellow.png"),
        1 => include_bytes!("../icons/tray-green.png"),
        _ => include_bytes!("../icons/tray-grey.png"),
    };
    if let Ok(img) = tauri::image::Image::from_bytes(icon_bytes) {
        tray.set_icon(Some(img)).ok();
    }
    if let Ok(menu) = build_menu(app) {
        tray.set_menu(Some(menu)).ok();
    }
}

/// Aggregate severity: failed > reconnecting/busy > running > idle.
const fn severity(state: &NodeState) -> u8 {
    match state {
        NodeState::Failed { .. } => 3,
        NodeState::Starting
        | NodeState::Connecting
        | NodeState::Reconnecting { .. }
        | NodeState::Stopping => 2,
        NodeState::Connected { .. } | NodeState::Running => 1,
        NodeState::Stopped => 0,
    }
}
