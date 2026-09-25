//! System tray: per-node start/stop, aggregate status icon, show/stop-all/
//! quit — plus the single source of truth for the window ↔ tray lifecycle
//! ([hide_to_tray] / [show_main_window], shared by every put-away and
//! bring-back path).
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
    // tooltip names the machine (a node is an identity, not a machine) —
    // and carries the build identity, so a remote machine's version is
    // readable without opening the window.
    let tooltip = format!(
        "Interflow v{} ({}) — {}",
        env!("CARGO_PKG_VERSION"),
        interflow_buildinfo::BUILD_TAG,
        gethostname::gethostname().to_string_lossy()
    );
    let builder = TrayIconBuilder::with_id("main")
        .menu(&menu)
        .tooltip(tooltip)
        .show_menu_on_left_click(false)
        .on_tray_icon_event(|tray, event| {
            // Left-click = bring the window back (predictable single
            // direction; put-away stays on the minimize/close buttons).
            if let tauri::tray::TrayIconEvent::Click {
                button: tauri::tray::MouseButton::Left,
                button_state: tauri::tray::MouseButtonState::Up,
                ..
            } = event
            {
                show_main_window(tray.app_handle());
            }
        })
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

/// The single bring-back path, shared by the tray menu, tray left-click,
/// single-instance relaunch, and the macOS dock reopen event.
///
/// A window hidden mid-minimize stays iconic through `show()` — it would
/// reappear as a taskbar minimized button, not a window. `unminimize()`
/// (SW_RESTORE) returns it to its pre-minimize placement; a no-op when not
/// minimized, so the same sequence serves every state.
pub fn show_main_window(app: &AppHandle) {
    if let Some(win) = app.get_webview_window("main") {
        let _ = win.show();
        let _ = win.unminimize();
        let _ = win.set_focus();
    }
}

/// The single put-away path, shared by window close and (on Windows)
/// minimize: hide into the tray, nodes keep running.
pub fn hide_to_tray(win: &tauri::Window) {
    let _ = win.hide();
    announce_first_hide_to_tray(win.app_handle());
}

/// One toast per app run, on the first hide-to-tray regardless of path
/// (minimize or close) — the standard tray-app guard against "my app
/// vanished" confusion. Per-run (not persisted): a reboot earns the
/// unattended machine one gentle reminder, which is the point.
#[cfg(target_os = "windows")]
fn announce_first_hide_to_tray(app: &AppHandle) {
    use std::sync::atomic::{AtomicBool, Ordering};
    static ANNOUNCED: AtomicBool = AtomicBool::new(false);
    if ANNOUNCED.swap(true, Ordering::Relaxed) {
        return;
    }
    use tauri_plugin_notification::NotificationExt;
    let _ = app
        .notification()
        .builder()
        .title("Interflow is still running")
        .body("The window was tucked into the system tray — click the tray icon to bring it back.")
        .show();
}

#[cfg(not(target_os = "windows"))]
const fn announce_first_hide_to_tray(_app: &AppHandle) {}

/// Builds the full menu from the current node set (callers hold no manager
/// lock; the menu read is a snapshot). Nodes whose leaf is inside a warn
/// window carry a `⚠ leaf Nd` tail so the expiry is visible without
/// opening the window.
fn build_menu(app: &AppHandle) -> tauri::Result<Menu<tauri::Wry>> {
    let manager = manager(app);
    let mut items: Vec<tauri::menu::MenuItem<tauri::Wry>> = Vec::new();
    for snapshot in manager.snapshots() {
        let glyph = state_glyph(&snapshot.state);
        let mut title = format!(
            "{glyph} {} — {}",
            snapshot.spec.name,
            snapshot.spec.kind.label()
        );
        if let Some(health) = manager.credential_health(&snapshot.spec.id)
            && health.phase != interflow_identity::expiry::LeafPhase::Healthy
        {
            title.push_str("  ⚠ leaf ");
            title.push_str(&interflow_identity::expiry::format_remaining(
                health.remaining_secs,
            ));
        }
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

/// Menu/icon/tooltip refresh on any node state change. Rebuilds the menu
/// (cheap, happens on state transitions only — the busy states settle
/// within seconds) and sets the worst-of aggregate icon; credential
/// expiry joins the aggregate (a node inside its critical window is red
/// even while it still connects) and the most urgent node names itself in
/// the tooltip.
pub fn refresh(app: &AppHandle, tray: &TrayIcon) {
    use interflow_identity::expiry::LeafPhase;
    let manager = manager(app);
    let snapshots = manager.snapshots();
    let mut worst = snapshots
        .iter()
        .map(|s| severity(&s.state))
        .max()
        .unwrap_or(0);
    let mut most_urgent: Option<(String, i64, LeafPhase)> = None;
    for snapshot in &snapshots {
        let Some(health) = manager.credential_health(&snapshot.spec.id) else {
            continue;
        };
        let expiry_severity = match health.phase {
            LeafPhase::Critical => 3,
            LeafPhase::Warn => 2,
            LeafPhase::Healthy => 0,
        };
        worst = worst.max(expiry_severity);
        if health.phase != LeafPhase::Healthy
            && most_urgent
                .as_ref()
                .is_none_or(|(_, remaining, _)| health.remaining_secs < *remaining)
        {
            most_urgent = Some((
                snapshot.spec.name.clone(),
                health.remaining_secs,
                health.phase,
            ));
        }
    }
    let icon_bytes: &[u8] = match worst {
        3 => include_bytes!("../icons/tray-red.png"),
        2 => include_bytes!("../icons/tray-yellow.png"),
        1 => include_bytes!("../icons/tray-green.png"),
        _ => include_bytes!("../icons/tray-grey.png"),
    };
    if let Ok(img) = tauri::image::Image::from_bytes(icon_bytes) {
        tray.set_icon(Some(img)).ok();
    }
    // The tooltip carries the machine anchor + build identity (see
    // [setup]) plus, when any node's leaf is inside a warn window, the
    // single most urgent one — the tray's unattended-machine headline.
    let mut tooltip = format!(
        "Interflow v{} ({}) — {}",
        env!("CARGO_PKG_VERSION"),
        interflow_buildinfo::BUILD_TAG,
        gethostname::gethostname().to_string_lossy()
    );
    if let Some((name, remaining, phase)) = most_urgent {
        let line = format!(
            "\n{name}: leaf {} left ({})",
            interflow_identity::expiry::format_remaining(remaining),
            phase.as_str()
        );
        tooltip.push_str(&line);
    }
    tray.set_tooltip(Some(tooltip)).ok();
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
