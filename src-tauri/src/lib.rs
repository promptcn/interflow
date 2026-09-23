//! Interflow GUI: Tauri 2.0 backend — the unified node manager (expose
//! agents, mesh agents, mesh hubs, and ingresses side by side, each from a
//! Credential Pack).
//!
//! Components:
//! - `contract` —— the IPC boundary DTOs + events; `src/bindings.ts` is
//!   generated from them (tauri-specta), the frontend never hand-writes types
//! - `tracing_capture` —— captures library-level tracing events into the GUI
//!   log panel, attributed per node via the `node` field
//! - `node` —— NodeManager: multi-node lifecycle, renewal beside every
//!   engine, bounded death-restart (framework-free domain logic)
//! - `commands` —— Tauri invoke API
//! - `tray` —— tray icon/menu + hide on window close

mod commands;
mod contract;
mod deploy;
mod node;
mod profile;
mod tracing_capture;
mod tray;

use contract::NodeStateEvent;
use node::{NodeManager, NodeState};
use std::sync::Mutex;
use tauri::{AppHandle, Manager};

pub struct AppState {
    pub nodes: NodeManager,
    pub logs: tracing_capture::LogBuffer,
}

pub type SharedState = Mutex<AppState>;

/// The tauri-specta command/event registry: the Rust side of the generated
/// `src/bindings.ts` contract.
fn specta_builder() -> tauri_specta::Builder<tauri::Wry> {
    tauri_specta::Builder::<tauri::Wry>::new()
        .commands(tauri_specta::collect_commands![
            commands::list_nodes,
            commands::inspect_pack,
            commands::add_node,
            commands::remove_node,
            commands::start_node,
            commands::stop_node,
            commands::stop_all_nodes,
            commands::update_node_prefs,
            commands::get_recent_logs,
            commands::clear_logs,
            commands::get_host_name,
            commands::deploy_manifest_template,
            commands::deploy_read_text,
            commands::deploy_write_text,
            commands::deploy_validate,
            commands::deploy_apply,
            commands::deploy_list_packs,
            commands::deploy_seal_pack,
            commands::deploy_install_sealed,
            commands::deploy_update_node,
            commands::deploy_rotate,
            commands::deploy_revoke,
        ])
        .events(tauri_specta::collect_events![
            contract::NodeStateEvent,
            contract::LogEvent
        ])
}

/// Regenerates the TypeScript IPC contract (npm script `gen:bindings`).
pub fn export_bindings(path: &str) -> Result<(), String> {
    specta_builder()
        .export(specta_typescript::Typescript::default(), path)
        .map_err(|e| format!("failed to export bindings to {path}: {e}"))
}

/// Persists every panic to `panic.log` in the app's data dir, then chains
/// to the previous hook (stderr). Release builds abort without unwinding
/// and the bundled app has no stderr — the 2026-09-23 crash (a panic deep
/// under a Tauri sync command) left nothing on disk, and diagnosing it
/// required rerunning the binary from a terminal. The hook only formats
/// and appends once: no locks, no runtime re-entry.
fn install_panic_hook() {
    let Some(log_path) = panic_log_path() else {
        return; // no data dir resolvable (unusual) — keep default behavior
    };
    if let Some(parent) = log_path.parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    let previous = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |info| {
        let location = info.location().map_or_else(
            || "unknown".into(),
            |l| format!("{}:{}:{}", l.file(), l.line(), l.column()),
        );
        let thread = std::thread::current();
        append_panic_record(
            &log_path,
            thread.name().unwrap_or("<unnamed>"),
            &location,
            info.payload_as_str()
                .unwrap_or("<non-string panic payload>"),
        );
        previous(info);
    }));
}

fn panic_log_path() -> Option<std::path::PathBuf> {
    dirs::data_local_dir().map(|d| d.join("interflow").join("panic.log"))
}

/// One line per panic — message + file:line + thread is what localizes the
/// fault in a single glance (the same payoff the 2026-09-23 terminal rerun
/// bought, minus the rerun).
fn append_panic_record(path: &std::path::Path, thread: &str, location: &str, payload: &str) {
    use std::io::Write;
    let Ok(mut file) = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
    else {
        return;
    };
    let _ = writeln!(
        file,
        "{} thread '{thread}' panicked at {location}: {payload}",
        tracing_capture::rfc3339_now()
    );
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    install_panic_hook();

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

            // The node manager is GUI-framework-free domain logic; its UI
            // side effects (frontend event + tray refresh, profile
            // persistence) are injected here as sinks. The runtime handle
            // is injected too: it lets the (synchronous) manager spawn
            // engines from any thread — including Tauri's sync-command
            // pool, which has no ambient Tokio runtime
            let nodes_app = app.handle().clone();
            let manager = NodeManager::new(
                tauri::async_runtime::handle().inner().clone(),
                move |id, state| emit_node_state(&nodes_app, id, state),
                |entries| {
                    if let Err(e) = profile::save(&profile::Profile::new(entries.to_vec())) {
                        tracing::error!(node = "gui", "profile save failed: {e}");
                    }
                },
            );

            // Restore the persisted node set, then bring the desired set up
            // (Start intent survives GUI restarts). A corrupt profile is
            // logged and degraded to an empty list — the GUI must still
            // come up.
            match profile::load() {
                Ok(persisted) => manager.restore(persisted.nodes),
                Err(e) => tracing::error!(node = "gui", "profile load failed: {e}"),
            }

            app.manage(Mutex::new(AppState {
                nodes: manager.clone(),
                logs: tracing_capture::LogBuffer::new(),
            }));

            tauri::async_runtime::spawn(async move {
                manager.start_desired();
            });

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
                // Window close = hide to tray; nodes keep running
                api.prevent_close();
                let _ = window.hide();
            }
        })
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}

/// Node state → frontend `node-state` event + tray refresh. Runs on the
/// NodeManager's event-consumer task, never holding the manager lock — the
/// tray may read the manager back (`snapshots()`), which it does here
/// (see `node::StateSink`; the lock-free guarantee is why the 2026-09-23
/// Start-hang class cannot recur on this path).
fn emit_node_state(app: &AppHandle, id: &str, state: &NodeState) {
    use tauri_specta::Event;
    let _ = NodeStateEvent {
        id: id.to_string(),
        state: state.clone().into(),
    }
    .emit(app);
    if let Some(tray) = app.tray_by_id("main") {
        tray::refresh(app, &tray);
    }
}

/// Test-only helpers shared across the crate's unit modules.
#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
pub mod test_util {
    /// Bind 127.0.0.1:0 to grab an ephemeral port (released immediately;
    /// the usual tiny race between tests applies).
    pub fn free_port() -> u16 {
        std::net::TcpListener::bind("127.0.0.1:0")
            .expect("bind ephemeral")
            .local_addr()
            .expect("addr")
            .port()
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    /// Contract drift guard: the committed `src/bindings.ts` must be exactly
    /// what the current Rust contract generates. The 2026-09-18 incident
    /// (GUI sent `auth_token` after the mTLS migration) was this class of
    /// drift; this test turns it into a build failure instead of a
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

    /// One append must yield one line carrying thread, location and payload
    /// — the three fields that localized the 2026-09-23 crash.
    #[test]
    fn panic_record_is_one_localizing_line() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("panic.log");
        super::append_panic_record(
            &path,
            "main",
            "crates/mesh/src/agent/client.rs:200:13",
            "there is no reactor running",
        );
        let content = std::fs::read_to_string(&path).unwrap();
        assert!(
            content.contains(
                "thread 'main' panicked at \
                              crates/mesh/src/agent/client.rs:200:13: \
                              there is no reactor running"
            ),
            "wrong panic record: {content}"
        );
        assert_eq!(content.lines().count(), 1, "one panic = one line");
    }
}
