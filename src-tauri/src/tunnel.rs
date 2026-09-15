//! TunnelManager: wraps AgentHandle for start/stop and state broadcasting.
//!
//! The state directly uses the library-level `AgentState` (single source of truth);
//! the GUI only maps it for display.

use interflow_mesh::agent::{AgentHandle, AgentState};
use std::sync::Arc;
use tauri::{AppHandle, Emitter};
use tokio::sync::Mutex;

#[derive(Clone)]
pub struct TunnelManager {
    handle: Arc<Mutex<Option<AgentHandle>>>,
}

impl TunnelManager {
    pub fn new() -> Self {
        Self {
            handle: Arc::new(Mutex::new(None)),
        }
    }

    /// Current state (treated as Stopped when there is no handle).
    pub async fn state(&self) -> AgentState {
        match self.handle.lock().await.as_ref() {
            Some(h) => h.state(),
            None => AgentState::Stopped,
        }
    }

    /// Start the tunnel; on success, spawn a state listener that pushes changes to the frontend and the tray.
    pub async fn start(
        &self,
        app: &AppHandle,
        args: interflow_expose::client::ExposeArgs,
    ) -> Result<(), String> {
        let mut guard = self.handle.lock().await;
        if let Some(h) = guard.as_ref() {
            // Already running/reconnecting: reject duplicate starts (the frontend button is also disabled; this is the fallback)
            if !matches!(h.state(), AgentState::Stopped | AgentState::Failed { .. }) {
                return Err("tunnel is already running".into());
            }
        }

        let handle = interflow_expose::client::start(&args).map_err(|e| e.to_string())?;

        // State listener: watch → tunnel-state event + tray refresh
        {
            let app = app.clone();
            let mut rx = handle.subscribe_state();
            tauri::async_runtime::spawn(async move {
                loop {
                    let state = rx.borrow_and_update().clone();
                    emit_state(&app, &state);
                    if rx.changed().await.is_err() {
                        // The supervisor ended and the watch sender dropped; emit the final state one last time
                        return;
                    }
                }
            });
        }

        emit_state(app, &handle.state());
        *guard = Some(handle);
        Ok(())
    }

    /// Stop the tunnel (graceful shutdown); no-op when no tunnel is running.
    pub async fn stop(&self) -> Result<(), String> {
        let handle = self.handle.lock().await.take();
        if let Some(h) = handle {
            h.shutdown_graceful().await.map_err(|e| e.to_string())?;
        }
        Ok(())
    }
}

pub fn emit_state(app: &AppHandle, state: &AgentState) {
    let _ = app.emit("tunnel-state", state);
    if let Some(tray) = app.tray_by_id("main") {
        crate::tray::refresh(&tray, state);
    }
}
