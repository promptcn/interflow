//! Tauri invoke commands: profile read/write + tunnel start/stop + state/log queries.

use crate::SharedState;
use interflow_expose::client::ExposeArgs;
use interflow_expose::profile::{self, Profile};
use interflow_mesh::agent::AgentState;
use tauri::{AppHandle, State};

fn lock_error() -> String {
    "internal state lock poisoned".to_string()
}

#[tauri::command]
pub fn load_profile() -> Result<Profile, String> {
    profile::load().map_err(|e| e.to_string())
}

#[tauri::command]
#[allow(clippy::needless_pass_by_value)] // Tauri command parameters must be deserialized by value
pub fn save_profile(profile: Profile) -> Result<(), String> {
    profile::save(&profile).map_err(|e| e.to_string())
}

#[tauri::command]
pub fn profile_path() -> Result<String, String> {
    profile::profile_path()
        .map(|p| p.display().to_string())
        .map_err(|e| e.to_string())
}

#[tauri::command]
pub fn generate_agent_id() -> String {
    interflow_expose::client::default_agent_id()
}

/// Parameters for starting the tunnel (frontend form → Rust).
#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TunnelConfig {
    pub local_ports: Vec<u16>,
    pub hub_url: String,
    pub auth_token: String,
    pub agent_id: String,
    pub ca_path: Option<String>,
}

#[tauri::command]
pub async fn start_tunnel(
    app: AppHandle,
    state: State<'_, SharedState>,
    config: TunnelConfig,
) -> Result<(), String> {
    // Boundary validation (system boundary: user input)
    if config.local_ports.is_empty() {
        return Err("at least one local port is required".into());
    }
    if config.hub_url.trim().is_empty() {
        return Err("missing hub URL".into());
    }
    if config.auth_token.trim().is_empty() {
        return Err("missing token".into());
    }
    if config.agent_id.trim().is_empty() {
        return Err("missing agent ID".into());
    }
    if let Some(ca) = config
        .ca_path
        .as_deref()
        .filter(|s| !s.is_empty() && !std::path::Path::new(s).exists())
    {
        return Err(format!("CA file does not exist: {ca}"));
    }

    let args = ExposeArgs {
        local_ports: config.local_ports,
        hub_url: config.hub_url,
        auth_token: config.auth_token,
        agent_id: config.agent_id,
        ca_path: config.ca_path.filter(|s| !s.is_empty()),
    };

    let manager = {
        let guard = state.lock().map_err(|_| lock_error())?;
        guard.tunnel.clone()
    };
    manager.start(&app, args).await
}

#[tauri::command]
pub async fn stop_tunnel(state: State<'_, SharedState>) -> Result<(), String> {
    let manager = {
        let guard = state.lock().map_err(|_| lock_error())?;
        guard.tunnel.clone()
    };
    manager.stop().await
}

#[tauri::command]
pub async fn get_state(state: State<'_, SharedState>) -> Result<AgentState, String> {
    let manager = {
        let guard = state.lock().map_err(|_| lock_error())?;
        guard.tunnel.clone()
    };
    Ok(manager.state().await)
}

#[tauri::command]
#[allow(clippy::needless_pass_by_value)] // Tauri command parameters must be injected by value
pub fn get_recent_logs(
    state: State<'_, SharedState>,
) -> Result<Vec<crate::tracing_capture::LogLine>, String> {
    let guard = state.lock().map_err(|_| lock_error())?;
    Ok(guard.logs.snapshot())
}
