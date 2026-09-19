//! Tauri invoke commands: profile read/write + tunnel start/stop + state/log queries.
//!
//! The IPC schema (argument/return/event types) lives in [`crate::contract`]
//! and is exported to `src/bindings.ts` via tauri-specta — `#[specta::specta]`
//! registers each command in that generated contract.

use crate::SharedState;
use crate::contract::{Profile, TunnelConfig, TunnelState};
use interflow_core::config::paths::expand_tilde;
use interflow_expose::profile;
use tauri::State;

fn lock_error() -> String {
    "internal state lock poisoned".to_string()
}

/// Expands a leading `~` (hand-typed paths are shell muscle memory; Browse
/// emits absolute paths) and verifies existence. The expanded value is what
/// gets launched — the TLS loaders resolve no shell syntax — while the error
/// shows the user's original input. The form itself is frontend state and
/// keeps what the user typed.
fn expanded_existing(field: &mut String, label: &str) -> Result<(), String> {
    let expanded = expand_tilde(field);
    if !std::path::Path::new(&expanded).exists() {
        return Err(format!("{label} does not exist: {field}"));
    }
    *field = expanded;
    Ok(())
}

/// Boundary validation + normalization for Start (system boundary: user
/// input). Pure with respect to the tunnel manager, so it is unit-testable
/// without a Tauri app handle. The identity check (`agent_id == client
/// certificate CN`) lives one layer down, in `AgentClient` construction —
/// the single funnel every entry (GUI, CLIs, edge) passes through.
fn validate_start_config(config: &mut TunnelConfig) -> Result<(), String> {
    if config.local_ports.is_empty() {
        return Err("at least one local port is required".into());
    }
    if config.hub_url.trim().is_empty() {
        return Err("missing hub URL".into());
    }
    if config.client_cert.trim().is_empty() || config.client_key.trim().is_empty() {
        return Err("missing client certificate/key".into());
    }
    if config.agent_id.trim().is_empty() {
        return Err("missing agent ID".into());
    }
    expanded_existing(&mut config.client_cert, "client certificate file")?;
    expanded_existing(&mut config.client_key, "client key file")?;
    if let Some(ca) = config.ca_path.as_mut().filter(|s| !s.is_empty()) {
        expanded_existing(ca, "CA file")?;
    }
    Ok(())
}

#[tauri::command]
#[specta::specta]
pub fn load_profile() -> Result<Profile, String> {
    profile::load()
        .map(Profile::from)
        .map_err(|e| e.to_string())
}

#[tauri::command]
#[specta::specta]
#[allow(clippy::needless_pass_by_value)] // Tauri command parameters must be deserialized by value
pub fn save_profile(profile: Profile) -> Result<(), String> {
    profile::save(&profile.into()).map_err(|e| e.to_string())
}

#[tauri::command]
#[specta::specta]
pub fn generate_agent_id() -> String {
    interflow_expose::client::default_agent_id()
}

#[tauri::command]
#[specta::specta]
pub async fn start_tunnel(
    state: State<'_, SharedState>,
    mut config: TunnelConfig,
) -> Result<(), String> {
    validate_start_config(&mut config)?;

    let args = config.into();

    let manager = {
        let guard = state.lock().map_err(|_| lock_error())?;
        guard.tunnel.clone()
    };
    manager.start(&args)
}

#[tauri::command]
#[specta::specta]
pub async fn stop_tunnel(state: State<'_, SharedState>) -> Result<(), String> {
    let manager = {
        let guard = state.lock().map_err(|_| lock_error())?;
        guard.tunnel.clone()
    };
    manager.stop().await
}

#[tauri::command]
#[specta::specta]
pub async fn get_state(state: State<'_, SharedState>) -> Result<TunnelState, String> {
    let manager = {
        let guard = state.lock().map_err(|_| lock_error())?;
        guard.tunnel.clone()
    };
    Ok(TunnelState::from(manager.state()))
}

#[tauri::command]
#[specta::specta]
#[allow(clippy::needless_pass_by_value)] // Tauri command parameters must be injected by value
pub fn get_recent_logs(
    state: State<'_, SharedState>,
) -> Result<Vec<crate::tracing_capture::LogLine>, String> {
    let guard = state.lock().map_err(|_| lock_error())?;
    Ok(guard.logs.snapshot())
}

/// Clears the backend ring buffer too, not just the frontend view — the
/// buffer is replayed on webview reload/reconnect, so a view-only clear
/// would resurrect the cleared lines.
#[tauri::command]
#[specta::specta]
#[allow(clippy::needless_pass_by_value)] // Tauri command parameters must be injected by value
pub fn clear_logs(state: State<'_, SharedState>) -> Result<(), String> {
    let guard = state.lock().map_err(|_| lock_error())?;
    guard.logs.clear();
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::validate_start_config;
    use crate::contract::TunnelConfig;

    fn config_with(cert: &str, key: &str, ca: Option<&str>) -> TunnelConfig {
        TunnelConfig {
            local_ports: vec![8080],
            hub_url: "https://hub.example.com:6666".to_string(),
            client_cert: cert.to_string(),
            client_key: key.to_string(),
            agent_id: "agent-a".to_string(),
            ca_path: ca.map(str::to_string),
            transport: None,
            hub_quic_addr: None,
        }
    }

    /// A hand-typed `~/…` path that does not exist must fail with the
    /// user's original input in the message (the 2026-09-18 papercut:
    /// `~` reached `Path::exists` as a literal).
    #[test]
    fn validate_reports_missing_tilde_path_with_original_input() {
        let mut config = config_with("~/interflow-certs/missing-ca.crt", "/etc/hosts", None);
        let err = validate_start_config(&mut config).expect_err("missing cert must fail");
        assert!(
            err.contains("client certificate file does not exist")
                && err.contains("~/interflow-certs/missing-ca.crt"),
            "wrong message: {err}"
        );
    }

    /// Real files pass validation; an already-absolute input stays
    /// byte-identical (normalization must not rewrite what Browse picked).
    #[test]
    fn validate_accepts_real_files_unchanged() {
        let certs = interflow_testkit::certs::TestCerts::generate("gui-validate", "agent-a");
        let (cert, key) = certs.client_paths();
        let ca = certs.ca_path().display().to_string();
        let mut config = config_with(
            &cert.display().to_string(),
            &key.display().to_string(),
            Some(&ca),
        );
        validate_start_config(&mut config).expect("valid config passes");
        assert_eq!(config.client_cert, cert.display().to_string());
        assert_eq!(config.ca_path.as_deref(), Some(ca.as_str()));
    }

    /// Empty CA stays None-shaped (the From filter keeps treating it as
    /// absent) and does not trip the existence check.
    #[test]
    fn validate_treats_empty_ca_as_absent() {
        let certs = interflow_testkit::certs::TestCerts::generate("gui-validate-empty", "agent-a");
        let (cert, key) = certs.client_paths();
        let mut config = config_with(
            &cert.display().to_string(),
            &key.display().to_string(),
            Some(""),
        );
        validate_start_config(&mut config).expect("empty CA is absent, not missing");
    }

    /// The non-empty boundary checks keep their original messages.
    #[test]
    fn validate_keeps_missing_field_messages() {
        let mut config = config_with("", "/etc/hosts", None);
        assert_eq!(
            validate_start_config(&mut config).expect_err("must fail"),
            "missing client certificate/key"
        );
        let certs = interflow_testkit::certs::TestCerts::generate("gui-validate-fields", "agent-a");
        let (cert, key) = certs.client_paths();
        let mut config = config_with(
            &cert.display().to_string(),
            &key.display().to_string(),
            None,
        );
        config.agent_id = "  ".to_string();
        assert_eq!(
            validate_start_config(&mut config).expect_err("must fail"),
            "missing agent ID"
        );
    }
}
