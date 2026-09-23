//! Tauri invoke commands: node list management + per-node lifecycle + state
//! and log queries.
//!
//! The IPC schema (argument/return/event types) lives in [`crate::contract`]
//! and is exported to `src/bindings.ts` via tauri-specta — `#[specta::specta]`
//! registers each command in that generated contract.
//!
//! Persistence is incremental: add/remove/prefs/start/stop mutate the
//! in-memory node set and persist through the manager's sink; there is no
//! whole-profile save command.

use crate::SharedState;
use crate::contract::{
    AddNodeParams, DeployPackDto, ImportedPackDto, LocalNodeRefDto, ManifestTemplateParams,
    NodeInfo, NodePrefs, PackInspection, UpdatedNodeDto,
};
use crate::deploy;
use crate::node::{self, NodeKind, NodeSpec};
use interflow_core::config::paths::expand_tilde;
use interflow_mesh::config::TransportKind;
use std::path::PathBuf;
use tauri::State;

/// Expands `~` only (the deploy fields are inputs, not existing paths).
fn expanded(field: &str) -> PathBuf {
    PathBuf::from(expand_tilde(field))
}

fn lock_error() -> String {
    "internal state lock poisoned".to_string()
}

fn manager(state: &State<'_, SharedState>) -> Result<node::NodeManager, String> {
    let guard = state.lock().map_err(|_| lock_error())?;
    Ok(guard.nodes.clone())
}

/// Expands a leading `~` (hand-typed paths are shell muscle memory; Browse
/// emits absolute paths) and verifies existence. The expanded value is what
/// gets used, while the error shows the user's original input.
fn expanded_existing(field: &mut String, label: &str) -> Result<(), String> {
    let expanded = expand_tilde(field);
    if !std::path::Path::new(&expanded).exists() {
        return Err(format!("{label} does not exist: {field}"));
    }
    *field = expanded;
    Ok(())
}

/// Lists the managed nodes (name order).
#[tauri::command]
#[specta::specta]
#[allow(clippy::needless_pass_by_value)] // Tauri command parameters must be injected by value
pub fn list_nodes(state: State<'_, SharedState>) -> Result<Vec<NodeInfo>, String> {
    Ok(manager(&state)?
        .snapshots()
        .into_iter()
        .map(Into::into)
        .collect())
}

/// Validates a pack directory through the shared funnel and reports what it
/// is — the add flow's preview. Nothing is persisted.
#[tauri::command]
#[specta::specta]
pub fn inspect_pack(mut pack_dir: String) -> Result<PackInspection, String> {
    expanded_existing(&mut pack_dir, "Credential Pack directory")?;
    node::inspect_pack(std::path::Path::new(&pack_dir)).map(PackInspection::from)
}

/// Adds a node from a pack directory (kind and name come from the pack).
#[tauri::command]
#[specta::specta]
#[allow(clippy::needless_pass_by_value)] // Tauri command parameters must be deserialized by value
pub async fn add_node(
    state: State<'_, SharedState>,
    mut params: AddNodeParams,
) -> Result<NodeInfo, String> {
    expanded_existing(&mut params.pack_dir, "Credential Pack directory")?;
    let info = node::inspect_pack(std::path::Path::new(&params.pack_dir))?;
    let spec = NodeSpec {
        id: String::new(), // minted by the manager
        kind: info.kind,
        name: info.name,
        principal: Some(info.principal),
        pack_dir: std::path::PathBuf::from(&params.pack_dir),
        transport: params.transport.map(TransportKind::from),
        hub_quic_addr: params.hub_quic_addr.filter(|s| !s.trim().is_empty()),
        generation: info.generation,
        pack_services: info.services,
        pack_mesh: info.mesh,
        pack_listen: info.listen,
        // Fresh node: every service starts on its pack default.
        service_addresses: Default::default(),
    };
    let id = manager(&state)?.add(spec)?;
    let created = manager(&state)?
        .snapshots()
        .into_iter()
        .find(|s| s.spec.id == id)
        .expect("just inserted");
    Ok(created.into())
}

/// Removes a node (must be stopped).
#[tauri::command]
#[specta::specta]
#[allow(clippy::needless_pass_by_value)] // Tauri command parameters must be injected by value
pub fn remove_node(state: State<'_, SharedState>, id: String) -> Result<(), String> {
    manager(&state)?.remove(&id)
}

/// Starts one node (user action).
///
/// Stays synchronous on purpose: the pack-loading `prepare` is file IO that
/// belongs on Tauri's sync-command pool, and the engine spawns go through
/// the runtime handle the manager holds — safe from threads without an
/// ambient Tokio runtime
///.
#[tauri::command]
#[specta::specta]
#[allow(clippy::needless_pass_by_value)] // Tauri command parameters must be injected by value
pub fn start_node(state: State<'_, SharedState>, id: String) -> Result<(), String> {
    manager(&state)?.start(&id)
}

/// Stops one node (user action; clears the start intent).
#[tauri::command]
#[specta::specta]
pub async fn stop_node(state: State<'_, SharedState>, id: String) -> Result<(), String> {
    manager(&state)?.stop(&id).await
}

/// Stops every running node (app quit path).
#[tauri::command]
#[specta::specta]
pub async fn stop_all_nodes(state: State<'_, SharedState>) -> Result<(), String> {
    manager(&state)?.stop_all().await;
    Ok(())
}

/// Updates an agent node's runtime preferences (stopped nodes only).
#[tauri::command]
#[specta::specta]
#[allow(clippy::needless_pass_by_value)] // Tauri command parameters must be deserialized by value
pub fn update_node_prefs(
    state: State<'_, SharedState>,
    id: String,
    prefs: NodePrefs,
) -> Result<(), String> {
    let manager = manager(&state)?;
    let kind = manager
        .snapshots()
        .into_iter()
        .find(|s| s.spec.id == id)
        .map(|s| s.spec.kind)
        .ok_or_else(|| "unknown node".to_string())?;
    if !matches!(kind, NodeKind::ExposeAgent | NodeKind::MeshAgent) {
        return Err(
            "only agent nodes have local preferences — what this node is (identity, \
                    services) still comes entirely from its pack"
                .into(),
        );
    }
    manager.set_prefs(
        &id,
        prefs.transport.map(TransportKind::from),
        prefs.hub_quic_addr.filter(|s| !s.trim().is_empty()),
        &prefs
            .service_addresses
            .iter()
            .map(|p| crate::profile::ServiceAddressPref {
                id: p.id.clone(),
                address: p.address.clone(),
            })
            .collect::<Vec<_>>(),
    )
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

/// This machine's hostname — the GUI is machine-scoped, and the window
/// header/tray anchor on it (nodes are identities, not machines; a machine
/// can run any number of them).
#[tauri::command]
#[specta::specta]
pub fn get_host_name() -> Result<String, String> {
    gethostname::gethostname()
        .into_string()
        .map_err(|e| format!("hostname unavailable: {}", e.to_string_lossy()))
}

// -------------------------------------------------------------------------
// Deploy (operator) surface — the GUI twin of the `interflow` plan/rotate/
// revoke/pack commands, sharing the exact same library code paths.
// -------------------------------------------------------------------------

/// Renders the starter manifest template (the builder form's output).
#[tauri::command]
#[specta::specta]
#[allow(clippy::needless_pass_by_value, clippy::unnecessary_wraps)] // Tauri command shape
pub fn deploy_manifest_template(params: ManifestTemplateParams) -> Result<String, String> {
    Ok(interflow_cli::plan::setup_template(
        &params.realm,
        &params.control_endpoint,
        &params.registrar_endpoint,
        &params.host,
        &params.agent,
        &params.service,
        &params.service_address,
    ))
}

/// Reads a manifest (or any text file the deploy pane edits).
#[tauri::command]
#[specta::specta]
#[allow(clippy::needless_pass_by_value)] // Tauri command parameters arrive by value
pub fn deploy_read_text(path: String) -> Result<String, String> {
    let path = expanded(&path);
    std::fs::read_to_string(&path).map_err(|e| format!("read {}: {e}", path.display()))
}

/// Saves the deploy pane's manifest text back to its path (atomic enough for
/// an editor pane: write-to-temp + rename).
#[tauri::command]
#[specta::specta]
#[allow(clippy::needless_pass_by_value)] // Tauri command parameters arrive by value
pub fn deploy_write_text(path: String, text: String) -> Result<(), String> {
    let path = expanded(&path);
    let tmp = path.with_extension("toml.tmp");
    std::fs::write(&tmp, text).map_err(|e| format!("write {}: {e}", tmp.display()))?;
    std::fs::rename(&tmp, &path).map_err(|e| format!("replace {}: {e}", path.display()))
}

/// Validates a manifest; returns the human-readable report lines.
#[tauri::command]
#[specta::specta]
pub async fn deploy_validate(manifest: String) -> Result<Vec<String>, String> {
    let path = expanded(&manifest);
    tauri::async_runtime::spawn_blocking(move || {
        interflow_cli::plan::validate(&path).map_err(|e| e.to_string())
    })
    .await
    .map_err(|e| e.to_string())?
}

/// Issues identities + packs from the manifest (the deploy page's Apply).
#[tauri::command]
#[specta::specta]
pub async fn deploy_apply(
    manifest: String,
    issuer: String,
    out: String,
) -> Result<Vec<String>, String> {
    let (manifest, issuer, out) = (expanded(&manifest), expanded(&issuer), expanded(&out));
    tauri::async_runtime::spawn_blocking(move || {
        interflow_cli::plan::apply(&manifest, &issuer, &out).map_err(|e| e.to_string())
    })
    .await
    .map_err(|e| e.to_string())?
}

/// Lists the packs of a dist tree (the page's pack cards), enriched with
/// the local node matching each pack's identity — the "update local node"
/// hook (P1-2).
#[tauri::command]
#[specta::specta]
pub async fn deploy_list_packs(
    state: State<'_, SharedState>,
    out_root: String,
) -> Result<Vec<DeployPackDto>, String> {
    let root = expanded(&out_root);
    let packs = tauri::async_runtime::spawn_blocking(move || deploy::list_packs(&root))
        .await
        .map_err(|e| e.to_string())??;
    let local: Vec<(String, String, String, u64)> = manager(&state)?
        .snapshots()
        .into_iter()
        .filter_map(|s| {
            s.spec
                .principal
                .map(|p| (p, s.spec.id, s.spec.name, s.spec.generation))
        })
        .collect();
    Ok(packs
        .into_iter()
        .map(|pack| {
            let local_node = local.iter().find_map(|(principal, id, name, generation)| {
                (principal == &pack.principal).then(|| LocalNodeRefDto {
                    id: id.clone(),
                    name: name.clone(),
                    generation: u32::try_from(*generation).unwrap_or(u32::MAX),
                })
            });
            DeployPackDto {
                local_node,
                ..DeployPackDto::from(pack)
            }
        })
        .collect())
}

/// Seals a pack directory into a distributable `.iflowpack`.
#[tauri::command]
#[specta::specta]
pub async fn deploy_seal_pack(
    pack_dir: String,
    out_file: String,
    passphrase: String,
) -> Result<(), String> {
    let (pack_dir, out_file) = (expanded(&pack_dir), expanded(&out_file));
    tauri::async_runtime::spawn_blocking(move || {
        deploy::seal_pack(&pack_dir, &out_file, &passphrase)
    })
    .await
    .map_err(|e| e.to_string())?
}

/// Installs a sealed `.iflowpack` into the GUI-managed packs root — the
/// import half of "drag a pack in, add as node".
#[tauri::command]
#[specta::specta]
pub async fn deploy_install_sealed(
    sealed: String,
    passphrase: String,
) -> Result<ImportedPackDto, String> {
    let sealed = expanded(&sealed);
    tauri::async_runtime::spawn_blocking(move || {
        let imported = deploy::install_sealed(&sealed, &passphrase)?;
        Ok(ImportedPackDto {
            pack_dir: imported.pack_dir.display().to_string(),
            inspection: PackInspection::from(imported.info),
        })
    })
    .await
    .map_err(|e| e.to_string())?
}

/// Updates a local node's pack in place from a dist-tree pack directory
/// (P1-2: the GUI side of `node install`): stop → identity-checked swap
/// (state carried, `.previous` kept) → restore the start intent.
#[tauri::command]
#[specta::specta]
#[allow(clippy::needless_pass_by_value)] // Tauri command parameters must be deserialized by value
pub async fn deploy_update_node(
    state: State<'_, SharedState>,
    node_id: String,
    mut source_dir: String,
) -> Result<UpdatedNodeDto, String> {
    expanded_existing(&mut source_dir, "source pack directory")?;
    let report = manager(&state)?
        .update_pack(&node_id, std::path::Path::new(&source_dir))
        .await?;
    let node = manager(&state)?
        .snapshots()
        .into_iter()
        .find(|s| s.spec.id == node_id)
        .ok_or_else(|| "node vanished during update".to_string())?;
    Ok(UpdatedNodeDto {
        node: node.into(),
        generation_from: u32::try_from(report.generation_from).unwrap_or(u32::MAX),
        generation_to: u32::try_from(report.generation_to).unwrap_or(u32::MAX),
        restarted: report.restarted,
    })
}

/// Rotates one node's credential (issues the next generation).
#[tauri::command]
#[specta::specta]
pub async fn deploy_rotate(
    manifest: String,
    issuer: String,
    node: String,
    pack: Option<String>,
) -> Result<Vec<String>, String> {
    let (manifest, issuer) = (expanded(&manifest), expanded(&issuer));
    let pack = pack.map(|p| expanded(&p));
    tauri::async_runtime::spawn_blocking(move || {
        interflow_cli::plan::rotate(&manifest, &issuer, &node, pack.as_deref(), None)
            .map_err(|e| e.to_string())
    })
    .await
    .map_err(|e| e.to_string())?
}

/// Revokes a pack (deny list + CRL).
#[tauri::command]
#[specta::specta]
pub async fn deploy_revoke(
    issuer: String,
    pack: String,
    reason: String,
) -> Result<Vec<String>, String> {
    let (issuer, pack) = (expanded(&issuer), expanded(&pack));
    tauri::async_runtime::spawn_blocking(move || {
        interflow_cli::plan::revoke(&issuer, &pack, &reason).map_err(|e| e.to_string())
    })
    .await
    .map_err(|e| e.to_string())?
}

#[cfg(test)]
mod tests {
    use super::expanded_existing;

    /// A hand-typed `~/…` path that does not exist must fail with the
    /// user's original input in the message (the 2026-09-18 papercut:
    /// `~` reached `Path::exists` as a literal).
    #[test]
    fn expanded_existing_reports_missing_tilde_path_with_original_input() {
        let mut field = "~/interflow-packs/missing-pack".to_string();
        let err = expanded_existing(&mut field, "Credential Pack directory")
            .expect_err("missing pack must fail");
        assert!(
            err.contains("Credential Pack directory does not exist")
                && err.contains("~/interflow-packs/missing-pack"),
            "wrong message: {err}"
        );
    }

    /// A real directory passes; an already-absolute input stays
    /// byte-identical (normalization must not rewrite what Browse picked).
    #[test]
    fn expanded_existing_accepts_real_directory_unchanged() {
        let dir = tempfile::tempdir().expect("temp dir");
        let mut field = dir.path().display().to_string();
        expanded_existing(&mut field, "Credential Pack directory")
            .expect("existing directory passes");
        assert_eq!(field, dir.path().display().to_string());
    }
}
