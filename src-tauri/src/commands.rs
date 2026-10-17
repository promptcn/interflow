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
    AddNodeParams, AddedNodeDto, ApplyReportDto, ChangeStateDto, ControlProposalDto,
    DeployContextDto, DeployDefaultsDto, DeployPackDto, DeployPrefsDto, DeploymentDto,
    EditActionDto, EditedManifestDto, FleetDto, GuiPrefsDto, HubOverviewDto, ImportedPackDto,
    IssueNodeParams, LocalNodeRefDto, ManifestSummaryDto, ManifestTemplateParams,
    MeshTemplateParams, NodeInfo, NodePrefs, NodeUpdateFailureDto, PackInspection,
    ProposalSubmitOutcomeDto, PublishKindDto, PublishResultDto, SealedPackDto,
    StreamProposalRequestDto, UpdatedNodeDto, VersionInfo,
};
use crate::deploy;
use crate::i18n;
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
/// gets used, while the error shows the user's original input. `s` carries
/// the caller's language so the error speaks it (tests pin English).
fn expanded_existing(field: &mut String, label: &str, s: &i18n::Strings) -> Result<(), String> {
    let expanded = expand_tilde(field);
    if !std::path::Path::new(&expanded).exists() {
        return Err(i18n::render(
            s.err_path_not_exists,
            &[("label", label), ("path", field)],
        ));
    }
    *field = expanded;
    Ok(())
}

/// Lists the managed nodes (name order). The assembly lives in
/// [`node_infos`] so tests can assert on exactly what the GUI command
/// layer produces (the 2026-10-07 stale-panel bug hid in the gap between
/// the domain query and this composition).
#[tauri::command]
#[specta::specta]
#[allow(clippy::needless_pass_by_value)] // Tauri command parameters must be injected by value
pub fn list_nodes(state: State<'_, SharedState>) -> Result<Vec<NodeInfo>, String> {
    let manager = manager(&state)?;
    Ok(node_infos(&manager))
}

/// One full `NodeInfo` per managed node: the snapshot plus the credential,
/// policy, and peer health faces. This is the single composition the GUI's
/// node faces consume, on demand and (via `list_nodes`) as the baseline
/// behind the `policy-plane` / `mesh-peers` event streams.
pub fn node_infos(manager: &node::NodeManager) -> Vec<NodeInfo> {
    manager
        .snapshots()
        .into_iter()
        .map(|snapshot| {
            let id = snapshot.spec.id.clone();
            let mut info: NodeInfo = snapshot.into();
            info.credential = manager.credential_health(&id).map(Into::into);
            info.policy = manager.policy_plane(&id).map(Into::into);
            info.peers = manager.peers_plane(&id).map(Into::into);
            info.proposals = manager
                .proposals_plane(&id)
                .map(|receipts| receipts.into_iter().map(Into::into).collect());
            info.listeners = manager
                .listeners_plane(&id)
                .map(|faces| faces.into_iter().map(Into::into).collect());
            info
        })
        .collect()
}

/// Validates a pack directory through the shared funnel and reports what it
/// is — the add flow's preview. Nothing is persisted.
#[tauri::command]
#[specta::specta]
pub fn inspect_pack(mut pack_dir: String) -> Result<PackInspection, String> {
    let s = i18n::current();
    expanded_existing(&mut pack_dir, s.label_credential_pack_dir, s)?;
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
    let s = i18n::current();
    expanded_existing(&mut params.pack_dir, s.label_credential_pack_dir, s)?;
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
        pack_digest: info.digest,
        pack_services: info.services,
        pack_mesh: info.mesh,
        pack_listen: info.listen,
        pack_transport: info.transport,
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

/// Updates an agent node's runtime preferences. Service addresses apply
/// live on a running expose agent (the egress table re-derives; no
/// restart); transport and the hub QUIC address stay stopped-only — the
/// dial face must re-connect.
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
        .ok_or_else(|| i18n::current().err_unknown_node.to_string())?;
    if !matches!(kind, NodeKind::ExposeAgent | NodeKind::MeshAgent) {
        return Err(i18n::current().err_agent_prefs_only.to_string());
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
    gethostname::gethostname().into_string().map_err(|e| {
        i18n::render(
            i18n::current().err_hostname,
            &[("err", &e.to_string_lossy())],
        )
    })
}

/// This build's identity (machine header): crate version + the compile-time
/// build tag the engine binaries also log at startup.
#[tauri::command]
#[specta::specta]
#[allow(clippy::unnecessary_wraps)] // Tauri command shape
pub fn get_version_info() -> Result<VersionInfo, String> {
    Ok(VersionInfo {
        version: env!("CARGO_PKG_VERSION").to_string(),
        build_tag: interflow_buildinfo::BUILD_TAG.to_string(),
        dirty: interflow_buildinfo::DIRTY,
    })
}

// -------------------------------------------------------------------------
// Deploy (operator) surface — the GUI twin of the `interflow-cli` plan/rotate/
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

/// Reads the manifest (or any text file the deploy pane edits) with its
/// freshness token — the digest Saving hands back for the changed-on-disk
/// check. A missing file is named in the user's language — the
/// read-failure class the Overview must be able to tell apart from a TOML
/// syntax error.
#[tauri::command]
#[specta::specta]
#[allow(clippy::needless_pass_by_value)] // Tauri command parameters arrive by value
pub fn deploy_read_text(path: String) -> Result<crate::contract::DeployTextDto, String> {
    let path = expanded(&path);
    let document = interflow_cli::manifest_edit::read_manifest(&path).map_err(|e| {
        let s = i18n::current();
        if let interflow_core::error::InterflowError::Io(source) = &e
            && source.kind() == std::io::ErrorKind::NotFound
        {
            return i18n::render(s.err_not_found, &[("path", &path.display().to_string())]);
        }
        i18n::render(
            s.err_read,
            &[
                ("path", &path.display().to_string()),
                ("err", &e.to_string()),
            ],
        )
    })?;
    Ok(crate::contract::DeployTextDto {
        text: document.text,
        digest: document.digest,
    })
}

/// Saves the deploy pane's manifest text back to its path — the editor's
/// single write path, now with the changed-on-disk guard: `expected_digest`
/// is the freshness token from the read; a mismatch is NOT an error string
/// but a `Conflict` outcome carrying the current disk document (the
/// editor offers reload-or-keep; last-writer-wins clobbering is gone).
#[tauri::command]
#[specta::specta]
#[allow(clippy::needless_pass_by_value)] // Tauri command parameters arrive by value
pub fn deploy_write_text(
    path: String,
    text: String,
    expected_digest: Option<String>,
) -> Result<crate::contract::SaveManifestOutcomeDto, String> {
    let path = expanded(&path);
    let write =
        interflow_cli::manifest_edit::save_manifest(&path, &text, expected_digest.as_deref());
    let Err(e) = write else {
        return Ok(crate::contract::SaveManifestOutcomeDto::Saved {
            digest: interflow_util::sha256_hex(text.as_bytes()),
        });
    };
    if matches!(e, interflow_core::error::InterflowError::Conflict { .. }) {
        // Hand back what the disk holds now — the reload choice is one
        // round trip. A read failure here degrades to the plain error.
        return match interflow_cli::manifest_edit::read_manifest(&path) {
            Ok(current) => Ok(crate::contract::SaveManifestOutcomeDto::Conflict {
                text: current.text,
                digest: current.digest,
            }),
            Err(read_err) => {
                let s = i18n::current();
                Err(i18n::render(
                    s.err_read,
                    &[
                        ("path", &path.display().to_string()),
                        ("err", &read_err.to_string()),
                    ],
                ))
            }
        };
    }
    let s = i18n::current();
    Err(i18n::render(
        s.err_write,
        &[
            ("path", &path.display().to_string()),
            ("err", &e.to_string()),
        ],
    ))
}

/// The deployments root backing the deploy pane's placeholders and the
/// create-deployment dialog's starting folder: **one deployment = one
/// folder**, named by realm, under `~/interflow-deployments/`. Inside,
/// the names are fixed — `interflow.toml` / `issuer/` / `dist/` — which is
/// exactly the CLI's CWD-relative default set, so a `cd` into the folder
/// makes every CLI flag optional and the GUI's triple collapses to one
/// root. The root sits in the home directory (visible, operator-browsable,
/// never touched by the Documents-folder cloud sync); key material stays
/// protected by permissions (0600), not by hiding.
#[tauri::command]
#[specta::specta]
#[allow(clippy::unnecessary_wraps)] // Tauri command shape — every command returns Result
pub fn deploy_defaults() -> Result<DeployDefaultsDto, String> {
    Ok(DeployDefaultsDto {
        root: dirs::home_dir()
            .unwrap_or_else(std::env::temp_dir)
            .join("interflow-deployments")
            .display()
            .to_string(),
    })
}

/// Creates a new manifest at `path` from generated template text — the
/// write half of the create-deployment flow. Mirrors `interflow-cli
/// setup`: an existing file is refused outright (Save-in-the-editor stays
/// the only path that may overwrite, with its `.bak` discipline); missing
/// parent directories are created because template text always targets a
/// fresh deployment folder.
#[tauri::command]
#[specta::specta]
#[allow(clippy::needless_pass_by_value)] // Tauri command parameters arrive by value
pub fn deploy_create_manifest(path: String, text: String) -> Result<(), String> {
    let path = expanded(&path);
    let s = i18n::current();
    if path.exists() {
        return Err(i18n::render(
            s.err_manifest_exists,
            &[("path", &path.display().to_string())],
        ));
    }
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).map_err(|e| {
            i18n::render(
                s.err_write,
                &[
                    ("path", &parent.display().to_string()),
                    ("err", &e.to_string()),
                ],
            )
        })?;
    }
    interflow_util::atomic_write(
        &path,
        text.as_bytes(),
        interflow_util::WriteMode::PreserveOr(0o644),
    )
    .map_err(|e| {
        i18n::render(
            s.err_write,
            &[
                ("path", &path.display().to_string()),
                ("err", &e.to_string()),
            ],
        )
    })
}

/// Parses manifest text into the Form view's read model — shape-level, so
/// an under-construction document (a fresh mesh skeleton) still renders,
/// with its validation issues attached. A parse failure carries the source
/// chain (TOML position) for the TOML view to point at.
#[tauri::command]
#[specta::specta]
#[allow(clippy::needless_pass_by_value, clippy::unnecessary_wraps)] // Tauri command shape
pub fn deploy_parse_manifest(text: String) -> Result<ManifestSummaryDto, String> {
    match interflow_cli::manifest_edit::summarize(&text) {
        Ok(summary) => Ok(summary.into()),
        Err(e) => Err(interflow_cli::manifest_edit::error_chain(&e)),
    }
}

/// Applies one structured manifest edit — pure: `text → validated text`,
/// comments and layout preserved (the document model's one funnel). The
/// editor keeps owning the file write; this never touches the disk.
#[tauri::command]
#[specta::specta]
#[allow(clippy::needless_pass_by_value)] // Tauri command parameters arrive by value
pub fn deploy_edit_manifest(
    text: String,
    action: EditActionDto,
) -> Result<EditedManifestDto, String> {
    let action = interflow_cli::manifest_edit::ManifestEdit::from(action);
    let edited = interflow_cli::manifest_edit::apply_edit(&text, &action)
        .map_err(|e| interflow_cli::manifest_edit::error_chain(&e))?;
    let summary = interflow_cli::manifest_edit::summarize(&edited)
        .map_err(|e| interflow_cli::manifest_edit::error_chain(&e))?;
    Ok(EditedManifestDto {
        text: edited,
        summary: summary.into(),
    })
}

/// Renders the site-to-site (mesh) starter skeleton (the builder form's
/// second template).
#[tauri::command]
#[specta::specta]
#[allow(clippy::needless_pass_by_value, clippy::unnecessary_wraps)] // Tauri command shape
pub fn deploy_mesh_template(params: MeshTemplateParams) -> Result<String, String> {
    Ok(interflow_cli::plan::setup_mesh_template(
        &params.realm,
        &params.hub_name,
        &params.hub_endpoint,
    ))
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
#[allow(clippy::needless_pass_by_value)] // Tauri command parameters must be injected by value
pub async fn deploy_apply(
    manifest: String,
    issuer: String,
    out: String,
) -> Result<ApplyReportDto, String> {
    let (manifest, issuer, out) = (expanded(&manifest), expanded(&issuer), expanded(&out));
    tauri::async_runtime::spawn_blocking(move || {
        interflow_cli::plan::apply(
            &manifest,
            &issuer,
            &out,
            false,
            &interflow_cli::plan::BackupInitOptions::default(),
            false,
        )
        .map(ApplyReportDto::from)
        .map_err(|e| e.to_string())
    })
    .await
    .map_err(|e| e.to_string())?
}

/// The bookkeeping-level "would apply do anything" pre-check — the Deploy
/// overview's "unapplied changes" badge and next-steps face. No minting,
/// no hub dial (apply re-runs the full watermark-aware funnel).
#[tauri::command]
#[specta::specta]
#[allow(clippy::needless_pass_by_value)] // Tauri command parameters must be injected by value
pub async fn deploy_change_state(
    manifest: String,
    issuer: String,
) -> Result<ChangeStateDto, String> {
    let (manifest, issuer) = (expanded(&manifest), expanded(&issuer));
    tauri::async_runtime::spawn_blocking(move || {
        interflow_cli::plan::change_state(&manifest, &issuer)
            .map(ChangeStateDto::from)
            .map_err(|e| e.to_string())
    })
    .await
    .map_err(|e| e.to_string())?
}

/// The running hub's operator overview (watermarks + fleet presence and
/// pull convergence) — the Apply-result card and the fleet table's online
/// column. `None` = the manifest names no hub endpoint. Errors (hub
/// unreachable / issuer unreadable) surface as the caller's hint text.
#[tauri::command]
#[specta::specta]
#[allow(clippy::needless_pass_by_value)] // Tauri command parameters must be injected by value
pub async fn deploy_hub_overview(
    manifest: String,
    issuer: String,
) -> Result<Option<HubOverviewDto>, String> {
    let (manifest, issuer) = (expanded(&manifest), expanded(&issuer));
    tauri::async_runtime::spawn_blocking(move || {
        interflow_cli::plan::hub_overview(&manifest, &issuer)
            .map(|o| o.map(HubOverviewDto::from))
            .map_err(|e| e.to_string())
    })
    .await
    .map_err(|e| e.to_string())?
}

/// The hub's stream-proposal queue (the operator's approve/reject face).
/// `None` = the manifest names no hub endpoint.
#[tauri::command]
#[specta::specta]
#[allow(clippy::needless_pass_by_value)] // Tauri command parameters must be injected by value
pub async fn deploy_list_proposals(
    manifest: String,
    issuer: String,
) -> Result<Option<Vec<ControlProposalDto>>, String> {
    let (manifest, issuer) = (expanded(&manifest), expanded(&issuer));
    tauri::async_runtime::spawn_blocking(move || {
        interflow_cli::plan::list_proposals(&manifest, &issuer)
            .map(|list| list.map(|l| l.into_iter().map(Into::into).collect()))
            .map_err(|e| e.to_string())
    })
    .await
    .map_err(|e| e.to_string())?
}

/// Approve one stream proposal: edit the manifest (the single source of
/// truth) → apply (mint + publish, no-op gate protects a double-approve)
/// → record the decision at the hub. Returns the apply report (the
/// Overview's result card renders it like a manual apply).
#[tauri::command]
#[specta::specta]
#[allow(clippy::needless_pass_by_value)] // Tauri command parameters must be injected by value
pub async fn deploy_approve_proposal(
    manifest: String,
    issuer: String,
    out: String,
    id: String,
) -> Result<ApplyReportDto, String> {
    let (manifest, issuer, out) = (expanded(&manifest), expanded(&issuer), expanded(&out));
    tauri::async_runtime::spawn_blocking(move || {
        interflow_cli::plan::approve_proposal(&manifest, &issuer, &out, &id, false)
            .map(ApplyReportDto::from)
            .map_err(|e| e.to_string())
    })
    .await
    .map_err(|e| e.to_string())?
}

/// Reject one stream proposal with a reason (the requester's GUI shows it
/// as the receipt).
#[tauri::command]
#[specta::specta]
#[allow(clippy::needless_pass_by_value)] // Tauri command parameters must be injected by value
pub async fn deploy_reject_proposal(
    manifest: String,
    issuer: String,
    id: String,
    reason: String,
) -> Result<(), String> {
    let (manifest, issuer) = (expanded(&manifest), expanded(&issuer));
    tauri::async_runtime::spawn_blocking(move || {
        interflow_cli::plan::reject_proposal(&manifest, &issuer, &id, &reason)
            .map_err(|e| e.to_string())
    })
    .await
    .map_err(|e| e.to_string())?
}

/// Submits one self-service stream proposal through a running mesh
/// agent's session (the requester's face; the answer is the hub funnel's
/// verdict).
#[tauri::command]
#[specta::specta]
pub async fn mesh_submit_proposal(
    state: State<'_, SharedState>,
    node_id: String,
    request: StreamProposalRequestDto,
) -> Result<ProposalSubmitOutcomeDto, String> {
    let manager = manager(&state)?;
    let wire = interflow_core::tunnel::transport::StreamProposalRequest::from(request);
    manager
        .submit_stream_proposal(&node_id, &wire)
        .await
        .map(Into::into)
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
    let local: Vec<(String, String, String, u64, String)> = manager(&state)?
        .snapshots()
        .into_iter()
        .filter_map(|s| {
            s.spec.principal.map(|p| {
                (
                    p,
                    s.spec.id,
                    s.spec.name,
                    s.spec.generation,
                    s.spec.pack_digest,
                )
            })
        })
        .collect();
    Ok(packs
        .into_iter()
        .map(|pack| {
            let local_node = local
                .iter()
                .find_map(|(principal, id, name, generation, digest)| {
                    (principal == &pack.principal).then(|| LocalNodeRefDto {
                        id: id.clone(),
                        name: name.clone(),
                        generation: u32::try_from(*generation).unwrap_or(u32::MAX),
                        digest: digest.clone(),
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
    let s = i18n::current();
    expanded_existing(&mut source_dir, s.label_source_pack_dir, s)?;
    let report = manager(&state)?
        .update_pack(&node_id, std::path::Path::new(&source_dir))
        .await?;
    let node = manager(&state)?
        .snapshots()
        .into_iter()
        .find(|s| s.spec.id == node_id)
        .ok_or_else(|| i18n::current().err_node_vanished.to_string())?;
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
        interflow_cli::plan::rotate(&manifest, &issuer, &node, pack.as_deref(), None, false)
            .map_err(|e| e.to_string())
    })
    .await
    .map_err(|e| e.to_string())?
}

/// Revokes a pack (deny list + CRL). The node-owned renewal ledger is
/// deliberately OUTSIDE the GUI's revocation domain: killing a running
/// node's runtime credential is a CLI operator action
/// (`revoke --include-active-credentials`), never a one-click button.
#[tauri::command]
#[specta::specta]
pub async fn deploy_revoke(
    issuer: String,
    pack: String,
    reason: String,
) -> Result<Vec<String>, String> {
    let (issuer, pack) = (expanded(&issuer), expanded(&pack));
    tauri::async_runtime::spawn_blocking(move || {
        interflow_cli::plan::revoke(&issuer, &pack, &reason, None, false).map_err(|e| e.to_string())
    })
    .await
    .map_err(|e| e.to_string())?
}

/// Appends a node to the manifest — the issue wizard's core step, the GUI
/// twin of `interflow-cli node add`. Structured and non-destructive (comments
/// and layout stay); the edited manifest must pass the full validation
/// funnel before anything is written.
#[tauri::command]
#[specta::specta]
#[allow(clippy::needless_pass_by_value)] // Tauri command parameters must be deserialized by value
pub async fn deploy_add_node(params: IssueNodeParams) -> Result<AddedNodeDto, String> {
    let manifest = expanded(&params.manifest);
    let spec = issue_spec(&params);
    tauri::async_runtime::spawn_blocking(move || {
        interflow_cli::plan::add_node(&manifest, &spec)
            .map(|outcome| AddedNodeDto {
                manifest_text: outcome.manifest_text,
                pack_dir_name: outcome.pack_dir_name,
            })
            .map_err(|e| e.to_string())
    })
    .await
    .map_err(|e| e.to_string())?
}

/// Converts the wizard's parameters into the shared `node add` spec. The
/// role split is enforced here, not just suggested by the form: an expose
/// agent never carries mesh rows and vice versa (one pack, one role — a
/// stray row from a mid-form kind switch is dropped, not signed).
fn issue_spec(params: &IssueNodeParams) -> interflow_cli::plan::AddNodeSpec {
    use crate::contract::IssueNodeKindDto;
    use interflow_cli::plan::{
        AddMeshEgressSpec, AddMeshIngressSpec, AddNodeKind, AddNodeSpec, AddServiceSpec,
    };
    let udp = |protocol: crate::contract::MeshProtocolDto| {
        matches!(protocol, crate::contract::MeshProtocolDto::Udp)
    };
    let services = || {
        params
            .services
            .iter()
            .map(|s| AddServiceSpec {
                id: s.id.clone(),
                address: s.address.clone(),
            })
            .collect::<Vec<_>>()
    };
    let mesh_ingress = || {
        params
            .mesh_ingress
            .iter()
            .map(|r| AddMeshIngressSpec {
                name: r.name.clone(),
                listen: r.listen.clone(),
                udp: udp(r.protocol),
                target_agent: r.target_agent.clone(),
                remote_addr: r.remote_addr.clone(),
                idle_timeout_secs: None,
            })
            .collect::<Vec<_>>()
    };
    let mesh_egress = || {
        params
            .mesh_egress
            .iter()
            .map(|r| AddMeshEgressSpec {
                name: r.name.clone(),
                udp: udp(r.protocol),
                target_addr: r.target.clone().filter(|s| !s.trim().is_empty()),
                target_cidr: r.target_cidr.clone().filter(|s| !s.trim().is_empty()),
            })
            .collect::<Vec<_>>()
    };
    let (kind, services, mesh_ingress, mesh_egress) = match params.kind {
        IssueNodeKindDto::AgentExpose => (AddNodeKind::Agent, services(), Vec::new(), Vec::new()),
        IssueNodeKindDto::AgentMesh => (
            AddNodeKind::Agent,
            Vec::new(),
            mesh_ingress(),
            mesh_egress(),
        ),
        IssueNodeKindDto::Hub => (AddNodeKind::Hub, Vec::new(), Vec::new(), Vec::new()),
        IssueNodeKindDto::Ingress => (AddNodeKind::Ingress, Vec::new(), Vec::new(), Vec::new()),
    };
    AddNodeSpec {
        kind,
        node: params.node.clone(),
        workspace: params.workspace.clone().filter(|s| !s.trim().is_empty()),
        services,
        mesh_ingress,
        mesh_egress,
        ingress_workspaces: params.ingress_workspaces.clone(),
        hub_endpoint: params.hub_endpoint.clone().filter(|s| !s.trim().is_empty()),
    }
}

/// Generates a 144-bit sealing passphrase — the same source the CLI's
/// `pack seal --generate-passphrase` uses, so both surfaces seal with the
/// same entropy.
#[tauri::command]
#[specta::specta]
pub fn deploy_generate_passphrase() -> Result<String, String> {
    interflow_identity::pack::sealed::generate_passphrase().map_err(|e| e.to_string())
}

/// Seals a pack straight into the user's Downloads directory — the issue
/// wizard's one-click export. Collisions get a numeric suffix (a re-issue
/// never clobbers a file that may not have been transferred yet).
#[tauri::command]
#[specta::specta]
pub async fn deploy_seal_to_downloads(
    pack_dir: String,
    passphrase: String,
) -> Result<SealedPackDto, String> {
    let pack_dir = expanded(&pack_dir);
    let downloads =
        dirs::download_dir().ok_or_else(|| i18n::current().err_downloads_dir.to_string())?;
    let name = pack_dir
        .file_name()
        .map_or_else(|| "pack".to_owned(), |n| n.to_string_lossy().into_owned());
    let mut target = downloads.join(format!("{name}.iflowpack"));
    let mut counter = 2u32;
    while target.exists() {
        target = downloads.join(format!("{name}-{counter}.iflowpack"));
        counter += 1;
    }
    let out_file = target.display().to_string();
    let pack_for_task = pack_dir.clone();
    let out_for_task = target.clone();
    let pass_for_task = passphrase.clone();
    tauri::async_runtime::spawn_blocking(move || {
        deploy::seal_pack(&pack_for_task, &out_for_task, &pass_for_task)
    })
    .await
    .map_err(|e| e.to_string())??;
    Ok(SealedPackDto {
        path: out_file,
        passphrase,
    })
}

/// Loads the remembered deployment contexts (most recent first).
#[tauri::command]
#[specta::specta]
#[allow(clippy::unnecessary_wraps)] // Tauri command shape (load never fails)
pub fn deploy_prefs_load() -> Result<DeployPrefsDto, String> {
    let prefs = crate::deploy_prefs::load();
    Ok(DeployPrefsDto {
        recent: prefs
            .recent
            .into_iter()
            .map(|c| DeployContextDto {
                manifest: c.manifest,
                issuer: c.issuer,
                out: c.out,
            })
            .collect(),
    })
}

/// Persists the remembered deployment contexts (full-list replacement —
/// the frontend owns dedupe/promotion).
#[tauri::command]
#[specta::specta]
#[allow(clippy::needless_pass_by_value)] // Tauri command parameters must be deserialized by value
pub fn deploy_prefs_save(recent: Vec<DeployContextDto>) -> Result<(), String> {
    crate::deploy_prefs::save(&crate::deploy_prefs::DeployPrefs {
        recent: recent
            .into_iter()
            .map(|c| crate::deploy_prefs::DeployContext {
                manifest: c.manifest,
                issuer: c.issuer,
                out: c.out,
            })
            .collect(),
    })
}

/// Loads the GUI-wide preferences (interface language) — the frontend
/// awaits this before first paint, so the window never flashes the wrong
/// language.
#[tauri::command]
#[specta::specta]
#[allow(clippy::unnecessary_wraps)] // Tauri command shape (load never fails)
pub fn gui_prefs_load() -> Result<GuiPrefsDto, String> {
    let prefs = crate::gui_prefs::load();
    Ok(GuiPrefsDto {
        language: prefs.language.into(),
        current_deployment: prefs.current_deployment,
    })
}

/// Persists the GUI-wide preferences (language + the current deployment)
/// and rebuilds the tray in place — one switch flips every surface (window,
/// tray, command errors) at once.
#[tauri::command]
#[specta::specta]
#[allow(clippy::needless_pass_by_value)] // Tauri command parameters are deserialized by value
pub fn gui_prefs_save(app: tauri::AppHandle, prefs: GuiPrefsDto) -> Result<(), String> {
    crate::gui_prefs::save(&crate::gui_prefs::GuiPrefs {
        language: prefs.language.into(),
        current_deployment: prefs.current_deployment,
    })?;
    if let Some(tray) = app.tray_by_id("main") {
        crate::tray::refresh(&app, &tray);
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Deployment-as-root-object commands (2026-10-10 IA): discovery, current
// selection, the composed fleet read model, and the one-click publish.
// ---------------------------------------------------------------------------

/// Lists the deployments under `~/interflow-deployments` (name-sorted). A
/// missing root is an empty list — the first-run onboarding entry, not an
/// error.
#[tauri::command]
#[specta::specta]
#[allow(clippy::unnecessary_wraps)] // Tauri command shape
pub fn deployment_list() -> Result<Vec<DeploymentDto>, String> {
    Ok(crate::deployment::discover()
        .into_iter()
        .map(Into::into)
        .collect())
}

/// The deployment the app opens into (persisted in `gui.toml`); `None` on
/// first run or when the remembered folder vanished. The path is returned
/// UNVALIDATED-but-existing — the caller decides how to present a stale
/// pick (re-onboard, not an error dialog).
#[tauri::command]
#[specta::specta]
#[allow(clippy::unnecessary_wraps)] // Tauri command shape
pub fn deployment_current() -> Result<Option<DeploymentDto>, String> {
    let root = crate::gui_prefs::load().current_deployment;
    Ok(root
        .as_deref()
        .and_then(|r| crate::deployment::DeploymentDir::probe(std::path::Path::new(r)))
        .map(Into::into))
}

/// Opens (and persists) the current deployment. The folder must be a
/// deployment (an `interflow.toml`); the error names the path in the
/// user's language.
#[tauri::command]
#[specta::specta]
#[allow(clippy::needless_pass_by_value)] // Tauri command parameters arrive by value
pub fn deployment_set_current(
    app: tauri::AppHandle,
    root: String,
) -> Result<DeploymentDto, String> {
    let root = expanded(&root);
    let deployment = crate::deployment::DeploymentDir::probe(&root).ok_or_else(|| {
        let s = i18n::current();
        i18n::render(
            s.err_not_deployment,
            &[("path", &root.display().to_string())],
        )
    })?;
    let mut prefs = crate::gui_prefs::load();
    prefs.current_deployment = Some(root.display().to_string());
    crate::gui_prefs::save(&prefs)?;
    if let Some(tray) = app.tray_by_id("main") {
        crate::tray::refresh(&app, &tray);
    }
    Ok(deployment.into())
}

/// The deployment-scoped composed read model — ONE round trip backing the
/// 总览/流/服务 views: declared state + change classification + (when
/// `include_hub`) the hub's fleet face + every local join. The hub dial is
/// opt-in so hub latency can never hold the local view hostage.
#[tauri::command]
#[specta::specta]
#[allow(clippy::needless_pass_by_value)] // Tauri command parameters arrive by value
pub async fn fleet_overview(
    state: State<'_, SharedState>,
    manifest: String,
    issuer: String,
    include_hub: bool,
) -> Result<FleetDto, String> {
    let (manifest, issuer) = (expanded(&manifest), expanded(&issuer));
    let issuer_for_hub = issuer.clone();
    let manifest_for_hub = manifest.clone();
    let hub = if include_hub {
        tauri::async_runtime::spawn_blocking(move || {
            interflow_cli::plan::hub_overview(&manifest_for_hub, &issuer_for_hub)
                .ok()
                .flatten()
        })
        .await
        .map_err(|e| e.to_string())?
    } else {
        None
    };

    // Local faces + bookkeeping classification in one blocking batch.
    let manifest_for_state = manifest.clone();
    let issuer_for_state = issuer.clone();
    let (summary, change_state) = tauri::async_runtime::spawn_blocking(move || {
        let text = std::fs::read_to_string(&manifest_for_state)
            .map_err(|e| format!("{}: {e}", manifest_for_state.display()))?;
        let summary = interflow_cli::manifest_edit::summarize(&text)
            .map_err(|e| interflow_cli::manifest_edit::error_chain(&e))?;
        let change_state =
            interflow_cli::plan::change_state(&manifest_for_state, &issuer_for_state)
                .map_err(|e| e.to_string())?;
        Ok::<_, String>((summary, change_state))
    })
    .await
    .map_err(|e| e.to_string())??;

    let nodes = node_infos(&manager(&state)?);
    Ok(crate::fleet::compose(
        summary.into(),
        change_state.into(),
        hub.map(Into::into),
        nodes,
    ))
}

/// The 发布 button's single backend entry: save (when the editor hands
/// over text) → apply (the watermark-aware funnel; the policy-only fast
/// path when only rules/services/routes moved) → converge the local fleet
/// (policy-only: every local node hot-applies within a watcher period;
/// full render: every STALE local pack is swapped in place and running
/// nodes restart per their captured intent). Returns the classification
/// the status bar states plainly: what went hot, what restarted, what
/// needs a manual re-run.
#[tauri::command]
#[specta::specta]
#[allow(clippy::needless_pass_by_value)] // Tauri command parameters arrive by value
pub async fn deployment_publish(
    state: State<'_, SharedState>,
    manifest_text: Option<String>,
    manifest: String,
    issuer: String,
    out: String,
) -> Result<PublishResultDto, String> {
    let (manifest, issuer, out) = (expanded(&manifest), expanded(&issuer), expanded(&out));
    // 1. Auto-save escape hatch: the GUI's publish flow pre-saves through
    //    the changed-on-disk guard (deploy_write_text) and reaches this
    //    with no text; the parameter stays for callers that hand a document
    //    over wholesale, and saves unconditionally on their behalf.
    if let Some(text) = &manifest_text {
        interflow_cli::manifest_edit::save_manifest(&manifest, text, None)
            .map_err(|e| interflow_cli::manifest_edit::error_chain(&e))?;
    }

    // 2. The pre-apply classification (never minted, never dialed) decides
    //    the orchestration shape.
    let manifest_for_state = manifest.clone();
    let issuer_for_state = issuer.clone();
    let kind = tauri::async_runtime::spawn_blocking(move || {
        interflow_cli::plan::change_state(&manifest_for_state, &issuer_for_state)
            .map_err(|e| e.to_string())
    })
    .await
    .map_err(|e| e.to_string())??;

    // 3. Apply.
    let (manifest_for_apply, issuer_for_apply, out_for_apply) =
        (manifest.clone(), issuer.clone(), out.clone());
    let report = tauri::async_runtime::spawn_blocking(move || {
        interflow_cli::plan::apply(
            &manifest_for_apply,
            &issuer_for_apply,
            &out_for_apply,
            false,
            &interflow_cli::plan::BackupInitOptions::default(),
            false,
        )
        .map_err(|e| e.to_string())
    })
    .await
    .map_err(|e| e.to_string())??;

    // 4. Converge the local fleet. The scope is the deployment the manifest
    //    belongs to — every managed node whose pack renders into this dist
    //    tree.
    let manager = manager(&state)?;
    let deployment = crate::deployment::DeploymentDir::containing(&manifest);
    let mut hot_nodes = Vec::new();
    let mut updated_nodes = Vec::new();
    let mut failed_updates = Vec::new();
    let mut owned: Vec<crate::contract::NodeInfo> = Vec::new();
    for info in node_infos(&manager) {
        let in_scope = deployment.as_ref().is_some_and(|d| {
            info.deployment
                .as_ref()
                .is_some_and(|n| n.root == d.root.display().to_string())
        });
        if in_scope {
            owned.push(info);
        }
    }

    match kind {
        interflow_cli::plan::ChangeState::PolicyEditsPending => {
            // Hot: nothing to touch — the watcher plane converges each node
            // within its own period.
            for info in &owned {
                hot_nodes.push(info.name.clone());
            }
        }
        interflow_cli::plan::ChangeState::NeverApplied
        | interflow_cli::plan::ChangeState::IdentityEditsPending => {
            // Packs were (re)rendered: swap every STALE local pack in place;
            // `update_pack` stops, swaps, and restores the start intent.
            let dist_packs = tauri::async_runtime::spawn_blocking({
                let out = out.clone();
                move || crate::deploy::list_packs(&out)
            })
            .await
            .map_err(|e| e.to_string())??;
            for info in owned {
                // Several dist packs can share an identity once rotate's
                // `-genN` staging directories accumulate beside the base
                // pack; converging on the FIRST match could pick a stale
                // staging and (pre-gate) silently downgrade the node. Take
                // the newest generation for the identity — convergence
                // moves forward only, like every install surface.
                let dist = dist_packs
                    .iter()
                    .filter(|pack| pack.principal == info.principal.clone().unwrap_or_default())
                    .max_by_key(|pack| pack.generation);
                let Some(dist) = dist else {
                    continue;
                };
                let node = manager
                    .snapshots()
                    .into_iter()
                    .find(|snap| snap.spec.id == info.id);
                let Some(snapshot) = node else {
                    continue;
                };
                if snapshot.spec.pack_digest == dist.digest {
                    // Already current (an earlier update landed): converged
                    // untouched.
                    hot_nodes.push(info.name.clone());
                    continue;
                }
                match manager.update_pack(&info.id, &dist.path).await {
                    Ok(_) => updated_nodes.push(info.name.clone()),
                    Err(e) => failed_updates.push(NodeUpdateFailureDto {
                        node: info.name.clone(),
                        error: e,
                    }),
                }
            }
        }
        interflow_cli::plan::ChangeState::Applied { .. } => {
            // The idempotent gate said no-op — nothing to converge.
        }
    }

    Ok(PublishResultDto {
        kind: match kind {
            interflow_cli::plan::ChangeState::PolicyEditsPending => PublishKindDto::PolicyOnly,
            interflow_cli::plan::ChangeState::Applied { .. } => PublishKindDto::NoOp,
            _ => PublishKindDto::FullRender,
        },
        apply: report.into(),
        hot_nodes,
        updated_nodes,
        failed_updates,
    })
}

#[cfg(test)]
mod tests {
    use super::expanded_existing;
    use crate::i18n;

    /// A hand-typed `~/…` path that does not exist must fail with the
    /// user's original input in the message (the 2026-09-18 papercut:
    /// `~` reached `Path::exists` as a literal). Pinned in English — the
    /// language is an argument, not the machine's gui.toml.
    #[test]
    fn expanded_existing_reports_missing_tilde_path_with_original_input() {
        let mut field = "~/interflow-packs/missing-pack".to_string();
        let err = expanded_existing(&mut field, i18n::EN.label_credential_pack_dir, &i18n::EN)
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
        expanded_existing(&mut field, i18n::EN.label_credential_pack_dir, &i18n::EN)
            .expect("existing directory passes");
        assert_eq!(field, dir.path().display().to_string());
    }

    /// The deployments default is the one-deployment-one-folder root: an
    /// absolute home-based path ending in `interflow-deployments` — the
    /// convention the CLI's CWD-relative defaults (`interflow.toml` /
    /// `issuer` / `dist`) already encode, and never a cloud-synced
    /// documents folder.
    #[test]
    fn defaults_root_is_absolute_home_based_folder() {
        let dto = super::deploy_defaults().expect("defaults never fail");
        let root = std::path::Path::new(&dto.root);
        assert!(root.is_absolute(), "not absolute: {}", dto.root);
        assert_eq!(
            root.file_name().and_then(|s| s.to_str()),
            Some("interflow-deployments"),
            "wrong root name: {}",
            dto.root
        );
    }

    /// Creation writes missing parent directories and lands the text; a
    /// second create at the same path is refused (the CLI setup semantic —
    /// overwriting is the editor Save path's job, with its `.bak`).
    #[test]
    fn create_manifest_creates_parents_then_refuses_existing() {
        let dir = tempfile::tempdir().expect("temp dir");
        let path = dir
            .path()
            .join("nested")
            .join("deploy")
            .join("interflow.toml");
        let text = "# starter skeleton\n";
        super::deploy_create_manifest(path.display().to_string(), text.to_string())
            .expect("fresh path creates");
        assert_eq!(
            std::fs::read_to_string(&path).expect("created file reads back"),
            text
        );
        let err = super::deploy_create_manifest(path.display().to_string(), text.to_string())
            .expect_err("existing manifest must be refused");
        assert!(
            err.contains("interflow.toml"),
            "refusal names the path: {err}"
        );
    }

    /// A missing file is the read-failure class, not a syntax error: the
    /// message names the path in the UI language and never leaks the raw
    /// io errno string (English on every OS). Asserted locale-independently
    /// because `i18n::current()` reads this machine's gui.toml.
    #[test]
    fn read_text_names_missing_file_without_errno_noise() {
        let dir = tempfile::tempdir().expect("temp dir");
        let missing = dir.path().join("absent.toml");
        let err = super::deploy_read_text(missing.display().to_string())
            .expect_err("missing file must fail");
        assert!(err.contains("absent.toml"), "names the path: {err}");
        assert!(
            !err.contains("os error"),
            "no raw errno in the UI message: {err}"
        );
    }

    /// The wizard's kind split maps onto the CLI core correctly: both agent
    /// roles → one Agent kind (services vs mesh rules is one-pack-one-role,
    /// enforced downstream), and blank optionals are filtered to None so
    /// the core's defaults apply.
    #[test]
    fn issue_spec_splits_roles_and_filters_blanks() {
        use crate::contract::{
            IssueMeshEgressDto, IssueMeshIngressDto, IssueNodeKindDto, IssueNodeParams,
            IssueServiceSpecDto, MeshProtocolDto,
        };
        let expose = IssueNodeParams {
            kind: IssueNodeKindDto::AgentExpose,
            node: "desktop2".into(),
            manifest: "~/interflow.toml".into(),
            workspace: Some("  ".into()),
            services: vec![IssueServiceSpecDto {
                id: "asr".into(),
                address: "127.0.0.1:8080".into(),
            }],
            mesh_ingress: vec![IssueMeshIngressDto {
                name: "stale".into(),
                listen: "127.0.0.1:1".into(),
                protocol: MeshProtocolDto::Tcp,
                target_agent: "x".into(),
                remote_addr: "127.0.0.1:1".into(),
            }],
            mesh_egress: vec![],
            ingress_workspaces: vec![],
            hub_endpoint: Some(String::new()),
        };
        let spec = super::issue_spec(&expose);
        assert!(matches!(spec.kind, interflow_cli::plan::AddNodeKind::Agent));
        assert_eq!(spec.workspace, None, "blank workspace → core default");
        assert_eq!(spec.hub_endpoint, None);
        assert_eq!(spec.services.len(), 1);
        // A stray mesh row (e.g. left over from a mid-form kind switch)
        // must be dropped here — never signed into a mixed-role pack.
        assert!(
            spec.mesh_ingress.is_empty() && spec.mesh_egress.is_empty(),
            "the expose role carries no mesh rows"
        );

        let mesh = IssueNodeParams {
            kind: IssueNodeKindDto::AgentMesh,
            node: "home-win".into(),
            manifest: "~/interflow.toml".into(),
            workspace: Some("main".into()),
            services: vec![],
            mesh_ingress: vec![IssueMeshIngressDto {
                name: "ollama".into(),
                listen: "127.0.0.1:11434".into(),
                protocol: MeshProtocolDto::Udp,
                target_agent: "peer".into(),
                remote_addr: "127.0.0.1:11434".into(),
            }],
            mesh_egress: vec![IssueMeshEgressDto {
                name: "loop".into(),
                protocol: MeshProtocolDto::Tcp,
                target: None,
                target_cidr: Some("127.0.0.0/8".into()),
            }],
            ingress_workspaces: vec![],
            hub_endpoint: None,
        };
        let spec = super::issue_spec(&mesh);
        assert!(spec.services.is_empty());
        assert!(spec.mesh_ingress[0].udp, "Udp maps to the udp flag");
        assert_eq!(
            spec.mesh_egress[0].target_cidr.as_deref(),
            Some("127.0.0.0/8")
        );
        assert_eq!(spec.mesh_egress[0].target_addr, None);
        assert_eq!(spec.workspace.as_deref(), Some("main"));
    }
}
