//! Deploy surface: the operator face of the GUI — manifest template +
//! validate/apply, dist pack inventory, seal / rotate / revoke, and
//! sealed-pack import for "add as node".
//!
//! Framework-free domain logic over `interflow_cli` (the same code paths the
//! `interflow-cli` binary runs); `commands.rs` wraps these as Tauri commands.

use crate::node::{self, PackInfo};
use std::path::{Path, PathBuf};

/// Where the GUI installs imported `.iflowpack`s (stable, profile-stable
/// path — the pack is swapped in place on re-import).
pub fn managed_packs_root() -> PathBuf {
    dirs::data_dir()
        .unwrap_or_else(std::env::temp_dir)
        .join("interflow")
        .join("packs")
}

/// One rendered pack in a dist tree (the deploy page's card).
#[derive(Debug, Clone)]
pub struct DeployPack {
    pub dir_name: String,
    /// The pack directory's absolute path — the single source of truth for
    /// locating the pack (the layout probe may have found it outside
    /// `<out>/packs/`).
    pub path: PathBuf,
    pub kind: crate::node::NodeKind,
    pub node: String,
    pub generation: u64,
    /// Content digest — the same-generation-different-content detector.
    pub digest: String,
    pub expires: String,
    pub principal: String,
    /// One of rotate's `-gen<N>` staging outputs (see
    /// [`crate::node::is_rotate_staging`]) — the GUI badges these instead of
    /// letting them sit visually equal to the identity's base pack.
    pub is_staging: bool,
}

/// Resolves the pack directories under an operator-chosen output root.
///
/// The dist-tree shape (`<out>/packs/<name>`) is the primary layout, but a
/// bare pack directory (`<out>/pack.toml` — e.g. an unpacked single-pack
/// zip) and a packs root pointed at directly (`<out>/<name>/pack.toml` —
/// e.g. the zip's wrapper directory) are accepted too: the operator's
/// intent ("these are my packs") outranks the directory ceremony
fn resolve_pack_dirs(out_root: &Path) -> Result<Vec<(String, PathBuf)>, String> {
    /// One directory level of `<name>/pack.toml` children; IO errors
    /// propagate (silently skipping a failed read_dir would hide packs).
    /// Swap backups (`<pack>.previous`, kept by `update_pack` / `node
    /// install`) and staging directories (`.staging-*`, dot-prefixed)
    /// look like packs (they carry a `pack.toml`) but are NOT inventory —
    /// an old-generation backup must never appear as an installable or
    /// updatable row.
    fn child_packs(dir: &Path) -> Result<Vec<(String, PathBuf)>, String> {
        let entries =
            std::fs::read_dir(dir).map_err(|e| format!("cannot read {}: {e}", dir.display()))?;
        let mut out = Vec::new();
        for entry in entries {
            let entry = entry.map_err(|e| format!("read {}: {e}", dir.display()))?;
            let name = entry.file_name().to_string_lossy().into_owned();
            if name.starts_with('.') || name.ends_with(".previous") {
                continue;
            }
            let path = entry.path();
            if path.join("pack.toml").is_file() {
                out.push((name, path));
            }
        }
        Ok(out)
    }

    // Primary shape: the dist tree.
    let packs_dir = out_root.join("packs");
    if packs_dir.is_dir() {
        return child_packs(&packs_dir);
    }
    // A bare pack directory (an unpacked single-pack zip lands here).
    if out_root.join("pack.toml").is_file() {
        let dir_name = out_root.file_name().map_or_else(
            || out_root.display().to_string(),
            |n| n.to_string_lossy().into_owned(),
        );
        return Ok(vec![(dir_name, out_root.to_path_buf())]);
    }
    // The root used as the packs root itself (the zip's wrapper directory
    // with `<out>/<name>/pack.toml` children). Empty falls through to the
    // layout-spelling error below.
    if let Ok(found) = child_packs(out_root)
        && !found.is_empty()
    {
        return Ok(found);
    }
    Err(format!(
        "no packs under {}: expected a dist tree (`<out>/packs/<name>/pack.toml`), a bare pack \
         directory (one with `pack.toml` directly), or a directory of such packs",
        out_root.display()
    ))
}

/// Lists the packs of an output tree (`<out>/packs/*` and the accepted
/// alternates — see [`resolve_pack_dirs`]).
pub fn list_packs(out_root: &Path) -> Result<Vec<DeployPack>, String> {
    let mut out = Vec::new();
    for (dir_name, path) in resolve_pack_dirs(out_root)? {
        // One unreadable child must not take the whole inventory down (a
        // torn write mid-update, a hand-copied fragment): warn, skip, and
        // let the healthy packs list. The layout probe above still fails
        // loudly when there is nothing pack-shaped at all.
        let pack = match interflow_identity::pack::CredentialPack::load(&path) {
            Ok(pack) => pack,
            Err(e) => {
                tracing::warn!(
                    "skipping unreadable pack {}: {e} (torn update? hand-copied?)",
                    path.display()
                );
                continue;
            }
        };
        let info = match node::inspect_pack(&path) {
            Ok(info) => info,
            Err(e) => {
                tracing::warn!("skipping uninspectable pack {}: {e}", path.display());
                continue;
            }
        };
        out.push(DeployPack {
            is_staging: crate::node::is_rotate_staging(
                &dir_name,
                info.kind,
                &pack.metadata.node,
                pack.metadata.generation,
            ),
            dir_name,
            path,
            kind: info.kind,
            node: pack.metadata.node.clone(),
            generation: pack.metadata.generation,
            digest: pack.pack_digest,
            expires: pack.metadata.expires.clone(),
            principal: info.principal,
        });
    }
    out.sort_by(|a, b| a.dir_name.cmp(&b.dir_name));
    Ok(out)
}

/// Seals a pack directory into a distributable `.iflowpack`.
pub fn seal_pack(pack_dir: &Path, out_file: &Path, passphrase: &str) -> Result<(), String> {
    interflow_identity::pack::sealed::seal(
        pack_dir,
        out_file,
        &interflow_identity::pack::sealed::SealKey::Passphrase(passphrase.to_owned()),
    )
    .map_err(|e| format!("seal: {e}"))
}

/// What an import produced — feeds straight into "add as node".
pub struct ImportedPack {
    pub pack_dir: PathBuf,
    pub info: PackInfo,
}

/// Installs a sealed `.iflowpack` into the GUI-managed packs root (same
/// swap/backup discipline as `node install`), validated through the shared
/// funnel.
pub fn install_sealed(sealed: &Path, passphrase: &str) -> Result<ImportedPack, String> {
    let root = managed_packs_root();
    let report = interflow_cli::node_install::install(&interflow_cli::node_install::NodeInstall {
        pack: sealed.to_path_buf(),
        root,
        user: interflow_cli::render::INSTALL_USER.to_owned(),
        passphrase: Some(passphrase.to_owned()),
        // The GUI-managed layout runs no systemd units — the cross-unit
        // disk-swap restart pass has nothing to do here. And importing
        // moves forward only, like every install surface: the GUI has no
        // typed downgrade flag, so a lower-generation import of a known
        // identity is refused rather than offered silently.
        restart_stale_units: false,
        allow_downgrade: false,
    })
    .map_err(|e| format!("install: {e}"))?;
    let info = node::inspect_pack(&report.installed_to)?;
    Ok(ImportedPack {
        pack_dir: report.installed_to,
        info,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The inventory's exclusion + resilience contract: swap backups
    /// (`<pack>.previous`) and staging dirs (dot-prefixed) never list;
    /// one unreadable pack dir is skipped with a warning instead of
    /// failing the whole tree.
    #[test]
    fn list_packs_skips_backups_staging_and_unreadable_children() {
        let dir = tempfile::tempdir().expect("tempdir");
        let manifest = dir.path().join("interflow.toml");
        std::fs::write(
            &manifest,
            interflow_cli::plan::setup_template(
                "promptcn",
                "tunnel.example.com:443",
                "https://registrar.example.com",
                "app.example.com",
                "desktop",
                "asr",
                "127.0.0.1:8080",
            ),
        )
        .expect("write manifest");
        let issuer = dir.path().join("issuer");
        let out = dir.path().join("dist");
        interflow_cli::plan::apply(
            &manifest,
            &issuer,
            &out,
            false,
            &interflow_cli::plan::BackupInitOptions {
                skip: true,
                ..Default::default()
            },
            false,
        )
        .expect("apply");

        let packs_dir = out.join("packs");
        // The swap backup the GUI/CLI leave behind — old generation, and
        // (here) a pack.toml the loader rejects: it must not list at all.
        let backup = packs_dir.join("agent-desktop.previous");
        std::fs::create_dir_all(&backup).expect("backup dir");
        std::fs::write(backup.join("pack.toml"), "not a valid pack").expect("backup pack.toml");
        // A crash-left staging directory.
        let staging = packs_dir.join(".staging-install-999");
        std::fs::create_dir_all(staging.join("pack")).expect("staging dir");
        std::fs::write(staging.join("pack/pack.toml"), "x = 1").expect("staging pack.toml");
        // A hand-copied fragment (pack.toml-shaped but unloadable).
        let fragment = packs_dir.join("fragment");
        std::fs::create_dir_all(&fragment).expect("fragment dir");
        std::fs::write(fragment.join("pack.toml"), "broken").expect("fragment pack.toml");

        let packs = list_packs(&out).expect("lists despite junk");
        let names: Vec<&str> = packs.iter().map(|p| p.dir_name.as_str()).collect();
        assert!(!names.iter().any(|n| n.ends_with(".previous")), "{names:?}");
        assert!(!names.iter().any(|n| n.starts_with('.')), "{names:?}");
        assert!(!names.contains(&"fragment"), "{names:?}");
        assert!(names.contains(&"agent-desktop"), "{names:?}");
    }

    /// The staging badge's truth: rotate's `-gen<N>` output is flagged, the
    /// identity's base pack is not — the badge must survive staging
    /// directories accumulating beside the base pack, which is exactly the
    /// scene the 2026-10-14 backlog filed.
    #[test]
    fn list_packs_flags_rotate_staging_directories() {
        let dir = tempfile::tempdir().expect("tempdir");
        let manifest = dir.path().join("interflow.toml");
        std::fs::write(
            &manifest,
            interflow_cli::plan::setup_template(
                "promptcn",
                "tunnel.example.com:443",
                "https://registrar.example.com",
                "app.example.com",
                "desktop",
                "asr",
                "127.0.0.1:8080",
            ),
        )
        .expect("write manifest");
        let issuer = dir.path().join("issuer");
        let out = dir.path().join("dist");
        interflow_cli::plan::apply(
            &manifest,
            &issuer,
            &out,
            false,
            &interflow_cli::plan::BackupInitOptions {
                skip: true,
                ..Default::default()
            },
            false,
        )
        .expect("apply");
        interflow_cli::plan::rotate(
            &manifest,
            &issuer,
            "agent/desktop",
            Some(&out.join("packs/agent-desktop")),
            None,
            false,
        )
        .expect("rotate");

        let packs = list_packs(&out).expect("lists");
        let base = packs
            .iter()
            .find(|p| p.dir_name == "agent-desktop")
            .expect("base pack lists");
        assert!(!base.is_staging, "the identity's base pack is not staging");
        let staging = packs
            .iter()
            .find(|p| p.dir_name == "agent-desktop-gen2")
            .expect("rotate's staging output lists");
        assert!(staging.is_staging, "rotate's -genN output is staging");
        assert_eq!(staging.generation, 2);
        let ingress = packs
            .iter()
            .find(|p| p.dir_name == "ingress-edge")
            .expect("neighbor pack lists");
        assert!(!ingress.is_staging);
    }

    /// The template → apply → list_packs loop over a temp deployment: the
    /// same plan code the CLI runs, exercised end to end.
    #[test]
    fn template_validate_apply_lists_packs() {
        let dir = tempfile::tempdir().expect("tempdir");
        let manifest = dir.path().join("interflow.toml");
        let text = interflow_cli::plan::setup_template(
            "promptcn",
            "tunnel.example.com:443",
            "https://registrar.example.com",
            "app.example.com",
            "desktop",
            "asr",
            "127.0.0.1:8080",
        );
        std::fs::write(&manifest, &text).expect("write manifest");
        let lines = interflow_cli::plan::validate(&manifest).expect("validates");
        assert!(lines.iter().any(|l| l.contains("is valid")), "{lines:?}");

        let issuer = dir.path().join("issuer").display().to_string();
        let out = dir.path().join("dist").display().to_string();
        let apply_report = interflow_cli::plan::apply(
            &manifest,
            Path::new(&issuer),
            Path::new(&out),
            false,
            // Throwaway test store: no backup setup.
            &interflow_cli::plan::BackupInitOptions {
                skip: true,
                ..Default::default()
            },
            false,
        )
        .expect("applies");
        assert_eq!(apply_report.generation, 1);
        assert!(
            apply_report.lines.iter().any(|l| l.contains("✔ applied")),
            "{:?}",
            apply_report.lines
        );

        let packs = list_packs(Path::new(&out)).expect("lists");
        let names: Vec<&str> = packs.iter().map(|p| p.dir_name.as_str()).collect();
        assert!(names.contains(&"ingress-edge"), "{names:?}");
        assert!(names.contains(&"agent-desktop"), "{names:?}");
        assert!(packs.iter().all(|p| p.generation == 1));
    }

    #[test]
    fn sealed_import_round_trips_through_the_managed_root() {
        let dir = tempfile::tempdir().expect("tempdir");
        let manifest = dir.path().join("interflow.toml");
        std::fs::write(
            &manifest,
            interflow_cli::plan::setup_template(
                "promptcn",
                "tunnel.example.com:443",
                "https://registrar.example.com",
                "app.example.com",
                "desktop",
                "asr",
                "127.0.0.1:8080",
            ),
        )
        .expect("write manifest");
        let issuer = dir.path().join("issuer");
        let out = dir.path().join("dist");
        interflow_cli::plan::apply(
            &manifest,
            &issuer,
            &out,
            false,
            // Throwaway test store: no backup setup.
            &interflow_cli::plan::BackupInitOptions {
                skip: true,
                ..Default::default()
            },
            false,
        )
        .expect("apply");

        let sealed = dir.path().join("agent.iflowpack");
        seal_pack(&out.join("packs/agent-desktop"), &sealed, "open sesame").expect("seals");

        // The managed root is global state across tests — point it at a temp
        // area via install's root parameter through the public surface.
        let report =
            interflow_cli::node_install::install(&interflow_cli::node_install::NodeInstall {
                pack: sealed,
                root: dir.path().join("srv"),
                user: interflow_cli::render::INSTALL_USER.to_owned(),
                passphrase: Some("open sesame".to_owned()),
                restart_stale_units: false,
                allow_downgrade: false,
            })
            .expect("installs");
        assert!(report.installed_to.join("pack.toml").is_file());
        assert!(node::inspect_pack(&report.installed_to).is_ok());
    }

    #[test]
    fn list_packs_accepts_bare_pack_dir_and_packs_root() {
        let dir = tempfile::tempdir().expect("tempdir");
        let manifest = dir.path().join("interflow.toml");
        std::fs::write(
            &manifest,
            interflow_cli::plan::setup_template(
                "promptcn",
                "tunnel.example.com:443",
                "https://registrar.example.com",
                "app.example.com",
                "desktop",
                "asr",
                "127.0.0.1:8080",
            ),
        )
        .expect("write manifest");
        let issuer = dir.path().join("issuer");
        let out = dir.path().join("dist");
        interflow_cli::plan::apply(
            &manifest,
            &issuer,
            &out,
            false,
            // Throwaway test store: no backup setup.
            &interflow_cli::plan::BackupInitOptions {
                skip: true,
                ..Default::default()
            },
            false,
        )
        .expect("apply");

        // The primary dist shape.
        let dist = list_packs(&out).expect("lists dist tree");
        assert!(dist.iter().any(|p| p.dir_name == "agent-desktop"));
        let agent_path = out.join("packs/agent-desktop");

        // A bare pack directory (an unpacked single-pack zip): `out` points
        // at the pack itself — same single entry, absolute path intact.
        let bare = list_packs(&agent_path).expect("lists bare pack dir");
        assert_eq!(bare.len(), 1);
        assert_eq!(bare[0].dir_name, "agent-desktop");
        assert_eq!(bare[0].path, agent_path);
        assert!(!bare[0].digest.is_empty(), "digest must ride along");

        // The packs root pointed at directly (the zip's wrapper directory).
        let root = list_packs(&out.join("packs")).expect("lists packs root");
        assert!(root.iter().any(|p| p.dir_name == "agent-desktop"));

        // None of the shapes present: the error spells the expected layouts.
        let empty = tempfile::tempdir().expect("tempdir");
        let err = list_packs(empty.path()).unwrap_err();
        assert!(err.contains("no packs under"), "wrong error: {err}");
        assert!(
            err.contains("<out>/packs/<name>/pack.toml"),
            "layout hint missing: {err}"
        );
    }
}
