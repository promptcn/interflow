//! Deploy surface: the operator face of the GUI — manifest template +
//! validate/apply, dist pack inventory, seal / rotate / revoke, and
//! sealed-pack import for "add as node".
//!
//! Framework-free domain logic over `interflow_cli` (the same code paths the
//! `interflow` binary runs); `commands.rs` wraps these as Tauri commands.

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
    pub kind: crate::node::NodeKind,
    pub node: String,
    pub generation: u64,
    pub expires: String,
    pub principal: String,
}

/// Lists the packs of a `plan apply` output tree (`<out>/packs/*`).
pub fn list_packs(out_root: &Path) -> Result<Vec<DeployPack>, String> {
    let packs_dir = out_root.join("packs");
    let entries = std::fs::read_dir(&packs_dir)
        .map_err(|e| format!("no packs under {}: {e}", packs_dir.display()))?;
    let mut out = Vec::new();
    for entry in entries {
        let entry = entry.map_err(|e| format!("read packs dir: {e}"))?;
        let path = entry.path();
        if !path.join("pack.toml").is_file() {
            continue;
        }
        let pack = interflow_identity::pack::CredentialPack::load(&path)
            .map_err(|e| format!("{}: {e}", path.display()))?;
        let info = node::inspect_pack(&path)?;
        out.push(DeployPack {
            dir_name: entry.file_name().to_string_lossy().into_owned(),
            kind: info.kind,
            node: pack.metadata.node.clone(),
            generation: pack.metadata.generation,
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
        let apply_lines =
            interflow_cli::plan::apply(&manifest, Path::new(&issuer), Path::new(&out), false)
                .expect("applies");
        assert!(
            apply_lines.iter().any(|l| l.contains("✔ applied")),
            "{apply_lines:?}"
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
        interflow_cli::plan::apply(&manifest, &issuer, &out, false).expect("apply");

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
            })
            .expect("installs");
        assert!(report.installed_to.join("pack.toml").is_file());
        assert!(node::inspect_pack(&report.installed_to).is_ok());
    }
}
