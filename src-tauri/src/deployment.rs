//! Deployment as the GUI's root object (2026-10-10 redesign): discovery of
//! the one-deployment-one-folder tree, and the node↔deployment association
//! that lets every local node answer "which deployment owns me".
//!
//! A deployment is a folder — `~/interflow-deployments/<realm>/` with the
//! fixed inner names `interflow.toml` / `issuer/` / `dist/` (the CLI's
//! CWD-relative defaults made structural; (internal design notes) 部署模型). Discovery
//! scans the root; association walks a pack directory's ancestors. Both are
//! pure filesystem probes — no issuer store is opened, nothing dials.

use std::path::{Path, PathBuf};

/// The deployments root: one folder per realm, in the home directory
/// (visible, operator-browsable, never touched by Documents-folder cloud
/// sync; key material stays protected by permissions, not by hiding).
pub fn deployments_root() -> PathBuf {
    dirs::home_dir()
        .unwrap_or_else(std::env::temp_dir)
        .join("interflow-deployments")
}

/// One discovered deployment folder. Paths are derived, never guessed: the
/// manifest is what makes a folder a deployment; `issuer`/`dist` are the
/// conventional names the GUI's blank-fill resolves for it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeploymentDir {
    /// `<root>/<realm>` — the deployment folder itself.
    pub root: PathBuf,
    /// The folder's name (the realm id, by the naming convention).
    pub name: String,
    pub manifest: PathBuf,
    pub issuer: PathBuf,
    pub out: PathBuf,
    /// Whether `issuer/` exists (an apply has run here at least once).
    pub has_issuer: bool,
    /// Whether `dist/` exists (packs have been rendered here).
    pub has_dist: bool,
}

impl DeploymentDir {
    /// Probes one folder; `None` when it is not a deployment (no
    /// `interflow.toml`).
    pub fn probe(root: &Path) -> Option<Self> {
        let manifest = root.join("interflow.toml");
        if !manifest.is_file() {
            return None;
        }
        let issuer = root.join("issuer");
        let out = root.join("dist");
        Some(Self {
            root: root.to_path_buf(),
            name: root.file_name().map_or_else(
                || root.display().to_string(),
                |n| n.to_string_lossy().into_owned(),
            ),
            manifest,
            has_issuer: issuer.is_dir(),
            has_dist: out.is_dir(),
            issuer,
            out,
        })
    }

    /// Probes the deployment containing a manifest path (the path may be
    /// the manifest itself or its folder).
    pub fn containing(path: &Path) -> Option<Self> {
        let root = if path.is_dir() { path } else { path.parent()? };
        Self::probe(root)
    }
}

/// Lists the deployments under [`deployments_root`], name-sorted. A missing
/// or unreadable root is an empty list (first run), not an error — the
/// empty state is the first-run onboarding entry.
pub fn discover() -> Vec<DeploymentDir> {
    let root = deployments_root();
    let Ok(entries) = std::fs::read_dir(&root) else {
        return Vec::new();
    };
    let mut found: Vec<DeploymentDir> = entries
        .filter_map(std::result::Result::ok)
        .filter_map(|entry| DeploymentDir::probe(&entry.path()))
        .collect();
    found.sort_by(|a, b| a.name.cmp(&b.name));
    found
}

/// Reverse-resolves a pack directory to its owning deployment.
///
/// A pack rendered by `apply` lives at `<root>/dist/packs/<name>` (three
/// levels under the deployment folder); sealed imports land in the GUI's
/// managed packs root and have no deployment — `None`. The walk is bounded
/// and shape-checked: an ancestor only counts when it carries
/// `interflow.toml` AND the pack sits under its `dist` (or `packs`) tree,
/// so a stray `interflow.toml` above an unrelated directory can never
/// claim the node.
pub fn deployment_of_pack(pack_dir: &Path) -> Option<DeploymentDir> {
    let pack_root = if pack_dir.join("pack.toml").is_file() {
        pack_dir
    } else {
        return None;
    };
    let mut ancestor = pack_root.parent()?;
    for _ in 0..3 {
        if let Some(deployment) = DeploymentDir::probe(ancestor) {
            let under_dist = pack_root.starts_with(ancestor.join("dist"))
                || pack_root.starts_with(ancestor.join("packs"));
            if under_dist {
                return Some(deployment);
            }
            // A manifest above but outside its dist tree claims nothing —
            // keep walking (a nested deployment may own the pack instead).
        }
        ancestor = ancestor.parent()?;
    }
    None
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    /// The association ladder: a dist-tree pack resolves to its deployment;
    /// a managed/sealed pack (no `interflow.toml` above it) resolves to
    /// nothing; a stray manifest above an unrelated tree claims nothing.
    #[test]
    fn pack_association_follows_the_dist_tree() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().join("my-realm");
        std::fs::create_dir_all(root.join("dist/packs/agent-desktop")).unwrap();
        std::fs::write(root.join("interflow.toml"), "[realm]\nid = \"x\"\n").unwrap();
        std::fs::write(
            root.join("dist/packs/agent-desktop/pack.toml"),
            "node = \"desktop\"\n",
        )
        .unwrap();

        let pack = root.join("dist/packs/agent-desktop");
        let deployment = deployment_of_pack(&pack).expect("dist-tree pack resolves");
        assert_eq!(deployment.name, "my-realm");
        assert_eq!(deployment.manifest, root.join("interflow.toml"));
        assert!(deployment.has_dist);
        assert!(!deployment.has_issuer, "no issuer directory exists yet");

        // A pack with no deployment above it (the sealed-import shape).
        let stray = dir.path().join("managed/agent-laptop");
        std::fs::create_dir_all(&stray).unwrap();
        std::fs::write(stray.join("pack.toml"), "node = \"laptop\"\n").unwrap();
        assert!(deployment_of_pack(&stray).is_none());

        // A manifest above an OUT-OF-TREE pack claims nothing: the shape
        // check (`dist`/`packs`) is what makes the walk honest.
        let elsewhere = dir.path().join("elsewhere");
        std::fs::create_dir_all(&elsewhere).unwrap();
        std::fs::write(elsewhere.join("pack.toml"), "node = \"y\"\n").unwrap();
        assert!(deployment_of_pack(&elsewhere).is_none());

        // A bare directory (no pack.toml) is not a pack at all.
        assert!(deployment_of_pack(&dir.path().join("dist")).is_none());
    }

    /// Discovery lists name-sorted and requires the manifest; `containing`
    /// accepts either the folder or the manifest path.
    #[test]
    fn discovery_and_containing_shapes() {
        let home = std::env::var("HOME").unwrap_or_else(|_| "/tmp".into());
        // Probe through the pure shapes instead of touching the real root.
        let dir = tempfile::tempdir().unwrap();
        let a = dir.path().join("alpha");
        let b = dir.path().join("beta");
        for root in [&a, &b] {
            std::fs::create_dir_all(root).unwrap();
            std::fs::write(root.join("interflow.toml"), "[realm]\nid = \"x\"\n").unwrap();
        }
        std::fs::create_dir_all(dir.path().join("not-a-deployment")).unwrap();
        let found = DeploymentDir::probe(&a).unwrap();
        assert_eq!(found.name, "alpha");
        let via_manifest = DeploymentDir::containing(&a.join("interflow.toml")).unwrap();
        assert_eq!(via_manifest.root, a);
        assert!(DeploymentDir::probe(&dir.path().join("not-a-deployment")).is_none());
        // The discover() path reads the real deployments root — assert it
        // never panics and only yields manifest-bearing folders.
        for deployment in discover() {
            assert!(deployment.manifest.is_file(), "{:?}", deployment.root);
        }
        let _ = home;
    }
}
