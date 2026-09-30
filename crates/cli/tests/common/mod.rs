//! Shared helpers for the cli crate's integration tests (each `tests/*.rs`
//! file is its own crate, so the common module is how they share code; the
//! `common/` subdirectory is not itself a test target).

#![allow(clippy::all, clippy::pedantic, clippy::nursery)]

use interflow_identity::Manifest;
use std::path::{Path, PathBuf};

pub fn workspace_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(|p| p.parent())
        .expect("cli crate should be at <workspace>/crates/cli")
        .to_path_buf()
}

pub fn load_and_validate(path: &Path) -> Manifest {
    let manifest = Manifest::load(path).unwrap_or_else(|e| panic!("{}: {e}", path.display()));
    manifest
        .validate()
        .unwrap_or_else(|e| panic!("{}: {e}", path.display()));
    manifest
}
