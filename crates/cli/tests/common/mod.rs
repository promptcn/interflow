//! Shared helpers for the cli crate's integration tests (each `tests/*.rs`
//! file is its own crate, so the common module is how they share code; the
//! `common/` subdirectory is not itself a test target).
//!
//! New tests take the subprocess trio (`bin`/`RunOutcome`/`run`, plus
//! `run_ok`) from here rather than copying it again; older files whose
//! local copies drifted (struct name, extra wrappers) keep theirs until
//! they are next touched — migrate on touch, do not churn.

// Test-support code: panicking on a broken fixture IS the failure mode, and
// each including test crate uses only a subset of the helpers (dead_code is
// per-binary here).
#![allow(
    dead_code,
    clippy::all,
    clippy::pedantic,
    clippy::nursery,
    clippy::panic,
    clippy::unwrap_used,
    clippy::expect_used
)]

use interflow_identity::Manifest;
use std::path::{Path, PathBuf};
use std::process::Command;

/// The crate's real binary — the integration tests exercise the shipped
/// face (argument parsing, output lines, exit codes), not library
/// internals.
pub fn bin() -> PathBuf {
    let mut p = std::env::current_exe().expect("test bin path");
    p.pop(); // deps/
    p.pop(); // tests/
    p.join(format!("interflow-cli{}", std::env::consts::EXE_SUFFIX))
}

/// One invocation's outcome.
pub struct RunOutcome {
    pub success: bool,
    pub stdout: String,
    pub stderr: String,
}

pub fn run(args: &[&str]) -> RunOutcome {
    let output = Command::new(bin())
        .args(args)
        .output()
        .expect("spawn interflow");
    RunOutcome {
        success: output.status.success(),
        stdout: String::from_utf8_lossy(&output.stdout).into_owned(),
        stderr: String::from_utf8_lossy(&output.stderr).into_owned(),
    }
}

/// `run` that must succeed — the failure message carries both streams, so
/// a red test is readable without re-running by hand.
pub fn run_ok(args: &[&str]) -> RunOutcome {
    let out = run(args);
    assert!(
        out.success,
        "interflow {args:?} failed:\nstdout: {}\nstderr: {}",
        out.stdout, out.stderr,
    );
    out
}

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
