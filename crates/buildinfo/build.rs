//! Build script: computes the one build identity every Interflow binary
//! shares (see `BUILD_TAG` in src/lib.rs).

use std::process::Command;

fn main() {
    // The workspace root is found by walking up from CARGO_MANIFEST_DIR
    // (relative paths keep working if the crate moves).
    let manifest_dir = std::env::var("CARGO_MANIFEST_DIR").unwrap_or_default();
    let root = std::path::Path::new(&manifest_dir)
        .ancestors()
        .find(|dir| dir.join(".git/HEAD").exists());
    let Some(root) = root else {
        emit("unknown", false);
        return;
    };

    watch(root);

    // Identity = the commit, not the build clock: the date is the commit
    // date, so the same commit yields the same tag in any timezone or
    // rebuild (a build-clock date made midnight/timezone rebuilds disagree
    // with themselves and broke reproducibility for no information gain —
    // the hash beside it already names the code).
    let Some(date) = git(root, &["log", "-1", "--format=%cs"]) else {
        emit("unknown", false);
        return;
    };
    let Some(hash) = git(root, &["rev-parse", "--short", "HEAD"]) else {
        emit("unknown", false);
        return;
    };

    // Dirty = any uncommitted change, modified OR untracked: an untracked
    // source file compiles into the binary just the same, so excluding it
    // would let the tag claim a commit identity the binary does not have.
    // Over-marking (a stray untracked file) is cheap and honest; under-
    // marking is the lie this suffix exists to prevent.
    let dirty = git(root, &["status", "--porcelain"]).is_some_and(|s| !s.is_empty());

    let tag = if dirty {
        format!("{date}_{hash}-dirty")
    } else {
        format!("{date}_{hash}")
    };
    emit(&tag, dirty);
}

/// Re-run triggers. Besides the git state files (branch switches, new
/// commits), the watched paths cover the workspace source roots: the dirty
/// suffix must stay truthful across incremental builds, and a rebuild of
/// only one crate would otherwise keep a stale clean/dirty flag baked by an
/// earlier compile. A mere re-run is cheap; cargo only rebuilds the
/// dependents when the emitted tag value actually changes, so the flag
/// flipping costs one relink — the price of an identity that never lies
/// about the tree it was built from.
fn watch(root: &std::path::Path) {
    println!(
        "cargo:rerun-if-changed={}",
        root.join(".git/HEAD").display()
    );
    println!(
        "cargo:rerun-if-changed={}",
        root.join(".git/logs/HEAD").display()
    );
    // New commits on the current branch rewrite the reflog (a symbolic HEAD
    // file itself is not touched), which is why the reflog is watched too.
    for source_root in ["crates", "src", "src-tauri"] {
        let path = root.join(source_root);
        if path.exists() {
            println!("cargo:rerun-if-changed={}", path.display());
        }
    }
}

fn git(root: &std::path::Path, args: &[&str]) -> Option<String> {
    Command::new("git")
        .current_dir(root)
        .args(args)
        .output()
        .ok()
        .filter(|output| output.status.success())
        .map(|output| String::from_utf8_lossy(&output.stdout).trim().to_string())
}

fn emit(tag: &str, dirty: bool) {
    println!("cargo:rustc-env=INTERFLOW_BUILD_TAG={tag}");
    println!("cargo:rustc-env=INTERFLOW_DIRTY={dirty}");
}
