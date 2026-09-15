//! Build script: injects the build date and git hash into environment variables.

use std::process::Command;

fn main() {
    // Make build.rs re-run when the git state changes:
    //   - .git/HEAD: catches branch switches / detached HEAD
    //   - .git/logs/HEAD: catches new commits on the same branch (when HEAD is
    //     a symbolic ref, .git/HEAD itself is not rewritten, so the reflog is
    //     required to notice new commits)
    // Derive the workspace root from CARGO_MANIFEST_DIR so relative paths
    // keep working if the crate moves.
    if let Ok(manifest_dir) = std::env::var("CARGO_MANIFEST_DIR") {
        let mut dir = std::path::PathBuf::from(manifest_dir);
        while dir.pop() {
            let git_head = dir.join(".git/HEAD");
            if git_head.exists() {
                println!("cargo:rerun-if-changed={}", git_head.display());
                let reflog = dir.join(".git/logs/HEAD");
                println!("cargo:rerun-if-changed={}", reflog.display());
                break;
            }
        }
    }

    // Get the current date, formatted YYYY-MM-DD
    let date = chrono::Local::now().format("%Y-%m-%d").to_string();

    // Get the git commit hash (short format)
    let git_hash = Command::new("git")
        .args(["rev-parse", "--short", "HEAD"])
        .output()
        .map_or_else(
            |_| "unknown".to_string(),
            |output| String::from_utf8_lossy(&output.stdout).trim().to_string(),
        );

    // Set compile-time environment variables
    println!("cargo:rustc-env=INTERFLOW_BUILD_DATE={date}");
    println!("cargo:rustc-env=INTERFLOW_GIT_HASH={git_hash}");
}
