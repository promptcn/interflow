//! Structural contract for user-facing examples.
//!
//! `examples/` is public, neutral, self-contained documentation. Real Promptcn
//! material belongs under the private `deployments/` tree, and Cargo package
//! `examples/` directories are reserved for Rust example targets.

#![allow(
    clippy::all,
    clippy::pedantic,
    clippy::nursery,
    clippy::panic,
    clippy::unwrap_used,
    clippy::expect_used,
    missing_docs
)]

use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

fn workspace_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(|parent| parent.parent())
        .expect("testkit should be at <workspace>/crates/testkit")
        .to_path_buf()
}

fn entries(path: &Path) -> Vec<String> {
    let mut names: Vec<String> = std::fs::read_dir(path)
        .unwrap_or_else(|e| panic!("read {}: {e}", path.display()))
        .map(|entry| {
            entry
                .expect("directory entry")
                .file_name()
                .to_string_lossy()
                .into_owned()
        })
        .collect();
    names.sort();
    names
}

fn assert_regular_file(path: &Path) {
    assert!(path.is_file(), "missing required file: {}", path.display());
}

fn check_scenario_shape(base: &Path, required: &[&str]) {
    for name in required {
        assert_regular_file(&base.join(name));
    }
    for entry in std::fs::read_dir(base).expect("scenario should be listable") {
        let path = entry.expect("directory entry").path();
        if path.extension().and_then(|ext| ext.to_str()) == Some("sh") {
            assert!(
                path.metadata()
                    .expect("script metadata")
                    .permissions()
                    .mode()
                    & 0o111
                    != 0,
                "script is not executable: {}",
                path.display()
            );
            let output = std::process::Command::new("bash")
                .arg("-n")
                .arg(&path)
                .output()
                .expect("run bash -n");
            assert!(
                output.status.success(),
                "{} failed bash -n: {}",
                path.display(),
                String::from_utf8_lossy(&output.stderr)
            );
        }
    }
}

fn visit_files(root: &Path, callback: &mut dyn FnMut(&Path)) {
    if root.is_file() {
        callback(root);
        return;
    }
    for entry in std::fs::read_dir(root).unwrap_or_else(|e| panic!("read {}: {e}", root.display()))
    {
        let path = entry.expect("directory entry").path();
        if path.is_dir()
            && path
                .file_name()
                .and_then(|name| name.to_str())
                .is_some_and(|name| name == "certs")
        {
            continue;
        }
        visit_files(&path, callback);
    }
}

#[test]
fn examples_tree_is_public_neutral_and_complete() {
    let root = workspace_root();
    let examples = root.join("examples");
    assert_eq!(
        entries(&examples),
        ["README.md", "public-domain-to-lan", "site-to-site"],
        "examples must remain the fixed public scenario index"
    );

    check_scenario_shape(
        &examples.join("public-domain-to-lan"),
        &[
            "README.md",
            "generate-certs.sh",
            "nginx.conf",
            "profile.toml",
            "routes.toml",
            "start-edge.sh",
            "start-expose.sh",
        ],
    );
    check_scenario_shape(
        &examples.join("site-to-site"),
        &[
            "README.md",
            "agent-lan-a.toml",
            "agent-lan-b.toml",
            "generate-certs.sh",
            "hub.toml",
            "start-agent-lan-a.sh",
            "start-agent-lan-b.sh",
            "start-hub.sh",
        ],
    );

    let forbidden_extensions = ["key", "crt", "csr", "srl", "pem", "p12"];
    visit_files(&examples, &mut |path| {
        let extension = path.extension().and_then(|ext| ext.to_str()).unwrap_or("");
        assert!(
            !forbidden_extensions.contains(&extension),
            "certificate material must never ship in examples: {}",
            path.display()
        );
    });

    // Construct private markers so this exported test source cannot itself trip
    // the public-export literal grep gates.
    let private_domain = ["promptcn", ".com"].concat();
    let private_machines = [
        ["leo-", "mac"].concat(),
        ["leo-", "desktop"].concat(),
        ["agent-", "pzy"].concat(),
    ];
    visit_files(&examples, &mut |path| {
        let text = std::fs::read_to_string(path)
            .unwrap_or_else(|e| panic!("read {}: {e}", path.display()));
        assert!(
            !text.contains(&private_domain),
            "private domain in {}",
            path.display()
        );
        for marker in &private_machines {
            assert!(
                !text.contains(marker),
                "private machine {marker} in {}",
                path.display()
            );
        }
        for token in text.split(|c: char| !c.is_ascii_digit() && c != '.') {
            let octets: Vec<u8> = token
                .split('.')
                .map(|part| part.parse::<u8>().ok())
                .collect::<Option<_>>()
                .unwrap_or_default();
            if octets.len() != 4 {
                continue;
            }
            let private = matches!(
                octets[..],
                [10, _, _, _] | [172, 16..=31, _, _] | [192, 168, _, _]
            );
            assert!(
                !private,
                "non-loopback private address {token} in {}",
                path.display()
            );
        }
    });
}

#[test]
fn cargo_example_directories_contain_only_rust_targets() {
    let crates = workspace_root().join("crates");
    for entry in std::fs::read_dir(&crates).expect("crates directory should be listable") {
        let crate_dir = entry.expect("crate entry").path();
        let examples = crate_dir.join("examples");
        if !examples.is_dir() {
            continue;
        }
        visit_files(&examples, &mut |path| {
            assert_eq!(
                path.extension().and_then(|ext| ext.to_str()),
                Some("rs"),
                "Cargo examples must contain Rust targets only: {}",
                path.display()
            );
        });
    }
}

#[test]
fn active_entrypoints_do_not_reference_removed_example_paths() {
    let root = workspace_root();
    let active_paths = [
        root.join("README.md"),
        root.join("justfile"),
        root.join("Dockerfile"),
        root.join("scripts/export_public.sh"),
    ];
    for path in active_paths.iter().take(3) {
        assert!(
            path.is_file(),
            "required active entrypoint missing: {}",
            path.display()
        );
    }
    let active_paths = active_paths
        .into_iter()
        .filter(|path| path.is_file())
        .collect::<Vec<_>>();
    let old_paths = [
        ["reverse-tunnel-", "public"].concat(),
        ["reverse-tunnel-", "private"].concat(),
        ["crates/mesh/", "examples"].concat(),
    ];
    for path in active_paths {
        let text = std::fs::read_to_string(&path)
            .unwrap_or_else(|e| panic!("read {}: {e}", path.display()));
        for old in &old_paths {
            assert!(
                !text.contains(old),
                "{} references removed path {old}",
                path.display()
            );
        }
    }
}
