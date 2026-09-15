//! Config-relative path anchoring.
//!
//! Invariant: every relative filesystem path that appears inside a config
//! file resolves against the directory containing that config file — never
//! against the process working directory, which is meaningless under
//! systemd, Docker, or GUI launches. CLI-flag paths keep the standard Unix
//! CWD semantics and are out of scope.
//!
//! Anchoring happens at load time, immediately after secret expansion and
//! before validation, so every downstream consumer (validation, TLS
//! acceptors, audit writers, hot-reload) sees absolute paths and needs no
//! path handling of its own.

use crate::error::{InterflowError, Result};
use std::path::{Path, PathBuf};

/// Absolutizes `path` against the process working directory when relative.
///
/// `fs::canonicalize` is deliberately avoided: it requires the file to
/// already exist and prefixes `\\?\` on Windows.
pub fn absolutize(path: &Path) -> Result<PathBuf> {
    if path.is_absolute() {
        return Ok(path.to_path_buf());
    }
    let cwd = std::env::current_dir().map_err(|e| {
        InterflowError::config(format!(
            "cannot resolve relative config path {}: {e}",
            path.display()
        ))
    })?;
    Ok(cwd.join(path))
}

/// Anchors a config-file path string against the config file's directory.
///
/// Absolute values and empty values pass through unchanged (empty is
/// reported by load-time validation, not silently rewritten here). `.`
/// components are lexically dropped; `..` is preserved (no symlink-aware
/// canonicalization — the target may not exist yet).
pub fn anchor(base_dir: &Path, value: &str) -> String {
    if value.is_empty() || Path::new(value).is_absolute() {
        value.to_string()
    } else {
        let anchored: PathBuf = base_dir.join(value).components().collect();
        anchored.to_string_lossy().into_owned()
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)] // unwrap is test convention
mod tests {
    use super::*;

    #[test]
    fn absolute_passes_through() {
        let abs = std::env::current_dir().unwrap().join("x.pem");
        assert_eq!(
            anchor(Path::new("/etc/interflow"), &abs.display().to_string()),
            abs.display().to_string()
        );
    }

    #[test]
    fn relative_joins_base() {
        let anchored = anchor(Path::new("/etc/interflow"), "certs/hub.crt");
        assert_eq!(anchored, "/etc/interflow/certs/hub.crt");
    }

    #[test]
    fn dot_slash_prefix_joins_base() {
        // "." components drop lexically; ".." is preserved.
        assert_eq!(
            anchor(Path::new("/etc/interflow"), "./audit.jsonl"),
            "/etc/interflow/audit.jsonl"
        );
        assert_eq!(
            anchor(Path::new("/etc/interflow"), "../log/audit.jsonl"),
            "/etc/interflow/../log/audit.jsonl"
        );
    }

    #[test]
    fn empty_passes_through() {
        assert_eq!(anchor(Path::new("/etc/interflow"), ""), "");
    }

    #[test]
    fn absolutize_keeps_absolute() {
        let abs = std::env::temp_dir();
        assert_eq!(absolutize(&abs).unwrap(), abs);
    }

    #[test]
    fn absolutize_joins_cwd_for_relative() {
        let joined = absolutize(Path::new("hub.toml")).unwrap();
        assert!(joined.is_absolute());
        assert!(joined.ends_with("hub.toml"));
    }
}
