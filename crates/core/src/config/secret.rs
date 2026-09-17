//! Secret field expansion: supports literals / `${ENV}` / `${ENV:-default}` / `@file:path`.
//!
//! [`resolve_all`] is invoked to expand after [`crate::config::loader`]
//! parses the TOML. File references enforce 0600 permissions (Unix).
//!
//! Relative `@file:` references anchor to `base` (the config file's
//! directory).

use crate::error::{InterflowError, Result};
use std::path::{Path, PathBuf};

/// Expands a single secret string.
///
/// Syntax:
/// - `"plain literal"` → returned as-is
/// - `"${VAR}"` → read from env; error if unset
/// - `"${VAR:-default}"` → read from env; use `default` if unset
/// - `"@file:path"` → read the file content and trim trailing whitespace;
///   Unix enforces 0600; a relative `path` resolves against `base`
///
/// Any other form is returned as-is (a plain string). `base` only affects
/// `@file:` references; environment lookups ignore it.
pub fn resolve(value: &str, base: &Path) -> Result<String> {
    if let Some(rest) = value.strip_prefix("@file:") {
        return resolve_file(rest, base);
    }
    if let Some(rest) = value.strip_prefix("${")
        && let Some(end) = rest.find('}')
    {
        let inner = &rest[..end];
        // Supports `VAR:-default`
        let (var, default) = inner.find(":-").map_or((inner, None), |idx| {
            (&inner[..idx], Some(&inner[idx + 2..]))
        });
        return std::env::var(var).map_or_else(
            |_| {
                default.map_or_else(
                    || {
                        Err(InterflowError::config(format!(
                            "secret references an unset environment variable: {var}"
                        )))
                    },
                    |d| Ok(d.to_string()),
                )
            },
            Ok,
        );
    }
    Ok(value.to_string())
}

fn resolve_file(path: &str, base: &Path) -> Result<String> {
    let resolved = if Path::new(path).is_absolute() {
        PathBuf::from(path)
    } else {
        base.join(path)
    };
    let display = resolved.display().to_string();
    check_secret_file_perms(&display, Strictness::Strict)?;
    let content = std::fs::read_to_string(&resolved).map_err(|e| {
        InterflowError::config(format!("failed to read secret file {display}: {e}"))
    })?;
    Ok(content.trim_end().to_string())
}

/// Validation strictness for secret material file permissions.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Strictness {
    /// Private key / secret: any group/other permission bit is an error.
    Strict,
    /// Certificate: overly broad permissions only warn.
    Lenient,
}

/// Validates secret material (key / secret / certificate) file permissions on
/// Unix to avoid leaks. Single implementation shared by `@file:` secret
/// resolution and TLS material loading.
#[cfg(unix)]
pub(crate) fn check_secret_file_perms(path: &str, strictness: Strictness) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    let meta = std::fs::metadata(path).map_err(|e| {
        InterflowError::config(format!("failed to read file metadata for {path}: {e}"))
    })?;
    let mode = meta.permissions().mode();
    // 0o077 mask: group/other must not have any permission bits
    let leak = mode & 0o077;
    if leak == 0 {
        return Ok(());
    }
    // Display-only permission mask: the full st_mode value includes file type
    // bits (e.g. 0100644); printing it directly yields a confusing
    // "mode=100644" that does not match the suggested value (2026-09-13 bug
    // doc §3, for reference)
    let perm = mode & 0o777;
    match strictness {
        Strictness::Strict => Err(InterflowError::config(format!(
            "file {path} has overly broad permissions (mode={perm:o}); 600 required (owner read/write only). Run chmod 600 {path}"
        ))),
        Strictness::Lenient => {
            tracing::warn!(
                "certificate file {path} has overly broad permissions (mode={perm:o}), chmod 644 recommended"
            );
            Ok(())
        }
    }
}

#[cfg(not(unix))]
pub(crate) fn check_secret_file_perms(_path: &str, _strictness: Strictness) -> Result<()> {
    Ok(())
}

/// Determines whether a string is a secret reference (used to decide whether to trigger resolution).
pub fn is_indirection(s: &str) -> bool {
    s.starts_with("${") || s.starts_with("@file:")
}

/// Convenience function: resolves `value` if it is a reference; returns it as-is otherwise.
pub fn maybe_resolve(value: &str, base: &Path) -> Result<String> {
    if is_indirection(value) {
        resolve(value, base)
    } else {
        Ok(value.to_string())
    }
}

#[cfg(test)]
#[allow(unsafe_code, clippy::unwrap_used, clippy::expect_used)] // tests need set_var/remove_var, unsafe in edition 2024; unwrap is test convention
mod tests {
    use super::*;
    use std::io::Write;

    #[test]
    fn literal_passes_through() {
        assert_eq!(resolve("hello", Path::new("")).unwrap(), "hello");
    }

    #[test]
    fn env_var_resolves_when_set() {
        // safety: test runs single-threaded for env mutation.
        unsafe {
            std::env::set_var("INTERFLOW_TEST_SECRET", "abc123");
        }
        assert_eq!(
            resolve("${INTERFLOW_TEST_SECRET}", Path::new("")).unwrap(),
            "abc123"
        );
        unsafe {
            std::env::remove_var("INTERFLOW_TEST_SECRET");
        }
    }

    #[test]
    fn env_var_with_default_uses_default_when_unset() {
        // safety: test runs single-threaded for env mutation.
        unsafe {
            std::env::remove_var("INTERFLOW_UNSET_VAR_XYZ");
        }
        assert_eq!(
            resolve("${INTERFLOW_UNSET_VAR_XYZ:-fallback}", Path::new("")).unwrap(),
            "fallback"
        );
    }

    #[test]
    fn env_var_without_default_errors_when_unset() {
        // safety: test runs single-threaded for env mutation.
        unsafe {
            std::env::remove_var("INTERFLOW_UNSET_VAR_XYZ");
        }
        assert!(resolve("${INTERFLOW_UNSET_VAR_XYZ}", Path::new("")).is_err());
    }

    #[test]
    fn file_reference_reads_and_trims() {
        let dir = std::env::temp_dir();
        let path = dir.join("interflow_secret_test.txt");
        {
            let mut f = std::fs::File::create(&path).unwrap();
            writeln!(f, "file-secret-value\n").unwrap();
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mut perms = std::fs::metadata(&path).unwrap().permissions();
            perms.set_mode(0o600);
            std::fs::set_permissions(&path, perms).unwrap();
        }
        let spec = format!("@file:{}", path.display());
        assert_eq!(resolve(&spec, Path::new("")).unwrap(), "file-secret-value");
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    #[cfg(unix)]
    fn file_reference_rejects_world_readable() {
        let dir = std::env::temp_dir();
        let path = dir.join("interflow_secret_test_leaky.txt");
        {
            let mut f = std::fs::File::create(&path).unwrap();
            writeln!(f, "leaky").unwrap();
        }
        use std::os::unix::fs::PermissionsExt;
        let mut perms = std::fs::metadata(&path).unwrap().permissions();
        perms.set_mode(0o644);
        std::fs::set_permissions(&path, perms).unwrap();
        let spec = format!("@file:{}", path.display());
        assert!(
            resolve(&spec, Path::new("")).is_err(),
            "should reject 0644 secret file"
        );
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn file_reference_anchors_relative_path_to_base() {
        let dir = std::env::temp_dir().join("interflow_secret_base_test");
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("token");
        {
            let mut f = std::fs::File::create(&path).unwrap();
            writeln!(f, "anchored-secret").unwrap();
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mut perms = std::fs::metadata(&path).unwrap().permissions();
            perms.set_mode(0o600);
            std::fs::set_permissions(&path, perms).unwrap();
        }
        // Relative reference resolves against the config dir, not the CWD.
        assert_eq!(resolve("@file:token", &dir).unwrap(), "anchored-secret");
        // Absolute reference is untouched by base.
        let spec = format!("@file:{}", path.display());
        assert_eq!(resolve(&spec, &dir).unwrap(), "anchored-secret");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn is_indirection_detects() {
        assert!(is_indirection("${VAR}"));
        assert!(is_indirection("@file:/etc/x"));
        assert!(!is_indirection("plain"));
    }
}
