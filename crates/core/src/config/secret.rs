//! Secret material file-permission validation.
//!
//! TLS material loading (`crate::tls`) enforces Unix permission hygiene
//! here: private keys must be owner-only (0600), certificates only warn.
//! The former `${ENV}` / `@file:` secret-indirection syntax died with the
//! engine TOML file face (removed 2026-09-22) — packs carry material as
//! files, never as inlined secret strings.

use crate::error::Result;

/// Validation strictness for secret material file permissions.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Strictness {
    /// Private key / secret: any group/other permission bit is an error.
    Strict,
    /// Certificate: overly broad permissions only warn.
    Lenient,
}

/// Validates secret material (key / secret / certificate) file permissions on
/// Unix to avoid leaks. Shared by TLS material loading.
#[cfg(unix)]
pub(crate) fn check_secret_file_perms(path: &str, strictness: Strictness) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    let meta = std::fs::metadata(path).map_err(|e| {
        crate::error::InterflowError::config(format!("failed to read file metadata for {path}"))
            .with_source(e)
    })?;
    let mode = meta.permissions().mode();
    // Display-only permission mask: the full st_mode value includes file type
    // bits (e.g. 0100644); printing it directly yields a confusing
    // "mode=100644" that does not match the suggested value (2026-09-13 bug
    // doc §3, for reference)
    let perm = mode & 0o777;
    match strictness {
        // Private keys: owner-only, any group/other bit is an error.
        Strictness::Strict => {
            if mode & 0o077 != 0 {
                Err(crate::error::InterflowError::config(format!(
                    "file {path} has overly broad permissions (mode={perm:o}); 600 required (owner read/write only). Run chmod 600 {path}"
                )))
            } else {
                Ok(())
            }
        }
        // Certificates are public material — group/other READ (0644, the
        // issuance default) is fine and must stay silent. Only the
        // local-tamper surface warns: group/other write bits or any execute
        // bit. With this threshold the "chmod 644" advice is self-consistent
        // (0664/0755 → 0644 clears it), fixing the 2026-09-23 report of a
        // 644 file being warned at with a 644 recommendation.
        Strictness::Lenient => {
            if lenient_risky(mode) {
                tracing::warn!(
                    "certificate file {path} has overly broad permissions (mode={perm:o}), chmod 644 recommended"
                );
            }
            Ok(())
        }
    }
}

/// Group/other write bits (0o022) plus every execute bit (0o111): the bits
/// that turn a public certificate into a local tamper surface.
#[cfg(unix)]
const fn lenient_risky(mode: u32) -> bool {
    mode & 0o133 != 0
}

#[cfg(not(unix))]
pub(crate) fn check_secret_file_perms(_path: &str, _strictness: Strictness) -> Result<()> {
    Ok(())
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    fn temp_file_with_mode(mode: u32) -> String {
        use std::sync::atomic::{AtomicU32, Ordering};
        static SEQ: AtomicU32 = AtomicU32::new(0);
        let path = std::env::temp_dir().join(format!(
            "interflow-secret-perms-{}-{}.crt",
            std::process::id(),
            SEQ.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::write(&path, b"placeholder\n").expect("write temp file");
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(mode))
            .expect("chmod temp file");
        path.display().to_string()
    }

    #[test]
    fn lenient_threshold_truth_table() {
        // 0644 (the issuance default for .crt) and 0640 stay silent.
        assert!(!lenient_risky(0o644));
        assert!(!lenient_risky(0o640));
        assert!(!lenient_risky(0o600));
        // Group/other write and any execute bit warn (tamper surface).
        assert!(lenient_risky(0o664));
        assert!(lenient_risky(0o646));
        assert!(lenient_risky(0o755));
        assert!(lenient_risky(0o700));
    }

    #[test]
    fn certificate_at_issuance_default_passes_silently() {
        // 2026-09-23 report: a 644 certificate warned "chmod 644 recommended"
        // on every fresh pack load — the issuance default must be clean.
        let path = temp_file_with_mode(0o644);
        assert!(check_secret_file_perms(&path, Strictness::Lenient).is_ok());
        std::fs::remove_file(path).ok();
    }

    #[test]
    fn strict_keys_reject_group_other_bits() {
        let broad = temp_file_with_mode(0o644);
        let err = check_secret_file_perms(&broad, Strictness::Strict)
            .expect_err("0644 key must be an error");
        let msg = err.to_string();
        assert!(msg.contains("chmod 600"), "advice must say 600: {msg}");
        std::fs::remove_file(broad).ok();

        let tight = temp_file_with_mode(0o600);
        assert!(check_secret_file_perms(&tight, Strictness::Strict).is_ok());
        std::fs::remove_file(tight).ok();
    }
}
