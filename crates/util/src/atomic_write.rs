//! Atomic file replacement.
//!
//! Interflow used to carry six hand-rolled `.tmp` + rename writers with
//! diverging behavior: fixed temp names (concurrent instances collide), no
//! fsync (crash durability incomplete), inconsistent permission handling.
//! This helper is the single implementation, with the mesh rule-persister's
//! semantics as the baseline — unique same-directory temp file, explicit
//! permission policy, `sync_all`, atomic rename, best-effort parent
//! directory fsync — now backed by [`tempfile`]:
//!
//! - the temp file is unique per call, so concurrent writers (multi-process
//!   or multi-thread) never fight over one `.tmp` name;
//! - permissions are a policy choice, never an accident of umask;
//! - the data is on disk (`sync_all`) before the rename makes it visible;
//! - a failed write leaves the original file untouched and no leftovers
//!   behind (the temp file is removed on failure).

use std::io;
use std::path::Path;
use tempfile::Builder;

/// Permission policy for the file being written.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WriteMode {
    /// Always apply exactly this mode (Unix). Pre-existing files with wrong
    /// bits are corrected — a private key sitting at 0644 must be tightened,
    /// not preserved.
    Set(u32),
    /// Preserve the target's existing permission bits; a new file gets this
    /// mode. This is the continuity policy for state/config files that
    /// users may have chmod'd deliberately.
    PreserveOr(u32),
}

/// Atomically replaces `path` with `bytes`.
///
/// The caller owns the parent-directory lifecycle: create the directory
/// beforehand if the file may not exist yet (this function does not create
/// directories). Multi-file sequences (credential generations) are not
/// transactions — ordering and rollback remain the caller's business.
pub fn atomic_write(path: &Path, bytes: &[u8], mode: WriteMode) -> io::Result<()> {
    let dir = path.parent().unwrap_or_else(|| Path::new("."));
    let file_name = path
        .file_name()
        .map_or_else(|| "file".to_owned(), |n| n.to_string_lossy().into_owned());

    let mut tmp = Builder::new()
        .prefix(&format!(".{file_name}.tmp-"))
        .tempfile_in(dir)?;

    let staging = || -> io::Result<()> {
        apply_mode(&tmp, path, mode)?;
        io::Write::write_all(&mut tmp, bytes)?;
        tmp.as_file().sync_all()?;
        Ok(())
    }();
    if let Err(e) = staging {
        // Dropping `tmp` removes the partial temp file; the original file
        // is untouched.
        drop(tmp);
        return Err(e);
    }

    if let Err(e) = tmp.persist(path) {
        // persist consumed the temp file handle; its error carries the file
        // back — remove the leftover explicitly, best-effort.
        let _ = std::fs::remove_file(e.file.path());
        return Err(e.error);
    }

    // Unix: best-effort fsync of the parent directory so the rename itself
    // hits disk. Some filesystems/platforms refuse this; the rename is
    // already atomic for readers, so this stays best-effort.
    #[cfg(unix)]
    if let Ok(dir_file) = std::fs::File::open(dir) {
        let _ = dir_file.sync_all();
    }

    Ok(())
}

/// Applies the [`WriteMode`] policy to the staged temp file.
fn apply_mode(tmp: &tempfile::NamedTempFile, target: &Path, mode: WriteMode) -> io::Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let requested = match mode {
            WriteMode::Set(m) => m,
            WriteMode::PreserveOr(m) => std::fs::metadata(target)
                .ok()
                .map_or(m, |meta| meta.permissions().mode() & 0o777),
        };
        std::fs::set_permissions(tmp.path(), std::fs::Permissions::from_mode(requested))?;
    }
    #[cfg(not(unix))]
    {
        // No mode bits on this platform; the policy is a no-op. Reference
        // the parameters so the signature stays checked.
        let _ = (tmp, target, mode);
    }
    Ok(())
}

#[cfg(test)]
#[allow(
    clippy::panic,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::missing_docs_in_private_items
)]
mod tests {
    use super::*;

    #[cfg(unix)]
    fn mode_of(path: &Path) -> u32 {
        use std::os::unix::fs::PermissionsExt;
        std::fs::metadata(path).unwrap().permissions().mode() & 0o777
    }

    #[test]
    fn creates_new_file_with_requested_mode_and_content() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("state.json");
        atomic_write(&path, b"{\"a\":1}", WriteMode::PreserveOr(0o600)).unwrap();
        assert_eq!(std::fs::read(&path).unwrap(), b"{\"a\":1}");
        #[cfg(unix)]
        assert_eq!(mode_of(&path), 0o600);
    }

    #[test]
    fn replaces_existing_content_atomically() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("cfg.toml");
        std::fs::write(&path, b"old").unwrap();
        atomic_write(&path, b"new contents", WriteMode::PreserveOr(0o644)).unwrap();
        assert_eq!(std::fs::read(&path).unwrap(), b"new contents");
        // no temp leftovers after success
        let leftovers: Vec<_> = std::fs::read_dir(dir.path())
            .unwrap()
            .filter_map(std::result::Result::ok)
            .filter(|e| e.file_name().to_string_lossy().contains(".tmp-"))
            .collect();
        assert!(leftovers.is_empty(), "no temp files may survive success");
    }

    #[cfg(unix)]
    #[test]
    fn preserve_mode_keeps_existing_bits_and_falls_back_for_new_files() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("rules.toml");
        std::fs::write(&path, b"x").unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o640)).unwrap();
        atomic_write(&path, b"y", WriteMode::PreserveOr(0o600)).unwrap();
        assert_eq!(mode_of(&path), 0o640, "existing bits are preserved");

        let fresh = dir.path().join("fresh.toml");
        atomic_write(&fresh, b"y", WriteMode::PreserveOr(0o600)).unwrap();
        assert_eq!(mode_of(&fresh), 0o600, "new files use the fallback mode");
    }

    #[cfg(unix)]
    #[test]
    fn set_mode_corrects_wrong_existing_bits() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("server.key");
        std::fs::write(&path, b"secret").unwrap();
        // a pre-existing world-readable key must be tightened, not preserved
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
        atomic_write(&path, b"secret2", WriteMode::Set(0o600)).unwrap();
        assert_eq!(mode_of(&path), 0o600);
    }

    #[cfg(unix)]
    #[test]
    fn persist_failure_leaves_target_intact_and_cleans_up() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("agent.toml");
        std::fs::write(&path, b"original").unwrap();
        // the real write-failure surface on Unix is a read-only directory
        std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o555)).unwrap();
        let err = atomic_write(&path, b"replacement", WriteMode::PreserveOr(0o600));
        std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o755)).unwrap();
        assert!(err.is_err(), "write to a read-only directory must fail");
        assert_eq!(
            std::fs::read(&path).unwrap(),
            b"original",
            "the target must be untouched by a failed write"
        );
        let leftovers: Vec<_> = std::fs::read_dir(dir.path())
            .unwrap()
            .filter_map(std::result::Result::ok)
            .filter(|e| e.file_name().to_string_lossy().contains(".tmp-"))
            .collect();
        assert!(
            leftovers.is_empty(),
            "the failure path should clean up temp files"
        );
    }

    #[test]
    fn concurrent_writers_use_distinct_temp_files() {
        // Fixed-name .tmp writers could clobber each other; the helper's
        // temp names must be unique even for the same target.
        let dir = tempfile::tempdir().unwrap();
        let a = dir.path().join("shared");
        let b = a.clone();
        let left = std::thread::spawn(move || {
            for i in 0..50 {
                atomic_write(&a, format!("left{i}").as_bytes(), WriteMode::Set(0o600)).unwrap();
            }
        });
        for i in 0..50 {
            atomic_write(&b, format!("right{i}").as_bytes(), WriteMode::Set(0o600)).unwrap();
        }
        left.join().unwrap();
        // Both writers succeeded and the target holds one of their payloads
        // — no interleaved corruption.
        let final_content = std::fs::read_to_string(&b).unwrap();
        assert!(
            final_content.starts_with("left") || final_content.starts_with("right"),
            "corrupted content: {final_content:?}"
        );
    }
}
