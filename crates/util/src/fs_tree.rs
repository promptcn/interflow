//! Deterministic directory-tree traversal and the one recursive copy.

use std::path::Path;

/// The one recursive copy in the product (`plan stage` copies packs with
/// it too, so every pack copy in the tree takes the same path — the
/// 2026-11 staging incident was a hand-rolled `cp` missing `-R`).
///
/// Follows directory entries in `read_dir` order; regular files copy via
/// `fs::copy` (permissions preserved). Not symlink-aware: the pack trees
/// this serves are product-rendered and symlink-free, and a dangling link
/// surfaces as the copy error it is.
pub fn copy_dir_recursive(src: &Path, dst: &Path) -> std::io::Result<()> {
    std::fs::create_dir_all(dst)?;
    for entry in std::fs::read_dir(src)? {
        let entry = entry?;
        let path = entry.path();
        let target = dst.join(entry.file_name());
        if path.is_dir() {
            copy_dir_recursive(&path, &target)?;
        } else {
            std::fs::copy(&path, &target)?;
        }
    }
    Ok(())
}

/// One tree member, relative to the walk's root (forward slashes).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WalkEntry {
    /// Path relative to the root, `/`-separated, no leading slash.
    pub rel: String,
    /// Directory (`true`) or regular file (`false`).
    pub is_dir: bool,
    /// The entry's permission bits (`mode & 0o7777` on unix; `0o755`/`0o644`
    /// heuristics elsewhere).
    pub mode: u32,
}

/// Every member under `root`, depth-first with each directory's entries
/// sorted by name.
///
/// The walk is a pure, byte-stable function of the tree — which is what
/// makes digest manifests and tars derived from it reproducible. Does not
/// follow symlinks (they read as their link entry).
pub fn walk_sorted(root: &Path) -> std::io::Result<Vec<WalkEntry>> {
    let mut out = Vec::new();
    walk(root, "", &mut out)?;
    Ok(out)
}

fn walk(dir: &Path, prefix: &str, out: &mut Vec<WalkEntry>) -> std::io::Result<()> {
    let mut entries = std::fs::read_dir(dir)?.collect::<std::io::Result<Vec<_>>>()?;
    entries.sort_by_key(std::fs::DirEntry::file_name);
    for entry in entries {
        let name = entry.file_name().to_string_lossy().into_owned();
        let rel = if prefix.is_empty() {
            name
        } else {
            format!("{prefix}/{name}")
        };
        let meta = entry.metadata()?;
        if meta.is_dir() {
            out.push(WalkEntry {
                rel: rel.clone(),
                is_dir: true,
                mode: entry_mode(&meta, true),
            });
            walk(&entry.path(), &rel, out)?;
        } else {
            out.push(WalkEntry {
                rel,
                is_dir: false,
                mode: entry_mode(&meta, false),
            });
        }
    }
    Ok(())
}

#[cfg(unix)]
fn entry_mode(meta: &std::fs::Metadata, _is_dir: bool) -> u32 {
    use std::os::unix::fs::MetadataExt;
    meta.mode() & 0o7777
}

#[cfg(not(unix))]
fn entry_mode(_meta: &std::fs::Metadata, is_dir: bool) -> u32 {
    if is_dir { 0o755 } else { 0o644 }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The walk is sorted, `/`-separated, and reports dirs and modes.
    #[test]
    #[allow(clippy::unwrap_used)]
    fn walk_is_sorted_and_shaped() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path();
        std::fs::create_dir_all(root.join("b/sub")).unwrap();
        std::fs::create_dir_all(root.join("a")).unwrap();
        std::fs::write(root.join("b/sub/z.txt"), b"z").unwrap();
        std::fs::write(root.join("b/a.txt"), b"a").unwrap();
        std::fs::write(root.join("m.txt"), b"m").unwrap();
        let rels: Vec<(String, bool)> = walk_sorted(root)
            .unwrap()
            .into_iter()
            .map(|e| (e.rel, e.is_dir))
            .collect();
        assert_eq!(
            rels,
            vec![
                ("a".to_owned(), true),
                ("b".to_owned(), true),
                ("b/a.txt".to_owned(), false),
                ("b/sub".to_owned(), true),
                ("b/sub/z.txt".to_owned(), false),
                ("m.txt".to_owned(), false),
            ]
        );
    }

    /// The recursive copy reproduces content and permissions.
    #[test]
    #[cfg(unix)]
    #[allow(clippy::unwrap_used)]
    fn copy_reproduces_the_tree() {
        use std::os::unix::fs::PermissionsExt;
        let tmp = tempfile::tempdir().unwrap();
        let src = tmp.path().join("src");
        std::fs::create_dir_all(src.join("d")).unwrap();
        std::fs::write(src.join("d/f"), b"content").unwrap();
        std::fs::set_permissions(src.join("d/f"), std::fs::Permissions::from_mode(0o600)).unwrap();
        let dst = tmp.path().join("dst");
        copy_dir_recursive(&src, &dst).unwrap();
        assert_eq!(std::fs::read(dst.join("d/f")).unwrap(), b"content");
        assert_eq!(
            std::fs::metadata(dst.join("d/f"))
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o600
        );
    }
}
