//! User-typed path handling (tilde expansion + base anchoring).
//!
//! A leading `~` (bare or `~/…`) expands to the user's home directory at
//! every entry point. Hand-typed paths (GUI forms, profiles) never pass
//! through a shell, so the program itself carries this one shell
//! convention instead of each entry failing on the literal.
//!
//! [`anchor`] resolves a relative path against a base directory (the
//! profile's directory on the GUI path) — never against the process
//! working directory, which is meaningless under systemd, Docker, or GUI
//! launches.

use std::path::{Path, PathBuf};

/// Expands a leading `~` to the user's home directory.
///
/// Covers the two forms a user can type: `~` alone and `~/rest`. `~user/…`
/// would require the user database (getpwent) and is deliberately left as a
/// literal — existence validation then reports it instead of silently
/// rewriting it into the wrong home. Unexpandable inputs (no home dir, other
/// prefixes) pass through unchanged.
pub fn expand_tilde(path: &str) -> String {
    expand_tilde_opt(path).unwrap_or_else(|| path.to_string())
}

/// `Some` only when `path` is `~` or `~/…` and the home directory resolves.
fn expand_tilde_opt(path: &str) -> Option<String> {
    let rest = match path {
        "~" => "",
        p if p.starts_with("~/") => &p[2..],
        _ => return None,
    };
    let home = dirs::home_dir()?;
    // join("") would append a trailing separator to the bare `~` form.
    Some(if rest.is_empty() {
        home.display().to_string()
    } else {
        home.join(rest).display().to_string()
    })
}

/// Anchors a relative path string against `base_dir`.
///
/// Absolute values and empty values pass through unchanged (empty is
/// reported by validation, not silently rewritten here). `.`
/// components are lexically dropped; `..` is preserved (no symlink-aware
/// canonicalization — the target may not exist yet).
pub fn anchor(base_dir: &Path, value: &str) -> String {
    // Tilde expansion wins over anchoring: `~/x` is lexically relative but
    // semantically absolute, so it must never join the base directory.
    if let Some(expanded) = expand_tilde_opt(value) {
        return expanded;
    }
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
    fn tilde_expands_to_home() {
        let home = dirs::home_dir().unwrap();
        assert_eq!(expand_tilde("~"), home.display().to_string());
        assert_eq!(
            expand_tilde("~/interflow-certs/agents/edge-lan-agent.crt"),
            home.join("interflow-certs/agents/edge-lan-agent.crt")
                .display()
                .to_string()
        );
    }

    #[test]
    fn tilde_user_and_other_prefixes_stay_literal() {
        // `~user` needs getpwent; leaving it literal lets existence
        // validation report it instead of rewriting into the wrong home.
        assert_eq!(expand_tilde("~leo/certs/hub.crt"), "~leo/certs/hub.crt");
        assert_eq!(expand_tilde("certs/hub.crt"), "certs/hub.crt");
        assert_eq!(
            expand_tilde("/etc/interflow/hub.crt"),
            "/etc/interflow/hub.crt"
        );
        assert_eq!(expand_tilde(""), "");
    }

    #[test]
    fn anchor_expands_tilde_instead_of_joining_base() {
        let home = dirs::home_dir().unwrap();
        assert_eq!(
            anchor(Path::new("/etc/interflow"), "~/certs/agent.crt"),
            home.join("certs/agent.crt").display().to_string()
        );
    }
}
