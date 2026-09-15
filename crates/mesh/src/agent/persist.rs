//! Control-plane rule persistence: add/remove writes from the control API are
//! written back to the agent TOML (the file is the source of truth).
//!
//! Design notes:
//! - `toml_edit` performs surgical edits on the `[[ingress]]` / `[[egress]]`
//!   arrays-of-tables — preserving the original file's comments, field order,
//!   and remaining sections;
//! - atomic write: temp file in the same directory + `rename` replacement
//!   (preserves the original file's permission bits; best-effort directory
//!   fsync on Unix), so a crash cannot leave a half-written config behind;
//! - within the process, a `Mutex` serializes writes — the ingress / egress
//!   handler tasks may write the same file concurrently, so
//!   read-modify-write must be mutually exclusive;
//! - removing an entry that does not exist in the file is idempotent
//!   (`RuleStore` treats in-memory state as the strict existence criterion;
//!   the file may lag behind memory due to external manual edits).

use crate::config::{EgressRule, IngressRule};
use futures::future::BoxFuture;
use interflow_core::error::{InterflowError, Result};
use serde::Serialize;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tokio::sync::Mutex;

/// A single rule edit. `Add*` with the same name = replace the existing entry
/// (aligned with runtime Egress semantics).
#[derive(Debug, Clone)]
pub enum RuleEdit {
    /// Add (or replace) an ingress rule.
    AddIngress(IngressRule),
    /// Remove an ingress rule.
    RemoveIngress(String),
    /// Add (or replace) an egress rule.
    AddEgress(EgressRule),
    /// Remove an egress rule.
    RemoveEgress(String),
}

impl RuleEdit {
    /// Target array-of-tables section name (`ingress` / `egress`).
    const fn section(&self) -> &'static str {
        match self {
            Self::AddIngress(_) | Self::RemoveIngress(_) => "ingress",
            Self::AddEgress(_) | Self::RemoveEgress(_) => "egress",
        }
    }

    /// The rule name involved.
    fn rule_name(&self) -> &str {
        match self {
            Self::AddIngress(r) => &r.name,
            Self::AddEgress(r) => &r.name,
            Self::RemoveIngress(name) | Self::RemoveEgress(name) => name,
        }
    }
}

/// Rule persistence backend. Abstracted as a trait so tests can inject a
/// failing implementation (to verify rollback paths).
///
/// Uses `BoxFuture` rather than `async fn` to stay object-safe
/// (`Arc<dyn RulePersister>`).
pub trait RulePersister: Send + Sync + 'static {
    /// Apply one edit. Implementations must serialize; on failure no partial
    /// write may be left behind.
    fn persist(&self, edit: RuleEdit) -> BoxFuture<'static, Result<()>>;
}

/// File backend: `toml_edit` round-trip + atomic replacement.
pub struct FileRulePersister {
    path: PathBuf,
    /// Serializes read-modify-write: the ingress / egress handlers may write
    /// the same file concurrently.
    write_lock: Arc<Mutex<()>>,
}

impl FileRulePersister {
    /// Construct with the given agent config file path.
    pub fn new(path: impl AsRef<Path>) -> Self {
        Self {
            path: path.as_ref().to_path_buf(),
            write_lock: Arc::new(Mutex::new(())),
        }
    }
}

impl RulePersister for FileRulePersister {
    fn persist(&self, edit: RuleEdit) -> BoxFuture<'static, Result<()>> {
        let path = self.path.clone();
        let lock = self.write_lock.clone();
        Box::pin(async move {
            let _guard = lock.lock().await;
            tokio::task::spawn_blocking(move || apply_edit(&path, &edit))
                .await
                .map_err(InterflowError::JoinError)?
        })
    }
}

/// Execute one read-modify-write synchronously (runs inside `spawn_blocking`).
fn apply_edit(path: &Path, edit: &RuleEdit) -> Result<()> {
    let original = std::fs::read_to_string(path)?;
    let mut doc: toml_edit::DocumentMut = original
        .parse()
        .map_err(|e| InterflowError::config(format!("config file parse failed: {e}")))?;

    let section = edit.section();
    match edit {
        RuleEdit::AddIngress(rule) => {
            let name = rule.name.clone();
            upsert_entry(&mut doc, section, &name, &rule_as_table(rule)?)
        }
        RuleEdit::AddEgress(rule) => {
            let name = rule.name.clone();
            upsert_entry(&mut doc, section, &name, &rule_as_table(rule)?)
        }
        RuleEdit::RemoveIngress(_) | RuleEdit::RemoveEgress(_) => {
            remove_entry(&mut doc, section, edit.rule_name())
        }
    }?;

    atomic_write(path, &doc.to_string())
}

/// Serialize a rule into a `toml_edit` table (field order = struct declaration
/// order).
fn rule_as_table<T: Serialize>(rule: &T) -> Result<toml_edit::Table> {
    let doc = toml_edit::ser::to_document(rule)
        .map_err(|e| InterflowError::config(format!("rule serialization failed: {e}")))?;
    let mut table = toml_edit::Table::new();
    for (key, item) in doc.iter() {
        table.insert(key, item.clone());
    }
    Ok(table)
}

/// Get (creating if necessary) the `[[section]]` array-of-tables; the inline
/// array form (`section = [...]`) cannot round-trip losslessly, so error out
/// explicitly and guide a rewrite into the array-of-tables form.
fn array_of_tables_mut<'a>(
    doc: &'a mut toml_edit::DocumentMut,
    section: &str,
) -> Result<&'a mut toml_edit::ArrayOfTables> {
    use toml_edit::Item;
    if !doc.contains_key(section) {
        doc[section] = Item::ArrayOfTables(toml_edit::ArrayOfTables::new());
    }
    doc[section].as_array_of_tables_mut().ok_or_else(|| {
        InterflowError::config(format!(
            "config section `{section}` is an inline array rather than a `[[{section}]]` array-of-tables, \
             cannot write back while preserving comments; please rewrite the section as `[[{section}]]`"
        ))
    })
}

/// Locate an entry's index by name.
fn find_entry(aot: &toml_edit::ArrayOfTables, name: &str) -> Option<usize> {
    aot.iter().position(|t| {
        t.get("name")
            .and_then(toml_edit::Item::as_str)
            .is_some_and(|n| n == name)
    })
}

/// Replace-by-name + append.
fn upsert_entry(
    doc: &mut toml_edit::DocumentMut,
    section: &str,
    name: &str,
    entry: &toml_edit::Table,
) -> Result<()> {
    let aot = array_of_tables_mut(doc, section)?;
    if let Some(idx) = find_entry(aot, name) {
        aot.remove(idx);
    }
    aot.push(entry.clone());
    Ok(())
}

/// Remove by name; idempotent success when absent from the file (memory is
/// the strict criterion, see the module docs).
fn remove_entry(doc: &mut toml_edit::DocumentMut, section: &str, name: &str) -> Result<()> {
    let aot = array_of_tables_mut(doc, section)?;
    if let Some(idx) = find_entry(aot, name) {
        aot.remove(idx);
    }
    Ok(())
}

/// Atomic write: temp file in the same directory -> preserve original
/// permission bits -> `sync_all` -> `rename` replacement.
fn atomic_write(path: &Path, content: &str) -> Result<()> {
    let dir = path.parent().unwrap_or_else(|| Path::new("."));
    let file_name = path.file_name().map_or_else(
        || "agent.toml".to_string(),
        |n| n.to_string_lossy().into_owned(),
    );
    let tmp = dir.join(format!(".{file_name}.tmp-{}", std::process::id()));

    let write_result = (|| -> Result<()> {
        let mut file = std::fs::File::create(&tmp)?;
        // Preserve the original file's permission bits: a 0600 config must
        // not be widened to 0644 by the default umask
        if let Ok(meta) = std::fs::metadata(path) {
            std::fs::set_permissions(&tmp, meta.permissions())?;
        }
        std::io::Write::write_all(&mut file, content.as_bytes())?;
        file.sync_all()?;
        Ok(())
    })();

    if let Err(e) = write_result {
        // Failure cleanup: best-effort removal of the partial temp file; the
        // original file is untouched
        let _ = std::fs::remove_file(&tmp);
        return Err(e);
    }

    std::fs::rename(&tmp, path)?;

    // Unix: best-effort directory fsync so the rename itself hits disk
    // (best-effort; failures are ignored)
    #[cfg(unix)]
    if let Ok(dir_file) = std::fs::File::open(dir) {
        let _ = dir_file.sync_all();
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

    /// Temp directory helper (the repo does not depend on tempfile, so tests
    /// build their own; cleaned up on Drop).
    struct TempDir(PathBuf);
    impl TempDir {
        fn new(tag: &str) -> Self {
            static SEQ: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
            let seq = SEQ.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            let dir = std::env::temp_dir().join(format!(
                "interflow-persist-{tag}-{}-{seq}",
                std::process::id()
            ));
            std::fs::create_dir_all(&dir).expect("mkdir");
            Self(dir)
        }
        fn path(&self, name: &str) -> PathBuf {
            self.0.join(name)
        }
    }
    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    fn ingress_rule(name: &str, port: u16) -> IngressRule {
        toml::from_str(&format!(
            r#"name = "{name}"
            listen_addr = "127.0.0.1:{port}"
            target_agent = "remote""#
        ))
        .unwrap()
    }

    fn egress_rule(name: &str, port: u16) -> EgressRule {
        toml::from_str(&format!(
            r#"name = "{name}"
            target_addr = "127.0.0.1:{port}""#
        ))
        .unwrap()
    }

    /// Fixture with comments, multiple sections, two ingress rules / one
    /// egress rule.
    fn fixture() -> &'static str {
        r#"# header comment: agent config
config_version = 2

[agent]
id = "a1"          # trailing comment
hub_url = "https://hub:6666"

# ---- ingress rules ----
[[ingress]]
name = "ssh"
listen_addr = "0.0.0.0:2222"
target_agent = "remote"

[[ingress]]
name = "web"
listen_addr = "0.0.0.0:8080"
target_agent = "remote"

[[egress]]
name = "backend"
target_addr = "10.0.0.1:80"
"#
    }

    fn parse_ingress_names(content: &str) -> Vec<String> {
        let doc: toml_edit::DocumentMut = content.parse().unwrap();
        doc["ingress"]
            .as_array_of_tables()
            .unwrap()
            .iter()
            .map(|t| t["name"].as_str().unwrap().to_string())
            .collect()
    }

    #[tokio::test]
    async fn add_ingress_appends_and_preserves_comments() {
        let tmp = TempDir::new("add");
        let path = tmp.path("agent.toml");
        std::fs::write(&path, fixture()).unwrap();

        FileRulePersister::new(&path)
            .persist(RuleEdit::AddIngress(ingress_rule("dns", 5353)))
            .await
            .unwrap();

        let content = std::fs::read_to_string(&path).unwrap();
        assert!(content.contains("# header comment: agent config"));
        assert!(content.contains("# trailing comment"));
        assert!(content.contains("# ---- ingress rules ----"));
        assert!(content.contains("[[egress]]"));
        assert_eq!(
            parse_ingress_names(&content),
            vec!["ssh".to_string(), "web".to_string(), "dns".to_string()]
        );
        // The new entry can be parsed again (the round-trip is valid)
        let cfg: crate::config::AgentConfig = toml::from_str(&content).unwrap();
        assert_eq!(cfg.ingress.len(), 3);
        assert_eq!(cfg.ingress[2].name, "dns");
    }

    #[tokio::test]
    async fn add_same_name_replaces_entry() {
        let tmp = TempDir::new("replace");
        let path = tmp.path("agent.toml");
        std::fs::write(&path, fixture()).unwrap();

        FileRulePersister::new(&path)
            .persist(RuleEdit::AddIngress(ingress_rule("web", 9090)))
            .await
            .unwrap();

        let content = std::fs::read_to_string(&path).unwrap();
        assert_eq!(
            parse_ingress_names(&content),
            vec!["ssh".to_string(), "web".to_string()]
        );
        let cfg: crate::config::AgentConfig = toml::from_str(&content).unwrap();
        assert_eq!(cfg.ingress[1].listen_addr.port(), 9090);
    }

    #[tokio::test]
    async fn remove_entry_and_idempotent_miss() {
        let tmp = TempDir::new("remove");
        let path = tmp.path("agent.toml");
        std::fs::write(&path, fixture()).unwrap();
        let persister = FileRulePersister::new(&path);

        persister
            .persist(RuleEdit::RemoveIngress("web".into()))
            .await
            .unwrap();
        assert_eq!(
            parse_ingress_names(&std::fs::read_to_string(&path).unwrap()),
            vec!["ssh".to_string()]
        );

        // Absent from the file -> idempotent success (the strict existence
        // criterion lives in RuleStore)
        persister
            .persist(RuleEdit::RemoveEgress("nope".into()))
            .await
            .unwrap();
        let content = std::fs::read_to_string(&path).unwrap();
        assert!(content.contains("# header comment: agent config"));
    }

    #[tokio::test]
    async fn add_creates_missing_section() {
        let tmp = TempDir::new("create");
        let path = tmp.path("agent.toml");
        std::fs::write(
            &path,
            "config_version = 2\n\n[agent]\nid = \"a1\"\nhub_url = \"https://hub\"\n",
        )
        .unwrap();

        FileRulePersister::new(&path)
            .persist(RuleEdit::AddEgress(egress_rule("e1", 80)))
            .await
            .unwrap();

        let cfg: crate::config::AgentConfig =
            toml::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
        assert_eq!(cfg.egress.len(), 1);
        assert_eq!(cfg.egress[0].name, "e1");
    }

    #[tokio::test]
    async fn inline_array_section_rejected_with_clear_error() {
        let tmp = TempDir::new("inline");
        let path = tmp.path("agent.toml");
        std::fs::write(
            &path,
            "config_version = 2\ningress = []\n[agent]\nid = \"a\"\nhub_url = \"https://h\"\n",
        )
        .unwrap();

        let err = FileRulePersister::new(&path)
            .persist(RuleEdit::AddIngress(ingress_rule("x", 1)))
            .await
            .unwrap_err();
        assert!(err.to_string().contains("[[ingress]]"));
    }

    #[tokio::test]
    async fn readonly_dir_leaves_original_intact() {
        let tmp = TempDir::new("readonly");
        let path = tmp.path("agent.toml");
        std::fs::write(&path, fixture()).unwrap();
        let before = std::fs::read_to_string(&path).unwrap();

        // On Unix a read-only file does not block rename (a writable
        // directory suffices to replace the file);
        // the real write-failure surface is a read-only directory
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&tmp.0, std::fs::Permissions::from_mode(0o555)).unwrap();
        }
        #[cfg(not(unix))]
        {
            let mut p = std::fs::metadata(&tmp.0).unwrap().permissions();
            p.set_readonly(true);
            std::fs::set_permissions(&tmp.0, p).unwrap();
        }

        let result = FileRulePersister::new(&path)
            .persist(RuleEdit::AddIngress(ingress_rule("y", 2)))
            .await;
        assert!(
            result.is_err(),
            "write to a read-only directory should fail"
        );

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&tmp.0, std::fs::Permissions::from_mode(0o755)).unwrap();
        }
        #[cfg(not(unix))]
        {
            let mut p = std::fs::metadata(&tmp.0).unwrap().permissions();
            p.set_readonly(false);
            std::fs::set_permissions(&tmp.0, p).unwrap();
        }
        assert_eq!(std::fs::read_to_string(&path).unwrap(), before);
        // No temp-file leftovers
        let leftovers: Vec<_> = std::fs::read_dir(&tmp.0)
            .unwrap()
            .filter_map(std::result::Result::ok)
            .filter(|e| e.file_name().to_string_lossy().contains(".tmp-"))
            .collect();
        assert!(
            leftovers.is_empty(),
            "the failure path should clean up temp files"
        );
    }

    #[tokio::test]
    async fn missing_file_errors() {
        let tmp = TempDir::new("missing");
        let path = tmp.path("nonexistent.toml");
        assert!(
            FileRulePersister::new(&path)
                .persist(RuleEdit::AddIngress(ingress_rule("x", 1)))
                .await
                .is_err()
        );
    }

    #[test]
    fn atomic_write_preserves_permissions() {
        let tmp = TempDir::new("perm");
        let path = tmp.path("agent.toml");
        std::fs::write(&path, fixture()).unwrap();

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
            atomic_write(&path, fixture()).unwrap();
            let mode = std::fs::metadata(&path).unwrap().permissions().mode();
            assert_eq!(
                mode & 0o777,
                0o600,
                "atomic write must not widen or tighten the original permission bits"
            );
        }
        #[cfg(not(unix))]
        {
            atomic_write(&path, fixture()).unwrap();
        }
    }
}
