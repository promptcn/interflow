//! Issuer-store backup: every store change becomes a versioned, encrypted
//! checkpoint — the loss branch of
//! `(internal design notes)`.
//!
//! Design (why not a manual `export` command):
//!
//! - **Change-triggered.** A manual export only happens when someone
//!   remembers to run it — the audit's finding in another shape. Every
//!   [`crate::issuance::IssuerStore`] mutation (CA creation, binding,
//!   revocations, applied state) checkpoints automatically.
//! - **Versioned.** A single overwritten backup captures garbage when it
//!   runs after the store is already corrupt. Versioned files (hash in the
//!   name, retention-pruned) always reach back past a corruption point.
//! - **Offline-recipient encryption.** Backups encrypt to an age X25519
//!   recipient; the matching identity is generated once, shown once, and
//!   never stored on this machine. Automation needs no secret on disk — a
//!   compromised operator machine cannot read its own backups.
//!
//! The one thing the operator must do is store that offline identity
//! (password manager / printed). `doctor issuer` and the restore drill in
//! the tests keep that honest.

use crate::{Error, Result};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use time::OffsetDateTime;

/// The store's backup configuration file (public data — recipient key +
/// layout, no secret).
const BACKUP_FILE: &str = "backup.json";
/// Default number of versioned checkpoints kept.
pub const DEFAULT_RETENTION: u32 = 20;
/// Backup file name prefix; versions sort lexicographically because the
/// embedded timestamp is fixed-width.
const NAME_PREFIX: &str = "issuer-";
/// backup.json format versions — a **local migration counter**, not a
/// format epoch (documentation/versioning.md#local-migration-counters): the
/// file lives on one operator machine, this binary is its only writer, and
/// v1 bytes on operators' disks must keep loading, so reads normalize old
/// shapes in memory instead of failing closed. The guard registers this
/// counter by name in its `LOCAL_MIGRATION_COUNTERS` list; this anchor
/// citation is the declaration's other half.
///
/// v1 (no `version` field on disk) is the original shape: `backup_dir`
/// stored exactly as the configure-time caller passed it — CWD-relative
/// when the operator ran from the deployment tree, so every later read
/// silently depended on process CWD. v2 pins the invariant: `backup_dir`
/// is absolute (canonicalized at configure time). See
/// (internal design notes).
const CONFIG_VERSION_LEGACY: u32 = 1;
const CONFIG_VERSION: u32 = 2;

fn legacy_config_version() -> u32 {
    CONFIG_VERSION_LEGACY
}

// ---------------------------------------------------------------------------
// Identity (offline) and configuration
// ---------------------------------------------------------------------------

/// A freshly generated age X25519 keypair. The secret is shown to the
/// operator exactly once and never persisted by this code; the recipient
/// (public) stays in [`BackupConfig`].
pub struct GeneratedIdentity {
    /// `AGE-SECRET-KEY-1...` — the operator's offline recovery key.
    pub secret: String,
    /// `age1...` — what backups encrypt to.
    pub recipient: String,
}

/// Generates a new offline identity pair.
pub fn generate_identity() -> Result<GeneratedIdentity> {
    use age::secrecy::ExposeSecret as _;
    let identity = age::x25519::Identity::generate();
    Ok(GeneratedIdentity {
        secret: identity.to_string().expose_secret().to_owned(),
        recipient: identity.to_public().to_string(),
    })
}

fn parse_recipient(recipient: &str) -> Result<age::x25519::Recipient> {
    use std::str::FromStr as _;
    age::x25519::Recipient::from_str(recipient.trim()).map_err(|e| {
        Error::issuance("backup recipient is not a valid age1... key".to_owned()).with_source(e)
    })
}

fn parse_identity(identity: &str) -> Result<age::x25519::Identity> {
    use std::str::FromStr as _;
    age::x25519::Identity::from_str(identity.trim()).map_err(|e| {
        Error::issuance("recovery identity is not a valid AGE-SECRET-KEY-1... value".to_owned())
            .with_source(e)
    })
}

/// The public recipient half of an offline recovery identity. Restore prints
/// it so the operator can re-arm backups with `backup init --recipient` and
/// keep using the one identity they already stored — the recipient is public
/// data (it lives in every `backup.json`), so printing it leaks nothing.
pub fn recipient_of(identity_secret: &str) -> Result<String> {
    Ok(parse_identity(identity_secret)?.to_public().to_string())
}

/// The persisted backup configuration (`<store>/backup.json`).
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct BackupConfig {
    /// Format version; absent in old files means v1 (see
    /// [`CONFIG_VERSION_LEGACY`]). Reads normalize v1 shapes in memory and
    /// stamp v2 on the next write.
    #[serde(default = "legacy_config_version")]
    pub version: u32,
    /// age X25519 recipient (`age1...`) backups encrypt to.
    pub recipient: String,
    /// Directory the versioned `issuer-*.age` checkpoints land in. Point it
    /// at a second medium (mounted disk, synced share) — same-disk defaults
    /// still lose both to one disk failure, and `doctor issuer` flags that.
    pub backup_dir: PathBuf,
    /// How many versions to keep.
    pub retention: u32,
    /// RFC 3339 timestamp of the (re)configuration — context for humans.
    pub initialized_at: String,
}

/// Reads the store's backup configuration, normalized: v1 shapes are
/// resolved in memory (see [`load_config`]), so every consumer is
/// CWD-independent. `Ok(None)` = not configured (checkpoints are no-ops); a
/// malformed file is an error, never a silent backup disable.
pub fn config(store_root: &Path) -> Result<Option<BackupConfig>> {
    Ok(load_config(store_root)?.map(|(cfg, _)| cfg))
}

/// [`config`] plus the "on-disk file differs from the normalized shape"
/// flag. The writing paths ([`checkpoint`], [`rekey`]) use it to persist
/// the normalization; readers never write.
///
/// The one v1 quirk worth an invariant: a v1 relative `backup_dir` is
/// anchored to the store root's PARENT — the sibling layout of
/// [`default_backup_dir`], which is the only shape that ever produced a
/// relative value (`plan apply` / default `init` run from the deployment
/// tree, where store and backups sit as siblings). That frozen v1 meaning
/// is applied here so reads never depend on process CWD; the bytes on disk
/// stay untouched, so the currency hash cannot drift from the newest
/// version just because someone ran `status` from `~`.
fn load_config(store_root: &Path) -> Result<Option<(BackupConfig, bool)>> {
    let path = store_root.join(BACKUP_FILE);
    let text = match std::fs::read_to_string(&path) {
        Ok(text) => text,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => {
            return Err(Error::Io {
                path: path.display().to_string(),
                source: e,
            });
        }
    };
    let mut cfg: BackupConfig = serde_json::from_str(&text).map_err(|e| {
        Error::issuance(format!(
            "issuer store has a malformed {BACKUP_FILE} — backups are NOT running; fix \
                 or remove the file and re-run `interflow-cli issuer backup init`"
        ))
        .with_source(e)
    })?;
    let mut migrated = false;
    if cfg.version < CONFIG_VERSION {
        if cfg.backup_dir.is_relative() {
            let anchor = store_root
                .canonicalize()
                .unwrap_or_else(|_| store_root.to_owned());
            let Some(parent) = anchor.parent() else {
                return Err(Error::issuance(format!(
                    "backup_dir \"{}\" is relative and the store root {} has no parent to anchor \
                     it against — fix the file and re-run `interflow-cli issuer backup init`",
                    cfg.backup_dir.display(),
                    store_root.display()
                )));
            };
            cfg.backup_dir = parent.join(&cfg.backup_dir);
        }
        cfg.version = CONFIG_VERSION;
        migrated = true;
    } else if cfg.backup_dir.is_relative() {
        // The v2 invariant is broken — a hand-edit, not a legacy shape.
        // Fail closed rather than guess an anchor for a file that promised
        // not to need one.
        return Err(Error::issuance(format!(
            "{} declares format version {} but stores a relative backup_dir \"{}\" — the on-disk \
             value must be absolute; fix the file and re-run `interflow-cli issuer backup init`",
            path.display(),
            cfg.version,
            cfg.backup_dir.display()
        )));
    }
    Ok(Some((cfg, migrated)))
}

/// Default backup directory: a sibling of the store root
/// (`<store>-backups`), so the two never nest.
#[must_use]
pub fn default_backup_dir(store_root: &Path) -> PathBuf {
    let name = store_root
        .file_name()
        .map_or_else(|| "issuer".to_owned(), |n| n.to_string_lossy().into_owned());
    store_root.with_file_name(format!("{name}-backups"))
}

/// Canonicalizes `path`, or — when it does not exist yet — canonicalizes
/// its deepest existing ancestor and re-appends the missing tail. Without
/// this, a symlinked temp root (macOS `/var` → `/private/var`) splits one
/// tree across two spellings and the nesting check below compares
/// `/private/var/.../store` against `/var/.../store/inside` — a mismatch
/// that lets a nested dir slip through.
fn anchored(path: &Path) -> PathBuf {
    if let Ok(canonical) = path.canonicalize() {
        return canonical;
    }
    for ancestor in path.ancestors().skip(1) {
        if let Ok(canonical) = ancestor.canonicalize() {
            let tail = path.strip_prefix(ancestor).unwrap_or(path);
            return canonical.join(tail);
        }
    }
    path.to_owned()
}

/// Validates and anchors a backup directory target for writing: refuses
/// nesting inside the store, creates the directory so writability fails
/// here (not at the first checkpoint), and returns the canonical absolute
/// path the v2 config stores.
fn resolve_backup_dir(store_root: &Path, backup_dir: &Path) -> Result<PathBuf> {
    // A backup dir inside the store would tuck the copies into the thing
    // they protect (and recurse into the tar).
    let root_canon = anchored(store_root);
    let backup_canon = anchored(backup_dir);
    if backup_canon.starts_with(&root_canon) {
        return Err(Error::issuance(format!(
            "backup directory {} must live OUTSIDE the issuer store {} — otherwise one disk \
             loss takes both",
            backup_dir.display(),
            store_root.display()
        )));
    }
    std::fs::create_dir_all(backup_dir).map_err(|e| Error::Io {
        path: backup_dir.display().to_string(),
        source: e,
    })?;
    // The dir exists now, so this canonicalize succeeds where the nesting
    // pre-check above could only fall back to raw text. Stored absolute on
    // purpose: a relative backup_dir is a CWD-dependent config, and CWD is
    // process state, not store state — it must not survive the invocation
    // that created it.
    Ok(match backup_dir.canonicalize() {
        Ok(canonical) => canonical,
        Err(_) => std::env::current_dir()
            .map(|cwd| cwd.join(backup_dir))
            .unwrap_or_else(|_| backup_dir.to_owned()),
    })
}

/// Writes the backup configuration (one-time; refuses to overwrite —
/// changing the key is [`rekey`], moving the directory is [`relocate`]).
/// Creates the backup directory so writability fails here, not at the first
/// checkpoint.
pub fn configure(
    store_root: &Path,
    recipient: &str,
    backup_dir: &Path,
    retention: u32,
) -> Result<BackupConfig> {
    if config(store_root)?.is_some() {
        return Err(Error::issuance(format!(
            "{} already configures backups — use `interflow-cli issuer backup rekey` to change \
             the key (old backups stay readable by the old identity), or `interflow-cli issuer \
             backup relocate --backup-dir <dir>` to move the target directory",
            store_root.join(BACKUP_FILE).display()
        )));
    }
    parse_recipient(recipient)?;
    if retention == 0 {
        return Err(Error::issuance(
            "backup retention must keep at least one version".to_owned(),
        ));
    }
    let stored_dir = resolve_backup_dir(store_root, backup_dir)?;
    let initialized_at = rfc3339_now()?;
    let cfg = BackupConfig {
        version: CONFIG_VERSION,
        recipient: recipient.trim().to_owned(),
        backup_dir: stored_dir,
        retention,
        initialized_at,
    };
    write_config(store_root, &cfg)?;
    Ok(cfg)
}

/// Replaces the encryption recipient, keeping directory and retention.
/// Existing backups remain readable only by the OLD identity — checkpoint
/// immediately after rekeying so the newest version follows the new key.
pub fn rekey(store_root: &Path, new_recipient: &str) -> Result<BackupConfig> {
    let Some(mut cfg) = config(store_root)? else {
        return Err(Error::issuance(
            "issuer store has no backup configuration — run `interflow-cli issuer backup init` \
             first"
                .to_owned(),
        ));
    };
    parse_recipient(new_recipient)?;
    cfg.recipient = new_recipient.trim().to_owned();
    cfg.initialized_at = rfc3339_now()?;
    write_config(store_root, &cfg)?;
    Ok(cfg)
}

/// Moves the backup target directory, keeping recipient and retention.
/// Prior versions stay in the old directory — readable by the same recovery
/// identity, untouched by the new directory's retention — while new
/// checkpoints land in the new one. This is the sanctioned way to point
/// backups at a second medium (the doctor hint's destination).
pub fn relocate(store_root: &Path, backup_dir: &Path) -> Result<BackupConfig> {
    let Some(mut cfg) = config(store_root)? else {
        return Err(Error::issuance(
            "issuer store has no backup configuration — run `interflow-cli issuer backup init` \
             first"
                .to_owned(),
        ));
    };
    cfg.backup_dir = resolve_backup_dir(store_root, backup_dir)?;
    write_config(store_root, &cfg)?;
    Ok(cfg)
}

fn write_config(store_root: &Path, cfg: &BackupConfig) -> Result<()> {
    std::fs::create_dir_all(store_root).map_err(|e| Error::Io {
        path: store_root.display().to_string(),
        source: e,
    })?;
    let text = serde_json::to_string_pretty(cfg)
        .map_err(|e| Error::serialize("backup config".to_owned()).with_source(e))?;
    // Public data (recipient key + layout): 0644.
    interflow_util::atomic_write(
        &store_root.join(BACKUP_FILE),
        text.as_bytes(),
        interflow_util::WriteMode::PreserveOr(0o644),
    )
    .map_err(|e| Error::Io {
        path: store_root.join(BACKUP_FILE).display().to_string(),
        source: e,
    })
}

fn rfc3339_now() -> Result<String> {
    OffsetDateTime::now_utc()
        .format(&time::format_description::well_known::Rfc3339)
        .map_err(|e| Error::issuance("backup timestamp".to_owned()).with_source(e))
}

// ---------------------------------------------------------------------------
// Checkpoint (change-triggered, versioned, deduplicated)
// ---------------------------------------------------------------------------

/// The outcome of one checkpoint attempt.
#[derive(Debug, PartialEq, Eq)]
pub enum Checkpoint {
    /// No `backup.json` under the store — checkpoint is a no-op. Configured
    /// by `plan apply` / `issuer backup init`; surfaced by `doctor issuer`.
    Unconfigured,
    /// The newest version already carries this exact content.
    Unchanged,
    /// A new version was written.
    Written { path: PathBuf },
}

/// Writes a new encrypted, versioned checkpoint of the store, or reports
/// that nothing changed. The tar is deterministic (sorted entries, mtimes
/// zeroed), so the content hash — and with it the version name — is a pure
/// function of file contents and modes.
pub fn checkpoint(store_root: &Path) -> Result<Checkpoint> {
    let Some((cfg, migrated)) = load_config(store_root)? else {
        return Ok(Checkpoint::Unconfigured);
    };
    // The bookkeeping db lives under the store root and rides along in the
    // tar — flush its WAL first so the plain file copy carries every
    // committed row (the sidecar files themselves are skipped below).
    crate::state_db::wal_checkpoint(store_root)?;
    if migrated {
        // Persist the normalized config BEFORE hashing: the migration is a
        // store change like any other, and the version this checkpoint
        // writes must cover it — never a side-channel edit that silently
        // stales the newest backup against the store it just recorded.
        write_config(store_root, &cfg)?;
    }
    let files = collect_files(store_root, &cfg.backup_dir)?;
    let tar_bytes = build_tar(&files)?;
    let hash8 = interflow_util::sha256_hex(&tar_bytes)[..8].to_owned();
    if newest_version(&cfg.backup_dir)?.is_some_and(|newest| newest.hash8 == hash8) {
        return Ok(Checkpoint::Unchanged);
    }
    let timestamp = timestamp_compact(OffsetDateTime::now_utc());
    let path = cfg
        .backup_dir
        .join(format!("{NAME_PREFIX}{timestamp}-{hash8}.age"));
    let recipient = parse_recipient(&cfg.recipient)?;
    let ciphertext = encrypt_to(&recipient, &tar_bytes)?;
    interflow_util::atomic_write(&path, &ciphertext, interflow_util::WriteMode::Set(0o600))
        .map_err(|e| {
            Error::issuance(format!(
                "issuer store backup failed — the store itself is intact at {}; fix the backup \
                 target and re-run: the next run retries the backup",
                store_root.display()
            ))
            .with_source(e)
        })?;
    prune(&cfg.backup_dir, cfg.retention);
    Ok(Checkpoint::Written { path })
}

/// The version-name timestamp format. Compile-time on purpose (the `time`
/// `macros` feature): the writer ([`timestamp_compact`]) and the reader
/// ([`parse_name_timestamp`]) share one description and cannot drift, so
/// every name this tool emits parses back.
const COMPACT_TIMESTAMP: &[time::format_description::BorrowedFormatItem] =
    time::macros::format_description!("[year][month][day]T[hour][minute][second]Z");

/// `20261009T153000Z` — fixed width and human-readable in listings. The
/// description is compile-time, so formatting an in-range datetime cannot
/// fail; the unix-seconds fallback only guarantees a checkpoint never
/// aborts for want of a name. Ordering DOES depend on the name:
/// [`parse_name_timestamp`] accepts both emitted shapes, so every name
/// written here stays orderable.
fn timestamp_compact(now: OffsetDateTime) -> String {
    match now.format(&COMPACT_TIMESTAMP) {
        Ok(stamp) => stamp,
        Err(_) => now.unix_timestamp().to_string(),
    }
}

/// `issuer-<timestamp>-<hash8>.age` → the `<timestamp>` as an instant.
/// Accepts both shapes [`timestamp_compact`] can emit (the fixed-width
/// compact form and its unix-seconds fallback), so any name this tool
/// wrote is orderable. `None` means a foreign file, not a version.
///
/// The compact form carries no `[offset]` component — the trailing `Z` is
/// a literal — so it parses as a `PrimitiveDateTime` that is then pinned
/// to UTC (the names are minted from `now_utc`).
fn parse_name_timestamp(stem: &str) -> Option<OffsetDateTime> {
    let middle = stem.strip_prefix(NAME_PREFIX)?.rsplit_once('-')?.0;
    if let Ok(stamp) = time::PrimitiveDateTime::parse(middle, &COMPACT_TIMESTAMP) {
        return Some(stamp.assume_utc());
    }
    middle
        .parse::<i64>()
        .ok()
        .and_then(|secs| OffsetDateTime::from_unix_timestamp(secs).ok())
}

struct Version {
    path: PathBuf,
    hash8: String,
    /// The instant parsed from the file name's embedded timestamp — the
    /// ordering key. Unlike mtime it travels with the file through copies,
    /// syncs and unpacks (the recovery scenario this subsystem exists
    /// for); unlike the hash it is an ordering, not content.
    timestamp: OffsetDateTime,
    /// Last-write time — tiebreak ONLY, ordering two checkpoints written
    /// inside the same second (the name's second-resolution timestamp
    /// cannot; the hash in the name is content, not an ordering).
    modified: std::time::SystemTime,
}

/// All versions, oldest first, ordered by (name timestamp, mtime, name).
/// The file name's timestamp is the primary key: mtime is file-system
/// state that any copy/sync/unpack resets (a `cp -r` of the backup dir
/// collapses every mtime onto one instant and made "newest" a coin toss —
/// (internal design notes)), while the name
/// is part of the artifact. mtime only breaks same-second ties, which is
/// the one thing the name cannot express.
fn list_versions(backup_dir: &Path) -> Result<Vec<Version>> {
    let entries = match std::fs::read_dir(backup_dir) {
        Ok(entries) => entries,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(e) => {
            return Err(Error::Io {
                path: backup_dir.display().to_string(),
                source: e,
            });
        }
    };
    let mut versions = Vec::new();
    for entry in entries {
        let entry = entry.map_err(|e| Error::Io {
            path: backup_dir.display().to_string(),
            source: e,
        })?;
        let Some(name) = entry.file_name().to_str().map(str::to_owned) else {
            continue;
        };
        if !(name.starts_with(NAME_PREFIX) && name.ends_with(".age")) {
            continue;
        }
        let stem = name.trim_end_matches(".age");
        let Some(timestamp) = parse_name_timestamp(stem) else {
            tracing::warn!("skipping foreign file in backup dir: {name}");
            continue;
        };
        let meta = entry.metadata().map_err(|e| Error::Io {
            path: entry.path().display().to_string(),
            source: e,
        })?;
        // issuer-<timestamp>-<hash8>.age → hash8 is the last dash group.
        let hash8 = stem.rsplit('-').next().unwrap_or_default().to_owned();
        versions.push(Version {
            path: entry.path(),
            hash8,
            timestamp,
            modified: meta.modified().unwrap_or(std::time::SystemTime::UNIX_EPOCH),
        });
    }
    versions.sort_by(|a, b| {
        a.timestamp
            .cmp(&b.timestamp)
            .then_with(|| a.modified.cmp(&b.modified))
            .then_with(|| a.path.cmp(&b.path))
    });
    Ok(versions)
}

/// The newest `issuer-*.age` version.
/// Number of versioned checkpoints currently in `backup_dir` (0 when the
/// directory is absent) — CLI narration for [`relocate`].
pub fn version_count(backup_dir: &Path) -> usize {
    list_versions(backup_dir).map_or(0, |versions| versions.len())
}

fn newest_version(backup_dir: &Path) -> Result<Option<Version>> {
    Ok(list_versions(backup_dir)?.pop())
}

/// Drops the oldest versions beyond `retention`. Best-effort: a failed
/// unlink logs and leaves the extra version in place.
fn prune(backup_dir: &Path, retention: u32) {
    let Ok(versions) = list_versions(backup_dir) else {
        return;
    };
    let keep = usize::try_from(retention).unwrap_or(0);
    if versions.len() > keep {
        for old in &versions[..versions.len() - keep] {
            if let Err(e) = std::fs::remove_file(&old.path) {
                tracing::warn!(
                    "backup retention prune failed for {}: {e}",
                    old.path.display()
                );
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Deterministic tar of the store
// ---------------------------------------------------------------------------

struct FileEntry {
    rel: String,
    bytes: Vec<u8>,
    mode: u32,
}

/// Collects every regular file under `root`, sorted by relative path. The
/// issuer store is regular files only; a symlink or anything else in there
/// is unexpected and fails the checkpoint rather than silently diverging
/// from what restore would write. The bookkeeping db's WAL sidecars
/// (`store.db-wal` / `store.db-shm`) are skipped: transient by design, and
/// the db is flushed whole by [`crate::state_db::wal_checkpoint`] before
/// the walk.
fn collect_files(root: &Path, skip_dir: &Path) -> Result<Vec<FileEntry>> {
    let mut files = Vec::new();
    walk(root, root, skip_dir, &mut files)?;
    files.sort_by(|a, b| a.rel.cmp(&b.rel));
    Ok(files)
}

fn walk(root: &Path, dir: &Path, skip_dir: &Path, out: &mut Vec<FileEntry>) -> Result<()> {
    let entries = match std::fs::read_dir(dir) {
        Ok(entries) => entries,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(e) => {
            return Err(Error::Io {
                path: dir.display().to_string(),
                source: e,
            });
        }
    };
    for entry in entries {
        let entry = entry.map_err(|e| Error::Io {
            path: dir.display().to_string(),
            source: e,
        })?;
        let path = entry.path();
        // Defensive: never tuck the backup directory into its own tar even
        // if a hand-edited config nests it.
        let canonical_skip = skip_dir
            .canonicalize()
            .unwrap_or_else(|_| skip_dir.to_owned());
        if path.canonicalize().is_ok_and(|p| p == canonical_skip) {
            continue;
        }
        if let Some(name) = path.file_name().and_then(|n| n.to_str())
            && matches!(name, "store.db-wal" | "store.db-shm")
        {
            continue;
        }
        let rel = path
            .strip_prefix(root)
            .map(|p| p.to_string_lossy().replace('\\', "/"))
            .map_err(|_| {
                Error::issuance(format!("store file outside store root: {}", path.display()))
            })?;
        let meta = entry.metadata().map_err(|e| Error::Io {
            path: path.display().to_string(),
            source: e,
        })?;
        if meta.is_dir() {
            walk(root, &path, skip_dir, out)?;
        } else if meta.is_file() {
            #[cfg(unix)]
            let mode = {
                use std::os::unix::fs::PermissionsExt;
                meta.permissions().mode() & 0o777
            };
            #[cfg(not(unix))]
            let mode = 0o644;
            let bytes = std::fs::read(&path).map_err(|e| Error::Io {
                path: path.display().to_string(),
                source: e,
            })?;
            out.push(FileEntry { rel, bytes, mode });
        } else {
            return Err(Error::issuance(format!(
                "unexpected non-regular file in issuer store: {rel} — the store is plain files; \
                 resolve it before backing up"
            )));
        }
    }
    Ok(())
}

/// Deterministic tar: sorted entries, mtime/uid/gid zeroed, modes kept (the
/// 0600 discipline must survive the round trip). Same content ⇒ same bytes
/// ⇒ same hash ⇒ dedup works.
fn build_tar(files: &[FileEntry]) -> Result<Vec<u8>> {
    let mut tar_bytes = Vec::new();
    {
        let mut builder = tar::Builder::new(&mut tar_bytes);
        for file in files {
            let mut header = tar::Header::new_gnu();
            header.set_size(file.bytes.len() as u64);
            header.set_mode(file.mode);
            header.set_mtime(0);
            header.set_uid(0);
            header.set_gid(0);
            header.set_entry_type(tar::EntryType::Regular);
            header.set_cksum();
            builder
                .append_data(&mut header, &file.rel, file.bytes.as_slice())
                .map_err(|e| {
                    Error::issuance(format!("backup tar entry {:?}", file.rel)).with_source(e)
                })?;
        }
        builder
            .into_inner()
            .map_err(|e| Error::issuance("backup tar finish".to_owned()).with_source(e))?;
    }
    Ok(tar_bytes)
}

fn encrypt_to(recipient: &age::x25519::Recipient, tar_bytes: &[u8]) -> Result<Vec<u8>> {
    let encryptor =
        age::Encryptor::with_recipients(std::iter::once(recipient as &dyn age::Recipient))
            .map_err(|e| Error::issuance("backup encryption".to_owned()).with_source(e))?;
    let mut out = Vec::new();
    let mut wrapper = encryptor
        .wrap_output(&mut out)
        .map_err(|e| Error::issuance("backup encryption".to_owned()).with_source(e))?;
    wrapper
        .write_all(tar_bytes)
        .map_err(|e| Error::issuance("backup write".to_owned()).with_source(e))?;
    wrapper
        .finish()
        .map_err(|e| Error::issuance("backup finish".to_owned()).with_source(e))?;
    Ok(out)
}

fn decrypt_to_tar(backup_file: &Path, identity: &str) -> Result<Vec<u8>> {
    let bytes = std::fs::read(backup_file).map_err(|e| Error::Io {
        path: backup_file.display().to_string(),
        source: e,
    })?;
    let identity = parse_identity(identity)?;
    let decryptor = age::Decryptor::new_buffered(&bytes[..])
        .map_err(|e| Error::issuance("backup archive format".to_owned()).with_source(e))?;
    let mut reader = decryptor
        .decrypt(std::iter::once(&identity as &dyn age::Identity))
        .map_err(|e| {
            Error::issuance(
                "backup decryption failed — wrong recovery identity, or the archive is \
                 corrupt/truncated",
            )
            .with_source(e)
        })?;
    let mut tar_bytes = Vec::new();
    reader
        .read_to_end(&mut tar_bytes)
        .map_err(|e| Error::issuance("backup read".to_owned()).with_source(e))?;
    Ok(tar_bytes)
}

/// Parses a tar into sanitized entries: regular files with relative,
/// traversal-free paths only. Directories become implicit (parents are
/// created on write); symlinks/hardlinks/devices are rejected outright.
fn parse_tar(tar_bytes: &[u8]) -> Result<Vec<FileEntry>> {
    let mut archive = tar::Archive::new(tar_bytes);
    let mut files = Vec::new();
    for entry in archive
        .entries()
        .map_err(|e| Error::issuance("backup archive entries".to_owned()).with_source(e))?
    {
        let mut entry =
            entry.map_err(|e| Error::issuance("backup archive entry".to_owned()).with_source(e))?;
        let rel = entry
            .path()
            .map_err(|e| Error::issuance("backup archive path".to_owned()).with_source(e))?
            .to_string_lossy()
            .replace('\\', "/");
        if Path::new(&rel).is_absolute() || rel.split('/').any(|c| c == ".." || c.is_empty()) {
            return Err(Error::issuance(format!(
                "backup archive member {rel:?} escapes the restore target — refusing"
            )));
        }
        match entry.header().entry_type() {
            tar::EntryType::Regular => {}
            tar::EntryType::Directory => continue,
            other => {
                return Err(Error::issuance(format!(
                    "backup archive member {rel:?} has type {other:?} — only plain files are \
                     restorable"
                )));
            }
        }
        let mode = entry.header().mode().unwrap_or(0o644) & 0o777;
        let mut bytes = Vec::new();
        entry.read_to_end(&mut bytes).map_err(|e| {
            Error::issuance(format!("backup archive member {rel:?}")).with_source(e)
        })?;
        files.push(FileEntry { rel, bytes, mode });
    }
    if files.is_empty() {
        return Err(Error::issuance(
            "backup archive carries no files — refusing to restore an empty store".to_owned(),
        ));
    }
    Ok(files)
}

// ---------------------------------------------------------------------------
// Verify and restore
// ---------------------------------------------------------------------------

/// One certificate found in the archive (`.crt` members may carry chains).
#[derive(Debug, Clone)]
pub struct CertSummary {
    pub path: String,
    pub subject: String,
    pub not_after: String,
}

/// What `issuer verify` reports: member inventory plus parsed certificate
/// detail — the pre-restore health check, no disk writes.
#[derive(Debug, Clone)]
pub struct VerifyReport {
    pub members: Vec<String>,
    pub certs: Vec<CertSummary>,
    pub key_files: usize,
}

/// Decrypts and fully parses a backup archive (needs the offline identity).
pub fn verify(backup_file: &Path, identity: &str) -> Result<VerifyReport> {
    let tar_bytes = decrypt_to_tar(backup_file, identity)?;
    let files = parse_tar(&tar_bytes)?;
    let mut certs = Vec::new();
    let mut key_files = 0;
    for file in &files {
        if file.rel.ends_with(".key") {
            key_files += 1;
        }
        if file.rel.ends_with(".crt") {
            for der in crate::pem_certs(&file.bytes)? {
                let (_, cert) = x509_parser::parse_x509_certificate(&der).map_err(|e| {
                    Error::issuance(format!("certificate in backup member {:?}", file.rel))
                        .with_source(e)
                })?;
                certs.push(CertSummary {
                    path: file.rel.clone(),
                    subject: cert.subject().to_string(),
                    not_after: cert.validity().not_after.to_string(),
                });
            }
        }
    }
    Ok(VerifyReport {
        members: files.into_iter().map(|f| f.rel).collect(),
        certs,
        key_files,
    })
}

/// One restored workspace issuer (validated during restore).
#[derive(Debug, Clone)]
pub struct WorkspaceSummary {
    pub name: String,
    pub fingerprint: String,
}

/// What `issuer restore` reports: the unpack plus immediate validation —
/// realm CA, policy key, every workspace CA load, and the deny list size.
#[derive(Debug, Clone)]
pub struct RestoreReport {
    pub root: PathBuf,
    pub realm_fingerprint: String,
    pub policy_key: bool,
    pub workspaces: Vec<WorkspaceSummary>,
    pub revocations: usize,
}

/// Restores a backup into a fresh directory and validates it end to end.
/// Refuses a non-empty target so a live store is never overwritten.
pub fn restore(backup_file: &Path, identity: &str, to_dir: &Path) -> Result<RestoreReport> {
    if to_dir.exists() {
        let empty = std::fs::read_dir(to_dir)
            .map(|mut d| d.next().is_none())
            .unwrap_or(false);
        if !empty {
            return Err(Error::issuance(format!(
                "restore target {} is not empty — move it aside first (a live issuer store is \
                 never overwritten)",
                to_dir.display()
            )));
        }
    }
    let tar_bytes = decrypt_to_tar(backup_file, identity)?;
    let files = parse_tar(&tar_bytes)?;
    std::fs::create_dir_all(to_dir).map_err(|e| Error::Io {
        path: to_dir.display().to_string(),
        source: e,
    })?;
    for file in &files {
        // The backup configuration is machine-local state: its backup_dir is
        // an absolute path from the machine that wrote it, so carrying it
        // over would point this machine's checkpoints at a directory that
        // has nothing to do with it (or silently create it when restore
        // validation triggers a checkpoint). The restored store is
        // "unconfigured" by design — the same shape as a freshly created
        // one; `issuer backup init` re-arms backups for THIS machine.
        if file.rel == BACKUP_FILE {
            continue;
        }
        let path = to_dir.join(&file.rel);
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).map_err(|e| Error::Io {
                path: parent.display().to_string(),
                source: e,
            })?;
        }
        std::fs::write(&path, &file.bytes).map_err(|e| Error::Io {
            path: path.display().to_string(),
            source: e,
        })?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(file.mode)).map_err(
                |e| Error::Io {
                    path: path.display().to_string(),
                    source: e,
                },
            )?;
        }
    }
    validate_restored(to_dir)
}

/// Loads every identity object of the unpacked store — the restore is only
/// done when the whole PKI face actually reads back.
fn validate_restored(root: &Path) -> Result<RestoreReport> {
    let store = crate::issuance::IssuerStore::open(root);
    store.ensure_realm()?;
    let realm_fingerprint = store.realm_issuer()?.fingerprint()?;
    let policy_key = store.ensure_policy_key().is_ok();
    let mut workspaces = Vec::new();
    for name in store.workspace_names()? {
        store.ensure_workspace(&name)?;
        let fingerprint = store.workspace_issuer(&name)?.fingerprint()?;
        workspaces.push(WorkspaceSummary { name, fingerprint });
    }
    let revocations = crate::revocation::RevocationList::load(root)?.entries.len();
    Ok(RestoreReport {
        root: root.to_owned(),
        realm_fingerprint,
        policy_key,
        workspaces,
        revocations,
    })
}

// ---------------------------------------------------------------------------
// Status (doctor / `issuer backup status`)
// ---------------------------------------------------------------------------

/// Backup health facts for one store.
#[derive(Debug, Clone)]
pub struct BackupStatus {
    pub config: Option<BackupConfig>,
    /// Versioned checkpoints present (paths, oldest-first).
    pub versions: Vec<PathBuf>,
    /// Content hash of the store as it stands now (configured stores only).
    pub current_hash8: Option<String>,
    /// The newest version already matches the current store content.
    pub newest_is_current: bool,
    /// `Some(true)` when backup dir and store share one filesystem (unix).
    pub same_device: Option<bool>,
}

/// Computes backup health: configuration, version inventory, and whether
/// the newest checkpoint matches the store's current content (with dedup,
/// a mismatch means a mutation happened without a successful checkpoint).
pub fn status(store_root: &Path) -> Result<BackupStatus> {
    let cfg = config(store_root)?;
    let Some(cfg) = cfg else {
        return Ok(BackupStatus {
            config: None,
            versions: Vec::new(),
            current_hash8: None,
            newest_is_current: false,
            same_device: None,
        });
    };
    let versions: Vec<PathBuf> = list_versions(&cfg.backup_dir)?
        .into_iter()
        .map(|v| v.path)
        .collect();
    crate::state_db::wal_checkpoint(store_root)?;
    let files = collect_files(store_root, &cfg.backup_dir)?;
    let tar_bytes = build_tar(&files)?;
    let current_hash8 = interflow_util::sha256_hex(&tar_bytes)[..8].to_owned();
    let newest_is_current =
        newest_version(&cfg.backup_dir)?.is_some_and(|newest| newest.hash8 == current_hash8);
    let same_device = same_device(store_root, &cfg.backup_dir);
    Ok(BackupStatus {
        config: Some(cfg),
        versions,
        current_hash8: Some(current_hash8),
        newest_is_current,
        same_device,
    })
}

#[cfg(unix)]
fn same_device(a: &Path, b: &Path) -> Option<bool> {
    use std::os::unix::fs::MetadataExt;
    let ma = std::fs::metadata(a).ok()?;
    let mb = std::fs::metadata(b).ok()?;
    Some(ma.dev() == mb.dev())
}

#[cfg(not(unix))]
fn same_device(_a: &Path, _b: &Path) -> Option<bool> {
    None
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use crate::issuance::IssuerStore;

    fn configured_store(tag: &str) -> (tempfile::TempDir, PathBuf, GeneratedIdentity) {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().join(tag);
        let backup_dir = dir.path().join(format!("{tag}-backups"));
        let identity = generate_identity().unwrap();
        configure(&root, &identity.recipient, &backup_dir, DEFAULT_RETENTION).unwrap();
        (dir, root, identity)
    }

    #[test]
    fn generated_identities_are_distinct_and_well_formed() {
        let a = generate_identity().unwrap();
        let b = generate_identity().unwrap();
        assert!(a.secret.starts_with("AGE-SECRET-KEY-1"));
        assert!(a.recipient.starts_with("age1"));
        assert_ne!(a.secret, b.secret);
        assert_ne!(a.recipient, b.recipient);
    }

    #[test]
    fn checkpoint_is_versioned_deduplicated_and_restorable() {
        let (_guard, root, identity) = configured_store("roundtrip");
        let store = IssuerStore::open(&root);
        store.ensure_realm().unwrap();
        store.ensure_policy_key().unwrap();
        store.ensure_workspace("atlas").unwrap();

        let status_now = status(&root).unwrap();
        assert!(
            status_now.newest_is_current,
            "ensure hooks checkpoint the store"
        );

        // Unchanged store → dedup, no new version.
        let before = status_now.versions.len();
        assert_eq!(checkpoint(&root).unwrap(), Checkpoint::Unchanged);
        assert_eq!(
            list_versions(status_now.config.as_ref().unwrap().backup_dir.as_path())
                .unwrap()
                .len(),
            before
        );

        // Mutate → a new version lands.
        store.ensure_workspace("second").unwrap();
        let after = status(&root).unwrap();
        assert!(after.versions.len() > before);

        // Restore into a fresh directory: same CA fingerprints, same deny list.
        let newest = after.versions.last().unwrap().clone();
        let to = root.parent().unwrap().join("restored");
        let report = restore(&newest, &identity.secret, &to).unwrap();
        assert_eq!(
            report.realm_fingerprint,
            store.realm_issuer().unwrap().fingerprint().unwrap()
        );
        assert_eq!(report.workspaces.len(), 2);
        assert!(report.policy_key);
        assert_eq!(report.revocations, 0);
        // 0600 discipline survives the round trip.
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(to.join("realm-issuer.key"))
                .unwrap()
                .permissions()
                .mode()
                & 0o777;
            assert_eq!(mode, 0o600);
        }
    }

    #[test]
    fn unconfigured_stores_checkpoint_as_noops() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().join("bare");
        assert_eq!(checkpoint(&root).unwrap(), Checkpoint::Unconfigured);
        assert!(status(&root).unwrap().config.is_none());
    }

    #[test]
    fn wrong_identity_and_tampered_archives_fail_closed() {
        let (_guard, root, identity) = configured_store("hostile");
        IssuerStore::open(&root).ensure_realm().unwrap();
        let newest = status(&root).unwrap().versions.last().unwrap().clone();

        let other = generate_identity().unwrap();
        assert!(
            verify(&newest, &other.secret).is_err(),
            "wrong identity must not decrypt"
        );

        let mut bytes = std::fs::read(&newest).unwrap();
        let last = bytes.len() - 1;
        bytes[last] ^= 0xff;
        let tampered = root.parent().unwrap().join("tampered.age");
        std::fs::write(&tampered, bytes).unwrap();
        assert!(
            verify(&tampered, &identity.secret).is_err(),
            "flipped ciphertext byte must fail"
        );
    }

    #[test]
    fn traversal_and_non_regular_members_are_rejected_on_restore() {
        let (_guard, root, identity) = configured_store("traversal");
        // Hand-craft a hostile archive. tar-rs itself refuses to BUILD a
        // member with `..` in its path — good, but the restore-side
        // sanitizer must not lean on that (archives can come from
        // anywhere), so the escaping name is flipped in at the byte level.
        let hostile_tar = {
            let mut bytes = Vec::new();
            let mut builder = tar::Builder::new(&mut bytes);
            let mut regular = tar::Header::new_gnu();
            regular.set_size(5);
            regular.set_mode(0o600);
            regular.set_mtime(0);
            regular.set_uid(0);
            regular.set_gid(0);
            regular.set_entry_type(tar::EntryType::Regular);
            regular.set_cksum();
            builder
                .append_data(&mut regular, "realm-issuer.crt", &b"data!"[..])
                .unwrap();
            let mut evil = tar::Header::new_gnu();
            evil.set_size(5);
            evil.set_mode(0o644);
            evil.set_mtime(0);
            evil.set_entry_type(tar::EntryType::Symlink);
            evil.set_cksum();
            builder
                .append_data(&mut evil, "escape", &b"../x!"[..])
                .unwrap();
            builder.into_inner().unwrap();
            // Retarget the first header's name to "../evil" and recompute
            // its checksum so the archive still parses.
            let mut i = 0;
            while i + 512 <= bytes.len() {
                if bytes[i..i + 16].starts_with(b"realm-issuer.crt") {
                    let block = &mut bytes[i..i + 512];
                    for b in block[..100].iter_mut() {
                        *b = 0;
                    }
                    block[..7].copy_from_slice(b"../evil");
                    for b in block[148..156].iter_mut() {
                        *b = b' ';
                    }
                    let sum: u64 = block.iter().map(|&b| u64::from(b)).sum();
                    let octal = format!("{sum:06o}\0 ");
                    block[148..156].copy_from_slice(octal.as_bytes());
                    break;
                }
                i += 512;
            }
            assert!(
                i + 512 <= bytes.len(),
                "the member header to tamper must exist"
            );
            bytes
        };
        let recipient = parse_recipient(&identity.recipient).unwrap();
        let hostile_age = {
            let mut out = Vec::new();
            let encryptor =
                age::Encryptor::with_recipients(std::iter::once(&recipient as &dyn age::Recipient))
                    .unwrap();
            let mut wrapper = encryptor.wrap_output(&mut out).unwrap();
            wrapper.write_all(&hostile_tar).unwrap();
            wrapper.finish().unwrap();
            out
        };
        let file = root.parent().unwrap().join("hostile.age");
        std::fs::write(&file, &hostile_age).unwrap();
        let to = root.parent().unwrap().join("hostile-target");
        assert!(
            restore(&file, &identity.secret, &to).is_err(),
            "hostile members must be refused"
        );
        assert!(
            !to.join("realm-issuer.crt").exists() || !to.exists(),
            "nothing may be written from a rejected archive"
        );
    }

    #[test]
    fn restore_refuses_a_non_empty_target() {
        let (_guard, root, identity) = configured_store("busy");
        IssuerStore::open(&root).ensure_realm().unwrap();
        let newest = status(&root).unwrap().versions.last().unwrap().clone();
        let to = root.parent().unwrap().join("busy-target");
        std::fs::create_dir_all(&to).unwrap();
        std::fs::write(to.join("live.key"), b"do not clobber").unwrap();
        assert!(restore(&newest, &identity.secret, &to).is_err());
    }

    #[test]
    fn retention_prunes_oldest_versions() {
        let (_guard, root, _identity) = configured_store("prune");
        let store = IssuerStore::open(&root);
        store.ensure_realm().unwrap();
        let cfg_dir = status(&root).unwrap().config.unwrap().backup_dir;
        // Mutate repeatedly: each distinct content gets its own version.
        for i in 0..5 {
            std::fs::write(
                root.join(format!("generation-{i}.txt")),
                format!("state {i}"),
            )
            .unwrap();
            store.ensure_realm().unwrap(); // triggers checkpoint on the validate path
        }
        let versions = list_versions(&cfg_dir).unwrap();
        assert!(versions.len() > 5, "each mutation writes a version");
        prune(&cfg_dir, 3);
        let after = list_versions(&cfg_dir).unwrap();
        assert_eq!(after.len(), 3);
        assert_eq!(
            after.last().unwrap().path,
            versions.last().unwrap().path,
            "newest survives"
        );
    }

    #[test]
    fn configure_rejects_nesting_and_bad_recipients() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().join("nest");
        let identity = generate_identity().unwrap();
        assert!(configure(&root, &identity.recipient, &root.join("inside"), 5).is_err());
        assert!(configure(&root, "not-a-recipient", &dir.path().join("out"), 5).is_err());
        assert!(configure(&root, &identity.recipient, &dir.path().join("out"), 0).is_err());
        // Second configure on the same store is refused (rekey is the path).
        configure(&root, &identity.recipient, &dir.path().join("out"), 5).unwrap();
        assert!(configure(&root, &identity.recipient, &dir.path().join("out2"), 5).is_err());
    }

    #[test]
    fn rekey_keeps_layout_and_retargets_encryption() {
        let (_guard, root, old_identity) = configured_store("rekey");
        IssuerStore::open(&root).ensure_realm().unwrap();
        let backup_dir = status(&root).unwrap().config.unwrap().backup_dir;
        let pre_rekey_newest = list_versions(&backup_dir).unwrap().pop().unwrap().path;

        let next = generate_identity().unwrap();
        rekey(&root, &next.recipient).unwrap();
        // backup.json itself changed (new recipient) → the checkpoint is a
        // fresh version, encrypted to the new key.
        assert!(matches!(
            checkpoint(&root).unwrap(),
            Checkpoint::Written { .. }
        ));

        let newest = list_versions(&backup_dir).unwrap().pop().unwrap().path;
        assert!(
            verify(&newest, &next.secret).is_ok(),
            "new identity reads the new version"
        );
        assert!(
            verify(&pre_rekey_newest, &old_identity.secret).is_ok(),
            "old identity keeps reading pre-rekey versions"
        );
        assert!(
            verify(&pre_rekey_newest, &next.secret).is_err(),
            "new identity cannot read versions sealed before the rekey"
        );
    }

    #[test]
    fn recipient_of_derives_the_public_key() {
        let identity = generate_identity().unwrap();
        assert_eq!(recipient_of(&identity.secret).unwrap(), identity.recipient);
        assert!(recipient_of("AGE-SECRET-KEY-1not-a-key").is_err());
    }

    #[test]
    fn restore_strips_the_backup_configuration() {
        let (_guard, root, identity) = configured_store("strip");
        IssuerStore::open(&root).ensure_realm().unwrap();
        let backup_dir = status(&root).unwrap().config.unwrap().backup_dir;
        let newest = list_versions(&backup_dir).unwrap().pop().unwrap().path;

        let to = root.parent().unwrap().join("stripped-restored");
        restore(&newest, &identity.secret, &to).unwrap();

        // The restored store is "unconfigured" — the old machine's absolute
        // backup_dir never travels.
        assert!(
            config(&to).unwrap().is_none(),
            "backup.json must not survive a restore"
        );
        assert!(!to.join(BACKUP_FILE).exists());
        // Restore validation fires ensure_* hooks → best-effort checkpoints
        // are no-ops against an unconfigured store, never writes into the
        // OLD machine's directory.
        assert_eq!(checkpoint(&to).unwrap(), Checkpoint::Unconfigured);
        assert_eq!(
            list_versions(&backup_dir).unwrap().len(),
            1,
            "restore must not checkpoint into the old machine's backup dir"
        );
        // The store itself is fully intact.
        IssuerStore::open(&to).ensure_realm().unwrap();
    }

    #[test]
    fn relocate_moves_the_target_and_keeps_prior_versions() {
        let (_guard, root, identity) = configured_store("relocate");
        IssuerStore::open(&root).ensure_realm().unwrap();
        let old_dir = status(&root).unwrap().config.unwrap().backup_dir;
        let old_versions = list_versions(&old_dir).unwrap().len();
        assert!(old_versions >= 1);

        let new_dir = root.parent().unwrap().join("relocate-second-medium");
        let cfg = relocate(&root, &new_dir).unwrap();
        assert_eq!(cfg.backup_dir, new_dir.canonicalize().unwrap());
        assert_eq!(
            cfg.recipient,
            status(&root).unwrap().config.unwrap().recipient
        );

        // The checkpoint right after the move lands in the NEW directory.
        assert!(matches!(
            checkpoint(&root).unwrap(),
            Checkpoint::Written { path } if path.starts_with(new_dir.canonicalize().unwrap())
        ));
        // Prior versions stay behind, readable by the SAME identity.
        assert_eq!(
            list_versions(&old_dir).unwrap().len(),
            old_versions,
            "relocate never touches the old directory"
        );
        let old_newest = list_versions(&old_dir).unwrap().pop().unwrap().path;
        assert!(verify(&old_newest, &identity.secret).is_ok());
        // Retention now prunes the new directory only — the old history is
        // out of the pruning loop by construction.
        let status_now = status(&root).unwrap();
        assert!(status_now.newest_is_current);
        assert_eq!(status_now.versions.len(), 1);
    }

    #[test]
    fn relocate_refuses_unconfigured_and_nested() {
        let dir = tempfile::tempdir().unwrap();
        let bare = dir.path().join("bare");
        assert!(
            relocate(&bare, &dir.path().join("anywhere")).is_err(),
            "relocate requires an existing configuration"
        );
        let (_guard, root, _identity) = configured_store("relocate-nest");
        assert!(
            relocate(&root, &root.join("inside")).is_err(),
            "a backup dir inside the store is refused exactly like configure"
        );
    }

    #[test]
    fn malformed_backup_config_is_loud_not_silent() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().join("broken-cfg");
        std::fs::create_dir_all(&root).unwrap();
        std::fs::write(root.join(BACKUP_FILE), "{ not json").unwrap();
        assert!(
            config(&root).is_err(),
            "a corrupt backup.json must not silently disable backups"
        );
    }

    fn set_mtime(path: &Path, at: std::time::SystemTime) {
        let file = std::fs::OpenOptions::new().append(true).open(path).unwrap();
        file.set_modified(at).unwrap();
    }

    /// The store exactly as the 2026-10-10 deployments stood when the CWD
    /// bug was found: v1 backup.json with a raw relative backup_dir, its
    /// sibling backup dir already populated, and (for the read-only test)
    /// a newest version whose hash covers those very bytes.
    fn legacy_v1_store(tag: &str) -> (tempfile::TempDir, PathBuf, GeneratedIdentity) {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().join(tag);
        std::fs::create_dir_all(&root).unwrap();
        std::fs::create_dir_all(dir.path().join(format!("{tag}-backups"))).unwrap();
        let identity = generate_identity().unwrap();
        std::fs::write(root.join("realm-issuer.crt"), b"a store file").unwrap();
        std::fs::write(
            root.join(BACKUP_FILE),
            serde_json::json!({
                "recipient": identity.recipient,
                "backup_dir": format!("{tag}-backups"),
                "retention": DEFAULT_RETENTION,
                "initialized_at": "2026-10-10T04:20:00Z",
            })
            .to_string(),
        )
        .unwrap();
        (dir, root, identity)
    }

    #[test]
    fn legacy_v1_relative_backup_dir_resolves_on_read_without_writing() {
        let (dir, root, identity) = legacy_v1_store("legacy-ro");
        // The version a pre-fix binary would have left: hash over the
        // store exactly as it stands (v1 bytes included), in the sibling
        // dir the deployment-tree operator meant.
        let backup_dir = dir.path().join("legacy-ro-backups");
        let files = collect_files(&root, &backup_dir).unwrap();
        let tar_bytes = build_tar(&files).unwrap();
        let hash8 = interflow_util::sha256_hex(&tar_bytes)[..8].to_owned();
        let ciphertext =
            encrypt_to(&parse_recipient(&identity.recipient).unwrap(), &tar_bytes).unwrap();
        std::fs::write(
            backup_dir.join(format!("{NAME_PREFIX}20261010T042000Z-{hash8}.age")),
            ciphertext,
        )
        .unwrap();

        let bytes_before = std::fs::read(root.join(BACKUP_FILE)).unwrap();
        let s = status(&root).unwrap();
        let cfg = s.config.as_ref().unwrap();
        assert_eq!(cfg.version, CONFIG_VERSION);
        assert!(
            cfg.backup_dir.is_absolute(),
            "the v1 relative value is anchored to the store's parent"
        );
        assert_eq!(
            cfg.backup_dir.canonicalize().unwrap(),
            backup_dir.canonicalize().unwrap()
        );
        assert_eq!(s.versions.len(), 1);
        assert!(
            s.newest_is_current,
            "reads never rewrite backup.json — the currency hash cannot drift from the newest \
             version just because someone ran from another CWD"
        );
        assert_eq!(
            std::fs::read(root.join(BACKUP_FILE)).unwrap(),
            bytes_before,
            "status is read-only"
        );
    }

    #[test]
    fn checkpoint_persists_the_v2_migration_inside_its_hash() {
        let (_dir, root, _identity) = legacy_v1_store("migrate");
        let (cfg, migrated) = load_config(&root).unwrap().unwrap();
        assert!(migrated, "the v1 shape is normalized in memory");
        assert!(cfg.backup_dir.is_absolute());

        assert!(matches!(
            checkpoint(&root).unwrap(),
            Checkpoint::Written { .. }
        ));
        let on_disk: BackupConfig =
            serde_json::from_str(&std::fs::read_to_string(root.join(BACKUP_FILE)).unwrap())
                .unwrap();
        assert_eq!(on_disk.version, CONFIG_VERSION);
        assert!(on_disk.backup_dir.is_absolute());
        assert!(
            status(&root).unwrap().newest_is_current,
            "the migration was persisted BEFORE hashing — the checkpoint that wrote it covers \
             it, with no stale window and no follow-up runbook step"
        );
    }

    #[test]
    fn v2_relative_backup_dir_fails_closed() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().join("v2rel");
        std::fs::create_dir_all(&root).unwrap();
        std::fs::write(
            root.join(BACKUP_FILE),
            serde_json::json!({
                "version": CONFIG_VERSION,
                "recipient": "age1placeholder",
                "backup_dir": "relative-backups",
                "retention": DEFAULT_RETENTION,
                "initialized_at": "2026-10-12T00:00:00Z",
            })
            .to_string(),
        )
        .unwrap();
        let err = config(&root).unwrap_err().to_string();
        assert!(
            err.contains("relative backup_dir"),
            "a broken v2 invariant is loud, not guessed: {err}"
        );
    }

    #[test]
    fn configure_stores_an_absolute_v2_backup_dir() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().join("abscfg");
        let backup_dir = dir.path().join("abscfg-backups");
        let identity = generate_identity().unwrap();
        let cfg = configure(&root, &identity.recipient, &backup_dir, DEFAULT_RETENTION).unwrap();
        assert_eq!(cfg.version, CONFIG_VERSION);
        assert!(cfg.backup_dir.is_absolute());
        let on_disk: BackupConfig =
            serde_json::from_str(&std::fs::read_to_string(root.join(BACKUP_FILE)).unwrap())
                .unwrap();
        assert_eq!(on_disk.version, CONFIG_VERSION);
        assert!(on_disk.backup_dir.is_absolute());
        // The relative-ARG shape (init run from the deployment tree root)
        // is exercised end-to-end by the CLI integration test — a unit
        // test cannot spawn with a foreign CWD.
    }

    #[test]
    fn newest_orders_by_name_timestamp_and_survives_mtime_resets() {
        let (_guard, root, identity) = configured_store("mtimereset");
        IssuerStore::open(&root).ensure_realm().unwrap();
        let s0 = status(&root).unwrap();
        assert!(s0.newest_is_current);
        let backup_dir = s0.config.clone().unwrap().backup_dir;
        let current_hash8 = s0.current_hash8.clone().unwrap();

        // A decoy with an OLDER name timestamp carrying today's content —
        // what a synced-in copy of last week's backup looks like.
        let files = collect_files(&root, &backup_dir).unwrap();
        let tar_bytes = build_tar(&files).unwrap();
        let ciphertext =
            encrypt_to(&parse_recipient(&identity.recipient).unwrap(), &tar_bytes).unwrap();
        let decoy = backup_dir.join(format!("{NAME_PREFIX}20261010T042000Z-deadbeef.age"));
        std::fs::write(&decoy, &ciphertext).unwrap();

        // `cp -r` without -p: mtimes become per-file copy instants in
        // arbitrary order — here the OLDEST version lands with the
        // FRESHEST mtime, the exact field condition that made newest point
        // at the 10-10 decoy and report a false stale.
        let reset =
            std::time::SystemTime::UNIX_EPOCH + std::time::Duration::from_secs(1_700_000_000);
        for v in list_versions(&backup_dir).unwrap() {
            set_mtime(&v.path, reset);
        }
        set_mtime(&decoy, reset + std::time::Duration::from_secs(86_400));
        assert!(
            status(&root).unwrap().newest_is_current,
            "newest must follow the name timestamp, not the reset mtime"
        );
        assert_eq!(
            newest_version(&backup_dir).unwrap().unwrap().hash8,
            current_hash8
        );
    }

    #[test]
    fn same_second_versions_order_by_write_time() {
        let dir = tempfile::tempdir().unwrap();
        let backup_dir = dir.path().join("tie-backups");
        std::fs::create_dir_all(&backup_dir).unwrap();
        let identity = generate_identity().unwrap();
        let ciphertext = encrypt_to(
            &parse_recipient(&identity.recipient).unwrap(),
            b"ordering only",
        )
        .unwrap();
        let a = backup_dir.join(format!("{NAME_PREFIX}20261012T100000Z-aaaaaaaa.age"));
        let b = backup_dir.join(format!("{NAME_PREFIX}20261012T100000Z-bbbbbbbb.age"));
        std::fs::write(&a, &ciphertext).unwrap();
        std::fs::write(&b, &ciphertext).unwrap();
        let t0 = std::time::SystemTime::UNIX_EPOCH + std::time::Duration::from_secs(1_700_000_000);
        set_mtime(&a, t0);
        set_mtime(&b, t0 + std::time::Duration::from_secs(1));
        assert_eq!(
            newest_version(&backup_dir).unwrap().unwrap().path,
            b,
            "the later write wins the same-second tie"
        );
        set_mtime(&a, t0 + std::time::Duration::from_secs(2));
        assert_eq!(
            newest_version(&backup_dir).unwrap().unwrap().path,
            a,
            "mtime is only the tiebreak — reversing mtimes reverses the pair"
        );
    }
}
