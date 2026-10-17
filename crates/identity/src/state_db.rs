//! The issuer store's bookkeeping db (`store.db`): the binding contract,
//! the applied-state accounting, and the applied-declaration history — the
//! machine-owned state that used to be two bare JSON files (`binding.json`
//! / `applied.json`).
//!
//! Why a db and not files: the GUI's embedded apply and a terminal
//! `rotate` can land on the same issuer directory at the same moment, and
//! the JSON pair had no cross-process mutex — the check-then-write
//! sequence raced and lost updates. SQLite gives the sequence one
//! transactional home: WAL + busy_timeout serialize the writers properly
//!
//! The db is machine state, not an operator document: its shape lives in
//! code and migrates via `user_version` (the versioning doctrine's
//! "no counters in human-authored files" rule governs documents, not
//! machine state). Creation mints the store's UUID — the store is itself,
//! not the path it happens to sit at. Legacy JSON files next to a fresh db
//! are absorbed once, then renamed `.migrated`.

use crate::issuance::{AppliedState, StoreBinding};
use crate::{Error, Result};
use rusqlite::{Connection, OpenFlags};
use std::path::{Path, PathBuf};

const DB_FILE: &str = "store.db";
const LEGACY_BINDING: &str = "binding.json";
const LEGACY_APPLIED: &str = "applied.json";
const MIGRATED_SUFFIX: &str = "migrated";

/// The db's shape. Bump and extend [`StateDb::create_or_migrate`] whenever
/// a table changes; never reset (a higher number on disk than in code
/// means a newer build ran last — refuse loudly).
const SHAPE: i32 = 1;

/// The issuer store's bookkeeping db. Opened briefly per operation; every
/// mutation is one transaction.
#[derive(Debug)]
pub(crate) struct StateDb {
    conn: Connection,
    root: PathBuf,
}

impl StateDb {
    /// Opens the db without creating anything. `None` when no db exists
    /// yet (a store that has never recorded a binding — reads must not
    /// materialize files: the GUI treats `issuer/` existing as "an apply
    /// has run here").
    pub(crate) fn open_existing(root: &Path) -> Result<Option<Self>> {
        if !root.join(DB_FILE).is_file() {
            return Ok(None);
        }
        let conn =
            Connection::open_with_flags(root.join(DB_FILE), OpenFlags::SQLITE_OPEN_READ_WRITE)
                .map_err(|e| db_err("open", root, e))?;
        apply_connection_pragmas(&conn).map_err(|e| db_err("open", root, e))?;
        let db = Self {
            conn,
            root: root.to_owned(),
        };
        db.check_shape()?;
        Ok(Some(db))
    }

    /// Opens the db, creating (and migrating) on first use — the write
    /// paths only. Creation mints the store UUID and absorbs any legacy
    /// JSON pair sitting in the directory.
    pub(crate) fn open_or_create(root: &Path) -> Result<Self> {
        std::fs::create_dir_all(root).map_err(|e| Error::Io {
            path: root.display().to_string(),
            source: e,
        })?;
        let conn = Connection::open(root.join(DB_FILE)).map_err(|e| db_err("open", root, e))?;
        apply_connection_pragmas(&conn).map_err(|e| db_err("open", root, e))?;
        let mut db = Self {
            conn,
            root: root.to_owned(),
        };
        db.create_or_migrate()?;
        Ok(db)
    }

    /// The store's UUID (minted at db creation; stable for the store's
    /// life regardless of where the directory moves).
    pub(crate) fn store_uuid(&self) -> Result<String> {
        self.conn
            .query_row("SELECT store_uuid FROM meta WHERE id = 1", [], |row| {
                row.get(0)
            })
            .map_err(|e| db_err("read store id", &self.root, e))
    }

    pub(crate) fn binding(&self) -> Result<Option<StoreBinding>> {
        match self.conn.query_row(
            "SELECT realm, manifest_path, manifest_digest, bound_at FROM binding WHERE id = 1",
            [],
            |row| {
                Ok(StoreBinding {
                    realm: row.get(0)?,
                    manifest_path: row.get(1)?,
                    manifest_digest: row.get(2)?,
                    bound_at: row.get(3)?,
                })
            },
        ) {
            Ok(binding) => Ok(Some(binding)),
            Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
            Err(e) => Err(db_err("read binding", &self.root, e)),
        }
    }

    /// Upserts the binding row (single row — the store binds exactly one
    /// lineage; `plan apply`/`rotate` enforce the contract around this).
    pub(crate) fn record_binding(&mut self, binding: &StoreBinding) -> Result<()> {
        let tx = self
            .conn
            .transaction()
            .map_err(|e| db_err("bind", &self.root, e))?;
        tx.execute(
            "INSERT INTO binding (id, realm, manifest_path, manifest_digest, bound_at)
             VALUES (1, ?1, ?2, ?3, ?4)
             ON CONFLICT(id) DO UPDATE SET
                realm = excluded.realm,
                manifest_path = excluded.manifest_path,
                manifest_digest = excluded.manifest_digest,
                bound_at = excluded.bound_at",
            rusqlite::params![
                binding.realm,
                binding.manifest_path,
                binding.manifest_digest,
                binding.bound_at
            ],
        )
        .map_err(|e| db_err("record binding", &self.root, e))?;
        tx.commit()
            .map_err(|e| db_err("record binding", &self.root, e))?;
        Ok(())
    }

    pub(crate) fn applied_state(&self) -> Result<Option<AppliedState>> {
        match self.conn.query_row(
            "SELECT stripped_manifest_digest, policy_generation, policy_digest, packs
             FROM applied WHERE id = 1",
            [],
            |row| {
                let packs_json: String = row.get(3)?;
                let packs = serde_json::from_str(&packs_json).map_err(|_| {
                    rusqlite::Error::FromSqlConversionFailure(
                        3,
                        rusqlite::types::Type::Text,
                        box_err("applied packs are not valid JSON"),
                    )
                })?;
                Ok(AppliedState {
                    stripped_manifest_digest: row.get(0)?,
                    policy_generation: row.get::<_, i64>(1)? as u64,
                    policy_digest: row.get(2)?,
                    packs,
                })
            },
        ) {
            Ok(state) => Ok(Some(state)),
            Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
            Err(e) => Err(db_err("read applied state", &self.root, e)),
        }
    }

    /// The declaration text as it stood at the last record — the drift
    /// baseline `plan diff` compares the live manifest against. `None`
    /// before the first apply, or for a state absorbed from the legacy
    /// `applied.json` (which carried no snapshot).
    pub(crate) fn applied_manifest_text(&self) -> Result<Option<String>> {
        match self.conn.query_row(
            "SELECT manifest_text FROM applied WHERE id = 1",
            [],
            |row| row.get(0),
        ) {
            Ok(text) => Ok(text),
            Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
            Err(e) => Err(db_err("read applied manifest", &self.root, e)),
        }
    }

    /// Upserts the applied state, snapshots the declaration text, and
    /// appends the submission to the history — one transaction.
    pub(crate) fn record_applied(
        &mut self,
        state: &AppliedState,
        manifest_text: Option<&str>,
        kind: &str,
    ) -> Result<()> {
        let packs = serde_json::to_string(&state.packs)
            .map_err(|e| Error::serialize("applied packs".to_owned()).with_source(e))?;
        let at = crate::timestamp::rfc3339_now()?;
        let tx = self
            .conn
            .transaction()
            .map_err(|e| db_err("record applied", &self.root, e))?;
        tx.execute(
            "INSERT INTO applied
                (id, stripped_manifest_digest, policy_generation, policy_digest, packs,
                 manifest_text)
             VALUES (1, ?1, ?2, ?3, ?4, ?5)
             ON CONFLICT(id) DO UPDATE SET
                stripped_manifest_digest = excluded.stripped_manifest_digest,
                policy_generation = excluded.policy_generation,
                policy_digest = excluded.policy_digest,
                packs = excluded.packs,
                manifest_text = excluded.manifest_text",
            rusqlite::params![
                state.stripped_manifest_digest,
                state.policy_generation as i64,
                state.policy_digest,
                packs,
                manifest_text
            ],
        )
        .map_err(|e| db_err("record applied", &self.root, e))?;
        tx.execute(
            "INSERT INTO applied_log (at, kind, policy_generation, manifest_text)
             VALUES (?1, ?2, ?3, ?4)",
            rusqlite::params![at, kind, state.policy_generation as i64, manifest_text],
        )
        .map_err(|e| db_err("append applied history", &self.root, e))?;
        tx.commit()
            .map_err(|e| db_err("record applied", &self.root, e))?;
        Ok(())
    }

    fn check_shape(&self) -> Result<()> {
        let shape = self.read_shape()?;
        if shape > SHAPE {
            return Err(Error::issuance(format!(
                "issuer store db {} is shape {shape}, newer than this build understands \
                 ({SHAPE}) — upgrade before touching this store",
                self.root.join(DB_FILE).display()
            )));
        }
        if shape < SHAPE {
            // An older-shape db is upgraded by the next write path; reads
            // against it still work (the shape-1 tables are a subset).
            return Ok(());
        }
        Ok(())
    }

    fn read_shape(&self) -> Result<i32> {
        self.conn
            .query_row("PRAGMA user_version", [], |row| row.get(0))
            .map_err(|e| db_err("read shape", &self.root, e))
    }

    /// Creates the db at [`SHAPE`] when absent, minting the store UUID and
    /// absorbing the legacy JSON pair; one immediate transaction, so two
    /// racing first-writes settle with one absorb.
    fn create_or_migrate(&mut self) -> Result<()> {
        let tx = self
            .conn
            .transaction()
            .map_err(|e| db_err("open", &self.root, e))?;
        let shape: i32 = tx
            .query_row("PRAGMA user_version", [], |row| row.get(0))
            .map_err(|e| db_err("open", &self.root, e))?;
        if shape > SHAPE {
            return Err(Error::issuance(format!(
                "issuer store db {} is shape {shape}, newer than this build understands \
                 ({SHAPE}) — upgrade before touching this store",
                self.root.join(DB_FILE).display()
            )));
        }
        if shape == SHAPE {
            return Ok(());
        }
        tx.execute_batch(
            "CREATE TABLE meta (
                id INTEGER PRIMARY KEY CHECK (id = 1),
                store_uuid TEXT NOT NULL,
                created_at TEXT NOT NULL
            );
            CREATE TABLE binding (
                id INTEGER PRIMARY KEY CHECK (id = 1),
                realm TEXT NOT NULL,
                manifest_path TEXT NOT NULL,
                manifest_digest TEXT NOT NULL,
                bound_at TEXT NOT NULL
            );
            CREATE TABLE applied (
                id INTEGER PRIMARY KEY CHECK (id = 1),
                stripped_manifest_digest TEXT NOT NULL,
                policy_generation INTEGER NOT NULL,
                policy_digest TEXT NOT NULL,
                packs TEXT NOT NULL,
                manifest_text TEXT
            );
            CREATE TABLE applied_log (
                seq INTEGER PRIMARY KEY AUTOINCREMENT,
                at TEXT NOT NULL,
                kind TEXT NOT NULL,
                policy_generation INTEGER NOT NULL,
                manifest_text TEXT
            );",
        )
        .map_err(|e| db_err("create tables", &self.root, e))?;
        tx.execute(
            "INSERT INTO meta (id, store_uuid, created_at) VALUES (1, ?1, ?2)",
            rusqlite::params![mint_uuid()?, crate::timestamp::rfc3339_now()?],
        )
        .map_err(|e| db_err("mint store id", &self.root, e))?;
        tx.execute(
            "INSERT INTO applied_log (at, kind, policy_generation, manifest_text)
             VALUES (?1, 'created', 0, NULL)",
            rusqlite::params![crate::timestamp::rfc3339_now()?],
        )
        .map_err(|e| db_err("append applied history", &self.root, e))?;
        Self::absorb_legacy(&tx, &self.root)?;
        tx.pragma_update(None, "user_version", SHAPE)
            .map_err(|e| db_err("set shape", &self.root, e))?;
        tx.commit().map_err(|e| db_err("open", &self.root, e))?;
        // File renames happen after commit: a crash between commit and
        // rename re-absorbs idempotently on the next open.
        rename_legacy(&self.root, LEGACY_BINDING);
        rename_legacy(&self.root, LEGACY_APPLIED);
        Ok(())
    }

    /// Absorbs the legacy `binding.json` / `applied.json` into the fresh
    /// db (their row shapes are the JSON shapes verbatim). Malformed
    /// legacy files are errors — the same loudness their read paths had.
    fn absorb_legacy(tx: &rusqlite::Transaction<'_>, root: &Path) -> Result<()> {
        let binding_path = root.join(LEGACY_BINDING);
        if binding_path.is_file() {
            let raw = read_json(&binding_path)?;
            let binding: StoreBinding = serde_json::from_str(&raw).map_err(|e| {
                Error::issuance(format!(
                    "issuer store has a malformed {LEGACY_BINDING} — inspect it, or rebind \
                     deliberately by re-running with the allow-shared override"
                ))
                .with_source(e)
            })?;
            tx.execute(
                "INSERT INTO binding (id, realm, manifest_path, manifest_digest, bound_at)
                 VALUES (1, ?1, ?2, ?3, ?4)
                 ON CONFLICT(id) DO UPDATE SET
                    realm = excluded.realm,
                    manifest_path = excluded.manifest_path,
                    manifest_digest = excluded.manifest_digest,
                    bound_at = excluded.bound_at",
                rusqlite::params![
                    binding.realm,
                    binding.manifest_path,
                    binding.manifest_digest,
                    binding.bound_at
                ],
            )
            .map_err(|e| db_err("absorb binding", root, e))?;
        }
        let applied_path = root.join(LEGACY_APPLIED);
        if applied_path.is_file() {
            let raw = read_json(&applied_path)?;
            let state: AppliedState = serde_json::from_str(&raw).map_err(|e| {
                Error::issuance(format!(
                    "issuer store has a malformed {LEGACY_APPLIED} — delete it and re-run apply"
                ))
                .with_source(e)
            })?;
            let packs = serde_json::to_string(&state.packs)
                .map_err(|e| Error::serialize("applied packs".to_owned()).with_source(e))?;
            tx.execute(
                "INSERT INTO applied
                    (id, stripped_manifest_digest, policy_generation, policy_digest, packs,
                     manifest_text)
                 VALUES (1, ?1, ?2, ?3, ?4, NULL)
                 ON CONFLICT(id) DO UPDATE SET
                    stripped_manifest_digest = excluded.stripped_manifest_digest,
                    policy_generation = excluded.policy_generation,
                    policy_digest = excluded.policy_digest,
                    packs = excluded.packs,
                    manifest_text = excluded.manifest_text",
                rusqlite::params![
                    state.stripped_manifest_digest,
                    state.policy_generation as i64,
                    state.policy_digest,
                    packs
                ],
            )
            .map_err(|e| db_err("absorb applied", root, e))?;
            tx.execute(
                "INSERT INTO applied_log (at, kind, policy_generation, manifest_text)
                 VALUES (?1, 'absorbed-legacy', ?2, NULL)",
                rusqlite::params![
                    crate::timestamp::rfc3339_now()?,
                    state.policy_generation as i64
                ],
            )
            .map_err(|e| db_err("append applied history", root, e))?;
        }
        Ok(())
    }
}

/// Applies the WAL pragmas every connection needs (WAL so a GUI-embedded
/// apply and a terminal `rotate` serialize instead of clobber; busy
/// timeout so the loser of a write race waits briefly instead of failing).
pub(crate) fn apply_connection_pragmas(conn: &Connection) -> rusqlite::Result<()> {
    conn.pragma_update(None, "journal_mode", "WAL")?;
    conn.pragma_update(None, "synchronous", "NORMAL")?;
    conn.pragma_update(None, "busy_timeout", 5_000)?;
    Ok(())
}

/// Flushes the db's WAL into the main file so a plain file copy (the
/// backup tar) carries every committed row, leaving the sidecar empty.
/// No-op when the store has no db yet. A checkpoint that cannot complete
/// (a reader holds the log past the busy timeout) is an error: a backup
/// quietly missing the newest rows is worse than a loud retry.
pub(crate) fn wal_checkpoint(root: &Path) -> Result<()> {
    if !root.join(DB_FILE).is_file() {
        return Ok(());
    }
    let conn = Connection::open_with_flags(root.join(DB_FILE), OpenFlags::SQLITE_OPEN_READ_WRITE)
        .map_err(|e| db_err("open for checkpoint", root, e))?;
    conn.pragma_update(None, "busy_timeout", 5_000)
        .map_err(|e| db_err("checkpoint", root, e))?;
    let (busy, _log, _checkpointed): (i64, i64, i64) = conn
        .query_row("PRAGMA wal_checkpoint(TRUNCATE)", [], |row| {
            Ok((row.get(0)?, row.get(1)?, row.get(2)?))
        })
        .map_err(|e| db_err("checkpoint", root, e))?;
    if busy != 0 {
        return Err(Error::issuance(format!(
            "issuer store db {} could not flush its write-ahead log (a reader holds it) — \
             retry the operation",
            root.join(DB_FILE).display()
        )));
    }
    Ok(())
}

fn read_json(path: &Path) -> Result<String> {
    std::fs::read_to_string(path).map_err(|e| Error::Io {
        path: path.display().to_string(),
        source: e,
    })
}

fn rename_legacy(root: &Path, name: &str) {
    let from = root.join(name);
    if !from.is_file() {
        return;
    }
    let mut to = from.as_os_str().to_owned();
    to.push(".");
    to.push(MIGRATED_SUFFIX);
    if let Err(e) = std::fs::rename(&from, &to) {
        tracing::warn!(
            "could not rename the absorbed {} to {}: {e} — it is no longer read, but move it \
             aside to keep future opens clean",
            from.display(),
            Path::new(&to).display()
        );
    }
}

fn mint_uuid() -> Result<String> {
    let mut bytes = [0u8; 16];
    // `getrandom::Error` does not implement `std::error::Error`, so the
    // error is folded into the message (same shape as the issuance and
    // sealed-pack call sites).
    getrandom::fill(&mut bytes).map_err(|e| Error::issuance(format!("store id entropy: {e}")))?;
    // RFC 4122 random-UUID bits (version + variant), then the dashed form.
    bytes[6] = (bytes[6] & 0x0f) | 0x40;
    bytes[8] = (bytes[8] & 0x3f) | 0x80;
    let hex = hex::encode(bytes);
    Ok(format!(
        "{}-{}-{}-{}-{}",
        &hex[0..8],
        &hex[8..12],
        &hex[12..16],
        &hex[16..20],
        &hex[20..32]
    ))
}

fn db_err(context: &str, root: &Path, e: rusqlite::Error) -> Error {
    Error::issuance(format!(
        "{context} (issuer store db {}): {e}",
        root.join(DB_FILE).display()
    ))
}

/// `FromSqlConversionFailure` wants a boxed error whose message survives.
fn box_err(message: &'static str) -> Box<dyn std::error::Error + Send + Sync> {
    Box::<dyn std::error::Error + Send + Sync>::from(message)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    /// A fresh store mints a stable UUID; the binding round-trips through
    /// upsert (the silent-refresh path every apply takes).
    #[test]
    fn binding_round_trips_and_uuid_is_stable() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        let uuid = StateDb::open_or_create(root).unwrap().store_uuid().unwrap();
        assert_eq!(uuid.len(), 36, "dashed UUID v4 shape");
        {
            let mut db = StateDb::open_or_create(root).unwrap();
            db.record_binding(&StoreBinding {
                realm: "promptcn".into(),
                manifest_path: "/deploy/promptcn/interflow.toml".into(),
                manifest_digest: "sha256:aa".into(),
                bound_at: "2026-10-11T00:00:00Z".into(),
            })
            .unwrap();
        }
        let db = StateDb::open_existing(root).unwrap().unwrap();
        assert_eq!(db.store_uuid().unwrap(), uuid, "UUID survives reopen");
        let binding = db.binding().unwrap().unwrap();
        assert_eq!(binding.realm, "promptcn");
        assert_eq!(binding.manifest_digest, "sha256:aa");
        // Upsert (refresh) replaces in place — still one row.
        {
            let mut db = StateDb::open_or_create(root).unwrap();
            db.record_binding(&StoreBinding {
                realm: "promptcn".into(),
                manifest_path: "/deploy/promptcn/interflow.toml".into(),
                manifest_digest: "sha256:bb".into(),
                bound_at: "2026-10-11T01:00:00Z".into(),
            })
            .unwrap();
        }
        let db = StateDb::open_existing(root).unwrap().unwrap();
        assert_eq!(db.binding().unwrap().unwrap().manifest_digest, "sha256:bb");
    }

    /// Reads never materialize the db: a store with no db has no binding
    /// and no applied state, and no file appears.
    #[test]
    fn reads_do_not_create_the_db() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(dir.path().join("issuer")).unwrap();
        let root = dir.path().join("issuer");
        assert!(StateDb::open_existing(&root).unwrap().is_none());
        assert!(!root.join(DB_FILE).exists());
    }

    /// Applied state round-trips with the declaration snapshot; each
    /// record appends one history row.
    #[test]
    fn applied_state_and_history_round_trip() {
        let dir = tempfile::tempdir().unwrap();
        let mut db = StateDb::open_or_create(dir.path()).unwrap();
        assert!(db.applied_state().unwrap().is_none());
        assert!(db.applied_manifest_text().unwrap().is_none());
        let state = AppliedState {
            stripped_manifest_digest: "sha256:s1".into(),
            policy_generation: 7,
            policy_digest: "sha256:p1".into(),
            packs: [("hub-central".to_owned(), "sha256:pk1".to_owned())]
                .into_iter()
                .collect(),
        };
        db.record_applied(&state, Some("[realm]\nid = \"x\"\n"), "full-render")
            .unwrap();
        let db = StateDb::open_existing(dir.path()).unwrap().unwrap();
        assert_eq!(db.applied_state().unwrap().unwrap().policy_generation, 7);
        assert_eq!(
            db.applied_state()
                .unwrap()
                .unwrap()
                .packs
                .get("hub-central"),
            Some(&"sha256:pk1".to_owned())
        );
        assert_eq!(
            db.applied_manifest_text().unwrap().as_deref(),
            Some("[realm]\nid = \"x\"\n")
        );
        let rows: i64 = db
            .conn
            .query_row(
                "SELECT COUNT(*) FROM applied_log WHERE kind = 'full-render'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(rows, 1);
    }

    /// The legacy JSON pair is absorbed verbatim on first creation and
    /// renamed; the absorbed applied state carries no declaration
    /// snapshot (the files never had one).
    #[test]
    fn legacy_pair_is_absorbed_and_renamed() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        std::fs::write(
            root.join(LEGACY_BINDING),
            r#"{"realm":"promptcn","manifest_path":"/old/interflow.toml","manifest_digest":"sha256:old","bound_at":"2026-10-01T00:00:00Z"}"#,
        )
        .unwrap();
        std::fs::write(
            root.join(LEGACY_APPLIED),
            r#"{"stripped_manifest_digest":"sha256:st","policy_generation":3,"policy_digest":"sha256:pd","packs":{"agent-a":"sha256:z"}}"#,
        )
        .unwrap();
        let db = StateDb::open_or_create(root).unwrap();
        let binding = db.binding().unwrap().unwrap();
        assert_eq!(binding.realm, "promptcn");
        assert_eq!(binding.manifest_path, "/old/interflow.toml");
        let state = db.applied_state().unwrap().unwrap();
        assert_eq!(state.policy_generation, 3);
        assert!(db.applied_manifest_text().unwrap().is_none());
        assert!(!root.join(LEGACY_BINDING).exists());
        assert!(!root.join(LEGACY_APPLIED).exists());
        assert!(
            root.join(format!("{LEGACY_BINDING}.{MIGRATED_SUFFIX}"))
                .exists()
        );
        assert!(
            root.join(format!("{LEGACY_APPLIED}.{MIGRATED_SUFFIX}"))
                .exists()
        );
        // Reopening never re-absorbs (the files are gone).
        let again = StateDb::open_or_create(root).unwrap();
        assert_eq!(again.applied_state().unwrap().unwrap().policy_generation, 3);
    }

    /// A db written by a newer build is refused, not mangled.
    #[test]
    fn newer_shape_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        {
            StateDb::open_or_create(dir.path()).unwrap();
            let conn = Connection::open(dir.path().join(DB_FILE)).unwrap();
            conn.pragma_update(None, "user_version", 99).unwrap();
        }
        let err = StateDb::open_or_create(dir.path()).unwrap_err();
        assert!(err.to_string().contains("newer"), "wrong error: {err}");
        let err = StateDb::open_existing(dir.path()).unwrap_err();
        assert!(err.to_string().contains("newer"), "wrong error: {err}");
    }
}
