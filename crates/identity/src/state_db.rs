//! The issuer store's bookkeeping db (`store.db`): the binding contract,
//! the applied-state accounting, and the applied-declaration history.
//!
//! Why a db and not files: the GUI's embedded apply and a terminal
//! `rotate` can land on the same issuer directory at the same moment, and
//! file pairs have no cross-process mutex — the check-then-write sequence
//! raced and lost updates. SQLite gives the sequence one transactional
//! home: WAL + busy_timeout serialize the writers properly.
//!
//! The db is machine state, not an operator document: its shape lives in
//! code and is declared by `user_version`. There is exactly one shape per
//! build generation and no migration ladder — a store whose shape does not
//! match was written by a different deployment generation and is refused
//! loudly (re-provision it); stores are cheap, bookkeeping drift is not.
//!
//! The applied row's `stripped_manifest_digest` is a cache of the applied
//! declaration snapshot (`manifest_text`) — the snapshot is the truth a
//! digest mismatch is settled against, so the cache needs no label: the
//! same text, stripped by the same rule, compares equal.

use crate::issuance::{AppliedState, StoreBinding};
use crate::{Error, Result};
use rusqlite::{Connection, OpenFlags, TransactionBehavior};
use std::path::{Path, PathBuf};

const DB_FILE: &str = "store.db";

/// The db's shape — exactly one per build generation, never reset (a number
/// on disk this build does not recognize means a different generation ran
/// last — refuse loudly). Shape 3 retired the `digest_kind` column the
/// shape-2 generation carried: the declaration snapshot arbitrates digest
/// mismatches on its own, so the cache carries no label.
const SHAPE: i32 = 3;

/// The issuer store's bookkeeping db. Opened briefly per operation; every
/// mutation is one transaction.
#[derive(Debug)]
pub(crate) struct StateDb {
    conn: Connection,
    root: PathBuf,
}

impl StateDb {
    /// Opens the db without creating anything. `None` when no db exists
    /// yet — reads must not materialize files (the GUI treats `issuer/`
    /// existing as "an apply has run here"). `None` is the truth: this
    /// store has no recorded bookkeeping.
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

    /// Opens the db, creating it on first use — the write paths only.
    /// Creation mints the store UUID.
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
        db.create_if_absent()?;
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

    /// The applied row.
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
    /// before the first apply (every record writes the snapshot).
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
                (id, stripped_manifest_digest, policy_generation, policy_digest,
                 packs, manifest_text)
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

    /// One shape per build generation: any mismatch is refused loudly —
    /// there is no ladder to walk and nothing to salvage. A store written
    /// by another generation is re-provisioned, not migrated.
    fn check_shape(&self) -> Result<()> {
        let shape = self.read_shape()?;
        if shape != SHAPE {
            return Err(shape_mismatch(&self.root, shape));
        }
        Ok(())
    }

    fn read_shape(&self) -> Result<i32> {
        self.conn
            .query_row("PRAGMA user_version", [], |row| row.get(0))
            .map_err(|e| db_err("read shape", &self.root, e))
    }

    /// Creates the db at [`SHAPE`] when absent; one immediate transaction,
    /// so two racing first-writes settle with one creation and the loser
    /// sees the finished shape.
    fn create_if_absent(&mut self) -> Result<()> {
        let tx = self
            .conn
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|e| db_err("open", &self.root, e))?;
        let shape: i32 = tx
            .query_row("PRAGMA user_version", [], |row| row.get(0))
            .map_err(|e| db_err("open", &self.root, e))?;
        if shape == 0 {
            Self::create_at_current_shape(&tx, &self.root)?;
        } else if shape != SHAPE {
            return Err(shape_mismatch(&self.root, shape));
        }
        tx.commit().map_err(|e| db_err("open", &self.root, e))?;
        Ok(())
    }

    /// The [`SHAPE`] DDL plus the creation rows (store id, the `created`
    /// history row).
    fn create_at_current_shape(tx: &rusqlite::Transaction<'_>, root: &Path) -> Result<()> {
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
            );
            PRAGMA user_version = 3;",
        )
        .map_err(|e| db_err("create tables", root, e))?;
        tx.execute(
            "INSERT INTO meta (id, store_uuid, created_at) VALUES (1, ?1, ?2)",
            rusqlite::params![mint_uuid()?, crate::timestamp::rfc3339_now()?],
        )
        .map_err(|e| db_err("mint store id", root, e))?;
        tx.execute(
            "INSERT INTO applied_log (at, kind, policy_generation, manifest_text)
             VALUES (?1, 'created', 0, NULL)",
            rusqlite::params![crate::timestamp::rfc3339_now()?],
        )
        .map_err(|e| db_err("append applied history", root, e))?;
        Ok(())
    }
}

fn shape_mismatch(root: &Path, shape: i32) -> Error {
    Error::issuance(format!(
        "issuer store db {} is shape {shape}, this build expects {SHAPE} — the store was \
         written by a different deployment generation; re-provision it (fresh deployment) \
         rather than migrating bookkeeping",
        root.join(DB_FILE).display()
    ))
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
        let read = db.applied_state().unwrap().unwrap();
        assert_eq!(read.policy_generation, 7);
        assert_eq!(read.stripped_manifest_digest, "sha256:s1");
        assert_eq!(
            read.packs.get("hub-central"),
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

    /// Any shape this build does not recognize — older OR newer — is
    /// refused on both faces; there is no ladder and no salvage.
    #[test]
    fn foreign_shapes_are_refused_on_both_faces() {
        for shape in [1, 2, 99] {
            let dir = tempfile::tempdir().unwrap();
            {
                StateDb::open_or_create(dir.path()).unwrap();
                let conn = Connection::open(dir.path().join(DB_FILE)).unwrap();
                conn.pragma_update(None, "user_version", shape).unwrap();
            }
            let err = StateDb::open_or_create(dir.path()).unwrap_err();
            assert!(
                err.to_string().contains("re-provision"),
                "wrong error: {err}"
            );
            let err = StateDb::open_existing(dir.path()).unwrap_err();
            assert!(
                err.to_string().contains("re-provision"),
                "wrong error: {err}"
            );
        }
    }
}
