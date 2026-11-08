//! The GUI's local preferences store: one process-owned SQLite holding the
//! three domains the GUI persists — the node list, the deploy pane's recent
//! contexts, and the GUI-wide settings (language, current deployment).
//!
//! One db, one table per domain: domains share storage but never a write,
//! so a snapshot-style load-modify-save over one file can never clobber
//! another domain bolted onto it (the defect class that once forced a
//! separate file per domain).
//!
//! The db is machine-owned GUI state, not an operator document: its shape
//! lives in code and is declared by SQLite's `user_version` (the versioning
//! doctrine's "no counters in human-authored files" rule governs documents,
//! not machine state). The GUI process is the sole writer; WAL +
//! busy_timeout keep concurrent domain writes correct anyway.

use crate::deploy_prefs::DeployPrefs;
use crate::gui_prefs::{GuiPrefs, Lang};
use crate::profile::{NodeEntry, ServiceAddressPref};
use interflow_core::config::paths::anchor;
use interflow_core::error::{InterflowError, Result};
use rusqlite::Connection;
use std::path::{Path, PathBuf};

/// The shape of the prefs db. Bump whenever a table changes; never reset
/// (a number on disk this build does not recognize means a different GUI
/// generation ran last — refuse loudly).
const SHAPE: i32 = 1;

/// An open prefs db. Cheap to open per call (the GUI process is the only
/// writer); each domain's save is one short transaction.
#[derive(Debug)]
pub struct PrefsDb {
    conn: Connection,
    /// The db file's directory — the anchor base for relative `pack_dir`
    /// values.
    base: PathBuf,
}

impl PrefsDb {
    /// Opens the prefs db in the user config directory, creating it on
    /// first use.
    pub fn open() -> Result<Self> {
        let base = dirs::config_dir()
            .ok_or_else(|| InterflowError::config("cannot resolve user config directory"))?;
        let dir = base.join("interflow");
        std::fs::create_dir_all(&dir).map_err(InterflowError::from)?;
        Self::open_at(&dir.join("prefs.db"))
    }

    /// [`open`] at an explicit path (tests).
    pub fn open_at(path: &Path) -> Result<Self> {
        let existed = path.is_file();
        let conn = Connection::open(path)
            .map_err(|e| InterflowError::config(format!("prefs db {}: {e}", path.display())))?;
        conn.pragma_update(None, "journal_mode", "WAL")
            .map_err(|e| prefs_db_err(&e))?;
        conn.pragma_update(None, "synchronous", "NORMAL")
            .map_err(|e| prefs_db_err(&e))?;
        conn.pragma_update(None, "busy_timeout", 5_000)
            .map_err(|e| prefs_db_err(&e))?;
        let mut db = Self {
            conn,
            base: path
                .parent()
                .map_or_else(|| PathBuf::from("."), ToOwned::to_owned),
        };
        db.ensure_shape()?;
        if !existed {
            // Same hygiene the TOML files had: user-scoped config that may
            // carry internal endpoint addresses.
            restrict_to_owner(path);
        }
        Ok(db)
    }

    /// Creates the db at [`SHAPE`] when absent; one immediate transaction,
    /// so two racing first-opens settle with one creation. A shape this
    /// build does not recognize is refused — the GUI's preferences are
    /// cheap, bookkeeping drift is not.
    fn ensure_shape(&mut self) -> Result<()> {
        let tx = self.conn.transaction().map_err(|e| prefs_db_err(&e))?;
        let current: i32 = tx
            .query_row("PRAGMA user_version", [], |row| row.get(0))
            .map_err(|e| prefs_db_err(&e))?;
        if current == SHAPE {
            // Read-only open; dropping the transaction rolls nothing back.
            return Ok(());
        }
        if current != 0 {
            return Err(InterflowError::config(format!(
                "prefs db shape {current} is not this build's ({SHAPE}) — the preferences were \
                 written by a different GUI generation; remove prefs.db to start fresh"
            )));
        }
        tx.execute_batch(
            "CREATE TABLE nodes (
                ord INTEGER PRIMARY KEY,
                id TEXT NOT NULL UNIQUE,
                pack_dir TEXT NOT NULL,
                transport TEXT,
                hub_quic_addr TEXT,
                service_addresses TEXT NOT NULL DEFAULT '[]',
                desired_running INTEGER NOT NULL DEFAULT 0
            );
            CREATE TABLE deploy_recent (
                ord INTEGER PRIMARY KEY,
                manifest TEXT NOT NULL,
                issuer TEXT NOT NULL,
                out TEXT NOT NULL
            );
            CREATE TABLE gui (key TEXT PRIMARY KEY, value TEXT NOT NULL);",
        )
        .map_err(|e| prefs_db_err(&e))?;
        tx.pragma_update(None, "user_version", SHAPE)
            .map_err(|e| prefs_db_err(&e))?;
        tx.commit().map_err(|e| prefs_db_err(&e))?;
        Ok(())
    }

    /// The persisted node list, in profile order; relative `pack_dir`
    /// values anchor to the db's directory.
    pub fn nodes(&self) -> Result<Vec<NodeEntry>> {
        let mut stmt = self
            .conn
            .prepare(
                "SELECT id, pack_dir, transport, hub_quic_addr, service_addresses, \
                 desired_running FROM nodes ORDER BY ord",
            )
            .map_err(|e| prefs_db_err(&e))?;
        let rows = stmt
            .query_map([], |row| {
                Ok(NodeRow {
                    id: row.get(0)?,
                    pack_dir: row.get(1)?,
                    transport: row.get(2)?,
                    hub_quic_addr: row.get(3)?,
                    service_addresses: row.get(4)?,
                    desired_running: row.get(5)?,
                })
            })
            .map_err(|e| prefs_db_err(&e))?;
        let mut nodes = Vec::new();
        for row in rows {
            let row = row.map_err(|e| prefs_db_err(&e))?;
            nodes.push(row.into_entry(&self.base)?);
        }
        Ok(nodes)
    }

    /// Replaces the node list (one transaction; order is the `ord` column).
    pub fn save_nodes(&mut self, nodes: &[NodeEntry]) -> Result<()> {
        let tx = self.conn.transaction().map_err(|e| prefs_db_err(&e))?;
        tx.execute("DELETE FROM nodes", [])
            .map_err(|e| prefs_db_err(&e))?;
        insert_nodes(&tx, nodes)?;
        tx.commit().map_err(|e| prefs_db_err(&e))?;
        Ok(())
    }

    /// The deploy pane's remembered contexts (any failure is simply empty —
    /// paths fall back to their defaults, never worth a dialog).
    pub fn deploy(&self) -> DeployPrefs {
        self.deploy_checked().unwrap_or_default()
    }

    fn deploy_checked(&self) -> Result<DeployPrefs> {
        let mut stmt = self
            .conn
            .prepare("SELECT manifest, issuer, out FROM deploy_recent ORDER BY ord")
            .map_err(|e| prefs_db_err(&e))?;
        let rows = stmt
            .query_map([], |row| {
                Ok(crate::deploy_prefs::DeployContext {
                    manifest: row.get(0)?,
                    issuer: row.get(1)?,
                    out: row.get(2)?,
                })
            })
            .map_err(|e| prefs_db_err(&e))?;
        let mut recent = Vec::new();
        for row in rows {
            recent.push(row.map_err(|e| prefs_db_err(&e))?);
        }
        Ok(DeployPrefs { recent })
    }

    /// Replaces the remembered contexts (one transaction).
    pub fn save_deploy(&mut self, prefs: &DeployPrefs) -> Result<()> {
        let tx = self.conn.transaction().map_err(|e| prefs_db_err(&e))?;
        tx.execute("DELETE FROM deploy_recent", [])
            .map_err(|e| prefs_db_err(&e))?;
        insert_deploy(&tx, prefs)?;
        tx.commit().map_err(|e| prefs_db_err(&e))?;
        Ok(())
    }

    /// The GUI-wide settings; any read failure is the defaults (language
    /// must never block the GUI from coming up).
    pub fn gui(&self) -> GuiPrefs {
        self.gui_checked().unwrap_or_default()
    }

    fn gui_checked(&self) -> Result<GuiPrefs> {
        let language = read_gui_key(&self.conn, "language")?;
        let current = read_gui_key(&self.conn, "current_deployment")?;
        Ok(GuiPrefs {
            language: match language.as_deref() {
                Some("zh") => Lang::Zh,
                _ => Lang::En,
            },
            current_deployment: current,
        })
    }

    /// Persists the GUI-wide settings (one transaction, per-key upsert).
    pub fn save_gui(&mut self, prefs: &GuiPrefs) -> Result<()> {
        let tx = self.conn.transaction().map_err(|e| prefs_db_err(&e))?;
        insert_gui(&tx, prefs)?;
        tx.commit().map_err(|e| prefs_db_err(&e))?;
        Ok(())
    }
}

fn read_gui_key(conn: &Connection, key: &str) -> Result<Option<String>> {
    let mut stmt = conn
        .prepare("SELECT value FROM gui WHERE key = ?1")
        .map_err(|e| prefs_db_err(&e))?;
    match stmt.query_row([key], |row| row.get::<_, String>(0)) {
        Ok(value) => Ok(Some(value)),
        Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
        Err(e) => Err(prefs_db_err(&e)),
    }
}

/// One `nodes` row between storage and [`NodeEntry`].
struct NodeRow {
    id: String,
    pack_dir: String,
    transport: Option<String>,
    hub_quic_addr: Option<String>,
    service_addresses: String,
    desired_running: bool,
}

impl NodeRow {
    fn into_entry(self, base: &Path) -> Result<NodeEntry> {
        let service_addresses: Vec<ServiceAddressPref> =
            serde_json::from_str(&self.service_addresses).map_err(|e| {
                InterflowError::config("prefs db: malformed service_addresses").with_source(e)
            })?;
        let transport = self.transport.map(|raw| match raw.as_str() {
            "h2" => Ok(interflow_mesh::config::TransportKind::H2),
            "quic" => Ok(interflow_mesh::config::TransportKind::Quic),
            other => Err(InterflowError::config(format!(
                "prefs db: unknown transport {other:?}"
            ))),
        });
        let transport = transport.transpose()?;
        Ok(NodeEntry {
            id: self.id,
            pack_dir: anchor(base, &self.pack_dir),
            transport,
            hub_quic_addr: self.hub_quic_addr,
            service_addresses,
            desired_running: self.desired_running,
        })
    }
}

fn insert_nodes(tx: &rusqlite::Transaction<'_>, nodes: &[NodeEntry]) -> Result<()> {
    for (ord, node) in nodes.iter().enumerate() {
        let transport = node.transport.map(|kind| match kind {
            interflow_mesh::config::TransportKind::H2 => "h2".to_string(),
            interflow_mesh::config::TransportKind::Quic => "quic".to_string(),
        });
        let service_addresses = serde_json::to_string(&node.service_addresses)
            .map_err(|e| InterflowError::config("service-address serialization").with_source(e))?;
        tx.execute(
            "INSERT INTO nodes (ord, id, pack_dir, transport, hub_quic_addr, \
             service_addresses, desired_running) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            rusqlite::params![
                i64::try_from(ord).unwrap_or(i64::MAX),
                node.id,
                node.pack_dir,
                transport,
                node.hub_quic_addr,
                service_addresses,
                node.desired_running
            ],
        )
        .map_err(|e| prefs_db_err(&e))?;
    }
    Ok(())
}

fn insert_deploy(tx: &rusqlite::Transaction<'_>, prefs: &DeployPrefs) -> Result<()> {
    for (ord, context) in prefs.recent.iter().enumerate() {
        tx.execute(
            "INSERT INTO deploy_recent (ord, manifest, issuer, out) VALUES (?1, ?2, ?3, ?4)",
            rusqlite::params![
                i64::try_from(ord).unwrap_or(i64::MAX),
                context.manifest,
                context.issuer,
                context.out
            ],
        )
        .map_err(|e| prefs_db_err(&e))?;
    }
    Ok(())
}

fn insert_gui(tx: &rusqlite::Transaction<'_>, prefs: &GuiPrefs) -> Result<()> {
    let language = match prefs.language {
        Lang::En => "en",
        Lang::Zh => "zh",
    };
    tx.execute(
        "INSERT INTO gui (key, value) VALUES ('language', ?1)
         ON CONFLICT(key) DO UPDATE SET value = excluded.value",
        [language],
    )
    .map_err(|e| prefs_db_err(&e))?;
    match &prefs.current_deployment {
        Some(current) => {
            tx.execute(
                "INSERT INTO gui (key, value) VALUES ('current_deployment', ?1)
                 ON CONFLICT(key) DO UPDATE SET value = excluded.value",
                [current],
            )
            .map_err(|e| prefs_db_err(&e))?;
        }
        None => {
            tx.execute("DELETE FROM gui WHERE key = 'current_deployment'", [])
                .map_err(|e| prefs_db_err(&e))?;
        }
    }
    Ok(())
}

fn restrict_to_owner(path: &Path) {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if let Ok(perms) = std::fs::metadata(path) {
            let mut perms = perms.permissions();
            perms.set_mode(0o600);
            let _ = std::fs::set_permissions(path, perms);
        }
    }
    #[cfg(not(unix))]
    {
        let _ = path;
    }
}

fn prefs_db_err(e: &rusqlite::Error) -> InterflowError {
    InterflowError::config(format!("prefs db: {e}"))
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use crate::deploy_prefs::DeployContext;
    use interflow_mesh::config::TransportKind;

    fn db_in(dir: &Path) -> PrefsDb {
        PrefsDb::open_at(&dir.join("prefs.db")).unwrap()
    }

    fn node(id: &str, pack_dir: &str, running: bool) -> NodeEntry {
        NodeEntry {
            id: id.into(),
            pack_dir: pack_dir.into(),
            transport: None,
            hub_quic_addr: None,
            service_addresses: Vec::new(),
            desired_running: running,
        }
    }

    /// A fresh open creates the db at the current shape; reopening sees the
    /// same shape without touching anything.
    #[test]
    fn fresh_open_creates_current_shape() {
        let dir = tempfile::tempdir().unwrap();
        {
            let db = db_in(dir.path());
            assert_eq!(db.nodes().unwrap(), Vec::new());
        }
        let conn = Connection::open(dir.path().join("prefs.db")).unwrap();
        let shape: i32 = conn
            .query_row("PRAGMA user_version", [], |row| row.get(0))
            .unwrap();
        assert_eq!(shape, SHAPE);
        // Reopen: still empty, still current.
        assert_eq!(db_in(dir.path()).nodes().unwrap(), Vec::new());
    }

    /// Nodes round-trip with order and every field, including the optional
    /// transport and per-service address preferences.
    #[test]
    fn nodes_round_trip_all_fields() {
        let dir = tempfile::tempdir().unwrap();
        let mut db = db_in(dir.path());
        let nodes = vec![
            NodeEntry {
                id: "id-a".into(),
                pack_dir: "/packs/hub-central".into(),
                transport: None,
                hub_quic_addr: None,
                service_addresses: Vec::new(),
                desired_running: true,
            },
            NodeEntry {
                id: "id-b".into(),
                pack_dir: "/packs/agent-lan-a".into(),
                transport: Some(TransportKind::Quic),
                hub_quic_addr: Some("hub.example.com:16666".into()),
                service_addresses: vec![ServiceAddressPref {
                    id: "web".into(),
                    address: "127.0.0.1:5173".into(),
                }],
                desired_running: false,
            },
        ];
        db.save_nodes(&nodes).unwrap();
        assert_eq!(db_in(dir.path()).nodes().unwrap(), nodes);
    }

    /// A relative `pack_dir` anchors to the db's directory on load (the
    /// legacy files anchored to their own directory — the same directory).
    #[test]
    fn relative_pack_dir_anchors_to_db_dir() {
        let dir = tempfile::tempdir().unwrap();
        let mut db = db_in(dir.path());
        db.save_nodes(&[node("id", "packs/agent-x", false)])
            .unwrap();
        let loaded = db_in(dir.path()).nodes().unwrap();
        assert_eq!(loaded[0].pack_dir, anchor(dir.path(), "packs/agent-x"));
    }

    /// The regression the three workaround files existed for: a node-list
    /// save must not disturb the other domains' rows.
    #[test]
    fn domains_do_not_clobber_each_other() {
        let dir = tempfile::tempdir().unwrap();
        let mut db = db_in(dir.path());
        db.save_gui(&GuiPrefs {
            language: Lang::Zh,
            current_deployment: Some("/deployments/prod".into()),
        })
        .unwrap();
        db.save_deploy(&DeployPrefs {
            recent: vec![DeployContext {
                manifest: "/m".into(),
                issuer: "/i".into(),
                out: "/o".into(),
            }],
        })
        .unwrap();
        db.save_nodes(&[node("id", "/p", true)]).unwrap();
        let db = db_in(dir.path());
        assert_eq!(db.gui().language, Lang::Zh);
        assert_eq!(
            db.gui().current_deployment.as_deref(),
            Some("/deployments/prod")
        );
        assert_eq!(db.deploy().recent.len(), 1);
        assert_eq!(db.nodes().unwrap().len(), 1);
    }

    /// Saving the whole node list replaces it (removals stick), and
    /// clearing `current_deployment` deletes the key rather than leaving a
    /// stale value behind.
    #[test]
    fn saves_replace_and_clear() {
        let dir = tempfile::tempdir().unwrap();
        let mut db = db_in(dir.path());
        db.save_nodes(&[node("a", "/a", false), node("b", "/b", false)])
            .unwrap();
        db.save_nodes(&[node("a", "/a", false)]).unwrap();
        assert_eq!(
            db.nodes().unwrap(),
            vec![node("a", "/a", false)],
            "removed node stays removed"
        );
        db.save_gui(&GuiPrefs {
            language: Lang::En,
            current_deployment: None,
        })
        .unwrap();
        assert_eq!(db_in(dir.path()).gui().current_deployment, None);
    }

    #[test]
    fn newer_shape_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        {
            let conn = Connection::open(dir.path().join("prefs.db")).unwrap();
            conn.execute_batch(
                "CREATE TABLE gui (key TEXT PRIMARY KEY, value TEXT NOT NULL);
                 PRAGMA user_version = 99;",
            )
            .unwrap();
        }
        let err = PrefsDb::open_at(&dir.path().join("prefs.db")).unwrap_err();
        assert!(
            err.to_string().contains("different GUI generation"),
            "wrong error: {err}"
        );
    }
}
