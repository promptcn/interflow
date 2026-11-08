//! `PausedStreams`: the agent's pause-intent truth for ingress streams —
//! the stream-level half of "planned unavailability"
//!
//! A paused stream's listener is deliberately down and its port
//! deliberately free (the 127.0.0.1:11434 case: lending the port to a
//! local process without taking the whole node — or the whole fleet —
//! offline). The intent is INTENTIONAL and indefinite: it persists
//! across agent restarts (a restart must not quietly re-grab the port;
//! that would be the real surprise) and only an explicit resume ever
//! lifts it. Persistence lands in the pack's `state/` directory, whose
//! lifecycle is exactly the ruling's: kept across restarts and
//! same-node upgrades, absent from a fresh install (a re-provisioned
//! node is a new intent).
//!
//! Layer discipline: this is the layer BELOW `desired_running` — pausing
//! a stream never stops the unit, and stopping the unit never implies a
//! resume. It is also below the signed policy: the pause set is a
//! node-local, reversible suppression of rules the policy already
//! derives (a policy reload replaces rules by name; a re-added name
//! stays paused — the intent is keyed to the name, and pruning it on
//! reload would be a surprise of its own).
//!
//! The store is agent-scoped (survives session rebuilds like
//! [`IngressAddrs`](crate::agent::ingress_addrs::IngressAddrs)); the
//! reconciler filters its desired face through
//! [`PausedStreams::is_paused`] and re-derives level-triggered off the
//! version watch — the same contract [`RuleStore`] offers.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::Mutex;
use tokio::sync::watch;
use tracing::{info, warn};

/// The persisted file name under the pack's `state/` directory.
const FILE_NAME: &str = "paused_streams.json";

/// The persisted shape. `format_version` guards future edits; unknown
/// future shapes parse fail-open (see [`PausedStreams::load`]).
#[derive(serde::Serialize, serde::Deserialize)]
struct PausedFile {
    format_version: u32,
    #[serde(default)]
    paused: BTreeSet<String>,
}

/// The agent's paused-stream set: in-memory truth + optional `state/`
/// persistence + a version watch for level-triggered reconcile.
#[derive(Debug)]
pub struct PausedStreams {
    inner: Mutex<BTreeSet<String>>,
    /// Bumped on every mutation so the reconciler re-derives (same
    /// contract as `RuleStore::version_rx`).
    version: watch::Sender<u64>,
    /// Log attribution (`AgentInfo::effective_log_name`).
    node: String,
    /// `<pack>/state/paused_streams.json` (`None` = this agent has no
    /// pack state channel; the set lives exactly as long as the process).
    persist: Option<PathBuf>,
}

impl PausedStreams {
    /// Loads the persisted set (when a state directory is given) and
    /// returns the store. A malformed file warns and fails OPEN (empty
    /// set): a corrupt file names nothing, so there is nothing to pause
    /// either — but the warning must be loud, because an operator who
    /// paused a port will see it serving again.
    pub fn load(state_dir: Option<&Path>, node: &str) -> Arc<Self> {
        let persist = state_dir.map(|dir| dir.join(FILE_NAME));
        let mut loaded = BTreeSet::new();
        if let Some(path) = &persist
            && let Ok(raw) = std::fs::read_to_string(path)
        {
            match serde_json::from_str::<PausedFile>(&raw) {
                Ok(file) if file.format_version == 1 => loaded = file.paused,
                Ok(other) => warn!(
                    node,
                    path = %path.display(),
                    version = other.format_version,
                    "paused-streams file has an unknown format version — starting unpaused (fail-open)"
                ),
                Err(e) => warn!(
                    node,
                    path = %path.display(),
                    error = %e,
                    "paused-streams file is unreadable — starting unpaused (fail-open)"
                ),
            }
        }
        if !loaded.is_empty() {
            info!(
                node,
                count = loaded.len(),
                "restored paused-stream intent from the pack state channel"
            );
        }
        let (version, _) = watch::channel(0);
        Arc::new(Self {
            inner: Mutex::new(loaded),
            version,
            node: node.to_string(),
            persist,
        })
    }

    fn bump(&self) {
        self.version.send_modify(|v| *v = v.wrapping_add(1));
    }

    /// Subscribe to change notifications (the reconciler's wake-up).
    pub fn version_rx(&self) -> watch::Receiver<u64> {
        self.version.subscribe()
    }

    /// Whether the named stream is paused.
    pub fn is_paused(&self, name: &str) -> bool {
        self.inner
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .contains(name)
    }

    /// The paused names, sorted (the wire form of the set).
    pub fn snapshot(&self) -> Vec<String> {
        self.inner
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .iter()
            .cloned()
            .collect()
    }

    /// Pause a stream (idempotent: pausing an already-paused name is a
    /// quiet no-op — "what state is this in?" must never be an anxiety).
    /// Returns whether the set changed.
    pub fn pause(&self, name: &str) -> bool {
        self.mutate(name, Op::Pause)
    }

    /// Resume a stream (idempotent, and the ONLY unpause).
    pub fn resume(&self, name: &str) -> bool {
        self.mutate(name, Op::Resume)
    }

    fn mutate(&self, name: &str, op: Op) -> bool {
        let changed = {
            let mut set = self
                .inner
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            match op {
                Op::Pause => set.insert(name.to_string()),
                Op::Resume => set.remove(name),
            }
        };
        if !changed {
            return false;
        }
        self.persist();
        self.bump();
        info!(target: "audit", node = %self.node, stream = name, "{}", match op {
            Op::Pause => "stream pause intent recorded",
            Op::Resume => "stream resume intent recorded",
        });
        true
    }

    /// Best-effort persistence: the in-memory truth still governs this
    /// run even when the disk write fails (warned once per failure, the
    /// operator's doctor faces will show the divergence).
    fn persist(&self) {
        let Some(path) = &self.persist else { return };
        let file = PausedFile {
            format_version: 1,
            paused: self
                .inner
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .clone(),
        };
        let bytes = match serde_json::to_vec_pretty(&file) {
            Ok(bytes) => bytes,
            Err(e) => {
                warn!(node = %self.node, error = %e, "paused-streams encode failed (intent kept in memory only)");
                return;
            }
        };
        if let Some(dir) = path.parent()
            && let Err(e) = std::fs::create_dir_all(dir)
        {
            warn!(node = %self.node, path = %path.display(), error = %e, "paused-streams state dir unavailable (intent kept in memory only)");
            return;
        }
        if let Err(e) = interflow_util::atomic_write::atomic_write(
            path,
            &bytes,
            interflow_util::atomic_write::WriteMode::PreserveOr(0o644),
        ) {
            warn!(node = %self.node, path = %path.display(), error = %e, "paused-streams persist failed (intent kept in memory only)");
        }
    }
}

#[derive(Clone, Copy)]
enum Op {
    Pause,
    Resume,
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

    #[test]
    fn pause_resume_is_idempotent_and_bumps_only_on_change() {
        let store = PausedStreams::load(None, "node");
        assert!(store.pause("s1"));
        assert!(!store.pause("s1"), "double pause is a quiet no-op");
        assert!(store.is_paused("s1"));
        assert!(
            !store.resume("ghost"),
            "resuming an unpaused name is a no-op"
        );
        assert!(store.resume("s1"));
        assert!(!store.resume("s1"));
        assert_eq!(store.snapshot(), Vec::<String>::new());
    }

    #[test]
    fn snapshot_is_sorted_and_round_trips_through_disk() {
        let dir = tempfile::tempdir().unwrap();
        let store = PausedStreams::load(Some(dir.path()), "node");
        store.pause("b");
        store.pause("a");
        assert_eq!(store.snapshot(), vec!["a".to_string(), "b".to_string()]);

        // A fresh store over the same state dir restores the intent.
        let reloaded = PausedStreams::load(Some(dir.path()), "node");
        assert_eq!(reloaded.snapshot(), vec!["a".to_string(), "b".to_string()]);
        // Resume persists too: the next load starts unpaused.
        reloaded.resume("a");
        reloaded.resume("b");
        assert_eq!(
            PausedStreams::load(Some(dir.path()), "node").snapshot(),
            Vec::<String>::new()
        );
    }

    #[test]
    fn ghost_names_survive_and_clear_on_resume() {
        let store = PausedStreams::load(None, "node");
        store.pause("not-in-policy");
        assert!(store.is_paused("not-in-policy"));
        assert!(store.resume("not-in-policy"));
    }

    #[test]
    fn malformed_file_fails_open_with_empty_set() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join(FILE_NAME), "not json").unwrap();
        let store = PausedStreams::load(Some(dir.path()), "node");
        assert_eq!(store.snapshot(), Vec::<String>::new());
        // And the store still works for new intents (the next persist
        // rewrites the file into a valid shape).
        store.pause("s");
        assert!(PausedStreams::load(Some(dir.path()), "node").is_paused("s"));
    }

    #[tokio::test]
    async fn version_watch_fires_on_mutation_only() {
        let store = PausedStreams::load(None, "node");
        let mut rx = store.version_rx();
        store.pause("s");
        assert!(rx.changed().await.is_ok());
        rx.borrow_and_update();
        assert!(!store.pause("s"), "the no-op must report no change");
        assert!(
            !rx.has_changed().unwrap_or(false),
            "a no-op pause must not wake the reconciler"
        );
    }
}
