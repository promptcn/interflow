//! The hub's node-level maintenance declarations — the node half of
//! "planned unavailability"
//!
//! Semantics (expected-type, the mirror image of the stream pause's
//! intentional type): "I EXPECT this leg to be down; do not read its
//! absence as an accident." Declared hub-side (the node may already be
//! offline when the operator declares), PERSISTED in the hub's own state
//! channel (`<pack>/state/maintenance.json`, the proposals.json shape) —
//! a maintenance window may outlive a hub restart, and losing the
//! declaration mid-window would fire the very signals it exists to
//! suppress. Lifted two ways: by the operator (`maintenance off`), or
//! AUTOMATICALLY when the node rejoins (re-registration — the expected
//! condition came true; zero-operation recovery, no residual exemption to
//! remember).
//!
//! What the declaration exempts: eviction ACCOUNTING (the removal funnel
//! still cleans up the registry entry — the offline fact stands — but
//! `evicted_total` and the eviction metric do not move; the
//! voided-eviction discipline applied to planned absence) and the
//! heartbeat death window (a session under maintenance is not evicted
//! for going quiet — it is expected to). What it never exempts: a
//! `credential_revoked` removal (a security event outranks an ops
//! window). A stale declaration on a node that never went down is inert
//! while its session lives (heartbeats keep it online) and visible as a
//! yellow face — `maintenance off` is the explicit exit.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::Mutex;

use interflow_core::error::{InterflowError, Result};
use tracing::{info, warn};

/// The persisted file name under the hub pack's `state/` directory.
const FILE_NAME: &str = "maintenance.json";

/// The persisted shape.
#[derive(serde::Serialize, serde::Deserialize)]
struct MaintenanceFile {
    format_version: u32,
    /// Qualified agent id → declared-at unix seconds.
    #[serde(default)]
    under: BTreeMap<String, u64>,
}

/// The hub's maintenance ledger.
#[derive(Debug)]
pub struct MaintenanceLedger {
    inner: Mutex<BTreeMap<String, u64>>,
    /// `<pack>/state/maintenance.json` (`None` = no pack state channel;
    /// declarations live exactly as long as the hub process — e2e hubs).
    persist: Option<PathBuf>,
    /// The floor version clock: bumped when a declaration actually lands
    /// or lifts (the face is floor-visible; idempotent re-declares do not
    /// tick it).
    floor: crate::hub::floor_clock::FloorClock,
}

impl MaintenanceLedger {
    /// Loads the persisted declarations (when a state directory is given).
    /// A malformed file warns and starts empty: declarations are
    /// re-issuable in one command, so a fresh ledger is a safe default —
    /// but the warning must be loud, because an in-force window would
    /// stop exempting.
    pub fn load(state_dir: Option<&Path>, floor: crate::hub::floor_clock::FloorClock) -> Arc<Self> {
        let persist = state_dir.map(|dir| dir.join(FILE_NAME));
        let mut loaded = BTreeMap::new();
        if let Some(path) = &persist
            && let Ok(raw) = std::fs::read_to_string(path)
        {
            match serde_json::from_str::<MaintenanceFile>(&raw) {
                Ok(file) if file.format_version == 1 => loaded = file.under,
                Ok(other) => warn!(
                    path = %path.display(),
                    version = other.format_version,
                    "maintenance ledger has an unknown format version — starting with no declarations"
                ),
                Err(e) => warn!(
                    path = %path.display(),
                    error = %e,
                    "maintenance ledger unreadable — starting with no declarations"
                ),
            }
        }
        if !loaded.is_empty() {
            info!(
                count = loaded.len(),
                "restored maintenance declarations from the hub state channel"
            );
        }
        Arc::new(Self {
            inner: Mutex::new(loaded),
            persist,
            floor,
        })
    }

    /// Declares `agent` under maintenance. Idempotent (re-declaring
    /// refreshes nothing and returns false — the declaration has no TTL
    /// to refresh). Returns whether the state changed.
    pub fn declare(&self, agent: &str) -> bool {
        self.mutate(agent, MaintenanceOp::Declare)
    }

    /// Lifts the declaration. Idempotent. Returns whether the state
    /// changed.
    pub fn lift(&self, agent: &str) -> bool {
        self.mutate(agent, MaintenanceOp::Lift)
    }

    /// Whether `agent` is currently declared under maintenance.
    pub fn is_under(&self, agent: &str) -> bool {
        self.inner
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .contains_key(agent)
    }

    /// The snapshot/overview face: every declaration with its
    /// declared-at time.
    pub fn face(&self) -> BTreeMap<String, u64> {
        self.inner
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone()
    }

    fn mutate(&self, agent: &str, op: MaintenanceOp) -> bool {
        let changed = {
            let mut inner = self
                .inner
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            match op {
                MaintenanceOp::Declare => inner
                    .insert(
                        agent.to_string(),
                        u64::try_from(interflow_identity::expiry::now_unix()).unwrap_or(0),
                    )
                    .is_none(),
                MaintenanceOp::Lift => inner.remove(agent).is_some(),
            }
        };
        if changed {
            self.persist();
            self.floor.bump();
        }
        changed
    }

    /// Best-effort persistence (the in-memory ledger still governs this
    /// run when the write fails; the warn carries the divergence).
    fn persist(&self) {
        let Some(path) = &self.persist else { return };
        let file = MaintenanceFile {
            format_version: 1,
            under: self
                .inner
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .clone(),
        };
        let bytes = match serde_json::to_vec_pretty(&file) {
            Ok(bytes) => bytes,
            Err(e) => {
                warn!(error = %e, "maintenance ledger encode failed (kept in memory only)");
                return;
            }
        };
        if let Some(dir) = path.parent()
            && let Err(e) = std::fs::create_dir_all(dir)
        {
            warn!(path = %path.display(), error = %e, "maintenance state dir unavailable (kept in memory only)");
            return;
        }
        if let Err(e) = interflow_util::atomic_write::atomic_write(
            path,
            &bytes,
            interflow_util::atomic_write::WriteMode::PreserveOr(0o644),
        ) {
            warn!(path = %path.display(), error = %e, "maintenance ledger persist failed (kept in memory only)");
        }
    }
}

#[derive(Clone, Copy)]
enum MaintenanceOp {
    Declare,
    Lift,
}

/// The rejoin hook: a node registering again has satisfied the
/// maintenance expectation ("this leg is down" ceased to be true), so the
/// declaration lifts itself — zero-operation recovery, no residual
/// exemption to remember. A no-op for nodes never declared.
pub(crate) fn auto_lift_on_rejoin(h: &crate::hub::state::HubState, agent: &str) {
    if h.maintenance.lift(agent) {
        h.audit.record(
            interflow_core::security::audit::AuditKind::MaintenanceLifted {
                agent: agent.to_string(),
                via: "node_rejoined".to_string(),
            },
            Some(agent.to_string()),
            None,
        );
        info!("{agent} rejoined — maintenance declaration lifted automatically");
    }
}

impl crate::hub::service::HubService {
    /// `POST /maintenance/{agent}/on|off` — the operator's declaration
    /// pair (control-principal gated). Idempotent: re-declaring or
    /// lifting an absent declaration answers "already" without error.
    pub(crate) async fn handle_maintenance(
        &self,
        agent: &str,
        on: bool,
    ) -> interflow_core::error::Result<hyper::Response<crate::hub::state::HubResponseBody>> {
        use hyper::StatusCode;
        let what = if on {
            "declare node maintenance"
        } else {
            "lift node maintenance"
        };
        if let Err(reason) = self.require_control(what).await {
            return Ok(crate::hub::service::json_response(
                StatusCode::FORBIDDEN,
                serde_json::json!({ "ok": false, "reason": reason }).to_string(),
            ));
        }
        let changed = if on {
            self.state.maintenance.declare(agent)
        } else {
            self.state.maintenance.lift(agent)
        };
        if changed {
            self.state.audit.record(
                if on {
                    interflow_core::security::audit::AuditKind::MaintenanceDeclared {
                        agent: agent.to_string(),
                    }
                } else {
                    interflow_core::security::audit::AuditKind::MaintenanceLifted {
                        agent: agent.to_string(),
                        via: "operator".to_string(),
                    }
                },
                Some("control".to_string()),
                None,
            );
        }
        let note = match (on, changed) {
            (true, true) => format!(
                "{agent} declared under maintenance — its absence is expected, not an accident; the declaration lifts automatically when the node rejoins"
            ),
            (true, false) => format!("{agent} is already under maintenance"),
            (false, true) => format!("{agent} left maintenance"),
            (false, false) => format!("{agent} was not under maintenance"),
        };
        Ok(crate::hub::service::json_response(
            StatusCode::OK,
            serde_json::json!({ "ok": true, "changed": changed, "note": note }).to_string(),
        ))
    }
}

// ---------------------------------------------------------------------------
// Operator-side client (the CLI / GUI Deploy face drive this with a
// minted control credential).
// ---------------------------------------------------------------------------

/// Sets or lifts a node's maintenance declaration.
pub async fn set_maintenance(
    hub_endpoint: &str,
    ca_path: &std::path::Path,
    client_cert_path: &std::path::Path,
    client_key_path: &std::path::Path,
    agent: &str,
    on: bool,
) -> Result<String> {
    let path = format!("/maintenance/{agent}/{}", if on { "on" } else { "off" });
    let future = async {
        use http_body_util::BodyExt as _;
        let mut send_request = crate::hub::policy::control_plane_dial(
            hub_endpoint,
            crate::hub::policy::ServerTrust::Ca(ca_path),
            client_cert_path,
            client_key_path,
        )
        .await?;
        let request = hyper::Request::builder()
            .method(hyper::Method::POST)
            .uri(path)
            .body(
                http_body_util::Full::<bytes::Bytes>::new(bytes::Bytes::new())
                    .map_err(|never| match never {})
                    .boxed(),
            )
            .map_err(|e| {
                InterflowError::protocol("maintenance request build".to_string()).with_source(e)
            })?;
        let response = send_request.send_request(request).await?;
        let status = response.status();
        let collected = http_body_util::Limited::new(response.into_body(), 64 * 1024)
            .collect()
            .await
            .map_err(|e| {
                InterflowError::protocol("maintenance response read failed".to_string())
                    .with_source(e)
            })?;
        let bytes = collected.to_bytes();
        if !status.is_success() {
            return Err(InterflowError::connection(format!(
                "maintenance call rejected: {status} — {}",
                String::from_utf8_lossy(&bytes)
            )));
        }
        let parsed: serde_json::Value = serde_json::from_slice(&bytes).map_err(|e| {
            InterflowError::protocol("maintenance answer is malformed".to_string()).with_source(e)
        })?;
        Ok(parsed
            .get("note")
            .and_then(|v| v.as_str())
            .unwrap_or_default()
            .to_string())
    };
    tokio::time::timeout(std::time::Duration::from_secs(10), future)
        .await
        .map_err(|_| {
            InterflowError::connection(
                "maintenance call timed out (>10s) — is the mesh hub reachable?".to_string(),
            )
        })?
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
    fn declare_and_lift_are_idempotent_and_round_trip() {
        let dir = tempfile::tempdir().unwrap();
        let clock = crate::hub::floor_clock::FloorClock::new();
        let ledger = MaintenanceLedger::load(Some(dir.path()), clock.clone());
        assert_eq!(clock.version(), 0);
        assert!(ledger.declare("t/a"));
        assert_eq!(clock.version(), 1, "a landed declaration moves the face");
        assert!(!ledger.declare("t/a"), "re-declare is a no-op");
        assert_eq!(
            clock.version(),
            1,
            "the idempotent no-op does not tick the clock"
        );
        assert!(ledger.is_under("t/a"));
        assert!(ledger.lift("t/a"));
        assert_eq!(clock.version(), 2);
        assert!(!ledger.lift("t/a"), "lift of an undeclared node is a no-op");
        assert_eq!(clock.version(), 2);
        assert!(!ledger.is_under("t/a"));

        // Persistence round trip.
        ledger.declare("t/b");
        let reloaded = MaintenanceLedger::load(Some(dir.path()), clock.clone());
        assert!(reloaded.is_under("t/b"));
        reloaded.lift("t/b");
        assert!(!MaintenanceLedger::load(Some(dir.path()), clock).is_under("t/b"));
    }

    #[test]
    fn malformed_file_fails_open_with_no_declarations() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join(FILE_NAME), "not json").unwrap();
        let ledger =
            MaintenanceLedger::load(Some(dir.path()), crate::hub::floor_clock::FloorClock::new());
        assert!(!ledger.is_under("t/a"));
        assert!(ledger.face().is_empty());
        // And new declarations rewrite a valid file.
        ledger.declare("t/a");
        assert!(
            MaintenanceLedger::load(Some(dir.path()), crate::hub::floor_clock::FloorClock::new())
                .is_under("t/a")
        );
    }
}
