//! The hub floor watcher — the deployment-scoped background task that
//! keeps the GUI's fleet read model honest about EXTERNAL writers
//!
//! The composed fleet (`fleet_overview`) is a pull over the hub's
//! `/policy/floor`; the hub carries no push channel of its own, so a
//! pause issued from a terminal, a maintenance declaration, or another
//! operator's publish would land in a view that never re-reads. The
//! watcher closes that gap within the push-not-poll contract: it holds
//! one blocking watch on the hub's floor VERSION (`GET
//! /policy/floor/version?since=N&wait_secs=S` — the invalidation signal,
//! not the payload), and on every advance emits [`contract::HubFloorEvent`]
//! — the frontend's deployment scope answers with one re-pull.
//!
//! Lifecycle: started when a deployment opens (and on the mount-restore
//! of a remembered one), stopped on close; a new start pre-empts the
//! previous task. Reachability: a failed cycle (hub down, dial error,
//! version skew against an older hub) backs off 3s → 30s and retries —
//! a hub that comes back answers the next cycle with a diverged version
//! (its in-memory clock resets on restart), so catch-up is one cycle,
//! never a missed change. A manifest that names no hub endpoint parks
//! the loop at the backoff cap (the manifest may gain one).

use tauri::AppHandle;

/// The hold each watch cycle asks the hub for (the server clamps at 30s;
/// the cycle's overall budget is this + dial margin, see
/// `watch_floor_version`).
const WATCH_WAIT_SECS: u64 = 25;
/// Reconnect backoff after a failed cycle; doubles to the cap, resets on
/// the first success.
const BACKOFF_START: std::time::Duration = std::time::Duration::from_secs(3);
const BACKOFF_CAP: std::time::Duration = std::time::Duration::from_secs(30);

/// The loop's advance decision, split out so tests pin the contract:
/// the watcher's `since` moves to the answer and emits exactly when the
/// two diverge (equality = the hold ran out unchanged; ANY divergence —
/// ahead or behind — is a change, which is what makes a hub restart
/// self-healing instead of wedging the watcher at a stale `since`).
const fn advance(since: u64, answer: u64) -> (u64, bool) {
    if answer == since {
        (since, false)
    } else {
        (answer, true)
    }
}

/// Emits one advance to the frontend (see [`contract::HubFloorEvent`]).
fn emit_hub_floor(app: &AppHandle, version: u64) {
    use tauri_specta::Event;
    let _ = crate::contract::HubFloorEvent {
        version: u32::try_from(version).unwrap_or(u32::MAX),
    }
    .emit(app);
}

/// Spawns the watcher task for one deployment's (manifest, issuer)
/// pair. Seeding `since = 0` makes the FIRST cycle answer immediately
/// (0 diverges from any live clock) — opening a deployment buys one
/// fresh floor read right away, which also surfaces whatever changed
/// while the app was closed. Cancelling (deployment switch/close) takes
/// effect between cycles; an in-flight blocking cycle finishes and its
/// result is dropped.
pub fn spawn_watcher(
    app: AppHandle,
    manifest: std::path::PathBuf,
    issuer: std::path::PathBuf,
) -> tauri::async_runtime::JoinHandle<()> {
    tauri::async_runtime::spawn(async move {
        let mut since = 0_u64;
        let mut backoff = BACKOFF_START;
        loop {
            // One cycle on the blocking pool: the CLI plumbing mints a
            // throwaway control credential per cycle (1h TTL, so nothing
            // outlives its credential) and drives the hold on a dedicated
            // thread — the async task never blocks.
            let manifest_arg = manifest.clone();
            let issuer_arg = issuer.clone();
            let cycle = tauri::async_runtime::spawn_blocking(move || {
                interflow_cli::plan::hub_floor_watch_cycle(
                    &manifest_arg,
                    &issuer_arg,
                    since,
                    WATCH_WAIT_SECS,
                )
            })
            .await;
            match cycle {
                Ok(Ok(Some(answer))) => {
                    let (next, changed) = advance(since, answer);
                    if changed {
                        tracing::debug!(node = "gui", "hub floor advanced {since} → {answer}");
                        emit_hub_floor(&app, answer);
                        since = next;
                    }
                    backoff = BACKOFF_START;
                }
                Ok(Ok(None)) => {
                    // The manifest names no hub endpoint — park at the cap
                    // and re-read it on the next pass (it may gain one).
                    tokio::time::sleep(BACKOFF_CAP).await;
                }
                Ok(Err(e)) => {
                    tracing::debug!(node = "gui", "hub floor watch cycle failed: {e}");
                    tokio::time::sleep(backoff).await;
                    backoff = (backoff * 2).min(BACKOFF_CAP);
                }
                Err(e) => {
                    tracing::debug!(node = "gui", "hub floor watch task join failed: {e}");
                    tokio::time::sleep(backoff).await;
                    backoff = (backoff * 2).min(BACKOFF_CAP);
                }
            }
        }
    })
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn advance_moves_and_emits_exactly_on_divergence() {
        // Unchanged hold: nothing to say.
        assert_eq!(advance(7, 7), (7, false));
        // Ahead: the ordinary advance.
        assert_eq!(advance(7, 9), (9, true));
        // Behind (a hub restart reset its clock): still a change — the
        // watcher must re-read, not wedge.
        assert_eq!(advance(7, 2), (2, true));
        // The seed: 0 against any live clock is an immediate advance.
        assert_eq!(advance(0, 0), (0, false));
        assert_eq!(advance(0, 1), (1, true));
    }
}
