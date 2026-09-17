//! Deterministic fault injection for self-healing verification.
//!
//! The supervision layers (session-task death contract, stall heartbeats,
//! supervisor rebuild) exist to make *any* abnormal task exit recoverable.
//! Ordinary tests cannot produce such exits on demand — dependency panics and
//! wedged futures are bugs, not schedulable events — so the self-healing
//! tests inject them through these call points.
//!
//! Everything is gated by the `fault-injection` cargo feature:
//! - feature **off** (production builds): [`trigger`] and [`stall`] compile
//!   to no-ops and no hook can even be installed — zero cost, zero surface;
//! - feature **on** (tests via the testkit dev-dependency, soak via
//!   [`install_from_env`]): call points consult the installed [`Hook`].
//!
//! [`trigger`] panics with [`FaultPanic`] as the payload (through
//! `std::panic::panic_any` — a function call, not the `panic!` macro, so the
//! workspace `clippy::panic = "deny"` contract holds). [`stall`] reports
//! whether the call point should park forever, modeling a *wedged* task:
//! alive, but no longer progressing — the failure class that death-based
//! supervision (JoinError) cannot see.

#[cfg(feature = "fault-injection")]
use std::collections::HashMap;
use std::sync::Arc;
#[cfg(feature = "fault-injection")]
use std::sync::{Mutex, RwLock};

/// One variant per supervision scenario under test. Kept in this crate (the
/// workspace bottom) so both mesh- and core-level call points share one enum.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum FaultPoint {
    /// Panic in `run_session`'s own frame right after registration succeeds
    /// (session children already spawned — the leak/zombie scenario).
    AgentSessionAfterRegister,
    /// Panic in the supervisor loop's own frame (the outermost in-process
    /// layer; recovery belongs to the embedder, not the library).
    AgentSuperviseLoopTick,
    /// Panic in the h2 upload loop right after a round establishes.
    H2UploadLoopAfterEstablish,
    /// Panic in the h2 poll loop right after connecting to the hub.
    H2PollLoopAfterConnect,
    /// Wedge (park forever) the h2 upload loop right after a round
    /// establishes — the channel stays alive, so sends buffer as fake
    /// successes; only a stall heartbeat can catch this.
    H2UploadLoopStall,
    /// Panic in the QUIC control-stream read loop after registration.
    QuicControlReadLoop,
    /// Panic in the QUIC accept loop after registration.
    QuicAcceptLoop,
    /// Panic in the QUIC connection closed-watcher.
    QuicClosedWatcher,
    /// Wedge (park forever) the QUIC control-stream write forwarder after
    /// registration (Pong path dead while the connection stays healthy).
    QuicControlWriteStall,
}

impl FaultPoint {
    /// Parses a plan entry key (variant name, case-insensitive). Used by
    /// [`install_from_env`]; unknown names are rejected so a typo'd soak
    /// config fails loudly instead of silently testing nothing.
    #[cfg(feature = "fault-injection")]
    fn from_name(name: &str) -> Option<Self> {
        Some(match name.trim().to_ascii_lowercase().as_str() {
            "agentsessionafterregister" => Self::AgentSessionAfterRegister,
            "agentsuperviselooptick" => Self::AgentSuperviseLoopTick,
            "h2uploadloopafterestablish" => Self::H2UploadLoopAfterEstablish,
            "h2pollloopafterconnect" => Self::H2PollLoopAfterConnect,
            "h2uploadloopstall" => Self::H2UploadLoopStall,
            "quiccontrolreadloop" => Self::QuicControlReadLoop,
            "quicacceptloop" => Self::QuicAcceptLoop,
            "quicclosedwatcher" => Self::QuicClosedWatcher,
            "quiccontrolwritestall" => Self::QuicControlWriteStall,
            _ => return None,
        })
    }
}

/// What the installed plan wants at a triggered call point.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FaultAction {
    /// No fault: the default whenever no hook is installed (and always when
    /// the feature is off).
    Continue,
    /// Panic at the call point; [`FaultPanic`] is the payload.
    Panic,
    /// Park the call point forever (wedged-task model).
    Stall,
}

/// Panic payload carried by [`trigger`]; tests and logs downcast to this to
/// distinguish injected faults from real bugs.
#[derive(Debug)]
pub struct FaultPanic {
    /// The injection point that fired.
    pub point: FaultPoint,
}

/// Decision hook: consulted once per [`trigger`]/[`stall`] call.
pub type Hook = Arc<dyn Fn(FaultPoint) -> FaultAction + Send + Sync + 'static>;

#[cfg(feature = "fault-injection")]
static HOOK: RwLock<Option<Hook>> = RwLock::new(None);

/// Installs (replaces) the decision hook. Replacable rather than OnceLock
/// because one test binary hosts many serial test cases, each with its own
/// plan.
///
/// Does not exist when the feature is off.
#[cfg(feature = "fault-injection")]
pub fn install_hook(hook: Hook) {
    let mut slot = HOOK.write().expect("fault hook lock poisoned");
    *slot = Some(hook);
}

/// Removes any installed hook (test teardown / "faults off" phases).
#[cfg(feature = "fault-injection")]
pub fn clear_hook() {
    let mut slot = HOOK.write().expect("fault hook lock poisoned");
    *slot = None;
}

fn action(point: FaultPoint) -> FaultAction {
    #[cfg(feature = "fault-injection")]
    if let Some(hook) = HOOK.read().expect("fault hook lock poisoned").as_ref() {
        return hook(point);
    }
    #[cfg(not(feature = "fault-injection"))]
    let _ = point;
    FaultAction::Continue
}

/// Fires a panic-class fault point: when the installed plan targets `point`,
/// panics with [`FaultPanic`]; otherwise returns immediately.
// The workspace denies panics in production code; this is the single
// deliberate exception — fault injection whose whole purpose is to panic,
// feature-gated so release builds never compile it.
#[allow(clippy::panic)]
#[inline]
pub fn trigger(point: FaultPoint) {
    if action(point) == FaultAction::Panic {
        std::panic::panic_any(FaultPanic { point });
    }
}

/// Reports whether a stall-class call point should park forever.
#[inline]
pub fn stall(point: FaultPoint) -> bool {
    action(point) == FaultAction::Stall
}

/// Installs a once-each plan from an env var (soak gate driver for the real
/// release binaries, which cannot link the testkit).
///
/// Format: comma-separated `Point=action[*repeat]`, e.g.
/// `H2UploadLoopAfterEstablish=panic,H2UploadLoopStall=stall*2`.
/// Unknown points or actions fail the install (returns `false` after logging)
/// so a typo'd config makes the caller fail loudly instead of silently
/// testing nothing. Every fired fault is logged at WARN — the soak-visible
/// evidence.
///
/// Returns whether a non-empty valid plan was installed; `false` (and a WARN)
/// when the var is set but the feature is off.
pub fn install_from_env(var: &str) -> bool {
    #[cfg(feature = "fault-injection")]
    {
        let Some(raw) = std::env::var(var).ok().filter(|v| !v.trim().is_empty()) else {
            return false;
        };
        let plan = match parse_plan(&raw) {
            Ok(p) => Arc::new(Mutex::new(p)),
            Err(e) => {
                tracing::error!("fault plan in {var} is invalid ({e}); not installed");
                return false;
            }
        };
        let installed: Vec<FaultPoint> = plan
            .lock()
            .expect("fault plan lock poisoned")
            .keys()
            .copied()
            .collect();
        install_hook(Arc::new(move |point: FaultPoint| {
            let mut guard = plan.lock().expect("fault plan lock poisoned");
            let Some(entry) = guard.get_mut(&point) else {
                return FaultAction::Continue;
            };
            if entry.remaining == 0 {
                return FaultAction::Continue;
            }
            entry.remaining -= 1;
            let act = entry.action;
            drop(guard);
            tracing::warn!("fault injected: {point:?} ({act:?})");
            act
        }));
        tracing::warn!("fault plan installed from {var}: {installed:?}");
        true
    }
    #[cfg(not(feature = "fault-injection"))]
    {
        if std::env::var(var).is_ok_and(|v| !v.trim().is_empty()) {
            tracing::warn!("{var} is set but this build has fault-injection disabled; ignoring");
        }
        false
    }
}

/// One plan entry: action plus how many times it may still fire.
#[cfg(feature = "fault-injection")]
#[derive(Debug, Clone, Copy)]
struct PlanEntry {
    action: FaultAction,
    remaining: u32,
}

#[cfg(feature = "fault-injection")]
fn parse_plan(raw: &str) -> Result<HashMap<FaultPoint, PlanEntry>, String> {
    let mut plan = HashMap::new();
    for entry in raw.split(',') {
        let entry = entry.trim();
        if entry.is_empty() {
            continue;
        }
        let (name, spec) = entry
            .split_once('=')
            .ok_or_else(|| format!("'{entry}' lacks =action"))?;
        let (action_name, repeat) = match spec.split_once('*') {
            Some((a, n)) => (
                a,
                n.parse::<u32>()
                    .map_err(|e| format!("bad repeat in '{entry}': {e}"))?,
            ),
            None => (spec, 1),
        };
        let action = match action_name.trim() {
            "panic" => FaultAction::Panic,
            "stall" => FaultAction::Stall,
            other => return Err(format!("unknown action '{other}' in '{entry}'")),
        };
        let point = FaultPoint::from_name(name).ok_or_else(|| format!("unknown point '{name}'"))?;
        plan.insert(
            point,
            PlanEntry {
                action,
                remaining: repeat.max(1),
            },
        );
    }
    if plan.is_empty() {
        return Err("empty plan".into());
    }
    Ok(plan)
}

// The hook is process-global; the lifecycle tests share one #[test] so they
// cannot race each other under the default parallel test runner.
#[cfg(all(test, feature = "fault-injection"))]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    #[test]
    fn plan_parsing_roundtrip() {
        let plan = parse_plan(" H2UploadLoopStall=stall*3 ,QuicAcceptLoop=panic ").unwrap();
        assert_eq!(plan[&FaultPoint::H2UploadLoopStall].remaining, 3);
        assert_eq!(
            plan[&FaultPoint::H2UploadLoopStall].action,
            FaultAction::Stall
        );
        assert_eq!(plan[&FaultPoint::QuicAcceptLoop].action, FaultAction::Panic);
        assert_eq!(plan[&FaultPoint::QuicAcceptLoop].remaining, 1);
    }

    #[test]
    fn plan_parsing_rejects_unknowns() {
        assert!(parse_plan("NotAPoint=panic").is_err());
        assert!(parse_plan("QuicAcceptLoop=explode").is_err());
        assert!(parse_plan("").is_err());
        assert!(parse_plan("   ").is_err());
    }

    #[test]
    fn hook_lifecycle_is_inert_without_install() {
        clear_hook();
        trigger(FaultPoint::AgentSessionAfterRegister);
        assert!(!stall(FaultPoint::H2UploadLoopStall));

        // A counting hook counting only QuicClosedWatcher consults: one from
        // the trigger, none from the other point's stall check, and none at
        // all anymore after clear.
        let calls = Arc::new(AtomicUsize::new(0));
        let c = calls.clone();
        install_hook(Arc::new(move |p| {
            if p == FaultPoint::QuicClosedWatcher {
                c.fetch_add(1, Ordering::SeqCst);
            }
            FaultAction::Continue
        }));
        trigger(FaultPoint::QuicClosedWatcher);
        assert_eq!(calls.load(Ordering::SeqCst), 1);
        assert!(!stall(FaultPoint::H2UploadLoopStall));
        assert_eq!(calls.load(Ordering::SeqCst), 1);

        clear_hook();
        trigger(FaultPoint::QuicClosedWatcher);
        assert_eq!(calls.load(Ordering::SeqCst), 1);
    }
}
