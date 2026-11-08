//! The agent engine's per-rule byte-activity ledger — the node-side
//! half of the fossil-stream face
//!
//! A policy stream that is mounted, listener listening, but has not
//! carried a byte in days is invisible on every face: presence says
//! "rule exists", the counters say "nothing moved", and the cleanup
//! clue (the service is gone, the rule should be removed) lives only in
//! someone's memory. This ledger records, per stream rule, the last
//! instant any byte crossed the pump in either direction — one
//! `fetch_max` on a plain atomic at the pump's existing idle-deadline
//! reset points (no lock on the data-plane path) — and the node-status
//! reporter ships the levels to the hub
//! ([`crate::agent::node_status_report`]), where the fossil judgment
//! (`last_byte` quiet past a multiple of the rule's own idle budget)
//! renders.
//!
//! Baseline discipline: a rule's record is born at listener arm time
//! (the "mounted, listening, zero bytes so far" instant). A policy
//! reload re-arming the same rule KEEPS its history (the rule's age is
//! the story); only the budget anchor refreshes. Detection is
//! deliberate about NOT deleting: marking a fossil is an observation,
//! removing the rule is a policy-level operation on the plan-apply face.

use std::collections::BTreeMap;
use std::sync::Arc;
use std::sync::atomic::AtomicU64;

use interflow_core::tunnel::transport::NodeStreamActivity;

/// A budgeted stream reads fossil when quiet for STRICTLY more than
/// this multiple of its own `idle_timeout_secs`.
///
/// The per-row cadence anchor (10× a 300s budget ≈ 50 minutes of total
/// silence), so the judgment never hardcodes a rhythm the rule itself
/// does not set.
pub const FOSSIL_IDLE_MULTIPLE: u64 = 10;

/// A stream rule with NO idle budget (the e2e default) has no self-set
/// rhythm to anchor on; its fossil line is an absolute default.
///
/// 7 days, single-sourced here and self-reported through the GUI
/// classifier's overview fields.
pub const FOSSIL_UNBUDGETED_DAYS_SECS: u64 = 7 * 24 * 3600;
// Floor lock: the unbudgeted default never drops under a week (compile-time,
// so the lock holds in every build, not only under the test runner).
const _: () = assert!(FOSSIL_UNBUDGETED_DAYS_SECS >= 7 * 24 * 3600);

/// The fossil line for a budgeted rule: `budget × multiple` seconds of
/// total silence. Pure, shared by the hub-side band discipline and every
/// consumer's judgment.
pub const fn fossil_after_secs(budget_secs: u32, multiple: u64) -> u64 {
    budget_secs as u64 * multiple
}

/// The unix-seconds helper this module reads (one definition).
fn now_secs() -> u64 {
    u64::try_from(interflow_identity::expiry::now_unix()).unwrap_or(0)
}

/// One rule's retained record: the hot-path cell plus the budget anchor.
#[derive(Debug)]
struct RuleActivity {
    /// Millis since epoch of the last byte (or the arm-time baseline
    /// before the first byte ever crosses) — `fetch_max` keeps a clock
    /// jump back from regressing it. Plain atomic: the pump touches it
    /// with no lock, at its existing idle-deadline reset points.
    last_byte_unix_millis: Arc<AtomicU64>,
    /// The rule's `idle_timeout_secs`, when it sets one (the fossil
    /// judgment's anchor).
    idle_budget_secs: Option<u32>,
}

/// The shared per-rule ledger (in-memory by design).
///
/// A restart resets baselines to boot time, which reads "fresh" — the
/// honest bound of an in-memory level; the backlog's boundary with the
/// biography face stands: recent trend here, history there.
#[derive(Debug, Default)]
pub struct StreamActivity {
    inner: std::sync::Mutex<BTreeMap<String, RuleActivity>>,
}

impl StreamActivity {
    pub fn new() -> Self {
        Self::default()
    }

    /// Arms (or re-arms) one rule's record and returns the hot-path cell
    /// the pump touches. A NEW rule's baseline is now (arm time — the
    /// "mounted, listening" instant); an existing rule keeps its
    /// last-byte history across re-arms (a reload is not a rebirth) and
    /// only refreshes the budget anchor.
    pub fn arm_rule(&self, name: &str, idle_budget_secs: Option<u32>) -> Arc<AtomicU64> {
        let mut inner = self
            .inner
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let entry = inner
            .entry(name.to_owned())
            .or_insert_with(|| RuleActivity {
                last_byte_unix_millis: Arc::new(AtomicU64::new(now_secs().saturating_mul(1000))),
                idle_budget_secs,
            });
        entry.idle_budget_secs = idle_budget_secs;
        Arc::clone(&entry.last_byte_unix_millis)
    }

    /// The report snapshot: every armed rule's activity level,
    /// name-sorted (the wire form of the BTreeMap).
    pub fn snapshot(&self) -> Vec<NodeStreamActivity> {
        let inner = self
            .inner
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        inner
            .iter()
            .map(|(name, rule)| NodeStreamActivity {
                name: name.clone(),
                last_byte_unix: rule
                    .last_byte_unix_millis
                    .load(std::sync::atomic::Ordering::Relaxed)
                    / 1000,
                idle_budget_secs: rule.idle_budget_secs,
            })
            .collect()
    }
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
    fn fossil_lines_anchor_on_the_rules_own_budget() {
        // Budgeted: 10× the budget, strictly past.
        assert_eq!(fossil_after_secs(300, FOSSIL_IDLE_MULTIPLE), 3_000);
        // Unbudgeted: the absolute default's week floor is a compile-time
        // lock next to the constant (`const _: () = assert!(…)`).
    }

    #[test]
    fn arm_baseline_keeps_history_across_rearms_and_pump_touches_flow() {
        let ledger = StreamActivity::new();
        let cell = ledger.arm_rule("svc", Some(300));
        let first = ledger.snapshot();
        assert_eq!(first.len(), 1);
        assert_eq!(first[0].name, "svc");
        assert_eq!(first[0].idle_budget_secs, Some(300));
        let baseline = first[0].last_byte_unix;

        // A pump touch advances the level (millis cell, seconds snapshot).
        std::thread::sleep(std::time::Duration::from_millis(15));
        cell.fetch_max(
            u64::try_from(interflow_identity::expiry::now_unix()).unwrap_or(0) * 1000,
            std::sync::atomic::Ordering::Relaxed,
        );
        let touched = ledger.snapshot()[0].last_byte_unix;
        assert!(touched >= baseline);

        // Re-arm keeps the touched level (history survives a reload) and
        // refreshes only the budget.
        ledger.arm_rule("svc", Some(600));
        let after = ledger.snapshot();
        assert_eq!(after[0].last_byte_unix, touched);
        assert_eq!(after[0].idle_budget_secs, Some(600));
    }
}
