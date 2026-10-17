//! Reconcile-loop summary logging: transitions are events, no-op ticks are
//! samples.
//!
//! Periodic level-triggered loops (ingress/egress reconcile, policy pull)
//! fire on every tick even when nothing changed. Logging the pass summary
//! unconditionally at info turns the safety-net tick into per-node
//! heartbeat noise that evicts real events from bounded log faces — the
//! 2026-10-10 backlog measured the GUI capture ring (2000 lines) at 1733
//! ingress lines over 3h18m, almost all `+0 ~0 -0 !0` heartbeats. Same
//! lesson as the `policy_pulled` audit noise (backlog/2026-09-25): a loop
//! must not account heartbeats as events.
//!
//! Policy — this module is its one home for the whole crate:
//! - all-zero pass → `debug!`: a liveness sample. Steady-state liveness is
//!   metrics' and `RUST_LOG`'s job, not the info face's.
//! - any non-zero pass → `info!`: a real state transition the operator
//!   sees. In particular `!{failed}` stays visible on the bind-retry path.
//! - both variants share one byte-stable text, so level is the only
//!   difference — tests and docs assert this line verbatim.
//! - both variants carry the node attribution: the zero-bare-lines machine
//!   lock (node.rs `mesh_agent_lines_carry_node_attribution`) filters no
//!   level, so a bare debug line would fail it just the same.
//!
//! The steady-state property is machine-locked below: a no-op pass
//! emitting any info-level event fails the build.

use tracing::{debug, info};

/// One reconcile pass's outcome tally: how many rules were added /
/// param-changed-or-replaced / removed / failed to bind. The loop records
/// into it at each branch, then [`Self::log`] applies the module policy in
/// one place.
#[derive(Debug, Default)]
pub(crate) struct ReconcileReport {
    added: usize,
    changed: usize,
    removed: usize,
    failed: usize,
}

impl ReconcileReport {
    pub(crate) fn new() -> Self {
        Self::default()
    }

    pub(crate) const fn record_added(&mut self) {
        self.added += 1;
    }

    pub(crate) const fn record_changed(&mut self) {
        self.changed += 1;
    }

    pub(crate) const fn record_removed(&mut self) {
        self.removed += 1;
    }

    pub(crate) const fn record_failed(&mut self) {
        self.failed += 1;
    }

    /// Rules that want a listener but do not have one (bind failures
    /// pending retry) — the reconcile caller's return value.
    pub(crate) const fn failed(&self) -> usize {
        self.failed
    }

    const fn is_noop(&self) -> bool {
        self.added + self.changed + self.removed + self.failed == 0
    }

    /// Emit the pass summary under the module policy: transition → info,
    /// no-op sample → debug. `subject` names the loop ("Ingress"); the
    /// text is byte-stable across both variants and both carry the node
    /// attribution.
    pub(crate) fn log(&self, node: &str, subject: &str) {
        let Self {
            added,
            changed,
            removed,
            failed,
        } = self;
        if self.is_noop() {
            debug!(
                node = %node,
                "{subject} reconciled: +{added} ~{changed} -{removed} !{failed}"
            );
        } else {
            info!(
                node = %node,
                "{subject} reconciled: +{added} ~{changed} -{removed} !{failed}"
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Arc, Mutex};
    use tracing_subscriber::layer::SubscriberExt as _;

    /// Captures (level, node, message) for every event, level-unfiltered —
    /// the same shape the node.rs attribution recorder uses.
    type Captured = Arc<Mutex<Vec<(tracing::Level, Option<String>, String)>>>;

    struct CaptureLayer(Captured);

    impl<S: tracing::Subscriber> tracing_subscriber::layer::Layer<S> for CaptureLayer {
        fn on_event(
            &self,
            event: &tracing::Event<'_>,
            _ctx: tracing_subscriber::layer::Context<'_, S>,
        ) {
            let mut visitor = FieldVisitor::default();
            event.record(&mut visitor);
            self.0
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .push((*event.metadata().level(), visitor.node, visitor.message));
        }
    }

    #[derive(Default)]
    struct FieldVisitor {
        node: Option<String>,
        message: String,
    }

    impl tracing::field::Visit for FieldVisitor {
        fn record_debug(&mut self, field: &tracing::field::Field, value: &dyn std::fmt::Debug) {
            match field.name() {
                "node" => self.node = Some(format!("{value:?}")),
                "message" => self.message = format!("{value:?}"),
                _ => {}
            }
        }
    }

    fn capture(report: &ReconcileReport) -> Vec<(tracing::Level, Option<String>, String)> {
        let events: Captured = Arc::new(Mutex::new(Vec::new()));
        // `log` is synchronous, so a thread-scoped default subscriber sees
        // every event it emits — no timing, fully deterministic.
        let _guard = tracing::subscriber::set_default(
            tracing_subscriber::registry().with(CaptureLayer(Arc::clone(&events))),
        );
        report.log("node-a", "Ingress");
        events
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone()
    }

    fn info_messages(events: &[(tracing::Level, Option<String>, String)]) -> Vec<&str> {
        events
            .iter()
            .filter(|(level, _, _)| *level == tracing::Level::INFO)
            .map(|(_, _, msg)| msg.as_str())
            .collect()
    }

    /// Steady-state machine lock (the 2026-10-10 backlog's acceptance):
    /// a no-op pass must emit ZERO info events — the 15s heartbeat stays
    /// off the info face — while the liveness sample remains greppable
    /// under `RUST_LOG` at debug.
    #[test]
    fn noop_pass_emits_no_info_but_keeps_debug_sample() {
        let events = capture(&ReconcileReport::new());
        assert!(
            events
                .iter()
                .all(|(level, _, _)| *level != tracing::Level::INFO),
            "a no-op reconcile pass must not emit info-level events; captured: {events:?}"
        );
        assert!(
            events.iter().any(|(level, _, msg)| {
                *level == tracing::Level::DEBUG && msg == "Ingress reconciled: +0 ~0 -0 !0"
            }),
            "the no-op liveness sample must stay visible at debug; captured: {events:?}"
        );
    }

    /// Transition lock: a pass with changes emits exactly one info line,
    /// byte-stable — the node.rs attribution test waits for
    /// `Ingress reconciled: +1 ~0 -0 !0` verbatim. The bind-retry path
    /// (`!1`) rides the same non-zero branch.
    #[test]
    fn transition_pass_emits_exact_info_line() {
        let mut added_one = ReconcileReport::new();
        added_one.record_added();
        let events = capture(&added_one);
        assert_eq!(
            info_messages(&events),
            ["Ingress reconciled: +1 ~0 -0 !0"],
            "the transition summary text is load-bearing (asserted verbatim elsewhere)"
        );

        let mut failed_one = ReconcileReport::new();
        failed_one.record_failed();
        let events = capture(&failed_one);
        assert_eq!(
            info_messages(&events),
            ["Ingress reconciled: +0 ~0 -0 !1"],
            "the bind-failure retry path must stay on the info face (troubleshooting clue)"
        );
    }

    /// Attribution lock: every variant — no-op debug included — carries the
    /// node field; the agent zero-bare-lines machine lock filters no level.
    #[test]
    fn every_variant_carries_node_attribution() {
        let mut transition = ReconcileReport::new();
        transition.record_removed();
        for events in [capture(&ReconcileReport::new()), capture(&transition)] {
            assert_ne!(events.len(), 0);
            for (level, node, _) in &events {
                assert_eq!(
                    node.as_deref(),
                    Some("node-a"),
                    "level {level} variant must carry node attribution"
                );
            }
        }
    }
}
