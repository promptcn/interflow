//! The agent's background breaker-recovery prober — the active half of the
//! 2026-10-18 recovery fix
//!
//! Before this task, a tripped target's recovery was structurally passive:
//! OPEN entries reject pre-dial, so the agent stops dialing the backend —
//! the backend coming back was invisible until the cooldown elapsed and a
//! real stream probed. Recovery time was coupled to *when the breaker
//! tripped*, not to when the backend revived (the "local up, public 502"
//! window).
//!
//! This task decouples them: every tick it snapshots the breaker table's
//! OPEN TCP entries (`udp:` keys are skipped — a bare `UdpSocket::connect`
//! proves nothing, that population keeps the cooldown+stream-probe
//! recovery), bare-TCP-dials each due target, and calls `note_success` on
//! the first answer. The dial is **not a stream Open**: it consumes none
//! of the shared stream-open budget the cooldown exists to protect
//! (2026-09-16 budget isolation), so probing during the cooldown is not a
//! policy violation but the correct behavior — waiting for the deadline
//! would just re-couple recovery to the trip time.
//!
//! Cadence is address-class split: loopback targets (the dev-server
//! restart picture the case file was born from) probe at the fast lane
//! (default 1s); non-loopback targets probe on a politeness budget
//! (default 5s) — the remote-host SYN concern is answered with cadence
//! engineering, not by leaving remote recovery passive.
//!
//! On each prober-detected recovery the task also reports upstream
//! ([`AgentTunnel::report_target_recovered`]): an expose edge holds route
//! breakers of its own whose cooldown would otherwise gate the public face
//! for up to a full cooldown after this agent already knows the backend is
//! back (the outage-shorter-than-cooldown residual window). The notice is
//! informational — loss (old hub, mid-rebuild session, empty service set)
//! only means the receiver keeps its cooldown-based recovery.
//!
//! Lifecycle: spawned on the agent's task tree at
//! [`AgentClient::start`](crate::agent::client::AgentClient::start) beside
//! the intent watcher — same tracker, same shutdown token, ends with
//! `shutdown_graceful`; the breaker table is agent-level so the task spans
//! session rebuilds (the prober holds the session-slot tunnel facade and
//! simply has nothing to report while the slot is empty).

use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::time::Duration;

use interflow_core::tunnel::transport::TargetRecoveredNotice;
use tokio_util::sync::CancellationToken;
use tokio_util::task::TaskTracker;
use tracing::{debug, info};

use super::egress::EgressRuntime;
use super::rules::RuleStore;
use super::target_breaker::TargetBreakers;

/// Scan cadence: how often the table is re-snapshanked and due targets are
/// dialed. Coarse on purpose — the per-target *probe* cadence is the
/// address-class interval; this tick only decides when to look.
const SCAN_INTERVAL: Duration = Duration::from_millis(500);

/// Prober configuration (flattened from `AgentConfig`'s
/// `egress_recovery_probe_*` fields; validation guarantees non-zero
/// whenever enabled).
#[derive(Clone, Copy, Debug)]
pub(crate) struct ProbePolicy {
    pub(crate) loopback_interval: Duration,
    pub(crate) remote_interval: Duration,
    pub(crate) connect_timeout: Duration,
}

/// Per-target scheduling state (prober-local; the breaker table stays the
/// single health truth).
#[derive(Debug, Default)]
struct ProbeState {
    /// Earliest instant the target may be probed again (set from the
    /// address-class interval after each attempt).
    next_attempt: Option<tokio::time::Instant>,
}

/// Spawns the prober on the agent's task tree. Inert without a breaker
/// table (breaker disabled): nothing to watch, no task at all.
pub(crate) fn spawn(
    log_name: String,
    runtime: &Arc<EgressRuntime>,
    tunnel: interflow_core::tunnel::AgentTunnel,
    rules: Arc<RuleStore>,
    policy: ProbePolicy,
    shutdown: &CancellationToken,
    tracker: &TaskTracker,
) {
    let Some(breakers) = runtime.breakers().cloned() else {
        return;
    };
    let shutdown = shutdown.clone();
    tracker.spawn(async move {
        run(log_name, breakers, tunnel, rules, policy, shutdown).await;
    });
}

async fn run(
    log_name: String,
    breakers: Arc<TargetBreakers>,
    tunnel: interflow_core::tunnel::AgentTunnel,
    rules: Arc<RuleStore>,
    policy: ProbePolicy,
    shutdown: CancellationToken,
) {
    info!(
        node = %log_name,
        scan = ?SCAN_INTERVAL,
        loopback_secs = policy.loopback_interval.as_secs(),
        remote_secs = policy.remote_interval.as_secs(),
        "breaker recovery prober armed (bare-TCP dials, no stream-open budget)"
    );
    let mut ticker = tokio::time::interval(SCAN_INTERVAL);
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    // The first `tick` of a fresh interval fires immediately; skip it so a
    // just-tripped entry gets its address-class interval before the first
    // dial (trip → instant probe would make the breaker's own cooldown
    // theater for freshly-dead targets).
    ticker.tick().await;

    let mut schedule: HashMap<String, ProbeState> = HashMap::new();
    loop {
        tokio::select! {
            () = shutdown.cancelled() => return,
            _ = ticker.tick() => {}
        }
        // Level-triggered reconciliation against the OPEN set: entries that
        // recovered elsewhere (a real-stream probe) or vanished drop out of
        // the schedule for free; new trips enter below.
        let open: HashSet<String> = breakers.open_targets().into_iter().collect();
        schedule.retain(|key, _| open.contains(key));
        let now = tokio::time::Instant::now();
        for key in &open {
            schedule.entry(key.clone()).or_default();
        }
        for (key, state) in &mut schedule {
            let Some(target) = key.strip_prefix("tcp:") else {
                continue; // udp: population — cooldown+stream-probe recovery
            };
            match state.next_attempt {
                // First sight of this trip: honor one address-class interval
                // before the first dial (a just-tripped target just failed a
                // real dial; an instant extra SYN buys nothing).
                None => state.next_attempt = Some(now + probe_interval(policy, target)),
                Some(at) if now < at => {}
                Some(_) => {
                    state.next_attempt = Some(now + probe_interval(policy, target));
                    probe_one(&log_name, &breakers, &tunnel, &rules, policy, target).await;
                }
            }
        }
    }
}

/// The address-class probe cadence for one target (pure; unit-tested).
fn probe_interval(policy: ProbePolicy, target: &str) -> Duration {
    if super::backend_dial::is_loopback_target(target) {
        policy.loopback_interval
    } else {
        policy.remote_interval
    }
}

/// One bare-TCP dial toward a tripped target. Success runs the full
/// recovery: `note_success` (entry removed, next Open fully admitted) plus
/// the upstream notice. Failure is not breaker evidence — the breaker's
/// own failure accounting stays owned by real dials; the prober only
/// records "not yet" by leaving the entry OPEN.
async fn probe_one(
    log_name: &str,
    breakers: &Arc<TargetBreakers>,
    tunnel: &interflow_core::tunnel::AgentTunnel,
    rules: &Arc<RuleStore>,
    policy: ProbePolicy,
    target: &str,
) {
    metrics::counter!("interflow_agent_breaker_recovery_probes_total").increment(1);
    let addr =
        match super::backend_dial::resolve_first_allowed(target, policy.connect_timeout).await {
            Ok(addr) => addr,
            Err(e) => {
                // Resolve failures of a tripped target are expected (that is
                // often why it tripped); debug, and let the next tick retry.
                debug!(node = %log_name, "recovery probe could not resolve {target}: {e}");
                return;
            }
        };
    match tokio::time::timeout(policy.connect_timeout, tokio::net::TcpStream::connect(addr)).await {
        Ok(Ok(_stream)) => {
            metrics::counter!("interflow_agent_breaker_recovery_probes_succeeded_total")
                .increment(1);
            info!(
                node = %log_name,
                "target breaker recovered by probe: {target} answered a bare TCP dial"
            );
            breakers.note_success(&super::target_breaker::dial_key(
                interflow_core::protocol::StreamProto::Tcp,
                target,
            ));
            report_upstream(log_name, tunnel, rules, target).await;
        }
        Ok(Err(e)) => {
            debug!(node = %log_name, "recovery probe to {target} refused: {e}");
        }
        Err(_) => {
            debug!(node = %log_name, "recovery probe to {target} timed out");
        }
    }
}

/// Maps the recovered dial target to the egress-rule (service) ids offering
/// it over TCP and pushes the notice upstream. Skipped silently when no
/// named rule offers the target (dynamic addressing — nothing an edge
/// could reverse-map) or when the push fails (informational contract).
async fn report_upstream(
    log_name: &str,
    tunnel: &interflow_core::tunnel::AgentTunnel,
    rules: &Arc<RuleStore>,
    target: &str,
) {
    let service_ids: Vec<String> = rules
        .egress_snapshot()
        .await
        .iter()
        .filter(|rule| {
            rule.target_protocol == interflow_core::protocol::StreamProto::Tcp
                && matches!(
                    rule.target,
                    crate::config::EgressTarget::Addr(addr) if addr.to_string() == target
                )
        })
        .map(|rule| rule.name.clone())
        .collect();
    if service_ids.is_empty() {
        debug!(
            node = %log_name,
            "recovered target {target} matches no named TCP rule — no upstream notice"
        );
        return;
    }
    let notice = TargetRecoveredNotice {
        target_addr: target.to_string(),
        service_ids,
    };
    match tunnel.report_target_recovered(&notice).await {
        Ok(ack) => debug!(
            node = %log_name,
            closed_routes = ack.closed_routes,
            "target-recovery notice delivered"
        ),
        Err(e) => debug!(
            node = %log_name,
            "target-recovery notice dropped ({e}; receiver keeps cooldown recovery)"
        ),
    }
}

#[cfg(test)]
#[allow(clippy::panic, clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    fn policy() -> ProbePolicy {
        ProbePolicy {
            loopback_interval: Duration::from_secs(1),
            remote_interval: Duration::from_secs(5),
            connect_timeout: Duration::from_secs(1),
        }
    }

    #[test]
    fn loopback_targets_take_the_fast_lane() {
        let p = policy();
        assert_eq!(probe_interval(p, "127.0.0.1:5174"), p.loopback_interval);
        assert_eq!(probe_interval(p, "localhost:3000"), p.loopback_interval);
        assert_eq!(probe_interval(p, "[::1]:8080"), p.loopback_interval);
    }

    #[test]
    fn remote_targets_take_the_politeness_lane() {
        let p = policy();
        assert_eq!(probe_interval(p, "10.1.2.3:8080"), p.remote_interval);
        assert_eq!(probe_interval(p, "example.com:443"), p.remote_interval);
        // Prefix spoofs must not reach the fast lane.
        assert_eq!(
            probe_interval(p, "127.0.0.1.evil.com:8080"),
            p.remote_interval
        );
    }
}
