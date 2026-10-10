//! The agent engine's intrinsic peer-observability watcher.
//!
//! The hub always knew who is registered (`GET /agents` on h2, the
//! PeerList frame pair on QUIC — tenant-scoped by mTLS identity); before
//! this watcher no agent-side surface ever asked, so "is the peer up" was
//! answerable only by an operator reading hub journals. This watcher polls
//! the agents control plane on the **same cadence as the policy watcher**
//! ([`super::policy_watch::POLICY_WATCH_INTERVAL`], sharing the constant so
//! the two control-plane reads cannot drift apart) and on every `Connected`
//! transition, riding the same session tunnel — no new channel, no new
//! credential surface.
//!
//! Information minimization is the design line: each peer is a name, an
//! online reading, and a leaf-health phase (the same warn/critical tiering
//! the node's own credential face uses). Build tags, transports, and
//! addresses stay off this face until a real troubleshooting need names
//! them — the listing is tenant-scoped reconnaissance material in the
//! other direction too (THREAT_MODEL §6.5).
//!
//! Steady state is silent: presence and leaf-phase changes are logged as
//! transitions only (the 2026-09-25 audit-noise discipline — a peer that
//! stays online stays unlogged), and a failing fetch warns once per
//! distinct reason and resets on recovery. The [`PeerWatchState`]
//! subscription face mirrors [`super::policy_watch::PolicyWatchState`]:
//! embedding surfaces receive snapshots as events instead of polling.
//!
//! The same task also carries the stream-proposal receipts face
//! ([`ProposalWatchState`]): `my_proposals` rides the identical cadence
//! and tunnel, so a submit's decision (approved / rejected + reason)
//! reaches the requester's GUI within one interval without a second
//! channel or task.

use std::collections::HashMap;
use std::sync::Arc;

use interflow_core::tunnel::AgentTunnel;
use interflow_core::tunnel::transport::PeerInfo;
use tokio::sync::watch;
use tokio_util::sync::CancellationToken;
use tokio_util::task::TaskTracker;
use tracing::{debug, info, warn};

use super::handle::AgentState;
use super::policy_watch::POLICY_WATCH_INTERVAL;

/// One point-in-time reading of the peer plane: the tenant's agents
/// (self excluded) plus fetch liveness.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct PeerWatchSnapshot {
    /// The tenant's registered agents, self excluded, sorted by qualified
    /// id for stable rendering and diffing.
    pub peers: Vec<PeerInfo>,
    /// Unix seconds of the last successful fetch; `0` = never.
    pub last_ok_unix: u64,
    /// Fetches that failed at the transport/session level since watcher
    /// start (a mid-rebuild session, a protocol violation).
    pub failures_total: u64,
}

/// Live peer-plane telemetry for a running agent.
///
/// The authoritative latest snapshot lives in the watch channel itself
/// (peers are a `Vec`, not copy atomics); `snapshot()` borrows-and-clones
/// it. The sender lives exactly as long as this struct's `Arc` — receivers
/// observe the watcher's end as a closed channel, the intended shutdown
/// signal for forwarders (same contract as
/// [`super::policy_watch::PolicyWatchState`]).
#[derive(Debug)]
pub struct PeerWatchState {
    snapshot_tx: watch::Sender<PeerWatchSnapshot>,
    /// The birth receiver, kept alive for the struct's whole lifetime: a
    /// tokio watch channel CLOSES when its last receiver drops, after
    /// which sends silently stop landing — without this, `snapshot()`
    /// (the sender-side borrow) keeps returning the birth value forever
    /// on any state nobody happened to subscribe to.
    snapshot_rx: watch::Receiver<PeerWatchSnapshot>,
}

impl Default for PeerWatchState {
    fn default() -> Self {
        let (snapshot_tx, snapshot_rx) = watch::channel(PeerWatchSnapshot::default());
        Self {
            snapshot_tx,
            snapshot_rx,
        }
    }
}

impl PeerWatchState {
    /// Reads the latest snapshot.
    pub fn snapshot(&self) -> PeerWatchSnapshot {
        self.snapshot_tx.borrow().clone()
    }

    /// Subscribes to snapshot changes from here on; yields the watcher's
    /// next publish (at most one interval away) and errors once the
    /// watcher — and every handle to this state — is gone.
    pub fn subscribe(&self) -> watch::Receiver<PeerWatchSnapshot> {
        self.snapshot_rx.clone()
    }
}

/// The stream-proposal receipts face: this node's own proposals and their
/// decision state.
///
/// Refreshed on the peer watch's cadence (same task, same tunnel — see the
/// module docs). Same birth-receiver and subscription contracts as
/// [`PeerWatchState`].
#[derive(Debug)]
pub struct ProposalWatchState {
    tx: watch::Sender<Vec<interflow_core::tunnel::transport::ProposalReceipt>>,
    rx: watch::Receiver<Vec<interflow_core::tunnel::transport::ProposalReceipt>>,
}

impl Default for ProposalWatchState {
    fn default() -> Self {
        let (tx, rx) = watch::channel(Vec::new());
        Self { tx, rx }
    }
}

impl ProposalWatchState {
    /// Reads the latest receipts.
    pub fn snapshot(&self) -> Vec<interflow_core::tunnel::transport::ProposalReceipt> {
        self.tx.borrow().clone()
    }

    /// Subscribes to receipt changes from here on.
    pub fn subscribe(
        &self,
    ) -> watch::Receiver<Vec<interflow_core::tunnel::transport::ProposalReceipt>> {
        self.rx.clone()
    }
}

/// The presence/phase reading a transition is judged against.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct PeerReading {
    online: bool,
    /// `None` = no leaf info; transitions involving `None` still log (a
    /// peer gaining or losing its leaf reading is itself news).
    phase: Option<interflow_core::tunnel::transport::PeerLeafPhase>,
}

impl PeerReading {
    fn of(peer: &PeerInfo) -> Self {
        Self {
            online: peer.online,
            phase: peer.leaf_expiry.as_ref().map(|l| l.phase),
        }
    }
}

/// Spawns the peer watcher onto the agent's task group — same lifecycle
/// contract as the policy watcher: same tracker, same shutdown token, ends
/// with [`super::AgentHandle::shutdown_graceful`]. Returns the shared live
/// state for health faces.
pub(crate) fn spawn(
    self_agent: String,
    log_name: String,
    tunnel: AgentTunnel,
    state_rx: watch::Receiver<AgentState>,
    shutdown: &CancellationToken,
    tracker: &TaskTracker,
) -> (Arc<PeerWatchState>, Arc<ProposalWatchState>) {
    let state = Arc::new(PeerWatchState::default());
    let watch_state = Arc::clone(&state);
    let proposals = Arc::new(ProposalWatchState::default());
    let proposals_state = Arc::clone(&proposals);
    let shutdown = shutdown.clone();
    tracker.spawn(async move {
        run(
            self_agent,
            log_name,
            tunnel,
            state_rx,
            shutdown,
            watch_state,
            proposals_state,
        )
        .await;
    });
    (state, proposals)
}

/// The watcher body: interval ticks plus an immediate fetch on every
/// `Connected` transition (a re-registering agent converges in ~1s, not
/// one interval — same trigger discipline as the policy watcher).
async fn run(
    self_agent: String,
    log_name: String,
    tunnel: AgentTunnel,
    mut state_rx: watch::Receiver<AgentState>,
    shutdown: CancellationToken,
    state: Arc<PeerWatchState>,
    proposals: Arc<ProposalWatchState>,
) {
    info!(
        node = %log_name,
        build = %interflow_buildinfo::BUILD_TAG,
        interval_secs = POLICY_WATCH_INTERVAL.as_secs(),
        "peer watcher armed (hub agents control plane)"
    );

    // Presence/phase of the previous fetch — the transition ledger. Only
    // changes log; a steady fleet is silent.
    let mut previous: HashMap<String, PeerReading> = HashMap::new();
    // The fetch-failure reason already warned about (warn-once per distinct
    // reason, reset on recovery — the policy watcher's discipline).
    let mut warned_fetch_error: Option<String> = None;

    let mut session_event = matches!(&*state_rx.borrow_and_update(), AgentState::Connected { .. });
    let mut next_tick = tokio::time::Instant::now() + POLICY_WATCH_INTERVAL;

    loop {
        let due_now = session_event;
        session_event = false;
        if !due_now {
            tokio::select! {
                () = shutdown.cancelled() => return,
                () = tokio::time::sleep_until(next_tick) => {}
                changed = state_rx.changed() => {
                    if changed.is_err() {
                        // The supervisor is gone — the agent is shutting
                        // down; ride out with it.
                        return;
                    }
                    if matches!(
                        &*state_rx.borrow_and_update(),
                        AgentState::Connected { .. }
                    ) {
                        session_event = true;
                    }
                    continue;
                }
            }
        }
        if due_now {
            // An out-of-band fetch (session establishment): the periodic
            // schedule continues untouched — this fetch is ON TOP of the
            // cadence, not a replacement for the next tick. Advancing the
            // schedule here would stretch the worst-case visibility of a
            // peer that registers just after a session-triggered fetch to
            // two intervals (observed as the 20s gap the e2e caught).
        } else if next_tick <= tokio::time::Instant::now() {
            next_tick = tokio::time::Instant::now() + POLICY_WATCH_INTERVAL;
        } else {
            next_tick += POLICY_WATCH_INTERVAL;
        }

        match tunnel.list_agents().await {
            Err(e) => {
                let mut snapshot = state.snapshot();
                snapshot.failures_total += 1;
                let _ = state.snapshot_tx.send(snapshot);
                let reason = e.to_string();
                if warned_fetch_error.as_deref().is_none_or(|w| w != reason) {
                    warn!(
                        node = %log_name,
                        build = %interflow_buildinfo::BUILD_TAG,
                        "peer list fetch failing: {reason} — the Peers face stays on its last \
                         reading while this persists (retried every {}s)",
                        POLICY_WATCH_INTERVAL.as_secs()
                    );
                    warned_fetch_error = Some(reason);
                } else {
                    debug!(node = %log_name, "peer list fetch skipped this tick: {reason}");
                }
            }
            Ok(raw) => {
                warned_fetch_error = None;
                // Self exclusion by the qualified key's agent part: the
                // listing is already tenant-scoped, so within it the agent
                // id is unique — this row is us.
                let mut peers: Vec<PeerInfo> = raw
                    .into_iter()
                    .filter(|p| {
                        p.agent
                            .rsplit_once('/')
                            .is_none_or(|(_, a)| a != self_agent)
                    })
                    .collect();
                peers.sort_by(|a, b| a.agent.cmp(&b.agent));

                for peer in &peers {
                    let reading = PeerReading::of(peer);
                    match previous.get(&peer.agent) {
                        Some(prev) if *prev == reading => {}
                        Some(prev) => {
                            if prev.online != reading.online {
                                info!(
                                    node = %log_name,
                                    peer = %peer.agent,
                                    "peer {}",
                                    if reading.online {
                                        "came online"
                                    } else {
                                        "went offline"
                                    }
                                );
                            }
                            if prev.phase != reading.phase {
                                let phase = reading
                                    .phase
                                    .map_or_else(|| "unknown".to_string(), |p| format!("{p:?}"));
                                info!(
                                    node = %log_name,
                                    peer = %peer.agent,
                                    remaining_secs = peer
                                        .leaf_expiry
                                        .as_ref()
                                        .map_or(0, |l| l.remaining_secs),
                                    "peer leaf phase now {phase}"
                                );
                            }
                        }
                        None => {
                            // First sighting — one line introducing the peer
                            // with its reading; membership itself is news
                            // once.
                            info!(
                                node = %log_name,
                                peer = %peer.agent,
                                online = reading.online,
                                "peer visible"
                            );
                        }
                    }
                    previous.insert(peer.agent.clone(), reading);
                }
                // Peers that left the registry entirely (evicted, hub
                // restart) surface as a departure, not silence.
                let live: std::collections::HashSet<&str> =
                    peers.iter().map(|p| p.agent.as_str()).collect();
                previous.retain(|agent, _| {
                    if live.contains(agent.as_str()) {
                        true
                    } else {
                        info!(node = %log_name, peer = %agent, "peer left the registry");
                        false
                    }
                });

                let _ = state.snapshot_tx.send(PeerWatchSnapshot {
                    peers,
                    last_ok_unix: now_unix(),
                    failures_total: state.snapshot().failures_total,
                });
            }
        }

        // The receipts face rides the same cycle and tunnel: a decision
        // (approved / rejected) is a transition — logged once, then the
        // steady state stays silent. A failing fetch keeps the last
        // reading (the receipt window outlives any single session).
        if let Ok(receipts) = tunnel.my_proposals().await {
            let changed = {
                let current = proposals.tx.borrow();
                current.as_slice() != receipts.as_slice()
            };
            if changed {
                for receipt in &receipts {
                    let status_label = match &receipt.status {
                        interflow_core::tunnel::transport::ProposalStatusWire::Pending => None,
                        interflow_core::tunnel::transport::ProposalStatusWire::Approved {
                            generation,
                        } => Some(format!("approved (generation {generation})")),
                        interflow_core::tunnel::transport::ProposalStatusWire::Rejected {
                            reason,
                        } => Some(format!("rejected: {reason}")),
                    };
                    if let Some(label) = status_label {
                        info!(
                            node = %log_name,
                            proposal = %receipt.id,
                            "stream proposal {label}"
                        );
                    }
                }
                let _ = proposals.tx.send(receipts);
            }
        }
    }
}

fn now_unix() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}
