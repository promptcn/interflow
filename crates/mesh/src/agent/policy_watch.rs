//! The agent engine's intrinsic signed-policy watcher.
//!
//! Two distribution channels, one applying path: the node-local file
//! channel (`state/policy`) and the hub's control-plane pull (`GET /policy`
//! on h2, the PolicyPull frame pair on QUIC), which is how an update
//! published at the hub reaches every agent with zero physical touches (an
//! offline agent catches up on its first connected pull). Each tick
//! verifies candidates against the pack's trust bundle and the
//! anti-rollback floor, then hands the derived rules to
//! [`AgentClient::apply_policy`]. Rejection is fail-keep: a tampered
//! signature, a rollback, or an underivable rule face is logged (with its
//! category) while the current policy keeps serving.
//!
//! The watcher is spawned by [`super::AgentClient::start`] whenever the
//! config carries a policy plane (pack-built agents) — an engine-intrinsic
//! capability, not embedder wiring. Before 2026-10-07 every embedding
//! surface (the GUI node runner, the CLI binary, each e2e's start closure)
//! hand-spawned it, and the one surface that forgot shipped silently
//!; there
//! is no wiring left to forget.
//!
//! Observability contract (2026-10-06 silent-reject fix, extended
//! 2026-10-07): every policy-plane rejection or pathology leaves a trace —
//! a served generation below the local watermark (the lineage-deadlock
//! signature) warns once per crossing; a failing control-plane pull warns
//! once per distinct failure reason and resets on recovery; the watcher
//! names its build and transport when it arms. The steady state stays at
//! debug. [`PolicyWatchState`] exposes the same live values plus pull
//! liveness, so a health face can tell "pulling" from "never pulled".

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use interflow_contract::generation::floor_epoch;
use interflow_core::tunnel::AgentTunnel;
use interflow_core::tunnel::transport::PolicyPull;
use interflow_identity::pack::CredentialPack;
use interflow_identity::policy::RuntimePolicy;
use tokio::sync::watch;
use tokio_util::sync::CancellationToken;
use tokio_util::task::TaskTracker;
use tracing::{debug, info, warn};

use super::client::AgentClient;
use super::handle::AgentState;
use crate::config::TransportKind;
use crate::pack::{
    pack_error, policy_channel_fingerprint, policy_egress_rules, policy_ingress_rules,
    policy_service_egress_rules,
};

/// How often the node-local policy update channel (`state/policy`) is
/// polled — the renewal scheduler's polling discipline (no platform watch
/// dependencies); one interval of latency is well inside the product goal
/// for policy changes ("minutes, not days"). Session establishment (the
/// `Connected` state transition) triggers an immediate pull on top of this
/// cadence, so a re-registering agent converges in ~1s, not one interval.
pub(crate) const POLICY_WATCH_INTERVAL: Duration = Duration::from_secs(10);

/// One point-in-time reading of [`PolicyWatchState`]'s six live values.
///
/// The unit of the subscription face: the watcher publishes a snapshot
/// after each batch of writes, and embedding surfaces (the GUI's policy
/// health panel) receive it as an event instead of re-reading atomics on
/// their own schedule
/// ((internal design notes) —
/// the panel used to freeze on its start-time seed because nothing ever
/// told it the values had moved).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct PolicyWatchSnapshot {
    /// The node's current watermark — the highest generation applied.
    pub seen: u64,
    /// The hub's serving generation as of the last successful poll;
    /// `0` = never polled.
    pub hub_generation: u64,
    /// Whether the live policy came from the node-local update channel.
    pub state_channel: bool,
    /// Transport/session-level pull failures since watcher start.
    pub pull_failures_total: u64,
    /// Unix seconds of the last successful pull; `0` = never.
    pub pull_last_ok_unix: u64,
    /// Unix seconds of the watcher's most recent wake.
    pub last_tick_unix: u64,
}

/// Live policy-plane telemetry for a running agent's policy watcher.
///
/// The embedding surface's "policy health" face (the GUI's node detail
/// reads it). Plain atomics written by the watcher task, read by the
/// manager's snapshot path; no lock anywhere. Every write is followed (at
/// the latest by the next loop iteration's [`Self::publish`]) by a watch
/// channel send, so subscribers can be event-driven rather than polling —
/// a health face that only samples at its own convenience stays stale
/// between samples, which reads as "converged" when it is really
/// "frozen".
#[derive(Debug)]
pub struct PolicyWatchState {
    /// The node's current watermark — the highest generation applied.
    /// Seeded from the pack at watcher start; advances only on a successful
    /// application.
    pub seen: std::sync::atomic::AtomicU64,
    /// The hub's serving generation as of the last successful control-plane
    /// poll — always a value the hub actually reported (`PolicyPull::UpToDate`
    /// requires the header; a hub without a policy face is the distinct
    /// `NoPolicyFace` outcome and never touches this). `0` = never polled.
    /// A value *below* [`Self::seen`] is the lineage-deadlock signature.
    pub hub_generation: std::sync::atomic::AtomicU64,
    /// Whether the live policy came from the node-local update channel
    /// (`state/policy`) rather than the pack's embedded snapshot — updates
    /// it when an accepted hub pull lands there.
    pub state_channel: std::sync::atomic::AtomicBool,
    /// Control-plane pulls that failed at the transport/session level
    /// (a mid-rebuild session, a protocol violation), since watcher start.
    /// A permanently-failing pull channel is the 2026-10-07 bug's signature
    /// — this counter is what makes it machine-visible instead of a
    /// debug-level rumor.
    pub pull_failures_total: AtomicU64,
    /// Unix seconds of the last successful control-plane poll (`UpToDate`
    /// and `Update` alike). `0` = the watcher has never completed a pull —
    /// on a connected agent that means the distribution plane is dead, not
    /// idle.
    pub pull_last_ok_unix: AtomicU64,
    /// Unix seconds of the watcher's most recent wake (tick or session
    /// event). A value frozen in the past while the agent is running means
    /// the watcher task itself is dead — liveness made observable instead
    /// of trusted.
    pub last_tick_unix: AtomicU64,
    /// The subscription face. The sender lives exactly as long as this
    /// struct's `Arc` — when the watcher task ends and the handles drop,
    /// receivers observe it as a closed channel, which is the intended
    /// shutdown signal for forwarders (no separate token needed).
    snapshot_tx: watch::Sender<PolicyWatchSnapshot>,
}

impl Default for PolicyWatchState {
    fn default() -> Self {
        let (snapshot_tx, _) = watch::channel(PolicyWatchSnapshot::default());
        Self {
            snapshot_tx,
            seen: Default::default(),
            hub_generation: Default::default(),
            state_channel: Default::default(),
            pull_failures_total: Default::default(),
            pull_last_ok_unix: Default::default(),
            last_tick_unix: Default::default(),
        }
    }
}

impl PolicyWatchState {
    /// Reads all six live values at one instant.
    pub fn snapshot(&self) -> PolicyWatchSnapshot {
        PolicyWatchSnapshot {
            seen: self.seen.load(Ordering::Acquire),
            hub_generation: self.hub_generation.load(Ordering::Acquire),
            state_channel: self.state_channel.load(Ordering::Acquire),
            pull_failures_total: self.pull_failures_total.load(Ordering::Acquire),
            pull_last_ok_unix: self.pull_last_ok_unix.load(Ordering::Acquire),
            last_tick_unix: self.last_tick_unix.load(Ordering::Acquire),
        }
    }

    /// Pushes the current values to every subscriber. A send with an
    /// unchanged snapshot wakes nobody (watch semantics), so publishing
    /// generously is free — `last_tick_unix` moves every iteration anyway.
    /// A receiver-less send is likewise a no-op.
    fn publish(&self) {
        let _ = self.snapshot_tx.send(self.snapshot());
    }

    /// Subscribes to value changes from here on. The returned receiver
    /// yields the watcher's next publish (at most one interval away) and
    /// errors once the watcher — and every handle to this state — is gone.
    pub fn subscribe(&self) -> watch::Receiver<PolicyWatchSnapshot> {
        self.snapshot_tx.subscribe()
    }
}

/// The armed watcher's pack-derived inputs — everything the pull channel
/// needs that a per-tick pack reload cannot re-derive cheaply.
struct Armed {
    /// The trust bundle's policy verification key (hex) — hub-served bytes
    /// verify against this before anything else.
    verifier_key: String,
    /// The anti-rollback watermark; advances only on a successful apply.
    seen: u64,
}

/// Spawns the policy watcher onto the agent's task group. The task rides
/// the agent's own lifecycle: same tracker, same shutdown token — it ends
/// with [`super::AgentHandle::shutdown_graceful`], never before or after.
/// Returns the shared live state for health faces.
#[allow(clippy::too_many_arguments)] // session wiring handles are passed explicitly one by one
pub(crate) fn spawn(
    pack_dir: PathBuf,
    client: AgentClient,
    tunnel: AgentTunnel,
    state_rx: watch::Receiver<AgentState>,
    shutdown: &CancellationToken,
    tracker: &TaskTracker,
    transport: TransportKind,
    log_name: String,
    service_addresses: Option<crate::config::ServiceAddresses>,
) -> Arc<PolicyWatchState> {
    let watch = Arc::new(PolicyWatchState::default());
    let state = Arc::clone(&watch);
    let shutdown = shutdown.clone();
    tracker.spawn(async move {
        run(
            pack_dir,
            client,
            tunnel,
            state_rx,
            shutdown,
            Face {
                transport,
                log_name,
                service_addresses,
            },
            state,
        )
        .await;
    });
    watch
}

/// The watcher's rule-face inputs: log identity, transport tag, and the
/// expose face's address table (`None` = the mesh derivation).
struct Face {
    transport: TransportKind,
    log_name: String,
    service_addresses: Option<crate::config::ServiceAddresses>,
}

/// The watcher body. Arming (the initial pack load) is retried each tick:
/// a pack torn mid-update at spawn must defer the plane, not kill it.
async fn run(
    pack_dir: PathBuf,
    client: AgentClient,
    tunnel: AgentTunnel,
    mut state_rx: watch::Receiver<AgentState>,
    shutdown: CancellationToken,
    face: Face,
    watch: Arc<PolicyWatchState>,
) {
    let Face {
        transport,
        log_name,
        service_addresses,
    } = face;
    let transport = if transport == TransportKind::Quic {
        "quic"
    } else {
        "h2"
    };
    let policy_dir = pack_dir.join("state/policy");
    let mut fingerprint = policy_channel_fingerprint(&policy_dir);
    let mut armed = try_arm(&pack_dir, &watch, &log_name);
    if let Some(a) = &armed {
        info!(
            node = %log_name,
            build = %interflow_buildinfo::BUILD_TAG,
            transport,
            watermark = a.seen,
            interval_secs = POLICY_WATCH_INTERVAL.as_secs(),
            "policy watcher armed (node-local channel + hub control-plane pull)"
        );
    } else {
        warn!(
            node = %log_name,
            "policy watcher: pack unreadable at start — arming deferred, retried every {}s",
            POLICY_WATCH_INTERVAL.as_secs()
        );
    }

    // The hub generation whose inversion against the local watermark has
    // already been warned about — a crossing is news once; the steady state
    // (still inverted) is not.
    let mut warned_stale_at: u64 = 0;
    // The pull-failure reason already warned about — a dead channel is news
    // once; a flapping one is bounded by its distinct reasons. Any
    // successful poll resets it, so a failure after recovery warns again.
    let mut warned_pull_error: Option<String> = None;
    // The generation whose persist failure has been warned about — the hub
    // keeps serving it until it lands, so the failure would repeat every
    // tick.
    let mut warned_persist_at: Option<u64> = None;

    // An already-connected session (the watcher can spawn after a fast
    // establish) pulls immediately; later sessions trigger on the Connected
    // transition itself.
    let mut session_event = matches!(&*state_rx.borrow_and_update(), AgentState::Connected { .. });
    let mut next_tick = tokio::time::Instant::now() + POLICY_WATCH_INTERVAL;

    // The last successfully applied policy, cached for the override channel:
    // an address edit re-derives the egress table from THIS policy (same
    // generation — anti-rollback is about generations, and re-applying the
    // current one is a no-op watermark-wise). The expose face only.
    let mut applied: Option<(RuntimePolicy, String)> = None;
    let mut embedded_applied = false;
    let mut addresses_rx = service_addresses
        .as_ref()
        .map(crate::config::ServiceAddresses::subscribe);

    loop {
        watch.last_tick_unix.store(now_unix(), Ordering::Release);
        // Publish at the top of every iteration: the previous iteration's
        // writes (wherever they happened — pull branches, `try_reload`, a
        // re-arm) reach subscribers no matter which path cycled the loop,
        // including every `continue` that would skip a trailing publish.
        watch.publish();
        let due_now = session_event;
        session_event = false;
        if !due_now {
            let addresses_changed = async {
                match addresses_rx.as_mut() {
                    Some(rx) => rx.changed().await.map_err(|_| ()),
                    None => std::future::pending().await,
                }
            };
            tokio::select! {
                () = shutdown.cancelled() => return,
                () = tokio::time::sleep_until(next_tick) => {}
                changed = state_rx.changed() => {
                    if changed.is_err() {
                        // The supervisor (the state sender) is gone — the
                        // agent is shutting down; ride out with it.
                        return;
                    }
                    // borrow_and_update (not borrow): the change must be
                    // marked seen, else `changed()` re-fires on the same
                    // transition forever — a hot loop.
                    if matches!(
                        &*state_rx.borrow_and_update(),
                        AgentState::Connected { .. }
                    ) {
                        session_event = true;
                    }
                    continue;
                }
                result = addresses_changed => {
                    if result.is_ok() {
                        // A machine-local override moved: re-derive the
                        // egress table from the cached current policy.
                        // Same-generation, fail-keep — a bad edit (or no
                        // cached policy yet: the watcher has not applied
                        // anything) changes nothing until the next real
                        // derivation.
                        if let Some((policy, node)) = &applied
                            && let Some(addresses) = &service_addresses
                        {
                            rederive_egress_from_cached(policy, node, addresses, &client, &log_name)
                                .await;
                        }
                    } else {
                        // The table handle is gone (agent teardown) — stop
                        // selecting on it.
                        addresses_rx = None;
                    }
                    continue;
                }
            }
        }
        if next_tick <= tokio::time::Instant::now() {
            next_tick = tokio::time::Instant::now() + POLICY_WATCH_INTERVAL;
        } else {
            next_tick += POLICY_WATCH_INTERVAL;
        }

        // (Re)arming: nothing below can run without the trust bundle.
        if armed.is_none() {
            armed = try_arm(&pack_dir, &watch, &log_name);
            if let Some(a) = &armed {
                info!(
                    node = %log_name,
                    build = %interflow_buildinfo::BUILD_TAG,
                    transport,
                    watermark = a.seen,
                    interval_secs = POLICY_WATCH_INTERVAL.as_secs(),
                    "policy watcher armed (node-local channel + hub control-plane pull)"
                );
                // Expose face only, once per run: apply the pack's
                // EFFECTIVE policy (state-channel override included) so a
                // restart picks up updates that landed while the node was
                // stopped — the mesh face gets the same guarantee from
                // `build_agent_config` deriving its startup rules from the
                // effective policy; the expose seed comes from the pack's
                // node.toml render, so this pass is what reconciles the
                // two. `seen` already equals the effective generation, so
                // later `policy_update` probes stay correctly conditional.
                if !embedded_applied {
                    if let Some(addresses) = &service_addresses {
                        apply_effective_policy(
                            &pack_dir,
                            addresses,
                            &client,
                            &log_name,
                            &mut applied,
                        )
                        .await;
                    }
                    embedded_applied = true;
                }
            }
            continue;
        }
        let Some(Armed {
            ref verifier_key,
            ref mut seen,
        }) = armed
        else {
            unreachable!("armed is Some here");
        };

        // Channel 1: the node-local file drop.
        let current = policy_channel_fingerprint(&policy_dir);
        if current != fingerprint {
            fingerprint = current;
            try_reload(
                &pack_dir,
                &client,
                seen,
                &watch,
                &log_name,
                service_addresses.as_ref(),
                &mut applied,
            )
            .await;
        }

        // Channel 2: the hub's control plane, as a conditional request: a
        // hub serving at or below the caller's watermark answers
        // "unchanged" (carrying its serving generation); a hub with no
        // policy face says so explicitly; a pull that fails (a session
        // mid-rebuild, a protocol violation — never tolerated silently)
        // is skipped for this tick — and made visible: the first
        // occurrence of each distinct reason warns (the 2026-10-07
        // lesson — a channel that fails every tick forever must not look
        // like silence), repeats stay at debug.
        match tunnel.pull_policy(*seen).await {
            Err(e) => {
                watch.pull_failures_total.fetch_add(1, Ordering::Relaxed);
                let reason = e.to_string();
                if warned_pull_error.as_deref().is_none_or(|w| w != reason) {
                    warn!(
                        node = %log_name,
                        build = %interflow_buildinfo::BUILD_TAG,
                        transport,
                        "policy pull failing: {reason} — hub-served updates will not reach \
                         this node while this persists (retried every {}s)",
                        POLICY_WATCH_INTERVAL.as_secs()
                    );
                    warned_pull_error = Some(reason);
                } else {
                    debug!(node = %log_name, "policy pull skipped this tick: {reason}");
                }
            }
            Ok(PolicyPull::NoPolicyFace) => {
                // The roundtrip itself succeeded: reset the failure dedup and
                // record liveness, but there is no generation to report — the
                // node-local file channel remains the only distribution path.
                warned_pull_error = None;
                watch.pull_last_ok_unix.store(now_unix(), Ordering::Release);
                debug!(
                    node = %log_name,
                    "policy pull: hub carries no policy distribution face \
                     (node-local channel only)"
                );
            }
            Ok(PolicyPull::UpToDate { hub_generation }) => {
                warned_pull_error = None;
                watch.pull_last_ok_unix.store(now_unix(), Ordering::Release);
                watch
                    .hub_generation
                    .store(hub_generation, Ordering::Release);
                // Deadlock signature via the watermark-floor half of the
                // generational-handle contract (the shared
                // compare-before-mutate implementation): the hub serves
                // BELOW this node's watermark, so every future publish
                // below the watermark is dead on arrival here.
                if !floor_epoch(&hub_generation, seen).is_current() {
                    if warned_stale_at == hub_generation {
                        debug!(
                            node = %log_name,
                            "policy pull: hub still at generation {hub_generation} below \
                             local watermark {seen}"
                        );
                    } else {
                        warned_stale_at = hub_generation;
                        warn!(
                            node = %log_name,
                            "policy pull: hub serves generation {hub_generation} below this \
                             node's watermark {seen} — hub-served updates will be rejected \
                             as stale until the lineage catches up (check the issuer store's \
                             policy generation)"
                        );
                    }
                }
            }
            Ok(PolicyPull::Update(fetch)) => {
                warned_pull_error = None;
                watch.pull_last_ok_unix.store(now_unix(), Ordering::Release);
                watch
                    .hub_generation
                    .store(fetch.generation, Ordering::Release);
                if fetch.generation <= *seen {
                    // A hub that answered 200 below the watermark despite
                    // the conditional request — refuse with both
                    // generations on the record.
                    warn!(
                        node = %log_name,
                        "policy pull: rejecting hub-served generation {} (keeping current \
                         {seen}): stale",
                        fetch.generation
                    );
                    continue;
                }
                match RuntimePolicy::verify_with_hex_key(
                    &fetch.body,
                    &fetch.signature,
                    verifier_key,
                ) {
                    Ok(policy) => {
                        if let Err(e) = policy.check_not_rollback(*seen) {
                            warn!(
                                node = %log_name,
                                "policy pull: rejecting hub-served generation {} (keeping \
                                 current): {e}",
                                fetch.generation
                            );
                        } else {
                            // Persist into the node-local channel first: the
                            // applying path (and any restart) reads exactly
                            // these files.
                            let channel_dir = pack_dir.join("state/policy");
                            if let Err(e) = std::fs::create_dir_all(&channel_dir) {
                                warn!(node = %log_name, "policy pull: cannot persist update: {e}");
                            } else {
                                let write = |name: &str, bytes: &[u8]| {
                                    let path = channel_dir.join(name);
                                    let tmp = channel_dir.join(format!("{name}.tmp"));
                                    std::fs::write(&tmp, bytes)
                                        .and_then(|()| std::fs::rename(&tmp, &path))
                                };
                                if let Err(e) = write("policy.toml", &fetch.body)
                                    .and_then(|()| write("policy.sig", &fetch.signature))
                                {
                                    if warned_persist_at != Some(fetch.generation) {
                                        warned_persist_at = Some(fetch.generation);
                                        warn!(
                                            node = %log_name,
                                            "policy pull: persisting generation {} failed: \
                                             {e} — the hub will re-serve it every pull until \
                                             this lands",
                                            fetch.generation
                                        );
                                    }
                                } else {
                                    fingerprint = policy_channel_fingerprint(&policy_dir);
                                    watch.state_channel.store(true, Ordering::Release);
                                    info!(
                                        target: "audit",
                                        node = %log_name,
                                        generation = fetch.generation,
                                        "policy pull: accepted hub-served update into the \
                                         node-local channel"
                                    );
                                    try_reload(
                                        &pack_dir,
                                        &client,
                                        seen,
                                        &watch,
                                        &log_name,
                                        service_addresses.as_ref(),
                                        &mut applied,
                                    )
                                    .await;
                                }
                            }
                        }
                    }
                    Err(e) => {
                        warn!(
                            node = %log_name,
                            "policy pull: rejecting hub-served bytes (keeping current): {e}"
                        );
                    }
                }
            }
        }
    }
}

/// Seeds the watcher from the pack: the trust bundle's policy key plus the
/// authoritative watermark (state-channel override included), mirrored into
/// the shared state so health faces read the real baseline, not the
/// struct's zero default.
fn try_arm(pack_dir: &Path, watch: &PolicyWatchState, log_name: &str) -> Option<Armed> {
    let pack = CredentialPack::load_runtime(pack_dir)
        .map_err(pack_error)
        .map_err(|e| {
            debug!(node = %log_name, "policy watcher: pack reload failed (torn update?), retrying next tick: {e}");
            e
        })
        .ok()?;
    watch.seen.store(pack.policy.generation, Ordering::Release);
    watch
        .state_channel
        .store(pack.policy_from_state_channel, Ordering::Release);
    // The seed baseline, pushed immediately: a subscriber that attaches
    // before the first tick reads the armed watermark, not the zero
    // default.
    watch.publish();
    Some(Armed {
        verifier_key: pack.trust.metadata.policy_key.clone(),
        seen: pack.policy.generation,
    })
}

/// One apply attempt from the node-local channel: reload the pack (trust
/// bundle + update channel), verify + anti-rollback check, derive, apply.
/// `seen` advances only on a successful application (mirrored into `watch`).
async fn try_reload(
    dir: &Path,
    client: &AgentClient,
    seen: &mut u64,
    watch: &PolicyWatchState,
    log_name: &str,
    service_addresses: Option<&crate::config::ServiceAddresses>,
    applied: &mut Option<(RuntimePolicy, String)>,
) {
    // Re-load the pack for the trust bundle + update channel; a torn copy
    // mid-write fails here and is retried next tick.
    let Ok(pack) = CredentialPack::load_runtime(dir) else {
        warn!(node = %log_name, "policy reload: pack reload failed (torn update?), keeping current policy");
        return;
    };
    let node = pack.metadata.node.clone();
    let workspace = pack.metadata.workspace.clone().unwrap_or_default();
    match pack.policy_update(*seen) {
        Ok(Some(update)) => {
            let generation = update.policy.generation;
            // The rule face: mesh agents derive from the policy's mesh
            // tables; expose agents (config carries the address table) derive
            // one egress rule per service id × node-side resolution.
            let derived = match service_addresses {
                Some(addresses) => policy_service_egress_rules(&update.policy, &node, addresses)
                    .map(|(egress, allowed)| (Vec::new(), egress, allowed)),
                None => match (
                    policy_ingress_rules(&update.policy, &node, &workspace),
                    policy_egress_rules(&update.policy, &node),
                ) {
                    (Ok(i), Ok((e, a))) => Ok((i, e, a)),
                    (Err(e), _) | (_, Err(e)) => Err(e),
                },
            };
            match derived {
                Ok((ingress, egress, allowed)) => {
                    let signature = interflow_util::sha256_hex(&update.signature);
                    info!(
                        target: "audit",
                        node = %node,
                        generation,
                        signature_fingerprint = %signature,
                        ingress_rules = ingress.len(),
                        egress_rules = egress.len(),
                        "policy reload: applying signed policy update"
                    );
                    client.apply_policy(ingress, egress, allowed).await;
                    *seen = generation;
                    if service_addresses.is_some() {
                        *applied = Some((update.policy.clone(), node.clone()));
                    }
                    watch.seen.store(generation, Ordering::Release);
                    watch
                        .state_channel
                        .store(pack.policy_from_state_channel, Ordering::Release);
                }
                Err(e) => {
                    // The signed face is unusable on this node — keep the
                    // current policy; a corrected re-drop (new fingerprint)
                    // retries cleanly.
                    tracing::error!(
                        node = %node,
                        "policy reload: update does not derive valid rules, keeping current \
                         policy: {e}"
                    );
                }
            }
        }
        Ok(None) => {}
        Err(e) => {
            warn!(
                node = %node,
                "policy reload: rejecting update (keeping current policy): {e}"
            );
        }
    }
}

/// The expose face's arm-time pass: derive the startup rules from the
/// pack's effective policy (the state-channel override wins over the
/// embedded snapshot) and cache it as the current face. Idempotent by
/// construction — the whole table is replaced, the generation does not
/// move.
async fn apply_effective_policy(
    pack_dir: &Path,
    addresses: &crate::config::ServiceAddresses,
    client: &AgentClient,
    log_name: &str,
    applied: &mut Option<(RuntimePolicy, String)>,
) {
    let Ok(pack) = CredentialPack::load_runtime(pack_dir) else {
        // try_arm just succeeded on this directory; a second failure is a
        // torn write racing us — the next tick retries nothing here (the
        // flag is set), but any state-channel update re-arms the whole
        // watcher. Log and move on.
        tracing::warn!(
            node = %log_name,
            "policy watcher: pack reload failed at the expose arm pass — serving the seed table"
        );
        return;
    };
    let node = pack.metadata.node.clone();
    match policy_service_egress_rules(&pack.policy, &node, addresses) {
        Ok((egress, allowed)) => {
            info!(
                node = %log_name,
                generation = pack.policy.generation,
                services = egress.len(),
                "expose face: applying the pack's effective policy (state-channel override                  included) as the startup service set"
            );
            client.apply_policy(Vec::new(), egress, allowed).await;
            *applied = Some((pack.policy.clone(), node));
        }
        Err(e) => {
            tracing::error!(
                node = %log_name,
                "expose face: effective policy does not derive valid rules, keeping the seed                  table: {e}"
            );
        }
    }
}

/// Re-derives the egress table from a cached policy after an override
/// edit — the expose face's live address channel. Same-generation apply:
/// the watermark does not move, established streams drain untouched, the
/// next Open dials the new target.
async fn rederive_egress_from_cached(
    policy: &RuntimePolicy,
    node: &str,
    addresses: &crate::config::ServiceAddresses,
    client: &AgentClient,
    log_name: &str,
) {
    match policy_service_egress_rules(policy, node, addresses) {
        Ok((egress, allowed)) => {
            info!(
                node = %log_name,
                generation = policy.generation,
                services = egress.len(),
                "address override changed: re-derived egress table from the current policy"
            );
            client.apply_policy(Vec::new(), egress, allowed).await;
        }
        Err(e) => {
            tracing::error!(
                node = %log_name,
                "address override change does not derive valid rules, keeping current table: {e}"
            );
        }
    }
}

fn now_unix() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}
