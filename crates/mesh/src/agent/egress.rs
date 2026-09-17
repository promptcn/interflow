//! Egress handler: a per-stream forwarder for request-direction streams
//! (2026-09-12 final-state refactor).
//!
//! The old model (a single loop consuming broadcast + global
//! `backend_connections`/`stream_targets` tables) had two structural flaws:
//! broadcast overflow silently dropped frames (TCP streams missing bytes),
//! and a single slow backend dragged the whole consume loop to a halt,
//! amplifying into corruption of all streams. The new model:
//!
//! - dispatch (core) creates a dedicated mpsc channel per request-direction
//!   Open and hands it to this module via [`IncomingStream`] — the frame path
//!   has backpressure and drops no frames;
//! - one independent forwarder task per stream, holding all of that stream's
//!   state (target address, backend connection, frame channel): a single
//!   stalled stream only blocks itself, end-of-stream state dies with the
//!   task, and there is no global table to leak;
//! - a backend write stall beyond `backend_write_timeout` kills the stream
//!   (close connection + Close notification); the stall converges on both
//!   directions through a bounded wait poisoning dispatch (channel closed,
//!   `recv() == None`).
//!
//! Lifecycle invariant (2026-09-14 fd-leak root fix): forwarders hang off the
//! **session-level** TaskTracker and hold the session token — session end
//! (watchdog/disconnect/shutdown) makes them exit in place, and both halves
//! release the backend fd as the task drops; the tunnel-side termination
//! contract ([`interflow_core::tunnel::TunnelTransport::shutdown`]) clears the
//! dispatch tables as a fallback. All blocking points (`frames.recv` /
//! response send / wind-down Close) sit under the token or a timeout, so
//! structurally no await can hang
//! (docs/bug/2026-09-14-egress-fd-leak-session-rebuild.md).
//!
//! Open-flood resource defenses (2026-09-12 backlog: open-flood DoS surface;
//! hardened 2026-09-16 with per-target isolation — see
//! `docs/bug/2026-09-16-egress-global-rate-limit-starvation.md`):
//!
//! - **per-target circuit breaker** (`egress_target_breaker_*`): connect
//!   -phase failures are counted per backend target in a sliding window; a
//!   tripped target is rejected pre-dial **without consuming the open-rate
//!   budget**, so one dead target's retry storm cannot starve healthy
//!   targets (the 2026-09-16 case: an edge route to a dead local port plus
//!   a public retry loop took down every healthy route on the agent);
//! - **stream-open rate limit** (`max_stream_opens_per_sec`): open/close
//!   churn can stay forever below the concurrency cap while every Open still
//!   triggers resolve + connect against a real backend — the rate limit keeps
//!   sustained churn within budget, preventing the agent from becoming a
//!   connection-flood reflection surface aimed at the internal network.
//!   Charged only for opens that pass the cheap gates and will actually
//!   reach the dial path;
//! - **local concurrent stream cap** (`max_incoming_streams`): a second gate
//!   beyond the hub's `max_streams_per_agent`; even with a hub config slip
//!   the agent itself still has a ceiling;
//! - **dial timeouts** (resolve/connect): black-hole addresses no longer hold
//!   slots for the OS default ~75s. All rejections reply Close so the
//!   source fails fast, and bump the
//!   `interflow_agent_open_dropped_total{reason}` counter.
//!
//! Misrouting guard: with no dynamic target (empty Open payload target),
//! fall back only to an **exact** protocol match on egress rules; no match
//! means reject + Close — never fall through to the first rule (the old
//! `.or_else(rules.first())` would send bytes to an unrelated backend).

use crate::agent::control::{ControlOpError, EgressCommand};
use crate::agent::ingress_udp::UDP_RECV_BUF;
use crate::agent::rules::RuleStore;
use crate::agent::target_breaker::{BreakerDecision, BreakerKind, TargetBreakers};
use crate::config::{AgentConfig, EgressRule, SecurityConfig};
use bytes::{Bytes, BytesMut};
use interflow_core::config::params::BreakerPolicy;
use interflow_core::error::{InterflowError, Result};
use interflow_core::protocol::{CloseReason, FrameType, StreamProto};
use interflow_core::security::EventRateLimiter;
use interflow_core::tunnel::{AgentTunnel, IncomingStream, TunnelData};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::time::{Duration, Instant};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;
use tokio_util::task::TaskTracker;
use tracing::{debug, error, info, warn};

/// Bounded wait for sending back to the hub (response-direction send): when
/// the upstream channel is full/stalled (a pathological one-sided data
/// plane), the read side kills the stream rather than hang — fd release
/// takes priority over the last in-flight segment of data.
const RESPONSE_SEND_TIMEOUT: Duration = Duration::from_secs(10);

/// Session-level send-path stall threshold: send **demand** exists yet
/// nothing has gotten through for this long ⇒ the session (not the
/// individual stream) is declared wedged and torn down for reconnect.
///
/// The unit that actually failed is the session: when the whole send path
/// stalls, letting the per-stream guard above execute N streams one by one
/// is slower and noisier than failing the session once (design note from
/// the 2026-09-16 quic egress-stall case file). 3× the per-stream timeout
/// keeps the escalation strictly behind per-stream protection.
const SESSION_SEND_STALL_TIMEOUT: Duration = Duration::from_secs(30);

/// Session-wide send-path health: two lock-free clocks (same pattern as the
/// pump's `SharedProgress`) — last send **attempt** (demand) vs last send
/// **success**. Starvation is only declared when demand outlives success; an
/// idle session with no sends is healthy by definition.
///
/// Only the response-**data** send path participates: the Close-echo path
/// deliberately abandons its 1s sends during teardown ("expected during
/// session teardown") and must not count as unfulfilled demand.
struct SendPathHealth {
    /// `tokio::time::Instant` keeps paused-clock unit tests exact.
    epoch: tokio::time::Instant,
    last_attempt_us: AtomicU64,
    last_success_us: AtomicU64,
}

impl SendPathHealth {
    fn new() -> Self {
        Self {
            epoch: tokio::time::Instant::now(),
            last_attempt_us: AtomicU64::new(0),
            last_success_us: AtomicU64::new(0),
        }
    }

    fn note_attempt(&self) {
        self.last_attempt_us
            .store(self.elapsed_us(), Ordering::Release);
    }

    fn note_success(&self) {
        self.last_success_us
            .store(self.elapsed_us(), Ordering::Release);
    }

    /// How long send demand has existed without a single success; `None`
    /// when healthy (no pending demand, or successes keep flowing).
    fn demand_starved_for(&self) -> Option<Duration> {
        let last_attempt = self.last_attempt_us.load(Ordering::Acquire);
        let last_success = self.last_success_us.load(Ordering::Acquire);
        if last_attempt <= last_success {
            return None; // every demand has been met
        }
        Some(Duration::from_micros(
            self.elapsed_us().saturating_sub(last_success),
        ))
    }

    #[allow(clippy::cast_possible_truncation)] // wraps after ~585k years; the epoch is per-session
    fn elapsed_us(&self) -> u64 {
        tokio::time::Instant::now()
            .checked_duration_since(self.epoch)
            .map_or(0, |d| d.as_micros() as u64)
    }
}

/// Bounded wait for the wind-down Close notification: the wind-down path
/// (including session teardown) never hangs on a full-channel send; on
/// timeout the notification is abandoned (the peer has its own timeout
/// reclamation).
const CLOSE_NOTIFY_TIMEOUT: Duration = Duration::from_secs(1);

/// Bounded drain window after backend EOF.
///
/// After the backend sends FIN, under half-close semantics the source may
/// still have an in-flight request tail to land (HTTP pipelining, client
/// shutdown(write), etc.): within the window we keep consuming `frames` and
/// writing to the backend; when the window ends, close out and release the
/// fd. This replaces "waiting indefinitely for the peer's `_close_`" — a
/// lost hub-side close notification (the historical try-send drop path) once
/// left `write_half` and the backend fd lingering for the whole session
/// (docs/bug/2026-09-14-intrasession-orphan-stream-fd-leak.md).
/// Note: this is a fallback anchored on the certain fact "the backend is
/// dead", not an idle timeout — the design decision of no per-stream idle
/// timeout (to avoid killing SSE/HMR long connections on false positives)
/// stands unchanged.
const BACKEND_EOF_DRAIN_GRACE: Duration = Duration::from_secs(5);

/// Egress session resource policy: dial/write-stall timeouts (pure duration
/// parameters, no cross-session state).
#[allow(clippy::struct_field_names)] // each of the three timeouts governs one path; their semantics resist merged naming
pub struct EgressPolicy {
    /// Tolerance for a single stalled backend frame write: beyond it the
    /// stream is killed.
    backend_write_timeout: Duration,
    /// Backend DNS resolution timeout: a black-hole resolver must not fill
    /// the slots.
    resolve_timeout: Duration,
    /// Backend TCP connect timeout: a black-hole address must not fill the
    /// slots.
    connect_timeout: Duration,
}

impl From<&AgentConfig> for EgressPolicy {
    fn from(config: &AgentConfig) -> Self {
        Self {
            // 0 is rejected at validation time (validate_agent) — no
            // silent runtime clamping.
            backend_write_timeout: Duration::from_secs(config.egress_backend_write_timeout_secs),
            resolve_timeout: Duration::from_secs(config.egress_resolve_timeout_secs),
            connect_timeout: Duration::from_secs(config.egress_connect_timeout_secs),
        }
    }
}

impl From<&AgentConfig> for BreakerPolicy {
    fn from(config: &AgentConfig) -> Self {
        Self {
            failure_threshold: config.egress_target_breaker_failure_threshold,
            failure_window: Duration::from_secs(config.egress_target_breaker_window_secs),
            cooldown: Duration::from_secs(config.egress_target_breaker_cooldown_secs),
        }
    }
}

/// Egress flood-line runtime (**agent-level**, shared across sessions, held
/// by [`crate::agent::client::AgentClient`]).
///
/// The concurrency counter and rate buckets are not reset on session
/// rebuild: live/lingering flows from the previous session must keep
/// consuming quota, otherwise the local concurrency cap goes blind to
/// cross-session leftovers — creating fresh counters per session was one of
/// the root causes of the defenses going blind during the fd leak
/// (docs/bug/2026-09-14-egress-fd-leak-session-rebuild.md).
pub struct EgressRuntime {
    /// Local cap on concurrent incoming streams (0 = unlimited); a second
    /// gate beyond the hub quota.
    max_incoming_streams: usize,
    /// Agent-level count of active incoming streams (always incremented at
    /// the head, uniformly decremented in finish).
    active: AtomicUsize,
    /// Stream-open rate limit (None = disabled); the budget gate against the
    /// churn reflection surface.
    open_rate_limiter: Option<EventRateLimiter>,
    /// Per-target connect-phase circuit breaker (None = disabled). The
    /// isolation gate: a dead target's retry storm is rejected pre-dial and
    /// without consuming the shared open-rate budget above, so healthy
    /// targets keep their full budget (2026-09-16 starvation case file).
    breakers: Option<Arc<TargetBreakers>>,
}

impl EgressRuntime {
    pub fn from_config(config: &AgentConfig) -> Self {
        let breakers = config.egress_target_breaker_enabled.then(|| {
            Arc::new(TargetBreakers::new(
                BreakerKind::Egress,
                BreakerPolicy::from(config),
            ))
        });
        Self {
            max_incoming_streams: config.max_incoming_streams,
            active: AtomicUsize::new(0),
            open_rate_limiter: EventRateLimiter::new(
                config.max_stream_opens_per_sec,
                config.stream_open_burst,
            ),
            breakers,
        }
    }
}

/// The egress handler.
pub struct EgressHandler {
    agent_id: String,
    tunnel: AgentTunnel,
    /// Cross-session rule truth (in-memory + write-through persistence); the
    /// hot path matches against a local snapshot.
    store: Arc<RuleStore>,
    security: SecurityConfig,
    /// Session resource policy (timeout parameters).
    policy: EgressPolicy,
    /// Agent-level flood-line defenses (shared across sessions).
    runtime: Arc<EgressRuntime>,
    /// Session token: the lifecycle anchor of all forwarders — session end
    /// (watchdog/disconnect/shutdown) makes them exit in place, and backend
    /// connection fds release with the task.
    session: CancellationToken,
    /// Session-level task tracker: forwarders hang off it and close out
    /// boundedly in the teardown sequence.
    tracker: TaskTracker,
    command_rx: Option<mpsc::Receiver<EgressCommand>>,
    /// Request-direction new-stream events (handed over by dispatch,
    /// take-once).
    incoming: mpsc::Receiver<IncomingStream>,
}

/// Exit categories of the read task (backend -> hub): the basis on which the
/// main loop wakes up to self-heal.
///
/// Before 37808dc, after the read task exited the main loop still blocked
/// indefinitely in `frames.recv()`, waiting for a peer `_close_` that might
/// never come — `write_half` and the backend fd lingered for the whole
/// session. A oneshot send-then-recv loses no signal, so read-task exit is
/// guaranteed to arrive.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum BackendExit {
    /// Clean backend EOF: the main loop enters a [`BACKEND_EOF_DRAIN_GRACE`]
    /// bounded drain, then closes out.
    CleanEof,
    /// Sending back to the hub failed/stalled (this stream's response
    /// direction is pathological): the main loop closes out immediately.
    UpstreamSick,
    /// Error reading the backend: the main loop closes out immediately.
    ReadError,
}

impl EgressHandler {
    /// High-water warning for active incoming streams (**once on the rising
    /// edge**): accumulation of orphan streams/leaks surfaces early in the
    /// logs instead of being discovered at EMFILE. With a local cap
    /// configured it is 80% of it, otherwise a fixed 128 (half of the macOS
    /// GUI soft cap of 256).
    fn warn_high_water(runtime: &EgressRuntime, current: usize) {
        let high_water = if runtime.max_incoming_streams > 0 {
            runtime.max_incoming_streams / 5 * 4
        } else {
            128
        };
        if current == high_water.max(1) {
            warn!(
                "Active incoming streams reached high-water mark {high_water}: if this keeps growing, check the stream teardown path\
                 (interflow_egress_stream_closed_total{{reason}} / \
                 interflow_agent_incoming_streams_active)"
            );
        }
    }

    #[allow(clippy::too_many_arguments, clippy::missing_const_for_fn)]
    pub fn new(
        agent_id: String,
        tunnel: AgentTunnel,
        store: Arc<RuleStore>,
        security: SecurityConfig,
        policy: EgressPolicy,
        runtime: Arc<EgressRuntime>,
        session: CancellationToken,
        tracker: TaskTracker,
        command_rx: Option<mpsc::Receiver<EgressCommand>>,
        incoming: mpsc::Receiver<IncomingStream>,
    ) -> Self {
        Self {
            agent_id,
            tunnel,
            store,
            security,
            policy,
            runtime,
            session,
            tracker,
            command_rx,
            incoming,
        }
    }

    pub async fn run(self) -> Result<()> {
        info!("Egress handler started, agent_id={}", self.agent_id);

        // The hot path matches against a local snapshot: taken from the
        // store at session start (including API additions from the previous
        // session), refreshed after command changes — per-stream matching is
        // lock-free.
        let mut rules = self.store.egress_snapshot().await;
        let security = self.security;
        let policy = self.policy;
        let runtime = self.runtime;
        let session = self.session;
        let tracker = self.tracker;
        let store = self.store;

        for rule in &rules {
            info!(
                "Configured egress rule: {} -> {}",
                rule.name, rule.target_addr
            );
        }

        let tunnel = self.tunnel;
        let mut command_rx = self.command_rx;
        let mut incoming = self.incoming;

        // Session-wide send-path health (see SendPathHealth): evaluated on a
        // 1s cadence in the main loop — no cross-task signaling needed.
        let send_health = Arc::new(SendPathHealth::new());
        let mut health_tick = tokio::time::interval(Duration::from_secs(1));
        health_tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

        loop {
            tokio::select! {
                // Session-level send-path health: demand present but nothing
                // getting through past SESSION_SEND_STALL_TIMEOUT ⇒ fail the
                // session once and reconnect, instead of letting the
                // per-stream 10s guard execute streams one by one.
                _ = health_tick.tick() => {
                    if let Some(starved) = send_health.demand_starved_for()
                        && starved >= SESSION_SEND_STALL_TIMEOUT
                    {
                        error!(
                            "Egress send path starved for {starved:?} (demand present, no success) — failing session for reconnect"
                        );
                        return Err(InterflowError::connection(
                            "egress send path starved session-wide (send stall)".to_string(),
                        ));
                    }
                }
                // Handle rule add/remove commands (all with an
                // acknowledgment; the store persists first, then memory)
                cmd_opt = async {
                    if let Some(rx) = &mut command_rx {
                        rx.recv().await
                    } else {
                        std::future::pending().await
                    }
                } => {
                    match cmd_opt {
                        Some(EgressCommand::Add(rule, resp_tx)) => {
                            info!("Added egress rule: {}", rule.name);
                            let res = store.add_egress(rule).await
                                .map_err(ControlOpError::from);
                            rules = store.egress_snapshot().await;
                            let _ = resp_tx.send(res);
                        }
                        Some(EgressCommand::Remove(name, resp_tx)) => {
                            info!("Removed egress rule: {}", name);
                            let res = store.remove_egress(&name).await
                                .map_err(ControlOpError::from);
                            rules = store.egress_snapshot().await;
                            let _ = resp_tx.send(res);
                        }
                        Some(EgressCommand::List(resp_tx)) => {
                            let views = store.egress_views().await;
                            let _ = resp_tx.send(views);
                        }
                        None => {
                            info!("Egress command channel closed");
                            command_rx = None;
                        }
                    }
                }

                // Handle a request-direction new stream: rate/concurrency
                // gates -> resolve target -> security checks -> spawn the
                // forwarder. Channel closed = tunnel dead (dispatch already
                // dropped) -> session-level fail-loud, reusing the client
                // supervisor's existing reconnect path.
                ev = incoming.recv() => {
                    if let Some(stream) = ev {
                        Self::handle_incoming_stream(
                            stream,
                            &tunnel,
                            &rules,
                            &security,
                            &policy,
                            &runtime,
                            &session,
                            &tracker,
                            &send_health,
                        )
                        .await;
                    } else {
                        error!("Egress incoming-stream channel closed (tunnel dead), triggering session reconnect");
                        return Err(InterflowError::connection(
                            "egress incoming-stream channel closed (tunnel dead)".to_string(),
                        ));
                    }
                }
            }
        }
    }

    /// Taking over a single new stream. Gate order is load-bearing (the
    /// 2026-09-16 starvation case file): **cheap, target-aware rejections
    /// run first and consume no shared budget** —
    ///
    /// 1. target resolution + security + per-target breaker (pure in-memory;
    ///    a tripped or denied open costs nothing),
    /// 2. stream-open rate limit (charged only for opens that will actually
    ///    reach the dial path, matching the limiter's reflection-surface
    ///    threat model — a flood of garbage opens can no longer drain the
    ///    budget that healthy targets share),
    /// 3. local concurrency cap.
    ///
    /// Every rejection path completes inline and echoes Close so the source
    /// fails fast; a passing path spawns an independent forwarder (holding
    /// the session token) via the session tracker, and the main loop
    /// immediately returns to waiting.
    ///
    /// The active count is always incremented at the head: the main loop
    /// consumes single-threaded (no check race), and every exit path of this
    /// function (inline rejection and forwarder wind-down) funnels uniquely
    /// into [`Self::finish`] for the decrement, so increment-first balances
    /// on every path.
    #[allow(clippy::too_many_arguments)] // session-scoped plumbing (tunnel/rules/security/policy/runtime/session/tracker)
    async fn handle_incoming_stream(
        stream: IncomingStream,
        tunnel: &AgentTunnel,
        rules: &[EgressRule],
        security: &SecurityConfig,
        policy: &EgressPolicy,
        runtime: &Arc<EgressRuntime>,
        session: &CancellationToken,
        tracker: &TaskTracker,
        send_health: &Arc<SendPathHealth>,
    ) {
        let IncomingStream { open, frames } = stream;
        let stream_id = open.stream_id.clone();
        let prev_active = runtime.active.fetch_add(1, Ordering::Relaxed);
        metrics::gauge!("interflow_agent_incoming_streams_active").increment(1.0);
        Self::warn_high_water(runtime, prev_active + 1);

        let proto = StreamProto::from_frame_flags(open.flags);

        // Open payload = "{target_agent}:{target_addr}" (the hub uses
        // target_agent for routing; egress cares only about target_addr; it
        // may be empty = no dynamic target).
        let payload = String::from_utf8_lossy(&open.data);
        let dynamic_target = payload
            .split_once(':')
            .filter(|&(_, target)| !target.is_empty())
            .map(|(_, target)| target.to_string());

        let matched_rule = rules.iter().find(|r| r.target_protocol == proto);
        let target = dynamic_target.or_else(|| {
            // Static fallback: exact protocol match only, never fall
            // through to the first rule (misrouting guard).
            matched_rule.map(|r| r.target_addr.to_string())
        });

        let Some(target) = target else {
            warn!(
                "rejecting target-less stream (no dynamic target and no exact protocol match rule): stream_id={}, proto={:?}, source={}",
                stream_id, proto, open.source
            );
            Self::finish(
                tunnel,
                &stream_id,
                CloseReason::NoTarget,
                true,
                &runtime.active,
            )
            .await;
            return;
        };

        if !Self::is_target_allowed(&target, security) {
            warn!(
                "Security block: denying access to target {} (source: {})",
                target, open.source
            );
            Self::finish(
                tunnel,
                &stream_id,
                CloseReason::SecurityDenied,
                true,
                &runtime.active,
            )
            .await;
            return;
        }

        // Isolation gate: a target whose connect-phase failures clustered
        // within the window is tripped OPEN — reject pre-dial, without
        // consuming the shared open-rate budget (one dead target's retry
        // storm must not starve healthy targets; per-stream rejections stay
        // at debug, the trip/recovery transitions log once in the table).
        if let Some(breakers) = &runtime.breakers
            && breakers.check(&target) == BreakerDecision::Reject
        {
            metrics::counter!(
                "interflow_agent_open_dropped_total",
                "reason" => CloseReason::TargetCircuitOpen.to_string()
            )
            .increment(1);
            debug!(
                "target circuit open, rejecting stream without dial: stream_id={}, target={}, source={}",
                stream_id, target, open.source
            );
            Self::finish(
                tunnel,
                &stream_id,
                CloseReason::TargetCircuitOpen,
                true,
                &runtime.active,
            )
            .await;
            return;
        }

        // Stream-open rate limit (churn reflection-surface budget;
        // agent-level bucket, accumulated across sessions). Charged only now
        // — everything above this line rejects without doing (or paying for)
        // dial work.
        if let Some(limiter) = &runtime.open_rate_limiter
            && !limiter.check()
        {
            metrics::counter!(
                "interflow_agent_open_dropped_total",
                "reason" => CloseReason::RateLimited.to_string()
            )
            .increment(1);
            warn!(
                "stream open rate limit exceeded, rejecting new stream: stream_id={}, source={}",
                stream_id, open.source
            );
            Self::finish(
                tunnel,
                &stream_id,
                CloseReason::RateLimited,
                true,
                &runtime.active,
            )
            .await;
            return;
        }

        // Local concurrent stream cap (a second gate beyond the hub
        // quota; agent-level count)
        if runtime.max_incoming_streams > 0
            && runtime.active.load(Ordering::Relaxed) > runtime.max_incoming_streams
        {
            metrics::counter!(
                "interflow_agent_open_dropped_total",
                "reason" => CloseReason::LocalLimit.to_string()
            )
            .increment(1);
            warn!(
                "local concurrent stream limit ({}) reached, rejecting new stream: stream_id={}, source={}",
                runtime.max_incoming_streams, stream_id, open.source
            );
            Self::finish(
                tunnel,
                &stream_id,
                CloseReason::LocalLimit,
                true,
                &runtime.active,
            )
            .await;
            return;
        }

        info!(
            "Opening backend stream: {} -> {} ({:?})",
            stream_id, target, proto
        );
        match proto {
            StreamProto::Tcp => {
                tracker.spawn(Self::run_tcp_forwarder(
                    stream_id,
                    target,
                    frames,
                    tunnel.clone(),
                    policy.backend_write_timeout,
                    policy.resolve_timeout,
                    policy.connect_timeout,
                    Arc::clone(runtime),
                    session.clone(),
                    Arc::clone(send_health),
                ));
            }
            StreamProto::Udp => {
                let idle_timeout = matched_rule.map_or(
                    Duration::from_mins(1),
                    EgressRule::effective_udp_idle_timeout,
                );
                Self::spawn_udp_forwarder(
                    stream_id,
                    target,
                    frames,
                    tunnel.clone(),
                    idle_timeout,
                    policy.resolve_timeout,
                    Arc::clone(runtime),
                    session.clone(),
                    tracker,
                    Arc::clone(send_health),
                );
            }
        }
    }

    /// TCP forwarder: one tunnel stream <-> one backend TCP connection.
    ///
    /// - dial via resolve-then-check-then-connect (guards against the DNS
    ///   rebinding TOCTOU), with both resolve and connect bounded
    ///   (black-hole resolvers/addresses must not fill the slots);
    /// - inbound (tunnel -> backend): straight `write_all`; a stall past the
    ///   timeout kills the stream — a blocked write inside a per-stream task
    ///   only affects this stream, which is natural backpressure;
    /// - outbound (backend -> tunnel): an independent read task with a
    ///   1 MiB backpressure buffer; `cancel` forces exit, and the send back
    ///   is bounded (an upstream stall does not hang the read task);
    /// - frame channel closed (`recv() == None`) = dispatch poisoned /
    ///   tunnel dead -> kill the stream and notify;
    /// - **session token**: session end (watchdog/disconnect/shutdown)
    ///   exits in place — both halves release the backend fd as the task
    ///   drops. This is the structural fix for the fd-leak root cause
    ///   (docs/bug/2026-09-14-egress-fd-leak-session-rebuild.md).
    #[allow(clippy::too_many_arguments)]
    async fn run_tcp_forwarder(
        stream_id: String,
        target_addr: String,
        mut frames: mpsc::Receiver<TunnelData>,
        tunnel: AgentTunnel,
        write_timeout: Duration,
        resolve_timeout: Duration,
        connect_timeout: Duration,
        runtime: Arc<EgressRuntime>,
        session: CancellationToken,
        send_health: Arc<SendPathHealth>,
    ) {
        // 1. Resolve-then-check-then-connect: tokio::net::lookup_host
        //    resolves (IP literals trigger no DNS) -> filter out
        //    SSRF-blocklist IPs -> connect to the already-resolved address
        //    (the checked IP = the connected IP).
        let resolved = match tokio::time::timeout(
            resolve_timeout,
            tokio::net::lookup_host(&target_addr),
        )
        .await
        {
            Ok(Ok(addrs)) => addrs.collect::<Vec<_>>(),
            Ok(Err(e)) => {
                error!("Failed to resolve target address {}: {}", target_addr, e);
                if let Some(b) = &runtime.breakers {
                    b.note_failure(&target_addr);
                }
                Self::finish(
                    &tunnel,
                    &stream_id,
                    CloseReason::ConnectFailed,
                    true,
                    &runtime.active,
                )
                .await;
                return;
            }
            Err(_) => {
                error!(
                    "Target address resolution timed out {}: exceeded {:?}, killing stream",
                    target_addr, resolve_timeout
                );
                if let Some(b) = &runtime.breakers {
                    b.note_failure(&target_addr);
                }
                Self::finish(
                    &tunnel,
                    &stream_id,
                    CloseReason::ConnectFailed,
                    true,
                    &runtime.active,
                )
                .await;
                return;
            }
        };
        let safe_addr = resolved
            .into_iter()
            .find(|sa| !crate::agent::ssrf_deny::is_ip_ssrf_blocked(sa.ip()));
        let Some(target_socket_addr) = safe_addr else {
            error!(
                "Security block: all resolved IPs for target {} hit the SSRF blocklist",
                target_addr
            );
            Self::finish(
                &tunnel,
                &stream_id,
                CloseReason::SecurityDenied,
                true,
                &runtime.active,
            )
            .await;
            return;
        };

        let stream = match tokio::time::timeout(
            connect_timeout,
            TcpStream::connect(target_socket_addr),
        )
        .await
        {
            Ok(Ok(s)) => s,
            Ok(Err(e)) => {
                error!("Failed to connect to target {}: {}", target_addr, e);
                if let Some(b) = &runtime.breakers {
                    b.note_failure(&target_addr);
                }
                Self::finish(
                    &tunnel,
                    &stream_id,
                    CloseReason::ConnectFailed,
                    true,
                    &runtime.active,
                )
                .await;
                return;
            }
            Err(_) => {
                error!(
                    "Connect to target timed out {}: exceeded {:?} (black-hole address?), killing stream and releasing slot",
                    target_addr, connect_timeout
                );
                if let Some(b) = &runtime.breakers {
                    b.note_failure(&target_addr);
                }
                Self::finish(
                    &tunnel,
                    &stream_id,
                    CloseReason::ConnectFailed,
                    true,
                    &runtime.active,
                )
                .await;
                return;
            }
        };
        if let Some(b) = &runtime.breakers {
            b.note_success(&target_addr);
        }
        info!(
            "Backend connection established: {} -> {}",
            stream_id, target_addr
        );
        let (read_half, mut write_half) = stream.into_split();

        // 2. Read task (backend -> hub): cancel/session force exit (when the
        //    backend goes silent the read blocks in read_buf; polling a flag
        //    cannot interrupt a blocked read, so the token is mandatory).
        //    Exit notifies the main loop via oneshot (send-then-recv loses
        //    no signal) — when the read task dies first, the main loop no
        //    longer waits indefinitely for the peer's `_close_`; the fd
        //    self-heals and releases.
        let cancel = CancellationToken::new();
        let (exit_tx, mut exit_rx) = tokio::sync::oneshot::channel::<BackendExit>();
        let read_task = {
            let tunnel = tunnel.clone();
            let stream_id = stream_id.clone();
            let cancel = cancel.clone();
            let session = session.clone();
            let send_health = Arc::clone(&send_health);
            let mut read_half = read_half;
            async move {
                // 1 MiB cap: exceeding it triggers backpressure (stop
                // reading upstream), avoiding unbounded growth
                const MAX_BUFFER: usize = 1024 * 1024;
                const READ_CHUNK: usize = 64 * 1024; // same value as hub::quic::READ_CHUNK (TCP payload-stream read chunk)
                let mut buffer = BytesMut::with_capacity(READ_CHUNK);
                let exit = loop {
                    // Backpressure: stop reading when remaining capacity is
                    // low; wait for the send to drain
                    if buffer.capacity() < 1024 {
                        if buffer.len() >= MAX_BUFFER {
                            tokio::select! {
                                () = cancel.cancelled() => break BackendExit::UpstreamSick,
                                () = session.cancelled() => break BackendExit::UpstreamSick,
                                () = tokio::time::sleep(Duration::from_millis(1)) => {}
                            }
                            continue;
                        }
                        buffer.reserve(READ_CHUNK);
                    }
                    tokio::select! {
                        () = cancel.cancelled() => break BackendExit::UpstreamSick,
                        () = session.cancelled() => break BackendExit::UpstreamSick,
                        r = read_half.read_buf(&mut buffer) => match r {
                            Ok(0) => {
                                debug!("Backend connection closed: {}", stream_id);
                                // Note: we do **not** echo a Close response
                                // here — under half-close semantics the
                                // backend has only FIN'd its write side;
                                // the read side can still receive. Echoing
                                // immediately would make the hub tear the
                                // stream down on the spot, and request-tail
                                // data arriving within the drain window
                                // would be rejected as "Stream not found".
                                // The echo is deferred to the end of the
                                // drain and done uniformly and boundedly by
                                // finish().
                                break BackendExit::CleanEof;
                            }
                            Ok(_) => {
                                let data = buffer.split().freeze();
                                // Bounded send back: the read task must not
                                // hang when the upstream channel is
                                // full/stalled (otherwise the fd lingers
                                // inside a blocked send — leak path #2)
                                // Session send-path health: a frame to deliver
                                // is demand; the success note clears it.
                                send_health.note_attempt();
                                match tokio::time::timeout(
                                    RESPONSE_SEND_TIMEOUT,
                                    tunnel.send_data_response(&stream_id, data),
                                )
                                .await
                                {
                                    Ok(Ok(())) => {
                                        send_health.note_success();
                                    }
                                    Ok(Err(e)) => {
                                        error!("Failed to send to hub: {}", e);
                                        break BackendExit::UpstreamSick;
                                    }
                                    Err(_) => {
                                        error!(
                                            "Send to hub stalled for over {:?}, killing stream read side: {}",
                                            RESPONSE_SEND_TIMEOUT, stream_id
                                        );
                                        break BackendExit::UpstreamSick;
                                    }
                                }
                            }
                            Err(e) => {
                                error!("Failed to read from backend: {}", e);
                                break BackendExit::ReadError;
                            }
                        }
                    }
                };
                // If the main loop already closed out, the receiving end is
                // dropped; a failed send is harmless
                let _ = exit_tx.send(exit);
            }
        };
        let read_task = tokio::spawn(read_task);

        // 3. Forward loop (tunnel -> backend): bounded writes, a stall kills
        //    the stream; the session token takes priority. Exits keep
        //    CloseReason::CloseFrame (peer Close, no echo) as the default.
        //
        //    When the backend side dies first (read task exits): clean EOF
        //    enters a bounded drain (an in-flight request tail can still
        //    land under half-close semantics), and upstream pathology closes
        //    out immediately — `write_half` and the backend fd no longer
        //    depend on the arrival of the peer's `_close_` (whose loss once
        //    left fds lingering for a whole session).
        let mut exit_reason = CloseReason::CloseFrame;
        // Some(deadline) = backend EOF drain mode (the Close response is
        // deferred until the drain ends).
        let mut eof_drain: Option<tokio::time::Instant> = None;
        loop {
            tokio::select! {
                biased;
                // Session end (watchdog/disconnect/shutdown): exit
                // immediately. biased attributes the teardown instant (when
                // cancel and recv-None are both ready) to session_closed
                // rather than dispatch_poison, for more accurate metric
                // semantics.
                () = session.cancelled() => {
                    exit_reason = CloseReason::SessionClosed;
                    break;
                }
                // Read task exit (this branch is only enabled while not yet
                // in drain mode): EOF -> drain window; pathology ->
                // immediate close-out
                res = &mut exit_rx, if eof_drain.is_none() => {
                    match res {
                        Ok(BackendExit::CleanEof) => {
                            eof_drain = Some(tokio::time::Instant::now() + BACKEND_EOF_DRAIN_GRACE);
                            debug!(
                                "Backend EOF, entering {:?} drain window: {} -> {}",
                                BACKEND_EOF_DRAIN_GRACE, stream_id, target_addr
                            );
                        }
                        Ok(BackendExit::UpstreamSick | BackendExit::ReadError) | Err(_) => {
                            exit_reason = CloseReason::BackendClosed;
                            break;
                        }
                    }
                }
                frame = frames.recv() => {
                    let Some(frame) = frame else {
                        // dispatch poisoned or tunnel dead
                        exit_reason = CloseReason::DispatchPoison;
                        break;
                    };
                    match frame.stream_type {
                        FrameType::Data if !frame.data.is_empty() => {
                            match tokio::time::timeout(
                                write_timeout,
                                write_half.write_all(&frame.data),
                            )
                            .await
                            {
                                Ok(Ok(())) => {}
                                Ok(Err(e)) => {
                                    error!("Failed to write to backend: {}", e);
                                    exit_reason = CloseReason::BackendClosed;
                                    break;
                                }
                                Err(_) => {
                                    error!(
                                        "Backend write stalled for over {:?}, killing stream: {} -> {}",
                                        write_timeout, stream_id, target_addr
                                    );
                                    exit_reason = CloseReason::BackendWriteTimeout;
                                    break;
                                }
                            }
                        }
                        FrameType::Close => break,
                        _ => {}
                    }
                }
                // Drain window elapsed: the backend has FIN'd and the
                // in-flight request tail has had enough time; close out and
                // release the fd. (with biased, frames comes first: while
                // frames keep arriving within the window they are consumed
                // first; once idle, the deadline hits. None -> pending:
                // select pre-constructs each branch future, so we must not
                // destructure on None even when the precondition is false)
                () = async {
                    match eof_drain {
                        Some(deadline) => tokio::time::sleep_until(deadline).await,
                        None => std::future::pending::<()>().await,
                    }
                }, if eof_drain.is_some() => {
                    exit_reason = CloseReason::BackendClosed;
                    break;
                }
            }
        }

        // 4. Wind-down: force-stop the read task (both halves drop as the
        //    task exits, truly closing the backend connection), notify the
        //    hub + clean up the dispatch-table entry. Closures initiated by
        //    the peer/session end do not echo; the Close response of the EOF
        //    drain path is sent here uniformly and boundedly (deferred to
        //    here so the stream stays alive on the hub side during the
        //    half-close drain).
        cancel.cancel();
        let _ = read_task.await;
        drop(write_half);
        let echo_close = !matches!(
            exit_reason,
            CloseReason::CloseFrame | CloseReason::SessionClosed
        );
        Self::finish(
            &tunnel,
            &stream_id,
            exit_reason,
            echo_close,
            &runtime.active,
        )
        .await;
    }

    /// Unified forwarder wind-down: counting, Close echo as needed (bounded —
    /// the wind-down never hangs on a full-channel send), unregistering the
    /// request-direction channel, and decrementing the agent-level active
    /// stream count (paired with the increment at the head of
    /// `handle_incoming_stream`; every exit path funnels uniquely here).
    ///
    /// The echoed Close carries `reason` in its payload (empty for ordinary
    /// closes) so the far end — hub/edge — can distinguish backend failures
    /// from normal teardown (route-level negative caching, 2026-09-16).
    async fn finish(
        tunnel: &AgentTunnel,
        stream_id: &str,
        reason: CloseReason,
        echo_close: bool,
        active: &AtomicUsize,
    ) {
        metrics::counter!("interflow_egress_stream_closed_total", "reason" => reason.to_string())
            .increment(1);
        active.fetch_sub(1, Ordering::Relaxed);
        metrics::gauge!("interflow_agent_incoming_streams_active").decrement(1.0);
        if echo_close {
            match tokio::time::timeout(
                CLOSE_NOTIFY_TIMEOUT,
                tunnel.send_close_response(stream_id, reason.as_str()),
            )
            .await
            {
                Ok(Ok(())) => {}
                Ok(Err(_)) => {
                    debug!("Close echo failed (expected during session teardown): {stream_id}");
                }
                Err(_) => debug!(
                    "Close echo stalled for over {CLOSE_NOTIFY_TIMEOUT:?} (expected during session teardown): {stream_id}"
                ),
            }
        }
        tunnel.unregister_incoming_stream(stream_id).await;
    }

    /// UDP forwarder: one connected UDP socket + bidirectional pumps per
    /// stream (rathole style).
    ///
    /// - dial: resolve-then-check-then-connect (guards against DNS
    ///   rebinding, consistent with the TCP path, bounded resolve), bind a
    ///   same-family unspecified:0 then `connect` **once** (UDP connect is a
    ///   purely local operation with no network wait, so no timeout needed);
    /// - inbound (tunnel -> backend): each Data frame's payload is exactly
    ///   one complete datagram; a Close frame = peer reclaim; channel closed
    ///   = dispatch poisoned;
    /// - outbound (backend -> tunnel): recv buffer of 65535, one frame per
    ///   datagram on the return path, return send bounded (an upstream stall
    ///   does not hang the read task);
    /// - idle timeout (refreshed bidirectionally, deadline rebuilt each
    ///   round): on timeout notify the peer to reclaim — timed
    ///   independently of the ingress side, each side its own fallback;
    /// - lifecycle: hangs off the session tracker + holds the session token;
    ///   the per-stream child token uniformly reaps the read/write pumps
    ///   (every exit path cancels then joins — fixing the old lingering
    ///   where "after an idle exit, join hung forever on a blocked recv");
    ///   session end releases the whole stream in place.
    #[allow(clippy::too_many_arguments)]
    fn spawn_udp_forwarder(
        stream_id: String,
        target_addr: String,
        frames: mpsc::Receiver<TunnelData>,
        tunnel: AgentTunnel,
        idle_timeout: Duration,
        resolve_timeout: Duration,
        runtime: Arc<EgressRuntime>,
        session: CancellationToken,
        tracker: &TaskTracker,
        send_health: Arc<SendPathHealth>,
    ) {
        tracker.spawn(async move {
            let resolved =
                match tokio::time::timeout(resolve_timeout, tokio::net::lookup_host(&target_addr))
                    .await
                {
                    Ok(Ok(addrs)) => addrs.collect::<Vec<_>>(),
                    Ok(Err(e)) => {
                        error!("Failed to resolve UDP target address {}: {}", target_addr, e);
                        if let Some(b) = &runtime.breakers {
                            b.note_failure(&target_addr);
                        }
                        Self::finish(
                            &tunnel,
                            &stream_id,
                            CloseReason::ConnectFailed,
                            true,
                            &runtime.active,
                        )
                        .await;
                        return;
                    }
                    Err(_) => {
                        error!(
                            "UDP target address resolution timed out {}: exceeded {:?}, killing stream",
                            target_addr, resolve_timeout
                        );
                        if let Some(b) = &runtime.breakers {
                            b.note_failure(&target_addr);
                        }
                        Self::finish(
                            &tunnel,
                            &stream_id,
                            CloseReason::ConnectFailed,
                            true,
                            &runtime.active,
                        )
                        .await;
                        return;
                    }
                };
            let safe_addr = resolved
                .into_iter()
                .find(|sa| !crate::agent::ssrf_deny::is_ip_ssrf_blocked(sa.ip()));
            let Some(sa) = safe_addr else {
                error!(
                    "Security block: all resolved IPs for UDP target {} hit the SSRF blocklist",
                    target_addr
                );
                Self::finish(
                    &tunnel,
                    &stream_id,
                    CloseReason::SecurityDenied,
                    true,
                    &runtime.active,
                )
                .await;
                return;
            };

            let bind_addr = match sa {
                std::net::SocketAddr::V4(_) => std::net::SocketAddr::from(([0, 0, 0, 0], 0)),
                std::net::SocketAddr::V6(_) => std::net::SocketAddr::from(([0u16; 8], 0)),
            };
            let socket = match crate::agent::ingress_udp::bind_udp_socket(bind_addr) {
                Ok(s) => s,
                Err(e) => {
                    error!("UDP socket bind failed ({bind_addr}): {e}");
                    Self::finish(
                        &tunnel,
                        &stream_id,
                        CloseReason::ConnectFailed,
                        true,
                        &runtime.active,
                    )
                    .await;
                    return;
                }
            };
            if let Err(e) = socket.connect(sa).await {
                error!("UDP connect failed {target_addr}: {e}");
                if let Some(b) = &runtime.breakers {
                    b.note_failure(&target_addr);
                }
                Self::finish(
                    &tunnel,
                    &stream_id,
                    CloseReason::ConnectFailed,
                    true,
                    &runtime.active,
                )
                .await;
                return;
            }
            if let Some(b) = &runtime.breakers {
                b.note_success(&target_addr);
            }
            let socket = Arc::new(socket);
            let last_active = Arc::new(std::sync::Mutex::new(Instant::now()));
            // Close frame (peer reclaim) flag: decides whether to echo Close
            // on exit
            let peer_closed = Arc::new(AtomicBool::new(false));
            // per-stream child token: every forwarder exit path cancels it
            // uniformly to reap the child tasks
            let stream_token = session.child_token();

            // Write task (tunnel -> backend): each Data payload is one
            // complete datagram
            let write_task = {
                let socket = socket.clone();
                let last_active = last_active.clone();
                let peer_closed = peer_closed.clone();
                let token = stream_token.clone();
                let mut frames = frames;
                async move {
                    loop {
                        tokio::select! {
                            () = token.cancelled() => break,
                            d = frames.recv() => match d {
                                Some(td) => match td.stream_type {
                                    FrameType::Data if !td.data.is_empty() => {
                                        if let Err(e) = socket.send(&td.data).await {
                                            warn!("UDP send to backend failed: {e}");
                                            break;
                                        }
                                        metrics::counter!("interflow_udp_egress_datagrams_tx")
                                            .increment(1);
                                        *last_active.lock().unwrap_or_else(std::sync::PoisonError::into_inner) = Instant::now();
                                    }
                                    FrameType::Close => {
                                        peer_closed.store(true, Ordering::Relaxed);
                                        break;
                                    }
                                    _ => {}
                                },
                                // Channel closed = dispatch poisoned /
                                // session ended
                                None => break,
                            },
                        }
                    }
                }
            };
            let write_task = tokio::spawn(write_task);

            // Read task (backend -> tunnel): return path bounded
            let read_task = {
                let socket = socket.clone();
                let last_active = last_active.clone();
                let tunnel = tunnel.clone();
                let stream_id = stream_id.clone();
                let token = stream_token.clone();
                let send_health = Arc::clone(&send_health);
                async move {
                    let mut buf = vec![0u8; UDP_RECV_BUF];
                    loop {
                        tokio::select! {
                            () = token.cancelled() => break,
                            r = socket.recv(&mut buf) => match r {
                                Ok(0) => {} // zero-length datagram: skip
                                Ok(n) => {
                                    if n == UDP_RECV_BUF {
                                        metrics::counter!("interflow_udp_egress_truncated")
                                            .increment(1);
                                        warn!("Backend datagram likely truncated ({n} bytes), dropping");
                                        continue;
                                    }
                                    let data = Bytes::copy_from_slice(&buf[..n]);
                                    send_health.note_attempt();
                                    match tokio::time::timeout(
                                        RESPONSE_SEND_TIMEOUT,
                                        tunnel.send_data_response(&stream_id, data),
                                    )
                                    .await
                                    {
                                        Ok(Ok(())) => {
                                            send_health.note_success();
                                        }
                                        Ok(Err(e)) => {
                                            error!("UDP send to hub failed: {e}");
                                            break;
                                        }
                                        Err(_) => {
                                            error!(
                                                "UDP send to hub stalled for over {:?}, killing stream read side: {}",
                                                RESPONSE_SEND_TIMEOUT, stream_id
                                            );
                                            break;
                                        }
                                    }
                                    metrics::counter!("interflow_udp_egress_datagrams_rx")
                                        .increment(1);
                                    *last_active.lock().unwrap_or_else(std::sync::PoisonError::into_inner) = Instant::now();
                                }
                                Err(e) => {
                                    warn!("UDP recv from backend error: {e}");
                                    break;
                                }
                            },
                        }
                    }
                }
            };
            let read_task = tokio::spawn(read_task);

            // Idle supervision: reclaim when the bidirectional last_active
            // exceeds idle_timeout. A JoinHandle already polled to
            // completion by select cannot be awaited again (it would
            // panic); per the completed branch, await only the still-
            // pending task.
            enum Exit {
                ReadDone,
                WriteDone,
                Idle,
                Session,
            }
            let deadline = tokio::time::Instant::from_std(
                *last_active.lock().unwrap_or_else(std::sync::PoisonError::into_inner) + idle_timeout,
            );
            let mut read_task = read_task;
            let mut write_task = write_task;
            let which = tokio::select! {
                _ = &mut read_task => Exit::ReadDone,
                _ = &mut write_task => Exit::WriteDone,
                () = tokio::time::sleep_until(deadline) => {
                    metrics::counter!("interflow_udp_egress_idle_timeout").increment(1);
                    debug!("UDP forwarder idle timeout: stream_id={stream_id}");
                    Exit::Idle
                }
                () = session.cancelled() => Exit::Session,
            };
            // Reap the child tasks: cancel the child token first (blocked
            // recv/send unlock immediately), then finish to release the
            // slot, and finally, per the completed branch, await only the
            // still-pending task.
            stream_token.cancel();
            // A Close initiated by the peer (ingress) and session end do not
            // echo; only this side's timeout/poison/backend error notifies
            // for reclamation
            let (reason, echo) = match which {
                Exit::ReadDone => (CloseReason::BackendClosed, true),
                Exit::WriteDone => {
                    if peer_closed.load(Ordering::Relaxed) {
                        (CloseReason::CloseFrame, false)
                    } else {
                        (CloseReason::DispatchPoison, true)
                    }
                }
                Exit::Idle => (CloseReason::UdpIdle, true),
                Exit::Session => (CloseReason::SessionClosed, false),
            };
            Self::finish(&tunnel, &stream_id, reason, echo, &runtime.active).await;
            match which {
                Exit::ReadDone => {
                    let _ = write_task.await;
                }
                Exit::WriteDone => {
                    let _ = read_task.await;
                }
                Exit::Idle | Exit::Session => {
                    let _ = tokio::join!(read_task, write_task);
                }
            }
        });
    }

    fn is_target_allowed(target: &str, security: &SecurityConfig) -> bool {
        // Hard SSRF blocklist: however allowed_targets is configured, cloud
        // metadata / link-local are always denied.
        // Applied before allowed-list matching and before the loopback
        // fallback.
        if crate::agent::ssrf_deny::is_ssrf_blocked(target) {
            return false;
        }

        // Default Deny Policy: If no rules are configured, block everything except loopback
        if security.allowed_targets.is_empty() {
            return Self::is_loopback(target);
        }

        for rule in &security.allowed_targets {
            if rule == target {
                return true;
            }

            // Domain/Host matching
            if let Some((host, _port)) = target.split_once(':') {
                if rule == host {
                    return true;
                }

                // CIDR check
                if rule.contains('/')
                    && let Ok(target_ip) = host.parse::<std::net::IpAddr>()
                    && let Ok(network) = rule.parse::<ipnetwork::IpNetwork>()
                    && network.contains(target_ip)
                {
                    return true;
                }
            }
        }

        false
    }

    fn is_loopback(target: &str) -> bool {
        // Parse strictly to avoid prefix spoofing (e.g. "127.0.0.1.evil.com" / "localhostx" / "localhost:65535.evil")
        // Accepts "host:port" / "[::1]:port" / "host" / "::1" forms

        // 1) Whole-string SocketAddr parse (covers "127.0.0.1:80" and "[::1]:80")
        if let Ok(sa) = target.parse::<std::net::SocketAddr>() {
            return sa.ip().is_loopback();
        }
        // 2) Whole-string IpAddr parse (covers "127.0.0.1" / "::1")
        if let Ok(ip) = target.parse::<std::net::IpAddr>() {
            return ip.is_loopback();
        }
        // 3) Split as host[:port] (only when the target has no extra colons)
        if !target.starts_with('[')
            && let Some((host, _port)) = target.rsplit_once(':')
        {
            if host.eq_ignore_ascii_case("localhost") {
                return true;
            }
            if let Ok(ip) = host.parse::<std::net::IpAddr>() {
                return ip.is_loopback();
            }
        }
        // 4) Bracket-stripped IPv6 forms
        let stripped = target.trim_start_matches('[').trim_end_matches(']');
        if stripped.eq_ignore_ascii_case("localhost") {
            return true;
        }
        if let Ok(ip) = stripped.parse::<std::net::IpAddr>() {
            return ip.is_loopback();
        }
        false
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
    use crate::config::SecurityConfig;

    /// Idle session (no send demand ever) is healthy — the supervisor must
    /// not trip on a quiet session.
    #[test]
    fn send_path_health_idle_is_healthy() {
        let h = SendPathHealth::new();
        assert_eq!(h.demand_starved_for(), None);
    }

    /// Demand met by a success is healthy; unmet demand starves at the rate
    /// real time advances (paused clock: exactly the slept duration).
    #[tokio::test(start_paused = true)]
    async fn send_path_health_starves_only_unmet_demand() {
        let h = SendPathHealth::new();
        h.note_attempt();
        h.note_success();
        assert_eq!(h.demand_starved_for(), None);

        // A new attempt with no success: starvation grows with time.
        tokio::time::sleep(Duration::from_secs(5)).await;
        h.note_attempt();
        assert_eq!(h.demand_starved_for(), Some(Duration::from_secs(5)));
        tokio::time::sleep(Duration::from_secs(25)).await;
        assert_eq!(h.demand_starved_for(), Some(Duration::from_secs(30)));

        // Late success clears the starvation.
        h.note_success();
        assert_eq!(h.demand_starved_for(), None);
    }

    #[test]
    fn test_is_target_allowed() {
        let mut config = SecurityConfig::default();

        // Case 1: Empty config -> Deny all except loopback
        assert!(EgressHandler::is_loopback("127.0.0.1:8080"));
        assert!(EgressHandler::is_loopback("localhost:3000"));
        assert!(EgressHandler::is_loopback("[::1]:8080"));
        assert!(EgressHandler::is_loopback("::1"));
        assert!(!EgressHandler::is_loopback("127.0.0.1.evil.com:8080"));
        assert!(!EgressHandler::is_loopback("localhostx:3000"));
        assert!(!EgressHandler::is_loopback("10.0.0.1:8080"));
        assert!(EgressHandler::is_target_allowed("127.0.0.1:8080", &config));
        assert!(EgressHandler::is_target_allowed("localhost:3000", &config));
        assert!(!EgressHandler::is_target_allowed("192.168.1.1:80", &config));
        assert!(!EgressHandler::is_target_allowed("google.com:80", &config));

        // Case 2: Exact match
        config.allowed_targets.push("192.168.1.5:5432".to_string());
        assert!(EgressHandler::is_target_allowed(
            "192.168.1.5:5432",
            &config
        ));
        assert!(!EgressHandler::is_target_allowed("192.168.1.5:80", &config)); // Port mismatch
        assert!(!EgressHandler::is_target_allowed(
            "192.168.1.6:5432",
            &config
        )); // IP mismatch

        // Case 3: Domain match
        config.allowed_targets.push("example.local".to_string());
        assert!(EgressHandler::is_target_allowed(
            "example.local:80",
            &config
        ));
        assert!(EgressHandler::is_target_allowed(
            "example.local:8080",
            &config
        ));
        assert!(!EgressHandler::is_target_allowed("other.local:80", &config));

        // Case 4: CIDR match
        config.allowed_targets.push("10.0.0.0/24".to_string());
        assert!(EgressHandler::is_target_allowed("10.0.0.1:80", &config));
        assert!(EgressHandler::is_target_allowed("10.0.0.254:443", &config));
        assert!(!EgressHandler::is_target_allowed("10.0.1.1:80", &config));
    }

    #[test]
    fn ssrf_blocklist_overrides_allowlist() {
        // Even with a 0.0.0.0/0 allowlist, cloud metadata IPs are still denied
        let mut config = SecurityConfig::default();
        config.allowed_targets.push("0.0.0.0/0".to_string());

        assert!(
            !EgressHandler::is_target_allowed("169.254.169.254:80", &config),
            "AWS metadata must be blocked even with 0.0.0.0/0 allowlist"
        );
        assert!(
            !EgressHandler::is_target_allowed("169.254.0.1:80", &config),
            "link-local range must be blocked"
        );
        assert!(
            !EgressHandler::is_target_allowed("100.100.100.200:80", &config),
            "Alibaba metadata must be blocked"
        );
        assert!(
            !EgressHandler::is_target_allowed("metadata.google.internal:80", &config),
            "GCP metadata hostname must be blocked"
        );
        assert!(
            !EgressHandler::is_target_allowed("metadata.azure.com:80", &config),
            "Azure metadata hostname must be blocked"
        );

        // Normal internal IPs still pass
        assert!(EgressHandler::is_target_allowed("10.0.0.1:80", &config));
        assert!(EgressHandler::is_target_allowed(
            "192.168.1.5:3000",
            &config
        ));
    }

    #[test]
    fn ssrf_blocklist_applies_with_empty_allowlist() {
        let config = SecurityConfig::default();
        // Empty config defaults to loopback-only, but metadata IPs must
        // still be denied (they are not loopback, but belt-and-braces)
        assert!(!EgressHandler::is_target_allowed(
            "169.254.169.254:80",
            &config
        ));
        assert!(!EgressHandler::is_target_allowed(
            "metadata.google.internal:80",
            &config
        ));
        // loopback still allowed
        assert!(EgressHandler::is_target_allowed("127.0.0.1:8080", &config));
    }
}
