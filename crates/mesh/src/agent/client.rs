use crate::agent::control::ControlServer;
use crate::agent::egress::EgressHandler;
use crate::agent::handle::{AgentHandle, AgentState, EventSink, backoff_duration};
use crate::agent::ingress::IngressHandler;
use crate::agent::rules::RuleStore;
use crate::config::{AgentConfig, TransportKind};
use http::Uri;
use http_body_util::BodyExt;
use hyper::Request;
use hyper::client::conn::http2::SendRequest;
use hyper_util::rt::{TokioExecutor, TokioIo, TokioTimer};
use interflow_core::error::{InterflowError, Result};
use interflow_core::fault::FaultPoint;
use interflow_core::tls::client::build_client_config;
use interflow_core::tls::extract_cn_from_pem_file;
use interflow_core::tunnel::negotiation::RegisterResponse;
use interflow_core::tunnel::session_tasks::{
    SessionExitGuard, SessionTasks, TaskExit, TaskExitReason,
};
use interflow_core::tunnel::{
    AgentTunnel, DEFAULT_REQUEST_ESTABLISH_TIMEOUT, H2Liveness, H2RequestBody, SessionSlot,
    empty_request_body,
};
use rustls::pki_types::ServerName;
use std::sync::Arc;
use tokio::net::TcpStream;
use tokio::sync::mpsc;
use tokio::time::{Duration, sleep};
use tokio_rustls::TlsConnector;
use tokio_util::sync::CancellationToken;
use tokio_util::task::TaskTracker;
use tracing::{error, info, warn};

// The session wind-down trio is single-sourced in core
// `config::params::ShutdownBudget` (bounded by construction: wind-down may
// never wait on a wedged task forever); the local aliases keep the call
// sites reading naturally.
use interflow_core::config::params::ShutdownBudget;
use interflow_core::config::params::transport::{
    DEFAULT_H2_CONNECTION_WINDOW, DEFAULT_H2_STREAM_WINDOW,
};
const SESSION_SHUTDOWN_TIMEOUT: Duration = ShutdownBudget::DEFAULT.session_shutdown;

/// Bounded close-out grace for all child tasks (forwarders/pumps/listeners/
/// control) during session teardown.
///
/// After token cancellation child tasks should exit within milliseconds; the
/// grace only absorbs in-flight I/O wind-down (e.g. a final bounded frame
/// write). Exceeding it indicates a structural defect (a task ignoring the
/// token), counted + a loud warning.
const SESSION_DRAIN_GRACE: Duration = ShutdownBudget::DEFAULT.session_drain_grace;

/// Final bounded join grace for session child-task handles after the drain
/// grace has already warned: a task that still has not exited here is
/// ignoring the cancellation token — abort instead of waiting forever, so
/// `run_session` always returns and the supervisor always reaches its next
/// reconnect iteration (mechanism A of
/// docs/bug/2026-09-16-edge-self-dial-agent-no-reregister.md).
const HANDLER_JOIN_GRACE: Duration = ShutdownBudget::DEFAULT.handler_join;

/// The agent client.
#[derive(Clone)]
pub struct AgentClient {
    config: AgentConfig,
    /// Cross-session rule truth: control-API adds/removes are persisted
    /// through this (file-backed); after a tunnel reconnect the handlers take
    /// rules from here rather than the startup snapshot.
    rule_store: Arc<RuleStore>,
    /// Egress flood-line runtime (agent-scoped): concurrency counters and
    /// rate buckets are shared across sessions and not reset on session
    /// rebuild — residual flows from the previous session keep consuming
    /// quota, so the limit never goes blind.
    egress_runtime: Arc<crate::agent::egress::EgressRuntime>,
    /// E2e (inner TLS) runtime (agent-scoped, startup-only assembly);
    /// `None` when the mode is off.
    e2e_runtime: Option<Arc<crate::agent::e2e::E2eRuntime>>,
}

/// How one session ended (the supervisor decides reconnect or exit from this).
enum SessionOutcome {
    /// User-initiated shutdown; the supervisor should exit the loop.
    Shutdown,
    /// The session ended unexpectedly; it should reconnect.
    Ended(String),
}

/// One established hub session (h2): the product of connection + registration
/// completing.
pub struct HubConnection {
    /// This agent's id (from config; registration has confirmed it).
    pub agent_id: String,
    /// The hub URL.
    pub hub_url: String,
    /// h2 request sender (used to construct [`AgentTunnel`]).
    pub send_request: SendRequest<H2RequestBody>,
    /// Connection keep-alive task handle (its exit means the h2 connection
    /// is dead).
    pub conn_handle: tokio::task::JoinHandle<()>,
    /// The hub's capability declaration (the source for deriving the poll
    /// watchdog + task-stall cadence).
    pub negotiated: RegisterResponse,
}

impl HubConnection {
    /// h2 session liveness parameters derived from negotiation (without the
    /// agent-side config override); the [`AgentClient::start`] path layers
    /// the `poll_idle_timeout_secs` config override on top of it.
    fn h2_liveness(&self) -> H2Liveness {
        H2Liveness {
            incoming_streams_budget: 0, // caller-layered (config max_incoming_streams)
            poll_watchdog: self.negotiated.poll_watchdog(),
            establish_timeout: DEFAULT_REQUEST_ESTABLISH_TIMEOUT,
            // Never tolerate a wedged critical task longer than the hub's
            // own aging window (no extra margin: a local task's heartbeat
            // has none of the network jitter the poll watchdog's margin
            // covers).
            task_stall_timeout: self.negotiated.task_stall_timeout(),
        }
    }
}

impl AgentClient {
    /// Build purely in-memory (rules are not persisted; in-memory additions
    /// and changes survive reconnects).
    ///
    /// Suited to embedded agents (expose edge) and tests — there is no
    /// config file to write back to.
    pub fn new(config: AgentConfig) -> Result<Self> {
        Self::build(config, None)
    }

    /// File-backed construction: control-API rule adds/removes are atomically
    /// written back to this config file (the file is the source of truth).
    pub fn with_config_file(
        config: AgentConfig,
        path: impl Into<std::path::PathBuf>,
    ) -> Result<Self> {
        Self::build(config, Some(path.into()))
    }

    /// The single construction funnel: every production entry (mesh CLI,
    /// expose CLI, GUI, expose edge) passes through here, so the identity
    /// pre-validation below cannot be bypassed by picking a different
    /// constructor.
    fn build(config: AgentConfig, rule_path: Option<std::path::PathBuf>) -> Result<Self> {
        Self::validate_identity_binding(&config)?;
        let rule_store = RuleStore::from_config(&config, rule_path);
        let egress_runtime = Arc::new(crate::agent::egress::EgressRuntime::from_config(&config));
        // E2e (inner TLS) material: startup-only assembly — a bad anchor
        // set fails the agent here instead of per-stream at runtime.
        let e2e_runtime = crate::agent::e2e::E2eRuntime::from_config(&config)?;
        Ok(Self {
            config,
            rule_store,
            egress_runtime,
            e2e_runtime,
        })
    }

    /// Startup pre-validation of the identity binding (design
    /// `multi-tenant-mtls-only` §3.2): `agent.id` must equal the client
    /// certificate's CN — exactly what the hub enforces at registration
    /// (403 Identity mismatch), on every stream bind, and in the QUIC
    /// hello. Failing it here turns "everything looks right but the hub
    /// rejects me" into an immediate local error, before any supervisor
    /// task or TLS handshake exists.
    ///
    /// Only runs when a client certificate is configured: certificate-less
    /// constructions (plain-http dev/test setups) keep their meaning —
    /// *requiring* the certificate is the config loader's policy, not the
    /// client's.
    fn validate_identity_binding(config: &AgentConfig) -> Result<()> {
        let Some(cert_path) = config
            .tls
            .as_ref()
            .filter(|tls| tls.enabled)
            .and_then(|tls| tls.client_cert_path.as_deref())
        else {
            return Ok(());
        };
        let cn = extract_cn_from_pem_file(cert_path)?.ok_or_else(|| {
            InterflowError::config(format!("client certificate has no CN: {cert_path}"))
        })?;
        if cn != config.agent.id {
            return Err(InterflowError::config(format!(
                "agent ID must equal the certificate CN ({cn})"
            )));
        }
        Ok(())
    }

    /// Start the agent supervisor, returning the handle immediately.
    ///
    /// State is broadcast via `watch`, process events stream out via mpsc;
    /// stop with [`AgentHandle::shutdown_graceful`] (cooperative, waits for
    /// all child tasks to exit).
    pub fn start(self) -> AgentHandle {
        let shutdown = CancellationToken::new();
        let tracker = TaskTracker::new();
        let slot = SessionSlot::new();
        let (state_tx, state_rx) = tokio::sync::watch::channel(AgentState::Connecting);
        let (event_tx, event_rx) = mpsc::channel(64);
        let sink = EventSink { state_tx, event_tx };

        let join = {
            let shutdown = shutdown.clone();
            let tracker = tracker.clone();
            let slot_for_supervisor = slot.clone();
            tokio::spawn(async move {
                self.supervise(sink, shutdown, tracker, slot_for_supervisor)
                    .await
            })
        };

        AgentHandle::new(state_rx, event_rx, shutdown, tracker, slot, join)
    }

    /// Supervisor: state machine + reconnect loop (exponential backoff +
    /// jitter, capped at 30s). Backoff counts *consecutive* failures: a
    /// session that was established resets the counter, so only a
    /// never-connecting stretch ramps toward the cap.
    async fn supervise(
        self,
        sink: EventSink,
        shutdown: CancellationToken,
        tracker: TaskTracker,
        slot: SessionSlot,
    ) -> Result<()> {
        info!("Agent starting (auto-reconnect mode)");
        let mut attempt: u32 = 0;
        let mut failed = false;

        loop {
            sink.set_state(AgentState::Connecting);
            // Per-iteration visibility: with only the in-establishment
            // "Connecting to hub" log, a supervisor wedged between
            // iterations would leave zero log traces (the exact silence of
            // the 2026-09-16 edge incident).
            info!("Agent connecting (attempt {})", attempt.saturating_add(1));
            // Fault injection: panic in the supervisor's own frame — the
            // outermost in-process layer; recovery is the embedder's job.
            interflow_core::fault::trigger(FaultPoint::AgentSuperviseLoopTick);
            // Panic containment at the supervision boundary: each session
            // attempt runs as a child on the agent-level tracker and is
            // awaited through its JoinHandle — a panic anywhere inside
            // becomes a JoinError here and takes the ordinary retry path,
            // instead of un winding into this loop and killing the
            // supervisor (the 2026-09-16 gap A shape). Still a DIRECT await:
            // run_session itself responds to cancellation (including the
            // unified wind-down: session_token.cancel -> tunnel.shutdown ->
            // bounded tracker close-out); no outer select, otherwise shutdown
            // would drop the future and skip the wind-down.
            let attempt_session = {
                let this = self.clone();
                let sink = sink.clone();
                let shutdown = shutdown.clone();
                let slot = slot.clone();
                tracker.spawn(async move { this.run_session(&sink, &shutdown, &slot).await })
            };
            let outcome = match attempt_session.await {
                Ok(outcome) => outcome,
                Err(join_err) => Err(InterflowError::JoinError(join_err)),
            };

            let (reason, established) = match outcome {
                Ok(SessionOutcome::Shutdown) => break,
                Ok(SessionOutcome::Ended(reason)) => {
                    warn!("Agent session ended ({reason}), reconnecting...");
                    (reason, true)
                }
                Err(e) => {
                    // Retrying configuration-class errors is pointless
                    // (unopenable CA / invalid URL, etc.); fail and exit
                    // directly.
                    if e.is_fatal() {
                        error!("Agent configuration error, will not retry: {e}");
                        sink.set_state(AgentState::Failed {
                            error: e.to_string(),
                        });
                        failed = true;
                        break;
                    }
                    let reason = e.to_string();
                    error!("Agent error: {reason}, retrying after backoff...");
                    (reason, false)
                }
            };

            // Consecutive-failure semantics (the contract documented on
            // `backoff_duration`): `Ended` implies the session was fully
            // established — establish failures return `Err` — so the retry
            // that follows is the first after a healthy session, not another
            // consecutive failure. A hub that keeps killing sessions right
            // after registration therefore stays at the 1-2s floor (fast
            // recovery is what the data-plane-stall rebuild loop wants); hub
            // abuse is bounded by its own rate/conn limiters. Only a stretch
            // where connection never succeeds ramps toward the 30s cap.
            attempt = if established { 1 } else { attempt + 1 };
            let backoff = backoff_duration(attempt);
            sink.set_state(AgentState::Reconnecting {
                reason,
                backoff_secs: backoff.as_secs(),
            });
            tokio::select! {
                () = shutdown.cancelled() => break,
                () = sleep(backoff) => {}
            }
        }

        tracker.close();
        tracker.wait().await;
        if !failed {
            sink.set_state(AgentState::Stopped);
        }
        Ok(())
    }

    /// Establish one session; returns how it ended. All child tasks hang off
    /// the session-level tracker + session token for cooperative
    /// cancellation; the teardown sequence closes out boundedly (see the
    /// wind-down notes below).
    async fn run_session(
        &self,
        sink: &EventSink,
        shutdown: &CancellationToken,
        slot: &SessionSlot,
    ) -> Result<SessionOutcome> {
        // Session-level token: when the session ends (disconnect or user
        // shutdown alike), cancels all child tasks of this session.
        let session_token = shutdown.child_token();

        // Panic containment, last-resort layer: ANY exit from this frame —
        // including a panic unwind (dropping a child token does NOT cancel
        // it; only `cancel()` does) — tears the session's children down.
        // SessionTasks enforces the per-task contract on top of this.
        let _exit_guard = SessionExitGuard::new(session_token.clone());

        // The session task supervisor: critical-task death contract + stall
        // heartbeats + the bounded wind-down tracker.
        let tasks = SessionTasks::new(session_token.clone());
        let mut task_exits = tasks.exits().await;

        // Connect + register (branch by transport: h2 = HTTP/2 + /register;
        // quic = control-stream Hello)
        // Every transport yields a connection watcher; only h2 yields the
        // request sender for the control proxy (`None` on QUIC — the proxy
        // is a plain h2 pass-through).
        let (agent_id, tunnel, mut connection_handle, mut hub_client_for_control) = tokio::select! {
            r = self.establish_tunnel(&tasks) => r?.into_parts(),
            () = session_token.cancelled() => return Ok(SessionOutcome::Shutdown),
        };

        // Fault injection: panic in run_session's own frame right after
        // registration — session children (transport loops) are already
        // spawned at this point; the supervisor must survive this and the
        // leaked children must be cancelled (drop-guard) before the retry.
        interflow_core::fault::trigger(FaultPoint::AgentSessionAfterRegister);

        // Publish this session's transport into the embedder-facing slot
        // BEFORE broadcasting Connected: consumers must never observe a
        // connected agent whose facade sends fail (the reverse ordering —
        // withdraw on wind-down — is enforced below).
        slot.install(tunnel.backend()).await;

        sink.set_state(AgentState::Connected {
            agent_id: agent_id.clone(),
        });
        sink.emit(crate::agent::handle::AgentEvent::SessionEstablished {
            agent_id: agent_id.clone(),
        });

        // Session-level task tracker: all child tasks of this session
        // (control/handler/forwarder/pump/listeners) hang off it and close
        // out boundedly in the teardown sequence — the task-side carrier of
        // the invariant "no stream task may outlive the session lifecycle".
        // Owned by SessionTasks (shared with the critical-task wrappers).
        let session_tracker = tasks.tracker().clone();

        // Initialize control channels
        let (ingress_tx, ingress_rx) = if self.config.control.enabled {
            let (tx, rx) = mpsc::channel(32);
            (Some(tx), Some(rx))
        } else {
            (None, None)
        };

        let (egress_tx, egress_rx) = if self.config.control.enabled {
            let (tx, rx) = mpsc::channel(32);
            (Some(tx), Some(rx))
        } else {
            (None, None)
        };

        // Start Control Server (in QUIC mode the hub-proxy feature has no h2
        // sender for now; pass None to degrade)
        let mut control_handle = if self.config.control.enabled {
            let control_addr = self.config.control.listen_addr;
            let ingress_tx_clone = ingress_tx.clone();
            let egress_tx_clone = egress_tx.clone();
            let hub_client = hub_client_for_control.take();
            let auth_token = self.config.control.auth_token.clone();
            let token = session_token.clone();

            Some(session_tracker.spawn(async move {
                tokio::select! {
                    () = token.cancelled() => {}
                    r = async {
                        let server = ControlServer::new(
                            control_addr,
                            ingress_tx_clone,
                            egress_tx_clone,
                            hub_client,
                            auth_token,
                        );
                        if let Err(e) = server.run().await {
                            error!("Control Server Error: {}", e);
                        }
                    } => r,
                }
            }))
        } else {
            None
        };

        // Start ingress + egress mode
        // Resync the rule tables from disk at session establishment
        // (file-backed): externally hand-edited configs converge this way,
        // and rules the control API wrote in the previous session survive
        // reconnection.
        self.rule_store.resync_from_disk().await;
        let rule_store = self.rule_store.clone();
        let security_config = self.config.security.clone();
        let egress_policy = crate::agent::egress::EgressPolicy::from(&self.config);
        let egress_runtime = Arc::clone(&self.egress_runtime);
        let e2e_runtime = self.e2e_runtime.clone();
        let handler_token = session_token.clone();
        let handler_tracker = session_tracker.clone();
        let teardown_tunnel = tunnel.clone();
        let mut handler_task = session_tracker.spawn(async move {
            info!("Starting agent services (ingress & egress)");

            // Prepare for Egress: take the incoming-stream event channel for
            // the request direction (once per tunnel)
            let Some(incoming) = tunnel.take_incoming_streams().await else {
                return Err(InterflowError::connection(
                    "egress incoming-stream channel already taken".to_string(),
                ));
            };

            // Create Ingress Handler
            let ingress = IngressHandler::new_with_tunnel(
                agent_id.clone(),
                tunnel.clone(),
                rule_store.clone(),
                handler_token.clone(),
                handler_tracker.clone(),
                ingress_rx,
                e2e_runtime.clone(),
            );

            // Create Egress Handler (sends response-direction frames via the
            // tunnel; never touches the h2 sender again)
            let egress = EgressHandler::new(
                agent_id,
                tunnel,
                rule_store,
                security_config,
                egress_policy,
                egress_runtime,
                handler_token.clone(),
                handler_tracker,
                egress_rx,
                incoming,
                e2e_runtime,
            );

            // Run both concurrently; session cancellation counts as a normal
            // end (reconnect/shutdown paths)
            let handlers =
                async { tokio::try_join!(ingress.run(), egress.run()).map(|((), ())| ()) };
            tokio::select! {
                () = handler_token.cancelled() => Ok(()),
                r = handlers => r,
            }
        });

        // The Handler branch's result must be taken inside the branch body
        // (the result travels with the branch marker): select only picks a
        // branch once its future returns Ready — a Handler win means the
        // handle has already been polled to completion; awaiting the same
        // handle again outside the branch is a second poll, which tokio
        // panics on ("JoinHandle polled after completion",
        // docs/bug/2026-09-13-select-branch-double-await-joinhandle-panic.md).
        let ended_by = tokio::select! {
            biased;
            // Critical-task exit reports come first so the ending gets its
            // true attribution (the wrapper also cancels the token — the
            // next arm — but the report carries the task name and reason).
            exit = task_exits.recv() => match exit {
                Some(exit) => SessionEnd::CriticalTask(exit),
                None => SessionEnd::Watchdog,
            },
            // The session token has many cancellation sources: user shutdown
            // (parent cascade), the poll receive-side watchdog, or the
            // SessionExitGuard. Distinguish the user shutdown by the parent
            // token — it must take the Stopped path; every internal death
            // signal takes the reconnect path (mistaking one for Shutdown
            // would leave the agent zombied in Stopped).
            () = session_token.cancelled() => {
                if shutdown.is_cancelled() {
                    SessionEnd::Shutdown
                } else {
                    SessionEnd::Watchdog
                }
            }
            // h2 session: the hyper connection future ending = disconnect.
            // QUIC: the closed-watcher (a critical task) plays this role —
            // its exit lands in the CriticalTask arm above and the watcher
            // handle here resolves with it.
            _ = &mut connection_handle => SessionEnd::Disconnected,
            r = &mut handler_task => SessionEnd::Handler(r),
        };

        // Session wind-down (the enforcement point of "no stream task may
        // outlive the session lifecycle"):
        // 1. cancel the session token (forwarders/pumps/listeners exit in
        //    place, backend fds released);
        // 2. the tunnel termination contract (clear both dispatch tables +
        //    seal the upstream channel; QUIC also closes the connection/
        //    endpoint) — a fallback for any residual consumer not holding
        //    the token;
        // 3. bounded close-out of the session-level tracker: teardown only
        //    counts as complete when all child tasks exit within the grace.
        session_token.cancel();
        // Withdraw the embedder facade first: from this point new sends fail
        // fast ("session re-establishing") instead of riding a transport
        // that is about to be torn down. The bounded termination contract
        // below still runs on the concrete per-session tunnel.
        slot.withdraw();
        if tokio::time::timeout(SESSION_SHUTDOWN_TIMEOUT, teardown_tunnel.shutdown())
            .await
            .is_err()
        {
            warn!(
                "tunnel termination contract timed out ({:?}), continuing teardown",
                SESSION_SHUTDOWN_TIMEOUT
            );
        }
        connection_handle.abort();
        if let Some(mut control_handle) = control_handle.take() {
            join_or_abort(&mut control_handle, HANDLER_JOIN_GRACE, "control").await;
        }
        // Bounded close-out of every session child (critical wrappers,
        // stall monitors, handlers, listeners, forwarders). Reaching the
        // grace means some child ignored the token — a structural defect
        // that must be loudly counted and warned about rather than silently
        // leaked (lesson from the fd-leak incident, 2026-09-14).
        tasks.close_and_wait(SESSION_DRAIN_GRACE).await;

        match ended_by {
            // When Shutdown/Disconnected wins, the handler handle was never
            // polled to Ready (a branch polled to Ready necessarily wins on
            // the spot); the post-cancel await is a legal first wait — wait
            // for the handler to exit, preventing leaks. The join is
            // bounded: a handler ignoring the token is aborted rather than
            // allowed to park run_session (and with it the supervisor's
            // reconnect loop) forever.
            SessionEnd::Shutdown => {
                join_or_abort(&mut handler_task, HANDLER_JOIN_GRACE, "handler").await;
                Ok(SessionOutcome::Shutdown)
            }
            SessionEnd::Disconnected => {
                join_or_abort(&mut handler_task, HANDLER_JOIN_GRACE, "handler").await;
                error!("Hub connection lost");
                Ok(SessionOutcome::Ended("Hub connection lost".into()))
            }
            SessionEnd::Watchdog => {
                join_or_abort(&mut handler_task, HANDLER_JOIN_GRACE, "handler").await;
                warn!(
                    "internal death signal (watchdog / exit guard) cancelled the session, rebuilding"
                );
                Ok(SessionOutcome::Ended(
                    "poll data-plane stall (watchdog)".into(),
                ))
            }
            SessionEnd::CriticalTask(exit) => {
                join_or_abort(&mut handler_task, HANDLER_JOIN_GRACE, "handler").await;
                warn!(
                    "session-critical task '{}' exited ({:?}), rebuilding session",
                    exit.task, exit.reason
                );
                Ok(SessionOutcome::Ended(format!(
                    "critical task '{}' exited ({})",
                    exit.task,
                    match exit.reason {
                        TaskExitReason::Returned => "returned",
                        TaskExitReason::Panicked => "panicked",
                        TaskExitReason::Aborted => "aborted",
                    }
                )))
            }
            SessionEnd::Handler(handler_res) => match handler_res {
                Ok(Ok(())) => Ok(SessionOutcome::Ended("session ended normally".into())),
                Ok(Err(e)) => Err(e),
                Err(e) => Err(InterflowError::JoinError(e)),
            },
        }
    }

    /// Establish the tunnel per the configured transport.
    async fn establish_tunnel(&self, tasks: &SessionTasks) -> Result<EstablishedSession> {
        match self.config.agent.transport {
            TransportKind::H2 => {
                let conn = self.connect_and_register().await?;
                // Session liveness = negotiation result + agent config
                // override:
                // - `poll_idle_timeout_secs = 0`: explicitly disable the
                //   watchdog (e.g. old deployments where the hub heartbeat is
                //   disabled and no adaptive disable was negotiated);
                // - `Some(n)`: fixed value; `None`: derive automatically from
                //   the hub-advertised cadence.
                let mut liveness = conn.h2_liveness();
                // Dispatch event-channel budget: derived from the local
                // stream limit so a whole-table creation burst passes in one
                // go (core `incoming_channel_cap`).
                liveness.incoming_streams_budget = self.config.max_incoming_streams;
                match self.config.agent.poll_idle_timeout_secs {
                    Some(0) => liveness.poll_watchdog = Duration::ZERO,
                    Some(secs) => liveness.poll_watchdog = Duration::from_secs(secs),
                    None => {}
                }
                // Request send-establishment bound: same layering contract
                // (Some(0) keeps the negotiated default; Some(n) pins).
                if let Some(secs) = self.config.agent.request_establish_timeout_secs
                    && secs > 0
                {
                    liveness.establish_timeout = Duration::from_secs(secs);
                }
                // Critical-task stall timeout: same layering contract
                // (Some(0) disables; Some(n) pins; None keeps the negotiated
                // derivation — never tolerate a wedged task longer than the
                // hub's own aging window).
                match self.config.agent.task_stall_timeout_secs {
                    Some(0) => liveness.task_stall_timeout = Duration::ZERO,
                    Some(secs) => liveness.task_stall_timeout = Duration::from_secs(secs),
                    None => {}
                }
                let tunnel = AgentTunnel::from_sender(
                    conn.agent_id.clone(),
                    &conn.hub_url,
                    conn.send_request.clone(),
                    tasks,
                    liveness,
                )?;
                Ok(EstablishedSession::H2 {
                    agent_id: conn.agent_id,
                    tunnel,
                    conn_handle: conn.conn_handle,
                    hub_client: conn.send_request,
                })
            }
            TransportKind::Quic => {
                let (tunnel, closed_watcher) = self.connect_quic(tasks).await?;
                Ok(EstablishedSession::Quic {
                    agent_id: self.config.agent.id.clone(),
                    tunnel,
                    closed_watcher,
                })
            }
        }
    }

    /// QUIC connect (with an overall timeout, aligned with the h2 path's
    /// connect_timeout semantics).
    /// Returns the tunnel and a connection-death watcher (session-level
    /// disconnect detection, aligned with the h2 connection future).
    async fn connect_quic(
        &self,
        tasks: &SessionTasks,
    ) -> Result<(AgentTunnel, tokio::task::JoinHandle<()>)> {
        let timeout = Duration::from_secs(self.config.agent.connect_timeout_secs);
        match tokio::time::timeout(timeout, self.connect_quic_inner(tasks)).await {
            Ok(r) => r.map_err(quic_establish_error),
            Err(_) => Err(quic_establish_error(InterflowError::connection(format!(
                "QUIC connect/register timeout (>{timeout:?}): hub={:?}",
                self.config.agent.hub_quic_addr
            )))),
        }
    }

    async fn connect_quic_inner(
        &self,
        tasks: &SessionTasks,
    ) -> Result<(AgentTunnel, tokio::task::JoinHandle<()>)> {
        let quic_addr = self.config.agent.hub_quic_addr.as_deref().ok_or_else(|| {
            InterflowError::config(
                "[agent] transport = \"quic\" requires hub_quic_addr (host:port)".to_string(),
            )
        })?;
        let (server_addr, server_name) = if let Ok(sa) = quic_addr.parse::<std::net::SocketAddr>() {
            (sa, sa.ip().to_string())
        } else {
            // host:port form: resolve the hostname (take the first address)
            let name = quic_addr.rsplit_once(':').map_or(quic_addr, |(h, _)| {
                h.trim_start_matches('[').trim_end_matches(']')
            });
            let resolved = tokio::net::lookup_host(quic_addr)
                .await
                .map_err(|e| {
                    InterflowError::connection(format!(
                        "failed to resolve hub_quic_addr {quic_addr}: {e}"
                    ))
                })?
                .next()
                .ok_or_else(|| {
                    InterflowError::connection(format!(
                        "hub_quic_addr has no resolvable address: {quic_addr}"
                    ))
                })?;
            (resolved, name.to_string())
        };
        info!("Connecting to hub (QUIC): {server_addr} (SNI: {server_name})");

        // TLS client config (isomorphic with the h2 path: CA / cert-pin /
        // mTLS client certificate)
        let tls_config = self.build_quic_tls_config()?;

        // Critical-task stall timeout: `None` derives from the hub-advertised
        // heartbeat cadence (the HelloAck capability suffix; disabled
        // heartbeat falls back to the fixed value inside the negotiation
        // module); `Some(0)` disables; `Some(n)` pins.
        let stall_override = self
            .config
            .agent
            .task_stall_timeout_secs
            .map(Duration::from_secs);

        // Registration-exchange bound: same send→response-establishment
        // semantics as the h2 path (None keeps the shared default).
        let establish_timeout = match self.config.agent.request_establish_timeout_secs {
            Some(secs) if secs > 0 => Duration::from_secs(secs),
            _ => interflow_core::tunnel::DEFAULT_REQUEST_ESTABLISH_TIMEOUT,
        };

        let session_params = interflow_core::tunnel::quic::QuicSessionParams {
            stall_override,
            establish_timeout,
            transport: interflow_core::tunnel::quic::QuicEndpointParams {
                max_idle_timeout_ms: self.config.transport.quic.max_idle_timeout_ms,
                keepalive_interval: Duration::from_millis(u64::from(
                    self.config.transport.quic.keepalive_interval_ms,
                )),
            },
            incoming_streams_budget: self.config.max_incoming_streams,
            // Observation-only capability declaration (RFC §3.6).
            e2e_capable: self.config.e2e.enabled(),
        };
        let tunnel = std::sync::Arc::new(
            interflow_core::tunnel::quic::QuicTunnel::connect(
                self.config.agent.id.clone(),
                server_addr,
                &server_name,
                tls_config,
                tasks.clone(),
                session_params,
            )
            .await?,
        );

        // Session-level disconnect detection: quinn connection closed (hub
        // death / network drop / idle timeout) -> the session ends and
        // reconnects. Without this watcher, an idle agent would zombie in
        // Connected when the hub dies (the read loop exits silently without
        // ending the session). Critical under the death contract — before
        // the 2026-09-16 hardening its panic left QUIC with no client-side
        // disconnect sensor at all.
        let watcher_tunnel = tunnel.clone();
        // One budget per session: the watcher uses the transport's effective
        // (negotiated or pinned) stall timeout.
        let task_stall_timeout = tunnel.stall_timeout();
        let stall = if task_stall_timeout.is_zero() {
            None
        } else {
            Some(task_stall_timeout)
        };
        let beat_every = interflow_core::tunnel::session_tasks::beat_interval(task_stall_timeout);
        let closed_watcher =
            tasks.spawn_critical("quic-closed-watcher", stall, move |beat| async move {
                // Fault injection: panic at watcher start (QUIC's
                // only client-side disconnect sensor dies silently).
                interflow_core::fault::trigger(FaultPoint::QuicClosedWatcher);
                beat.during(beat_every, watcher_tunnel.closed()).await;
            });

        Ok((AgentTunnel::from_transport(tunnel), closed_watcher))
    }

    /// Build the rustls ClientConfig for QUIC (ALPN `interflow`).
    fn build_quic_tls_config(&self) -> Result<rustls::ClientConfig> {
        let Some(tls) = &self.config.tls else {
            // Fail fast at config assembly: QUIC has no plaintext mode, and
            // without [tls] there is no trust basis to verify the hub with.
            return Err(InterflowError::config(
                "QUIC requires [tls] (connections are not allowed without a [tls] section)"
                    .to_string(),
            ));
        };
        build_client_config(
            tls.hub_cert_fingerprint.as_deref(),
            tls.ca_path.as_deref(),
            tls.client_cert_path.as_deref(),
            tls.client_key_path.as_deref(),
            &[interflow_core::tunnel::quic::QUIC_ALPN],
        )
    }

    /// Connect to the hub and register the agent, returning the session
    /// artifact [`HubConnection`].
    ///
    /// After taking `send_request`, the caller can:
    /// - construct its own [`AgentTunnel`] to run custom ingress/egress (e.g.
    ///   the `interflow-expose` edge)
    /// - or continue down the standard ingress+egress path of
    ///   [`AgentClient::start`]
    ///
    /// No automatic reconnect; failures are the caller's to handle.
    pub async fn connect_and_register(&self) -> Result<HubConnection> {
        let timeout = Duration::from_secs(self.config.agent.connect_timeout_secs);
        match tokio::time::timeout(timeout, self.connect_and_register_inner()).await {
            Ok(r) => r,
            // After sleep/wake, DNS/TLS can hang forever without erroring;
            // without this timeout the supervisor would stay stuck in
            // Connecting forever (a fake "started" state in the GUI). The
            // timeout is a retryable error.
            Err(_) => Err(InterflowError::connection(format!(
                "connect/register timeout (>{timeout:?}): hub={}",
                self.config.agent.hub_url
            ))),
        }
    }

    async fn connect_and_register_inner(&self) -> Result<HubConnection> {
        let hub_url = &self.config.agent.hub_url;
        let uri: Uri = hub_url
            .parse()
            .map_err(|e| InterflowError::config(format!("invalid hub URL: {e}")))?;

        let host = uri
            .host()
            .ok_or_else(|| InterflowError::config("hub URL is missing a host".to_string()))?;

        let port = uri.port_u16().unwrap_or_else(|| {
            if uri.scheme_str() == Some("https") {
                443
            } else {
                80
            }
        });

        let addr = format!("{host}:{port}");
        info!("Connecting to hub: {}", addr);

        // Prepare the connection builder
        let mut http_builder = hyper::client::conn::http2::Builder::new(TokioExecutor::new());
        http_builder.timer(TokioTimer::new());
        // HTTP/2 PING keepalive from `[transport.h2]` (defaults 5s/10s — a
        // disconnect is noticed within ~15s worst case, e.g. a half-open TCP
        // connection after WiFi loss, triggering a supervisor reconnect).
        // The hub side reads the same section: both ends of a link probe on
        // the same schedule by construction.
        http_builder.keep_alive_interval(self.config.transport.h2.keepalive_interval());
        http_builder.keep_alive_timeout(self.config.transport.h2.keepalive_timeout());
        // Flow-control windows symmetric with the hub: the default 64KiB
        // stream window turns single-stream throughput for streaming upload /
        // poll into a window bottleneck (introduced with the 2026-09-12
        // upload-streaming work)
        http_builder.initial_stream_window_size(DEFAULT_H2_STREAM_WINDOW);
        http_builder.initial_connection_window_size(DEFAULT_H2_CONNECTION_WINDOW);

        // Establish the connection per config (TLS or TCP). The loading
        // layer has already normalized: Some means enabled.
        let (mut send_request, connection_handle) = if let Some(tls_config) = &self.config.tls {
            info!("Connecting with TLS");
            // cert pinning: when hub_cert_fingerprint is configured, use the
            // pinned verifier in place of CA validation
            if let Some(pin_hex) = &tls_config.hub_cert_fingerprint {
                info!(
                    "cert pinning enabled (bypasses system CAs, trusts only hub certificates with matching fingerprint)"
                );
                Self::connect_tls_pinned(
                    http_builder,
                    &addr,
                    host,
                    pin_hex,
                    tls_config.client_cert_path.as_deref(),
                    tls_config.client_key_path.as_deref(),
                )
                .await?
            } else {
                // Client TLS assembly (shared with the QUIC and pinned
                // paths): CA roots + optional mTLS client certificate.
                let config = build_client_config(
                    None,
                    tls_config.ca_path.as_deref(),
                    tls_config.client_cert_path.as_deref(),
                    tls_config.client_key_path.as_deref(),
                    &["h2"],
                )?;
                let connector = TlsConnector::from(Arc::new(config));
                let stream = TcpStream::connect(&addr).await?;

                let domain = ServerName::try_from(host)
                    .map_err(|e| InterflowError::config(format!("invalid domain {host}: {e}")))?
                    .to_owned();

                let tls_stream = connector.connect(domain, stream).await.map_err(|e| {
                    InterflowError::connection(format!("TLS handshake failed: {e}"))
                })?;

                let (send_request, connection) =
                    http_builder.handshake(TokioIo::new(tls_stream)).await?;

                let handle = tokio::spawn(async move {
                    if let Err(e) = connection.await {
                        error!("Hub connection error (TLS): {}", e);
                    }
                });
                (send_request, handle)
            }
        } else {
            // No TLS config; check whether the scheme is HTTPS
            if uri.scheme_str() == Some("https") {
                return Err(InterflowError::config(
                    "URL is HTTPS but TLS is not configured".to_string(),
                ));
            }
            Self::connect_tcp(&addr, http_builder).await?
        };

        // Register the agent + read the capability declaration
        let negotiated = self.register(&mut send_request).await?;

        Ok(HubConnection {
            agent_id: self.config.agent.id.clone(),
            hub_url: self.config.agent.hub_url.clone(),
            send_request,
            conn_handle: connection_handle,
            negotiated,
        })
    }

    async fn connect_tcp(
        addr: &str,
        builder: hyper::client::conn::http2::Builder<TokioExecutor>,
    ) -> Result<(SendRequest<H2RequestBody>, tokio::task::JoinHandle<()>)> {
        let stream = TcpStream::connect(addr).await?;
        let (send_request, connection) = builder.handshake(TokioIo::new(stream)).await?;

        let handle = tokio::spawn(async move {
            if let Err(e) = connection.await {
                error!("Hub connection error (TCP): {}", e);
            }
        });

        Ok((send_request, handle))
    }

    /// Establish a TLS connection with cert pinning (bypasses system CAs;
    /// trusts only hub certificates whose SHA256 fingerprint matches).
    async fn connect_tls_pinned(
        builder: hyper::client::conn::http2::Builder<TokioExecutor>,
        addr: &str,
        host: &str,
        pin_hex: &str,
        client_cert_path: Option<&str>,
        client_key_path: Option<&str>,
    ) -> Result<(SendRequest<H2RequestBody>, tokio::task::JoinHandle<()>)> {
        let config = build_client_config(
            Some(pin_hex),
            None,
            client_cert_path,
            client_key_path,
            &["h2"],
        )?;
        let connector = TlsConnector::from(Arc::new(config));
        let stream = TcpStream::connect(addr).await?;
        let domain = ServerName::try_from(host)
            .map_err(|e| InterflowError::config(format!("invalid domain {host}: {e}")))?
            .to_owned();
        let tls_stream = connector.connect(domain, stream).await.map_err(|e| {
            InterflowError::connection(format!("TLS handshake failed (pin verification): {e}"))
        })?;
        let (send_request, connection) = builder.handshake(TokioIo::new(tls_stream)).await?;
        let handle = tokio::spawn(async move {
            if let Err(e) = connection.await {
                error!("Hub connection error (TLS+pin): {}", e);
            }
        });
        Ok((send_request, handle))
    }
}

/// A fully established hub session, per transport — the transport shape is
/// encoded in the type rather than implicitly expressed via `Option` tuple
/// fields (aligned with [`crate::hub::state::StreamFace`]).
enum EstablishedSession {
    /// h2: tunnel facade + the connection future's handle + the request
    /// sender (reused by the control server's `/agents` proxy when
    /// `[control]` is enabled).
    H2 {
        agent_id: String,
        tunnel: AgentTunnel,
        conn_handle: tokio::task::JoinHandle<()>,
        hub_client: SendRequest<H2RequestBody>,
    },
    /// QUIC: tunnel facade + the connection-death watcher.
    Quic {
        agent_id: String,
        tunnel: AgentTunnel,
        closed_watcher: tokio::task::JoinHandle<()>,
    },
}

impl EstablishedSession {
    fn into_parts(
        self,
    ) -> (
        String,
        AgentTunnel,
        tokio::task::JoinHandle<()>,
        Option<SendRequest<H2RequestBody>>,
    ) {
        match self {
            Self::H2 {
                agent_id,
                tunnel,
                conn_handle,
                hub_client,
            } => (agent_id, tunnel, conn_handle, Some(hub_client)),
            Self::Quic {
                agent_id,
                tunnel,
                closed_watcher,
            } => (agent_id, tunnel, closed_watcher, None),
        }
    }
}

/// Branch markers for the main select.
///
/// [`SessionEnd::Handler`] carries the handler task's result: select only
/// picks a branch once its future returns Ready; a Handler win means the
/// handle has already been polled to completion, so the result can only be
/// taken inside the branch body — awaiting that handle again outside the
/// branch is a second poll, which tokio panics on
/// (docs/bug/2026-09-13-select-branch-double-await-joinhandle-panic.md).
enum SessionEnd {
    Shutdown,
    Disconnected,
    /// The session token was cancelled from inside the session while the
    /// user-level shutdown was not: the poll receive-side watchdog, a
    /// critical-task wrapper, or the exit guard. Semantically equivalent to
    /// Disconnected's reconnect behavior.
    Watchdog,
    /// A session-critical task exited (returned / panicked / aborted) — the
    /// death contract's attributed form; see [`SessionTasks`].
    CriticalTask(TaskExit),
    Handler(std::result::Result<Result<()>, tokio::task::JoinError>),
}

/// Bounded final join for a session child-task handle.
///
/// By the time this runs, the session token has been cancelled and the drain
/// grace has already elapsed (with a loud warning) — a task that still has
/// not exited is ignoring the token, a structural defect. Abort it instead
/// of waiting forever: `run_session` must always return so the supervisor
/// reaches its next reconnect iteration; an unbounded join here is exactly
/// how a wedged wind-down turns into a never-reconnecting agent
/// (docs/bug/2026-09-16-edge-self-dial-agent-no-reregister.md §机制A).
async fn join_or_abort<T>(
    handle: &mut tokio::task::JoinHandle<T>,
    grace: Duration,
    task: &'static str,
) {
    if tokio::time::timeout(grace, &mut *handle).await.is_err() {
        metrics::counter!("interflow_agent_session_join_timeout_total", "task" => task)
            .increment(1);
        error!(
            "{task} task did not exit within {grace:?} of session cancellation — \
             aborting (structural defect: the task ignores the cancellation token)"
        );
        handle.abort();
        // Reap the aborted task so the JoinHandle completes (and the tracker
        // close-out stays truthful).
        let _ = handle.await;
    }
}

impl AgentClient {
    async fn register(
        &self,
        send_request: &mut SendRequest<H2RequestBody>,
    ) -> Result<RegisterResponse> {
        let builder = Request::builder()
            .method("POST")
            .uri("/register")
            .header("x-agent-id", &self.config.agent.id);

        let register_req = builder.body(empty_request_body()).unwrap();

        let response = send_request.send_request(register_req).await?;
        if response.status() != 200 {
            return Err(InterflowError::registration(format!(
                "registration failed: {}",
                response.status()
            )));
        }
        // Capability negotiation: the declaration must parse (hub and agent
        // deploy as a versioned pair; a body read/parse failure is a
        // protocol violation — registration fails and the supervisor's
        // retry cycle handles it).
        let body = response.into_body();
        let collected = BodyExt::collect(body).await?;
        let negotiated = RegisterResponse::parse(&collected.to_bytes())?;
        info!(
            "Agent registered: {} (hub heartbeat: {:?})",
            self.config.agent.id, negotiated.heartbeat
        );
        Ok(negotiated)
    }
}

/// Appends the h2 escape-hatch hint to a QUIC establish failure.
///
/// There is deliberately no automatic transport fallback
/// on a UDP-blocked
/// network the only remedy is the user switching to h2, so the error must
/// point at that switch instead of leaving a bare timeout. Fatal (config)
/// errors pass through untouched — the supervisor's no-retry decision reads
/// the top-level variant, and wrapping a Config error inside a Connection
/// error would downgrade it to retried forever.
fn quic_establish_error(e: InterflowError) -> InterflowError {
    const HINT: &str = " - if this network blocks UDP egress, switch to the h2 transport \
         (expose client: --transport h2; mesh agent config: transport = \"h2\")";
    if e.is_fatal() {
        return e;
    }
    InterflowError::connection(format!("{e}; {HINT}")).with_source(e)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The bounded-join contract (mechanism A hardening,
    /// docs/bug/2026-09-16-edge-self-dial-agent-no-reregister.md): a task
    /// that never exits is aborted within the grace — never awaited forever.
    #[tokio::test]
    async fn join_or_abort_aborts_a_task_that_never_exits() {
        let mut handle = tokio::spawn(async {
            std::future::pending::<()>().await;
        });
        let started = std::time::Instant::now();
        join_or_abort(&mut handle, Duration::from_millis(100), "test").await;
        assert!(
            started.elapsed() < Duration::from_secs(2),
            "join_or_abort must be bounded, took {:?}",
            started.elapsed()
        );
        assert!(handle.is_finished(), "the stuck task must be aborted");
    }

    /// A well-behaved task passes through untouched (completes, no abort).
    #[tokio::test]
    async fn join_or_abort_passes_through_a_well_behaved_task() {
        let mut handle = tokio::spawn(async { 7_u32 });
        join_or_abort(&mut handle, Duration::from_secs(5), "test").await;
        assert!(handle.is_finished());
    }

    /// No-fallback policy: every retryable QUIC establish failure must point
    /// the user at the h2 escape hatch, without losing the original context.
    #[test]
    fn quic_establish_error_appends_h2_hint_to_retryable_failures() {
        let e = quic_establish_error(InterflowError::connection(
            "QUIC connect/register timeout (>15s): hub=\"hub:16666\"".to_string(),
        ));
        let msg = e.to_string();
        assert!(
            msg.contains("--transport h2"),
            "h2 escape hatch missing: {msg}"
        );
        assert!(
            msg.contains("hub:16666"),
            "original context lost behind the hint: {msg}"
        );
    }

    /// Config errors keep their fatal (no-retry) semantics: no hint, no
    /// downgrade into a retryable Connection error.
    #[test]
    fn quic_establish_error_leaves_fatal_config_errors_untouched() {
        let e = quic_establish_error(InterflowError::config(
            "transport = \"quic\" requires hub_quic_addr".to_string(),
        ));
        assert!(
            !e.to_string().contains("--transport h2"),
            "fatal errors carry no fallback hint: {e}"
        );
        assert!(e.is_fatal(), "wrapping must not downgrade a config error");
    }

    /// The identity binding pre-validation (design §3.2): an agent id that
    /// differs from the certificate CN — the macOS-autocapitalized
    /// `Expose-lan-agent` shape from the 2026-09-18 GUI papercuts — must fail
    /// at construction with the certificate's actual CN in the message,
    /// not at the hub with a 403 after a full TLS handshake.
    #[test]
    fn construction_rejects_agent_id_that_differs_from_cert_cn() {
        let certs = interflow_testkit::certs::TestCerts::generate("cn-bind", "expose-lan-agent");
        let (cert, key) = certs.client_paths();
        let config = AgentConfig {
            agent: crate::config::AgentInfo {
                id: "Expose-lan-agent".to_string(),
                hub_url: "https://127.0.0.1:16666".to_string(),
                ..crate::config::AgentInfo::default()
            },
            tls: Some(crate::config::AgentTlsConfig {
                enabled: true,
                ca_path: Some(certs.ca_path().display().to_string()),
                client_cert_path: Some(cert.display().to_string()),
                client_key_path: Some(key.display().to_string()),
                hub_cert_fingerprint: None,
            }),
            ..AgentConfig::default()
        };

        let err = AgentClient::new(config)
            .map(|_| ())
            .expect_err("CN mismatch must fail construction, not registration");
        let msg = err.to_string();
        assert!(
            msg.contains("agent ID must equal the certificate CN (expose-lan-agent)"),
            "wrong message: {msg}"
        );
        assert!(err.is_fatal(), "a wrong agent id is a config error");
    }

    /// The matching pair (id == CN) and the certificate-less constructions
    /// (plain-http test setups) must keep constructing.
    #[test]
    fn construction_accepts_matching_cn_and_certificate_less_configs() {
        let certs = interflow_testkit::certs::TestCerts::generate("cn-bind-ok", "agent-a");
        let (cert, key) = certs.named_client_cert("agent-a");
        let tls = |cert: std::path::PathBuf, key: std::path::PathBuf| {
            Some(crate::config::AgentTlsConfig {
                enabled: true,
                ca_path: Some(certs.ca_path().display().to_string()),
                client_cert_path: Some(cert.display().to_string()),
                client_key_path: Some(key.display().to_string()),
                hub_cert_fingerprint: None,
            })
        };
        let config = AgentConfig {
            agent: crate::config::AgentInfo {
                id: "agent-a".to_string(),
                hub_url: "https://127.0.0.1:16666".to_string(),
                ..crate::config::AgentInfo::default()
            },
            tls: tls(cert, key),
            ..AgentConfig::default()
        };
        assert!(AgentClient::new(config).is_ok());

        let plain = AgentConfig {
            tls: None,
            ..AgentConfig {
                agent: crate::config::AgentInfo {
                    id: "agent-a".to_string(),
                    hub_url: "https://127.0.0.1:16666".to_string(),
                    ..crate::config::AgentInfo::default()
                },
                ..AgentConfig::default()
            }
        };
        assert!(AgentClient::new(plain).is_ok());
    }
}
