use crate::agent::control::ControlServer;
use crate::agent::egress::EgressHandler;
use crate::agent::handle::{AgentHandle, AgentState, EventSink, backoff_duration};
use crate::agent::ingress::IngressHandler;
use crate::agent::rules::RuleStore;
use crate::config::{AgentConfig, TransportKind};
use crate::negotiation::Negotiated;
use http::Uri;
use http_body_util::BodyExt;
use hyper::Request;
use hyper::client::conn::http2::SendRequest;
use hyper_util::rt::{TokioExecutor, TokioIo, TokioTimer};
use interflow_core::error::{InterflowError, Result};
use interflow_core::tunnel::{
    AgentTunnel, DEFAULT_REQUEST_ESTABLISH_TIMEOUT, H2Liveness, H2RequestBody, SessionSlot,
    empty_request_body,
};
use rustls::ClientConfig;
use rustls::pki_types::ServerName;
use rustls_pemfile::certs;
use std::fs::File;
use std::io::BufReader;
use std::sync::Arc;
use tokio::net::TcpStream;
use tokio::sync::mpsc;
use tokio::time::{Duration, sleep};
use tokio_rustls::TlsConnector;
use tokio_util::sync::CancellationToken;
use tokio_util::task::TaskTracker;
use tracing::{error, info, warn};

/// Execution upper bound for the tunnel termination contract (`shutdown`:
/// clear both dispatch tables + seal the upstream channel).
const SESSION_SHUTDOWN_TIMEOUT: Duration = Duration::from_secs(1);

/// Bounded close-out grace for all child tasks (forwarders/pumps/listeners/
/// control) during session teardown.
///
/// After token cancellation child tasks should exit within milliseconds; the
/// grace only absorbs in-flight I/O wind-down (e.g. a final bounded frame
/// write). Exceeding it indicates a structural defect (a task ignoring the
/// token), counted + a loud warning.
const SESSION_DRAIN_GRACE: Duration = Duration::from_secs(5);

/// Final bounded join grace for session child-task handles after the drain
/// grace has already warned: a task that still has not exited here is
/// ignoring the cancellation token — abort instead of waiting forever, so
/// `run_session` always returns and the supervisor always reaches its next
/// reconnect iteration (mechanism A of
/// docs/bug/2026-09-16-edge-self-dial-agent-no-reregister.md).
const HANDLER_JOIN_GRACE: Duration = Duration::from_secs(1);

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
    /// Registration capability-negotiation result (the source for deriving
    /// the data-plane Pong + poll watchdog cadence).
    pub negotiated: Negotiated,
}

impl HubConnection {
    /// h2 session liveness parameters derived from negotiation (without the
    /// agent-side config override).
    ///
    /// Direct callers (expose edge, etc.) use this as is; the
    /// [`AgentClient::start`] path layers the `poll_idle_timeout_secs`
    /// config override on top of it.
    pub fn h2_liveness(&self) -> H2Liveness {
        H2Liveness {
            poll_watchdog: self.negotiated.poll_watchdog(),
            pong_via_upload: self.negotiated.pong_via_upload(),
            establish_timeout: DEFAULT_REQUEST_ESTABLISH_TIMEOUT,
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
        let rule_store = RuleStore::from_config(&config, None);
        let egress_runtime = Arc::new(crate::agent::egress::EgressRuntime::from_config(&config));
        Ok(Self {
            config,
            rule_store,
            egress_runtime,
        })
    }

    /// File-backed construction: control-API rule adds/removes are atomically
    /// written back to this config file (the file is the source of truth).
    pub fn with_config_file(
        config: AgentConfig,
        path: impl Into<std::path::PathBuf>,
    ) -> Result<Self> {
        let rule_store = RuleStore::from_config(&config, Some(path.into()));
        let egress_runtime = Arc::new(crate::agent::egress::EgressRuntime::from_config(&config));
        Ok(Self {
            config,
            rule_store,
            egress_runtime,
        })
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
            // Await directly: run_session itself responds to cancellation
            // (including the unified wind-down: session_token.cancel ->
            // tunnel.shutdown -> bounded tracker close-out); do not wrap it
            // in an outer select, otherwise shutdown would drop the future
            // and skip the wind-down.
            let outcome = self.run_session(&sink, &shutdown, &slot).await;

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

        // Connect + register (branch by transport: h2 = HTTP/2 + /register;
        // quic = control-stream Hello)
        let (agent_id, tunnel, mut connection_handle, mut hub_client_for_control) = tokio::select! {
            r = self.establish_tunnel(&session_token) => r?,
            () = session_token.cancelled() => return Ok(SessionOutcome::Shutdown),
        };

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
        let session_tracker = TaskTracker::new();

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
        let egress_policy = crate::agent::egress::EgressPolicy::from_config(&self.config);
        let egress_runtime = Arc::clone(&self.egress_runtime);
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
            // The session token has two cancellation sources: user shutdown
            // (parent cascade) or the poll receive-side watchdog (data-plane
            // stall self-healing inside the h2 tunnel). Distinguish by the
            // parent token — the watchdog must take the reconnect path;
            // mistaking it for Shutdown would leave the agent zombied in
            // Stopped.
            () = session_token.cancelled() => {
                if shutdown.is_cancelled() {
                    SessionEnd::Shutdown
                } else {
                    SessionEnd::Watchdog
                }
            }
            // h2 session: the hyper connection future ending = disconnect;
            // QUIC sessions have no separate connection task — sensed via
            // the tunnel path (never fires here)
            () = async {
                match connection_handle.as_mut() {
                    Some(h) => { let _ = h.await; }
                    None => std::future::pending::<()>().await,
                }
            } => SessionEnd::Disconnected,
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
        if let Some(h) = connection_handle.as_mut() {
            h.abort();
        }
        if let Some(mut control_handle) = control_handle.take() {
            join_or_abort(&mut control_handle, HANDLER_JOIN_GRACE, "control").await;
        }
        session_tracker.close();
        if tokio::time::timeout(SESSION_DRAIN_GRACE, session_tracker.wait())
            .await
            .is_err()
        {
            // Reaching this point means some child task ignored the token —
            // a structural defect that must be loudly warned about rather
            // than silently leaked (lesson from the fd-leak incident,
            // 2026-09-14).
            metrics::counter!("interflow_agent_session_drain_timeout_total").increment(1);
            error!(
                "session teardown did not close out within {:?} (some child tasks ignore the cancellation token)",
                SESSION_DRAIN_GRACE
            );
        }

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
                    "poll data-plane stall (receive-side watchdog triggered), rebuilding session"
                );
                Ok(SessionOutcome::Ended(
                    "poll data-plane stall (watchdog)".into(),
                ))
            }
            SessionEnd::Handler(handler_res) => match handler_res {
                Ok(Ok(())) => Ok(SessionOutcome::Ended("session ended normally".into())),
                Ok(Err(e)) => Err(e),
                Err(e) => Err(InterflowError::JoinError(e)),
            },
        }
    }

    /// Establish the tunnel per the configured transport.
    ///
    /// Returns (agent_id, tunnel facade, h2 connection task [h2 only], h2
    /// sender for control [h2 only]).
    async fn establish_tunnel(
        &self,
        session_token: &CancellationToken,
    ) -> Result<(
        String,
        AgentTunnel,
        Option<tokio::task::JoinHandle<()>>,
        Option<SendRequest<H2RequestBody>>,
    )> {
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
                let tunnel = AgentTunnel::from_sender(
                    conn.agent_id.clone(),
                    &conn.hub_url,
                    conn.send_request.clone(),
                    self.config.agent.auth_token.clone(),
                    session_token.clone(),
                    liveness,
                )?;
                Ok((
                    conn.agent_id,
                    tunnel,
                    Some(conn.conn_handle),
                    Some(conn.send_request),
                ))
            }
            TransportKind::Quic => {
                let (tunnel, closed_watcher) = self.connect_quic(session_token.clone()).await?;
                Ok((
                    self.config.agent.id.clone(),
                    tunnel,
                    Some(closed_watcher),
                    None,
                ))
            }
        }
    }

    /// QUIC connect (with an overall timeout, aligned with the h2 path's
    /// connect_timeout semantics).
    /// Returns the tunnel and a connection-death watcher (session-level
    /// disconnect detection, aligned with the h2 connection future).
    async fn connect_quic(
        &self,
        session_token: CancellationToken,
    ) -> Result<(AgentTunnel, tokio::task::JoinHandle<()>)> {
        let timeout = Duration::from_secs(self.config.agent.connect_timeout_secs);
        match tokio::time::timeout(timeout, self.connect_quic_inner(session_token)).await {
            Ok(r) => r,
            Err(_) => Err(InterflowError::connection(format!(
                "QUIC connect/register timeout (>{timeout:?}): hub={:?}",
                self.config.agent.hub_quic_addr
            ))),
        }
    }

    async fn connect_quic_inner(
        &self,
        session_token: CancellationToken,
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

        let tunnel = std::sync::Arc::new(
            interflow_core::tunnel::quic::QuicTunnel::connect(
                self.config.agent.id.clone(),
                server_addr,
                &server_name,
                tls_config,
                self.config.agent.auth_token.as_deref(),
                session_token,
            )
            .await?,
        );

        // Session-level disconnect detection: quinn connection closed (hub
        // death / network drop / idle timeout) -> the session ends and
        // reconnects. Without this watcher, an idle agent would zombie in
        // Connected when the hub dies (the read loop exits silently without
        // ending the session).
        let closed_watcher = tokio::spawn({
            let tunnel = tunnel.clone();
            async move {
                tunnel.closed().await;
            }
        });

        Ok((AgentTunnel::from_transport(tunnel), closed_watcher))
    }

    /// Build the rustls ClientConfig for QUIC (ALPN `interflow`).
    fn build_quic_tls_config(&self) -> Result<rustls::ClientConfig> {
        let alpn = |mut cfg: rustls::ClientConfig| {
            cfg.alpn_protocols = vec![interflow_core::tunnel::quic::QUIC_ALPN.as_bytes().to_vec()];
            cfg
        };

        let Some(tls) = &self.config.tls else {
            return Ok(alpn(rustls::ClientConfig::builder()
                .dangerous()
                .with_custom_certificate_verifier(interflow_core::tls::make_pinned_verifier(
                    "00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00"
                ).map_err(|_| InterflowError::config(
                    "QUIC requires [tls] (connections are not allowed without a [tls] section)".to_string(),
                ))?)
                .with_no_client_auth()));
        };

        // cert pinning: a fingerprint match bypasses the CA
        if let Some(pin_hex) = &tls.hub_cert_fingerprint {
            let verifier = interflow_core::tls::make_pinned_verifier(pin_hex).map_err(|e| {
                InterflowError::config(format!("cert pin configuration error: {e}"))
            })?;
            let builder = rustls::ClientConfig::builder()
                .dangerous()
                .with_custom_certificate_verifier(verifier);
            let cfg = match (&tls.client_cert_path, &tls.client_key_path) {
                (Some(cert_path), Some(key_path)) => builder
                    .with_client_auth_cert(
                        load_pem_cert_chain(cert_path)?,
                        load_pem_private_key(key_path)?,
                    )
                    .map_err(|e| {
                        InterflowError::config(format!("client certificate setup failed: {e}"))
                    })?,
                _ => builder.with_no_client_auth(),
            };
            return Ok(alpn(cfg));
        }

        // CA validation (system CA + optional custom CA)
        let root_store = build_root_store(tls.ca_path.as_ref())?;
        let builder = rustls::ClientConfig::builder().with_root_certificates(root_store);
        let cfg = match (&tls.client_cert_path, &tls.client_key_path) {
            (Some(cert_path), Some(key_path)) => builder
                .with_client_auth_cert(
                    load_pem_cert_chain(cert_path)?,
                    load_pem_private_key(key_path)?,
                )
                .map_err(|e| {
                    InterflowError::config(format!("client certificate setup failed: {e}"))
                })?,
            _ => builder.with_no_client_auth(),
        };
        Ok(alpn(cfg))
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
        // HTTP/2 PING keepalive: send PING after 5s without inbound frames; a
        // PONG not received within 10s declares the connection dead — a
        // disconnect is noticed within ~15s worst case (e.g. a half-open TCP
        // connection after WiFi loss), triggering a supervisor reconnect.
        http_builder.keep_alive_interval(Duration::from_secs(5));
        http_builder.keep_alive_timeout(Duration::from_secs(10));
        // Flow-control windows symmetric with the hub: the default 64KiB
        // stream window turns single-stream throughput for streaming upload /
        // poll into a window bottleneck (introduced with the 2026-09-12
        // upload-streaming work)
        http_builder.initial_stream_window_size(crate::hub::H2_INITIAL_STREAM_WINDOW);
        http_builder.initial_connection_window_size(crate::hub::H2_INITIAL_CONNECTION_WINDOW);

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
                // Build the client config: with mTLS attach the client cert +
                // key (for the hub to verify)
                let root_store = build_root_store(tls_config.ca_path.as_ref())?;
                let config = if let (Some(cert_path), Some(key_path)) =
                    (&tls_config.client_cert_path, &tls_config.client_key_path)
                {
                    info!("mTLS client certificate loaded: {cert_path}");
                    let chain = load_pem_cert_chain(cert_path)?;
                    let key = load_pem_private_key(key_path)?;
                    ClientConfig::builder()
                        .with_root_certificates(root_store)
                        .with_client_auth_cert(chain, key)
                        .map_err(|e| {
                            InterflowError::config(format!("client certificate setup failed: {e}"))
                        })?
                } else {
                    ClientConfig::builder()
                        .with_root_certificates(root_store)
                        .with_no_client_auth()
                };

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

        // Register the agent + capability negotiation (old hub's plain-text
        // response -> Legacy fallback)
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
        let verifier = interflow_core::tls::make_pinned_verifier(pin_hex)
            .map_err(|e| InterflowError::config(format!("cert pin configuration error: {e}")))?;

        let config_builder = ClientConfig::builder()
            .dangerous()
            .with_custom_certificate_verifier(verifier);

        let config = match (client_cert_path, client_key_path) {
            (Some(cert_path), Some(key_path)) => {
                let chain = load_pem_cert_chain(cert_path)?;
                let key = load_pem_private_key(key_path)?;
                config_builder
                    .with_client_auth_cert(chain, key)
                    .map_err(|e| {
                        InterflowError::config(format!("client certificate setup failed: {e}"))
                    })?
            }
            _ => config_builder.with_no_client_auth(),
        };

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
    /// The poll receive-side watchdog fired (data-plane stall self-healing):
    /// the session token was cancelled from inside the h2 tunnel while the
    /// user-level shutdown was not cancelled. Semantically equivalent to
    /// Disconnected's reconnect behavior.
    Watchdog,
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

/// Build the client root certificate store: system roots + optional custom
/// CA.
///
/// A single implementation shared by the h2 and QUIC paths; system-certificate
/// load failures only warn (degraded trust), while a custom-CA failure is a
/// configuration error (errors out).
fn build_root_store(ca_path: Option<&String>) -> Result<rustls::RootCertStore> {
    let mut root_store = rustls::RootCertStore::empty();
    let native_certs = rustls_native_certs::load_native_certs();
    for err in native_certs.errors {
        tracing::warn!("System certificate loading warning: {err}");
    }
    for cert in native_certs.certs {
        if let Err(e) = root_store.add(cert) {
            tracing::warn!("Failed to add system root certificate (skipping it): {e}");
        }
    }
    if let Some(ca_path) = ca_path {
        let file = File::open(ca_path).map_err(|e| {
            InterflowError::config(format!("cannot open CA certificate {ca_path}: {e}"))
        })?;
        let mut reader = BufReader::new(file);
        for cert in rustls_pemfile::certs(&mut reader) {
            let cert = cert.map_err(|e| {
                InterflowError::config(format!("failed to parse CA certificate: {e}"))
            })?;
            root_store.add(cert).map_err(|e| {
                InterflowError::config(format!("failed to add CA certificate: {e}"))
            })?;
        }
    }
    Ok(root_store)
}

/// Load a PEM-encoded client certificate chain (for mTLS).
fn load_pem_cert_chain(path: &str) -> Result<Vec<rustls::pki_types::CertificateDer<'static>>> {
    let file = File::open(path)
        .map_err(|e| InterflowError::config(format!("cannot open client cert {path}: {e}")))?;
    let mut reader = BufReader::new(file);
    certs(&mut reader)
        .collect::<std::result::Result<Vec<_>, _>>()
        .map_err(|e| InterflowError::config(format!("failed to parse client cert: {e}")))
}

/// Load a PEM-encoded PKCS#8 private key (for mTLS).
fn load_pem_private_key(path: &str) -> Result<rustls::pki_types::PrivateKeyDer<'static>> {
    let file = File::open(path)
        .map_err(|e| InterflowError::config(format!("cannot open client key {path}: {e}")))?;
    let mut reader = BufReader::new(file);
    let keys = rustls_pemfile::pkcs8_private_keys(&mut reader)
        .collect::<std::result::Result<Vec<_>, _>>()
        .map_err(|e| InterflowError::config(format!("failed to parse client key: {e}")))?;
    keys.into_iter()
        .next()
        .map(rustls::pki_types::PrivateKeyDer::Pkcs8)
        .ok_or_else(|| {
            InterflowError::config(format!("no PKCS#8 private key found in client key {path}"))
        })
}

impl AgentClient {
    async fn register(&self, send_request: &mut SendRequest<H2RequestBody>) -> Result<Negotiated> {
        let mut builder = Request::builder()
            .method("POST")
            .uri("/register")
            .header("x-agent-id", &self.config.agent.id);

        if let Some(token) = &self.config.agent.auth_token {
            builder = builder.header("Authorization", format!("Bearer {token}"));
        }

        let register_req = builder.body(empty_request_body()).unwrap();

        let response = send_request.send_request(register_req).await?;
        if response.status() != 200 {
            return Err(InterflowError::registration(format!(
                "registration failed: {}",
                response.status()
            )));
        }
        // Capability negotiation: best-effort parsing of the response body
        // (data-plane Pong + poll watchdog cadence).
        // A body-read failure also falls back to Legacy — registration
        // itself already succeeded; the connection must not be torn down
        // over a negotiation failure.
        let negotiated = {
            let body = response.into_body();
            match BodyExt::collect(body).await {
                Ok(collected) => Negotiated::parse(&collected.to_bytes()),
                Err(_) => Negotiated::Legacy,
            }
        };
        info!(
            "Agent registered: {} (capability negotiation: {})",
            self.config.agent.id,
            match &negotiated {
                Negotiated::Legacy => "legacy (old hub)".to_string(),
                Negotiated::Modern(r) => format!(
                    "pong_via_upload={}, heartbeat={:?}",
                    r.pong_via_upload, r.heartbeat
                ),
            }
        );
        Ok(negotiated)
    }
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
}
