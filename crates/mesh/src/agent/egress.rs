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
//!
//! Open-flood resource defenses (2026-09-12 backlog: open-flood DoS surface;
//! hardened 2026-09-16 with per-target isolation — see
//! `(internal design notes)`):
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
use bytes::Bytes;
use interflow_core::config::params::BreakerPolicy;
use interflow_core::error::{InterflowError, Result};
use interflow_core::protocol::{CloseReason, StreamProto};
use interflow_core::security::EventRateLimiter;
use interflow_core::tls::extract_cn_from_chain;
use interflow_core::tunnel::inner_udp::{
    self, ControlFrame, DatagramReassembler, SessionId, SessionReject,
};
use interflow_core::tunnel::{AgentTunnel, IncomingStream, TunnelData};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant};
use tokio::net::TcpStream;
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;
use tokio_util::task::TaskTracker;
use tracing::{debug, error, info, warn};

/// Bounded wait for the wind-down Close notification: the wind-down path
/// (including session teardown) never hangs on a full-channel send; on
/// timeout the notification is abandoned (the peer has its own timeout
/// reclamation).
const CLOSE_NOTIFY_TIMEOUT: Duration = Duration::from_secs(1);

/// Egress session resource policy: dial/write-stall timeouts (pure duration
/// parameters, no cross-session state).
#[allow(clippy::struct_field_names)] // each of the three timeouts governs one path; their semantics resist merged naming
#[derive(Clone, Copy)]
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
    /// Cross-session rule truth (in-memory); the
    /// hot path matches against a local snapshot.
    store: Arc<RuleStore>,
    command_rx: Option<mpsc::Receiver<EgressCommand>>,
    /// Request-direction new-stream events (handed over by dispatch,
    /// take-once).
    incoming: mpsc::Receiver<IncomingStream>,
    /// Session-scoped plumbing shared with every per-stream handler.
    sess: EgressSession,
}

enum UdpAssociationCommand {
    Send(SessionId, Bytes),
    Close(SessionId),
}

type UdpSessionSenders = Arc<std::sync::Mutex<HashMap<SessionId, mpsc::Sender<Bytes>>>>;
type UdpControlStreams = Arc<std::sync::Mutex<HashMap<SessionId, quinn::StreamId>>>;

/// Session-scoped egress plumbing: the handles every per-stream handler
/// needs beyond its rule snapshot. Assembled once per session (the same
/// fields [`EgressHandler::new`] receives beyond the agent id, rule store,
/// and channels), borrowed by in-session calls and cloned into spawned
/// tasks.
pub(crate) struct EgressSession {
    pub(crate) tunnel: AgentTunnel,
    pub(crate) security: SecurityConfig,
    /// Session resource policy (timeout parameters).
    pub(crate) policy: EgressPolicy,
    /// Agent-level flood-line defenses (shared across sessions).
    pub(crate) runtime: Arc<EgressRuntime>,
    /// Session token: the lifecycle anchor of all forwarders — session end
    /// (watchdog/disconnect/shutdown) makes them exit in place, and backend
    /// connection fds release with the task.
    pub(crate) session: CancellationToken,
    /// Session-level task tracker: forwarders hang off it and close out
    /// boundedly in the teardown sequence.
    pub(crate) tracker: TaskTracker,
    /// Mandatory inner-TLS runtime (startup-assembled).
    pub(crate) e2e: Arc<crate::agent::e2e::E2eRuntime>,
}

impl Clone for EgressSession {
    fn clone(&self) -> Self {
        Self {
            tunnel: self.tunnel.clone(),
            security: self.security.clone(),
            policy: self.policy,
            runtime: Arc::clone(&self.runtime),
            session: self.session.clone(),
            tracker: self.tracker.clone(),
            e2e: Arc::clone(&self.e2e),
        }
    }
}

/// Per-association UDP plumbing shared by the session reader, the datagram
/// dispatcher, and backend tasks (all cheap-clone handles).
#[derive(Clone)]
struct UdpAssociationChannels {
    senders: UdpSessionSenders,
    controls: UdpControlStreams,
    command_tx: mpsc::Sender<UdpAssociationCommand>,
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

    /// Runs one long-lived egress UDP inner QUIC association.
    ///
    /// Every inner control `OPEN` is authenticated by the QUIC mTLS verifier
    /// first; target selection, policy, breaker, rate, and concurrency checks
    /// run only after that handshake. No DNS or LAN UDP dial can occur for a
    /// malformed, wrong-CN, foreign-anchor, or revoked peer.
    async fn run_udp_inner_quic_association(
        stream_id: interflow_core::protocol::StreamId,
        rules: Vec<EgressRule>,
        frames: mpsc::Receiver<TunnelData>,
        sess: EgressSession,
        idle_timeout: Duration,
    ) {
        let association_token = sess.session.child_token();
        let tunnel = sess.tunnel.clone();
        let runtime = Arc::clone(&sess.runtime);
        let e2e = Arc::clone(&sess.e2e);
        let carrier = match inner_udp::accept_inner_quic(
            tunnel.clone(),
            stream_id,
            frames,
            e2e.material(),
            inner_udp::CarrierDirection::Egress,
            e2e.handshake_timeout,
        )
        .await
        {
            Ok(carrier) => carrier,
            Err(e) => {
                let reason = if e.to_string().contains("timed out") {
                    "timeout"
                } else {
                    crate::agent::e2e::failure_reason_of(&std::io::Error::other(e.to_string()))
                };
                crate::agent::e2e::record_handshake_failure(crate::agent::e2e::SIDE_EGRESS, reason);
                Self::finish(
                    &tunnel,
                    stream_id,
                    CloseReason::E2eHandshakeFailed,
                    true,
                    &runtime.active,
                )
                .await;
                return;
            }
        };
        crate::agent::e2e::record_handshake_ok(crate::agent::e2e::SIDE_EGRESS);
        metrics::counter!("interflow_agent_inner_quic_handshakes_total", "side" => "egress")
            .increment(1);
        metrics::gauge!("interflow_agent_inner_quic_associations_active").increment(1.0);

        let senders: UdpSessionSenders = Arc::new(std::sync::Mutex::new(HashMap::new()));
        let controls: UdpControlStreams = Arc::new(std::sync::Mutex::new(HashMap::new()));
        let (command_tx, mut command_rx) = mpsc::channel::<UdpAssociationCommand>(256);
        let udp = UdpAssociationChannels {
            senders: Arc::clone(&senders),
            controls: Arc::clone(&controls),
            command_tx: command_tx.clone(),
        };
        tokio::spawn(Self::dispatch_inner_udp_datagrams(
            carrier.clone(),
            Arc::clone(&senders),
        ));
        // The inner QUIC TLS verifier is unbound because the outer source is
        // opaque. The first encrypted control frame is an identity hello that
        // must match the certificate just authenticated by inner QUIC.
        let Ok(Ok(first_control)) =
            tokio::time::timeout(Duration::from_millis(250), carrier.accept_bi()).await
        else {
            carrier.close();
            tokio::time::sleep(Duration::from_millis(100)).await;
            metrics::gauge!("interflow_agent_inner_quic_associations_active").decrement(1.0);
            Self::finish(
                &tunnel,
                stream_id,
                CloseReason::E2eHandshakeFailed,
                true,
                &runtime.active,
            )
            .await;
            return;
        };
        let identity = match read_inner_udp_control(&carrier, first_control).await {
            Ok(ControlFrame::Identity {
                source_principal,
                source_fingerprint,
            }) => Ok((source_principal, source_fingerprint)),
            Ok(_) => Err(InterflowError::protocol("expected inner UDP identity")),
            Err(e) => Err(e),
        };
        let identity_valid = (|| -> bool {
            let Ok((source_principal, source_fingerprint)) = &identity else {
                return false;
            };
            let Some(peer_leaf) = carrier
                .peer_certificates()
                .and_then(|chain| chain.first().cloned())
            else {
                debug!("inner UDP identity has no captured peer certificate");
                return false;
            };
            let peer_cn =
                extract_cn_from_chain(std::slice::from_ref(&peer_leaf)).unwrap_or_default();
            let peer_fingerprint: [u8; 32] = Sha256::digest(peer_leaf.as_ref()).into();
            peer_cn == *source_principal && peer_fingerprint == *source_fingerprint
        })();
        if !identity_valid {
            debug!("first inner UDP identity rejected: {identity:?}");
            carrier.close();
            // Let the inner CONNECTION_CLOSE packet ride the outer Data path
            // before the outer Close tears down the relay state.
            tokio::time::sleep(Duration::from_millis(100)).await;
            metrics::gauge!("interflow_agent_inner_quic_associations_active").decrement(1.0);
            Self::finish(
                &tunnel,
                stream_id,
                CloseReason::E2eHandshakeFailed,
                true,
                &runtime.active,
            )
            .await;
            return;
        }

        loop {
            tokio::select! {
                accepted = carrier.accept_bi() => {
                    match accepted {
                        Ok(control) => {
                            if let Err(e) = Self::handle_inner_udp_session(
                                &carrier,
                                control,
                                &rules,
                                &sess,
                                idle_timeout,
                                &association_token,
                                udp.clone(),
                            ).await {
                                debug!("inner UDP session rejected or ended: {e}");
                            }
                        }
                        Err(e) => {
                            debug!("inner QUIC association ended: {e}");
                            break;
                        }
                    }
                }
                command = command_rx.recv() => {
                    let Some(command) = command else { break };
                    match command {
                        UdpAssociationCommand::Send(session, payload) => {
                            let Ok(fragments) =
                                inner_udp::encode_datagram_fragments(session, &payload)
                            else {
                                metrics::counter!("interflow_udp_fragment_invalid_total")
                                    .increment(1);
                                Self::close_inner_session(&carrier, &controls, session).await;
                                continue;
                            };
                            let mut failed = false;
                            for fragment in fragments {
                                if carrier.send_datagram(fragment).await.is_err() {
                                    failed = true;
                                    break;
                                }
                            }
                            if failed {
                                break;
                            }
                        }
                        UdpAssociationCommand::Close(session) => {
                            let existed = senders
                                .lock()
                                .unwrap_or_else(std::sync::PoisonError::into_inner)
                                .remove(&session)
                                .is_some();
                            Self::close_inner_session(&carrier, &controls, session).await;
                            if existed {
                                runtime.active.fetch_sub(1, Ordering::Relaxed);
                                metrics::gauge!("interflow_agent_incoming_streams_active")
                                    .decrement(1.0);
                            }
                        }
                    }
                }
                () = association_token.cancelled() => break,
            }
        }

        association_token.cancel();
        carrier.close();
        senders
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clear();
        controls
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clear();
        metrics::gauge!("interflow_agent_inner_quic_associations_active").decrement(1.0);
        Self::finish(
            &tunnel,
            stream_id,
            CloseReason::CloseFrame,
            true,
            &runtime.active,
        )
        .await;
    }

    async fn dispatch_inner_udp_datagrams(
        carrier: inner_udp::InnerQuicCarrier,
        senders: UdpSessionSenders,
    ) {
        let mut reassembler = DatagramReassembler::default();
        loop {
            let datagram = match carrier.recv_datagram().await {
                Ok(datagram) => datagram,
                Err(e) => {
                    debug!("UDP egress inner datagram dispatcher ended: {e}");
                    break;
                }
            };
            if datagram.len() < 16 {
                metrics::counter!("interflow_udp_fragment_invalid_total").increment(1);
                continue;
            }
            let Ok(session) = datagram[..16].try_into().map(SessionId) else {
                metrics::counter!("interflow_udp_fragment_invalid_total").increment(1);
                continue;
            };
            let sender = senders
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .get(&session)
                .cloned();
            let Some(sender) = sender else {
                metrics::counter!("interflow_udp_fragment_invalid_total").increment(1);
                continue;
            };
            match reassembler.push(&datagram) {
                Ok(Some(payload)) => {
                    if sender.try_send(payload).is_err() {
                        metrics::counter!("interflow_udp_rate_limited", "direction" => "ingress")
                            .increment(1);
                    }
                }
                Ok(None) => {}
                Err(_) => {
                    metrics::counter!("interflow_udp_fragment_invalid_total").increment(1);
                }
            }
        }
    }

    async fn handle_inner_udp_session(
        carrier: &inner_udp::InnerQuicCarrier,
        control: quinn::StreamId,
        rules: &[EgressRule],
        sess: &EgressSession,
        idle_timeout: Duration,
        association_token: &CancellationToken,
        udp: UdpAssociationChannels,
    ) -> Result<()> {
        let EgressSession {
            security,
            policy,
            runtime,
            ..
        } = sess;
        let UdpAssociationChannels {
            senders,
            controls,
            command_tx,
        } = udp;
        let open = match tokio::time::timeout(
            Duration::from_millis(250),
            read_inner_udp_control(carrier, control),
        )
        .await
        {
            Ok(Ok(ControlFrame::Open {
                session,
                source_principal,
                source_fingerprint,
                selector,
            })) => (session, source_principal, source_fingerprint, selector),
            Ok(Ok(_)) => return Err(InterflowError::protocol("expected inner UDP OPEN")),
            Ok(Err(e)) => return Err(e),
            Err(_) => return Err(InterflowError::connection("inner UDP OPEN timed out")),
        };
        let (session, source_principal, source_fingerprint, selector) = open;
        let Some(peer_leaf) = carrier
            .peer_certificates()
            .and_then(|chain| chain.first().cloned())
        else {
            write_inner_udp_control(
                carrier,
                control,
                &ControlFrame::Reject(session, SessionReject::SecurityDenied),
            )
            .await?;
            let _ = carrier.finish(control).await;
            return Ok(());
        };
        let peer_cn = extract_cn_from_chain(std::slice::from_ref(&peer_leaf)).unwrap_or_default();
        let peer_fingerprint: [u8; 32] = Sha256::digest(peer_leaf.as_ref()).into();
        if peer_cn != source_principal || peer_fingerprint != source_fingerprint {
            metrics::counter!(
                "interflow_agent_open_dropped_total",
                "reason" => "inner_udp_identity_mismatch"
            )
            .increment(1);
            write_inner_udp_control(
                carrier,
                control,
                &ControlFrame::Reject(session, SessionReject::SecurityDenied),
            )
            .await?;
            let _ = carrier.finish(control).await;
            return Ok(());
        }
        if senders
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .contains_key(&session)
        {
            let frame = ControlFrame::Reject(session, SessionReject::LocalLimit);
            write_inner_udp_control(carrier, control, &frame).await?;
            let _ = carrier.finish(control).await;
            return Ok(());
        }

        let target = match selector {
            interflow_core::tunnel::TargetSelector::Default => rules
                .iter()
                .find(|rule| rule.target_protocol == StreamProto::Udp)
                .map(|rule| rule.target_addr.to_string()),
            interflow_core::tunnel::TargetSelector::Address(address) => Some(address),
            interflow_core::tunnel::TargetSelector::Service(service) => rules
                .iter()
                .find(|rule| rule.target_protocol == StreamProto::Udp && rule.name == service)
                .map(|rule| rule.target_addr.to_string()),
        }
        .unwrap_or_default();

        let reject = if target.is_empty() {
            Some(SessionReject::NoTarget)
        } else if !Self::is_target_allowed(&target, security)
            || runtime
                .breakers
                .as_ref()
                .is_some_and(|breaker| breaker.check(&target) == BreakerDecision::Reject)
        {
            Some(SessionReject::SecurityDenied)
        } else if runtime
            .open_rate_limiter
            .as_ref()
            .is_some_and(|limiter| !limiter.check())
        {
            Some(SessionReject::RateLimited)
        } else if runtime.max_incoming_streams > 0
            && runtime.active.load(Ordering::Relaxed) >= runtime.max_incoming_streams
        {
            Some(SessionReject::LocalLimit)
        } else {
            None
        };

        if let Some(reason) = reject {
            metrics::counter!(
                "interflow_agent_open_dropped_total",
                "reason" => format!("inner_udp_{reason:?}")
            )
            .increment(1);
            write_inner_udp_control(carrier, control, &ControlFrame::Reject(session, reason))
                .await?;
            let _ = carrier.finish(control).await;
            return Ok(());
        }

        let prev = runtime.active.fetch_add(1, Ordering::Relaxed);
        metrics::gauge!("interflow_agent_incoming_streams_active").increment(1.0);
        Self::warn_high_water(runtime, prev + 1);
        let (backend_tx, backend_rx) = mpsc::channel(64);
        senders
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .insert(session, backend_tx);
        controls
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .insert(session, control);
        write_inner_udp_control(carrier, control, &ControlFrame::Accept(session)).await?;
        metrics::counter!("interflow_agent_inner_quic_sessions_total").increment(1);

        let session_token = association_token.child_token();
        tokio::spawn(Self::read_inner_udp_control(
            carrier.clone(),
            control,
            session,
            UdpAssociationChannels {
                senders: Arc::clone(&senders),
                controls: Arc::clone(&controls),
                command_tx: command_tx.clone(),
            },
            Arc::clone(runtime),
            session_token,
        ));
        Self::spawn_inner_udp_backend(
            session,
            target,
            backend_rx,
            command_tx,
            *policy,
            runtime.breakers.clone(),
            association_token.clone(),
            idle_timeout,
        );
        Ok(())
    }

    async fn read_inner_udp_control(
        carrier: inner_udp::InnerQuicCarrier,
        control: quinn::StreamId,
        session: SessionId,
        udp: UdpAssociationChannels,
        runtime: Arc<EgressRuntime>,
        token: CancellationToken,
    ) {
        let UdpAssociationChannels {
            senders,
            controls,
            command_tx,
        } = udp;
        tokio::select! {
            () = token.cancelled() => {}
            // Any close, malformed frame, or EOF ends this session; cleanup
            // is identical and handled below.
            _ = read_inner_udp_control(&carrier, control) => {}
        }
        let existed = senders
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .remove(&session)
            .is_some();
        controls
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .remove(&session);
        let _ = command_tx.send(UdpAssociationCommand::Close(session)).await;
        if existed {
            runtime.active.fetch_sub(1, Ordering::Relaxed);
            metrics::gauge!("interflow_agent_incoming_streams_active").decrement(1.0);
        }
    }

    async fn close_inner_session(
        carrier: &inner_udp::InnerQuicCarrier,
        controls: &UdpControlStreams,
        session: SessionId,
    ) {
        let control = controls
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .remove(&session);
        if let Some(control) = control
            && let Ok(frame) = ControlFrame::Close(session).encode()
        {
            let _ = carrier.write_all(control, &frame).await;
            let _ = carrier.finish(control).await;
        }
    }

    fn spawn_inner_udp_backend(
        session: SessionId,
        target_addr: String,
        mut backend_rx: mpsc::Receiver<Bytes>,
        command_tx: mpsc::Sender<UdpAssociationCommand>,
        policy: EgressPolicy,
        breakers: Option<Arc<TargetBreakers>>,
        session_token: CancellationToken,
        idle_timeout: Duration,
    ) {
        let resolve_timeout = policy.resolve_timeout;
        tokio::spawn(async move {
            let resolved =
                match tokio::time::timeout(resolve_timeout, tokio::net::lookup_host(&target_addr))
                    .await
                {
                    Ok(Ok(addrs)) => addrs.collect::<Vec<_>>(),
                    Ok(Err(e)) => {
                        error!("Failed to resolve UDP target {target_addr}: {e}");
                        if let Some(breakers) = &breakers {
                            breakers.note_failure(&target_addr);
                        }
                        let _ = command_tx.send(UdpAssociationCommand::Close(session)).await;
                        return;
                    }
                    Err(_) => {
                        error!("UDP target resolve timed out: {target_addr}");
                        if let Some(breakers) = &breakers {
                            breakers.note_failure(&target_addr);
                        }
                        let _ = command_tx.send(UdpAssociationCommand::Close(session)).await;
                        return;
                    }
                };
            let safe_address = resolved
                .into_iter()
                .find(|sa| !crate::agent::ssrf_deny::is_ip_ssrf_blocked(sa.ip()));
            let Some(address) = safe_address else {
                error!(
                    "Security block: all resolved IPs for UDP target {target_addr} hit the SSRF blocklist"
                );
                let _ = command_tx.send(UdpAssociationCommand::Close(session)).await;
                return;
            };
            let bind_addr = if address.is_ipv4() {
                "0.0.0.0:0"
            } else {
                "[::]:0"
            };
            let Ok(bind_address) = bind_addr.parse() else {
                return;
            };
            let Ok(socket) = crate::agent::ingress_udp::bind_udp_socket(bind_address) else {
                error!("UDP socket bind failed ({bind_address})");
                return;
            };
            if socket.connect(address).await.is_err() {
                error!("UDP connect failed {target_addr}");
                if let Some(breakers) = &breakers {
                    breakers.note_failure(&target_addr);
                }
                let _ = command_tx.send(UdpAssociationCommand::Close(session)).await;
                return;
            }
            if let Some(breakers) = &breakers {
                breakers.note_success(&target_addr);
            }
            let socket = Arc::new(socket);
            let last_active = Arc::new(std::sync::Mutex::new(Instant::now()));
            let child_token = session_token.child_token();

            let mut write_task = {
                let socket = Arc::clone(&socket);
                let last_active = Arc::clone(&last_active);
                let token = child_token.clone();
                tokio::spawn(async move {
                    loop {
                        tokio::select! {
                            () = token.cancelled() => break,
                            packet = backend_rx.recv() => {
                                let Some(packet) = packet else { break };
                                if packet.is_empty() {
                                    continue;
                                }
                                if socket.send(&packet).await.is_err() {
                                    break;
                                }
                                metrics::counter!("interflow_udp_egress_datagrams_tx").increment(1);
                                *last_active.lock().unwrap_or_else(std::sync::PoisonError::into_inner) = Instant::now();
                            }
                        }
                    }
                })
            };

            let mut read_task = {
                let socket = Arc::clone(&socket);
                let last_active = Arc::clone(&last_active);
                let command_tx = command_tx.clone();
                let token = child_token.clone();
                tokio::spawn(async move {
                    let mut buf = vec![0u8; UDP_RECV_BUF];
                    loop {
                        tokio::select! {
                            () = token.cancelled() => break,
                            result = socket.recv(&mut buf) => {
                                let Ok(n) = result else { break };
                                if n == UDP_RECV_BUF {
                                    metrics::counter!("interflow_udp_egress_truncated").increment(1);
                                    continue;
                                }
                                if command_tx
                                    .send(UdpAssociationCommand::Send(
                                        session,
                                        Bytes::copy_from_slice(&buf[..n]),
                                    ))
                                    .await
                                    .is_err()
                                {
                                    break;
                                }
                                metrics::counter!("interflow_udp_egress_datagrams_rx").increment(1);
                                *last_active.lock().unwrap_or_else(std::sync::PoisonError::into_inner) = Instant::now();
                            }
                        }
                    }
                })
            };

            tokio::select! {
                _ = &mut write_task => {}
                _ = &mut read_task => {}
                () = child_token.cancelled() => {}
                () = tokio::time::sleep_until(tokio::time::Instant::from_std(
                    *last_active.lock().unwrap_or_else(std::sync::PoisonError::into_inner) + idle_timeout,
                )) => {
                    metrics::counter!("interflow_udp_egress_idle_timeout").increment(1);
                }
            }
            child_token.cancel();
            let _ = command_tx.send(UdpAssociationCommand::Close(session)).await;
        });
    }

    pub(crate) const fn new(
        agent_id: String,
        store: Arc<RuleStore>,
        command_rx: Option<mpsc::Receiver<EgressCommand>>,
        incoming: mpsc::Receiver<IncomingStream>,
        sess: EgressSession,
    ) -> Self {
        Self {
            agent_id,
            store,
            command_rx,
            incoming,
            sess,
        }
    }

    pub async fn run(self) -> Result<()> {
        info!("Egress handler started, agent_id={}", self.agent_id);

        // The hot path matches against a local snapshot: taken from the
        // store at session start (including API additions from the previous
        // session), refreshed after command changes — per-stream matching is
        // lock-free.
        let mut rules = self.store.egress_snapshot().await;
        let store = self.store;
        let sess = self.sess;

        for rule in &rules {
            info!(
                "Configured egress rule: {} -> {}",
                rule.name, rule.target_addr
            );
        }

        let mut command_rx = self.command_rx;
        let mut incoming = self.incoming;

        loop {
            tokio::select! {
                // Handle rule add/remove commands (all acknowledged)
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
                        Self::handle_incoming_stream(stream, &sess, &rules).await;
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
    async fn handle_incoming_stream(
        stream: IncomingStream,
        sess: &EgressSession,
        rules: &[EgressRule],
    ) {
        let EgressSession {
            tunnel,
            runtime,
            tracker,
            ..
        } = sess;
        let IncomingStream { open, frames } = stream;
        let stream_id = open.stream_id;
        let prev_active = runtime.active.fetch_add(1, Ordering::Relaxed);
        metrics::gauge!("interflow_agent_incoming_streams_active").increment(1.0);
        Self::warn_high_water(runtime, prev_active + 1);

        let proto = StreamProto::from_frame_flags(open.flags);

        // Opens carry only the opaque source identity — the
        // requester's circuit rides the header field (the former payload hex
        // and the `src:target` split are gone). The LAN target stays
        // encrypted in the inner layer (TLS for TCP, QUIC for UDP).
        let src_agent = match open.origin {
            interflow_core::protocol::FrameOrigin::Agent(c) => c.to_hex(),
            _ => String::new(),
        };

        // E2e declaration on the stream. UDP has no plaintext fallback.
        let e2e_requested = open.flags & interflow_core::protocol::FLAG_E2E != 0;

        if runtime.max_incoming_streams > 0
            && runtime.active.load(Ordering::Relaxed) > runtime.max_incoming_streams
        {
            metrics::counter!(
                "interflow_agent_open_dropped_total",
                "reason" => CloseReason::LocalLimit.to_string()
            )
            .increment(1);
            Self::finish(
                tunnel,
                stream_id,
                CloseReason::LocalLimit,
                true,
                &runtime.active,
            )
            .await;
            return;
        }

        // Downgrade rejection (RFC §4/A5): in `required` mode a TCP stream
        // without the e2e declaration is a stripped flag or an old/foreign
        // initiator — closed fail-closed before any policy/dial work, never
        // a plaintext forward.
        if !e2e_requested {
            crate::agent::e2e::record_handshake_failure(
                crate::agent::e2e::SIDE_EGRESS,
                crate::agent::e2e::REASON_NOT_NEGOTIATED,
            );
            warn!(
                "e2e required: rejecting non-e2e {proto:?} stream {stream_id} (stripped FLAG_E2E or legacy peer), source={src_agent}"
            );
            Self::finish(
                tunnel,
                stream_id,
                CloseReason::E2eHandshakeFailed,
                true,
                &runtime.active,
            )
            .await;
            return;
        }

        let matched_rule = rules.iter().find(|r| r.target_protocol == proto);

        if proto == StreamProto::Tcp {
            // Dynamic target and policy checks happen only after the inner
            // handshake and encrypted selector have been validated.
            tracker.spawn(Self::run_tcp_forwarder(
                stream_id,
                rules.to_vec(),
                frames,
                src_agent.clone(),
                sess.clone(),
            ));
            return;
        }

        if proto == StreamProto::Udp {
            let idle_timeout = matched_rule.map_or(
                Duration::from_mins(1),
                EgressRule::effective_udp_idle_timeout,
            );
            tracker.spawn(Self::run_udp_inner_quic_association(
                stream_id,
                rules.to_vec(),
                frames,
                sess.clone(),
                idle_timeout,
            ));
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
    ///   drops. This is the structural fix for the fd-leak root cause.
    async fn run_tcp_forwarder(
        stream_id: interflow_core::protocol::StreamId,
        rules: Vec<EgressRule>,
        mut frames: mpsc::Receiver<TunnelData>,
        src_agent: String,
        sess: EgressSession,
    ) {
        let EgressSession {
            tunnel,
            security,
            policy,
            runtime,
            e2e,
            ..
        } = sess;
        let write_timeout = policy.backend_write_timeout;
        let resolve_timeout = policy.resolve_timeout;
        let connect_timeout = policy.connect_timeout;
        // 0. Mandatory inner TLS handshake phase — dial-after-handshake (RFC
        //    §3.3): the backend DNS resolve/TCP connect below runs only
        //    after the peer is cryptographically confirmed, so a malicious
        //    hub cannot drive a plaintext dial into the LAN with a
        //    redirected stream. A failed or absent handshake closes here
        //    with zero dial; there is no plaintext fallback.
        let adapter = interflow_core::tunnel::e2e::E2eTunnelIo::egress(
            std::mem::replace(&mut frames, mpsc::channel(1).1),
            tunnel.clone(),
            stream_id,
        );
        let acceptor = match e2e.server_acceptor_unbound() {
            Ok(a) => a,
            Err(e) => {
                // Startup-assembled material gone stale mid-session: fail closed.
                crate::agent::e2e::record_handshake_failure(
                    crate::agent::e2e::SIDE_EGRESS,
                    "protocol",
                );
                error!(
                    "inner TLS acceptor build failed for {stream_id} (source {src_agent}): {e}; closing stream"
                );
                Self::finish(
                    &tunnel,
                    stream_id,
                    CloseReason::E2eHandshakeFailed,
                    true,
                    &runtime.active,
                )
                .await;
                return;
            }
        };
        let (tls, close_reason, target_addr) = match interflow_core::tunnel::e2e::inner_tls_accept(
            adapter,
            acceptor,
            e2e.handshake_timeout,
        )
        .await
        {
            interflow_core::tunnel::e2e::E2eHandshakeOutcome::Established(mut tls, reason) => {
                crate::agent::e2e::record_handshake_ok(crate::agent::e2e::SIDE_EGRESS);
                let hello = match tokio::time::timeout(
                    e2e.handshake_timeout,
                    interflow_core::tunnel::InnerStreamHello::read(&mut tls),
                )
                .await
                {
                    Ok(Ok(hello)) => hello,
                    Ok(Err(e)) => {
                        error!("inner selector read failed for {stream_id}: {e}");
                        crate::agent::e2e::record_handshake_failure(
                            crate::agent::e2e::SIDE_EGRESS,
                            "protocol",
                        );
                        Self::finish(
                            &tunnel,
                            stream_id,
                            CloseReason::E2eHandshakeFailed,
                            true,
                            &runtime.active,
                        )
                        .await;
                        return;
                    }
                    Err(_) => {
                        error!("inner selector read timed out for {stream_id}");
                        crate::agent::e2e::record_handshake_failure(
                            crate::agent::e2e::SIDE_EGRESS,
                            "protocol",
                        );
                        Self::finish(
                            &tunnel,
                            stream_id,
                            CloseReason::E2eHandshakeFailed,
                            true,
                            &runtime.active,
                        )
                        .await;
                        return;
                    }
                };
                let (_, server_conn) = tls.get_ref();
                let Some(peer_leaf) = server_conn.peer_certificates().and_then(|c| c.first())
                else {
                    error!("inner TLS completed without a peer leaf for {stream_id}");
                    crate::agent::e2e::record_handshake_failure(
                        crate::agent::e2e::SIDE_EGRESS,
                        "protocol",
                    );
                    Self::finish(
                        &tunnel,
                        stream_id,
                        CloseReason::E2eHandshakeFailed,
                        true,
                        &runtime.active,
                    )
                    .await;
                    return;
                };
                let peer_cn =
                    extract_cn_from_chain(std::slice::from_ref(peer_leaf)).unwrap_or_default();
                let peer_fingerprint: [u8; 32] = Sha256::digest(peer_leaf.as_ref()).into();
                if peer_cn != hello.source_principal || peer_fingerprint != hello.source_fingerprint
                {
                    error!(
                        "inner selector identity mismatch for {stream_id}: claimed {}, presented {peer_cn}",
                        hello.source_principal
                    );
                    crate::agent::e2e::record_handshake_failure(
                        crate::agent::e2e::SIDE_EGRESS,
                        "protocol",
                    );
                    Self::finish(
                        &tunnel,
                        stream_id,
                        CloseReason::E2eHandshakeFailed,
                        true,
                        &runtime.active,
                    )
                    .await;
                    return;
                }
                let target_addr_selected = match hello.selector {
                    interflow_core::tunnel::TargetSelector::Default => rules
                        .iter()
                        .find(|r| r.target_protocol == StreamProto::Tcp)
                        .map(|r| r.target_addr.to_string()),
                    interflow_core::tunnel::TargetSelector::Address(addr) => Some(addr),
                    interflow_core::tunnel::TargetSelector::Service(service) => rules
                        .iter()
                        .find(|r| r.target_protocol == StreamProto::Tcp && r.name == service)
                        .map(|r| r.target_addr.to_string()),
                }
                .unwrap_or_default();
                if target_addr_selected.is_empty()
                    || !Self::is_target_allowed(&target_addr_selected, &security)
                    || runtime
                        .breakers
                        .as_ref()
                        .is_some_and(|b| b.check(&target_addr_selected) == BreakerDecision::Reject)
                {
                    let close_reason = if target_addr_selected.is_empty() {
                        CloseReason::NoTarget
                    } else if !Self::is_target_allowed(&target_addr_selected, &security) {
                        CloseReason::SecurityDenied
                    } else {
                        CloseReason::TargetCircuitOpen
                    };
                    metrics::counter!(
                        "interflow_agent_open_dropped_total",
                        "reason" => close_reason.to_string()
                    )
                    .increment(1);
                    Self::finish(&tunnel, stream_id, close_reason, true, &runtime.active).await;
                    return;
                }
                // Charge the open budget only for work that will actually
                // dial: inner identity/target/breaker rejections must not let
                // one dead target drain the shared stream budget.
                if let Some(limiter) = &runtime.open_rate_limiter
                    && !limiter.check()
                {
                    metrics::counter!(
                        "interflow_agent_open_dropped_total",
                        "reason" => CloseReason::RateLimited.to_string()
                    )
                    .increment(1);
                    Self::finish(
                        &tunnel,
                        stream_id,
                        CloseReason::RateLimited,
                        true,
                        &runtime.active,
                    )
                    .await;
                    return;
                }
                (tls, reason, target_addr_selected)
            }
            interflow_core::tunnel::e2e::E2eHandshakeOutcome::Failed { error } => {
                let reason = crate::agent::e2e::failure_reason_of(&error);
                crate::agent::e2e::record_handshake_failure(crate::agent::e2e::SIDE_EGRESS, reason);
                warn!(
                    "inner TLS handshake failed ({reason}: {error}), closing stream {stream_id} without dial"
                );
                Self::finish(
                    &tunnel,
                    stream_id,
                    CloseReason::E2eHandshakeFailed,
                    true,
                    &runtime.active,
                )
                .await;
                return;
            }
        };

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
                    stream_id,
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
                    stream_id,
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
                stream_id,
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
                    stream_id,
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
                    stream_id,
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

        // 1b. Established streams pump through the inner TLS layer: all tunnel
        //     bytes are ciphertext from here on. The pump's locally observed
        //     outcome is authoritative; the adapter's Close token is only a
        //     fallback for races where no local half reached EOF.
        let sid = stream_id;
        let t2 = tunnel.clone();
        let outcome = interflow_core::tunnel::pump::pump_duplex(
            stream,
            tls,
            &interflow_core::tunnel::pump::PumpConfig {
                // Egress TCP forwarders have no per-stream idle budget by
                // design (an SSE-style backend may stay legitimately silent);
                // MAX encodes "no idle teardown".
                idle_timeout: Duration::MAX,
                write_stall_timeout: write_timeout,
                idle_timeout_counter: "interflow_agent_e2e_egress_stream_idle_timeout",
                write_stall_counter: "interflow_agent_e2e_egress_backend_write_stall",
                log_label: "egress-e2e",
            },
            CloseReason::BackendClosed,
            interflow_core::tunnel::pump::DUPLEX_LOCAL_EOF_DRAIN,
            stream_id,
            async move { t2.unregister_incoming_stream(sid).await },
        )
        .await;
        let reason = outcome
            .close_reason
            .or_else(|| close_reason.get())
            .unwrap_or(CloseReason::CloseFrame);
        debug!(
            "inner TLS stream {stream_id} ended: {:?} (relayed={})",
            reason, outcome.response_relayed
        );
        // Unified wind-down: the TLS close_notify rode Data frames; the
        // stream Close response is sent here when we ended the stream
        // (peer-initiated ends need no echo — the hub already reaped it).
        let echo_close = !matches!(reason, CloseReason::CloseFrame | CloseReason::SessionClosed);
        Self::finish(&tunnel, stream_id, reason, echo_close, &runtime.active).await;
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
        stream_id: interflow_core::protocol::StreamId,
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
                tunnel.send_close_response(stream_id, reason),
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

async fn read_inner_udp_control(
    carrier: &inner_udp::InnerQuicCarrier,
    stream: quinn::StreamId,
) -> Result<ControlFrame> {
    let mut header = [0u8; 2];
    carrier.read_exact(stream, &mut header).await?;
    let len = u16::from_be_bytes(header) as usize;
    let mut body = vec![0u8; len];
    carrier.read_exact(stream, &mut body).await?;
    let mut encoded = header.to_vec();
    encoded.extend(body);
    Ok(ControlFrame::decode(&encoded)?.0)
}

async fn write_inner_udp_control(
    carrier: &inner_udp::InnerQuicCarrier,
    stream: quinn::StreamId,
    frame: &ControlFrame,
) -> Result<()> {
    carrier.write_all(stream, &frame.encode()?).await
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
