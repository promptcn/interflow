//! Frame-level stream routing: Open/Data/Close ACL checks, direction
//! determination, anti-forgery, and dispatch.
//!
//! 2026-09-12 upload streaming: `POST /stream` (one HTTP exchange per frame,
//! metadata in HTTP headers) was retired, and this module was refactored from
//! "HTTP header parsing + handling" into pure frame-level dispatch, called by
//! the `/stream/up` reader task of [`crate::hub::upload`]:
//! - Direction semantics come from the frame layer's flags
//!   (`FLAG_RESPONSE` / `FLAG_HUB_ORIGIN`);
//! - Frame-level rejections (ACL / stream limits / target unreachable) no
//!   longer have a per-frame HTTP status; instead a hub-origin Close frame
//!   (stream id in the header, u8 reason code in the payload) goes back via
//!   the sender's `/poll` channel — the pump side reuses the existing Close
//!   stream-teardown path (consistent with the existing "stream not found"
//!   convention).

use crate::hub::service::HubService;
use crate::hub::state::{
    HubState, PeerIdentity, SessionWitness, StreamFace, TunnelData, release_stream_slot,
};
use bytes::Bytes;
use interflow_core::protocol::{
    CircuitToken, CloseReason, FLAG_E2E, FLAG_RESPONSE, FrameOrigin, FrameType, RouteToken,
    StreamId, StreamProto,
};
use interflow_core::security::AuditKind;
use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::time::Duration;
use tokio::sync::mpsc;
use tracing::{debug, error, trace, warn};

/// Maximum agent_id length (128B), character allowlist `[A-Za-z0-9_.-]`.
pub(crate) const MAX_AGENT_ID_LEN: usize = 128;

/// The session-headroom warn ratio.
///
/// A scope (global or per-agent) whose remaining capacity falls under this
/// fraction reads ⚠ on the fleet faces — chronic growth (`incremental
/// sessions unbounded`) surfaces BEFORE the `Global stream limit reached`
/// wall, not at it. Single source: doctor reads it directly, the GUI reads
/// the self-reported overview field
pub const HEADROOM_WARN_RATIO: f64 = 0.2;

/// A frame-level stream rejection: the wire reason code plus the
/// hub-internal diagnostic.
///
/// Constructing a rejection picks its [`CloseReason`] at the source — the
/// former string→code matching layer (`close_reason_of`) is gone, so a new
/// rejection site cannot silently fall into the ordinary-close fallback.
/// The diagnostic never rides the wire (logs / metrics attribution only).
#[derive(Debug, Clone)]
pub struct StreamReject {
    /// The Close reason code delivered to the sender.
    pub code: CloseReason,
    /// The hub-internal diagnostic text.
    pub diagnostic: &'static str,
}

impl StreamReject {
    /// Builds a rejection from its parts.
    pub(crate) const fn new(code: CloseReason, diagnostic: &'static str) -> Self {
        Self { code, diagnostic }
    }
}

/// Frame direction (determined at the wire layer by `FLAG_RESPONSE`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Direction {
    /// Request direction (initiated by ingress → target agent).
    Request,
    /// Response direction (egress return path → source agent).
    Response,
}

impl Direction {
    /// Direction label (for logs / auditing).
    pub(crate) const fn label(self) -> &'static str {
        match self {
            Self::Request => "request",
            Self::Response => "response",
        }
    }
}

pub(crate) fn valid_agent_id(s: &str) -> bool {
    // The historical `_`-prefix ban was a guard for the deleted wire-layer
    // sentinel strings (`_response_` etc., retired with the flags-carried
    // origin rework) — the rationale is gone, so the allowlist is uniform.
    s.len() <= MAX_AGENT_ID_LEN
        && !s.is_empty()
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_' || b == b'.')
}

/// Qualifies a wire-level Open target: `"{tenant}/{agent}"` passes through
/// (validated), a bare id resolves into the source's own tenant.
/// `None` when the qualified form is malformed.
pub(crate) fn qualify_target(target: &str, source_tenant: &str) -> String {
    if target.contains('/') {
        target.to_string()
    } else {
        format!("{source_tenant}/{target}")
    }
}

/// Validates a qualified agent key `"{tenant}/{agent}"`: both parts
/// well-formed, the tenant part may carry the internal `_` prefix (the edge
/// gateway principal).
pub(crate) fn valid_qualified_agent(s: &str) -> bool {
    match s.split_once('/') {
        Some((tenant, agent)) => {
            !tenant.is_empty()
                && tenant.len() <= 64
                && tenant
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
                && valid_agent_id(agent)
        }
        None => false,
    }
}

/// The tenant isolation policy (RFC §4 evaluation order), shared by the h2
/// upload path (`frame_open`) and the QUIC relay open path:
/// 1. source is a trusted gateway → allow (the expose edge's principal is
///    the only legitimate cross-tenant opener)
/// 2. same tenant → allow
/// 3. explicit cross-tenant `[[acl.rules]]` exception → allow
/// 4. otherwise deny
pub(crate) async fn tenant_policy_allows(
    tls_plane: &crate::hub::state::SharedTlsPlane,
    config: &crate::hub::state::SharedHubConfig,
    source_qualified: &str,
    qualified_target: &str,
) -> bool {
    let Some((source_tenant, source_bare)) = PeerIdentity::split_qualified(source_qualified) else {
        return false;
    };
    let Some((target_tenant, target_bare)) = PeerIdentity::split_qualified(qualified_target) else {
        return false;
    };
    // Gateway status comes from the TLS plane's trust table (the same
    // generation the source connection was authenticated against).
    let gateway = {
        let plane = tls_plane
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone();
        plane.verifier.is_gateway_tenant(source_tenant)
    };
    if gateway || source_tenant == target_tenant {
        return true;
    }
    let config = config.read().await;
    config
        .acl
        .allows(source_tenant, source_bare, target_tenant, target_bare)
}

/// Verdict of the shared stream-admission gate.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum StreamAdmission {
    /// Policy and caps satisfied; the per-agent slot is acquired.
    Admitted,
    /// Tenant isolation policy denied the Open.
    TenantDenied,
    /// The global active-stream cap is exhausted.
    GlobalStreamLimit,
    /// The per-agent active-stream cap is exhausted.
    PerAgentStreamLimit,
}

/// The single stream-admission gate shared by the h2 upload path
/// ([`HubService::frame_open`]) and the QUIC relay open path: tenant
/// isolation policy + global/per-agent stream caps, with metrics and audit.
///
/// `peer` carries the connection's remote address on the h2 plane; the QUIC
/// plane currently reports `None` — an explicit, visible difference rather
/// than a hidden one.
pub(crate) async fn admit_stream(
    hub: &crate::hub::state::HubState,
    stream_id: StreamId,
    source_circuit: &CircuitToken,
    source_agent: &str,
    qualified_target: &str,
    peer: Option<&str>,
) -> StreamAdmission {
    if !tenant_policy_allows(&hub.tls_plane, &hub.config, source_agent, qualified_target).await {
        metrics::counter!("interflow_hub_acl_denied").increment(1);
        hub.audit.record(
            AuditKind::StreamDenied {
                stream_id: stream_id.to_string(),
                source_circuit: source_circuit.to_hex(),
                source_ip: None,
                reason: "tenant_denied".to_string(),
            },
            Some(source_circuit.to_hex()),
            peer.map(str::to_string),
        );
        return StreamAdmission::TenantDenied;
    }

    // Stream count caps (defend against DDoS / a compromised agent flooding
    // stream opens). Read from atomics to avoid taking the config RwLock
    // read lock on every Open.
    let max_per_agent = hub
        .limits
        .max_streams_per_agent
        .load(std::sync::atomic::Ordering::Relaxed);
    let max_total = hub
        .limits
        .max_streams_total
        .load(std::sync::atomic::Ordering::Relaxed);
    if max_total > 0 && hub.active_streams.total() >= max_total {
        metrics::counter!("interflow_hub_stream_limit_denied", "scope" => "total").increment(1);
        hub.audit.record(
            AuditKind::StreamDenied {
                stream_id: stream_id.to_string(),
                source_circuit: source_circuit.to_hex(),
                source_ip: None,
                reason: "global_stream_limit".into(),
            },
            Some(source_circuit.to_hex()),
            peer.map(str::to_string),
        );
        return StreamAdmission::GlobalStreamLimit;
    }
    if max_per_agent > 0
        && !crate::hub::state::try_acquire_stream_slot(
            &hub.stream_counts,
            source_agent,
            max_per_agent,
        )
    {
        metrics::counter!("interflow_hub_stream_limit_denied", "scope" => "per_agent").increment(1);
        hub.audit.record(
            AuditKind::StreamDenied {
                stream_id: stream_id.to_string(),
                source_circuit: source_circuit.to_hex(),
                source_ip: None,
                reason: "per_agent_stream_limit".into(),
            },
            Some(source_circuit.to_hex()),
            peer.map(str::to_string),
        );
        return StreamAdmission::PerAgentStreamLimit;
    }
    StreamAdmission::Admitted
}

/// Issues a source-session-scoped opaque route lease after the control-plane
/// target has been qualified and authorized. Route issuance is only a cache
/// optimization: every Open re-runs the same policy gate.
pub(crate) async fn issue_route(
    hub: &crate::hub::state::HubState,
    source_agent: &str,
    source_circuit: CircuitToken,
    target: &str,
) -> std::result::Result<RouteToken, &'static str> {
    let Some((source_tenant, _)) = PeerIdentity::split_qualified(source_agent) else {
        return Err("Invalid source identity");
    };
    let qualified_target = qualify_target(target, source_tenant);
    if !valid_qualified_agent(&qualified_target) {
        return Err("Invalid route target");
    }
    if !tenant_policy_allows(&hub.tls_plane, &hub.config, source_agent, &qualified_target).await {
        metrics::counter!("interflow_hub_acl_denied").increment(1);
        hub.audit.record(
            AuditKind::StreamDenied {
                stream_id: String::new(),
                source_circuit: source_circuit.to_hex(),
                source_ip: None,
                reason: "route_denied".to_string(),
            },
            Some(source_circuit.to_hex()),
            None,
        );
        return Err("Access denied by tenant policy");
    }
    let route = RouteToken::random().map_err(|_| "Route token unavailable")?;
    let session_arc = {
        let agents = hub.agents.read().await;
        agents.get(source_agent).cloned()
    };
    let Some(session_arc) = session_arc else {
        return Err("Source circuit not registered");
    };
    let session = session_arc.write().await;
    if session.circuit != source_circuit {
        return Err("Source circuit not registered");
    }
    drop(session);
    hub.route_leases.write().await.insert(
        route,
        (
            source_circuit,
            source_agent.to_string(),
            qualified_target.clone(),
        ),
    );
    Ok(route)
}

/// Resolution result of frame-level Data dispatch.
enum DataRoute {
    /// Normal route: recipient (for the re-registration fallback), frame
    /// origin, flags, the delivery sender and which plane it belongs to.
    Deliver {
        recipient: Arc<str>,
        origin: FrameOrigin,
        flags: u8,
        sink: mpsc::Sender<TunnelData>,
        relay_plane: bool,
    },
    /// Sender owns neither end of the stream (forged/late frame): drop.
    Forged,
    /// Stream does not exist: notify the sender, then drop.
    Missing,
}

/// Data-plane relay core, owned by [`HubState`]: every transport face (the
/// h2 upload reader, the QUIC relay loops, benches) drives the same frame
/// routing through these methods — the per-connection service object only
/// carries handshake context (identity, circuit, effective IP).
impl HubState {
    /// Looks up the `mpsc::Sender` of the given agent — the flat
    /// [`HubState::data_tx`] projection (one std read lock; the registry's
    /// two-level hop is a control-plane concern, never a per-frame one).
    pub fn lookup_tx(&self, agent_id: &str) -> Option<mpsc::Sender<TunnelData>> {
        self.data_tx(agent_id)
    }

    /// The agent's session sender for a poll-plane [`StreamFace`] at Open
    /// time. An agent that is not (yet) registered gets a sealed dummy
    /// channel: such an Open is rolled back by its failed notification
    /// moments later, and any stray frame in the window resolves
    /// Closed → flat-table miss → NoTarget (fail closed, never silent).
    pub(crate) fn poll_sender(&self, agent_id: &str) -> mpsc::Sender<TunnelData> {
        self.data_tx(agent_id).unwrap_or_else(|| {
            let (tx, rx) = mpsc::channel(1);
            drop(rx); // sealed: every send fails closed immediately
            tx
        })
    }

    /// Removes by agent_id (entry point for runtime death signals such as
    /// send timeout): resolves the registry entry to an armed
    /// [`SessionWitness`] and hands it to the unified removal funnel. The
    /// credential is armed at fire time, at the point of resolution — sound
    /// here because the signal (a send already observed stalled on this very
    /// entry) travels with the resolution itself; a re-registration between
    /// arming and the funnel's check still voids the removal.
    pub async fn evict_agent_by_id(&self, agent_id: &str, reason: &'static str) {
        let session = {
            let agents = self.agents.read().await;
            agents.get(agent_id).cloned()
        };
        if let Some(session) = session {
            let circuit = session.read().await.circuit;
            crate::hub::heartbeat::remove_agent_if_current(
                self,
                agent_id,
                SessionWitness { session, circuit },
                reason,
            )
            .await;
        }
    }

    /// Frame-level Data handling. Direction is given by [`Direction`]
    /// (determined at the frame layer via `FLAG_RESPONSE`);
    /// authorization: request direction must be the stream's source,
    /// response direction must be the stream's target.
    ///
    /// `Err(reject)` = dispatch failed (the caller informs the sender that
    /// the stream is unusable); stream-not-found / forged frames are handled
    /// per the existing convention (notify or drop) and return `Ok` — a
    /// single anomalous frame does not tear down the upload.
    pub async fn frame_data(
        &self,
        agent_id: &str,
        circuit: CircuitToken,
        stream_id: StreamId,
        direction: Direction,
        data: Bytes,
    ) -> std::result::Result<(), StreamReject> {
        trace!(
            "Data frame received: stream_id={}, source={circuit}",
            stream_id
        );

        // Look up the stream info to determine the receiving agent (also
        // taking the stream protocol and dispatch plane: a quic peer goes
        // through the relay channel, an h2 peer through poll). Loopback
        // (source == target) converges naturally: both directions'
        // recipient/frame-source conclusions match the explicit branches.
        // One shard read resolves the whole route (owner check, recipient,
        // delivery sender — both plane kinds carry their sender in the
        // entry since the §2.2 restructure).
        let route = self.active_streams.with(&stream_id, |stream| match stream {
            None => DataRoute::Missing,
            Some(stream) => {
                let forged = match direction {
                    Direction::Response => stream.target_circuit != circuit,
                    Direction::Request => stream.source_circuit != circuit,
                };
                if forged {
                    error!(
                        "Forgery check: {}-direction frame does not match the stream owner",
                        direction.label()
                    );
                    DataRoute::Forged
                } else if direction == Direction::Response {
                    trace!("Route direction: response path");
                    DataRoute::Deliver {
                        recipient: Arc::clone(&stream.source_agent),
                        origin: FrameOrigin::Response,
                        // UDP/E2E only ride Open; relaying Data with
                        // the stream's proto bits would violate the
                        // contract and kill the receiving decode.
                        flags: FLAG_RESPONSE,
                        sink: stream.source.sender().clone(),
                        relay_plane: stream.source.is_relay(),
                    }
                } else {
                    trace!("Route direction: request path");
                    DataRoute::Deliver {
                        recipient: Arc::clone(&stream.target_agent),
                        origin: FrameOrigin::Agent(circuit),
                        flags: 0,
                        sink: stream.target.sender().clone(),
                        relay_plane: stream.target.is_relay(),
                    }
                }
            }
        });

        let (recipient, origin, frame_flags, sink, relay_plane) = match route {
            DataRoute::Deliver {
                recipient,
                origin,
                flags,
                sink,
                relay_plane,
            } => (recipient, origin, flags, sink, relay_plane),
            DataRoute::Missing => {
                // Stream does not exist (late frame / already swept): notify
                // the sender so it disconnects the local connection
                metrics::counter!("interflow_hub_frames_dropped", "reason" => "no_route")
                    .increment(1);
                self.notify_sender_close(
                    agent_id,
                    stream_id,
                    &StreamReject::new(CloseReason::NoTarget, "Stream not found"),
                )
                .await;
                return Ok(());
            }
            DataRoute::Forged => {
                metrics::counter!("interflow_hub_frames_dropped", "reason" => "forged")
                    .increment(1);
                return Ok(());
            }
        };

        trace!("Data received: {} bytes", data.len());
        metrics::counter!("interflow_hub_bytes_rx").increment(data.len() as u64);
        metrics::counter!("interflow_hub_frames_rx", "type" => "data").increment(1);

        let data_frame = TunnelData {
            stream_id,
            origin,
            stream_type: FrameType::Data,
            flags: frame_flags,
            data,
        };

        // Execute send().await outside the shard lock, with a timeout: when
        // an agent dies and the channel (capacity 256) fills, an un-timed
        // send would hang forever, pinning hub connections and memory, with
        // upstream only able to wait for nginx to time out with a 502 (the
        // second root cause of the 2026-09-11 incident).
        //
        // Both planes carry their sender in the stream entry since the
        // §2.2 restructure; the planes differ in failure semantics:
        // - relay plane (QUIC peer): a Closed sink is the relay writer
        //   gone (the stream is being torn down) — fail the frame, no
        //   fallback; a timeout is the peer's disconnect watcher's
        //   business;
        // - poll plane (h2 peer): a Closed sink is an in-place
        //   re-registration having replaced the channels — re-resolve ONCE
        //   from the flat data_tx projection (the old receiver is dropped
        //   synchronously at replacement, so a stale sender always
        //   presents as Closed, never as silent loss); a timeout means no
        //   consumer has drained the channel — evict.
        let send_timeout = Duration::from_secs(
            self.limits
                .channel_send_timeout_secs
                .load(Ordering::Relaxed),
        );
        match tokio::time::timeout(send_timeout, sink.send(data_frame)).await {
            Ok(Ok(())) => {
                if relay_plane {
                    trace!("Data relayed over QUIC");
                } else {
                    trace!("Data sent to receiving endpoint");
                }
                Ok(())
            }
            Ok(Err(send_err)) if !relay_plane => {
                // Poll-plane stale sender: one flat-table re-resolution
                // (the failed send hands the frame back).
                if let Some(tx) = self.data_tx(&recipient) {
                    match tokio::time::timeout(send_timeout, tx.send(send_err.0)).await {
                        Ok(Ok(())) => {
                            trace!("Data sent to re-resolved endpoint channel");
                            Ok(())
                        }
                        Ok(Err(e)) => {
                            error!("Failed to send data (channel closed): {e}");
                            Err(StreamReject::new(
                                CloseReason::BackendClosed,
                                "Target agent channel closed",
                            ))
                        }
                        Err(_) => {
                            error!(
                                "Send data timed out (>{send_timeout:?}): channel has no consumer, evicting the endpoint"
                            );
                            self.evict_agent_by_id(&recipient, "send_timeout").await;
                            Err(StreamReject::new(
                                CloseReason::DispatchPoison,
                                "Target agent stalled",
                            ))
                        }
                    }
                } else {
                    error!("Receiving endpoint has no data channel");
                    Err(StreamReject::new(
                        CloseReason::NoTarget,
                        "Target agent not registered",
                    ))
                }
            }
            Ok(Err(_)) => {
                error!("QUIC relay channel closed");
                Err(StreamReject::new(
                    CloseReason::BackendClosed,
                    "Target agent channel closed",
                ))
            }
            Err(_) if relay_plane => {
                error!("QUIC relay send timed out (>{send_timeout:?})");
                Err(StreamReject::new(
                    CloseReason::DispatchPoison,
                    "Target agent stalled",
                ))
            }
            Err(_) => {
                // Poll-plane timeout: the receiving end has had no consumer
                // for a long time; declare it dead — evict (closing the
                // channel immediately unblocks the remaining blocked
                // senders) so subsequent requests take the fast-fail
                // "agent does not exist" path.
                error!(
                    "Send data timed out (>{send_timeout:?}): channel has no consumer, evicting the endpoint"
                );
                self.evict_agent_by_id(&recipient, "send_timeout").await;
                Err(StreamReject::new(
                    CloseReason::DispatchPoison,
                    "Target agent stalled",
                ))
            }
        }
    }

    /// Sends a hub-origin Close rejection notification back to `agent_id`
    /// via the **control channel** (guaranteed delivery).
    ///
    /// The wire payload is the single u8 reason code from
    /// [`StreamReject::code`]; the reject's diagnostic stays in logs and
    /// metrics. The pump side tears down the stream via the existing Close
    /// path.
    ///
    /// Before 2026-09-14 this function used `try_send` into the data
    /// channel: a full channel meant a **silent drop**, the egress
    /// forwarder never saw a Close, and the backend fd lingered for the
    /// whole session (EMFILE,
    /// (internal design notes)). The drop
    /// was harmless to stream state (the hub side had already torn the
    /// stream down) but harmful to the peer's fd — after control/data plane
    /// separation, "delivery while online".
    ///
    /// All call sites of this function (open rejection / forgery / late
    /// frames) carry "termination first" semantics; the only FIFO-sensitive
    /// case, a normal response-direction close, does not go through this
    /// function (see `frame_close`).
    pub async fn notify_sender_close(
        &self,
        agent_id: &str,
        stream_id: StreamId,
        reject: &StreamReject,
    ) {
        debug!(
            "close notification: stream_id={stream_id}, code={}, diagnostic={}",
            reject.code, reject.diagnostic
        );
        let _ = crate::hub::control::deliver_close_via_control(
            &self.agents,
            agent_id,
            stream_id,
            reject.code.clone(),
        )
        .await;
    }
}

impl HubService {
    /// Data-plane relay core lives on [`HubState`] (shared by every
    /// transport face); the service delegates with its connection context.
    pub(crate) async fn frame_data(
        &self,
        agent_id: &str,
        circuit: CircuitToken,
        stream_id: StreamId,
        direction: Direction,
        data: Bytes,
    ) -> std::result::Result<(), StreamReject> {
        self.state
            .frame_data(agent_id, circuit, stream_id, direction, data)
            .await
    }

    /// [`HubState::notify_sender_close`] delegate (upload reader call
    /// sites).
    pub(crate) async fn notify_sender_close(
        &self,
        agent_id: &str,
        stream_id: StreamId,
        reject: &StreamReject,
    ) {
        self.state
            .notify_sender_close(agent_id, stream_id, reject)
            .await;
    }

    /// Frame-level Open handling (called by the `/stream/up` reader;
    /// metadata comes from the wire frame rather than HTTP headers).
    ///
    /// `Err(reject)` = rejected (ACL / stream limits / target unreachable;
    /// metrics and audit already recorded); the caller informs the sender
    /// via a hub-origin Close notification on poll. `Ok(())` = stream
    /// established (or an empty target does not count as an active stream —
    /// the count is rolled back per existing semantics).
    #[allow(clippy::too_many_lines)]
    pub(crate) async fn frame_open(
        &self,
        source_state: &tokio::sync::RwLock<crate::hub::state::AgentSession>,
        source_agent: &str,
        source_circuit: CircuitToken,
        stream_id: StreamId,
        route: RouteToken,
        proto: StreamProto,
        e2e: bool,
    ) -> std::result::Result<(), StreamReject> {
        // Tenant isolation policy (RFC §4). Both endpoints arrive
        // tenant-qualified (`"{tenant}/{agent}"`); a bare target is
        // qualified with the source's own tenant (same-tenant shorthand on
        // the wire — agents do not know their tenant, and the default is
        // intra-tenant anyway).
        let Some((_source_tenant, _source_bare)) = PeerIdentity::split_qualified(source_agent)
        else {
            return Err(StreamReject::new(
                CloseReason::SecurityDenied,
                "Invalid source identity",
            ));
        };
        let qualified_target = {
            let session = source_state.read().await;
            if session.circuit != source_circuit {
                return Err(StreamReject::new(
                    CloseReason::SecurityDenied,
                    "Source circuit not registered",
                ));
            }
            drop(session);
            self.state.route_leases.read().await.get(&route).cloned()
        }
        .ok_or_else(|| StreamReject::new(CloseReason::NoTarget, "Unknown route token"))?;
        let qualified_target = match qualified_target {
            lease if lease.1 == source_agent => lease.2,
            _ => {
                return Err(StreamReject::new(
                    CloseReason::NoTarget,
                    "Unknown route token",
                ));
            }
        };

        match admit_stream(
            &self.state,
            stream_id,
            &source_circuit,
            source_agent,
            &qualified_target,
            Some(&self.peer_str()),
        )
        .await
        {
            StreamAdmission::Admitted => {}
            StreamAdmission::TenantDenied => {
                return Err(StreamReject::new(
                    CloseReason::SecurityDenied,
                    "Access denied by tenant policy",
                ));
            }
            StreamAdmission::GlobalStreamLimit => {
                return Err(StreamReject::new(
                    CloseReason::LocalLimit,
                    "Global stream limit reached",
                ));
            }
            StreamAdmission::PerAgentStreamLimit => {
                return Err(StreamReject::new(
                    CloseReason::LocalLimit,
                    "Per-agent stream limit reached",
                ));
            }
        }
        let target_agent = qualified_target.as_str();

        debug!(
            "Stream opened: stream_id={} (opaque data-plane identifiers only)",
            stream_id,
        );

        // An empty target never reaches this point on the h2 plane: the
        // upload payload gate (`hub/upload.rs`, `valid_agent_id` refuses the
        // empty string) rejects it with "invalid open payload" before
        // `frame_open` is called. The QUIC plane rejects empty targets at
        // the tenant-policy gate instead (no form validation there — a known
        // plane asymmetry). Both gates are pinned by
        // `tests/e2e_open_target_contract.rs`. A historical empty-target
        // no-op branch here was dead code from the pre-streaming-upload
        // architecture and has been removed.

        // Store the active stream (under lock). When the target is a quic
        // agent, first establish a relay stream to obtain the dispatch plane
        // (the h2 source → quic target interop path); h2 targets keep poll
        // channel notifications.
        // quic target: open a relay stream (failure rolls back like a
        // notification failure, same discipline as the poll path)
        let (target_sink, target_circuit) = {
            let target_state = {
                let agents = self.state.agents.read().await;
                agents.get(target_agent).cloned()
            };
            match target_state {
                Some(state) => {
                    let (quic_conn, target_circuit) = {
                        let session = state.read().await;
                        (session.quic.clone(), session.circuit)
                    };
                    match quic_conn {
                        Some(qc) => crate::hub::quic::open_relay_stream(
                            &self.state.clone(),
                            &qc,
                            stream_id,
                            source_circuit,
                            target_circuit,
                            proto,
                            e2e,
                        )
                        .await
                        .inspect(|_tx| {
                            debug!("QUIC relay established: stream_id={stream_id}");
                        })
                        .map_or((None, target_circuit), |tx| (Some(tx), target_circuit)),
                        None => (None, target_circuit), // h2 target: goes via poll
                    }
                }
                None => (
                    None,
                    CircuitToken::random().map_err(|_| {
                        StreamReject::new(CloseReason::CloseFrame, "Circuit token unavailable")
                    })?,
                ),
            }
        };

        // DATAGRAM eligibility (an h2 source only looks at the target side):
        // UDP stream + target capability + hub toggle
        let target_face = target_sink.map_or_else(
            || StreamFace::Poll(self.state.poll_sender(target_agent)),
            StreamFace::Relay,
        );
        let datagram_ok = matches!(proto, StreamProto::Udp)
            && target_face.is_relay()
            && self.state.limits.datagram_enabled.load(Ordering::Relaxed);
        let stream = crate::hub::ActiveStream {
            source_agent: Arc::from(source_agent),
            target_agent: Arc::from(target_agent),
            source_circuit,
            target_circuit,
            proto,
            target: target_face.clone(),
            // h2 source: return path goes via the source's own session channel
            source: StreamFace::Poll(self.state.poll_sender(source_agent)),
            datagram_ok,
        };
        self.state.active_streams.insert(stream_id, stream);
        metrics::gauge!("interflow_hub_streams_active").increment(1.0);
        metrics::counter!("interflow_hub_streams_total", "direction" => "request").increment(1);
        self.state.audit.record(
            AuditKind::StreamOpened {
                stream_id: stream_id.to_string(),
                source_circuit: source_circuit.to_hex(),
                route: route.to_hex(),
            },
            Some(source_circuit.to_hex()),
            Some(self.peer_str()),
        );

        // Notify the target agent (outside the lock). Failure must propagate:
        // roll back the inserted stream state so the sender fails fast via
        // the Close notification. Never allow "stream opened but the peer
        // doesn't know" — that leaves half the stream state alive in a black
        // hole, permanently occupying slots (one of the root causes of the
        // 2026-09-11 incident).
        // quic targets were already notified via the relay stream Open
        // (open_relay_stream writes the Open frame internally)
        //
        // Open goes through the **control channel** (2026-09-14 channel
        // separation): same-channel FIFO with a subsequent Close
        // notification of the same stream (the poll pump's control priority
        // does not reorder Open/Close of the same stream), and it is no
        // longer constrained by data channel capacity — during bursty stream
        // establishment, Open notifications are not delayed or dropped by
        // data backlog.
        let notify_result: std::result::Result<(), StreamReject> = if target_face.is_relay() {
            Ok(())
        } else {
            // The requester's circuit rides the header field (the former
            // `_open_` sentinel + payload hex are gone), payload empty.
            let frame = TunnelData {
                stream_id,
                origin: FrameOrigin::Agent(source_circuit),
                stream_type: FrameType::Open,
                // The hub rebuilds Open flags from the stream proto — the
                // e2e declaration must be carried through explicitly or it
                // would be silently stripped (the downgrade attack
                // e2e-required peers exist to reject).
                flags: proto.as_flag() | (u8::from(e2e) * FLAG_E2E),
                data: Bytes::new(),
            };
            if crate::hub::control::deliver_control(&self.state.agents, target_agent, frame).await {
                debug!("Notified target of stream open: stream_id={stream_id}");
                Ok(())
            } else {
                // Not registered / a QUIC session (the poll plane is
                // ineffective for it) / session already ended
                error!("Failed to send Open notification: stream_id={stream_id}");
                Err(StreamReject::new(
                    CloseReason::NoTarget,
                    "Target agent not registered",
                ))
            }
        };

        if let Err(reason) = notify_result {
            // Roll back the just-inserted active stream + release the stream
            // slot + correct metrics/audit
            if self.state.active_streams.remove(&stream_id).is_some() {
                metrics::gauge!("interflow_hub_streams_active").decrement(1.0);
            }
            release_stream_slot(&self.state.stream_counts, source_agent);
            self.state.audit.record(
                AuditKind::StreamClosed {
                    stream_id: stream_id.to_string(),
                    source_circuit: source_circuit.to_hex(),
                },
                Some(source_circuit.to_hex()),
                None,
            );
            return Err(reason);
        }

        Ok(())
    }

    /// Frame-level Close handling: notify the peer, remove the active
    /// stream, release the slot. `reason` (from the agent's Close payload)
    /// is forwarded to the peer's Close notification so the far end can
    /// react to backend failures (edge route-level negative caching,
    /// 2026-09-16).
    pub(crate) async fn frame_close(
        &self,
        _agent_id: &str,
        circuit: CircuitToken,
        stream_id: StreamId,
        direction: Direction,
        reason: &CloseReason,
    ) {
        debug!("Stream closed: stream_id={stream_id}, reason={reason}");

        // Look up the stream info and decide which peer to notify
        // (directional authorization: request direction must be the source,
        // response direction must be the target — otherwise drop as forgery)
        let Some((notify_agent, owner_agent)) =
            self.state.active_streams.with(&stream_id, |stream| {
                let stream = stream?;
                let authorized = match direction {
                    Direction::Response => stream.target_circuit == circuit,
                    Direction::Request => stream.source_circuit == circuit,
                };
                if !authorized {
                    warn!(
                        "Forgery check: Close frame does not own either end of stream {stream_id}"
                    );
                    return None;
                }
                let notify = if direction == Direction::Response {
                    Arc::clone(&stream.source_agent)
                } else {
                    Arc::clone(&stream.target_agent)
                };
                Some((notify, Arc::clone(&stream.source_agent)))
            })
        else {
            return;
        };

        // Remove the active stream + decrement the count together
        // (prevents drift)
        if self.state.active_streams.remove(&stream_id).is_some() {
            metrics::gauge!("interflow_hub_streams_active").decrement(1.0);
            release_stream_slot(&self.state.stream_counts, &owner_agent);
            self.state.audit.record(
                AuditKind::StreamClosed {
                    stream_id: stream_id.to_string(),
                    source_circuit: circuit.to_hex(),
                },
                Some(circuit.to_hex()),
                None,
            );
        }

        // Notify the peer agent that the stream is closed (dispatched by
        // direction, 2026-09-14 channel separation):
        // - response direction (egress closed the backend): data-channel FIFO
        //   first — queued response tail bytes are still deliverable to the
        //   visitor, and the Close queues after them; only on a stall timeout
        //   does it fall back to the control channel;
        // - request direction (source closed the stream): guaranteed delivery
        //   directly via the control channel — the source end is dead,
        //   queued request tail data is meaningless, and releasing the
        //   peer's fd takes priority (overtaking queued data is the correct
        //   semantic here).
        if direction == Direction::Response {
            crate::hub::control::deliver_response_close(
                &self.state.agents,
                &notify_agent,
                stream_id,
                reason.clone(),
            )
            .await;
        } else {
            crate::hub::control::deliver_close_via_control(
                &self.state.agents,
                &notify_agent,
                stream_id,
                reason.clone(),
            )
            .await;
        }
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
    use crate::hub::state::SharedStreamCounts;
    use crate::hub::state::try_acquire_stream_slot;
    use std::collections::HashMap;
    use std::sync::Arc;

    #[test]
    fn agent_id_validation_allows_dot() {
        assert!(valid_agent_id("agent-1.local"));
        assert!(!valid_agent_id("agent 1"));
    }

    #[test]
    fn agent_id_validation_allows_leading_underscore() {
        // The wire-layer sentinel strings are gone (flags-carried origin);
        // no reservation keeps the `_` prefix out of the agent namespace.
        assert!(valid_agent_id("_internal"));
    }

    fn make_counts() -> SharedStreamCounts {
        Arc::new(std::sync::Mutex::new(HashMap::new()))
    }

    #[test]
    fn stream_slot_acquires_until_max_then_rejects() {
        let counts = make_counts();
        assert!(try_acquire_stream_slot(&counts, "a1", 3));
        assert!(try_acquire_stream_slot(&counts, "a1", 3));
        assert!(try_acquire_stream_slot(&counts, "a1", 3));
        assert!(
            !try_acquire_stream_slot(&counts, "a1", 3),
            "4th acquire over cap must fail"
        );
    }

    #[test]
    fn stream_slot_release_allows_reacquire() {
        let counts = make_counts();
        try_acquire_stream_slot(&counts, "a1", 2);
        try_acquire_stream_slot(&counts, "a1", 2);
        assert!(!try_acquire_stream_slot(&counts, "a1", 2));
        release_stream_slot(&counts, "a1");
        assert!(
            try_acquire_stream_slot(&counts, "a1", 2),
            "after release, slot should be available"
        );
    }

    #[test]
    fn stream_slot_per_agent_isolation() {
        let counts = make_counts();
        try_acquire_stream_slot(&counts, "a1", 1);
        assert!(
            try_acquire_stream_slot(&counts, "a2", 1),
            "different agent has independent budget"
        );
        assert!(!try_acquire_stream_slot(&counts, "a1", 1));
    }

    #[test]
    fn stream_slot_release_removes_zero_entry() {
        let counts = make_counts();
        try_acquire_stream_slot(&counts, "a1", 5);
        release_stream_slot(&counts, "a1");
        assert!(
            counts.lock().unwrap().get("a1").is_none(),
            "counter entry should be removed at zero to prevent map growth"
        );
    }

    #[test]
    fn stream_slot_zero_max_means_unlimited() {
        let counts = make_counts();
        for _ in 0..1000 {
            assert!(try_acquire_stream_slot(&counts, "a1", 0));
        }
    }

    /// §2.2 data-plane restructure: a poll face whose captured sender went
    /// stale (an in-place re-registration replaced the session channels)
    /// must deliver via ONE flat-table re-resolution — the old receiver is
    /// dropped at replacement, so the stale sender presents as Closed, and
    /// the current session's channel receives the frame.
    #[tokio::test]
    async fn poll_face_stale_sender_falls_back_to_current_session() {
        use crate::hub::state::{ActiveStream, StreamFace};
        use interflow_core::protocol::StreamProto;
        let dir = tempfile::tempdir().unwrap();
        let state = crate::hub::test_support::test_state(dir.path());

        let source = "test/src".to_owned();
        let target = "test/dst".to_owned();
        let identity = crate::hub::state::PeerIdentity {
            tenant: std::sync::Arc::from("test"),
            agent: "dst".to_owned(),
            trusted_gateway: false,
            leaf_validity_unix: None,
            leaf_serial_hex: None,
        };
        let circuit =
            interflow_core::protocol::CircuitToken::from_hex("12078a05e14f4e2c99b1679be1df7c31")
                .unwrap();
        state
            .register_agent(&identity, circuit, None, None, "bench")
            .await
            .unwrap();

        // The stream's poll face captured a sender whose receiver is gone
        // (the re-registration shape: install_channels replaces channels in
        // place, dropping the old receiver synchronously).
        let (stale_tx, stale_rx) = tokio::sync::mpsc::channel(256);
        drop(stale_rx);
        let stream_id =
            interflow_core::protocol::StreamId::from_hex("12078a05e14f4e2c99b1679be1df7c31")
                .unwrap();
        state.active_streams.insert(
            stream_id,
            ActiveStream {
                source_agent: std::sync::Arc::from(source.as_str()),
                target_agent: std::sync::Arc::from(target.as_str()),
                source_circuit: circuit,
                target_circuit: circuit,
                proto: StreamProto::Tcp,
                target: StreamFace::Poll(stale_tx),
                source: StreamFace::Poll(state.data_tx(&source).unwrap_or_else(|| {
                    let (tx, rx) = tokio::sync::mpsc::channel(1);
                    drop(rx);
                    tx
                })),
                datagram_ok: false,
            },
        );

        // The current session's receiver (the poll consumer's shape).
        let mut current_rx = {
            let agents = state.agents.read().await;
            let session = agents.get(&target).cloned().unwrap();
            drop(agents);
            let mut guard = session.write().await;
            guard.rx.take().unwrap()
        };

        state
            .frame_data(
                &source,
                circuit,
                stream_id,
                Direction::Request,
                bytes::Bytes::from_static(b"payload"),
            )
            .await
            .unwrap();

        let frame = tokio::time::timeout(std::time::Duration::from_secs(2), current_rx.recv())
            .await
            .expect("fallback delivery within timeout")
            .expect("frame delivered via the re-resolved session channel");
        assert_eq!(frame.data.as_ref(), b"payload");
    }

    /// The sharded table's cross-shard behavior: entries spread across
    /// shards route, sweep and count correctly (the sweep paths iterate
    /// every shard).
    #[tokio::test]
    async fn sharded_streams_sweep_across_shards() {
        use crate::hub::state::{ActiveStream, StreamFace};
        use interflow_core::protocol::StreamProto;
        let dir = tempfile::tempdir().unwrap();
        let state = crate::hub::test_support::test_state(dir.path());

        let (tx, rx) = tokio::sync::mpsc::channel(1);
        drop(rx);
        let face = StreamFace::Poll(tx);
        let circuit =
            interflow_core::protocol::CircuitToken::from_hex("12078a05e14f4e2c99b1679be1df7c31")
                .unwrap();
        // 64 distinct ids hash across all 16 shards with certainty.
        for i in 0..64u64 {
            let id =
                interflow_core::protocol::StreamId::from_hex(&format!("{:032x}", i + 1)).unwrap();
            state.active_streams.insert(
                id,
                ActiveStream {
                    source_agent: std::sync::Arc::from("test/src"),
                    target_agent: std::sync::Arc::from("test/dst"),
                    source_circuit: circuit,
                    target_circuit: circuit,
                    proto: StreamProto::Tcp,
                    target: face.clone(),
                    source: face.clone(),
                    datagram_ok: false,
                },
            );
        }
        assert_eq!(state.active_streams.total(), 64);

        // Sweep one agent's streams: every shard's retain runs.
        super::HubService::sweep_agent_streams(
            &state.agents,
            &state.active_streams,
            &state.stream_counts,
            "test/src",
        )
        .await;
        assert_eq!(
            state.active_streams.total(),
            0,
            "sweep must reach entries in every shard"
        );
    }
}
