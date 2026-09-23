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

use crate::config::AclRule;
use crate::hub::service::HubService;
use crate::hub::state::{PeerIdentity, StreamFace, TunnelData, release_stream_slot};
use bytes::Bytes;
use interflow_core::protocol::{
    CircuitToken, CloseReason, FLAG_E2E, FLAG_RESPONSE, FrameOrigin, FrameType, RouteToken,
    StreamId, StreamProto,
};
use interflow_core::security::AuditKind;
use std::sync::atomic::Ordering;
use std::time::Duration;
use tokio::sync::mpsc;
use tracing::{debug, error, warn};

/// Maximum agent_id length (128B), character allowlist `[A-Za-z0-9_.-]`.
pub(crate) const MAX_AGENT_ID_LEN: usize = 128;

/// Frame direction (determined at the wire layer by `FLAG_RESPONSE`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Direction {
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
    // Forbid the _ prefix: the wire layer reserves sentinels (_response_
    // etc.) that reuse the source-circuit field
    !s.starts_with('_')
        && s.len() <= MAX_AGENT_ID_LEN
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
    config.acl.contains(&AclRule {
        source_tenant: source_tenant.to_string(),
        source: source_bare.to_string(),
        target_tenant: target_tenant.to_string(),
        target: target_bare.to_string(),
    })
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
    if max_total > 0 && hub.active_streams.read().await.len() >= max_total {
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
    /// Normal route: recipient, frame origin, flags, dispatch sink.
    Deliver {
        recipient: String,
        origin: FrameOrigin,
        flags: u8,
        sink: Option<mpsc::Sender<TunnelData>>,
    },
    /// Sender owns neither end of the stream (forged/late frame): drop.
    Forged,
    /// Stream does not exist: notify the sender, then drop.
    Missing,
}

impl HubService {
    /// Looks up the `mpsc::Sender` of the given agent.
    /// Locks are taken only within two very short critical sections (outer
    /// read takes the Arc, inner read clones tx); no awaiting while holding
    /// a lock.
    pub(crate) async fn lookup_tx(&self, agent_id: &str) -> Option<mpsc::Sender<TunnelData>> {
        let state_arc = {
            let agents = self.state.agents.read().await;
            agents.get(agent_id).cloned()
        };
        if let Some(state_arc) = state_arc {
            let state = state_arc.read().await;
            Some(state.tx.clone())
        } else {
            None
        }
    }

    /// Evicts by agent_id (entry point for runtime death signals such as
    /// send timeout). Captures the current entry's Arc and hands it to the
    /// unified eviction primitive; if the agent re-registers in the
    /// meantime, the eviction is automatically voided.
    pub(crate) async fn evict_agent_by_id(&self, agent_id: &str, reason: &'static str) {
        let expected = {
            let agents = self.state.agents.read().await;
            agents.get(agent_id).cloned()
        };
        if let Some(expected) = expected {
            crate::hub::heartbeat::evict_agent(&self.state.clone(), agent_id, &expected, reason)
                .await;
        }
    }

    /// Frame-level Open handling (called by the `/stream/up` reader;
    /// metadata comes from the wire frame rather than HTTP headers).
    ///
    /// `Err(reason)` = rejected (ACL / stream limits / target unreachable;
    /// metrics and audit already recorded); the caller informs the sender
    /// via an `_close_` frame on poll. `Ok(())` = stream established (or an
    /// empty target does not count as an active stream — the count is
    /// rolled back per existing semantics).
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
    ) -> std::result::Result<(), &'static str> {
        // Tenant isolation policy (RFC §4). Both endpoints arrive
        // tenant-qualified (`"{tenant}/{agent}"`); a bare target is
        // qualified with the source's own tenant (same-tenant shorthand on
        // the wire — agents do not know their tenant, and the default is
        // intra-tenant anyway).
        let Some((_source_tenant, _source_bare)) = PeerIdentity::split_qualified(source_agent)
        else {
            return Err("Invalid source identity");
        };
        let qualified_target = {
            let session = source_state.read().await;
            if session.circuit != source_circuit {
                return Err("Source circuit not registered");
            }
            drop(session);
            self.state.route_leases.read().await.get(&route).cloned()
        }
        .ok_or("Unknown route token")?;
        let qualified_target = match qualified_target {
            lease if lease.1 == source_agent => lease.2,
            _ => return Err("Unknown route token"),
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
            StreamAdmission::TenantDenied => return Err("Access denied by tenant policy"),
            StreamAdmission::GlobalStreamLimit => return Err("Global stream limit reached"),
            StreamAdmission::PerAgentStreamLimit => return Err("Per-agent stream limit reached"),
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
                    CircuitToken::random().map_err(|_| "Circuit token unavailable")?,
                ),
            }
        };

        // DATAGRAM eligibility (an h2 source only looks at the target side):
        // UDP stream + target capability + hub toggle
        let target_face = target_sink
            .clone()
            .map_or(StreamFace::Poll, StreamFace::Relay);
        let datagram_ok = matches!(proto, StreamProto::Udp)
            && target_face.is_relay()
            && self
                .state
                .config
                .read()
                .await
                .transport
                .quic
                .datagram_enabled;
        let stream = crate::hub::ActiveStream {
            source_agent: source_agent.to_string(),
            target_agent: target_agent.to_string(),
            source_circuit,
            target_circuit,
            proto,
            target: target_face.clone(),
            source: StreamFace::Poll, // h2 source: return path goes via poll
            datagram_ok,
        };
        {
            let mut streams = self.state.active_streams.write().await;
            streams.insert(stream_id, stream);
        }
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
        // the _close_ notification. Never allow "stream opened but the peer
        // doesn't know" — that leaves half the stream state alive in a black
        // hole, permanently occupying slots (one of the root causes of the
        // 2026-09-11 incident).
        // quic targets were already notified via the relay stream Open
        // (open_relay_stream writes the Open frame internally)
        //
        // Open goes through the **control channel** (2026-09-14 channel
        // separation): same-channel FIFO with a subsequent `_close_` of the
        // same stream (the poll pump's control priority does not reorder
        // Open/Close of the same stream), and it is no longer constrained by
        // data channel capacity — during bursty stream establishment, Open
        // notifications are not delayed or dropped by data backlog.
        let notify_result: std::result::Result<(), &'static str> = if target_face.is_relay() {
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
                Err("Target agent not registered")
            }
        };

        if let Err(reason) = notify_result {
            // Roll back the just-inserted active stream + release the stream
            // slot + correct metrics/audit
            {
                let mut streams = self.state.active_streams.write().await;
                if streams.remove(&stream_id).is_some() {
                    metrics::gauge!("interflow_hub_streams_active").decrement(1.0);
                }
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

    /// Frame-level Data handling. Direction is given by [`Direction`]
    /// (determined at the frame layer via the `"_response_"` sentinel);
    /// authorization: request direction must be the stream's source,
    /// response direction must be the stream's target.
    ///
    /// `Err(reason)` = dispatch failed (the caller informs the sender that
    /// the stream is unusable); stream-not-found / forged frames are handled
    /// per the existing convention (notify or drop) and return `Ok` — a
    /// single anomalous frame does not tear down the upload.
    pub(crate) async fn frame_data(
        &self,
        agent_id: &str,
        circuit: CircuitToken,
        stream_id: StreamId,
        direction: Direction,
        data: Bytes,
    ) -> std::result::Result<(), &'static str> {
        debug!(
            "Data frame received: stream_id={}, source={circuit}",
            stream_id
        );

        // Look up the stream info to determine the receiving agent (also
        // taking the stream protocol and dispatch plane: a quic peer goes
        // through the relay channel, an h2 peer through poll). Loopback
        // (source == target) converges naturally: both directions'
        // recipient/frame-source conclusions match the explicit branches.
        let route = {
            let streams = self.state.active_streams.read().await;
            match streams.get(&stream_id) {
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
                        debug!("Route direction: response path");
                        DataRoute::Deliver {
                            recipient: stream.source_agent.clone(),
                            origin: FrameOrigin::Response,
                            // UDP/E2E only ride Open; relaying Data with
                            // the stream's proto bits would violate the
                            // contract and kill the receiving decode.
                            flags: FLAG_RESPONSE,
                            sink: stream.source.relay_sender().cloned(),
                        }
                    } else {
                        debug!("Route direction: request path");
                        DataRoute::Deliver {
                            recipient: stream.target_agent.clone(),
                            origin: FrameOrigin::Agent(circuit),
                            flags: 0,
                            sink: stream.target.relay_sender().cloned(),
                        }
                    }
                }
            }
        };

        let (recipient, origin, frame_flags, recipient_sink) = match route {
            DataRoute::Deliver {
                recipient,
                origin,
                flags,
                sink,
            } => (recipient, origin, flags, sink),
            DataRoute::Missing => {
                // Stream does not exist (late frame / already swept): notify
                // the sender so it disconnects the local connection
                self.notify_sender_close(agent_id, stream_id, "Stream not found")
                    .await;
                return Ok(());
            }
            DataRoute::Forged => return Ok(()),
        };

        debug!("Data received: {} bytes", data.len());
        metrics::counter!("interflow_hub_bytes_rx").increment(data.len() as u64);
        metrics::counter!("interflow_hub_frames_rx", "type" => "data").increment(1);

        let data_frame = TunnelData {
            stream_id,
            origin,
            stream_type: FrameType::Data,
            flags: frame_flags,
            data,
        };

        // Execute send().await outside the lock, with a timeout: when an
        // agent dies and the channel (capacity 256) fills, an un-timed send
        // would hang forever, pinning hub connections and memory, with
        // upstream only able to wait for nginx to time out with a 502
        // (the second root cause of the 2026-09-11 incident).
        //
        // quic peer: sink channel write (same timeout discipline; its
        // disconnect watcher is responsible for eviction).
        // h2 peer: lookup_tx → poll channel (existing path).
        if let Some(sink) = recipient_sink {
            let send_timeout = Duration::from_secs(
                self.state
                    .limits
                    .channel_send_timeout_secs
                    .load(Ordering::Relaxed),
            );
            match tokio::time::timeout(send_timeout, sink.send(data_frame)).await {
                Ok(Ok(())) => {
                    debug!("Data relayed over QUIC");
                    Ok(())
                }
                Ok(Err(_)) => {
                    error!("QUIC relay channel closed");
                    Err("Target agent channel closed")
                }
                Err(_) => {
                    error!("QUIC relay send timed out (>{send_timeout:?})");
                    Err("Target agent stalled")
                }
            }
        } else {
            let Some(tx) = self.lookup_tx(&recipient).await else {
                error!("Receiving endpoint has no data channel");
                return Err("Target agent not registered");
            };
            let send_timeout = Duration::from_secs(
                self.state
                    .limits
                    .channel_send_timeout_secs
                    .load(Ordering::Relaxed),
            );
            match tokio::time::timeout(send_timeout, tx.send(data_frame)).await {
                Ok(Ok(())) => {
                    debug!("Data sent to receiving endpoint");
                    Ok(())
                }
                Ok(Err(e)) => {
                    // Channel closed: the agent was just evicted or
                    // re-registered. Fail honestly so upstream disconnects;
                    // never fake success and throw data into a black hole.
                    error!("Failed to send data (channel closed): {e}");
                    Err("Target agent channel closed")
                }
                Err(_) => {
                    // Timeout = the receiving end has had no consumer for a
                    // long time; declare it dead: evict that agent (closing
                    // the channel immediately unblocks the remaining blocked
                    // senders), and subsequent requests take the fast-fail
                    // "agent does not exist" path.
                    error!(
                        "Send data timed out (>{send_timeout:?}): channel has no consumer, evicting the endpoint"
                    );
                    self.evict_agent_by_id(&recipient, "send_timeout").await;
                    Err("Target agent stalled")
                }
            }
        }
    }

    /// Frame-level Close handling: notify the peer, remove the active
    /// stream, release the slot. `reason` (from the agent's Close payload)
    /// is forwarded to the peer's `_close_` notification so the far end can
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
        let (notify_agent, owner_agent) = {
            let streams = self.state.active_streams.read().await;
            let Some(stream) = streams.get(&stream_id) else {
                return;
            };
            let authorized = match direction {
                Direction::Response => stream.target_circuit == circuit,
                Direction::Request => stream.source_circuit == circuit,
            };
            if !authorized {
                warn!("Forgery check: Close frame does not own either end of stream {stream_id}");
                return;
            }
            let notify = if direction == Direction::Response {
                stream.source_agent.clone()
            } else {
                stream.target_agent.clone()
            };
            (notify, stream.source_agent.clone())
        };

        // Remove the active stream + decrement the count in the same
        // critical section (prevents drift)
        {
            let mut streams = self.state.active_streams.write().await;
            if streams.remove(&stream_id).is_some() {
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

    /// Sends a `_close_` close/rejection notification back to `agent_id`
    /// via the **control channel** (guaranteed delivery).
    ///
    /// The payload convention is `CLOSE:{sid}:{reason}` (empty reason means
    /// an ordinary close); the pump side tears down the stream via the
    /// existing Close path.
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
    pub(crate) async fn notify_sender_close(
        &self,
        agent_id: &str,
        stream_id: StreamId,
        reason: &str,
    ) {
        let code = crate::hub::control::close_reason_of(reason);
        let _ = crate::hub::control::deliver_close_via_control(
            &self.state.agents,
            agent_id,
            stream_id,
            code,
        )
        .await;
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
}
