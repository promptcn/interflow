//! Frame-level stream routing: Open/Data/Close ACL checks, direction
//! determination, anti-forgery, and dispatch.
//!
//! 2026-09-12 upload streaming: `POST /stream` (one HTTP exchange per frame,
//! metadata in HTTP headers) was retired, and this module was refactored from
//! "HTTP header parsing + handling" into pure frame-level dispatch, called by
//! the `/stream/up` reader task of [`crate::hub::upload`]:
//! - Direction semantics now come from the frame layer: response-direction
//!   frames carry `source_agent = "_response_"`
//!   (the `x-direction` header is retired);
//! - Frame-level rejections (ACL / stream limits / target unreachable) no
//!   longer have a per-frame HTTP status; instead a `"_close_"` frame
//!   carrying `CLOSE:{sid}:{reason}` goes back via the sender's `/poll`
//!   channel — the pump side reuses the existing Close stream-teardown path
//!   (consistent with the existing "stream not found" convention).

use crate::config::AclRule;
use crate::hub::service::HubService;
use crate::hub::state::{SharedStreamCounts, StreamFace, TunnelData};
use bytes::Bytes;
use interflow_core::protocol::{FrameType, StreamProto};
use interflow_core::security::AuditKind;
use interflow_core::tunnel::FrameSource;
use std::sync::atomic::Ordering;
use std::time::Duration;
use tokio::sync::mpsc;
use tracing::{debug, error, warn};

/// Maximum stream_id length (128B), character allowlist `[A-Za-z0-9_-]`.
pub(crate) const MAX_STREAM_ID_LEN: usize = 128;
/// Maximum agent_id length (128B), character allowlist `[A-Za-z0-9_.-]`.
pub(crate) const MAX_AGENT_ID_LEN: usize = 128;
/// Maximum target_addr length (256B), control characters forbidden.
pub(crate) const MAX_ADDR_LEN: usize = 256;

/// Frame direction (determined at the wire layer by the `"_response_"`
/// sentinel).
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

pub(crate) fn valid_stream_id(s: &str) -> bool {
    s.len() <= MAX_STREAM_ID_LEN
        && !s.is_empty()
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
}

pub(crate) fn valid_agent_id(s: &str) -> bool {
    // Forbid the _ prefix: the wire layer reserves sentinels (_response_
    // etc.) that reuse the source_agent field
    !s.starts_with('_')
        && s.len() <= MAX_AGENT_ID_LEN
        && !s.is_empty()
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_' || b == b'.')
}

pub(crate) fn valid_target_addr(s: &str) -> bool {
    s.len() <= MAX_ADDR_LEN && !s.bytes().any(|b| b.is_ascii_control())
}

/// Resolution result of frame-level Data dispatch.
enum DataRoute {
    /// Normal route: recipient, frame source, flags, dispatch sink.
    Deliver {
        recipient: String,
        frame_source: FrameSource,
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
            let agents = self.agents.read().await;
            agents.get(agent_id).cloned()
        };
        if let Some(state_arc) = state_arc {
            let state = state_arc.read().await;
            Some(state.tx.clone())
        } else {
            None
        }
    }

    /// Tries to acquire a stream slot for `agent`. Returns true on success;
    /// returns false without incrementing when over `max`.
    /// `max = 0` means unlimited. The lock is held only briefly
    /// (check-and-increment, nanosecond scale), never across an await.
    fn try_acquire_stream_slot(counts: &SharedStreamCounts, agent: &str, max: usize) -> bool {
        if max == 0 {
            return true;
        }
        let mut map = counts
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let entry = map.entry(agent.to_string()).or_insert(0);
        if *entry >= max {
            false
        } else {
            *entry += 1;
            true
        }
    }

    /// Releases one stream slot for `agent`. Removes the key when the count
    /// reaches zero to prevent unbounded HashMap growth.
    fn release_stream_slot(counts: &SharedStreamCounts, agent: &str) {
        let mut map = counts
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if let Some(entry) = map.get_mut(agent) {
            *entry = entry.saturating_sub(1);
            if *entry == 0 {
                map.remove(agent);
            }
        }
    }

    /// Evicts by agent_id (entry point for runtime death signals such as
    /// send timeout). Captures the current entry's Arc and hands it to the
    /// unified eviction primitive; if the agent re-registers in the
    /// meantime, the eviction is automatically voided.
    pub(crate) async fn evict_agent_by_id(&self, agent_id: &str, reason: &'static str) {
        let expected = {
            let agents = self.agents.read().await;
            agents.get(agent_id).cloned()
        };
        if let Some(expected) = expected {
            crate::hub::heartbeat::evict_agent(&self.handles(), agent_id, &expected, reason).await;
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
        source_agent: &str,
        stream_id: &str,
        target_agent: &str,
        target_addr: Option<&str>,
        proto: StreamProto,
    ) -> std::result::Result<(), &'static str> {
        // ACL check (lock taken only when enabled)
        if self.limits.acl_enabled.load(Ordering::Relaxed) {
            let config = self.config.read().await;
            if !config.acl.is_empty() {
                let rule = AclRule {
                    source: source_agent.to_string(),
                    target: target_agent.to_string(),
                };
                if !config.acl.contains(&rule) {
                    warn!("ACL denied: {} -> {}", source_agent, target_agent);
                    metrics::counter!("interflow_hub_acl_denied").increment(1);
                    self.audit.record(
                        AuditKind::StreamDenied {
                            stream_id: stream_id.to_string(),
                            source: source_agent.to_string(),
                            reason: format!("acl_denied: target={target_agent}"),
                        },
                        Some(source_agent.to_string()),
                        Some(self.peer_str()),
                    );
                    return Err("Access denied by ACL");
                }
            }
        }

        // Stream count cap check (defends against DDoS / a compromised agent
        // flooding stream opens)
        // Read from atomics to avoid taking the config RwLock read lock on
        // every Open
        let max_per_agent = self
            .limits
            .max_streams_per_agent
            .load(std::sync::atomic::Ordering::Relaxed);
        let max_total = self
            .limits
            .max_streams_total
            .load(std::sync::atomic::Ordering::Relaxed);
        if max_total > 0 {
            let current = self.active_streams.read().await.len();
            if current >= max_total {
                metrics::counter!("interflow_hub_stream_limit_denied", "scope" => "total")
                    .increment(1);
                self.audit.record(
                    AuditKind::StreamDenied {
                        stream_id: stream_id.to_string(),
                        source: source_agent.to_string(),
                        reason: "global_stream_limit".into(),
                    },
                    Some(source_agent.to_string()),
                    Some(self.peer_str()),
                );
                return Err("Global stream limit reached");
            }
        }
        if max_per_agent > 0
            && !Self::try_acquire_stream_slot(&self.stream_counts, source_agent, max_per_agent)
        {
            metrics::counter!("interflow_hub_stream_limit_denied", "scope" => "per_agent")
                .increment(1);
            self.audit.record(
                AuditKind::StreamDenied {
                    stream_id: stream_id.to_string(),
                    source: source_agent.to_string(),
                    reason: "per_agent_stream_limit".into(),
                },
                Some(source_agent.to_string()),
                Some(self.peer_str()),
            );
            return Err("Per-agent stream limit reached");
        }

        debug!(
            "Stream opened: stream_id={}, source={}, target={target_agent}, addr={target_addr:?}",
            stream_id, source_agent,
        );

        // No target agent: does not count as an active stream; roll back the
        // count and succeed directly (existing semantics)
        if target_agent.is_empty() {
            if max_per_agent > 0 {
                Self::release_stream_slot(&self.stream_counts, source_agent);
            }
            return Ok(());
        }

        // Store the active stream (under lock). When the target is a quic
        // agent, first establish a relay stream to obtain the dispatch plane
        // (the h2 source → quic target interop path); h2 targets keep poll
        // channel notifications.
        // quic target: open a relay stream (failure rolls back like a
        // notification failure, same discipline as the poll path)
        let target_sink = {
            let target_state = {
                let agents = self.agents.read().await;
                agents.get(target_agent).cloned()
            };
            match target_state {
                Some(state) => {
                    let quic_conn = { state.read().await.quic.clone() };
                    match quic_conn {
                        Some(qc) => crate::hub::quic::open_relay_stream(
                            &self.core(),
                            &qc,
                            stream_id,
                            source_agent,
                            target_addr,
                            proto,
                        )
                        .await
                        .inspect(|_tx| {
                            debug!("QUIC relay established: target={target_agent}, stream_id={stream_id}");
                        }),
                        None => None, // h2 target: goes via poll
                    }
                }
                None => None,
            }
        };

        // DATAGRAM eligibility (an h2 source only looks at the target side):
        // UDP stream + target capability + hub toggle
        let target_face = target_sink
            .clone()
            .map_or(StreamFace::Poll, StreamFace::Relay);
        let datagram_ok = matches!(proto, StreamProto::Udp)
            && target_face.is_relay()
            && self.config.read().await.quic.datagram_enabled;
        let stream = crate::hub::ActiveStream {
            source_agent: source_agent.to_string(),
            target_agent: target_agent.to_string(),
            target_addr: target_addr.map(str::to_string),
            proto,
            target: target_face.clone(),
            source: StreamFace::Poll, // h2 source: return path goes via poll
            datagram_ok,
        };
        {
            let mut streams = self.active_streams.write().await;
            streams.insert(stream_id.to_string(), stream);
        }
        metrics::gauge!("interflow_hub_streams_active").increment(1.0);
        metrics::counter!("interflow_hub_streams_total", "direction" => "request").increment(1);
        self.audit.record(
            AuditKind::StreamOpened {
                stream_id: stream_id.to_string(),
                source: source_agent.to_string(),
                target: target_agent.to_string(),
            },
            Some(source_agent.to_string()),
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
            let addr_str = target_addr.unwrap_or_default();
            let open_data = format!("{source_agent}:{addr_str}");
            let frame = TunnelData {
                stream_id: stream_id.to_string(),
                source: FrameSource::Open,
                stream_type: FrameType::Open,
                flags: proto.as_flag(),
                data: Bytes::from(open_data),
            };
            if crate::hub::control::deliver_control(&self.agents, target_agent, frame).await {
                debug!("Notified {target_agent} of stream open: stream_id={stream_id}");
                Ok(())
            } else {
                // Not registered / a QUIC session (the poll plane is
                // ineffective for it) / session already ended
                error!(
                    "Failed to send Open notification: target={target_agent}, stream_id={stream_id}"
                );
                Err("Target agent not registered")
            }
        };

        if let Err(reason) = notify_result {
            // Roll back the just-inserted active stream + release the stream
            // slot + correct metrics/audit
            {
                let mut streams = self.active_streams.write().await;
                if streams.remove(stream_id).is_some() {
                    metrics::gauge!("interflow_hub_streams_active").decrement(1.0);
                }
            }
            if max_per_agent > 0 {
                Self::release_stream_slot(&self.stream_counts, source_agent);
            }
            self.audit.record(
                AuditKind::StreamClosed {
                    stream_id: stream_id.to_string(),
                    source: source_agent.to_string(),
                },
                Some(source_agent.to_string()),
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
        stream_id: &str,
        direction: Direction,
        data: Bytes,
    ) -> std::result::Result<(), &'static str> {
        debug!(
            "Data frame received: stream_id={}, source={agent_id}",
            stream_id
        );

        // Look up the stream info to determine the receiving agent (also
        // taking the stream protocol and dispatch plane: a quic peer goes
        // through the relay channel, an h2 peer through poll). Loopback
        // (source == target) converges naturally: both directions'
        // recipient/frame-source conclusions match the explicit branches.
        let route = {
            let streams = self.active_streams.read().await;
            match streams.get(stream_id) {
                None => DataRoute::Missing,
                Some(stream) => {
                    let proto_flag = stream.proto.as_flag();
                    let forged = match direction {
                        Direction::Response => stream.target_agent != agent_id,
                        Direction::Request => stream.source_agent != agent_id,
                    };
                    if forged {
                        error!(
                            "Forgery check: {}-direction frame from {agent_id} does not match the stream owner",
                            direction.label()
                        );
                        DataRoute::Forged
                    } else if direction == Direction::Response {
                        debug!(
                            "Route direction: {agent_id} -> {} (response path)",
                            stream.source_agent
                        );
                        DataRoute::Deliver {
                            recipient: stream.source_agent.clone(),
                            frame_source: FrameSource::Response,
                            flags: proto_flag,
                            sink: stream.source.relay_sender().cloned(),
                        }
                    } else {
                        debug!(
                            "Route direction: {agent_id} -> {} (request path)",
                            stream.target_agent
                        );
                        DataRoute::Deliver {
                            recipient: stream.target_agent.clone(),
                            frame_source: FrameSource::Agent(agent_id.into()),
                            flags: proto_flag,
                            sink: stream.target.relay_sender().cloned(),
                        }
                    }
                }
            }
        };

        let (recipient, frame_source, frame_flags, recipient_sink) = match route {
            DataRoute::Deliver {
                recipient,
                frame_source,
                flags,
                sink,
            } => (recipient, frame_source, flags, sink),
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
            stream_id: stream_id.to_string(),
            source: frame_source,
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
                self.limits
                    .channel_send_timeout_secs
                    .load(Ordering::Relaxed),
            );
            match tokio::time::timeout(send_timeout, sink.send(data_frame)).await {
                Ok(Ok(())) => {
                    debug!("Data relayed to {recipient} (QUIC)");
                    Ok(())
                }
                Ok(Err(_)) => {
                    error!("QUIC relay channel closed: {recipient}");
                    Err("Target agent channel closed")
                }
                Err(_) => {
                    error!("QUIC relay send timed out (>{send_timeout:?}): {recipient}");
                    Err("Target agent stalled")
                }
            }
        } else {
            let Some(tx) = self.lookup_tx(&recipient).await else {
                error!("Receiving agent {recipient} has no data channel");
                return Err("Target agent not registered");
            };
            let send_timeout = Duration::from_secs(
                self.limits
                    .channel_send_timeout_secs
                    .load(Ordering::Relaxed),
            );
            match tokio::time::timeout(send_timeout, tx.send(data_frame)).await {
                Ok(Ok(())) => {
                    debug!("Data sent to {recipient}");
                    Ok(())
                }
                Ok(Err(e)) => {
                    // Channel closed: the agent was just evicted or
                    // re-registered. Fail honestly so upstream disconnects;
                    // never fake success and throw data into a black hole.
                    error!("Failed to send data (channel closed): {recipient} : {e}");
                    Err("Target agent channel closed")
                }
                Err(_) => {
                    // Timeout = the receiving end has had no consumer for a
                    // long time; declare it dead: evict that agent (closing
                    // the channel immediately unblocks the remaining blocked
                    // senders), and subsequent requests take the fast-fail
                    // "agent does not exist" path.
                    error!(
                        "Send data timed out (>{send_timeout:?}): {recipient} channel has no consumer, evicting the agent"
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
        agent_id: &str,
        stream_id: &str,
        direction: Direction,
        reason: &str,
    ) {
        debug!("Stream closed: stream_id={stream_id}, reason={reason}");

        // Look up the stream info and decide which peer to notify
        // (directional authorization: request direction must be the source,
        // response direction must be the target — otherwise drop as forgery)
        let (notify_agent, owner_agent) = {
            let streams = self.active_streams.read().await;
            let Some(stream) = streams.get(stream_id) else {
                return;
            };
            let authorized = match direction {
                Direction::Response => stream.target_agent == agent_id,
                Direction::Request => stream.source_agent == agent_id,
            };
            if !authorized {
                warn!(
                    "Forgery check: Close frame from {agent_id} does not own either end of stream {stream_id}"
                );
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
            let mut streams = self.active_streams.write().await;
            if streams.remove(stream_id).is_some() {
                metrics::gauge!("interflow_hub_streams_active").decrement(1.0);
                Self::release_stream_slot(&self.stream_counts, &owner_agent);
                self.audit.record(
                    AuditKind::StreamClosed {
                        stream_id: stream_id.to_string(),
                        source: agent_id.to_string(),
                    },
                    Some(agent_id.to_string()),
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
                &self.agents,
                &notify_agent,
                stream_id,
                reason,
            )
            .await;
        } else {
            crate::hub::control::deliver_close_via_control(
                &self.agents,
                &notify_agent,
                stream_id,
                reason,
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
    /// docs/bug/2026-09-14-intrasession-orphan-stream-fd-leak.md). The drop
    /// was harmless to stream state (the hub side had already torn the
    /// stream down) but harmful to the peer's fd — after control/data plane
    /// separation, "delivery while online".
    ///
    /// All call sites of this function (open rejection / forgery / late
    /// frames) carry "termination first" semantics; the only FIFO-sensitive
    /// case, a normal response-direction close, does not go through this
    /// function (see `frame_close`).
    pub(crate) async fn notify_sender_close(&self, agent_id: &str, stream_id: &str, reason: &str) {
        crate::hub::control::deliver_close_via_control(&self.agents, agent_id, stream_id, reason)
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
    use std::collections::HashMap;
    use std::sync::Arc;

    #[test]
    fn stream_id_validation() {
        assert!(valid_stream_id("abc"));
        assert!(valid_stream_id("a-b_c"));
        assert!(!valid_stream_id(""));
        assert!(!valid_stream_id("a/b"));
        assert!(!valid_stream_id("a b"));
    }

    #[test]
    fn agent_id_validation_allows_dot() {
        assert!(valid_agent_id("agent-1.local"));
        assert!(!valid_agent_id("agent 1"));
    }

    #[test]
    fn target_addr_rejects_control_chars() {
        assert!(valid_target_addr("127.0.0.1:3000"));
        assert!(!valid_target_addr("a\nb"));
    }

    fn make_counts() -> SharedStreamCounts {
        Arc::new(std::sync::Mutex::new(HashMap::new()))
    }

    #[test]
    fn stream_slot_acquires_until_max_then_rejects() {
        let counts = make_counts();
        assert!(HubService::try_acquire_stream_slot(&counts, "a1", 3));
        assert!(HubService::try_acquire_stream_slot(&counts, "a1", 3));
        assert!(HubService::try_acquire_stream_slot(&counts, "a1", 3));
        assert!(
            !HubService::try_acquire_stream_slot(&counts, "a1", 3),
            "4th acquire over cap must fail"
        );
    }

    #[test]
    fn stream_slot_release_allows_reacquire() {
        let counts = make_counts();
        HubService::try_acquire_stream_slot(&counts, "a1", 2);
        HubService::try_acquire_stream_slot(&counts, "a1", 2);
        assert!(!HubService::try_acquire_stream_slot(&counts, "a1", 2));
        HubService::release_stream_slot(&counts, "a1");
        assert!(
            HubService::try_acquire_stream_slot(&counts, "a1", 2),
            "after release, slot should be available"
        );
    }

    #[test]
    fn stream_slot_per_agent_isolation() {
        let counts = make_counts();
        HubService::try_acquire_stream_slot(&counts, "a1", 1);
        assert!(
            HubService::try_acquire_stream_slot(&counts, "a2", 1),
            "different agent has independent budget"
        );
        assert!(!HubService::try_acquire_stream_slot(&counts, "a1", 1));
    }

    #[test]
    fn stream_slot_release_removes_zero_entry() {
        let counts = make_counts();
        HubService::try_acquire_stream_slot(&counts, "a1", 5);
        HubService::release_stream_slot(&counts, "a1");
        assert!(
            counts.lock().unwrap().get("a1").is_none(),
            "counter entry should be removed at zero to prevent map growth"
        );
    }

    #[test]
    fn stream_slot_zero_max_means_unlimited() {
        let counts = make_counts();
        for _ in 0..1000 {
            assert!(HubService::try_acquire_stream_slot(&counts, "a1", 0));
        }
    }
}
