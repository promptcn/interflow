//! Control-plane dispatch: guaranteed-delivery channel for stream lifecycle
//! notifications (Open / `_close_`).
//!
//! Before the 2026-09-14 in-session orphan-stream root fix
//! (docs/bug/2026-09-14-intrasession-orphan-stream-fd-leak.md), hub → agent
//! close notifications shared the same capacity-256 poll data channel as
//! business Data frames: when a traffic burst filled the channel,
//! `try_send` silently dropped `_close_`, the egress forwarder never saw a
//! Close, and the backend fd lingered for the whole session (EMFILE). The
//! data plane must be bounded (backpressure) and the control plane must not
//! drop (otherwise the peer's fd lingers) — the two semantics conflict, so
//! the channels must be separated:
//!
//! - **Data channel** (capacity 256, `AgentSession::tx`): Data / Ping; when
//!   full the sender waits in a bounded fashion (backpressure propagates to
//!   upstream TCP flow control);
//! - **Control channel** (unbounded, `AgentSession::ctrl_tx`): Open and
//!   `_close_` notifications. `send` is synchronous, never blocks, and fails
//!   only when the peer's session ends (receiver dropped) — "delivery while
//!   online".
//!
//! Ordering contract (the semantic boundary of the poll pump's
//! control-priority):
//! - The hub processes frames on the same upload connection in order, and
//!   Open and a later Close of the same stream both go through the control
//!   channel, preserving FIFO — close-before-open cannot happen;
//! - `_close_` is allowed to overtake **request-direction** tail data still
//!   queued in the data channel (the stream is already dead at its source,
//!   the tail request data is meaningless; termination and fd release take
//!   priority);
//! - **Response-direction** Close (backend EOF) is the exception: queued
//!   response tail bytes are still deliverable to the visitor, and
//!   truncating them corrupts the page — first queue in the data channel in
//!   a bounded wait (preserving FIFO); only on a stall timeout does it fall
//!   back to the control channel (under a pathological stall, stream
//!   teardown takes priority over tail bytes).
//!
//! QUIC-registered agents do not consume `/poll`; control notifications are
//! conveyed by the write task writing the outstanding Close+FIN when the
//! relay-plane table entry is removed — this module always skips QUIC
//! sessions (otherwise the control channel, drained by no one, would build
//! up unboundedly).

use crate::hub::state::{SharedAgents, TunnelData};
use bytes::Bytes;
use interflow_core::protocol::FrameType;
use interflow_core::tunnel::FrameSource;
use std::time::Duration;
use tokio::sync::mpsc;
use tracing::{debug, error, warn};

/// Control channel backlog sentinel: exceeding it fails loud (error log +
/// counter).
///
/// The structural upper bound is backed by the data-plane death signals:
/// when the poll pump stalls, the data channel fills first (capacity 256),
/// the Data dispatch timeout triggers a `send_timeout` eviction, and the
/// control channel becomes void along with it — the sentinel only covers the
/// pathological scenario of "the eviction chain itself malfunctioning".
/// Sending still proceeds (no drops): 10k notification frames are only
/// ~1 MiB, and the cost of losing one (the peer's fd lingering) is higher
/// than the cost of buffering.
pub(crate) const CONTROL_BACKLOG_SENTINEL: usize = 10_000;

/// Bounded wait for a response-direction Close to keep FIFO on the data channel.
///
/// Significantly smaller than the data-plane `channel_send_timeout_secs`
/// (default 30s): this is a close-out path — a stall here is pathological,
/// and past this bound termination takes priority (fall back to the control
/// channel).
pub(crate) const RESPONSE_CLOSE_FIFO_TIMEOUT: Duration = Duration::from_secs(2);

/// Snapshot of an agent's channels (fetched in one inner read lock; dispatched
/// outside the lock).
struct AgentChannels {
    data_tx: mpsc::Sender<TunnelData>,
    ctrl_tx: mpsc::UnboundedSender<TunnelData>,
    ctrl_backlog: std::sync::Arc<std::sync::atomic::AtomicUsize>,
}

/// Fetches an agent's data/control channels via two short critical sections
/// (same discipline as `lookup_tx`; no awaiting while holding a lock).
async fn lookup_channels(agents: &SharedAgents, agent_id: &str) -> Option<AgentChannels> {
    let state_arc = {
        let agents = agents.read().await;
        agents.get(agent_id).cloned()
    }?;
    let state = state_arc.read().await;
    // QUIC agent: does not consume via /poll; control notifications are
    // conveyed by the relay teardown (see module docs)
    if state.quic.is_some() {
        return None;
    }
    Some(AgentChannels {
        data_tx: state.tx.clone(),
        ctrl_tx: state.ctrl_tx.clone(),
        ctrl_backlog: state.ctrl_backlog.clone(),
    })
}

/// Control channel dispatch (with backlog accounting and the sentinel's
/// death nudge).
///
/// Sends are never dropped: an unbounded `send` fails only when the peer's
/// session ends (receiver dropped). Backlog exceeding
/// [`CONTROL_BACKLOG_SENTINEL`] means the poll pump has been stalled for a
/// long time and the regular death signals (data-plane send_timeout / poll
/// grace) did not fire — advance the generation + close the control channel
/// to nudge the residual poll body to death, letting grace eviction /
/// re-registration take over the cleanup, while dispatch continues (10k
/// notification frames are only ~1 MiB; the cost of losing one is the
/// peer's fd lingering).
async fn control_send(
    agents: &SharedAgents,
    agent_id: &str,
    ch: &AgentChannels,
    frame: TunnelData,
) -> bool {
    let backlog = ch
        .ctrl_backlog
        .fetch_add(1, std::sync::atomic::Ordering::Relaxed)
        + 1;
    let sent = ch.ctrl_tx.send(frame).is_ok();
    if !sent {
        ch.ctrl_backlog
            .fetch_sub(1, std::sync::atomic::Ordering::Relaxed);
        debug!(
            "Control notification failed (agent {agent_id} session already ended, its streams released with teardown)"
        );
        return false;
    }
    if backlog >= CONTROL_BACKLOG_SENTINEL {
        metrics::counter!("interflow_hub_control_backlog_exceeded_total").increment(1);
        error!(
            "agent {agent_id} control channel backlog {backlog} (poll most likely stalled and eviction chain not triggered),\
             killing the old session and continuing dispatch"
        );
        // Death nudge: advance the generation + close the control channel +
        // wake the poll body (generation self-check ends the response).
        // The poll grace eviction / agent re-registration afterwards
        // completes the full cleanup.
        let state_arc = {
            let map = agents.read().await;
            map.get(agent_id).cloned()
        };
        if let Some(state_arc) = state_arc {
            let mut st = state_arc.write().await;
            st.ctrl_rx = None;
            st.generation += 1;
            st.wake_poll();
        }
    }
    true
}

/// Builds a `_close_` notification frame (payload convention
/// `CLOSE:{sid}:{reason}`, consistent with the existing wire semantics).
pub(crate) fn close_frame(stream_id: &str, reason: &str) -> TunnelData {
    TunnelData {
        stream_id: stream_id.to_string(),
        source: FrameSource::Close,
        stream_type: FrameType::Close,
        flags: 0,
        data: Bytes::from(format!("CLOSE:{stream_id}:{reason}")),
    }
}

/// Defensive extraction of the close reason from an agent→hub Close payload.
///
/// The reason is a short machine token emitted by the egress forwarder
/// (`CloseReason::as_str()`, e.g. `connect_failed`); empty = ordinary
/// close. A pre-2026-09-16 agent sends an empty payload. Anything odd-shaped
/// (a hostile agent) is pruned to a bounded `[A-Za-z0-9_.-]` token before it
/// is embedded into the downstream `CLOSE:{sid}:{reason}` convention.
pub(crate) fn close_reason_of(payload: &[u8]) -> String {
    String::from_utf8_lossy(payload)
        .chars()
        .take_while(|c| *c != ':')
        .filter(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '-' | '.'))
        .take(64)
        .collect()
}

/// Delivers one lifecycle notification frame (Open / `_close_`) to an h2
/// (poll) agent via the control channel with guaranteed delivery.
///
/// Returns `false` = peer not registered / a QUIC session (conveyed by the
/// relay teardown) / session already ended (receiver dropped — the peer's
/// streams were released with its session teardown, so nothing is lost).
pub(crate) async fn deliver_control(
    agents: &SharedAgents,
    agent_id: &str,
    frame: TunnelData,
) -> bool {
    let Some(ch) = lookup_channels(agents, agent_id).await else {
        debug!(
            "Control notification skipped: agent {agent_id} not registered or is a QUIC session"
        );
        return false;
    };
    control_send(agents, agent_id, &ch, frame).await
}

/// `_close_` with request-direction semantics: guaranteed delivery via the
/// control channel.
///
/// Overtaking queued request-direction tail data is the **correct** semantic
/// (the stream is already dead at its source, the tail data is meaningless,
/// and releasing the peer's fd takes priority).
pub(crate) async fn deliver_close_via_control(
    agents: &SharedAgents,
    agent_id: &str,
    stream_id: &str,
    reason: &str,
) -> bool {
    deliver_control(agents, agent_id, close_frame(stream_id, reason)).await
}

/// `_close_` with response-direction semantics (backend EOF): data-channel
/// FIFO first, falling back to the control channel on stall. `reason`
/// (empty = ordinary close) rides in the payload so the receiving end can
/// distinguish backend failures from normal teardown.
///
/// Queued response tail bytes are still deliverable to the visitor — under
/// normal congestion the Close queues after the data (`send().await` waits
/// for capacity; enqueueing puts it at the tail); only when the data channel
/// goes unconsumed for a long time (pathological stall) does termination
/// take priority, falling back to the control channel and counting it.
pub(crate) async fn deliver_response_close(
    agents: &SharedAgents,
    agent_id: &str,
    stream_id: &str,
    reason: &str,
) -> bool {
    let Some(ch) = lookup_channels(agents, agent_id).await else {
        debug!(
            "Response close notification skipped: agent {agent_id} not registered or is a QUIC session"
        );
        return false;
    };
    let sent = tokio::time::timeout(
        RESPONSE_CLOSE_FIFO_TIMEOUT,
        ch.data_tx.send(close_frame(stream_id, reason)),
    )
    .await;
    // FIFO preserved: under normal congestion the Close succeeds by queueing
    // after the existing response data
    if matches!(sent, Ok(Ok(()))) {
        return true;
    }
    // Data channel unconsumed for a long time (pathological stall):
    // termination takes priority, fall back to the control channel and count
    metrics::counter!("interflow_hub_close_notify_fifo_fallback_total").increment(1);
    warn!(
        "agent {agent_id} data channel stalled/closed, response close falling back to control channel: stream_id={stream_id}"
    );
    control_send(agents, agent_id, &ch, close_frame(stream_id, reason)).await
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
    use crate::hub::state::AgentSession;
    use std::collections::HashMap;
    use std::sync::Arc;
    use std::time::Instant;
    use tokio::sync::RwLock;

    async fn registered_agent(agents: &SharedAgents, id: &str) {
        // A fresh session keeps its rx "not yet taken by poll"; control
        // sends do not depend on data-channel consumption.
        agents.write().await.insert(
            id.to_string(),
            Arc::new(RwLock::new(AgentSession::new(None))),
        );
    }

    /// Core T3 assertion: with the data channel saturated, control
    /// notifications are still delivered immediately (before the fix,
    /// try_send dropped them outright — a full poll channel meant silent
    /// failure and a lingering egress fd).
    #[tokio::test]
    async fn control_delivery_survives_saturated_data_channel() {
        let agents: SharedAgents = Arc::new(RwLock::new(HashMap::new()));
        registered_agent(&agents, "egress-1").await;

        // Fill the data channel: capacity 256, no consumer
        {
            let state_arc = agents.read().await.get("egress-1").cloned().unwrap();
            let st = state_arc.read().await;
            for i in 0..256 {
                let frame = TunnelData {
                    stream_id: format!("fill-{i}"),
                    source: FrameSource::Agent("x".into()),
                    stream_type: FrameType::Data,
                    flags: 0,
                    data: Bytes::from_static(b"x"),
                };
                st.tx
                    .try_send(frame)
                    .expect("enqueue must succeed within capacity");
            }
            // Full now: one more frame must fail (mirrors the pre-fix notify behavior)
            assert!(
                st.tx
                    .try_send(TunnelData {
                        stream_id: "more".into(),
                        source: FrameSource::Agent("x".into()),
                        stream_type: FrameType::Data,
                        flags: 0,
                        data: Bytes::new(),
                    })
                    .is_err(),
                "precondition: data channel is full (pre-fix try_send dropped close notifications here)"
            );
        }

        // Control channel delivery: immediate, no waiting, no dropping
        let started = Instant::now();
        assert!(deliver_close_via_control(&agents, "egress-1", "s-1", "").await);
        assert!(
            started.elapsed() < Duration::from_millis(500),
            "delivery must be immediate"
        );

        let mut ctrl_rx = {
            let state_arc = agents.read().await.get("egress-1").cloned().unwrap();
            state_arc.write().await.ctrl_rx.take().unwrap()
        };
        let frame = tokio::time::timeout(Duration::from_secs(1), ctrl_rx.recv())
            .await
            .expect("control channel must have the frame enqueued")
            .expect("channel alive");
        assert_eq!(frame.stream_type, FrameType::Close);
        assert_eq!(frame.stream_id, "s-1");
    }

    /// Unregistered agent: returns false (the peer has no session; its
    /// streams are released with the peer's session teardown).
    #[tokio::test]
    async fn control_delivery_missing_agent_is_false() {
        let agents: SharedAgents = Arc::new(RwLock::new(HashMap::new()));
        assert!(!deliver_close_via_control(&agents, "ghost", "s-1", "").await);
    }
}
