//! TCP tunnel stream pump: bidirectional socket ↔ tunnel-frame transfer,
//! shared by the expose edge and mesh ingress.
//!
//! Design motivation (docs/bug/2026-09-13-select-branch-double-await-joinhandle-panic.md):
//! the old implementation `tokio::spawn`ed the read/write halves separately,
//! then `select!`ed two `&mut JoinHandle`s and awaited the winning handle
//! again inside the branch body — polling a JoinHandle already polled to
//! completion, which makes tokio panic ("JoinHandle polled after
//! completion"). This module makes the two halves **inline futures**
//! (`tokio::pin!` + select, no spawn): after the winning branch completes,
//! the loser is cancelled in place when dropped with its scope, ruling out
//! the JoinHandle-and-its-double-poll panic class structurally.
//!
//! Close-out semantics:
//! - **Write half exits first** (peer Close frame / channel closed
//!   (poisoning · peer teardown) / write error / client write stall / idle
//!   timeout): the read half is cancelled by drop (equivalent to the old
//!   implementation's abort — leaving the read half running would hold the
//!   half-open socket until the idle timeout, with the client unable to sense
//!   the abandonment), then the stream is unregistered;
//! - **Read half exits first** (client EOF, TCP half-close): unregister the
//!   stream first (cutting off dispatch delivery of new frames for that
//!   stream), then wait for the write half to drain the frames already
//!   buffered in the channel before exiting — the connection task does not
//!   return before the socket is truly closed, so the caller's connection
//!   accounting no longer misses the detached write-task window.
//!
//! Outcome reporting: the pump returns a [`StreamOutcome`] assembled from
//! **local observation only** (did a peer Close frame reach the write half;
//! were response bytes written to the client socket). This is deliberately
//! race-free: whether the peer's Close *reason* arrives in time is itself a
//! cross-hop race (an HTTP/1.1 keepalive client hangs up first, the hub tears
//! the stream on our request-direction close, and the reason token never
//! lands) — callers deriving health signals from the stream must not depend
//! on that timing (docs/bug/2026-09-17-edge-route-breaker-stuck-open.md).
//!
//! For reference: the egress UDP pump (mesh/src/agent/egress.rs) must spawn
//! (it shares last_active idle supervision etc., which is not isomorphic);
//! its rule "a JoinHandle already polled by select must not be awaited
//! again; on the completion branch only await tasks still pending" is the
//! correct paradigm for spawn-style supervision loops.

use crate::error::Result;
use crate::protocol::CloseReason;
use crate::protocol::FrameType;
use crate::tunnel::AgentTunnel;
use crate::tunnel::transport::TunnelData;
use async_trait::async_trait;
use bytes::{Bytes, BytesMut};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::sync::mpsc;
use tracing::{debug, warn};

/// Lock-free shared progress clock: elapsed-micros since a per-pump epoch,
/// bumped by whichever direction last moved.
///
/// An atomic replaces the earlier `Mutex<Instant>` outright: the mutex's
/// critical section was a single copy, so lock-freedom costs nothing while
/// removing the lock/poison class entirely; `fetch_max` keeps the clock
/// monotonic under concurrent `touch`es. `tokio::time::Instant` is required
/// so paused-clock tests observe the same clock as the `timeout()` waits.
struct SharedProgress {
    epoch: tokio::time::Instant,
    last_progress_us: AtomicU64,
}

impl SharedProgress {
    fn new() -> Self {
        Self {
            epoch: tokio::time::Instant::now(),
            last_progress_us: AtomicU64::new(0),
        }
    }

    /// Marks progress on one direction, extending both halves' deadlines.
    #[allow(clippy::cast_possible_truncation)] // truncation wraps after ~585k
    // years of monotonic clock; the epoch is per-pump, so unreachable
    fn touch(&self) {
        let us = tokio::time::Instant::now()
            .checked_duration_since(self.epoch)
            .map_or(0, |d| d.as_micros() as u64);
        self.last_progress_us.fetch_max(us, Ordering::Release);
    }

    /// Remaining wait until the shared idle budget expires, or `None` when it
    /// already has (no progress on either direction for `budget`).
    fn remaining(&self, budget: Duration) -> Option<Duration> {
        let last = Duration::from_micros(self.last_progress_us.load(Ordering::Acquire));
        let since_last = tokio::time::Instant::now()
            .checked_duration_since(self.epoch)?
            .checked_sub(last)?;
        budget.checked_sub(since_last).filter(|d| !d.is_zero())
    }
}

/// The minimal peer-operation surface needed by a tunnel stream pump.
///
/// These three methods are extracted from [`AgentTunnel`] so the pump can run
/// in unit tests without a real transport backend.
#[async_trait]
pub trait StreamPumpTarget: Send + Sync {
    /// Sends a data frame to the peer (request direction).
    async fn send_data(&self, stream_id: &str, data: Bytes) -> Result<()>;

    /// Notifies the peer of stream teardown (request-direction Close).
    async fn send_close(&self, stream_id: &str) -> Result<()>;

    /// Unregisters this stream's response-direction channel in dispatch
    /// (idempotent).
    ///
    /// Contract: once this returns, dispatch MUST stop delivering new frames
    /// for the stream — the response channel is closed/detached, so the
    /// pump's write half drains what is already buffered and then observes
    /// `None`. This coupling was implicit (undocumented, untested) until the
    /// 2026-09-16 one-way-idle postmortem; it is now part of the trait
    /// contract and mirrored by the pump unit-test mock.
    async fn unregister_stream(&self, stream_id: &str);
}

// Fully-qualified calls forward to AgentTunnel's inherent methods (inherent
// takes precedence over trait methods); writing them as method calls would
// rely on the same precedence rule but with unclear intent, so per clippy
// convention we use `Self::` and keep this note here.
#[allow(clippy::use_self)]
#[async_trait]
impl StreamPumpTarget for AgentTunnel {
    async fn send_data(&self, stream_id: &str, data: Bytes) -> Result<()> {
        Self::send_data(self, stream_id, data).await
    }

    async fn send_close(&self, stream_id: &str) -> Result<()> {
        Self::send_close(self, stream_id).await
    }

    async fn unregister_stream(&self, stream_id: &str) {
        Self::unregister_stream(self, stream_id).await;
    }
}

/// Pump parameters: liveness deadlines + metric counter names (the caller
/// passes existing names so monitoring dashboards see no change).
pub struct PumpConfig {
    /// Shared idle budget: the stream is closed only when NO direction carries
    /// bytes (read side) or frames (write side) for this long — activity on
    /// either side resets both halves' deadlines. A receive-only push stream
    /// (SSE-style consumer that never transmits) therefore survives as long as
    /// the server keeps sending.
    pub idle_timeout: Duration,
    /// Client write-stall deadline: writing one frame to the socket for
    /// longer than this abandons the connection.
    pub write_stall_timeout: Duration,
    /// Idle-timeout counter name (shared by read/write sides, e.g. "interflow_edge_stream_idle_timeout").
    pub idle_timeout_counter: &'static str,
    /// Write-stall counter name (e.g. "interflow_edge_client_write_stall").
    pub write_stall_counter: &'static str,
    /// Log prefix ("edge" / "ingress").
    pub log_label: &'static str,
}

/// How one pumped stream ended, assembled from **local observation only** —
/// immune to the cross-hop delivery race of the peer's Close reason token.
///
/// This is the health-evidence surface for callers like the expose edge route
/// breaker: `response_relayed` proves the far side actually served bytes
/// (observed by the write half writing them to the client socket), while
/// `close_reason` carries the peer's explanation when one arrived in time.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StreamOutcome {
    /// The peer's Close reason, when a Close frame reached the write half
    /// before the stream closed out. `None` = no Close frame observed (the
    /// HTTP/1.1 keepalive norm: the client hangs up first, the stream is torn
    /// down on both sides, and any in-flight reason token is dropped);
    /// `Some(CloseReason::CloseFrame)` = a close arrived without a reason.
    pub close_reason: Option<CloseReason>,
    /// Whether any response-direction payload was written to the client
    /// socket. Distinguishes "the backend served data" from "the connection
    /// merely closed without failure" — a bare connect-and-abort proves
    /// nothing about route health.
    pub response_relayed: bool,
}

/// Bidirectionally pumps one TCP tunnel stream.
///
/// `rd`: the client socket read half; `wr`: the write half; `data_rx`: the
/// response-direction frames delivered by dispatch (obtained by the caller
/// via `register_stream` first). On return, the whole stream has been closed
/// out and unregistered.
///
/// Returns the locally-observed [`StreamOutcome`] (see the struct docs for
/// why the outcome must not depend on the peer Close reason's arrival
/// timing).
///
/// Cancellation safety: this future may be cancelled at any time by an outer
/// select/drop — the socket half and channel half are released in place on
/// drop, losing at most one in-flight data frame (the stream was being torn
/// down anyway).
#[allow(clippy::too_many_arguments)]
pub async fn pump_tcp_stream<R, W, T>(
    rd: R,
    wr: W,
    mut data_rx: mpsc::Receiver<TunnelData>,
    target: &T,
    stream_id: &str,
    cfg: &PumpConfig,
) -> StreamOutcome
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
    T: StreamPumpTarget + ?Sized,
{
    let label = cfg.log_label;

    // Shared idle clock: the instant either direction last made progress.
    // Each half waits only until the budget since that instant elapses and
    // then re-derives its remaining wait, so the peer direction's traffic
    // extends its deadline (the fix for the one-way-idle teardown the soak
    // gate caught on 2026-09-16: receive-only streams died at exactly
    // idle_timeout of stream age no matter how much response data flowed).
    let progress = SharedProgress::new();

    // Read half: socket → tunnel (request direction).
    let read_half = async {
        let mut rd = rd;
        // Reuse the buffer to avoid per-read allocation; use BytesMut::split
        // so the Bytes is zero-copy
        let mut buf = BytesMut::with_capacity(16 * 1024);
        loop {
            // Reserve when capacity runs low; capacity shrinks after split
            if buf.capacity() < 4096 {
                buf.reserve(16 * 1024);
            }
            let Some(remaining) = progress.remaining(cfg.idle_timeout) else {
                metrics::counter!(cfg.idle_timeout_counter).increment(1);
                debug!("{label} stream idle timeout (read side): {stream_id}");
                break;
            };
            match tokio::time::timeout(remaining, rd.read_buf(&mut buf)).await {
                Ok(Ok(0)) => break,
                Ok(Ok(_)) => {
                    progress.touch();
                    let chunk = buf.split().freeze();
                    if let Err(e) = target.send_data(stream_id, chunk).await {
                        warn!("{label} failed to send data: {e}");
                        break;
                    }
                }
                Ok(Err(e)) => {
                    warn!("{label} failed to read socket: {e}");
                    break;
                }
                // Own deadline hit: loop and re-derive from the shared clock —
                // either the write side extended it, or the next iteration's
                // `remaining` expires the stream.
                Err(_) => {}
            }
        }
        // Client direction closed/errored: notify the peer of stream
        // teardown (the write-half-first cancellation path never gets here).
        let _ = target.send_close(stream_id).await;
    };

    // Write half: tunnel → socket (response direction). Sole observer of
    // both outcome facts, so it returns the StreamOutcome itself.
    let write_half = async {
        let mut wr = wr;
        let mut outcome = StreamOutcome {
            close_reason: None,
            response_relayed: false,
        };
        loop {
            let Some(remaining) = progress.remaining(cfg.idle_timeout) else {
                metrics::counter!(cfg.idle_timeout_counter).increment(1);
                debug!("{label} stream idle timeout (write side): {stream_id}");
                break;
            };
            match tokio::time::timeout(remaining, data_rx.recv()).await {
                Ok(Some(msg)) => {
                    progress.touch();
                    if matches!(msg.stream_type, FrameType::Close) {
                        outcome.close_reason = Some(parse_close_reason(stream_id, &msg.data));
                        break;
                    }
                    if !msg.data.is_empty() {
                        match tokio::time::timeout(cfg.write_stall_timeout, wr.write_all(&msg.data))
                            .await
                        {
                            Ok(Ok(())) => outcome.response_relayed = true,
                            Ok(Err(e)) => {
                                warn!("{label} failed to write socket: {e}");
                                break;
                            }
                            Err(_) => {
                                metrics::counter!(cfg.write_stall_counter).increment(1);
                                debug!(
                                    "{label} client response write stalled, closing: {stream_id}"
                                );
                                break;
                            }
                        }
                    }
                }
                // Channel closed = dispatch poisoning / peer teardown / stream already unregistered
                Ok(None) => break,
                // Own deadline hit: re-derive from the shared clock next loop.
                Err(_) => {}
            }
        }
        outcome
    };

    tokio::pin!(read_half, write_half);

    enum HalfDone {
        Read,
        Write(StreamOutcome),
    }
    let done = tokio::select! {
        out = &mut write_half => HalfDone::Write(out),
        () = &mut read_half => HalfDone::Read,
    };

    match done {
        // Write half exits first: the read half is no longer polled and is
        // dropped when this function returns (the half-open socket connection
        // is released with it). No JoinHandle, no close-out await ceremony.
        HalfDone::Write(outcome) => {
            target.unregister_stream(stream_id).await;
            outcome
        }
        // Read half exits first (client EOF, TCP half-close): unregister
        // first to cut off dispatch delivery of new frames for this stream;
        // the write half afterwards only drains frames already buffered in
        // the channel. Awaiting the write half here is legal: it was never
        // polled to Ready — select only selects a branch future when it
        // returns Ready.
        HalfDone::Read => {
            target.unregister_stream(stream_id).await;
            (&mut write_half).await
        }
    }
}

/// Extracts the reason from a `_close_` notification payload.
///
/// The hub emits `CLOSE:{sid}:{reason}` (empty reason = ordinary close);
/// anything that does not carry this prefix (a late/foreign frame) is
/// treated as a reason-less close.
pub(crate) fn parse_close_reason(stream_id: &str, data: &[u8]) -> CloseReason {
    let prefix = format!("CLOSE:{stream_id}:");
    String::from_utf8_lossy(data)
        .strip_prefix(&prefix)
        .map_or(CloseReason::CloseFrame, CloseReason::from_token)
}

/// Pumps one e2e (inner TLS) stream between two full duplex endpoints.
///
/// `local`: the local data endpoint (client socket on the ingress / backend
/// TCP on the egress). `tunnel`: the inner TLS stream over the tunnel side
/// (the handshake already succeeded). The same shared-progress idle clock
/// and write-stall budget discipline as [`pump_tcp_stream`] apply; the
/// write-stall budget guards writes toward `local` (the only sink that can
/// stall — the tunnel side is a channel send with backpressure).
///
/// `cut_delivery` is invoked exactly once before the pump returns (both
/// end paths): it must stop dispatch from delivering new frames for the
/// stream — the ingress unregisters its response channel, the egress its
/// incoming-stream channel (the same contract
/// [`StreamPumpTarget::unregister_stream`] documents for the plain pump).
/// On the local-EOF path it is what converges the drain half: the channel
/// closure surfaces as the tunnel side's EOF.
///
/// End-of-stream choreography (mirroring [`pump_tcp_stream`]'s close-out
/// semantics):
/// - `local` EOF first → `tunnel.shutdown()` (TLS close_notify rides Data
///   frames, then the adapter's Close) and the tunnel→local half drains
///   what is already in flight;
/// - tunnel EOF first (peer Close / channel closure surfaced as EOF by the
///   TLS layer) → `local` is shut down and the pump returns.
///
/// Cancellation safety: same as [`pump_tcp_stream`] — droppable at any
/// time by an outer select, losing at most one in-flight chunk.
pub async fn pump_duplex<L, T, F>(
    local: L,
    tunnel: T,
    cfg: &PumpConfig,
    stream_id: &str,
    cut_delivery: F,
) -> StreamOutcome
where
    L: AsyncRead + AsyncWrite + Unpin,
    T: AsyncRead + AsyncWrite + Unpin,
    F: std::future::Future<Output = ()>,
{
    let label = cfg.log_label;
    let progress = SharedProgress::new();
    // Each half owns the crossed halves of the two endpoints (the same
    // single-reader/single-writer split the plain pump gets for free from
    // `TcpStream::into_split`).
    let (mut local_rd, mut local_wr) = tokio::io::split(local);
    let (mut tunnel_rd, mut tunnel_wr) = tokio::io::split(tunnel);

    // local → tunnel: reads the local endpoint, writes into the inner TLS
    // stream (channel-backed; bounded by the shared idle budget).
    let local_half = async {
        let mut buf = BytesMut::with_capacity(16 * 1024);
        loop {
            if buf.capacity() < 4096 {
                buf.reserve(16 * 1024);
            }
            let Some(remaining) = progress.remaining(cfg.idle_timeout) else {
                metrics::counter!(cfg.idle_timeout_counter).increment(1);
                debug!("{label} e2e stream idle timeout (local side): {stream_id}");
                break;
            };
            match tokio::time::timeout(remaining, local_rd.read_buf(&mut buf)).await {
                Ok(Ok(0)) => break,
                Ok(Ok(_)) => {
                    progress.touch();
                    let chunk = buf.split().freeze();
                    if let Err(e) = tunnel_wr.write_all(&chunk).await {
                        debug!("{label} e2e tunnel write failed: {e}");
                        break;
                    }
                    if let Err(e) = tunnel_wr.flush().await {
                        debug!("{label} e2e tunnel flush failed: {e}");
                        break;
                    }
                }
                Ok(Err(e)) => {
                    debug!("{label} failed to read local endpoint: {e}");
                    break;
                }
                Err(_) => {}
            }
        }
        // Local direction ended: send the TLS close_notify through the
        // tunnel (Data frames), then the adapter's stream close.
        let _ = tunnel_wr.shutdown().await;
    };

    // tunnel → local: sole observer of the outcome facts.
    let tunnel_half = async {
        let mut outcome = StreamOutcome {
            close_reason: None,
            response_relayed: false,
        };
        let mut buf = BytesMut::with_capacity(16 * 1024);
        loop {
            if buf.capacity() < 4096 {
                buf.reserve(16 * 1024);
            }
            let Some(remaining) = progress.remaining(cfg.idle_timeout) else {
                metrics::counter!(cfg.idle_timeout_counter).increment(1);
                debug!("{label} e2e stream idle timeout (tunnel side): {stream_id}");
                break;
            };
            match tokio::time::timeout(remaining, tunnel_rd.read_buf(&mut buf)).await {
                Ok(Ok(0)) => break, // peer Close / channel EOF via the TLS layer
                Ok(Ok(_)) => {
                    progress.touch();
                    let chunk = buf.split().freeze();
                    match tokio::time::timeout(cfg.write_stall_timeout, local_wr.write_all(&chunk))
                        .await
                    {
                        Ok(Ok(())) => outcome.response_relayed = true,
                        Ok(Err(e)) => {
                            debug!("{label} failed to write local endpoint: {e}");
                            break;
                        }
                        Err(_) => {
                            metrics::counter!(cfg.write_stall_counter).increment(1);
                            debug!("{label} local write stalled, closing: {stream_id}");
                            break;
                        }
                    }
                }
                Ok(Err(e)) => {
                    // Missing close_notify and similar TLS-layer reports of
                    // the peer's departure end the stream the same way.
                    debug!("{label} e2e tunnel read ended: {e}");
                    break;
                }
                Err(_) => {}
            }
        }
        // Tunnel side done: half-close the local endpoint so its reader
        // sees the end (best effort — a dead socket still ends the pump).
        let _ = local_wr.shutdown().await;
        outcome
    };

    tokio::pin!(local_half, tunnel_half, cut_delivery);

    enum HalfDone {
        Local,
        Tunnel(StreamOutcome),
    }
    let done = tokio::select! {
        out = &mut tunnel_half => HalfDone::Tunnel(out),
        () = &mut local_half => HalfDone::Local,
    };
    // Dispatch stops delivering for this stream before the pump returns —
    // on the local-EOF path that closure is what converges the drain half.
    (&mut cut_delivery).await;

    match done {
        // Tunnel side ended (peer Close / EOF): the local endpoint is
        // dropped with this function — nothing more to relay.
        HalfDone::Tunnel(outcome) => outcome,
        // Local endpoint EOF: drain the tunnel→local direction until the
        // peer's Close arrives (our close_notify went out in the local
        // half's epilogue; the cut channel closure ends the drain).
        HalfDone::Local => (&mut tunnel_half).await,
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
    use std::sync::Arc;
    use std::sync::Mutex as StdMutex;
    use tokio::io::{AsyncReadExt, AsyncWriteExt, duplex};

    /// Recording mock: asserts the pump's calls to the tunnel side.
    #[derive(Default)]
    struct MockTarget {
        data: StdMutex<Vec<Bytes>>,
        closes: StdMutex<Vec<String>>,
        unregisters: StdMutex<Vec<String>>,
        /// Mirrors the dispatch contract: a clone of the response channel's
        /// sender, dropped on `unregister_stream`, so "unregister cuts frame
        /// delivery" is exercised in unit tests too — the write half exits
        /// via its natural `Ok(None)` once the test's own senders are gone.
        response_tx: StdMutex<Option<mpsc::Sender<TunnelData>>>,
    }

    impl MockTarget {
        fn sent_data(&self) -> Vec<Bytes> {
            self.data.lock().unwrap().clone()
        }
        fn close_calls(&self) -> Vec<String> {
            self.closes.lock().unwrap().clone()
        }
        fn unregister_events(&self) -> Vec<String> {
            self.unregisters.lock().unwrap().clone()
        }
        /// Arms the dispatch-contract mirror with a clone of the sender.
        fn mirror_dispatch_channel(&self, tx: &mpsc::Sender<TunnelData>) {
            *self.response_tx.lock().unwrap() = Some(tx.clone());
        }
    }

    #[async_trait]
    impl StreamPumpTarget for MockTarget {
        async fn send_data(&self, _stream_id: &str, data: Bytes) -> Result<()> {
            self.data.lock().unwrap().push(data);
            Ok(())
        }
        async fn send_close(&self, stream_id: &str) -> Result<()> {
            self.closes.lock().unwrap().push(stream_id.to_string());
            Ok(())
        }
        async fn unregister_stream(&self, stream_id: &str) {
            self.unregisters.lock().unwrap().push(stream_id.to_string());
            // Dispatch contract: cut frame delivery for this stream.
            *self.response_tx.lock().unwrap() = None;
        }
    }

    fn td(ftype: FrameType, data: &[u8]) -> TunnelData {
        TunnelData {
            stream_id: "s1".to_string(),
            source: crate::tunnel::transport::FrameSource::Response,
            data: Bytes::copy_from_slice(data),
            stream_type: ftype,
            flags: 0,
        }
    }

    fn test_cfg() -> PumpConfig {
        PumpConfig {
            idle_timeout: Duration::from_secs(30),
            write_stall_timeout: Duration::from_millis(50),
            idle_timeout_counter: "interflow_pump_test_idle",
            write_stall_counter: "interflow_pump_test_stall",
            log_label: "pump-test",
        }
    }

    /// Peer Close frame (hub rejecting the Open / peer teardown) → the pump
    /// closes out + unregisters exactly once + the socket closes, and the
    /// reason token is decoded into the outcome. A unit-level reproduction of
    /// the agent-offline scenario (the production trigger chain of the
    /// 2026-09-13 bug).
    #[tokio::test]
    async fn close_frame_ends_pump_and_unregisters_once() {
        let (sock, mut peer) = duplex(64 * 1024);
        let (rd, wr) = tokio::io::split(sock);
        let (tx, rx) = mpsc::channel(8);
        let target = MockTarget::default();
        tx.send(td(FrameType::Close, b"CLOSE:s1:connect_failed"))
            .await
            .unwrap();

        let outcome = pump_tcp_stream(rd, wr, rx, &target, "s1", &test_cfg()).await;

        assert_eq!(outcome.close_reason, Some(CloseReason::ConnectFailed));
        assert!(!outcome.response_relayed);
        assert_eq!(target.unregister_events(), vec!["s1".to_string()]);
        // After the pump returns the write half is dropped: the client reads EOF
        let mut buf = [0u8; 1];
        assert_eq!(peer.read(&mut buf).await.unwrap(), 0);
    }

    /// A Close notification without a parsable reason payload decodes to the
    /// ordinary reason-less close (`Some(CloseReason::CloseFrame)`), not None:
    /// a close frame WAS observed.
    #[tokio::test]
    async fn reasonless_close_frame_decodes_to_closeframe() {
        let (sock, _peer) = duplex(64 * 1024);
        let (rd, wr) = tokio::io::split(sock);
        let (tx, rx) = mpsc::channel(8);
        let target = MockTarget::default();
        tx.send(td(FrameType::Close, b"")).await.unwrap();

        let outcome = pump_tcp_stream(rd, wr, rx, &target, "s1", &test_cfg()).await;

        assert_eq!(outcome.close_reason, Some(CloseReason::CloseFrame));
        assert_eq!(target.unregister_events(), vec!["s1".to_string()]);
    }

    /// Regression (the exact shape of the 2026-09-17 stuck-OPEN bug): an
    /// HTTP/1.1 keepalive client hangs up first — the read half exits, the
    /// stream is unregistered, and the peer's Close reason never lands (the
    /// hub tears the stream on our request-direction close; nothing is in
    /// flight). The pump must still report the locally-observed facts: no
    /// close reason, but response bytes WERE relayed — the race-free evidence
    /// the edge route breaker's probe accounting is built on.
    #[tokio::test(start_paused = true)]
    async fn client_first_close_reports_relayed_without_reason() {
        let (sock, mut peer) = duplex(64 * 1024);
        let (rd, wr) = tokio::io::split(sock);
        let (tx, rx) = mpsc::channel(8);
        let target = MockTarget::default();
        tx.send(td(FrameType::Data, b"resp-1")).await.unwrap();
        tx.send(td(FrameType::Data, b"resp-2")).await.unwrap();
        target.mirror_dispatch_channel(&tx);
        // The backend finished responding; no Close ever arrives.
        drop(tx);

        peer.write_all(b"GET / HTTP/1.1\r\nHost: x\r\n\r\n")
            .await
            .unwrap();
        peer.shutdown().await.unwrap();

        let outcome = pump_tcp_stream(rd, wr, rx, &target, "s1", &test_cfg()).await;

        assert_eq!(outcome.close_reason, None);
        assert!(
            outcome.response_relayed,
            "response bytes were written to the client before it hung up"
        );
    }

    /// A bare connect-and-abort (client leaves before any response frame)
    /// reports NO evidence: nothing relayed, no reason — callers must treat
    /// it as neutral, not as recovery proof.
    #[tokio::test(start_paused = true)]
    async fn bare_connect_aborts_without_evidence() {
        let (sock, mut peer) = duplex(64 * 1024);
        let (rd, wr) = tokio::io::split(sock);
        let (tx, rx) = mpsc::channel(8);
        let target = MockTarget::default();
        // Held open with no frames; the unregister cut ends the write half.
        target.mirror_dispatch_channel(&tx);

        peer.write_all(b"req").await.unwrap();
        peer.shutdown().await.unwrap();

        let outcome = pump_tcp_stream(rd, wr, rx, &target, "s1", &test_cfg()).await;

        assert_eq!(outcome.close_reason, None);
        assert!(!outcome.response_relayed);
    }

    /// Client EOF (TCP half-close): read-side data goes to the tunnel +
    /// send_close, then unregister and flush every response frame already
    /// buffered in the channel to the socket.
    #[tokio::test(start_paused = true)]
    async fn client_eof_flushes_buffered_frames_then_unregisters() {
        let (sock, mut peer) = duplex(64 * 1024);
        let (rd, wr) = tokio::io::split(sock);
        let (tx, rx) = mpsc::channel(8);
        let target = MockTarget::default();
        tx.send(td(FrameType::Data, b"resp-1")).await.unwrap();
        tx.send(td(FrameType::Data, b"resp-2")).await.unwrap();
        target.mirror_dispatch_channel(&tx);
        // The backend finished responding: dropping the test-side sender lets
        // the write half exit via its natural `Ok(None)` after the drain,
        // instead of riding the idle budget to expiry.
        drop(tx);

        peer.write_all(b"req").await.unwrap();
        peer.shutdown().await.unwrap();

        pump_tcp_stream(rd, wr, rx, &target, "s1", &test_cfg()).await;

        assert_eq!(target.sent_data(), vec![Bytes::from_static(b"req")]);
        assert_eq!(target.close_calls(), vec!["s1".to_string()]);
        assert_eq!(target.unregister_events(), vec!["s1".to_string()]);
        let mut got = Vec::new();
        peer.read_to_end(&mut got).await.unwrap();
        assert_eq!(got, b"resp-1resp-2");
    }

    /// Client not reading (send buffer full): the write-stall deadline closes
    /// out the pump instead of hanging forever on write_all.
    #[tokio::test(start_paused = true)]
    async fn write_stall_terminates_pump() {
        let (sock, _peer_stays_alive) = duplex(8);
        let (rd, wr) = tokio::io::split(sock);
        let (tx, rx) = mpsc::channel(8);
        let target = MockTarget::default();
        // Frame larger than the duplex buffer with a non-reading peer →
        // write_all hangs → stall timeout
        tx.send(td(FrameType::Data, &[7u8; 64])).await.unwrap();

        pump_tcp_stream(rd, wr, rx, &target, "s1", &test_cfg()).await;

        assert_eq!(target.unregister_events(), vec!["s1".to_string()]);
    }

    /// Channel closed (dispatch poisoning / peer teardown / already
    /// unregistered) → the write half gets Ok(None) and closes out.
    #[tokio::test]
    async fn channel_close_terminates_pump() {
        let (sock, _peer) = duplex(64 * 1024);
        let (rd, wr) = tokio::io::split(sock);
        let (tx, rx) = mpsc::channel(8);
        drop(tx);
        let target = MockTarget::default();

        pump_tcp_stream(rd, wr, rx, &target, "s1", &test_cfg()).await;

        assert_eq!(target.unregister_events(), vec!["s1".to_string()]);
    }

    /// Peer gone: a socket write error closes out the pump.
    #[tokio::test]
    async fn socket_write_error_terminates_pump() {
        let (sock, peer) = duplex(64 * 1024);
        let (rd, wr) = tokio::io::split(sock);
        drop(peer);
        let (tx, rx) = mpsc::channel(8);
        let target = MockTarget::default();
        tx.send(td(FrameType::Data, b"x")).await.unwrap();

        pump_tcp_stream(rd, wr, rx, &target, "s1", &test_cfg()).await;

        assert_eq!(target.unregister_events(), vec!["s1".to_string()]);
    }

    /// Regression (caught by the soak gate's first full-duration run,
    /// 2026-09-16): a receive-only stream — the client never transmits a
    /// single byte, like an SSE/token-stream consumer — must survive beyond
    /// `idle_timeout` while the tunnel keeps delivering response frames.
    /// Pre-fix semantics gave each half its own timer, so the read side
    /// expired at exactly idle_timeout of stream age regardless of
    /// response-direction traffic (killing every push-style stream at 300s
    /// under production defaults).
    #[tokio::test(start_paused = true)]
    async fn one_way_response_traffic_keeps_stream_alive_beyond_idle() {
        let (sock, _peer_quiet) = duplex(64 * 1024);
        let (rd, wr) = tokio::io::split(sock);
        let (tx, rx) = mpsc::channel(8);
        let target = Arc::new(MockTarget::default());
        target.mirror_dispatch_channel(&tx);

        let mut cfg = test_cfg();
        cfg.idle_timeout = Duration::from_millis(100);

        // 20 frames × 25ms = 500ms of response-direction activity, then the
        // channel closes (the pump's natural end via Ok(None)).
        let feeder = tokio::spawn(async move {
            for _ in 0..20 {
                tokio::time::sleep(Duration::from_millis(25)).await;
                if tx.send(td(FrameType::Data, b"tick")).await.is_err() {
                    break;
                }
            }
            drop(tx);
        });

        let started = tokio::time::Instant::now();
        let t = Arc::clone(&target);
        let pump = tokio::spawn(async move {
            pump_tcp_stream(rd, wr, rx, &*t, "s1", &cfg).await;
        });

        // Mid-run probe at 3× the idle budget with response frames flowing:
        // the stream must show NO teardown traces. Teardown evidence — not
        // pump-return timing — stays the decisive assertion even with the
        // mock mirroring the dispatch channel-cut contract: the feeder's
        // live sender keeps the channel open, so a buggy early unregister
        // would not by itself end the pump; only the traces reveal it.
        tokio::time::sleep(Duration::from_millis(300)).await;
        assert!(
            target.unregister_events().is_empty() && target.close_calls().is_empty(),
            "one-way idle tore down an actively served push stream mid-run"
        );

        pump.await.unwrap();
        let elapsed = started.elapsed();
        feeder.await.unwrap();

        assert!(
            elapsed >= Duration::from_millis(450),
            "pump died after {elapsed:?} — one-way idle tore down an actively served push stream"
        );
        assert_eq!(target.unregister_events(), vec!["s1".to_string()]);
    }

    /// The shared budget still expires: with no traffic in either direction
    /// the stream is torn down at the idle deadline (anti-zombie semantics,
    /// unchanged by the shared-clock fix).
    #[tokio::test(start_paused = true)]
    async fn both_directions_silent_expires_shared_idle() {
        let (sock, _peer) = duplex(64 * 1024);
        let (rd, wr) = tokio::io::split(sock);
        let (tx, rx) = mpsc::channel(8); // held open, deliberately silent
        let target = MockTarget::default();

        let mut cfg = test_cfg();
        cfg.idle_timeout = Duration::from_millis(120);

        let started = tokio::time::Instant::now();
        pump_tcp_stream(rd, wr, rx, &target, "s1", &cfg).await;
        let elapsed = started.elapsed();
        drop(tx);

        assert!(
            elapsed >= Duration::from_millis(100) && elapsed <= Duration::from_millis(250),
            "idle teardown fired at {elapsed:?}, expected ~120ms"
        );
        assert_eq!(target.unregister_events(), vec!["s1".to_string()]);
    }

    // ---- pump_duplex (e2e streams) ----

    /// Tunnel side EOF: buffered tunnel data is relayed to the local
    /// endpoint first, then the pump returns and shuts the local side.
    #[tokio::test]
    async fn duplex_tunnel_eof_relays_data_then_closes_local() {
        let (local, mut local_peer) = duplex(64 * 1024);
        let (tunnel, mut tunnel_peer) = duplex(64 * 1024);

        tunnel_peer.write_all(b"resp-data").await.unwrap();
        drop(tunnel_peer); // peer Close → tunnel EOF

        let outcome = pump_duplex(local, tunnel, &test_cfg(), "s1", async {}).await;
        assert!(
            outcome.response_relayed,
            "tunnel bytes must reach the local end"
        );

        let mut got = Vec::new();
        local_peer.read_to_end(&mut got).await.unwrap();
        assert_eq!(got, b"resp-data");
    }

    /// Local endpoint EOF: its bytes flow to the tunnel side, the shutdown
    /// propagates, and the pump returns after draining the reverse
    /// direction (no unregister — that stays with the caller).
    #[tokio::test]
    async fn duplex_local_eof_forwards_and_returns() {
        let (local, mut local_peer) = duplex(64 * 1024);
        let (tunnel, mut tunnel_peer) = duplex(64 * 1024);

        local_peer.write_all(b"req-data").await.unwrap();
        local_peer.shutdown().await.unwrap();

        // Tunnel peer: collects the request, then departs so the drain ends.
        let tunnel_side = tokio::spawn(async move {
            let mut got = Vec::new();
            tunnel_peer.read_to_end(&mut got).await.unwrap();
            got
        });

        let outcome = pump_duplex(local, tunnel, &test_cfg(), "s1", async {}).await;
        assert!(!outcome.response_relayed);
        assert_eq!(tunnel_side.await.unwrap(), b"req-data");
    }

    /// A non-reading local endpoint hits the write-stall budget and ends
    /// the pump (the only stallable sink is the local endpoint).
    #[tokio::test(start_paused = true)]
    async fn duplex_write_stall_terminates_pump() {
        let (local, _non_reading_peer) = duplex(8);
        let (tunnel, mut tunnel_peer) = duplex(64 * 1024);
        tunnel_peer.write_all(&[7u8; 64]).await.unwrap();

        pump_duplex(local, tunnel, &test_cfg(), "s1", async {}).await;
        // Reaching here at all is the assertion: the stall budget fired
        // instead of hanging forever on write_all.
    }
}
