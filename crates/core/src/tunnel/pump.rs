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
//! For reference: the egress UDP pump (mesh/src/agent/egress.rs) must spawn
//! (it shares last_active idle supervision etc., which is not isomorphic);
//! its rule "a JoinHandle already polled by select must not be awaited
//! again; on the completion branch only await tasks still pending" is the
//! correct paradigm for spawn-style supervision loops.

use crate::error::Result;
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

/// Bidirectionally pumps one TCP tunnel stream.
///
/// `rd`: the client socket read half; `wr`: the write half; `data_rx`: the
/// response-direction frames delivered by dispatch (obtained by the caller
/// via `register_stream` first). On return, the whole stream has been closed
/// out and unregistered.
///
/// `close_reason`: when `Some`, the write half reports the reason token
/// carried by the peer's Close notification (`CLOSE:{sid}:{reason}` payload;
/// empty string = ordinary close / no Close observed, e.g. the client side
/// disconnected first) — the hook the expose edge uses for route-level
/// negative caching (2026-09-16 reason propagation).
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
    close_reason: Option<tokio::sync::oneshot::Sender<String>>,
) where
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

    // Write half: tunnel → socket (response direction).
    let mut close_reason_tx = close_reason;
    let write_half = async {
        let mut wr = wr;
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
                        if let Some(tx) = close_reason_tx.take() {
                            // Dropping without send also communicates "no
                            // reason" (receiver treats Err as empty), but
                            // sending "" keeps the channel semantics
                            // unambiguous.
                            let _ = tx.send(parse_close_reason(stream_id, &msg.data));
                        }
                        break;
                    }
                    if !msg.data.is_empty() {
                        match tokio::time::timeout(cfg.write_stall_timeout, wr.write_all(&msg.data))
                            .await
                        {
                            Ok(Ok(())) => {}
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
    };

    tokio::pin!(read_half, write_half);

    enum HalfDone {
        Read,
        Write,
    }
    let done = tokio::select! {
        () = &mut write_half => HalfDone::Write,
        () = &mut read_half => HalfDone::Read,
    };

    match done {
        // Write half exits first: the read half is no longer polled and is
        // dropped when this function returns (the half-open socket connection
        // is released with it). No JoinHandle, no close-out await ceremony.
        HalfDone::Write => {
            target.unregister_stream(stream_id).await;
        }
        // Read half exits first (client EOF, TCP half-close): unregister
        // first to cut off dispatch delivery of new frames for this stream;
        // the write half afterwards only drains frames already buffered in
        // the channel. Awaiting the write half here is legal: it was never
        // polled to Ready — select only selects a branch future when it
        // returns Ready.
        HalfDone::Read => {
            target.unregister_stream(stream_id).await;
            (&mut write_half).await;
        }
    }
}

/// Extracts the reason token from a `_close_` notification payload.
///
/// The hub emits `CLOSE:{sid}:{reason}` (empty reason = ordinary close);
/// anything that does not carry this prefix (a late/foreign frame) is
/// treated as reason-less.
fn parse_close_reason(stream_id: &str, data: &[u8]) -> String {
    let prefix = format!("CLOSE:{stream_id}:");
    String::from_utf8_lossy(data)
        .strip_prefix(&prefix)
        .unwrap_or("")
        .to_string()
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
    /// closes out + unregisters exactly once + the socket closes. A
    /// unit-level reproduction of the agent-offline scenario (the production
    /// trigger chain of the 2026-09-13 bug).
    #[tokio::test]
    async fn close_frame_ends_pump_and_unregisters_once() {
        let (sock, mut peer) = duplex(64 * 1024);
        let (rd, wr) = tokio::io::split(sock);
        let (tx, rx) = mpsc::channel(8);
        let target = MockTarget::default();
        tx.send(td(FrameType::Close, b"")).await.unwrap();

        pump_tcp_stream(rd, wr, rx, &target, "s1", &test_cfg(), None).await;

        assert_eq!(target.unregister_events(), vec!["s1".to_string()]);
        // After the pump returns the write half is dropped: the client reads EOF
        let mut buf = [0u8; 1];
        assert_eq!(peer.read(&mut buf).await.unwrap(), 0);
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

        pump_tcp_stream(rd, wr, rx, &target, "s1", &test_cfg(), None).await;

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

        pump_tcp_stream(rd, wr, rx, &target, "s1", &test_cfg(), None).await;

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

        pump_tcp_stream(rd, wr, rx, &target, "s1", &test_cfg(), None).await;

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

        pump_tcp_stream(rd, wr, rx, &target, "s1", &test_cfg(), None).await;

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
            pump_tcp_stream(rd, wr, rx, &*t, "s1", &cfg, None).await;
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
        pump_tcp_stream(rd, wr, rx, &target, "s1", &cfg, None).await;
        let elapsed = started.elapsed();
        drop(tx);

        assert!(
            elapsed >= Duration::from_millis(100) && elapsed <= Duration::from_millis(250),
            "idle teardown fired at {elapsed:?}, expected ~120ms"
        );
        assert_eq!(target.unregister_events(), vec!["s1".to_string()]);
    }
}
