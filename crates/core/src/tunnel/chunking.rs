//! h2 body chunk hygiene: the single enforcement point for wire-safe body
//! chunking on every long-lived HTTP/2 tunnel stream (`/poll` response,
//! `/stream/up` request).
//!
//! Why this exists (2026-09-17 GOAWAY churn bug,
//! (internal design notes)): HTTP body chunk
//! boundaries become h2 DATA frame boundaries, and h2 ≥ 0.4.16 (anti
//! framing-overhead DoS hardening) *accounts* those boundaries:
//!
//! - every received non-final DATA frame smaller than 256 bytes consumes
//!   `256 − len` from a 25600-byte budget at **receipt**; the budget is only
//!   returned when the application consumes the frame — so frames buffered
//!   in an unconsumed recv queue (e.g. under egress backpressure) hold their
//!   deduction, and ~113 stalled small frames kill the whole connection with
//!   `GOAWAY ENHANCE_YOUR_CALM "too_many_data_frames"`;
//! - every received non-final **empty** DATA frame increments a separate
//!   cumulative counter capped at 100 **with no release path at all** — the
//!   frame is dropped inside h2 and never reaches the application
//!   (upstream hyperium/h2#944: non-final 0-byte DATA frames are considered
//!   protocol abuse with no legitimate use case).
//!
//! hyper (through 1.11.1) forwards empty body chunks as real empty DATA
//! frames ("zero-length data frames need no capacity; send them straight
//! through"), so the sender must not emit them.
//!
//! This adapter enforces three invariants on everything it emits, regardless
//! of which code produced the frames:
//!
//! 1. **never** an empty non-final data chunk (the 25-minute session-killer:
//!    one heartbeat Ping per 15 s carried an empty payload chunk → the 101st
//!    empty frame GOAWAY'd the connection at exactly 1514.1 s);
//! 2. consecutive small chunks are coalesced opportunistically up to
//!    [`H2_SMALL_FRAME_THRESHOLD`], so bursts and backlogged sends become
//!    few large DATA frames that are budget-*neutral at receipt. No timers:
//!    a trailing small chunk is flushed as soon as the inner stream goes
//!    Pending, keeping idle-path latency identical to today (steady-state
//!    accounting is balanced by consumption-side release);
//! 3. chunks already ≥ [`H2_SMALL_FRAME_THRESHOLD`] pass through untouched
//!    (`Bytes` moved, zero copy) — the large-payload fast path keeps its
//!    performance contract.
//!
//! Chunk merging is invisible to peers: both h2 receivers in this codebase
//! accumulate body bytes into a `BytesMut` and decode frames incrementally
//! (`drain_poll_response` / `upload_reader`), so DATA frame boundaries carry
//! no semantics.

use bytes::{Bytes, BytesMut};
use futures::Stream;
use hyper::body::Frame;
use std::pin::Pin;
use std::task::{Context, Poll};

/// The h2 framing-overhead threshold (mirrors h2's
/// `DEFAULT_DATA_FRAME_OVERHEAD_THRESHOLD`): DATA frames at or above this
/// size never consume the receiver's small-frame budget.
pub const H2_SMALL_FRAME_THRESHOLD: usize = 256;

/// Wire-hygiene adapter over an h2 body chunk stream; see the module docs
/// for the invariants and their rationale.
///
/// The inner stream is pin-boxed so any `Stream` can be wrapped without
/// `Unpin` bounds or unsafe projection. Item errors pass through (after any
/// staged bytes have been flushed, so no data is lost ahead of an error).
pub struct ChunkHygiene<S, E> {
    inner: Pin<Box<S>>,
    /// Small chunks (< [`H2_SMALL_FRAME_THRESHOLD`]) accumulate here until
    /// the threshold is reached or the inner stream goes Pending / ends.
    /// Bounded: flushed at ≥ threshold, so it never holds more than one
    /// small chunk beyond the threshold.
    staging: BytesMut,
    /// One-slot out-queue used to keep ordering when a flush and a
    /// pass-through frame must be emitted back to back. The error is boxed
    /// so the adapter is `Unpin` for any error type (no pin projection
    /// needed).
    pending: Option<Result<Frame<Bytes>, Box<E>>>,
}

impl<S, E> ChunkHygiene<S, E>
where
    S: Stream<Item = Result<Frame<Bytes>, E>>,
{
    /// Wraps an h2 body chunk stream.
    pub fn new(inner: S) -> Self {
        Self {
            inner: Box::pin(inner),
            staging: BytesMut::new(),
            pending: None,
        }
    }

    /// Takes the staged bytes once they have reached the coalescing
    /// threshold (the burst path: emit as one large DATA frame).
    fn take_staged_full(&mut self) -> Option<Frame<Bytes>> {
        (self.staging.len() >= H2_SMALL_FRAME_THRESHOLD)
            .then(|| Frame::data(self.staging.split().freeze()))
    }

    /// Takes whatever is staged (the drain path — inner Pending / ended /
    /// a pass-through frame must not be held back by a small tail).
    fn take_staged_any(&mut self) -> Option<Frame<Bytes>> {
        (!self.staging.is_empty()).then(|| Frame::data(self.staging.split().freeze()))
    }
}

impl<S, E> Stream for ChunkHygiene<S, E>
where
    S: Stream<Item = Result<Frame<Bytes>, E>>,
{
    type Item = Result<Frame<Bytes>, E>;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let this = self.get_mut();
        loop {
            if let Some(item) = this.pending.take() {
                return Poll::Ready(Some(item.map_err(|e| *e)));
            }
            if let Some(frame) = this.take_staged_full() {
                return Poll::Ready(Some(Ok(frame)));
            }
            match this.inner.as_mut().poll_next(cx) {
                Poll::Ready(Some(Ok(frame))) => {
                    // Non-data frames (trailers etc.) keep their position:
                    // staged bytes go out first. `into_data` hands the frame
                    // back on the error arm.
                    let data = match frame.into_data() {
                        Ok(data) => data,
                        Err(frame) => {
                            this.pending = Some(Ok(frame));
                            if let Some(staged) = this.take_staged_any() {
                                return Poll::Ready(Some(Ok(staged)));
                            }
                            continue;
                        }
                    };
                    // Invariant 1: empty non-final chunks never reach the wire.
                    if data.is_empty() {
                        continue;
                    }
                    // Invariant 3: large chunks pass through zero-copy; any
                    // staged bytes precede them (invariant: FIFO order).
                    if data.len() >= H2_SMALL_FRAME_THRESHOLD {
                        if let Some(staged) = this.take_staged_any() {
                            this.pending = Some(Ok(Frame::data(data)));
                            return Poll::Ready(Some(Ok(staged)));
                        }
                        return Poll::Ready(Some(Ok(Frame::data(data))));
                    }
                    // Invariant 2: coalesce; the loop head flushes once the
                    // threshold is reached.
                    this.staging.extend_from_slice(&data);
                }
                Poll::Ready(Some(Err(e))) => {
                    // Flush staged bytes ahead of the error (lossless).
                    if let Some(staged) = this.take_staged_any() {
                        this.pending = Some(Err(Box::new(e)));
                        return Poll::Ready(Some(Ok(staged)));
                    }
                    return Poll::Ready(Some(Err(e)));
                }
                Poll::Ready(None) => {
                    // Inner ended: flush the tail (may be small — see the
                    // module docs), then the next iteration returns None.
                    if let Some(staged) = this.take_staged_any() {
                        return Poll::Ready(Some(Ok(staged)));
                    }
                    return Poll::Ready(None);
                }
                Poll::Pending => {
                    // Invariant 2's no-timer flush: a chunk must not wait for
                    // a successor that may never come.
                    if let Some(staged) = this.take_staged_any() {
                        return Poll::Ready(Some(Ok(staged)));
                    }
                    return Poll::Pending;
                }
            }
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
    use futures::StreamExt;
    use futures::stream;
    use std::convert::Infallible;

    type ChunkStream = stream::Iter<std::vec::IntoIter<Result<Frame<Bytes>, Infallible>>>;

    fn chunks(parts: Vec<Frame<Bytes>>) -> ChunkStream {
        let iter = parts.into_iter().map(Ok).collect::<Vec<_>>().into_iter();
        stream::iter(iter)
    }

    fn data(n: usize) -> Bytes {
        Bytes::from(vec![0xA5; n])
    }

    fn into_data(frame: Frame<Bytes>) -> Bytes {
        let Ok(bytes) = frame.into_data() else {
            panic!("expected a data frame");
        };
        bytes
    }

    /// Invariant 1: empty chunks never reach the wire, in any mix.
    #[tokio::test]
    async fn empty_chunks_are_dropped() {
        let out: Vec<Bytes> = ChunkHygiene::new(chunks(vec![
            Frame::data(Bytes::new()),
            Frame::data(data(64)),
            Frame::data(Bytes::new()),
            Frame::data(Bytes::new()),
            Frame::data(data(32)),
        ]))
        .map(|item| into_data(item.unwrap()))
        .collect()
        .await;
        // One coalesced flush at end-of-stream: 64B + 32B = 96B, no empties.
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].len(), 96);
        assert!(out.iter().all(|c| !c.is_empty()));
    }

    /// A stream of only empty chunks yields no data frames at all.
    #[tokio::test]
    async fn all_empty_chunks_yield_nothing() {
        let out: Vec<Bytes> = ChunkHygiene::new(chunks(vec![
            Frame::data(Bytes::new()),
            Frame::data(Bytes::new()),
        ]))
        .map(|item| into_data(item.unwrap()))
        .collect()
        .await;
        assert!(out.is_empty());
    }

    /// Invariant 2: consecutive small chunks coalesce into one ≥256B chunk.
    #[tokio::test]
    async fn small_chunks_coalesce_to_threshold() {
        let out: Vec<Bytes> = ChunkHygiene::new(chunks(vec![
            Frame::data(data(100)),
            Frame::data(data(100)),
            Frame::data(data(100)),
        ]))
        .map(|item| into_data(item.unwrap()))
        .collect()
        .await;
        assert_eq!(out.len(), 1, "all three should coalesce into one chunk");
        assert_eq!(out[0].len(), 300);
        assert_eq!(out[0].as_ref(), vec![0xA5; 300].as_slice());
    }

    /// Invariant 3: a chunk ≥ threshold passes through untouched (zero copy)
    /// while preceding staged bytes flush first (order preserved).
    #[tokio::test]
    async fn large_chunk_passes_through_zero_copy_after_staging_flush() {
        let big = data(1024);
        let big_ptr = big.as_ptr();
        let out: Vec<Bytes> = ChunkHygiene::new(chunks(vec![
            Frame::data(data(100)),
            Frame::data(big.clone()),
        ]))
        .map(|item| into_data(item.unwrap()))
        .collect()
        .await;
        assert_eq!(out.len(), 2);
        assert_eq!(out[0].len(), 100, "staged small chunk flushes first");
        assert_eq!(out[1].len(), 1024);
        assert_eq!(out[1].as_ptr(), big_ptr, "large chunk must not be copied");
    }

    /// The staging flush fires as soon as the inner stream goes Pending — a
    /// small chunk must not wait for a successor (no added latency).
    #[tokio::test]
    async fn pending_inner_flushes_staging() {
        let (tx, mut rx) = tokio::sync::mpsc::channel::<Frame<Bytes>>(8);
        let inner = stream::poll_fn(move |cx| rx.poll_recv(cx).map(|i| i.map(Ok)));
        let mut hygiene: ChunkHygiene<_, Infallible> = ChunkHygiene::new(inner);

        tx.send(Frame::data(data(64))).await.unwrap();
        let first = tokio::time::timeout(std::time::Duration::from_secs(1), hygiene.next())
            .await
            .expect("staged chunk must flush without waiting for more input")
            .unwrap()
            .unwrap();
        assert_eq!(into_data(first).len(), 64);

        drop(tx);
        assert!(hygiene.next().await.is_none());
    }

    /// Non-data frames (trailers) keep their position relative to staged data.
    #[tokio::test]
    async fn trailers_flush_staging_first() {
        let trailers = Frame::trailers(http::HeaderMap::new());
        let mut hygiene = ChunkHygiene::new(chunks(vec![
            Frame::data(data(50)),
            trailers,
            Frame::data(data(60)),
        ]));

        let first = into_data(hygiene.next().await.unwrap().unwrap());
        assert_eq!(first.len(), 50, "staged bytes precede the trailers");
        let second = hygiene.next().await.unwrap().unwrap();
        assert!(second.is_trailers(), "trailers frame passes through");
        let third = into_data(hygiene.next().await.unwrap().unwrap());
        assert_eq!(third.len(), 60);
        assert!(hygiene.next().await.is_none());
    }

    /// Errors surface only after staged bytes have been emitted (lossless).
    #[tokio::test]
    async fn error_surfaces_after_staged_flush() {
        let parts = vec![
            Ok::<Frame<Bytes>, std::io::Error>(Frame::data(data(70))),
            Err(std::io::Error::other("boom")),
        ];
        let mut hygiene = ChunkHygiene::new(stream::iter(parts));

        let first = into_data(hygiene.next().await.unwrap().unwrap());
        assert_eq!(first.len(), 70);
        let err = hygiene.next().await.unwrap().unwrap_err();
        assert_eq!(err.to_string(), "boom");
        assert!(hygiene.next().await.is_none());
    }
}
