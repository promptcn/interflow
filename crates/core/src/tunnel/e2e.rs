//! The agent↔agent inner TLS transport adaptation (e2e encryption).
//!
//! Design (docs/design/agent-e2e-encryption.md §3.1): the inner TLS 1.3
//! handshake and record stream ride the tunnel stream as ordinary Data
//! frames — the hub only ever relays opaque bytes. This module bridges the
//! frame world (a per-stream `mpsc::Receiver<TunnelData>` + the tunnel's
//! send methods) to the byte-stream world rustls needs
//! ([`E2eTunnelIo`]: `AsyncRead` + `AsyncWrite`).
//!
//! **Why the pipe indirection** (RFC §10.7 risk note): `tokio-rustls`
//! consumes the IO on a failed handshake, but the `opportunistic` mode
//! must recover the receiver *and any peer bytes already buffered* to fall
//! back to plaintext. So the TLS layer always runs over an in-memory
//! duplex pipe, and a shuttle task owns the adapter, pumping pipe ↔
//! adapter for the whole stream lifetime; when the TLS side dies
//! (handshake error *or* deadline), the shuttle hands the adapter back as
//! [`E2eFallbackParts`]. The cost is one extra memcpy hop per chunk —
//! accepted for v1 in exchange for zero hand-rolled rustls state-machine
//! code (the pipe keeps `tokio_rustls::TlsStream` end-to-end battle-tested
//! paths).

use crate::error::Result;
use crate::protocol::FrameType;
use crate::protocol::MAX_FRAME_PAYLOAD;
use crate::tunnel::AgentTunnel;
use crate::tunnel::pump::parse_close_reason;
use crate::tunnel::transport::TunnelData;
use async_trait::async_trait;
use bytes::{Bytes, BytesMut};
use futures::future::BoxFuture;
use std::io;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::Mutex as StdMutex;
use std::task::Context;
use std::task::Poll;
use std::time::Duration;
use tokio::io::DuplexStream;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};
use tokio::sync::mpsc;
use tokio::sync::oneshot;
use tokio_rustls::TlsAcceptor;
use tokio_rustls::TlsConnector;

use crate::protocol::CloseReason;

/// Buffer size of the in-memory duplex pipe between rustls and the shuttle
/// (one direction must hold a couple of maximum-size TLS records; 64 KiB).
const PIPE_CAPACITY: usize = 64 * 1024;

/// How long the caller waits for the shuttle to hand the adapter back
/// after the TLS side died. The handover is normally immediate (the pipe
/// EOFs the moment the TLS side drops); a hub withholding the stream's
/// Close response could otherwise stall it forever.
const FALLBACK_GRACE: Duration = Duration::from_secs(5);

/// Which direction of the tunnel this side drives.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum E2eDirection {
    /// Ingress side: request-direction frames (`send_data` / `send_close`).
    Ingress,
    /// Egress side: response-direction frames (`send_data_response` /
    /// `send_close_response`).
    Egress,
}

/// The minimal tunnel send surface the adapter needs, extracted from
/// [`AgentTunnel`] the same way the pump extracts [`StreamPumpTarget`] —
/// so the adapter runs in unit tests against a recording mock.
#[async_trait]
pub trait E2eIoSink: Send + Sync {
    /// Sends a data frame (request direction, ingress → hub).
    async fn send_data(&self, stream_id: &str, data: Bytes) -> Result<()>;
    /// Sends a data frame (response direction, egress → hub).
    async fn send_data_response(&self, stream_id: &str, data: Bytes) -> Result<()>;
    /// Closes the stream (request direction).
    async fn send_close(&self, stream_id: &str) -> Result<()>;
    /// Closes the stream (response direction; empty reason = ordinary close).
    async fn send_close_response(&self, stream_id: &str, reason: &str) -> Result<()>;
}

#[async_trait]
impl E2eIoSink for AgentTunnel {
    async fn send_data(&self, stream_id: &str, data: Bytes) -> Result<()> {
        Self::send_data(self, stream_id, data).await
    }

    async fn send_data_response(&self, stream_id: &str, data: Bytes) -> Result<()> {
        Self::send_data_response(self, stream_id, data).await
    }

    async fn send_close(&self, stream_id: &str) -> Result<()> {
        Self::send_close(self, stream_id).await
    }

    async fn send_close_response(&self, stream_id: &str, reason: &str) -> Result<()> {
        Self::send_close_response(self, stream_id, reason).await
    }
}

/// A shared, cloneable handle onto the peer Close reason observed by an
/// [`E2eTunnelIo`].
///
/// The adapter itself is consumed by the handshake/pump; callers like the
/// expose edge route breaker need the token afterwards.
#[derive(Clone, Debug, Default)]
pub struct E2eCloseReason {
    slot: Arc<StdMutex<Option<CloseReason>>>,
}

impl E2eCloseReason {
    /// The peer Close reason, once observed (`None` before that / never).
    pub fn get(&self) -> Option<CloseReason> {
        self.slot.lock().expect("e2e reason slot poisoned").clone()
    }
}

/// The frame-channel side of one e2e stream, adapted to `AsyncRead +
/// AsyncWrite` for rustls.
///
/// Read: Data frame payloads are surfaced as bytes (leftovers buffer
/// across reads); a Close frame (or channel closure — poisoning/teardown)
/// is EOF; the reason token is recorded in the shared [`E2eCloseReason`].
/// Write: chunks capped at [`MAX_FRAME_PAYLOAD`] become one send each.
/// Shutdown maps to the direction's close. All async tunnel sends are
/// stored as futures polled inside the poll methods (the sync poll
/// contract cannot await).
pub struct E2eTunnelIo {
    rx: mpsc::Receiver<TunnelData>,
    read_buf: BytesMut,
    eof: bool,
    reason_slot: Arc<StdMutex<Option<CloseReason>>>,
    sink: Arc<dyn E2eIoSink>,
    stream_id: String,
    direction: E2eDirection,
    write_fut: Option<BoxFuture<'static, io::Result<()>>>,
    /// Byte count reported to the caller once `write_fut` completes
    /// (the future owns the chunk; the length must survive outside it).
    pending_len: usize,
    close_fut: Option<BoxFuture<'static, io::Result<()>>>,
    write_failed: bool,
}

impl E2eTunnelIo {
    /// Ingress-side adapter (request-direction sends).
    pub fn ingress(rx: mpsc::Receiver<TunnelData>, tunnel: AgentTunnel, stream_id: String) -> Self {
        Self::with_sink(rx, Arc::new(tunnel), stream_id, E2eDirection::Ingress)
    }

    /// Egress-side adapter (response-direction sends).
    pub fn egress(rx: mpsc::Receiver<TunnelData>, tunnel: AgentTunnel, stream_id: String) -> Self {
        Self::with_sink(rx, Arc::new(tunnel), stream_id, E2eDirection::Egress)
    }

    /// Test/alternative-construction entry with an explicit sink.
    pub fn with_sink(
        rx: mpsc::Receiver<TunnelData>,
        sink: Arc<dyn E2eIoSink>,
        stream_id: String,
        direction: E2eDirection,
    ) -> Self {
        Self {
            rx,
            read_buf: BytesMut::new(),
            eof: false,
            reason_slot: Arc::new(StdMutex::new(None)),
            sink,
            stream_id,
            direction,
            write_fut: None,
            pending_len: 0,
            close_fut: None,
            write_failed: false,
        }
    }

    /// A handle onto the peer Close reason this adapter will observe.
    pub fn reason_handle(&self) -> E2eCloseReason {
        E2eCloseReason {
            slot: Arc::clone(&self.reason_slot),
        }
    }

    /// Whether a Close frame or channel closure already ended the read side.
    pub const fn is_eof(&self) -> bool {
        self.eof
    }

    /// Hands back the raw parts for an `opportunistic` plaintext fallback:
    /// the stream's frame channel plus any peer bytes buffered during the
    /// failed handshake attempt (the caller replays them before resuming
    /// the plain pump).
    pub fn into_parts(mut self) -> E2eFallbackParts {
        let close_reason = self.reason_handle().get();
        E2eFallbackParts {
            rx: self.rx,
            buffered: std::mem::take(&mut self.read_buf).freeze(),
            close_reason,
        }
    }

    fn record_close(&mut self, data: &[u8]) {
        self.eof = true;
        let reason = parse_close_reason(&self.stream_id, data);
        *self.reason_slot.lock().expect("e2e reason slot poisoned") = Some(reason);
    }

    fn spawn_close_future(&mut self) {
        if self.close_fut.is_some() {
            return;
        }
        let sink = Arc::clone(&self.sink);
        let sid = self.stream_id.clone();
        let fut: BoxFuture<'static, io::Result<()>> = match self.direction {
            E2eDirection::Ingress => Box::pin(async move {
                sink.send_close(&sid)
                    .await
                    .map_err(|e| io::Error::other(e.to_string()))
            }),
            E2eDirection::Egress => Box::pin(async move {
                sink.send_close_response(&sid, "")
                    .await
                    .map_err(|e| io::Error::other(e.to_string()))
            }),
        };
        self.close_fut = Some(fut);
    }
}

impl AsyncRead for E2eTunnelIo {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = &mut *self;
        // Buffered leftovers first (previous frame larger than the caller's buf).
        if !this.read_buf.is_empty() {
            let n = buf.remaining().min(this.read_buf.len());
            let chunk = this.read_buf.split_to(n).freeze();
            buf.put_slice(&chunk);
            return Poll::Ready(Ok(()));
        }
        if this.eof {
            return Poll::Ready(Ok(()));
        }
        loop {
            match this.rx.poll_recv(cx) {
                Poll::Ready(Some(frame)) => match frame.stream_type {
                    FrameType::Data => {
                        if frame.data.is_empty() {
                            continue;
                        }
                        let n = buf.remaining().min(frame.data.len());
                        buf.put_slice(&frame.data[..n]);
                        if n < frame.data.len() {
                            this.read_buf.extend_from_slice(&frame.data[n..]);
                        }
                        return Poll::Ready(Ok(()));
                    }
                    FrameType::Close => {
                        this.record_close(&frame.data);
                        return Poll::Ready(Ok(()));
                    }
                    // Control-plane frames never ride a stream channel
                    // (OpenAck is UDP-only); anything else is skipped and
                    // the loop polls again.
                    _ => {}
                },
                Poll::Ready(None) => {
                    // Channel closed: dispatch poisoning / session teardown /
                    // already unregistered — the tunnel side is done.
                    this.eof = true;
                    return Poll::Ready(Ok(()));
                }
                Poll::Pending => return Poll::Pending,
            }
        }
    }
}

impl AsyncWrite for E2eTunnelIo {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = &mut *self;
        if this.write_failed {
            return Poll::Ready(Err(io::Error::other(
                "inner TLS adapter: write side already failed",
            )));
        }
        if this.close_fut.is_some() {
            return Poll::Ready(Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "inner TLS adapter: write after shutdown",
            )));
        }
        if this.write_fut.is_none() {
            if buf.is_empty() {
                return Poll::Ready(Ok(0));
            }
            let n = buf.len().min(MAX_FRAME_PAYLOAD);
            let chunk = Bytes::copy_from_slice(&buf[..n]);
            let sink = Arc::clone(&this.sink);
            let sid = this.stream_id.clone();
            let fut: BoxFuture<'static, io::Result<()>> = match this.direction {
                E2eDirection::Ingress => Box::pin(async move {
                    sink.send_data(&sid, chunk)
                        .await
                        .map_err(|e| io::Error::other(e.to_string()))
                }),
                E2eDirection::Egress => Box::pin(async move {
                    sink.send_data_response(&sid, chunk)
                        .await
                        .map_err(|e| io::Error::other(e.to_string()))
                }),
            };
            this.pending_len = n;
            this.write_fut = Some(fut);
        }
        match this
            .write_fut
            .as_mut()
            .expect("write future armed")
            .as_mut()
            .poll(cx)
        {
            Poll::Ready(Ok(())) => {
                this.write_fut = None;
                Poll::Ready(Ok(this.pending_len))
            }
            Poll::Ready(Err(e)) => {
                this.write_fut = None;
                this.write_failed = true;
                Poll::Ready(Err(e))
            }
            Poll::Pending => Poll::Pending,
        }
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = &mut *self;
        if let Some(fut) = this.write_fut.as_mut() {
            match fut.as_mut().poll(cx) {
                Poll::Ready(Ok(())) => {
                    this.write_fut = None;
                    Poll::Ready(Ok(()))
                }
                Poll::Ready(Err(e)) => {
                    this.write_fut = None;
                    this.write_failed = true;
                    Poll::Ready(Err(e))
                }
                Poll::Pending => Poll::Pending,
            }
        } else {
            Poll::Ready(Ok(()))
        }
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = &mut *self;
        // A send still in flight must complete before the close goes out
        // (ordering: payload bytes precede the Close frame).
        if let Some(fut) = this.write_fut.as_mut() {
            match fut.as_mut().poll(cx) {
                Poll::Ready(Ok(())) => this.write_fut = None,
                Poll::Ready(Err(e)) => {
                    this.write_fut = None;
                    this.write_failed = true;
                    return Poll::Ready(Err(e));
                }
                Poll::Pending => return Poll::Pending,
            }
        }
        this.spawn_close_future();
        match this
            .close_fut
            .as_mut()
            .expect("close future armed")
            .as_mut()
            .poll(cx)
        {
            Poll::Ready(result) => Poll::Ready(result),
            Poll::Pending => Poll::Pending,
        }
    }
}

/// What the shuttle hands back when the TLS side died: everything needed to
/// resume the stream as plaintext (opportunistic fallback) or observe the
/// peer's close token.
pub struct E2eFallbackParts {
    /// The stream's frame channel, still live.
    pub rx: mpsc::Receiver<TunnelData>,
    /// Peer bytes buffered during the handshake attempt (replay these
    /// before resuming the plain pump).
    pub buffered: Bytes,
    /// The peer Close reason if one was observed mid-attempt.
    pub close_reason: Option<CloseReason>,
}

impl E2eFallbackParts {
    /// A dead receiver (already-closed channel): used when the shuttle
    /// could not be recovered within the grace window (malicious peer
    /// withholding the Close response) — the stream is unusable either way.
    fn dead() -> Self {
        Self {
            rx: mpsc::channel(1).1,
            buffered: Bytes::new(),
            close_reason: None,
        }
    }
}

/// The outcome of an inner TLS handshake attempt over an [`E2eTunnelIo`].
///
/// `Established` carries the rustls stream (over the internal pipe — keep
/// pumping it for the stream lifetime) plus the shared close-reason handle.
/// `Failed` carries the adapter's parts back for the caller's mode
/// semantics: `required` closes the stream, `opportunistic` replays and
/// resumes plaintext.
///
/// Generic over the concrete TLS stream (client and server handshake
/// produce different wrapper types; both satisfy what the pump needs).
pub enum E2eHandshakeOutcome<T> {
    /// Handshake verified: pump the returned stream.
    Established(T, E2eCloseReason),
    /// Handshake failed or hit the deadline: everything needed to fall
    /// back / close out. The error is `TimedOut` when the deadline hit.
    Failed {
        parts: E2eFallbackParts,
        error: io::Error,
    },
}

/// Runs an inner TLS **client** handshake (ingress side) over the adapter.
///
/// `connector` comes from [`crate::tls::inner_client_config`]; the server
/// name is the shared [`crate::tls::INNER_SERVER_NAME`] placeholder (the
/// real identity binding is the verifier's CN check). See
/// [`E2eHandshakeOutcome`] and the module docs for the pipe/shuttle
/// mechanics.
pub async fn inner_tls_connect(
    adapter: E2eTunnelIo,
    connector: TlsConnector,
    deadline: Duration,
) -> E2eHandshakeOutcome<tokio_rustls::client::TlsStream<DuplexStream>> {
    run_inner_tls(adapter, deadline, move |tls_side| async move {
        connector
            .connect(
                tokio_rustls::rustls::pki_types::ServerName::try_from(
                    crate::tls::INNER_SERVER_NAME.to_string(),
                )
                .map_err(|e| io::Error::other(e.to_string()))?,
                tls_side,
            )
            .await
    })
    .await
}

/// Runs an inner TLS **server** handshake (egress side) over the adapter.
pub async fn inner_tls_accept(
    adapter: E2eTunnelIo,
    acceptor: TlsAcceptor,
    deadline: Duration,
) -> E2eHandshakeOutcome<tokio_rustls::server::TlsStream<DuplexStream>> {
    run_inner_tls(adapter, deadline, move |tls_side| async move {
        acceptor.accept(tls_side).await
    })
    .await
}

/// The shared driver behind connect/accept: rustls talks to a duplex pipe;
/// a shuttle task pumps the pipe against the adapter and, once the TLS
/// side dies, hands the adapter back as [`E2eFallbackParts`].
async fn run_inner_tls<F, Fut, T>(
    adapter: E2eTunnelIo,
    deadline: Duration,
    start: F,
) -> E2eHandshakeOutcome<T>
where
    F: FnOnce(DuplexStream) -> Fut,
    Fut: std::future::Future<Output = io::Result<T>>,
{
    let reason = adapter.reason_handle();
    let (fallback_tx, fallback_rx) = oneshot::channel::<E2eFallbackParts>();
    let (tls_side, adapter_side) = tokio::io::duplex(PIPE_CAPACITY);

    // Shuttle: for the whole TLS-side lifetime, pipe bytes ↔ adapter
    // frames. The moment the TLS side dies (handshake error, deadline drop,
    // or the eventual stream end → pipe EOF), everything is handed back
    // IMMEDIATELY — the live channel and any buffered peer bytes; frames
    // still in flight stay queued in the channel for the fallback consumer.
    //
    // The shuttle deliberately does NOT send the stream Close on TLS-side
    // death: the caller owns that decision (`required` closes explicitly;
    // `opportunistic` resumes the plain pump on the returned channel — an
    // eager Close here would tear the fallback stream down at the hub).
    let shuttle = tokio::spawn(async move {
        let mut adapter = adapter;
        let mut pipe = adapter_side;
        let mut buf_to_adapter = vec![0u8; 16 * 1024];
        let mut buf_to_pipe = vec![0u8; 16 * 1024];
        let mut pipe_dead = false;
        let mut adapter_dead = false;
        loop {
            if pipe_dead {
                let _ = fallback_tx.send(adapter.into_parts());
                return;
            }
            tokio::select! {
                // Always enabled: pipe EOF is the TLS-side death detector.
                r = pipe.read(&mut buf_to_adapter) => match r {
                    Ok(0) | Err(_) => {
                        pipe_dead = true;
                    }
                    Ok(n) => {
                        if adapter.write_all(&buf_to_adapter[..n]).await.is_err() {
                            adapter_dead = true;
                            // Surface tunnel-write death to the TLS layer.
                            let _ = pipe.shutdown().await;
                        }
                    }
                },
                r = adapter.read(&mut buf_to_pipe), if !adapter_dead => match r {
                    Ok(0) | Err(_) => {
                        adapter_dead = true;
                        // Surface the tunnel-side end to the TLS layer.
                        let _ = pipe.shutdown().await;
                    }
                    Ok(n) => {
                        if pipe.write_all(&buf_to_pipe[..n]).await.is_err() {
                            pipe_dead = true;
                        }
                    }
                },
            }
        }
    });
    // The shuttle outlives the handshake (it keeps pumping for the whole
    // stream lifetime); detaching here is deliberate.
    drop(shuttle);

    let mut handshake = Box::pin(start(tls_side));
    match tokio::time::timeout(deadline, &mut handshake).await {
        Ok(Ok(stream)) => E2eHandshakeOutcome::Established(stream, reason),
        Ok(Err(error)) => E2eHandshakeOutcome::Failed {
            parts: recover_parts(fallback_rx).await,
            error,
        },
        Err(_) => {
            // Deadline: dropping the handshake future drops the pipe's TLS
            // side; the shuttle observes EOF and returns the parts.
            drop(handshake);
            E2eHandshakeOutcome::Failed {
                parts: recover_parts(fallback_rx).await,
                error: io::Error::new(
                    io::ErrorKind::TimedOut,
                    "inner TLS handshake deadline elapsed",
                ),
            }
        }
    }
}

/// Waits (bounded) for the shuttle's handover; on a withheld-Close stall
/// returns dead parts — the stream is already torn down at the TLS layer.
async fn recover_parts(rx: oneshot::Receiver<E2eFallbackParts>) -> E2eFallbackParts {
    match tokio::time::timeout(FALLBACK_GRACE, rx).await {
        Ok(Ok(parts)) => parts,
        // Sender dropped without sending (shuttle panicked / already gone)
        // or the grace window expired.
        Ok(Err(_)) | Err(_) => E2eFallbackParts::dead(),
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
    use crate::tls::{InnerTlsMaterial, inner_client_config, inner_server_config};
    use crate::tunnel::transport::FrameSource;
    use std::sync::Mutex as StdMutex2;
    use std::time::Duration;
    use tokio::io::AsyncReadExt;
    use tokio::io::AsyncWriteExt;

    /// Recording sink asserting the adapter's frame sends.
    #[derive(Default)]
    struct MockSink {
        data: StdMutex2<Vec<Bytes>>,
        data_response: StdMutex2<Vec<Bytes>>,
        closes: StdMutex2<Vec<String>>,
        close_responses: StdMutex2<Vec<String>>,
    }

    #[async_trait]
    impl E2eIoSink for MockSink {
        async fn send_data(&self, _stream_id: &str, data: Bytes) -> Result<()> {
            self.data.lock().unwrap().push(data);
            Ok(())
        }
        async fn send_data_response(&self, _stream_id: &str, data: Bytes) -> Result<()> {
            self.data_response.lock().unwrap().push(data);
            Ok(())
        }
        async fn send_close(&self, stream_id: &str) -> Result<()> {
            self.closes.lock().unwrap().push(stream_id.to_string());
            Ok(())
        }
        async fn send_close_response(&self, stream_id: &str, _reason: &str) -> Result<()> {
            self.close_responses
                .lock()
                .unwrap()
                .push(stream_id.to_string());
            Ok(())
        }
    }

    fn td(ftype: FrameType, data: &[u8]) -> TunnelData {
        TunnelData {
            stream_id: "s1".to_string(),
            source: FrameSource::Response,
            data: Bytes::copy_from_slice(data),
            stream_type: ftype,
            flags: 0,
        }
    }

    fn adapter(sink: Arc<MockSink>) -> (E2eTunnelIo, mpsc::Sender<TunnelData>) {
        let (tx, rx) = mpsc::channel(8);
        let dyn_sink: Arc<dyn E2eIoSink> = sink;
        let io = E2eTunnelIo::with_sink(rx, dyn_sink, "s1".to_string(), E2eDirection::Ingress);
        (io, tx)
    }

    fn dyn_sink(sink: &Arc<MockSink>) -> Arc<dyn E2eIoSink> {
        let cloned: Arc<MockSink> = Arc::clone(sink);
        cloned
    }

    /// Data frames surface as read bytes, in order, with small caller
    /// buffers splitting across frames exactly as byte-stream semantics
    /// require.
    #[tokio::test]
    async fn data_frames_bridge_to_reads() {
        let sink = Arc::new(MockSink::default());
        let (mut io, tx) = adapter(Arc::clone(&sink));
        tx.send(td(FrameType::Data, b"hello ")).await.unwrap();
        tx.send(td(FrameType::Data, b"world")).await.unwrap();
        // Dropping the sender closes the channel = EOF (teardown semantics).
        drop(tx);

        let mut buf = [0u8; 4];
        io.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, b"hell");
        let mut rest = Vec::new();
        io.read_to_end(&mut rest).await.unwrap();
        assert_eq!(rest, b"o world");
    }

    /// A Close frame is EOF with the reason token recorded in the handle.
    #[tokio::test]
    async fn close_frame_is_eof_with_reason() {
        let sink = Arc::new(MockSink::default());
        let (mut io, tx) = adapter(Arc::clone(&sink));
        let reason = io.reason_handle();
        tx.send(td(FrameType::Data, b"x")).await.unwrap();
        tx.send(td(FrameType::Close, b"CLOSE:s1:connect_failed"))
            .await
            .unwrap();

        let mut buf = [0u8; 16];
        assert_eq!(io.read(&mut buf).await.unwrap(), 1);
        assert_eq!(io.read(&mut buf).await.unwrap(), 0, "Close = EOF");
        assert_eq!(reason.get(), Some(CloseReason::ConnectFailed));
    }

    /// Writes become direction-correct sends, capped at MAX_FRAME_PAYLOAD.
    #[tokio::test]
    async fn writes_chunk_to_direction_capped_sends() {
        let sink = Arc::new(MockSink::default());
        let (mut io, _tx) = adapter(Arc::clone(&sink));
        io.write_all(b"client-hello").await.unwrap();
        assert_eq!(
            sink.data.lock().unwrap().clone(),
            vec![Bytes::from_static(b"client-hello")]
        );
        assert!(sink.data_response.lock().unwrap().is_empty());

        let big = vec![7u8; MAX_FRAME_PAYLOAD + 100];
        let n = io.write(&big).await.unwrap();
        assert_eq!(n, MAX_FRAME_PAYLOAD);
        assert_eq!(sink.data.lock().unwrap().len(), 2);

        // Egress direction sends responses instead.
        let (_tx2, rx2) = mpsc::channel(8);
        let mut io2 =
            E2eTunnelIo::with_sink(rx2, dyn_sink(&sink), "s1".to_string(), E2eDirection::Egress);
        io2.write_all(b"server-data").await.unwrap();
        assert_eq!(
            sink.data_response.lock().unwrap().clone(),
            vec![Bytes::from_static(b"server-data")]
        );
    }

    /// Shutdown maps to the direction's close and rejects later writes.
    #[tokio::test]
    async fn shutdown_sends_close_and_blocks_writes() {
        let sink = Arc::new(MockSink::default());
        let (mut io, _tx) = adapter(Arc::clone(&sink));
        io.shutdown().await.unwrap();
        assert_eq!(sink.closes.lock().unwrap().clone(), vec!["s1".to_string()]);
        assert!(io.write(b"late").await.is_err());

        let (_tx, rx) = mpsc::channel(8);
        let mut io2 =
            E2eTunnelIo::with_sink(rx, dyn_sink(&sink), "s2".into(), E2eDirection::Egress);
        io2.shutdown().await.unwrap();
        assert_eq!(
            sink.close_responses.lock().unwrap().clone(),
            vec!["s2".to_string()]
        );
    }

    /// into_parts returns the channel and any buffered peer bytes for the
    /// plaintext fallback replay.
    #[tokio::test]
    async fn into_parts_returns_buffered_bytes() {
        let sink = Arc::new(MockSink::default());
        let (mut io, tx) = adapter(Arc::clone(&sink));
        tx.send(td(FrameType::Data, b"banner-bytes")).await.unwrap();
        // Partial read: everything beyond the caller's buffer stays in the
        // adapter's read_buf and must survive into_parts.
        let mut buf = [0u8; 3];
        io.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, b"ban");
        // A further undelivered frame keeps the channel live for the pump.
        tx.send(td(FrameType::Data, b"next-frame")).await.unwrap();

        let parts = io.into_parts();
        assert_eq!(parts.buffered, Bytes::from_static(b"ner-bytes"));
        // The channel still works for the fallback pump.
        let mut rx = parts.rx;
        let td = rx.recv().await.expect("channel alive");
        assert_eq!(td.stream_type, FrameType::Data);
        assert_eq!(&td.data[..], b"next-frame");
    }

    /// A sink wired to the opposite side's channel: everything one adapter
    /// sends lands in the other adapter's receiver — the two adapters plus
    /// two cross-wired sinks model two agents talking through a hub that
    /// only relays frames (closes included: teardown must propagate like
    /// the hub's `_close_` notifications do).
    struct WiredSink {
        tx: mpsc::Sender<TunnelData>,
    }

    #[async_trait]
    impl E2eIoSink for WiredSink {
        async fn send_data(&self, _sid: &str, data: Bytes) -> Result<()> {
            let _ = self.tx.send(td(FrameType::Data, &data)).await;
            Ok(())
        }
        async fn send_data_response(&self, _sid: &str, data: Bytes) -> Result<()> {
            let _ = self.tx.send(td(FrameType::Data, &data)).await;
            Ok(())
        }
        async fn send_close(&self, sid: &str) -> Result<()> {
            let payload = format!("CLOSE:{sid}:");
            let _ = self.tx.send(td(FrameType::Close, payload.as_bytes())).await;
            Ok(())
        }
        async fn send_close_response(&self, sid: &str, reason: &str) -> Result<()> {
            let payload = format!("CLOSE:{sid}:{reason}");
            let _ = self.tx.send(td(FrameType::Close, payload.as_bytes())).await;
            Ok(())
        }
    }

    fn tls_material(cn: &str) -> (InnerTlsMaterial, InnerTlsMaterial) {
        // One CA; both pairs signed by it (same-tenant shape). Anchors hold
        // the CA; each side presents its own pair.
        let validity = interflow_certs::Validity::from_now(30);
        let ca = interflow_certs::LoadedCa::from_material(
            &interflow_certs::build_ca("t", validity).unwrap(),
        )
        .unwrap();
        let mut reader = std::io::BufReader::new(ca.cert_pem().as_bytes());
        let mut roots = tokio_rustls::rustls::RootCertStore::empty();
        for cert in rustls_pemfile::certs(&mut reader)
            .collect::<std::result::Result<Vec<_>, _>>()
            .unwrap()
        {
            let _ = roots.add(cert);
        }
        let mk = |cn: &str| {
            let leaf = ca.build_client_cert(cn, validity).unwrap();
            let chain_pem = format!("{}{}", leaf.cert_pem, ca.cert_pem());
            let mut reader = std::io::BufReader::new(chain_pem.as_bytes());
            let chain: Vec<_> = rustls_pemfile::certs(&mut reader)
                .collect::<std::result::Result<_, _>>()
                .unwrap();
            let mut key_reader = std::io::BufReader::new(leaf.key_pem.as_bytes());
            let key = rustls_pemfile::pkcs8_private_keys(&mut key_reader)
                .next()
                .unwrap()
                .unwrap();
            InnerTlsMaterial {
                roots: roots.clone(),
                cert_chain: chain,
                key: tokio_rustls::rustls::pki_types::PrivateKeyDer::Pkcs8(key),
            }
        };
        (mk(cn), mk("agent-2"))
    }

    /// Full machinery chain: two adapters cross-wired (frames relayed both
    /// ways), handshake succeeds through the pipe+shuttle indirection, and
    /// application bytes flow end to end.
    #[tokio::test]
    async fn wired_handshake_succeeds_and_relays_data() {
        let (mat_1, mat_2) = tls_material("agent-1");
        let (tx_to_b, rx_b) = mpsc::channel(64);
        let (tx_to_a, rx_a) = mpsc::channel(64);
        let client_adapter = E2eTunnelIo::with_sink(
            rx_a,
            Arc::new(WiredSink {
                tx: tx_to_b.clone(),
            }),
            "s1".into(),
            E2eDirection::Ingress,
        );
        let server_adapter = E2eTunnelIo::with_sink(
            rx_b,
            Arc::new(WiredSink {
                tx: tx_to_a.clone(),
            }),
            "s1".into(),
            E2eDirection::Egress,
        );

        let deadline = Duration::from_secs(10);
        let client = inner_tls_connect(
            client_adapter,
            tokio_rustls::TlsConnector::from(Arc::new(
                inner_client_config(&mat_1, "agent-2").unwrap(),
            )),
            deadline,
        );
        let server = inner_tls_accept(
            server_adapter,
            tokio_rustls::TlsAcceptor::from(Arc::new(
                inner_server_config(&mat_2, "agent-1").unwrap(),
            )),
            deadline,
        );
        let (client, server) = tokio::join!(client, server);
        let (mut tls_client, _) = match client {
            E2eHandshakeOutcome::Established(s, r) => (s, r),
            E2eHandshakeOutcome::Failed { error, .. } => panic!("client handshake failed: {error}"),
        };
        let (mut tls_server, reason) = match server {
            E2eHandshakeOutcome::Established(s, r) => (s, r),
            E2eHandshakeOutcome::Failed { error, .. } => panic!("server handshake failed: {error}"),
        };

        tls_client
            .write_all(b"ping-through-the-tunnel")
            .await
            .unwrap();
        let mut buf = vec![0u8; b"ping-through-the-tunnel".len()];
        tls_server.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, b"ping-through-the-tunnel");
        tls_server.write_all(b"pong").await.unwrap();
        let mut small = [0u8; 4];
        tls_client.read_exact(&mut small).await.unwrap();
        assert_eq!(&small, b"pong");

        // Teardown: the handshake/data contract is what this unit pins;
        // stream close-out belongs to the CALLERS under the close-ownership
        // contract (the shuttle never closes on TLS-side death — mesh/edge
        // call sites send it explicitly, pinned by tests/e2e_inner_tls).
        drop(tls_client);
        drop(tls_server);
        drop(tx_to_b);
        drop(tx_to_a);
        // No peer Close ever crossed the adapters here, so no reason was
        // observed.
        assert_eq!(reason.get(), None);
    }

    /// A handshake failure (server expects a different client CN) must
    /// hand the channel and any buffered peer bytes back for the plaintext
    /// fallback — the whole point of the pipe/shuttle indirection.
    #[tokio::test]
    async fn failed_handshake_returns_fallback_parts() {
        let (mat_1, mat_2) = tls_material("agent-1");
        let (tx_to_b, rx_b) = mpsc::channel(64);
        let (silent_to_a, rx_a) = mpsc::channel(64);
        let client_adapter = E2eTunnelIo::with_sink(
            rx_a,
            Arc::new(WiredSink {
                tx: tx_to_b.clone(),
            }),
            "s1".into(),
            E2eDirection::Ingress,
        );
        let server_adapter = E2eTunnelIo::with_sink(
            rx_b,
            Arc::new(WiredSink {
                tx: silent_to_a.clone(),
            }),
            "s1".into(),
            E2eDirection::Egress,
        );

        // Server demands a CN nobody presents.
        let server = inner_tls_accept(
            server_adapter,
            tokio_rustls::TlsAcceptor::from(Arc::new(
                inner_server_config(&mat_2, "someone-else").unwrap(),
            )),
            Duration::from_secs(10),
        );
        let client = inner_tls_connect(
            client_adapter,
            tokio_rustls::TlsConnector::from(Arc::new(
                inner_client_config(&mat_1, "agent-2").unwrap(),
            )),
            Duration::from_secs(10),
        );
        let (server, client) = tokio::join!(server, client);
        // TLS 1.3 shape: the client considers the handshake done once it
        // sends its Finished (server-side client-cert verification happens
        // after), so the CLIENT succeeds while the SERVER — the side whose
        // CN expectation was violated, and the side our security model
        // makes the enforcer (egress) — fails and gets its parts back.
        let (mut tls_client, _) = match client {
            E2eHandshakeOutcome::Established(s, r) => (s, r),
            E2eHandshakeOutcome::Failed { error, .. } => {
                panic!("client handshake unexpectedly failed: {error}")
            }
        };
        let (parts, error) = match server {
            E2eHandshakeOutcome::Failed { parts, error } => (parts, error),
            E2eHandshakeOutcome::Established(..) => {
                panic!("server handshake must fail on client CN mismatch")
            }
        };
        assert!(!error.to_string().is_empty());
        // The receiver is recoverable (the fallback pump's input).
        drop(parts.rx);
        // The server's rejection alert reaches the client as a read error.
        let mut sink_buf = [0u8; 8];
        assert!(tls_client.read(&mut sink_buf).await.is_err());
        drop(tls_client);
    }

    /// The deadline path: nobody answers the handshake, the deadline hits,
    /// and the parts still come back (bounded by the fallback grace, not
    /// forever).
    #[tokio::test]
    async fn deadline_expires_and_returns_parts() {
        let (mat_1, _mat_2) = tls_material("agent-1");
        // Read side: a channel nobody feeds (silent peer). Write side: a
        // separate discard channel — the adapter must not read its own
        // ClientHello back.
        let (_silent_tx, rx) = mpsc::channel(8);
        let (discard_tx, _discard_rx) = mpsc::channel(8);
        let adapter = E2eTunnelIo::with_sink(
            rx,
            Arc::new(WiredSink { tx: discard_tx }),
            "s1".into(),
            E2eDirection::Ingress,
        );
        let started = std::time::Instant::now();
        let outcome = inner_tls_connect(
            adapter,
            tokio_rustls::TlsConnector::from(Arc::new(
                inner_client_config(&mat_1, "agent-2").unwrap(),
            )),
            Duration::from_millis(300),
        )
        .await;
        let E2eHandshakeOutcome::Failed { error, .. } = outcome else {
            panic!("deadline must fail the handshake");
        };
        assert_eq!(error.kind(), std::io::ErrorKind::TimedOut);
        assert!(
            started.elapsed() < Duration::from_secs(6),
            "parts recovery must stay inside the grace window"
        );
    }
}
