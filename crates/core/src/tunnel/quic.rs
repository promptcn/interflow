//! QUIC tunnel backend: one QUIC connection carries all tunnel streams (frp-isomorphic, backlog §6.2 option 2).
//!
//! - **Control stream** (the first bidirectional stream): Hello
//!   (registration, payload = token) → HelloAck; hub heartbeat Pings are
//!   intercepted on the control stream and answered with Pong (aligned with
//!   the h2 backend's automatic answering at the poll layer).
//! - **Traffic streams**: each tunnel stream = one bidirectional QUIC stream
//!   with custom frames written directly (no HTTP header semantics) — fully
//!   eliminating TCP single-connection head-of-line blocking and "one full
//!   HTTP exchange per uplink chunk".
//! - Inbound frames go through [`TunnelDispatch`] (same rules as the h2
//!   backend: a stream_map hit goes to the dedicated channel, otherwise
//!   broadcast).
//!
//! Write path: one dedicated write task per stream + an mpsc of capacity 64
//! (`SendStream` is exclusively written); a full channel means backpressure
//! (equivalent to h2 flow-control semantics); close = Close frame command +
//! FIN.
//!
//! Parameters (backlog §6.4, starting from frp defaults): KeepAlive 10s /
//! MaxIdleTimeout 30s. ALPN fixed to `"interflow"`.

// QUIC async tasks hold a 64KiB read buffer, so future size naturally
// exceeds the pedantic threshold; the Pending/UnknownType branches of the
// frame decode loop and let-else rewrites are protocol-handling idioms.
#![allow(
    clippy::large_futures,
    clippy::needless_continue,
    clippy::match_same_arms,
    clippy::manual_let_else
)]
use crate::error::{InterflowError, Result};
use crate::protocol::frame as wire;
use crate::protocol::{FrameType, StreamProto};
use crate::tunnel::transport::FrameSource;
use crate::tunnel::transport::{TunnelData, TunnelDispatch, TunnelTransport};
use async_trait::async_trait;
use bytes::{Bytes, BytesMut};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex as StdMutex};
use std::time::Duration;
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;
use tracing::{debug, warn};

/// The QUIC ALPN protocol identifier (cf. frp's `"frp"`).
pub const QUIC_ALPN: &str = "interflow";

/// KeepAlive interval (frp default).
const KEEPALIVE: Duration = Duration::from_secs(10);

/// Transport-stats sampling interval (cheap snapshot; always on). The CC
/// forensics anchor for the 2026-09-16 quic egress-stall case file: cwnd
/// collapse / loss bursts / black holes show up in these logs with no
/// extra tooling. Counters are cumulative — diff adjacent samples.
const STATS_SAMPLE_INTERVAL: Duration = Duration::from_secs(10);
/// Idle timeout (frp default).
const IDLE_TIMEOUT_MS: u32 = 30_000;
/// Per-stream write-command channel capacity (backpressure threshold).
const WRITE_CHANNEL_CAP: usize = 64;

/// Capability bit in the first byte of the Hello/HelloAck payload: the QUIC DATAGRAM (RFC 9221) fast path.
pub const CAP_DATAGRAM: u8 = 0x01;

/// Budget for a whole frame carried in a DATAGRAM.
///
/// QUIC initial MTU 1200 − worst-case frame header (13 fixed + 36 uuid +
/// 128 agent id = 177). Datagrams over budget fall back to stream carriage
/// (reliable and ordered; under mixed carriage, UDP semantics allow
/// out-of-order arrival).
pub const DATAGRAM_FRAME_BUDGET: usize = 1023;

/// Hello/HelloAck payload encoding: `[caps u8][token]`.
fn encode_hello_payload(caps: u8, token: &str) -> Bytes {
    let mut buf = BytesMut::with_capacity(1 + token.len());
    buf.extend_from_slice(&[caps]);
    buf.extend_from_slice(token.as_bytes());
    buf.freeze()
}

/// Hello/HelloAck payload decoding: returns (caps, token).
fn decode_hello_payload(payload: &[u8]) -> (u8, String) {
    match payload.split_first() {
        Some((caps, token)) => (*caps, String::from_utf8_lossy(token).to_string()),
        None => (0, String::new()),
    }
}
/// Wait timeout for HelloAck.
const HELLO_ACK_TIMEOUT: Duration = Duration::from_secs(10);

/// Write command: an ordinary frame, or a Close frame (FIN closes out after the write).
enum WriteCmd {
    Frame(Bytes),
    CloseFrame(Bytes),
}

/// Write handle for a single tunnel stream: cheap to clone; writes are serialized through the dedicated write task.
#[derive(Clone)]
struct StreamHandle {
    tx: mpsc::Sender<WriteCmd>,
}

/// The QUIC tunnel backend.
pub struct QuicTunnel {
    agent_id: String,
    /// The local endpoint (held to keep the connection alive; the QUIC connection's UDP socket hangs off the endpoint).
    endpoint: quinn::Endpoint,
    conn: quinn::Connection,
    /// Session-termination token (a same-node clone passed in at connect): `shutdown()` cancels it,
    /// stopping the accept/control-stream/DATAGRAM read loops.
    token: CancellationToken,
    dispatch: Arc<TunnelDispatch>,
    /// stream_id → write handle (one shared table for locally initiated and hub-initiated streams).
    streams: Arc<StdMutex<HashMap<String, StreamHandle>>>,
    /// The negotiated DATAGRAM capability (true only if both this end and the hub support it).
    datagram_ok: bool,
    /// Streams whose OpenAck has been received (small Data packets on these streams take the DATAGRAM fast path).
    datagram_streams: Arc<StdMutex<std::collections::HashSet<String>>>,
}

/// Encodes a frame as `Bytes`.
fn encode_frame_bytes(
    frame_type: FrameType,
    flags: u8,
    stream_id: &str,
    source_agent: &str,
    payload: &[u8],
) -> Result<Bytes> {
    let mut buf = BytesMut::with_capacity(wire::decoded_frame_len(
        stream_id,
        source_agent,
        payload.len(),
    ));
    wire::encode_frame(
        frame_type,
        flags,
        stream_id,
        source_agent,
        payload,
        &mut buf,
    )
    .ok_or_else(|| {
        InterflowError::protocol(format!(
            "QUIC frame encoding failed (field too long): {stream_id}"
        ))
    })?;
    Ok(buf.freeze())
}

/// Dedicated write task: owns the `SendStream` exclusively, flushes after each
/// written command; FIN closes out after a CloseFrame; when the channel
/// closes (all handles dropped / session ended), FIN only.
async fn stream_write_loop(mut send: quinn::SendStream, mut rx: mpsc::Receiver<WriteCmd>) {
    while let Some(cmd) = rx.recv().await {
        match cmd {
            WriteCmd::Frame(buf) => {
                if let Err(e) = send.write_all(&buf).await {
                    debug!("QUIC stream write failed (peer already closed): {e}");
                    break;
                }
            }
            WriteCmd::CloseFrame(buf) => {
                if let Err(e) = send.write_all(&buf).await {
                    debug!("QUIC Close frame write failed (peer already closed): {e}");
                }
                let _ = send.finish();
                break;
            }
        }
    }
    // Channel closed without an explicit Close: half-close (FIN) so the peer reads EOF
    let _ = send.finish();
}

/// Control-stream read loop: on receiving a Ping, answer with a Pong on the control stream (hub heartbeat reply).
async fn control_read_loop(mut rx: quinn::RecvStream, tx: mpsc::Sender<WriteCmd>) {
    let mut buf = BytesMut::with_capacity(256);
    let mut chunk = [0u8; 1024];
    loop {
        let n = match rx.read(&mut chunk).await {
            Ok(Some(n)) => n,
            Ok(None) | Err(_) => break,
        };
        buf.extend_from_slice(&chunk[..n]);
        while let Some(frame) = TunnelDispatch::decode_tunnel_data(&mut buf) {
            if matches!(frame.stream_type, FrameType::Ping) {
                let pong = encode_frame_bytes(FrameType::Pong, 0, "", frame.source.as_str(), b"");
                if let Ok(pong) = pong
                    && tx.send(WriteCmd::Frame(pong)).await.is_err()
                {
                    return;
                }
            }
            // Other frames on the control stream (late HelloAck copies / Error) are ignored
        }
    }
    debug!("QUIC control stream read loop finished");
}

/// Accept loop: hub-initiated traffic streams. The first frame must be an
/// Open; the stream's SendStream goes to a dedicated write task (registered
/// as the response-direction write handle), and subsequent frames go through
/// unified dispatch.
async fn accept_loop(
    conn: quinn::Connection,
    dispatch: Arc<TunnelDispatch>,
    streams: Arc<StdMutex<HashMap<String, StreamHandle>>>,
    datagram_streams: Arc<StdMutex<std::collections::HashSet<String>>>,
    shutdown: CancellationToken,
) {
    loop {
        let (tx, rx) = tokio::select! {
            () = shutdown.cancelled() => break,
            r = conn.accept_bi() => match r {
                Ok(pair) => pair,
                Err(_) => break, // connection closed
            },
        };
        let dispatch = dispatch.clone();
        let streams = streams.clone();
        let datagram_streams = datagram_streams.clone();
        let token = shutdown.clone();
        tokio::spawn(async move {
            // Read the first frame (Open) to obtain the stream_id, then
            // register the write handle and enter the regular read loop.
            let mut rx = rx;
            let mut buf = BytesMut::with_capacity(512);
            let mut chunk = vec![0u8; 16 * 1024];
            let opened = loop {
                let n = match rx.read(&mut chunk).await {
                    Ok(Some(n)) => n,
                    Ok(None) | Err(_) => return,
                };
                buf.extend_from_slice(&chunk[..n]);
                match wire::decode_frame(&mut buf) {
                    wire::DecodeOutcome::Ok(f) => break f,
                    wire::DecodeOutcome::Error => {
                        warn!("QUIC stream first frame has invalid format, dropping the stream");
                        return;
                    }
                    // Pending / UnknownType: keep accumulating / skip
                    wire::DecodeOutcome::Pending | wire::DecodeOutcome::UnknownType { .. } => {}
                }
            };
            let (wtx, wrx) = mpsc::channel(WRITE_CHANNEL_CAP);
            tokio::spawn(stream_write_loop(tx, wrx));
            let handle = StreamHandle { tx: wtx };
            let td = TunnelData {
                stream_id: opened.stream_id.clone(),
                source: FrameSource::parse(&opened.source_agent),
                data: opened.payload,
                stream_type: opened.frame_type,
                flags: opened.flags,
            };
            streams
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .insert(opened.stream_id, handle);
            // The first frame (Open) must also enter dispatch (egress relies on the Open frame to establish the stream channel)
            dispatch.dispatch(td).await;
            // Session termination → the connection will be closed and the
            // read loop exits in place (not left hanging on a blocking read)
            tokio::select! {
                () = token.cancelled() => {}
                () = stream_read_loop(rx, buf, dispatch, Some(datagram_streams)) => {}
            }
        });
    }
}

/// Traffic-stream read loop: decode frames → dispatch.
///
/// `buf` may carry residual frames that arrived in the same packet as the
/// first frame during its read — it must be drained before entering the read
/// loop, otherwise residual frames of a short session would wait for new
/// data to arrive before being processed.
async fn stream_read_loop(
    mut rx: quinn::RecvStream,
    mut buf: BytesMut,
    dispatch: Arc<TunnelDispatch>,
    datagram_streams: Option<Arc<StdMutex<std::collections::HashSet<String>>>>,
) {
    let mut chunk = vec![0u8; 16 * 1024];
    // Intercept OpenAck (the hub confirming this stream may take the DATAGRAM fast path); other frames dispatch as usual
    let process = |buf: &mut BytesMut| {
        let mut deferred: Vec<TunnelData> = Vec::new();
        while let Some(td) = TunnelDispatch::decode_tunnel_data(buf) {
            if matches!(td.stream_type, FrameType::OpenAck)
                && let Some(set) = &datagram_streams
            {
                set.lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner)
                    .insert(td.stream_id.clone());
                continue;
            }
            deferred.push(td);
        }
        deferred
    };
    for td in process(&mut buf) {
        dispatch.dispatch(td).await;
    }
    loop {
        let n = match rx.read(&mut chunk).await {
            Ok(Some(n)) => n,
            Ok(None) | Err(_) => break,
        };
        buf.extend_from_slice(&chunk[..n]);
        for td in process(&mut buf) {
            dispatch.dispatch(td).await;
        }
    }
}

/// DATAGRAM receive loop: hub-relayed datagram frames → dispatch (same rules as stream frames).
async fn datagram_read_loop(conn: quinn::Connection, dispatch: Arc<TunnelDispatch>) {
    loop {
        let datagram = match conn.read_datagram().await {
            Ok(d) => d,
            Err(_) => break, // connection closed
        };
        let mut buf = BytesMut::from(&datagram[..]);
        while let Some(td) = TunnelDispatch::decode_tunnel_data(&mut buf) {
            if matches!(td.stream_type, FrameType::Ping) {
                continue; // heartbeats only ride the control stream
            }
            dispatch.dispatch(td).await;
        }
    }
}

impl QuicTunnel {
    /// Connects to the hub and completes Hello/HelloAck registration.
    ///
    /// `tls` is built by the caller (CA / mTLS client certificate / cert pin
    /// are all isomorphic with the h2 path); `server_name` is used for SNI.
    /// The overall timeout is applied by the caller (`AgentClient`).
    pub async fn connect(
        agent_id: String,
        server_addr: SocketAddr,
        server_name: &str,
        tls: rustls::ClientConfig,
        auth_token: Option<&str>,
        shutdown: CancellationToken,
    ) -> Result<Self> {
        let mut transport = quinn::TransportConfig::default();
        transport.keep_alive_interval(Some(KEEPALIVE));
        transport.max_idle_timeout(Some(quinn::IdleTimeout::from(quinn::VarInt::from_u32(
            IDLE_TIMEOUT_MS,
        ))));

        let quic_tls =
            quinn::crypto::rustls::QuicClientConfig::try_from(Arc::new(tls)).map_err(|e| {
                InterflowError::config(format!("invalid QUIC client TLS configuration: {e}"))
            })?;
        let mut client_config = quinn::ClientConfig::new(Arc::new(quic_tls));
        client_config.transport_config(Arc::new(transport));

        let mut endpoint = quinn::Endpoint::client("0.0.0.0:0".parse().map_err(|e| {
            InterflowError::connection(format!("QUIC local endpoint bind failed: {e}"))
        })?)
        .map_err(|e| {
            InterflowError::connection(format!("QUIC local endpoint creation failed: {e}"))
        })?;
        endpoint.set_default_client_config(client_config);

        let conn = endpoint
            .connect(server_addr, server_name)
            .map_err(|e| {
                InterflowError::connection(format!("QUIC connection initiation failed: {e}"))
            })?
            .await
            .map_err(|e| InterflowError::connection(format!("QUIC handshake failed: {e}")))?;

        // Control stream: open_bi → Hello (source_agent = agent_id, payload = token) → await HelloAck
        let (control_tx, mut control_rx) = conn.open_bi().await.map_err(|e| {
            InterflowError::connection(format!("QUIC control stream open failed: {e}"))
        })?;

        let hello = encode_frame_bytes(
            FrameType::Hello,
            0,
            "",
            &agent_id,
            &encode_hello_payload(CAP_DATAGRAM, auth_token.unwrap_or("")),
        )?;
        let (wtx, wrx) = mpsc::channel(WRITE_CHANNEL_CAP);
        // The control stream's write volume is small (Hello + occasional
        // Pong); one forwarding task owns the SendStream exclusively
        tokio::spawn(control_write_forward(control_tx, wrx));
        wtx.send(WriteCmd::Frame(hello)).await.map_err(|_| {
            InterflowError::connection("QUIC control stream write channel closed".to_string())
        })?;
        // pong_tx is held long-term: the control-stream channel never
        // closes; the forwarding task lives as long as the connection
        let pong_tx = wtx;

        // Await HelloAck (the hub sends an Error frame and closes the connection on validation failure)
        let ack_frame = tokio::time::timeout(HELLO_ACK_TIMEOUT, async {
            let mut buf = BytesMut::with_capacity(256);
            let mut chunk = vec![0u8; 1024];
            loop {
                let n = control_rx
                    .read(&mut chunk)
                    .await
                    .map_err(|e| InterflowError::connection(format!("HelloAck read failed: {e}")))?
                    .unwrap_or(0);
                if n == 0 {
                    return Err(InterflowError::connection(
                        "QUIC control stream closed before registration completed".to_string(),
                    ));
                }
                buf.extend_from_slice(&chunk[..n]);
                match wire::decode_frame(&mut buf) {
                    wire::DecodeOutcome::Ok(f) => return Ok(f),
                    wire::DecodeOutcome::Error => {
                        return Err(InterflowError::protocol(
                            "invalid QUIC control stream frame format".to_string(),
                        ));
                    }
                    wire::DecodeOutcome::Pending | wire::DecodeOutcome::UnknownType { .. } => {}
                }
            }
        })
        .await
        .map_err(|_| {
            InterflowError::connection("QUIC registration timed out (>10s)".to_string())
        })??;

        let datagram_ok = match ack_frame.frame_type {
            FrameType::HelloAck => {
                let (hub_caps, _) = decode_hello_payload(&ack_frame.payload);
                hub_caps & CAP_DATAGRAM != 0
            }
            FrameType::Error => {
                return Err(InterflowError::connection(format!(
                    "hub rejected registration: {}",
                    String::from_utf8_lossy(&ack_frame.payload)
                )));
            }
            other => {
                return Err(InterflowError::protocol(format!(
                    "expected HelloAck, got {other:?}"
                )));
            }
        };

        let dispatch = Arc::new(TunnelDispatch::new());
        let streams: Arc<StdMutex<HashMap<String, StreamHandle>>> =
            Arc::new(StdMutex::new(HashMap::new()));
        let datagram_streams: Arc<StdMutex<std::collections::HashSet<String>>> =
            Arc::new(StdMutex::new(std::collections::HashSet::new()));

        // Control-stream read loop: Ping → Pong (the Pong goes through the wtx forwarding write task)
        {
            let shutdown_control = shutdown.clone();
            tokio::spawn(async move {
                tokio::select! {
                    () = shutdown_control.cancelled() => {}
                    () = control_read_loop(control_rx, pong_tx) => {}
                }
            });
        }

        // Accept loop: hub-initiated traffic streams (egress role)
        tokio::spawn(accept_loop(
            conn.clone(),
            dispatch.clone(),
            streams.clone(),
            datagram_streams.clone(),
            shutdown.clone(),
        ));

        // DATAGRAM receive loop (enabled only on successful negotiation; the
        // hub's relayed datagrams arrive here)
        if datagram_ok {
            let conn2 = conn.clone();
            let dispatch2 = dispatch.clone();
            let shutdown2 = shutdown.clone();
            tokio::spawn(async move {
                tokio::select! {
                    () = shutdown2.cancelled() => {}
                    () = datagram_read_loop(conn2, dispatch2) => {}
                }
            });
        }

        // Transport-stats sampler (see STATS_SAMPLE_INTERVAL)
        {
            let conn_stats = conn.clone();
            let shutdown_stats = shutdown.clone();
            tokio::spawn(async move {
                let mut tick = tokio::time::interval(STATS_SAMPLE_INTERVAL);
                tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
                loop {
                    tokio::select! {
                        () = shutdown_stats.cancelled() => break,
                        _ = tick.tick() => {}
                    }
                    let s = conn_stats.stats();
                    let p = &s.path;
                    debug!(
                        cwnd = p.cwnd,
                        rtt_us = p.rtt.as_micros(),
                        sent_packets = p.sent_packets,
                        lost_packets = p.lost_packets,
                        congestion_events = p.congestion_events,
                        black_holes = p.black_holes_detected,
                        "QUIC transport stats"
                    );
                }
            });
        }

        Ok(Self {
            agent_id,
            endpoint,
            conn,
            token: shutdown,
            dispatch,
            streams,
            datagram_ok,
            datagram_streams,
        })
    }

    fn lookup_handle(&self, stream_id: &str) -> Option<StreamHandle> {
        self.streams
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .get(stream_id)
            .cloned()
    }

    /// Connection death signal: completes on network loss / peer CONNECTION_CLOSE / idle timeout.
    ///
    /// Used for session-level disconnect detection — the read loops exiting
    /// silently is not enough to terminate the session (the agent side must
    /// have an independent observer; otherwise, when the hub dies, an idle
    /// agent session never notices and hangs in Connected).
    pub async fn closed(&self) {
        self.conn.closed().await;
    }

    /// Writes one frame on the stream (request/response directions are equivalent under QUIC: the same bidirectional stream).
    async fn send_frame_on(
        &self,
        stream_id: &str,
        frame_type: FrameType,
        flags: u8,
        payload: &[u8],
    ) -> Result<()> {
        let handle = self
            .lookup_handle(stream_id)
            .ok_or_else(|| InterflowError::stream(format!("QUIC stream not found: {stream_id}")))?;
        let buf = encode_frame_bytes(frame_type, flags, stream_id, &self.agent_id, payload)?;
        handle.tx.send(WriteCmd::Frame(buf)).await.map_err(|_| {
            InterflowError::stream(format!("QUIC stream write task exited: {stream_id}"))
        })?;
        Ok(())
    }
}

/// Control-stream forwarding write task (lands mpsc commands on the control-stream SendStream).
///
/// Reuses the command semantics of [`stream_write_loop`] but without FIN —
/// the control stream's lifetime is bound to the connection; it exits only
/// on write failure.
async fn control_write_forward(mut tx: quinn::SendStream, mut rx: mpsc::Receiver<WriteCmd>) {
    while let Some(cmd) = rx.recv().await {
        let buf = match cmd {
            WriteCmd::Frame(b) | WriteCmd::CloseFrame(b) => b,
        };
        if let Err(e) = tx.write_all(&buf).await {
            debug!("QUIC control stream write failed: {e}");
            return;
        }
    }
}

#[async_trait]
impl TunnelTransport for QuicTunnel {
    async fn send_open(
        &self,
        stream_id: &str,
        target_agent: &str,
        target_addr: Option<&str>,
        proto: StreamProto,
    ) -> Result<()> {
        let (tx, rx) = self
            .conn
            .open_bi()
            .await
            .map_err(|e| InterflowError::connection(format!("QUIC stream open failed: {e}")))?;

        let (wtx, wrx) = mpsc::channel(WRITE_CHANNEL_CAP);
        tokio::spawn(stream_write_loop(tx, wrx));
        self.streams
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .insert(stream_id.to_string(), StreamHandle { tx: wtx });

        // Read loop (return-path frames on this stream → dispatch; the
        // ingress role hits via the response-direction dedicated channel)
        let dispatch = self.dispatch.clone();
        let datagram_set = if self.datagram_ok {
            Some(self.datagram_streams.clone())
        } else {
            None
        };
        let token = self.token.clone();
        tokio::spawn(async move {
            tokio::select! {
                () = token.cancelled() => {}
                () = stream_read_loop(rx, BytesMut::new(), dispatch, datagram_set) => {}
            }
        });

        // Open frame: payload = "{target_agent}:{target_addr}" (the hub
        // parses the target and dynamic address; the initiator's identity is
        // bound by connection registration, and the in-frame source_agent is
        // only a redundant check)
        let payload = format!("{target_agent}:{}", target_addr.unwrap_or(""));
        self.send_frame_on(
            stream_id,
            FrameType::Open,
            proto.as_flag(),
            payload.as_bytes(),
        )
        .await
    }

    async fn send_data(&self, stream_id: &str, data: Bytes) -> Result<()> {
        self.send_data_smart(stream_id, data).await
    }

    async fn send_data_response(&self, stream_id: &str, data: Bytes) -> Result<()> {
        // QUIC bidirectional streams have no direction concept: responses are written on the same stream
        self.send_data_smart(stream_id, data).await
    }

    async fn send_close(&self, stream_id: &str) -> Result<()> {
        self.close_stream(stream_id).await
    }

    async fn send_close_response(&self, stream_id: &str) -> Result<()> {
        self.close_stream(stream_id).await
    }

    async fn register_stream(&self, stream_id: String) -> mpsc::Receiver<TunnelData> {
        self.dispatch.register_stream(stream_id).await
    }

    async fn unregister_stream(&self, stream_id: &str) {
        self.dispatch.unregister_stream(stream_id).await;
    }

    async fn take_incoming_streams(
        &self,
    ) -> Option<mpsc::Receiver<crate::tunnel::transport::IncomingStream>> {
        self.dispatch.take_incoming_streams()
    }

    async fn unregister_incoming_stream(&self, stream_id: &str) {
        self.dispatch.unregister_incoming_stream(stream_id).await;
        // Request-direction forwarder exiting: synchronously release the
        // stream's QUIC write resources — remove the streams table entry
        // (drop the write handle → the write loop gets recv None → SendStream
        // finish() half-close + task exit) and the DATAGRAM fast-path marker.
        // No Close frame is sent back: the echo-back semantics are decided by
        // egress finish()'s echo_close; this path only does resource release
        // (idempotent).
        self.streams
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .remove(stream_id);
        self.datagram_streams
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .remove(stream_id);
    }

    /// Termination contract: cancel the token (stop the read loops) → CONNECTION_CLOSE (all quinn streams
    /// fail immediately; read/write loops exit in place, independent of peer
    /// behavior) → clear both dispatch tables and the streams write-handle
    /// table → close the endpoint. Idempotent; on a second call every step is
    /// a no-op.
    async fn shutdown(&self) {
        self.token.cancel();
        // 0x0 = NO_ERROR (normal session termination, not a protocol fault)
        self.conn
            .close(quinn::VarInt::from_u32(0), b"session shutdown");
        let req = self.dispatch.close_all_request_streams().await;
        let resp = self.dispatch.close_all_response_streams().await;
        let handles = self
            .streams
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .drain()
            .count();
        self.datagram_streams
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clear();
        // Release the local endpoint (UDP socket) — no longer relying on all
        // Arc clones dropping to zero
        self.endpoint
            .close(quinn::VarInt::from_u32(0), b"session shutdown");
        if req + resp + handles > 0 {
            metrics::counter!("interflow_agent_session_teardown_streams_killed_total")
                .increment(u64::try_from(req + resp + handles).unwrap_or(u64::MAX));
            debug!(
                "QUIC tunnel teardown: released {req} request-direction / {resp} response-direction streams and {handles} write handles"
            );
        }
    }
}

impl QuicTunnel {
    /// Data send: streams within budget that have received OpenAck take the
    /// DATAGRAM fast path (unreliable and unordered — zero translation of
    /// UDP semantics; packet loss does not HOL the whole connection);
    /// otherwise fall back to stream carriage. Control frames such as
    /// Open/Close always ride a stream (reliable ordering is a hard
    /// prerequisite for session establishment).
    async fn send_data_smart(&self, stream_id: &str, data: Bytes) -> Result<()> {
        if self.datagram_ok
            && data.len() <= DATAGRAM_FRAME_BUDGET
            && self
                .datagram_streams
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .contains(stream_id)
        {
            let frame = encode_frame_bytes(FrameType::Data, 0, stream_id, &self.agent_id, &data)?;
            return self.conn.send_datagram(frame).map_err(|e| {
                InterflowError::connection(format!("QUIC DATAGRAM send failed: {e}"))
            });
        }
        self.send_frame_on(stream_id, FrameType::Data, 0, &data)
            .await
    }

    /// Closes the stream: writes the Close frame + FIN and removes the handle (idempotent).
    async fn close_stream(&self, stream_id: &str) -> Result<()> {
        let Some(handle) = self
            .streams
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .remove(stream_id)
        else {
            return Ok(());
        };
        self.datagram_streams
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .remove(stream_id);
        let buf = encode_frame_bytes(FrameType::Close, 0, stream_id, &self.agent_id, b"")?;
        // The write task FINs automatically after receiving the CloseFrame
        let _ = handle.tx.send(WriteCmd::CloseFrame(buf)).await;
        Ok(())
    }
}
