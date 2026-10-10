//! QUIC tunnel backend: one QUIC connection carries all tunnel streams (frp-isomorphic, backlog §6.2 option 2).
//!
//! - **Control stream** (the first bidirectional stream): Hello
//!   (registration + capability bits; authentication is exclusively the TLS
//!   client certificate) → HelloAck; hub heartbeat Pings are
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
//! Endpoint transport parameters (idle/keepalive) come from the caller —
//! the endpoint TOML `[transport.quic]`, defaulting to the shared transport
//! profile (frp lineage: KeepAlive 10s / MaxIdleTimeout 30s). ALPN is fixed
//! to `"interflow"`.

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
use crate::protocol::{
    CircuitToken, CloseReason, FrameOrigin, FrameType, RouteToken, StreamId, StreamProto,
};
use crate::tunnel::negotiation::{
    HeartbeatAd, RegisterResponse, decode_error_payload, decode_policy_pull_response,
    decode_route_ack_payload, encode_hello_payload, encode_policy_pull_request,
    encode_route_request_payload,
};
use crate::tunnel::transport::{
    PolicyPull, SteadyStateLiveness, TunnelData, TunnelDispatch, TunnelTransport, unix_millis_now,
};
use async_trait::async_trait;
use bytes::{Bytes, BytesMut};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex as StdMutex};
use std::time::Duration;
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;

use crate::tunnel::session_tasks::{Beat, SessionTasks, beat_interval};
use tracing::{debug, info, warn};

/// The QUIC ALPN protocol identifier (cf. frp's `"frp"`).
pub const QUIC_ALPN: &str = "interflow";

/// QUIC session construction parameters: everything the tunnel needs beyond
/// identity/TLS, single-sourced from the agent config + negotiation outcome.
///
/// Carries the stall supervision choice, establishment bound, transport
/// tuning, and the dispatch budget.
#[derive(Debug, Clone, Copy)]
pub struct QuicSessionParams {
    /// Critical-task stall timeout: `None` derives from the negotiated hub
    /// cadence; `Some(ZERO)` disables the stall monitor; `Some(n)` pins.
    pub stall_override: Option<Duration>,
    /// Bound for the registration exchange (Hello → HelloAck).
    pub establish_timeout: Duration,
    /// Endpoint transport parameters (idle/keepalive).
    pub transport: QuicEndpointParams,
    /// Local concurrent-stream limit the dispatch event channel is sized
    /// from (agent `max_incoming_streams`; 0 = the shared floor).
    pub incoming_streams_budget: usize,
}

impl QuicSessionParams {
    /// The shared-profile defaults (derive stall from negotiation; the
    /// shared establish bound; default transport; floor-sized channel).
    pub const DEFAULT: Self = Self {
        stall_override: None,
        establish_timeout: crate::tunnel::agent::DEFAULT_REQUEST_ESTABLISH_TIMEOUT,
        transport: QuicEndpointParams::DEFAULT,
        incoming_streams_budget: 0,
    };
}

impl Default for QuicSessionParams {
    fn default() -> Self {
        Self::DEFAULT
    }
}

/// QUIC endpoint transport parameters (idle timeout + keepalive), sourced
/// from the shared transport profile / the endpoint TOML `[transport.quic]`.
///
/// QUIC negotiates the idle timeout as the *minimum* of the two endpoints'
/// values — which is exactly why these must be configured symmetrically
/// (same schema, same defaults on hub and agent) instead of per side: a
/// value raised on one endpoint alone silently does nothing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct QuicEndpointParams {
    /// Connection idle timeout (milliseconds).
    pub max_idle_timeout_ms: u32,
    /// KeepAlive interval.
    pub keepalive_interval: Duration,
}

impl QuicEndpointParams {
    /// The shared-profile defaults (frp lineage: 30s idle / 10s keepalive).
    pub const DEFAULT: Self = Self {
        max_idle_timeout_ms: crate::config::params::transport::DEFAULT_QUIC_IDLE_TIMEOUT_MS,
        keepalive_interval: crate::config::params::transport::DEFAULT_QUIC_KEEPALIVE_INTERVAL,
    };
}

impl Default for QuicEndpointParams {
    fn default() -> Self {
        Self::DEFAULT
    }
}

/// Transport-stats sampling interval (cheap snapshot; always on). The CC
/// forensics anchor for the 2026-09-16 quic egress-stall case file: cwnd
/// collapse / loss bursts / black holes show up in these logs with no
/// extra tooling. Counters are cumulative — diff adjacent samples.
const STATS_SAMPLE_INTERVAL: Duration = Duration::from_secs(10);
/// Per-stream write-command channel capacity (backpressure threshold).
const WRITE_CHANNEL_CAP: usize = 64;

/// Floor for the QUIC steady-state silence budget
/// ([`QuicTunnel::steady_state_liveness`]). Even with heartbeat disabled
/// the in-connection policy pull (10s cadence) keeps a downlink alive, so
/// 90s ≈ 9 missed pulls is unambiguously fatal; with heartbeat the budget
/// rides the cadence instead (`interval × 6`, see
/// [`steady_state_silence_budget`]). Always strictly above the in-tree
/// stall/death lines (75s at the default cadence) so a living task tree
/// reacts first and the out-of-tree probe stays a pure backstop.
///
/// The 2026-10-09 one-way-blackhole case added the supervisor's demanding
/// tier (answer-required roundtrips on a fixed monotonic cadence), so this
/// cadence-derived budget no longer carries the detection burden alone —
/// a deployment that raises the heartbeat interval inflates only the
/// passive tier's window, never the demanding tier's.
const MIN_STEADY_STATE_SILENCE_BUDGET: Duration = Duration::from_secs(90);

/// The QUIC backend's steady-state silence budget: with heartbeat,
/// `interval × 6`; without, the floor (the policy-pull cadence is the
/// surviving downlink guarantee). Public to the crate for unit tests.
pub(crate) fn steady_state_silence_budget(heartbeat: Option<&HeartbeatAd>) -> Duration {
    heartbeat
        .map_or(Duration::ZERO, |ad| {
            Duration::from_secs(ad.interval_secs.saturating_mul(6))
        })
        .max(MIN_STEADY_STATE_SILENCE_BUDGET)
}

/// Capability bit in the Hello/HelloAck caps word: the QUIC DATAGRAM
/// (RFC 9221) fast path (shared table: `interflow_contract::caps`).
pub const CAP_DATAGRAM: u32 = interflow_contract::caps::DATAGRAM;

/// The QUIC guaranteed minimum datagram/packet budget (RFC 9000 initial
/// packet size — endpoints must be able to process 1200-byte packets
/// throughout the connection).
const QUIC_MIN_PACKET_BUDGET: usize = 1200;
/// Worst-case QUIC packet overhead around a DATAGRAM frame's payload:
/// short-header flags(1) + DCID(20, max connection-id length) + packet
/// number(4) + AEAD tag(16) + DATAGRAM frame type varint(1) + length
/// varint(2) = 44; rounded to 64 to absorb future header expansion. A
/// datagram larger than `1200 − overhead` exceeds the initial MTU and is
/// dropped by the network rather than fragmented — the budget keeps the
/// fast path's whole frame inside one initial-MTU packet.
const QUIC_PACKET_OVERHEAD_ALLOWANCE: usize = 64;

/// Budget for a whole frame carried in a DATAGRAM:
/// `1200 − 41 (frame header) − 64 (packet overhead allowance)` = 1095.
///
/// (The pre-2026-10-10 value 1023 was a fossil of the old 177-byte
/// worst-case frame header era — carried over unchanged when the header
/// shrank to 41 bytes, silently forfeiting ~72 bytes per datagram.)
/// Datagrams over budget fall back to stream carriage (reliable and
/// ordered; under mixed carriage, UDP semantics allow out-of-order
/// arrival).
pub const DATAGRAM_FRAME_BUDGET: usize =
    QUIC_MIN_PACKET_BUDGET - wire::FRAME_HEADER_LEN - QUIC_PACKET_OVERHEAD_ALLOWANCE;

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
    circuit: CircuitToken,
    /// The hub's registration declaration verbatim (heartbeat cadence +
    /// observed egress); kept so embedders can surface the hub-confirmed
    /// receipt after the exchange ([`QuicTunnel::negotiated`]).
    negotiated: RegisterResponse,
    /// The local endpoint (held to keep the connection alive; the QUIC connection's UDP socket hangs off the endpoint).
    endpoint: quinn::Endpoint,
    conn: quinn::Connection,
    /// Session-termination token (a same-node clone passed in at connect): `shutdown()` cancels it,
    /// stopping the accept/control-stream/DATAGRAM read loops.
    token: CancellationToken,
    dispatch: Arc<TunnelDispatch>,
    /// stream_id → write handle (one shared table for locally initiated and hub-initiated streams).
    streams: Arc<StdMutex<HashMap<StreamId, StreamHandle>>>,
    /// The negotiated DATAGRAM capability (true only if both this end and the hub support it).
    datagram_ok: bool,
    /// Streams whose OpenAck has been received (small Data packets on these streams take the DATAGRAM fast path).
    datagram_streams: Arc<StdMutex<std::collections::HashSet<StreamId>>>,
    /// The effective critical-task stall timeout (negotiated or pinned at
    /// connect) — session-level consumers (e.g. the agent's closed watcher)
    /// read it so every critical task in the session shares one budget.
    stall_timeout: Duration,
    /// Semantic target → opaque route token, valid for this QUIC session only.
    routes: StdMutex<HashMap<String, RouteToken>>,
    /// Unix millis of the last inbound byte on any receive path (control
    /// frames, stream data, datagrams, in-connection request/response
    /// exchanges). Task-independent shared state — the out-of-tree silence
    /// probe reads it without any session task being alive
    /// ([`SteadyStateLiveness`]).
    last_rx: Arc<AtomicU64>,
}

/// Encodes a frame as `Bytes`.
fn encode_frame_bytes(
    frame_type: FrameType,
    flags: u8,
    stream_id: StreamId,
    circuit: CircuitToken,
    payload: &[u8],
) -> Result<Bytes> {
    let mut buf = BytesMut::with_capacity(wire::decoded_frame_len(payload.len()));
    wire::encode_frame(frame_type, flags, stream_id, circuit, payload, &mut buf).ok_or_else(
        || {
            InterflowError::protocol(format!(
                "QUIC frame encoding failed (contract violation): {stream_id}"
            ))
        },
    )?;
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
async fn control_read_loop(
    mut rx: quinn::RecvStream,
    tx: mpsc::Sender<WriteCmd>,
    circuit: CircuitToken,
    last_rx: Arc<AtomicU64>,
    beat: Beat,
    beat_every: Duration,
) {
    let mut buf = BytesMut::with_capacity(256);
    let mut chunk = [0u8; 1024];
    loop {
        beat.beat();
        let n = match beat.during(beat_every, rx.read(&mut chunk)).await {
            Ok(Some(n)) => n,
            Ok(None) | Err(_) => break,
        };
        last_rx.store(unix_millis_now(), Ordering::Relaxed);
        buf.extend_from_slice(&chunk[..n]);
        while let Some(frame) = TunnelDispatch::decode_tunnel_data(&mut buf) {
            if matches!(frame.stream_type, FrameType::Ping) {
                // The Pong carries this agent's own circuit (Ping is
                // hub-origin with the zero circuit; the reply re-identifies).
                let Ok(pong) = encode_frame_bytes(FrameType::Pong, 0, StreamId::ZERO, circuit, b"")
                else {
                    return;
                };
                if tx.send(WriteCmd::Frame(pong)).await.is_err() {
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
    streams: Arc<StdMutex<HashMap<StreamId, StreamHandle>>>,
    datagram_streams: Arc<StdMutex<std::collections::HashSet<StreamId>>>,
    last_rx: Arc<AtomicU64>,
    shutdown: CancellationToken,
    beat: Beat,
    beat_every: Duration,
) {
    // Fault injection: panic at accept-loop start (inbound-stream intake
    // death while the connection stays healthy).
    crate::fault::trigger(crate::fault::FaultPoint::QuicAcceptLoop);
    loop {
        beat.beat();
        let (tx, rx) = tokio::select! {
            () = shutdown.cancelled() => break,
            r = beat.during(beat_every, conn.accept_bi()) => match r {
                Ok(pair) => pair,
                Err(_) => break, // connection closed
            },
        };
        last_rx.store(unix_millis_now(), Ordering::Relaxed);
        let dispatch = dispatch.clone();
        let streams = streams.clone();
        let datagram_streams = datagram_streams.clone();
        let stream_last_rx = last_rx.clone();
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
                stream_id: opened.stream_id,
                origin: FrameOrigin::from_parts(opened.flags, opened.circuit),
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
                () = stream_read_loop(rx, buf, dispatch, Some(datagram_streams), stream_last_rx) => {}
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
    datagram_streams: Option<Arc<StdMutex<std::collections::HashSet<StreamId>>>>,
    last_rx: Arc<AtomicU64>,
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
                    .insert(td.stream_id);
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
        last_rx.store(unix_millis_now(), Ordering::Relaxed);
        buf.extend_from_slice(&chunk[..n]);
        for td in process(&mut buf) {
            dispatch.dispatch(td).await;
        }
    }
}

/// DATAGRAM receive loop: hub-relayed datagram frames → dispatch (same rules as stream frames).
async fn datagram_read_loop(
    conn: quinn::Connection,
    dispatch: Arc<TunnelDispatch>,
    last_rx: Arc<AtomicU64>,
    beat: Beat,
    beat_every: Duration,
) {
    loop {
        beat.beat();
        let datagram = match beat.during(beat_every, conn.read_datagram()).await {
            Ok(d) => d,
            Err(_) => break, // connection closed
        };
        last_rx.store(unix_millis_now(), Ordering::Relaxed);
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
    /// Resolves (and caches) one semantic target into a session-scoped route
    /// token using a short-lived QUIC control stream.
    async fn resolve_route(&self, target_agent: &str) -> Result<RouteToken> {
        let cached = self
            .routes
            .lock()
            .map_err(|_| InterflowError::protocol("route cache poisoned"))?
            .get(target_agent)
            .copied();
        if let Some(route) = cached {
            return Ok(route);
        }
        if target_agent.len() > 256 {
            return Err(InterflowError::protocol("route target is too long"));
        }
        let request_id = crate::protocol::StreamId::random()?;
        let (mut tx, mut rx) = self.conn.open_bi().await.map_err(|e| {
            InterflowError::connection("QUIC route stream open failed".to_string()).with_source(e)
        })?;
        let request = encode_frame_bytes(
            FrameType::RouteRequest,
            0,
            request_id,
            CircuitToken::ZERO,
            &encode_route_request_payload(target_agent)?,
        )?;
        tx.write_all(&request).await.map_err(|e| {
            InterflowError::connection("QUIC route request write failed".to_string()).with_source(e)
        })?;
        let _ = tx.finish();

        let response = tokio::time::timeout(Duration::from_secs(10), async {
            let mut buf = BytesMut::with_capacity(256);
            let mut chunk = [0u8; 1024];
            loop {
                let n = rx
                    .read(&mut chunk)
                    .await
                    .map_err(|e| {
                        InterflowError::connection("QUIC route response read failed".to_string())
                            .with_source(e)
                    })?
                    .unwrap_or(0);
                if n == 0 {
                    return Err(InterflowError::connection(
                        "QUIC route stream closed before RouteAck",
                    ));
                }
                self.last_rx.store(unix_millis_now(), Ordering::Relaxed);
                buf.extend_from_slice(&chunk[..n]);
                match wire::decode_frame(&mut buf) {
                    wire::DecodeOutcome::Ok(frame) => return Ok(frame),
                    wire::DecodeOutcome::Error => {
                        return Err(InterflowError::protocol(
                            "invalid QUIC route response frame",
                        ));
                    }
                    wire::DecodeOutcome::Pending | wire::DecodeOutcome::UnknownType { .. } => {}
                }
            }
        })
        .await
        .map_err(|_| InterflowError::connection("QUIC route lease timed out"))??;
        if response.frame_type != FrameType::RouteAck || response.stream_id != request_id {
            return Err(InterflowError::protocol("unexpected QUIC route response"));
        }
        let Some(route) = decode_route_ack_payload(&response.payload)? else {
            return Err(InterflowError::connection("route lease rejected"));
        };
        self.routes
            .lock()
            .map_err(|_| InterflowError::protocol("route cache poisoned"))?
            .insert(target_agent.to_owned(), route);
        Ok(route)
    }

    /// Connects to the hub and completes Hello/HelloAck registration.
    ///
    /// `tls` is built by the caller (CA / mTLS client certificate / cert pin
    /// are all isomorphic with the h2 path); `server_name` is used for SNI.
    /// The overall timeout is applied by the caller (`AgentClient`).
    ///
    /// `stall_override` selects the critical-task stall timeout: `None`
    /// derives it from the hub-advertised heartbeat cadence (the HelloAck
    /// capability suffix; heartbeat-disabled hubs fall back to the fixed
    /// fallback — see [`RegisterResponse::task_stall_timeout`]);
    /// `Some(ZERO)` disables the stall monitor; `Some(n)` pins a value.
    ///
    /// `establish_timeout` bounds the registration exchange (Hello →
    /// HelloAck) — the same send→response-establishment semantics as the h2
    /// path's request-establish timeout. Pre-establishment there are no
    /// critical session tasks: this bound IS the establishment watchdog.
    ///
    /// `params` carries the session construction parameters (stall
    /// supervision, establishment bound, endpoint transport tuning, dispatch
    /// budget) — see [`QuicSessionParams`].
    pub async fn connect(
        agent_id: String,
        server_addr: SocketAddr,
        server_name: &str,
        tls: rustls::ClientConfig,
        tasks: SessionTasks,
        params: QuicSessionParams,
    ) -> Result<Self> {
        let shutdown = tasks.token().clone();
        let mut transport = quinn::TransportConfig::default();
        transport.keep_alive_interval(Some(params.transport.keepalive_interval));
        transport.max_idle_timeout(Some(quinn::IdleTimeout::from(quinn::VarInt::from_u32(
            params.transport.max_idle_timeout_ms,
        ))));

        let quic_tls =
            quinn::crypto::rustls::QuicClientConfig::try_from(Arc::new(tls)).map_err(|e| {
                InterflowError::config("invalid QUIC client TLS configuration".to_string())
                    .with_source(e)
            })?;
        let mut client_config = quinn::ClientConfig::new(Arc::new(quic_tls));
        client_config.transport_config(Arc::new(transport));

        let mut endpoint = quinn::Endpoint::client("0.0.0.0:0".parse().map_err(|e| {
            InterflowError::connection("QUIC local endpoint bind failed".to_string()).with_source(e)
        })?)
        .map_err(|e| {
            InterflowError::connection("QUIC local endpoint creation failed".to_string())
                .with_source(e)
        })?;
        endpoint.set_default_client_config(client_config);

        let conn = endpoint
            .connect(server_addr, server_name)
            .map_err(|e| {
                InterflowError::connection("QUIC connection initiation failed".to_string())
                    .with_source(e)
            })?
            .await
            .map_err(|e| {
                InterflowError::connection("QUIC handshake failed".to_string()).with_source(e)
            })?;

        // Control stream: open_bi → write Hello directly → await HelloAck.
        //
        // Nothing is spawned before establishment completes on purpose: a
        // wedged write or a silent hub is caught by `establish_timeout`
        // (plus the caller's overall connect timeout) — the establishment
        // phase needs no stall heartbeat of its own.
        let (mut control_tx, mut control_rx) = conn.open_bi().await.map_err(|e| {
            InterflowError::connection("QUIC control stream open failed".to_string()).with_source(e)
        })?;

        let hello_caps = CAP_DATAGRAM;
        let hello = encode_frame_bytes(
            FrameType::Hello,
            0,
            StreamId::ZERO,
            CircuitToken::ZERO,
            // The build tag rides the registration intent: the hub keeps a
            // fleet view of which binary each node runs (a stale node is a
            // one-line journal answer, not per-host forensics).
            &encode_hello_payload(hello_caps, &agent_id, Some(interflow_buildinfo::BUILD_TAG))?,
        )?;
        control_tx.write_all(&hello).await.map_err(|e| {
            InterflowError::connection("QUIC Hello write failed".to_string()).with_source(e)
        })?;

        // Await HelloAck (the hub sends an Error frame and closes the
        // connection on validation failure)
        let ack_frame = tokio::time::timeout(params.establish_timeout, async {
            let mut buf = BytesMut::with_capacity(256);
            let mut chunk = vec![0u8; 1024];
            loop {
                let n = control_rx
                    .read(&mut chunk)
                    .await
                    .map_err(|e| {
                        InterflowError::connection("HelloAck read failed".to_string())
                            .with_source(e)
                    })?
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
            InterflowError::connection(format!(
                "QUIC registration timed out (>{:?})",
                params.establish_timeout
            ))
        })??;

        // Capability negotiation: the HelloAck payload is the same JSON
        // declaration the h2 face carries as the /register body (the caps
        // word flattened in as a top-level key; see
        // RegisterResponse::parse_ack_payload).
        let (hub_caps, declaration) = match ack_frame.frame_type {
            FrameType::HelloAck => RegisterResponse::parse_ack_payload(&ack_frame.payload)?,
            FrameType::Error => {
                // A malformed Error payload must not mask the rejection
                // itself — degrade to the generic message.
                let detail = decode_error_payload(&ack_frame.payload).map_or_else(
                    |_| "hub rejected registration".to_string(),
                    |(code, text)| format!("hub rejected registration: {code:#06x} {text}"),
                );
                return Err(InterflowError::connection(detail));
            }
            other => {
                return Err(InterflowError::protocol(format!(
                    "expected HelloAck, got {other:?}"
                )));
            }
        };
        let datagram_ok = hub_caps & CAP_DATAGRAM != 0;

        // Effective critical-task stall: explicit pin/disable wins;
        // otherwise the advertised cadence's aging window (dead line), with
        // the fixed fallback for disabled heartbeat — the same derivation
        // family the h2 path uses, so a wedged task is never tolerated
        // longer than the hub's own eviction window on either transport.
        let task_stall_timeout = params
            .stall_override
            .unwrap_or_else(|| declaration.task_stall_timeout());
        let beat_every = beat_interval(task_stall_timeout);

        // Effective-parameter forensics (the 2026-10-09 case file §4's ask):
        // pin what this endpoint actually armed at connect time. QUIC
        // negotiates the idle timeout as the *minimum* of both endpoints'
        // advertised values, so incident timelines get reconciled against
        // logged facts instead of guesses about the deployed configs.
        info!(
            idle_timeout_ms = params.transport.max_idle_timeout_ms,
            keepalive_interval_ms = u64::try_from(params.transport.keepalive_interval.as_millis())
                .unwrap_or(u64::MAX),
            heartbeat_interval_secs =
                ?declaration.heartbeat.as_ref().map(|ad| ad.interval_secs),
            "QUIC session established (effective transport parameters)"
        );

        // Pong write path: the control-stream forwarding task takes over
        // AFTER establishment. Critical under the death contract: its death
        // takes the Pong path (and every outbound control frame) with it.
        let (wtx, wrx) = mpsc::channel(WRITE_CHANNEL_CAP);
        // Out-of-tree receive-liveness ledger: registration just completed,
        // so "now" is the honest initial freshness (see SteadyStateLiveness).
        let last_rx = Arc::new(AtomicU64::new(unix_millis_now()));
        tasks.spawn_critical(
            "quic-control-write",
            Some(task_stall_timeout),
            move |beat| control_write_forward(control_tx, wrx, beat, beat_every),
        );
        // pong_tx is held long-term: the control-stream channel never
        // closes; the forwarding task lives as long as the connection
        let pong_tx = wtx;

        let dispatch = Arc::new(TunnelDispatch::with_stream_limit(
            params.incoming_streams_budget,
        ));
        let streams: Arc<StdMutex<HashMap<StreamId, StreamHandle>>> =
            Arc::new(StdMutex::new(HashMap::new()));
        let datagram_streams: Arc<StdMutex<std::collections::HashSet<StreamId>>> =
            Arc::new(StdMutex::new(std::collections::HashSet::new()));

        // Control-stream read loop: Ping → Pong (the Pong goes through the
        // wtx forwarding write task). Critical under the death contract:
        // its death silences heartbeat answering while the connection stays
        // healthy.
        {
            let shutdown_control = shutdown.clone();
            let control_last_rx = last_rx.clone();
            tasks.spawn_critical(
                "quic-control-read",
                Some(task_stall_timeout),
                move |beat| async move {
                    // Fault injection: panic at read-loop start (the heartbeat
                    // answering task's death scenario).
                    crate::fault::trigger(crate::fault::FaultPoint::QuicControlReadLoop);
                    tokio::select! {
                        () = shutdown_control.cancelled() => {}
                        () = control_read_loop(control_rx, pong_tx, declaration.circuit_token, control_last_rx, beat, beat_every) => {}
                    }
                },
            );
        }

        // Accept loop: hub-initiated traffic streams (egress role).
        // Critical under the death contract: its death stops all inbound
        // stream intake while the connection stays healthy.
        {
            let accept_conn = conn.clone();
            let accept_dispatch = dispatch.clone();
            let accept_streams = streams.clone();
            let accept_datagrams = datagram_streams.clone();
            let accept_last_rx = last_rx.clone();
            let accept_shutdown = shutdown.clone();
            tasks.spawn_critical("quic-accept", Some(task_stall_timeout), move |beat| {
                accept_loop(
                    accept_conn,
                    accept_dispatch,
                    accept_streams,
                    accept_datagrams,
                    accept_last_rx,
                    accept_shutdown,
                    beat,
                    beat_every,
                )
            });
        }

        // DATAGRAM receive loop (enabled only on successful negotiation; the
        // hub's relayed datagrams arrive here)
        if datagram_ok {
            let conn2 = conn.clone();
            let dispatch2 = dispatch.clone();
            let datagram_last_rx = last_rx.clone();
            let shutdown2 = shutdown.clone();
            tasks.spawn_critical(
                "quic-datagram",
                Some(task_stall_timeout),
                move |beat| async move {
                    tokio::select! {
                        () = shutdown2.cancelled() => {}
                        () = datagram_read_loop(conn2, dispatch2, datagram_last_rx, beat, beat_every) => {}
                    }
                },
            );
        }

        // Transport-stats sampler (see STATS_SAMPLE_INTERVAL) — auxiliary:
        // forensics only, its death degrades nothing.
        {
            let conn_stats = conn.clone();
            let shutdown_stats = shutdown.clone();
            tasks.spawn_auxiliary(async move {
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
            circuit: declaration.circuit_token,
            negotiated: declaration,
            endpoint,
            conn,
            token: shutdown,
            dispatch,
            streams,
            datagram_ok,
            datagram_streams,
            stall_timeout: task_stall_timeout,
            routes: StdMutex::new(HashMap::new()),
            last_rx,
        })
    }

    /// The session's effective critical-task stall timeout (negotiated from
    /// the hub cadence, or pinned via agent config at connect).
    #[must_use]
    pub const fn stall_timeout(&self) -> Duration {
        self.stall_timeout
    }

    /// The hub's registration declaration for this session (the HelloAck
    /// content) — the receipt an embedder surfaces as "hub-confirmed"
    /// connectivity detail.
    #[must_use]
    pub const fn negotiated(&self) -> &RegisterResponse {
        &self.negotiated
    }

    fn lookup_handle(&self, stream_id: StreamId) -> Option<StreamHandle> {
        self.streams
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .get(&stream_id)
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

    /// Writes one frame on the stream (agent-origin; the hub derives response
    /// direction from the relay-stream side under QUIC — both directions ride
    /// the same bidirectional stream).
    async fn send_frame_on(
        &self,
        stream_id: StreamId,
        frame_type: FrameType,
        flags: u8,
        payload: &[u8],
    ) -> Result<()> {
        let handle = self
            .lookup_handle(stream_id)
            .ok_or_else(|| InterflowError::stream(format!("QUIC stream not found: {stream_id}")))?;
        let buf = encode_frame_bytes(frame_type, flags, stream_id, self.circuit, payload)?;
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
async fn control_write_forward(
    mut tx: quinn::SendStream,
    mut rx: mpsc::Receiver<WriteCmd>,
    beat: Beat,
    beat_every: Duration,
) {
    let mut hello_written = false;
    loop {
        beat.beat();
        let Some(cmd) = beat.during(beat_every, rx.recv()).await else {
            return;
        };
        let buf = match cmd {
            WriteCmd::Frame(b) | WriteCmd::CloseFrame(b) => b,
        };
        if let Err(e) = tx.write_all(&buf).await {
            debug!("QUIC control stream write failed: {e}");
            return;
        }
        // Fault injection: wedge after the first forwarded frame (the first
        // Pong) — the Pong path dies post-registration while the connection
        // stays healthy; only a stall heartbeat catches it.
        if !hello_written {
            hello_written = true;
            if crate::fault::stall(crate::fault::FaultPoint::QuicControlWriteStall) {
                std::future::pending::<()>().await;
            }
        }
    }
}

#[async_trait]
impl TunnelTransport for QuicTunnel {
    async fn send_open_with(
        &self,
        stream_id: StreamId,
        target_agent: &str,
        proto: StreamProto,
        e2e: bool,
    ) -> Result<()> {
        let (tx, rx) = self.conn.open_bi().await.map_err(|e| {
            InterflowError::connection("QUIC stream open failed".to_string()).with_source(e)
        })?;

        let (wtx, wrx) = mpsc::channel(WRITE_CHANNEL_CAP);
        tokio::spawn(stream_write_loop(tx, wrx));
        self.streams
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .insert(stream_id, StreamHandle { tx: wtx });

        // Read loop (return-path frames on this stream → dispatch; the
        // ingress role hits via the response-direction dedicated channel)
        let dispatch = self.dispatch.clone();
        let datagram_set = if self.datagram_ok {
            Some(self.datagram_streams.clone())
        } else {
            None
        };
        let token = self.token.clone();
        let open_last_rx = self.last_rx.clone();
        tokio::spawn(async move {
            tokio::select! {
                () = token.cancelled() => {}
                () = stream_read_loop(rx, BytesMut::new(), dispatch, datagram_set, open_last_rx) => {}
            }
        });

        // The payload is the raw 16-byte route token (the data plane stays
        // opaque; the transport resolves the local semantic target through
        // the control-plane route lease first).
        let route = self.resolve_route(target_agent).await?;
        let flags = proto.as_flag() | (u8::from(e2e) * crate::protocol::FLAG_E2E);
        self.send_frame_on(stream_id, FrameType::Open, flags, &route.to_bytes())
            .await
    }

    async fn send_data(&self, stream_id: StreamId, data: Bytes) -> Result<()> {
        self.send_data_smart(stream_id, data).await
    }

    async fn send_data_response(&self, stream_id: StreamId, data: Bytes) -> Result<()> {
        // QUIC bidirectional streams have no direction concept: responses are written on the same stream
        self.send_data_smart(stream_id, data).await
    }

    async fn send_close(&self, stream_id: StreamId) -> Result<()> {
        self.close_stream(stream_id, CloseReason::CloseFrame).await
    }

    async fn send_close_response(&self, stream_id: StreamId, reason: CloseReason) -> Result<()> {
        self.close_stream(stream_id, reason).await
    }

    async fn register_stream(&self, stream_id: StreamId) -> mpsc::Receiver<TunnelData> {
        self.dispatch.register_stream(stream_id).await
    }

    async fn unregister_stream(&self, stream_id: StreamId) {
        self.dispatch.unregister_stream(stream_id).await;
    }

    async fn take_incoming_streams(
        &self,
    ) -> Option<mpsc::Receiver<crate::tunnel::transport::IncomingStream>> {
        self.dispatch.take_incoming_streams()
    }

    async fn unregister_incoming_stream(&self, stream_id: StreamId) {
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
            .remove(&stream_id);
        self.datagram_streams
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .remove(&stream_id);
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

    /// The QUIC face of the policy watcher's conditional pull: one
    /// short-lived bi-stream per request (the same carriage as the route
    /// lease — `resolve_route`), correlation id in the frame's `stream_id`,
    /// the answer frame on the same stream. The requester is the connection's
    /// registered agent, so the frame carries no circuit. A mid-rebuild
    /// session surfaces as the usual connection error; the watcher retries
    /// next tick. A hub that cannot serve the request answers with an Error
    /// frame on the same stream (fail-closed, never a silent drop-to-timeout).
    async fn pull_policy(&self, seen: u64) -> Result<PolicyPull> {
        let response = self
            .control_roundtrip(
                FrameType::PolicyPullRequest,
                FrameType::PolicyPullResponse,
                &encode_policy_pull_request(seen),
            )
            .await?;
        decode_policy_pull_response(&response.payload)
    }

    /// The QUIC face of the peer-observability read (`GET /agents`): one
    /// short-lived bi-stream per request, empty request payload, the answer
    /// frame on the same stream. The payload is the same JSON array the h2
    /// face serves, decoded into the transport-uniform
    /// [`PeerInfo`](crate::tunnel::transport::PeerInfo) shape. Same
    /// soft-fail contract as [`Self::pull_policy`].
    async fn list_agents(&self) -> Result<Vec<crate::tunnel::transport::PeerInfo>> {
        let response = self
            .control_roundtrip(FrameType::PeerListRequest, FrameType::PeerListResponse, &[])
            .await?;
        serde_json::from_slice(&response.payload).map_err(|e| {
            InterflowError::protocol("QUIC peer list payload is not the peer shape".to_string())
                .with_source(e)
        })
    }

    /// The QUIC face of the proposal submission (kube-CSR shape): same
    /// short-bi-stream carriage, JSON payload in / answer out.
    async fn submit_stream_proposal(
        &self,
        request: &crate::tunnel::transport::StreamProposalRequest,
    ) -> Result<crate::tunnel::transport::ProposalSubmitOutcome> {
        let payload = serde_json::to_vec(request).map_err(|e| {
            InterflowError::protocol("QUIC proposal request encode failed".to_string())
                .with_source(e)
        })?;
        let response = self
            .control_roundtrip(
                FrameType::ProposalSubmitRequest,
                FrameType::ProposalSubmitResponse,
                &payload,
            )
            .await?;
        serde_json::from_slice(&response.payload).map_err(|e| {
            InterflowError::protocol("QUIC proposal answer is not the outcome shape".to_string())
                .with_source(e)
        })
    }

    /// The QUIC face of the receipts query: this node's own proposals.
    async fn my_proposals(&self) -> Result<Vec<crate::tunnel::transport::ProposalReceipt>> {
        let response = self
            .control_roundtrip(
                FrameType::ProposalMineRequest,
                FrameType::ProposalMineResponse,
                &[],
            )
            .await?;
        serde_json::from_slice(&response.payload).map_err(|e| {
            InterflowError::protocol("QUIC proposal receipts payload is malformed".to_string())
                .with_source(e)
        })
    }

    /// The QUIC face of the demanding liveness roundtrip: a
    /// [`FrameType::LivenessPing`] on the shared control-roundtrip
    /// carriage, a [`FrameType::LivenessPong`] on the same stream. The
    /// control-stream heartbeat Ping does not apply here — that form is
    /// contract-pinned to zero stream_id + HUB_ORIGIN (hub-authored); the
    /// roundtrip form carries the correlation id in the frame's
    /// `stream_id` exactly like every other request on this carriage, and
    /// [`Self::control_roundtrip`] validates the echo.
    async fn liveness_roundtrip(&self) -> Result<()> {
        self.control_roundtrip(FrameType::LivenessPing, FrameType::LivenessPong, &[])
            .await
            .map(|_| ())
    }

    fn steady_state_liveness(&self) -> Option<SteadyStateLiveness> {
        Some(SteadyStateLiveness {
            last_rx_unix_millis: self.last_rx.load(Ordering::Relaxed),
            silence_budget: steady_state_silence_budget(self.negotiated.heartbeat.as_ref()),
        })
    }
}

impl QuicTunnel {
    /// One control-plane request/response round trip on a fresh
    /// short-lived bi-stream: send `request_type` with `payload`
    /// (correlation id in the frame's `stream_id`, zero circuit — the
    /// requester is always the connection's registered agent), await
    /// `expected_type` on the same stream. The shared carriage of the
    /// policy pull, the peer list, and the stream-proposal ops. The hub
    /// answers every request — an unsupported or malformed request is
    /// answered with an Error frame on the same stream, decoded here into
    /// an immediate failure (paired-build doctrine: no silent
    /// drop-to-timeout); a mid-rebuild session surfaces as the usual
    /// connection error. The 10s bound below is a defensive deadline, not
    /// a tolerated failure mode.
    async fn control_roundtrip(
        &self,
        request_type: FrameType,
        expected_type: FrameType,
        payload: &[u8],
    ) -> Result<crate::protocol::frame::DecodedFrame> {
        let request_id = crate::protocol::StreamId::random()?;
        let (mut tx, mut rx) = self.conn.open_bi().await.map_err(|e| {
            InterflowError::connection("QUIC control stream open failed".to_string()).with_source(e)
        })?;
        let request = encode_frame_bytes(request_type, 0, request_id, CircuitToken::ZERO, payload)?;
        tx.write_all(&request).await.map_err(|e| {
            InterflowError::connection("QUIC control request write failed".to_string())
                .with_source(e)
        })?;
        let _ = tx.finish();

        let response = tokio::time::timeout(Duration::from_secs(10), async {
            let mut buf = BytesMut::with_capacity(64);
            let mut chunk = [0u8; 1024];
            loop {
                let n = rx
                    .read(&mut chunk)
                    .await
                    .map_err(|e| {
                        InterflowError::connection("QUIC control response read failed".to_string())
                            .with_source(e)
                    })?
                    .unwrap_or(0);
                if n == 0 {
                    return Err(InterflowError::connection(
                        "QUIC control stream closed before the response frame",
                    ));
                }
                self.last_rx.store(unix_millis_now(), Ordering::Relaxed);
                buf.extend_from_slice(&chunk[..n]);
                match wire::decode_frame(&mut buf) {
                    wire::DecodeOutcome::Ok(frame) => {
                        // The hub's explicit refusal: decode the code + text
                        // and fail immediately — never a generic mismatch
                        // error, never a silent drop-to-timeout.
                        if frame.frame_type == FrameType::Error {
                            let text =
                                crate::tunnel::negotiation::decode_error_payload(&frame.payload)
                                    .map_or_else(
                                        |_| "hub rejected the request".to_string(),
                                        |(code, text)| {
                                            format!(
                                                "hub rejected the request (code {code}): {text}"
                                            )
                                        },
                                    );
                            return Err(InterflowError::protocol(text));
                        }
                        return Ok(frame);
                    }
                    wire::DecodeOutcome::Error => {
                        return Err(InterflowError::protocol(
                            "invalid QUIC control response frame",
                        ));
                    }
                    wire::DecodeOutcome::Pending | wire::DecodeOutcome::UnknownType { .. } => {}
                }
            }
        })
        .await
        .map_err(|_| InterflowError::connection("QUIC control roundtrip timed out"))??;
        if response.frame_type != expected_type || response.stream_id != request_id {
            return Err(InterflowError::protocol("unexpected QUIC control response"));
        }
        Ok(response)
    }

    /// Data send: streams within budget that have received OpenAck take the
    /// DATAGRAM fast path (unreliable and unordered — zero translation of
    /// UDP semantics; packet loss does not HOL the whole connection);
    /// otherwise fall back to stream carriage. Control frames such as
    /// Open/Close always ride a stream (reliable ordering is a hard
    /// prerequisite for session establishment).
    async fn send_data_smart(&self, stream_id: StreamId, data: Bytes) -> Result<()> {
        if self.datagram_ok
            && data.len() <= DATAGRAM_FRAME_BUDGET
            && self
                .datagram_streams
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .contains(&stream_id)
        {
            let frame = encode_frame_bytes(FrameType::Data, 0, stream_id, self.circuit, &data)?;
            return self.conn.send_datagram(frame).map_err(|e| {
                InterflowError::connection("QUIC DATAGRAM send failed".to_string()).with_source(e)
            });
        }
        self.send_frame_on(stream_id, FrameType::Data, 0, &data)
            .await
    }

    /// Closes the stream: writes the Close frame (payload = the u8 reason
    /// code) + FIN and removes the handle (idempotent).
    async fn close_stream(&self, stream_id: StreamId, reason: CloseReason) -> Result<()> {
        let Some(handle) = self
            .streams
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .remove(&stream_id)
        else {
            return Ok(());
        };
        self.datagram_streams
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .remove(&stream_id);
        let buf = encode_frame_bytes(
            FrameType::Close,
            0,
            stream_id,
            self.circuit,
            &[reason.as_code()],
        )?;
        // The write task FINs automatically after receiving the CloseFrame
        let _ = handle.tx.send(WriteCmd::CloseFrame(buf)).await;
        Ok(())
    }
}

#[cfg(test)]
#[allow(clippy::panic, clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use crate::protocol::CircuitToken;
    use crate::tunnel::negotiation::HeartbeatAd;

    /// The Hello frame satisfies the type × field contract (zero ids, no
    /// origin flags) and the Pong frame carries the sender circuit.
    #[test]
    fn hello_and_pong_frames_satisfy_the_contract() {
        let hello = encode_frame_bytes(
            FrameType::Hello,
            0,
            StreamId::ZERO,
            CircuitToken::ZERO,
            &encode_hello_payload(CAP_DATAGRAM, "edge-1", None).unwrap(),
        )
        .unwrap();
        let mut rx = BytesMut::from(&hello[..]);
        let wire::DecodeOutcome::Ok(f) = wire::decode_frame(&mut rx) else {
            panic!("hello must decode");
        };
        assert_eq!(f.frame_type, FrameType::Hello);
        assert!(f.stream_id.is_zero() && f.circuit.is_zero());

        let circuit = CircuitToken::from_hex("12078a05e14f4e2c99b1679be1df7c30").unwrap();
        let pong = encode_frame_bytes(FrameType::Pong, 0, StreamId::ZERO, circuit, b"").unwrap();
        let mut rx = BytesMut::from(&pong[..]);
        let wire::DecodeOutcome::Ok(f) = wire::decode_frame(&mut rx) else {
            panic!("pong must decode");
        };
        assert_eq!(f.frame_type, FrameType::Pong);
        assert_eq!(f.circuit, circuit);
        assert!(f.stream_id.is_zero());

        // HeartbeatAd is still referenced by the negotiation derivations.
        let _ = HeartbeatAd {
            interval_secs: 1,
            max_missed: 0,
        };
    }

    /// The steady-state silence budget contract: heartbeat-enabled hubs ride
    /// `interval × 6`; heartbeat-disabled hubs (and any cadence whose product
    /// lands below the floor) fall back to the 90s floor — the 10s
    /// in-connection policy pull is the surviving downlink guarantee. The
    /// budget must always stay strictly above the default-cadence in-tree
    /// stall/death line (75s) so a living tree reacts first.
    #[test]
    fn steady_state_silence_budget_rides_the_cadence_with_a_floor() {
        use crate::tunnel::negotiation::HeartbeatAd;
        let disabled = steady_state_silence_budget(None);
        assert_eq!(disabled, MIN_STEADY_STATE_SILENCE_BUDGET);

        let fast = HeartbeatAd {
            interval_secs: 1,
            max_missed: 0,
        };
        assert_eq!(
            steady_state_silence_budget(Some(&fast)),
            MIN_STEADY_STATE_SILENCE_BUDGET,
            "a fast cadence's product must not undercut the floor"
        );

        let production = HeartbeatAd {
            interval_secs: 15,
            max_missed: 4,
        };
        let budget = steady_state_silence_budget(Some(&production));
        assert_eq!(budget, Duration::from_secs(90));
        assert!(
            budget > Duration::from_secs(15 * (4 + 1)),
            "the out-of-tree budget must strictly exceed the in-tree stall line"
        );

        let slow = HeartbeatAd {
            interval_secs: 60,
            max_missed: 4,
        };
        assert_eq!(
            steady_state_silence_budget(Some(&slow)),
            Duration::from_secs(360)
        );
    }
}
