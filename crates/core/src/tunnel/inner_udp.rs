//! Agent-to-agent inner QUIC for UDP datagrams.
//!
//! One outer tunnel stream carries one inner QUIC association. The direct
//! `quinn-proto` state machine treats outer `Data` payloads as inner UDP
//! packets; generated `Transmit` values are written back to the same stream.
//! All UDP application data rides QUIC DATAGRAM frames, preserving datagram
//! semantics while encrypting payload and target selection.

use std::collections::{HashMap, VecDeque};
use std::future::poll_fn;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::ops::{Deref, DerefMut};
use std::pin::pin;
use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::task::Poll;
use std::time::{Duration, Instant};

use bytes::{BufMut, Bytes, BytesMut};
use tokio::sync::mpsc;
use tokio::time::timeout;

use crate::error::{InterflowError, Result};
use crate::tunnel::agent::AgentTunnel;
use crate::tunnel::transport::TunnelData;

/// Inner association idle timeout. A new association resumes with the cached
/// rustls session ticket when traffic returns.
const ENDPOINT_DRIVER_IDLE: Duration = Duration::from_secs(300);
/// Maximum inner-QUIC packets queued toward a stalled outer tunnel.
const CARRIER_QUEUE_CAPACITY: usize = 1024;
/// Maximum decrypted application datagrams buffered for a stalled consumer.
const RECEIVED_DATAGRAM_CAPACITY: usize = 1024;
/// Byte cap for the decrypted application-datagram queue.
const RECEIVED_DATAGRAM_BYTES: usize = 1024 * 1024;

/// Direction of the outer carrier stream.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CarrierDirection {
    /// Ingress sends request-direction Data frames.
    Ingress,
    /// Egress sends response-direction Data frames.
    Egress,
}

/// A random inner UDP session identifier.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct SessionId(pub [u8; 16]);

impl SessionId {
    /// Generates a cryptographically random id.
    pub fn random() -> Self {
        let mut bytes = [0u8; 16];
        getrandom::fill(&mut bytes).expect("system RNG");
        Self(bytes)
    }

    const fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    fn is_zero(&self) -> bool {
        self.0.iter().all(|byte| *byte == 0)
    }
}

/// A random datagram identifier used to reassemble fragments.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct DatagramId(pub [u8; 16]);

impl DatagramId {
    /// Generates a cryptographically random id.
    pub fn random() -> Self {
        let mut bytes = [0u8; 16];
        getrandom::fill(&mut bytes).expect("system RNG");
        Self(bytes)
    }
}

/// Short result code carried on the encrypted control stream.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SessionReject {
    /// No matching UDP egress rule.
    NoTarget,
    /// The target is denied by policy or breaker.
    SecurityDenied,
    /// Local open-rate budget exhausted.
    RateLimited,
    /// Local concurrency budget exhausted.
    LocalLimit,
}

impl SessionReject {
    const fn code(self) -> u8 {
        match self {
            Self::NoTarget => 1,
            Self::SecurityDenied => 2,
            Self::RateLimited => 3,
            Self::LocalLimit => 4,
        }
    }

    const fn decode(code: u8) -> Option<Self> {
        match code {
            1 => Some(Self::NoTarget),
            2 => Some(Self::SecurityDenied),
            3 => Some(Self::RateLimited),
            4 => Some(Self::LocalLimit),
            _ => None,
        }
    }
}

/// Frames on each session's reliable inner QUIC control stream.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ControlFrame {
    /// Ingress proposes a session and (possibly dynamic) target selector.
    Open {
        session: SessionId,
        source_principal: String,
        source_fingerprint: [u8; 32],
        selector: crate::tunnel::TargetSelector,
    },
    /// Egress accepts the session.
    Accept(SessionId),
    /// Egress rejects the session before any LAN work.
    Reject(SessionId, SessionReject),
    /// Either side ends the session.
    Close(SessionId),
    /// Post-TLS source identity hello. It authorizes the association but never
    /// triggers a LAN dial.
    Identity {
        source_principal: String,
        source_fingerprint: [u8; 32],
    },
}

impl ControlFrame {
    /// Encodes a length-prefixed control frame.
    pub fn encode(&self) -> Result<Bytes> {
        let mut body = BytesMut::new();
        match self {
            Self::Open {
                session,
                source_principal,
                source_fingerprint,
                selector,
            } => {
                if session.is_zero() {
                    return Err(InterflowError::protocol(
                        "inner UDP session id must not be zero",
                    ));
                }
                body.put_u8(1);
                body.put_slice(session.as_bytes());
                if source_principal.len() > 2048 {
                    return Err(InterflowError::protocol(
                        "inner UDP source principal is too long",
                    ));
                }
                body.put_slice(source_fingerprint);
                body.put_u16(u16::try_from(source_principal.len()).map_err(|_| {
                    InterflowError::protocol("inner UDP source principal is too long")
                })?);
                body.put_slice(source_principal.as_bytes());
                let (kind, value): (u8, &str) = match selector {
                    crate::tunnel::TargetSelector::Default => (0, ""),
                    crate::tunnel::TargetSelector::Address(value)
                    | crate::tunnel::TargetSelector::Service(value) => (
                        if matches!(selector, crate::tunnel::TargetSelector::Address(_)) {
                            1
                        } else {
                            2
                        },
                        value,
                    ),
                };
                if value.len() > 256 {
                    return Err(InterflowError::protocol("inner UDP selector too long"));
                }
                body.put_u8(kind);
                body.put_u16(
                    u16::try_from(value.len())
                        .map_err(|_| InterflowError::protocol("selector too long"))?,
                );
                body.put_slice(value.as_bytes());
            }
            Self::Accept(session) => {
                body.put_u8(2);
                body.put_slice(session.as_bytes());
            }
            Self::Reject(session, reason) => {
                body.put_u8(3);
                body.put_slice(session.as_bytes());
                body.put_u8(reason.code());
            }
            Self::Close(session) => {
                body.put_u8(4);
                body.put_slice(session.as_bytes());
            }
            Self::Identity {
                source_principal,
                source_fingerprint,
            } => {
                if source_principal.len() > 2048 {
                    return Err(InterflowError::protocol(
                        "inner UDP identity principal is too long",
                    ));
                }
                body.put_u8(5);
                body.put_slice(source_fingerprint);
                body.put_u16(u16::try_from(source_principal.len()).map_err(|_| {
                    InterflowError::protocol("inner UDP identity principal is too long")
                })?);
                body.put_slice(source_principal.as_bytes());
            }
        }
        if body.len() > u16::MAX as usize {
            return Err(InterflowError::protocol("inner UDP control frame too long"));
        }
        let mut out = BytesMut::with_capacity(2 + body.len());
        out.put_u16(
            u16::try_from(body.len())
                .map_err(|_| InterflowError::protocol("inner UDP control frame too long"))?,
        );
        out.extend_from_slice(&body);
        Ok(out.freeze())
    }

    /// Decodes exactly one length-prefixed control frame and returns its byte length.
    pub fn decode(bytes: &[u8]) -> Result<(Self, usize)> {
        if bytes.len() < 3 {
            return Err(InterflowError::protocol("short inner UDP control frame"));
        }
        let body_len = u16::from_be_bytes([bytes[0], bytes[1]]) as usize;
        if bytes.len() < 2 + body_len {
            return Err(InterflowError::protocol(
                "incomplete inner UDP control frame",
            ));
        }
        let body = &bytes[2..2 + body_len];
        let kind = body
            .first()
            .copied()
            .ok_or_else(|| InterflowError::protocol("empty inner UDP control frame"))?;
        let tail = &body[1..];
        let frame = match kind {
            1 => {
                if tail.len() < 53 {
                    return Err(InterflowError::protocol("short inner UDP OPEN"));
                }
                let session = SessionId(
                    tail[..16]
                        .try_into()
                        .map_err(|_| InterflowError::protocol("invalid inner UDP session id"))?,
                );
                if session.is_zero() {
                    return Err(InterflowError::protocol(
                        "inner UDP session id must not be zero",
                    ));
                }
                let mut source_fingerprint = [0u8; 32];
                source_fingerprint.copy_from_slice(&tail[16..48]);
                let principal_len = u16::from_be_bytes([tail[48], tail[49]]) as usize;
                if principal_len > 2048 || tail.len() < 50 + principal_len {
                    return Err(InterflowError::protocol(
                        "invalid inner UDP source principal",
                    ));
                }
                let source_principal = std::str::from_utf8(&tail[50..50 + principal_len])
                    .map_err(|_| {
                        InterflowError::protocol("inner UDP source principal is not UTF-8")
                    })?
                    .to_owned();
                let tail = &tail[50 + principal_len..];
                let selector_kind = tail
                    .first()
                    .copied()
                    .ok_or_else(|| InterflowError::protocol("invalid inner UDP selector"))?;
                let value_len = u16::from_be_bytes([
                    *tail
                        .get(1)
                        .ok_or_else(|| InterflowError::protocol("invalid inner UDP selector"))?,
                    *tail
                        .get(2)
                        .ok_or_else(|| InterflowError::protocol("invalid inner UDP selector"))?,
                ]) as usize;
                if value_len > 256 || tail.len() != 3 + value_len {
                    return Err(InterflowError::protocol("invalid inner UDP selector"));
                }
                let value = std::str::from_utf8(&tail[3..])
                    .map_err(|_| InterflowError::protocol("inner UDP selector is not UTF-8"))?;
                let selector = match selector_kind {
                    0 if value.is_empty() => crate::tunnel::TargetSelector::Default,
                    1 if !value.is_empty() => {
                        crate::tunnel::TargetSelector::Address(value.to_owned())
                    }
                    2 if !value.is_empty() => {
                        crate::tunnel::TargetSelector::Service(value.to_owned())
                    }
                    _ => return Err(InterflowError::protocol("invalid inner UDP selector kind")),
                };
                Self::Open {
                    session,
                    source_principal,
                    source_fingerprint,
                    selector,
                }
            }
            2..=4 => {
                let expected = if kind == 3 { 17 } else { 16 };
                if tail.len() != expected {
                    return Err(InterflowError::protocol("invalid inner UDP control length"));
                }
                let session = SessionId(
                    tail[..16]
                        .try_into()
                        .map_err(|_| InterflowError::protocol("invalid inner UDP session id"))?,
                );
                match kind {
                    2 => Self::Accept(session),
                    3 => Self::Reject(
                        session,
                        SessionReject::decode(tail[16]).ok_or_else(|| {
                            InterflowError::protocol("invalid inner UDP reject code")
                        })?,
                    ),
                    _ => Self::Close(session),
                }
            }
            5 => {
                if tail.len() < 34 {
                    return Err(InterflowError::protocol("short inner UDP identity"));
                }
                let mut source_fingerprint = [0u8; 32];
                source_fingerprint.copy_from_slice(&tail[..32]);
                let principal_len = u16::from_be_bytes([tail[32], tail[33]]) as usize;
                if principal_len > 2048 || tail.len() != 34 + principal_len {
                    return Err(InterflowError::protocol(
                        "invalid inner UDP identity principal",
                    ));
                }
                let source_principal = std::str::from_utf8(&tail[34..])
                    .map_err(|_| {
                        InterflowError::protocol("inner UDP identity principal is not UTF-8")
                    })?
                    .to_owned();
                Self::Identity {
                    source_principal,
                    source_fingerprint,
                }
            }
            _ => return Err(InterflowError::protocol("unknown inner UDP control frame")),
        };
        Ok((frame, 2 + body_len))
    }
}

/// Maximum application bytes carried by one inner QUIC DATAGRAM.
pub const FRAGMENT_CHUNK: usize = 768;
/// Maximum fragments in one original UDP datagram.
pub const MAX_FRAGMENTS: usize = 128;
/// Maximum datagrams kept by one reassembler.
pub const MAX_PENDING_DATAGRAMS: usize = 128;
/// Maximum bytes buffered by one reassembler.
pub const MAX_REASSEMBLY_BYTES: usize = 256 * 1024;
/// Incomplete datagrams older than this are discarded as lost.
const REASSEMBLY_TTL: Duration = Duration::from_secs(2);

/// Header size preceding every UDP fragment.
const FRAGMENT_HEADER: usize = 36;

/// Encodes one datagram as one or more QUIC DATAGRAM payloads.
pub fn encode_datagram_fragments(session: SessionId, payload: &[u8]) -> Result<Vec<Bytes>> {
    if payload.len() > 65507 {
        return Err(InterflowError::protocol("UDP datagram exceeds 65507 bytes"));
    }
    let datagram = DatagramId::random();
    let count = payload.len().div_ceil(FRAGMENT_CHUNK).max(1);
    if count > MAX_FRAGMENTS {
        return Err(InterflowError::protocol(
            "UDP datagram requires too many fragments",
        ));
    }
    let mut out = Vec::with_capacity(count);
    if payload.is_empty() {
        let mut frame = BytesMut::with_capacity(FRAGMENT_HEADER);
        frame.put_slice(session.as_bytes());
        frame.put_slice(&datagram.0);
        frame.put_u16(0);
        frame.put_u16(1);
        return Ok(vec![frame.freeze()]);
    }
    for (index, chunk) in payload.chunks(FRAGMENT_CHUNK).enumerate() {
        let mut frame = BytesMut::with_capacity(FRAGMENT_HEADER + chunk.len());
        frame.put_slice(session.as_bytes());
        frame.put_slice(&datagram.0);
        frame.put_u16(
            u16::try_from(index)
                .map_err(|_| InterflowError::protocol("fragment index overflow"))?,
        );
        frame.put_u16(
            u16::try_from(count)
                .map_err(|_| InterflowError::protocol("fragment count overflow"))?,
        );
        frame.put_slice(chunk);
        out.push(frame.freeze());
    }
    Ok(out)
}

/// Errors produced while decoding or reassembling fragments.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FragmentError {
    ShortHeader,
    InvalidCount,
    DuplicateDatagram,
    TooManyPending,
    TooManyBytes,
}

#[derive(Debug)]
struct PartialDatagram {
    count: u16,
    received: HashMap<u16, Vec<u8>>,
    bytes: usize,
}

/// Bounded reassembler for inner UDP DATAGRAM fragments.
#[derive(Debug, Default)]
pub struct DatagramReassembler {
    pending: HashMap<(SessionId, DatagramId), PartialDatagram>,
    order: VecDeque<((SessionId, DatagramId), Instant)>,
    bytes: usize,
}

impl DatagramReassembler {
    /// Pushes one fragment, returning the complete datagram when its last
    /// missing piece arrives.
    pub fn push(&mut self, frame: &[u8]) -> std::result::Result<Option<Bytes>, FragmentError> {
        if frame.len() < FRAGMENT_HEADER {
            return Err(FragmentError::ShortHeader);
        }
        let session = SessionId(frame[..16].try_into().expect("16 byte prefix"));
        let datagram = DatagramId(frame[16..32].try_into().expect("16 byte prefix"));
        let index = u16::from_be_bytes([frame[32], frame[33]]);
        let count = u16::from_be_bytes([frame[34], frame[35]]);
        let count_total = usize::from(count);
        if count == 0 || count_total > MAX_FRAGMENTS || index >= count {
            return Err(FragmentError::InvalidCount);
        }
        let key = (session, datagram);
        let chunk = &frame[FRAGMENT_HEADER..];
        let now = Instant::now();
        self.prune_expired(now);
        if !self.pending.contains_key(&key) {
            self.evict_for(chunk.len());
            self.pending.insert(
                key,
                PartialDatagram {
                    count,
                    received: HashMap::new(),
                    bytes: 0,
                },
            );
            self.order.push_back((key, now));
        }
        let entry = self
            .pending
            .get_mut(&key)
            .ok_or(FragmentError::DuplicateDatagram)?;
        if entry.count != count {
            return Err(FragmentError::DuplicateDatagram);
        }
        if entry.received.contains_key(&index) {
            return Ok(None);
        }
        if self.bytes + chunk.len() > MAX_REASSEMBLY_BYTES {
            return Err(FragmentError::TooManyBytes);
        }
        entry.bytes += chunk.len();
        self.bytes += chunk.len();
        entry.received.insert(index, chunk.to_vec());
        if entry.received.len() != count_total {
            return Ok(None);
        }
        let mut partial = self
            .pending
            .remove(&key)
            .ok_or(FragmentError::DuplicateDatagram)?;
        self.bytes -= partial.bytes;
        self.order.retain(|(candidate, _)| candidate != &key);
        let mut out = Vec::with_capacity(partial.bytes);
        for index in 0..count {
            let chunk = partial
                .received
                .remove(&index)
                .ok_or(FragmentError::InvalidCount)?;
            out.extend_from_slice(&chunk);
        }
        Ok(Some(Bytes::from(out)))
    }

    /// Number of partially received datagrams.
    pub fn len(&self) -> usize {
        self.pending.len()
    }

    /// Whether no datagrams are pending.
    pub fn is_empty(&self) -> bool {
        self.pending.is_empty()
    }

    fn prune_expired(&mut self, now: Instant) {
        while let Some((_, created)) = self.order.front().copied() {
            if now.duration_since(created) < REASSEMBLY_TTL {
                break;
            }
            let Some(((session, datagram), _)) = self.order.pop_front() else {
                break;
            };
            if let Some(partial) = self.pending.remove(&(session, datagram)) {
                self.bytes = self.bytes.saturating_sub(partial.bytes);
            }
        }
    }

    fn evict_for(&mut self, incoming_bytes: usize) {
        while self.pending.len() >= MAX_PENDING_DATAGRAMS
            || self.bytes + incoming_bytes > MAX_REASSEMBLY_BYTES
        {
            let Some(((session, datagram), _)) = self.order.pop_front() else {
                break;
            };
            if let Some(partial) = self.pending.remove(&(session, datagram)) {
                self.bytes = self.bytes.saturating_sub(partial.bytes);
            }
        }
    }
}

/// Synthetic peer address supplied to quinn-proto; no physical socket is used.
const SYNTHETIC_PEER: SocketAddr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 9);

#[derive(Debug)]
struct ProtoState {
    endpoint: quinn_proto::Endpoint,
    outbound: mpsc::Sender<Bytes>,
    handle: Option<quinn_proto::ConnectionHandle>,
    connection: Option<quinn_proto::Connection>,
    connected: bool,
    lost: Option<quinn_proto::ConnectionError>,
    received_datagrams: VecDeque<Bytes>,
    received_datagram_bytes: usize,
}

#[derive(Debug)]
struct SharedProto {
    state: std::sync::Mutex<ProtoState>,
    notify: tokio::sync::Notify,
    shutdown: std::sync::atomic::AtomicBool,
}

type PeerCertificateSlot =
    Arc<std::sync::Mutex<Option<Vec<tokio_rustls::rustls::pki_types::CertificateDer<'static>>>>>;

/// Server crypto wrapper that captures the authenticated inner peer leaf for
/// post-handshake application checks. The outer tunnel source is opaque, so the
/// QUIC TLS verifier is unbound; possession and chain validity still happen in
/// the wrapped rustls session.
struct CapturingServerConfig {
    inner: Arc<quinn_proto::crypto::rustls::QuicServerConfig>,
    peers: PeerCertificateSlot,
}

impl quinn_proto::crypto::ServerConfig for CapturingServerConfig {
    fn initial_keys(
        &self,
        version: u32,
        dst_cid: &quinn_proto::ConnectionId,
    ) -> std::result::Result<quinn_proto::crypto::Keys, quinn_proto::crypto::UnsupportedVersion>
    {
        self.inner.initial_keys(version, dst_cid)
    }

    fn retry_tag(
        &self,
        version: u32,
        orig_dst_cid: &quinn_proto::ConnectionId,
        packet: &[u8],
    ) -> [u8; 16] {
        self.inner.retry_tag(version, orig_dst_cid, packet)
    }

    fn start_session(
        self: Arc<Self>,
        version: u32,
        params: &quinn_proto::transport_parameters::TransportParameters,
    ) -> Box<dyn quinn_proto::crypto::Session> {
        let session = self.inner.clone().start_session(version, params);
        Box::new(CapturingSession {
            inner: session,
            peers: self.peers.clone(),
        })
    }
}

struct CapturingSession {
    inner: Box<dyn quinn_proto::crypto::Session>,
    peers: PeerCertificateSlot,
}

impl quinn_proto::crypto::Session for CapturingSession {
    fn initial_keys(
        &self,
        dst_cid: &quinn_proto::ConnectionId,
        side: quinn_proto::Side,
    ) -> quinn_proto::crypto::Keys {
        self.inner.initial_keys(dst_cid, side)
    }

    fn handshake_data(&self) -> Option<Box<dyn std::any::Any>> {
        self.inner.handshake_data()
    }

    fn peer_identity(&self) -> Option<Box<dyn std::any::Any>> {
        let identity = self.inner.peer_identity();
        if let Some(certs) = identity
            .as_ref()
            .and_then(|value| {
                value
                    .downcast_ref::<Vec<tokio_rustls::rustls::pki_types::CertificateDer<'static>>>()
            })
            .cloned()
        {
            *self
                .peers
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(certs);
        }
        identity
    }

    fn early_crypto(
        &self,
    ) -> Option<(
        Box<dyn quinn_proto::crypto::HeaderKey>,
        Box<dyn quinn_proto::crypto::PacketKey>,
    )> {
        self.inner.early_crypto()
    }

    fn early_data_accepted(&self) -> Option<bool> {
        self.inner.early_data_accepted()
    }

    fn is_handshaking(&self) -> bool {
        self.inner.is_handshaking()
    }

    fn read_handshake(
        &mut self,
        buf: &[u8],
    ) -> std::result::Result<bool, quinn_proto::TransportError> {
        let ready = self.inner.read_handshake(buf)?;
        if ready {
            let _ = self.peer_identity();
        }
        Ok(ready)
    }

    fn transport_parameters(
        &self,
    ) -> std::result::Result<
        Option<quinn_proto::transport_parameters::TransportParameters>,
        quinn_proto::TransportError,
    > {
        self.inner.transport_parameters()
    }

    fn write_handshake(&mut self, buf: &mut Vec<u8>) -> Option<quinn_proto::crypto::Keys> {
        let keys = self.inner.write_handshake(buf);
        let _ = self.peer_identity();
        keys
    }

    fn next_1rtt_keys(
        &mut self,
    ) -> Option<quinn_proto::crypto::KeyPair<Box<dyn quinn_proto::crypto::PacketKey>>> {
        self.inner.next_1rtt_keys()
    }

    fn is_valid_retry(
        &self,
        orig_dst_cid: &quinn_proto::ConnectionId,
        packet: &[u8],
        payload: &[u8],
    ) -> bool {
        self.inner.is_valid_retry(orig_dst_cid, packet, payload)
    }

    fn export_keying_material(
        &self,
        output: &mut [u8],
        label: &[u8],
        context: &[u8],
    ) -> std::result::Result<(), quinn_proto::crypto::ExportKeyingMaterialError> {
        self.inner.export_keying_material(output, label, context)
    }
}

/// A connected inner QUIC carrier association.
#[derive(Debug, Clone)]
pub struct InnerQuicCarrier {
    shared: Arc<SharedProto>,
    peer_certificates: Option<PeerCertificateSlot>,
}

impl InnerQuicCarrier {
    /// The authenticated inner peer's certificate chain, when this is the
    /// egress/server side.
    pub fn peer_certificates(
        &self,
    ) -> Option<Vec<tokio_rustls::rustls::pki_types::CertificateDer<'static>>> {
        self.peer_certificates.as_ref()?.lock().ok()?.clone()
    }

    /// Opens a bidirectional inner stream.
    pub async fn open_bi(&self) -> Result<quinn_proto::StreamId> {
        self.wait_ready().await?;
        poll_fn(|cx| {
            let mut notified = pin!(self.shared.notify.notified());
            let _ = notified.as_mut().poll(cx);
            let mut guard = self.lock_state();
            let state = &mut *guard;
            if state.lost.is_some() {
                return Poll::Ready(Err(InnerQuicError::Lost));
            }
            if let Some(id) = state
                .connection
                .as_mut()
                .and_then(|conn| conn.streams().open(quinn_proto::Dir::Bi))
            {
                state.drive()?;
                return Poll::Ready(Ok(id));
            }
            state.drive()?;
            drop(guard);
            Self::poll_pending(cx)
        })
        .await
        .map_err(InterflowError::from)
    }

    /// Accepts a peer-initiated bidirectional inner stream.
    pub async fn accept_bi(&self) -> Result<quinn_proto::StreamId> {
        self.wait_ready().await?;
        poll_fn(|cx| {
            let mut notified = pin!(self.shared.notify.notified());
            let _ = notified.as_mut().poll(cx);
            let mut guard = self.lock_state();
            let state = &mut *guard;
            if state.lost.is_some() {
                return Poll::Ready(Err(InnerQuicError::Lost));
            }
            if let Some(id) = state
                .connection
                .as_mut()
                .and_then(|conn| conn.streams().accept(quinn_proto::Dir::Bi))
            {
                state.drive()?;
                return Poll::Ready(Ok(id));
            }
            state.drive()?;
            drop(guard);
            Self::poll_pending(cx)
        })
        .await
        .map_err(InterflowError::from)
    }

    /// Sends one unreliable inner datagram.
    pub async fn send_datagram(&self, data: Bytes) -> Result<()> {
        self.wait_ready().await?;
        poll_fn(|cx| {
            let mut notified = pin!(self.shared.notify.notified());
            let _ = notified.as_mut().poll(cx);
            let mut guard = self.lock_state();
            let state = &mut *guard;
            if state.lost.is_some() {
                return Poll::Ready(Err(InnerQuicError::Lost));
            }
            let result = state
                .connection
                .as_mut()
                .ok_or(InnerQuicError::Lost)?
                .datagrams()
                .send(data.clone(), true);
            match result {
                Ok(()) => {
                    state.drive()?;
                    Poll::Ready(Ok(()))
                }
                Err(quinn_proto::SendDatagramError::Blocked(_)) => {
                    state.drive()?;
                    drop(guard);
                    Self::poll_pending(cx)
                }
                Err(e) => Poll::Ready(Err(InnerQuicError::proto_with("datagram send failed", e))),
            }
        })
        .await
        .map_err(InterflowError::from)
    }

    /// Receives one unreliable inner datagram.
    pub async fn recv_datagram(&self) -> Result<Bytes> {
        self.wait_ready().await?;
        poll_fn(|cx| {
            let mut notified = pin!(self.shared.notify.notified());
            let _ = notified.as_mut().poll(cx);
            let mut guard = self.lock_state();
            let state = &mut *guard;
            if state.lost.is_some() {
                return Poll::Ready(Err(InnerQuicError::Lost));
            }
            if let Some(data) = state.received_datagrams.pop_front() {
                state.received_datagram_bytes =
                    state.received_datagram_bytes.saturating_sub(data.len());
                return Poll::Ready(Ok(data));
            }
            state.drive()?;
            drop(guard);
            Self::poll_pending(cx)
        })
        .await
        .map_err(InterflowError::from)
    }

    /// Writes all bytes to a reliable inner stream.
    pub async fn write_all(&self, stream: quinn_proto::StreamId, mut data: &[u8]) -> Result<()> {
        while !data.is_empty() {
            let written = self.write_some(stream, data).await?;
            if written == 0 {
                return Err(InnerQuicError::proto("stream write stalled").into());
            }
            data = &data[written..];
        }
        Ok(())
    }

    async fn write_some(
        &self,
        stream: quinn_proto::StreamId,
        data: &[u8],
    ) -> std::result::Result<usize, InnerQuicError> {
        poll_fn(|cx| {
            let mut notified = pin!(self.shared.notify.notified());
            let _ = notified.as_mut().poll(cx);
            let mut guard = self.lock_state();
            let state = &mut *guard;
            if state.lost.is_some() {
                return Poll::Ready(Err(InnerQuicError::Lost));
            }
            let result = state
                .connection
                .as_mut()
                .ok_or(InnerQuicError::Lost)?
                .send_stream(stream)
                .write(data);
            match result {
                Ok(written) => {
                    state.drive()?;
                    Poll::Ready(Ok(written))
                }
                Err(quinn_proto::WriteError::Blocked) => {
                    state.drive()?;
                    drop(guard);
                    Self::poll_pending(cx)
                }
                Err(e) => Poll::Ready(Err(InnerQuicError::proto_with("stream write failed", e))),
            }
        })
        .await
    }

    /// Reads available bytes from a reliable inner stream; `Ok(None)` is FIN.
    async fn read_some(
        &self,
        stream: quinn_proto::StreamId,
        buf: &mut [u8],
    ) -> std::result::Result<Option<usize>, InnerQuicError> {
        poll_fn(|cx| {
            let mut notified = pin!(self.shared.notify.notified());
            let _ = notified.as_mut().poll(cx);
            let mut guard = self.lock_state();
            let state = &mut *guard;
            if state.lost.is_some() {
                return Poll::Ready(Err(InnerQuicError::Lost));
            }
            let connection = state.connection.as_mut().ok_or(InnerQuicError::Lost)?;
            let mut recv_stream = connection.recv_stream(stream);
            let Ok(mut chunks) = recv_stream.read(true) else {
                return Poll::Ready(Ok(None));
            };
            let outcome = match chunks.next(buf.len()) {
                Ok(Some(chunk)) => {
                    let len = chunk.bytes.len().min(buf.len());
                    buf[..len].copy_from_slice(&chunk.bytes[..len]);
                    Ok(Some(len))
                }
                Ok(None) => Ok(None),
                Err(quinn_proto::ReadError::Blocked) => {
                    drop(chunks);
                    state.drive()?;
                    drop(guard);
                    return Self::poll_pending(cx);
                }
                Err(e) => Err(InnerQuicError::proto_with("stream chunk finish failed", e)),
            };
            let _ = chunks.finalize();
            state.drive()?;
            Poll::Ready(outcome)
        })
        .await
    }

    /// Reads an exact number of bytes from a reliable inner stream.
    pub async fn read_exact(&self, stream: quinn_proto::StreamId, buf: &mut [u8]) -> Result<()> {
        let mut offset = 0;
        while offset < buf.len() {
            let Some(n) = self.read_some(stream, &mut buf[offset..]).await? else {
                return Err(InterflowError::connection("inner QUIC stream EOF"));
            };
            offset += n;
        }
        Ok(())
    }

    /// Half-closes a reliable inner stream.
    #[allow(
        clippy::unused_async,
        clippy::unused_async_trait_impl // ergonomic ownership/API symmetry with read/write
    )]
    pub async fn finish(&self, stream: quinn_proto::StreamId) -> Result<()> {
        let mut guard = self.lock_state();
        let state = &mut *guard;
        state
            .connection
            .as_mut()
            .ok_or_else(|| InterflowError::connection("inner QUIC connection lost"))?
            .send_stream(stream)
            .finish()
            .map_err(|e| {
                InterflowError::connection("inner QUIC finish".to_string()).with_source(e)
            })?;
        state.drive().map_err(|e| {
            InterflowError::connection("inner QUIC endpoint drive failed").with_source(e)
        })?;
        self.shared.notify.notify_one();
        Ok(())
    }

    /// Gracefully closes the association.
    pub fn close(&self) {
        if let Ok(mut guard) = self.shared.state.lock()
            && let Some(conn) = guard.connection.as_mut()
        {
            conn.close(
                std::time::Instant::now(),
                quinn_proto::VarInt::from_u32(0),
                Bytes::from_static(b"inner udp closed"),
            );
            let _ = guard.drive();
        }
        self.shared.shutdown.store(true, Ordering::Relaxed);
        self.shared.notify.notify_one();
    }

    fn lock_state(&self) -> StateGuard<'_> {
        StateGuard {
            guard: self
                .shared
                .state
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner),
        }
    }

    /// Schedules a one-millisecond retry for a blocked carrier operation.
    ///
    /// `poll_fn` closures cannot keep a `Notified` future alive across polls;
    /// this bounded retry prevents a wake emitted between helper futures from
    /// being lost, without a busy loop.
    fn poll_pending<T>(cx: &std::task::Context<'_>) -> Poll<T> {
        let waker = cx.waker().clone();
        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(1)).await;
            waker.wake_by_ref();
        });
        Poll::Pending
    }

    async fn wait_ready(&self) -> std::result::Result<(), InnerQuicError> {
        poll_fn(|cx| {
            let mut notified = pin!(self.shared.notify.notified());
            let _ = notified.as_mut().poll(cx);
            let mut guard = self.lock_state();
            if guard.connected {
                return Poll::Ready(Ok(()));
            }
            if guard.lost.is_some() {
                return Poll::Ready(Err(InnerQuicError::Lost));
            }
            let _ = guard.drive();
            drop(guard);
            Self::poll_pending(cx)
        })
        .await
    }
}

#[derive(Debug)]
struct StateGuard<'a> {
    guard: std::sync::MutexGuard<'a, ProtoState>,
}

impl Deref for StateGuard<'_> {
    type Target = ProtoState;
    fn deref(&self) -> &Self::Target {
        &self.guard
    }
}

impl DerefMut for StateGuard<'_> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.guard
    }
}

#[derive(Debug, thiserror::Error)]
enum InnerQuicError {
    #[error("inner QUIC connection lost")]
    Lost,
    #[error("inner QUIC protocol error: {message}")]
    Proto {
        message: String,
        #[source]
        source: Option<crate::error::BoxError>,
    },
}

impl InnerQuicError {
    fn proto(message: impl Into<String>) -> Self {
        Self::Proto {
            message: message.into(),
            source: None,
        }
    }

    fn proto_with(message: impl Into<String>, source: impl Into<crate::error::BoxError>) -> Self {
        Self::Proto {
            message: message.into(),
            source: Some(source.into()),
        }
    }
}

impl From<InnerQuicError> for InterflowError {
    fn from(error: InnerQuicError) -> Self {
        Self::connection("inner QUIC failure").with_source(error)
    }
}

impl ProtoState {
    const fn new(endpoint: quinn_proto::Endpoint, outbound: mpsc::Sender<Bytes>) -> Self {
        Self {
            endpoint,
            outbound,
            handle: None,
            connection: None,
            connected: false,
            lost: None,
            received_datagrams: VecDeque::new(),
            received_datagram_bytes: 0,
        }
    }

    fn start_client(
        &mut self,
        config: quinn_proto::ClientConfig,
        server_name: &str,
    ) -> std::result::Result<(), InnerQuicError> {
        let (handle, connection) = self
            .endpoint
            .connect(
                std::time::Instant::now(),
                config,
                SYNTHETIC_PEER,
                server_name,
            )
            .map_err(|e| InnerQuicError::proto_with("inner QUIC connect failed", e))?;
        self.handle = Some(handle);
        self.connection = Some(connection);
        self.drive()
    }

    fn handle_packet(&mut self, packet: Bytes) -> std::result::Result<(), InnerQuicError> {
        let mut response = Vec::with_capacity(2048);
        let event = self.endpoint.handle(
            std::time::Instant::now(),
            SYNTHETIC_PEER,
            None,
            None,
            BytesMut::from(packet),
            &mut response,
        );
        match event {
            Some(quinn_proto::DatagramEvent::NewConnection(incoming)) => {
                let (handle, connection) = self
                    .endpoint
                    .accept(incoming, std::time::Instant::now(), &mut response, None)
                    .map_err(|e| InnerQuicError::proto_with("inner QUIC accept failed", e.cause))?;
                self.handle = Some(handle);
                self.connection = Some(connection);
            }
            Some(quinn_proto::DatagramEvent::ConnectionEvent(handle, event)) => {
                if Some(handle) == self.handle
                    && let Some(conn) = self.connection.as_mut()
                {
                    conn.handle_event(event);
                }
            }
            Some(quinn_proto::DatagramEvent::Response(transmit)) => {
                let packet = Bytes::copy_from_slice(&response[..transmit.size]);
                let _ = self.send_packet(packet);
            }
            None => {}
        }
        self.drive()
    }

    fn handle_timeout(&mut self) -> std::result::Result<(), InnerQuicError> {
        if let Some(conn) = self.connection.as_mut() {
            conn.handle_timeout(std::time::Instant::now());
        }
        self.drive()
    }

    fn send_packet(&self, packet: Bytes) -> std::result::Result<(), InnerQuicError> {
        metrics::counter!("interflow_inner_quic_carrier_bytes_total")
            .increment(packet.len() as u64);
        match self.outbound.try_send(packet) {
            Ok(()) => {}
            Err(tokio::sync::mpsc::error::TrySendError::Full(_)) => {
                metrics::counter!("interflow_inner_quic_carrier_dropped_total").increment(1);
            }
            Err(tokio::sync::mpsc::error::TrySendError::Closed(_)) => {
                return Err(InnerQuicError::Lost);
            }
        }
        Ok(())
    }

    fn drive(&mut self) -> std::result::Result<(), InnerQuicError> {
        loop {
            let Some(handle) = self.handle else {
                return Ok(());
            };
            let Some(conn) = self.connection.as_mut() else {
                return Ok(());
            };
            let Some(event) = conn.poll_endpoint_events() else {
                break;
            };
            if let Some(connection_event) = self.endpoint.handle_event(handle, event) {
                conn.handle_event(connection_event);
            }
        }

        let mut packets = Vec::new();
        if let Some(conn) = self.connection.as_mut() {
            let mut buffer = Vec::with_capacity(2048);
            while let Some(transmit) = conn.poll_transmit(std::time::Instant::now(), 1, &mut buffer)
            {
                packets.push(Bytes::copy_from_slice(&buffer[..transmit.size]));
                buffer.clear();
            }
        }
        for packet in packets {
            self.send_packet(packet)?;
        }

        if let Some(conn) = self.connection.as_mut() {
            while let Some(event) = conn.poll() {
                match event {
                    quinn_proto::Event::Connected => self.connected = true,
                    quinn_proto::Event::ConnectionLost { reason } => self.lost = Some(reason),
                    quinn_proto::Event::DatagramReceived => {
                        while let Some(datagram) = conn.datagrams().recv() {
                            if self.received_datagrams.len() >= RECEIVED_DATAGRAM_CAPACITY
                                || self.received_datagram_bytes + datagram.len()
                                    > RECEIVED_DATAGRAM_BYTES
                            {
                                metrics::counter!("interflow_inner_quic_datagrams_dropped_total")
                                    .increment(1);
                                continue;
                            }
                            self.received_datagram_bytes += datagram.len();
                            self.received_datagrams.push_back(datagram);
                        }
                    }
                    _ => {}
                }
            }
        }
        Ok(())
    }
}

fn transport_config() -> Arc<quinn_proto::TransportConfig> {
    let mut config = quinn_proto::TransportConfig::default();
    let mut ack_frequency = quinn_proto::AckFrequencyConfig::default();
    ack_frequency
        .ack_eliciting_threshold(0u32.into())
        .max_ack_delay(Some(Duration::ZERO))
        .reordering_threshold(0u32.into());
    config
        .max_concurrent_bidi_streams(256u32.into())
        .max_concurrent_uni_streams(0u32.into())
        .max_idle_timeout(Some(
            ENDPOINT_DRIVER_IDLE.try_into().expect("valid idle timeout"),
        ))
        .datagram_receive_buffer_size(Some(1024 * 1024));
    config.ack_frequency_config(Some(ack_frequency));
    Arc::new(config)
}

fn endpoint_config() -> std::result::Result<quinn_proto::EndpointConfig, InnerQuicError> {
    let mut config = quinn_proto::EndpointConfig::default();
    config
        .max_udp_payload_size(1200)
        .map_err(|e| InnerQuicError::proto_with("endpoint max_udp_payload_size rejected", e))?;
    Ok(config)
}

async fn output_pump(
    tunnel: AgentTunnel,
    stream_id: crate::protocol::StreamId,
    direction: CarrierDirection,
    mut rx: mpsc::Receiver<Bytes>,
) {
    while let Some(packet) = rx.recv().await {
        let result = match direction {
            CarrierDirection::Ingress => tunnel.send_data(stream_id, packet).await,
            CarrierDirection::Egress => tunnel.send_data_response(stream_id, packet).await,
        };
        if result.is_err() {
            break;
        }
    }
}

async fn input_pump(mut frames: mpsc::Receiver<TunnelData>, carrier: InnerQuicCarrier) {
    while let Some(frame) = frames.recv().await {
        if !matches!(frame.stream_type, crate::protocol::FrameType::Data) || frame.data.is_empty() {
            continue;
        }
        let mut guard = carrier.lock_state();
        if let Err(error) = guard.handle_packet(frame.data) {
            drop(guard);
            tracing::debug!(%error, "inner QUIC input error");
            break;
        }
        carrier.shared.notify.notify_one();
    }
    carrier.close();
}

async fn timer_pump(carrier: InnerQuicCarrier) {
    while !carrier.shared.shutdown.load(Ordering::Relaxed) {
        tokio::time::sleep(Duration::from_millis(50)).await;
        let (timer_due, already_lost) = {
            let mut guard = carrier.lock_state();
            if let Some(conn) = guard.connection.as_mut()
                && let Some(deadline) = conn.poll_timeout()
            {
                (deadline <= std::time::Instant::now(), guard.lost.is_some())
            } else {
                (false, guard.lost.is_some())
            }
        };
        if already_lost {
            carrier.shared.shutdown.store(true, Ordering::Relaxed);
            break;
        }
        if timer_due {
            let mut guard = carrier.lock_state();
            let _ = guard.handle_timeout();
            let lost = guard.lost.is_some();
            drop(guard);
            if lost {
                carrier.shared.shutdown.store(true, Ordering::Relaxed);
                break;
            }
        }
    }
}

fn spawn_carrier(
    endpoint: quinn_proto::Endpoint,
    tunnel: AgentTunnel,
    stream_id: crate::protocol::StreamId,
    frames: mpsc::Receiver<TunnelData>,
    direction: CarrierDirection,
) -> InnerQuicCarrier {
    let (outbound_tx, outbound_rx) = mpsc::channel(CARRIER_QUEUE_CAPACITY);
    let shared = Arc::new(SharedProto {
        state: std::sync::Mutex::new(ProtoState::new(endpoint, outbound_tx)),
        notify: tokio::sync::Notify::new(),
        shutdown: std::sync::atomic::AtomicBool::new(false),
    });
    let carrier = InnerQuicCarrier {
        shared,
        peer_certificates: None,
    };
    tokio::spawn(output_pump(tunnel, stream_id, direction, outbound_rx));
    tokio::spawn(input_pump(frames, carrier.clone()));
    tokio::spawn(timer_pump(carrier.clone()));
    carrier
}

/// Connects an ingress-side inner QUIC association over an opened outer stream.
#[allow(clippy::too_many_arguments)]
pub async fn connect_inner_quic(
    tunnel: AgentTunnel,
    stream_id: crate::protocol::StreamId,
    frames: mpsc::Receiver<TunnelData>,
    client_config: tokio_rustls::rustls::ClientConfig,
    server_name: String,
    source_principal: String,
    source_fingerprint: [u8; 32],
    direction: CarrierDirection,
    handshake_timeout: Duration,
) -> Result<InnerQuicCarrier> {
    let quic_crypto = quinn_proto::crypto::rustls::QuicClientConfig::try_from(client_config)
        .map_err(|e| {
            InterflowError::config("inner QUIC client config".to_string()).with_source(e)
        })?;
    let mut quinn_client_config = quinn_proto::ClientConfig::new(Arc::new(quic_crypto));
    quinn_client_config.transport_config(Arc::clone(&transport_config()));
    let endpoint = quinn_proto::Endpoint::new(
        Arc::new(
            endpoint_config()
                .map_err(|e| InterflowError::config("inner QUIC endpoint config").with_source(e))?,
        ),
        None,
        false,
        None,
    );
    let carrier = spawn_carrier(endpoint, tunnel, stream_id, frames, direction);
    {
        let mut state = carrier.lock_state();
        if let Err(e) = state.start_client(quinn_client_config, &server_name) {
            drop(state);
            carrier.close();
            return Err(InterflowError::connection("inner QUIC client start failed").with_source(e));
        }
    }
    carrier.shared.notify.notify_one();
    match timeout(handshake_timeout, carrier.wait_ready()).await {
        Ok(Ok(())) => {
            let control = carrier.open_bi().await?;
            let identity = ControlFrame::Identity {
                source_principal,
                source_fingerprint,
            };
            carrier.write_all(control, &identity.encode()?).await?;
            carrier.finish(control).await?;
            Ok(carrier)
        }
        Ok(Err(e)) => {
            carrier.close();
            Err(e.into())
        }
        Err(_) => {
            carrier.close();
            Err(InterflowError::connection("inner QUIC handshake timed out"))
        }
    }
}

/// Accepts an egress-side inner QUIC association over an opened outer stream.
pub async fn accept_inner_quic(
    tunnel: AgentTunnel,
    stream_id: crate::protocol::StreamId,
    frames: mpsc::Receiver<TunnelData>,
    material: &crate::tls::InnerTlsMaterial,
    direction: CarrierDirection,
    handshake_timeout: Duration,
) -> Result<InnerQuicCarrier> {
    let mut rustls_config = crate::tls::inner_server_config_unbound(material)?;
    rustls_config.alpn_protocols = vec![crate::tls::INNER_QUIC_ALPN.as_bytes().to_vec()];
    let quic_crypto = quinn_proto::crypto::rustls::QuicServerConfig::try_from(rustls_config)
        .map_err(|e| {
            InterflowError::config("inner QUIC server config".to_string()).with_source(e)
        })?;
    let peer_certificates: PeerCertificateSlot = Arc::default();
    let capturing = Arc::new(CapturingServerConfig {
        inner: Arc::new(quic_crypto),
        peers: peer_certificates.clone(),
    });
    let mut server_config = quinn_proto::ServerConfig::with_crypto(capturing);
    server_config.transport_config(Arc::clone(&transport_config()));
    let endpoint = quinn_proto::Endpoint::new(
        Arc::new(
            endpoint_config()
                .map_err(|e| InterflowError::config("inner QUIC endpoint config").with_source(e))?,
        ),
        Some(Arc::new(server_config)),
        false,
        None,
    );
    let mut carrier = spawn_carrier(endpoint, tunnel, stream_id, frames, direction);
    carrier.peer_certificates = Some(peer_certificates);
    match timeout(handshake_timeout, carrier.wait_ready()).await {
        Ok(Ok(())) => Ok(carrier),
        Ok(Err(e)) => {
            carrier.close();
            Err(e.into())
        }
        Err(_) => {
            carrier.close();
            Err(InterflowError::connection("inner QUIC handshake timed out"))
        }
    }
}

#[cfg(test)]
#[allow(clippy::panic, clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn control_frames_round_trip() {
        let frames = [
            ControlFrame::Open {
                session: SessionId([1; 16]),
                source_principal: "in".to_owned(),
                source_fingerprint: [2; 32],
                selector: crate::tunnel::TargetSelector::Address("10.1.1.1:53".to_owned()),
            },
            ControlFrame::Accept(SessionId([2; 16])),
            ControlFrame::Reject(SessionId([3; 16]), SessionReject::SecurityDenied),
            ControlFrame::Close(SessionId([4; 16])),
            ControlFrame::Close(SessionId([5; 16])),
        ];
        for frame in frames {
            let bytes = frame.encode().unwrap();
            assert_eq!(ControlFrame::decode(&bytes).unwrap(), (frame, bytes.len()));
        }
    }

    #[test]
    fn fragments_round_trip_out_of_order() {
        let session = SessionId::random();
        let payload = vec![7u8; 2000];
        let fragments = encode_datagram_fragments(session, &payload).unwrap();
        assert_eq!(fragments.len(), 3);
        let mut reassembler = DatagramReassembler::default();
        assert!(reassembler.push(&fragments[2]).unwrap().is_none());
        assert!(reassembler.push(&fragments[0]).unwrap().is_none());
        assert_eq!(
            reassembler.push(&fragments[1]).unwrap().unwrap(),
            Bytes::from(payload)
        );
        assert!(reassembler.is_empty());
    }

    #[test]
    fn malformed_fragments_and_control_frames_fail() {
        let mut reassembler = DatagramReassembler::default();
        assert_eq!(
            reassembler.push(&[0; 16]).unwrap_err(),
            FragmentError::ShortHeader
        );
        let frame = ControlFrame::Accept(SessionId([1; 16])).encode().unwrap();
        assert!(ControlFrame::decode(&frame[..frame.len() - 1]).is_err());
    }

    #[test]
    fn duplicate_fragments_do_not_poison_reassembly() {
        let session = SessionId::random();
        let fragments = encode_datagram_fragments(session, &[9; 2000]).unwrap();
        let mut reassembler = DatagramReassembler::default();
        assert!(reassembler.push(&fragments[0]).unwrap().is_none());
        assert!(reassembler.push(&fragments[0]).unwrap().is_none());
        assert!(reassembler.push(&fragments[1]).unwrap().is_none());
        assert_eq!(
            reassembler.push(&fragments[2]).unwrap().unwrap(),
            Bytes::from(vec![9; 2000])
        );
    }

    #[test]
    fn zero_length_datagram_round_trips() {
        let session = SessionId::random();
        let fragments = encode_datagram_fragments(session, &[]).unwrap();
        assert_eq!(fragments.len(), 1);
        let mut reassembler = DatagramReassembler::default();
        assert_eq!(
            reassembler.push(&fragments[0]).unwrap().unwrap(),
            Bytes::new()
        );
    }

    #[test]
    fn reassembler_evicts_oldest_when_full() {
        let session = SessionId::random();
        let mut reassembler = DatagramReassembler::default();
        for value in 0..MAX_PENDING_DATAGRAMS {
            let fragments =
                encode_datagram_fragments(session, &[u8::try_from(value).unwrap(); 800]).unwrap();
            assert!(reassembler.push(&fragments[0]).unwrap().is_none());
        }
        assert_eq!(reassembler.len(), MAX_PENDING_DATAGRAMS);
        let fragments = encode_datagram_fragments(session, &[7; 800]).unwrap();
        assert!(reassembler.push(&fragments[0]).is_ok());
        assert_eq!(reassembler.len(), MAX_PENDING_DATAGRAMS);
    }

    #[test]
    fn invalid_session_ids_and_selectors_are_rejected() {
        let zero = ControlFrame::Open {
            session: SessionId([0; 16]),
            source_principal: "in".to_owned(),
            source_fingerprint: [2; 32],
            selector: crate::tunnel::TargetSelector::Default,
        };
        assert!(zero.encode().is_err());
        let long = ControlFrame::Open {
            session: SessionId::random(),
            source_principal: "in".to_owned(),
            source_fingerprint: [2; 32],
            selector: crate::tunnel::TargetSelector::Address("x".repeat(257)),
        };
        assert!(long.encode().is_err());
        let mut zero_accept = vec![0u8, 2, 2];
        zero_accept.extend([0u8; 16]);
        assert!(ControlFrame::decode(&zero_accept).is_err());
    }
}
