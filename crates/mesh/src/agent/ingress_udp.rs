//! UDP ingress: one tunnel stream per client source address (plan A,
//! 2026-09-11 backlog §5.1).
//!
//! Data-plane shape (compare frp/rathole):
//! - one shared `UdpSocket` for send/receive; the ingress-side session table
//!   is indexed by client source `SocketAddr`, each session = one UUID
//!   `stream_id` + a dedicated return channel (`register_stream`).
//! - datagram boundaries are preserved by the frame `payload_len`: one
//!   datagram = one Data frame payload.
//! - the read buffer is fixed at 65535 (> the IPv4 theoretical max of
//!   65507) -> structurally eliminates the silent kernel truncation seen in
//!   frp (default 1500) / rathole (2048); a defensive check covers the IPv6
//!   jumbo case.
//! - idle reclamation: the recv loop and the return pump both refresh
//!   `last_active`; on timeout send Close and remove from the table.
//!   The egress forwarder times independently; each side is its own
//!   fallback.
//! - amplification guard: inbound per-source-IP token bucket (pps + byte
//!   rate), outbound per-session byte rate limit.
//! - late return packets: once a session is reclaimed, tunnel-side data
//!   cannot be delivered (a stream_map miss goes to broadcast, which egress
//!   ignores) -> no error; the client's next datagram creates a new session
//!   (rathole semantics, documented).

use crate::config::IngressRule;
use bytes::Bytes;
use interflow_core::protocol::FrameType;
use interflow_core::security::{ByteRateLimiter, UdpIngressLimiter};
use interflow_core::tunnel::AgentTunnel;
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tokio::net::UdpSocket;
use tokio::sync::mpsc;
use tracing::{debug, info, warn};

/// UDP send/receive buffer. 65535 > 65507 (the IPv4 datagram theoretical
/// max), so normal traffic can never be truncated by the kernel; a
/// `recv_from` that fills the entire buffer (only possible with an IPv6
/// jumbogram) is treated as suspected truncation, explicitly dropped +
/// counted, never silently tail-truncated.
pub(crate) const UDP_RECV_BUF: usize = 65535;

/// Target value for the UDP socket send/receive buffers.
///
/// macOS's default UDP buffer (~9 KiB) makes sending datagrams >9 KiB fail
/// outright with EMSGSIZE; Linux's default wmem (212 KiB) accommodates
/// 65507. Raise uniformly to 256 KiB so datagrams within the theoretical
/// max are not rejected over socket buffers (best effort; the platform may
/// clamp).
const UDP_SOCK_BUF: usize = 256 * 1024;

/// Bind a UDP socket and enlarge its send/receive buffers (shared by the
/// ingress listener / egress forwarder / tests).
pub fn bind_udp_socket(addr: SocketAddr) -> std::io::Result<UdpSocket> {
    let sock = socket2::Socket::new(
        socket2::Domain::for_address(addr),
        socket2::Type::DGRAM,
        None,
    )?;
    let _ = sock.set_recv_buffer_size(UDP_SOCK_BUF);
    let _ = sock.set_send_buffer_size(UDP_SOCK_BUF);
    sock.set_nonblocking(true)?;
    sock.bind(&socket2::SockAddr::from(addr))?;
    let std_sock: std::net::UdpSocket = sock.into();
    UdpSocket::from_std(std_sock)
}

/// Session for a single client source address.
struct UdpSession {
    stream_id: String,
    /// Most recent bidirectional activity (refreshed by both the recv loop
    /// and the return pump; the basis for idle timing).
    last_active: Arc<Mutex<Instant>>,
}

type SharedSessions = Arc<Mutex<HashMap<SocketAddr, UdpSession>>>;

/// Run the UDP ingress listener on an already-bound socket (blocks until the
/// socket closes).
///
/// Binding is done by the caller (`IngressHandler::start_listener`) so bind
/// failures surface immediately at startup, as with the TCP path.
pub(crate) async fn run_udp_listener(socket: UdpSocket, rule: IngressRule, tunnel: AgentTunnel) {
    info!(
        "Starting UDP ingress listener: {} -> {} (target_addr={:?})",
        rule.listen_addr, rule.target_agent, rule.remote_addr
    );
    serve(socket, rule, tunnel).await;
}

async fn serve(socket: UdpSocket, rule: IngressRule, tunnel: AgentTunnel) {
    // tokio UdpSocket has no Clone: share via Arc with the return pump
    // (the same object = the same local port)
    let socket = Arc::new(socket);
    let ingress_limiter: Option<Arc<UdpIngressLimiter>> = rule.udp_ingress_limiter();
    let sessions: SharedSessions = Arc::new(Mutex::new(HashMap::new()));
    let mut buf = vec![0u8; UDP_RECV_BUF];

    loop {
        let (n, client) = match socket.recv_from(&mut buf).await {
            Ok(v) => v,
            Err(e) => {
                warn!("UDP recv_from error (rule {}): {}", rule.name, e);
                tokio::time::sleep(Duration::from_millis(100)).await;
                continue;
            }
        };

        if n == UDP_RECV_BUF {
            metrics::counter!("interflow_udp_datagram_truncated").increment(1);
            warn!(
                "Likely truncated datagram ({} bytes filled the read buffer), dropping",
                n
            );
            continue;
        }

        // Inbound per-source-IP rate limit (the first amplification gate)
        if let Some(limiter) = &ingress_limiter
            && !limiter.check(client.ip(), n)
        {
            metrics::counter!("interflow_udp_rate_limited", "direction" => "ingress").increment(1);
            continue;
        }

        let Some(session) =
            session_stream_id(&sessions, &tunnel, &rule, client, socket.clone()).await
        else {
            // Stream creation failed (hub unreachable / stream quota):
            // datagram dropped, already counted
            continue;
        };
        // Inbound traffic refreshes the idle timer (the return path is
        // refreshed by the pump; bidirectional activity prevents expiry)
        *session
            .last_active
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = Instant::now();

        metrics::counter!("interflow_udp_datagrams_rx").increment(1);
        metrics::counter!("interflow_udp_bytes_rx").increment(n as u64);

        // Inline await: under h2 semantics each frame costs one POST
        // round-trip, fine at DNS scale;
        // the QUIC transport (P2/P3) removes this constraint.
        let datagram = Bytes::copy_from_slice(&buf[..n]);
        if let Err(e) = tunnel.send_data(&session.stream_id, datagram).await {
            // The session is most likely already dead (hub removed it /
            // peer Close): drop it from the table immediately;
            // the next datagram rebuilds the session.
            warn!(
                "UDP session send failed: stream_id={}, {e}",
                session.stream_id
            );
            remove_session(&sessions, client, &session.stream_id);
            tunnel.unregister_stream(&session.stream_id).await;
        }
    }
}

/// Get the session; when absent, create the stream (register -> open ->
/// spawn the return pump).
///
/// Session creation happens only inside the single-task recv loop, so it is
/// naturally free of concurrency races.
async fn session_stream_id(
    sessions: &SharedSessions,
    tunnel: &AgentTunnel,
    rule: &IngressRule,
    client: SocketAddr,
    socket: Arc<UdpSocket>,
) -> Option<UdpSession> {
    if let Some(session) = sessions
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .get(&client)
    {
        return Some(UdpSession {
            stream_id: session.stream_id.clone(),
            last_active: session.last_active.clone(),
        });
    }

    let stream_id = uuid::Uuid::new_v4().to_string();
    let data_rx = tunnel.register_stream(stream_id.clone()).await;

    if let Err(e) = tunnel
        .send_open(
            &stream_id,
            &rule.target_agent,
            rule.remote_addr.as_deref(),
            interflow_core::protocol::StreamProto::Udp,
        )
        .await
    {
        metrics::counter!("interflow_udp_session_open_failed").increment(1);
        debug!("UDP stream open failed (client={client}): {e}");
        tunnel.unregister_stream(&stream_id).await;
        return None;
    }

    metrics::counter!("interflow_udp_session_opened").increment(1);

    let last_active = Arc::new(Mutex::new(Instant::now()));
    let session = UdpSession {
        stream_id: stream_id.clone(),
        last_active: last_active.clone(),
    };
    sessions
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .insert(
            client,
            UdpSession {
                stream_id: stream_id.clone(),
                last_active: last_active.clone(),
            },
        );

    tokio::spawn(pump_response(
        tunnel.clone(),
        data_rx,
        socket,
        client,
        stream_id.clone(),
        last_active,
        rule.effective_idle_timeout(),
        rule.udp_egress_bytes_per_sec,
        sessions.clone(),
    ));

    Some(session)
}

/// Return pump: tunnel -> public-network client.
///
/// - Close frame (egress-side close / hub notification) -> exit, no Close
///   echo.
/// - Channel closed (local unregister / session replaced) -> exit.
/// - Return-path byte rate limit (the second amplification gate): over the
///   limit, drop + count.
/// - Idle timeout: bidirectional `last_active` past `idle_timeout` -> echo
///   Close and remove from the table.
///
/// Sends must go through the same listening socket the datagram arrived on
/// (tokio `UdpSocket` has an internal Arc; clones share the same object):
/// clients match responses by "the address they sent to", and a different
/// port would be rejected.
#[allow(clippy::too_many_arguments)]
async fn pump_response(
    tunnel: AgentTunnel,
    mut data_rx: mpsc::Receiver<interflow_core::tunnel::TunnelData>,
    socket: Arc<UdpSocket>,
    client: SocketAddr,
    stream_id: String,
    last_active: Arc<Mutex<Instant>>,
    idle_timeout: Duration,
    egress_bytes_per_sec: u32,
    sessions: SharedSessions,
) {
    // Per-session limiter (sharing one would let a busy session eat the
    // other sessions' budget)
    let egress_limiter = ByteRateLimiter::new(egress_bytes_per_sec);

    let mut closed_by_peer = false;
    loop {
        let deadline = tokio::time::Instant::from_std(
            *last_active
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                + idle_timeout,
        );
        tokio::select! {
            msg = data_rx.recv() => {
                match msg {
                    Some(m) if matches!(m.stream_type, FrameType::Close) => {
                        closed_by_peer = true;
                        break;
                    }
                    Some(m) => {
                        if m.data.is_empty() {
                            continue;
                        }
                        if let Some(limiter) = &egress_limiter
                            && !limiter.check(m.data.len())
                        {
                            metrics::counter!("interflow_udp_rate_limited", "direction" => "egress")
                                .increment(1);
                            continue;
                        }
                        if let Err(e) = socket.send_to(&m.data, client).await {
                            warn!("UDP return send_to failed (client={client}): {e}");
                            break;
                        }
                        metrics::counter!("interflow_udp_datagrams_tx").increment(1);
                        metrics::counter!("interflow_udp_bytes_tx").increment(m.data.len() as u64);
                        *last_active.lock().unwrap_or_else(std::sync::PoisonError::into_inner) = Instant::now();
                    }
                    None => break,
                }
            }
            () = tokio::time::sleep_until(deadline) => {
                metrics::counter!("interflow_udp_session_idle_timeout").increment(1);
                debug!("UDP session idle timeout: client={client} stream_id={stream_id}");
                break;
            }
        }
    }

    if !closed_by_peer {
        let _ = tunnel.send_close(&stream_id).await;
    }
    tunnel.unregister_stream(&stream_id).await;
    remove_session(&sessions, client, &stream_id);
    metrics::counter!("interflow_udp_session_closed").increment(1);
}

/// Remove the session-table entry (only when it still points at this
/// stream_id, to avoid deleting a fresh session created by a rebuild).
fn remove_session(sessions: &SharedSessions, client: SocketAddr, stream_id: &str) {
    let mut map = sessions
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    if map.get(&client).is_some_and(|s| s.stream_id == stream_id) {
        map.remove(&client);
    }
}
