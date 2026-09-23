//! UDP ingress over one agent-to-agent inner QUIC association.
//!
//! One outer tunnel stream is retained per listener/target pair. Public client
//! source addresses map to random inner session ids; the LAN target travels
//! only inside the encrypted inner control stream, and every datagram rides an
//! inner QUIC DATAGRAM.

use crate::agent::e2e::E2eRuntime;
use crate::config::IngressRule;
use bytes::Bytes;
use interflow_core::protocol::StreamProto;
use interflow_core::security::ByteRateLimiter;
use interflow_core::tunnel::inner_udp::{
    self, ControlFrame, DatagramReassembler, InnerQuicCarrier, SessionId,
};
use interflow_core::tunnel::{AgentTunnel, TargetSelector};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tokio::net::UdpSocket;
use tokio::sync::mpsc;
use tracing::{debug, info, warn};

/// UDP receive buffer: larger than the IPv4 theoretical maximum so normal
/// datagrams cannot be silently truncated.
pub(crate) const UDP_RECV_BUF: usize = 65535;
/// UDP socket buffer target.
const UDP_SOCK_BUF: usize = 256 * 1024;
/// Capacity for one session's decrypted return datagrams.
const SESSION_CHANNEL_CAP: usize = 128;
/// Conservative per-packet QUIC/AEAD overhead used by the ciphertext budget.
const INNER_QUIC_PACKET_OVERHEAD: usize = 32;

/// Bind and enlarge a UDP socket (also used by egress and tests).
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

struct UdpSession {
    session: SessionId,
    last_active: Arc<Mutex<Instant>>,
}

type ClientSessions = Arc<Mutex<HashMap<SocketAddr, UdpSession>>>;
type InnerSessions = Arc<Mutex<HashMap<SessionId, mpsc::Sender<Bytes>>>>;

struct Association {
    outer_stream: interflow_core::protocol::StreamId,
    carrier: InnerQuicCarrier,
    /// Association-keyed request budget, charged on encrypted inner-QUIC bytes.
    cipher_limiter: Option<ByteRateLimiter>,
}

/// Runs a UDP listener until the caller cancels the agent session.
pub(crate) async fn run_udp_listener(
    socket: UdpSocket,
    rule: IngressRule,
    tunnel: AgentTunnel,
    e2e: Arc<E2eRuntime>,
) {
    info!(
        "Starting UDP ingress listener: {} -> {} (target_addr={:?})",
        rule.listen_addr, rule.target_agent, rule.remote_addr
    );
    serve(socket, rule, tunnel, e2e).await;
}

async fn serve(socket: UdpSocket, rule: IngressRule, tunnel: AgentTunnel, e2e: Arc<E2eRuntime>) {
    let socket = Arc::new(socket);
    let ingress_limiter = rule.udp_ingress_limiter();
    let clients: ClientSessions = Arc::new(Mutex::new(HashMap::new()));
    let inner_sessions: InnerSessions = Arc::new(Mutex::new(HashMap::new()));
    let mut association: Option<Association> = None;
    let mut buf = vec![0u8; UDP_RECV_BUF];

    loop {
        let (n, client) = match socket.recv_from(&mut buf).await {
            Ok(value) => value,
            Err(e) => {
                warn!("UDP recv_from error (rule {}): {e}", rule.name);
                tokio::time::sleep(Duration::from_millis(100)).await;
                continue;
            }
        };
        if n == UDP_RECV_BUF {
            metrics::counter!("interflow_udp_datagram_truncated").increment(1);
            warn!("Likely truncated datagram ({n} bytes), dropping");
            continue;
        }
        if let Some(limiter) = &ingress_limiter
            && !limiter.check(client.ip(), n)
        {
            metrics::counter!("interflow_udp_rate_limited", "direction" => "ingress").increment(1);
            continue;
        }

        if association.is_none() {
            match open_association(&tunnel, &rule, &e2e, inner_sessions.clone()).await {
                Ok(value) => association = Some(value),
                Err(e) => {
                    metrics::counter!("interflow_udp_session_open_failed").increment(1);
                    debug!("UDP inner QUIC association failed: {e}");
                    continue;
                }
            }
        }
        let Some(assoc) = association.as_ref() else {
            continue;
        };

        let mut new_session = false;
        if !clients
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .contains_key(&client)
        {
            let selector = rule
                .remote_addr
                .clone()
                .map_or_else(|| TargetSelector::Default, TargetSelector::Address);
            match open_session(
                assoc.carrier.clone(),
                selector,
                e2e.source_principal().to_owned(),
                e2e.material().leaf_fingerprint(),
                inner_sessions.clone(),
                socket.clone(),
                client,
                clients.clone(),
                rule.effective_idle_timeout(),
                rule.udp_egress_bytes_per_sec,
                e2e.handshake_timeout,
            )
            .await
            {
                Ok(()) => new_session = true,
                Err(e) => {
                    metrics::counter!("interflow_udp_session_open_failed").increment(1);
                    if e.to_string().contains("inner UDP session rejected") {
                        debug!("UDP inner session rejected for {client}: {e}");
                    } else {
                        warn!("UDP inner session failed for {client}: {e}; rebuilding association");
                        close_association(
                            association.take().as_ref(),
                            &tunnel,
                            clients.clone(),
                            inner_sessions.clone(),
                        )
                        .await;
                    }
                    continue;
                }
            }
        }

        let session_info = clients
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .get(&client)
            .map(|session| (session.session, session.last_active.clone()));
        let Some((session, last_active)) = session_info else {
            continue;
        };
        *last_active
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = Instant::now();
        metrics::counter!("interflow_udp_datagrams_rx").increment(1);
        metrics::counter!("interflow_udp_bytes_rx").increment(n as u64);
        if new_session {
            metrics::counter!("interflow_udp_session_opened").increment(1);
        }

        let fragments = match inner_udp::encode_datagram_fragments(session, &buf[..n]) {
            Ok(fragments) => fragments,
            Err(e) => {
                metrics::counter!("interflow_udp_fragment_invalid_total").increment(1);
                debug!("UDP datagram rejected before inner QUIC: {e}");
                continue;
            }
        };
        let cipher_bytes = fragments
            .iter()
            .map(|fragment| fragment.len() + INNER_QUIC_PACKET_OVERHEAD)
            .sum::<usize>();
        if let Some(limiter) = &assoc.cipher_limiter
            && !limiter.check(cipher_bytes)
        {
            metrics::counter!("interflow_udp_rate_limited", "direction" => "carrier").increment(1);
            continue;
        }
        let mut failed = false;
        for fragment in fragments {
            if assoc.carrier.send_datagram(fragment).await.is_err() {
                failed = true;
                break;
            }
        }
        if failed {
            warn!("UDP inner QUIC send failed; rebuilding association");
            close_association(
                association.take().as_ref(),
                &tunnel,
                clients.clone(),
                inner_sessions.clone(),
            )
            .await;
        }
    }
}

async fn open_association(
    tunnel: &AgentTunnel,
    rule: &IngressRule,
    e2e: &Arc<E2eRuntime>,
    inner_sessions: InnerSessions,
) -> interflow_core::error::Result<Association> {
    let outer_stream = interflow_core::protocol::StreamId::random()?;
    let frames = tunnel.register_stream(outer_stream).await;
    tunnel
        .send_open_with(outer_stream, &rule.target_agent, StreamProto::Udp, true)
        .await?;
    let expected_peer = crate::agent::e2e::bare_agent_id(&rule.target_agent);
    let client_config = e2e.quic_client_config(expected_peer)?;
    let server_name = interflow_core::tls::inner_quic_server_name(expected_peer);
    let carrier = inner_udp::connect_inner_quic(
        tunnel.clone(),
        outer_stream,
        frames,
        client_config,
        server_name,
        e2e.source_principal().to_owned(),
        e2e.material().leaf_fingerprint(),
        inner_udp::CarrierDirection::Ingress,
        e2e.handshake_timeout,
    )
    .await?;
    tokio::spawn(dispatch_datagrams(carrier.clone(), inner_sessions));
    metrics::counter!("interflow_agent_inner_quic_handshakes_total", "side" => "ingress")
        .increment(1);
    metrics::gauge!("interflow_agent_inner_quic_associations_active").increment(1.0);
    Ok(Association {
        outer_stream,
        carrier,
        cipher_limiter: ByteRateLimiter::new(rule.udp_egress_bytes_per_sec),
    })
}

#[allow(clippy::too_many_arguments)]
async fn open_session(
    carrier: InnerQuicCarrier,
    selector: TargetSelector,
    source_principal: String,
    source_fingerprint: [u8; 32],
    inner_sessions: InnerSessions,
    socket: Arc<UdpSocket>,
    client: SocketAddr,
    clients: ClientSessions,
    idle_timeout: Duration,
    egress_bytes_per_sec: u32,
    handshake_timeout: Duration,
) -> interflow_core::error::Result<()> {
    let session = SessionId::random();
    let (response_tx, response_rx) = mpsc::channel(SESSION_CHANNEL_CAP);
    inner_sessions
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .insert(session, response_tx);
    let control = carrier.open_bi().await?;
    let open = ControlFrame::Open {
        session,
        source_principal,
        source_fingerprint,
        selector,
    };
    carrier.write_all(control, &open.encode()?).await?;
    let Ok(reply) = tokio::time::timeout(handshake_timeout, read_control(&carrier, control)).await
    else {
        remove_inner_session(&inner_sessions, session);
        return Err(interflow_core::error::InterflowError::connection(
            "inner UDP session handshake timed out",
        ));
    };
    let reply = reply?;
    match reply {
        ControlFrame::Accept(accepted) if accepted == session => {}
        ControlFrame::Reject(rejected, reason) if rejected == session => {
            remove_inner_session(&inner_sessions, session);
            return Err(interflow_core::error::InterflowError::connection(format!(
                "inner UDP session rejected: {reason:?}"
            )));
        }
        _ => {
            remove_inner_session(&inner_sessions, session);
            return Err(interflow_core::error::InterflowError::connection(
                "inner UDP session handshake mismatch",
            ));
        }
    }
    let last_active = Arc::new(Mutex::new(Instant::now()));
    clients
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .insert(
            client,
            UdpSession {
                session,
                last_active: last_active.clone(),
            },
        );
    tokio::spawn(pump_response(
        carrier,
        control,
        session,
        response_rx,
        socket,
        client,
        clients,
        inner_sessions,
        last_active,
        idle_timeout,
        egress_bytes_per_sec,
    ));
    Ok(())
}

async fn read_control(
    carrier: &InnerQuicCarrier,
    stream: quinn::StreamId,
) -> interflow_core::error::Result<ControlFrame> {
    let mut header = [0u8; 2];
    carrier.read_exact(stream, &mut header).await?;
    let len = u16::from_be_bytes(header) as usize;
    let mut body = vec![0u8; len];
    carrier.read_exact(stream, &mut body).await?;
    let mut bytes = header.to_vec();
    bytes.extend(body);
    Ok(ControlFrame::decode(&bytes)?.0)
}

async fn dispatch_datagrams(carrier: InnerQuicCarrier, sessions: InnerSessions) {
    let mut reassembler = DatagramReassembler::default();
    loop {
        let Ok(datagram) = carrier.recv_datagram().await else {
            break;
        };
        if datagram.len() < 16 {
            metrics::counter!("interflow_udp_fragment_invalid_total").increment(1);
            continue;
        }
        let Ok(session) = datagram[..16].try_into().map(SessionId) else {
            metrics::counter!("interflow_udp_fragment_invalid_total").increment(1);
            continue;
        };
        let sender = sessions
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .get(&session)
            .cloned();
        let Some(sender) = sender else {
            metrics::counter!("interflow_udp_fragment_invalid_total").increment(1);
            continue;
        };
        match reassembler.push(&datagram) {
            Ok(Some(payload)) => {
                if sender.try_send(payload).is_err() {
                    metrics::counter!("interflow_udp_rate_limited", "direction" => "egress")
                        .increment(1);
                }
            }
            Ok(None) => {}
            Err(_) => metrics::counter!("interflow_udp_fragment_invalid_total").increment(1),
        }
    }
}

#[allow(clippy::too_many_arguments)]
async fn pump_response(
    carrier: InnerQuicCarrier,
    control: quinn::StreamId,
    session: SessionId,
    mut response_rx: mpsc::Receiver<Bytes>,
    socket: Arc<UdpSocket>,
    client: SocketAddr,
    clients: ClientSessions,
    inner_sessions: InnerSessions,
    last_active: Arc<Mutex<Instant>>,
    idle_timeout: Duration,
    egress_bytes_per_sec: u32,
) {
    let egress_limiter = ByteRateLimiter::new(egress_bytes_per_sec);
    loop {
        let deadline = tokio::time::Instant::from_std(
            *last_active
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                + idle_timeout,
        );
        tokio::select! {
            packet = response_rx.recv() => {
                let Some(packet) = packet else { break };
                if packet.is_empty() {
                    continue;
                }
                if let Some(limiter) = &egress_limiter
                    && !limiter.check(packet.len())
                {
                    metrics::counter!("interflow_udp_rate_limited", "direction" => "egress").increment(1);
                    continue;
                }
                if socket.send_to(&packet, client).await.is_err() {
                    break;
                }
                metrics::counter!("interflow_udp_datagrams_tx").increment(1);
                metrics::counter!("interflow_udp_bytes_tx").increment(packet.len() as u64);
                *last_active.lock().unwrap_or_else(std::sync::PoisonError::into_inner) = Instant::now();
            }
            () = tokio::time::sleep_until(deadline) => {
                metrics::counter!("interflow_udp_session_idle_timeout").increment(1);
                break;
            }
        }
    }
    if let Ok(close) = ControlFrame::Close(session).encode() {
        let _ = carrier.write_all(control, &close).await;
        let _ = carrier.finish(control).await;
    }
    remove_inner_session(&inner_sessions, session);
    remove_client(&clients, client, session);
    metrics::counter!("interflow_udp_session_closed").increment(1);
}

fn remove_inner_session(sessions: &InnerSessions, session: SessionId) {
    sessions
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .remove(&session);
}

fn remove_client(clients: &ClientSessions, client: SocketAddr, session: SessionId) {
    let mut map = clients
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    if map
        .get(&client)
        .is_some_and(|current| current.session == session)
    {
        map.remove(&client);
    }
}

async fn close_association(
    association: Option<&Association>,
    tunnel: &AgentTunnel,
    clients: ClientSessions,
    inner_sessions: InnerSessions,
) {
    let Some(association) = association else {
        return;
    };
    association.carrier.close();
    tunnel.unregister_stream(association.outer_stream).await;
    clients
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .clear();
    inner_sessions
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .clear();
    metrics::gauge!("interflow_agent_inner_quic_associations_active").decrement(1.0);
}
