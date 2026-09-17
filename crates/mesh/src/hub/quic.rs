//! QUIC transport plane: hub-side listening, registration, heartbeat, and
//! stream relay (backlog §6.2, option 2).
//!
//! Coexists with the h2 plane (dual-stack) and **interoperates across
//! transports**:
//! - quic agent → quic agent: the hub relays between the two connections
//!   (frame-aware pump);
//! - quic agent → h2 agent: the relay read pump converts frames into
//!   `TunnelData` and pushes them into the poll channel;
//! - h2 agent → quic agent: `handle_open`/`handle_data` write into the relay
//!   stream via `ActiveStream::target` (relay-facing)
//!   (see [`crate::hub::routing`] and [`open_relay_stream`]).
//!
//! Connection lifecycle:
//! - Control stream (first bidirectional stream): Hello (`source_agent` =
//!   agent_id, payload = token) → HelloAck; Ping/Pong heartbeat runs on the
//!   control stream (reusing `AgentSession::last_pong` and the eviction
//!   primitive);
//! - Connection-lost watcher: deregister + sweep orphan streams.
//!
//! Open frame (agent → hub) payload convention:
//! `"{target_agent}:{target_addr}"`; the Open frame the hub forwards to the
//! target agent has payload `"{source_agent}:{target_addr}"` (identical to
//! the h2 `handle_open` notification format — zero perceptible difference at
//! the egress end).

// QUIC async tasks hold a 64KiB read buffer, so the future size naturally
// exceeds pedantic thresholds; the frame-decode loop's Pending/UnknownType
// branches and let-else rewrites follow protocol-handling conventions.
#![allow(
    clippy::large_futures,
    clippy::needless_continue,
    clippy::match_same_arms,
    clippy::manual_let_else
)]
use crate::hub::accept::AcceptContext;
use crate::hub::state::{
    AgentSession, HubCore, QuicAgentConn, SharedAgents, StreamFace, TunnelData,
};
use bytes::{Bytes, BytesMut};
use interflow_core::error::{InterflowError, Result};
use interflow_core::protocol::frame as wire;
use interflow_core::protocol::{FrameType, StreamProto};
use interflow_core::security::AuditKind;
use interflow_core::tunnel::FrameSource;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::{RwLock, mpsc};
use tracing::{debug, error, info, warn};

use crate::config::AuthMode;
use interflow_core::tunnel::negotiation::{HeartbeatAd, RegisterResponse};

/// Relay channel capacity (same as the poll channel).
const RELAY_CHANNEL_CAP: usize = 256;
/// Whole-frame budget for the DATAGRAM fast path (same as the agent side,
/// see core::tunnel::quic).
const DATAGRAM_FRAME_BUDGET: usize = interflow_core::tunnel::quic::DATAGRAM_FRAME_BUDGET;

/// Takes the agent's quinn connection (for the writer fast path).
async fn conn_for_datagram(core: &HubCore, agent_id: &str) -> Option<quinn::Connection> {
    let agents = core.agents.read().await;
    let state = agents.get(agent_id)?;
    let qc = state.read().await.quic.clone();
    qc.filter(|qc| qc.datagram_cap.load(std::sync::atomic::Ordering::Relaxed))
        .map(|qc| qc.conn.clone())
}

/// Whether the hub enables the DATAGRAM fast path.
async fn quinn_caps_enabled(ctx: &AcceptContext) -> bool {
    ctx.config.read().await.transport.quic.datagram_enabled
}

/// Read chunk size for traffic streams.
const READ_CHUNK: usize = 64 * 1024;

/// Starts the QUIC listener. Returns an error when enabled but TLS
/// certificates are missing (QUIC mandates TLS).
pub(crate) async fn spawn_quic_listener(ctx: AcceptContext) -> Result<()> {
    let (quic_cfg, tls_cfg, auth_mode, tcp_listen) = {
        let cfg = ctx.config.read().await;
        (
            cfg.transport.quic.clone(),
            cfg.tls.clone(),
            cfg.auth.mode,
            cfg.server.listen_addr,
        )
    };
    if !quic_cfg.enabled {
        return Ok(());
    }

    let Some(tls) = tls_cfg else {
        return Err(InterflowError::config(
            "[transport.quic] enabled = true requires certificates from [tls] (QUIC mandates TLS)"
                .to_string(),
        ));
    };

    let client_ca = match auth_mode {
        AuthMode::Mtls => {
            let cfg = ctx.config.read().await;
            cfg.auth.mtls.as_ref().map(|m| m.ca_path.clone())
        }
        _ => None,
    };
    let min_version = {
        let cfg = ctx.config.read().await;
        cfg.tls
            .as_ref()
            .map_or_else(interflow_core::tls::TlsMinVersion::default, |t| {
                t.min_version
            })
    };
    let mut server_tls = interflow_core::tls::build_rustls_server_config(
        &tls.cert_path,
        &tls.key_path,
        client_ca.as_deref(),
        min_version,
    )?;
    server_tls.alpn_protocols = vec![interflow_core::tunnel::quic::QUIC_ALPN.as_bytes().to_vec()];

    let listen_addr = quic_cfg.listen_addr.unwrap_or(tcp_listen);

    let mut transport = quinn::TransportConfig::default();
    transport.max_idle_timeout(Some(quinn::IdleTimeout::from(quinn::VarInt::from_u32(
        quic_cfg.max_idle_timeout_ms,
    ))));
    transport.keep_alive_interval(Some(Duration::from_millis(u64::from(
        quic_cfg.keepalive_interval_ms,
    ))));
    if let Ok(v) = quinn::VarInt::from_u64(quic_cfg.max_concurrent_bidi_streams) {
        transport.max_concurrent_bidi_streams(v);
    }
    if quic_cfg.datagram_enabled {
        transport.datagram_receive_buffer_size(Some(1024 * 1024));
        transport.datagram_send_buffer_size(256 * 1024);
    }
    let quic_tls = quinn::crypto::rustls::QuicServerConfig::try_from(Arc::new(server_tls))
        .map_err(|e| {
            InterflowError::config(format!("invalid QUIC server TLS configuration: {e}"))
        })?;
    let mut server_config = quinn::ServerConfig::with_crypto(Arc::new(quic_tls));
    server_config.transport_config(Arc::new(transport));

    let endpoint = quinn::Endpoint::server(server_config, listen_addr)?;
    info!("Hub QUIC listener started: {listen_addr} (ALPN: interflow)");

    let tasks = ctx.tasks.clone();
    let shutdown = ctx.shutdown.clone();
    tasks.clone().spawn(async move {
        loop {
            tokio::select! {
                () = shutdown.cancelled() => {
                    // CONNECTION_CLOSE is delivered to all connections
                    // (application error code 0 = NO_ERROR); agent-side
                    // sessions end, in-flight streams close out; accept then
                    // returns None.
                    endpoint.close(quinn::VarInt::from_u32(0), b"hub shutting down");
                    break;
                }
                incoming = endpoint.accept() => {
                    let Some(incoming) = incoming else {
                        break;
                    };
                    let ctx = ctx.clone();
                    tasks.spawn(async move {
                        match incoming.await {
                            Ok(conn) => handle_connection(ctx, conn).await,
                            Err(e) => {
                                debug!("QUIC handshake failed: {e}");
                                metrics::counter!("interflow_quic_handshake_failures").increment(1);
                            }
                        }
                    });
                }
            }
        }
    });
    Ok(())
}

/// One QUIC connection: control-stream registration + traffic-stream accept
/// loop + disconnect watcher.
async fn handle_connection(ctx: AcceptContext, conn: quinn::Connection) {
    let peer = conn.remote_address().to_string();

    // First bidirectional stream = control stream
    let (control_tx, control_rx) = match conn.accept_bi().await {
        Ok(pair) => pair,
        Err(e) => {
            debug!("QUIC connection closed before control stream established: {e}");
            return;
        }
    };

    let quic_conn = Arc::new(QuicAgentConn {
        conn: conn.clone(),
        control: tokio::sync::Mutex::new(control_tx),
        datagram_cap: std::sync::atomic::AtomicBool::new(false),
    });

    let Some((agent_id, state_arc)) =
        register_quic_agent(&ctx, &conn, control_rx, &quic_conn, &peer).await
    else {
        // Registration failed (authentication/validation): the connection
        // has already been closed
        return;
    };

    // DATAGRAM receive loop: datagram frames from the agent → table lookup
    // → dispatch to the peer
    if quic_conn
        .datagram_cap
        .load(std::sync::atomic::Ordering::Relaxed)
    {
        let core2 = ctx.core();
        let conn2 = conn.clone();
        let agent_id2 = agent_id.clone();
        ctx.tasks.spawn(async move {
            datagram_relay_loop(core2, conn2, agent_id2).await;
        });
    }

    // Connection-lost watcher: eviction + orphan stream sweep
    {
        let ctx2 = ctx.clone();
        let agent_id2 = agent_id.clone();
        let expected = state_arc.clone();
        let conn_watcher = conn.clone();
        ctx.tasks.spawn(async move {
            let reason = conn_watcher.closed().await;
            info!("QUIC agent {agent_id2} connection lost: {reason}");
            crate::hub::heartbeat::evict_agent(
                &ctx2.handles(),
                &agent_id2,
                &expected,
                "quic_connection_closed",
            )
            .await;
        });
    }

    // Transport-stats sampler (twin of the egress-side sampler in core
    // tunnel/quic.rs): the CC forensics anchor for the 2026-09-16 quic
    // egress-stall case file — cumulative counters, diff adjacent samples.
    {
        let conn_stats = conn.clone();
        let agent_stats = agent_id.clone();
        ctx.tasks.spawn(async move {
            let mut tick = tokio::time::interval(Duration::from_secs(10));
            tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
            loop {
                tokio::select! {
                    _ = conn_stats.closed() => break,
                    _ = tick.tick() => {}
                }
                let p = &conn_stats.stats().path;
                debug!(
                    agent = %agent_stats,
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

    // Traffic stream loop
    loop {
        let (tx, rx) = match conn.accept_bi().await {
            Ok(pair) => pair,
            Err(_) => break,
        };
        let ctx = ctx.clone();
        let source_agent = agent_id.clone();
        let stream_tasks = ctx.tasks.clone();
        stream_tasks.spawn(async move {
            if let Err(e) = handle_quic_stream(ctx, source_agent, tx, rx).await {
                debug!("QUIC stream handling finished: {e}");
            }
        });
    }
}

/// Continuously decodes all complete frames from the buffer (skipping
/// unknown types; on invalid input, clears and stops).
fn drain_frames(buf: &mut BytesMut) -> Vec<wire::DecodedFrame> {
    let mut out = Vec::new();
    loop {
        match wire::decode_frame(buf) {
            wire::DecodeOutcome::Ok(f) => out.push(f),
            wire::DecodeOutcome::Pending | wire::DecodeOutcome::Error => break,
            wire::DecodeOutcome::UnknownType { .. } => continue,
        }
    }
    out
}

/// Reads the stream until one frame decodes (`Ok(None)` = EOF;
/// `Err` = protocol violation).
async fn read_first_frame(
    rx: &mut quinn::RecvStream,
    buf: &mut BytesMut,
) -> Result<Option<wire::DecodedFrame>> {
    let mut chunk = [0u8; 16 * 1024];
    loop {
        let n = rx
            .read(&mut chunk)
            .await
            .map_err(|e| InterflowError::connection(format!("{e}")))?
            .unwrap_or(0);
        if n == 0 {
            return Ok(None);
        }
        buf.extend_from_slice(&chunk[..n]);
        match wire::decode_frame(buf) {
            wire::DecodeOutcome::Ok(f) => return Ok(Some(f)),
            wire::DecodeOutcome::Pending => continue,
            wire::DecodeOutcome::Error => {
                return Err(InterflowError::protocol(
                    "invalid QUIC frame format".to_string(),
                ));
            }
            wire::DecodeOutcome::UnknownType { .. } => continue,
        }
    }
}

/// Control-stream registration: read Hello → authenticate → register
/// (replace-in-place semantics identical to h2 /register) → HelloAck.
async fn register_quic_agent(
    ctx: &AcceptContext,
    conn: &quinn::Connection,
    mut control_rx: quinn::RecvStream,
    quic_conn: &Arc<QuicAgentConn>,
    peer: &str,
) -> Option<(String, Arc<RwLock<AgentSession>>)> {
    let mut buf = BytesMut::with_capacity(256);
    // Bounded wait for the agent's Hello: an established connection that
    // never speaks must not pin a registration task until the QUIC idle
    // timeout catches it. The budget mirrors the agent's own registration
    // bound (the shared establish default).
    let hello = if let Ok(r) = tokio::time::timeout(
        interflow_core::tunnel::DEFAULT_REQUEST_ESTABLISH_TIMEOUT,
        read_first_frame(&mut control_rx, &mut buf),
    )
    .await
    {
        r.ok().flatten()
    } else {
        warn!("QUIC registration stalled: no Hello within the establish deadline ({peer})");
        None
    }?;

    if !matches!(hello.frame_type, FrameType::Hello) {
        warn!("QUIC first frame is not Hello ({peer})");
        return None;
    }
    let agent_id = hello.source_agent;
    if agent_id.is_empty() || agent_id.len() > 128 {
        warn!("QUIC Hello agent_id invalid ({peer})");
        return None;
    }

    // Authentication: static-token (constant-time comparison) / mTLS (CN binding)
    let (auth_mode, allow_anonymous, static_token) = {
        let cfg = ctx.config.read().await;
        (
            cfg.auth.mode,
            cfg.auth.allow_anonymous,
            cfg.auth.static_token.as_ref().and_then(|s| s.agent.clone()),
        )
    };
    let (hello_caps, token) = interflow_core::tunnel::quic::decode_hello_payload(&hello.payload);
    let agent_datagram_cap = quinn_caps_enabled(ctx).await
        && (hello_caps & interflow_core::tunnel::quic::CAP_DATAGRAM != 0);
    match auth_mode {
        AuthMode::StaticToken => {
            if !allow_anonymous {
                let expected = static_token.unwrap_or_default();
                let ok = !token.is_empty()
                    && subtle::ConstantTimeEq::ct_eq(token.as_bytes(), expected.as_bytes()).into();
                if !ok {
                    warn!("QUIC registration rejected: invalid token agent={agent_id} ({peer})");
                    metrics::counter!("interflow_hub_auth_failures", "reason" => "quic_token")
                        .increment(1);
                    send_error_and_close(conn, "invalid token").await;
                    return None;
                }
            }
        }
        AuthMode::Mtls => {
            let cn = interflow_core::tls::extract_cn_from_quinn_identity(conn.peer_identity());
            match cn {
                Some(cn) if cn == agent_id => {}
                _ => {
                    warn!(
                        "QUIC registration rejected: mTLS CN does not match agent_id agent={agent_id} ({peer})"
                    );
                    metrics::counter!("interflow_hub_auth_failures", "reason" => "quic_mtls_cn")
                        .increment(1);
                    send_error_and_close(conn, "cn mismatch").await;
                    return None;
                }
            }
        }
        AuthMode::Anonymous => {}
    }

    // Register (reuses registration semantics: replace in place + sweep
    // orphan streams + absolute-value gauge)
    let state_arc = {
        let mut agents = ctx.agents.write().await;
        if let Some(existing) = agents.get(&agent_id) {
            // QUIC registration overwrites an h2 session (same preemption
            // semantics, mirrored)
            existing
                .write()
                .await
                .install_channels(Some(quic_conn.clone()));
            existing.clone()
        } else {
            let arc = Arc::new(RwLock::new(AgentSession::new(Some(quic_conn.clone()))));
            agents.insert(agent_id.clone(), arc.clone());
            arc
        }
    };
    metrics::gauge!("interflow_hub_agents_registered").set(crate::hub::state::count_as_f64(
        ctx.agents.read().await.len(),
    ));
    quic_conn
        .datagram_cap
        .store(agent_datagram_cap, std::sync::atomic::Ordering::Relaxed);
    metrics::counter!("interflow_quic_agents_registered").increment(1);

    crate::hub::service::HubService::sweep_agent_streams(
        &ctx.agents,
        &ctx.active_streams,
        &ctx.stream_counts,
        &agent_id,
    )
    .await;

    // HelloAck payload: `[caps u8][capability JSON]` — the same capability
    // declaration the h2 register response body carries (heartbeat cadence
    // for the agent-side stall derivation). QUIC Pongs ride the control
    // stream, so there is nothing transport-specific to declare.
    let hub_caps = if quinn_caps_enabled(ctx).await {
        interflow_core::tunnel::quic::CAP_DATAGRAM
    } else {
        0
    };
    let capability = {
        let cfg = ctx.config.read().await;
        RegisterResponse {
            heartbeat: cfg
                .heartbeat
                .enabled
                .then_some(HeartbeatAd::from(&cfg.heartbeat)),
        }
    };
    let payload = match interflow_core::tunnel::quic::encode_helloack_payload(hub_caps, &capability)
    {
        Ok(payload) => payload,
        Err(e) => {
            warn!("QUIC capability declaration encode failed agent={agent_id}: {e}");
            return None;
        }
    };
    let mut ack = BytesMut::with_capacity(64);
    wire::encode_frame(FrameType::HelloAck, 0, "", "hub", &payload, &mut ack);
    {
        let mut control = quic_conn.control.lock().await;
        if control.write_all(&ack).await.is_err() {
            warn!("QUIC HelloAck send failed agent={agent_id}");
            return None;
        }
    }

    // Heartbeat (control-stream Ping + last_pong death decision; reuses the
    // heartbeat configuration and the eviction primitive)
    spawn_quic_heartbeat(
        ctx.clone(),
        agent_id.clone(),
        state_arc.clone(),
        quic_conn.clone(),
    );

    // Control stream read loop (Pong → last_pong)
    let state_for_pong = state_arc.clone();
    let pong_tasks = ctx.tasks.clone();
    pong_tasks.spawn(async move {
        let mut buf = BytesMut::with_capacity(256);
        let mut chunk = [0u8; 1024];
        loop {
            let n = match control_rx.read(&mut chunk).await {
                Ok(Some(n)) => n,
                Ok(None) | Err(_) => break,
            };
            buf.extend_from_slice(&chunk[..n]);
            for f in drain_frames(&mut buf) {
                if matches!(f.frame_type, FrameType::Pong) {
                    let mut st = state_for_pong.write().await;
                    st.last_pong = std::time::Instant::now();
                }
            }
        }
    });

    ctx.audit.record(
        AuditKind::AgentRegistered {
            agent_id: agent_id.clone(),
        },
        Some(agent_id.clone()),
        Some(peer.to_string()),
    );
    info!("QUIC agent registered: {agent_id} ({peer})");
    Some((agent_id, state_arc))
}

/// Authentication failure: best-effort send of an Error frame, then close
/// the connection.
async fn send_error_and_close(conn: &quinn::Connection, msg: &str) {
    let Ok((mut tx, rx)) = conn.open_bi().await else {
        conn.close(0_u32.into(), b"auth failed");
        return;
    };
    let mut buf = BytesMut::new();
    wire::encode_frame(FrameType::Error, 0, "", "hub", msg.as_bytes(), &mut buf);
    if tx.write_all(&buf).await.is_ok() {
        let _ = tx.finish();
    }
    drop(rx);
    conn.close(0_u32.into(), b"auth failed");
}

/// QUIC heartbeat: send a Ping every interval seconds (control stream);
/// evict once last_pong exceeds the threshold.
///
/// Shares `AgentSession::last_pong` and the eviction primitive with the h2
/// heartbeat.
fn spawn_quic_heartbeat(
    ctx: AcceptContext,
    agent_id: String,
    state: Arc<RwLock<AgentSession>>,
    conn: Arc<QuicAgentConn>,
) {
    let tasks = ctx.tasks.clone();
    tasks.spawn(async move {
        let ctx = ctx;
        let death_watch = conn.conn.closed();
        tokio::pin!(death_watch);
        loop {
            let (enabled, interval_secs, max_missed) = {
                let cfg = ctx.config.read().await;
                (
                    cfg.heartbeat.enabled,
                    cfg.heartbeat.interval_secs,
                    cfg.heartbeat.max_missed,
                )
            };
            if !enabled {
                // Polling interval while heartbeats are disabled (waiting
                // for a hot reload), same as the h2 heartbeat; exit
                // immediately when the connection dies (releases the
                // Connection reference promptly — otherwise the quinn driver
                // and the UDP socket have to wait for the next polling cycle)
                tokio::select! {
                    () = tokio::time::sleep(
                        interflow_core::config::params::liveness::HEARTBEAT_DISABLED_POLL,
                    ) => continue,
                    _ = &mut death_watch => return,
                }
            }
            tokio::select! {
                () = tokio::time::sleep(Duration::from_secs(interval_secs)) => {}
                _ = &mut death_watch => return,
            }

            let mut ping = BytesMut::with_capacity(32);
            wire::encode_frame(FrameType::Ping, 0, "", &agent_id, b"", &mut ping);
            {
                let mut control = conn.control.lock().await;
                if control.write_all(&ping).await.is_err() {
                    // Connection is gone; the disconnect watcher handles
                    // eviction
                    return;
                }
            }

            // The eviction dead line — the canonical derivation, identical
            // to the h2 heartbeat loop (single source: core params).
            let deadline = interflow_core::config::params::liveness::HeartbeatCadence {
                interval_secs,
                max_missed,
            }
            .dead_line();
            let dead = {
                let st = state.read().await;
                st.last_pong.elapsed() > deadline
            };
            if dead {
                warn!("QUIC agent {agent_id} heartbeat lost (>{deadline:?}), evicting");
                crate::hub::heartbeat::evict_agent(
                    &ctx.handles(),
                    &agent_id,
                    &state,
                    "quic_heartbeat_timeout",
                )
                .await;
                return;
            }
        }
    });
}

/// Relay stream writer task: encodes `TunnelData` and writes it out; when
/// the channel closes (ActiveStream removed) it **writes the outstanding
/// Close frame + FIN**, so the peer's read loop exits cleanly and triggers
/// its cleanup path.
async fn relay_stream_writer(
    mut tx: quinn::SendStream,
    mut rx: mpsc::Receiver<TunnelData>,
    stream_id: String,
    datagram_conn: Option<quinn::Connection>,
) {
    while let Some(df) = rx.recv().await {
        let mut buf = BytesMut::with_capacity(64 + df.data.len());
        if wire::encode_frame(
            df.stream_type,
            df.flags,
            &df.stream_id,
            df.source.as_str(),
            &df.data,
            &mut buf,
        )
        .is_none()
        {
            error!("QUIC relay frame encode failed: stream_id={}", df.stream_id);
            break;
        }
        // DATAGRAM fast path: UDP stream + small frame + peer capability —
        // unreliable, unordered direct delivery with no HOL blocking on
        // loss; on send failure fall back to stream carriage
        if let Some(conn) = &datagram_conn
            && df.flags & interflow_core::protocol::FLAG_UDP != 0
            && matches!(df.stream_type, FrameType::Data)
            && buf.len() <= DATAGRAM_FRAME_BUDGET
            && conn.send_datagram(buf.clone().freeze()).is_ok()
        {
            continue;
        }
        if tx.write_all(&buf).await.is_err() {
            debug!(
                "QUIC relay write failed (peer connection closed): stream_id={}",
                df.stream_id
            );
            break;
        }
    }
    // Outstanding Close + FIN (double Close is idempotent: the agent side's
    // first Close triggers cleanup); the sentinel-source rationale lives on
    // [`write_close_frame`].
    write_close_frame(tx, &stream_id).await;
}

/// Opens a relay stream to a quic target agent and writes the Open frame;
/// starts the writer task and the target-side read pump.
///
/// Returns the dispatch channel (`TunnelData` is encoded and written to the
/// stream). The target-side read pump feeds return-path frames back to the
/// source via [`deliver_dataframe`] (a quic source goes via the Relay plane,
/// h2 via poll).
pub(crate) async fn open_relay_stream(
    core: &HubCore,
    target_conn: &QuicAgentConn,
    stream_id: &str,
    source_agent: &str,
    target_addr: Option<&str>,
    proto: StreamProto,
) -> Option<mpsc::Sender<TunnelData>> {
    let (tx, rx) = mpsc::channel::<TunnelData>(RELAY_CHANNEL_CAP);
    let (mut send, recv) = target_conn.conn.open_bi().await.ok()?;
    let target_datagram = target_conn
        .datagram_cap
        .load(std::sync::atomic::Ordering::Relaxed);

    // Open frame: payload = "{source}:{addr}" (egress parsing format
    // identical to the h2 path)
    let open_payload = format!("{source_agent}:{}", target_addr.unwrap_or(""));
    let mut open = BytesMut::with_capacity(64 + open_payload.len());
    wire::encode_frame(
        FrameType::Open,
        proto.as_flag(),
        stream_id,
        source_agent,
        open_payload.as_bytes(),
        &mut open,
    )?;
    if send.write_all(&open).await.is_err() {
        return None;
    }

    // egress-side OpenAck: target capability + UDP stream (equally
    // applicable to an h2 source — the fast path concerns only the
    // hub↔target hop)
    if target_datagram && matches!(proto, StreamProto::Udp) {
        let mut ack = BytesMut::with_capacity(64);
        wire::encode_frame(FrameType::OpenAck, 0, stream_id, "hub", b"", &mut ack);
        if send.write_all(&ack).await.is_err() {
            return None;
        }
    }

    tokio::spawn(relay_stream_writer(
        send,
        rx,
        stream_id.to_string(),
        if target_datagram {
            Some(target_conn.conn.clone())
        } else {
            None
        },
    ));

    // Target-side read pump (return direction; the Open frame was written
    // directly by this function, no residue)
    tokio::spawn(relay_reader(
        core.clone(),
        recv,
        BytesMut::new(),
        stream_id.to_string(),
        source_agent.to_string(),
        true,
    ));

    Some(tx)
}

/// Unified dispatch: go through the relay stream when a sink exists,
/// otherwise through the poll channel (with timeout discipline).
pub(crate) async fn deliver_dataframe(
    agents: &SharedAgents,
    sink: Option<&mpsc::Sender<TunnelData>>,
    recipient: &str,
    df: TunnelData,
    timeout_secs: u64,
) -> std::result::Result<(), RelayDeliveryError> {
    let timeout = Duration::from_secs(timeout_secs.max(1));
    if let Some(sink) = sink {
        return match tokio::time::timeout(timeout, sink.send(df)).await {
            Ok(Ok(())) => Ok(()),
            Ok(Err(_)) => Err(RelayDeliveryError::ChannelClosed),
            Err(_) => Err(RelayDeliveryError::Timeout),
        };
    }
    // h2 peer: lookup_tx → poll channel (two short critical sections for
    // locking; no awaiting while holding a lock)
    let state_arc = {
        let map = agents.read().await;
        map.get(recipient).cloned()
    };
    let Some(state_arc) = state_arc else {
        return Err(RelayDeliveryError::AgentMissing);
    };
    let tx = {
        let st = state_arc.read().await;
        st.tx.clone()
    };
    match tokio::time::timeout(timeout, tx.send(df)).await {
        Ok(Ok(())) => Ok(()),
        Ok(Err(_)) => Err(RelayDeliveryError::ChannelClosed),
        Err(_) => Err(RelayDeliveryError::Timeout),
    }
}

/// Dispatch failure classification.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum RelayDeliveryError {
    AgentMissing,
    ChannelClosed,
    Timeout,
}

/// Connection-level DATAGRAM receive loop: decode frames → look up the
/// ActiveStream → dispatch to the peer.
///
/// Datagrams carry only Data frames (Open/Close go over streams, where
/// reliable ordering is a hard prerequisite for session establishment);
/// unknown streams (late/reordered) are dropped and counted — the OpenAck
/// handshake guarantees they cannot occur on the normal path.
async fn datagram_relay_loop(core: HubCore, conn: quinn::Connection, agent_id: String) {
    let timeout_secs = core
        .channel_send_timeout_secs
        .load(std::sync::atomic::Ordering::Relaxed);
    loop {
        let datagram = match conn.read_datagram().await {
            Ok(d) => d,
            Err(_) => break, // connection closed
        };
        let mut buf = BytesMut::from(&datagram[..]);
        // One datagram holds exactly one frame (the sender encodes whole
        // frames)
        let frame = if let wire::DecodeOutcome::Ok(f) = wire::decode_frame(&mut buf) {
            f
        } else {
            metrics::counter!("interflow_quic_datagram_dropped").increment(1);
            continue;
        };
        if !matches!(frame.frame_type, FrameType::Data) {
            continue; // control frames are not allowed on datagrams
        }
        // Direction awareness: is the sender the stream's source
        // (request direction → target) or the target (response direction →
        // source)? Anti-forgery: it must match one of the stream's ends.
        let (recipient, sink, frame_source, proto_flag) = {
            let streams = core.active_streams.read().await;
            let Some(st) = streams.get(&frame.stream_id) else {
                metrics::counter!("interflow_quic_datagram_dropped").increment(1);
                continue;
            };
            let proto_flag = st.proto.as_flag();
            if agent_id == st.source_agent {
                (
                    st.target_agent.clone(),
                    st.target.relay_sender().cloned(),
                    FrameSource::Agent(agent_id.clone().into()),
                    proto_flag,
                )
            } else if agent_id == st.target_agent {
                (
                    st.source_agent.clone(),
                    st.source.relay_sender().cloned(),
                    FrameSource::Response,
                    proto_flag,
                )
            } else {
                metrics::counter!("interflow_quic_datagram_dropped").increment(1);
                continue;
            }
        };
        if recipient.is_empty() {
            continue;
        }
        let df = TunnelData {
            stream_id: frame.stream_id,
            source: frame_source,
            stream_type: FrameType::Data,
            flags: proto_flag,
            data: frame.payload,
        };
        let stream_id = df.stream_id.clone();
        if deliver_dataframe(&core.agents, sink.as_ref(), &recipient, df, timeout_secs)
            .await
            .is_err()
        {
            // Dispatch failure reclaims the stream (same discipline as the
            // stream path). Direction semantics: the sender is the target
            // (response-direction data) → notify the source end with
            // response FIFO semantics; otherwise request direction →
            // guaranteed delivery via the control channel.
            let sender_is_target = {
                let streams = core.active_streams.read().await;
                streams
                    .get(&stream_id)
                    .is_some_and(|st| st.target_agent == agent_id)
            };
            teardown_stream(&core, &stream_id, sender_is_target, "").await;
        }
        metrics::counter!("interflow_quic_datagrams_relayed").increment(1);
    }
}

/// Removes an active stream: drop the table entry + release the source
/// agent's slot + gauge + **notify the poll-plane peer**.
///
/// Termination contract (2026-09-14 in-session orphan-stream root fix):
/// removing the entry must produce a termination signal on the **peer's
/// dispatch plane** — on the Relay plane (QUIC peer) it is conveyed by the
/// entry drop closing the senders and the relay writer task writing the
/// outstanding Close+FIN; on the Poll plane (h2 peer) an explicit `_close_`
/// must be delivered, otherwise the peer's forwarder waits forever for a
/// Close and the backend fd lingers for the whole session.
///
/// `response_dir = true` means the dead end is the target side (egress):
/// the peer is the source agent, notified with response-direction semantics
/// (data-channel FIFO first; queued response tail bytes are still
/// deliverable); `false` means the dead end is the source side: the peer is
/// the target agent, notified via the control channel with guaranteed
/// delivery (the source end is dead; releasing the peer's fd takes
/// priority).
pub(crate) async fn teardown_stream(
    core: &HubCore,
    stream_id: &str,
    response_dir: bool,
    reason: &str,
) {
    let removed = {
        let mut streams = core.active_streams.write().await;
        streams.remove(stream_id)
    };
    if let Some(stream) = removed {
        metrics::gauge!("interflow_hub_streams_active").decrement(1.0);
        {
            // The count lock is confined to an independent scope: never
            // hold a std Mutex guard across an await
            let mut map = core
                .stream_counts
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            if let Some(entry) = map.get_mut(&stream.source_agent) {
                *entry = entry.saturating_sub(1);
                if *entry == 0 {
                    map.remove(&stream.source_agent);
                }
            }
        }
        // Poll-plane peer notification (the relay plane is informed by the
        // entry drop above)
        let (peer, face) = if response_dir {
            (stream.source_agent.clone(), &stream.source)
        } else {
            (stream.target_agent.clone(), &stream.target)
        };
        if !peer.is_empty() && !face.is_relay() {
            if response_dir {
                let _ = crate::hub::control::deliver_response_close(
                    &core.agents,
                    &peer,
                    stream_id,
                    reason,
                )
                .await;
            } else {
                let _ = crate::hub::control::deliver_close_via_control(
                    &core.agents,
                    &peer,
                    stream_id,
                    reason,
                )
                .await;
            }
        }
    }
}

/// Handles one traffic stream from a quic agent (the first frame must be
/// Open).
async fn handle_quic_stream(
    ctx: AcceptContext,
    source_agent: String,
    tx: quinn::SendStream,
    rx: quinn::RecvStream,
) -> Result<()> {
    let core = ctx.core();
    let mut rx = rx;
    let mut buf = BytesMut::with_capacity(512);

    let Some(opened) = read_first_frame(&mut rx, &mut buf).await? else {
        return Ok(()); // EOF before Open: drop silently
    };
    if !matches!(opened.frame_type, FrameType::Open) {
        return Err(InterflowError::protocol(
            "QUIC stream first frame must be Open".to_string(),
        ));
    }
    // Anti-forgery: the frame's declared source must match the connection
    // identity
    if opened.source_agent != source_agent {
        warn!(
            "QUIC forgery check: connection identity {source_agent}, frame claims {}",
            opened.source_agent
        );
        return Ok(());
    }

    let stream_id = opened.stream_id;
    // payload = "{target_agent}:{target_addr}"
    let payload_str = String::from_utf8_lossy(&opened.payload).to_string();
    let (target_agent, target_addr) = match payload_str.split_once(':') {
        Some((t, a)) => (t.to_string(), (!a.is_empty()).then(|| a.to_string())),
        None => (payload_str, None),
    };
    let proto = StreamProto::from_frame_flags(opened.flags);

    // ACL (same judgment as handle_open)
    if ctx
        .limits
        .acl_enabled
        .load(std::sync::atomic::Ordering::Relaxed)
    {
        let config = ctx.config.read().await;
        if !config.acl.is_empty() {
            let rule = crate::config::AclRule {
                source: source_agent.clone(),
                target: target_agent.clone(),
            };
            if !config.acl.contains(&rule) {
                warn!("ACL denied (QUIC): {source_agent} -> {target_agent}");
                metrics::counter!("interflow_hub_acl_denied").increment(1);
                ctx.audit.record(
                    AuditKind::StreamDenied {
                        stream_id: stream_id.clone(),
                        source: source_agent.clone(),
                        reason: format!("acl_denied: target={target_agent}"),
                    },
                    Some(source_agent.clone()),
                    None,
                );
                write_close_frame(tx, &stream_id).await;
                return Ok(());
            }
        }
    }

    // Stream limits (same table as handle_open)
    let (max_per_agent, max_total) = (
        ctx.limits
            .max_streams_per_agent
            .load(std::sync::atomic::Ordering::Relaxed),
        ctx.limits
            .max_streams_total
            .load(std::sync::atomic::Ordering::Relaxed),
    );
    if max_total > 0 && core.active_streams.read().await.len() >= max_total {
        metrics::counter!("interflow_hub_stream_limit_denied", "scope" => "total").increment(1);
        write_close_frame(tx, &stream_id).await;
        return Ok(());
    }
    if max_per_agent > 0
        && !crate::hub::state::try_acquire_stream_slot(
            &core.stream_counts,
            &source_agent,
            max_per_agent,
        )
    {
        metrics::counter!("interflow_hub_stream_limit_denied", "scope" => "per_agent").increment(1);
        write_close_frame(tx, &stream_id).await;
        return Ok(());
    }

    // Target resolution: quic → relay stream; h2 → Open notification via
    // poll; nonexistent → roll back
    let target_state = {
        let agents = core.agents.read().await;
        agents.get(&target_agent).cloned()
    };
    let Some(target_state) = target_state else {
        crate::hub::state::release_stream_slot(&core.stream_counts, &source_agent);
        write_close_frame(tx, &stream_id).await;
        return Ok(());
    };

    let target_sink = {
        let st = target_state.read().await;
        if let Some(qc) = st.quic.clone() {
            drop(st);
            open_relay_stream(
                &core,
                &qc,
                &stream_id,
                &source_agent,
                target_addr.as_deref(),
                proto,
            )
            .await
        } else {
            // h2 target: Open notification goes via the poll channel
            // (payload format identical to handle_open)
            let open_df = TunnelData {
                stream_id: stream_id.clone(),
                source: FrameSource::Open,
                stream_type: FrameType::Open,
                flags: proto.as_flag(),
                data: Bytes::from(format!(
                    "{source_agent}:{}",
                    target_addr.clone().unwrap_or_default()
                )),
            };
            match deliver_dataframe(&core.agents, None, &target_agent, open_df, 1).await {
                Ok(()) => None, // goes via lookup_tx / poll
                Err(e) => {
                    warn!("QUIC Open notification failed target={target_agent}: {e:?}");
                    crate::hub::state::release_stream_slot(&core.stream_counts, &source_agent);
                    write_close_frame(tx, &stream_id).await;
                    return Ok(());
                }
            }
        }
    };

    // DATAGRAM fast-path eligibility: UDP stream + capability on both the
    // source and (if quic) target sides + hub toggle
    let target_datagram_cap = target_state
        .read()
        .await
        .quic
        .as_ref()
        .is_some_and(|qc| qc.datagram_cap.load(std::sync::atomic::Ordering::Relaxed));
    let source_datagram_cap = quinn_caps_enabled(&ctx).await;
    let datagram_ok = matches!(proto, StreamProto::Udp) && target_datagram_cap;

    // Source writer task (return-path frames → this stream of the source
    // agent); the ingress-side connection enables the writer fast path
    let (source_tx, source_rx) = mpsc::channel::<TunnelData>(RELAY_CHANNEL_CAP);
    tokio::spawn(relay_stream_writer(
        tx,
        source_rx,
        stream_id.clone(),
        if datagram_ok && source_datagram_cap {
            conn_for_datagram(&core, &source_agent).await
        } else {
            None
        },
    ));
    let source_face = StreamFace::Relay(source_tx);

    // Insert the ActiveStream
    {
        let mut streams = core.active_streams.write().await;
        streams.insert(
            stream_id.clone(),
            crate::hub::ActiveStream {
                source_agent: source_agent.clone(),
                target_agent: target_agent.clone(),
                target_addr: target_addr.clone(),
                proto,
                target: target_sink
                    .clone()
                    .map_or(StreamFace::Poll, StreamFace::Relay),
                source: source_face,
                datagram_ok,
            },
        );
    }

    // OpenAck: only after the source (ingress) receives it does it switch
    // to DATAGRAM (eliminates the first-packet reordering/loss race)
    if datagram_ok && source_datagram_cap {
        let ack = TunnelData {
            stream_id: stream_id.clone(),
            source: FrameSource::Agent("hub".into()),
            stream_type: FrameType::OpenAck,
            flags: 0,
            data: Bytes::new(),
        };
        let sink = {
            let streams = core.active_streams.read().await;
            streams
                .get(stream_id.as_str())
                .and_then(|st| st.source.relay_sender().cloned())
        };
        if let Some(sink) = sink {
            let _ = sink.send(ack).await;
        }
    }
    metrics::gauge!("interflow_hub_streams_active").increment(1.0);
    metrics::counter!("interflow_hub_streams_total", "direction" => "request").increment(1);
    ctx.audit.record(
        AuditKind::StreamOpened {
            stream_id: stream_id.clone(),
            source: source_agent.clone(),
            target: target_agent.clone(),
        },
        Some(source_agent.clone()),
        None,
    );

    // Source read pump (request direction; buf carries residual bytes that
    // arrived after the Open frame in the same packet)
    tracing::debug!(
        "handle_quic_stream: entering relay_reader stream={stream_id} leftover={}",
        buf.len()
    );
    relay_reader(core, rx, buf, stream_id, source_agent, false).await;
    Ok(())
}

/// Frame-aware read pump: reads frames from one side of a stream and, by
/// direction, dispatches them to the peer via an ActiveStream table lookup.
///
/// Routing by table lookup (rather than capturing the sink in a closure)
/// makes dispatch semantics fully identical across the two transport planes,
/// and it automatically follows a new sink after the target re-registers or
/// the relay is rebuilt. `response_dir = true` means the target-side stream
/// is being read.
///
/// Subsequent frames arriving in the same packet as the first frame
/// (`initial_buf` residue) must be drained **before the read loop** — short
/// sessions (Open and Data in one packet, then nothing) would leave residual
/// frames postponed indefinitely if they were only processed on the next
/// read.
async fn relay_reader(
    core: HubCore,
    mut rx: quinn::RecvStream,
    initial_buf: BytesMut,
    stream_id: String,
    source_agent: String,
    response_dir: bool,
) {
    let mut buf = initial_buf;
    let mut chunk = vec![0u8; READ_CHUNK];
    let stream_id = stream_id.as_str();
    let source_agent = source_agent.as_str();

    // Drain the initial residue first (this may directly terminate the
    // stream, e.g. if the residue already contains a Close)
    if process_frames(&core, &mut buf, stream_id, source_agent, response_dir).await {
        return;
    }

    loop {
        let n = match rx.read(&mut chunk).await {
            Ok(Some(n)) => n,
            Ok(None) | Err(_) => break,
        };
        buf.extend_from_slice(&chunk[..n]);
        if process_frames(&core, &mut buf, stream_id, source_agent, response_dir).await {
            return;
        }
    }
    // EOF: peer half-closed (Close already handled or an abnormal stream
    // cut) — close out as a close (termination contract: the poll-plane peer
    // is notified by teardown_stream, with direction following this read
    // pump's directional semantics)
    teardown_stream(&core, stream_id, response_dir, "").await;
}

/// Decodes and dispatches all complete frames in `buf`; returns true when
/// this stream has terminated (Close received / dispatch failure triggered
/// teardown).
async fn process_frames(
    core: &HubCore,
    buf: &mut BytesMut,
    stream_id: &str,
    source_agent: &str,
    response_dir: bool,
) -> bool {
    let timeout_secs = core
        .channel_send_timeout_secs
        .load(std::sync::atomic::Ordering::Relaxed);

    for frame in drain_frames(buf) {
        // Look up the table for direction info (target/source agent ids,
        // sink, and stream protocol). Data frame flags are filled in from
        // the protocol recorded in the ActiveStream (same semantics as h2
        // handle_data — egress relies on frame flags for stateless UDP
        // stream identification; the Data frames sent by ingress do not
        // carry the proto bit themselves).
        let route = {
            let streams = core.active_streams.read().await;
            streams.get(stream_id).map(|s| {
                let proto_flag = s.proto.as_flag();
                if response_dir {
                    (
                        s.source_agent.clone(),
                        s.source.relay_sender().cloned(),
                        proto_flag,
                    )
                } else {
                    (
                        s.target_agent.clone(),
                        s.target.relay_sender().cloned(),
                        proto_flag,
                    )
                }
            })
        };
        let Some((recipient, sink, proto_flag)) = route else {
            debug!("QUIC relay frame has no route: stream_id={stream_id}, dropping");
            continue;
        };

        if matches!(frame.frame_type, FrameType::Close) {
            // Termination: the poll peer's `_close_` notification is
            // guaranteed delivery by teardown_stream per directional
            // semantics (the old path silently lost it when the data
            // channel was full, leaving the peer's fd lingering for the
            // whole session); the quic peer is informed by the entry drop
            // triggering the writer task to write the outstanding Close +
            // FIN. The Close payload carries the egress close reason
            // (empty = ordinary close) and is forwarded to the poll peer.
            let reason = crate::hub::control::close_reason_of(&frame.payload);
            teardown_stream(core, stream_id, response_dir, &reason).await;
            return true;
        }

        let df = TunnelData {
            stream_id: stream_id.to_string(),
            source: if response_dir {
                FrameSource::Response
            } else {
                FrameSource::Agent(source_agent.into())
            },
            stream_type: frame.frame_type,
            flags: proto_flag,
            data: frame.payload,
        };
        if recipient.is_empty() {
            continue;
        }
        if let Err(e) =
            deliver_dataframe(&core.agents, sink.as_ref(), &recipient, df, timeout_secs).await
        {
            warn!(
                "QUIC relay dispatch failed: stream_id={stream_id}, recipient={recipient}: {e:?}"
            );
            // Termination contract: poll-plane peer notification (direction
            // follows this read pump's semantics: the peer of a
            // response_dir pump is the source agent, using response-FIFO
            // priority; the peer of a request-direction pump is the target
            // agent, with guaranteed delivery via the control channel)
            teardown_stream(core, stream_id, response_dir, "").await;
            return true;
        }
        metrics::counter!("interflow_hub_frames_rx", "type" => "data").increment(1);
    }
    false
}

/// Writes a Close frame to a quinn SendStream and FINs it (rollback path
/// notifying the source side).
/// Writes the Close frame to the stream's source end with the `_close_`
/// sentinel (synchronous failure paths such as target missing / ACL denial /
/// limit denial). Tagging the source sentinel with an agent name instead
/// would make the source agent's dispatch drop it as a late
/// request-direction frame, leaving the client connection silently hung
/// until the idle timeout.
async fn write_close_frame(mut tx: quinn::SendStream, stream_id: &str) {
    let mut buf = BytesMut::with_capacity(64);
    if wire::encode_frame(
        FrameType::Close,
        0,
        stream_id,
        FrameSource::Close.as_str(),
        b"",
        &mut buf,
    )
    .is_some()
    {
        let _ = tx.write_all(&buf).await;
    }
    let _ = tx.finish();
}
