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
//! - Control stream (first bidirectional stream): Hello (payload =
//!   `[caps u32][name_len u16][name]`, the intended semantic id; identity is
//!   the mTLS client certificate, CN must equal the declared name) →
//!   HelloAck (the binary capability payload); Ping/Pong heartbeat runs
//!   on the control stream (reusing `AgentSession::last_pong` and the
//!   eviction primitive);
//! - Connection-lost watcher: deregister + sweep orphan streams.
//!
//! Traffic Open frames carry only a route token. The Open frame forwarded to
//! the target carries only the source circuit token; semantic source/target
//! names stay in the control-plane route lease and inner handshake.

// QUIC async tasks hold a 64KiB read buffer, so the future size naturally
// exceeds pedantic thresholds; the frame-decode loop's Pending/UnknownType
// branches and let-else rewrites follow protocol-handling conventions.
#![allow(
    clippy::large_futures,
    clippy::needless_continue,
    clippy::match_same_arms,
    clippy::manual_let_else
)]
use crate::hub::state::{
    AgentSession, HubState, QuicAgentConn, SharedAgents, StreamFace, TunnelData,
};
use bytes::{BufMut, Bytes, BytesMut};
use interflow_core::error::{InterflowError, Result};
use interflow_core::protocol::frame as wire;
use interflow_core::protocol::{
    CircuitToken, CloseReason, FLAG_E2E, FLAG_HUB_ORIGIN, FLAG_RESPONSE, FrameOrigin, FrameType,
    RouteToken, StreamId, StreamProto,
};
use interflow_core::security::AuditKind;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::{RwLock, mpsc};
use tracing::{debug, error, info, warn};

use interflow_core::tunnel::negotiation::{HeartbeatAd, RegisterResponse};
use tokio_rustls::rustls::pki_types::CertificateDer;

/// Relay channel capacity (same as the poll channel).
const RELAY_CHANNEL_CAP: usize = 256;
/// Whole-frame budget for the DATAGRAM fast path (same as the agent side,
/// see core::tunnel::quic).
const DATAGRAM_FRAME_BUDGET: usize = interflow_core::tunnel::quic::DATAGRAM_FRAME_BUDGET;

/// Takes the agent's quinn connection (for the writer fast path).
async fn conn_for_datagram(hub: &HubState, agent_id: &str) -> Option<quinn::Connection> {
    let agents = hub.agents.read().await;
    let state = agents.get(agent_id)?;
    let qc = state.read().await.quic.clone();
    qc.filter(|qc| qc.datagram_cap.load(std::sync::atomic::Ordering::Relaxed))
        .map(|qc| qc.conn.clone())
}

/// Whether the hub enables the DATAGRAM fast path.
async fn quinn_caps_enabled(hub: &HubState) -> bool {
    hub.config.read().await.transport.quic.datagram_enabled
}

/// Read chunk size for traffic streams.
const READ_CHUNK: usize = 64 * 1024;

/// Starts the QUIC listener. Returns an error when enabled but TLS
/// certificates are missing (QUIC mandates TLS).
pub(crate) async fn spawn_quic_listener(hub: std::sync::Arc<HubState>) -> Result<()> {
    let (quic_cfg, tcp_listen) = {
        let cfg = hub.config.read().await;
        (cfg.transport.quic.clone(), cfg.server.listen_addr)
    };
    if !quic_cfg.enabled {
        return Ok(());
    }

    let Some(tls) = hub.config.read().await.tls.clone() else {
        return Err(InterflowError::config(
            "[transport.quic] enabled = true requires certificates from [tls] (QUIC mandates TLS)"
                .to_string(),
        ));
    };

    // mTLS on the QUIC plane: the merged tenant roots enforce client
    // certificates at the handshake; tenant derivation runs post-handshake
    // against the shared TLS plane (hot-reloadable, same generation as the
    // h2 acceptor). The QUIC listener itself is bound once at startup
    // (reload of the rustls config remains restart-required, per the
    // reload contract).
    //
    // QUIC mandates TLS 1.3: a [tls] min_version of 1.2 is honored on the h2
    // plane only — here it is clamped to 1.3 (quinn/rustls reject 1.2-only
    // version lists for QUIC).
    let plane = hub
        .tls_plane
        .read()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .clone();
    let mut server_tls = interflow_core::tls::build_rustls_server_config_with_roots(
        &tls.cert_path,
        &tls.key_path,
        Some(&plane.verifier.merged_roots()),
        interflow_core::tls::TlsMinVersion::V1_3,
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
            InterflowError::config("invalid QUIC server TLS configuration".to_string())
                .with_source(e)
        })?;
    let mut server_config = quinn::ServerConfig::with_crypto(Arc::new(quic_tls));
    server_config.transport_config(Arc::new(transport));

    let endpoint = quinn::Endpoint::server(server_config, listen_addr)?;
    info!("Hub QUIC listener started: {listen_addr} (ALPN: interflow)");

    let tasks = hub.tasks.clone();
    let shutdown = hub.shutdown.clone();
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
                    let hub = hub.clone();
                    tasks.spawn(async move {
                        match incoming.await {
                            Ok(conn) => handle_connection(hub, conn).await,
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
async fn handle_connection(hub: std::sync::Arc<HubState>, conn: quinn::Connection) {
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
        register_quic_agent(&hub, &conn, control_rx, &quic_conn, &peer).await
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
        let conn2 = conn.clone();
        let agent_id2 = agent_id.clone();
        let hub_relay = hub.clone();
        hub.tasks.spawn(async move {
            datagram_relay_loop(hub_relay, conn2, agent_id2).await;
        });
    }

    // Connection-lost watcher: eviction + orphan stream sweep
    {
        let agent_id2 = agent_id.clone();
        let expected = state_arc.clone();
        let circuit_cleanup = state_arc.read().await.circuit;
        let conn_watcher = conn.clone();
        let hub_watcher = hub.clone();
        let watcher_tasks = hub_watcher.tasks.clone();
        watcher_tasks.spawn(async move {
            let reason = conn_watcher.closed().await;
            info!("QUIC agent connection lost: {reason}");
            crate::hub::heartbeat::evict_agent(
                &hub_watcher,
                &agent_id2,
                &expected,
                "quic_connection_closed",
            )
            .await;
            hub_watcher
                .route_leases
                .write()
                .await
                .retain(|_, (lease_circuit, _, _)| *lease_circuit != circuit_cleanup);
        });
    }

    // Transport-stats sampler (twin of the egress-side sampler in core
    // tunnel/quic.rs): the CC forensics anchor for the 2026-09-16 quic
    // egress-stall case file — cumulative counters, diff adjacent samples.
    {
        let conn_stats = conn.clone();
        hub.tasks.spawn(async move {
            let mut tick = tokio::time::interval(Duration::from_secs(10));
            tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
            loop {
                tokio::select! {
                    _ = conn_stats.closed() => break,
                    _ = tick.tick() => {}
                }
                let p = &conn_stats.stats().path;
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

    // Traffic stream loop
    loop {
        let (tx, rx) = match conn.accept_bi().await {
            Ok(pair) => pair,
            Err(_) => break,
        };
        let hub_stream = hub.clone();
        let source_agent = agent_id.clone();
        let source_state = state_arc.clone();
        hub.tasks.spawn(async move {
            if let Err(e) = handle_quic_stream(hub_stream, source_agent, source_state, tx, rx).await
            {
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
            .map_err(|e| InterflowError::connection("control stream read failed").with_source(e))?
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
    hub: &HubState,
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
    // The intended semantic id rides the Hello payload (the header
    // circuit field is the zero marker on Hello).
    let Ok((hello_caps, agent_id)) =
        interflow_core::tunnel::quic::decode_hello_payload(&hello.payload)
    else {
        warn!("QUIC Hello payload malformed ({peer})");
        return None;
    };

    // Authentication: the QUIC handshake's client certificate. Identity =
    // (tenant from the chain's anchoring root, agent from the leaf CN); the
    // Hello's semantic identity must equal the CN. The tenant is derived against
    // the shared TLS plane (hot-reloadable generation).
    let agent_datagram_cap = quinn_caps_enabled(hub).await
        && (hello_caps & interflow_core::tunnel::quic::CAP_DATAGRAM != 0);
    let identity: Option<crate::hub::state::PeerIdentity> = 'auth: {
        let plane = hub
            .tls_plane
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone();
        let chain = conn
            .peer_identity()
            .and_then(|id| id.downcast::<Vec<CertificateDer<'static>>>().ok())
            .map(|boxed| *boxed);
        let Some(chain) = chain else {
            warn!("QUIC registration rejected: no client certificate ({peer})");
            metrics::counter!("interflow_hub_auth_failures", "reason" => "quic_no_cert")
                .increment(1);
            send_error_and_close(conn, "client certificate required").await;
            break 'auth None;
        };
        let Some(tenant) = plane.verifier.derive(&chain) else {
            warn!("QUIC registration rejected: chain claimed by no tenant ({peer})");
            metrics::counter!("interflow_hub_auth_failures", "reason" => "tenant_unclaimed")
                .increment(1);
            send_error_and_close(conn, "tenant unclaimed").await;
            break 'auth None;
        };
        let cn = interflow_core::tls::extract_cn_from_chain(&chain);
        let Some(cn) = cn.filter(|cn| cn == &agent_id) else {
            warn!("QUIC registration rejected: mTLS CN does not match Hello identity ({peer})");
            metrics::counter!("interflow_hub_auth_failures", "reason" => "quic_mtls_cn")
                .increment(1);
            send_error_and_close(conn, "cn mismatch").await;
            break 'auth None;
        };
        let _ = cn;
        break 'auth Some(crate::hub::state::PeerIdentity {
            tenant: tenant.tenant,
            agent: agent_id.clone(),
            trusted_gateway: tenant.trusted_gateway,
        });
    };
    let identity = identity?;
    let agent_key = identity.qualified();
    let circuit = CircuitToken::random().ok()?;
    hub.route_leases
        .write()
        .await
        .retain(|_, (_, source, _)| source != &agent_key);

    // Register (reuses registration semantics: replace in place + sweep
    // orphan streams + absolute-value gauge). The registry key is
    // tenant-qualified — same-tenant reconnect preemption works, cross-tenant
    // same-name ids never collide.
    let state_arc = {
        let mut agents = hub.agents.write().await;
        if let Some(existing) = agents.get(&agent_key) {
            // QUIC registration overwrites an h2 session (same preemption
            // semantics, mirrored)
            existing
                .write()
                .await
                .install_channels(circuit, Some(quic_conn.clone()));
            existing.clone()
        } else {
            let arc = Arc::new(RwLock::new(AgentSession::new(
                circuit,
                Some(quic_conn.clone()),
            )));
            agents.insert(agent_key.clone(), arc.clone());
            arc
        }
    };
    hub.route_leases
        .write()
        .await
        .retain(|_, (_, source, _)| source != &agent_key);
    metrics::gauge!("interflow_hub_agents_registered").set(crate::hub::state::count_as_f64(
        hub.agents.read().await.len(),
    ));
    quic_conn
        .datagram_cap
        .store(agent_datagram_cap, std::sync::atomic::Ordering::Relaxed);
    metrics::counter!("interflow_quic_agents_registered").increment(1);

    crate::hub::service::HubService::sweep_agent_streams(
        &hub.agents,
        &hub.active_streams,
        &hub.stream_counts,
        &agent_key,
    )
    .await;

    // HelloAck payload: the binary capability declaration (caps word +
    // registration — the same fields the h2 register response body carries
    // as JSON; heartbeat cadence for the agent-side stall derivation). QUIC
    // Pongs ride the control stream, so there is nothing transport-specific
    // to declare.
    let hub_caps = if quinn_caps_enabled(hub).await {
        interflow_core::tunnel::quic::CAP_DATAGRAM
    } else {
        0
    };
    let capability = {
        let cfg = hub.config.read().await;
        RegisterResponse {
            circuit_token: circuit,
            heartbeat: cfg
                .heartbeat
                .enabled
                .then_some(HeartbeatAd::from(&cfg.heartbeat)),
        }
    };
    let payload = capability.encode_wire(hub_caps);
    let mut ack = BytesMut::with_capacity(wire::FRAME_HEADER_LEN + payload.len());
    wire::encode_frame(
        FrameType::HelloAck,
        FLAG_HUB_ORIGIN,
        StreamId::ZERO,
        CircuitToken::ZERO,
        &payload,
        &mut ack,
    );
    {
        let mut control = quic_conn.control.lock().await;
        if control.write_all(&ack).await.is_err() {
            warn!("QUIC HelloAck send failed");
            return None;
        }
    }

    // Heartbeat (control-stream Ping + last_pong death decision; reuses the
    // heartbeat configuration and the eviction primitive)
    spawn_quic_heartbeat(
        std::sync::Arc::new(hub.clone()),
        agent_key.clone(),
        state_arc.clone(),
        quic_conn.clone(),
    );

    // Control stream read loop (Pong → last_pong)
    let state_for_pong = state_arc.clone();
    let pong_tasks = hub.tasks.clone();
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

    hub.audit.record(
        AuditKind::AgentRegistered {
            circuit: circuit.to_hex(),
        },
        Some(circuit.to_hex()),
        Some(peer.to_string()),
    );
    info!("QUIC agent registered: circuit={circuit} ({peer})");
    Some((agent_key, state_arc))
}

/// Authentication failure: best-effort send of an Error frame
/// (`[code u16][text]`), then close the connection.
async fn send_error_and_close(conn: &quinn::Connection, msg: &str) {
    let Ok((mut tx, rx)) = conn.open_bi().await else {
        conn.close(0_u32.into(), b"auth failed");
        return;
    };
    let mut payload = BytesMut::with_capacity(2 + msg.len());
    payload.put_u16(interflow_contract::error_code::REGISTER_REJECTED);
    payload.put_slice(msg.as_bytes());
    let mut buf = BytesMut::with_capacity(wire::FRAME_HEADER_LEN + payload.len());
    wire::encode_frame(
        FrameType::Error,
        FLAG_HUB_ORIGIN,
        StreamId::ZERO,
        CircuitToken::ZERO,
        &payload,
        &mut buf,
    );
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
    hub: std::sync::Arc<HubState>,
    agent_id: String,
    state: Arc<RwLock<AgentSession>>,
    conn: Arc<QuicAgentConn>,
) {
    let tasks = hub.tasks.clone();
    tasks.spawn(async move {
        let agent_state = state;
        let death_watch = conn.conn.closed();
        tokio::pin!(death_watch);
        loop {
            // One cadence snapshot per tick, shared with the h2 loop (see
            // `heartbeat::cadence_snapshot`).
            let cadence = {
                let cfg = hub.config.read().await;
                crate::hub::heartbeat::cadence_snapshot(&cfg)
            };
            let Some(cadence) = cadence else {
                // Polling interval while heartbeats are disabled (waiting
                // for a hot reload); exit immediately when the connection
                // dies (releases the Connection reference promptly —
                // otherwise the quinn driver and the UDP socket have to wait
                // for the next polling cycle)
                tokio::select! {
                    () = tokio::time::sleep(
                        interflow_core::config::params::liveness::HEARTBEAT_DISABLED_POLL,
                    ) => continue,
                    _ = &mut death_watch => return,
                }
            };
            tokio::select! {
                () = tokio::time::sleep(crate::hub::heartbeat::tick_sleep(Some(cadence))) => {}
                _ = &mut death_watch => return,
            }

            let ping_source = agent_state.read().await.circuit;
            let mut ping = BytesMut::with_capacity(wire::FRAME_HEADER_LEN);
            wire::encode_frame(
                FrameType::Ping,
                FLAG_HUB_ORIGIN,
                StreamId::ZERO,
                CircuitToken::ZERO,
                b"",
                &mut ping,
            );
            {
                let mut control = conn.control.lock().await;
                if control.write_all(&ping).await.is_err() {
                    // Connection is gone; the disconnect watcher handles
                    // eviction
                    return;
                }
            }

            // The eviction dead line — the shared derivation with the h2
            // heartbeat loop.
            let deadline = cadence.dead_line();
            let dead = {
                let st = agent_state.read().await;
                crate::hub::heartbeat::pong_expired(&st, &cadence)
            };
            if dead {
                warn!("QUIC agent circuit={ping_source} heartbeat lost (>{deadline:?}), evicting");
                crate::hub::heartbeat::evict_agent(
                    &hub,
                    &agent_id,
                    &agent_state,
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
    stream_id: StreamId,
    close_reason: CloseReason,
    datagram_conn: Option<quinn::Connection>,
) {
    while let Some(df) = rx.recv().await {
        let circuit = match df.origin {
            FrameOrigin::Agent(c) => c,
            FrameOrigin::Response | FrameOrigin::Hub => CircuitToken::ZERO,
        };
        let mut buf = BytesMut::with_capacity(wire::FRAME_HEADER_LEN + df.data.len());
        if wire::encode_frame(
            df.stream_type,
            df.flags,
            df.stream_id,
            circuit,
            &df.data,
            &mut buf,
        )
        .is_none()
        {
            error!("QUIC relay frame encode failed: stream_id={}", df.stream_id);
            break;
        }
        // DATAGRAM fast path: eligibility (UDP stream + peer capability) was
        // decided by the caller and is folded into `datagram_conn` — small
        // Data frames go unreliable/unordered with no HOL blocking on loss;
        // on send failure fall back to stream carriage.
        if let Some(conn) = &datagram_conn
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
    // first Close triggers cleanup); the hub-origin rationale lives on
    // [`write_close_frame`].
    write_close_frame(tx, stream_id, close_reason).await;
}

/// Opens a relay stream to a quic target agent and writes the Open frame;
/// starts the writer task and the target-side read pump.
///
/// Returns the dispatch channel (`TunnelData` is encoded and written to the
/// stream). The target-side read pump feeds return-path frames back to the
/// source via [`deliver_dataframe`] (a quic source goes via the Relay plane,
/// h2 via poll).
pub(crate) async fn open_relay_stream(
    hub: &HubState,
    target_conn: &QuicAgentConn,
    stream_id: StreamId,
    source_circuit: CircuitToken,
    target_circuit: CircuitToken,
    proto: StreamProto,
    e2e: bool,
) -> Option<mpsc::Sender<TunnelData>> {
    let (tx, rx) = mpsc::channel::<TunnelData>(RELAY_CHANNEL_CAP);
    let (mut send, recv) = target_conn.conn.open_bi().await.ok()?;
    let target_datagram = target_conn
        .datagram_cap
        .load(std::sync::atomic::Ordering::Relaxed);
    let udp = matches!(proto, StreamProto::Udp);

    // The requester's circuit rides the header field, the payload is
    // empty (the former payload hex + `"hub"` source are gone). The e2e
    // declaration rides the flags so the target knows the stream wants the
    // inner TLS layer.
    let mut open = BytesMut::with_capacity(wire::FRAME_HEADER_LEN);
    wire::encode_frame(
        FrameType::Open,
        proto.as_flag() | (u8::from(e2e) * FLAG_E2E),
        stream_id,
        source_circuit,
        b"",
        &mut open,
    )?;
    if send.write_all(&open).await.is_err() {
        return None;
    }

    // egress-side OpenAck: target capability + UDP stream (equally
    // applicable to an h2 source — the fast path concerns only the
    // hub↔target hop)
    if target_datagram && udp {
        let mut ack = BytesMut::with_capacity(wire::FRAME_HEADER_LEN);
        wire::encode_frame(
            FrameType::OpenAck,
            FLAG_HUB_ORIGIN,
            stream_id,
            CircuitToken::ZERO,
            b"",
            &mut ack,
        );
        if send.write_all(&ack).await.is_err() {
            return None;
        }
    }

    tokio::spawn(relay_stream_writer(
        send,
        rx,
        stream_id,
        CloseReason::CloseFrame,
        // DATAGRAM eligibility folded in: UDP stream + peer capability.
        (target_datagram && udp).then(|| target_conn.conn.clone()),
    ));

    // Target-side read pump (return direction; the Open frame was written
    // directly by this function, no residue)
    tokio::spawn(relay_reader(
        std::sync::Arc::new(hub.clone()),
        recv,
        BytesMut::new(),
        stream_id,
        target_circuit,
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
async fn datagram_relay_loop(
    hub: std::sync::Arc<HubState>,
    conn: quinn::Connection,
    agent_id: String,
) {
    let timeout_secs = hub
        .limits
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
        // source)? Anti-forgery: it must match one of the stream's ends
        // (raw 16-byte circuit compare).
        let (recipient, sink, origin, flags) = {
            let streams = hub.active_streams.read().await;
            let Some(st) = streams.get(&frame.stream_id) else {
                metrics::counter!("interflow_quic_datagram_dropped").increment(1);
                continue;
            };
            if frame.circuit == st.source_circuit {
                (
                    st.target_agent.clone(),
                    st.target.relay_sender().cloned(),
                    FrameOrigin::Agent(frame.circuit),
                    0u8,
                )
            } else if frame.circuit == st.target_circuit {
                (
                    st.source_agent.clone(),
                    st.source.relay_sender().cloned(),
                    FrameOrigin::Response,
                    FLAG_RESPONSE,
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
            origin,
            stream_type: FrameType::Data,
            flags,
            data: frame.payload,
        };
        let stream_id = df.stream_id;
        if deliver_dataframe(&hub.agents, sink.as_ref(), &recipient, df, timeout_secs)
            .await
            .is_err()
        {
            // Dispatch failure reclaims the stream (same discipline as the
            // stream path). Direction semantics: the sender is the target
            // (response-direction data) → notify the source end with
            // response FIFO semantics; otherwise request direction →
            // guaranteed delivery via the control channel.
            let sender_is_target = {
                let streams = hub.active_streams.read().await;
                streams
                    .get(&stream_id)
                    .is_some_and(|st| st.target_agent == agent_id)
            };
            teardown_stream(&hub, stream_id, sender_is_target, CloseReason::CloseFrame).await;
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
    hub: &HubState,
    stream_id: StreamId,
    response_dir: bool,
    reason: CloseReason,
) {
    let removed = {
        let mut streams = hub.active_streams.write().await;
        streams.remove(&stream_id)
    };
    if let Some(stream) = removed {
        metrics::gauge!("interflow_hub_streams_active").decrement(1.0);
        {
            // The count lock is confined to an independent scope: never
            // hold a std Mutex guard across an await
            let mut map = hub
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
                    &hub.agents,
                    &peer,
                    stream_id,
                    reason,
                )
                .await;
            } else {
                let _ = crate::hub::control::deliver_close_via_control(
                    &hub.agents,
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
    hub: std::sync::Arc<HubState>,
    source_agent: String,
    source_state: Arc<RwLock<AgentSession>>,
    mut tx: quinn::SendStream,
    rx: quinn::RecvStream,
) -> Result<()> {
    let hub = hub.clone();
    let mut rx = rx;
    let mut buf = BytesMut::with_capacity(512);

    let Some(opened) = read_first_frame(&mut rx, &mut buf).await? else {
        return Ok(()); // EOF before Open: drop silently
    };
    if matches!(opened.frame_type, FrameType::RouteRequest) {
        // The requester is identified by the connection (the RouteRequest
        // carries the correlation id + zero circuit; the codec enforces it).
        let circuit = source_state.read().await.circuit;
        let invalid = || InterflowError::protocol("invalid QUIC route request payload");
        if opened.payload.len() < 2 {
            return Err(invalid());
        }
        let name_len = u16::from_be_bytes([opened.payload[0], opened.payload[1]]) as usize;
        if opened.payload.len() != 2 + name_len {
            return Err(invalid());
        }
        let Ok(target) = std::str::from_utf8(&opened.payload[2..]).map(str::to_owned) else {
            return Err(invalid());
        };
        // RouteAck payload: `[granted u8][route token 16 B]` (zero token =
        // denied).
        let mut payload = BytesMut::with_capacity(1 + 16);
        match crate::hub::routing::issue_route(&hub, &source_agent, circuit, &target).await {
            Ok(route) => {
                payload.put_u8(1);
                payload.put_slice(&route.to_bytes());
            }
            Err(reason) => {
                warn!("QUIC route lease denied: reason={reason}");
                payload.put_u8(0);
                payload.put_slice(&[0u8; 16]);
            }
        }
        let mut out = BytesMut::with_capacity(wire::FRAME_HEADER_LEN + payload.len());
        wire::encode_frame(
            FrameType::RouteAck,
            FLAG_HUB_ORIGIN,
            opened.stream_id,
            CircuitToken::ZERO,
            &payload,
            &mut out,
        );
        tx.write_all(&out).await.map_err(|e| {
            InterflowError::connection("QUIC route ack write failed".to_string()).with_source(e)
        })?;
        let _ = tx.finish();
        return Ok(());
    }
    if !matches!(opened.frame_type, FrameType::Open) {
        return Err(InterflowError::protocol(
            "QUIC stream first frame must be Open".to_string(),
        ));
    }
    // Anti-forgery: the frame's circuit must equal this QUIC connection's
    // registration circuit (raw compare).
    let source_circuit = source_state.read().await.circuit;
    if opened.circuit != source_circuit {
        warn!("QUIC forgery check: stream source circuit mismatch");
        return Ok(());
    }

    let stream_id = opened.stream_id;
    let route = (opened.payload.len() == 16)
        .then(|| RouteToken::from_bytes(opened.payload[..16].try_into().expect("16B")))
        .filter(|t| !t.is_zero());
    let Some(route) = route else {
        write_close_frame(tx, stream_id, CloseReason::NoTarget).await;
        return Ok(());
    };
    let target_agent = {
        let session = source_state.read().await;
        if session.circuit != source_circuit {
            return Ok(());
        }
        drop(session);
        hub.route_leases
            .read()
            .await
            .get(&route)
            .filter(|(_, source, _)| source == &source_agent)
            .map(|(_, _, target)| target.clone())
            .unwrap_or_default()
    };
    if target_agent.is_empty() {
        write_close_frame(tx, stream_id, CloseReason::NoTarget).await;
        return Ok(());
    }
    let proto = StreamProto::from_frame_flags(opened.flags);
    let e2e = opened.flags & interflow_core::protocol::FLAG_E2E != 0;

    // Shared stream-admission gate (tenant policy + stream caps): a bare
    // target resolves into the source's own tenant, a `tenant/agent` form is
    // cross-tenant and needs gateway status or an explicit ACL exception.
    // The QUIC plane reports no peer address to audit — explicit `None`.
    match crate::hub::routing::admit_stream(
        &hub,
        stream_id,
        &source_circuit,
        &source_agent,
        &target_agent,
        None,
    )
    .await
    {
        crate::hub::routing::StreamAdmission::Admitted => {}
        verdict => {
            debug!("stream admission denied (QUIC): stream_id={stream_id}, verdict={verdict:?}");
            let reason = match verdict {
                crate::hub::routing::StreamAdmission::TenantDenied => CloseReason::SecurityDenied,
                crate::hub::routing::StreamAdmission::GlobalStreamLimit
                | crate::hub::routing::StreamAdmission::PerAgentStreamLimit => {
                    CloseReason::LocalLimit
                }
                crate::hub::routing::StreamAdmission::Admitted => unreachable!(),
            };
            write_close_frame(tx, stream_id, reason).await;
            return Ok(());
        }
    }

    // Target resolution: quic → relay stream; h2 → Open notification via
    // poll; nonexistent → roll back
    let target_state = {
        let agents = hub.agents.read().await;
        agents.get(&target_agent).cloned()
    };
    let Some(target_state) = target_state else {
        crate::hub::state::release_stream_slot(&hub.stream_counts, &source_agent);
        write_close_frame(tx, stream_id, CloseReason::NoTarget).await;
        return Ok(());
    };

    let (target_sink, target_circuit) = {
        let st = target_state.read().await;
        let target_circuit = st.circuit;
        if let Some(qc) = st.quic.clone() {
            drop(st);
            (
                open_relay_stream(
                    &hub,
                    &qc,
                    stream_id,
                    source_circuit,
                    target_circuit,
                    proto,
                    e2e,
                )
                .await,
                target_circuit,
            )
        } else {
            // h2 target: Open notification goes via the poll channel
            // requester circuit in the header, empty payload)
            let open_df = TunnelData {
                stream_id,
                origin: FrameOrigin::Agent(source_circuit),
                stream_type: FrameType::Open,
                flags: proto.as_flag() | (u8::from(e2e) * FLAG_E2E),
                data: Bytes::new(),
            };
            match deliver_dataframe(&hub.agents, None, &target_agent, open_df, 1).await {
                Ok(()) => (None, target_circuit), // goes via lookup_tx / poll
                Err(e) => {
                    warn!("QUIC Open notification failed: {e:?}");
                    crate::hub::state::release_stream_slot(&hub.stream_counts, &source_agent);
                    write_close_frame(tx, stream_id, CloseReason::NoTarget).await;
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
    let source_datagram_cap = quinn_caps_enabled(&hub).await;
    let datagram_ok = matches!(proto, StreamProto::Udp) && target_datagram_cap;

    // Source writer task (return-path frames → this stream of the source
    // agent); the ingress-side connection enables the writer fast path
    let (source_tx, source_rx) = mpsc::channel::<TunnelData>(RELAY_CHANNEL_CAP);
    tokio::spawn(relay_stream_writer(
        tx,
        source_rx,
        stream_id,
        CloseReason::CloseFrame,
        if datagram_ok && source_datagram_cap {
            conn_for_datagram(&hub, &source_agent).await
        } else {
            None
        },
    ));
    let source_face = StreamFace::Relay(source_tx);

    // Insert the ActiveStream
    {
        let mut streams = hub.active_streams.write().await;
        streams.insert(
            stream_id,
            crate::hub::ActiveStream {
                source_agent: source_agent.clone(),
                target_agent: target_agent.clone(),
                source_circuit,
                target_circuit,
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
            stream_id,
            origin: FrameOrigin::Hub,
            stream_type: FrameType::OpenAck,
            flags: FLAG_HUB_ORIGIN,
            data: Bytes::new(),
        };
        let sink = {
            let streams = hub.active_streams.read().await;
            streams
                .get(&stream_id)
                .and_then(|st| st.source.relay_sender().cloned())
        };
        if let Some(sink) = sink {
            let _ = sink.send(ack).await;
        }
    }
    metrics::gauge!("interflow_hub_streams_active").increment(1.0);
    metrics::counter!("interflow_hub_streams_total", "direction" => "request").increment(1);
    hub.audit.record(
        AuditKind::StreamOpened {
            stream_id: stream_id.to_string(),
            source_circuit: source_circuit.to_hex(),
            route: route.to_hex(),
        },
        Some(source_circuit.to_hex()),
        None,
    );

    // Source read pump (request direction; buf carries residual bytes that
    // arrived after the Open frame in the same packet)
    tracing::debug!(
        "handle_quic_stream: entering relay_reader stream={stream_id} leftover={}",
        buf.len()
    );
    relay_reader(hub, rx, buf, stream_id, source_circuit, false).await;
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
    hub: std::sync::Arc<HubState>,
    mut rx: quinn::RecvStream,
    initial_buf: BytesMut,
    stream_id: StreamId,
    circuit: CircuitToken,
    response_dir: bool,
) {
    let mut buf = initial_buf;
    let mut chunk = vec![0u8; READ_CHUNK];

    // Drain the initial residue first (this may directly terminate the
    // stream, e.g. if the residue already contains a Close)
    if process_frames(&hub, &mut buf, stream_id, circuit, response_dir).await {
        return;
    }

    loop {
        let n = match rx.read(&mut chunk).await {
            Ok(Some(n)) => n,
            Ok(None) | Err(_) => break,
        };
        buf.extend_from_slice(&chunk[..n]);
        if process_frames(&hub, &mut buf, stream_id, circuit, response_dir).await {
            return;
        }
    }
    // EOF: peer half-closed (Close already handled or an abnormal stream
    // cut) — close out as a close (termination contract: the poll-plane peer
    // is notified by teardown_stream, with direction following this read
    // pump's directional semantics)
    teardown_stream(&hub, stream_id, response_dir, CloseReason::CloseFrame).await;
}

/// Decodes and dispatches all complete frames in `buf`; returns true when
/// this stream has terminated (Close received / dispatch failure triggered
/// teardown).
async fn process_frames(
    hub: &HubState,
    buf: &mut BytesMut,
    stream_id: StreamId,
    circuit: CircuitToken,
    response_dir: bool,
) -> bool {
    let timeout_secs = hub
        .limits
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
            let streams = hub.active_streams.read().await;
            streams.get(&stream_id).map(|s| {
                if response_dir {
                    (s.source_agent.clone(), s.source.relay_sender().cloned())
                } else {
                    (s.target_agent.clone(), s.target.relay_sender().cloned())
                }
            })
        };
        let Some((recipient, sink)) = route else {
            debug!("QUIC relay frame has no route: stream_id={stream_id}, dropping");
            continue;
        };

        if matches!(frame.frame_type, FrameType::Close) {
            if frame.circuit != circuit {
                warn!("QUIC relay Close circuit mismatch: stream_id={stream_id}");
                continue;
            }
            // Termination: the poll peer's `_close_` notification is
            // guaranteed delivery by teardown_stream per directional
            // semantics (the old path silently lost it when the data
            // channel was full, leaving the peer's fd lingering for the
            // whole session); the quic peer is informed by the entry drop
            // triggering the writer task to write the outstanding Close +
            // FIN. The Close payload carries the egress close reason code
            // and is forwarded to the poll peer.
            let reason = CloseReason::from_payload(&frame.payload);
            teardown_stream(hub, stream_id, response_dir, reason).await;
            return true;
        }
        if frame.circuit != circuit {
            warn!("QUIC relay frame circuit mismatch: stream_id={stream_id}");
            continue;
        }

        let df = TunnelData {
            stream_id,
            origin: if response_dir {
                FrameOrigin::Response
            } else {
                FrameOrigin::Agent(circuit)
            },
            stream_type: frame.frame_type,
            flags: if response_dir { FLAG_RESPONSE } else { 0 },
            data: frame.payload,
        };
        if recipient.is_empty() {
            continue;
        }
        if let Err(e) =
            deliver_dataframe(&hub.agents, sink.as_ref(), &recipient, df, timeout_secs).await
        {
            warn!("QUIC relay dispatch failed: stream_id={stream_id}: {e:?}");
            // Termination contract: poll-plane peer notification (direction
            // follows this read pump's semantics: the peer of a
            // response_dir pump is the source agent, using response-FIFO
            // priority; the peer of a request-direction pump is the target
            // agent, with guaranteed delivery via the control channel)
            teardown_stream(hub, stream_id, response_dir, CloseReason::CloseFrame).await;
            return true;
        }
        metrics::counter!("interflow_hub_frames_rx", "type" => "data").increment(1);
    }
    false
}

/// Writes a hub-origin Close frame to a quinn SendStream and FINs it
/// (rollback path notifying the source side; synchronous failure paths such
/// as target missing / ACL denial / limit denial). The flags make the
/// origin unmistakable — the former `_close_` sentinel's "must not look like an
/// agent frame" rationale is now enforced by the codec contract itself.
async fn write_close_frame(mut tx: quinn::SendStream, stream_id: StreamId, reason: CloseReason) {
    let mut buf = BytesMut::with_capacity(wire::FRAME_HEADER_LEN + 1);
    if wire::encode_frame(
        FrameType::Close,
        FLAG_HUB_ORIGIN,
        stream_id,
        CircuitToken::ZERO,
        &[reason.as_code()],
        &mut buf,
    )
    .is_some()
    {
        let _ = tx.write_all(&buf).await;
    }
    let _ = tx.finish();
}
