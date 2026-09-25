//! Accept loop: PROXY negotiation → mTLS handshake → tenant identity
//! derivation → dispatch to hyper HTTP/2 services.
//!
//! Per-connection pipeline (RFC (internal design notes) §5):
//! 1. PROXY protocol v2 negotiation under the fail-closed trust matrix —
//!    the effective client IP restored here keys rate limiting, connection
//!    caps and audit (never identity or ACL decisions)
//! 2. per-IP rate limit + connection-cap check on the effective IP
//! 3. mTLS handshake (client certificates required — the acceptor is built
//!    from the merged tenant roots)
//! 4. tenant derivation: which tenant's root anchors the presented chain
//!    (post-handshake re-verification per tenant), agent id from the leaf CN
//! 5. hyper h2 service; every request then binds to the derived
//!    [`PeerIdentity`]

use crate::hub::service::HubService;
use crate::hub::state::{HubState, PeerIdentity};
use hyper::server::conn::http2;
use hyper_util::rt::{TokioExecutor, TokioIo, TokioTimer};
use interflow_core::error::Result;
use interflow_core::security::AuditKind;
use interflow_core::security::proxy_protocol::{
    PrefixedStream, ProxyError, ProxyOutcome, ProxyProtocolPolicy,
};
use interflow_core::tls::{extract_cn_from_chain, extract_leaf_validity_from_chain};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::net::TcpStream;
use tokio::sync::RwLock;
use tokio_util::sync::CancellationToken;
use tracing::{debug, error, info, warn};

/// PROXY-preamble read budget: the same slow-loris discipline as the edge's
/// host-peek phase.
const PROXY_BUDGET: Duration = Duration::from_secs(10);

/// Handles a new TCP connection: PROXY negotiation → resource gating on the
/// effective IP → mTLS handshake → tenant identity derivation → h2 service.
///
/// The mTLS-derived identity (tenant from the chain's anchoring root, agent
/// from the leaf CN) is preset as `connection_identity`; the later
/// `x-agent-id` in `/register` must equal the CN, otherwise the existing
/// `Identity mismatch` path rejects it. A chain no tenant claims (only
/// reachable in a hot-reload window) is rejected fail-closed.
pub(crate) async fn handle_connection(
    state: std::sync::Arc<HubState>,
    stream: TcpStream,
    addr: SocketAddr,
) -> Result<()> {
    // 1. PROXY protocol negotiation (budgeted).
    let policy = {
        let cfg = state.config.read().await;
        Arc::new(ProxyProtocolPolicy::from_config(
            &cfg.server.proxy_protocol,
        )?)
    };
    let mut raw = stream;
    let (effective_ip, replay) =
        match tokio::time::timeout(PROXY_BUDGET, policy.read(&mut raw, addr.ip())).await {
            Ok(Ok(ProxyOutcome::Proxied { effective })) => (effective, Vec::new()),
            Ok(Ok(ProxyOutcome::Direct { read_back })) => (addr.ip(), read_back),
            Ok(Err(e)) => {
                metrics::counter!("interflow_hub_proxy_protocol_rejected").increment(1);
                let reason = match &e {
                    ProxyError::UntrustedSignature => "untrusted_proxy_signature",
                    ProxyError::RequiredMissing => "proxy_header_required",
                    ProxyError::Malformed(_) => "malformed_proxy_header",
                    ProxyError::Io(_) => "proxy_read_error",
                };
                warn!("PROXY protocol negotiation rejected ({reason}): peer={addr}");
                state.audit.record(
                    AuditKind::StreamDenied {
                        stream_id: String::new(),
                        source_circuit: String::new(),
                        source_ip: None,
                        reason: reason.to_string(),
                    },
                    None,
                    Some(addr.to_string()),
                );
                return Ok(());
            }
            Err(_) => {
                metrics::counter!("interflow_hub_proxy_protocol_timeout").increment(1);
                debug!("PROXY preamble read timed out (peer={addr})");
                return Ok(());
            }
        };

    // 2. Resource gating on the effective IP (per-IP new-conn rate +
    // concurrency caps; behind nginx these key on the real client, not 127.0.0.1).
    if let Some(limiter) = &state.rate_limiter
        && !limiter.check(effective_ip)
    {
        metrics::counter!("interflow_hub_conn_rate_limited").increment(1);
        state.audit.record(
            AuditKind::StreamDenied {
                stream_id: String::new(),
                source_circuit: String::new(),
                source_ip: None,
                reason: "rate_limited".into(),
            },
            None,
            Some(addr.to_string()),
        );
        debug!("connection denied (rate limited): effective={effective_ip} peer={addr}");
        return Ok(());
    }
    let Some(guard) = state.conn_tracker.try_acquire(effective_ip) else {
        metrics::counter!("interflow_hub_conn_rejected").increment(1);
        state.audit.record(
            AuditKind::ConnLimitExceeded {
                peer_ip: effective_ip.to_string(),
                scope: "conn_limit".into(),
            },
            None,
            Some(addr.to_string()),
        );
        debug!("connection denied (connection limit): effective={effective_ip} peer={addr}");
        return Ok(());
    };

    // 3. mTLS handshake via the plane snapshot (acceptor + verifier from the
    // same configuration generation).
    let plane = state
        .tls_plane
        .read()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .clone();
    let stream = PrefixedStream::new(raw, replay);
    let tls_stream = match plane.acceptor.accept(stream).await {
        Ok(s) => s,
        Err(e) => {
            warn!("TLS handshake failed (peer={addr}): {e}");
            metrics::counter!("interflow_hub_tls_handshake_failures").increment(1);
            return Ok(());
        }
    };

    serve_established(state, tls_stream, addr, effective_ip).await?;
    drop(guard);
    Ok(())
}

/// Steps 4-5 of the accept pipeline on a connection whose mTLS handshake
/// already completed: tenant identity derivation, then the h2 service.
///
/// Shared by the TCP accept loop (which owns PROXY negotiation, gating and
/// the handshake) and dispatched connections whose handshake a fronting
/// listener completed with this plane's configuration — same identity and
/// admission semantics either way.
pub(crate) async fn serve_established<S>(
    state: std::sync::Arc<HubState>,
    tls_stream: tokio_rustls::server::TlsStream<S>,
    addr: SocketAddr,
    effective_ip: std::net::IpAddr,
) -> Result<()>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
{
    let _ = &state;
    // 4. Tenant identity derivation: which tenant's root anchors the chain.
    let connection_identity: Arc<RwLock<Option<PeerIdentity>>> = Arc::new(RwLock::new(None));
    let connection_circuit: Arc<RwLock<Option<interflow_core::protocol::CircuitToken>>> =
        Arc::new(RwLock::new(None));
    {
        let (_, server_conn) = tls_stream.get_ref();
        let Some(certs) = server_conn.peer_certificates() else {
            // The acceptor requires client certs; reaching here means the
            // acceptor was misassembled — fail closed.
            error!("no client certificate presented despite mTLS acceptor (peer={addr})");
            metrics::counter!("interflow_hub_auth_failures", "reason" => "no_client_cert")
                .increment(1);
            return Ok(());
        };
        // Per-connection plane snapshot (same generation discipline as the
        // accept loop; dispatched connections read the live plane too).
        let verifier = state
            .tls_plane
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone();
        let derived = verifier.verifier.derive(certs);
        let Some(tenant_ident) = derived else {
            warn!(
                "client chain claimed by no tenant (hot-reload window?) — rejecting (peer={addr})"
            );
            metrics::counter!("interflow_hub_auth_failures", "reason" => "tenant_unclaimed")
                .increment(1);
            state.audit.record(
                AuditKind::AgentRegisterDenied {
                    reason: "tenant_unclaimed".into(),
                },
                None,
                Some(addr.to_string()),
            );
            return Ok(());
        };
        if let Some(cn) = extract_cn_from_chain(certs) {
            debug!(
                "mTLS identity derived and bound to this connection (gateway={})",
                tenant_ident.trusted_gateway
            );
            *connection_identity.write().await = Some(PeerIdentity {
                tenant: tenant_ident.tenant,
                agent: cn,
                trusted_gateway: tenant_ident.trusted_gateway,
                leaf_validity_unix: extract_leaf_validity_from_chain(certs),
            });
        } else {
            warn!("client certificate carries no CN — rejecting (peer={addr})");
            metrics::counter!("interflow_hub_auth_failures", "reason" => "cert_no_cn").increment(1);
            return Ok(());
        }
    }

    // Per-connection snapshot of the transport tuning (hot-reload friendly:
    // a SIGHUP applies to connections accepted afterwards).
    let h2_transport = state.config.read().await.transport.h2.clone();
    let shutdown = state.shutdown.clone();
    let cleanup_state = state.clone();
    let cleanup_circuit = connection_circuit.clone();

    let conn = h2_builder(&h2_transport).serve_connection(
        TokioIo::new(tls_stream),
        HubService::new(state, effective_ip, connection_identity, connection_circuit),
    );
    serve_h2(conn, shutdown, addr, true).await;
    let finished_circuit = *cleanup_circuit.read().await;
    if let Some(circuit) = finished_circuit {
        cleanup_state
            .route_leases
            .write()
            .await
            .retain(|_, (lease_circuit, _, _)| *lease_circuit != circuit);
    }
    Ok(())
}

/// Common parameters for serving an h2 connection (shared by the TLS/plain
/// branches). The keepalive pair comes from `[transport.h2]` — the same
/// shape and defaults the agent side uses.
fn h2_builder(transport: &crate::config::H2TransportConfig) -> http2::Builder<TokioExecutor> {
    let mut builder = http2::Builder::new(TokioExecutor::new());
    builder
        .timer(TokioTimer::new())
        .keep_alive_interval(transport.keepalive_interval())
        .keep_alive_timeout(transport.keepalive_timeout())
        .initial_stream_window_size(
            interflow_core::config::params::transport::DEFAULT_H2_STREAM_WINDOW,
        )
        .initial_connection_window_size(
            interflow_core::config::params::transport::DEFAULT_H2_CONNECTION_WINDOW,
        );
    builder
}

/// Graceful close-out grace for a single connection after shutdown: the upper
/// bound for waiting on existing streams (e.g. an agent's long poll) to end
/// naturally after GOAWAY; on timeout the connection is dropped (TCP closed,
/// treated as a disconnect by the peer).
const CONN_SHUTDOWN_GRACE: Duration = Duration::from_secs(2);

/// Drives one served h2 connection; the shutdown signal triggers a graceful
/// GOAWAY close-out.
async fn serve_h2<I>(
    conn: http2::Connection<I, HubService, TokioExecutor>,
    shutdown: CancellationToken,
    addr: SocketAddr,
    tls: bool,
) where
    I: hyper::rt::Read + hyper::rt::Write + Unpin + Send + 'static,
{
    let label = if tls {
        "h2 connection ended"
    } else {
        "plain connection ended"
    };
    tokio::pin!(conn);
    tokio::select! {
        res = &mut conn => {
            if let Err(e) = res {
                error!("{label} (peer={addr}): {e}");
            }
        }
        () = shutdown.cancelled() => {
            debug!("Shutdown: GOAWAY (peer={addr})");
            conn.as_mut().graceful_shutdown();
            match tokio::time::timeout(CONN_SHUTDOWN_GRACE, conn.as_mut()).await {
                Ok(Ok(())) => {}
                Ok(Err(e)) => debug!("{label} (shutdown drain) (peer={addr}): {e}"),
                Err(_) => debug!("Shutdown grace exhausted, forcibly closing connection (peer={addr})"),
            }
        }
    }
    info!("{label} (peer={addr})");
}
