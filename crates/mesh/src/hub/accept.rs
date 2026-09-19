//! Accept loop: PROXY negotiation → mTLS handshake → tenant identity
//! derivation → dispatch to hyper HTTP/2 services.
//!
//! Per-connection pipeline (RFC docs/design/multi-tenant-mtls-only.md §5):
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
use crate::hub::state::{
    ActiveStream, PeerIdentity, SharedAgents, SharedHubConfig, SharedStreamCounts, SharedTlsPlane,
};
use hyper::server::conn::http2;
use hyper_util::rt::{TokioExecutor, TokioIo, TokioTimer};
use interflow_core::error::Result;
use interflow_core::security::proxy_protocol::{
    PrefixedStream, ProxyError, ProxyOutcome, ProxyProtocolPolicy,
};
use interflow_core::security::{AuditKind, AuditSink, AuthRateLimiter, ConnTracker};
use interflow_core::tls::extract_cn_from_chain;
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::net::TcpStream;
use tokio::sync::RwLock;
use tokio_util::sync::CancellationToken;
use tokio_util::task::TaskTracker;
use tracing::{debug, error, info, warn};

/// PROXY-preamble read budget: the same slow-loris discipline as the edge's
/// host-peek phase.
const PROXY_BUDGET: Duration = Duration::from_secs(10);

/// Shared state for a single inbound TCP connection.
///
/// Each `accept` assembles a fresh [`HubService`] from these fields; identity
/// binding is per-connection.
#[derive(Clone)]
pub(crate) struct AcceptContext {
    pub(crate) agents: SharedAgents,

    pub(crate) config: SharedHubConfig,
    pub(crate) active_streams: Arc<RwLock<HashMap<String, ActiveStream>>>,
    pub(crate) tls_plane: SharedTlsPlane,
    pub(crate) limits: crate::hub::state::HubLimits,
    pub(crate) rate_limiter: Option<Arc<AuthRateLimiter>>,
    pub(crate) stream_counts: SharedStreamCounts,
    pub(crate) audit: AuditSink,
    pub(crate) conn_tracker: Arc<ConnTracker>,
    /// Hub background task group: connection-level tasks are attached here so
    /// shutdown drain waits for all of them to close out.
    pub(crate) tasks: TaskTracker,
    /// Hub shutdown signal: once triggered, connections enter graceful
    /// GOAWAY close-out.
    pub(crate) shutdown: CancellationToken,
}

impl AcceptContext {
    /// Derives the core state for stream routing (shared by QUIC relay / h2 routing).
    pub(crate) fn core(&self) -> crate::hub::state::HubCore {
        crate::hub::state::HubCore {
            agents: self.agents.clone(),
            active_streams: self.active_streams.clone(),
            stream_counts: self.stream_counts.clone(),
            channel_send_timeout_secs: self.limits.channel_send_timeout_secs.clone(),
        }
    }

    /// Handles needed by the eviction primitive (same shape as `HubService::handles`).
    pub(crate) fn handles(&self) -> crate::hub::state::HubHandles {
        crate::hub::state::HubHandles {
            agents: self.agents.clone(),
            active_streams: self.active_streams.clone(),
            stream_counts: self.stream_counts.clone(),
            audit: self.audit.clone(),
            config: self.config.clone(),
            poll_grace_secs: self.limits.poll_grace_secs.clone(),
        }
    }
}

/// Handles a new TCP connection: PROXY negotiation → resource gating on the
/// effective IP → mTLS handshake → tenant identity derivation → h2 service.
///
/// The mTLS-derived identity (tenant from the chain's anchoring root, agent
/// from the leaf CN) is preset as `connection_identity`; the later
/// `x-agent-id` in `/register` must equal the CN, otherwise the existing
/// `Identity mismatch` path rejects it. A chain no tenant claims (only
/// reachable in a hot-reload window) is rejected fail-closed.
pub(crate) async fn handle_connection(
    ctx: AcceptContext,
    stream: TcpStream,
    addr: SocketAddr,
) -> Result<()> {
    // 1. PROXY protocol negotiation (budgeted).
    let policy = {
        let cfg = ctx.config.read().await;
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
                ctx.audit.record(
                    AuditKind::StreamDenied {
                        stream_id: String::new(),
                        source: addr.ip().to_string(),
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
    if let Some(limiter) = &ctx.rate_limiter
        && !limiter.check(effective_ip)
    {
        metrics::counter!("interflow_hub_conn_rate_limited").increment(1);
        ctx.audit.record(
            AuditKind::StreamDenied {
                stream_id: String::new(),
                source: effective_ip.to_string(),
                reason: "rate_limited".into(),
            },
            None,
            Some(addr.to_string()),
        );
        debug!("connection denied (rate limited): effective={effective_ip} peer={addr}");
        return Ok(());
    }
    let Some(guard) = ctx.conn_tracker.try_acquire(effective_ip) else {
        metrics::counter!("interflow_hub_conn_rejected").increment(1);
        ctx.audit.record(
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
    let plane = ctx
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

    // 4. Tenant identity derivation: which tenant's root anchors the chain.
    let connection_identity: Arc<RwLock<Option<PeerIdentity>>> = Arc::new(RwLock::new(None));
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
        let derived = plane.verifier.derive(certs);
        let Some(tenant_ident) = derived else {
            warn!(
                "client chain claimed by no tenant (hot-reload window?) — rejecting (peer={addr})"
            );
            metrics::counter!("interflow_hub_auth_failures", "reason" => "tenant_unclaimed")
                .increment(1);
            ctx.audit.record(
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
                "mTLS identity derived: tenant={} agent={cn} gateway={}",
                tenant_ident.tenant, tenant_ident.trusted_gateway
            );
            *connection_identity.write().await = Some(PeerIdentity {
                tenant: tenant_ident.tenant,
                agent: cn,
                trusted_gateway: tenant_ident.trusted_gateway,
            });
        } else {
            warn!("client certificate carries no CN — rejecting (peer={addr})");
            metrics::counter!("interflow_hub_auth_failures", "reason" => "cert_no_cn").increment(1);
            return Ok(());
        }
    }

    // Per-connection snapshot of the transport tuning (hot-reload friendly:
    // a SIGHUP applies to connections accepted afterwards).
    let h2_transport = ctx.config.read().await.transport.h2.clone();
    let shutdown = ctx.shutdown.clone();

    let conn = h2_builder(&h2_transport).serve_connection(
        TokioIo::new(tls_stream),
        HubService::new(ctx, addr, effective_ip, connection_identity),
    );
    serve_h2(conn, shutdown, addr, true).await;
    drop(guard);
    Ok(())
}

/// Common parameters for serving an h2 connection (shared by the TLS/plain
/// branches). The keepalive pair comes from `[transport.h2]` — the same
/// schema and defaults the agent side uses (endpoint-symmetric since schema
/// v3; previously hard-coded and asymmetric, 10s/20s here vs 5s/10s there).
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
