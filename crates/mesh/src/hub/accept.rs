//! Accept loop: dispatches TLS/plain traffic to hyper HTTP/2 services.

use crate::hub::service::HubService;
use crate::hub::{
    ActiveStream, SharedAgents, SharedHubConfig, SharedStreamCounts, SharedTlsAcceptor,
};
use hyper::server::conn::http2;
use hyper_util::rt::{TokioExecutor, TokioIo, TokioTimer};
use interflow_core::error::Result;
use interflow_core::security::{AuditSink, AuthRateLimiter};
use interflow_core::tls::extract_cn_from_chain;
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::net::TcpStream;
use tokio::sync::RwLock;
use tokio_util::sync::CancellationToken;
use tokio_util::task::TaskTracker;
use tracing::{debug, error, warn};

/// Shared state for a single inbound TCP connection.
///
/// Each `accept` assembles a fresh [`HubService`] from these fields; identity
/// binding is per-connection.
#[derive(Clone)]
pub(crate) struct AcceptContext {
    pub(crate) agents: SharedAgents,

    pub(crate) config: SharedHubConfig,
    pub(crate) active_streams: Arc<RwLock<HashMap<String, ActiveStream>>>,
    pub(crate) tls_acceptor: SharedTlsAcceptor,
    pub(crate) limits: crate::hub::state::HubLimits,
    pub(crate) rate_limiter: Option<Arc<AuthRateLimiter>>,
    pub(crate) stream_counts: SharedStreamCounts,
    pub(crate) audit: AuditSink,
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

/// Handles a new TCP connection: takes a TLS snapshot, performs the (optional)
/// TLS handshake, assembles the service, and hands it to hyper.
///
/// When mTLS is enabled, the client cert CN is extracted after a successful
/// handshake and preset as `connection_identity` — the later `x-agent-id` in
/// `/register` must equal the CN, otherwise the existing `Identity mismatch`
/// path rejects it.
///
/// Shutdown: when `ctx.shutdown` fires, hyper connections get a GOAWAY
/// graceful close-out; if the peer does not cooperate, the drain deadline of
/// `run_until` acts as the fallback.
pub(crate) async fn handle_connection(
    ctx: AcceptContext,
    stream: TcpStream,
    addr: SocketAddr,
) -> Result<()> {
    // Create independent identity state for each connection
    let connection_identity = Arc::new(RwLock::new(None));

    // Take a snapshot of the current TLS acceptor
    let acceptor = {
        let guard = ctx.tls_acceptor.read().await;
        guard.clone()
    };

    if let Some(acceptor) = acceptor {
        match acceptor.accept(stream).await {
            Ok(tls_stream) => {
                // Try to extract the client cert CN (only present after a
                // handshake in mTLS mode)
                if let Some(cn) = extract_peer_cn(&tls_stream) {
                    debug!("mTLS handshake succeeded: peer CN = {cn}");
                    let mut guard = connection_identity.write().await;
                    *guard = Some(cn);
                }

                let conn = h2_builder().serve_connection(
                    TokioIo::new(tls_stream),
                    HubService::new(ctx.clone(), addr, connection_identity),
                );
                serve_h2(conn, ctx.shutdown, addr, true).await;
            }
            Err(e) => {
                warn!("TLS handshake failed (peer={addr}): {e}");
                metrics::counter!("interflow_hub_tls_handshake_failures").increment(1);
            }
        }
    } else {
        let conn = h2_builder().serve_connection(
            TokioIo::new(stream),
            HubService::new(ctx.clone(), addr, connection_identity),
        );
        serve_h2(conn, ctx.shutdown, addr, false).await;
    }
    Ok(())
}

/// Common parameters for serving an h2 connection (shared by the TLS/plain branches).
fn h2_builder() -> http2::Builder<TokioExecutor> {
    let mut builder = http2::Builder::new(TokioExecutor::new());
    builder
        .timer(TokioTimer::new())
        .keep_alive_interval(std::time::Duration::from_secs(10))
        .keep_alive_timeout(std::time::Duration::from_secs(20))
        .initial_stream_window_size(crate::hub::H2_INITIAL_STREAM_WINDOW)
        .initial_connection_window_size(crate::hub::H2_INITIAL_CONNECTION_WINDOW);
    builder
}

/// Graceful close-out grace for a single connection after shutdown: the upper
/// bound for waiting on existing streams (e.g. an agent's long poll) to end
/// naturally after GOAWAY; on timeout the connection is dropped (TCP closed,
/// treated as a disconnect by the peer).
const CONN_SHUTDOWN_GRACE: std::time::Duration = std::time::Duration::from_secs(2);

/// Drives one served h2 connection; the shutdown signal triggers a graceful
/// GOAWAY close-out.
///
/// Two phases: first GOAWAY gives the peer a cooperation window (new streams
/// rejected immediately, existing streams close out); if close-out does not
/// finish within the grace, the connection is dropped to force an end —
/// resident streams like long polls never end on their own, and waiting
/// forever would make drain always hit its timeout.
async fn serve_h2<I>(
    conn: http2::Connection<I, HubService, TokioExecutor>,
    shutdown: CancellationToken,
    addr: SocketAddr,
    tls: bool,
) where
    I: hyper::rt::Read + hyper::rt::Write + Unpin + Send + 'static,
{
    let label = if tls {
        "connection error (TLS)"
    } else {
        "connection error"
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
}

/// Extracts the CN from the peer client cert chain of a `TlsStream<TcpStream>`.
///
/// Returns `None` in non-mTLS mode (no client cert).
fn extract_peer_cn<S>(tls_stream: &tokio_rustls::server::TlsStream<S>) -> Option<String> {
    let (_, server_conn) = tls_stream.get_ref();
    let certs = server_conn.peer_certificates()?;
    extract_cn_from_chain(certs)
}
