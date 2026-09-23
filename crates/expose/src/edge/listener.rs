//! Edge public (internet-facing) listener: TCP listener + peek the first
//! bytes to parse the `Host` header → route → forward through the tunnel.
//!
//! Shares the [`interflow_core::tunnel::pump`] byte pump with
//! `mesh::agent::ingress::IngressHandler::handle_connection`; the only
//! difference is what happens after the listener accepts: read the first
//! 8KB looking for the `Host:` header, look up the route table by Host to
//! get `(target_agent, remote_addr)`, send the already-read bytes into the
//! tunnel first, then continue with the bidirectional pump.
//!
//! Hardening:
//! - Host peek phase has a timeout (default 10s) to defend against slow-loris
//! - Per-IP + global connection caps (reusing `ConnTracker`) so a single IP cannot exhaust us
//! - Unmatched routes are closed silently (no 404), not leaking that the edge is alive
//! - `extract_host` rejects duplicate Host headers, validates characters, and enforces a length limit to prevent header injection
//! - TCP_NODELAY immediately after accept to reduce small-packet latency
//! - Route-level circuit breaker (2026-09-16): a route whose backend keeps
//!   failing (agent close reasons within a window) is tripped — new public
//!   connections are closed right after the Host lookup, **without** an Open
//!   through the tunnel, until a recovery probe succeeds. One dead route's
//!   public retry loop therefore stops at the internet edge instead of
//!   flooding hub + agent.
//! - Probe accounting (2026-09-17): recovery evidence must not depend on the
//!   peer Close reason's arrival timing — an HTTP/1.1 keepalive client hangs
//!   up first and the `backend_closed` token structurally never lands
//!  . A probe that
//!   relayed response bytes to the client without a failure reason is
//!   therefore itself recovery evidence, classified by [`route_evidence`]
//!   from the pump's locally-observed [`StreamOutcome`].

use super::HTTP_HEAD_MAX_BYTES;
use crate::edge::host_router::HostRouter;
use crate::edge::ingress_identity::IngressIdentity;
use interflow_core::protocol::{CloseReason, StreamProto};
use interflow_core::security::ProxyProtocolPolicy;
use interflow_core::security::XffPolicy;
use interflow_core::security::forwarded_for::XffResolution;
use interflow_core::security::proxy_protocol::{ProxyError, ProxyOutcome};
use interflow_core::security::{
    AuditKind, AuditSink, AuthRateLimiter, ConnGuard, ConnTracker, XffError,
};
use interflow_core::tunnel::AgentTunnel;
use interflow_core::tunnel::pump::{PumpConfig, StreamOutcome};
use interflow_mesh::agent::target_breaker::{BreakerDecision, TargetBreakers};
use std::collections::HashMap;
use std::net::IpAddr;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tracing::{debug, error, info, warn};

/// What a finished public connection proves about its route's health — the
/// single classification authority feeding the route breaker.
///
/// Direct evidence (`connect_failed` — the dial itself failed) re-arms;
/// derivative evidence (`target_circuit_open` — the agent's own breaker
/// reacted) counts toward tripping but must never extend an outage (the
/// §3.3 interlock of the 2026-09-17 case file: two breaker layers feeding
/// each other's cooldowns lock each other open).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RouteEvidence {
    /// Direct backend-down proof: counts toward tripping, re-arms an OPEN
    /// entry.
    Failure,
    /// Derivative backend-down signal (the agent's breaker, not the
    /// backend): counts toward tripping while CLOSED, never re-arms.
    DerivativeFailure,
    /// Backend-up proof: clears a tripped route.
    Recovery,
    /// Proves nothing (client aborts, ordinary closes, rate limits) — no
    /// breaker transition.
    Neutral,
}

/// Classifies one finished connection's [`StreamOutcome`] into
/// [`RouteEvidence`].
///
/// `probe`: this connection was admitted as the OPEN breaker's recovery
/// probe of the interval ([`BreakerDecision::Probe`]). The
/// `probe && response_relayed` arm is the structural fix for the stuck-OPEN
/// bug: response bytes reaching the client socket is observed **locally by
/// the pump**, immune to the cross-hop race that loses the peer's Close
/// reason — while a bare connect-and-abort (no bytes relayed) still proves
/// nothing, so transient client noise cannot clear a tripped route.
const fn route_evidence(outcome: &StreamOutcome, probe: bool) -> RouteEvidence {
    match outcome.close_reason {
        // The dial itself failed: direct backend-down evidence.
        Some(CloseReason::ConnectFailed) => RouteEvidence::Failure,
        // The agent's own breaker rejected pre-dial: derivative evidence.
        Some(CloseReason::TargetCircuitOpen) => RouteEvidence::DerivativeFailure,
        // A clean backend EOF proves the dial and the conversation both worked.
        Some(CloseReason::BackendClosed) => RouteEvidence::Recovery,
        // No failure token + a probe that actually served bytes: the backend
        // dialed and answered through to the client.
        _ if probe && outcome.response_relayed => RouteEvidence::Recovery,
        _ => RouteEvidence::Neutral,
    }
}

/// Client response write-stall tolerance: a single-frame write timeout (client
/// not reading → send buffer full) closes the connection. Pairs with poisoning
/// of the dispatch response direction (channel closed when full) — without this
/// upper bound, the write task would hang forever in `write_all` and the poison
/// signal (channel close) would never be consumed.
// Single-sourced with the mesh ingress response path (core transport profile).
const CLIENT_WRITE_STALL_TIMEOUT: Duration =
    interflow_core::config::params::DEFAULT_CLIENT_WRITE_STALL_TIMEOUT;

/// The two rustls configs ACME mode needs on the public listener.
///
/// Ordinary handshakes get the live certificate; ACME-ALPN handshakes get
/// the challenge certificate (`None` in fronted modes — plain TCP).
#[derive(Clone)]
pub struct PublicTlsPlanes {
    /// TLS-ALPN-01 challenge config.
    pub challenge: std::sync::Arc<tokio_rustls::rustls::ServerConfig>,
    /// Live-certificate config (swapped by the renewal loop).
    pub default: std::sync::Arc<tokio_rustls::rustls::ServerConfig>,
    /// Normalized certificate/route host set (from `build_host_allowlist`):
    /// a ClientHello whose SNI is outside this set is closed right after the
    /// acceptor, before the handshake — the connection could never be
    /// routed, so the check only saves handshake and peek cost.
    pub host_allowlist: std::sync::Arc<std::collections::HashSet<String>>,
    /// Single-public-port mode: connections whose SNI is `host` complete
    /// their handshake with the control plane's own mTLS configuration and
    /// are served by the embedded control endpoint (P2). `None` = the
    /// control plane lives on its own port only.
    pub control: Option<std::sync::Arc<ControlDispatch>>,
}

/// The public listener's door into the embedded control endpoint.
pub struct ControlDispatch {
    /// The control endpoint's server name (must differ from every route
    /// host — the manifest validator enforces it).
    pub host: String,
    /// The control plane's mTLS server configuration.
    pub config: std::sync::Arc<tokio_rustls::rustls::ServerConfig>,
    /// Serve handle into the embedded hub.
    pub hub: interflow_mesh::hub::HubDispatchHandle,
}

pub struct EdgeListener {
    /// Listen address (e.g. `0.0.0.0:443` in ACME mode).
    pub listen_addr: SocketAddr,
    /// Log attribution for this edge's lines (display only): the value the
    /// hosting node's "This node" log filter matches. Every listener-side
    /// event carries it via the `node` field.
    pub node: String,
    /// Public-HTTPS termination (`None` = plain TCP behind a front proxy).
    pub tls: Option<PublicTlsPlanes>,
    /// Host route table.
    pub router: Arc<HostRouter>,
    /// One tunnel session per workspace (injected by the per-workspace
    /// internal agents; each route selects its own workspace's session).
    pub tunnels: HashMap<String, WorkspaceSession>,
    /// Host peek timeout (slow-loris defense). Defaults to 10s.
    pub host_peek_timeout: Duration,
    /// Stream idle timeout (close when no data flows in either direction).
    /// Fixed `EdgeListenerPolicy` default (300s); must be ≤ the fronting
    /// nginx `proxy_read_timeout` in the fronted topology.
    pub stream_idle_timeout: Duration,
    /// Connection tracker (per-IP + global caps).
    pub conn_tracker: Arc<ConnTracker>,
    /// Per-IP new-connection rate limit (None = disabled). Checked before
    /// conn_tracker to stop connect→peek→disconnect loop attacks from
    /// bypassing the concurrency cap.
    pub rate_limiter: Option<Arc<AuthRateLimiter>>,
    /// Audit sink (connection denials and other events).
    pub audit: AuditSink,
    /// Route-level circuit breaker (None = disabled): keyed by host, fed by
    /// agent close reasons, stops dead-route retry loops at the internet
    /// edge (no Open through the tunnel while tripped).
    pub route_breaker: Option<Arc<TargetBreakers>>,
    /// Compiled PROXY-protocol policy: restores real client IPs behind a
    /// PROXY-v2-capable front (rate limit / caps / audit key on the
    /// effective IP — never identity).
    pub proxy_policy: Arc<ProxyProtocolPolicy>,
    /// Compiled X-Forwarded-For policy: restores real client IPs on the
    /// standard nginx HTTP `proxy_pass` leg (stock nginx cannot emit the
    /// PROXY protocol there). Shares the proxy policy's trusted set; the
    /// derived IP keys governance/audit only — never identity.
    pub xff_policy: Arc<XffPolicy>,
    /// Workspace-scoped ingress identity. Every flow declares `FLAG_E2E`
    /// and completes the inner handshake with the route's workspace
    /// principal against that workspace's anchor; failure closes the
    /// stream. The edge host remains the public plaintext terminus, but the
    /// control endpoint never carries payload plaintext.
    pub identity: Arc<IngressIdentity>,
}

/// One workspace's tunnel session on the listener.
#[derive(Clone)]
pub struct WorkspaceSession {
    /// The hub-plane agent id (the workspace principal's CN — the inner
    /// layer's source-principal binding).
    pub agent_id: String,
    /// The session-slot tunnel facade (rides supervisor rebuilds).
    pub tunnel: AgentTunnel,
}

impl EdgeListener {
    /// Binds the listen port and runs the accept loop. Blocks the caller.
    pub async fn run(self) -> std::io::Result<()> {
        Self::run_inner(self, None).await
    }

    /// [`run`] with an external readiness signal: `ready` fires once the
    /// listen port is bound, just before the accept loop starts. Callers
    /// that need "accepting by the time this returns" (the edge's readiness
    /// barrier, the GUI's ingress engine) get an exact signal instead of
    /// probing the port.
    pub async fn run_signalled(
        self,
        ready: tokio::sync::oneshot::Sender<()>,
    ) -> std::io::Result<()> {
        Self::run_inner(self, Some(ready)).await
    }

    async fn run_inner(
        self,
        ready: Option<tokio::sync::oneshot::Sender<()>>,
    ) -> std::io::Result<()> {
        let listener = TcpListener::bind(self.listen_addr).await?;
        if let Some(ready) = ready {
            let _ = ready.send(());
        }
        info!(
            node = %self.node,
            "Edge public listener started: {} ({} routes)",
            self.listen_addr,
            self.router.len()
        );

        let tls = self.tls;
        let node = self.node;
        let router = self.router;
        let tunnels = self.tunnels;
        let host_peek_timeout = self.host_peek_timeout;
        let stream_idle_timeout = self.stream_idle_timeout;
        let conn_tracker = self.conn_tracker;
        let rate_limiter = self.rate_limiter;
        let audit = self.audit;
        let route_breaker = self.route_breaker;

        let proxy_policy = self.proxy_policy;
        let xff_policy = self.xff_policy;
        let identity = self.identity;

        loop {
            let (stream, addr) = listener.accept().await?;

            // Per-IP resource gating runs inside the connection task. In
            // fronted mode it waits for the PROXY negotiation to key on the
            // real client IP (behind nginx every TCP peer is 127.0.0.1 —
            // gating there would throttle the proxy itself); in ACME mode
            // (80/443 direct, no front) it runs before the TLS accept, on
            // the TCP peer IP.
            let tls = tls.clone();
            let node = node.clone();
            let router = router.clone();
            let tunnels = tunnels.clone();
            let audit = audit.clone();
            let route_breaker = route_breaker.clone();
            let conn_tracker = conn_tracker.clone();
            let rate_limiter = rate_limiter.clone();
            let proxy_policy = proxy_policy.clone();
            let xff_policy = xff_policy.clone();
            let identity = identity.clone();

            tokio::spawn(async move {
                if let Err(e) = handle_public_connection(
                    &node,
                    stream,
                    addr,
                    tls.as_ref(),
                    &router,
                    &tunnels,
                    host_peek_timeout,
                    stream_idle_timeout,
                    &audit,
                    route_breaker.as_ref(),
                    &conn_tracker,
                    rate_limiter.as_ref(),
                    &proxy_policy,
                    &xff_policy,
                    &identity,
                )
                .await
                {
                    debug!(node = %node, "edge connection finished ({addr}): {e}");
                }
            });
        }
    }
}

/// Handles a single public connection: (TLS mode: pre-handshake gate →
/// ClientHello under the handshake deadline → SNI allowlist → handshake)
/// then peek the first bytes for Host → look up the route → (route breaker
/// gate) → open a stream → bidirectional pump → feed the close reason back
/// into the route breaker.
#[allow(clippy::too_many_arguments)]
async fn handle_public_connection(
    node: &str,
    tcp: TcpStream,
    peer: SocketAddr,
    tls: Option<&PublicTlsPlanes>,
    router: &HostRouter,
    tunnels: &HashMap<String, WorkspaceSession>,
    host_peek_timeout: Duration,
    stream_idle_timeout: Duration,
    audit: &AuditSink,
    route_breaker: Option<&Arc<TargetBreakers>>,
    conn_tracker: &Arc<ConnTracker>,
    rate_limiter: Option<&Arc<AuthRateLimiter>>,
    proxy_policy: &Arc<ProxyProtocolPolicy>,
    xff_policy: &Arc<XffPolicy>,
    identity: &Arc<IngressIdentity>,
) -> interflow_core::error::Result<()> {
    let _ = tcp.set_nodelay(true);
    let Some(tls) = tls else {
        return handle_connection(
            node,
            tcp,
            peer,
            None,
            router,
            tunnels,
            host_peek_timeout,
            stream_idle_timeout,
            audit,
            route_breaker,
            conn_tracker,
            rate_limiter,
            proxy_policy,
            xff_policy,
            identity,
        )
        .await;
    };
    // Pre-handshake gate: ACME mode is 80/443 direct by product definition
    // (no PROXY/XFF front), so the TCP peer IP is the client IP. Running the
    // gate here — before any handshake byte is read — extends the per-IP
    // rate limit and concurrency caps over the handshake itself; the guard
    // is handed down to `handle_connection` and reused, never re-acquired.
    // A denial stays a silent close on this path: no handshake has started,
    // so there is no channel to answer on (and answering would spend the
    // handshake work this gate exists to withhold).
    let ConnAdmission::Admitted(guard) =
        gate_connection(node, peer.ip(), peer, audit, rate_limiter, conn_tracker)
    else {
        return Ok(());
    };
    let Some(start) = tls_stage(
        node,
        tokio_rustls::LazyConfigAcceptor::new(
            tokio_rustls::rustls::server::Acceptor::default(),
            tcp,
        ),
    )
    .await?
    else {
        return Ok(());
    };
    if rustls_acme::is_tls_alpn_challenge(&start.client_hello()) {
        debug!(node = %node, "acme TLS-ALPN-01 validation request: peer={peer}");
        let Some(mut challenge) = tls_stage(node, start.into_stream(tls.challenge.clone())).await?
        else {
            return Ok(());
        };
        challenge.shutdown().await?;
        return Ok(());
    }
    // Single-public-port mode: the control endpoint's own server name rides
    // the same port. Complete the handshake with the control plane's mTLS
    // configuration and hand the stream to the embedded hub — identity,
    // tenant derivation and admission semantics are unchanged; this
    // listener's pre-handshake gate already admitted the connection (the
    // `guard` stays held for the connection's lifetime below).
    if let Some(control) = &tls.control
        && start
            .client_hello()
            .server_name()
            .is_some_and(|sni| sni.eq_ignore_ascii_case(control.host.as_str()))
    {
        metrics::counter!("interflow_edge_control_dispatched").increment(1);
        debug!(node = %node, "control-plane SNI dispatched to embedded hub: peer={peer}");
        let Some(control_stream) =
            tls_stage(node, start.into_stream(control.config.clone())).await?
        else {
            return Ok(());
        };
        return control.hub.serve_tls(control_stream, peer).await;
    }
    // SNI allowlist pre-check (defense in depth): the connection could never
    // be routed under this name — close before the handshake saves the cert
    // exchange and the peek cost. A TLS-ALPN-01 validation SNI is one of the
    // certificate hosts, so the branch above is unaffected; an SNI-less
    // client is closed here exactly as the cert resolver would reject it.
    let sni_known = start
        .client_hello()
        .server_name()
        .is_some_and(|sni| tls.host_allowlist.contains(&sni.to_ascii_lowercase()));
    if !sni_known {
        metrics::counter!("interflow_edge_sni_rejected").increment(1);
        debug!(node = %node, "edge TLS SNI outside host allowlist, closing: peer={peer}");
        return Ok(());
    }
    let Some(tls_stream) = tls_stage(node, start.into_stream(tls.default.clone())).await? else {
        return Ok(());
    };
    handle_connection(
        node,
        tls_stream,
        peer,
        Some(guard),
        router,
        tunnels,
        host_peek_timeout,
        stream_idle_timeout,
        audit,
        route_breaker,
        conn_tracker,
        rate_limiter,
        proxy_policy,
        xff_policy,
        identity,
    )
    .await
}

/// Runs one TLS-accept stage (the ClientHello read or handshake completion)
/// under [`super::TLS_HANDSHAKE_TIMEOUT`]: a stalled handshake counts
/// `interflow_edge_tls_handshake_timeout` and yields `Ok(None)` for a silent
/// close, while transport errors propagate to the caller.
async fn tls_stage<T>(
    node: &str,
    stage: impl std::future::Future<Output = std::io::Result<T>>,
) -> interflow_core::error::Result<Option<T>> {
    match tokio::time::timeout(super::TLS_HANDSHAKE_TIMEOUT, stage).await {
        Ok(Ok(value)) => Ok(Some(value)),
        Ok(Err(e)) => Err(e.into()),
        Err(_) => {
            metrics::counter!("interflow_edge_tls_handshake_timeout").increment(1);
            debug!(node = %node, "edge TLS handshake stalled past the deadline, closing");
            Ok(None)
        }
    }
}

/// Handles a single public connection (plaintext at the byte level): peek
/// the first bytes for Host → look up the route → (route breaker gate) →
/// open a stream → bidirectional pump → feed the close reason back into the
/// route breaker.
///
/// `pre_gate`: a guard already acquired by the pre-TLS gate (ACME mode). It
/// is THE connection's admission — reused here, never re-acquired — so the
/// deferred-XFF re-gate never runs on a pre-gated connection and the quota
/// is counted exactly once.
#[allow(clippy::too_many_arguments)]
async fn handle_connection<S>(
    node: &str,
    mut socket: S,
    peer: SocketAddr,
    pre_gate: Option<ConnGuard>,
    router: &HostRouter,
    tunnels: &HashMap<String, WorkspaceSession>,
    host_peek_timeout: Duration,
    stream_idle_timeout: Duration,
    audit: &AuditSink,
    route_breaker: Option<&Arc<TargetBreakers>>,
    conn_tracker: &Arc<ConnTracker>,
    rate_limiter: Option<&Arc<AuthRateLimiter>>,
    proxy_policy: &Arc<ProxyProtocolPolicy>,
    xff_policy: &Arc<XffPolicy>,
    identity: &Arc<IngressIdentity>,
) -> interflow_core::error::Result<()>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    use interflow_core::error::InterflowError;

    // 1. PROXY protocol negotiation (same budget as the Host peek): derives
    //    the effective client IP; over-read bytes of a direct connection are
    //    replayed as the start of the HTTP buffer.
    let mut initial = bytes::BytesMut::with_capacity(HTTP_HEAD_MAX_BYTES);
    let mut effective_ip =
        match tokio::time::timeout(host_peek_timeout, proxy_policy.read(&mut socket, peer.ip()))
            .await
        {
            Ok(Ok(ProxyOutcome::Proxied { effective })) => effective,
            Ok(Ok(ProxyOutcome::Direct { read_back })) => {
                if !read_back.is_empty() {
                    initial.extend_from_slice(&read_back);
                }
                peer.ip()
            }
            Ok(Err(e)) => {
                metrics::counter!("interflow_edge_proxy_rejected").increment(1);
                let reason = match &e {
                    ProxyError::UntrustedSignature => "untrusted_proxy_signature",
                    ProxyError::RequiredMissing => "proxy_header_required",
                    ProxyError::Malformed(_) => "malformed_proxy_header",
                    ProxyError::Io(_) => "proxy_read_error",
                };
                warn!(
                    node = %node,
                    "PROXY negotiation rejected ({reason}): peer={peer}"
                );
                audit.record(
                    AuditKind::StreamDenied {
                        stream_id: String::new(),
                        source_circuit: String::new(),
                        source_ip: None,
                        reason: reason.to_string(),
                    },
                    None,
                    Some(peer.to_string()),
                );
                return Ok(());
            }
            Err(_) => {
                metrics::counter!("interflow_edge_proxy_timeout").increment(1);
                return Ok(());
            }
        };

    // 2. Real-IP source selection. X-Forwarded-For restoration applies only
    //    when the mechanism is enabled AND the TCP peer is a trusted proxy
    //    (the header from anyone else is attacker-controlled). For everyone
    //    else the peer IP is authoritative and the per-IP gate runs before
    //    the peek, preserving the connect→peek→disconnect flood defense.
    //    For a trusted proxy the gate is deferred until the request head is
    //    buffered: the effective IP lives in the XFF header, and nginx's own
    //    limit_req/limit_conn cap that fronting leg meanwhile. A pre-gated
    //    connection (ACME mode: gated pre-TLS on the TCP peer key) skips
    //    both paths below — its admission is already held, and ACME's
    //    80/443-direct product definition has no XFF face to defer to.
    let xff_deferred =
        pre_gate.is_none() && xff_policy.mode.enabled() && xff_policy.is_trusted(peer.ip());
    let mut guard = if xff_deferred {
        None
    } else {
        match pre_gate {
            Some(g) => Some(g),
            None => {
                match gate_connection(node, effective_ip, peer, audit, rate_limiter, conn_tracker) {
                    ConnAdmission::Admitted(g) => Some(g),
                    // `pre_gate=None` reaches here only on the plaintext
                    // (fronted) face — answer the denial with a real status so
                    // the front relays 429/503 instead of synthesizing 502.
                    ConnAdmission::Denied(kind) => {
                        write_deny_response(&mut socket, kind).await;
                        return Ok(());
                    }
                }
            }
        }
    };

    // Buffer the request head until it is complete (blank line) or the cap
    // is reached. The whole peek phase is bounded by a timeout to defend
    // against slow-loris. Waiting for the complete head lets core's shared
    // `http_head` parser own all HTTP/1.x syntax: Host extraction, duplicate
    // rejection and the XFF-deferred path all see the same parsed head, and
    // a head that trickles in slowly is bounded by the timeout — the
    // clients that sent Host early but stalled before the blank line are
    // exactly the slow-loris profile this budget exists for.
    let host = tokio::time::timeout(host_peek_timeout, async {
        let mut tmp = vec![0u8; 4096];
        loop {
            if initial.len() >= HTTP_HEAD_MAX_BYTES {
                return Err(InterflowError::protocol(format!(
                    "request head exceeds the first {HTTP_HEAD_MAX_BYTES} bytes"
                )));
            }
            let n = socket.read(&mut tmp).await?;
            if n == 0 {
                return Err(InterflowError::protocol("connection closed early"));
            }
            initial.extend_from_slice(&tmp[..n]);
            if interflow_core::security::http_head::find_headers_end(&initial).is_none() {
                continue;
            }
            let outcome = match interflow_core::security::http_head::parse_request_head(&initial) {
                // Complete head: find_headers_end saw the blank line, so a
                // Partial here means an early stray terminator — keep reading.
                interflow_core::security::http_head::HeadParse::Partial => continue,
                interflow_core::security::http_head::HeadParse::Invalid(reason) => {
                    Err(reason.as_str().to_owned())
                }
                interflow_core::security::http_head::HeadParse::Complete(head) => {
                    interflow_core::security::http_head::validated_host(&head.headers)
                        .map(str::to_owned)
                        .map_err(|e| e.as_str().to_owned())
                }
            };
            return outcome.map_err(|reason| {
                metrics::counter!("interflow_edge_host_invalid").increment(1);
                InterflowError::protocol(reason)
            });
        }
    })
    .await
    .inspect_err(|_| {
        metrics::counter!("interflow_edge_host_peek_timeout").increment(1);
    })
    .map_err(|_| InterflowError::connection(format!("Host peek timeout ({peer})")))?
    .inspect_err(|_| {
        metrics::counter!("interflow_edge_host_peek_failed").increment(1);
    })?;

    // 3. Deferred XFF resolution + gate: the head is buffered, the
    //    right-most chain entry is the IP our trusted proxy observed.
    if xff_deferred {
        effective_ip = match xff_policy.resolve(&initial) {
            XffResolution::Effective(ip) => ip,
            XffResolution::Peer => peer.ip(),
            XffResolution::Denied(err) => {
                let (reason, missing) = match err {
                    XffError::Missing => {
                        metrics::counter!("interflow_edge_xff_missing").increment(1);
                        ("x_forwarded_for_required", true)
                    }
                    XffError::Invalid => {
                        metrics::counter!("interflow_edge_xff_invalid").increment(1);
                        ("x_forwarded_for_invalid", false)
                    }
                };
                if missing {
                    // The browser sees an unexplained 502 — name the fix here.
                    warn!(
                        node = %node,
                        "X-Forwarded-For rejected ({reason}): peer={peer} — the fronting \
                         proxy sent no X-Forwarded-For; fix the proxy with \
                         `proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;` \
                         (diagnose: interflow doctor ingress)"
                    );
                } else {
                    warn!(node = %node, "X-Forwarded-For rejected ({reason}): peer={peer}");
                }
                audit.record(
                    AuditKind::StreamDenied {
                        stream_id: String::new(),
                        source_circuit: String::new(),
                        source_ip: None,
                        reason: reason.to_string(),
                    },
                    None,
                    Some(peer.to_string()),
                );
                return Ok(());
            }
        };
        match gate_connection(node, effective_ip, peer, audit, rate_limiter, conn_tracker) {
            ConnAdmission::Admitted(g) => guard = Some(g),
            // The request head is fully buffered and this path exists only
            // behind a trusted front on the plaintext face — the 429/503 is
            // a complete, valid HTTP answer, not a mid-handshake abort.
            ConnAdmission::Denied(kind) => {
                write_deny_response(&mut socket, kind).await;
                return Ok(());
            }
        }
    }

    let Some(route) = router.lookup(&host) else {
        // No route matched: close silently, send no 404, do not leak that the edge is alive
        warn!(
            node = %node,
            "no route matched host={host} (peer={peer}, effective={effective_ip})"
        );
        metrics::counter!("interflow_edge_no_route").increment(1);
        audit.record(
            AuditKind::StreamDenied {
                stream_id: String::new(),
                source_circuit: String::new(),
                source_ip: None,
                reason: format!("no_route: {host}"),
            },
            None,
            Some(peer.to_string()),
        );
        return Ok(());
    };

    debug!(
        node = %node,
        "edge route hit: {host} → {}/{} service={}",
        route.workspace, route.agent_id, route.service_id
    );

    // Route-level breaker gate: a tripped route is closed right here — no
    // register, no Open, no tunnel round trip. Same public behavior as an
    // agent-side rejection (fast zero-byte close; the fronting nginx
    // surfaces 502), but the storm stops at the internet edge. The verdict
    // also tells us whether an admitted connection is the OPEN breaker's
    // recovery probe of the interval — its outcome, not just its close
    // reason, is the recovery evidence (see route_evidence).
    let route_decision = route_breaker.map(|b| b.check(&host));
    if route_decision == Some(BreakerDecision::Reject) {
        metrics::counter!("interflow_edge_route_breaker_rejected").increment(1);
        audit.record(
            AuditKind::StreamDenied {
                stream_id: String::new(),
                source_circuit: String::new(),
                source_ip: None,
                reason: format!("route_circuit_open: {host}"),
            },
            None,
            Some(peer.to_string()),
        );
        debug!(
            node = %node,
            "route circuit open, closing without tunnel open: host={host} peer={peer}"
        );
        return Ok(());
    }
    let route_probe = route_decision == Some(BreakerDecision::Probe);

    // Resolve the route's workspace session. Every workspace's presence
    // was validated at startup, so a miss here is an internal invariant
    // break — fail this connection closed rather than rerouting it through
    // another workspace's principal.
    let Some(session) = tunnels.get(&route.workspace) else {
        error!(
            node = %node,
            "route workspace {} has no tunnel session (startup invariant broken): host={host}",
            route.workspace
        );
        metrics::counter!("interflow_edge_no_route").increment(1);
        audit.record(
            AuditKind::StreamDenied {
                stream_id: String::new(),
                source_circuit: String::new(),
                source_ip: None,
                reason: format!("workspace_session_missing: {}", route.workspace),
            },
            None,
            Some(peer.to_string()),
        );
        return Ok(());
    };
    let tunnel = &session.tunnel;

    let stream_id = interflow_core::protocol::StreamId::random()?;
    let data_rx = tunnel.register_stream(stream_id).await;

    // Every ingress stream uses inner TLS. A missing per-route workspace
    // anchor or stale principal material is a configuration error: close this stream
    // rather than downgrading the hub leg to plaintext.
    let material = match identity.material_for(&route.workspace) {
        Ok(material) => material,
        Err(e) => {
            warn!(
                node = %node,
                "ingress inner TLS material unavailable: host={host} workspace={} peer={peer}: {e}",
                route.workspace
            );
            metrics::counter!("interflow_edge_e2e_handshake_failures_total",
                "reason" => "protocol")
            .increment(1);
            if let Some(breaker) = route_breaker {
                breaker.note_failure(&host);
            }
            let _ = tunnel.send_close(stream_id).await;
            tunnel.unregister_stream(stream_id).await;
            return Ok(());
        }
    };

    let qualified_target = format!("{}/{}", route.workspace, route.agent_id);
    if let Err(e) = tunnel
        .send_open_with(stream_id, &qualified_target, StreamProto::Tcp, true)
        .await
    {
        tunnel.unregister_stream(stream_id).await;
        return Err(e);
    }
    let _ = guard;

    let connector = match interflow_core::tls::inner_client_config(&material, &route.agent_id) {
        Ok(config) => tokio_rustls::TlsConnector::from(std::sync::Arc::new(config)),
        Err(e) => {
            warn!(
                node = %node,
                "ingress inner TLS connector build failed: host={host} agent={} peer={peer}: {e}",
                route.agent_id
            );
            metrics::counter!("interflow_edge_e2e_handshake_failures_total",
                "reason" => "protocol")
            .increment(1);
            if let Some(breaker) = route_breaker {
                breaker.note_failure(&host);
            }
            let _ = tunnel.send_close(stream_id).await;
            tunnel.unregister_stream(stream_id).await;
            return Ok(());
        }
    };

    let adapter =
        interflow_core::tunnel::e2e::E2eTunnelIo::ingress(data_rx, tunnel.clone(), stream_id);
    let (tls, peer_close_reason) = match interflow_core::tunnel::e2e::inner_tls_connect(
        adapter,
        connector,
        EDGE_E2E_HANDSHAKE_TIMEOUT,
    )
    .await
    {
        interflow_core::tunnel::e2e::E2eHandshakeOutcome::Established(mut tls, reason) => {
            metrics::counter!("interflow_edge_e2e_handshakes_total").increment(1);
            let hello = interflow_core::tunnel::InnerStreamHello {
                source_principal: session.agent_id.clone(),
                source_fingerprint: material.leaf_fingerprint(),
                // Select by service **id**: the target agent resolves the
                // id to its own effective dial target (pack default or
                // machine-local preference). The edge never names an
                // address, so an ingress compromise can only select among
                // the services the agent itself declares.
                selector: interflow_core::tunnel::TargetSelector::Service(route.service_id.clone()),
                correlation_id: *uuid::Uuid::new_v4().as_bytes(),
            };
            if hello.write(&mut tls).await.is_err() {
                if let Some(breaker) = route_breaker {
                    breaker.note_failure(&host);
                }
                let _ = tunnel.send_close(stream_id).await;
                tunnel.unregister_stream(stream_id).await;
                return Ok(());
            }
            if !initial.is_empty() && tls.write_all(&initial).await.is_err() {
                if let Some(breaker) = route_breaker {
                    breaker.note_failure(&host);
                }
                let _ = tunnel.send_close(stream_id).await;
                tunnel.unregister_stream(stream_id).await;
                return Ok(());
            }
            (tls, reason)
        }
        interflow_core::tunnel::e2e::E2eHandshakeOutcome::Failed { error } => {
            let reason_label = interflow_core::tls::classify_handshake_error(&error);
            metrics::counter!("interflow_edge_e2e_handshake_failures_total",
                "reason" => reason_label)
            .increment(1);
            warn!(
                node = %node,
                "gateway inner TLS handshake failed ({reason_label}: {error}), closing: host={host} peer={peer}"
            );
            if let Some(breaker) = route_breaker {
                breaker.note_failure(&host);
            }
            let _ = tunnel.send_close(stream_id).await;
            tunnel.unregister_stream(stream_id).await;
            return Ok(());
        }
    };

    let sid = stream_id;
    let t2 = tunnel.clone();
    let outcome = interflow_core::tunnel::pump::pump_duplex(
        socket,
        tls,
        &pump_cfg(stream_idle_timeout),
        CloseReason::CloseFrame,
        Duration::ZERO,
        stream_id,
        async move {
            let _ = t2.send_close(sid).await;
            t2.unregister_stream(sid).await;
        },
    )
    .await;
    let outcome = StreamOutcome {
        close_reason: outcome.close_reason.or_else(|| peer_close_reason.get()),
        response_relayed: outcome.response_relayed,
    };
    // Feed the route breaker from the classified evidence: a failing dial
    // counts (and re-arms), the agent's own breaker verdict counts without
    // re-arming (derivative), recovery evidence clears a tripped route, and
    // everything else (client-side aborts, ordinary closes) is neutral.
    if let Some(breaker) = route_breaker {
        match route_evidence(&outcome, route_probe) {
            RouteEvidence::Failure => breaker.note_failure(&host),
            RouteEvidence::DerivativeFailure => breaker.note_soft_failure(&host),
            RouteEvidence::Recovery => breaker.note_success(&host),
            RouteEvidence::Neutral => {}
        }
    }
    Ok(())
}

/// Why [`gate_connection`] denied a connection.
///
/// The answer differs by surface: plaintext (fronted) faces answer the
/// denial with a real HTTP status ([`write_deny_response`]); the pre-TLS
/// gate cannot answer at all — no handshake bytes have been exchanged yet.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum DenialKind {
    /// Per-IP new-connection quota exceeded → HTTP 429 + `Retry-After`.
    RateLimited {
        /// The configured per-IP-per-minute quota (drives `Retry-After`).
        quota_per_minute: u32,
    },
    /// Per-IP concurrent connection cap exceeded → HTTP 503.
    ConnLimitExceeded,
}

/// The admission verdict of [`gate_connection`].
pub(super) enum ConnAdmission {
    Admitted(ConnGuard),
    Denied(DenialKind),
}

/// Applies the per-IP new-connection rate limit and concurrency caps to one
/// connection, keyed on the effective client IP (TCP peer, PROXY-asserted,
/// or XFF-restored). A denial records metrics + audit and logs at WARN — a
/// security rejection that was invisible at the production INFO level
/// already cost one full misdirected diagnostic round
///.
pub(super) fn gate_connection(
    node: &str,
    effective_ip: IpAddr,
    peer: SocketAddr,
    audit: &AuditSink,
    rate_limiter: Option<&Arc<AuthRateLimiter>>,
    conn_tracker: &Arc<ConnTracker>,
) -> ConnAdmission {
    if let Some(limiter) = rate_limiter
        && !limiter.check(effective_ip)
    {
        metrics::counter!("interflow_edge_conn_rate_limited").increment(1);
        audit.record(
            AuditKind::StreamDenied {
                stream_id: String::new(),
                source_circuit: String::new(),
                source_ip: Some(effective_ip.to_string()),
                reason: "rate_limited".into(),
            },
            None,
            Some(peer.to_string()),
        );
        warn!(
            node = %node,
            "edge connection denied (rate limited): effective={effective_ip} peer={peer} — \
             per-IP new-connection quota ({} per minute) exceeded; legitimate traffic behind a \
             front proxy should raise [edge] new_conn_rate_per_ip_per_minute",
            limiter.quota()
        );
        return ConnAdmission::Denied(DenialKind::RateLimited {
            quota_per_minute: limiter.quota(),
        });
    }
    if let Some(guard) = conn_tracker.try_acquire(effective_ip) {
        return ConnAdmission::Admitted(guard);
    }
    metrics::counter!("interflow_edge_conn_rejected").increment(1);
    audit.record(
        AuditKind::StreamDenied {
            stream_id: String::new(),
            source_circuit: String::new(),
            source_ip: None,
            reason: "conn_limit_exceeded".into(),
        },
        None,
        Some(peer.to_string()),
    );
    warn!(
        node = %node,
        "edge connection denied (connection limit): effective={effective_ip} peer={peer} — \
         per-IP concurrent connection cap exceeded"
    );
    ConnAdmission::Denied(DenialKind::ConnLimitExceeded)
}

/// Answers a plaintext gate denial with a real HTTP status before the close.
///
/// A fronting proxy then relays the edge's semantics (429/503 +
/// `Retry-After`) instead of synthesizing 502 "upstream prematurely closed"
/// — the failure mode that misdirected the 2026-09-23 investigation toward
/// the tunnel and backends. One bounded write; a client that never reads it
/// loses nothing (the connection was doomed regardless).
pub(super) async fn write_deny_response<S>(socket: &mut S, kind: DenialKind)
where
    S: tokio::io::AsyncWrite + Unpin,
{
    let (status, retry_after, body) = match kind {
        // One token refills every 60/quota seconds — the next attempt
        // realistically succeeds after one refill interval.
        DenialKind::RateLimited { quota_per_minute } => (
            "429 Too Many Requests",
            60_u32.div_ceil(quota_per_minute.max(1)).clamp(1, 60),
            "edge: per-IP new-connection rate limit exceeded\n",
        ),
        // A concurrency slot frees as soon as any one connection closes.
        DenialKind::ConnLimitExceeded => (
            "503 Service Unavailable",
            1,
            "edge: per-IP concurrent connection limit exceeded\n",
        ),
    };
    let answer = format!(
        "HTTP/1.1 {status}\r\nRetry-After: {retry_after}\r\n\
         Content-Type: text/plain; charset=utf-8\r\nContent-Length: {}\r\n\
         Connection: close\r\n\r\n{body}",
        body.len()
    );
    let _ = socket.write_all(answer.as_bytes()).await;
    let _ = socket.shutdown().await;
}

// Host extraction from the buffered request head lives in core's shared
// `http_head` module (httparse-backed): duplicate-Host rejection, Host
// charset/length validation and the header-region-only scan are preserved
// there under test. The hand-written scanner this replaces (plus its
// private find_headers_end/trim helpers) had already diverged from the
// X-Forwarded-For copy in core.

/// Inner-TLS handshake deadline for gateway flows (mirrors the mesh
/// agent-side `[inner_tls] handshake_timeout_secs` default).
const EDGE_E2E_HANDSHAKE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(10);

/// The listener's inner-TLS pump configuration.
const fn pump_cfg(stream_idle_timeout: std::time::Duration) -> PumpConfig {
    PumpConfig {
        idle_timeout: stream_idle_timeout,
        write_stall_timeout: CLIENT_WRITE_STALL_TIMEOUT,
        idle_timeout_counter: "interflow_edge_stream_idle_timeout",
        write_stall_counter: "interflow_edge_client_write_stall",
        log_label: "edge",
    }
}

/// Hardening (kept from the original implementation, now enforced by the
/// shared parser): duplicate Host rejects the whole connection; host
/// characters are limited to `[A-Za-z0-9.\-:\[\]]`; host length ≤ 255; only
/// the header region is scanned, so binary bodies cannot smuggle headers.
#[cfg(test)]
#[allow(
    clippy::panic,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::missing_docs_in_private_items
)]
mod tests {
    use super::*;

    fn outcome(close_reason: Option<CloseReason>, response_relayed: bool) -> StreamOutcome {
        StreamOutcome {
            close_reason,
            response_relayed,
        }
    }

    /// The classification matrix feeding the route breaker — the contract
    /// the 2026-09-17 stuck-OPEN fix is built on.
    #[test]
    fn route_evidence_matrix() {
        use CloseReason::{
            BackendClosed, CloseFrame, ConnectFailed, DispatchPoison, RateLimited,
            TargetCircuitOpen,
        };
        // Direct failure re-arms; derivative failure never re-arms.
        assert_eq!(
            route_evidence(&outcome(Some(ConnectFailed), false), false),
            RouteEvidence::Failure
        );
        assert_eq!(
            route_evidence(&outcome(Some(TargetCircuitOpen), false), false),
            RouteEvidence::DerivativeFailure
        );
        // A clean backend EOF is recovery regardless of probe status.
        assert_eq!(
            route_evidence(&outcome(Some(BackendClosed), false), false),
            RouteEvidence::Recovery
        );
        // THE bug shape: keepalive client hung up first (no Close reason
        // landed) but the probe relayed response bytes — locally observed,
        // race-free recovery evidence.
        assert_eq!(
            route_evidence(&outcome(None, true), true),
            RouteEvidence::Recovery
        );
        // The same shape on a non-probe connection proves nothing for a
        // tripped route (the entry was tripped after this connection was
        // admitted; stale liveness must not clear it).
        assert_eq!(
            route_evidence(&outcome(None, true), false),
            RouteEvidence::Neutral
        );
        // A probe that never relayed bytes (bare connect-and-abort, or the
        // agent's rate limiter dropping the Open) proves nothing.
        assert_eq!(
            route_evidence(&outcome(None, false), true),
            RouteEvidence::Neutral
        );
        // Ordinary / unrelated closes stay neutral on both probe statuses.
        assert_eq!(
            route_evidence(&outcome(Some(CloseFrame), true), true),
            RouteEvidence::Recovery, // CloseFrame without failure + served bytes on a probe
        );
        assert_eq!(
            route_evidence(&outcome(Some(CloseFrame), false), false),
            RouteEvidence::Neutral
        );
        assert_eq!(
            route_evidence(&outcome(Some(RateLimited), false), true),
            RouteEvidence::Neutral
        );
        // Post-connection pathologies with bytes already served: the backend
        // dialed and answered — for route *reachability* that is recovery
        // evidence, not a failure (mirrors the target breaker's
        // connect-phase-only failure semantics).
        assert_eq!(
            route_evidence(&outcome(Some(DispatchPoison), true), true),
            RouteEvidence::Recovery
        );
    }

    // The Host-extraction unit suite (basic/case/port/missing/duplicate/
    // invalid-chars/too-long/ipv6/binary-body/first-host-scan/invalid-utf8/
    // host-like-in-body/LF-only) moved with the parser into
    // interflow-core's `security::http_head` tests; the listener keeps the
    // behavioral integration tests (slow-loris, duplicate-Host close,
    // binary-body routing, XFF) in crates/expose/tests.
}
