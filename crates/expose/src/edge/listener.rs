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
//!   failing (agent close reasons `connect_failed`/`target_circuit_open`
//!   within a window) is tripped — new public connections are closed right
//!   after the Host lookup, **without** an Open through the tunnel, until a
//!   recovery probe succeeds. One dead route's public retry loop therefore
//!   stops at the internet edge instead of flooding hub + agent.

use crate::edge::host_router::HostRouter;
use interflow_core::protocol::StreamProto;
use interflow_core::security::{AuditKind, AuditSink, AuthRateLimiter, ConnTracker};
use interflow_core::tunnel::AgentTunnel;
use interflow_core::tunnel::pump::{PumpConfig, pump_tcp_stream};
use interflow_mesh::agent::target_breaker::{BreakerDecision, TargetBreakers};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::AsyncReadExt;
use tokio::net::{TcpListener, TcpStream};
use tracing::{debug, info, warn};

/// Agent close reasons that count as backend-down evidence for the route
/// breaker (`CloseReason::as_str()` tokens from the egress forwarder).
const ROUTE_FAILURE_REASONS: [&str; 2] = ["connect_failed", "target_circuit_open"];
/// Agent close reasons that count as backend-up evidence (a normal
/// backend EOF means the dial and the conversation both worked).
const ROUTE_SUCCESS_REASONS: [&str; 1] = ["backend_closed"];

/// Maximum number of bytes read per connection while looking for the Host
/// header (HTTP/1.x request headers are typically < 8KB).
const HOST_PEEK_BYTES: usize = 8 * 1024;
/// Maximum allowed length of the Host header value (RFC 3986 recommends ≤ 255).
const HOST_MAX_LEN: usize = 255;
/// Client response write-stall tolerance: a single-frame write timeout (client
/// not reading → send buffer full) closes the connection. Pairs with poisoning
/// of the dispatch response direction (channel closed when full) — without this
/// upper bound, the write task would hang forever in `write_all` and the poison
/// signal (channel close) would never be consumed.
const CLIENT_WRITE_STALL_TIMEOUT: Duration = Duration::from_secs(10);

/// Edge public (internet-facing) listener.
pub struct EdgeListener {
    /// Listen address (e.g. `0.0.0.0:8443`).
    pub listen_addr: SocketAddr,
    /// Host route table.
    pub router: Arc<HostRouter>,
    /// Established tunnel (injected by AgentClient; agent_id is usually `edge`).
    pub tunnel: AgentTunnel,
    /// Host peek timeout (slow-loris defense). Defaults to 10s.
    pub host_peek_timeout: Duration,
    /// Stream idle timeout (close when no data flows in either direction).
    /// Configured via CLI `--stream-idle-timeout-secs`, defaults to 300s;
    /// must be ≤ the fronting nginx `proxy_read_timeout`.
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
}

impl EdgeListener {
    /// Binds the listen port and runs the accept loop. Blocks the caller.
    pub async fn run(self) -> std::io::Result<()> {
        let listener = TcpListener::bind(self.listen_addr).await?;
        info!(
            "Edge public listener started: {} ({} routes)",
            self.listen_addr,
            self.router.len()
        );

        let router = self.router;
        let tunnel = self.tunnel;
        let host_peek_timeout = self.host_peek_timeout;
        let stream_idle_timeout = self.stream_idle_timeout;
        let conn_tracker = self.conn_tracker;
        let rate_limiter = self.rate_limiter;
        let audit = self.audit;
        let route_breaker = self.route_breaker;

        loop {
            let (stream, addr) = listener.accept().await?;

            // Per-IP new-connection rate limit (before conn_tracker: prevents
            // attackers from exhausting the ConnTracker map via rapid
            // acquire/release)
            if let Some(limiter) = &rate_limiter
                && !limiter.check(addr.ip())
            {
                metrics::counter!("interflow_edge_conn_rate_limited").increment(1);
                audit.record(
                    AuditKind::StreamDenied {
                        stream_id: String::new(),
                        source: addr.ip().to_string(),
                        reason: "rate_limited".into(),
                    },
                    None,
                    Some(addr.to_string()),
                );
                debug!("edge connection denied (rate limited): {addr}");
                drop(stream);
                continue;
            }

            // Per-IP + global connection cap check
            let Some(guard) = conn_tracker.try_acquire(addr.ip()) else {
                metrics::counter!("interflow_edge_conn_rejected").increment(1);
                audit.record(
                    AuditKind::StreamDenied {
                        stream_id: String::new(),
                        source: addr.ip().to_string(),
                        reason: "conn_limit_exceeded".into(),
                    },
                    None,
                    Some(addr.to_string()),
                );
                debug!("edge connection denied (connection limit): {addr}");
                continue;
            };

            let router = router.clone();
            let tunnel = tunnel.clone();
            let audit = audit.clone();
            let route_breaker = route_breaker.clone();

            tokio::spawn(async move {
                let _guard = guard;
                if let Err(e) = handle_connection(
                    stream,
                    addr,
                    &router,
                    &tunnel,
                    host_peek_timeout,
                    stream_idle_timeout,
                    &audit,
                    route_breaker.as_ref(),
                )
                .await
                {
                    debug!("edge connection finished ({addr}): {e}");
                }
            });
        }
    }
}

/// Handles a single public connection: peek the first bytes for Host → look
/// up the route → (route breaker gate) → open a stream → bidirectional
/// pump → feed the close reason back into the route breaker.
#[allow(clippy::too_many_arguments)]
async fn handle_connection(
    mut socket: TcpStream,
    peer: SocketAddr,
    router: &HostRouter,
    tunnel: &AgentTunnel,
    host_peek_timeout: Duration,
    stream_idle_timeout: Duration,
    audit: &AuditSink,
    route_breaker: Option<&Arc<TargetBreakers>>,
) -> interflow_core::error::Result<()> {
    use interflow_core::error::InterflowError;
    // TCP_NODELAY: disable Nagle to reduce small-packet latency (notable for echo / ping-pong workloads)
    let _ = socket.set_nodelay(true);

    // Read the first bytes into a buffer, accumulating until the Host header
    // is found or the cap is reached. The whole peek phase is bounded by a
    // timeout to defend against slow-loris.
    let mut initial = bytes::BytesMut::with_capacity(HOST_PEEK_BYTES);
    let host = tokio::time::timeout(host_peek_timeout, async {
        let mut tmp = vec![0u8; 4096];
        loop {
            if initial.len() >= HOST_PEEK_BYTES {
                return Err(InterflowError::protocol(format!(
                    "Host header not found within the first {HOST_PEEK_BYTES} bytes"
                )));
            }
            let n = socket.read(&mut tmp).await?;
            if n == 0 {
                return Err(InterflowError::protocol("connection closed early"));
            }
            initial.extend_from_slice(&tmp[..n]);
            match extract_host(&initial) {
                HostParseResult::Found(h) => return Ok(h),
                HostParseResult::Invalid(reason) => {
                    metrics::counter!("interflow_edge_host_invalid").increment(1);
                    return Err(InterflowError::protocol(reason));
                }
                HostParseResult::NotFound => {}
            }
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

    let Some(route) = router.lookup(&host) else {
        // No route matched: close silently, send no 404, do not leak that the edge is alive
        warn!("no route matched host={host} (peer={peer})");
        metrics::counter!("interflow_edge_no_route").increment(1);
        audit.record(
            AuditKind::StreamDenied {
                stream_id: String::new(),
                source: peer.ip().to_string(),
                reason: format!("no_route: {host}"),
            },
            None,
            Some(peer.to_string()),
        );
        return Ok(());
    };

    debug!(
        "edge route hit: {host} → agent={} remote={}",
        route.agent_id, route.remote_addr
    );

    // Route-level breaker gate: a tripped route is closed right here — no
    // register, no Open, no tunnel round trip. Same public behavior as an
    // agent-side rejection (fast zero-byte close; the fronting nginx
    // surfaces 502), but the storm stops at the internet edge.
    if let Some(breaker) = route_breaker
        && breaker.check(&host) == BreakerDecision::Reject
    {
        metrics::counter!("interflow_edge_route_breaker_rejected").increment(1);
        audit.record(
            AuditKind::StreamDenied {
                stream_id: String::new(),
                source: peer.ip().to_string(),
                reason: format!("route_circuit_open: {host}"),
            },
            None,
            Some(peer.to_string()),
        );
        debug!("route circuit open, closing without tunnel open: host={host} peer={peer}");
        return Ok(());
    }

    let stream_id = uuid::Uuid::new_v4().to_string();
    let data_rx = tunnel.register_stream(stream_id.clone()).await;

    let remote_addr_str = route.remote_addr.to_string();
    if let Err(e) = tunnel
        .send_open(
            &stream_id,
            &route.agent_id,
            Some(&remote_addr_str),
            StreamProto::Tcp,
        )
        .await
    {
        tunnel.unregister_stream(&stream_id).await;
        return Err(e);
    }

    // Send the already-read first bytes into the tunnel first (the egress
    // side will use them as the start of the HTTP request).
    if !initial.is_empty() {
        let initial_bytes = initial.split().freeze();
        if let Err(e) = tunnel.send_data(&stream_id, initial_bytes).await {
            tunnel.unregister_stream(&stream_id).await;
            return Err(e);
        }
    }

    // Bidirectional pump (shared implementation, inline future without
    // spawn): when either half exits, the whole stream is closed out and
    // unregistered — if the write half exits first, the read half is
    // cancelled by drop (so a half-open socket cannot linger until the idle
    // timeout); if the read half exits first, unregister first then flush the
    // buffer. The JoinHandle double-poll panic class is structurally excluded
    // (docs/bug/2026-09-13-select-branch-double-await-joinhandle-panic.md).
    //
    // The oneshot captures the peer Close's reason token (empty = no Close
    // observed / ordinary close) to feed the route breaker.
    let (close_reason_tx, close_reason_rx) = if route_breaker.is_some() {
        let (tx, rx) = tokio::sync::oneshot::channel();
        (Some(tx), Some(rx))
    } else {
        (None, None)
    };
    let (rd, wr) = socket.into_split();
    pump_tcp_stream(
        rd,
        wr,
        data_rx,
        tunnel,
        &stream_id,
        &PumpConfig {
            idle_timeout: stream_idle_timeout,
            write_stall_timeout: CLIENT_WRITE_STALL_TIMEOUT,
            idle_timeout_counter: "interflow_edge_stream_idle_timeout",
            write_stall_counter: "interflow_edge_client_write_stall",
            log_label: "edge",
        },
        close_reason_tx,
    )
    .await;

    // Feed the route breaker from the close reason: backend-down tokens
    // count as failures, a normal backend EOF proves reachability (clears a
    // tripped route), everything else (client-side aborts, rate limits,
    // ordinary closes) is neutral.
    if let Some(breaker) = route_breaker
        && let Some(rx) = close_reason_rx
    {
        let reason = rx.await.unwrap_or_default();
        if ROUTE_FAILURE_REASONS.contains(&reason.as_str()) {
            breaker.note_failure(&host);
        } else if ROUTE_SUCCESS_REASONS.contains(&reason.as_str()) {
            breaker.note_success(&host);
        }
    }

    Ok(())
}

/// Host parse result: three states, distinguishing "not found yet" from
/// "definitely invalid".
enum HostParseResult {
    /// A valid Host was found.
    Found(String),
    /// Definitely invalid (duplicate Host, illegal characters, too long) —
    /// reject the whole connection immediately.
    Invalid(&'static str),
    /// Not found yet; keep reading.
    NotFound,
}

/// Extracts the Host header value from the bytes read so far (case-insensitive).
///
/// Binary safe: matching happens only on ASCII bytes and does not require the
/// whole peek buffer to be valid UTF-8. Otherwise requests with binary bodies
/// such as multipart/form-data would contain non-UTF-8 bytes within the first
/// 8KB, making `from_utf8` fail wholesale so the Host is never found and the
/// request eventually hits host_peek_timeout (user-visible symptom: 502).
///
/// Scan range: only the header region; stop immediately at the blank line
/// (`\r\n\r\n` or `\n\n`). Otherwise a binary body might happen to contain a
/// 5-byte sliding-window match like `\nHost: ...\n`, which would be
/// misjudged as duplicate_host and reject a legitimate request.
///
/// Hardening (kept from the original implementation):
/// - Return `Invalid` immediately upon detecting a second Host header (reject the whole connection; prevents header injection/smuggling)
/// - Validate host characters: only `[A-Za-z0-9.\-:()\[\]]` allowed; values with control characters/spaces are rejected
/// - Limit host length to ≤ 255
fn extract_host(buf: &[u8]) -> HostParseResult {
    // Find the end of the header region (first `\r\n\r\n` or `\n\n`); if not
    // found, scan to the end of buf.
    let headers_end = find_headers_end(buf).unwrap_or(buf.len());

    let mut found: Option<String> = None;
    // Search byte-wise for line-leading `Host:` / `host:` etc. (line start =
    // buffer beginning or after \r\n / \n).
    let mut i = 0;
    while i < headers_end {
        // The current line starts at i; find the next CRLF/LF.
        let line_end = buf[i..headers_end]
            .iter()
            .position(|&b| b == b'\n')
            .map_or(headers_end, |p| i + p);
        let line = trim_cr(&buf[i..line_end]);

        if line.len() >= 5 && eq_ignore_ascii_case_bytes(&line[..5], b"host:") {
            // Take the value segment and trim ASCII whitespace from both
            // ends. The value must be valid UTF-8 (hosts are ASCII).
            let value = trim_ascii_whitespace(&line[5..]);
            if value.is_empty() {
                // Empty value: treat as absent and keep looking
            } else if value.len() > HOST_MAX_LEN {
                return HostParseResult::Invalid("host_too_long");
            } else if let Ok(s) = std::str::from_utf8(value) {
                if !is_valid_host(s) {
                    return HostParseResult::Invalid("host_invalid_chars");
                }
                if found.is_some() {
                    return HostParseResult::Invalid("duplicate_host");
                }
                found = Some(s.to_string());
            } else {
                return HostParseResult::Invalid("host_invalid_chars");
            }
        }

        if line_end == headers_end {
            break;
        }
        i = line_end + 1;
    }
    match found {
        Some(h) if !h.is_empty() => HostParseResult::Found(h),
        _ => HostParseResult::NotFound,
    }
}

/// Locates the end of the HTTP/1.x header region (first byte after the blank line).
///
/// Matches the first `\r\n\r\n` or `\n\n`. The return value is the index of
/// the first byte after the header terminator, i.e. the header region is
/// `&buf[..pos]` (excluding the terminator itself). Both orders are scanned
/// byte-wise in a single O(n) pass.
const fn find_headers_end(buf: &[u8]) -> Option<usize> {
    let mut i = 0;
    let n = buf.len();
    while i + 1 < n {
        if buf[i] == b'\n' {
            if buf[i + 1] == b'\n' {
                return Some(i + 2);
            }
            if i + 2 < n && buf[i + 1] == b'\r' && buf[i + 2] == b'\n' {
                return Some(i + 3);
            }
        }
        i += 1;
    }
    None
}

/// Strips a trailing `\r` from the line (CRLF → LF tolerance). No allocation.
fn trim_cr(line: &[u8]) -> &[u8] {
    if line.last() == Some(&b'\r') {
        &line[..line.len() - 1]
    } else {
        line
    }
}

/// Trims ASCII whitespace (space / tab). Other whitespace is not allowed in
/// HTTP header values.
fn trim_ascii_whitespace(s: &[u8]) -> &[u8] {
    let mut start = 0;
    let mut end = s.len();
    while start < end && (s[start] == b' ' || s[start] == b'\t') {
        start += 1;
    }
    while end > start && (s[end - 1] == b' ' || s[end - 1] == b'\t') {
        end -= 1;
    }
    &s[start..end]
}

/// Byte-slice version of `eq_ignore_ascii_case` (avoids converting to str).
fn eq_ignore_ascii_case_bytes(a: &[u8], b: &[u8]) -> bool {
    a.len() == b.len()
        && a.iter()
            .zip(b.iter())
            .all(|(x, y)| x.eq_ignore_ascii_case(y))
}

/// Validates host characters: only letters, digits, dot, hyphen, colon
/// (port), and square brackets (IPv6) are allowed. Hosts containing control
/// characters, spaces, or other separators are rejected outright.
fn is_valid_host(s: &str) -> bool {
    s.chars().all(|c| {
        c.is_ascii_alphanumeric() || c == '.' || c == '-' || c == ':' || c == '[' || c == ']'
    })
}

#[cfg(test)]
#[allow(
    clippy::panic,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::missing_docs_in_private_items
)]
mod tests {
    use super::*;

    #[test]
    fn extract_host_basic() {
        let req = b"GET / HTTP/1.1\r\nHost: myapp.example.com\r\nUser-Agent: x\r\n\r\n";
        assert!(matches!(extract_host(req), HostParseResult::Found(h) if h == "myapp.example.com"));
    }

    #[test]
    fn extract_host_case_insensitive() {
        let req = b"GET / HTTP/1.1\r\nhOsT: myapp.example.com\r\n\r\n";
        assert!(matches!(extract_host(req), HostParseResult::Found(h) if h == "myapp.example.com"));
    }

    #[test]
    fn extract_host_with_port() {
        let req = b"GET / HTTP/1.1\r\nHost: myapp.example.com:8443\r\n\r\n";
        assert!(
            matches!(extract_host(req), HostParseResult::Found(h) if h == "myapp.example.com:8443")
        );
    }

    #[test]
    fn extract_host_missing_returns_notfound() {
        let req = b"GET / HTTP/1.1\r\nUser-Agent: x\r\n\r\n";
        assert!(matches!(extract_host(req), HostParseResult::NotFound));
    }

    #[test]
    fn extract_host_rejects_duplicate() {
        let req = b"GET / HTTP/1.1\r\nHost: a.com\r\nHost: b.com\r\n\r\n";
        assert!(
            matches!(extract_host(req), HostParseResult::Invalid(_)),
            "duplicate Host must be rejected"
        );
    }

    #[test]
    fn extract_host_rejects_invalid_chars() {
        let req = b"GET / HTTP/1.1\r\nHost: evil.com extra\r\n\r\n";
        assert!(matches!(extract_host(req), HostParseResult::Invalid(_)));
    }

    #[test]
    fn extract_host_rejects_too_long() {
        let long = "a".repeat(HOST_MAX_LEN + 1);
        let req = format!("GET / HTTP/1.1\r\nHost: {long}\r\n\r\n");
        assert!(matches!(
            extract_host(req.as_bytes()),
            HostParseResult::Invalid(_)
        ));
    }

    #[test]
    fn extract_host_allows_ipv6() {
        let req = b"GET / HTTP/1.1\r\nHost: [::1]:8443\r\n\r\n";
        assert!(matches!(extract_host(req), HostParseResult::Found(h) if h == "[::1]:8443"));
    }

    #[test]
    fn is_valid_host_basic() {
        assert!(is_valid_host("example.com"));
        assert!(is_valid_host("example.com:8443"));
        assert!(is_valid_host("[::1]:8443"));
        assert!(!is_valid_host("evil.com extra"));
        assert!(!is_valid_host("evil.com\r\nX: y"));
        assert!(!is_valid_host("evil\x00.com"));
    }

    /// Regression: a multipart request whose body contains binary (gzip
    /// bytes) is not valid UTF-8 as a whole. The old implementation
    /// `from_utf8(buf).ok()` failed outright → always `NotFound` → 10s peek
    /// timeout → upstream 502. The new implementation searches for the Host
    /// header byte-wise and correctly recognizes the Host even in a buffer
    /// containing a binary body.
    #[test]
    fn extract_host_with_binary_body() {
        let mut req = b"POST /v1/workers/x/builds HTTP/1.1\r\n\
Host: fetch.example.com\r\n\
Content-Type: multipart/form-data; boundary=---x\r\n\
Content-Length: 1102\r\n\
\r\n\
-----x\r\n\
Content-Disposition: form-data; name=\"file\"; filename=\"a.tar.gz\"\r\n\
\r\n"
            .to_vec();
        // Inject non-UTF-8 bytes (gzip magic followed by some continuation bytes).
        req.extend_from_slice(&[0x1f, 0x8b, 0x80, 0xc0, 0xff, 0xfe, 0x00, 0x7f]);
        req.extend_from_slice(b"\r\n-----x--\r\n");
        assert!(matches!(
            extract_host(&req),
            HostParseResult::Found(h) if h == "fetch.example.com"
        ));
    }

    /// Regression: non-UTF-8 bytes are also tolerated between HTTP headers
    /// (theoretically they shouldn't occur, but once the peek buffer has read
    /// into the body we must not give up on the Host just because the body
    /// isn't UTF-8).
    #[test]
    fn extract_host_finds_first_host_then_keeps_scanning() {
        let mut req = b"GET / HTTP/1.1\r\nHost: a.example.com\r\n\r\n".to_vec();
        // Headers ended; the body is arbitrary binary.
        req.extend_from_slice(&[0xff, 0xfe, 0xfd, 0x00, 0x01]);
        assert!(matches!(
            extract_host(&req),
            HostParseResult::Found(h) if h == "a.example.com"
        ));
    }

    #[test]
    fn extract_host_rejects_invalid_utf8_value() {
        // The Host header name is ASCII, but the value has non-ASCII bytes
        // mixed in: must be judged Invalid.
        let req = b"GET / HTTP/1.1\r\nHost: ev\xffel.com\r\n\r\n";
        assert!(matches!(extract_host(req), HostParseResult::Invalid(_)));
    }

    /// Regression: if the body region after the header terminator in the
    /// peek buffer happens to contain a 5-byte sliding-window match like
    /// `\nHost: ...\n`, it must never be misjudged as duplicate_host. Scanning
    /// must stop at the first blank line.
    #[test]
    fn extract_host_ignores_host_like_pattern_in_body() {
        let mut req = b"POST /x HTTP/1.1\r\n\
Host: real.example.com\r\n\
Content-Type: application/octet-stream\r\n\
Content-Length: 100\r\n\
\r\n"
            .to_vec();
        // Stuff a byte sequence into the body that looks like a second Host
        // header; it must be ignored.
        req.extend_from_slice(b"\nHost: fake.example.com\r\n");
        req.extend_from_slice(&[0xff; 80]);
        assert!(matches!(
            extract_host(&req),
            HostParseResult::Found(h) if h == "real.example.com"
        ));
    }

    /// Regression: an LF-only header terminator (`\n\n`) must also be recognized.
    #[test]
    fn extract_host_stops_at_lf_only_header_end() {
        let req = b"GET / HTTP/1.1\nHost: real.example.com\n\nHost: fake.example.com\n";
        assert!(matches!(
            extract_host(req),
            HostParseResult::Found(h) if h == "real.example.com"
        ));
    }
}
