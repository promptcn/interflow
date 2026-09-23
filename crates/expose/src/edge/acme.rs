//! Public-HTTPS termination via ACME (the ingress's default product path).
//!
//! Runtime shape: rustls-acme's low-level tokio API —
//! - one background event loop drives orders, renewals, and the cert cache;
//! - **TLS-ALPN-01** rides the public :443 listener (a `LazyConfigAcceptor`
//!   sniffs the ACME ALPN and hands challenge connections the challenge
//!   config, everything else the live-cert config);
//! - **HTTP-01** plus the HTTP→HTTPS redirect ride a dedicated :80 listener.

use futures::StreamExt;
use interflow_core::error::{InterflowError, Result};
use interflow_core::security::{AuditSink, AuthRateLimiter, ConnTracker};
use rustls_acme::caches::DirCache;
use std::collections::HashSet;
use std::io;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio_rustls::rustls::ServerConfig;
use tracing::{error, info, warn};

use super::listener::{ConnAdmission, gate_connection, write_deny_response};
use super::{HOST_MAX_LEN, HTTP_HEAD_MAX_BYTES, is_valid_host};

/// The default public-HTTPS ACME directory (Let's Encrypt production).
pub const LETS_ENCRYPT_PRODUCTION: &str = "https://acme-v02.api.letsencrypt.org/directory";

/// ACME runtime options (from the signed manifest via the pack).
#[derive(Debug, Clone)]
pub struct AcmeOptions {
    /// Route hosts (the certificate SAN set).
    pub hosts: Vec<String>,
    /// Account contact email (required for production directories).
    pub email: String,
    /// ACME directory URL; `None` = Let's Encrypt production.
    pub directory: Option<String>,
    /// Trust anchor for the directory's own HTTPS certificate (private /
    /// test ACME CAs; `None` = the built-in WebPKI roots).
    pub directory_ca: Option<PathBuf>,
    /// Persistent cert/account cache (inside the pack's state directory).
    pub cache_dir: PathBuf,
    /// The HTTP-01 + redirect listener address (the public listener's IP,
    /// port 80).
    pub http_listen: SocketAddr,
}

/// A running ACME runtime.
///
/// Holds the live-cert server config for the public listener plus the
/// background tasks it owns (the order/renewal event loop and the HTTP-01
/// :80 listener). Both stop — and the listener releases its port — when
/// [`AcmeRuntime::shutdown`] cancels the token.
pub struct AcmeRuntime {
    default_config: Arc<ServerConfig>,
    challenge_config: Arc<ServerConfig>,
    host_allowlist: Arc<HashSet<String>>,
    shutdown_token: tokio_util::sync::CancellationToken,
}

impl AcmeRuntime {
    /// The server config for ordinary TLS handshakes (the live certificate;
    /// swapped by the renewal loop).
    pub fn default_config(&self) -> Arc<ServerConfig> {
        Arc::clone(&self.default_config)
    }

    /// The server config for TLS-ALPN-01 challenge handshakes.
    pub fn challenge_config(&self) -> Arc<ServerConfig> {
        Arc::clone(&self.challenge_config)
    }

    /// The normalized certificate/route host set backing the public
    /// listener's SNI allowlist pre-check.
    pub fn host_allowlist(&self) -> Arc<HashSet<String>> {
        Arc::clone(&self.host_allowlist)
    }

    /// Stops the event loop and the HTTP-01 listener. Idempotent; in-flight
    /// challenge connections finish on their own deadlines.
    pub fn shutdown(&self) {
        self.shutdown_token.cancel();
    }
}

/// Connection governance for the :80 face — the SAME tracker, rate limiter
/// and audit the public :443 listener applies (one shared budget across both
/// public ports, keyed on the TCP peer IP; the :80 face has no PROXY/XFF
/// front, so the peer IP is the client IP).
pub(crate) struct AcmeConnGovernance {
    pub(crate) conn_tracker: Arc<ConnTracker>,
    pub(crate) rate_limiter: Option<Arc<AuthRateLimiter>>,
    pub(crate) audit: AuditSink,
}

/// Spawns the ACME runtime: the order/renewal event loop, the TLS-ALPN-01
/// resolver, and the HTTP-01 + redirect listener. The returned handle feeds
/// the public listener's accept path.
pub(crate) fn spawn(
    options: &AcmeOptions,
    public_https_port: u16,
    node: &str,
    governance: AcmeConnGovernance,
) -> Result<AcmeRuntime> {
    if options.hosts.is_empty() {
        return Err(InterflowError::config(
            "acme mode requires at least one route host",
        ));
    }
    let production = options
        .directory
        .as_deref()
        .is_none_or(|url| url == LETS_ENCRYPT_PRODUCTION);
    if production && options.email.trim().is_empty() {
        return Err(InterflowError::config(
            "acme mode against a production directory requires a contact email \
             ([public_tls] email)",
        ));
    }
    let allowed_hosts = Arc::new(build_host_allowlist(&options.hosts)?);
    // The same normalized set also backs the public listener's SNI pre-check.
    let host_allowlist = Arc::clone(&allowed_hosts);

    let config = rustls_acme::AcmeConfig::new(options.hosts.clone())
        .contact([format!("mailto:{}", options.email)])
        .cache_option(Some(DirCache::new(options.cache_dir.clone())));
    let config = match options.directory.as_deref() {
        Some(url) => config.directory(url),
        None => config.directory_lets_encrypt(true),
    };
    let config = match &options.directory_ca {
        Some(path) => config.client_tls_config(directory_client_config(path)?),
        None => config,
    };
    let mut state = config.state();
    let challenge_config = state.challenge_rustls_config();
    let default_config = state.default_rustls_config();
    let resolver = state.resolver();
    let shutdown_token = tokio_util::sync::CancellationToken::new();

    // Order / renewal / cache event loop: logs every transition; failures
    // back off inside rustls-acme (renewal retries with exponential delay).
    let event_shutdown = shutdown_token.clone();
    let node_owned = node.to_string();
    tokio::spawn(async move {
        loop {
            let event = tokio::select! {
                () = event_shutdown.cancelled() => return,
                event = state.next() => event,
            };
            match event {
                Some(Ok(event)) => info!(node = %node_owned, "acme event: {event:?}"),
                Some(Err(event)) => {
                    warn!(node = %node_owned, "acme event (backoff/retry): {event:?}")
                }
                None => {
                    error!(node = %node_owned, "acme event loop terminated unexpectedly");
                    return;
                }
            }
        }
    });

    // HTTP-01 challenge answers + permanent redirect to HTTPS. The accept
    // loop runs the same per-IP gate as the :443 listener BEFORE spawning a
    // task: a denied peer costs one accept, no task; rejections reuse the
    // shared rejection counters and audit records. The whole task — bind
    // included — is cancellation-aware: a stopped runtime must release :80.
    let http_listen = options.http_listen;
    let http01_config = Http01Config {
        allowed_hosts,
        public_https_port,
    };
    let http_shutdown = shutdown_token.clone();
    let node_owned = node.to_string();
    tokio::spawn(async move {
        let listener = match tokio::select! {
            () = http_shutdown.cancelled() => return,
            bind = tokio::net::TcpListener::bind(http_listen) => bind,
        } {
            Ok(listener) => listener,
            Err(e) => {
                error!(
                    node = %node_owned,
                    "acme http listener bind {http_listen} failed: {e} — HTTP-01 and the https redirect are unavailable"
                );
                return;
            }
        };
        info!(node = %node_owned, "acme http listener started: {http_listen} (HTTP-01 + redirect)");
        loop {
            let (mut stream, peer) = tokio::select! {
                () = http_shutdown.cancelled() => return,
                accepted = listener.accept() => match accepted {
                    Ok(pair) => pair,
                    Err(_) => return,
                },
            };
            // :80 is a direct plaintext listener — no PROXY/XFF face — so the
            // gate keys on the TCP peer IP. A denial is answered with a real
            // status (the face speaks HTTP; the write is one small bounded
            // buffer on a fresh socket, so the accept loop never parks).
            match gate_connection(
                &node_owned,
                peer.ip(),
                peer,
                &governance.audit,
                governance.rate_limiter.as_ref(),
                &governance.conn_tracker,
            ) {
                ConnAdmission::Admitted(guard) => {
                    let resolver = Arc::clone(&resolver);
                    let http01_config = http01_config.clone();
                    let node = node_owned.clone();
                    tokio::spawn(async move {
                        let _guard = guard; // hold the slot for the connection's lifetime
                        if let Err(e) = serve_http01(&mut stream, &resolver, &http01_config).await {
                            warn!(node = %node, "acme http connection failed: {e}");
                        }
                    });
                }
                ConnAdmission::Denied(kind) => {
                    write_deny_response(&mut stream, kind).await;
                }
            }
        }
    });

    Ok(AcmeRuntime {
        default_config,
        challenge_config,
        host_allowlist,
        shutdown_token,
    })
}

/// A rustls client config trusting `path` as the directory server's root
/// (private / test ACME CAs whose HTTPS certificate is not WebPKI-anchored).
fn directory_client_config(
    path: &std::path::Path,
) -> Result<std::sync::Arc<tokio_rustls::rustls::ClientConfig>> {
    let pem = std::fs::read(path).map_err(|e| {
        InterflowError::config(format!(
            "acme directory CA read failed ({})",
            path.display()
        ))
        .with_source(e)
    })?;
    let mut roots = tokio_rustls::rustls::RootCertStore::empty();
    for cert in rustls_pemfile::certs(&mut &pem[..]) {
        let cert = cert
            .map_err(|e| InterflowError::config("acme directory CA parse failed").with_source(e))?;
        roots
            .add(cert)
            .map_err(|e| InterflowError::config("acme directory CA rejected").with_source(e))?;
    }
    Ok(std::sync::Arc::new(
        tokio_rustls::rustls::ClientConfig::builder()
            .with_root_certificates(roots)
            .with_no_client_auth(),
    ))
}

/// Overall budget for receiving the HTTP/1.x request head.
const HTTP01_HEAD_TIMEOUT: Duration = Duration::from_secs(10);

/// Size of each incremental read while waiting for a complete request head.
const HTTP01_READ_CHUNK: usize = 4096;

/// Immutable policy shared by every :80 connection.
#[derive(Clone)]
struct Http01Config {
    /// Hosts normalized from the ACME certificate/route set.
    allowed_hosts: Arc<HashSet<String>>,
    /// Public HTTPS port used to construct the redirect authority.
    public_https_port: u16,
}

/// The subset of an HTTP request needed by HTTP-01 and redirect handling.
struct Http01Request {
    method: String,
    target: String,
    host: String,
}

/// Result of attempting to parse the bytes buffered so far.
enum Http01ParseResult {
    /// More bytes may complete the request head.
    Partial,
    /// The request head is structurally and semantically valid.
    Complete(Http01Request),
    /// The request is definitely invalid.
    Invalid(&'static str),
}

/// Read failures, including whether an HTTP response is safe and useful.
#[derive(Debug)]
enum Http01ReadFailure {
    /// Close silently (timeout, EOF, or transport error).
    Close(&'static str),
    /// Reply `400` and close.
    BadRequest(&'static str),
    /// Reply `431` and close.
    HeadTooLarge,
}

/// One :80 connection: answer `/.well-known/acme-challenge/<token>` or
/// redirect everything else to the configured HTTPS authority.
async fn serve_http01(
    stream: &mut tokio::net::TcpStream,
    resolver: &Arc<rustls_acme::ResolvesServerCertAcme>,
    config: &Http01Config,
) -> io::Result<()> {
    let _ = stream.set_nodelay(true);
    serve_http01_stream(stream, |token| resolver.get_http_01_key_auth(token), config).await
}

/// Transport-independent HTTP-01 handler, separated for duplex-based tests.
async fn serve_http01_stream<S, F>(
    stream: &mut S,
    lookup_key_auth: F,
    config: &Http01Config,
) -> io::Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin,
    F: FnOnce(&str) -> Option<String> + Send,
{
    match read_http01_head(stream).await {
        Ok(request) => write_http01_response(stream, request, lookup_key_auth, config).await,
        Err(Http01ReadFailure::Close(reason)) => {
            reject_http01(reason);
            Ok(())
        }
        Err(Http01ReadFailure::BadRequest(reason)) => {
            reject_http01(reason);
            write_empty_response(stream, 400, "Bad Request").await
        }
        Err(Http01ReadFailure::HeadTooLarge) => {
            reject_http01("head_too_large");
            write_empty_response(stream, 431, "Request Header Fields Too Large").await
        }
    }
}

/// Reads until `httparse` reports a complete head, the global budget expires,
/// or an unambiguous violation is found.
async fn read_http01_head<S>(
    stream: &mut S,
) -> std::result::Result<Http01Request, Http01ReadFailure>
where
    S: AsyncRead + Unpin,
{
    let read = tokio::time::timeout(HTTP01_HEAD_TIMEOUT, async {
        let mut head = Vec::new();
        let mut chunk = [0u8; HTTP01_READ_CHUNK];
        loop {
            match parse_http01_head(&head) {
                Http01ParseResult::Complete(request) => return Ok(request),
                Http01ParseResult::Invalid(reason) => {
                    return Err(Http01ReadFailure::BadRequest(reason));
                }
                Http01ParseResult::Partial => {}
            }
            if head.len() >= HTTP_HEAD_MAX_BYTES {
                return Err(Http01ReadFailure::HeadTooLarge);
            }
            let n = stream
                .read(&mut chunk)
                .await
                .map_err(|_| Http01ReadFailure::Close("io_error"))?;
            if n == 0 {
                return Err(Http01ReadFailure::Close("incomplete_head"));
            }
            head.extend_from_slice(&chunk[..n]);
        }
    })
    .await;

    match read {
        Ok(result) => result,
        Err(_) => Err(Http01ReadFailure::Close("head_timeout")),
    }
}

/// Parses one buffered request head via the shared core parser (httparse
/// syntax + the Host policy this path originally defined: duplicate-Host,
/// charset, length). Only the ACME-specific target rule stays local.
fn parse_http01_head(buf: &[u8]) -> Http01ParseResult {
    use interflow_core::security::http_head::{self, HeadParse};
    let head = match http_head::parse_request_head(buf) {
        HeadParse::Partial => return Http01ParseResult::Partial,
        HeadParse::Invalid(reason) => return Http01ParseResult::Invalid(reason.as_str()),
        HeadParse::Complete(head) => head,
    };
    if !is_valid_redirect_target(head.target) {
        return Http01ParseResult::Invalid("invalid_target");
    }
    match http_head::validated_host(&head.headers) {
        Ok(host) => Http01ParseResult::Complete(Http01Request {
            method: head.method.to_owned(),
            target: head.target.to_owned(),
            host: host.to_owned(),
        }),
        Err(e) => Http01ParseResult::Invalid(e.as_str()),
    }
}

/// Writes either a challenge answer or a canonical HTTPS redirect.
async fn write_http01_response<S, F>(
    stream: &mut S,
    request: Http01Request,
    lookup_key_auth: F,
    config: &Http01Config,
) -> io::Result<()>
where
    S: AsyncWrite + Unpin,
    F: FnOnce(&str) -> Option<String>,
{
    let Some(host) = canonical_host(&request.host) else {
        reject_http01("host_invalid_chars");
        return write_empty_response(stream, 400, "Bad Request").await;
    };
    if !config.allowed_hosts.contains(&host) {
        reject_http01("host_unknown");
        return write_empty_response(stream, 421, "Misdirected Host").await;
    }

    if request.method == "GET"
        && let Some(token) = challenge_token(&request.target)
        && let Some(key_auth) = lookup_key_auth(token)
    {
        return stream
            .write_all(
                format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: application/octet-stream\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{key_auth}",
                    key_auth.len()
                )
                .as_bytes(),
            )
            .await;
    }

    let status = if request.method == "GET" || request.method == "HEAD" {
        (301, "Moved Permanently")
    } else {
        (308, "Permanent Redirect")
    };
    let authority = https_authority(&host, config.public_https_port);
    let response = format!(
        "HTTP/1.1 {} {}\r\nLocation: https://{authority}{target}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
        status.0,
        status.1,
        target = request.target
    );
    stream.write_all(response.as_bytes()).await
}

/// Writes a fixed, bodyless HTTP status response.
async fn write_empty_response<S>(stream: &mut S, code: u16, reason: &str) -> io::Result<()>
where
    S: AsyncWrite + Unpin,
{
    stream
        .write_all(
            format!("HTTP/1.1 {code} {reason}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
                .as_bytes(),
        )
        .await
}

/// Counts rejected :80 requests by a stable reason label.
fn reject_http01(reason: &'static str) {
    metrics::counter!("interflow_edge_acme_http01_rejected_total", "reason" => reason).increment(1);
}

/// Normalizes the configured certificate/route host set once at startup.
fn build_host_allowlist(hosts: &[String]) -> Result<HashSet<String>> {
    let mut allowlist = HashSet::with_capacity(hosts.len());
    for host in hosts {
        let canonical = canonical_host(host).ok_or_else(|| {
            InterflowError::config(format!("ACME route host {host:?} is not a valid authority"))
        })?;
        if !allowlist.insert(canonical.clone()) {
            return Err(InterflowError::config(format!(
                "duplicate normalized ACME route host: {canonical}"
            )));
        }
    }
    Ok(allowlist)
}

/// Canonicalizes an HTTP authority by removing an optional valid port and
/// lowercasing the host. Unlike a blind `rsplit_once(':')`, this preserves
/// bracketed IPv6 literals.
fn canonical_host(authority: &str) -> Option<String> {
    if authority.len() > HOST_MAX_LEN || !is_valid_host(authority) {
        return None;
    }
    let host = host_without_port(authority)?;
    if host.is_empty() || !is_valid_host(host) {
        return None;
    }
    Some(host.to_ascii_lowercase())
}

/// Removes a syntactically valid optional port from an HTTP authority.
fn host_without_port(authority: &str) -> Option<&str> {
    if authority.starts_with('[') {
        let close = authority.find(']')?;
        let host = &authority[..=close];
        let suffix = &authority[close + 1..];
        if suffix.is_empty() {
            return Some(host);
        }
        let port = suffix.strip_prefix(':')?;
        port.parse::<u16>().ok()?;
        Some(host)
    } else {
        match authority.rsplit_once(':') {
            Some((host, port)) if !host.contains(':') => {
                port.parse::<u16>().ok()?;
                Some(host)
            }
            _ if !authority.contains(':') => Some(authority),
            _ => None,
        }
    }
}

/// Constructs an HTTPS authority, omitting the default HTTPS port.
fn https_authority(host: &str, port: u16) -> String {
    if port == 443 {
        host.to_owned()
    } else {
        format!("{host}:{port}")
    }
}

/// Accepts only origin-form targets that are safe to reflect in `Location`.
fn is_valid_redirect_target(target: &str) -> bool {
    target.starts_with('/')
        && !target.starts_with("//")
        && !target.contains(['#', '\\'])
        && target.bytes().all(|b| b.is_ascii_graphic())
}

/// Extracts the exact base64url token from the HTTP-01 well-known path.
fn challenge_token(target: &str) -> Option<&str> {
    let path = target.split('?').next().unwrap_or(target);
    let token = path.strip_prefix("/.well-known/acme-challenge/")?;
    (!token.is_empty()
        && !token.contains('/')
        && token
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_'))
    .then_some(token)
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
    use interflow_core::security::http_head::MAX_HEAD_HEADERS;
    use interflow_testkit::metrics_harness::counter_value;
    use std::fmt::Write;
    use tokio::io::{AsyncReadExt, AsyncWriteExt, duplex};

    fn parse_invalid(input: &[u8]) -> &'static str {
        match parse_http01_head(input) {
            Http01ParseResult::Invalid(reason) => reason,
            Http01ParseResult::Complete(_) => panic!("request should be rejected"),
            Http01ParseResult::Partial => panic!("complete malformed request parsed as partial"),
        }
    }

    fn test_config(hosts: &[&str], public_https_port: u16) -> Http01Config {
        Http01Config {
            allowed_hosts: Arc::new(
                hosts
                    .iter()
                    .map(|host| canonical_host(host).unwrap())
                    .collect::<HashSet<_>>(),
            ),
            public_https_port,
        }
    }

    async fn exchange<F>(input: &[u8], config: Http01Config, lookup_key_auth: F) -> Vec<u8>
    where
        F: FnOnce(&str) -> Option<String> + Send + 'static,
    {
        let (mut client, mut server) = duplex(64 * 1024);
        let server_task = tokio::spawn(async move {
            serve_http01_stream(&mut server, lookup_key_auth, &config)
                .await
                .unwrap();
        });
        client.write_all(input).await.unwrap();
        let mut response = Vec::new();
        client.read_to_end(&mut response).await.unwrap();
        server_task.await.unwrap();
        response
    }

    fn response_head(response: &[u8]) -> String {
        let text = String::from_utf8_lossy(response);
        text.split_once("\r\n\r\n").unwrap().0.to_owned()
    }

    fn response_body(response: &[u8]) -> &[u8] {
        let separator = response
            .windows(4)
            .position(|window| window == b"\r\n\r\n")
            .unwrap();
        &response[separator + 4..]
    }

    fn header_value(response: &[u8], name: &str) -> String {
        let head = response_head(response);
        head.lines()
            .skip(1)
            .find_map(|line| {
                let (header_name, value) = line.split_once(':')?;
                header_name
                    .trim()
                    .eq_ignore_ascii_case(name)
                    .then(|| value.trim())
            })
            .unwrap()
            .to_owned()
    }

    #[test]
    fn parser_rejects_host_injection_and_invalid_hosts() {
        let cases: &[(&[u8], &str)] = &[
            (
                b"GET / HTTP/1.1\r\nHost: good.com\revil.com\r\n\r\n",
                "malformed_request",
            ),
            (
                b"GET / HTTP/1.1\r\nHost: good.com\r\nHost: evil.com\r\n\r\n",
                "duplicate_host",
            ),
            (b"GET / HTTP/1.1\r\nUser-Agent: x\r\n\r\n", "missing_host"),
            (
                b"GET / HTTP/1.1\r\nHost: \xff\r\n\r\n",
                "host_invalid_chars",
            ),
            (
                b"GET / HTTP/1.1\r\nHost: evil.com extra\r\n\r\n",
                "host_invalid_chars",
            ),
        ];
        for (input, expected) in cases {
            assert_eq!(parse_invalid(input), *expected);
        }

        let long_host = "a".repeat(HOST_MAX_LEN + 1);
        let request = format!("GET / HTTP/1.1\r\nHost: {long_host}\r\n\r\n");
        assert_eq!(parse_invalid(request.as_bytes()), "host_too_long");
    }

    #[test]
    fn parser_rejects_invalid_targets_and_too_many_headers() {
        let targets = [
            "http://evil.example",
            "//evil.example",
            "/path#fragment",
            "/path\\evil",
            "/path script",
        ];
        for target in targets {
            let request = format!("GET {target} HTTP/1.1\r\nHost: a.com\r\n\r\n");
            assert_eq!(
                parse_invalid(request.as_bytes()),
                if target == "/path script" {
                    "malformed_request"
                } else {
                    "invalid_target"
                }
            );
        }

        let request = b"GET /x\ry HTTP/1.1\r\nHost: a.com\r\n\r\n";
        assert_eq!(parse_invalid(request), "malformed_request");

        let mut too_many_headers = String::from("GET / HTTP/1.1\r\nHost: a.com\r\n");
        for i in 0..=MAX_HEAD_HEADERS {
            let _ = write!(too_many_headers, "X-Test-{i}: v\r\n");
        }
        too_many_headers.push_str("\r\n");
        assert_eq!(
            parse_invalid(too_many_headers.as_bytes()),
            "too_many_headers"
        );
    }

    #[test]
    fn parser_accepts_valid_requests_and_normalizes_authorities() {
        let request = b"GET /path?a=1&b=%2F HTTP/1.1\r\nhOsT: EXAMPLE.com:80\r\n\r\n";
        let Http01ParseResult::Complete(parsed) = parse_http01_head(request) else {
            panic!("valid request should parse");
        };
        assert_eq!(parsed.method, "GET");
        assert_eq!(parsed.target, "/path?a=1&b=%2F");
        assert_eq!(parsed.host, "EXAMPLE.com:80");

        assert_eq!(
            canonical_host("[2001:DB8::1]:8443").as_deref(),
            Some("[2001:db8::1]")
        );
        assert_eq!(
            canonical_host("EXAMPLE.com:80").as_deref(),
            Some("example.com")
        );
        assert_eq!(canonical_host("2001:db8::1"), None);
        assert_eq!(canonical_host("example.com:bad"), None);
    }

    #[test]
    fn allowlist_rejects_duplicate_normalized_hosts() {
        let hosts = vec!["Example.com".to_owned(), "example.com:443".to_owned()];
        assert!(build_host_allowlist(&hosts).is_err());
    }

    #[test]
    fn challenge_token_requires_exact_base64url_segment() {
        assert_eq!(
            challenge_token("/.well-known/acme-challenge/token-_?x=1"),
            Some("token-_")
        );
        assert_eq!(challenge_token("/.well-known/acme-challenge/"), None);
        assert_eq!(challenge_token("/.well-known/acme-challenge/a/b"), None);
        assert_eq!(challenge_token("/.well-known/acme-challenge/a b"), None);
    }

    #[tokio::test]
    async fn read_head_waits_for_segmented_request() {
        let (mut client, mut server) = duplex(4096);
        let read_task = tokio::spawn(async move { read_http01_head(&mut server).await });
        client
            .write_all(b"GET /delayed HTTP/1.1\r\nHost:")
            .await
            .unwrap();
        tokio::time::sleep(Duration::from_millis(10)).await;
        client.write_all(b" example.com\r\n\r\n").await.unwrap();

        let request = read_task.await.unwrap().unwrap();
        assert_eq!(request.method, "GET");
        assert_eq!(request.target, "/delayed");
        assert_eq!(request.host, "example.com");
    }

    #[tokio::test]
    async fn http01_network_behavior_is_fail_closed_and_canonical() {
        let malformed = exchange(
            b"GET / HTTP/1.1\r\nHost: good.com\revil.com\r\n\r\n",
            test_config(&["good.com"], 443),
            |_| None,
        )
        .await;
        assert!(response_head(&malformed).starts_with("HTTP/1.1 400 Bad Request"));
        assert_eq!(header_value(&malformed, "Content-Length"), "0");

        let unknown = exchange(
            b"GET / HTTP/1.1\r\nHost: other.com\r\n\r\n",
            test_config(&["good.com"], 443),
            |_| None,
        )
        .await;
        assert!(response_head(&unknown).starts_with("HTTP/1.1 421 Misdirected Host"));

        let unknown_challenge = exchange(
            b"GET /.well-known/acme-challenge/token HTTP/1.1\r\nHost: other.com\r\n\r\n",
            test_config(&["good.com"], 443),
            |_| Some("must-not-leak".to_owned()),
        )
        .await;
        assert!(response_head(&unknown_challenge).starts_with("HTTP/1.1 421 Misdirected Host"));

        let challenge = exchange(
            b"GET /.well-known/acme-challenge/token?x=1 HTTP/1.1\r\nHost: GOOD.com:80\r\n\r\n",
            test_config(&["good.com"], 443),
            |token| {
                assert_eq!(token, "token");
                Some("key-auth".to_owned())
            },
        )
        .await;
        assert!(response_head(&challenge).starts_with("HTTP/1.1 200 OK"));
        assert_eq!(
            header_value(&challenge, "Content-Type"),
            "application/octet-stream"
        );
        assert_eq!(header_value(&challenge, "Content-Length"), "8");
        assert_eq!(response_body(&challenge), b"key-auth");

        let get_redirect = exchange(
            b"GET /path?a=1&b=%2F HTTP/1.1\r\nHost: GOOD.com:80\r\n\r\n",
            test_config(&["good.com"], 443),
            |_| None,
        )
        .await;
        assert!(response_head(&get_redirect).starts_with("HTTP/1.1 301 Moved Permanently"));
        assert_eq!(
            header_value(&get_redirect, "Location"),
            "https://good.com/path?a=1&b=%2F"
        );
        assert_eq!(header_value(&get_redirect, "Content-Length"), "0");
        assert!(response_body(&get_redirect).is_empty());

        let head_redirect = exchange(
            b"HEAD / HTTP/1.1\r\nHost: good.com\r\n\r\n",
            test_config(&["good.com"], 443),
            |_| None,
        )
        .await;
        assert!(response_head(&head_redirect).starts_with("HTTP/1.1 301 Moved Permanently"));
        assert!(response_body(&head_redirect).is_empty());

        let post_redirect = exchange(
            b"POST /submit?a=1 HTTP/1.1\r\nHost: [2001:db8::1]:80\r\n\r\n",
            test_config(&["[2001:db8::1]"], 8443),
            |_| None,
        )
        .await;
        assert!(response_head(&post_redirect).starts_with("HTTP/1.1 308 Permanent Redirect"));
        assert_eq!(
            header_value(&post_redirect, "Location"),
            "https://[2001:db8::1]:8443/submit?a=1"
        );
        assert!(response_body(&post_redirect).is_empty());

        let before = counter_value("interflow_edge_acme_http01_rejected_total");
        let oversized = vec![b'X'; HTTP_HEAD_MAX_BYTES + 1];
        let oversized = exchange(&oversized, test_config(&["good.com"], 443), |_| None).await;
        assert!(response_head(&oversized).starts_with("HTTP/1.1 431"));
        assert!(
            counter_value("interflow_edge_acme_http01_rejected_total") > before,
            "head-limit rejection should increment the rejection metric"
        );
    }
}
