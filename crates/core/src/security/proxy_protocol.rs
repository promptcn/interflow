//! PROXY protocol negotiation (v1 + v2): restore the real client IP behind
//! a PROXY-capable front (LB / nginx stream).
//!
//! In the nginx-fronted topology both the edge public listener and the hub
//! agent plane see every connection arriving from 127.0.0.1 — per-IP rate
//! limits, per-IP connection caps and audit records all key on the proxy
//! instead of the client. This module negotiates the PROXY protocol
//! preamble under a strict fail-closed trust matrix. Note: the standard
//! nginx **HTTP** `proxy_pass` leg cannot emit the PROXY protocol (that
//! directive exists only in the stream module) — that topology uses the
//! sibling `forwarded_for` module instead:
//!
//! | Source                                    | Behavior                                            |
//! |---|---|
//! | trusted proxy + v2 header                 | real IP used for limiting / caps / audit / metrics  |
//! | trusted proxy + v1 header (strict form)   | same as v2 — stock nginx emits v1                   |
//! | trusted proxy, no header, `required`      | connection rejected                                |
//! | **untrusted source + PROXY signature (either version)** | **hard reject** (anti-spoof)       |
//! | untrusted source, plain bytes             | direct mode, the TCP peer is the real client        |
//!
//! The derived IP is used for **resource governance and audit only** — never
//! for identity or ACL decisions (identity is exclusively mTLS, RFC
//! `(internal design notes)` §5.2).
//!
//! Parsing is delegated to the `ppp` crate (the ecosystem's de-facto
//! standard; single dependency `thiserror`) for **both** versions — one
//! audited grammar, not a hand-rolled twin. Version 1 (text) headers are
//! accepted **only from explicitly trusted proxy sources**: stock nginx
//! (the stream fragment's `proxy_protocol on;`) emits v1, while an
//! untrusted emission stays a hard spoofing rejection. Our framing bounds
//! the v1 parse surface before ppp sees it: one CRLF-terminated line of at
//! most [`V1_MAX`] bytes, malformed → fail-closed.
//!
//! The read stops exactly at each version's boundary (v2 self-describes its
//! length; v1 ends at the CRLF), so a proxied connection never over-reads
//! into payload bytes. A *direct* connection over-reads at most 12 bytes,
//! returned in [`ProxyOutcome::Direct::read_back`] for replay (see
//! [`PrefixedStream`]).

use crate::error::{InterflowError, Result};
use ipnetwork::IpNetwork;
use serde::{Deserialize, Serialize};
use std::io;
use std::net::IpAddr;
use std::pin::Pin;
use std::task::{Context, Poll};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, ReadBuf};

/// PROXY protocol v2 signature (12 bytes): `\r\n\r\n\0\r\nQUIT\n`.
pub const V2_SIGNATURE: [u8; 12] = [
    0x0d, 0x0a, 0x0d, 0x0a, 0x00, 0x0d, 0x0a, 0x51, 0x55, 0x49, 0x54, 0x0a,
];
/// v1 (text) preamble prefix — accepted from trusted proxies only; an
/// untrusted emission of it is a hard spoofing rejection.
const V1_PREFIX: &[u8; 6] = b"PROXY ";
/// Total v1 (text) header cap including the trailing CRLF (spec limit: the
/// longest well-formed `PROXY TCP6 …` line is 107 bytes). Bounds the text
/// parse surface; anything longer is not a header we are willing to buffer.
const V1_MAX: usize = 108;
/// v2 fixed part: 12-byte signature + ver/cmd + fam/proto + u16 length.
const V2_FIXED: usize = 16;
/// Total header cap. A v2 header without TLVs is 16–36 bytes; our nginx sends
/// none. Anything larger is not a header we are willing to buffer.
const V2_MAX: usize = 1024;

/// Whether PROXY protocol is expected on a listener.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ProxyProtocolMode {
    /// Disabled: the TCP peer is the real client.
    #[default]
    Off,
    /// Accept the header from trusted proxies; plain connections also pass.
    On,
    /// Trusted proxies must send the header; anything else is rejected.
    Required,
}

impl std::str::FromStr for ProxyProtocolMode {
    type Err = String;

    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        match s.trim().to_ascii_lowercase().as_str() {
            "off" => Ok(Self::Off),
            "on" => Ok(Self::On),
            "required" => Ok(Self::Required),
            other => Err(format!(
                "unknown proxy protocol mode {other:?} (expected off | on | required)"
            )),
        }
    }
}

/// Configuration (`[server.proxy_protocol]` on the hub, `--proxy-protocol` on
/// the edge).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProxyProtocolConfig {
    /// Negotiation mode.
    #[serde(default)]
    pub mode: ProxyProtocolMode,
    /// Trusted proxy CIDRs (bare IPs allowed). Only these sources may speak
    /// the PROXY preamble; loopback by default.
    #[serde(default = "default_trusted_proxies")]
    pub trusted_proxies: Vec<String>,
}

impl Default for ProxyProtocolConfig {
    fn default() -> Self {
        Self {
            mode: ProxyProtocolMode::Off,
            trusted_proxies: default_trusted_proxies(),
        }
    }
}

fn default_trusted_proxies() -> Vec<String> {
    vec!["127.0.0.1".to_string(), "::1".to_string()]
}

/// Negotiation outcome.
#[derive(Debug)]
pub enum ProxyOutcome {
    /// No PROXY header. `read_back` bytes were consumed from the stream and
    /// must be replayed before the payload (empty when the mode is off).
    Direct { read_back: Vec<u8> },
    /// Header consumed; `effective` is the real client IP.
    Proxied { effective: IpAddr },
}

/// Negotiation failure. Every variant is fail-closed: the caller drops the
/// connection.
#[derive(Debug, thiserror::Error)]
pub enum ProxyError {
    /// An untrusted source sent bytes carrying a PROXY signature (v1 or v2).
    #[error("untrusted source sent a PROXY protocol signature")]
    UntrustedSignature,
    /// A trusted proxy sent a non-PROXY preamble while the mode is required.
    #[error("trusted proxy sent no PROXY header while mode=required")]
    RequiredMissing,
    /// A trusted proxy sent a malformed v1/v2 header (bad grammar, over the
    /// size cap, or an address family we refuse — e.g. UNIX over TCP).
    #[error("malformed PROXY header: {0}")]
    Malformed(&'static str),
    /// Peer closed the stream or IO error while reading the preamble.
    #[error("io error reading PROXY preamble: {0}")]
    Io(#[from] io::Error),
}

/// The compiled negotiation policy (mode + parsed CIDRs).
#[derive(Debug, Clone)]
pub struct ProxyProtocolPolicy {
    /// Negotiation mode.
    pub mode: ProxyProtocolMode,
    /// Parsed trusted proxy networks.
    pub trusted: Vec<IpNetwork>,
}

impl ProxyProtocolPolicy {
    /// Compiles the configuration. Invalid CIDR entries are configuration
    /// errors, surfaced at startup / reload — never silently ignored.
    pub fn from_config(cfg: &ProxyProtocolConfig) -> Result<Self> {
        let mut trusted = Vec::with_capacity(cfg.trusted_proxies.len());
        for entry in &cfg.trusted_proxies {
            let net: IpNetwork = entry.trim().parse().map_err(|e| {
                InterflowError::config(format!("invalid trusted proxy CIDR '{entry}'"))
                    .with_source(e)
            })?;
            trusted.push(net);
        }
        Ok(Self {
            mode: cfg.mode,
            trusted,
        })
    }

    /// Whether `ip` may speak the PROXY preamble.
    pub fn is_trusted(&self, ip: IpAddr) -> bool {
        self.trusted.iter().any(|net| net.contains(ip))
    }

    /// Reads the PROXY preamble from the front of `stream`.
    ///
    /// The caller owns the time budget: wrap the call in a timeout (the edge
    /// reuses its host-peek budget, the hub uses its handshake deadline).
    /// The read stops exactly at each version's boundary, so a proxied
    /// connection over-reads nothing; a direct connection over-reads at
    /// most 12 bytes (returned for replay).
    pub async fn read<S: AsyncRead + Unpin>(
        &self,
        stream: &mut S,
        peer_ip: IpAddr,
    ) -> std::result::Result<ProxyOutcome, ProxyError> {
        if self.mode == ProxyProtocolMode::Off {
            return Ok(ProxyOutcome::Direct {
                read_back: Vec::new(),
            });
        }
        let trusted = self.is_trusted(peer_ip);

        // Phase 1: read one byte at a time until the preamble is decidable
        // — the first byte alone rules out both signatures ('\r' for v2,
        // 'P' for v1); a diverging prefix match short-circuits to Direct.
        // Byte orientation is load-bearing for v1: the text header has no
        // length field, so a chunked read could swallow the TLS
        // ClientHello that follows the CRLF (kernel segment coalescing
        // makes that the common case, not an edge) and `Proxied` has no
        // replay channel to hand those bytes back.
        let mut buf: Vec<u8> = Vec::with_capacity(V2_FIXED);
        let mut byte = [0u8; 1];
        loop {
            let n = stream.read(&mut byte).await?;
            if n == 0 {
                // EOF before any decidable byte: treat as a (degenerate)
                // direct connection — the subsequent protocol read hits the
                // same EOF immediately.
                return Ok(ProxyOutcome::Direct { read_back: buf });
            }
            buf.push(byte[0]);
            let class = classify_prefix(&buf);
            if class == PrefixClass::V1 {
                if !trusted {
                    return Err(ProxyError::UntrustedSignature);
                }
                return read_v1(stream, buf, peer_ip).await;
            }
            if class == PrefixClass::V2 && buf.len() >= V2_FIXED {
                break;
            }
            // Still forming: a v2 signature prefix, or a "P..." shorter than
            // v1's. Everything else is a decidable direct connection
            // (NotProxy now, or a Pending prefix past v1's length that can
            // never become v2 either).
            let still_forming = class == PrefixClass::V2
                || (class == PrefixClass::Pending && buf.len() < V1_PREFIX.len());
            if !still_forming {
                return if trusted && self.mode == ProxyProtocolMode::Required {
                    Err(ProxyError::RequiredMissing)
                } else {
                    Ok(ProxyOutcome::Direct { read_back: buf })
                };
            }
        }

        if !trusted {
            // A full v2 signature from an untrusted source: spoofing attempt.
            return Err(ProxyError::UntrustedSignature);
        }

        // Phase 2: exact-length read of the declared payload.
        let len = u16::from_be_bytes([buf[V2_FIXED - 2], buf[V2_FIXED - 1]]) as usize;
        let total = V2_FIXED + len;
        if total > V2_MAX {
            return Err(ProxyError::Malformed("declared header exceeds size cap"));
        }
        while buf.len() < total {
            let mut chunk = vec![0u8; total - buf.len()];
            let n = stream.read(&mut chunk).await?;
            if n == 0 {
                return Err(ProxyError::Malformed("EOF inside declared header"));
            }
            buf.extend_from_slice(&chunk[..n]);
        }
        buf.truncate(total);

        let header = ppp::v2::Header::try_from(buf.as_slice())
            .map_err(|_| ProxyError::Malformed("v2 parse failed"))?;
        let effective = match header.addresses {
            ppp::v2::Addresses::IPv4(a) => IpAddr::V4(a.source_address),
            ppp::v2::Addresses::IPv6(a) => IpAddr::V6(a.source_address),
            // UNSPEC (UNKNOWN): the trusted front could not determine the
            // client address — keep the connection, keyed under the front
            // itself (same fallback as v1 UNKNOWN).
            ppp::v2::Addresses::Unspecified => peer_ip,
            // UNIX addressing over a TCP listener is nonsense, not unknown.
            ppp::v2::Addresses::Unix(_) => {
                return Err(ProxyError::Malformed("non-IP address family"));
            }
        };
        Ok(ProxyOutcome::Proxied { effective })
    }
}

/// Reads a v1 (text) preamble to its CRLF terminator and parses it.
///
/// `buf` holds exactly the 6-byte `PROXY ` prefix — byte-at-a-time phase 1
/// guarantees no more. Byte-oriented reads stop exactly at the CRLF so the
/// payload that follows (typically a TLS ClientHello) is never consumed;
/// the line is capped at [`V1_MAX`] bytes before the grammar is applied,
/// and the grammar itself is the same audited `ppp` parser the v2 path
/// uses. `UNKNOWN` falls back to the TCP peer, mirroring v2 UNSPEC.
async fn read_v1<S: AsyncRead + Unpin>(
    stream: &mut S,
    mut buf: Vec<u8>,
    peer_ip: IpAddr,
) -> std::result::Result<ProxyOutcome, ProxyError> {
    let mut byte = [0u8; 1];
    loop {
        let n = stream.read(&mut byte).await?;
        if n == 0 {
            return Err(ProxyError::Malformed("EOF inside v1 header"));
        }
        buf.push(byte[0]);
        if buf.ends_with(b"\r\n") {
            break;
        }
        if buf.len() >= V1_MAX {
            return Err(ProxyError::Malformed("v1 header exceeds size cap"));
        }
    }
    let header = ppp::v1::Header::try_from(buf.as_slice())
        .map_err(|_| ProxyError::Malformed("v1 parse failed"))?;
    let effective = match header.addresses {
        ppp::v1::Addresses::Tcp4(a) => IpAddr::V4(a.source_address),
        ppp::v1::Addresses::Tcp6(a) => IpAddr::V6(a.source_address),
        ppp::v1::Addresses::Unknown => peer_ip,
    };
    Ok(ProxyOutcome::Proxied { effective })
}

/// Prefix classification of the bytes read so far.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PrefixClass {
    /// Definitely not a PROXY preamble (first byte or prefix diverged).
    NotProxy,
    /// Too short to decide ("P..." may still become "PROXY ").
    Pending,
    /// A complete v1 text prefix.
    V1,
    /// Matches the v2 signature so far (or completely).
    V2,
}

fn classify_prefix(buf: &[u8]) -> PrefixClass {
    match buf.first() {
        // The v2 signature starts with \r; only a prefix match can follow.
        Some(b'\r') => {
            let n = buf.len().min(V2_SIGNATURE.len());
            if buf[..n] == V2_SIGNATURE[..n] {
                PrefixClass::V2
            } else {
                PrefixClass::NotProxy
            }
        }
        Some(b'P') => {
            if buf.len() < V1_PREFIX.len() {
                PrefixClass::Pending
            } else if &buf[..V1_PREFIX.len()] == V1_PREFIX {
                PrefixClass::V1
            } else {
                PrefixClass::NotProxy
            }
        }
        _ => PrefixClass::NotProxy,
    }
}

/// A stream wrapper replaying previously-read bytes before delegating to the
/// inner stream. Used when the PROXY negotiation read payload bytes of a
/// direct (non-proxied) connection.
pub struct PrefixedStream<S> {
    inner: S,
    prefix: Vec<u8>,
    pos: usize,
}

impl<S> PrefixedStream<S> {
    /// Wraps `inner`, replaying `prefix` first.
    pub const fn new(inner: S, prefix: Vec<u8>) -> Self {
        Self {
            inner,
            prefix,
            pos: 0,
        }
    }
}

impl<S: AsyncRead + Unpin> AsyncRead for PrefixedStream<S> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        if self.pos < self.prefix.len() {
            let remaining = &self.prefix[self.pos..];
            let n = remaining.len().min(buf.remaining());
            buf.put_slice(&remaining[..n]);
            self.pos += n;
            return Poll::Ready(Ok(()));
        }
        Pin::new(&mut self.inner).poll_read(cx, buf)
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for PrefixedStream<S> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.inner).poll_write(cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
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

    fn policy(mode: ProxyProtocolMode, trusted: &[&str]) -> ProxyProtocolPolicy {
        ProxyProtocolPolicy::from_config(&ProxyProtocolConfig {
            mode,
            trusted_proxies: trusted
                .iter()
                .map(std::string::ToString::to_string)
                .collect(),
        })
        .unwrap()
    }

    /// Builds a valid v2 header for 1.2.3.4:55555 → 10.0.0.1:443.
    fn v2_header() -> Vec<u8> {
        let mut h = Vec::new();
        h.extend_from_slice(&V2_SIGNATURE);
        h.extend([0x21, 0x11]); // ver2 cmd PROXY, fam TCP4
        h.extend([0x00, 0x0c]); // len 12
        h.extend_from_slice(&[1, 2, 3, 4]); // src
        h.extend_from_slice(&[10, 0, 0, 1]); // dst
        h.extend_from_slice(&55555u16.to_be_bytes()); // src port
        h.extend_from_slice(&[0x01, 0xbb]); // dst port 443
        h
    }

    /// Builds a valid v2 UNKNOWN (UNSPEC family) header.
    fn v2_unknown_header() -> Vec<u8> {
        let mut h = Vec::new();
        h.extend_from_slice(&V2_SIGNATURE);
        h.extend([0x21, 0x00]); // ver2 cmd PROXY, fam UNSPEC/dgram unspecified
        h.extend([0x00, 0x00]); // len 0
        h
    }

    #[tokio::test]
    async fn off_mode_returns_direct_without_reading() {
        let mut cursor = std::io::Cursor::new(v2_header());
        let out = policy(ProxyProtocolMode::Off, &[])
            .read(&mut cursor, "127.0.0.1".parse().unwrap())
            .await
            .unwrap();
        assert!(matches!(out, ProxyOutcome::Direct { ref read_back } if read_back.is_empty()));
        // Nothing was consumed.
        assert_eq!(cursor.position(), 0);
    }

    #[tokio::test]
    async fn trusted_proxy_v2_yields_effective_ip() {
        let mut cursor = std::io::Cursor::new(v2_header());
        let out = policy(ProxyProtocolMode::Required, &["127.0.0.1"])
            .read(&mut cursor, "127.0.0.1".parse().unwrap())
            .await
            .unwrap();
        assert!(
            matches!(out, ProxyOutcome::Proxied { effective } if effective.to_string() == "1.2.3.4")
        );
        // The whole header was consumed, nothing more.
        assert_eq!(
            usize::try_from(cursor.position()).unwrap_or(usize::MAX),
            v2_header().len()
        );
    }

    #[tokio::test]
    async fn untrusted_source_with_signature_is_hard_rejected() {
        let mut cursor = std::io::Cursor::new(v2_header());
        let err = policy(ProxyProtocolMode::On, &["127.0.0.1"])
            .read(&mut cursor, "9.9.9.9".parse().unwrap())
            .await
            .unwrap_err();
        assert!(matches!(err, ProxyError::UntrustedSignature));
    }

    #[tokio::test]
    async fn untrusted_source_with_v1_signature_is_hard_rejected() {
        let mut cursor = std::io::Cursor::new(b"PROXY TCP4 1.2.3.4 5.6.7.8 1 2\r\n".to_vec());
        let err = policy(ProxyProtocolMode::On, &["127.0.0.1"])
            .read(&mut cursor, "9.9.9.9".parse().unwrap())
            .await
            .unwrap_err();
        assert!(matches!(err, ProxyError::UntrustedSignature));
    }

    /// A v1 line exactly as stock nginx stream emits it (the front we
    /// actually deploy).
    const V1_TCP4: &[u8] = b"PROXY TCP4 198.51.100.7 10.0.0.1 47115 443\r\n";

    #[tokio::test]
    async fn trusted_proxy_v1_tcp4_yields_effective_ip() {
        let mut cursor = std::io::Cursor::new(V1_TCP4.to_vec());
        let out = policy(ProxyProtocolMode::On, &["127.0.0.1"])
            .read(&mut cursor, "127.0.0.1".parse().unwrap())
            .await
            .unwrap();
        assert!(
            matches!(out, ProxyOutcome::Proxied { effective } if effective.to_string() == "198.51.100.7")
        );
    }

    #[tokio::test]
    async fn trusted_proxy_v1_tcp6_yields_effective_ip() {
        let line = b"PROXY TCP6 2001:db8::7 2001:db8::1 47115 443\r\n".to_vec();
        let mut cursor = std::io::Cursor::new(line.clone());
        let out = policy(ProxyProtocolMode::Required, &["::1"])
            .read(&mut cursor, "::1".parse().unwrap())
            .await
            .unwrap();
        assert!(
            matches!(out, ProxyOutcome::Proxied { effective } if effective.to_string() == "2001:db8::7")
        );
    }

    #[tokio::test]
    async fn trusted_proxy_v1_unknown_falls_back_to_peer() {
        let mut cursor = std::io::Cursor::new(b"PROXY UNKNOWN\r\n".to_vec());
        let out = policy(ProxyProtocolMode::On, &["127.0.0.1"])
            .read(&mut cursor, "127.0.0.1".parse().unwrap())
            .await
            .unwrap();
        assert!(
            matches!(out, ProxyOutcome::Proxied { effective } if effective.to_string() == "127.0.0.1")
        );
    }

    #[tokio::test]
    async fn trusted_proxy_v2_unknown_falls_back_to_peer() {
        // v1 and v2 UNKNOWN share one semantic: key the connection under
        // the trusted front itself.
        let mut cursor = std::io::Cursor::new(v2_unknown_header());
        let out = policy(ProxyProtocolMode::On, &["127.0.0.1"])
            .read(&mut cursor, "127.0.0.1".parse().unwrap())
            .await
            .unwrap();
        assert!(
            matches!(out, ProxyOutcome::Proxied { effective } if effective.to_string() == "127.0.0.1")
        );
    }

    /// Load-bearing framing property: the v1 read stops exactly at the
    /// CRLF — the payload that follows (a TLS ClientHello in production)
    /// must stay in the stream for the protocol layer.
    #[tokio::test]
    async fn v1_consumes_exactly_the_header() {
        let mut bytes = V1_TCP4.to_vec();
        bytes.extend_from_slice(&[0x16, 0x03, 0x01]); // TLS ClientHello start
        let mut cursor = std::io::Cursor::new(bytes);
        policy(ProxyProtocolMode::On, &["127.0.0.1"])
            .read(&mut cursor, "127.0.0.1".parse().unwrap())
            .await
            .unwrap();
        assert_eq!(
            usize::try_from(cursor.position()).unwrap_or(usize::MAX),
            V1_TCP4.len()
        );
    }

    #[tokio::test]
    async fn v1_missing_crlf_is_malformed() {
        // Stream ends mid-line: fail-closed, not a silent passthrough.
        let mut cursor = std::io::Cursor::new(b"PROXY TCP4 198.51.100.7 10.0.0.1 47115".to_vec());
        let err = policy(ProxyProtocolMode::On, &["127.0.0.1"])
            .read(&mut cursor, "127.0.0.1".parse().unwrap())
            .await
            .unwrap_err();
        assert!(matches!(err, ProxyError::Malformed(_)));
    }

    #[tokio::test]
    async fn v1_over_size_cap_is_malformed() {
        let mut line = b"PROXY ".to_vec();
        line.extend(std::iter::repeat_n(b'a', V1_MAX));
        let mut cursor = std::io::Cursor::new(line);
        let err = policy(ProxyProtocolMode::On, &["127.0.0.1"])
            .read(&mut cursor, "127.0.0.1".parse().unwrap())
            .await
            .unwrap_err();
        assert!(matches!(
            err,
            ProxyError::Malformed("v1 header exceeds size cap")
        ));
    }

    #[tokio::test]
    async fn v1_bad_tokens_are_malformed() {
        for line in [
            // Not a port.
            &b"PROXY TCP4 198.51.100.7 10.0.0.1 seventeen 443\r\n"[..],
            // Leading-zero port (ppp grammar rejects).
            b"PROXY TCP4 198.51.100.7 10.0.0.1 07 443\r\n",
            // Bad source IP.
            b"PROXY TCP4 999.51.100.7 10.0.0.1 47115 443\r\n",
            // Unknown family keyword.
            b"PROXY TCP5 198.51.100.7 10.0.0.1 47115 443\r\n",
            // Missing destination port.
            b"PROXY TCP4 198.51.100.7 10.0.0.1 47115\r\n",
        ] {
            let mut cursor = std::io::Cursor::new(line.to_vec());
            let err = policy(ProxyProtocolMode::On, &["127.0.0.1"])
                .read(&mut cursor, "127.0.0.1".parse().unwrap())
                .await
                .unwrap_err();
            assert!(matches!(err, ProxyError::Malformed(_)), "line: {line:?}");
        }
    }

    #[tokio::test]
    async fn direct_connection_in_on_mode_replays_read_bytes() {
        let payload = b"GET / HTTP/1.1\r\nHost: x\r\n\r\n".to_vec();
        let mut cursor = std::io::Cursor::new(payload.clone());
        let out = policy(ProxyProtocolMode::On, &["127.0.0.1"])
            .read(&mut cursor, "127.0.0.1".parse().unwrap())
            .await
            .unwrap();
        let ProxyOutcome::Direct { read_back } = out else {
            panic!("expected direct");
        };
        assert!(!read_back.is_empty());
        // Invariant: replayed prefix ⊕ bytes still in the stream == the
        // original payload (nothing lost, nothing duplicated).
        let mut rest = Vec::new();
        cursor.read_to_end(&mut rest).await.unwrap();
        let mut joined = read_back;
        joined.extend_from_slice(&rest);
        assert_eq!(joined, payload);
        // And the replay wrapper drains prefix first, then the inner stream.
        let mut prefixed_reader = std::io::Cursor::new(rest.clone());
        let mut wrapped = PrefixedStream::new(&mut prefixed_reader, Vec::new());
        let mut got = Vec::new();
        wrapped.read_to_end(&mut got).await.unwrap();
        assert_eq!(got, rest);
    }

    #[tokio::test]
    async fn direct_connection_in_required_mode_is_rejected() {
        let mut cursor = std::io::Cursor::new(b"GET / HTTP/1.1\r\n".to_vec());
        let err = policy(ProxyProtocolMode::Required, &["127.0.0.1"])
            .read(&mut cursor, "127.0.0.1".parse().unwrap())
            .await
            .unwrap_err();
        assert!(matches!(err, ProxyError::RequiredMissing));
    }

    #[tokio::test]
    async fn untrusted_direct_connection_passes_through() {
        // An untrusted source speaking plain HTTP is a direct client — fine.
        let mut cursor = std::io::Cursor::new(b"GET / HTTP/1.1\r\n".to_vec());
        let out = policy(ProxyProtocolMode::Required, &["127.0.0.1"])
            .read(&mut cursor, "8.8.8.8".parse().unwrap())
            .await
            .unwrap();
        assert!(matches!(out, ProxyOutcome::Direct { .. }));
    }

    #[tokio::test]
    async fn declared_length_over_cap_is_malformed() {
        let mut h = Vec::new();
        h.extend_from_slice(&V2_SIGNATURE);
        h.extend([0x21, 0x11]);
        h.extend([0xff, 0xff]); // len 65535 — over cap
        let mut cursor = std::io::Cursor::new(h);
        let err = policy(ProxyProtocolMode::On, &["127.0.0.1"])
            .read(&mut cursor, "127.0.0.1".parse().unwrap())
            .await
            .unwrap_err();
        assert!(matches!(err, ProxyError::Malformed(_)));
    }

    #[tokio::test]
    async fn garbage_first_byte_is_direct() {
        let mut cursor = std::io::Cursor::new(vec![0x16, 0x03, 0x01]); // TLS ClientHello start
        let out = policy(ProxyProtocolMode::On, &["127.0.0.1"])
            .read(&mut cursor, "127.0.0.1".parse().unwrap())
            .await
            .unwrap();
        assert!(matches!(out, ProxyOutcome::Direct { .. }));
    }

    #[tokio::test]
    async fn invalid_cidr_is_config_error() {
        let err = ProxyProtocolPolicy::from_config(&ProxyProtocolConfig {
            mode: ProxyProtocolMode::On,
            trusted_proxies: vec!["not-a-cidr".to_string()],
        });
        assert!(err.is_err());
    }

    #[tokio::test]
    async fn cidr_trust_matching() {
        let pol = policy(ProxyProtocolMode::On, &["10.0.0.0/8", "::1"]);
        assert!(pol.is_trusted("10.1.2.3".parse().unwrap()));
        assert!(!pol.is_trusted("11.0.0.1".parse().unwrap()));
        assert!(pol.is_trusted("::1".parse().unwrap()));
    }

    /// Fuzz-style property: arbitrary hostile bytes from an untrusted source
    /// never produce an IP — they are either Direct (plain bytes) or a hard
    /// rejection; never a panic.
    #[tokio::test]
    async fn hostile_bytes_never_yield_ip_nor_panic() {
        let mut seed: u64 = 0xdead_beef;
        let mut next = move || {
            seed ^= seed << 13;
            seed ^= seed >> 7;
            seed ^= seed << 17;
            seed
        };
        for _ in 0..500 {
            let len = usize::try_from(next() % 64).unwrap_or(64);
            let bytes: Vec<u8> = (0..len).map(|_| (next() & 0xff) as u8).collect();
            for peer in ["9.9.9.9", "127.0.0.1"] {
                let mut cursor = std::io::Cursor::new(bytes.clone());
                let res = policy(ProxyProtocolMode::On, &["127.0.0.1"])
                    .read(&mut cursor, peer.parse().unwrap())
                    .await;
                if let Ok(ProxyOutcome::Proxied { .. }) = res {
                    // Only reachable from the trusted proxy with a
                    // structurally valid header.
                    assert_eq!(peer, "127.0.0.1");
                }
            }
        }
    }

    /// Fuzz-style property, v1-guided: mutations seeded from real v1 lines
    /// (uniform random bytes essentially never spell "PROXY ", so the
    /// battery above never reaches the v1 grammar). Same invariant: never a
    /// panic, `Proxied` only from the trusted proxy.
    #[tokio::test]
    async fn hostile_v1_seeded_bytes_never_yield_ip_nor_panic() {
        let mut seed: u64 = 0xfeed_face;
        let mut next = move || {
            seed ^= seed << 13;
            seed ^= seed >> 7;
            seed ^= seed << 17;
            seed
        };
        let seeds: [&[u8]; 4] = [
            b"PROXY TCP4 198.51.100.7 10.0.0.1 47115 443\r\n",
            b"PROXY TCP6 2001:db8::7 2001:db8::1 47115 443\r\n",
            b"PROXY UNKNOWN\r\n",
            b"PROXY ",
        ];
        for round in 0..1000u64 {
            let base = seeds[usize::try_from(next() % seeds.len() as u64).unwrap()];
            let mut bytes = base.to_vec();
            let mutations = usize::try_from(next() % 3).unwrap();
            for _ in 0..mutations {
                match next() % 3 {
                    0 => {
                        // Flip a random byte.
                        let idx = usize::try_from(next() % 120).unwrap() % bytes.len().max(1);
                        if let Some(slot) = bytes.get_mut(idx) {
                            *slot = (next() & 0xff) as u8;
                        }
                    }
                    1 => {
                        // Truncate.
                        let at = usize::try_from(next() % 120).unwrap() % bytes.len().max(1);
                        bytes.truncate(at);
                    }
                    _ => {
                        // Append random junk (oversize lines included).
                        let extra = usize::try_from(next() % 40).unwrap();
                        for _ in 0..extra {
                            bytes.push((next() & 0xff) as u8);
                        }
                    }
                }
            }
            for peer in ["9.9.9.9", "127.0.0.1"] {
                let mut cursor = std::io::Cursor::new(bytes.clone());
                let res = policy(ProxyProtocolMode::On, &["127.0.0.1"])
                    .read(&mut cursor, peer.parse().unwrap())
                    .await;
                if let Ok(ProxyOutcome::Proxied { .. }) = res {
                    assert_eq!(peer, "127.0.0.1", "round {round}: {bytes:?}");
                }
            }
        }
    }
}
