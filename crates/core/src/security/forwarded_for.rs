//! X-Forwarded-For real-IP restoration for the edge's HTTP leg.
//!
//! Stock nginx's HTTP `proxy_pass` cannot emit the PROXY protocol (that
//! directive exists only in the stream module), so behind the standard
//! topology every public connection arrives at the edge from the proxy's
//! loopback address — per-IP rate limits, per-IP connection caps and audit
//! records would all key on the proxy instead of the client. This module
//! restores the real client IP from the de-facto standard
//! `X-Forwarded-For` header under a strict trust model:
//!
//! | Source                              | Behavior                                        |
//! |---|---|
//! | trusted proxy + right-most entry parses | real IP used for limiting / caps / audit / metrics |
//! | trusted proxy, header absent, `on`  | TCP peer is the real client (fail-open availability) |
//! | trusted proxy, absent/invalid, `required` | connection rejected (fail-closed)          |
//! | untrusted source                    | header ignored entirely (attacker-controlled)   |
//!
//! The **right-most** entry of the combined chain is used: nginx's
//! `$proxy_add_x_forwarded_for` appends the client the proxy itself observed
//! to the end of whatever the client sent, so left-side entries are
//! attacker-chosen and must never influence governance. When several
//! `X-Forwarded-For` header lines are present, the combined list is their
//! entries in header order — the right-most entry of the last line is the
//! one appended by the nearest trusted proxy.
//!
//! Like the PROXY-protocol path, the derived IP is used for **resource
//! governance and audit only** — never for identity or ACL decisions
//! (identity is exclusively mTLS, RFC
//! `docs/design/multi-tenant-mtls-only.md` §5.2).

use ipnetwork::IpNetwork;
use serde::{Deserialize, Serialize};
use std::net::IpAddr;

/// Whether `X-Forwarded-For` restoration is expected on the listener.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum XffMode {
    /// Disabled: the TCP peer is the real client.
    #[default]
    Off,
    /// Trust the header from trusted proxies; absent/invalid falls back to
    /// the TCP peer.
    On,
    /// Trusted proxies must send a parseable header; anything else is
    /// rejected.
    Required,
}

impl XffMode {
    /// Whether the mode participates in real-IP restoration at all.
    pub const fn enabled(self) -> bool {
        !matches!(self, Self::Off)
    }
}

impl std::str::FromStr for XffMode {
    type Err = String;

    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        match s.trim().to_ascii_lowercase().as_str() {
            "off" => Ok(Self::Off),
            "on" => Ok(Self::On),
            "required" => Ok(Self::Required),
            other => Err(format!(
                "unknown X-Forwarded-For mode {other:?} (expected off | on | required)"
            )),
        }
    }
}

/// Restoration outcome for a connection whose TCP peer is a trusted proxy.
#[derive(Debug, PartialEq, Eq)]
pub enum XffResolution {
    /// The chain yielded this effective client IP.
    Effective(IpAddr),
    /// No usable header and the mode tolerates that: the TCP peer is the
    /// client.
    Peer,
    /// `required` semantics were violated.
    Denied(XffError),
}

/// `required`-mode failures. Every variant is fail-closed: the caller drops
/// the connection.
#[derive(Debug, PartialEq, Eq, thiserror::Error)]
pub enum XffError {
    /// A trusted proxy sent no `X-Forwarded-For` header (or it lay beyond
    /// the request-head peek budget).
    #[error("trusted proxy sent no X-Forwarded-For header")]
    Missing,
    /// The right-most entry is not a bare IP address.
    #[error("X-Forwarded-For right-most entry is not a valid IP")]
    Invalid,
}

/// The compiled restoration policy (mode + parsed trusted proxy networks).
///
/// The trusted set is deliberately shared with the PROXY-protocol
/// configuration (`--trusted-proxy` on the edge): both mechanisms describe
/// the same deployment fact — which reverse proxies may assert client
/// addresses.
#[derive(Debug, Clone)]
pub struct XffPolicy {
    /// Restoration mode.
    pub mode: XffMode,
    /// Parsed trusted proxy networks.
    pub trusted: Vec<IpNetwork>,
}

impl XffPolicy {
    /// Builds the policy from a mode and the shared trusted-proxy entries.
    /// Invalid CIDRs are configuration errors, surfaced at startup — never
    /// silently ignored.
    pub fn new(mode: XffMode, trusted: &[String]) -> crate::error::Result<Self> {
        if mode == XffMode::Off {
            // Off never consults the trusted set; the PROXY-protocol policy
            // compilation validates the same shared list.
            return Ok(Self {
                mode,
                trusted: Vec::new(),
            });
        }
        let mut parsed = Vec::with_capacity(trusted.len());
        for entry in trusted {
            let net: IpNetwork = entry.trim().parse().map_err(|e| {
                crate::error::InterflowError::config(format!(
                    "invalid trusted proxy CIDR '{entry}': {e}"
                ))
            })?;
            parsed.push(net);
        }
        Ok(Self {
            mode,
            trusted: parsed,
        })
    }

    /// Whether `ip` may assert client addresses.
    pub fn is_trusted(&self, ip: IpAddr) -> bool {
        self.trusted.iter().any(|net| net.contains(ip))
    }

    /// Resolves the effective client IP from the buffered HTTP request head
    /// of a connection whose TCP peer is already known to be trusted.
    ///
    /// `head` is the peeked bytes of the request head (the same buffer the
    /// edge already accumulates for its `Host` peek). Only the header region
    /// (up to the first blank line) is scanned; anything beyond is body
    /// bytes and is ignored, so a binary body can never smuggle a forged
    /// chain past the parser.
    pub fn resolve(&self, head: &[u8]) -> XffResolution {
        let Some(entry) = rightmost_entry(head) else {
            return match self.mode {
                XffMode::Required => XffResolution::Denied(XffError::Missing),
                XffMode::On | XffMode::Off => XffResolution::Peer,
            };
        };
        match parse_ip_entry(entry) {
            Some(ip) => XffResolution::Effective(ip),
            None => match self.mode {
                XffMode::Required => XffResolution::Denied(XffError::Invalid),
                XffMode::On | XffMode::Off => XffResolution::Peer,
            },
        }
    }
}

/// Returns the right-most comma-separated entry of the last
/// `X-Forwarded-For` header line in the request head, or `None` when the
/// header is absent from the buffered region.
///
/// Binary safe: matching happens only on ASCII bytes, mirroring the Host
/// parser's rules (a multipart body containing non-UTF-8 bytes must not
/// break the scan). obs-fold continuation lines are not joined — a folded
/// XFF value is not something a conforming proxy emits, and treating it as
/// absent is the fail-closed answer.
fn rightmost_entry(head: &[u8]) -> Option<&[u8]> {
    let headers_end = find_headers_end(head).unwrap_or(head.len());
    let mut last_value: Option<&[u8]> = None;

    let mut i = 0;
    while i < headers_end {
        let line_end = head[i..headers_end]
            .iter()
            .position(|&b| b == b'\n')
            .map_or(headers_end, |p| i + p);
        let line = trim_cr(&head[i..line_end]);

        if line.len() >= 16 && eq_ignore_ascii_case(&line[..16], b"x-forwarded-for:") {
            let value = trim_ascii_whitespace(&line[16..]);
            last_value = Some(value);
        }

        if line_end == headers_end {
            break;
        }
        i = line_end + 1;
    }

    let value = last_value?;
    // Right-most non-empty entry: proxies may append ", <ip>" to a chain the
    // client terminated with a dangling comma.
    value
        .rsplit(|&b| b == b',')
        .map(trim_ascii_whitespace)
        .find(|entry| !entry.is_empty())
}

/// Parses one chain entry: bare IPv4/IPv6, with optional `[...]` brackets
/// around IPv6 (the bracketed form appears in the wild even though RFC 7239
/// deprecates it for the legacy XFF header).
fn parse_ip_entry(entry: &[u8]) -> Option<IpAddr> {
    let s = std::str::from_utf8(entry).ok()?;
    let s = s.trim();
    let unbracketed = s
        .strip_prefix('[')
        .and_then(|rest| rest.strip_suffix(']'))
        .unwrap_or(s);
    unbracketed.parse().ok()
}

/// Trims a trailing `\r` (CRLF line ending).
fn trim_cr(line: &[u8]) -> &[u8] {
    line.strip_suffix(b"\r").unwrap_or(line)
}

/// Trims ASCII whitespace (space + horizontal tab) from both ends.
fn trim_ascii_whitespace(mut v: &[u8]) -> &[u8] {
    while v.first().is_some_and(|&b| b == b' ' || b == b'\t') {
        v = &v[1..];
    }
    while v.last().is_some_and(|&b| b == b' ' || b == b'\t') {
        v = &v[..v.len() - 1];
    }
    v
}

/// ASCII case-insensitive comparison.
fn eq_ignore_ascii_case(a: &[u8], b: &[u8]) -> bool {
    a.len() == b.len() && a.iter().zip(b).all(|(x, y)| x.eq_ignore_ascii_case(y))
}

/// Locates the end of the HTTP/1.x header region (the blank line). Mirrors
/// the edge listener's Host parser so both scan exactly the same region.
const fn find_headers_end(buf: &[u8]) -> Option<usize> {
    let mut i = 0;
    while i + 1 < buf.len() {
        if buf[i] == b'\n' && buf[i + 1] == b'\n' {
            return Some(i + 2);
        }
        if buf[i] == b'\r'
            && i + 3 < buf.len()
            && buf[i + 1] == b'\n'
            && buf[i + 2] == b'\r'
            && buf[i + 3] == b'\n'
        {
            return Some(i + 4);
        }
        i += 1;
    }
    None
}

#[cfg(test)]
#[allow(clippy::panic, clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    fn required() -> XffPolicy {
        XffPolicy::new(XffMode::Required, &["127.0.0.1".to_string()]).unwrap()
    }

    #[test]
    fn mode_parses_off_on_required_and_rejects_aliases() {
        assert_eq!("off".parse::<XffMode>().unwrap(), XffMode::Off);
        assert_eq!("on".parse::<XffMode>().unwrap(), XffMode::On);
        assert_eq!("required".parse::<XffMode>().unwrap(), XffMode::Required);
        assert!("preferred".parse::<XffMode>().is_err());
    }

    #[test]
    fn rightmost_entry_wins_across_chain_and_multiple_headers() {
        let head = b"GET / HTTP/1.1\r\nHost: x\r\nX-Forwarded-For: 1.2.3.4, 9.9.9.9\r\nX-Forwarded-For: 5.6.7.8, 203.0.113.7\r\n\r\nbody";
        assert_eq!(
            required().resolve(head),
            XffResolution::Effective("203.0.113.7".parse().unwrap())
        );
    }

    #[test]
    fn client_forged_left_side_cannot_override() {
        let head =
            b"GET / HTTP/1.1\r\nHost: x\r\nX-Forwarded-For: 6.6.6.6, 8.8.4.4, 198.51.100.9\r\n\r\n";
        assert_eq!(
            required().resolve(head),
            XffResolution::Effective("198.51.100.9".parse().unwrap())
        );
    }

    #[test]
    fn header_name_is_case_insensitive() {
        let head = b"GET / HTTP/1.1\nhost: x\nx-FORWARDED-for: 192.0.2.10\n\n";
        assert_eq!(
            required().resolve(head),
            XffResolution::Effective("192.0.2.10".parse().unwrap())
        );
    }

    #[test]
    fn ipv6_bare_and_bracketed_parse() {
        let bare = b"GET / HTTP/1.1\r\nHost: x\r\nX-Forwarded-For: 2001:db8::1\r\n\r\n";
        assert_eq!(
            required().resolve(bare),
            XffResolution::Effective("2001:db8::1".parse().unwrap())
        );
        let bracketed = b"GET / HTTP/1.1\r\nHost: x\r\nX-Forwarded-For: [2001:db8::2]\r\n\r\n";
        assert_eq!(
            required().resolve(bracketed),
            XffResolution::Effective("2001:db8::2".parse().unwrap())
        );
    }

    #[test]
    fn dangling_comma_falls_back_to_previous_entry() {
        let head = b"GET / HTTP/1.1\r\nHost: x\r\nX-Forwarded-For: 203.0.113.20,\r\n\r\n";
        assert_eq!(
            required().resolve(head),
            XffResolution::Effective("203.0.113.20".parse().unwrap())
        );
    }

    #[test]
    fn missing_header_required_denies_on_falls_back() {
        let head = b"GET / HTTP/1.1\r\nHost: x\r\n\r\n";
        assert_eq!(
            required().resolve(head),
            XffResolution::Denied(XffError::Missing)
        );

        let on = XffPolicy::new(XffMode::On, &[]).unwrap();
        assert_eq!(on.resolve(head), XffResolution::Peer);
    }

    #[test]
    fn non_ip_rightmost_entry_required_denies_on_falls_back() {
        let head = b"GET / HTTP/1.1\r\nHost: x\r\nX-Forwarded-For: 1.2.3.4, unknown\r\n\r\n";
        assert_eq!(
            required().resolve(head),
            XffResolution::Denied(XffError::Invalid)
        );

        let on = XffPolicy::new(XffMode::On, &[]).unwrap();
        assert_eq!(on.resolve(head), XffResolution::Peer);
    }

    #[test]
    fn body_bytes_are_never_scanned() {
        let head = b"POST / HTTP/1.1\r\nHost: x\r\n\r\nX-Forwarded-For: 6.6.6.6";
        assert_eq!(
            required().resolve(head),
            XffResolution::Denied(XffError::Missing)
        );
    }

    #[test]
    fn trusted_membership_follows_cidrs() {
        let policy =
            XffPolicy::new(XffMode::On, &["10.0.0.0/8".to_string(), "::1".to_string()]).unwrap();
        assert!(policy.is_trusted("10.1.2.3".parse().unwrap()));
        assert!(policy.is_trusted("::1".parse().unwrap()));
        assert!(!policy.is_trusted("127.0.0.1".parse().unwrap()));
    }

    #[test]
    fn invalid_trusted_entry_is_a_config_error() {
        assert!(
            XffPolicy::new(XffMode::On, &["not-a-cidr".to_string()]).is_err(),
            "invalid trusted proxies must fail at startup, not silently pass"
        );
    }
}
