//! Shared authority / endpoint parsing.
//!
//! Interflow previously carried seven hand-written parsers for `host:port`
//! material (`strip_prefix("https://")` followed by `rsplit_once(':')`;
//! certificate SANs, SNI, SSRF checks, Host routing, QUIC dial addresses).
//! They disagreed on IPv6 (brackets were mangled or dropped), accepted
//! userinfo implicitly, and failed open on garbage. This module funnels all
//! of them through [`http::uri::Authority`] / [`http::Uri`], which supply
//! RFC 3986 syntax, and layers Interflow's product rules on top:
//!
//! - endpoints accept only the `http`/`https` schemes;
//! - userinfo is rejected outright (`http` already refuses it — no
//!   credential material may hide inside an authority);
//! - IPv6 hosts are exposed bracket-free in [`EndpointAuthority::host`] so
//!   SAN/SNI/routing comparisons see one canonical form;
//! - IPv6 zone identifiers (`fe80::1%eth0`) are rejected: they name
//!   link-local interfaces and have no meaning in an endpoint;
//! - non-ASCII hosts are rejected rather than IDNA/punycode-translated —
//!   certificate SAN generation must not gain encoding behaviour silently;
//! - empty hosts, invalid ports and malformed IPv6 fail closed.
//!
//! The parser never *guesses* a port: [`EndpointAuthority::explicit_port`]
//! is `None` unless the input spelled the port out. Callers that need a
//! port (e.g. the QUIC dial address) must decide what an absent port means
//! instead of inheriting a hidden 80/443 default.

use http::Uri;
use http::uri::Authority;

/// A parsed `host[:port]` authority, optionally with endpoint context
/// (scheme, path and query).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EndpointAuthority {
    /// Lowercase scheme, present only for full-endpoint parses
    /// ([`parse_endpoint`]); `None` for bare authorities
    /// ([`parse_authority`]).
    pub scheme: Option<String>,
    /// Host with IPv6 brackets stripped (`[::1]` → `::1`) — the canonical
    /// form for SAN/SNI/routing comparisons.
    pub host: String,
    /// Whether the host was an IPv6 literal.
    pub is_ipv6: bool,
    /// The port exactly as spelled in the input; `None` when absent. No
    /// 80/443 defaulting happens here.
    pub explicit_port: Option<u16>,
    /// The original authority (brackets/port/case preserved) for rendering
    /// dial strings.
    pub authority: Authority,
    /// Path-and-query of a full endpoint URL; `None` for bare authorities
    /// and scheme-only inputs without a path.
    pub path_and_query: Option<String>,
}

impl EndpointAuthority {
    /// The authority as a dial string (`host:port`, brackets preserved) —
    /// byte-identical to the input's authority component.
    #[must_use]
    pub fn authority_str(&self) -> &str {
        self.authority.as_str()
    }
}

/// Why an authority/endpoint failed to parse. Every variant fails closed:
/// callers surface these as configuration errors instead of issuing
/// certificates (or dialing addresses) derived from garbage input.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum EndpointParseError {
    /// A scheme was present but is not http/https.
    #[error("unsupported endpoint scheme {0:?} (only http/https)")]
    UnsupportedScheme(String),
    /// `scheme://` was present but no authority followed.
    #[error("endpoint has no authority component")]
    MissingAuthority,
    /// Not a syntactically valid authority (bad port, malformed IPv6,
    /// userinfo, stray delimiters, …).
    #[error("invalid authority {0:?}")]
    Invalid(String),
    /// The authority has no host component.
    #[error("empty host in {0:?}")]
    EmptyHost(String),
    /// IPv6 zone identifiers name link-local interfaces and are rejected.
    #[error("IPv6 zone identifiers are unsupported (link-local): {0:?}")]
    ZoneId(String),
    /// Non-ASCII hosts are rejected rather than IDNA-translated.
    #[error("non-ASCII host in {0:?} (no IDNA/punycode translation is applied)")]
    NonAsciiHost(String),
}

/// Parses a bare authority — `host`, `host:port`, `[IPv6-literal]:port` — as
/// found in Host headers, route table keys and QUIC dial addresses.
///
/// Surrounding whitespace is trimmed. Anything that is not exactly an
/// authority (paths, schemes, userinfo, empty hosts, out-of-range ports)
/// is an error.
pub fn parse_authority(input: &str) -> Result<EndpointAuthority, EndpointParseError> {
    let trimmed = input.trim();
    let authority: Authority = trimmed
        .parse()
        .map_err(|_| EndpointParseError::Invalid(input.to_owned()))?;
    from_parts(None, authority, None, input)
}

/// Parses a full endpoint — `http(s)://host[:port][/path?query]` — or a
/// bare authority, as found in control-endpoint and hub-URL configuration.
///
/// Only the http/https schemes are accepted (case-insensitive); every other
/// scheme, including typos like `htps://`, fails closed. A path/query is
/// captured but never interpreted here.
pub fn parse_endpoint(input: &str) -> Result<EndpointAuthority, EndpointParseError> {
    let trimmed = input.trim();
    if let Some((scheme, _rest)) = trimmed.split_once("://") {
        let lowered = scheme.to_ascii_lowercase();
        if lowered != "http" && lowered != "https" {
            return Err(EndpointParseError::UnsupportedScheme(scheme.to_owned()));
        }
        // Note: `Uri` cannot be the first thing tried — a scheme-less
        // `host:port` such as `example.com:16666` parses as a *scheme*
        // (`.` is a legal scheme character) plus path. Only inputs that
        // really carry `scheme://` go through `Uri`.
        let uri: Uri = trimmed
            .parse()
            .map_err(|_| EndpointParseError::Invalid(input.to_owned()))?;
        let authority = uri
            .authority()
            .ok_or(EndpointParseError::MissingAuthority)?
            .clone();
        let path_and_query = uri
            .path_and_query()
            .map(|pq| pq.as_str().to_owned())
            .filter(|pq| pq != "/");
        return from_parts(Some(lowered), authority, path_and_query, input);
    }
    parse_authority(input)
}

/// Applies the product rules shared by both entry points.
fn from_parts(
    scheme: Option<String>,
    authority: Authority,
    path_and_query: Option<String>,
    original: &str,
) -> Result<EndpointAuthority, EndpointParseError> {
    // Belt-and-braces: `http` refuses userinfo, and `@` can never appear in
    // a legal reg-name — so an `@` here is userinfo by definition.
    if authority.as_str().contains('@') {
        return Err(EndpointParseError::Invalid(original.to_owned()));
    }
    // `Authority` accepts out-of-range port components (`host:99999` parses
    // and `port_u16()` silently yields None — the port is swallowed, not
    // rejected). An explicit-but-invalid port must fail closed instead of
    // masquerading as portless.
    let port_component: Option<&str> = if authority.as_str().starts_with('[') {
        authority
            .as_str()
            .split_once(']')
            .and_then(|(_, rest)| rest.strip_prefix(':'))
    } else {
        authority.as_str().rsplit_once(':').map(|(_, port)| port)
    };
    if port_component.is_some_and(|p| p.parse::<u16>().is_err()) {
        return Err(EndpointParseError::Invalid(original.to_owned()));
    }
    let raw_host = authority.host();
    let is_ipv6 = raw_host.starts_with('[') && raw_host.ends_with(']');
    let host = if is_ipv6 {
        // `Authority::host()` keeps the brackets; comparisons and SANs want
        // the bare address.
        raw_host[1..raw_host.len() - 1].to_owned()
    } else {
        raw_host.to_owned()
    };
    if host.is_empty() {
        return Err(EndpointParseError::EmptyHost(original.to_owned()));
    }
    if host.contains('%') {
        return Err(EndpointParseError::ZoneId(original.to_owned()));
    }
    if !host.is_ascii() {
        return Err(EndpointParseError::NonAsciiHost(original.to_owned()));
    }
    Ok(EndpointAuthority {
        scheme,
        host,
        is_ipv6,
        explicit_port: authority.port_u16(),
        authority,
        path_and_query,
    })
}

#[cfg(test)]
#[allow(clippy::panic, clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    fn authority(input: &str) -> EndpointAuthority {
        parse_authority(input).unwrap()
    }

    fn endpoint(input: &str) -> EndpointAuthority {
        parse_endpoint(input).unwrap()
    }

    #[test]
    fn bare_authority_with_and_without_port() {
        let a = authority("hub.example.com");
        assert_eq!(a.host, "hub.example.com");
        assert!(!a.is_ipv6);
        assert_eq!(a.explicit_port, None);
        assert_eq!(a.scheme, None);
        assert_eq!(a.path_and_query, None);
        assert_eq!(a.authority_str(), "hub.example.com");

        let a = authority("hub.example.com:16666");
        assert_eq!(a.host, "hub.example.com");
        assert_eq!(a.explicit_port, Some(16_666));
    }

    #[test]
    fn dotted_host_with_port_is_an_authority_not_a_scheme() {
        // The trap this module exists for: `Uri`-first parsing would read
        // `example.com` as the scheme. The shared parser must treat this
        // as host + port.
        let a = endpoint("example.com:16666");
        assert_eq!(a.host, "example.com");
        assert_eq!(a.scheme, None);
        assert_eq!(a.explicit_port, Some(16_666));
    }

    #[test]
    fn ipv6_brackets_are_stripped_from_host_but_kept_for_dialing() {
        let a = authority("[2001:db8::1]:16666");
        assert_eq!(a.host, "2001:db8::1");
        assert!(a.is_ipv6);
        assert_eq!(a.explicit_port, Some(16_666));
        assert_eq!(a.authority_str(), "[2001:db8::1]:16666");
    }

    #[test]
    fn portless_ipv6_bracketed_authority_parses() {
        let a = authority("[::1]");
        assert_eq!(a.host, "::1");
        assert!(a.is_ipv6);
        assert_eq!(a.explicit_port, None);
    }

    #[test]
    fn endpoint_url_components() {
        let e = endpoint("https://hub.example.com:16666/base?token=1");
        assert_eq!(e.scheme.as_deref(), Some("https"));
        assert_eq!(e.host, "hub.example.com");
        assert_eq!(e.explicit_port, Some(16_666));
        assert_eq!(e.path_and_query.as_deref(), Some("/base?token=1"));
        assert_eq!(e.authority_str(), "hub.example.com:16666");

        // bare "/" path is normalized away: nothing to interpret
        let e = endpoint("https://hub.example.com/");
        assert_eq!(e.path_and_query, None);

        // scheme is lowercased for comparison; original case preserved in
        // the rendered authority
        let e = endpoint("HTTPS://Hub.Example.COM");
        assert_eq!(e.scheme.as_deref(), Some("https"));
        assert_eq!(e.authority_str(), "Hub.Example.COM");
    }

    #[test]
    fn surrounding_whitespace_is_trimmed() {
        let a = authority("  hub.example.com:443 \r\n");
        assert_eq!(a.host, "hub.example.com");
        assert_eq!(a.explicit_port, Some(443));
    }

    #[test]
    fn rejections_fail_closed() {
        use EndpointParseError::*;

        // userinfo is never an authority
        assert_eq!(
            parse_authority("user:secret@host:443"),
            Err(Invalid("user:secret@host:443".into()))
        );
        assert_eq!(
            parse_endpoint("https://user@host/"),
            Err(Invalid("https://user@host/".into()))
        );

        // empty host / empty input (http accepts a port-only authority; the
        // product rule rejects it with the more specific variant)
        assert_eq!(parse_authority(""), Err(Invalid(String::new())));
        assert_eq!(parse_authority(":16666"), Err(EmptyHost(":16666".into())));
        assert_eq!(parse_authority("[],:1"), Err(EmptyHost("[],:1".into())));

        // invalid / out-of-range ports
        assert_eq!(
            parse_authority("host:99999"),
            Err(Invalid("host:99999".into()))
        );
        assert_eq!(
            parse_authority("host:port"),
            Err(Invalid("host:port".into()))
        );
        assert_eq!(parse_authority("host:"), Err(Invalid("host:".into())));

        // bare (unbracketed) IPv6 is not an authority
        assert_eq!(parse_authority("::1"), Err(Invalid("::1".into())));

        // zone ids are link-local and rejected
        assert_eq!(
            parse_authority("[fe80::1%eth0]"),
            Err(ZoneId("[fe80::1%eth0]".into()))
        );

        // non-ASCII hosts fail closed — `http` rejects them outright; the
        // parser's own NonAsciiHost guard is belt-and-braces for a future
        // http version accepting UTF-8 reg-names (still no IDNA translation)
        assert!(
            parse_authority("例え.jp").is_err(),
            "non-ASCII hosts must fail closed"
        );

        // endpoints accept only http/https
        assert_eq!(
            parse_endpoint("ftp://host/"),
            Err(UnsupportedScheme("ftp".into()))
        );
        assert_eq!(
            parse_endpoint("htps://host/"),
            Err(UnsupportedScheme("htps".into()))
        );

        // paths do not leak into a bare-authority parse
        assert_eq!(
            parse_authority("host/path"),
            Err(Invalid("host/path".into()))
        );

        // `//host` authority-form URIs have no scheme marker; `http::Uri`
        // does not expose an authority for them, so they fail closed rather
        // than being half-parsed (no call site emits this form)
        assert!(parse_endpoint("//host:443/x").is_err());
    }

    #[test]
    fn no_implicit_port_is_ever_derived() {
        // The product decision: never guess 80/443. Scheme presence must not
        // synthesize a port.
        assert_eq!(endpoint("https://host").explicit_port, None);
        assert_eq!(endpoint("http://host").explicit_port, None);
        assert_eq!(authority("host").explicit_port, None);
    }
}
