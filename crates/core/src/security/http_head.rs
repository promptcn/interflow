//! Shared HTTP/1.x request-head parsing for the edge's peek paths.
//!
//! The edge listener (Host routing), the ACME HTTP-01 responder and the
//! X-Forwarded-For restoration each need to look into a buffered request
//! head. They used to carry three hand-written scanners that had already
//! diverged (the two `find_headers_end` copies disagreed on mixed
//! LF/CRLF blank lines). This module is the single parser: [`httparse`]
//! owns RFC 7230 syntax (request line, header names, obs-fold rejection,
//! bare-CR rejection, LF-only tolerance), and Interflow's product policy —
//! duplicate-Host rejection, Host charset/length, header-count ceilings —
//! is layered on top in [`validated_host`].
//!
//! Semantics preserved from the hand-written scanners:
//!
//! - LF-only and CRLF line endings are both accepted;
//! - only the header region (up to the blank line) is ever inspected, so
//!   binary body bytes cannot smuggle headers;
//! - a second valid `Host` header rejects the whole connection
//!   (anti-smuggling);
//! - empty Host values are treated as absent.

/// Maximum number of bytes buffered while reading an HTTP/1.x request head.
pub const HTTP_HEAD_MAX_BYTES: usize = 8 * 1024;

/// Maximum allowed length of the Host header value.
pub const HOST_MAX_LEN: usize = 255;

/// Header-count ceiling per request head. The ACME path always enforced
/// this via `httparse`; the Host-peek path previously had no limit and now
/// inherits the same one.
pub const MAX_HEAD_HEADERS: usize = 100;

/// Validates Host-authority characters.
///
/// The value may contain a bracketed IPv6 literal and an optional port;
/// callers that need to remove the port use an authority-aware normalizer
/// rather than a blind suffix split.
#[must_use]
pub fn is_valid_host(s: &str) -> bool {
    s.chars().all(|c| {
        c.is_ascii_alphanumeric() || c == '.' || c == '-' || c == ':' || c == '[' || c == ']'
    })
}

/// Locates the end of the HTTP/1.x header region (the blank line), or
/// `None` while the head is incomplete.
///
/// Accepts every mix of LF and CRLF line endings — `\n\n`, `\n\r\n`,
/// `\r\n\n` (via its inner LF) and `\r\n\r\n` (via the LF of the first
/// CRLF). This supersedes the two diverging copies it replaces, one of
/// which failed to recognize `\n\r\n`.
#[must_use]
pub fn find_headers_end(buf: &[u8]) -> Option<usize> {
    let mut i = 0;
    while i < buf.len() {
        if buf[i] == b'\n'
            && let Some(&next) = buf.get(i + 1)
            && (next == b'\n' || (next == b'\r' && buf.get(i + 2) == Some(&b'\n')))
        {
            return Some(i + if next == b'\n' { 2 } else { 3 });
        }
        i += 1;
    }
    None
}

/// A syntactically complete request head. Header name/value slices borrow
/// from the parsed buffer; nothing beyond the blank line is touched.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RequestHead<'a> {
    /// Request method (e.g. `GET`).
    pub method: &'a str,
    /// Request target as spelled on the request line.
    pub target: &'a str,
    /// HTTP minor version: 0 for HTTP/1.0, 1 for HTTP/1.1.
    pub version: u8,
    /// Headers of the head region, in order.
    pub headers: Vec<httparse::Header<'a>>,
}

/// Outcome of [`parse_request_head`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HeadParse<'a> {
    /// The head is incomplete — keep reading bytes.
    Partial,
    /// The head parsed completely.
    Complete(RequestHead<'a>),
    /// The head is malformed or unsupported — reject the connection.
    Invalid(HeadInvalid),
}

/// Rejection reasons, spelled for metrics/audit labels.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HeadInvalid {
    /// More than [`MAX_HEAD_HEADERS`] header lines.
    TooManyHeaders,
    /// A completed parse carried a minor version other than 0/1.
    /// (httparse rejects non-1.x version labels before completing, so this
    /// is currently unreachable — the guard exists for a future parser
    /// relaxing that.)
    UnsupportedVersion,
    /// Syntax error: bad request line, bare CR, obs-fold continuation,
    /// invalid header name, …
    Malformed,
}

impl HeadInvalid {
    /// Metric/audit label for this rejection.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::TooManyHeaders => "too_many_headers",
            Self::UnsupportedVersion => "unsupported_http_version",
            Self::Malformed => "malformed_request",
        }
    }
}

/// Parses a buffered request head with `httparse`.
///
/// `Partial` means "need more bytes", never "partially valid": callers
/// must not route on partial data. obs-fold (continuation lines starting
/// with SP/HTAB) is rejected by `httparse` — a folded header is a
/// malformed head, which is the fail-closed answer.
#[must_use]
pub fn parse_request_head(buf: &[u8]) -> HeadParse<'_> {
    let mut headers = [httparse::EMPTY_HEADER; MAX_HEAD_HEADERS];
    let mut request = httparse::Request::new(&mut headers);
    match request.parse(buf) {
        Ok(httparse::Status::Complete(_)) => {
            // httparse only completes with minor versions 0/1 (anything
            // else — the h2 preface, HTTP/1.9 — is an Err(Version) below);
            // the filter is defense-in-depth for a future parser relaxing
            // that.
            let Some(version) = request.version.filter(|v| *v <= 1) else {
                return HeadParse::Invalid(HeadInvalid::UnsupportedVersion);
            };
            let (Some(method), Some(target)) = (request.method, request.path) else {
                return HeadParse::Invalid(HeadInvalid::Malformed);
            };
            HeadParse::Complete(RequestHead {
                method,
                target,
                version,
                headers: request.headers.to_vec(),
            })
        }
        // Err(Version) covers both genuinely unsupported version labels and
        // request lines whose shape derails the version scan (e.g. a space
        // inside the target); the hand-written paths called all of these
        // "malformed_request", so the label stays.
        Ok(httparse::Status::Partial) => HeadParse::Partial,
        Err(httparse::Error::TooManyHeaders) => HeadParse::Invalid(HeadInvalid::TooManyHeaders),
        Err(_) => HeadParse::Invalid(HeadInvalid::Malformed),
    }
}

/// Host-header policy failures.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HostError {
    /// No non-empty `Host` header in the head.
    Missing,
    /// More than one valid `Host` header.
    Duplicate,
    /// Host value longer than [`HOST_MAX_LEN`].
    TooLong,
    /// Host value failed UTF-8 or charset validation.
    InvalidChars,
}

impl HostError {
    /// Metric/audit label for this rejection.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Missing => "missing_host",
            Self::Duplicate => "duplicate_host",
            Self::TooLong => "host_too_long",
            Self::InvalidChars => "host_invalid_chars",
        }
    }
}

/// Extracts and validates the single `Host` header of a parsed head.
///
/// Policy (unchanged from the hand-written scanners it replaces): the
/// first valid host wins, a second valid host rejects the connection
/// (anti-smuggling), any invalid value (bad UTF-8, bad charset, too long)
/// rejects immediately, and empty values are treated as absent.
pub fn validated_host<'a>(headers: &'a [httparse::Header<'a>]) -> Result<&'a str, HostError> {
    let mut found: Option<&str> = None;
    for header in headers {
        if !header.name.eq_ignore_ascii_case("host") {
            continue;
        }
        let Ok(value) = std::str::from_utf8(header.value) else {
            return Err(HostError::InvalidChars);
        };
        let value = value.trim_ascii();
        if value.is_empty() {
            // An empty Host line is treated as absent, not invalid.
            continue;
        }
        if value.len() > HOST_MAX_LEN {
            return Err(HostError::TooLong);
        }
        if !is_valid_host(value) {
            return Err(HostError::InvalidChars);
        }
        if found.is_some() {
            return Err(HostError::Duplicate);
        }
        found = Some(value);
    }
    found.ok_or(HostError::Missing)
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

    fn head_of(buf: &[u8]) -> RequestHead<'_> {
        match parse_request_head(buf) {
            HeadParse::Complete(head) => head,
            other => panic!("expected complete head, got {other:?}"),
        }
    }

    #[test]
    fn find_headers_end_accepts_all_blank_line_spellings() {
        // The four LF/CRLF combinations; the two old hand-written scanners
        // disagreed on the mixed ones. Expectations are the byte index just
        // past the blank line (i.e. the first body byte, or the buffer end).
        let a = b"GET / HTTP/1.1\nHost: x\n\nbody";
        assert_eq!(find_headers_end(a), Some(a.len() - b"body".len()));
        let b = b"GET / HTTP/1.1\nHost: x\n\r\n";
        assert_eq!(find_headers_end(b), Some(b.len()));
        let c = b"GET / HTTP/1.1\r\nHost: x\r\n\n";
        assert_eq!(find_headers_end(c), Some(c.len()));
        let d = b"GET / HTTP/1.1\r\nHost: x\r\n\r\nbody";
        assert_eq!(find_headers_end(d), Some(d.len() - b"body".len()));
        // Incomplete head: no blank line yet
        assert_eq!(find_headers_end(b"GET / HTTP/1.1\r\nHost: x"), None);
        assert_eq!(find_headers_end(b""), None);
        assert_eq!(find_headers_end(b"GET / HTTP/1.1\r\nHost: x\r\n\r"), None);
    }

    #[test]
    fn parses_method_target_version_and_headers() {
        let head = head_of(b"GET /a?q=1 HTTP/1.1\r\nHost: example.com:8443\r\nX-B: 2\r\n\r\nbody");
        assert_eq!(head.method, "GET");
        assert_eq!(head.target, "/a?q=1");
        assert_eq!(head.version, 1);
        assert_eq!(head.headers.len(), 2);
        assert_eq!(head.headers[0].name, "Host");
        assert_eq!(head.headers[0].value, b"example.com:8443");
    }

    #[test]
    fn lf_only_heads_parse() {
        // httparse tolerates bare-LF line endings (locked by an upstream
        // test; the edge scanners always did too)
        let head = head_of(b"GET / HTTP/1.1\nhost: x\nx-forwarded-for: 192.0.2.1\n\n");
        assert_eq!(
            validated_host(&head.headers).map_err(HostError::as_str),
            Ok("x")
        );
    }

    #[test]
    fn partial_until_blank_line() {
        let partial = b"GET / HTTP/1.1\r\nHost: x\r\n";
        assert_eq!(parse_request_head(partial), HeadParse::Partial);
    }

    #[test]
    fn rejects_malformed_shapes() {
        // obs-fold continuation → malformed (fail-closed: a folded header
        // is not something a conforming client or proxy emits)
        assert_eq!(
            parse_request_head(b"GET / HTTP/1.1\r\nHost: x\r\nX-Fold: a\r\n  b\r\n\r\n"),
            HeadParse::Invalid(HeadInvalid::Malformed)
        );
        // bare CR inside a header value → malformed
        assert_eq!(
            parse_request_head(b"GET / HTTP/1.1\r\nHost: a\rb\r\n\r\n"),
            HeadParse::Invalid(HeadInvalid::Malformed)
        );
        // garbage request line
        assert_eq!(
            parse_request_head(b"\x16\x03\x01\x02\x00\x01\x00\x00\x00"),
            HeadParse::Invalid(HeadInvalid::Malformed)
        );
        // h2 connection preface: httparse's Version error — labeled
        // malformed_request like every other bad request line (the label
        // the hand-written paths used)
        assert_eq!(
            parse_request_head(b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"),
            HeadParse::Invalid(HeadInvalid::Malformed)
        );
        // space inside the target derails the version scan the same way
        assert_eq!(
            parse_request_head(b"GET /path script HTTP/1.1\r\nHost: a\r\n\r\n"),
            HeadParse::Invalid(HeadInvalid::Malformed)
        );
        // header-count ceiling
        let mut many = String::from("GET / HTTP/1.1\r\n");
        for i in 0..=MAX_HEAD_HEADERS {
            many.push_str("X-N");
            many.push_str(&(i.to_string()));
            many.push_str(": v\r\n");
        }
        many.push_str("\r\n");
        assert_eq!(
            parse_request_head(many.as_bytes()),
            HeadParse::Invalid(HeadInvalid::TooManyHeaders)
        );
    }

    #[test]
    fn host_policy_matches_the_edge_semantics() {
        // owned for assertions: the parsed borrow lives inside this closure
        let host_of = |buf: &[u8]| {
            validated_host(&head_of(buf).headers)
                .map(str::to_owned)
                .map_err(HostError::as_str)
        };

        // basic, case-insensitive name, port kept, surrounding OWS trimmed
        assert_eq!(
            host_of(b"GET / HTTP/1.1\r\nHoSt: example.com:8443\r\n\r\n"),
            Ok("example.com:8443".to_owned())
        );
        assert_eq!(
            host_of(b"GET / HTTP/1.1\r\nHost:  \t[::1]:80\t \r\n\r\n"),
            Ok("[::1]:80".to_owned())
        );

        // missing → Missing; empty value treated as absent
        assert_eq!(
            host_of(b"GET / HTTP/1.1\r\nX-Other: 1\r\n\r\n"),
            Err("missing_host")
        );
        assert_eq!(
            host_of(b"GET / HTTP/1.1\r\nHost: \r\nHost: ok.example\r\n\r\n"),
            Ok("ok.example".to_owned())
        );

        // duplicate valid hosts → Duplicate (whole connection rejected)
        assert_eq!(
            host_of(b"GET / HTTP/1.1\r\nHost: a.example\r\nHost: b.example\r\n\r\n"),
            Err("duplicate_host")
        );

        // invalid charset / non-UTF-8 / too long → InvalidChars / TooLong
        assert_eq!(
            host_of(b"GET / HTTP/1.1\r\nHost: bad host\r\n\r\n"),
            Err("host_invalid_chars")
        );
        assert_eq!(
            host_of(b"GET / HTTP/1.1\r\nHost: \xff\xfe\r\n\r\n"),
            Err("host_invalid_chars")
        );
        let long = "a".repeat(HOST_MAX_LEN + 1);
        assert_eq!(
            host_of(format!("GET / HTTP/1.1\r\nHost: {long}\r\n\r\n").as_bytes()),
            Err("host_too_long")
        );

        // body bytes beyond the blank line are never scanned for headers
        assert_eq!(
            host_of(b"POST / HTTP/1.1\r\nHost: real.example\r\n\r\nHost: fake.example"),
            Ok("real.example".to_owned())
        );
    }

    #[test]
    fn binary_body_after_head_is_ignored() {
        // gzip-magic multipart body must not disturb parsing (regression:
        // the original whole-buffer UTF-8 scan timed such connections out)
        let mut buf = b"POST /upload HTTP/1.1\r\nHost: app.example\r\nContent-Type: multipart/form-data\r\n\r\n".to_vec();
        buf.extend_from_slice(&[0x1f, 0x8b, 0x08, 0x00, 0xff, 0xfe, 0x0d, 0x0a]);
        let head = head_of(&buf);
        assert_eq!(validated_host(&head.headers), Ok("app.example"));
    }
}
