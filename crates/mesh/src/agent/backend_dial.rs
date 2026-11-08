//! Shared backend-dial support: target resolution with the SSRF filter, and
//! loopback classification.
//!
//! The 2026-09-16 egress hardening inlined resolve-then-filter twice (the
//! TCP forwarder and the inner-QUIC UDP backend); the 2026-10-18 recovery
//! prober ([`super::breaker_probe`]) would have been a third copy. One
//! constructor now owns the sequence — resolve (bounded), then pick the
//! first address the SSRF blocklist does not deny — so all three dialing
//! populations see identical semantics. The checked IP is the connected IP
//! (callers connect to exactly what this returns).

use std::net::SocketAddr;
use std::time::Duration;

/// Why [`resolve_first_allowed`] could not produce a dialable address.
#[derive(Debug)]
pub(crate) enum BackendResolveError {
    /// DNS resolution failed (the resolver answered with an error).
    Failed(String),
    /// Resolution exceeded its budget (a black-hole resolver).
    TimedOut,
    /// Every resolved address is on the SSRF blocklist — the target names
    /// infrastructure this agent must never dial.
    SsrfBlocked,
}

impl std::fmt::Display for BackendResolveError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Failed(e) => write!(f, "resolve failed: {e}"),
            Self::TimedOut => write!(f, "resolve timed out"),
            Self::SsrfBlocked => write!(f, "all resolved IPs hit the SSRF blocklist"),
        }
    }
}

/// Resolves `target` (`host:port`; IP literals trigger no DNS) and returns
/// the first address passing the SSRF filter — the one address every dialing
/// path (TCP forwarder, UDP backend, recovery prober) actually connects to.
pub(crate) async fn resolve_first_allowed(
    target: &str,
    resolve_timeout: Duration,
) -> Result<SocketAddr, BackendResolveError> {
    let resolved =
        match tokio::time::timeout(resolve_timeout, tokio::net::lookup_host(target)).await {
            Ok(Ok(addrs)) => addrs.collect::<Vec<_>>(),
            Ok(Err(e)) => return Err(BackendResolveError::Failed(e.to_string())),
            Err(_) => return Err(BackendResolveError::TimedOut),
        };
    resolved
        .into_iter()
        .find(|sa| !super::ssrf_deny::is_ip_ssrf_blocked(sa.ip()))
        .ok_or(BackendResolveError::SsrfBlocked)
}

/// Whether `target` names a loopback dial endpoint.
///
/// Parses strictly to avoid prefix spoofing (e.g. `127.0.0.1.evil.com` /
/// `localhostx` / `localhost:65535.evil`); accepts `host:port` /
/// `[::1]:port` / `host` / `::1` forms. Shared by the egress allowlist's
/// default (loopback-only) and the recovery prober's loopback/remote
/// cadence split.
#[must_use]
pub fn is_loopback_target(target: &str) -> bool {
    // 1) Whole-string SocketAddr parse (covers "127.0.0.1:80" and "[::1]:80")
    if let Ok(sa) = target.parse::<SocketAddr>() {
        return sa.ip().is_loopback();
    }
    // 2) Whole-string IpAddr parse (covers "127.0.0.1" / "::1")
    if let Ok(ip) = target.parse::<std::net::IpAddr>() {
        return ip.is_loopback();
    }
    // 3) Split as host[:port] (only when the target has no extra colons)
    if !target.starts_with('[')
        && let Some((host, _port)) = target.rsplit_once(':')
    {
        if host.eq_ignore_ascii_case("localhost") {
            return true;
        }
        if let Ok(ip) = host.parse::<std::net::IpAddr>() {
            return ip.is_loopback();
        }
    }
    // 4) Bracket-stripped IPv6 forms
    let stripped = target.trim_start_matches('[').trim_end_matches(']');
    if stripped.eq_ignore_ascii_case("localhost") {
        return true;
    }
    stripped
        .parse::<std::net::IpAddr>()
        .is_ok_and(|ip| ip.is_loopback())
}
