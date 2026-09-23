//! Hard SSRF blocklist: whatever `allowed_targets` says, these targets are
//! always denied.
//!
//! What this guards:
//! - cloud metadata services (AWS/Azure/GCP/Alibaba): leaking IMDS
//!   credentials = account takeover
//! - link-local addresses (169.254.0.0/16, fe80::/10): cloud metadata +
//!   DHCP/ARP attack surface
//!
//! Note: `is_ssrf_blocked` only does string + IP-literal checks. Checking
//! the IP after hostname resolution is the egress `resolve_and_check`'s job
//! (guards against the DNS rebinding TOCTOU).

use std::net::IpAddr;

/// Hard-denied hostnames (case-insensitive). A port, if present, is
/// stripped automatically.
///
/// List sources:
/// - `169.254.169.254` — AWS/Azure/GCP metadata IPv4
/// - `metadata.google.internal` / `metadata.google.com` — GCP metadata DNS
/// - `metadata` — GCP metadata short name
/// - `metadata.azure.com` — Azure metadata DNS
/// - `100.100.100.200` — Alibaba Cloud metadata
const HARD_DENY_HOSTNAMES: &[&str] = &[
    "169.254.169.254",
    "metadata.google.internal",
    "metadata.google.com",
    "metadata",
    "metadata.azure.com",
    "100.100.100.200",
];

/// Extract the host part from a target string (strips the port and square
/// brackets) via the shared authority parser.
///
/// Accepts: `host` / `host:port` / `[::1]` / `[::1]:port` / `1.2.3.4` /
/// `1.2.3.4:port`. Forms the parser rejects (bare unbracketed IPv6,
/// malformed brackets, garbage ports) are returned whole: the deny
/// comparison simply misses them and the dial path rejects them — fail
/// closed downstream, same as before.
fn extract_host(target: &str) -> String {
    let t = target.trim();
    interflow_util::parse_authority(t).map_or_else(|_| t.to_owned(), |parsed| parsed.host)
}

/// Check at the string level whether a target hits the SSRF blocklist.
///
/// - After stripping the port/brackets, compare case-insensitively against
///   `HARD_DENY_HOSTNAMES`
/// - If the host parses as an `IpAddr`, also check `is_ip_ssrf_blocked`
pub(crate) fn is_ssrf_blocked(target: &str) -> bool {
    let host = extract_host(target);
    let lower = host.to_ascii_lowercase();
    if HARD_DENY_HOSTNAMES.contains(&lower.as_str()) {
        return true;
    }
    if let Ok(ip) = host.parse::<IpAddr>() {
        return is_ip_ssrf_blocked(ip);
    }
    false
}

/// Check at the IP level: link-local or a known cloud-metadata IP.
///
/// - `is_link_local()` covers 169.254.0.0/16 (IPv4) and fe80::/10 (IPv6)
/// - Exact match on 169.254.169.254 (belt-and-braces, so even a flawed
///   is_link_local implementation does not miss it)
/// - Exact match on 100.100.100.200 (Alibaba metadata, not link-local)
pub fn is_ip_ssrf_blocked(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => {
            v4.is_link_local()
                || v4 == std::net::Ipv4Addr::new(169, 254, 169, 254)
                || v4 == std::net::Ipv4Addr::new(100, 100, 100, 200)
        }
        IpAddr::V6(v6) => {
            // fe80::/10 is IPv6 link-local
            (v6.segments()[0] & 0xffc0) == 0xfe80
                || v6 == std::net::Ipv6Addr::UNSPECIFIED
                // IPv6-mapped 169.254.169.254 (::ffff:a9fe:a9fe)
                || v6.to_ipv4_mapped().is_some_and(is_ip_ssrf_blocked_v4_mapped)
        }
    }
}

fn is_ip_ssrf_blocked_v4_mapped(v4: std::net::Ipv4Addr) -> bool {
    v4.is_link_local()
        || v4 == std::net::Ipv4Addr::new(169, 254, 169, 254)
        || v4 == std::net::Ipv4Addr::new(100, 100, 100, 200)
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
    fn blocks_aws_metadata_ip() {
        assert!(is_ssrf_blocked("169.254.169.254"));
        assert!(is_ssrf_blocked("169.254.169.254:80"));
        assert!(is_ip_ssrf_blocked("169.254.169.254".parse().unwrap()));
    }

    #[test]
    fn blocks_link_local_range() {
        assert!(is_ssrf_blocked("169.254.0.1"));
        assert!(is_ssrf_blocked("169.254.255.254:443"));
        assert!(is_ip_ssrf_blocked("169.254.42.42".parse().unwrap()));
    }

    #[test]
    fn blocks_gcp_metadata_hostnames() {
        assert!(is_ssrf_blocked("metadata.google.internal"));
        assert!(is_ssrf_blocked("metadata.google.internal:80"));
        assert!(is_ssrf_blocked("METADATA.GOOGLE.INTERNAL")); // case-insensitive
        assert!(is_ssrf_blocked("metadata.google.com"));
        assert!(is_ssrf_blocked("metadata"));
        assert!(is_ssrf_blocked("metadata:80"));
    }

    #[test]
    fn blocks_azure_metadata_hostname() {
        assert!(is_ssrf_blocked("metadata.azure.com"));
        assert!(is_ssrf_blocked("metadata.azure.com:443"));
    }

    #[test]
    fn blocks_alibaba_metadata_ip() {
        assert!(is_ssrf_blocked("100.100.100.200"));
        assert!(is_ssrf_blocked("100.100.100.200:80"));
    }

    #[test]
    fn blocks_ipv6_link_local() {
        assert!(is_ssrf_blocked("[fe80::1]"));
        assert!(is_ssrf_blocked("[fe80::1]:80"));
        assert!(is_ssrf_blocked("[febf::1]")); // febf is within fe80::/10 (fe8x-febx)
        assert!(is_ip_ssrf_blocked("fe80::1".parse().unwrap()));
    }

    #[test]
    fn blocks_ipv6_mapped_metadata() {
        // ::ffff:a9fe:a9fe = IPv6-mapped 169.254.169.254
        assert!(is_ssrf_blocked("[::ffff:169.254.169.254]"));
    }

    #[test]
    fn allows_normal_intranet_targets() {
        assert!(!is_ssrf_blocked("192.168.1.5:3000"));
        assert!(!is_ssrf_blocked("10.0.0.1"));
        assert!(!is_ssrf_blocked("172.16.0.1:5432"));
        assert!(!is_ssrf_blocked("127.0.0.1:8080"));
        assert!(!is_ssrf_blocked("example.internal:443"));
        assert!(!is_ssrf_blocked("[::1]:8080")); // loopback is not link-local
        assert!(!is_ssrf_blocked("[2001:db8::1]:443"));
    }

    #[test]
    fn does_not_block_lookalike_hostnames() {
        // Prefix spoofing: contains a blocklisted substring but is not an
        // exact match
        assert!(!is_ssrf_blocked("169.254.169.254.evil.com"));
        assert!(!is_ssrf_blocked("metadata.evil.com"));
        assert!(!is_ssrf_blocked("not-metadata.google.internal"));
    }

    #[test]
    fn extract_host_handles_various_forms() {
        assert_eq!(extract_host("1.2.3.4"), "1.2.3.4");
        assert_eq!(extract_host("1.2.3.4:80"), "1.2.3.4");
        assert_eq!(extract_host("[::1]:80"), "::1");
        assert_eq!(extract_host("[fe80::1]"), "fe80::1");
        assert_eq!(extract_host("example.com:443"), "example.com");
        assert_eq!(extract_host("example.com"), "example.com");
        // surrounding whitespace is trimmed
        assert_eq!(extract_host("  example.com:443\r\n"), "example.com");
    }

    #[test]
    fn unparseable_targets_pass_through_whole_and_still_fail_closed() {
        // Forms the authority parser rejects keep the old defer semantics:
        // returned whole, missed by the string deny list, and rejected by
        // the dial path's own parsing. The bare IPv6 still parses as an
        // IpAddr for the IP-level check.
        assert_eq!(extract_host("::1"), "::1");
        assert_eq!(extract_host("[malformed"), "[malformed");
        assert!(!is_ssrf_blocked("[malformed"));
        // bare unbracketed IPv6 still reaches the IP-level check
        assert!(is_ssrf_blocked("::ffff:169.254.169.254"));
    }
}
