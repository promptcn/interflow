//! Per-client identity for admission controls (rate limits, connection caps).
//!
//! Every per-client budget in this layer is keyed on a [`ClientKey`], never
//! on a raw [`IpAddr`]: what counts as "one client" is defined here, once.
//!
//! - **IPv4-mapped IPv6 addresses fold to IPv4.** A dual-stack listener
//!   reports an IPv4 peer as `::ffff:a.b.c.d` while a fronting proxy's
//!   X-Forwarded-For / PROXY header may carry the plain form — one client,
//!   two spellings, which must not mean two budgets.
//! - **IPv6 clients are keyed by their /64.** A /64 is the smallest prefix
//!   an IPv6 site is routed (SLAAC subnets are /64), so one host can rotate
//!   through 2^64 source addresses at will. Keyed per address, a per-client
//!   limit is bypassed by rotation and one attacker can mint an unbounded
//!   number of keys; keyed per /64, the subnet shares one budget — the same
//!   trade IPv4 NAT already makes for the hosts behind one address.
//!
//! The key is for budget accounting only: trust decisions (trusted-proxy
//! CIDR matching), logs and audit records keep the exact address.

use std::fmt;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

/// One client as every per-client budget counts it: an IPv4 address
/// (IPv4-mapped IPv6 spellings included), or the /64 an IPv6 address
/// belongs to.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ClientKey {
    /// An IPv4 client.
    V4(Ipv4Addr),
    /// An IPv6 client's /64 network prefix (the leading four segments).
    V6Net([u16; 4]),
}

impl From<IpAddr> for ClientKey {
    fn from(ip: IpAddr) -> Self {
        match ip.to_canonical() {
            IpAddr::V4(ip) => Self::V4(ip),
            IpAddr::V6(ip) => {
                let seg = ip.segments();
                Self::V6Net([seg[0], seg[1], seg[2], seg[3]])
            }
        }
    }
}

impl fmt::Display for ClientKey {
    /// `198.51.100.7` for an IPv4 client, `2001:db8:1:2::/64` for an IPv6 one.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match *self {
            Self::V4(ip) => ip.fmt(f),
            Self::V6Net(prefix) => {
                let net = Ipv6Addr::new(prefix[0], prefix[1], prefix[2], prefix[3], 0, 0, 0, 0);
                write!(f, "{net}/64")
            }
        }
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

    fn key(ip: &str) -> ClientKey {
        ClientKey::from(ip.parse::<IpAddr>().unwrap())
    }

    #[test]
    fn mapped_ipv4_is_the_same_client_as_plain_ipv4() {
        assert_eq!(key("::ffff:198.51.100.7"), key("198.51.100.7"));
        assert_eq!(key("::ffff:198.51.100.7").to_string(), "198.51.100.7");
    }

    #[test]
    fn one_ipv6_slash64_is_one_client() {
        assert_eq!(
            key("2001:db8:1:2::a"),
            key("2001:db8:1:2:ffff:ffff:ffff:ffff")
        );
        assert_ne!(key("2001:db8:1:2::a"), key("2001:db8:1:3::a"));
        assert_eq!(key("2001:db8:1:2::a").to_string(), "2001:db8:1:2::/64");
    }

    #[test]
    fn ipv4_and_ipv6_keys_never_collide() {
        // Same numeric content on both sides: the variant keeps them apart.
        assert_ne!(key("0.0.0.0"), key("::"));
        // IPv4-compatible (deprecated, not mapped) stays an IPv6 key.
        assert_ne!(key("::198.51.100.7"), key("198.51.100.7"));
    }

    #[test]
    fn distinct_ipv4_addresses_stay_distinct() {
        assert_ne!(key("198.51.100.7"), key("198.51.100.8"));
    }
}
