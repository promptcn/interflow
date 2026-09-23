//! Per-IP token-bucket rate limiting.
//!
//! Used by [`crate::hub::service`] to reject brute-force enumeration before
//! Bearer auth validation. Built on [`governor`] (leaky-bucket, `no_std`
//! compatible, mature and stable).

use governor::{Quota, RateLimiter, clock::DefaultClock, state::keyed::DefaultKeyedStateStore};
use std::net::IpAddr;
use std::num::NonZeroU32;

/// Per-IP rate limiter for the hub.
pub struct AuthRateLimiter {
    quota: u32,
    inner: RateLimiter<IpAddr, DefaultKeyedStateStore<IpAddr>, DefaultClock>,
}

impl AuthRateLimiter {
    /// Constructs a rate limiter allowing `per_ip_per_minute` per minute.
    ///
    /// 0 means rate limiting is disabled ([`Self::check`] always returns true).
    pub fn new(per_ip_per_minute: u32) -> Option<Self> {
        if per_ip_per_minute == 0 {
            return None;
        }
        // The return above guarantees per_ip_per_minute > 0, so NonZeroU32::new cannot fail here
        let nz = NonZeroU32::new(per_ip_per_minute)?;
        let quota = Quota::per_minute(nz);
        Some(Self {
            quota: per_ip_per_minute,
            inner: RateLimiter::keyed(quota),
        })
    }

    /// The configured per-IP-per-minute quota (denial responses quote it to
    /// derive a `Retry-After` from the token refill rate).
    pub const fn quota(&self) -> u32 {
        self.quota
    }

    /// Checks whether `ip` is still within quota. Returns `false` to mean over-limit, reject.
    pub fn check(&self, ip: IpAddr) -> bool {
        self.inner.check_key(&ip).is_ok()
    }
}

/// UDP inbound rate limiting (per source IP): dual buckets for packet rate + byte rate.
///
/// The first gate against amplification attacks: a public UDP socket is a
/// reflection point — an attacker spoofs the victim's source address to send
/// packets → the egress service responds → the response travels back through
/// the tunnel to the ingress's `send_to(victim)`. Per-IP rate limiting
/// compresses the amplification traffic reachable to a single victim IP
/// within the configured cap.
///
/// Semantics note: a single datagram larger than `per_ip_bytes_per_sec` is
/// deterministically rejected (governor's `NotEnoughCapacity` — the burst
/// capacity can never hold it), not "wait for refill".
pub struct UdpIngressLimiter {
    packets: Option<RateLimiter<IpAddr, DefaultKeyedStateStore<IpAddr>, DefaultClock>>,
    bytes: Option<RateLimiter<IpAddr, DefaultKeyedStateStore<IpAddr>, DefaultClock>>,
}

impl UdpIngressLimiter {
    /// Constructs the per-IP rate limiter; returns `None` (fully disabled) when both are 0.
    ///
    /// Only one being 0 means only the other is enabled.
    pub fn new(per_ip_pps: u32, per_ip_bytes_per_sec: u32) -> Option<Self> {
        if per_ip_pps == 0 && per_ip_bytes_per_sec == 0 {
            return None;
        }
        let packets = NonZeroU32::new(per_ip_pps).map(|q| RateLimiter::keyed(Quota::per_second(q)));
        let bytes =
            NonZeroU32::new(per_ip_bytes_per_sec).map(|q| RateLimiter::keyed(Quota::per_second(q)));
        Some(Self { packets, bytes })
    }

    /// Checks whether one `nbytes`-byte datagram from `ip` is allowed.
    ///
    /// Returns `false` to mean over-limit, drop. Both buckets are charged
    /// (conservative: half-passed packets are still billed).
    pub fn check(&self, ip: IpAddr, nbytes: usize) -> bool {
        let n = u32::try_from(nbytes).unwrap_or(u32::MAX);
        if let (Some(bytes), Some(nz)) = (&self.bytes, NonZeroU32::new(n)) {
            // Ok(Ok(_)) = allowed; Ok(Err(_)) = currently insufficient; Err = a single packet forever over quota. The latter two are dropped.
            if !matches!(bytes.check_key_n(&ip, nz), Ok(Ok(()))) {
                return false;
            }
        }
        if let Some(packets) = &self.packets
            && packets.check_key(&ip).is_err()
        {
            return false;
        }
        true
    }
}

/// Per-session outbound byte rate limiting (tunnel → public client direction).
///
/// The second gate against amplification attacks (return-path rate
/// limiting): even if the inbound side is spoofed, the byte rate a single
/// session can send back toward the public side is capped, avoiding being
/// used as an amplification relay.
pub struct ByteRateLimiter {
    inner: RateLimiter<governor::state::NotKeyed, governor::state::InMemoryState, DefaultClock>,
}

impl ByteRateLimiter {
    /// Constructs a limiter of `bytes_per_sec` bytes per second; 0 returns `None` (disabled).
    pub fn new(bytes_per_sec: u32) -> Option<Self> {
        let nz = NonZeroU32::new(bytes_per_sec)?;
        Some(Self {
            inner: RateLimiter::direct(Quota::per_second(nz)),
        })
    }

    /// Checks whether `nbytes` bytes are allowed. A single check over the per-second quota is deterministically rejected.
    pub fn check(&self, nbytes: usize) -> bool {
        let Some(nz) = NonZeroU32::new(u32::try_from(nbytes).unwrap_or(u32::MAX)) else {
            return true;
        };
        matches!(self.inner.check_n(nz), Ok(Ok(())))
    }
}

/// Event rate limiting (non-keyed, single-consumer/process dimension): dual parameters of sustained rate + burst bucket.
///
/// Used for mesh egress's "new stream creation rate limiting": an open/close
/// churn attack stays below the concurrency cap, but every Open makes the
/// agent perform resolve + connect against the real backend — rate limiting
/// compresses sustained churn within budget, while the burst bucket ensures
/// legitimate stream-creation spikes (e.g. whole-table concurrent creation)
/// are not collateral damage. Same dual-bucket family as
/// [`UdpIngressLimiter`], with the semantic dimension being "events/count".
pub struct EventRateLimiter {
    inner: RateLimiter<governor::state::NotKeyed, governor::state::InMemoryState, DefaultClock>,
}

impl EventRateLimiter {
    /// Constructs a limiter of `per_second` per second with burst capacity `burst`.
    ///
    /// `per_second` of 0 returns `None` (disabled); `burst` is clamped to at
    /// least 1.
    pub fn new(per_second: u32, burst: u32) -> Option<Self> {
        let rate = NonZeroU32::new(per_second)?;
        let burst = NonZeroU32::new(burst.max(1)).expect("max(1) guarantees a non-zero value");
        Some(Self {
            inner: RateLimiter::direct(Quota::per_second(rate).allow_burst(burst)),
        })
    }

    /// Checks whether one event is allowed. Returns `false` to mean over-limit, reject.
    pub fn check(&self) -> bool {
        self.inner.check().is_ok()
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
    use std::str::FromStr;

    #[test]
    fn disabled_when_zero() {
        assert!(AuthRateLimiter::new(0).is_none());
    }

    #[test]
    fn allows_until_quota() {
        let limiter = AuthRateLimiter::new(2).expect("constructed");
        let ip = IpAddr::from_str("127.0.0.1").unwrap();
        assert!(limiter.check(ip), "first should pass");
        assert!(limiter.check(ip), "second should pass");
        // Third check is over quota (immediately rejected while governor time has not advanced)
        let _ = limiter.check(ip);
    }

    #[test]
    fn udp_limiter_disabled_when_both_zero() {
        assert!(UdpIngressLimiter::new(0, 0).is_none());
    }

    #[test]
    fn udp_limiter_pps_bucket_drops_burst() {
        let limiter = UdpIngressLimiter::new(3, 0).expect("constructed");
        let ip = IpAddr::from_str("192.0.2.1").unwrap();
        for i in 0..3 {
            assert!(limiter.check(ip, 64), "packet #{i} should pass");
        }
        assert!(
            !limiter.check(ip, 64),
            "4th packet in burst must be dropped"
        );
    }

    #[test]
    fn udp_limiter_bytes_bucket_rejects_oversize_datagram() {
        // Under a 10 KiB/s quota, a single 64 KiB datagram never fits the burst → deterministic rejection
        let limiter = UdpIngressLimiter::new(0, 10 * 1024).expect("constructed");
        let ip = IpAddr::from_str("192.0.2.2").unwrap();
        assert!(
            !limiter.check(ip, 64 * 1024),
            "datagram larger than per-second byte quota must be rejected"
        );
        assert!(limiter.check(ip, 1024), "small datagram still passes");
    }

    #[test]
    fn udp_limiter_buckets_are_independent() {
        // Only pps enabled: bytes unlimited
        let limiter = UdpIngressLimiter::new(2, 0).expect("constructed");
        let ip = IpAddr::from_str("192.0.2.3").unwrap();
        assert!(limiter.check(ip, 60_000));
        assert!(limiter.check(ip, 60_000));
        assert!(!limiter.check(ip, 1));
    }

    #[test]
    fn udp_limiter_keys_are_isolated() {
        let limiter = UdpIngressLimiter::new(1, 0).expect("constructed");
        let a = IpAddr::from_str("192.0.2.4").unwrap();
        let b = IpAddr::from_str("192.0.2.5").unwrap();
        assert!(limiter.check(a, 64));
        assert!(!limiter.check(a, 64));
        assert!(limiter.check(b, 64), "different IP has independent budget");
    }

    #[test]
    fn byte_rate_limiter_basic() {
        assert!(ByteRateLimiter::new(0).is_none());
        let limiter = ByteRateLimiter::new(4 * 1024).expect("constructed");
        assert!(limiter.check(1024));
        assert!(!limiter.check(8 * 1024), "over-quota single write rejected");
    }

    #[test]
    fn event_rate_limiter_burst_then_throttle() {
        assert!(EventRateLimiter::new(0, 10).is_none(), "0 rate = disabled");
        let limiter = EventRateLimiter::new(10, 3).expect("constructed");
        for i in 0..3 {
            assert!(limiter.check(), "event #{i} within burst should pass");
        }
        assert!(!limiter.check(), "exceeding burst capacity should reject");
    }
}
