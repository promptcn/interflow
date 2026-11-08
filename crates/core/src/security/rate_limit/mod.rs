//! Per-client token-bucket rate limiting.
//!
//! Used by the mesh hub (per request, against brute-force enumeration
//! before Bearer auth validation) and the expose edge (per accepted
//! connection on the public entrances). Built on [`governor`] (leaky-bucket
//! GCRA arithmetic; the state store is ours, see [`store`]).
//!
//! Keys are [`ClientKey`]s — IPv4 by address, IPv6 by /64, IPv4-mapped
//! spellings folded (see that type's docs). Idle clients expire losslessly
//! and the table has a hard bound ([`store::BoundedStore`]), so keying by
//! remote address cannot grow without end

mod store;

use std::net::IpAddr;
use std::num::NonZeroU32;

use governor::Quota;
use governor::RateLimiter;
use governor::clock::{Clock, DefaultClock};
use governor::middleware::NoOpMiddleware;
use store::BoundedStore;

use super::client_key::ClientKey;

/// Default hard bound on the distinct clients one limiter instance tracks.
///
/// Honest traffic is far under the bound: the listener whose growth exposed
/// the bug saw ~10⁴ distinct sources a day (≈7/min) — this bound sits 3-4
/// orders of magnitude above that with no legitimate eviction, and 2-3
/// below an internet scan, where dropping the debt of generation-idle keys
/// is exactly the intended degradation. ≈3 MB at worst per limiter
/// instance (see `store_capacity_is_a_memory_bound`).
///
/// Operators size it per deployment: the hub's `auth.max_tracked_clients`
/// and the edge listener's `max_tracked_clients` feed
/// [`AuthRateLimiter::with_max_tracked_clients`]; this constant is what
/// both default to. The store rounds a bound down to a whole number of
/// keys per generation per shard (multiples of 32), at least one.
pub const MAX_TRACKED_CLIENTS: usize = 65_536;

/// Where a limiter runs; names its metrics and its pressure warnings.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RateLimitScope {
    /// The expose edge's per-connection gate (the public entrances: the
    /// shared 443/:80 budget and the ACME listener).
    EdgeNewConn,
    /// The mesh hub's per-request gate.
    Hub,
}

impl RateLimitScope {
    /// The `limiter` metric-label value (also names the store's warnings).
    const fn label(self) -> &'static str {
        match self {
            Self::EdgeNewConn => "edge_new_conn",
            Self::Hub => "hub",
        }
    }
}

/// A keyed GCRA limiter over the bounded store: quota and decisions are
/// governor's, keying and lifecycle are ours.
struct KeyedLimiter<C: Clock = DefaultClock> {
    inner: RateLimiter<ClientKey, BoundedStore<ClientKey, C>, C, NoOpMiddleware<C::Instant>>,
    /// The store's effective bound (the configured one after rounding).
    max_tracked: usize,
}

impl KeyedLimiter<DefaultClock> {
    /// A limiter enforcing `quota` over at most `max_tracked` clients,
    /// reporting under `label`.
    fn new(quota: Quota, max_tracked: usize, label: &'static str) -> Self {
        Self::with_clock(quota, max_tracked, DefaultClock::default(), label)
    }
}

impl<C: Clock + Clone> KeyedLimiter<C> {
    /// [`Self::new`] on an injected clock — the test seam (a fake clock
    /// makes rotation and debt deterministic).
    fn with_clock(quota: Quota, max_tracked: usize, clock: C, label: &'static str) -> Self {
        let store = BoundedStore::new(quota, max_tracked, clock.clone(), label);
        let max_tracked = store.capacity();
        Self {
            inner: RateLimiter::new(quota, store, clock),
            max_tracked,
        }
    }

    /// The most clients the limiter tracks at once (the configured bound
    /// after the store's rounding).
    const fn max_tracked_clients(&self) -> usize {
        self.max_tracked
    }

    /// Whether one event from `ip` is within quota.
    fn check(&self, ip: IpAddr) -> bool {
        self.inner.check_key(&ClientKey::from(ip)).is_ok()
    }

    /// Whether `n` units (e.g. datagram bytes) from `ip` are within quota.
    fn check_n(&self, ip: IpAddr, n: NonZeroU32) -> bool {
        matches!(self.inner.check_key_n(&ClientKey::from(ip), n), Ok(Ok(())))
    }
}

/// Per-client rate limiter for the hub and the edge's public entrances.
pub struct AuthRateLimiter {
    quota: u32,
    inner: KeyedLimiter,
}

impl AuthRateLimiter {
    /// Constructs a rate limiter allowing `per_client_per_minute` per
    /// minute, running at `scope`, tracking at most
    /// [`MAX_TRACKED_CLIENTS`] distinct clients.
    ///
    /// 0 means rate limiting is disabled ([`Self::check`] always returns true).
    pub fn new(scope: RateLimitScope, per_client_per_minute: u32) -> Option<Self> {
        Self::with_max_tracked_clients(scope, per_client_per_minute, MAX_TRACKED_CLIENTS)
    }

    /// [`Self::new`] with an explicit bound on the distinct clients tracked
    /// — the deployment-sized memory cap (hub `auth.max_tracked_clients`,
    /// edge listener `max_tracked_clients`). Beyond the bound the store
    /// forgets the debt of clients idle for a whole generation first, counts
    /// the degradation (`interflow_rate_limit_capacity_evictions`) and warns;
    /// new clients are always admitted. The bound rounds down to a whole
    /// number of keys per generation per shard (multiples of 32), at least
    /// one — [`Self::max_tracked_clients`] reports the effective value.
    pub fn with_max_tracked_clients(
        scope: RateLimitScope,
        per_client_per_minute: u32,
        max_tracked_clients: usize,
    ) -> Option<Self> {
        if per_client_per_minute == 0 {
            return None;
        }
        // The return above guarantees per_client_per_minute > 0, so NonZeroU32::new cannot fail here
        let nz = NonZeroU32::new(per_client_per_minute)?;
        Some(Self {
            quota: per_client_per_minute,
            inner: KeyedLimiter::new(Quota::per_minute(nz), max_tracked_clients, scope.label()),
        })
    }

    /// The configured per-client-per-minute quota (denial responses quote it
    /// to derive a `Retry-After` from the token refill rate).
    pub const fn quota(&self) -> u32 {
        self.quota
    }

    /// The most distinct clients this limiter tracks at once (the
    /// configured bound after rounding) — the value the tracked-clients
    /// gauge can never exceed.
    pub const fn max_tracked_clients(&self) -> usize {
        self.inner.max_tracked_clients()
    }

    /// Checks whether `ip` is still within quota. Returns `false` to mean over-limit, reject.
    pub fn check(&self, ip: IpAddr) -> bool {
        self.inner.check(ip)
    }
}

/// UDP inbound rate limiting (per source client): dual buckets for packet rate + byte rate.
///
/// The first gate against amplification attacks: a public UDP socket is a
/// reflection point — an attacker spoofs the victim's source address to send
/// packets → the egress service responds → the response travels back through
/// the tunnel to the ingress's `send_to(victim)`. Per-client rate limiting
/// compresses the amplification traffic reachable to a single victim IP
/// within the configured cap.
///
/// Semantics note: a single datagram larger than `per_ip_bytes_per_sec` is
/// deterministically rejected (governor's `NotEnoughCapacity` — the burst
/// capacity can never hold it), not "wait for refill".
pub struct UdpIngressLimiter {
    packets: Option<KeyedLimiter>,
    bytes: Option<KeyedLimiter>,
}

impl UdpIngressLimiter {
    /// Constructs the per-client rate limiter; returns `None` (fully disabled) when both are 0.
    ///
    /// Only one being 0 means only the other is enabled.
    pub fn new(per_ip_pps: u32, per_ip_bytes_per_sec: u32) -> Option<Self> {
        if per_ip_pps == 0 && per_ip_bytes_per_sec == 0 {
            return None;
        }
        let packets = NonZeroU32::new(per_ip_pps).map(|q| {
            KeyedLimiter::new(
                Quota::per_second(q),
                MAX_TRACKED_CLIENTS,
                "udp_ingress_packets",
            )
        });
        let bytes = NonZeroU32::new(per_ip_bytes_per_sec).map(|q| {
            KeyedLimiter::new(
                Quota::per_second(q),
                MAX_TRACKED_CLIENTS,
                "udp_ingress_bytes",
            )
        });
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
            if !bytes.check_n(ip, nz) {
                return false;
            }
        }
        if let Some(packets) = &self.packets
            && !packets.check(ip)
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
mod tests;
