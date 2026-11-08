//! Tests for the per-client limiters and their bounded store. Determinism
//! comes from a [`FakeRelativeClock`] shared by the bounded limiter, its
//! store and the reference limiter — no sleeps, no real time.

use std::net::{IpAddr, Ipv4Addr};
use std::num::NonZeroU32;
use std::str::FromStr;

use governor::Quota;
use governor::clock::FakeRelativeClock;
use governor::middleware::NoOpMiddleware;
use governor::state::keyed::{DashMapStateStore, ShrinkableKeyedStateStore};
use governor::{RateLimiter, nanos::Nanos};

use super::store::BoundedStore;
use super::{ClientKey, KeyedLimiter, MAX_TRACKED_CLIENTS};

/// A bounded limiter and a never-evicting governor limiter running the SAME
/// quota on the SAME fake clock — every decision of the two must agree
/// while the bounded one is within capacity.
struct Differential {
    clock: FakeRelativeClock,
    bounded: KeyedLimiter<FakeRelativeClock>,
    reference: RateLimiter<
        ClientKey,
        DashMapStateStore<ClientKey>,
        FakeRelativeClock,
        NoOpMiddleware<Nanos>,
    >,
}

impl Differential {
    /// `quota`/minute (the auth shape).
    fn minute(quota: u32) -> Self {
        let q = Quota::per_minute(NonZeroU32::new(quota).unwrap());
        let clock = FakeRelativeClock::default();
        let reference = RateLimiter::dashmap_with_clock(q, clock.clone());
        let bounded = KeyedLimiter::with_clock(q, MAX_TRACKED_CLIENTS, clock.clone(), "test");
        Self {
            clock,
            bounded,
            reference,
        }
    }

    /// `quota`/second (the UDP shape).
    fn second(quota: u32) -> Self {
        let q = Quota::per_second(NonZeroU32::new(quota).unwrap());
        let clock = FakeRelativeClock::default();
        let reference = RateLimiter::dashmap_with_clock(q, clock.clone());
        let bounded = KeyedLimiter::with_clock(q, MAX_TRACKED_CLIENTS, clock.clone(), "test");
        Self {
            clock,
            bounded,
            reference,
        }
    }

    /// One single-cell decision on both limiters; they must agree.
    fn step(&self, ip: IpAddr) -> bool {
        let key = ClientKey::from(ip);
        let bounded = self.bounded.inner.check_key(&key).is_ok();
        let reference = self.reference.check_key(&key).is_ok();
        assert_eq!(
            bounded, reference,
            "bounded and reference limiters disagree on {ip}"
        );
        bounded
    }

    /// One n-cell decision on both limiters; they must agree.
    fn step_n(&self, ip: IpAddr, n: u32) -> bool {
        let key = ClientKey::from(ip);
        let nz = NonZeroU32::new(n).unwrap();
        let bounded = self.bounded.inner.check_key_n(&key, nz);
        let reference = self.reference.check_key_n(&key, nz);
        assert_eq!(
            bounded, reference,
            "bounded and reference limiters disagree on {ip} x{n}"
        );
        matches!(bounded, Ok(Ok(())))
    }

    /// Keys currently tracked by the bounded store.
    fn len(&self) -> usize {
        self.bounded.inner.len()
    }
}

/// n-th distinct scanner address: 1.<n/65536>.<n/256>.<n%256> (distinct
/// for the first 2^24 values of n).
fn scanner_ip(n: u64) -> IpAddr {
    let top = u8::try_from(n / 65_536 % 256).unwrap();
    let high = u8::try_from(n / 256 % 256).unwrap();
    let low = u8::try_from(n % 256).unwrap();
    IpAddr::V4(Ipv4Addr::new(1, top, high, low))
}

/// Deterministic mixed load across ~10 rotation periods: a hot client
/// carrying debt through every rotation, a stream of one-shot scanner
/// keys (the bug's growth face), and clients revisiting at the rotation
/// boundary. Every decision must match the never-evicting reference.
#[test]
fn decisions_match_a_never_evicting_limiter() {
    let d = Differential::minute(30);
    // P = one burst refill + one emission interval = 61s.
    let step = std::time::Duration::from_millis(500);
    let mut scanner = 0_u64;
    for t in 0..1600_u64 {
        d.clock.advance(step);
        let now = t * 500; // ms
        // The hot client: hammered every step, debt grows through rotations.
        let _ = d.step("203.0.113.1".parse().unwrap());
        // Scanner keys: 5 fresh addresses per second.
        for _ in 0..2 {
            scanner += 1;
            let _ = d.step(scanner_ip(scanner));
        }
        // Boundary revisits: first scanner key of each past 61s window.
        if now % 61_000 < 500 {
            let _ = d.step(scanner_ip(1 + now / 122_000));
        }
    }
    // The bounded store forgot the idle generations; the reference (the
    // pre-fix behavior) kept them all.
    assert!(
        d.len() < d.reference.len(),
        "idle scanner keys must be forgotten"
    );
    // Still agreeing after 800 periods' worth of distinct keys.
    let _ = d.step("203.0.113.1".parse().unwrap());
}

/// Same differential over the n-cell path (UDP byte bucket), including
/// over-capacity datagrams.
#[test]
fn decisions_match_a_never_evicting_limiter_on_n_cells() {
    let d = Differential::second(10 * 1024);
    let step = std::time::Duration::from_millis(50);
    let mut scanner = 0_u64;
    for t in 0..600_u64 {
        d.clock.advance(step);
        let now = t * 50; // ms
        let _ = d.step_n("203.0.113.1".parse().unwrap(), 1500);
        scanner += 1;
        let _ = d.step_n(scanner_ip(scanner), 700);
        if now % 2_000 < 50 {
            let _ = d.step_n("198.51.100.9".parse().unwrap(), 1024);
        }
    }
    // One over-capacity datagram: 64 KiB never fits a 10 KiB/s burst.
    assert!(!d.step_n("198.51.100.9".parse().unwrap(), 64 * 1024));
    assert!(d.len() < d.reference.len());
}

/// The rotation-period boundaries. P = burst refill W + one emission
/// interval w (62s for a 30/min quota), and since P > W, a key idle for a
/// whole period is ALWAYS fully refilled — its stored TAT is exactly the
/// fresh-seed state, so time-based eviction cannot change any decision.
/// A key idle less than P still carries its debt: kept, it shows as a
/// smaller available burst than a fresh key would have.
#[test]
fn rotation_boundaries() {
    let clock = FakeRelativeClock::default();
    let q = Quota::per_minute(NonZeroU32::new(30).unwrap());
    let limiter = KeyedLimiter::with_clock(q, MAX_TRACKED_CLIENTS, clock.clone(), "test");
    let a: IpAddr = "198.51.100.1".parse().unwrap();

    // Exhaust the burst: 30 allowed, the 31st rejected.
    for _ in 0..30 {
        assert!(limiter.check(a), "within the 30 burst");
    }
    assert!(!limiter.check(a), "burst exhausted");

    // Idle 58s (< P = 62s, but > one full refill W−w): the state is KEPT,
    // and the debt shows — only 29 more fit (a fresh key at this instant
    // would allow the full 30; numbers pinned against the reference
    // limiter).
    clock.advance(std::time::Duration::from_secs(58));
    for i in 0..29 {
        assert!(limiter.check(a), "refilled cell {i} should pass");
    }
    assert!(
        !limiter.check(a),
        "29 refilled + 1: the key's pre-idle debt still counts below P"
    );

    // Idle well past P (and past the second burst's own window): the key
    // is evicted with its generation, and because P > W its state had
    // refilled anyway — the budget reads fresh (a full burst), losslessly.
    clock.advance(std::time::Duration::from_secs(120));
    for i in 0..30 {
        assert!(limiter.check(a), "fresh burst cell {i} after P idle");
    }
    assert!(!limiter.check(a), "fresh burst exhausted at 30");
    // The touched key is the only one tracked: it left with its generation
    // and re-entered fresh.
    assert_eq!(limiter.inner.len(), 1);
}

/// The hard bound under a 10x-capacity flood: `len` never exceeds capacity,
/// table capacity stays under the derived memory bound, evictions are
/// counted, and a client touched in every generation keeps its debt —
/// the flood cannot wash out an active abuser.
#[test]
fn flood_is_bounded_and_keeps_the_abuser_indebted() {
    let clock = FakeRelativeClock::default();
    let q = Quota::per_second(NonZeroU32::new(5).unwrap());
    // The store's own capacity contract, checked before it moves in.
    let store = BoundedStore::<ClientKey, _>::new(q, 2_048, clock.clone(), "test");
    assert_eq!(store.capacity(), 2_048);
    let limiter: RateLimiter<
        ClientKey,
        BoundedStore<ClientKey, FakeRelativeClock>,
        FakeRelativeClock,
        NoOpMiddleware<Nanos>,
    > = RateLimiter::new(q, store, clock.clone());
    let abuser: IpAddr = "203.0.113.66".parse().unwrap();
    let abuser_key = ClientKey::from(abuser);

    // Spend the abuser's whole burst up front, so "allowed" below always
    // means "a refilled cell", never leftover budget.
    for _ in 0..5 {
        assert!(limiter.check_key(&abuser_key).is_ok());
    }
    assert!(limiter.check_key(&abuser_key).is_err());

    // 60 iterations x 20ms = 1.2s of flood; at 5 cells/s the abuser can
    // legitimately earn back 1.2s / 0.2s = 6 cells — never more.
    let mut abuser_allowed = 0_u32;
    let mut n = 0_u64;
    for t in 0..60_u64 {
        clock.advance(std::time::Duration::from_millis(20));
        for _ in 0..400 {
            n += 1;
            let key = ClientKey::from(scanner_ip(n));
            let _ = limiter.check_key(&key);
        }
        assert!(
            limiter.len() <= 2_048,
            "len {} over the hard bound at t={t}",
            limiter.len()
        );
        if limiter.check_key(&abuser_key).is_ok() {
            abuser_allowed += 1;
        }
    }
    assert!(
        abuser_allowed <= 6,
        "abuser may only spend refilled cells ({abuser_allowed} allowed in 1.2s at 5/s) — \
         the flood must not reset its budget"
    );
}

/// The production bound holds in bytes, not just in keys: twice
/// `MAX_TRACKED_CLIENTS` distinct clients arrive with no time passing (so
/// only capacity-forced rotation can keep the table bounded), and no
/// generation table's allocation outgrows the generation it holds.
/// hashbrown sizes a table to the smallest power-of-two bucket count at
/// 7/8 load, so a table of at most n keys has capacity < 2n; at 2048 keys
/// per table that is 4096 buckets x (24 B entry + 1 B control), x 32 tables
/// ≈ 3.3 MB per limiter instance.
#[test]
fn store_capacity_is_a_memory_bound() {
    let clock = FakeRelativeClock::default();
    let q = Quota::per_minute(NonZeroU32::new(30).unwrap());
    let store = BoundedStore::<ClientKey, _>::new(q, MAX_TRACKED_CLIENTS, clock, "test");
    assert_eq!(store.capacity(), MAX_TRACKED_CLIENTS);
    let per_generation = store.generation_capacity_for_test();
    assert_eq!(per_generation, MAX_TRACKED_CLIENTS / 32);

    for n in 0..u64::try_from(2 * MAX_TRACKED_CLIENTS).unwrap() {
        store.track_for_test(&ClientKey::from(scanner_ip(n)));
    }
    assert!(
        store.len() <= MAX_TRACKED_CLIENTS,
        "{} keys tracked over the {MAX_TRACKED_CLIENTS} bound",
        store.len()
    );
    assert!(
        store.max_table_capacity_for_test() < 2 * per_generation,
        "a generation table allocated {} slots for at most {per_generation} keys",
        store.max_table_capacity_for_test()
    );
}

/// A capacity-forced rotation restarts the shard's period: the keys it
/// demotes were touched up to that instant, and only a whole period
/// untouched from THERE makes dropping them lossless. Without the restart,
/// the next touch past the shard's original period would rotate out a key
/// touched seconds earlier, debt and all. Checked against the
/// never-evicting reference: across the forced rotation every decision
/// agrees.
#[test]
fn forced_rotation_restarts_the_period() {
    let clock = FakeRelativeClock::default();
    let q = Quota::per_minute(NonZeroU32::new(30).unwrap()); // P = 62s
    // Capacity 32 = one key per generation per shard.
    let store = BoundedStore::<ClientKey, _>::new(q, 32, clock.clone(), "test");
    assert_eq!(store.generation_capacity_for_test(), 1);
    let a = ClientKey::from(scanner_ip(1));
    // A second key in a's shard (placement is randomly keyed per store:
    // search this store's own).
    let b = (2_u64..10_000)
        .map(|n| ClientKey::from(scanner_ip(n)))
        .find(|k| store.shard_index_for_test(k) == store.shard_index_for_test(&a))
        .expect("one of 10k keys shares a's shard (16 shards)");
    let bounded: RateLimiter<
        ClientKey,
        BoundedStore<ClientKey, FakeRelativeClock>,
        FakeRelativeClock,
        NoOpMiddleware<Nanos>,
    > = RateLimiter::new(q, store, clock.clone());
    let reference: RateLimiter<
        ClientKey,
        DashMapStateStore<ClientKey>,
        FakeRelativeClock,
        NoOpMiddleware<Nanos>,
    > = RateLimiter::dashmap_with_clock(q, clock.clone());
    let step = |key: &ClientKey| {
        let decision = bounded.check_key(key).is_ok();
        assert_eq!(decision, reference.check_key(key).is_ok());
        decision
    };

    // Just before the shard's first period ends, a spends its burst...
    clock.advance(std::time::Duration::from_secs(61));
    for _ in 0..30 {
        assert!(step(&a));
    }
    assert!(!step(&a), "a's burst is spent");
    // ...and b's arrival forces a rotation (one key per generation): a is
    // demoted with its debt.
    assert!(step(&b));
    // Past the shard's ORIGINAL period, but 2s after the forced rotation:
    // a has earned back exactly one cell — its debt survived.
    clock.advance(std::time::Duration::from_secs(2));
    assert!(step(&a), "one cell refilled in 2s");
    assert!(!step(&a), "only one: the debt survived the forced rotation");
}

/// Metrics: the tracked-clients gauge follows the population up, down
/// (rotation) and to zero when the store drops — so a hot-reload rebuild
/// (UDP) cannot leave a stale population behind. Rotation is per shard and
/// lazy (a shard rotates on its next touch), so the decay here goes through
/// the every-shard sweep the tests use; a quiet shard holding its last
/// generation is the documented lazy behavior (the bound is unaffected).
#[test]
fn tracked_clients_gauge_follows_the_store() {
    let mut line = String::new();

    // Same direct-read in-process recorder shape as the mesh e2e tests.
    let recorder = metrics_exporter_prometheus::PrometheusBuilder::new().build_recorder();
    let handle = recorder.handle();
    metrics::set_global_recorder(recorder).ok(); // may already be set by another test

    let read = |line: &mut String| {
        *line = handle.render();
    };
    let gauge_line = |line: &str| {
        line.lines()
            .find(|l| l.starts_with("interflow_rate_limit_tracked_clients{limiter=\"test\"}"))
            .unwrap_or_default()
            .to_string()
    };

    // 1) Population up, then away with the store on drop.
    {
        let clock = FakeRelativeClock::default();
        let q = Quota::per_second(NonZeroU32::new(5).unwrap());
        let store = BoundedStore::<ClientKey, _>::new(q, 4_096, clock, "test");
        for i in 1..=100_u32 {
            store.track_for_test(&ClientKey::from(IpAddr::V4(Ipv4Addr::new(
                1,
                0,
                0,
                u8::try_from(i).unwrap(),
            ))));
        }
        read(&mut line);
        assert_eq!(
            gauge_line(&line),
            "interflow_rate_limit_tracked_clients{limiter=\"test\"} 100",
            "gauge must read 100 after 100 clients, got: {line}"
        );
        store.expire_all_for_test();
    }
    read(&mut line);
    assert!(
        gauge_line(&line).ends_with(" 0"),
        "gauge must read 0 after the store drops (still tracking keys), got: {}",
        gauge_line(&line)
    );

    // 2) Idle decay: two periods idle, every shard swept — the gauge
    // follows the evictions down.
    {
        let clock = FakeRelativeClock::default();
        let q = Quota::per_second(NonZeroU32::new(5).unwrap());
        let store = BoundedStore::<ClientKey, _>::new(q, 4_096, clock.clone(), "test");
        for i in 1..=100_u32 {
            store.track_for_test(&ClientKey::from(IpAddr::V4(Ipv4Addr::new(
                1,
                0,
                0,
                u8::try_from(i).unwrap(),
            ))));
        }
        clock.advance(std::time::Duration::from_secs(4));
        store.expire_all_for_test();
        read(&mut line);
        assert!(
            gauge_line(&line).ends_with(" 0"),
            "gauge must read 0 after idle expiry, got: {}",
            gauge_line(&line)
        );
    }
}

/// A capacity-forced rotation reports itself in the evictions counter.
#[test]
fn capacity_evictions_are_counted() {
    let recorder = metrics_exporter_prometheus::PrometheusBuilder::new().build_recorder();
    let handle = recorder.handle();
    metrics::set_global_recorder(recorder).ok();

    let clock = FakeRelativeClock::default();
    let q = Quota::per_second(NonZeroU32::new(5).unwrap());
    let store = BoundedStore::<ClientKey, _>::new(q, 256, clock, "test");
    for i in 0..2_000_u32 {
        store.track_for_test(&ClientKey::from(IpAddr::V4(Ipv4Addr::new(
            1,
            0,
            u8::try_from(i / 256).unwrap(),
            u8::try_from(i % 256).unwrap(),
        ))));
    }
    let line = handle.render();
    let needle = "interflow_rate_limit_capacity_evictions{limiter=\"test\"}";
    let value = line
        .split(&format!("{needle} "))
        .nth(1)
        .and_then(|rest| rest.split(['\n', ' ']).next())
        .unwrap_or_default();
    assert!(
        value.parse::<u64>().is_ok_and(|v| v > 0),
        "capacity evictions must be counted > 0, got: {line}"
    );
}

/// The public auth limiter keys clients, not addresses: one IPv6 /64 and
/// the IPv4-mapped fold share one budget through `AuthRateLimiter::check`.
#[test]
fn auth_limiter_keys_clients() {
    use super::RateLimitScope;

    let limiter =
        super::AuthRateLimiter::new(RateLimitScope::Hub, 1).expect("non-zero quota constructs");
    assert!(limiter.check("2001:db8:1:2::1".parse().unwrap()));
    assert!(
        !limiter.check("2001:db8:1:2::2".parse().unwrap()),
        "same /64 shares the budget"
    );
    assert!(
        limiter.check("2001:db8:1:3::1".parse().unwrap()),
        "another /64 is fresh"
    );
}

/// The deployment-sized bound: the default constructor runs on
/// `MAX_TRACKED_CLIENTS`; an explicit bound rounds down to whole
/// generations per shard (multiples of 32, at least one key each) and is
/// reported back — so a soak gate or an operator asserts the tracked-
/// clients gauge against the number the limiter actually enforces.
#[test]
fn auth_limiter_reports_its_effective_bound() {
    use super::{AuthRateLimiter, RateLimitScope};

    let default = AuthRateLimiter::new(RateLimitScope::Hub, 30).expect("constructed");
    assert_eq!(default.max_tracked_clients(), MAX_TRACKED_CLIENTS);
    let sized = AuthRateLimiter::with_max_tracked_clients(RateLimitScope::Hub, 30, 8_192)
        .expect("constructed");
    assert_eq!(
        sized.max_tracked_clients(),
        8_192,
        "a whole number of generations per shard is kept exactly"
    );
    let rounded = AuthRateLimiter::with_max_tracked_clients(RateLimitScope::Hub, 30, 100)
        .expect("constructed");
    assert_eq!(
        rounded.max_tracked_clients(),
        96,
        "rounds down to 3 keys per generation per shard"
    );
    let floor =
        AuthRateLimiter::with_max_tracked_clients(RateLimitScope::Hub, 30, 1).expect("constructed");
    assert_eq!(
        floor.max_tracked_clients(),
        32,
        "at least one key per generation per shard"
    );
    assert!(
        AuthRateLimiter::with_max_tracked_clients(RateLimitScope::Hub, 0, 8_192).is_none(),
        "a zero quota disables the limiter regardless of the bound"
    );
}

// --- The pre-existing limiter unit tests, carried over from the module. ---

#[test]
fn disabled_when_zero() {
    assert!(super::AuthRateLimiter::new(super::RateLimitScope::Hub, 0).is_none());
}

#[test]
fn allows_until_quota() {
    let limiter = super::AuthRateLimiter::new(super::RateLimitScope::Hub, 2).expect("constructed");
    let ip = IpAddr::from_str("127.0.0.1").unwrap();
    assert!(limiter.check(ip), "first should pass");
    assert!(limiter.check(ip), "second should pass");
    // Third check is over quota (immediately rejected while governor time has not advanced)
    let _ = limiter.check(ip);
}

#[test]
fn udp_limiter_disabled_when_both_zero() {
    assert!(super::UdpIngressLimiter::new(0, 0).is_none());
}

#[test]
fn udp_limiter_pps_bucket_drops_burst() {
    let limiter = super::UdpIngressLimiter::new(3, 0).expect("constructed");
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
    let limiter = super::UdpIngressLimiter::new(0, 10 * 1024).expect("constructed");
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
    let limiter = super::UdpIngressLimiter::new(2, 0).expect("constructed");
    let ip = IpAddr::from_str("192.0.2.3").unwrap();
    assert!(limiter.check(ip, 60_000));
    assert!(limiter.check(ip, 60_000));
    assert!(!limiter.check(ip, 1));
}

#[test]
fn udp_limiter_keys_are_isolated() {
    let limiter = super::UdpIngressLimiter::new(1, 0).expect("constructed");
    let a = IpAddr::from_str("192.0.2.4").unwrap();
    let b = IpAddr::from_str("192.0.2.5").unwrap();
    assert!(limiter.check(a, 64));
    assert!(!limiter.check(a, 64));
    assert!(limiter.check(b, 64), "different IP has independent budget");
}

#[test]
fn byte_rate_limiter_basic() {
    assert!(super::ByteRateLimiter::new(0).is_none());
    let limiter = super::ByteRateLimiter::new(4 * 1024).expect("constructed");
    assert!(limiter.check(1024));
    assert!(!limiter.check(8 * 1024), "over-quota single write rejected");
}

#[test]
fn event_rate_limiter_burst_then_throttle() {
    assert!(
        super::EventRateLimiter::new(0, 10).is_none(),
        "0 rate = disabled"
    );
    let limiter = super::EventRateLimiter::new(10, 3).expect("constructed");
    for i in 0..3 {
        assert!(limiter.check(), "event #{i} within burst should pass");
    }
    assert!(!limiter.check(), "exceeding burst capacity should reject");
}
