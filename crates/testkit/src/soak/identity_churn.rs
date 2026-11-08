//! Identity-churn phase: the soak's visitor-identity axis
//!
//! The soak's other churn axes kill CONNECTIONS (short-lived streams,
//! SIGKILL waves); this one manufactures IDENTITIES — thousands of client
//! addresses the hub has never seen, each appearing once and never again.
//! It is the automated form of the 2026-11-01 memory experiment that found
//! the per-client rate limiter's state table growing without bound
//! (71d1b20, `BoundedStore`): a state keyed by visitor identity has to be
//! bounded, and the only test that exercises the bound is one that
//! presents more distinct visitors than the bound holds.
//!
//! # How the identities are made
//!
//! Through the PROXY protocol, not through source addresses: the hub's
//! accept path negotiates a PROXY preamble from trusted (loopback) peers
//! BEFORE the mTLS handshake and gates the connection on the effective
//! client address the preamble names — the exact path a front proxy uses.
//! One loopback connection per synthetic client, a `PROXY TCP4 <addr> …`
//! line naming the next address of the RFC 2544 benchmark range
//! (198.18.0.0/15), then close. The limiter sees a fresh `ClientKey`
//! every time; the hub logs one failed-handshake warning per connection
//! (we never start TLS) and nothing else happens. No 127/8 aliasing, no
//! platform-specific bind behavior, no raw sockets.
//!
//! # Schedule, from the store's physics
//!
//! The bounded store keeps two generations per shard and rotates a shard
//! when it is touched after a whole rotation period `P` idle (`P` = the
//! quota's full-burst replenish time plus one emission interval: ~60s for
//! any per-minute quota); a generation that fills within `P` forces a
//! rotation and evicts the previous one (counted). The phase therefore:
//!
//! 1. **churns** `3/2 × bound` clients at a steady rate — on average three
//!    generation capacities (`bound / 32`) per shard inside one `P`. The
//!    first overflow of a shard only moves its full generation aside
//!    (the previous one was empty: nothing to evict); the SECOND is what
//!    evicts a whole generation and counts. Three per shard makes that
//!    certain for every shard despite hashing variance;
//! 2. **idles** `2P` — after which every untouched shard's generations are
//!    both droppable;
//! 3. **sweeps** a few hundred fresh clients across all shards — rotation
//!    is lazy (a shard rotates when touched), so the sweep is what makes
//!    the gauge actually recede.
//!
//! Each step needs real wall time (the rotation period is the product's,
//! not the test's), so the phase declares its budget and the runner
//! refuses a run too short to hold it — honest scheduling, never a
//! silently skipped assertion.

use super::scrape;
use serde::Serialize;
use std::net::{Ipv4Addr, SocketAddr};
use std::time::{Duration, Instant};
use tokio::io::AsyncWriteExt;
use tokio_util::sync::CancellationToken;

/// The tracked-population gauge the bounded store exports.
pub const TRACKED_GAUGE: &str = "interflow_rate_limit_tracked_clients";
/// The capacity-eviction counter the bounded store exports.
pub const EVICTIONS_COUNTER: &str = "interflow_rate_limit_capacity_evictions";

/// How many fresh clients the post-idle sweep presents: 32 per shard on
/// average, so every one of the store's 16 shards is touched (and
/// rotates) with overwhelming probability.
pub const SWEEP_CLIENTS: usize = 512;

/// The bounded store's rotation period for a per-minute quota: the full
/// burst replenishes in one minute, plus one emission interval. Mirrors
/// `rate_limit::store::rotation_period` — a period a test derives rather
/// than guesses, so the idle step cannot silently fall short of it.
#[must_use]
pub fn rotation_period(per_minute: u32) -> Duration {
    Duration::from_secs_f64(60.0 + 60.0 / f64::from(per_minute.max(1)))
}

/// The phase's sizing for one hub configuration.
#[derive(Debug, Clone, Copy)]
pub struct Schedule {
    /// Distinct clients presented in the churn step.
    pub churn_clients: usize,
    /// Churn pace (clients per second).
    pub per_sec: u32,
    /// Distinct clients presented in the sweep step.
    pub sweep_clients: usize,
    /// Idle between churn and sweep (`2P` plus a margin).
    pub idle: Duration,
}

impl Schedule {
    /// Sizes the phase for a limiter bounded at `max_tracked` clients on a
    /// `per_minute` quota, churning at `per_sec`.
    #[must_use]
    pub fn for_bound(max_tracked: usize, per_minute: u32, per_sec: u32) -> Self {
        Self {
            churn_clients: max_tracked / 2 * 3,
            per_sec: per_sec.max(1),
            sweep_clients: SWEEP_CLIENTS,
            idle: rotation_period(per_minute) * 2 + Duration::from_secs(5),
        }
    }

    /// Wall time the churn step takes at its pace.
    #[must_use]
    pub fn churn_duration(&self) -> Duration {
        Duration::from_secs_f64(self.churn_clients as f64 / f64::from(self.per_sec))
    }

    /// Wall time the sweep step takes (same pace).
    #[must_use]
    pub fn sweep_duration(&self) -> Duration {
        Duration::from_secs_f64(self.sweep_clients as f64 / f64::from(self.per_sec))
    }

    /// The wall budget the whole phase needs once started: churn + idle +
    /// sweep + a settle for the post-sweep scrape.
    #[must_use]
    pub fn budget(&self) -> Duration {
        self.churn_duration() + self.idle + self.sweep_duration() + Duration::from_secs(10)
    }
}

/// The run duration a scenario needs to hold the phase: the warmup it
/// starts after, the phase's budget, and a margin for the closing scrape.
#[must_use]
pub fn min_duration_secs(warmup: Duration, schedule: &Schedule) -> u64 {
    (warmup + schedule.budget() + Duration::from_secs(20)).as_secs() + 1
}

/// What the phase did and what the hub's limiter reported around it.
#[derive(Debug, Clone, Default, Serialize)]
pub struct IdentityChurnSummary {
    /// `false` when the phase was disabled (`--identity-churn-per-sec 0`).
    pub enabled: bool,
    /// The limiter's configured tracked-client bound.
    pub bound: usize,
    /// Synthetic clients presented in the churn step.
    pub churned: u64,
    /// Churn connections that failed before the preamble was written.
    pub churn_failures: u64,
    /// Fresh clients presented in the sweep step.
    pub swept: u64,
    /// `interflow_rate_limit_tracked_clients` right after the churn step.
    pub tracked_after_churn: Option<u64>,
    /// `interflow_rate_limit_capacity_evictions` right after the churn step.
    pub evictions_after_churn: Option<u64>,
    /// `interflow_rate_limit_tracked_clients` after idle + sweep.
    pub tracked_after_sweep: Option<u64>,
    /// Seconds into the run at which each step completed.
    pub churn_done_secs: Option<f64>,
    pub sweep_done_secs: Option<f64>,
    /// `true` when the run was cancelled before the phase completed.
    pub interrupted: bool,
}

/// The synthetic client addresses: a walk through 198.18.0.0/15 (the RFC
/// 2544 benchmark range — never routable, never a real visitor), each
/// address used exactly once per run.
struct AddressWalk {
    next: u32,
}

impl AddressWalk {
    const fn new() -> Self {
        Self {
            next: u32::from_be_bytes([198, 18, 0, 1]),
        }
    }

    fn next_addr(&mut self) -> Ipv4Addr {
        let addr = Ipv4Addr::from(self.next);
        self.next = self.next.wrapping_add(1);
        addr
    }
}

/// One synthetic client: connect to the hub from loopback, present the
/// PROXY v1 preamble naming `client`, close. The hub gates the connection
/// on `client` (admitting it into the limiter's store) before the TLS
/// handshake it never gets.
async fn present_client(hub: SocketAddr, client: Ipv4Addr) -> bool {
    let Ok(mut sock) = tokio::net::TcpStream::connect(hub).await else {
        return false;
    };
    let line = format!("PROXY TCP4 {client} {} 40000 {}\r\n", hub.ip(), hub.port());
    if sock.write_all(line.as_bytes()).await.is_err() {
        return false;
    }
    // Let the preamble reach the peer before the FIN; the hub reads the
    // line, gates, then sees EOF at the TLS accept.
    let _ = sock.flush().await;
    let _ = sock.shutdown().await;
    true
}

/// Presents `count` fresh clients at `per_sec`, returning `(presented,
/// failed)`; stops early on cancel.
async fn present_wave(
    hub: SocketAddr,
    walk: &mut AddressWalk,
    count: usize,
    per_sec: u32,
    cancel: &CancellationToken,
) -> (u64, u64) {
    let mut pace = tokio::time::interval(Duration::from_secs_f64(1.0 / f64::from(per_sec.max(1))));
    pace.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Burst);
    let (mut presented, mut failed) = (0u64, 0u64);
    for _ in 0..count {
        tokio::select! {
            _ = pace.tick() => {}
            _ = cancel.cancelled() => break,
        }
        if present_client(hub, walk.next_addr()).await {
            presented += 1;
        } else {
            failed += 1;
        }
    }
    (presented, failed)
}

async fn read_limiter(metrics: SocketAddr) -> (Option<u64>, Option<u64>) {
    match scrape::scrape(metrics, "/metrics").await {
        Ok(text) => (
            scrape::gauge_value(&text, TRACKED_GAUGE),
            Some(scrape::counter_value(&text, EVICTIONS_COUNTER).unwrap_or(0)),
        ),
        Err(_) => (None, None),
    }
}

/// Runs the phase: waits `start_after`, churns, idles, sweeps, reading the
/// hub's limiter metrics after the churn and after the sweep. Returns
/// early (with `interrupted = true`) on cancel.
pub async fn run_phase(
    hub: SocketAddr,
    metrics: SocketAddr,
    schedule: Schedule,
    bound: usize,
    start_after: Duration,
    cancel: CancellationToken,
) -> IdentityChurnSummary {
    let t0 = Instant::now();
    let mut summary = IdentityChurnSummary {
        enabled: true,
        bound,
        ..IdentityChurnSummary::default()
    };
    let mut walk = AddressWalk::new();

    tokio::select! {
        _ = tokio::time::sleep(start_after) => {}
        _ = cancel.cancelled() => { summary.interrupted = true; return summary; }
    }

    let (churned, failed) = present_wave(
        hub,
        &mut walk,
        schedule.churn_clients,
        schedule.per_sec,
        &cancel,
    )
    .await;
    summary.churned = churned;
    summary.churn_failures = failed;
    if cancel.is_cancelled() {
        summary.interrupted = true;
        return summary;
    }
    // A beat for the last admissions to land before the scrape.
    tokio::time::sleep(Duration::from_millis(500)).await;
    let (tracked, evictions) = read_limiter(metrics).await;
    summary.tracked_after_churn = tracked;
    summary.evictions_after_churn = evictions;
    summary.churn_done_secs = Some(t0.elapsed().as_secs_f64());

    tokio::select! {
        _ = tokio::time::sleep(schedule.idle) => {}
        _ = cancel.cancelled() => { summary.interrupted = true; return summary; }
    }

    let (swept, _) = present_wave(
        hub,
        &mut walk,
        schedule.sweep_clients,
        schedule.per_sec,
        &cancel,
    )
    .await;
    summary.swept = swept;
    if cancel.is_cancelled() {
        summary.interrupted = true;
        return summary;
    }
    tokio::time::sleep(Duration::from_millis(500)).await;
    let (tracked, _) = read_limiter(metrics).await;
    summary.tracked_after_sweep = tracked;
    summary.sweep_done_secs = Some(t0.elapsed().as_secs_f64());
    summary
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rotation_period_is_one_minute_plus_an_emission_interval() {
        let p = rotation_period(30_000);
        assert!(
            p > Duration::from_secs(60) && p < Duration::from_secs(61),
            "{p:?}"
        );
        let slow = rotation_period(1);
        assert_eq!(
            slow,
            Duration::from_secs(120),
            "a 1/min quota emits once a minute"
        );
    }

    #[test]
    fn schedule_sizes_past_every_generation_within_one_period() {
        let s = Schedule::for_bound(8_192, 30_000, 400);
        assert_eq!(s.churn_clients, 12_288, "three halves of the bound");
        // 16 shards × (8192 / 32 = 256 per generation): the churn presents
        // 768 per shard on average — three generation capacities, so every
        // shard overflows at least twice and the second overflow evicts.
        assert!(s.churn_clients / 16 >= 3 * (8_192 / 32));
        assert!(
            s.churn_duration() < rotation_period(30_000),
            "the churn lands inside one rotation period: {:?}",
            s.churn_duration()
        );
        assert!(s.idle > rotation_period(30_000) * 2, "idle covers 2P");
        assert_eq!(s.sweep_clients, SWEEP_CLIENTS);
    }

    #[test]
    fn min_duration_covers_warmup_and_the_whole_phase() {
        let s = Schedule::for_bound(8_192, 30_000, 400);
        let min = min_duration_secs(Duration::from_secs(60), &s);
        let budget = s.budget().as_secs();
        assert!(
            min >= 60 + budget + 20,
            "{min} vs warmup 60 + budget {budget} + 20"
        );
        assert!(
            min < 300,
            "a default soak run (600s) holds the phase comfortably: {min}"
        );
    }

    #[test]
    fn address_walk_never_repeats_inside_the_benchmark_range() {
        let mut walk = AddressWalk::new();
        let first = walk.next_addr();
        assert_eq!(first, Ipv4Addr::new(198, 18, 0, 1));
        let mut seen = std::collections::HashSet::new();
        seen.insert(first);
        for _ in 0..10_000 {
            let addr = walk.next_addr();
            assert!(seen.insert(addr), "{addr} repeated");
            assert!(
                addr.octets()[0] == 198 && (addr.octets()[1] == 18 || addr.octets()[1] == 19),
                "{addr} left 198.18.0.0/15"
            );
        }
    }
}
