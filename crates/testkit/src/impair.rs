//! Impairment-injection proxies: simulate a lossy link between hub and agent.
//!
//! Two semantics (dictated by physical facts, not interchangeable):
//! - **UDP (QUIC)**: a user-space proxy can **really drop** datagrams — quinn's
//!   loss recovery retransmits per stream, so cross-stream isolation is real
//!   protocol behavior.
//! - **TCP (h2)**: a user-space proxy terminates TCP and cannot drop kernel
//!   segments; **byte withholding** simulates "lost segment + retransmit
//!   recovery" — after a withheld chunk, all subsequent bytes are blocked too
//!   (TCP's in-order semantics), and the observable effect matches a real lost
//!   segment: every stream on the same connection stalls together (cross-stream
//!   HOL). The withhold duration is the recovery-model parameter (on the order
//!   of ≈1-2×RTT for retransmit recovery).
//!
//! Latency model: propagation delay of an unconstrained-bandwidth link —
//! `forward = arrival + delay`, no queueing by intent. The UDP delay lines
//! are bounded FIFO queues with dedicated forwarders (see `DelayLine`);
//! the only queueing source on the TCP side is a withheld chunk (in-order
//! floor = the previous chunk's forward time).
//!
//! Randomness source: seeded StdRng — same seed and same input sequence → the
//! same impairment pattern (reproducible). `DropPattern::Every` provides a
//! timing-independent deterministic pattern (for unit tests and exact
//! assertions).
//!
//! Harness self-health: delay-line overflow (tail-drop) is recorded as
//! `ImpairKind::QueueOverflowDropped` — a **harness fault**, never an
//! injected impairment; soak attribution excludes it and fails the scenario
//! instead of mistaking it for injected loss (a proxy that overflows its own
//! delay line silently flatters the product under test).

use rand::rngs::StdRng;
use rand::{Rng, SeedableRng};
use std::collections::{HashMap, VecDeque};
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tokio::sync::Notify;
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;

/// An impairment event (for event-anchored metrics: how many streams stall per loss).
#[derive(Debug, Clone, Copy)]
pub struct ImpairEvent {
    /// When the impairment takes effect (TCP withholding = release time; UDP drop = drop time).
    pub at: Instant,
    /// Number of affected bytes.
    pub bytes: usize,
    /// Kind of impairment.
    pub kind: ImpairKind,
}

/// Kind of impairment.
#[derive(Debug, Clone, Copy)]
pub enum ImpairKind {
    /// TCP byte withholding (simulating lost segment + retransmit recovery); `for_duration` is the withhold duration.
    Withheld {
        /// Withhold duration.
        for_duration: Duration,
    },
    /// Real UDP datagram drop.
    Dropped,
    /// Delay-line overflow tail-drop (harness fault, NOT an injected
    /// impairment): the proxy's own bounded delay line was full — excluded
    /// from stall-explanation attribution and surfaced as a run-invalidating
    /// red flag by the soak gate. `capacity` is the configured line capacity.
    QueueOverflowDropped { capacity: usize },
}

/// Packet-drop decision pattern.
#[derive(Debug, Clone, Copy)]
pub enum DropPattern {
    /// No drops (control group).
    None,
    /// Independent probability (each decision: `rng < rate`).
    Rate(f64),
    /// Drop one of every N packets/chunks (deterministic; timing-independent, allows exact assertions).
    Every(u64),
}

/// Impairment configuration.
#[derive(Debug, Clone)]
pub struct ImpairConfig {
    /// One-way propagation delay (applied in both directions; RTT = 2× this value).
    pub one_way_delay: Duration,
    /// Packet-drop decision on agent→hub (the data direction).
    pub drop: DropPattern,
    /// TCP withhold duration (lost-segment retransmit-recovery model, ≈1-2×RTT).
    pub withhold: Duration,
    /// UDP delay-line capacity per direction (datagrams): beyond it the line
    /// tail-drops like a router queue and the drop is accounted as a harness
    /// fault (`ImpairKind::QueueOverflowDropped`).
    pub queue_capacity: usize,
    /// Random seed for probability patterns.
    pub seed: u64,
}

impl Default for ImpairConfig {
    fn default() -> Self {
        Self {
            one_way_delay: Duration::from_millis(25),
            drop: DropPattern::None,
            withhold: Duration::from_millis(100),
            queue_capacity: 8192,
            seed: 0x1F_9E_53,
        }
    }
}

/// Per-packet/per-chunk drop decision (consumed in order, keeping the pattern deterministic).
struct DropDecider {
    pattern: DropPattern,
    rng: StdRng,
    count: u64,
}

impl DropDecider {
    fn new(pattern: DropPattern, seed: u64) -> Self {
        Self {
            pattern,
            rng: StdRng::seed_from_u64(seed),
            count: 0,
        }
    }

    fn should_drop(&mut self) -> bool {
        self.count += 1;
        match self.pattern {
            DropPattern::None => false,
            DropPattern::Every(n) => n > 0 && self.count % n == 0,
            DropPattern::Rate(r) => self.rng.random::<f64>() < r,
        }
    }
}

type SharedEvents = Arc<Mutex<Vec<ImpairEvent>>>;

/// One forwarding direction of an impairment proxy.
///
/// From the proxy's perspective the proxied client is the agent and the
/// upstream is the hub (that is the only topology these proxies serve).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Direction {
    /// Client → upstream (agent → hub).
    AgentToHub,
    /// Upstream → client (hub → agent).
    HubToAgent,
}

/// Runtime per-direction blackhole control — the **one-way-hang injection
/// primitive** (the 2026-10-09 one-way-blackhole form: one direction dead,
/// the other alive, the connection establishment face untouched).
///
/// A cut direction silently drops/withholds everything flowing that way:
/// - UDP: datagrams are not forwarded (a real blackhole);
/// - TCP: chunks are read and drained but never written (a hang, not a
///   close — the connection stays ESTABLISHED and the receiver sees
///   silence, matching "lost segment that never recovers").
///
/// Cuts are deliberate test controls driven by the test's own timeline, so
/// they are not recorded as impairment events (unlike the stochastic
/// `DropPattern` machinery, which exists to be attributed).
#[derive(Debug, Default)]
struct DirectionCuts {
    agent_to_hub: AtomicBool,
    hub_to_agent: AtomicBool,
}

impl DirectionCuts {
    fn is_cut(&self, dir: Direction) -> bool {
        match dir {
            Direction::AgentToHub => self.agent_to_hub.load(Ordering::Relaxed),
            Direction::HubToAgent => self.hub_to_agent.load(Ordering::Relaxed),
        }
    }

    fn set(&self, dir: Direction, cut: bool) {
        match dir {
            Direction::AgentToHub => self.agent_to_hub.store(cut, Ordering::Relaxed),
            Direction::HubToAgent => self.hub_to_agent.store(cut, Ordering::Relaxed),
        }
    }
}

fn record_event(events: &SharedEvents, event: ImpairEvent) {
    events
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .push(event);
}

// ---------------------------------------------------------------------------
// TCP impairment proxy
// ---------------------------------------------------------------------------

/// TCP impairment proxy: client → proxy → upstream, an order-preserving pump in each direction.
///
/// The data direction (client→upstream) gets the drop decision (withholding); the
/// reverse direction only gets added delay.
pub struct TcpImpairProxy {
    local_addr: SocketAddr,
    shutdown: CancellationToken,
    task: JoinHandle<()>,
    events: SharedEvents,
    cuts: Arc<DirectionCuts>,
}

impl TcpImpairProxy {
    /// Start the proxy (random local port). `upstream` is the real target address.
    pub async fn spawn(upstream: SocketAddr, cfg: ImpairConfig) -> std::io::Result<Self> {
        let listener = TcpListener::bind("127.0.0.1:0").await?;
        let local_addr = listener.local_addr()?;
        let events: SharedEvents = Arc::new(Mutex::new(Vec::new()));
        let shutdown = CancellationToken::new();
        let token = shutdown.clone();
        let task_events = events.clone();
        let cuts = Arc::new(DirectionCuts::default());
        let task_cuts = Arc::clone(&cuts);

        let task = tokio::spawn(async move {
            loop {
                let (client, _) = tokio::select! {
                    () = token.cancelled() => break,
                    accepted = listener.accept() => match accepted {
                        Ok(pair) => pair,
                        Err(_) => break,
                    },
                };
                // Upstream unreachable: just drop the client connection (simulating a connection failure)
                let Ok(up) = TcpStream::connect(upstream).await else {
                    continue;
                };
                let events = task_events.clone();
                let cfg = cfg.clone();
                let cuts = Arc::clone(&task_cuts);
                tokio::spawn(relay_tcp(client, up, cfg, events, cuts));
            }
        });

        Ok(Self {
            local_addr,
            shutdown,
            task,
            events,
            cuts,
        })
    }

    /// The proxy's listen address (clients should connect here).
    pub fn local_addr(&self) -> SocketAddr {
        self.local_addr
    }

    /// Impairment events that have occurred (in time order).
    pub fn events(&self) -> Vec<ImpairEvent> {
        self.events
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone()
    }

    /// Cuts one direction (see [`DirectionCuts`]): chunks keep being read
    /// and drained but never written — a hang, not a close.
    pub fn cut(&self, dir: Direction) {
        self.cuts.set(dir, true);
    }

    /// Restores a cut direction; the next chunk flows again.
    pub fn restore(&self, dir: Direction) {
        self.cuts.set(dir, false);
    }

    /// Shutdown: stop accepting; existing connection pumps end with the task group.
    pub async fn shutdown(self) {
        self.shutdown.cancel();
        let _ = self.task.await;
    }
}

/// Bidirectional relay for one TCP connection: one order-preserving pump per direction.
async fn relay_tcp(
    client: TcpStream,
    upstream: TcpStream,
    cfg: ImpairConfig,
    events: SharedEvents,
    cuts: Arc<DirectionCuts>,
) {
    let (client_rd, client_wr) = client.into_split();
    let (up_rd, up_wr) = upstream.into_split();

    // client→upstream: data direction, gets drop-withholding
    let up_pump = pump_tcp(
        client_rd,
        up_wr,
        cfg.one_way_delay,
        Some((cfg.drop, cfg.withhold, cfg.seed, events)),
        Direction::AgentToHub,
        cuts.clone(),
    );
    // upstream→client: reverse direction only gets added delay
    let down_pump = pump_tcp(
        up_rd,
        client_wr,
        cfg.one_way_delay,
        None,
        Direction::HubToAgent,
        cuts,
    );

    let (a, b) = tokio::join!(up_pump, down_pump);
    let _ = (a, b);
}

/// One-direction TCP pump: read chunk → (optionally withhold) → delayed forward → write.
///
/// Virtual clock: `forward = max(arrival + delay + withhold, previous forward)` —
/// propagation delay never queues; the only queueing source is the in-order floor
/// imposed by withheld chunks. EOF is passed through as a half-close.
///
/// A cut direction (see [`DirectionCuts`]) switches the pump to drain mode:
/// chunks are consumed but never written — the sender never blocks and the
/// receiver sees silence (a hang, not a close).
#[allow(clippy::too_many_arguments)]
async fn pump_tcp<R, W>(
    mut rd: R,
    mut wr: W,
    delay: Duration,
    impair: Option<(DropPattern, Duration, u64, SharedEvents)>,
    dir: Direction,
    cuts: Arc<DirectionCuts>,
) where
    R: tokio::io::AsyncRead + Unpin,
    W: tokio::io::AsyncWrite + Unpin,
{
    let (mut decider, withhold, events) = match impair {
        Some((pattern, withhold, seed, events)) => {
            (DropDecider::new(pattern, seed), withhold, Some(events))
        }
        None => (DropDecider::new(DropPattern::None, 0), Duration::ZERO, None),
    };

    let mut next_free = Instant::now();
    let mut buf = vec![0u8; 256 * 1024];
    loop {
        let n = match rd.read(&mut buf).await {
            Ok(0) => {
                let _ = wr.shutdown().await;
                return;
            }
            Ok(n) => n,
            Err(_) => return,
        };
        if cuts.is_cut(dir) {
            // One-way hang: consume and discard (keep the connection
            // ESTABLISHED and the peer waiting, never signaling EOF).
            continue;
        }
        let arrival = Instant::now();

        let extra = if decider.should_drop() {
            if let Some(events) = &events {
                record_event(
                    events,
                    ImpairEvent {
                        at: arrival + delay + withhold,
                        bytes: n,
                        kind: ImpairKind::Withheld {
                            for_duration: withhold,
                        },
                    },
                );
            }
            withhold
        } else {
            Duration::ZERO
        };

        let forward_at = (arrival + delay + extra).max(next_free);
        next_free = forward_at;
        if forward_at > arrival {
            tokio::time::sleep_until(tokio::time::Instant::from_std(forward_at)).await;
        }
        if wr.write_all(&buf[..n]).await.is_err() {
            return;
        }
    }
}

// ---------------------------------------------------------------------------
// UDP impairment proxy
// ---------------------------------------------------------------------------

/// Where a delayed datagram is forwarded when its deadline arrives.
#[derive(Clone)]
enum DelayDest {
    /// Return direction: back to the client via the shared front-door socket.
    Front(SocketAddr),
    /// Data direction: to the hub via this NAT entry's upstream socket.
    Upstream(Arc<UdpSocket>, SocketAddr),
}

struct DelayItem {
    /// Deadline for forwarding (`tokio::time::Instant` keeps paused-clock
    /// unit tests coherent with the forwarder's `sleep_until`).
    ready_at: tokio::time::Instant,
    data: Vec<u8>,
    dest: DelayDest,
}

/// Delay-line health snapshot (the decisive observable for the 2026-09-16
/// quic egress-stall case file: exploding depth/overflow convicts the
/// harness; a flat depth with the product still stalling promotes the
/// quinn-side suspect with evidence).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct DelayLineStats {
    /// Datagrams currently queued.
    pub depth: usize,
    /// High-water mark of `depth` since spawn.
    pub high_water: usize,
    /// Datagrams tail-dropped on overflow (harness fault, not injected loss).
    pub overflow_dropped: u64,
}

struct DelayLineShared {
    queue: Mutex<VecDeque<DelayItem>>,
    notify: Notify,
    capacity: usize,
    high_water: AtomicUsize,
    overflow_dropped: AtomicU64,
}

/// Bounded FIFO delay line with a single dedicated forwarding task.
///
/// Replaces the former spawn-per-datagram sleeps, which were unbounded in
/// task count, unordered, and unobservable. Ordering invariant: the
/// configured `one_way_delay` is constant, so arrival order equals deadline
/// order — a FIFO `VecDeque` is exact (switch to a deadline heap if
/// per-packet jitter is ever introduced). A blocked `send_to` (destination
/// not draining) head-of-line blocks the line **by design**: that is the
/// saturation the depth/overflow accounting exists to expose.
#[derive(Clone)]
struct DelayLine {
    shared: Arc<DelayLineShared>,
}

impl DelayLine {
    /// Spawns the forwarding task (runs until `token` is cancelled).
    fn spawn(capacity: usize, front: Arc<UdpSocket>, token: CancellationToken) -> Self {
        let shared = Arc::new(DelayLineShared {
            queue: Mutex::new(VecDeque::new()),
            notify: Notify::new(),
            capacity,
            high_water: AtomicUsize::new(0),
            overflow_dropped: AtomicU64::new(0),
        });
        tokio::spawn(run_delay_forwarder(Arc::clone(&shared), front, token));
        Self { shared }
    }

    /// Enqueues one datagram for delayed forwarding. Returns `false` on
    /// overflow (tail-dropped, router-queue semantics) — the caller must
    /// record it as a harness-fault event.
    fn push(&self, delay: Duration, data: Vec<u8>, dest: DelayDest) -> bool {
        let item = DelayItem {
            ready_at: tokio::time::Instant::now() + delay,
            data,
            dest,
        };
        let mut q = self
            .shared
            .queue
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if q.len() >= self.shared.capacity {
            self.shared.overflow_dropped.fetch_add(1, Ordering::Relaxed);
            return false;
        }
        let was_empty = q.is_empty();
        q.push_back(item);
        let depth = q.len();
        drop(q);
        self.shared.high_water.fetch_max(depth, Ordering::Relaxed);
        if was_empty {
            // Only the empty→non-empty transition needs a wake: with equal
            // delays the head is always the earliest deadline, so a push
            // behind existing items can never move the forwarder's deadline.
            self.shared.notify.notify_one();
        }
        true
    }

    fn stats(&self) -> DelayLineStats {
        let depth = self
            .shared
            .queue
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .len();
        DelayLineStats {
            depth,
            high_water: self.shared.high_water.load(Ordering::Relaxed),
            overflow_dropped: self.shared.overflow_dropped.load(Ordering::Relaxed),
        }
    }
}

/// Forwarder loop: sleep until the head's deadline, send it, repeat; park on
/// `notify` while empty. The only exit is cancellation.
async fn run_delay_forwarder(
    shared: Arc<DelayLineShared>,
    front: Arc<UdpSocket>,
    token: CancellationToken,
) {
    loop {
        let head_ready = {
            let q = shared
                .queue
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            q.front().map(|item| item.ready_at)
        };
        let Some(ready_at) = head_ready else {
            tokio::select! {
                () = token.cancelled() => break,
                _ = shared.notify.notified() => {}
            }
            continue;
        };
        if ready_at > tokio::time::Instant::now() {
            tokio::select! {
                () = token.cancelled() => break,
                _ = tokio::time::sleep_until(ready_at) => {}
            }
            continue;
        }
        let item = shared
            .queue
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .pop_front();
        if let Some(item) = item {
            // Send errors (swept NAT entry, gone client) are silent: UDP has
            // no delivery contract, matching the previous spawn-per-packet
            // behavior.
            let _ = match item.dest {
                DelayDest::Front(addr) => front.send_to(&item.data, addr).await,
                DelayDest::Upstream(sock, addr) => sock.send_to(&item.data, addr).await,
            };
        }
    }
}

/// UDP NAT entry: one upstream socket per client (return traffic is mapped back to the client by originating socket).
struct UdpNatEntry {
    upstream: Arc<UdpSocket>,
    last_used: Instant,
}

/// UDP impairment proxy: the front-door socket receives client datagrams and per-client
/// upstream sockets forward them.
///
/// The data direction (client→upstream) is judged per datagram: a hit is a **real drop**
/// (QUIC's loss recovery takes over), otherwise it is enqueued on the data delay line;
/// the reverse direction only gets added delay via the return delay line. Each line is
/// bounded (`ImpairConfig::queue_capacity`) and exposes depth/overflow accounting —
/// the receive loops themselves never sleep, so per-packet parallelism is preserved
/// without unbounded task spawn.
pub struct UdpImpairProxy {
    local_addr: SocketAddr,
    shutdown: CancellationToken,
    task: JoinHandle<()>,
    events: SharedEvents,
    data_line: DelayLine,
    return_line: DelayLine,
    queue_capacity: usize,
    cuts: Arc<DirectionCuts>,
}

/// Idle timeout for reclaiming NAT entries.
const NAT_IDLE_TIMEOUT: Duration = Duration::from_secs(60);

impl UdpImpairProxy {
    /// Start the proxy (random local port). `upstream` is the real target UDP address.
    pub async fn spawn(upstream: SocketAddr, cfg: ImpairConfig) -> std::io::Result<Self> {
        let front = UdpSocket::bind("127.0.0.1:0").await?;
        let local_addr = front.local_addr()?;
        let front = Arc::new(front);
        let events: SharedEvents = Arc::new(Mutex::new(Vec::new()));
        let shutdown = CancellationToken::new();
        let token = shutdown.clone();
        let task_events = events.clone();
        let cuts = Arc::new(DirectionCuts::default());

        let data_line = DelayLine::spawn(cfg.queue_capacity, Arc::clone(&front), token.clone());
        let return_line = DelayLine::spawn(cfg.queue_capacity, Arc::clone(&front), token.clone());
        let queue_capacity = cfg.queue_capacity;
        // The front-loop task gets clones; the handle keeps the originals for
        // `delay_stats` (both share the same underlying line state).
        let task_data_line = data_line.clone();
        let task_return_line = return_line.clone();
        let task_cuts = Arc::clone(&cuts);

        let task = tokio::spawn(async move {
            let front = front;
            let data_line = task_data_line;
            let return_line = task_return_line;
            let cuts = task_cuts;
            let mut nat: HashMap<SocketAddr, UdpNatEntry> = HashMap::new();
            let mut decider = DropDecider::new(cfg.drop, cfg.seed);
            let mut sweep = tokio::time::interval(Duration::from_secs(15));
            let mut buf = vec![0u8; 65535];

            loop {
                tokio::select! {
                    () = token.cancelled() => break,

                    _ = sweep.tick() => {
                        nat.retain(|_, entry| entry.last_used.elapsed() < NAT_IDLE_TIMEOUT);
                    }

                    recv = front.recv_from(&mut buf) => {
                        let Ok((n, client)) = recv else { break };

                        let entry = match nat.entry(client) {
                            std::collections::hash_map::Entry::Occupied(e) => {
                                let e = e.into_mut();
                                e.last_used = Instant::now();
                                Arc::clone(&e.upstream)
                            }
                            std::collections::hash_map::Entry::Vacant(v) => {
                                let up = match UdpSocket::bind("127.0.0.1:0").await {
                                    Ok(s) => Arc::new(s),
                                    Err(_) => continue,
                                };
                                // Return pump: datagrams from this upstream socket are
                                // enqueued on the shared return delay line (bounded,
                                // observable — the former spawn-per-packet sleeps were
                                // neither). One resident task per NAT entry: bounded by
                                // the entry count, unlike per-datagram spawn.
                                let token2 = token.clone();
                                let cuts2 = Arc::clone(&cuts);
                                let events = task_events.clone();
                                let return_line = return_line.clone();
                                let delay = cfg.one_way_delay;
                                let capacity = cfg.queue_capacity;
                                let up_task = Arc::clone(&up);
                                tokio::spawn(async move {
                                    let mut b = vec![0u8; 65535];
                                    loop {
                                        tokio::select! {
                                            () = token2.cancelled() => break,
                                            recv = up_task.recv_from(&mut b) => {
                                                let Ok((n, _)) = recv else { break };
                                                // One-way hang (hub→agent cut): consume
                                                // and drop the datagram — a blackhole,
                                                // not a close.
                                                if cuts2.is_cut(Direction::HubToAgent) {
                                                    continue;
                                                }
                                                if !return_line.push(delay, b[..n].to_vec(), DelayDest::Front(client)) {
                                                    record_event(
                                                        &events,
                                                        ImpairEvent {
                                                            at: Instant::now(),
                                                            bytes: n,
                                                            kind: ImpairKind::QueueOverflowDropped { capacity },
                                                        },
                                                    );
                                                }
                                            }
                                        }
                                    }
                                });
                                Arc::clone(&v.insert(UdpNatEntry { upstream: up, last_used: Instant::now() }).upstream)
                            }
                        };

                        // One-way hang (agent→hub cut): a real blackhole —
                        // the datagram is consumed and never forwarded.
                        if cuts.is_cut(Direction::AgentToHub) {
                            continue;
                        }

                        // Data direction: a hit on the decision is a real drop
                        if decider.should_drop() {
                            record_event(
                                &task_events,
                                ImpairEvent {
                                    at: Instant::now() + cfg.one_way_delay,
                                    bytes: n,
                                    kind: ImpairKind::Dropped,
                                },
                            );
                            continue;
                        }

                        if !data_line.push(cfg.one_way_delay, buf[..n].to_vec(), DelayDest::Upstream(entry, upstream)) {
                            record_event(
                                &task_events,
                                ImpairEvent {
                                    at: Instant::now(),
                                    bytes: n,
                                    kind: ImpairKind::QueueOverflowDropped { capacity: queue_capacity },
                                },
                            );
                        }
                    }
                }
            }
        });

        Ok(Self {
            local_addr,
            shutdown,
            task,
            events,
            data_line,
            return_line,
            queue_capacity,
            cuts,
        })
    }

    /// The proxy's listen address (clients should send here).
    pub fn local_addr(&self) -> SocketAddr {
        self.local_addr
    }

    /// Impairment events that have occurred (in time order).
    pub fn events(&self) -> Vec<ImpairEvent> {
        self.events
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone()
    }

    /// Delay-line health per direction: `(data (egress→hub), return (hub→egress))`.
    /// The queue capacity is included for context.
    pub fn delay_stats(&self) -> (DelayLineStats, DelayLineStats, usize) {
        (
            self.data_line.stats(),
            self.return_line.stats(),
            self.queue_capacity,
        )
    }

    /// Cuts one direction (see [`DirectionCuts`]): datagrams flowing that
    /// way are silently dropped while the other direction keeps flowing —
    /// the one-way-blackhole form.
    pub fn cut(&self, dir: Direction) {
        self.cuts.set(dir, true);
    }

    /// Restores a cut direction; the next datagram flows again.
    pub fn restore(&self, dir: Direction) {
        self.cuts.set(dir, false);
    }

    /// Shutdown: stop sending and receiving.
    pub async fn shutdown(self) {
        self.shutdown.cancel();
        let _ = self.task.await;
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

    async fn socket_pair() -> (Arc<UdpSocket>, UdpSocket) {
        let front = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let receiver = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        (front, receiver)
    }

    /// FIFO delivery after the configured delay, in arrival order (equal
    /// delays ⇒ arrival order equals deadline order — the line's core
    /// invariant).
    #[tokio::test(start_paused = true)]
    async fn delay_line_delivers_in_fifo_order_after_delay() {
        let (front, rx) = socket_pair().await;
        let dest = rx.local_addr().unwrap();
        let token = CancellationToken::new();
        let line = DelayLine::spawn(8, front, token.clone());

        line.push(
            Duration::from_millis(50),
            b"one".to_vec(),
            DelayDest::Front(dest),
        );
        line.push(
            Duration::from_millis(50),
            b"two".to_vec(),
            DelayDest::Front(dest),
        );

        let t0 = tokio::time::Instant::now();
        let mut buf = [0u8; 16];
        let (n, _) = rx.recv_from(&mut buf).await.unwrap();
        assert_eq!(&buf[..n], b"one");
        let (n, _) = rx.recv_from(&mut buf).await.unwrap();
        assert_eq!(&buf[..n], b"two");
        // Nothing forwarded before the delay elapsed.
        assert!(t0.elapsed() >= Duration::from_millis(50));

        token.cancel();
    }

    /// Overflow tail-drops (router-queue semantics) and the accounting
    /// exposes it: depth capped at capacity, high-water recorded, overflow
    /// counted — the red flag the soak gate turns into a scenario failure.
    #[tokio::test]
    async fn delay_line_tail_drops_on_overflow_and_counts() {
        let (front, _rx) = socket_pair().await;
        let dest = "127.0.0.1:1".parse().unwrap();
        let token = CancellationToken::new();
        let line = DelayLine::spawn(2, front, token.clone());

        // Deliberately far-future deadlines: nothing drains during the test.
        let far = Duration::from_secs(3600);
        assert!(line.push(far, vec![1], DelayDest::Front(dest)));
        assert!(line.push(far, vec![2], DelayDest::Front(dest)));
        assert!(!line.push(far, vec![3], DelayDest::Front(dest)));

        assert_eq!(
            line.stats(),
            DelayLineStats {
                depth: 2,
                high_water: 2,
                overflow_dropped: 1,
            }
        );
        token.cancel();
    }

    /// A bound socket playing the "hub": echoes every datagram back to its
    /// source address.
    async fn udp_echo_upstream() -> Arc<UdpSocket> {
        let sock = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let s = Arc::clone(&sock);
        tokio::spawn(async move {
            let mut b = vec![0u8; 65535];
            loop {
                let Ok((n, from)) = s.recv_from(&mut b).await else {
                    break;
                };
                let _ = s.send_to(&b[..n], from).await;
            }
        });
        sock
    }

    /// The one-way-hang primitive on the UDP face: a cut direction is a
    /// total silent blackhole while the other direction (and the NAT
    /// mapping) stays alive — the 2026-10-09 one-way-blackhole form.
    #[tokio::test]
    async fn udp_direction_cut_blackholes_only_that_direction() {
        let upstream = udp_echo_upstream().await;
        let proxy = UdpImpairProxy::spawn(
            upstream.local_addr().unwrap(),
            ImpairConfig {
                one_way_delay: Duration::ZERO,
                ..ImpairConfig::default()
            },
        )
        .await
        .unwrap();
        let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let mut buf = [0u8; 64];
        let silent = Duration::from_millis(300);

        // Control: round trip through both directions.
        client.send_to(b"ping", proxy.local_addr()).await.unwrap();
        let (n, _) = tokio::time::timeout(silent, client.recv_from(&mut buf))
            .await
            .expect("round trip before any cut")
            .unwrap();
        assert_eq!(&buf[..n], b"ping");

        // Cut agent→hub: the echo never sees the datagram, so nothing comes
        // back — but the reverse direction is provably intact (next case).
        proxy.cut(Direction::AgentToHub);
        client
            .send_to(b"swallowed", proxy.local_addr())
            .await
            .unwrap();
        assert!(
            tokio::time::timeout(silent, client.recv_from(&mut buf))
                .await
                .is_err(),
            "agent→hub cut must blackhole the round trip"
        );

        // Restore agent→hub, cut hub→agent: the echo receives and replies,
        // but the reply never reaches the client.
        proxy.restore(Direction::AgentToHub);
        proxy.cut(Direction::HubToAgent);
        client
            .send_to(b"half-duplex", proxy.local_addr())
            .await
            .unwrap();
        assert!(
            tokio::time::timeout(silent, client.recv_from(&mut buf))
                .await
                .is_err(),
            "hub→agent cut must swallow the return leg"
        );

        // Restore: the same NAT mapping round trips again.
        proxy.restore(Direction::HubToAgent);
        client.send_to(b"pong", proxy.local_addr()).await.unwrap();
        let (n, _) = tokio::time::timeout(silent, client.recv_from(&mut buf))
            .await
            .expect("round trip after restore")
            .unwrap();
        assert_eq!(&buf[..n], b"pong");

        proxy.shutdown().await;
    }

    /// The one-way-hang primitive on the TCP face: a cut direction drains
    /// and withholds (a hang, not a close — the connection stays
    /// established); restore resumes in place.
    #[tokio::test]
    async fn tcp_direction_cut_hangs_without_closing() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let upstream = listener.local_addr().unwrap();
        tokio::spawn(async move {
            loop {
                let Ok((mut sock, _)) = listener.accept().await else {
                    break;
                };
                tokio::spawn(async move {
                    let mut b = [0u8; 1024];
                    loop {
                        match sock.read(&mut b).await {
                            Ok(0) | Err(_) => break,
                            Ok(n) => {
                                if sock.write_all(&b[..n]).await.is_err() {
                                    break;
                                }
                            }
                        }
                    }
                });
            }
        });

        let proxy = TcpImpairProxy::spawn(
            upstream,
            ImpairConfig {
                one_way_delay: Duration::ZERO,
                ..ImpairConfig::default()
            },
        )
        .await
        .unwrap();
        let mut sock = TcpStream::connect(proxy.local_addr()).await.unwrap();
        sock.write_all(b"ping").await.unwrap();
        let mut b = [0u8; 64];
        let n = tokio::time::timeout(Duration::from_millis(500), sock.read(&mut b))
            .await
            .expect("echo before cut")
            .unwrap();
        assert_eq!(&b[..n], b"ping");

        // Cut client→upstream: writes are drained (never block, no FIN), the
        // echo never sees them, so no reply arrives — but the connection is
        // NOT closed (a further restored exchange proves it stayed up).
        proxy.cut(Direction::AgentToHub);
        sock.write_all(b"withheld").await.unwrap();
        assert!(
            tokio::time::timeout(Duration::from_millis(300), sock.read(&mut b))
                .await
                .is_err(),
            "cut direction must produce silence, not EOF (read would return Ok(0))"
        );

        proxy.restore(Direction::AgentToHub);
        sock.write_all(b"pong").await.unwrap();
        let n = tokio::time::timeout(Duration::from_millis(500), sock.read(&mut b))
            .await
            .expect("echo after restore (connection stayed established)")
            .unwrap();
        assert_eq!(&b[..n], b"pong");

        proxy.shutdown().await;
    }
}
