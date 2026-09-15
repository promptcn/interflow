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
//! `forward = arrival + delay`, no queueing; the only queueing source is a
//! withheld chunk (in-order floor = the previous chunk's forward time).
//!
//! Randomness source: seeded StdRng — same seed and same input sequence → the
//! same impairment pattern (reproducible). `DropPattern::Every` provides a
//! timing-independent deterministic pattern (for unit tests and exact
//! assertions).

use rand::rngs::StdRng;
use rand::{Rng, SeedableRng};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UdpSocket};
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
    /// Random seed for probability patterns.
    pub seed: u64,
}

impl Default for ImpairConfig {
    fn default() -> Self {
        Self {
            one_way_delay: Duration::from_millis(25),
            drop: DropPattern::None,
            withhold: Duration::from_millis(100),
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
                tokio::spawn(relay_tcp(client, up, cfg, events));
            }
        });

        Ok(Self {
            local_addr,
            shutdown,
            task,
            events,
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
) {
    let (client_rd, client_wr) = client.into_split();
    let (up_rd, up_wr) = upstream.into_split();

    // client→upstream: data direction, gets drop-withholding
    let up_pump = pump_tcp(
        client_rd,
        up_wr,
        cfg.one_way_delay,
        Some((cfg.drop, cfg.withhold, cfg.seed, events)),
    );
    // upstream→client: reverse direction only gets added delay
    let down_pump = pump_tcp(up_rd, client_wr, cfg.one_way_delay, None);

    let (a, b) = tokio::join!(up_pump, down_pump);
    let _ = (a, b);
}

/// One-direction TCP pump: read chunk → (optionally withhold) → delayed forward → write.
///
/// Virtual clock: `forward = max(arrival + delay + withhold, previous forward)` —
/// propagation delay never queues; the only queueing source is the in-order floor
/// imposed by withheld chunks. EOF is passed through as a half-close.
#[allow(clippy::too_many_arguments)]
async fn pump_tcp<R, W>(
    mut rd: R,
    mut wr: W,
    delay: Duration,
    impair: Option<(DropPattern, Duration, u64, SharedEvents)>,
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

/// UDP NAT entry: one upstream socket per client (return traffic is mapped back to the client by originating socket).
struct UdpNatEntry {
    upstream: Arc<UdpSocket>,
    last_used: Instant,
}

/// UDP impairment proxy: the front-door socket receives client datagrams and per-client
/// upstream sockets forward them.
///
/// The data direction (client→upstream) is judged per datagram: a hit is a **real drop**
/// (QUIC's loss recovery takes over), otherwise it is forwarded after `one_way_delay`;
/// the reverse direction only gets added delay.
pub struct UdpImpairProxy {
    local_addr: SocketAddr,
    shutdown: CancellationToken,
    task: JoinHandle<()>,
    events: SharedEvents,
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

        let task = tokio::spawn(async move {
            let front = front;
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
                                &e.upstream
                            }
                            std::collections::hash_map::Entry::Vacant(v) => {
                                let up = match UdpSocket::bind("127.0.0.1:0").await {
                                    Ok(s) => Arc::new(s),
                                    Err(_) => continue,
                                };
                                // Return pump: datagrams from this upstream socket → back to the client via the
                                // front door. Delay injection must be per-packet and parallel (UDP is unordered) —
                                // a serial sleep inside the loop would cap downstream throughput at 1 packet per
                                // delay and grow the queue without bound.
                                let back = front.clone();
                                let token2 = token.clone();
                                let up_sock = up.clone();
                                let delay = cfg.one_way_delay;
                                tokio::spawn(async move {
                                    let mut b = vec![0u8; 65535];
                                    loop {
                                        tokio::select! {
                                            () = token2.cancelled() => break,
                                            recv = up_sock.recv_from(&mut b) => {
                                                let Ok((n, _)) = recv else { break };
                                                let data = b[..n].to_vec();
                                                let back = back.clone();
                                                tokio::spawn(async move {
                                                    tokio::time::sleep(delay).await;
                                                    let _ = back.send_to(&data, client).await;
                                                });
                                            }
                                        }
                                    }
                                });
                                &v.insert(UdpNatEntry { upstream: up, last_used: Instant::now() }).upstream
                            }
                        };

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

                        let data = buf[..n].to_vec();
                        let up = entry.clone();
                        tokio::spawn(async move {
                            tokio::time::sleep(cfg.one_way_delay).await;
                            let _ = up.send_to(&data, upstream).await;
                        });
                    }
                }
            }
        });

        Ok(Self {
            local_addr,
            shutdown,
            task,
            events,
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

    /// Shutdown: stop sending and receiving.
    pub async fn shutdown(self) {
        self.shutdown.cancel();
        let _ = self.task.await;
    }
}
