//! Soak scenario orchestration: a long-running regression gate over a real
//! process topology (backlog §1.7).
//!
//! System under test = three real processes (`interflow-mesh hub` + one egress
//! and one ingress `interflow-mesh agent`, with real TOML configs + TLS
//! certificates + SIGTERM graceful shutdown); load generation and observation
//! stay in this process: the phased SSE backend, N consumer streams, the
//! impairment proxies (egress↔hub link), per-PID RSS sampling, and hub
//! `/metrics` scraping.
//!
//! Eight assertions (any failure → fail-fast + exit(1)):
//! 1. **Zero corruption**: strictly consecutive chunk seq per stream + full
//!    payload pattern verification;
//! 2. **Stall bound**: inter-chunk gap on any stream ≤ `--stall-bound-secs`
//!    (default 135s = max(heartbeat liveness deadline 75s [15s×(4+1), the
//!    `HeartbeatConfig` default], poll watchdog 105s [75s+30s margin,
//!    derived from the negotiation]) + 30s recovery margin. The 30s silent
//!    window + propagation is well within the bound; a 7.5h-class data-plane
//!    stall gets caught at 135s);
//! 3. **Memory drift**: per-component RSS timelines (hub / egress / ingress);
//!    after warmup, last-1/4 mean − first-1/4 mean ≤ max(pct×baseline,
//!    per-component absolute floor);
//! 4. **Heartbeat canary** (production /metrics path):
//!    `interflow_hub_heartbeat_supervisor_restarts == 0` (any death of the
//!    global supervision loop is caught — the direct sentinel for the 7.5h
//!    incident species); h2 scenarios additionally require monotonically
//!    growing pings (QUIC sessions are skipped by the supervision loop and
//!    covered by the quinn idle timeout);
//! 5. **Process liveness**: all three processes under test stay alive for the
//!    whole run (an unexpected exit fails immediately and dumps log tails);
//! 6. **Graceful shutdown**: bounded clean exit after SIGTERM (hub exit code
//!    0 / agent 143);
//! 7. **No egress fd growth** (sentinel of the 2026-09-14 orphaned-stream
//!    fix): under churn short-lived streams (connect → receive a stretch →
//!    disconnect) plus periodic SIGKILL/restart of the churn agent (source-side
//!    re-registration eviction waves), the egress process's open-fd count from
//!    first-half median → final value must grow by ≤ the bound — in-session
//!    orphaned streams (lost close notification / never notifying the peer)
//!    surface directly here;
//! 8. **Sweep-notification canary** (poll-plane/h2 only): when there is ≥1
//!    eviction wave and churn has traffic, the hub's
//!    `interflow_hub_sweep_peer_notified_total` must be ≥1 (regression
//!    sentinel for sweeps that clear the table without notifying the peer, on
//!    the production /metrics path). A relay-plane (QUIC) peer is torn down by
//!    the table-entry drop and never increments this counter, so the QUIC
//!    scenario skips the canary by design.
//!
//! Run: `just soak [-- args]`; smoke: `just soak -- --quick`.

#![allow(
    clippy::cast_precision_loss,
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss
)]

use crate::backend::{
    CHUNK_HEADER, chunk_instant, decode_chunk, sse_backend, verify_chunk_payload,
};
use crate::impair::{DropPattern, ImpairConfig, ImpairKind, TcpImpairProxy, UdpImpairProxy};
use crate::metrics::{LatencyStats, fmt_ms, latency_stats};
use crate::soak::phases::{PhaseTimeline, SerializedSpan, run_phases};
use crate::soak::proc::{
    MeshProcess, churn_agent_config, egress_agent_config, hub_config, ingress_agent_config,
    spawn_mesh, write_toml,
};
use crate::soak::{rss, scrape};
use crate::stack::{pick_ephemeral_port, wait_for_tcp};
use clap::Parser;
use interflow_mesh::config::TransportKind;
use serde::Serialize;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::io::AsyncReadExt;
use tokio::net::TcpStream;
use tokio::sync::Mutex;
use tokio::task::JoinSet;
use tokio_util::sync::CancellationToken;

// ---------------------------------------------------------------------------
// CLI
// ---------------------------------------------------------------------------

/// CLI arguments (defaults double as the gate's reference settings).
#[derive(Parser, Debug, Clone)]
#[command(
    name = "soak",
    about = "Long-running soak gate (real process topology + eight assertions; run several rounds nightly/before releases)"
)]
pub struct SoakArgs {
    /// Transports to exercise (comma-separated: h2,quic)
    #[arg(long, value_delimiter = ',', default_value = "h2,quic")]
    transports: Vec<String>,

    /// Number of concurrent streams
    #[arg(long, default_value_t = 8)]
    streams: usize,

    /// Duration per transport in seconds
    #[arg(long, default_value_t = 600)]
    duration_secs: u64,

    /// Chunk size in bytes (SSE token magnitude)
    #[arg(long, default_value_t = 256)]
    chunk_bytes: usize,

    /// Chunk send interval in ms per stream
    #[arg(long, default_value_t = 25)]
    chunk_interval_ms: u64,

    /// Injected packet loss (%, egress↔hub link)
    #[arg(long, default_value_t = 1)]
    loss_pct: u8,

    /// Injected RTT in ms (proxy splits it evenly across both directions)
    #[arg(long, default_value_t = 50)]
    rtt_ms: u64,

    /// TCP withhold duration in ms (h2 lost-segment retransmit recovery model)
    #[arg(long, default_value_t = 100)]
    withhold_ms: u64,

    /// UDP impair-proxy delay-line capacity in datagrams per direction (overflow tail-drops
    /// and fails the scenario as a harness fault — 2026-09-16 quic-stall case file)
    #[arg(long, default_value_t = 8192)]
    impair_queue_capacity: usize,

    /// Phase cycle length in seconds (tail is the silent window)
    #[arg(long, default_value_t = 300)]
    cycle_secs: u64,

    /// Silent window length at each cycle tail in seconds (must be < idle budget; streams must survive it)
    #[arg(long, default_value_t = 30)]
    silence_secs: u64,

    /// Burst chunk count per stream on silence recovery
    #[arg(long, default_value_t = 64)]
    burst_chunks: usize,

    /// Ingress rule idle budget in seconds
    #[arg(long, default_value_t = 300)]
    idle_timeout_secs: u64,

    /// Stall bound in seconds: any stream gap above this fails the run. Default 135s = max(heartbeat
    /// liveness deadline 75s, poll watchdog 105s) + 30s recovery margin (derivation in module docs)
    #[arg(long, default_value_t = 135)]
    stall_bound_secs: u64,

    /// RSS/metrics sampling interval in seconds
    #[arg(long, default_value_t = 30)]
    mem_sample_secs: u64,

    /// RSS drift tolerance (%, last 1/4 vs first 1/4 after warmup)
    #[arg(long, default_value_t = 20)]
    rss_drift_max_pct: u64,

    /// Churn short-lived stream interval in ms (data-plane payload of the eviction scenario)
    #[arg(long, default_value_t = 200)]
    churn_interval_ms: u64,

    /// Churn agent eviction wave interval in seconds (SIGKILL + restart → source-side re-registration sweep)
    #[arg(long, default_value_t = 60)]
    churn_restart_every_secs: u64,

    /// Upper bound of the egress fd growth assertion (sentinel threshold for orphaned streams under churn + eviction waves)
    #[arg(long, default_value_t = 16)]
    fd_growth_bound: u64,

    /// Path to the interflow-mesh binary (default target/release/interflow-mesh)
    #[arg(long)]
    mesh_bin: Option<PathBuf>,

    /// Random seed (impair proxies)
    #[arg(long, default_value_t = 20260913)]
    seed: u64,

    /// Results JSON output path (default bench-results/soak-<timestamp>/results.json)
    #[arg(long)]
    out: Option<PathBuf>,

    /// Smoke profile: h2 × 4 streams × 120s × cycle 30s/silence 8s
    #[arg(long, default_value_t = false)]
    quick: bool,

    /// Absorb flags injected by `cargo bench` (cargo bench entry compatibility)
    #[arg(long, hide = true)]
    bench: bool,
}

impl SoakArgs {
    fn apply_quick(&mut self) {
        self.transports = vec!["h2".to_string()];
        self.streams = 4;
        self.duration_secs = 120;
        self.cycle_secs = 30;
        self.silence_secs = 8;
        self.loss_pct = 1;
        self.churn_restart_every_secs = 40;
    }
}

/// Cross-parameter constraint validation (the precondition for the gate's semantics).
fn validate(args: &SoakArgs) -> Result<(), String> {
    if args.chunk_bytes < CHUNK_HEADER {
        return Err(format!(
            "chunk size must be at least {CHUNK_HEADER} bytes (header)"
        ));
    }
    if args.streams == 0 {
        return Err("streams must be at least 1".into());
    }
    if args.silence_secs >= args.idle_timeout_secs {
        return Err(format!(
            "silent window ({}s) must be < idle budget ({}s): silence ended by a legitimate stream teardown is not the bug this gate is meant to catch",
            args.silence_secs, args.idle_timeout_secs
        ));
    }
    if args.silence_secs + 30 >= args.stall_bound_secs {
        return Err(format!(
            "silent window ({}s) + 30s recovery margin must be < stall bound ({}s), otherwise the silence itself would falsely trigger a failure",
            args.silence_secs, args.stall_bound_secs
        ));
    }
    if args.cycle_secs <= args.silence_secs {
        return Err(format!(
            "cycle ({}s) must be > silent window ({}s), otherwise there is no normal sending window",
            args.cycle_secs, args.silence_secs
        ));
    }
    if args.duration_secs < args.cycle_secs {
        return Err(format!(
            "duration ({}s) must cover at least one full cycle ({}s)",
            args.duration_secs, args.cycle_secs
        ));
    }
    Ok(())
}

fn transport_id(t: TransportKind) -> u64 {
    match t {
        TransportKind::H2 => 1,
        TransportKind::Quic => 2,
    }
}

fn transport_name(t: TransportKind) -> &'static str {
    match t {
        TransportKind::H2 => "h2",
        TransportKind::Quic => "quic",
    }
}

fn workspace_root() -> PathBuf {
    // testkit lives at crates/testkit → the root is two levels up
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn resolve_mesh_bin(arg: Option<&Path>) -> Result<PathBuf, String> {
    if let Some(p) = arg {
        return if p.is_file() {
            Ok(p.to_path_buf())
        } else {
            Err(format!(
                "file specified by --mesh-bin does not exist: {}",
                p.display()
            ))
        };
    }
    let default = workspace_root().join("target/release/interflow-mesh");
    if default.is_file() {
        return Ok(default);
    }
    Err(format!(
        "interflow-mesh binary not found ({}). Run `cargo build --release -p interflow-mesh` first \
         or pass a path via --mesh-bin (just soak builds it automatically)",
        default.display()
    ))
}

/// (run directory, artifact path). A relative `--out` path is resolved against the workspace root.
fn resolve_out(out: Option<&Path>) -> (PathBuf, PathBuf) {
    let root = workspace_root();
    match out {
        Some(p) => {
            let full = if p.is_absolute() {
                p.to_path_buf()
            } else {
                root.join(p)
            };
            let dir = full.parent().map(Path::to_path_buf).unwrap_or(root);
            (dir, full)
        }
        None => {
            let ts = chrono::Local::now().format("%Y%m%d-%H%M%S");
            let dir = root.join("bench-results").join(format!("soak-{ts}"));
            let path = dir.join("results.json");
            (dir, path)
        }
    }
}

// ---------------------------------------------------------------------------
// Result structures (artifact schema)
// ---------------------------------------------------------------------------

/// An assertion record in the artifact.
#[derive(Serialize, Debug)]
struct AssertionOut {
    name: String,
    pass: bool,
    /// Failure detail when pass=false; for skipped-type assertions pass=true and this explains why.
    detail: String,
}

#[derive(Serialize)]
struct StreamStat {
    stream: usize,
    chunks: usize,
    #[serde(flatten)]
    stats: LatencyStats,
    max_gap_ms: f64,
    /// Number of significant gaps that do not overlap a silent window (a real stall).
    unexpected_stalls: usize,
}

#[derive(Serialize)]
struct RssSummary {
    name: String,
    samples: usize,
    misses: usize,
    first_quarter_bytes: Option<u64>,
    last_quarter_bytes: Option<u64>,
    drift_bytes: Option<i64>,
    threshold_bytes: u64,
    pass: bool,
    /// Downsampled timeline (at most 240 points; for artifact readability).
    timeline: Vec<(f64, u64)>,
}

/// Churn + eviction-wave summary (artifact; fd timeline downsampled to at most 240 points).
#[derive(Serialize, Default)]
struct ChurnSummary {
    /// Number of successfully completed short-lived streams.
    successes: u64,
    /// Number of eviction waves (SIGKILL + restart).
    waves: u64,
    /// Egress fd timeline (seconds relative to scenario start, count).
    fd_timeline: Vec<(f64, u64)>,
    /// Number of missed fd samples (platform unsupported, etc.).
    fd_misses: usize,
    /// Sweep peer-notification count (final value from production /metrics).
    sweep_peer_notified: Option<u64>,
}

#[derive(Serialize, Default)]
struct HeartbeatSummary {
    samples: usize,
    misses: usize,
    pings_first: u64,
    pings_last: u64,
    supervisor_restarts: u64,
    pong_total: u64,
}

/// Impairment-harness self-health: UDP delay-line depth/overflow accounting
/// (2026-09-16 quic-stall case file — the decisive observable separating a
/// harness bottleneck from a product-side quinn stall).
#[derive(Serialize, Default)]
struct HarnessSummary {
    /// Delay-line high-water mark, data direction (egress→hub), datagrams.
    udp_data_high_water: usize,
    /// Tail-dropped datagrams, data direction (harness fault).
    udp_data_overflow: u64,
    /// Delay-line high-water mark, return direction (hub→egress).
    udp_return_high_water: usize,
    /// Tail-dropped datagrams, return direction (harness fault).
    udp_return_overflow: u64,
    /// Configured line capacity per direction (0 = no UDP proxy in this scenario).
    udp_queue_capacity: usize,
}

#[derive(Serialize)]
struct TransportResult {
    transport: String,
    pass: bool,
    /// Reason when the scenario itself failed (startup/readiness/topology error).
    error: Option<String>,
    duration_secs: u64,
    streams: usize,
    chunks_verified: usize,
    silence_cycles: usize,
    stall_bound_secs: u64,
    phases: Vec<SerializedSpan>,
    streams_detail: Vec<StreamStat>,
    max_gap_ms: f64,
    rss: Vec<RssSummary>,
    heartbeat: HeartbeatSummary,
    churn: ChurnSummary,
    harness: HarnessSummary,
    assertions: Vec<AssertionOut>,
}

fn failed_result(name: &str, args: &SoakArgs, err: String) -> TransportResult {
    TransportResult {
        transport: name.to_string(),
        pass: false,
        error: Some(err),
        duration_secs: args.duration_secs,
        streams: args.streams,
        chunks_verified: 0,
        silence_cycles: 0,
        stall_bound_secs: args.stall_bound_secs,
        phases: Vec::new(),
        streams_detail: Vec::new(),
        max_gap_ms: 0.0,
        rss: Vec::new(),
        heartbeat: HeartbeatSummary::default(),
        churn: ChurnSummary::default(),
        harness: HarnessSummary::default(),
        assertions: Vec::new(),
    }
}

// ---------------------------------------------------------------------------
// Consumers
// ---------------------------------------------------------------------------

/// Consumer error classification (used for assertion attribution).
enum ConsumerError {
    /// Broken seq or corrupted pattern (zero-corruption assertion).
    Corruption(String),
    /// Gap above the stall bound (stall assertion; the interception point for 7.5h-class liveness bugs).
    Stalled(String),
    /// Connection torn down / read-write failure (data-plane break).
    Transport(String),
}

impl ConsumerError {
    fn detail(&self) -> &str {
        match self {
            ConsumerError::Corruption(d)
            | ConsumerError::Stalled(d)
            | ConsumerError::Transport(d) => d,
        }
    }
}

/// Per-stream consumption result (this structure only exists when all checks pass).
struct ConsumerOutcome {
    stream: usize,
    chunks: usize,
    latencies: Vec<u64>,
    recv: Vec<Instant>,
}

/// A single consumer stream: connect to the ingress local listener, receive fixed-size
/// chunks, and fully verify each one (seq continuity + pattern); a gap above the
/// stall bound fails immediately (fail-fast).
async fn consumer(
    idx: usize,
    ingress_addr: SocketAddr,
    chunk_bytes: usize,
    duration: Duration,
    stall_bound: Duration,
) -> Result<ConsumerOutcome, ConsumerError> {
    let mut sock = TcpStream::connect(ingress_addr)
        .await
        .map_err(|e| ConsumerError::Transport(format!("stream {idx} connect ingress: {e}")))?;
    let _ = sock.set_nodelay(true);
    let deadline = tokio::time::Instant::now() + duration + Duration::from_secs(5);
    let mut buf = vec![0u8; chunk_bytes];
    let mut out = ConsumerOutcome {
        stream: idx,
        chunks: 0,
        latencies: Vec::new(),
        recv: Vec::new(),
    };
    let mut expected_seq: u32 = 0;

    loop {
        // Read exactly one fixed-size chunk (frame-aligned: the connection starts at chunk 0)
        let mut got = 0usize;
        let fill = async {
            while got < buf.len() {
                match sock.read(&mut buf[got..]).await {
                    Ok(0) => {
                        return Err(ConsumerError::Transport(
                            "ingress connection closed prematurely (stream teardown)".to_string(),
                        ));
                    }
                    Ok(n) => got += n,
                    Err(e) => return Err(ConsumerError::Transport(e.to_string())),
                }
            }
            Ok(())
        };
        tokio::select! {
            _ = tokio::time::sleep_until(deadline) => return Ok(out),
            r = tokio::time::timeout(stall_bound, fill) => match r {
                Err(_) => {
                    return Err(ConsumerError::Stalled(format!(
                        "stream {idx} stalled beyond bound: no complete chunk for >{stall_bound:?} (interception point for 7.5h-class liveness stalls)"
                    )))
                }
                Ok(Err(e)) => return Err(e),
                Ok(Ok(())) => {}
            },
        }

        let now = Instant::now();
        let (send_ts_ns, seq) = decode_chunk(&buf);
        if seq != expected_seq {
            return Err(ConsumerError::Corruption(format!(
                "stream {idx} seq break: expected {expected_seq}, got {seq} (lost or reordered frames)"
            )));
        }
        if let Err(off) = verify_chunk_payload(&buf, seq) {
            return Err(ConsumerError::Corruption(format!(
                "stream {idx} pattern corruption: seq={seq} first mismatching byte at payload offset {off}"
            )));
        }
        expected_seq = expected_seq.wrapping_add(1);
        let sent_at = chunk_instant(send_ts_ns);
        out.latencies
            .push(now.duration_since(sent_at).as_nanos() as u64);
        out.recv.push(now);
        out.chunks += 1;
    }
}

/// Data-path readiness probe: a temporary stream receives the first chunk (proof the full path is
/// ready, frame boundary seq=0).
async fn probe_first_chunk(addr: SocketAddr, chunk_bytes: usize) -> Result<(), String> {
    let mut sock = TcpStream::connect(addr)
        .await
        .map_err(|e| format!("probe connect: {e}"))?;
    let mut buf = vec![0u8; chunk_bytes];
    sock.read_exact(&mut buf)
        .await
        .map_err(|e| format!("probe first-chunk read failed (data path not ready): {e}"))?;
    let (_, seq) = decode_chunk(&buf);
    if seq != 0 {
        return Err(format!(
            "probe first chunk seq={seq} (expected 0, frame boundary not aligned)"
        ));
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Sampling and supervision tasks
// ---------------------------------------------------------------------------

async fn rss_sampler(
    targets: Vec<(&'static str, u32)>,
    interval: Duration,
    cancel: CancellationToken,
) -> Vec<RssSeries> {
    let t0 = Instant::now();
    let mut series: Vec<RssSeries> = targets
        .iter()
        .map(|(name, _)| RssSeries {
            name: (*name).to_string(),
            samples: Vec::new(),
            misses: 0,
        })
        .collect();
    loop {
        for (i, (_, pid)) in targets.iter().enumerate() {
            match rss::sample_rss(*pid).await {
                Some(bytes) => series[i].samples.push((t0.elapsed().as_secs_f64(), bytes)),
                None => series[i].misses += 1,
            }
        }
        tokio::select! {
            _ = tokio::time::sleep(interval) => {}
            _ = cancel.cancelled() => return series,
        }
    }
}

struct RssSeries {
    name: String,
    /// (seconds relative to scenario start, bytes)
    samples: Vec<(f64, u64)>,
    misses: usize,
}

/// Egress fd timeline (the data source for the orphaned-stream sentinel assertion).
#[derive(Default)]
struct FdSeries {
    samples: Vec<(f64, u64)>,
    misses: usize,
}

/// Periodically sample the target process's open fd count until cancelled.
async fn fd_sampler(pid: u32, interval: Duration, cancel: CancellationToken) -> FdSeries {
    let t0 = Instant::now();
    let mut series = FdSeries::default();
    loop {
        match rss::sample_fd_count(pid).await {
            Some(n) => series.samples.push((t0.elapsed().as_secs_f64(), n)),
            None => series.misses += 1,
        }
        tokio::select! {
            _ = tokio::time::sleep(interval) => {}
            _ = cancel.cancelled() => return series,
        }
    }
}

/// Churn short-lived stream client: connect → hold the receiving stream for
/// [`CHURN_HOLD`] → disconnect, looping until cancelled.
///
/// Every loop iteration is one complete end-to-end stream (visitor conn →
/// ingress → hub → egress → backend) that walks the whole teardown chain for
/// real — close-notification-loss defects keep accumulating here. Holding the
/// stream (rather than disconnecting after a single chunk) guarantees that at
/// any moment ~`HOLD/interval` streams are in service: only then does the
/// eviction wave's sweep have streams to orphan (with a 200ms lifetime, the
/// sweep that follows re-registration ~1s after SIGKILL often found nothing —
/// a hard-won lesson from the first production runs).
///
/// Connect/read failures while the agent is being killed by an eviction wave
/// are expected; retry silently.
const CHURN_HOLD: Duration = Duration::from_secs(3);

async fn churn_client(
    addr: SocketAddr,
    chunk_bytes: usize,
    interval: Duration,
    cancel: CancellationToken,
    successes: Arc<std::sync::atomic::AtomicU64>,
) {
    loop {
        let attempt = async {
            let mut sock = TcpStream::connect(addr).await.ok()?;
            let _ = sock.set_nodelay(true);
            let mut buf = vec![0u8; chunk_bytes];
            let hold_until = tokio::time::Instant::now() + CHURN_HOLD;
            let mut got_any = false;
            loop {
                match tokio::time::timeout_at(hold_until, sock.read_exact(&mut buf)).await {
                    Err(_) => break,     // hold expired, disconnect on purpose (normal teardown chain)
                    Ok(Err(_)) => break, // connection broke (eviction wave killed the agent, etc.), retry silently
                    Ok(Ok(_)) => got_any = true,
                }
            }
            got_any.then_some(())
        };
        if tokio::time::timeout(Duration::from_secs(10), attempt)
            .await
            .is_ok_and(|r| r.is_some())
        {
            successes.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        }
        tokio::select! {
            _ = tokio::time::sleep(interval) => {}
            _ = cancel.cancelled() => return,
        }
    }
}

/// Eviction waves: periodically SIGKILL the churn agent and restart it (same-id
/// re-registration → hub sweep → notify the peer egress to release in-service
/// streams).
///
/// This faithfully reproduces an "abnormally dying / reconnecting source-side
/// agent": no graceful Close, no connection-layer notification — the peer
/// egress's in-service streams can only be terminated via the hub's sweep
/// notification.
async fn churn_eviction_waves(
    churn_proc: Arc<Mutex<MeshProcess>>,
    mesh_bin: PathBuf,
    config_path: PathBuf,
    log_path: PathBuf,
    listen: SocketAddr,
    every: Duration,
    cancel: CancellationToken,
    waves: Arc<std::sync::atomic::AtomicU64>,
) {
    loop {
        tokio::select! {
            _ = tokio::time::sleep(every) => {}
            _ = cancel.cancelled() => return,
        }
        {
            let mut g = churn_proc.lock().await;
            // SIGKILL: simulate abnormal death (no graceful drain)
            if g.kill_and_wait().await.is_err() {
                continue;
            }
            let Ok(replacement) = spawn_mesh(&mesh_bin, "agent", &config_path, &log_path, "churn")
            else {
                continue;
            };
            *g = replacement;
        }
        // Wait for the listener to be ready before counting the wave (the next wave kills a live new process)
        if wait_for_tcp(listen, Duration::from_secs(60)).await.is_ok() {
            waves.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        }
    }
}

#[derive(Serialize, Clone, Copy)]
struct MetricSample {
    elapsed_secs: f64,
    pings_sent: u64,
    supervisor_restarts: u64,
    pong_total: u64,
}

struct MetricsSeries {
    samples: Vec<MetricSample>,
    misses: usize,
}

async fn metrics_sampler(
    metrics_addr: SocketAddr,
    interval: Duration,
    cancel: CancellationToken,
) -> MetricsSeries {
    let t0 = Instant::now();
    let mut out = MetricsSeries {
        samples: Vec::new(),
        misses: 0,
    };
    loop {
        if let Ok(text) = scrape::scrape(metrics_addr, "/metrics").await {
            // Prometheus semantics: a counter that has never incremented does not appear in
            // the text — a successful scrape treats it as 0 (the steady state of
            // supervisor_restarts being always zero must not be misjudged as unreadable).
            let or_zero = |key: &str| scrape::counter_value(&text, key).unwrap_or(0);
            out.samples.push(MetricSample {
                elapsed_secs: t0.elapsed().as_secs_f64(),
                pings_sent: or_zero("interflow_hub_heartbeat_pings_sent"),
                supervisor_restarts: or_zero("interflow_hub_heartbeat_supervisor_restarts"),
                pong_total: or_zero("interflow_hub_pong_received"),
            });
        } else {
            out.misses += 1;
        }
        tokio::select! {
            _ = tokio::time::sleep(interval) => {}
            _ = cancel.cancelled() => return out,
        }
    }
}

/// Process liveness supervision: any process under test exiting cancels the whole run
/// (fail-fast) and records the exit event.
async fn liveness_monitor(
    procs: Vec<Arc<Mutex<MeshProcess>>>,
    cancel: CancellationToken,
    events: Arc<Mutex<Vec<(&'static str, Option<i32>)>>>,
) {
    let mut tick = tokio::time::interval(Duration::from_secs(1));
    loop {
        tokio::select! {
            _ = cancel.cancelled() => return,
            _ = tick.tick() => {}
        }
        for p in &procs {
            let mut g = p.lock().await;
            if let Some(code) = g.try_exit_code() {
                events.lock().await.push((g.name, code));
                cancel.cancel();
                return;
            }
        }
    }
}

async fn log_tails(procs: &[Arc<Mutex<MeshProcess>>]) -> String {
    let mut out = String::new();
    for p in procs {
        let tail = {
            let g = p.lock().await;
            format!("--- {} log tail ---\n{}\n", g.name, g.log_tail(4096))
        };
        out.push_str(&tail);
    }
    out
}

/// Graceful shutdown: agents first, hub last (same teardown order as loss_hol).
/// Returns per-process (name, result).
async fn teardown_procs(
    procs: &[Arc<Mutex<MeshProcess>>],
) -> Vec<(&'static str, Result<Option<i32>, String>)> {
    let mut results = Vec::new();
    for idx in [1usize, 2, 0] {
        if let Some(p) = procs.get(idx) {
            let mut g = p.lock().await;
            results.push((g.name, g.terminate_graceful(Duration::from_secs(30)).await));
        }
    }
    results
}

// ---------------------------------------------------------------------------
// Analysis
// ---------------------------------------------------------------------------

/// Per-stream gap analysis: max gap + count of unexpected stalls (significant
/// gaps that neither overlap a silent window nor have a nearby impairment
/// event — HOL stalls caused by injected impairment are the expected effect
/// and do not count as unexpected).
fn analyze_stream(
    out: &ConsumerOutcome,
    timeline: &PhaseTimeline,
    impair_events: &[crate::impair::ImpairEvent],
) -> StreamStat {
    let stats = latency_stats(out.latencies.clone());
    let mut gaps: Vec<(Instant, Instant, u64)> = Vec::new(); // (prev, next, gap_ns)
    for w in out.recv.windows(2) {
        gaps.push((w[0], w[1], w[1].duration_since(w[0]).as_nanos() as u64));
    }
    let mut gap_durs: Vec<u64> = gaps.iter().map(|(_, _, g)| *g).collect();
    gap_durs.sort_unstable();
    let gap_p50 = gap_durs.get(gap_durs.len() / 2).copied().unwrap_or(0);
    let stall_threshold = (gap_p50 * 3).max(60_000_000); // same criterion as loss_hol
    let slack = Duration::from_secs(3);
    let unexpected = gaps
        .iter()
        .filter(|&&(prev, next, g)| {
            if g < stall_threshold {
                return false;
            }
            if timeline.overlaps_silence(prev, next, slack) {
                return false; // expected pause from the periodic silent window
            }
            // An impairment event inside the gap window (counting from 500ms before) = expected HOL
            // from injected loss/withholding. Harness-fault overflow drops are deliberately
            // excluded: a delay line that tail-dropped must not masquerade as injected loss
            // and silently flatter the product (it fails `harness_delay_line_no_overflow`).
            let explained_by_impair = impair_events.iter().any(|e| {
                if matches!(e.kind, ImpairKind::QueueOverflowDropped { .. }) {
                    return false;
                }
                let lo = prev.checked_sub(Duration::from_millis(500));
                e.at <= next && lo.is_none_or(|l| e.at >= l)
            });
            !explained_by_impair
        })
        .count();
    let max_gap = gap_durs.last().copied().unwrap_or(0);
    StreamStat {
        stream: out.stream,
        chunks: out.chunks,
        stats,
        max_gap_ms: max_gap as f64 / 1e6,
        unexpected_stalls: unexpected,
    }
}

/// RSS drift: returns None when there are too few post-warmup samples (skip the
/// assertion); otherwise (first-1/4 mean, last-1/4 mean, last−first).
fn rss_drift(series: &RssSeries, warmup_secs: f64) -> Option<(u64, u64, i64)> {
    let post: Vec<u64> = series
        .samples
        .iter()
        .filter(|&&(t, _)| t >= warmup_secs)
        .map(|&(_, b)| b)
        .collect();
    if post.len() < 4 {
        return None;
    }
    let q = post.len() / 4;
    let mean = |s: &[u64]| -> u64 { s.iter().sum::<u64>() / s.len() as u64 };
    let first = mean(&post[..q]);
    let last = mean(&post[post.len() - q..]);
    Some((first, last, last as i64 - first as i64))
}

fn downsample(samples: &[(f64, u64)], cap: usize) -> Vec<(f64, u64)> {
    if samples.len() <= cap {
        return samples.to_vec();
    }
    let step = samples.len().div_ceil(cap);
    samples.iter().step_by(step).copied().collect()
}

/// Absolute floor for RSS drift (bytes): the floor below single-sample noise and allocator jitter.
fn rss_floor_bytes(name: &str) -> u64 {
    if name == "hub" {
        64 * 1024 * 1024
    } else {
        32 * 1024 * 1024
    }
}

// ---------------------------------------------------------------------------
// Scenario execution
// ---------------------------------------------------------------------------

async fn run_scenario(
    args: &SoakArgs,
    transport: TransportKind,
    run_dir: &Path,
    mesh_bin: &Path,
) -> TransportResult {
    let name = transport_name(transport);
    let t0 = Instant::now();
    let scenario_dir = run_dir.join(name);
    let logs_dir = scenario_dir.join("logs");
    if let Err(e) = std::fs::create_dir_all(&logs_dir) {
        return failed_result(
            name,
            args,
            format!("failed to create scenario directory: {e}"),
        );
    }

    // ---- Ports and infrastructure (load/observation side, stays in this process) ----
    let hub_port = pick_ephemeral_port();
    let hub_addr: SocketAddr = format!("127.0.0.1:{hub_port}").parse().expect("hub addr");
    let metrics_port = pick_ephemeral_port();
    let metrics_addr: SocketAddr = format!("127.0.0.1:{metrics_port}")
        .parse()
        .expect("metrics");
    let ingress_port = pick_ephemeral_port();
    let ingress_addr: SocketAddr = format!("127.0.0.1:{ingress_port}")
        .parse()
        .expect("ingress");

    let interval = Duration::from_millis(args.chunk_interval_ms);
    let (backend_addr, backend, backend_task) = sse_backend(args.chunk_bytes, interval).await;
    backend.set_burst_chunks(args.burst_chunks);
    let certs = crate::certs::TestCerts::generate("soak", "soak-egress");

    let impair_cfg = ImpairConfig {
        one_way_delay: Duration::from_millis(args.rtt_ms / 2),
        drop: if args.loss_pct == 0 {
            DropPattern::None
        } else {
            DropPattern::Rate(f64::from(args.loss_pct) / 100.0)
        },
        withhold: Duration::from_millis(args.withhold_ms),
        queue_capacity: args.impair_queue_capacity,
        seed: args.seed + transport_id(transport),
    };
    let tcp_proxy = if transport == TransportKind::H2 {
        match TcpImpairProxy::spawn(hub_addr, impair_cfg.clone()).await {
            Ok(p) => Some(p),
            Err(e) => {
                return failed_result(name, args, format!("failed to start TCP impair proxy: {e}"));
            }
        }
    } else {
        None
    };
    let udp_proxy = if transport == TransportKind::Quic {
        match UdpImpairProxy::spawn(hub_addr, impair_cfg).await {
            Ok(p) => Some(p),
            Err(e) => {
                return failed_result(name, args, format!("failed to start UDP impair proxy: {e}"));
            }
        }
    } else {
        None
    };
    // The egress agent connects to the proxy (impairment sits on the egress↔hub link); ingress connects directly
    let hub_endpoint_via_proxy = match (&tcp_proxy, &udp_proxy) {
        (Some(p), _) => p.local_addr(),
        (_, Some(p)) => p.local_addr(),
        _ => hub_addr,
    };

    // ---- Processes under test: real config files + spawn + readiness ----
    let hub_cfg = hub_config(hub_addr, metrics_addr, &certs);
    let egress_cfg = egress_agent_config(hub_endpoint_via_proxy, transport, &certs, backend_addr);
    let ingress_cfg = ingress_agent_config(
        hub_addr,
        transport,
        &certs,
        ingress_addr,
        backend_addr,
        args.idle_timeout_secs,
    );
    if let Err(e) = write_toml(&scenario_dir.join("hub.toml"), &hub_cfg)
        .and_then(|()| write_toml(&scenario_dir.join("egress.toml"), &egress_cfg))
        .and_then(|()| write_toml(&scenario_dir.join("ingress.toml"), &ingress_cfg))
    {
        return failed_result(name, args, e);
    }

    let mut procs: Vec<Arc<Mutex<MeshProcess>>> = Vec::new();
    let spawn_one = |subcmd: &'static str,
                     cfg_file: &'static str,
                     log_file: &'static str,
                     pname: &'static str| {
        spawn_mesh(
            mesh_bin,
            subcmd,
            &scenario_dir.join(cfg_file),
            &logs_dir.join(log_file),
            pname,
        )
    };
    let startup: Result<(), String> = async {
        let hub = spawn_one("hub", "hub.toml", "hub.log", "hub")?;
        procs.push(Arc::new(Mutex::new(hub)));
        wait_for_tcp(hub_addr, Duration::from_secs(30))
            .await
            .map_err(|e| format!("hub listener not ready: {e}"))?;
        wait_for_tcp(metrics_addr, Duration::from_secs(20))
            .await
            .map_err(|e| format!("hub metrics not ready: {e}"))?;
        let egress = spawn_one("agent", "egress.toml", "egress.log", "egress")?;
        procs.push(Arc::new(Mutex::new(egress)));
        let ingress = spawn_one("agent", "ingress.toml", "ingress.log", "ingress")?;
        procs.push(Arc::new(Mutex::new(ingress)));
        wait_for_tcp(ingress_addr, Duration::from_secs(60))
            .await
            .map_err(|e| format!("ingress local listener not ready: {e}"))?;
        Ok(())
    }
    .await;

    if let Err(e) = startup {
        let tails = log_tails(&procs).await;
        teardown_procs(&procs).await;
        backend_task.abort();
        if let Some(p) = tcp_proxy {
            p.shutdown().await;
        }
        if let Some(p) = udp_proxy {
            p.shutdown().await;
        }
        return failed_result(name, args, format!("{e}\n{tails}"));
    }

    // Data-path readiness probe (egress registered + full tunnel path). With retries:
    // the egress TLS handshake through the impairment proxy is occasionally slower
    // than the ingress's first Open (an unregistered target fails fast by design), so
    // a one-shot probe would misjudge a normal startup race as a scenario failure.
    let probe = 'probe: {
        for attempt in 0..10 {
            let r = tokio::time::timeout(
                Duration::from_secs(30),
                probe_first_chunk(ingress_addr, args.chunk_bytes),
            )
            .await
            .map_err(|_| "probe timed out after 30s".to_string())
            .and_then(|r| r);
            match r {
                Ok(()) => break 'probe Ok(()),
                Err(e) if attempt < 9 => {
                    eprintln!(
                        "probe attempt {} failed ({}), retrying in 1s",
                        attempt + 1,
                        e
                    );
                    tokio::time::sleep(Duration::from_secs(1)).await;
                }
                Err(e) => break 'probe Err(e),
            }
        }
        unreachable!()
    };
    if let Err(e) = probe {
        let tails = log_tails(&procs).await;
        teardown_procs(&procs).await;
        backend_task.abort();
        if let Some(p) = tcp_proxy {
            p.shutdown().await;
        }
        if let Some(p) = udp_proxy {
            p.shutdown().await;
        }
        return failed_result(name, args, format!("data path not ready: {e}\n{tails}"));
    }

    // ---- Churn + eviction-wave topology (4th process: a separate ingress agent, id=churn) ----
    // Separated from the main ingress: the eviction waves (SIGKILL + restart) never touch the
    // persistent consumer streams; also not added to `procs` (liveness supervision would
    // misjudge the "planned death" as a process exit).
    let churn_port = pick_ephemeral_port();
    let churn_addr: SocketAddr = format!("127.0.0.1:{churn_port}")
        .parse()
        .expect("churn addr");
    let churn_cfg = churn_agent_config(hub_addr, transport, &certs, churn_addr, backend_addr);
    let churn_config_path = scenario_dir.join("churn.toml");
    if let Err(e) = write_toml(&churn_config_path, &churn_cfg) {
        teardown_procs(&procs).await;
        backend_task.abort();
        if let Some(p) = tcp_proxy {
            p.shutdown().await;
        }
        if let Some(p) = udp_proxy {
            p.shutdown().await;
        }
        return failed_result(name, args, e);
    }
    let churn_proc: Arc<Mutex<MeshProcess>> = match spawn_mesh(
        mesh_bin,
        "agent",
        &churn_config_path,
        &logs_dir.join("churn.log"),
        "churn",
    ) {
        Ok(c) => Arc::new(Mutex::new(c)),
        Err(e) => {
            let tails = log_tails(&procs).await;
            teardown_procs(&procs).await;
            backend_task.abort();
            if let Some(p) = tcp_proxy {
                p.shutdown().await;
            }
            if let Some(p) = udp_proxy {
                p.shutdown().await;
            }
            return failed_result(
                name,
                args,
                format!(
                    "churn agent failed to start: {e}
{tails}"
                ),
            );
        }
    };
    if let Err(e) = wait_for_tcp(churn_addr, Duration::from_secs(60)).await {
        let tails = log_tails(&procs).await;
        teardown_procs(&procs).await;
        {
            let mut g = churn_proc.lock().await;
            let _ = g.terminate_graceful(Duration::from_secs(5)).await;
        }
        backend_task.abort();
        if let Some(p) = tcp_proxy {
            p.shutdown().await;
        }
        if let Some(p) = udp_proxy {
            p.shutdown().await;
        }
        return failed_result(
            name,
            args,
            format!(
                "churn listener not ready: {e}
{tails}"
            ),
        );
    }

    // ---- Main run: phase scheduling + N consumer streams + sampling + liveness supervision ----
    let cancel = CancellationToken::new();
    let exit_events: Arc<Mutex<Vec<(&'static str, Option<i32>)>>> =
        Arc::new(Mutex::new(Vec::new()));
    let liveness = tokio::spawn(liveness_monitor(
        procs.clone(),
        cancel.clone(),
        Arc::clone(&exit_events),
    ));

    let scheduler = tokio::spawn(run_phases(
        backend.clone(),
        Duration::from_secs(args.cycle_secs),
        Duration::from_secs(args.silence_secs),
        Duration::from_secs(args.duration_secs),
        cancel.clone(),
    ));

    let mut rss_targets: Vec<(&'static str, u32)> = Vec::new();
    for p in &procs {
        let (pname, pid) = {
            let g = p.lock().await;
            (g.name, g.pid())
        };
        if let Some(pid) = pid {
            rss_targets.push((pname, pid));
        }
    }
    rss_targets.push(("runner", std::process::id()));
    let mem_interval = Duration::from_secs(args.mem_sample_secs.max(1));
    let rss_task = tokio::spawn(rss_sampler(rss_targets, mem_interval, cancel.clone()));
    let metrics_task = tokio::spawn(metrics_sampler(metrics_addr, mem_interval, cancel.clone()));

    // Egress fd sampling (data source for the orphaned-stream sentinel; fixed 10s interval,
    // denser than RSS — the leak signal is "accumulated across waves", so the sampling
    // granularity must be smaller than the wave interval)
    let mut egress_pid: Option<u32> = None;
    for p in &procs {
        let (pname, pid) = {
            let g = p.lock().await;
            (g.name, g.pid())
        };
        if pname == "egress" {
            egress_pid = pid;
        }
    }
    let fd_task = tokio::spawn(fd_sampler(
        egress_pid.expect("egress process handle must be present in procs"),
        Duration::from_secs(10),
        cancel.clone(),
    ));

    // Churn short-lived stream clients + eviction waves (SIGKILL → restart → source-side re-registration sweep)
    let churn_successes = Arc::new(std::sync::atomic::AtomicU64::new(0));
    let churn_waves = Arc::new(std::sync::atomic::AtomicU64::new(0));
    // 8 concurrent clients (each serially "hold 3s → 200ms interval"): ~7 streams in
    // service at any moment — the eviction wave's sweep has streams to orphan, and the
    // leak signal is amplified by the client count too
    let churn_client_tasks: Vec<_> = (0..8)
        .map(|_| {
            tokio::spawn(churn_client(
                churn_addr,
                args.chunk_bytes,
                Duration::from_millis(args.churn_interval_ms.max(50)),
                cancel.clone(),
                Arc::clone(&churn_successes),
            ))
        })
        .collect();
    let churn_log_path = logs_dir.join("churn.log");
    let churn_wave_task = tokio::spawn(churn_eviction_waves(
        Arc::clone(&churn_proc),
        mesh_bin.to_path_buf(),
        churn_config_path.clone(),
        churn_log_path.clone(),
        churn_addr,
        Duration::from_secs(args.churn_restart_every_secs.max(10)),
        cancel.clone(),
        Arc::clone(&churn_waves),
    ));

    let mut set = JoinSet::new();
    let stall_bound = Duration::from_secs(args.stall_bound_secs);
    let run_duration = Duration::from_secs(args.duration_secs);
    for i in 0..args.streams {
        set.spawn(consumer(
            i,
            ingress_addr,
            args.chunk_bytes,
            run_duration,
            stall_bound,
        ));
    }

    let mut outcomes: Vec<ConsumerOutcome> = Vec::new();
    let mut consumer_err: Option<ConsumerError> = None;
    let mut join_err: Option<String> = None;
    loop {
        tokio::select! {
            _ = cancel.cancelled() => break,
            joined = set.join_next() => match joined {
                Some(Ok(Ok(o))) => outcomes.push(o),
                Some(Ok(Err(e))) => {
                    if consumer_err.is_none() {
                        consumer_err = Some(e);
                    }
                    cancel.cancel(); // fail-fast: abort the remaining streams too
                }
                Some(Err(e)) => {
                    join_err = Some(format!("consumer task exited abnormally: {e}"));
                    cancel.cancel();
                }
                None => break,
            },
        }
    }
    set.abort_all();
    while set.join_next().await.is_some() {}

    // Cancel first, then collect: the sampling/scheduling tasks terminate on cancel; in the
    // reverse order you would wait until the timeout and get empty results (a pitfall hit
    // during the first production runs).
    cancel.cancel();
    let timeline = match tokio::time::timeout(Duration::from_secs(10), scheduler).await {
        Ok(Ok(t)) => t,
        _ => PhaseTimeline::default(),
    };
    let rss_series = match tokio::time::timeout(Duration::from_secs(10), rss_task).await {
        Ok(Ok(s)) => s,
        _ => Vec::new(),
    };
    let metrics_series = match tokio::time::timeout(Duration::from_secs(10), metrics_task).await {
        Ok(Ok(s)) => s,
        _ => MetricsSeries {
            samples: Vec::new(),
            misses: 0,
        },
    };
    // Impairment events (fetched before shutdown; used for stall attribution)
    let impair_events: Vec<crate::impair::ImpairEvent> = match (&tcp_proxy, &udp_proxy) {
        (Some(p), _) => p.events(),
        (_, Some(p)) => p.events(),
        _ => Vec::new(),
    };
    // Delay-line health (fetched before shutdown; the harness red-flag source)
    let harness = udp_proxy.as_ref().map_or(HarnessSummary::default(), |p| {
        let (data, ret, capacity) = p.delay_stats();
        HarnessSummary {
            udp_data_high_water: data.high_water,
            udp_data_overflow: data.overflow_dropped,
            udp_return_high_water: ret.high_water,
            udp_return_overflow: ret.overflow_dropped,
            udp_queue_capacity: capacity,
        }
    });
    let _ = liveness.await;

    // Final metrics snapshot before shutdown (the most authoritative closing counts)
    let final_scrape = scrape::scrape(metrics_addr, "/metrics").await.ok();

    // Reap the churn tasks (after cancel, the client/wave tasks exit on their own)
    for t in churn_client_tasks {
        let _ = t.await;
    }
    let _ = churn_wave_task.await;
    let churn_successes_final = churn_successes.load(std::sync::atomic::Ordering::Relaxed);
    let churn_waves_final = churn_waves.load(std::sync::atomic::Ordering::Relaxed);
    let fd_series = match tokio::time::timeout(Duration::from_secs(10), fd_task).await {
        Ok(Ok(series)) => series,
        _ => FdSeries::default(),
    };

    // ---- Graceful shutdown (agents first, hub last) + impairment proxy/backend close-out ----
    // The churn agent shuts down before the main topology (also an agent, before the hub)
    {
        let mut g = churn_proc.lock().await;
        let _ = g.terminate_graceful(Duration::from_secs(10)).await;
    }
    let teardown_results = teardown_procs(&procs).await;
    backend_task.abort();
    if let Some(p) = tcp_proxy {
        p.shutdown().await;
    }
    if let Some(p) = udp_proxy {
        p.shutdown().await;
    }

    // ---- Analysis and assertions ----
    let mut assertions: Vec<AssertionOut> = Vec::new();
    let mut pass = true;
    fn push_assert(
        assertions: &mut Vec<AssertionOut>,
        pass: &mut bool,
        name: &str,
        ok: bool,
        detail: String,
    ) {
        if !ok {
            *pass = false;
        }
        assertions.push(AssertionOut {
            name: name.to_string(),
            pass: ok,
            detail,
        });
    }

    // 1. Zero corruption (covers data-plane breaks too: a torn-down connection is also something the
    //    gate must catch; stall-type errors belong to assertion 2)
    let corruption_detail = match &consumer_err {
        Some(e) => e.detail().to_string(),
        None => join_err.clone().unwrap_or_default(),
    };
    let intact = !matches!(
        consumer_err,
        Some(ConsumerError::Corruption(_)) | Some(ConsumerError::Transport(_))
    ) && join_err.is_none();
    push_assert(
        &mut assertions,
        &mut pass,
        "zero_corruption",
        intact,
        if intact {
            format!("{} streams closed out with zero corruption", outcomes.len())
        } else {
            format!("verification failed: {corruption_detail}")
        },
    );

    // 2. Stall bound
    let stream_stats: Vec<StreamStat> = outcomes
        .iter()
        .map(|o| analyze_stream(o, &timeline, &impair_events))
        .collect();
    let max_gap_ms = stream_stats
        .iter()
        .map(|s| s.max_gap_ms)
        .fold(0.0_f64, f64::max);
    let stalled_err = matches!(consumer_err, Some(ConsumerError::Stalled(_)));
    let bound_ms = (args.stall_bound_secs * 1000) as f64;
    push_assert(
        &mut assertions,
        &mut pass,
        "stall_bound",
        !stalled_err && max_gap_ms <= bound_ms,
        format!(
            "worst-stream max gap {} vs bound {}s{}",
            fmt_ms((max_gap_ms * 1e6) as u64),
            args.stall_bound_secs,
            if stalled_err {
                " (fail-fast triggered)"
            } else {
                ""
            }
        ),
    );

    // 3. Memory drift (per-component attribution; the runner itself is recorded but not asserted)
    let warmup_secs = (f64::from(u32::try_from(args.cycle_secs).expect("cycle_secs")) * 2.0)
        .min(args.duration_secs as f64 / 2.0);
    let mut rss_summaries = Vec::new();
    for series in &rss_series {
        let drift = rss_drift(series, warmup_secs);
        let (asserting, ok, detail) = match (&drift, series.name.as_str()) {
            (_, "runner") => (
                false,
                true,
                "runner itself is recorded but not asserted".to_string(),
            ),
            (None, _) => (
                false,
                true,
                format!(
                    "insufficient samples after warmup ({} samples, {} misses), skipping assertion",
                    series.samples.len(),
                    series.misses
                ),
            ),
            (Some((first, last, drift_bytes)), pname) => {
                let threshold =
                    (first * u64::from(args.rss_drift_max_pct) / 100).max(rss_floor_bytes(pname));
                (
                    true,
                    *drift_bytes <= threshold as i64,
                    format!(
                        "{first} → {last} bytes, drift {drift_bytes} vs threshold {threshold} (max of {}% × baseline and {} MiB floor)",
                        args.rss_drift_max_pct,
                        rss_floor_bytes(pname) / 1024 / 1024
                    ),
                )
            }
        };
        let (first_q, last_q, drift_bytes) = drift
            .map(|(f, l, d)| (Some(f), Some(l), Some(d)))
            .unwrap_or((None, None, None));
        if asserting {
            assertions.push(AssertionOut {
                name: format!("rss_drift_{}", series.name),
                pass: ok,
                detail,
            });
            if !ok {
                pass = false;
            }
        } else {
            assertions.push(AssertionOut {
                name: format!("rss_drift_{}", series.name),
                pass: true,
                detail,
            });
        }
        rss_summaries.push(RssSummary {
            name: series.name.clone(),
            samples: series.samples.len(),
            misses: series.misses,
            first_quarter_bytes: first_q,
            last_quarter_bytes: last_q,
            drift_bytes,
            threshold_bytes: rss_floor_bytes(&series.name),
            pass: ok,
            timeline: downsample(&series.samples, 240),
        });
    }

    // 4. Heartbeat canary (production /metrics path)
    let last_sample = metrics_series.samples.last().copied();
    // Prefer the final snapshot; a counter missing from a successful scrape is treated as 0
    // per Prometheus semantics (a never-incremented counter does not appear in the text).
    // Only when both sources are unavailable is it judged "unreadable".
    let counter_of = |key: &str| -> Option<u64> {
        if let Some(text) = final_scrape.as_ref() {
            return Some(scrape::counter_value(text, key).unwrap_or(0));
        }
        last_sample.map(|s| match key {
            "interflow_hub_heartbeat_pings_sent" => s.pings_sent,
            "interflow_hub_heartbeat_supervisor_restarts" => s.supervisor_restarts,
            _ => s.pong_total,
        })
    };
    let restarts_final =
        counter_of("interflow_hub_heartbeat_supervisor_restarts").unwrap_or(u64::MAX);
    let pings_last = counter_of("interflow_hub_heartbeat_pings_sent").unwrap_or(0);
    let pings_first = metrics_series
        .samples
        .first()
        .map(|s| s.pings_sent)
        .unwrap_or(0);
    let pong_final = counter_of("interflow_hub_pong_received").unwrap_or(0);
    push_assert(
        &mut assertions,
        &mut pass,
        "heartbeat_supervisor_restarts",
        restarts_final == 0,
        if restarts_final == 0 {
            "global heartbeat supervisor loop with zero restarts".to_string()
        } else if restarts_final == u64::MAX {
            "metrics unreadable (treated as failure)".to_string()
        } else {
            format!(
                "supervisor loop restarted {restarts_final} times (sentinel for an unnoticed liveness-supervisor death)"
            )
        },
    );
    if transport == TransportKind::H2 {
        push_assert(
            &mut assertions,
            &mut pass,
            "heartbeat_pings_growing",
            pings_last >= 1 && pings_last >= pings_first,
            format!("pings {pings_first} → {pings_last}"),
        );
    } else {
        assertions.push(AssertionOut {
            name: "heartbeat_pings_growing".to_string(),
            pass: true,
            detail: "QUIC sessions are covered by the quinn idle timeout; the supervisor loop skips them (by design)".to_string(),
        });
    }

    // 5. Process liveness
    let exits = exit_events.lock().await.clone();
    let alive_detail = if exits.is_empty() {
        "hub / egress / ingress stayed alive throughout".to_string()
    } else {
        exits
            .iter()
            .map(|(n, c)| format!("{n} exited (code={c:?})"))
            .collect::<Vec<_>>()
            .join(", ")
    };
    push_assert(
        &mut assertions,
        &mut pass,
        "processes_alive",
        exits.is_empty(),
        alive_detail,
    );

    // 6. Graceful shutdown (SIGTERM → bounded clean exit; exit code matches signal semantics)
    let mut shutdown_ok = true;
    let mut shutdown_detail = Vec::new();
    for (pname, result) in &teardown_results {
        match result {
            Ok(code) => {
                #[cfg(unix)]
                {
                    let expected = if *pname == "hub" { Some(0) } else { Some(143) };
                    let ok = *code == expected;
                    if !ok {
                        shutdown_ok = false;
                    }
                    shutdown_detail.push(format!("{pname}: code={code:?} (expected {expected:?})"));
                }
                #[cfg(not(unix))]
                {
                    shutdown_detail.push(format!("{pname}: code={code:?}"));
                }
            }
            Err(e) => {
                shutdown_ok = false;
                shutdown_detail.push(format!("{pname}: {e}"));
            }
        }
    }
    push_assert(
        &mut assertions,
        &mut pass,
        "graceful_shutdown",
        shutdown_ok,
        shutdown_detail.join("; "),
    );

    // 7. No egress fd growth (orphaned-stream sentinel under churn + eviction waves):
    //    first-half median → final value. Noise is ± a few; orphan leaks accumulate per wave
    //    (each wave orphans the churn streams in service at that moment, starting at tens).
    let fd_growth = {
        if fd_series.samples.len() >= 4 {
            let mut first_half: Vec<u64> = fd_series.samples[..fd_series.samples.len() / 2]
                .iter()
                .map(|(_, v)| *v)
                .collect();
            first_half.sort_unstable();
            let baseline = first_half[first_half.len() / 2];
            let last = fd_series.samples.last().map_or(baseline, |(_, v)| *v);
            Some((baseline, last, last.saturating_sub(baseline)))
        } else {
            None
        }
    };
    let sweep_notified_final = final_scrape
        .as_ref()
        .and_then(|t| scrape::counter_value(t, "interflow_hub_sweep_peer_notified_total"));
    match fd_growth {
        Some((baseline, last, growth)) => {
            push_assert(
                &mut assertions,
                &mut pass,
                "egress_fd_no_growth",
                growth <= args.fd_growth_bound,
                format!(
                    "fd {baseline} → {last} (growth {growth} vs bound {}; churn {} short-lived streams × {} waves)",
                    args.fd_growth_bound, churn_successes_final, churn_waves_final
                ),
            );
        }
        None => push_assert(
            &mut assertions,
            &mut pass,
            "egress_fd_no_growth",
            true,
            format!(
                "insufficient fd samples ({} samples / {} misses, unsupported platform or scenario too short), skipping assertion",
                fd_series.samples.len(),
                fd_series.misses
            ),
        ),
    }

    // 8. Sweep-notification canary (production /metrics path): eviction waves must produce peer notifications.
    //    Poll-plane (h2) peers only: a relay-plane (QUIC) peer is torn down by
    //    the table-entry drop itself and never touches this counter, so the
    //    canary is meaningful on the h2 scenario alone.
    if churn_waves_final >= 1 && churn_successes_final >= 10 {
        if transport == TransportKind::H2 {
            let notified = sweep_notified_final.unwrap_or(0);
            push_assert(
                &mut assertions,
                &mut pass,
                "sweep_peer_notified",
                notified >= 1,
                format!(
                    "eviction waves {} × churn {} streams → sweep peer notifications {} (regression sentinel for sweep clearing state without notifying peers)",
                    churn_waves_final, churn_successes_final, notified
                ),
            );
        } else {
            push_assert(
                &mut assertions,
                &mut pass,
                "sweep_peer_notified",
                true,
                "relay-plane (QUIC) sweep teardown is carried by the table-entry drop, not the control-channel notification this counter tracks — poll-plane-only canary, skipped".to_string(),
            );
        }
    } else {
        push_assert(
            &mut assertions,
            &mut pass,
            "sweep_peer_notified",
            true,
            format!(
                "eviction waves {} / churn {} streams (insufficient, skipping assertion)",
                churn_waves_final, churn_successes_final
            ),
        );
    }

    // 9. Harness self-health: the UDP impairment proxy's delay lines must not
    //    overflow — an overflow tail-drop is a harness fault that, if mistaken
    //    for injected loss, would silently flatter the product under test, so
    //    it fails the scenario outright. The h2 TCP proxy has no delay line
    //    (serial virtual-clock model): vacuously green, noted as such.
    let harness_ok = harness.udp_data_overflow == 0 && harness.udp_return_overflow == 0;
    push_assert(
        &mut assertions,
        &mut pass,
        "harness_delay_line_no_overflow",
        harness_ok,
        if transport == TransportKind::Quic {
            format!(
                "udp delay lines capacity {}: high-water {}/{} datagrams (data/return), overflow drops {}/{}",
                harness.udp_queue_capacity,
                harness.udp_data_high_water,
                harness.udp_return_high_water,
                harness.udp_data_overflow,
                harness.udp_return_overflow,
            )
        } else {
            "tcp impairment proxy uses the serial virtual-clock model (no delay line)".to_string()
        },
    );

    let chunks_verified: usize = stream_stats.iter().map(|s| s.chunks).sum();
    TransportResult {
        transport: name.to_string(),
        pass,
        error: None,
        duration_secs: args.duration_secs,
        streams: args.streams,
        chunks_verified,
        silence_cycles: timeline.silence_count(),
        stall_bound_secs: args.stall_bound_secs,
        phases: timeline.to_secs(t0),
        streams_detail: stream_stats,
        max_gap_ms,
        rss: rss_summaries,
        harness,
        heartbeat: HeartbeatSummary {
            samples: metrics_series.samples.len(),
            misses: metrics_series.misses,
            pings_first,
            pings_last,
            supervisor_restarts: restarts_final,
            pong_total: pong_final,
        },
        churn: ChurnSummary {
            successes: churn_successes_final,
            waves: churn_waves_final,
            fd_timeline: downsample(&fd_series.samples, 240),
            fd_misses: fd_series.misses,
            sweep_peer_notified: sweep_notified_final,
        },
        assertions,
    }
}

// ---------------------------------------------------------------------------
// Top-level entry
// ---------------------------------------------------------------------------

/// Soak outcome summary (the bin only needs the overall verdict and the artifact location).
pub struct SoakOutcome {
    pub pass: bool,
    pub artifact_path: Option<PathBuf>,
}

/// Top-level run: per-transport scenarios → artifact → report. Returns the overall pass (the bin decides the exit code).
pub async fn run(mut args: SoakArgs) -> SoakOutcome {
    if args.quick {
        args.apply_quick();
    }
    if let Err(e) = validate(&args) {
        eprintln!("argument validation failed: {e}");
        return SoakOutcome {
            pass: false,
            artifact_path: None,
        };
    }
    let mesh_bin = match resolve_mesh_bin(args.mesh_bin.as_deref()) {
        Ok(b) => b,
        Err(e) => {
            eprintln!("{e}");
            return SoakOutcome {
                pass: false,
                artifact_path: None,
            };
        }
    };
    let transports: Vec<TransportKind> = args
        .transports
        .iter()
        .map(|t| match t.to_ascii_lowercase().as_str() {
            "h2" => TransportKind::H2,
            "quic" => TransportKind::Quic,
            other => {
                eprintln!("unknown transport {other} (options: h2, quic)");
                std::process::exit(2);
            }
        })
        .collect();

    let (run_dir, out_path) = resolve_out(args.out.as_deref());
    let _ = std::fs::create_dir_all(&run_dir);

    println!(
        "## soak long-running gate (real process topology): {} × {} streams × {}s/transport, cycle {}s/silence {}s, loss {}%/RTT {}ms",
        transports
            .iter()
            .map(|&t| transport_name(t))
            .collect::<Vec<_>>()
            .join("+"),
        args.streams,
        args.duration_secs,
        args.cycle_secs,
        args.silence_secs,
        args.loss_pct,
        args.rtt_ms,
    );

    let mut results = Vec::new();
    for &t in &transports {
        println!(
            "=== scenario {} starting (config and logs: {})",
            transport_name(t),
            scenario_dir_display(&run_dir, t)
        );
        let r = run_scenario(&args, t, &run_dir, &mesh_bin).await;
        println!(
            "=== scenario {} finished: {} (verified {} chunks, max gap {})",
            r.transport,
            if r.pass { "PASS" } else { "FAIL" },
            r.chunks_verified,
            fmt_ms((r.max_gap_ms * 1e6) as u64),
        );
        results.push(r);
    }

    let pass = results.iter().all(|r| r.pass);
    print_report(&args, &results);

    let artifact_path = write_artifact(&out_path, &args, &results);
    SoakOutcome {
        pass,
        artifact_path,
    }
}

fn scenario_dir_display(run_dir: &Path, t: TransportKind) -> String {
    run_dir.join(transport_name(t)).display().to_string()
}

fn write_artifact(
    out_path: &Path,
    args: &SoakArgs,
    results: &[TransportResult],
) -> Option<PathBuf> {
    #[derive(Serialize)]
    struct Artifact<'a> {
        meta: serde_json::Value,
        results: &'a [TransportResult],
    }
    let artifact = Artifact {
        meta: serde_json::json!({
            "bench": "soak",
            "args": {
                "transports": args.transports,
                "streams": args.streams,
                "duration_secs": args.duration_secs,
                "chunk_bytes": args.chunk_bytes,
                "chunk_interval_ms": args.chunk_interval_ms,
                "loss_pct": args.loss_pct,
                "rtt_ms": args.rtt_ms,
                "withhold_ms": args.withhold_ms,
                "cycle_secs": args.cycle_secs,
                "silence_secs": args.silence_secs,
                "burst_chunks": args.burst_chunks,
                "idle_timeout_secs": args.idle_timeout_secs,
                "stall_bound_secs": args.stall_bound_secs,
                "mem_sample_secs": args.mem_sample_secs,
                "rss_drift_max_pct": args.rss_drift_max_pct,
                "seed": args.seed,
                "quick": args.quick,
            },
            "ts": chrono::Local::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true),
        }),
        results,
    };
    if let Some(parent) = out_path.parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    match serde_json::to_string_pretty(&artifact) {
        Ok(text) => match std::fs::write(out_path, text) {
            Ok(()) => {
                println!("JSON artifact written to {}", out_path.display());
                Some(out_path.to_path_buf())
            }
            Err(e) => {
                eprintln!("failed to write artifact {}: {e}", out_path.display());
                None
            }
        },
        Err(e) => {
            eprintln!("failed to serialize artifact: {e}");
            None
        }
    }
}

fn print_report(args: &SoakArgs, results: &[TransportResult]) {
    println!();
    println!(
        "| transport | result | verified chunks | worst-stream max gap | unexpected stalls | heartbeat pings | supervisor restarts | RSS drift (hub/egress/ingress) |"
    );
    println!("|---|---|---|---|---|---|---|---|");
    for r in results {
        if r.error.is_some() {
            println!(
                "| {} | ❌ scenario failed | - | - | - | - | - | - |",
                r.transport
            );
            continue;
        }
        let worst_stalls: usize = r
            .streams_detail
            .iter()
            .map(|s| s.unexpected_stalls)
            .max()
            .unwrap_or(0);
        let drift = |pname: &str| -> String {
            r.rss
                .iter()
                .find(|s| s.name == pname)
                .and_then(|s| s.drift_bytes)
                .map(|d| format!("{} KiB", d / 1024))
                .unwrap_or_else(|| "n/a".to_string())
        };
        println!(
            "| {} | {} | {} | {} (bound {}s) | {} | {} → {} | {} | {} / {} / {} |",
            r.transport,
            if r.pass { "✅" } else { "❌" },
            r.chunks_verified,
            fmt_ms((r.max_gap_ms * 1e6) as u64),
            args.stall_bound_secs,
            worst_stalls,
            r.heartbeat.pings_first,
            r.heartbeat.pings_last,
            r.heartbeat.supervisor_restarts,
            drift("hub"),
            drift("egress"),
            drift("ingress"),
        );
    }
    println!();
    for r in results {
        if let Some(err) = &r.error {
            println!("[{}] scenario failed:\n{err}", r.transport);
        }
        for a in &r.assertions {
            if !a.pass {
                println!(
                    "[{}] assertion failed {}: {}",
                    r.transport, a.name, a.detail
                );
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn args() -> SoakArgs {
        SoakArgs::parse_from(["soak"])
    }

    #[test]
    fn defaults_satisfy_constraints() {
        assert!(validate(&args()).is_ok());
    }

    #[test]
    fn silence_must_stay_under_idle_budget() {
        let mut a = args();
        a.silence_secs = a.idle_timeout_secs;
        assert!(validate(&a).is_err());
    }

    #[test]
    fn silence_plus_grace_must_stay_under_stall_bound() {
        let mut a = args();
        a.silence_secs = 120;
        a.stall_bound_secs = 140;
        assert!(validate(&a).is_err(), "120+30 >= 140 must be rejected");
        a.stall_bound_secs = 160;
        assert!(validate(&a).is_ok());
    }

    #[test]
    fn quick_profile_satisfies_constraints() {
        let mut a = args();
        a.apply_quick();
        assert!(validate(&a).is_ok());
    }

    #[test]
    fn rss_drift_math_quarters() {
        let series = RssSeries {
            name: "hub".into(),
            samples: (0..12u64)
                .map(|i| {
                    (
                        f64::from(i as u32) * 30.0,
                        100 * 1024 * 1024 + i * 1024 * 1024,
                    )
                })
                .collect(),
            misses: 0,
        };
        // warmup=60s → samples i=2..=11 (10 of them), q=2: first 1/4 = mean(i=2,3)=102.5MiB,
        // last 1/4 = mean(i=10,11)=110.5MiB, drift = 8MiB
        let (first, last, drift) = rss_drift(&series, 60.0).expect("enough samples");
        let mib: u64 = 1024 * 1024;
        assert_eq!(first, 102 * mib + mib / 2);
        assert_eq!(last, 110 * mib + mib / 2);
        assert_eq!(drift, (8 * mib) as i64);
    }

    #[test]
    fn rss_drift_skips_when_insufficient() {
        let series = RssSeries {
            name: "hub".into(),
            samples: vec![(0.0, 1), (31.0, 1), (62.0, 1)],
            misses: 9,
        };
        assert!(rss_drift(&series, 60.0).is_none());
    }

    #[test]
    fn downsample_caps_points() {
        let samples: Vec<(f64, u64)> = (0..1000u64).map(|i| (i as f64, i)).collect();
        // step = ceil(1000/240) = 5 → 1000/5 = 200 points
        assert_eq!(downsample(&samples, 240).len(), 200);
        assert!(
            downsample(&samples, 240)
                .iter()
                .all(|&(t, v)| (t as u64) == v)
        );
    }
}
