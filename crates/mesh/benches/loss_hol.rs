//! QUIC vs h2 concurrent-stream loss benchmark (backlog 1.5 / backing
//! artifact #2).
//!
//! Narrative claim: **on a lossy link, one stream's loss does not stall all
//! the others** — N SSE-style TCP tunnel streams run concurrently over the
//! hub↔egress-agent link; after injecting loss:
//! - h2: all tunnel frames multiplex onto one TCP connection
//!   (`core/tunnel/h2.rs`, a single `POST /stream/up`), so one lost segment →
//!   every stream on that connection stalls together (cross-stream HOL);
//! - QUIC: each tunnel stream is an independent bidirectional stream, so a
//!   loss only retransmits the victim stream's own data.
//!
//! Methodology (honest boundaries):
//! - The QUIC side has **real loss** (a user-space UDP proxy drops datagrams
//!   one by one) + real quinn retransmissions;
//! - The h2 side **simulates loss via byte withholding** — a lost segment plus
//!   retransmit recovery (user space cannot drop kernel TCP segments;
//!   withholding one chunk blocks all subsequent bytes in order — the observed
//!   effect matches a real lost segment). The withhold duration
//!   `--withhold-ms` is a recovery-model parameter (default 100ms ≈ 2×RTT,
//!   fast-retransmit scale); the comparison focuses on **whether HOL
//!   propagates across streams** (the collateral metric), not on absolute
//!   stall durations.
//! - Single-machine loopback + injected RTT; report quantiles and relative
//!   conclusions only, not absolute throughput.
//!
//! Run: `cargo bench -p interflow-mesh --bench loss_hol [-- args]`
//! Smoke: `cargo bench -p interflow-mesh --bench loss_hol -- --quick`

#![allow(
    clippy::all,
    clippy::pedantic,
    clippy::nursery,
    clippy::panic,
    clippy::unwrap_used,
    clippy::expect_used,
    missing_docs,
    dead_code,
    unused_mut
)]

use clap::Parser;
use interflow_mesh::config::{AgentTlsConfig, TransportKind};
use interflow_testkit::backend::{CHUNK_HEADER, chunk_instant, decode_chunk, sse_backend};
use interflow_testkit::config::{
    agent_config, agent_quic_config, hub_quic_config, tcp_egress_rule, tcp_ingress_rule,
    unlock_stream_limits,
};
use interflow_testkit::impair::{DropPattern, ImpairConfig, TcpImpairProxy, UdpImpairProxy};
use interflow_testkit::metrics::{LatencyStats, fmt_ms, latency_stats};
use interflow_testkit::stack::{pick_ephemeral_port, spawn_agent, spawn_hub, wait_for_tcp};
use serde::Serialize;
use std::net::SocketAddr;
use std::path::Path;
use std::time::{Duration, Instant};

fn certs() -> &'static interflow_testkit::certs::TestCerts {
    static C: std::sync::OnceLock<interflow_testkit::certs::TestCerts> = std::sync::OnceLock::new();
    C.get_or_init(|| interflow_testkit::certs::TestCerts::generate("e2e", "agent"))
}

/// CLI arguments (defaults match the backlog 1.5 baseline).
#[derive(Parser, Debug, Clone)]
#[command(
    name = "loss_hol",
    about = "QUIC vs h2 concurrent-stream loss comparison (SSE-style long-lived streams)"
)]
struct Args {
    /// Transports to compare (comma-separated: h2,quic)
    #[arg(long, value_delimiter = ',', default_value = "h2,quic")]
    transports: Vec<String>,

    /// Loss rate levels (%, comma-separated; 0 is the control group)
    #[arg(long, value_delimiter = ',', default_value = "0,1,2,5")]
    loss_rates: Vec<u8>,

    /// Injected RTT (milliseconds; the proxy splits it half per direction)
    #[arg(long, default_value_t = 50)]
    rtt_ms: u64,

    /// TCP withhold duration (milliseconds; the h2 lost-segment retransmit
    /// recovery model)
    #[arg(long, default_value_t = 100)]
    withhold_ms: u64,

    /// Number of concurrent streams
    #[arg(long, default_value_t = 8)]
    streams: usize,

    /// Per-scenario duration (seconds)
    #[arg(long, default_value_t = 15)]
    duration_secs: u64,

    /// Chunk size (bytes; SSE token scale)
    #[arg(long, default_value_t = 256)]
    chunk_bytes: usize,

    /// Chunk send interval (ms per stream)
    #[arg(long, default_value_t = 25)]
    chunk_interval_ms: u64,

    /// Repetitions per configuration (different seeds)
    #[arg(long, default_value_t = 3)]
    reps: u32,

    /// Random seed base (scenario seed = base + combination offset)
    #[arg(long, default_value_t = 20260913)]
    seed: u64,

    /// Output path for the results JSON
    #[arg(long)]
    out: Option<std::path::PathBuf>,

    /// Smoke mode: 2 streams × 5s × loss {0,5}% × 1 rep
    #[arg(long, default_value_t = false)]
    quick: bool,

    /// Absorbs flags injected by `cargo bench` (a harness=false binary stays
    /// compatible with the cargo bench entry point)
    #[arg(long, hide = true)]
    bench: bool,
}

/// Per-stream result.
#[derive(Serialize, Debug)]
struct StreamResult {
    stream: usize,
    chunks: usize,
    #[serde(flatten)]
    stats: LatencyStats,
    max_gap_ms: f64,
    stalls: usize,
}

/// Single-scenario result (aggregates + full per-stream detail go into the
/// JSON artifact).
#[derive(Serialize, Debug)]
struct ScenarioResult {
    transport: String,
    loss_pct: u8,
    rep: u32,
    seed: u64,
    healthy: bool,
    streams: Vec<StreamResult>,
    events: usize,
    /// Mean number of stalled streams implicated per impairment event
    /// (headline: how many streams stall per loss).
    mean_collateral_streams: f64,
    median_stream_p95_ms: f64,
    worst_stream_p99_ms: f64,
    worst_max_gap_ms: f64,
}

fn main() {
    let mut args = Args::parse();
    if args.quick {
        args.streams = 4;
        args.duration_secs = 5;
        args.loss_rates = vec![0, 5];
        args.reps = 1;
    }
    assert!(
        args.chunk_bytes >= CHUNK_HEADER,
        "chunk size must be at least {CHUNK_HEADER} bytes (header)"
    );

    let transports: Vec<TransportKind> = args
        .transports
        .iter()
        .map(|t| match t.to_ascii_lowercase().as_str() {
            "h2" => TransportKind::H2,
            "quic" => TransportKind::Quic,
            other => panic!("unknown transport {other} (options: h2, quic)"),
        })
        .collect();

    let rt = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(4)
        .enable_all()
        .build()
        .expect("runtime");

    let mut results: Vec<ScenarioResult> = Vec::new();
    for &transport in &transports {
        for &loss in &args.loss_rates {
            for rep in 1..=args.reps {
                let t0 = Instant::now();
                let scenario_seed = args.seed
                    + u64::from(loss) * 100
                    + u64::from(rep) * 10
                    + transport_id(transport);
                // At most 2 attempts per scenario (failures are usually
                // transient handshake timing, not seed determinism)
                let outcome = {
                    let mut last = None;
                    for attempt in 1..=2 {
                        match rt.block_on(run_scenario(&args, transport, loss, rep, scenario_seed))
                        {
                            Ok(r) => {
                                if attempt > 1 {
                                    println!(
                                        "  [{} loss={}% rep={}] attempt {attempt} succeeded",
                                        transport_name(transport),
                                        loss,
                                        rep
                                    );
                                }
                                last = Some(Ok(r));
                                break;
                            }
                            Err(e) => {
                                eprintln!(
                                    "scenario failed (attempt {attempt}) {} loss={loss}% rep={rep}: {e}",
                                    transport_name(transport)
                                );
                                last = Some(Err(e));
                            }
                        }
                    }
                    last.expect("at least one attempt")
                };
                match outcome {
                    Ok(r) => {
                        println!(
                            "  [{} loss={}% rep={}] {:.1}s → stalled streams/event={:.2}, median per-stream p95={}, worst stream p99={}, events={}{}",
                            transport_name(transport),
                            loss,
                            rep,
                            t0.elapsed().as_secs_f64(),
                            r.mean_collateral_streams,
                            fmt_ms((r.median_stream_p95_ms * 1e6) as u64),
                            fmt_ms((r.worst_stream_p99_ms * 1e6) as u64),
                            r.events,
                            if r.healthy { "" } else { " ⚠unhealthy" },
                        );
                        results.push(r);
                    }
                    Err(_) => {}
                }
            }
        }
    }

    print_report(&args, &results);

    if let Some(out) = &args.out {
        #[derive(Serialize)]
        struct Artifact<'a> {
            meta: serde_json::Value,
            results: &'a [ScenarioResult],
        }
        let artifact = Artifact {
            meta: serde_json::json!({
                "bench": "loss_hol",
                "args": {
                    "rtt_ms": args.rtt_ms,
                    "withhold_ms": args.withhold_ms,
                    "streams": args.streams,
                    "duration_secs": args.duration_secs,
                    "chunk_bytes": args.chunk_bytes,
                    "chunk_interval_ms": args.chunk_interval_ms,
                    "reps": args.reps,
                    "seed_base": args.seed,
                },
                "ts": chrono_like_now(),
            }),
            results: &results,
        };
        // Relative paths resolve against the workspace root: cargo bench runs
        // the process with cwd at the package root (crates/mesh), while the
        // intuitive base for --out is the workspace root where the user ran
        // the command.
        let out = match out {
            p if p.is_absolute() => p.to_path_buf(),
            p => Path::new(env!("CARGO_MANIFEST_DIR")).join("../../").join(p),
        };
        if let Some(parent) = out.parent() {
            std::fs::create_dir_all(parent).expect("create artifact dir");
        }
        std::fs::write(
            &out,
            serde_json::to_string_pretty(&artifact).expect("serde"),
        )
        .expect("write artifact");
        println!("JSON artifact written to {}", out.display());
    }
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

/// RFC3339 local timestamp (for artifact metadata; no chrono dependency, a
/// good-enough format).
fn chrono_like_now() -> String {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default();
    format!("{} (unix {})", local_date_string(), now.as_secs())
}

fn local_date_string() -> String {
    // Simplified: unix seconds → UTC date (the bench artifact only needs an
    // identifiable time).
    let days = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
        / 86_400;
    let (mut y, mut m, mut d) = (1970u32, 1u32, 1u32);
    let mut remaining = days;
    loop {
        let leap = (y % 4 == 0 && y % 100 != 0) || y % 400 == 0;
        let len = match m {
            2 if leap => 29,
            2 => 28,
            4 | 6 | 9 | 11 => 30,
            _ => 31,
        };
        if remaining < len {
            break;
        }
        remaining -= len;
        m += 1;
        if m > 12 {
            m = 1;
            y += 1;
        }
    }
    d += remaining as u32;
    format!("{y:04}-{m:02}-{d:02}")
}

// ---------------------------------------------------------------------------
// Scenario execution
// ---------------------------------------------------------------------------

/// Samples for a single consumer stream.
struct StreamSamples {
    /// (latency_ns, recv_instant)
    samples: Vec<(u64, Instant)>,
}

async fn run_scenario(
    args: &Args,
    transport: TransportKind,
    loss_pct: u8,
    rep: u32,
    seed: u64,
) -> Result<ScenarioResult, String> {
    let hub_port = pick_ephemeral_port();
    let hub_addr: SocketAddr = format!("127.0.0.1:{hub_port}").parse().unwrap();
    let ingress_port = pick_ephemeral_port();
    let ingress_addr: SocketAddr = format!("127.0.0.1:{ingress_port}").parse().unwrap();

    let interval = Duration::from_millis(args.chunk_interval_ms);
    let (backend_addr, _backend, backend_task) = sse_backend(args.chunk_bytes, interval).await;

    // Hub: TLS + QUIC dual stack (the same hub shape for both transports,
    // ensuring comparability)
    let mut hub_cfg = hub_quic_config(hub_port, certs(), Vec::new());
    unlock_stream_limits(&mut hub_cfg);
    let hub = spawn_hub(hub_cfg).await;

    // Impairment proxies (egress↔hub link; ingress connects directly without
    // impairment)
    let impair_cfg = ImpairConfig {
        one_way_delay: Duration::from_millis(args.rtt_ms / 2),
        drop: DropPattern::Rate(f64::from(loss_pct) / 100.0),
        withhold: Duration::from_millis(args.withhold_ms),
        seed,
        ..ImpairConfig::default()
    };
    let tcp_proxy = if transport == TransportKind::H2 {
        Some(
            TcpImpairProxy::spawn(hub_addr, impair_cfg.clone())
                .await
                .map_err(|e| format!("TCP proxy failed to start: {e}"))?,
        )
    } else {
        None
    };
    let udp_proxy = if transport == TransportKind::Quic {
        Some(
            UdpImpairProxy::spawn(hub_addr, impair_cfg.clone())
                .await
                .map_err(|e| format!("UDP proxy failed to start: {e}"))?,
        )
    } else {
        None
    };

    let tls = AgentTlsConfig {
        enabled: true,
        ca_path: Some(certs().ca_path().display().to_string()),
        client_cert_path: None,
        client_key_path: None,
        hub_cert_fingerprint: None,
    };

    // Egress agent: connect target = the proxy (impairment lives on this link)
    let mut egress_cfg = match transport {
        TransportKind::H2 => {
            let mut cfg = agent_config("egress", hub_port, certs());
            cfg.agent.hub_url = format!("http://{}", tcp_proxy.as_ref().unwrap().local_addr());
            cfg
        }
        TransportKind::Quic => {
            let mut cfg = agent_quic_config("egress", hub_port, certs());
            cfg.agent.hub_quic_addr = Some(udp_proxy.as_ref().unwrap().local_addr().to_string());
            cfg
        }
    };
    egress_cfg.agent.connect_timeout_secs = 10; // retransmission headroom for the handshake under loss
    egress_cfg.tls = Some(tls.clone());
    egress_cfg.egress = vec![tcp_egress_rule("sse", backend_addr)];
    let egress = spawn_agent(egress_cfg);

    // Ingress agent: connects directly to the hub (no impairment)
    let mut ingress_cfg = match transport {
        TransportKind::H2 => agent_config("ingress", hub_port, certs()),
        TransportKind::Quic => agent_quic_config("ingress", hub_port, certs()),
    };
    ingress_cfg.agent.connect_timeout_secs = 10;
    ingress_cfg.tls = Some(tls);
    ingress_cfg.ingress = vec![tcp_ingress_rule(
        "sse",
        ingress_addr,
        "egress",
        Some(backend_addr),
    )];
    let ingress = spawn_agent(ingress_cfg);

    // Ready → sample → collect events (failures still flow into the teardown
    // close-out, no leaks: a leaked agent's supervisor retries forever and
    // pollutes subsequent scenarios)
    let phase = async {
        if !interflow_testkit::stack::wait_agent_connected(&egress, Duration::from_secs(45)).await {
            return Err(format!(
                "egress agent did not connect within 45s (state {:?})",
                egress.state()
            ));
        }
        if !interflow_testkit::stack::wait_agent_connected(&ingress, Duration::from_secs(20)).await
        {
            return Err(format!(
                "ingress agent did not connect within 45s (state {:?})",
                ingress.state()
            ));
        }
        wait_for_tcp(ingress_addr, Duration::from_secs(10))
            .await
            .map_err(|e| format!("ingress listener not ready: {e}"))?;

        // Consumers: N concurrent streams, sampling for the full duration
        let duration = Duration::from_secs(args.duration_secs);
        let mut consumers = Vec::with_capacity(args.streams);
        for i in 0..args.streams {
            consumers.push(tokio::spawn(consumer(
                i,
                ingress_addr,
                args.chunk_bytes,
                duration,
            )));
        }
        let mut all_samples = Vec::with_capacity(args.streams);
        for c in consumers {
            let samples = c
                .await
                .map_err(|e| format!("consumer join: {e}"))?
                .map_err(|e| format!("consumer: {e}"))?;
            all_samples.push(samples);
        }

        // Impairment events (collected before shutdown)
        let events: Vec<interflow_testkit::impair::ImpairEvent> = match (&tcp_proxy, &udp_proxy) {
            (Some(p), _) => p.events(),
            (_, Some(p)) => p.events(),
            _ => Vec::new(),
        };
        Ok((all_samples, events))
    };

    let phase_result = phase.await;

    // Unconditional graceful shutdown
    let teardown = async {
        let _ = egress.shutdown_graceful().await;
        let _ = ingress.shutdown_graceful().await;
        hub.shutdown()
            .await
            .map_err(|e| format!("hub shutdown: {e}"))?;
        if let Some(p) = tcp_proxy {
            p.shutdown().await;
        }
        if let Some(p) = udp_proxy {
            p.shutdown().await;
        }
        backend_task.abort();
        Ok::<(), String>(())
    };
    tokio::time::timeout(Duration::from_secs(30), teardown)
        .await
        .map_err(|_| "shutdown timed out after 30s")??;

    let (all_samples, events) = phase_result?;

    // ---- Metrics ----
    let expected = (args.duration_secs * 1000) / u64::from(args.chunk_interval_ms.max(1));
    let mut stream_results = Vec::with_capacity(all_samples.len());
    let mut all_stalls: Vec<Vec<Instant>> = Vec::with_capacity(all_samples.len());
    let mut healthy = true;

    for (idx, s) in all_samples.iter().enumerate() {
        let lats: Vec<u64> = s.samples.iter().map(|(l, _)| *l).collect();
        let stats = latency_stats(lats);

        // Adjacent-chunk gaps (the stutter a consumer perceives)
        let mut gaps: Vec<(Instant, u64)> = Vec::new();
        for w in s.samples.windows(2) {
            let gap = w[1].1.duration_since(w[0].1).as_nanos() as u64;
            gaps.push((w[1].1, gap));
        }
        let mut gap_durs: Vec<u64> = gaps.iter().map(|(_, g)| *g).collect();
        gap_durs.sort_unstable();
        let gap_p50 = gap_durs.get(gap_durs.len() / 2).copied().unwrap_or(0);
        // Stall threshold: 3× the baseline gap and ≥60ms (both h2 withholding
        // and QUIC retransmit recovery far exceed this bound)
        let stall_threshold_ns = (gap_p50 * 3).max(60_000_000);
        let stalls: Vec<Instant> = gaps
            .iter()
            .filter(|(_, g)| *g >= stall_threshold_ns)
            .map(|(end, _)| *end)
            .collect();

        if usize::try_from(expected).unwrap_or(usize::MAX) / 10 * 9 > stats.samples {
            healthy = false;
        }
        let max_gap = gaps.iter().map(|(_, g)| *g).max().unwrap_or(0);
        stream_results.push(StreamResult {
            stream: idx,
            chunks: stats.samples,
            stats,
            max_gap_ms: max_gap as f64 / 1e6,
            stalls: stalls.len(),
        });
        all_stalls.push(stalls);
    }

    // Anchor collateral to events: the number of streams that stall within
    // each impairment event's window (how many streams stall per loss)
    let mut collateral_sum = 0usize;
    let mut collateral_events = 0usize;
    for e in &events {
        let recovery = match e.kind {
            interflow_testkit::impair::ImpairKind::Withheld { for_duration } => for_duration,
            // For loss recovery a drop is a drop either way (QUIC retransmits
            // regardless of who dropped it); overflow should not occur at the
            // default capacity — if it ever does, the soak gate flags it.
            interflow_testkit::impair::ImpairKind::Dropped
            | interflow_testkit::impair::ImpairKind::QueueOverflowDropped { .. } => {
                Duration::from_millis(args.rtt_ms)
            }
        };
        let win_start = e.at.checked_sub(Duration::from_millis(50));
        let win_end = e.at + recovery + Duration::from_millis(150);
        let count = all_stalls
            .iter()
            .filter(|stalls| {
                stalls.iter().any(|&t| {
                    let after_start = win_start.is_none_or(|s| t >= s);
                    after_start && t <= win_end
                })
            })
            .count();
        collateral_sum += count;
        collateral_events += 1;
    }
    let mean_collateral = if collateral_events == 0 {
        0.0
    } else {
        collateral_sum as f64 / collateral_events as f64
    };

    // Cross-stream aggregation: median of the p95s (typical stream), worst
    // p99 (victim stream)
    let mut p95s: Vec<f64> = stream_results
        .iter()
        .map(|r| r.stats.p95_ns as f64 / 1e6)
        .collect();
    p95s.sort_by(|a, b| a.partial_cmp(b).unwrap());
    let median_p95 = p95s.get(p95s.len() / 2).copied().unwrap_or(0.0);
    let worst_p99 = stream_results
        .iter()
        .map(|r| r.stats.p99_ns as f64 / 1e6)
        .fold(0.0_f64, f64::max);
    let worst_gap = stream_results
        .iter()
        .map(|r| r.max_gap_ms)
        .fold(0.0_f64, f64::max);

    Ok(ScenarioResult {
        transport: transport_name(transport).to_string(),
        loss_pct,
        rep,
        seed,
        healthy,
        streams: stream_results,
        events: events.len(),
        mean_collateral_streams: mean_collateral,
        median_stream_p95_ms: median_p95,
        worst_stream_p99_ms: worst_p99,
        worst_max_gap_ms: worst_gap,
    })
}

/// One consumer stream: connects to ingress, receives fixed-size chunks, and
/// records latency and arrival time. The first 10 chunks are discarded
/// (handshake/ramp-up) and excluded from statistics.
async fn consumer(
    _idx: usize,
    ingress_addr: SocketAddr,
    chunk_bytes: usize,
    duration: Duration,
) -> Result<StreamSamples, String> {
    let mut sock = tokio::net::TcpStream::connect(ingress_addr)
        .await
        .map_err(|e| format!("connect: {e}"))?;
    let _ = sock.set_nodelay(true);
    let deadline = tokio::time::Instant::now() + duration + Duration::from_secs(2);
    let mut buf = vec![0u8; chunk_bytes];
    let mut samples: Vec<(u64, Instant)> = Vec::new();
    let mut received = 0usize;

    loop {
        let mut got = 0usize;
        while got < buf.len() {
            use tokio::io::AsyncReadExt;
            let n = tokio::select! {
                () = tokio::time::sleep_until(deadline) => {
                    return Ok(StreamSamples { samples });
                }
                r = sock.read(&mut buf[got..]) => {
                    r.map_err(|e| format!("read: {e}"))?
                }
            };
            if n == 0 {
                return Err("ingress connection closed prematurely".to_string());
            }
            got += n;
        }
        received += 1;
        if received <= 10 {
            continue; // warm-up discard
        }
        let now = Instant::now();
        let (send_ts_ns, _seq) = decode_chunk(&buf);
        let send_at = chunk_instant(send_ts_ns);
        samples.push((now.duration_since(send_at).as_nanos() as u64, now));
    }
}

// ---------------------------------------------------------------------------
// Report
// ---------------------------------------------------------------------------

fn print_report(args: &Args, results: &[ScenarioResult]) {
    println!();
    println!(
        "## QUIC vs h2 concurrent-stream loss comparison (SSE-style {} streams × {}B/{}ms, injected RTT {}ms, {}s/scenario)",
        args.streams, args.chunk_bytes, args.chunk_interval_ms, args.rtt_ms, args.duration_secs,
    );
    println!();
    println!(
        "| transport | loss | rep | median per-stream p95 | worst stream p99 | worst stream max stutter | impairment events | mean stalled streams/event |"
    );
    println!("|---|---|---|---|---|---|---|---|");
    for r in results {
        println!(
            "| {} | {}% | {} | {} | {} | {} | {} | {:.2} |{}",
            r.transport,
            r.loss_pct,
            r.rep,
            fmt_ms((r.median_stream_p95_ms * 1e6) as u64),
            fmt_ms((r.worst_stream_p99_ms * 1e6) as u64),
            fmt_ms((r.worst_max_gap_ms * 1e6) as u64),
            r.events,
            r.mean_collateral_streams,
            if r.healthy { "" } else { " ⚠unhealthy" },
        );
    }
    println!();
    println!(
        "- \"mean stalled streams/event\" = the number of streams that stall within the window of each injected loss/withhold event (h2 expected ≈ all streams, QUIC expected ≈ 1)"
    );
    println!(
        "- The h2 side simulates loss via byte withholding (recovery duration = the withhold parameter); the QUIC side has real loss + quinn retransmissions"
    );
}
