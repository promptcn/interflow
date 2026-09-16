//! Custom throughput/latency benchmark (no criterion dependency).
//!
//! Usage: cargo run --release --example bench_throughput -- [--payload 1048576] [--iters 50] [--concurrency 1]
//!
//! Outputs JSON to stdout; it can be redirected to a file.

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

use bytes::Bytes;
use interflow_core::protocol::StreamProto;
use std::net::SocketAddr;
use std::time::{Duration, Instant};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::task::JoinHandle;

#[derive(serde::Serialize)]
struct BenchResult {
    scenario: String,
    payload_bytes: usize,
    concurrency: usize,
    iterations: usize,
    total_bytes: u64,
    total_secs: f64,
    throughput_mibps: f64,
    latency_us_min: u64,
    latency_us_p50: u64,
    latency_us_p99: u64,
    latency_us_max: u64,
}

#[tokio::main(flavor = "multi_thread", worker_threads = 8)]
async fn main() {
    let args: Vec<String> = std::env::args().collect();
    let mut payload_size: usize = 1024 * 1024; // 1 MiB
    let mut iters: usize = 50;
    let mut concurrency: usize = 1;
    let mut mode = "throughput".to_string();

    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "--payload" => {
                payload_size = args[i + 1].parse().unwrap();
                i += 2;
            }
            "--iters" => {
                iters = args[i + 1].parse().unwrap();
                i += 2;
            }
            "--concurrency" => {
                concurrency = args[i + 1].parse().unwrap();
                i += 2;
            }
            "--mode" => {
                mode = args[i + 1].clone();
                i += 2;
            }
            _ => {
                eprintln!("Unknown arg: {}", args[i]);
                i += 1;
            }
        }
    }

    eprintln!("Starting mesh stack...");
    let (ingress_addr, _hub, _ing, _eg, _echo) = spawn_stack().await;
    eprintln!("ingress addr = {ingress_addr}");

    if mode == "pingpong" {
        run_pingpong(ingress_addr, iters).await;
    } else {
        run_throughput(ingress_addr, payload_size, concurrency, iters).await;
    }
}

async fn run_throughput(
    ingress_addr: SocketAddr,
    payload_size: usize,
    concurrency: usize,
    iters: usize,
) {
    let payload = Bytes::from(vec![0xABu8; payload_size]);
    let mut latencies_us: Vec<u64> = Vec::with_capacity(iters);

    // warmup
    eprintln!("warmup (5 iters)...");
    for _ in 0..5 {
        let mut sock = TcpStream::connect(ingress_addr)
            .await
            .expect("connect warmup");
        let p = payload.clone();
        sock.write_all(&p).await.expect("write warmup");
        sock.flush().await.expect("flush warmup");
        let mut r = vec![0u8; p.len()];
        sock.read_exact(&mut r).await.expect("read warmup");
    }

    eprintln!(
        "Measuring {iters} iters, concurrency={concurrency}, payload={payload_size} bytes..."
    );

    let total_start = Instant::now();
    for _ in 0..iters {
        let iter_start = Instant::now();
        let mut handles = Vec::with_capacity(concurrency);
        for _ in 0..concurrency {
            let payload = payload.clone();
            handles.push(tokio::spawn(async move {
                let mut sock = TcpStream::connect(ingress_addr).await.expect("connect");
                sock.write_all(&payload).await.expect("write");
                sock.flush().await.expect("flush");
                let mut r = vec![0u8; payload.len()];
                sock.read_exact(&mut r).await.expect("read");
            }));
        }
        for h in handles {
            h.await.expect("task");
        }
        latencies_us.push(iter_start.elapsed().as_micros() as u64);
    }
    let total = total_start.elapsed();

    latencies_us.sort_unstable();
    let total_bytes = (payload_size * concurrency * iters) as u64;
    let throughput_mibps = (total_bytes as f64 / 1024.0 / 1024.0) / total.as_secs_f64();

    let result = BenchResult {
        scenario: "mesh_throughput".into(),
        payload_bytes: payload_size,
        concurrency,
        iterations: iters,
        total_bytes,
        total_secs: total.as_secs_f64(),
        throughput_mibps,
        latency_us_min: *latencies_us.first().unwrap(),
        latency_us_p50: latencies_us[latencies_us.len() / 2],
        latency_us_p99: latencies_us[(latencies_us.len() * 99) / 100],
        latency_us_max: *latencies_us.last().unwrap(),
    };

    println!("{}", serde_json::to_string_pretty(&result).unwrap());
    eprintln!(
        "Throughput = {:.1} MiB/s, p50 = {} µs, p99 = {} µs",
        result.throughput_mibps, result.latency_us_p50, result.latency_us_p99
    );
}

async fn run_pingpong(ingress_addr: SocketAddr, iters: usize) {
    let payload: Bytes = Bytes::from_static(b"x");
    let mut latencies_us: Vec<u64> = Vec::with_capacity(iters);

    // warmup
    eprintln!("warmup (100 pingpongs)...");
    let mut sock = TcpStream::connect(ingress_addr)
        .await
        .expect("connect warmup");
    let mut buf = [0u8; 1];
    for _ in 0..100 {
        sock.write_all(&payload).await.expect("write warmup");
        sock.flush().await.expect("flush warmup");
        sock.read_exact(&mut buf).await.expect("read warmup");
    }
    drop(sock);

    eprintln!("Measuring {iters} pingpong RTTs...");

    let mut sock = TcpStream::connect(ingress_addr).await.expect("connect");
    for _ in 0..iters {
        let start = Instant::now();
        sock.write_all(&payload).await.expect("write");
        sock.flush().await.expect("flush");
        sock.read_exact(&mut buf).await.expect("read");
        latencies_us.push(start.elapsed().as_micros() as u64);
    }

    latencies_us.sort_unstable();
    let result = BenchResult {
        scenario: "mesh_pingpong".into(),
        payload_bytes: 1,
        concurrency: 1,
        iterations: iters,
        total_bytes: iters as u64,
        total_secs: latencies_us.iter().map(|&u| u as f64 / 1e6).sum::<f64>(),
        throughput_mibps: 0.0,
        latency_us_min: *latencies_us.first().unwrap(),
        latency_us_p50: latencies_us[latencies_us.len() / 2],
        latency_us_p99: latencies_us[(latencies_us.len() * 99) / 100],
        latency_us_max: *latencies_us.last().unwrap(),
    };

    println!("{}", serde_json::to_string_pretty(&result).unwrap());
    eprintln!(
        "pingpong p50 = {} µs, p99 = {} µs, min = {} µs, max = {} µs",
        result.latency_us_p50, result.latency_us_p99, result.latency_us_min, result.latency_us_max
    );
}

async fn spawn_stack() -> (
    SocketAddr,
    JoinHandle<()>,
    JoinHandle<()>,
    JoinHandle<()>,
    JoinHandle<()>,
) {
    let hub_port = pick_port();
    let ingress_port = pick_port();

    let echo_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let echo_addr = echo_listener.local_addr().unwrap();
    let echo_handle = tokio::spawn(async move {
        loop {
            let Ok((mut sock, _)) = echo_listener.accept().await else {
                return;
            };
            tokio::spawn(async move {
                let mut buf = [0u8; 8192];
                loop {
                    match sock.read(&mut buf).await {
                        Ok(0) | Err(_) => break,
                        Ok(n) => {
                            if sock.write_all(&buf[..n]).await.is_err() {
                                break;
                            }
                        }
                    }
                }
            });
        }
    });

    use interflow_core::config::AuditConfig;
    use interflow_mesh::config::*;
    let hub_cfg = HubConfig {
        config_version: HUB_CONFIG_VERSION,
        server: ServerConfig {
            listen_addr: format!("127.0.0.1:{hub_port}").parse().unwrap(),
        },
        auth: AuthConfig {
            mode: AuthMode::Anonymous,
            allow_anonymous: true,
            rate_limit_per_minute: 0,
            static_token: None,
            mtls: None,
        },
        tls: None,
        acl: AclConfig {
            rules: vec![AclRule {
                source: "ingress".into(),
                target: "egress".into(),
            }]
            .into_iter()
            .collect(),
        },
        security: HubSecurityConfig::default(),
        heartbeat: interflow_mesh::config::HeartbeatConfig::default(),
        routes: Default::default(),
        metrics: MetricsConfig::default(),
        audit: AuditConfig::default(),
        logging: LoggingConfig {
            level: "error".into(),
            format: interflow_mesh::config::LogFormat::Plain,
        },
        quic: Default::default(),
    };
    let hub_handle = tokio::spawn(async move {
        let s = interflow_mesh::hub::HubServer::new(hub_cfg, "<bench>".into()).expect("hub");
        let _ = s.run().await;
    });

    let egress_cfg = AgentConfig {
        config_version: AGENT_CONFIG_VERSION,
        agent: AgentInfo {
            id: "egress".into(),
            hub_url: format!("http://127.0.0.1:{hub_port}"),
            transport: TransportKind::H2,
            hub_quic_addr: None,
            auth_token: None,
            connect_timeout_secs: 5,
            poll_idle_timeout_secs: None,
        },
        ingress: vec![],
        egress: vec![EgressRule {
            name: "echo".into(),
            target_addr: echo_addr,

            target_protocol: StreamProto::Tcp,
            udp_idle_timeout_secs: None,
        }],
        egress_backend_write_timeout_secs: 10,
        egress_resolve_timeout_secs: 5,
        egress_connect_timeout_secs: 5,
        max_incoming_streams: 256,
        max_stream_opens_per_sec: 100,
        stream_open_burst: 256,
        egress_target_breaker_enabled: true,
        egress_target_breaker_failure_threshold: 5,
        egress_target_breaker_window_secs: 10,
        egress_target_breaker_cooldown_secs: 30,
        control: ControlConfig {
            enabled: false,
            ..ControlConfig::default()
        },
        security: SecurityConfig::default(),
        tls: None,
        logging: LoggingConfig {
            level: "error".into(),
            format: LogFormat::Plain,
        },
    };
    let egress_handle = tokio::spawn(async move {
        let c = interflow_mesh::agent::AgentClient::new(egress_cfg).expect("agent");
        let _ = c.start().join().await;
    });

    let ingress_cfg = AgentConfig {
        config_version: AGENT_CONFIG_VERSION,
        agent: AgentInfo {
            id: "ingress".into(),
            hub_url: format!("http://127.0.0.1:{hub_port}"),
            transport: TransportKind::H2,
            hub_quic_addr: None,
            auth_token: None,
            connect_timeout_secs: 5,
            poll_idle_timeout_secs: None,
        },
        ingress: vec![IngressRule {
            name: "to-egress".into(),
            listen_addr: format!("127.0.0.1:{ingress_port}").parse().unwrap(),
            target_agent: "egress".into(),
            remote_addr: Some(echo_addr.to_string()),

            listen_protocol: StreamProto::Tcp,
            idle_timeout_secs: None,
            udp_per_ip_pps: 0,
            udp_per_ip_bytes_per_sec: 0,
            udp_egress_bytes_per_sec: 0,
        }],
        egress: vec![],
        egress_backend_write_timeout_secs: 10,
        egress_resolve_timeout_secs: 5,
        egress_connect_timeout_secs: 5,
        max_incoming_streams: 256,
        max_stream_opens_per_sec: 100,
        stream_open_burst: 256,
        egress_target_breaker_enabled: true,
        egress_target_breaker_failure_threshold: 5,
        egress_target_breaker_window_secs: 10,
        egress_target_breaker_cooldown_secs: 30,
        control: ControlConfig {
            enabled: false,
            ..ControlConfig::default()
        },
        security: SecurityConfig::default(),
        tls: None,
        logging: LoggingConfig {
            level: "error".into(),
            format: LogFormat::Plain,
        },
    };
    let ingress_handle = tokio::spawn(async move {
        let c = interflow_mesh::agent::AgentClient::new(ingress_cfg).expect("agent");
        let _ = c.start().join().await;
    });

    let ingress_addr: SocketAddr = format!("127.0.0.1:{ingress_port}").parse().unwrap();
    let deadline = tokio::time::Instant::now() + Duration::from_secs(20);
    loop {
        if TcpStream::connect(ingress_addr).await.is_ok() {
            break;
        }
        if tokio::time::Instant::now() >= deadline {
            panic!("ingress listener not ready");
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }

    (
        ingress_addr,
        hub_handle,
        ingress_handle,
        egress_handle,
        echo_handle,
    )
}

fn pick_port() -> u16 {
    let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    l.local_addr().unwrap().port()
}
