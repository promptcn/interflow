//! RPS / latency benchmark for the expose scenario (custom, no criterion
//! dependency).
//!
//! Usage: cargo run --release -p interflow-expose --example bench_expose -- [--concurrency 1] [--iters 200]
//!
//! Outputs JSON to stdout.

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

use interflow_expose::client::ExposeArgs;
use interflow_expose::edge::{EdgeArgs, Route, RoutesConfig};
use std::net::SocketAddr;
use std::time::{Duration, Instant};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::task::JoinHandle;

#[derive(Debug)]
struct BenchResult {
    scenario: String,
    concurrency: usize,
    iterations: usize,
    total_secs: f64,
    rps: f64,
    latency_us_min: u64,
    latency_us_p50: u64,
    latency_us_p99: u64,
    latency_us_max: u64,
}

#[tokio::main(flavor = "multi_thread", worker_threads = 8)]
async fn main() {
    let args: Vec<String> = std::env::args().collect();
    let mut concurrency: usize = 10;
    let mut iters: usize = 200;

    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "--concurrency" => {
                concurrency = args[i + 1].parse().unwrap();
                i += 2;
            }
            "--iters" => {
                iters = args[i + 1].parse().unwrap();
                i += 2;
            }
            _ => {
                eprintln!("Unknown arg: {}", args[i]);
                i += 1;
            }
        }
    }

    eprintln!("starting expose stack...");
    let (edge_listen, _edge, _client, _echo) = spawn_stack().await;
    eprintln!("edge listen = {edge_listen}");

    let request = b"GET / HTTP/1.1\r\nHost: test.local\r\nConnection: close\r\n\r\n";

    // warmup
    eprintln!("warmup (10 requests)...");
    for _ in 0..10 {
        let mut sock = TcpStream::connect(edge_listen)
            .await
            .expect("connect warmup");
        sock.write_all(request).await.expect("write warmup");
        sock.flush().await.expect("flush warmup");
        let mut resp = vec![0u8; request.len()];
        sock.read_exact(&mut resp).await.expect("read warmup");
    }

    eprintln!("measuring {iters} iters, concurrency={concurrency}...");

    let mut latencies_us: Vec<u64> = Vec::with_capacity(iters);
    let total_start = Instant::now();

    for _ in 0..iters {
        let iter_start = Instant::now();
        let mut handles = Vec::with_capacity(concurrency);
        for _ in 0..concurrency {
            handles.push(tokio::spawn(async move {
                let mut sock = TcpStream::connect(edge_listen).await.expect("connect");
                sock.write_all(request).await.expect("write");
                sock.flush().await.expect("flush");
                let mut resp = vec![0u8; request.len()];
                sock.read_exact(&mut resp).await.expect("read");
            }));
        }
        for h in handles {
            h.await.expect("task");
        }
        latencies_us.push(iter_start.elapsed().as_micros() as u64);
    }
    let total = total_start.elapsed();

    latencies_us.sort_unstable();
    let total_requests = (concurrency * iters) as u64;
    let rps = total_requests as f64 / total.as_secs_f64();

    let result = BenchResult {
        scenario: "expose_rps".into(),
        concurrency,
        iterations: iters,
        total_secs: total.as_secs_f64(),
        rps,
        latency_us_min: *latencies_us.first().unwrap(),
        latency_us_p50: latencies_us[latencies_us.len() / 2],
        latency_us_p99: latencies_us[(latencies_us.len() * 99) / 100],
        latency_us_max: *latencies_us.last().unwrap(),
    };

    println!("scenario = {}", result.scenario);
    println!("concurrency = {}", result.concurrency);
    println!("iterations = {}", result.iterations);
    println!("total_secs = {:.6}", result.total_secs);
    println!("rps = {:.2}", result.rps);
    println!("latency_us_min = {}", result.latency_us_min);
    println!("latency_us_p50 = {}", result.latency_us_p50);
    println!("latency_us_p99 = {}", result.latency_us_p99);
    println!("latency_us_max = {}", result.latency_us_max);
    eprintln!(
        "RPS = {:.0}, p50 = {} µs, p99 = {} µs",
        result.rps, result.latency_us_p50, result.latency_us_p99
    );
}

async fn spawn_stack() -> (
    SocketAddr,
    JoinHandle<interflow_core::error::Result<()>>,
    JoinHandle<Result<(), interflow_core::error::InterflowError>>,
    JoinHandle<()>,
) {
    let echo_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let echo_addr = echo_listener.local_addr().unwrap();
    let echo_handle = tokio::spawn(async move {
        loop {
            let Ok((mut sock, _)) = echo_listener.accept().await else {
                return;
            };
            tokio::spawn(async move {
                let mut buf = [0u8; 1024];
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

    let edge_port = pick_port();
    let hub_port = pick_port();
    let edge_listen: SocketAddr = format!("127.0.0.1:{edge_port}").parse().unwrap();
    let hub_listen: SocketAddr = format!("127.0.0.1:{hub_port}").parse().unwrap();

    let routes = RoutesConfig {
        routes: vec![Route {
            host: "test.local".into(),
            agent_id: "expose-test".into(),
            remote_addr: echo_addr,
        }],
    };
    let routes_path = std::env::temp_dir().join(format!(
        "interflow_bench_routes_{}.toml",
        uuid::Uuid::new_v4()
    ));
    let routes_str = toml::to_string(&routes).expect("serialize routes");
    std::fs::write(&routes_path, &routes_str).expect("write routes.toml");

    let edge_args = EdgeArgs {
        listen_addr: edge_listen,
        hub_listen_addr: hub_listen,
        routes_path: routes_path.to_string_lossy().into_owned(),
        agent_token: "test-token".into(),
        hub_tls: None,
        audit_path: None,
        new_conn_rate_per_ip_per_minute: 0,
        stream_idle_timeout_secs: 300,
    };
    let edge_handle = tokio::task::spawn(interflow_expose::edge::run(edge_args));

    wait_for_tcp(edge_listen, Duration::from_secs(5))
        .await
        .expect("edge listener should start within 5s");
    wait_for_tcp(hub_listen, Duration::from_secs(5))
        .await
        .expect("hub should start within 5s");

    let client_args = ExposeArgs {
        local_ports: vec![echo_addr.port()],
        hub_url: format!("http://127.0.0.1:{hub_port}"),
        auth_token: "test-token".into(),
        agent_id: "expose-test".into(),
        ca_path: None,
    };
    let client_handle =
        tokio::task::spawn(
            async move { interflow_expose::client::start(&client_args)?.join().await },
        );

    tokio::time::sleep(Duration::from_millis(500)).await;
    let _ = std::fs::remove_file(&routes_path);

    (edge_listen, edge_handle, client_handle, echo_handle)
}

fn pick_port() -> u16 {
    let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    l.local_addr().unwrap().port()
}

async fn wait_for_tcp(addr: SocketAddr, timeout: Duration) -> std::io::Result<()> {
    let deadline = tokio::time::Instant::now() + timeout;
    loop {
        match TcpStream::connect(addr).await {
            Ok(_) => return Ok(()),
            Err(e) => {
                if tokio::time::Instant::now() >= deadline {
                    return Err(e);
                }
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
        }
    }
}
