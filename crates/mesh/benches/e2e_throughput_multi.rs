//! Multi-stream concurrent throughput benchmark.
//!
//! On a single hub+agents stack, opens N concurrent streams (each an
//! independent TCP connection) all pushing 1 MiB at the same time, measuring
//! aggregate throughput and per-stream fairness. Used to evaluate scheduling
//! fairness and contention overhead under multiplexing.
//!
//! Run: `cargo bench --bench e2e_throughput_multi`

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
use criterion::{BenchmarkId, Criterion, Throughput, criterion_group, criterion_main};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

const CONCURRENCIES: &[usize] = &[1, 4, 16, 64];
const PAYLOAD_SIZE: usize = 1024 * 1024; // 1 MiB per stream

fn bench_multi(c: &mut Criterion) {
    let rt = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(8)
        .enable_all()
        .build()
        .expect("tokio runtime");
    let _guard = rt.enter();

    let (ingress_addr, _stack) = rt.block_on(async { setup::spawn_stack().await });

    let mut group = c.benchmark_group("e2e_throughput_multi");
    for &n in CONCURRENCIES {
        // Aggregate throughput = N * PAYLOAD_SIZE (each stream pushes 1 MiB)
        group.throughput(Throughput::Bytes((n * PAYLOAD_SIZE) as u64));
        group.sample_size(if n >= 16 { 10 } else { 20 });

        // N long-lived connections held across measurements: this measures
        // "N-stream concurrent throughput", not connection-setup rate. (The
        // historical shape redialed N TCPs per iteration — after the
        // 2026-09-12 upstream streaming change, iterations became fast enough
        // to exhaust macOS ephemeral ports during warmup, os error 49 /
        // early eof.)
        let socks: Vec<std::sync::Arc<tokio::sync::Mutex<TcpStream>>> = rt.block_on(async {
            let mut v = Vec::with_capacity(n);
            for _ in 0..n {
                v.push(std::sync::Arc::new(tokio::sync::Mutex::new(
                    TcpStream::connect(ingress_addr).await.expect("connect"),
                )));
            }
            v
        });

        group.bench_with_input(BenchmarkId::from_parameter(n), &n, |b, _| {
            b.to_async(&rt).iter(|| {
                let payload = Bytes::from(vec![0xABu8; PAYLOAD_SIZE]);
                let socks = socks.clone();
                async move {
                    let mut handles = Vec::with_capacity(socks.len());
                    for sock in socks {
                        let payload = payload.clone();
                        handles.push(tokio::spawn(async move {
                            let mut s = sock.lock().await;
                            s.write_all(&payload).await.expect("write");
                            s.flush().await.expect("flush");
                            let mut received = vec![0u8; payload.len()];
                            s.read_exact(&mut received).await.expect("read");
                            assert_eq!(received.as_slice(), payload.as_ref());
                        }));
                    }
                    // Wait for all streams; total time is dictated by the
                    // slowest stream
                    for h in handles {
                        h.await.expect("stream task");
                    }
                }
            });
        });
    }
    group.finish();
}

mod setup {
    // Thin glue: stack assembly lives in interflow-testkit (hub/agent
    // configs, echo backend, readiness probe).
    use interflow_mesh::agent::AgentHandle;
    use interflow_testkit::config::{
        acl, agent_config, hub_config, tcp_egress_rule, tcp_ingress_rule, unlock_stream_limits,
    };
    use interflow_testkit::stack::{
        HubHandle, pick_ephemeral_port, spawn_agent, spawn_hub, wait_for_tcp,
    };
    use std::net::SocketAddr;
    use std::time::Duration;
    use tokio::task::JoinHandle;

    /// h2 stack: hub + ingress/egress agents + TCP echo. Bench presets:
    /// stream caps lifted, warn-level logs. Returns (ingress address,
    /// keep-alive handles).
    pub async fn spawn_stack() -> (
        SocketAddr,
        (HubHandle, AgentHandle, AgentHandle, JoinHandle<()>),
    ) {
        let hub_port = pick_ephemeral_port();
        let ingress_port = pick_ephemeral_port();
        let (echo_addr, echo) = interflow_testkit::echo_server().await;

        let mut hub_cfg = hub_config(hub_port, vec![acl("ingress", "egress")]);
        unlock_stream_limits(&mut hub_cfg);
        hub_cfg.logging.level = "warn".into();
        let hub = spawn_hub(hub_cfg).await;

        let mut egress_cfg = agent_config("egress", hub_port);
        egress_cfg.egress = vec![tcp_egress_rule("echo", echo_addr)];
        let egress = spawn_agent(egress_cfg);

        let ingress_addr: SocketAddr = format!("127.0.0.1:{ingress_port}").parse().expect("addr");
        let mut ingress_cfg = agent_config("ingress", hub_port);
        ingress_cfg.ingress = vec![tcp_ingress_rule(
            "to-egress",
            ingress_addr,
            "egress",
            Some(echo_addr),
        )];
        let ingress = spawn_agent(ingress_cfg);

        wait_for_tcp(ingress_addr, Duration::from_secs(20))
            .await
            .expect("ingress listener not ready");

        (ingress_addr, (hub, ingress, egress, echo))
    }
}

criterion_group!(benches, bench_multi);
criterion_main!(benches);
