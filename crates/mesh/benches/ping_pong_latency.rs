//! Ping-pong latency benchmark.
//!
//! On a hub+agents stack, each round sends 1 byte and reads 1 byte back (echo
//! backend), measuring end-to-end RTT. Used to evaluate small-packet latency
//! and the impact of Nagle's algorithm (before/after P1-3 TCP_NODELAY).
//!
//! Run: `cargo bench --bench ping_pong_latency`

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
use criterion::{Criterion, Throughput, criterion_group, criterion_main};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

fn certs() -> &'static interflow_testkit::certs::TestCerts {
    static C: std::sync::OnceLock<interflow_testkit::certs::TestCerts> = std::sync::OnceLock::new();
    C.get_or_init(|| interflow_testkit::certs::TestCerts::generate("e2e", "agent"))
}

const ITERATIONS: usize = 1000;

fn bench_pingpong(c: &mut Criterion) {
    let rt = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(4)
        .enable_all()
        .build()
        .expect("tokio runtime");
    let _guard = rt.enter();

    let (ingress_addr, _stack) = rt.block_on(async { setup::spawn_stack().await });

    let mut group = c.benchmark_group("ping_pong_latency");
    // Each iter does 1000 1-byte round trips; total bytes = 1000 (counting
    // both directions as 1000)
    group.throughput(Throughput::Elements(ITERATIONS as u64));
    group.sample_size(30);

    group.bench_function("1B_rtt_x1000", |b| {
        b.to_async(&rt).iter(|| async move {
            let mut sock = TcpStream::connect(ingress_addr).await.expect("connect");
            let payload: Bytes = Bytes::from_static(b"x");
            let mut buf = [0u8; 1];
            for _ in 0..ITERATIONS {
                sock.write_all(&payload).await.expect("write");
                sock.flush().await.expect("flush");
                sock.read_exact(&mut buf).await.expect("read");
                assert_eq!(buf, [b'x']);
            }
        });
    });

    group.finish();
}

mod setup {
    use super::certs;
    // Thin glue: stack assembly lives in interflow-testkit (hub/agent
    // configs, echo backend, readiness probe).
    use interflow_mesh::agent::AgentHandle;
    use interflow_testkit::config::{
        agent_config, hub_config, tcp_egress_rule, tcp_ingress_rule, unlock_stream_limits,
    };
    use interflow_testkit::stack::{HubHandle, spawn_agent, spawn_hub};
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
        let (echo_addr, echo) = interflow_testkit::echo_server().await;

        let mut hub_cfg = hub_config(0, certs(), Vec::new());
        unlock_stream_limits(&mut hub_cfg);
        hub_cfg.logging.level = "warn".into();
        let hub = spawn_hub(hub_cfg).await;
        let hub_port = hub.local_addr().expect("hub bound").port();

        let mut egress_cfg = agent_config("egress", hub_port, certs());
        egress_cfg.egress = vec![tcp_egress_rule("echo", echo_addr)];
        let egress = spawn_agent(egress_cfg);

        let mut ingress_cfg = agent_config("ingress", hub_port, certs());
        ingress_cfg.ingress = vec![tcp_ingress_rule(
            "to-egress",
            "127.0.0.1:0".parse().expect("addr"),
            "egress",
            Some(echo_addr),
        )];
        let ingress = spawn_agent(ingress_cfg);

        let ingress_addr = ingress
            .wait_ingress_addr("to-egress", Duration::from_secs(20))
            .await
            .expect("ingress listener bound");

        (ingress_addr, (hub, ingress, egress, echo))
    }
}

criterion_group!(benches, bench_pingpong);
criterion_main!(benches);
