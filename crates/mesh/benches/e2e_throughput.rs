//! End-to-end throughput benchmark.
//!
//! Starts a hub + ingress agent + egress agent + echo backend (reusing the
//! tests/common harness), then repeatedly pushes an N-byte payload to measure
//! MB/s. Only the data transfer itself is measured — hub/agent setup happens
//! outside b.iter and is excluded.
//!
//! Run: `cargo bench --bench e2e_throughput`

// Benchmark code conventionally uses unwrap/expect.
#![allow(
    clippy::all,
    clippy::pedantic,
    clippy::nursery,
    clippy::panic,
    clippy::unwrap_used,
    clippy::expect_used,
    missing_docs,
    dead_code,
    unused_mut,
    unsafe_code
)]

use bytes::Bytes;
use criterion::{BenchmarkId, Criterion, Throughput, criterion_group, criterion_main};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

const PAYLOAD_SIZES: &[(usize, &str)] = &[
    (4 * 1024, "4 KiB"),
    (64 * 1024, "64 KiB"),
    (256 * 1024, "256 KiB"),
    (1024 * 1024, "1 MiB"),
];

fn bench_e2e(c: &mut Criterion) {
    let rt = tokio::runtime::Runtime::new().expect("tokio runtime");
    let _guard = rt.enter();

    // One-time setup: hub + agents + echo. Shared by the whole bench group.
    let (ingress_addr, _stack) = rt.block_on(async { setup::spawn_stack().await });

    let mut group = c.benchmark_group("e2e_throughput");
    for (size, label) in PAYLOAD_SIZES {
        group.throughput(Throughput::Bytes(*size as u64));
        let payload = Bytes::from(vec![0xABu8; *size]);

        // One long-lived connection per size, held across measurements: this
        // measures "single-stream bulk throughput", not connection-setup
        // rate. (The historical shape opened a new TCP per iteration — after
        // the 2026-09-12 upstream streaming change, a single iteration became
        // fast enough to exhaust macOS ephemeral ports during warmup:
        // TIME_WAITs on both the bench client and the egress→echo side
        // accumulate per connection, os error 49 / early eof.)
        let sock = std::sync::Arc::new(tokio::sync::Mutex::new(
            rt.block_on(async { TcpStream::connect(ingress_addr).await })
                .expect("connect ingress"),
        ));

        group.bench_with_input(BenchmarkId::from_parameter(label), size, |b, _| {
            b.to_async(&rt).iter(|| {
                let payload = payload.clone();
                let sock = sock.clone();
                async move {
                    let mut s = sock.lock().await;
                    s.write_all(&payload).await.expect("write");
                    s.flush().await.expect("flush");

                    // Read the same number of bytes back
                    let mut received = vec![0u8; payload.len()];
                    s.read_exact(&mut received).await.expect("read_exact");
                    assert_eq!(received.as_slice(), payload.as_ref());
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

criterion_group!(benches, bench_e2e);
criterion_main!(benches);
