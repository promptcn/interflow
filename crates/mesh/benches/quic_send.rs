//! QUIC transport send-path benchmark: TCP-echo round trips over an
//! agent↔hub QUIC data plane (both agents on `transport = "quic"`).
//!
//! This is the anchor for the agent-side QUIC send path (frame encode +
//! stream-table lookup + per-stream write channel) and its per-frame
//! buffering; the DATAGRAM fast path is covered by `udp_throughput` with
//! `INTERFLOW_QUIC_BENCH=1`.
//!
//! Payload sizes map onto the wire behavior: 512 B and below ride the
//! per-stream buffered writes, 16 KiB/256 KiB exercise bulk stream writes.
//!
//! Run: `cargo bench -p interflow-mesh --bench quic_send`

// Benchmark code conventionally uses unwrap/expect.
#![allow(
    clippy::all,
    clippy::pedantic,
    clippy::nursery,
    clippy::panic,
    clippy::unwrap_used,
    clippy::expect_used,
    missing_docs
)]

use bytes::Bytes;
use criterion::{BenchmarkId, Criterion, Throughput, criterion_group, criterion_main};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

fn certs() -> &'static interflow_testkit::certs::TestCerts {
    static C: std::sync::OnceLock<interflow_testkit::certs::TestCerts> = std::sync::OnceLock::new();
    C.get_or_init(|| interflow_testkit::certs::TestCerts::generate("e2e", "agent"))
}

const PAYLOAD_SIZES: &[(usize, &str)] = &[
    (512, "512 B"),
    (16 * 1024, "16 KiB"),
    (256 * 1024, "256 KiB"),
];

fn bench_quic_send(c: &mut Criterion) {
    let rt = tokio::runtime::Runtime::new().expect("tokio runtime");
    let _guard = rt.enter();

    // One-time setup: QUIC-transport hub + ingress/egress agents + echo.
    let (ingress_addr, _stack) = rt.block_on(async { setup::spawn_quic_stack().await });

    let mut group = c.benchmark_group("quic_send");
    for (size, label) in PAYLOAD_SIZES {
        group.throughput(Throughput::Bytes(*size as u64));
        let payload = Bytes::from(vec![0xABu8; *size]);

        // One long-lived connection per size (single-stream bulk shape;
        // avoids per-connection TIME_WAIT accumulation during warmup).
        let sock = std::sync::Arc::new(tokio::sync::Mutex::new(
            rt.block_on(async { TcpStream::connect(ingress_addr).await })
                .expect("connect"),
        ));

        group.bench_with_input(BenchmarkId::from_parameter(label), size, |b, _| {
            b.to_async(&rt).iter(|| {
                let payload = payload.clone();
                let sock = sock.clone();
                async move {
                    let mut s = sock.lock().await;
                    s.write_all(&payload).await.expect("write");
                    s.flush().await.expect("flush");
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
    use super::certs;
    // Thin glue: stack assembly lives in interflow-testkit. QUIC preset on
    // both the hub and the agents (dual-stack listener on one port).
    use interflow_mesh::agent::AgentHandle;
    use interflow_testkit::config::{
        agent_quic_config, hub_quic_config, tcp_egress_rule, tcp_ingress_rule, unlock_stream_limits,
    };
    use interflow_testkit::stack::{HubHandle, spawn_agent, spawn_hub};
    use std::net::SocketAddr;
    use std::time::Duration;
    use tokio::task::JoinHandle;

    /// QUIC stack: hub + ingress/egress agents + TCP echo.
    pub async fn spawn_quic_stack() -> (
        SocketAddr,
        (HubHandle, AgentHandle, AgentHandle, JoinHandle<()>),
    ) {
        let (echo_addr, echo) = interflow_testkit::echo_server().await;

        let mut hub_cfg = hub_quic_config(0, certs(), Vec::new());
        unlock_stream_limits(&mut hub_cfg);
        hub_cfg.logging.level = "warn".into();
        let hub = spawn_hub(hub_cfg).await;
        let hub_port = hub.local_addr().expect("hub bound").port();

        let mut egress_cfg = agent_quic_config("egress", hub_port, certs());
        egress_cfg.egress = vec![tcp_egress_rule("echo", echo_addr)];
        let egress = spawn_agent(egress_cfg);

        let mut ingress_cfg = agent_quic_config("ingress", hub_port, certs());
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

criterion_group!(benches, bench_quic_send);
criterion_main!(benches);
