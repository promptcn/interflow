//! UDP throughput benchmark: datagram size × echo round-trip throughput (over
//! the h2 tunnel).
//!
//! `clippy::panic` allowed: there is no point continuing the benchmark once
//! stack readiness has failed.
//!
//! The size matrix comes from frp's `udp_benchmark_test.go` (64/512/1200/1472,
//! covering typical DNS / gaming / near-MTU workload shapes). After the QUIC
//! DATAGRAM fast path (P3) landed, this is where h2 vs quic per-frame costs
//! are compared.
//!
//! History: before 2026-09-12 the h2 upstream was "one full POST round trip
//! per datagram" (an inline await inside the ingress recv loop); throughput
//! was RTT-bound (~172µs/frame), and on some machines this bench wedged
//! forever because recv had no timeout and the per-agent stream cap's default
//! value rejected opens after 256 iterations. After the upstream was streamed
//! (`POST /stream/up`): the upstream is just frame encoding + a channel
//! write, the stop-and-wait full-path round trip is ~120µs (dominated by
//! downstream dispatch), with zero loss across all sizes.

#![allow(
    clippy::panic, // no point continuing the benchmark once stack readiness has failed
    clippy::cast_possible_truncation
)]

use criterion::{Criterion, Throughput, criterion_group, criterion_main};
use std::net::SocketAddr;

fn certs() -> &'static interflow_testkit::certs::TestCerts {
    static C: std::sync::OnceLock<interflow_testkit::certs::TestCerts> = std::sync::OnceLock::new();
    C.get_or_init(|| interflow_testkit::certs::TestCerts::generate("e2e", "agent"))
}

fn bench_udp_throughput(c: &mut Criterion) {
    let rt = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(4)
        .enable_all()
        .build()
        .expect("runtime");

    // h2 stack
    let (ingress_addr, _stack) = rt.block_on(async { setup::spawn_stack().await });

    bench_group(c, &rt, "h2", ingress_addr);

    // QUIC stack (with the DATAGRAM fast path: small packets ride RFC 9221,
    // loss does not HOL). Enabled by an explicit switch:
    // INTERFLOW_QUIC_BENCH=1 cargo bench --bench udp_throughput
    //
    // Lossy-environment comparison (T11 netem recipe, needs root, two machines
    // or network namespaces):
    //   sudo tc qdisc add dev eth0 root netem delay 10ms loss 2%
    //   # Run h2 (default) and quic (INTERFLOW_QUIC_BENCH=1) separately, then
    //   # compare the criterion reports:
    //   #   the h2 group's throughput is expected to degrade significantly
    //   #     (TCP HOL + one POST round trip per frame)
    //   #   the quic group's datagram path is not dragged down by
    //   #     reliable-stream retransmissions
    //   sudo tc qdisc del dev eth0 root
    if std::env::var("INTERFLOW_QUIC_BENCH").ok().as_deref() == Some("1") {
        match rt.block_on(async { setup::spawn_quic_stack().await }) {
            Ok((quic_addr, _stack)) => bench_group(c, &rt, "quic", quic_addr),
            Err(e) => eprintln!("QUIC bench stack failed to start, skipping: {e}"),
        }
    }
}

/// Shared group: transport × datagram size matrix.
fn bench_group(
    c: &mut Criterion,
    rt: &tokio::runtime::Runtime,
    transport: &str,
    ingress_addr: SocketAddr,
) {
    let mut group = c.benchmark_group(format!("udp_throughput_{transport}"));

    const DATAGRAMS_PER_ITER: usize = 100;

    for size in [64usize, 512, 1200, 1472] {
        let payload: Vec<u8> = (0..size).map(|i| (i % 251) as u8).collect();
        // Keep one public source address across all criterion samples. The
        // The data plane intentionally amortizes the inner QUIC association
        // and inner session handshake across datagrams; measuring a new source
        // per sample would benchmark session churn, not steady-state forwarding.
        let socket = rt
            .block_on(async {
                interflow_mesh::agent::ingress_udp::bind_udp_socket(
                    "127.0.0.1:0".parse().expect("addr"),
                )
            })
            .expect("client bind");
        let sock = std::sync::Arc::new(socket);
        group.throughput(Throughput::Bytes(
            (size * DATAGRAMS_PER_ITER).saturating_mul(2) as u64, // sent + received
        ));
        group.bench_with_input(
            format!("{transport}_size_{size}"),
            &payload,
            |b, payload| {
                b.to_async(rt).iter(|| {
                    let sock = std::sync::Arc::clone(&sock);
                    async move {
                    let mut buf = vec![0u8; 65535];
                    let mut lost = 0usize;
                    for _ in 0..DATAGRAMS_PER_ITER {
                        // recv must carry a timeout: even loopback UDP
                        // occasionally drops packets under local load spikes
                        // (before this change, a recv_from without a timeout
                        // blocked the entire bench forever — the historical
                        // wedge root cause). Transient loss gets a bounded
                        // number of retries; a persistent stall counts as
                        // lost and we move on — the throughput number and the
                        // loss count together reflect path quality (loss is
                        // not fatal, otherwise a single random loss would
                        // kill the whole benchmark).
                        let mut got: Option<usize> = None;
                        for _attempt in 0..3 {
                            sock.send_to(payload, ingress_addr).await.expect("send");
                            match tokio::time::timeout(
                                std::time::Duration::from_secs(2),
                                sock.recv_from(&mut buf),
                            )
                            .await
                            {
                                Ok(Ok((n, _))) => {
                                    got = Some(n);
                                    break;
                                }
                                Ok(Err(e)) => panic!("recv error: {e}"),
                                Err(_) => {}
                            }
                        }
                        match got {
                            Some(n) => assert_eq!(n, payload.len(), "datagram not truncated"),
                            None => lost += 1,
                        }
                    }
                    if lost > 0 {
                        const D: usize = DATAGRAMS_PER_ITER;
                        eprintln!("[bench] lost {lost}/{D} datagrams (counted in the timing, reflecting path stalls)");
                    }
                    std::hint::black_box(lost);
                }
                });
            },
        );
    }
    group.finish();
}

criterion_group!(benches, bench_udp_throughput);

criterion_main!(benches);

mod setup {
    use super::certs;
    // Thin glue: stack assembly lives in interflow-testkit (certs, hub/agent
    // configs, UDP echo, probes).
    use interflow_mesh::agent::AgentHandle;
    use interflow_testkit::config::{
        agent_config, agent_quic_config, hub_config, hub_quic_config, udp_egress_rule,
        udp_ingress_rule, unlock_stream_limits,
    };
    use interflow_testkit::stack::{HubHandle, spawn_agent, spawn_hub};
    use std::net::SocketAddr;
    use std::time::Duration;
    use tokio::task::JoinHandle;

    type StackKeep = (HubHandle, AgentHandle, AgentHandle, JoinHandle<()>);

    const fn udp_idle(
        mut rule: interflow_mesh::config::EgressRule,
    ) -> interflow_mesh::config::EgressRule {
        rule.udp_idle_timeout_secs = Some(300);
        rule
    }
    const fn udp_ingress_idle(
        mut rule: interflow_mesh::config::IngressRule,
    ) -> interflow_mesh::config::IngressRule {
        rule.idle_timeout_secs = Some(300);
        rule
    }

    /// h2 stack: hub + ingress/egress agents + UDP echo (stream caps lifted).
    /// Returns the ingress UDP address.
    pub async fn spawn_stack() -> (SocketAddr, StackKeep) {
        let (echo_addr, echo) = interflow_testkit::spawn_udp_echo().await;

        let mut hub_cfg = hub_config(0, certs(), Vec::new());
        unlock_stream_limits(&mut hub_cfg);
        let hub = spawn_hub(hub_cfg).await;
        let hub_port = hub.local_addr().expect("hub bound").port();

        let mut egress_cfg = agent_config("egress", hub_port, certs());
        egress_cfg.egress = vec![udp_idle(udp_egress_rule("echo", echo_addr))];
        let egress = spawn_agent(egress_cfg);

        let mut ingress_cfg = agent_config("ingress", hub_port, certs());
        ingress_cfg.ingress = vec![udp_ingress_idle(udp_ingress_rule(
            "to-egress",
            "127.0.0.1:0".parse().expect("addr"),
            "egress",
            Some(echo_addr),
        ))];
        let ingress = spawn_agent(ingress_cfg);

        let ingress_addr = ingress
            .wait_ingress_addr("to-egress", Duration::from_secs(20))
            .await
            .expect("ingress listener bound");
        ready_probe(ingress_addr).await;
        (ingress_addr, (hub, ingress, egress, echo))
    }

    /// QUIC stack (with the DATAGRAM fast path: small packets ride RFC 9221,
    /// loss does not HOL).
    pub async fn spawn_quic_stack() -> std::result::Result<(SocketAddr, StackKeep), String> {
        let (echo_addr, echo) = interflow_testkit::spawn_udp_echo().await;

        let mut hub_cfg = hub_quic_config(0, certs(), Vec::new());
        unlock_stream_limits(&mut hub_cfg);
        let hub = spawn_hub(hub_cfg).await;
        let hub_port = hub.local_addr().expect("hub bound").port();

        let mut egress_cfg = agent_quic_config("egress", hub_port, certs());
        egress_cfg.egress = vec![udp_idle(udp_egress_rule("echo", echo_addr))];
        let egress = spawn_agent(egress_cfg);

        let mut ingress_cfg = agent_quic_config("ingress", hub_port, certs());
        ingress_cfg.ingress = vec![udp_ingress_idle(udp_ingress_rule(
            "to-egress",
            "127.0.0.1:0".parse().expect("addr"),
            "egress",
            Some(echo_addr),
        ))];
        let ingress = spawn_agent(ingress_cfg);

        let ingress_addr = ingress
            .wait_ingress_addr("to-egress", Duration::from_secs(20))
            .await
            .expect("ingress listener bound");
        ready_probe(ingress_addr).await;
        Ok((ingress_addr, (hub, ingress, egress, echo)))
    }

    /// Readiness probe: a UDP echo round trip with retries (absorbs
    /// registration/TLS handshake latency).
    async fn ready_probe(ingress_addr: SocketAddr) {
        interflow_testkit::udp_echo_round_trip(ingress_addr, b"ready", Duration::from_secs(15))
            .await
            .expect("UDP bench stack not ready within 15s");
    }
}
