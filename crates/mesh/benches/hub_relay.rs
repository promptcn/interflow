//! Hub data-plane relay microbenchmark — the anchor for
//! `HubState::frame_data` (active-stream routing → dispatch-plane send),
//! driven directly at the frame layer, without any transport stack.
//!
//! Two shapes per matrix point:
//! - `poll` target face: the h2 path (route lookup + agent-table/session
//!   channel resolution per frame);
//! - `relay` target face: the QUIC path (route lookup + per-stream sink
//!   channel).
//!
//! Consumers drain continuously, matching the steady-state shape.
//!
//! Run: `cargo bench -p interflow-mesh --bench hub_relay`

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

use criterion::{BenchmarkId, Criterion, Throughput, criterion_group, criterion_main};
use interflow_core::protocol::StreamProto;
use std::sync::Arc;
use tokio::sync::mpsc;

const STREAM_COUNTS: &[usize] = &[1, 64, 1024];
const PAYLOAD_SIZES: &[(usize, &str)] = &[(64, "64 B"), (16 * 1024, "16 KiB")];

use interflow_mesh::hub::routing::Direction;
use interflow_mesh::hub::server::HubServer;
use interflow_mesh::hub::state::{ActiveStream, PeerIdentity, StreamFace};

const TENANT: &str = interflow_testkit::config::TEST_TENANT;
const SOURCE: &str = "bench-src";
const TARGET: &str = "bench-dst";

fn circuit(seed: u8) -> interflow_core::protocol::CircuitToken {
    interflow_core::protocol::CircuitToken::from_hex(&format!("{seed:032x}")).unwrap()
}

fn stream_id(index: usize) -> interflow_core::protocol::StreamId {
    interflow_core::protocol::// +1: StreamId::ZERO is a reserved value (never a data stream).
    StreamId::from_hex(&format!("{:032x}", index + 1))
    .unwrap()
}

fn identity(agent: &str) -> PeerIdentity {
    PeerIdentity {
        tenant: Arc::from(TENANT),
        agent: agent.to_owned(),
        trusted_gateway: false,
        leaf_validity_unix: None,
        leaf_serial_hex: None,
    }
}

/// One hub fixture per (face, streams) cell: a minimal assembled hub (no
/// listeners), both agents registered, `streams` active routes to the
/// target on the requested dispatch plane, and continuously draining
/// consumers.
struct Fixture {
    state: Arc<interflow_mesh::hub::state::HubState>,
    _server: HubServer,
    source_circuit: interflow_core::protocol::CircuitToken,
    streams: usize,
}

async fn fixture(face: &str, streams: usize) -> Fixture {
    let certs = interflow_testkit::certs::TestCerts::generate("hubrelay", "agent");
    let mut cfg = interflow_testkit::config::hub_config(0, &certs, Vec::new());
    interflow_testkit::config::unlock_stream_limits(&mut cfg);
    let server = HubServer::new(cfg, interflow_core::security::AuditSink::disabled()).unwrap();
    let state = server.state_handle();

    let source_circuit = circuit(1);
    let target_circuit = circuit(2);
    state
        .register_agent(&identity(SOURCE), source_circuit, None, None, "bench")
        .await
        .unwrap();
    state
        .register_agent(&identity(TARGET), target_circuit, None, None, "bench")
        .await
        .unwrap();

    // Drain the target agent's data channel (the poll consumer): take the
    // rx out of the session — exactly what the poll handler does — and
    // keep receiving for the fixture's lifetime.
    {
        let agents = state.agents.read().await;
        let session = agents.get(&format!("{TENANT}/{TARGET}")).cloned().unwrap();
        drop(agents);
        let mut guard = session.write().await;
        let mut rx = guard.rx.take().unwrap();
        drop(guard);
        tokio::spawn(async move {
            while let Some(frame) = rx.recv().await {
                std::hint::black_box(frame.data.len());
            }
        });
    }

    let qualified_source = format!("{TENANT}/{SOURCE}");
    let qualified_target = format!("{TENANT}/{TARGET}");
    let mut relay_rxs = Vec::new();
    // The poll faces carry the real session senders (exactly what frame_open
    // captures — the bench measures the production route shape).
    let target_poll = state
        .data_tx(&qualified_target)
        .expect("target session registered");
    let source_poll = state
        .data_tx(&qualified_source)
        .expect("source session registered");
    for i in 0..streams {
        // Relay face: a per-stream sink channel with its own drainer
        // (the QUIC relay writer task shape).
        let target_face = if face == "relay" {
            let (tx, mut rx) = mpsc::channel::<interflow_core::tunnel::TunnelData>(256);
            relay_rxs.push(tokio::spawn(async move {
                while let Some(frame) = rx.recv().await {
                    std::hint::black_box(frame.data.len());
                }
            }));
            StreamFace::Relay(tx)
        } else {
            StreamFace::Poll(target_poll.clone())
        };
        state.active_streams.insert(
            stream_id(i),
            ActiveStream {
                source_agent: std::sync::Arc::from(qualified_source.as_str()),
                target_agent: std::sync::Arc::from(qualified_target.as_str()),
                source_circuit,
                target_circuit,
                proto: StreamProto::Tcp,
                target: target_face,
                source: StreamFace::Poll(source_poll.clone()),
                datagram_ok: false,
            },
        );
    }
    std::hint::black_box(&relay_rxs);

    Fixture {
        state,
        _server: server,
        source_circuit,
        streams,
    }
}

fn bench_frame_data(c: &mut Criterion) {
    let rt = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .expect("runtime");

    let mut group = c.benchmark_group("hub_relay");
    for (size, label) in PAYLOAD_SIZES {
        for face in ["poll", "relay"] {
            for &streams in STREAM_COUNTS {
                group.throughput(Throughput::Bytes(*size as u64));
                let fixture = rt.block_on(fixture(face, streams));
                let payload = bytes::Bytes::from(vec![0xABu8; *size]);
                let id = format!("{face}/{label}/{streams} streams");
                let state = fixture.state.clone();
                let circuit = fixture.source_circuit;
                let n = fixture.streams;
                drop(fixture);
                group.bench_with_input(BenchmarkId::from_parameter(id.clone()), &id, |b, _| {
                    b.to_async(&rt).iter(|| {
                        let state = state.clone();
                        let frame = stream_id(std::hint::black_box(0) % n);
                        let payload = payload.clone();
                        async move {
                            state
                                .frame_data(
                                    &format!("{TENANT}/{SOURCE}"),
                                    circuit,
                                    frame,
                                    Direction::Request,
                                    payload,
                                )
                                .await
                                .unwrap();
                        }
                    });
                });
            }
        }
    }
    group.finish();
}

criterion_group!(benches, bench_frame_data);
criterion_main!(benches);
