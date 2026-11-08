//! Agent-side dispatch/deliver microbenchmark — the anchor for the
//! per-frame downstream hot path shared by the h2 and QUIC loops
//! (`TunnelDispatch::dispatch` → stream-table lookup → bounded send).
//!
//! Variables: registered-stream count (table size / lock behavior) and
//! payload size; plus the stream-miss drop path (late frames). Consumers
//! drain continuously, matching the steady-state shape.
//!
//! Run: `cargo bench -p interflow-core --bench tunnel_dispatch`

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
use interflow_core::protocol::{FrameOrigin, FrameType, StreamId};
use interflow_core::tunnel::{TunnelData, TunnelDispatch};
use std::sync::Arc;

const STREAM_COUNTS: &[usize] = &[1, 64, 1024];
const PAYLOAD_SIZES: &[(usize, &str)] = &[(64, "64 B"), (16 * 1024, "16 KiB")];

fn stream_id(index: usize) -> StreamId {
    // Distinct, deterministic 128-bit ids (hex of the index, zero-padded).
    // +1: StreamId::ZERO is a reserved value (never a data stream).
    StreamId::from_hex(&format!("{:032x}", index + 1)).unwrap()
}

fn response_frame(stream_id: StreamId, payload: Bytes) -> TunnelData {
    TunnelData {
        stream_id,
        origin: FrameOrigin::Response,
        data: payload,
        stream_type: FrameType::Data,
        flags: 0,
    }
}

/// Registers `streams` response-direction channels and spawns one draining
/// consumer per stream (steady-state shape: the consumer keeps up).
fn setup(rt: &tokio::runtime::Runtime, dispatch: &TunnelDispatch, streams: usize) {
    rt.block_on(async {
        let mut rxs = Vec::with_capacity(streams);
        for i in 0..streams {
            rxs.push(dispatch.register_stream(stream_id(i)));
        }
        for mut rx in rxs {
            tokio::spawn(async move {
                // Continuous drain: recv until the dispatch is dropped at
                // group teardown; black-box the payload length so the loop
                // is not optimized away.
                while let Some(frame) = rx.recv().await {
                    std::hint::black_box(frame.data.len());
                }
            });
        }
    });
}

fn bench_dispatch(c: &mut Criterion) {
    let rt = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .expect("runtime");
    let _guard = rt.enter();

    let mut group = c.benchmark_group("tunnel_dispatch");
    for (size, label) in PAYLOAD_SIZES {
        for &streams in STREAM_COUNTS {
            group.throughput(Throughput::Bytes(*size as u64));
            let dispatch = Arc::new(TunnelDispatch::new());
            setup(&rt, &dispatch, streams);
            let payload = Bytes::from(vec![0xABu8; *size]);
            let id = format!("{label}/{streams} streams");
            group.bench_with_input(BenchmarkId::from_parameter(id.clone()), &id, |b, _| {
                b.to_async(&rt).iter(|| {
                    let dispatch = dispatch.clone();
                    let frame = response_frame(
                        // Rotate across the registered table (locks + lookup,
                        // not a single hot entry).
                        stream_id(std::hint::black_box(0) % streams),
                        payload.clone(),
                    );
                    async move {
                        dispatch.dispatch(frame).await;
                    }
                });
            });
        }
    }
    group.finish();
}

fn bench_dispatch_miss(c: &mut Criterion) {
    let rt = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .expect("runtime");
    let _guard = rt.enter();

    let mut group = c.benchmark_group("tunnel_dispatch");
    // Late-frame shape: the stream is long gone (consumer exited, entry
    // removed); every frame pays the table lookup + miss-drop accounting.
    let dispatch = Arc::new(TunnelDispatch::new());
    let payload = Bytes::from(vec![0xABu8; 64]);
    group.throughput(Throughput::Bytes(64));
    group.bench_function("miss/late frame", |b| {
        b.to_async(&rt).iter(|| {
            let dispatch = dispatch.clone();
            let frame = response_frame(stream_id(4095), payload.clone());
            async move {
                dispatch.dispatch(frame).await;
            }
        });
    });
    group.finish();
}

criterion_group!(benches, bench_dispatch, bench_dispatch_miss);
criterion_main!(benches);
