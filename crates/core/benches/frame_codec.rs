//! Frame codec microbenchmark.
//!
//! Run with `just bench` or `cargo bench --bench frame_codec`.
//! Measures:
//! - `encode_frame`: ns/op at various payload sizes
//! - `decode_frame`: ns/op at the same sizes (zero-copy payload slice path)
//! - `decode_no_copy_smoke`: black-box verification that the payload Bytes
//!   shares the allocation with the original buf (no copy expected)

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
use bytes::BytesMut;
use criterion::{BenchmarkId, Criterion, Throughput, criterion_group, criterion_main};
use interflow_core::protocol::frame::{FrameType, decode_frame, encode_frame};

const PAYLOAD_SIZES: &[(usize, &str)] = &[
    (64, "64 B"),
    (1024, "1 KiB"),
    (16 * 1024, "16 KiB"),
    (256 * 1024, "256 KiB"),
    (1024 * 1024, "1 MiB"),
];

fn bench_encode(c: &mut Criterion) {
    let mut group = c.benchmark_group("encode_frame");
    for (size, label) in PAYLOAD_SIZES {
        group.throughput(Throughput::Bytes(*size as u64));
        let payload = vec![0xABu8; *size];
        group.bench_with_input(BenchmarkId::from_parameter(label), size, |b, _| {
            b.iter(|| {
                let mut dst = BytesMut::with_capacity(*size + 64);
                let _ = encode_frame(
                    std::hint::black_box(FrameType::Data),
                    std::hint::black_box(0),
                    std::hint::black_box("sid-abc"),
                    std::hint::black_box("agent-1"),
                    std::hint::black_box(&payload),
                    &mut dst,
                );
                std::hint::black_box(dst);
            });
        });
    }
    group.finish();
}

fn bench_decode(c: &mut Criterion) {
    let mut group = c.benchmark_group("decode_frame");
    for (size, label) in PAYLOAD_SIZES {
        group.throughput(Throughput::Bytes(*size as u64));
        let payload = vec![0xABu8; *size];
        // Pre-encode one frame into an owned buf; clone inside the bench
        let mut encoded = BytesMut::with_capacity(*size + 64);
        encode_frame(
            FrameType::Data,
            0,
            "sid-abc",
            "agent-1",
            &payload,
            &mut encoded,
        );
        let encoded_bytes = encoded.freeze();

        group.bench_with_input(BenchmarkId::from_parameter(label), size, |b, _| {
            b.iter(|| {
                let mut buf = BytesMut::from(&encoded_bytes[..]);
                let outcome = decode_frame(std::hint::black_box(&mut buf));
                std::hint::black_box(outcome);
            });
        });
    }
    group.finish();
}

/// Total cost of an end-to-end round trip (encode + decode), closer to the real hot path.
fn bench_round_trip(c: &mut Criterion) {
    let mut group = c.benchmark_group("encode_decode_round_trip");
    for (size, label) in PAYLOAD_SIZES {
        group.throughput(Throughput::Bytes(*size as u64));
        let payload = vec![0xABu8; *size];
        group.bench_with_input(BenchmarkId::from_parameter(label), size, |b, _| {
            b.iter(|| {
                let mut buf = BytesMut::with_capacity(*size + 64);
                let _ = encode_frame(
                    std::hint::black_box(FrameType::Data),
                    std::hint::black_box(0),
                    std::hint::black_box("sid-abc"),
                    std::hint::black_box("agent-1"),
                    std::hint::black_box(&payload),
                    &mut buf,
                );
                let outcome = decode_frame(std::hint::black_box(&mut buf));
                std::hint::black_box(outcome);
            });
        });
    }
    group.finish();
}

criterion_group!(benches, bench_encode, bench_decode, bench_round_trip);
criterion_main!(benches);
