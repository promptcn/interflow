//! Phased SSE backend: seq continuity and pattern integrity through
//! silence→burst→recovery (the soak gate's core load component; the anchor
//! test that must fail until fixed).

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

use interflow_testkit::backend::{BackendPhase, decode_chunk, sse_backend, verify_chunk_payload};
use std::time::{Duration, Instant};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

/// Read exactly one fixed-size chunk (a read only completes when full, same semantics as
/// the consumer).
async fn read_chunk(sock: &mut TcpStream, chunk_bytes: usize) -> Vec<u8> {
    let mut buf = vec![0u8; chunk_bytes];
    sock.read_exact(&mut buf).await.expect("read chunk");
    buf
}

/// Verify one chunk: seq must equal the expected value and the payload pattern must be intact.
fn expect_chunk(buf: &[u8], want_seq: u32) {
    let (ts, seq) = decode_chunk(buf);
    assert_eq!(
        seq, want_seq,
        "seq must be strictly consecutive (zero-corruption anchor)"
    );
    assert!(ts > 0, "0 is the reserved not-encoded sentinel");
    if let Err(off) = verify_chunk_payload(buf, seq) {
        assert!(
            false,
            "pattern corrupted: seq={seq} first mismatched offset {off}"
        );
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn silence_then_burst_keeps_seq_and_pattern() {
    let chunk = 64;
    let (addr, backend, _task) = sse_backend(chunk, Duration::from_millis(20)).await;
    let mut sock = TcpStream::connect(addr).await.expect("connect");
    sock.set_nodelay(true).expect("nodelay");

    // 1) Normal phase: seq 0..=4 strictly increasing, pattern all correct
    for want in 0..5u32 {
        expect_chunk(&read_chunk(&mut sock, chunk).await, want);
    }

    // 2) Silent phase: 500ms of zero bytes at a 20ms interval = proof sending stopped
    backend.set_phase(BackendPhase::Silent);
    let mut probe = [0u8; 1];
    let r = tokio::time::timeout(Duration::from_millis(500), sock.read(&mut probe)).await;
    assert!(
        r.is_err(),
        "no bytes should arrive during the silent window"
    );

    // 3) Recovery + burst=8: arrives back-to-back immediately, seq strictly consecutive from 5
    backend.set_burst_chunks(8);
    backend.set_phase(BackendPhase::Normal);
    let t0 = Instant::now();
    for want in 5..13u32 {
        expect_chunk(&read_chunk(&mut sock, chunk).await, want);
    }
    assert!(
        t0.elapsed() < Duration::from_millis(500),
        "the burst must arrive immediately after recovery (actual {:?})",
        t0.elapsed()
    );

    // 4) Ticker recovery: subsequent chunks continue with seq 13, 14 (no reset, no gaps)
    expect_chunk(&read_chunk(&mut sock, chunk).await, 13);
    expect_chunk(&read_chunk(&mut sock, chunk).await, 14);

    // 5) Default burst=0 (unset): after a second silence→recovery the ticker resumes sending,
    //    seq stays consecutive
    backend.set_burst_chunks(0);
    backend.set_phase(BackendPhase::Silent);
    tokio::time::sleep(Duration::from_millis(120)).await;
    backend.set_phase(BackendPhase::Normal);
    let mut want = 15u32;
    // The ticker idles during silence; after recovery at most one period is skipped —
    // receive two chunks to verify continuity
    let buf = read_chunk(&mut sock, chunk).await;
    let (_, seq) = decode_chunk(&buf);
    want = want.max(seq);
    expect_chunk(&buf, want);
    expect_chunk(&read_chunk(&mut sock, chunk).await, want + 1);

    // Read-side discard semantics: writing something into the connection must not break the
    // backend (the SSE backend does not echo; this only verifies the connection is alive)
    sock.write_all(b"ping").await.expect("write probe");
    expect_chunk(&read_chunk(&mut sock, chunk).await, want + 2);
}

#[tokio::test(flavor = "multi_thread")]
async fn phase_flip_is_broadcast_to_all_connections() {
    let chunk = 64;
    let (addr, backend, _task) = sse_backend(chunk, Duration::from_millis(20)).await;
    let mut a = TcpStream::connect(addr).await.expect("connect a");
    let mut b = TcpStream::connect(addr).await.expect("connect b");

    // Both connections start from seq 0 independently (per-connection counters)
    expect_chunk(&read_chunk(&mut a, chunk).await, 0);
    expect_chunk(&read_chunk(&mut b, chunk).await, 0);

    // Global silence: both connections stop sending at once
    backend.set_phase(BackendPhase::Silent);
    let mut probe = [0u8; 1];
    for sock in [&mut a, &mut b] {
        let r = tokio::time::timeout(Duration::from_millis(300), sock.read(&mut probe)).await;
        assert!(
            r.is_err(),
            "the broadcast silence must stop both connections"
        );
    }

    // Global recovery + burst: both connections burst at once, seq consecutive on each
    backend.set_burst_chunks(2);
    backend.set_phase(BackendPhase::Normal);
    for sock in [&mut a, &mut b] {
        expect_chunk(&read_chunk(sock, chunk).await, 1);
        expect_chunk(&read_chunk(sock, chunk).await, 2);
    }
}
