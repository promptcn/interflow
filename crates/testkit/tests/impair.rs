//! Impairment proxy unit tests: ordering, withholding propagating across
//! subsequent bytes (the core HOL-simulation semantics), real UDP drops, NAT
//! return-traffic mapping, and seed determinism of the probability pattern.

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

use interflow_testkit::backend::echo_server;
use interflow_testkit::impair::{DropPattern, ImpairConfig, TcpImpairProxy, UdpImpairProxy};
use std::time::{Duration, Instant};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

/// No impairment: delay injection takes effect (RTT ≈ 2× one-way), data passes through ordered and unchanged.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn tcp_delay_only_passes_ordered() {
    let (echo_addr, _echo) = echo_server().await;
    let cfg = ImpairConfig {
        one_way_delay: Duration::from_millis(30),
        ..Default::default()
    };
    let proxy = TcpImpairProxy::spawn(echo_addr, cfg).await.unwrap();

    let mut sock = tokio::net::TcpStream::connect(proxy.local_addr())
        .await
        .unwrap();
    let t0 = Instant::now();
    sock.write_all(b"hello").await.unwrap();
    let mut buf = [0u8; 5];
    sock.read_exact(&mut buf).await.unwrap();
    let rtt = t0.elapsed();

    assert_eq!(&buf, b"hello");
    assert!(
        rtt >= Duration::from_millis(55),
        "RTT must be >= 2x one-way delay (actual {rtt:?})"
    );
    assert!(
        rtt < Duration::from_millis(500),
        "the unimpaired path must not have extra stalls (actual {rtt:?})"
    );
    proxy.shutdown().await;
}

/// Withholding simulates a lost segment: every byte after the withheld chunk is
/// blocked (TCP in-order), while the first byte is unaffected — this is exactly
/// the propagation mechanism of cross-stream HOL.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn tcp_withhold_stalls_subsequent_bytes_in_order() {
    let (echo_addr, _echo) = echo_server().await;
    let d = Duration::from_millis(30);
    let w = Duration::from_millis(150);
    let cfg = ImpairConfig {
        one_way_delay: d,
        drop: DropPattern::Every(2), // the 2nd chunk is withheld
        withhold: w,
        ..Default::default()
    };
    let proxy = TcpImpairProxy::spawn(echo_addr, cfg).await.unwrap();

    let mut sock = tokio::net::TcpStream::connect(proxy.local_addr())
        .await
        .unwrap();
    let t0 = Instant::now();
    // 4 small chunks sent back-to-back (interval far below the withhold duration)
    for b in b"ABCD" {
        sock.write_all(&[*b]).await.unwrap();
        tokio::time::sleep(Duration::from_millis(5)).await;
    }

    let mut got = Vec::with_capacity(4);
    let mut arrival = Vec::with_capacity(4);
    for _ in 0..4 {
        let mut one = [0u8; 1];
        sock.read_exact(&mut one).await.unwrap();
        arrival.push(t0.elapsed());
        got.push(one[0]);
    }

    // Ordered and complete
    assert_eq!(got, b"ABCD".to_vec());
    // First byte normal: ≈ RTT (2D), well before withhold recovery
    assert!(
        arrival[0] < d * 2 + w,
        "the first byte must not be slowed by the withhold (actual {:?})",
        arrival[0]
    );
    // Last byte held back by the withhold: >= RTT + W (the echo return also passes the proxy, last byte >= 2D + W)
    assert!(
        arrival[3] >= d * 2 + w,
        "the last byte must wait for the withhold release (actual {:?}, expected >= {:?})",
        arrival[3],
        d * 2 + w
    );
    // The withhold must not amplify unboundedly: last byte < RTT + W + slack
    assert!(
        arrival[3] < d * 2 + w * 2 + Duration::from_millis(200),
        "the withhold should only stall for one round (actual {:?})",
        arrival[3]
    );
    proxy.shutdown().await;
}

/// Real UDP drops: Every(2) drops even sequence numbers, odd ones arrive late.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn udp_every2_drops_alternate_datagrams() {
    // Use a plain UdpSocket echo directly (no mesh assembly; a pure proxy-semantics test)
    let echo = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let echo_addr = echo.local_addr().unwrap();
    let echo_task = tokio::spawn(async move {
        let mut buf = [0u8; 64];
        loop {
            let Ok((n, peer)) = echo.recv_from(&mut buf).await else {
                return;
            };
            let _ = echo.send_to(&buf[..n], peer).await;
        }
    });

    let d = Duration::from_millis(30);
    let cfg = ImpairConfig {
        one_way_delay: d,
        drop: DropPattern::Every(2),
        ..Default::default()
    };
    let proxy = UdpImpairProxy::spawn(echo_addr, cfg).await.unwrap();

    let client = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let mut replied = Vec::new();
    let mut t0 = None;
    for seq in 0u8..6 {
        let msg = [0xF0, seq];
        client.send_to(&msg, proxy.local_addr()).await.unwrap();
        if t0.is_none() {
            t0 = Some(Instant::now());
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    // Collect replies within 2s
    let deadline = tokio::time::Instant::now() + Duration::from_secs(2);
    while tokio::time::Instant::now() < deadline {
        let mut buf = [0u8; 64];
        match tokio::time::timeout(Duration::from_millis(200), client.recv_from(&mut buf)).await {
            Ok(Ok((n, _))) if n == 2 => replied.push(buf[1]),
            _ => {
                if replied.len() >= 3 {
                    break;
                }
            }
        }
    }
    replied.sort_unstable();
    assert_eq!(
        replied,
        vec![0, 2, 4],
        "Every(2) must drop exactly the 2nd/4th/6th datagrams (actual replied seq: {replied:?})"
    );
    assert!(
        t0.unwrap().elapsed() >= d,
        "delivered datagrams must also carry the one-way delay"
    );
    proxy.shutdown().await;
    echo_task.abort();
}

/// UDP NAT return mapping: two clients through the same proxy each receive their own replies.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn udp_nat_routes_replies_per_client() {
    let echo = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let echo_addr = echo.local_addr().unwrap();
    let echo_task = tokio::spawn(async move {
        let mut buf = [0u8; 64];
        loop {
            let Ok((n, peer)) = echo.recv_from(&mut buf).await else {
                return;
            };
            let _ = echo.send_to(&buf[..n], peer).await;
        }
    });

    let cfg = ImpairConfig {
        one_way_delay: Duration::from_millis(10),
        ..Default::default()
    };
    let proxy = UdpImpairProxy::spawn(echo_addr, cfg).await.unwrap();

    let a = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let b = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    a.send_to(b"from-a", proxy.local_addr()).await.unwrap();
    b.send_to(b"from-b", proxy.local_addr()).await.unwrap();

    let mut buf = [0u8; 64];
    let (n, _) = tokio::time::timeout(Duration::from_secs(2), a.recv_from(&mut buf))
        .await
        .expect("a receives its reply")
        .expect("a recv");
    assert_eq!(&buf[..n], b"from-a", "a must only receive its own reply");

    let mut buf = [0u8; 64];
    let (n, _) = tokio::time::timeout(Duration::from_secs(2), b.recv_from(&mut buf))
        .await
        .expect("b receives its reply")
        .expect("b recv");
    assert_eq!(&buf[..n], b"from-b", "b must only receive its own reply");

    proxy.shutdown().await;
    echo_task.abort();
}

/// Seed determinism of the probability pattern: same seed + same input sequence → same drop sequence.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn udp_rate_pattern_is_seed_deterministic() {
    async fn run_round(seed: u64) -> Vec<u8> {
        let echo = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let echo_addr = echo.local_addr().unwrap();
        let echo_task = tokio::spawn(async move {
            let mut buf = [0u8; 64];
            loop {
                let Ok((n, peer)) = echo.recv_from(&mut buf).await else {
                    return;
                };
                let _ = echo.send_to(&buf[..n], peer).await;
            }
        });

        let cfg = ImpairConfig {
            one_way_delay: Duration::from_millis(5),
            drop: DropPattern::Rate(0.3),
            seed,
            ..Default::default()
        };
        let proxy = UdpImpairProxy::spawn(echo_addr, cfg).await.unwrap();
        let client = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        for seq in 0u8..10 {
            client
                .send_to(&[0xF0, seq], proxy.local_addr())
                .await
                .unwrap();
            tokio::time::sleep(Duration::from_millis(15)).await;
        }
        // Collect replies for 1s
        let mut replied = Vec::new();
        let deadline = tokio::time::Instant::now() + Duration::from_secs(1);
        while tokio::time::Instant::now() < deadline {
            let mut buf = [0u8; 64];
            match tokio::time::timeout(Duration::from_millis(150), client.recv_from(&mut buf)).await
            {
                Ok(Ok((n, _))) if n == 2 => replied.push(buf[1]),
                _ => {}
            }
        }
        proxy.shutdown().await;
        echo_task.abort();
        replied.sort_unstable();
        replied
    }

    let round1 = run_round(1234).await;
    let round2 = run_round(1234).await;
    assert!(
        !round1.is_empty() && round1.len() < 10,
        "a 0.3 drop rate should drop some but not all"
    );
    assert_eq!(
        round1, round2,
        "the same seed must produce the same drop sequence (precondition for reproducibility)"
    );
}

/// Return-direction (upstream→client) delay injection must not serialize: replies to a burst
/// of datagrams must all arrive within one-way delay + slack rather than queue up one by one
/// (historically the return pump put the sleep inside the loop body, capping downstream
/// throughput at 1 packet per delay and growing the queue without bound — the loss bench's
/// QUIC baseline was inflated 8x because of this).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn udp_downstream_delay_does_not_serialize() {
    let echo = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let echo_addr = echo.local_addr().unwrap();
    let echo_task = tokio::spawn(async move {
        let mut buf = [0u8; 64];
        loop {
            let Ok((n, peer)) = echo.recv_from(&mut buf).await else {
                return;
            };
            let _ = echo.send_to(&buf[..n], peer).await;
        }
    });

    const N: usize = 20;
    const D: Duration = Duration::from_millis(40);
    let cfg = ImpairConfig {
        one_way_delay: D,
        ..Default::default()
    };
    let proxy = UdpImpairProxy::spawn(echo_addr, cfg).await.unwrap();

    let client = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let t0 = Instant::now();
    // Burst to the limit: N datagrams sent back-to-back (interval far below the one-way delay)
    for i in 0..N {
        client
            .send_to(&[0xB0, i as u8], proxy.local_addr())
            .await
            .unwrap();
    }

    let mut got = 0usize;
    let deadline = tokio::time::Instant::now() + Duration::from_secs(2);
    while got < N && tokio::time::Instant::now() < deadline {
        let mut buf = [0u8; 64];
        match tokio::time::timeout(Duration::from_millis(200), client.recv_from(&mut buf)).await {
            Ok(Ok((n, _))) if n == 2 => got += 1,
            _ => {}
        }
    }
    let elapsed = t0.elapsed();

    assert_eq!(
        got, N,
        "the no-drop pattern must reply to all (actual {got}/{N})"
    );
    // Serializing would take N×2D = 1.6s; with parallel delay injection the total is ≈ 2D + slack
    assert!(
        elapsed < Duration::from_millis(300),
        "replies to {N} burst datagrams must finish within ~2x one-way delay (actual {elapsed:?})"
    );
    proxy.shutdown().await;
    echo_task.abort();
}
