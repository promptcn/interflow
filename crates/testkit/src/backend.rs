//! Test backends: TCP echo, the UDP echo family, and an SSE-style timestamped-chunk backend.

use std::net::SocketAddr;
use std::sync::OnceLock;
use std::time::{Duration, Instant};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tokio::task::JoinHandle;

/// Start a simple TCP echo server; returns (bound address, JoinHandle).
pub async fn echo_server() -> (SocketAddr, JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind echo");
    let addr = listener.local_addr().expect("echo addr");
    let handle = tokio::spawn(async move {
        loop {
            let Ok((mut sock, _)) = listener.accept().await else {
                return;
            };
            tokio::spawn(async move {
                let mut buf = [0u8; 8192];
                loop {
                    match sock.read(&mut buf).await {
                        Ok(0) | Err(_) => break,
                        Ok(n) => {
                            if sock.write_all(&buf[..n]).await.is_err() {
                                break;
                            }
                        }
                    }
                }
            });
        }
    });
    (addr, handle)
}

/// Send a byte stream to `addr` and read back an equal-length response.
pub async fn echo_round_trip(addr: SocketAddr, payload: &[u8]) -> std::io::Result<Vec<u8>> {
    let mut sock = TcpStream::connect(addr).await?;
    sock.write_all(payload).await?;
    sock.flush().await?;
    let mut received = vec![0u8; payload.len()];
    sock.read_exact(&mut received).await?;
    Ok(received)
}

/// Start a UDP echo server (every received datagram is echoed back verbatim to its source).
pub async fn spawn_udp_echo() -> (SocketAddr, JoinHandle<()>) {
    spawn_udp_echo_with_delay(Duration::ZERO).await
}

/// Start a UDP echo where only the first datagram's reply is delayed.
///
/// Late-reply scenario: the first reply arrives after the session's idle
/// reclamation (dropped via the cleanup path), while subsequent datagrams are
/// answered immediately (verifying the stack stays healthy after cleanup).
pub async fn spawn_udp_echo_first_delayed(delay: Duration) -> (SocketAddr, JoinHandle<()>) {
    let sock = bind_udp("127.0.0.1:0".parse().expect("addr")).expect("bind udp echo");
    let addr = sock.local_addr().expect("udp echo addr");
    let handle = tokio::spawn(async move {
        let mut buf = vec![0u8; 65535];
        let mut first = true;
        loop {
            let Ok((n, peer)) = sock.recv_from(&mut buf).await else {
                return;
            };
            if first {
                first = false;
                tokio::time::sleep(delay).await;
            }
            let _ = sock.send_to(&buf[..n], peer).await;
        }
    });
    (addr, handle)
}

/// Start a delayed-reply UDP echo (the late-reply scenario where replies outlive the session's idle reclamation).
pub async fn spawn_udp_echo_with_delay(delay: Duration) -> (SocketAddr, JoinHandle<()>) {
    let sock = bind_udp("127.0.0.1:0".parse().expect("addr")).expect("bind udp echo");
    let addr = sock.local_addr().expect("udp echo addr");
    let handle = tokio::spawn(async move {
        let mut buf = vec![0u8; 65535];
        loop {
            let Ok((n, peer)) = sock.recv_from(&mut buf).await else {
                return;
            };
            if delay > Duration::ZERO {
                tokio::time::sleep(delay).await;
            }
            let _ = sock.send_to(&buf[..n], peer).await;
        }
    });
    (addr, handle)
}

/// UDP client: send one datagram and wait for the reply (with timeout).
pub async fn udp_round_trip_once(
    sock: &UdpSocket,
    server: SocketAddr,
    payload: &[u8],
    timeout: Duration,
) -> std::io::Result<Vec<u8>> {
    sock.send_to(payload, server).await?;
    let mut buf = vec![0u8; 65535];
    let n = tokio::time::timeout(timeout, sock.recv(&mut buf))
        .await
        .map_err(|_| {
            std::io::Error::new(std::io::ErrorKind::TimedOut, "udp round trip timeout")
        })??;
    Ok(buf[..n].to_vec())
}

/// UDP echo round trip with retries: absorbs agent startup/registration delay (each
/// retry rebuilds the session). Returns the first successful reply.
pub async fn udp_echo_round_trip(
    server: SocketAddr,
    payload: &[u8],
    overall_timeout: Duration,
) -> std::io::Result<Vec<u8>> {
    let deadline = tokio::time::Instant::now() + overall_timeout;
    let sock = bind_udp("127.0.0.1:0".parse().expect("addr"))?;
    loop {
        let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
        if remaining.is_zero() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                "udp echo stack never became ready",
            ));
        }
        match udp_round_trip_once(
            &sock,
            server,
            payload,
            remaining.min(Duration::from_secs(2)),
        )
        .await
        {
            Ok(resp) => return Ok(resp),
            Err(e) if e.kind() == std::io::ErrorKind::TimedOut => {
                tokio::time::sleep(Duration::from_millis(200)).await;
            }
            Err(e) => return Err(e),
        }
    }
}

/// Bind a UDP client socket (concurrent tests need several distinct source ports).
pub async fn udp_client() -> UdpSocket {
    UdpSocket::bind("127.0.0.1:0")
        .await
        .expect("bind udp client")
}

/// Reuse the mesh's UDP socket assembly (with buffers and other settings aligned with production).
pub fn bind_udp(addr: SocketAddr) -> std::io::Result<UdpSocket> {
    interflow_mesh::agent::ingress_udp::bind_udp_socket(addr)
}

// ---------------------------------------------------------------------------
// SSE-style timestamped-chunk backend (for the loss-comparison bench)
// ---------------------------------------------------------------------------

/// Chunk header size in bytes: u64 send-time nanos + u32 sequence number.
pub const CHUNK_HEADER: usize = 12;

fn chunk_epoch() -> Instant {
    static EPOCH: OnceLock<Instant> = OnceLock::new();
    *EPOCH.get_or_init(Instant::now)
}

/// Current time in nanos relative to the in-process chunk epoch (encoded into the chunk header).
///
/// Wire contract: an encoded timestamp is always ≥ 1; 0 is reserved as the
/// "not encoded" sentinel (decoding a never-encoded, all-zero buffer yields ts == 0).
/// `elapsed()` can legitimately read 0 nanoseconds close to the epoch, hence the floor.
pub fn chunk_now_nanos() -> u64 {
    chunk_epoch().elapsed().as_nanos().max(1) as u64
}

/// Convert a nanos value back to an Instant (within the same process).
pub fn chunk_instant(nanos: u64) -> Instant {
    chunk_epoch() + Duration::from_nanos(nanos)
}

/// Encode a chunk: `[u64 send_ts_nanos (>=1)][u32 seq][padding]`.
/// `send_ts_nanos == 0` is rejected: 0 is the reserved not-encoded sentinel
/// (see [`chunk_now_nanos`]).
pub fn encode_chunk(buf: &mut [u8], seq: u32, send_ts_nanos: u64) {
    assert!(
        buf.len() >= CHUNK_HEADER,
        "chunk must be at least {CHUNK_HEADER} bytes"
    );
    assert!(
        send_ts_nanos > 0,
        "send_ts_nanos must be >= 1: 0 is the reserved not-encoded sentinel"
    );
    buf[..8].copy_from_slice(&send_ts_nanos.to_be_bytes());
    buf[8..12].copy_from_slice(&seq.to_be_bytes());
    // Fill with a fixed pattern so content integrity can be verified quickly
    for (i, b) in buf[CHUNK_HEADER..].iter_mut().enumerate() {
        *b = ((seq as usize + i) % 251) as u8;
    }
}

/// Decode a chunk header: `(send_ts_nanos, seq)`.
/// A returned ts == 0 means the buffer was never encoded (reserved sentinel).
pub fn decode_chunk(buf: &[u8]) -> (u64, u32) {
    assert!(
        buf.len() >= CHUNK_HEADER,
        "chunk must be at least {CHUNK_HEADER} bytes"
    );
    let ts = u64::from_be_bytes(buf[..8].try_into().expect("ts bytes"));
    let seq = u32::from_be_bytes(buf[8..12].try_into().expect("seq bytes"));
    (ts, seq)
}

/// Verify a chunk's padding pattern (the `(seq+i)%251` written by [`encode_chunk`]).
/// `Ok(())` = content intact; `Err(off)` = offset of the first mismatched byte in the
/// payload area (after the header).
pub fn verify_chunk_payload(buf: &[u8], seq: u32) -> Result<(), usize> {
    for (i, b) in buf[CHUNK_HEADER..].iter().enumerate() {
        if *b != ((seq as usize + i) % 251) as u8 {
            return Err(i);
        }
    }
    Ok(())
}

/// Backend phase (for the phased SSE backend).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum BackendPhase {
    /// Normal: fixed-size sends on the ticker.
    #[default]
    Normal,
    /// Silent: stop sending but keep the connection alive (the read side keeps discarding as
    /// usual — SSE clients send no upstream data).
    Silent,
}

/// Phase-control handle for the SSE backend (cloneable; watch broadcast, all connections
/// flip simultaneously).
///
/// `burst_chunks` sets how many chunks each connection immediately sends back-to-back on a
/// Silent→Normal flip (default 0 = pure ticker recovery, identical to the unphased version).
#[derive(Clone)]
pub struct SseBackendHandle {
    tx: tokio::sync::watch::Sender<BackendPhase>,
    burst_chunks: std::sync::Arc<std::sync::atomic::AtomicUsize>,
}

impl SseBackendHandle {
    /// Flip the phase on all connections. A Silent→Normal flip immediately sends a burst per connection.
    pub fn set_phase(&self, phase: BackendPhase) {
        let _ = self.tx.send(phase);
    }

    /// Current phase.
    pub fn phase(&self) -> BackendPhase {
        *self.tx.borrow()
    }

    /// Set the burst chunk count for Silent→Normal recovery.
    pub fn set_burst_chunks(&self, n: usize) {
        self.burst_chunks
            .store(n, std::sync::atomic::Ordering::Relaxed);
    }
}

/// SSE-style backend: every connection continuously sends fixed-size timestamped chunks at a
/// fixed interval (no request echo); global phase switching is available via the returned
/// handle (periodic silence/burst, for the soak gate). Per-connection seq increases
/// monotonically from 0 and is never reset across phases — the anchor for the
/// zero-corruption assertion.
pub async fn sse_backend(
    chunk_bytes: usize,
    interval: Duration,
) -> (SocketAddr, SseBackendHandle, JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind sse");
    let addr = listener.local_addr().expect("sse addr");
    let (tx, rx) = tokio::sync::watch::channel(BackendPhase::Normal);
    let burst_chunks = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let handle = SseBackendHandle {
        tx,
        burst_chunks: std::sync::Arc::clone(&burst_chunks),
    };
    let task = tokio::spawn(async move {
        loop {
            let Ok((mut sock, _)) = listener.accept().await else {
                return;
            };
            let mut rx = rx.clone();
            let burst_chunks = std::sync::Arc::clone(&burst_chunks);
            tokio::spawn(async move {
                let mut buf = vec![0u8; chunk_bytes];
                let mut seq: u32 = 0;
                let mut ticker = tokio::time::interval(interval);
                ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
                loop {
                    tokio::select! {
                        _ = ticker.tick() => {
                            if *rx.borrow() == BackendPhase::Normal {
                                encode_chunk(&mut buf, seq, chunk_now_nanos());
                                if sock.write_all(&buf).await.is_err() {
                                    break;
                                }
                                seq = seq.wrapping_add(1);
                            }
                        }
                        changed = rx.changed() => {
                            if changed.is_err() {
                                return; // all handles dropped: nobody controls the phase anymore
                            }
                            if *rx.borrow() == BackendPhase::Normal {
                                // Silent→Normal: immediately burst to fill the silent-window gap
                                let burst =
                                    burst_chunks.load(std::sync::atomic::Ordering::Relaxed);
                                for _ in 0..burst {
                                    encode_chunk(&mut buf, seq, chunk_now_nanos());
                                    if sock.write_all(&buf).await.is_err() {
                                        return;
                                    }
                                    seq = seq.wrapping_add(1);
                                }
                            }
                        }
                    }
                }
            });
        }
    });
    (addr, handle, task)
}
