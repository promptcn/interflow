//! RPS / latency benchmark for the expose scenario.
//!
//! Starts edge + expose client + echo backend in a single process, sends N
//! HTTP/1.1 requests, and measures RPS and p99 latency. Used to evaluate the
//! request-handling capacity of the edge public entry point.
//!
//! Run: `cargo bench -p interflow-expose --bench expose_rps`

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

use criterion::{Criterion, Throughput, criterion_group, criterion_main};
use std::net::SocketAddr;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::task::JoinHandle;

const CONCURRENCIES: &[usize] = &[1, 10, 50];

fn bench_expose_rps(c: &mut Criterion) {
    let rt = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(8)
        .enable_all()
        .build()
        .expect("tokio runtime");
    let _guard = rt.enter();

    let (edge_listen, _edge, _client, _echo) = rt.block_on(async { setup::spawn_stack().await });

    let request = b"GET / HTTP/1.1\r\nHost: test.local\r\nConnection: close\r\n\r\n";

    let mut group = c.benchmark_group("expose_rps");
    for &c in CONCURRENCIES {
        group.throughput(Throughput::Elements(1));
        group.sample_size(if c >= 50 { 20 } else { 50 });

        group.bench_function(format!("c{c}"), |b| {
            b.to_async(&rt).iter(|| async move {
                // Each round opens c connections per the concurrency level,
                // fires requests simultaneously, then waits for all of them
                let mut handles = Vec::with_capacity(c);
                for _ in 0..c {
                    let addr = edge_listen;
                    handles.push(tokio::spawn(async move {
                        let mut sock = TcpStream::connect(addr).await.expect("connect edge");
                        sock.write_all(request).await.expect("write req");
                        sock.flush().await.expect("flush");
                        // Read back the request bytes echoed by the echo backend
                        let mut resp = vec![0u8; request.len()];
                        sock.read_exact(&mut resp).await.expect("read resp");
                    }));
                }
                for h in handles {
                    h.await.expect("conn task");
                }
            });
        });
    }
    group.finish();
}

mod setup {
    use super::*;
    use interflow_expose::client::ExposeArgs;
    use interflow_expose::edge::{EdgeArgs, Route, RoutesConfig};
    use interflow_mesh::config::TransportKind;

    pub async fn spawn_stack() -> (
        SocketAddr,
        JoinHandle<interflow_core::error::Result<()>>,
        JoinHandle<Result<(), interflow_core::error::InterflowError>>,
        JoinHandle<()>,
    ) {
        // echo backend
        let echo_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let echo_addr = echo_listener.local_addr().unwrap();
        let echo_handle = tokio::spawn(async move {
            loop {
                let Ok((mut sock, _)) = echo_listener.accept().await else {
                    return;
                };
                tokio::spawn(async move {
                    let mut buf = [0u8; 1024];
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

        let edge_port = pick_port();
        let hub_port = pick_port();
        let edge_listen: SocketAddr = format!("127.0.0.1:{edge_port}").parse().unwrap();
        let hub_listen: SocketAddr = format!("127.0.0.1:{hub_port}").parse().unwrap();

        // Construct RoutesConfig directly; no file read
        let routes = RoutesConfig {
            routes: vec![Route {
                host: "test.local".into(),
                agent_id: "expose-test".into(),
                remote_addr: echo_addr,
            }],
        };
        let routes_path = std::env::temp_dir().join(format!(
            "interflow_bench_routes_{}.toml",
            uuid::Uuid::new_v4()
        ));
        let routes_str = toml::to_string(&routes).expect("serialize routes");
        std::fs::write(&routes_path, &routes_str).expect("write routes.toml");

        let edge_args = EdgeArgs {
            listen_addr: edge_listen,
            hub_listen_addr: hub_listen,
            routes_path: routes_path.to_string_lossy().into_owned(),
            agent_token: "test-token".into(),
            hub_tls: None,
            quic_listen: None,
            audit_path: None,
            new_conn_rate_per_ip_per_minute: 0,
            stream_idle_timeout_secs: 300,
            route_breaker_enabled: true,
            route_breaker_failure_threshold: 10,
            route_breaker_window_secs: 60,
            route_breaker_cooldown_secs: 30,
            agent_recovery_timeout_secs: 120,
        };
        let edge_handle = tokio::task::spawn(interflow_expose::edge::run(edge_args));

        // Wait for the edge listener to be ready
        wait_for_tcp(edge_listen, Duration::from_secs(5))
            .await
            .expect("edge listener should start within 5s");
        wait_for_tcp(hub_listen, Duration::from_secs(5))
            .await
            .expect("hub should start within 5s");

        let client_args = ExposeArgs {
            local_ports: vec![echo_addr.port()],
            hub_url: format!("http://127.0.0.1:{hub_port}"),
            auth_token: "test-token".into(),
            agent_id: "expose-test".into(),
            ca_path: None,
            transport: TransportKind::H2,
            hub_quic_addr: None,
        };
        let client_handle = tokio::task::spawn(async move {
            interflow_expose::client::start(&client_args)?.join().await
        });

        // Wait for the agent to register
        tokio::time::sleep(Duration::from_millis(500)).await;

        // The routes file can be deleted after reading (edge already loaded
        // it into memory at startup)
        let _ = std::fs::remove_file(&routes_path);

        (edge_listen, edge_handle, client_handle, echo_handle)
    }

    fn pick_port() -> u16 {
        let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        l.local_addr().unwrap().port()
    }

    async fn wait_for_tcp(addr: SocketAddr, timeout: Duration) -> std::io::Result<()> {
        let deadline = tokio::time::Instant::now() + timeout;
        loop {
            match TcpStream::connect(addr).await {
                Ok(_) => return Ok(()),
                Err(e) => {
                    if tokio::time::Instant::now() >= deadline {
                        return Err(e);
                    }
                    tokio::time::sleep(Duration::from_millis(50)).await;
                }
            }
        }
    }
}

criterion_group!(benches, bench_expose_rps);
criterion_main!(benches);
