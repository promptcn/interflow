//! e2e: the edge's per-client new-connection limiter under VISITOR-IDENTITY
//! churn ((internal design notes), the edge
//! face): a thousand clients the listener has never seen, each presenting
//! once through the standard fronted topology (trusted loopback proxy +
//! `X-Forwarded-For`), against a deployment-sized tracked-client bound
//! (`EdgeListenerPolicy::max_tracked_clients`).
//!
//! What this locks, on the production metrics path:
//! - the limiter's tracked population never exceeds its configured bound
//!   (`interflow_rate_limit_tracked_clients{limiter="edge_new_conn"}`);
//! - the capacity path runs for real — generations overflow and evict
//!   (`interflow_rate_limit_capacity_evictions`);
//! - pressure past the bound never refuses a newcomer: every one of the
//!   churned clients is routed (the degradation forgets idle clients'
//!   debt, it does not turn visitors away).
//!
//! The recede half (idle two rotation periods, sweep, population back
//! near the sweep) needs ~2 real minutes on a per-minute quota and lives
//! in the soak gate's identity-churn phase; the store's rotation
//! arithmetic itself is pinned by core's `rate_limit::tests`.

#![allow(
    clippy::all,
    clippy::pedantic,
    clippy::nursery,
    clippy::panic,
    clippy::unwrap_used,
    clippy::expect_used,
    missing_docs
)]
use interflow_core::security::{ProxyProtocolConfig, ProxyProtocolMode, XffMode};
use interflow_expose::client::ExposeArgs;
use interflow_expose::edge::{
    ControlEndpointTls, EdgeConfig, EdgeListenerPolicy, IngressPrincipal, Route, WorkspaceTrust,
};
use interflow_mesh::config::TransportKind;
use interflow_testkit::metrics_harness::{counter_value, gauge_value, init_tracing};
use std::net::{Ipv4Addr, SocketAddr};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

/// The bound under test: 256 → 8 keys per generation per shard, so a
/// thousand distinct clients (≈64 per shard) overflow every shard's
/// generation several times over.
const MAX_TRACKED_CLIENTS: usize = 256;
const CHURNED_CLIENTS: u32 = 1_024;

const TRACKED_GAUGE: &str = "interflow_rate_limit_tracked_clients{limiter=\"edge_new_conn\"}";
const EVICTIONS_COUNTER: &str = "interflow_rate_limit_capacity_evictions";

/// Edge + expose client + echo backend behind a trusted loopback "proxy":
/// the fronted topology, with a small tracked-client bound.
async fn spawn_stack() -> SocketAddr {
    let echo_addr = interflow_testkit::echo_server().await.0;
    let certs = interflow_testkit::certs::TestCerts::generate("e2e", "expose-test");
    let (principal_cert, principal_key) = certs.named_client_cert("edge");
    let edge_config = EdgeConfig {
        listen_addr: "127.0.0.1:0".parse().unwrap(),
        control_listen_addr: "127.0.0.1:0".parse().unwrap(),
        control_tls: ControlEndpointTls {
            cert: certs.server_cert_path(),
            key: certs.server_key_path(),
        },
        workspace_trust: vec![WorkspaceTrust {
            workspace: "test".to_string(),
            ca: certs.ca_path(),
        }],
        principals: vec![IngressPrincipal {
            workspace: "test".to_string(),
            cert: principal_cert,
            key: principal_key,
        }],
        routes: vec![Route {
            host: "test.local".to_string(),
            workspace: "test".to_string(),
            agent_id: "expose-test".to_string(),
            service_id: "web".to_string(),
        }],
        audit_path: None,
        listener: EdgeListenerPolicy {
            proxy_protocol: ProxyProtocolConfig {
                mode: ProxyProtocolMode::Off,
                trusted_proxies: vec!["127.0.0.1".to_string()],
            },
            x_forwarded_for: XffMode::Required,
            // Generous per-client quota: every churned client spends one
            // cell of its own budget; the pressure is on the population,
            // not the rate.
            new_conn_rate_per_ip_per_minute: 600,
            max_tracked_clients: MAX_TRACKED_CLIENTS,
            ..EdgeListenerPolicy::default()
        },
        agent_recovery_timeout: Duration::from_secs(120),
        ..EdgeConfig::default()
    };
    let edge = interflow_testkit::spawn_edge(edge_config).await;
    let edge_listen = edge.public_addr();
    let hub_port = edge.control_addr().port();

    let (client_cert, client_key) = certs.client_paths();
    let client_args = ExposeArgs {
        log_name: None,
        service_addresses: interflow_mesh::config::ServiceAddresses::of(&[("web", echo_addr)], &[]),
        pack_dir: None,
        hub_url: format!("https://127.0.0.1:{hub_port}"),
        client_cert: Some(client_cert.display().to_string()),
        client_key: Some(client_key.display().to_string()),
        agent_id: "expose-test".into(),
        ingress_ca_path: Some(certs.ca_path().display().to_string()),
        ca_path: Some(certs.ca_path().display().to_string()),
        transport: TransportKind::H2,
        hub_quic_addr: None,
        identity_offline: false,
        renewal_face: None,
    };
    let client = interflow_expose::client::start(&client_args).expect("expose client start");
    assert!(
        interflow_testkit::wait_agent_connected(&client, Duration::from_secs(5)).await,
        "expose client should register within 5s"
    );
    tokio::task::spawn(async move { client.join().await });
    edge_listen
}

/// One connection from `client` (the right-most XFF entry the trusted
/// proxy appends) carrying a request for a host no route serves: the
/// connection passes the real-IP restoration and the limiter gate, is
/// counted at the route lookup (`interflow_edge_no_route`) and closed —
/// the gate is exercised without touching the data plane. (A thousand
/// sequential ROUTED one-shot connections would instead race the
/// hub's per-agent stream accounting — close propagation lags opens —
/// which is stream-cap behavior, not the limiter's.)
async fn present_client(edge: SocketAddr, client: Ipv4Addr) -> Result<(), String> {
    let mut sock = TcpStream::connect(edge)
        .await
        .map_err(|e| format!("connect: {e}"))?;
    let req = format!(
        "GET / HTTP/1.1\r\nHost: churn.invalid\r\nX-Forwarded-For: {client}\r\nConnection: close\r\n\r\n"
    );
    sock.write_all(req.as_bytes())
        .await
        .map_err(|e| format!("write: {e}"))?;
    // Drain to the close (the no-route answer is a bare close).
    let mut buf = [0u8; 256];
    while let Ok(n) = sock.read(&mut buf).await {
        if n == 0 {
            break;
        }
    }
    Ok(())
}

/// One ROUTED request from `client`: `true` = the echo backend mirrored
/// it (the data plane is alive and the limiter admitted the client).
async fn request_routes_as(edge: SocketAddr, client: Ipv4Addr) -> bool {
    let Ok(mut sock) = TcpStream::connect(edge).await else {
        return false;
    };
    let req = format!(
        "GET / HTTP/1.1\r\nHost: test.local\r\nX-Forwarded-For: {client}\r\nConnection: close\r\n\r\n"
    );
    if sock.write_all(req.as_bytes()).await.is_err() {
        return false;
    }
    let mut buf = [0u8; 512];
    match sock.read(&mut buf).await {
        Ok(n) if n > 0 => !String::from_utf8_lossy(&buf[..n]).starts_with("HTTP/1.1 429"),
        _ => false,
    }
}

#[tokio::test]
async fn tracked_clients_stay_bounded_and_newcomers_are_never_refused_under_identity_churn() {
    init_tracing();
    let edge = spawn_stack().await;

    // A walk through 198.18.0.0/15 (the RFC 2544 benchmark range): every
    // client a different /32, none ever seen before, none ever seen again.
    let gate_denials_before = counter_value("interflow_edge_conn_rate_limited");
    let no_route_before = counter_value("interflow_edge_no_route");
    for i in 0..CHURNED_CLIENTS {
        let client = Ipv4Addr::from(u32::from_be_bytes([198, 18, 0, 1]) + i);
        present_client(edge, client)
            .await
            .unwrap_or_else(|e| panic!("presenting client {client}: {e}"));
    }
    // Every client reached the route lookup — i.e. passed the limiter gate
    // — and the gate denied none of them: pressure past the bound forgets
    // idle clients' debt, it never turns a newcomer away.
    assert_eq!(
        counter_value("interflow_edge_no_route") - no_route_before,
        u64::from(CHURNED_CLIENTS),
        "every churned client passed the gate and reached the route lookup"
    );
    assert_eq!(
        counter_value("interflow_edge_conn_rate_limited") - gate_denials_before,
        0,
        "capacity pressure must never refuse a newcomer"
    );

    let tracked = gauge_value(TRACKED_GAUGE).expect("the limiter exports its population");
    assert!(
        tracked <= MAX_TRACKED_CLIENTS as f64,
        "tracked clients {tracked} must stay within the bound {MAX_TRACKED_CLIENTS} after \
         {CHURNED_CLIENTS} distinct visitors"
    );
    assert!(
        tracked > 0.0,
        "the population is live (the churn's last generation is still tracked)"
    );
    let evictions = counter_value(EVICTIONS_COUNTER);
    assert!(
        evictions >= 1,
        "a thousand visitors against a bound of {MAX_TRACKED_CLIENTS} must overflow generations \
         and evict: counter {evictions}"
    );
    // The arithmetic the counter should reflect: each of the 16 shards saw
    // ~64 clients against a generation capacity of 8, so forced rotations
    // evicted whole previous generations many times over.
    assert!(
        evictions as usize >= MAX_TRACKED_CLIENTS,
        "evictions {evictions} — at least one full bound's worth of generations was forgotten"
    );

    // The data plane is untouched by the churn: a real client still routes.
    assert!(
        request_routes_as(edge, Ipv4Addr::new(203, 0, 113, 9)).await,
        "a routed request after the churn still reaches the backend"
    );
}
