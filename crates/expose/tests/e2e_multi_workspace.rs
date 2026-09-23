//! Multi-workspace ingress: one tunnel session (and principal) per
//! authorized workspace; each public host routes through its own
//! workspace's session.
//!
//! The hub's inter-workspace deny policy makes correct session selection
//! observable: if host `a.local` were dialed through workspace B's session,
//! the Open (`test-a/agent-a` from tenant `test-b`) would find no target and
//! the connection would close — so a clean round trip per host proves the
//! per-workspace wiring end to end.

use interflow_expose::client::{ExposeArgs, LocalService};
use interflow_expose::edge::{
    ControlEndpointTls, EdgeConfig, IngressPrincipal, Route, WorkspaceTrust,
};
use interflow_mesh::config::TransportKind;
use std::net::SocketAddr;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn routes_select_their_own_workspace_session() {
    let _ = tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info,interflow=debug")),
        )
        .try_init();

    // Two isolated workspaces: each its own issuer (CA), principal, agent,
    // and echo backend.
    let certs_a = interflow_testkit::certs::TestCerts::generate("ws-a", "agent-a");
    let certs_b = interflow_testkit::certs::TestCerts::generate("ws-b", "agent-b");
    let (echo_a, _echo_a_task) = interflow_testkit::echo_server().await;
    let (echo_b, _echo_b_task) = interflow_testkit::echo_server().await;
    let edge_port = interflow_testkit::pick_ephemeral_port();
    let hub_port = interflow_testkit::pick_ephemeral_port();
    let edge_listen: SocketAddr = format!("127.0.0.1:{edge_port}").parse().unwrap();
    let hub_listen: SocketAddr = format!("127.0.0.1:{hub_port}").parse().unwrap();

    // Workspace-scoped ingress principals (CN `edge`, each signed by its
    // own workspace's issuer).
    let mut principals = Vec::new();
    for (certs, workspace) in [(&certs_a, "test-a"), (&certs_b, "test-b")] {
        let (cert, key) = certs.named_client_cert("edge");
        principals.push(IngressPrincipal {
            workspace: workspace.to_string(),
            cert,
            key,
        });
    }

    let edge_config = EdgeConfig {
        listen_addr: edge_listen,
        control_listen_addr: hub_listen,
        control_tls: ControlEndpointTls {
            cert: certs_a.server_cert_path(),
            key: certs_a.server_key_path(),
        },
        workspace_trust: vec![
            WorkspaceTrust {
                workspace: "test-a".to_string(),
                ca: certs_a.ca_path(),
            },
            WorkspaceTrust {
                workspace: "test-b".to_string(),
                ca: certs_b.ca_path(),
            },
        ],
        principals,
        routes: vec![
            Route {
                host: "a.local".to_string(),
                workspace: "test-a".to_string(),
                agent_id: "agent-a".to_string(),
                service_id: "web".to_string(),
            },
            Route {
                host: "b.local".to_string(),
                workspace: "test-b".to_string(),
                agent_id: "agent-b".to_string(),
                service_id: "web".to_string(),
            },
        ],
        agent_recovery_timeout: Duration::from_secs(120),
        ..EdgeConfig::default()
    };
    tokio::task::spawn(interflow_expose::edge::run(edge_config));

    interflow_testkit::wait_for_tcp(hub_listen, Duration::from_secs(5))
        .await
        .expect("control endpoint should start within 5s");
    interflow_testkit::wait_for_tcp(edge_listen, Duration::from_secs(5))
        .await
        .expect("edge listener should start within 5s");

    // One egress agent per workspace. Both verify the control endpoint via
    // workspace A's CA (the control cert is issued by it) and anchor their
    // inner TLS on their own workspace's issuer.
    for (certs, agent_id, workspace) in [
        (&certs_a, "agent-a", "test-a"),
        (&certs_b, "agent-b", "test-b"),
    ] {
        let (cert, key) = certs.client_paths();
        let args = ExposeArgs {
            log_name: None,
            services: vec![LocalService {
                id: "web".to_string(),
                target_addr: if workspace == "test-a" {
                    echo_a
                } else {
                    echo_b
                },
                overridden: false,
            }],
            hub_url: format!("https://127.0.0.1:{hub_port}"),
            client_cert: Some(cert.display().to_string()),
            client_key: Some(key.display().to_string()),
            agent_id: agent_id.to_string(),
            ca_path: Some(certs_a.ca_path().display().to_string()),
            ingress_ca_path: Some(certs.ca_path().display().to_string()),
            transport: TransportKind::H2,
            hub_quic_addr: None,
        };
        let client = interflow_expose::client::start(&args).expect("agent start");
        assert!(
            interflow_testkit::wait_agent_connected(&client, Duration::from_secs(5)).await,
            "{agent_id} should register within 5s"
        );
        tokio::task::spawn(async move {
            let _ = client.join().await;
        });
    }

    // Each host round-trips through its own workspace's session + backend;
    // a misrouted session would be denied cross-workspace by the hub and
    // close without bytes.
    for host in ["a.local", "b.local"] {
        let mut sock = TcpStream::connect(edge_listen).await.expect("connect edge");
        let request = format!("GET / HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n");
        sock.write_all(request.as_bytes())
            .await
            .expect("write request");
        let mut response = vec![0u8; request.len()];
        tokio::time::timeout(Duration::from_secs(3), sock.read_exact(&mut response))
            .await
            .expect("read should not timeout")
            .expect("read_exact should succeed");
        assert_eq!(
            response,
            request.into_bytes(),
            "host {host} should round-trip through its own workspace session"
        );
    }
}
