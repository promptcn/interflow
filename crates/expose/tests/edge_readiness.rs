//! e2e: edge readiness signal — `run_until_signalled` fires only once both
//! listener faces (public listener + control endpoint) are bound. This is
//! the readiness channel that replaced TCP liveness probing (`node install`
//! and the GUI's ingress engine used to synthesize connections to learn
//! this); the test asserts the signal fires promptly AND is honest — both
//! ports actually accept by the time it does.

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
use interflow_expose::edge::{
    ControlEndpointTls, EdgeConfig, EdgeListenerPolicy, IngressPrincipal, Route, WorkspaceTrust,
};
use std::time::Duration;
use tokio_util::sync::CancellationToken;

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn readiness_signal_fires_once_both_listener_faces_accept() {
    let _ = tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "info,interflow=debug".into()),
        )
        .try_init();

    let certs = interflow_testkit::certs::TestCerts::generate("e2e", "readiness-test");
    let (principal_cert, principal_key) = certs.named_client_cert("edge");
    let edge_config = EdgeConfig {
        // :0 = kernel-assigned; the readiness signal carries the bound
        // addresses.
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
            agent_id: "readiness-test".to_string(),
            service_id: "web".to_string(),
        }],
        listener: EdgeListenerPolicy::default(),
        agent_recovery_timeout: Duration::from_secs(120),
        ..EdgeConfig::default()
    };

    let (ready_tx, ready_rx) = tokio::sync::oneshot::channel();
    let token = CancellationToken::new();
    let edge_handle = tokio::task::spawn(interflow_expose::edge::run_until_signalled(
        edge_config,
        token.clone(),
        ready_tx,
    ));

    // The signal itself — the whole point of the change.
    let ready = tokio::time::timeout(Duration::from_secs(10), ready_rx)
        .await
        .expect("readiness signal within 10s")
        .expect("edge run must not end before signalling readiness");
    let (edge_listen, hub_listen) = (ready.public, ready.control);

    // Honesty check: by ready-time both faces accept a TCP connection
    // (short budgets — they must already be up, not merely soon).
    interflow_testkit::wait_for_tcp(hub_listen, Duration::from_secs(1))
        .await
        .expect("control endpoint accepting at ready-time");
    interflow_testkit::wait_for_tcp(edge_listen, Duration::from_secs(1))
        .await
        .expect("public listener accepting at ready-time");

    token.cancel();
    let outcome = tokio::time::timeout(Duration::from_secs(10), edge_handle)
        .await
        .expect("edge exits within 10s of cancellation")
        .expect("edge task joins");
    assert!(outcome.is_ok(), "cancelled run resolves Ok: {outcome:?}");
}
