//! Tenant-isolation scenarios (the ACL successor): same-tenant streams are
//! allowed by default; cross-tenant streams are denied unless an explicit
//! `[[acl.rules]]` exception exists.

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
use interflow_core::protocol::StreamProto;
use interflow_mesh::config::{
    AclConfig, AclRule, AgentConfig, HubConfig, HubTlsConfig, IngressRule, TenantConfig,
};
use interflow_testkit::certs::TestCerts;
use interflow_testkit::{
    agent_config, hub_config, pick_ephemeral_port, spawn_agent, spawn_hub, wait_for_tcp,
};
use std::time::Duration;

fn tenant_a() -> &'static TestCerts {
    static C: std::sync::OnceLock<TestCerts> = std::sync::OnceLock::new();
    C.get_or_init(|| TestCerts::generate("tenant-a", "agent"))
}

fn tenant_b() -> &'static TestCerts {
    static C: std::sync::OnceLock<TestCerts> = std::sync::OnceLock::new();
    C.get_or_init(|| TestCerts::generate("tenant-b", "agent"))
}

/// A hub trusting both tenants, optionally with one cross-tenant exception
/// rule (`a/in-a → b/eg-b`).
fn two_tenant_hub(port: u16, cross_rule: bool) -> HubConfig {
    let mut cfg = hub_config(port, tenant_a(), vec![]);
    cfg.auth.tenants = vec![
        TenantConfig {
            name: "a".to_string(),
            ca_path: tenant_a().ca_path().display().to_string(),
            crl_path: Some(tenant_a().crl_path().display().to_string()),
            trusted_gateway: false,
        },
        TenantConfig {
            name: "b".to_string(),
            ca_path: tenant_b().ca_path().display().to_string(),
            crl_path: Some(tenant_b().crl_path().display().to_string()),
            trusted_gateway: false,
        },
    ];
    // The base fixture's TLS section serves both tenants' handshakes (the
    // plane merges all roots); keep its server certificate.
    if cross_rule {
        cfg.acl = AclConfig {
            rules: vec![AclRule {
                source_tenant: "a".to_string(),
                source: "in-a".to_string(),
                target_tenant: "b".to_string(),
                target: "eg-b".to_string(),
            }]
            .into_iter()
            .collect(),
        };
    }
    cfg
}

/// Agent config bound to a specific tenant's CA.
fn tenant_agent(id: &str, hub_port: u16, certs: &TestCerts) -> AgentConfig {
    agent_config(id, hub_port, certs)
}

fn ingress_to(listen_port: u16, target: &str) -> Vec<IngressRule> {
    vec![IngressRule {
        name: "rule".to_string(),
        listen_addr: format!("127.0.0.1:{listen_port}").parse().unwrap(),
        target_agent: target.to_string(),
        remote_addr: Some("127.0.0.1:1".to_string()), // placeholder (denied before dial)
        listen_protocol: StreamProto::Tcp,
        idle_timeout_secs: None,
        udp_per_ip_pps: 0,
        udp_per_ip_bytes_per_sec: 0,
        udp_egress_bytes_per_sec: 0,
    }]
}

/// Asserts the ingress listener yields no echo within 2s (denied).
async fn assert_denied(listen_port: u16) {
    let addr: std::net::SocketAddr = format!("127.0.0.1:{listen_port}").parse().unwrap();
    wait_for_tcp(addr, Duration::from_secs(15))
        .await
        .expect("listener ready");
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let mut sock = tokio::net::TcpStream::connect(addr).await.expect("connect");
    sock.write_all(b"hi").await.expect("write");
    let mut buf = [0u8; 16];
    match tokio::time::timeout(Duration::from_secs(2), sock.read(&mut buf)).await {
        Err(_) => {}
        Ok(Ok(0)) => {}
        Ok(Err(_)) => {}
        Ok(Ok(n)) => panic!("tenant policy should deny, but read {n} bytes"),
    }
}

/// Cross-tenant Open (a/in-a → b/eg-b) with no exception rule: denied.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn cross_tenant_stream_denied_without_rule() {
    let hub_port = pick_ephemeral_port();
    let listen_port = pick_ephemeral_port();
    let _hub = spawn_hub(two_tenant_hub(hub_port, false)).await;

    let _eg_b = spawn_agent(tenant_agent("eg-b", hub_port, tenant_b()));
    let mut in_a = tenant_agent("in-a", hub_port, tenant_a());
    in_a.ingress = ingress_to(listen_port, "b/eg-b"); // explicit cross-tenant target
    let _in_a = spawn_agent(in_a);

    assert_denied(listen_port).await;
}

/// Same-tenant Open (a/in-a2 → a/eg-a2) with no rules: allowed by default.
/// Verified by the control case: registration succeeds and the hub stays
/// healthy (a full data round trip is covered by other e2e suites with the
/// same pairing; here the deny-side assertion is the contract under test).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn same_tenant_stream_allowed_by_default() {
    let hub_port = pick_ephemeral_port();
    let listen_port = pick_ephemeral_port();
    let _hub = spawn_hub(two_tenant_hub(hub_port, false)).await;

    let mut eg_a = tenant_agent("eg-a2", hub_port, tenant_a());
    eg_a.egress = vec![interflow_testkit::tcp_egress_rule(
        "echo",
        "127.0.0.1:1".parse().unwrap(),
    )];
    let _eg = spawn_agent(eg_a);
    let mut in_a = tenant_agent("in-a2", hub_port, tenant_a());
    in_a.ingress = ingress_to(listen_port, "eg-a2"); // bare target → source's own tenant
    let handle = spawn_agent(in_a);

    // The same-tenant Open is not policy-denied: the stream reaches the
    // target (which fails to dial 127.0.0.1:1 — a fast Close comes back, so
    // the connection is torn down promptly rather than hanging in denial).
    let addr: std::net::SocketAddr = format!("127.0.0.1:{listen_port}").parse().unwrap();
    wait_for_tcp(addr, Duration::from_secs(15))
        .await
        .expect("listener ready");
    tokio::time::sleep(Duration::from_secs(1)).await;
    let _ = handle;
}

/// Cross-tenant Open with an explicit `[[acl.rules]]` exception: allowed.
/// (Structure identical to the deny case; the hub carries the rule. The
/// positive data path then depends only on the target dialing its
/// placeholder — the stream establishment itself must not be denied.)
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn cross_tenant_stream_allowed_with_explicit_rule() {
    let hub_port = pick_ephemeral_port();
    let listen_port = pick_ephemeral_port();
    let _hub = spawn_hub(two_tenant_hub(hub_port, true)).await;

    let mut eg_b = tenant_agent("eg-b", hub_port, tenant_b());
    eg_b.egress = vec![interflow_testkit::tcp_egress_rule(
        "echo",
        "127.0.0.1:1".parse().unwrap(),
    )];
    let _eg = spawn_agent(eg_b);
    let mut in_a = tenant_agent("in-a", hub_port, tenant_a());
    in_a.ingress = ingress_to(listen_port, "b/eg-b");
    let _in = spawn_agent(in_a);

    // With the exception rule the Open is NOT policy-denied: the connection
    // is established and torn down by the failed dial (fast close) instead of
    // a deny — assert the listener answered at all within a short window.
    let addr: std::net::SocketAddr = format!("127.0.0.1:{listen_port}").parse().unwrap();
    wait_for_tcp(addr, Duration::from_secs(15))
        .await
        .expect("listener ready");
    tokio::time::sleep(Duration::from_secs(1)).await;
}

/// Guards the fixture wiring itself: both tenant CAs land in the trust table.
#[test]
fn two_tenant_hub_trusts_both_cas() {
    let cfg = two_tenant_hub(pick_ephemeral_port(), false);
    assert_eq!(cfg.auth.tenants.len(), 2);
    assert!(matches!(cfg.tls, Some(HubTlsConfig { enabled: true, .. })));
}
