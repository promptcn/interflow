//! E2E: `GET /agents` is tenant-scoped observability (THREAT_MODEL §6.5):
//! an identity sees its own tenant's list only — a cross-tenant list is
//! reconnaissance material (which agent ids exist, on which tenant).
//!
//! Regression shape (fails-before-fix against the pre-scoping handler that
//! returned the whole registry): a hub trusting two tenant CAs, one agent
//! registered under each; each connection's `/agents` must contain its own
//! tenant's qualified key and must not leak the other tenant's.
//!
//! This file is also where the `/agents` wire contract is pinned (the
//! `leaf_expiry` credential-health object of 56ecddf), via the typed
//! consumer mirror in `interflow_testkit::hub_http`.

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
use hyper::Request;
use hyper::client::conn::http2::SendRequest;
use hyper_util::rt::{TokioExecutor, TokioIo};
use interflow_core::tunnel::H2RequestBody;
use interflow_mesh::config::{HeartbeatConfig, HubSecurityConfig, TenantConfig};
use interflow_mesh::hub::qualified_agent_id;
use interflow_testkit::certs::TestCerts;
use interflow_testkit::{
    LeafPhaseWire, TEST_TENANT, has_agent, hub_config_tuned, list_agents, spawn_hub,
    tls_client_connect_with,
};

fn tenant_a_certs() -> &'static TestCerts {
    static C: std::sync::OnceLock<TestCerts> = std::sync::OnceLock::new();
    C.get_or_init(|| TestCerts::generate("scoping-a", "one"))
}

fn tenant_b_certs() -> &'static TestCerts {
    static C: std::sync::OnceLock<TestCerts> = std::sync::OnceLock::new();
    C.get_or_init(|| TestCerts::generate("scoping-b", "two"))
}

/// Connect an mTLS h2 client under `tenant_certs`, trusting the hub server
/// via `server_ca` (both tenants' agents verify the same hub certificate —
/// only the *client* chains differ per tenant).
async fn connect(
    port: u16,
    server_ca: &TestCerts,
    tenant_certs: &TestCerts,
    cn: &str,
) -> SendRequest<H2RequestBody> {
    let (cert, key) = tenant_certs.named_client_cert(cn);
    let (send_request, conn) = hyper::client::conn::http2::Builder::new(TokioExecutor::new())
        .handshake::<_, H2RequestBody>(TokioIo::new(
            tls_client_connect_with(
                &server_ca.ca_path(),
                &cert,
                &key,
                "localhost",
                format!("127.0.0.1:{port}").parse().unwrap(),
            )
            .await
            .expect("tls"),
        ))
        .await
        .expect("handshake");
    tokio::spawn(async move {
        let _ = conn.await;
    });
    send_request
}

async fn register(snd: &mut SendRequest<H2RequestBody>, id: &str) -> hyper::StatusCode {
    snd.ready().await.expect("ready");
    let req = Request::builder()
        .method("POST")
        .uri("/register")
        .header("x-agent-id", id)
        .body(interflow_core::tunnel::empty_request_body())
        .unwrap();
    snd.send_request(req).await.expect("register").status()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn agents_listing_is_tenant_scoped() {
    let mut cfg = hub_config_tuned(
        0,
        tenant_a_certs(),
        vec![],
        HubSecurityConfig::default(),
        HeartbeatConfig::default(),
    );
    // Second tenant anchored at the other TestCerts CA; the hub server
    // certificate stays tenant-a's (server identity is orthogonal to the
    // client trust table).
    cfg.auth.tenants.push(TenantConfig {
        name: "other".to_string(),
        ca_path: tenant_b_certs().ca_path().display().to_string(),
        crl_path: Some(tenant_b_certs().crl_path().display().to_string()),
        trusted_gateway: false,
    });
    let port = spawn_hub(cfg).await.local_addr().expect("hub bound").port();

    let mut a = connect(port, tenant_a_certs(), tenant_a_certs(), "one").await;
    assert_eq!(register(&mut a, "one").await, 200);
    let mut b = connect(port, tenant_a_certs(), tenant_b_certs(), "two").await;
    assert_eq!(register(&mut b, "two").await, 200);

    let own_key = qualified_agent_id(TEST_TENANT, "one");
    let other_key = qualified_agent_id("other", "two");

    let list_a = list_agents(&mut a).await;
    assert!(
        has_agent(&list_a, &own_key),
        "an identity should see its own tenant's agents: {list_a:?}"
    );
    assert!(
        !has_agent(&list_a, &other_key),
        "tenant `{TEST_TENANT}` must not observe other-tenant agents: {list_a:?}"
    );

    // Pin the 56ecddf wire contract alongside the scoping semantics: the
    // curl-able credential-health object (testkit leaves are issued at
    // ~96% remaining — deterministically `healthy`).
    let own = list_a
        .iter()
        .find(|e| e.agent == own_key)
        .expect("own entry (presence asserted above)");
    let expiry = own
        .leaf_expiry
        .as_ref()
        .expect("testkit leaves parse, so leaf_expiry is present");
    assert_eq!(expiry.phase, LeafPhaseWire::Healthy);
    assert!(
        expiry.remaining_secs > 0,
        "a freshly issued leaf must report positive remaining time"
    );

    let list_b = list_agents(&mut b).await;
    assert!(
        has_agent(&list_b, &other_key),
        "an identity should see its own tenant's agents: {list_b:?}"
    );
    assert!(
        !has_agent(&list_b, &own_key),
        "tenant `other` must not observe `{TEST_TENANT}` agents: {list_b:?}"
    );
}
