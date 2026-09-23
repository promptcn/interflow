//! E2E: `GET /agents` is tenant-scoped observability (THREAT_MODEL §6.5):
//! an identity sees its own tenant's list only — a cross-tenant list is
//! reconnaissance material (which agent ids exist, on which tenant).
//!
//! Regression shape (fails-before-fix against the pre-scoping handler that
//! returned the whole registry): a hub trusting two tenant CAs, one agent
//! registered under each; each connection's `/agents` must contain its own
//! tenant's qualified key and must not leak the other tenant's.

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
use http_body_util::BodyExt;
use hyper::client::conn::http2::SendRequest;
use hyper::{Request, Response};
use hyper_util::rt::{TokioExecutor, TokioIo};
use interflow_core::tunnel::H2RequestBody;
use interflow_mesh::config::{HeartbeatConfig, HubSecurityConfig, TenantConfig};
use interflow_mesh::hub::qualified_agent_id;
use interflow_testkit::certs::TestCerts;
use interflow_testkit::{
    TEST_TENANT, hub_config_tuned, pick_ephemeral_port, spawn_hub, tls_client_connect_with,
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

async fn list_agents(snd: &mut SendRequest<H2RequestBody>) -> Vec<String> {
    snd.ready().await.expect("ready");
    let req = Request::builder()
        .method("GET")
        .uri("/agents")
        .body(interflow_core::tunnel::empty_request_body())
        .unwrap();
    let resp: Response<hyper::body::Incoming> = snd.send_request(req).await.expect("agents");
    assert!(
        resp.status().is_success(),
        "authenticated identity should be able to list its own tenant"
    );
    let body = resp.into_body().collect().await.expect("body").to_bytes();
    serde_json::from_slice(&body).expect("agents json")
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn agents_listing_is_tenant_scoped() {
    let port = pick_ephemeral_port();
    let mut cfg = hub_config_tuned(
        port,
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
    spawn_hub(cfg).await;

    let mut a = connect(port, tenant_a_certs(), tenant_a_certs(), "one").await;
    assert_eq!(register(&mut a, "one").await, 200);
    let mut b = connect(port, tenant_a_certs(), tenant_b_certs(), "two").await;
    assert_eq!(register(&mut b, "two").await, 200);

    let own_key = qualified_agent_id(TEST_TENANT, "one");
    let other_key = qualified_agent_id("other", "two");

    let list_a = list_agents(&mut a).await;
    assert!(
        list_a.contains(&own_key),
        "an identity should see its own tenant's agents: {list_a:?}"
    );
    assert!(
        !list_a.contains(&other_key),
        "tenant `{TEST_TENANT}` must not observe other-tenant agents: {list_a:?}"
    );

    let list_b = list_agents(&mut b).await;
    assert!(
        list_b.contains(&other_key),
        "an identity should see its own tenant's agents: {list_b:?}"
    );
    assert!(
        !list_b.contains(&own_key),
        "tenant `other` must not observe `{TEST_TENANT}` agents: {list_b:?}"
    );
}
