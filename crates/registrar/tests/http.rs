//! HTTP/mTLS smoke test for the registrar lifecycle.

use interflow_identity::issuance::{IssuerStore, LeafTtl, generate_csr};
use interflow_identity::{PrincipalKind, PrincipalPath};
use interflow_registrar::EnrollmentCodes;
use serde_json::Value;
use std::net::TcpListener;
use std::path::{Path, PathBuf};
use std::sync::Arc;

/// Serializes the tests: the fault hook is process-global (the same
/// discipline as core's fault tests), so the happy-path case must not race
/// an armed plan.
static SERIAL: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

/// A live in-process registrar: tempdir + endpoint + realm CA PEM.
struct Registrar {
    #[expect(dead_code, reason = "holds the tempdir alive for the test body")]
    dir: tempfile::TempDir,
    endpoint: String,
    ca: String,
    issuer_dir: PathBuf,
}

async fn spawn_registrar() -> Registrar {
    let _ = tokio_rustls::rustls::crypto::aws_lc_rs::default_provider().install_default();
    let dir = tempfile::tempdir().unwrap();
    let issuer_dir = dir.path().join("issuer");
    let issuer = IssuerStore::open(&issuer_dir);
    issuer.ensure_realm().unwrap();
    issuer.ensure_workspace("main").unwrap();
    issuer.ensure_policy_key().unwrap();
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    drop(listener);
    let endpoint = format!("https://127.0.0.1:{port}");
    let tls = issuer
        .issue_control_endpoint("test", "registrar", &endpoint)
        .unwrap();
    std::fs::write(dir.path().join("registrar.crt"), &tls.chain_pem).unwrap();
    std::fs::write(dir.path().join("registrar.key"), &tls.key_pem).unwrap();
    tokio::spawn(interflow_registrar::server::serve(
        issuer_dir.clone(),
        interflow_registrar::server::ServeOptions {
            listen: format!("127.0.0.1:{port}").parse().unwrap(),
            public_endpoint: endpoint.clone(),
            tls_cert: dir.path().join("registrar.crt"),
            tls_key: dir.path().join("registrar.key"),
            ttl: LeafTtl::default_ttl(),
            control_endpoint: "https://relay.test".to_owned(),
            hub_endpoints: Default::default(),
        },
    ));
    let ca = issuer.realm_issuer().unwrap().cert_pem().to_owned();
    wait_ready(&endpoint, &ca).await.unwrap();
    Registrar {
        dir,
        endpoint,
        ca,
        issuer_dir,
    }
}

/// Enrolls one agent identity by code and returns its mTLS client.
async fn enrolled_agent(registrar: &Registrar) -> reqwest::Client {
    let code = EnrollmentCodes::open(registrar.issuer_dir.join("enrollments.json"))
        .unwrap()
        .create("test", PrincipalKind::Agent, Some("main"), "desktop")
        .unwrap();
    let principal =
        PrincipalPath::workspace_member("test", "main", PrincipalKind::Agent, "desktop").unwrap();
    let csr = generate_csr(&principal, &[], false).unwrap();
    let initial: Value = reqwest::Client::builder()
        .add_root_certificate(reqwest::Certificate::from_pem(registrar.ca.as_bytes()).unwrap())
        .build()
        .unwrap()
        .post(format!("{}/v1/enroll", registrar.endpoint))
        .json(&serde_json::json!({
            "code": code.code,
            "csr_pem": csr.csr_pem,
        }))
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap()
        .json()
        .await
        .unwrap();
    reqwest::Client::builder()
        .add_root_certificate(reqwest::Certificate::from_pem(registrar.ca.as_bytes()).unwrap())
        .identity(
            reqwest::Identity::from_pem(
                format!("{}{}", initial["chain_pem"].as_str().unwrap(), csr.key_pem).as_bytes(),
            )
            .unwrap(),
        )
        .build()
        .unwrap()
}

/// A fresh CSR body for `/v1/renew`.
fn renew_body() -> serde_json::Value {
    let principal =
        PrincipalPath::workspace_member("test", "main", PrincipalKind::Agent, "desktop").unwrap();
    let csr = generate_csr(&principal, &[], false).unwrap();
    serde_json::json!({ "csr_pem": csr.csr_pem })
}

#[tokio::test]
async fn renew_without_client_certificate_is_rejected() {
    let _serial = SERIAL.lock().await;
    let registrar = spawn_registrar().await;

    // The TLS plane admits anonymous peers (the CRL pull lane relies on
    // it); the renew handler must still refuse them.
    let response = reqwest::Client::builder()
        .add_root_certificate(reqwest::Certificate::from_pem(registrar.ca.as_bytes()).unwrap())
        .build()
        .unwrap()
        .post(format!("{}/v1/renew", registrar.endpoint))
        .json(&renew_body())
        .send()
        .await
        .unwrap();
    let text = response.text().await.unwrap();
    assert!(
        text.contains("certificate renewal requires a client certificate"),
        "{text}"
    );
}

#[tokio::test]
async fn fault_injected_renew_is_a_503_then_recovers() {
    let _serial = SERIAL.lock().await;
    interflow_registrar::fault::clear_hook();
    let registrar = spawn_registrar().await;
    let client = enrolled_agent(&registrar).await;

    // One injected 503 on /v1/renew: server-side trouble, distinct from
    // the 400s semantic rejections carry — the renewal client's retry
    // ladder (locked in crates/renewal/tests/scheduler.rs) keys off this
    // class.
    let served = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let hook_served = Arc::clone(&served);
    interflow_registrar::fault::install_hook(Arc::new(move |point| {
        if point == interflow_registrar::fault::FaultPoint::Renew
            && hook_served.fetch_add(1, std::sync::atomic::Ordering::SeqCst) == 0
        {
            interflow_registrar::fault::FaultAction::ServiceUnavailable
        } else {
            interflow_registrar::fault::FaultAction::Continue
        }
    }));

    let failed = client
        .post(format!("{}/v1/renew", registrar.endpoint))
        .json(&renew_body())
        .send()
        .await
        .unwrap();
    assert_eq!(failed.status(), reqwest::StatusCode::SERVICE_UNAVAILABLE);
    let body = failed.text().await.unwrap();
    assert!(body.contains("injected fault"), "{body}");

    // The fault is request-scoped: health never failed, and the very next
    // renew succeeds (recovery).
    let health = reqwest::Client::builder()
        .add_root_certificate(reqwest::Certificate::from_pem(registrar.ca.as_bytes()).unwrap())
        .build()
        .unwrap()
        .get(format!("{}/health", registrar.endpoint))
        .send()
        .await
        .unwrap();
    assert!(health.status().is_success());

    let recovered = client
        .post(format!("{}/v1/renew", registrar.endpoint))
        .json(&renew_body())
        .send()
        .await
        .unwrap();
    assert_eq!(recovered.status(), reqwest::StatusCode::OK);
    let text = recovered.text().await.unwrap();
    assert!(text.contains("\"serial\""), "{text}");
    interflow_registrar::fault::clear_hook();
}

async fn wait_ready(endpoint: &str, ca: &str) -> Result<(), String> {
    for _ in 0..100 {
        let client = reqwest::Client::builder()
            .add_root_certificate(reqwest::Certificate::from_pem(ca.as_bytes()).unwrap())
            .build()
            .unwrap();
        let response = client.get(format!("{endpoint}/health")).send().await;
        if response.is_ok_and(|response| response.status().is_success()) {
            return Ok(());
        }
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    }
    Err("registrar did not become ready".to_owned())
}

#[tokio::test]
async fn enroll_renew_and_confirm_over_https_mtls() -> Result<(), Box<dyn std::error::Error>> {
    let _serial = SERIAL.lock().await;
    let _ = tokio_rustls::rustls::crypto::aws_lc_rs::default_provider().install_default();
    let dir = tempfile::tempdir().unwrap();
    let issuer = IssuerStore::open(dir.path().join("issuer"));
    issuer.ensure_realm().unwrap();
    issuer.ensure_workspace("main").unwrap();
    issuer.ensure_policy_key().unwrap();
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    drop(listener);
    let endpoint = format!("https://127.0.0.1:{port}");
    let tls = issuer
        .issue_control_endpoint("test", "registrar", &endpoint)
        .unwrap();
    std::fs::write(dir.path().join("registrar.crt"), &tls.chain_pem).unwrap();
    std::fs::write(dir.path().join("registrar.key"), &tls.key_pem).unwrap();
    let code = EnrollmentCodes::open(dir.path().join("issuer/enrollments.json"))
        .unwrap()
        .create("test", PrincipalKind::Agent, Some("main"), "desktop")
        .unwrap();

    tokio::spawn(interflow_registrar::server::serve(
        dir.path().join("issuer"),
        interflow_registrar::server::ServeOptions {
            listen: format!("127.0.0.1:{port}").parse().unwrap(),
            public_endpoint: endpoint.clone(),
            tls_cert: dir.path().join("registrar.crt"),
            tls_key: dir.path().join("registrar.key"),
            ttl: LeafTtl::default_ttl(),
            control_endpoint: "https://relay.test".to_owned(),
            hub_endpoints: Default::default(),
        },
    ));
    let ca = issuer.realm_issuer().unwrap().cert_pem().to_owned();
    wait_ready(&endpoint, &ca).await?;
    let principal =
        PrincipalPath::workspace_member("test", "main", PrincipalKind::Agent, "desktop").unwrap();
    let enrollment_csr = generate_csr(&principal, &[], false).unwrap();
    let initial: Value = reqwest::Client::builder()
        .add_root_certificate(reqwest::Certificate::from_pem(ca.as_bytes()).unwrap())
        .build()
        .unwrap()
        .post(format!("{endpoint}/v1/enroll"))
        .json(&serde_json::json!({
            "code": code.code,
            "csr_pem": enrollment_csr.csr_pem,
        }))
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap()
        .json()
        .await
        .unwrap();

    let initial_identity = reqwest::Identity::from_pem(
        format!(
            "{}{}",
            initial["chain_pem"].as_str().unwrap(),
            enrollment_csr.key_pem
        )
        .as_bytes(),
    )
    .unwrap();
    let initial_client = reqwest::Client::builder()
        .add_root_certificate(reqwest::Certificate::from_pem(ca.as_bytes()).unwrap())
        .identity(initial_identity)
        .build()
        .unwrap();
    let renewal_csr = generate_csr(&principal, &[], false).unwrap();
    let renewed_response = initial_client
        .post(format!("{endpoint}/v1/renew"))
        .json(&serde_json::json!({
            "csr_pem": renewal_csr.csr_pem,
        }))
        .send()
        .await
        .unwrap();
    let renewed_text = renewed_response.text().await.unwrap();
    assert!(renewed_text.contains("\"serial\""), "{renewed_text}");
    let renewed: Value = serde_json::from_str(&renewed_text).unwrap();
    assert_ne!(
        initial["serial"].as_str().unwrap(),
        renewed["serial"].as_str().unwrap()
    );

    let renewed_identity = reqwest::Identity::from_pem(
        format!(
            "{}{}",
            renewed["chain_pem"].as_str().unwrap(),
            renewal_csr.key_pem
        )
        .as_bytes(),
    )
    .unwrap();
    let confirmed_response = reqwest::Client::builder()
        .add_root_certificate(reqwest::Certificate::from_pem(ca.as_bytes()).unwrap())
        .identity(renewed_identity)
        .build()
        .unwrap()
        .post(format!("{endpoint}/v1/confirm"))
        .json(&serde_json::json!({
            "renewal_id": renewed["renewal_id"],
        }))
        .send()
        .await
        .unwrap();
    let confirmed_text = confirmed_response.text().await.unwrap();
    assert!(confirmed_text.contains("confirmed"), "{confirmed_text}");
    let confirmed: Value = serde_json::from_str(&confirmed_text).unwrap();
    assert_eq!(confirmed["confirmed"], true);
    assert!(Path::new(&dir.path().join("issuer/registrar-audit.jsonl")).exists());
    Ok(())
}
