//! HTTP/mTLS smoke test for the registrar lifecycle.

use interflow_identity::issuance::{IssuerStore, LeafTtl, generate_csr};
use interflow_identity::{PrincipalKind, PrincipalPath};
use interflow_registrar::EnrollmentCodes;
use serde_json::Value;
use std::net::TcpListener;
use std::path::Path;

#[tokio::test]
async fn enroll_renew_and_confirm_over_https_mtls() -> Result<(), Box<dyn std::error::Error>> {
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
