//! HTTP/mTLS smoke test for the registrar lifecycle.

use interflow_identity::issuance::generate_csr;
use interflow_identity::{PrincipalKind, PrincipalPath};
use interflow_registrar::EnrollmentCodes;
use interflow_testkit::http::direct_client;
use interflow_testkit::registrar::{RegistrarFixture, RegistrarFixtureOptions};
use serde_json::Value;
use std::sync::Arc;

/// Serializes the tests: the fault hook is process-global (the same
/// discipline as core's fault tests), so the happy-path case must not race
/// an armed plan.
static SERIAL: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

/// A live in-process registrar, already answering `GET /health`.
async fn spawn_registrar() -> RegistrarFixture {
    let registrar =
        interflow_testkit::registrar::spawn_registrar(RegistrarFixtureOptions::default()).await;
    registrar.wait_ready().await;
    registrar
}

/// Enrolls one agent identity by code and returns its mTLS client.
async fn enrolled_agent(registrar: &RegistrarFixture) -> reqwest::Client {
    let code = EnrollmentCodes::open(registrar.issuer_dir().join("enrollments.json"))
        .unwrap()
        .create("test", PrincipalKind::Agent, Some("main"), "desktop")
        .unwrap();
    let principal =
        PrincipalPath::workspace_member("test", "main", PrincipalKind::Agent, "desktop").unwrap();
    let csr = generate_csr(&principal, &[], false).unwrap();
    let initial: Value = direct_client()
        .add_root_certificate(
            reqwest::Certificate::from_pem(registrar.ca_pem().as_bytes()).unwrap(),
        )
        .build()
        .unwrap()
        .post(format!("{}/v1/enroll", registrar.endpoint()))
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
    direct_client()
        .add_root_certificate(
            reqwest::Certificate::from_pem(registrar.ca_pem().as_bytes()).unwrap(),
        )
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
    let response = direct_client()
        .add_root_certificate(
            reqwest::Certificate::from_pem(registrar.ca_pem().as_bytes()).unwrap(),
        )
        .build()
        .unwrap()
        .post(format!("{}/v1/renew", registrar.endpoint()))
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
        .post(format!("{}/v1/renew", registrar.endpoint()))
        .json(&renew_body())
        .send()
        .await
        .unwrap();
    assert_eq!(failed.status(), reqwest::StatusCode::SERVICE_UNAVAILABLE);
    let body = failed.text().await.unwrap();
    assert!(body.contains("injected fault"), "{body}");

    // The fault is request-scoped: health never failed, and the very next
    // renew succeeds (recovery).
    let health = direct_client()
        .add_root_certificate(
            reqwest::Certificate::from_pem(registrar.ca_pem().as_bytes()).unwrap(),
        )
        .build()
        .unwrap()
        .get(format!("{}/health", registrar.endpoint()))
        .send()
        .await
        .unwrap();
    assert!(health.status().is_success());

    let recovered = client
        .post(format!("{}/v1/renew", registrar.endpoint()))
        .json(&renew_body())
        .send()
        .await
        .unwrap();
    assert_eq!(recovered.status(), reqwest::StatusCode::OK);
    let text = recovered.text().await.unwrap();
    assert!(text.contains("\"serial\""), "{text}");
    interflow_registrar::fault::clear_hook();
}

#[tokio::test]
async fn enroll_renew_and_confirm_over_https_mtls() -> Result<(), Box<dyn std::error::Error>> {
    let _serial = SERIAL.lock().await;
    let registrar = spawn_registrar().await;
    let code = EnrollmentCodes::open(registrar.issuer_dir().join("enrollments.json"))
        .unwrap()
        .create("test", PrincipalKind::Agent, Some("main"), "desktop")
        .unwrap();

    let endpoint = registrar.endpoint().to_owned();
    let principal =
        PrincipalPath::workspace_member("test", "main", PrincipalKind::Agent, "desktop").unwrap();
    let enrollment_csr = generate_csr(&principal, &[], false).unwrap();
    let initial: Value = direct_client()
        .add_root_certificate(
            reqwest::Certificate::from_pem(registrar.ca_pem().as_bytes()).unwrap(),
        )
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
    let initial_client = direct_client()
        .add_root_certificate(
            reqwest::Certificate::from_pem(registrar.ca_pem().as_bytes()).unwrap(),
        )
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
    let confirmed_response = direct_client()
        .add_root_certificate(
            reqwest::Certificate::from_pem(registrar.ca_pem().as_bytes()).unwrap(),
        )
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
    assert!(
        registrar
            .issuer_dir()
            .join("registrar-audit.jsonl")
            .exists()
    );
    Ok(())
}

/// Identity-plane event matrix row 5 (`crates/mesh/tests/identity_
/// lifecycle_matrix.rs`): one enrollment code presented by many clients
/// at once admits exactly one of them — the code's single-use arbitration
/// (`EnrollmentCodes::consume`: load → check `used` → mark → save under
/// one process-wide lock) holds under concurrency, so no two leaves are
/// ever issued for one code. The losers are refused in the 400 class with
/// the "already been used" reason, and a second code is unaffected.
#[tokio::test]
async fn concurrent_enrolls_with_one_code_admit_exactly_one() {
    let _serial = SERIAL.lock().await;
    interflow_registrar::fault::clear_hook();
    let registrar = spawn_registrar().await;
    let codes = EnrollmentCodes::open(registrar.issuer_dir().join("enrollments.json")).unwrap();
    let code = codes
        .create("test", PrincipalKind::Agent, Some("main"), "desktop")
        .unwrap();
    let principal =
        PrincipalPath::workspace_member("test", "main", PrincipalKind::Agent, "desktop").unwrap();

    const RACERS: usize = 8;
    let barrier = Arc::new(tokio::sync::Barrier::new(RACERS));
    let endpoint = registrar.endpoint().to_owned();
    let ca_pem = registrar.ca_pem().to_owned();
    let mut racers = Vec::with_capacity(RACERS);
    for _ in 0..RACERS {
        // Distinct key pairs: every racer is a real, separately-generated
        // client; only the code is shared.
        let csr = generate_csr(&principal, &[], false).unwrap();
        let code = code.code.clone();
        let endpoint = endpoint.clone();
        let ca_pem = ca_pem.clone();
        let barrier = Arc::clone(&barrier);
        racers.push(tokio::spawn(async move {
            let client = direct_client()
                .add_root_certificate(reqwest::Certificate::from_pem(ca_pem.as_bytes()).unwrap())
                .build()
                .unwrap();
            barrier.wait().await;
            let response = client
                .post(format!("{endpoint}/v1/enroll"))
                .json(&serde_json::json!({ "code": code, "csr_pem": csr.csr_pem }))
                .send()
                .await
                .unwrap();
            let status = response.status();
            let body = response.text().await.unwrap();
            (status, body)
        }));
    }
    let mut admitted = Vec::new();
    let mut refused = Vec::new();
    for racer in racers {
        let (status, body) = racer.await.unwrap();
        if status == reqwest::StatusCode::OK {
            let issued: Value = serde_json::from_str(&body).unwrap();
            admitted.push(issued["serial"].as_str().unwrap().to_owned());
        } else {
            refused.push((status, body));
        }
    }
    assert_eq!(
        admitted.len(),
        1,
        "exactly one racer is issued a leaf: {admitted:?} / refused {refused:?}"
    );
    assert_eq!(refused.len(), RACERS - 1);
    for (status, body) in &refused {
        assert_eq!(
            *status,
            reqwest::StatusCode::BAD_REQUEST,
            "a spent code is a semantic rejection, not server trouble: {body}"
        );
        assert!(
            body.contains("already been used"),
            "the loser learns why: {body}"
        );
    }
    // The ledger agrees: the code is spent once, and a fresh code is
    // unaffected by the race.
    let fresh = codes
        .create("test", PrincipalKind::Agent, Some("main"), "laptop")
        .unwrap();
    assert!(
        EnrollmentCodes::open(registrar.issuer_dir().join("enrollments.json"))
            .unwrap()
            .consume(&code.code)
            .is_err(),
        "the raced code stays spent on disk"
    );
    let laptop =
        PrincipalPath::workspace_member("test", "main", PrincipalKind::Agent, "laptop").unwrap();
    let csr = generate_csr(&laptop, &[], false).unwrap();
    let status = direct_client()
        .add_root_certificate(reqwest::Certificate::from_pem(ca_pem.as_bytes()).unwrap())
        .build()
        .unwrap()
        .post(format!("{endpoint}/v1/enroll"))
        .json(&serde_json::json!({ "code": fresh.code, "csr_pem": csr.csr_pem }))
        .send()
        .await
        .unwrap()
        .status();
    assert_eq!(
        status,
        reqwest::StatusCode::OK,
        "a fresh code still enrolls"
    );
}
