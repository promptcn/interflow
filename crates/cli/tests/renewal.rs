//! End-to-end pack → registrar → active-credential renewal test.

use interflow_identity::issuance::{IssuerStore, LeafTtl};
use std::net::TcpListener;
use std::path::{Path, PathBuf};

fn bin() -> PathBuf {
    let mut path = std::env::current_exe().unwrap();
    path.pop();
    path.pop();
    path.join(format!("interflow{}", std::env::consts::EXE_SUFFIX))
}

#[tokio::test]
async fn agent_pack_renews_without_operator_intervention() {
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
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
    tokio::spawn(interflow_registrar::server::serve(
        dir.path().join("issuer"),
        interflow_registrar::server::ServeOptions {
            listen: format!("127.0.0.1:{port}").parse().unwrap(),
            public_endpoint: endpoint.clone(),
            tls_cert: dir.path().join("registrar.crt"),
            tls_key: dir.path().join("registrar.key"),
            ttl: LeafTtl::default_ttl(),
            control_endpoint: "127.0.0.1:16666".to_owned(),
            hub_endpoints: Default::default(),
        },
    ));
    let ca = issuer.realm_issuer().unwrap().cert_pem().to_owned();
    for _ in 0..100 {
        let client = reqwest::Client::builder()
            .add_root_certificate(reqwest::Certificate::from_pem(ca.as_bytes()).unwrap())
            .build()
            .unwrap();
        if client
            .get(format!("{endpoint}/health"))
            .send()
            .await
            .is_ok_and(|response| response.status().is_success())
        {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    }

    let manifest_path = dir.path().join("interflow.toml");
    std::fs::write(
        &manifest_path,
        format!(
            r#"
[realm]
id = "test"
control_endpoint = "127.0.0.1:16666"
[identity]
leaf_ttl = "24h"
[registrar]
endpoint = "{endpoint}"
[ingress.edge]
workspaces = ["main"]
[workspace.main]
[agent.desktop]
workspace = "main"
[[agent.desktop.services]]
id = "web"
address = "127.0.0.1:18080"
[[route]]
host = "web.test"
service = "main/desktop/web"
"#
        ),
    )
    .unwrap();
    let output = std::process::Command::new(bin())
        .args([
            "plan",
            "apply",
            "--manifest",
            manifest_path.to_str().unwrap(),
            "--issuer",
            dir.path().join("issuer").to_str().unwrap(),
            "--out",
            dir.path().join("dist").to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    let pack_dir = dir.path().join("dist/packs/agent-desktop");
    let before = interflow_identity::credentials::ActiveCredentialSet::load_or_bootstrap(
        &interflow_identity::CredentialPack::load_runtime(&pack_dir).unwrap(),
    )
    .unwrap();
    let report = interflow_renewal::renew_all(&pack_dir, true).await.unwrap();
    assert_eq!(report.renewed.len(), 1);
    let after = interflow_identity::credentials::ActiveCredentialSet::load_or_bootstrap(
        &interflow_identity::CredentialPack::load_runtime(&pack_dir).unwrap(),
    )
    .unwrap();
    assert_ne!(before.sequence, after.sequence);
    assert_ne!(
        before.entries["agent-main"].serial,
        after.entries["agent-main"].serial
    );
    let ingress_dir = dir.path().join("dist/packs/ingress-edge");
    let ingress_report = interflow_renewal::renew_all(&ingress_dir, true)
        .await
        .unwrap();
    assert_eq!(ingress_report.renewed.len(), 2);
    interflow_renewal::renewal_scheduler(&pack_dir)
        .await
        .unwrap();
    assert!(
        dir.path()
            .join("dist/packs/agent-desktop/state/crls/workspace-main.crl.pem")
            .is_file()
    );
    assert!(Path::new(&dir.path().join("issuer/registrar-audit.jsonl")).exists());
}
