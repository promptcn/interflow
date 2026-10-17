//! End-to-end pack → registrar → active-credential renewal test.

fn bin() -> std::path::PathBuf {
    let mut path = std::env::current_exe().unwrap();
    path.pop();
    path.pop();
    path.join(format!("interflow-cli{}", std::env::consts::EXE_SUFFIX))
}

#[tokio::test]
async fn agent_pack_renews_without_operator_intervention() {
    let registrar = interflow_testkit::registrar::spawn_registrar(Default::default()).await;
    registrar.wait_ready().await;
    let dir = tempfile::tempdir().unwrap();
    let endpoint = registrar.endpoint().to_owned();
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
            registrar.issuer_dir().to_str().unwrap(),
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
    assert!(
        registrar
            .issuer_dir()
            .join("registrar-audit.jsonl")
            .exists()
    );
}
