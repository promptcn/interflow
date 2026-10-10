//! A corrupt `state/proposals.json` neither kills the hub nor silently
//! disappears: the file is quarantined beside the queue, one
//! `ProposalQueueQuarantined` audit event records the loss, and the face
//! restarts empty (the data plane — every tenant's site-to-site traffic —
//! was never hostage to a 72h-TTL approval queue in the first place).
//!
//! (internal design notes) #1 (option b,
//! strengthened: quarantine + explicit audit event). All identifiers
//! fictional.

use interflow_core::security::AuditSink;
use interflow_identity::credentials::ActiveCredentialSet;
use interflow_identity::issuance::IssuerStore;
use interflow_identity::manifest::Manifest;
use interflow_identity::pack::CredentialPack;
use interflow_identity::pack::render::HubCredentialPack;

#[tokio::test]
async fn corrupt_proposals_json_is_quarantined_audited_and_the_face_restarts_empty() {
    let dir = tempfile::tempdir().expect("tempdir");
    let issuer = IssuerStore::open(dir.path().join("issuer"));
    issuer.ensure_realm().unwrap();
    issuer.ensure_workspace("atlas").unwrap();
    issuer.ensure_policy_key().unwrap();

    // A dedicated fictional mesh (realm `quarantine-lab`, hub `sentinel`).
    let manifest = Manifest::parse(
        r#"
[realm]
id = "quarantine-lab"
[registrar]
endpoint = "https://registrar.example.com"
[mesh.hub.sentinel]
listen = "127.0.0.1:26997"
endpoint = "127.0.0.1:26997"
[workspace.atlas]
[agent.courier]
workspace = "atlas"
[[agent.courier.mesh_egress]]
name = "api"
target_addr = "127.0.0.1:18097"
"#,
    )
    .unwrap();

    let hub_dir = dir.path().join("packs/hub-sentinel");
    HubCredentialPack::render(&issuer, &manifest, "sentinel", 1, &hub_dir).unwrap();
    let hub_pack = CredentialPack::load_runtime(&hub_dir).unwrap();
    let hub_active = ActiveCredentialSet::load_or_bootstrap(&hub_pack).unwrap();
    let hub_cfg = interflow_mesh::pack::build_hub_config(&hub_pack, &hub_active, &hub_dir).unwrap();
    assert!(
        hub_cfg.policy.verifier_key_hex.is_some(),
        "the pack configures the policy channel (the proposals face rides it)"
    );

    // The corrupt corpus: a truncated JSON array — the exact shape a torn
    // write or a hand edit leaves behind.
    let state_dir = hub_dir.join("state");
    let queue_path = state_dir.join("proposals.json");
    let corrupt_bytes = b"[{\"id\":\"torn-write\",\"requester\":\"atlas/courier\"";
    std::fs::create_dir_all(&state_dir).unwrap();
    std::fs::write(&queue_path, corrupt_bytes).unwrap();

    let audit = AuditSink::spawn(&hub_cfg.audit);
    let hub = interflow_mesh::hub::server::HubServer::new(hub_cfg, audit.clone())
        .expect("assembly survives a corrupt proposal queue");
    drop(hub);
    audit.flush().await;

    // The evidence is preserved under a .corrupt-<ts> name; the queue path
    // is free for the restarted (empty) face to persist into.
    assert!(
        !queue_path.exists(),
        "the corrupt file must not stay at the queue path"
    );
    let quarantined: Vec<_> = std::fs::read_dir(&state_dir)
        .unwrap()
        .filter_map(std::result::Result::ok)
        .map(|e| e.path())
        .filter(|p| {
            p.file_name()
                .and_then(|n| n.to_str())
                .is_some_and(|n| n.starts_with("proposals.json.corrupt-"))
        })
        .collect();
    assert_eq!(quarantined.len(), 1, "exactly one quarantine copy");
    assert_eq!(
        std::fs::read(&quarantined[0]).unwrap(),
        corrupt_bytes.to_vec(),
        "the quarantine copy preserves the corrupt bytes verbatim"
    );

    // The loss is explicit, in the hashed ledger.
    let ledger = std::fs::read_to_string(hub_dir.join("audit.jsonl")).unwrap();
    assert!(
        ledger.contains("proposal_queue_quarantined"),
        "the audit ledger must carry the quarantine event:\n{ledger}"
    );
    assert!(
        ledger.contains("not valid JSON"),
        "the event carries the load failure's cause:\n{ledger}"
    );

    // And the ledger still verifies end to end (the event is a first-class
    // chain citizen, not an out-of-band write).
    let report =
        interflow_core::security::verify_audit_files(&[hub_dir.join("audit.jsonl")]).unwrap();
    assert!(report.records >= 1);
}

#[tokio::test]
async fn a_clean_or_absent_queue_assembles_without_a_trace() {
    // Control: the same assembly with no queue file records no quarantine
    // event — the new path is invisible to healthy deployments.
    let dir = tempfile::tempdir().expect("tempdir");
    let issuer = IssuerStore::open(dir.path().join("issuer"));
    issuer.ensure_realm().unwrap();
    issuer.ensure_workspace("atlas").unwrap();
    issuer.ensure_policy_key().unwrap();
    let manifest = Manifest::parse(
        r#"
[realm]
id = "quarantine-lab"
[registrar]
endpoint = "https://registrar.example.com"
[mesh.hub.sentinel]
listen = "127.0.0.1:26998"
endpoint = "127.0.0.1:26998"
[workspace.atlas]
[agent.courier]
workspace = "atlas"
[[agent.courier.mesh_egress]]
name = "api"
target_addr = "127.0.0.1:18098"
"#,
    )
    .unwrap();
    let hub_dir = dir.path().join("packs/hub-sentinel");
    HubCredentialPack::render(&issuer, &manifest, "sentinel", 1, &hub_dir).unwrap();
    let hub_pack = CredentialPack::load_runtime(&hub_dir).unwrap();
    let hub_active = ActiveCredentialSet::load_or_bootstrap(&hub_pack).unwrap();
    let hub_cfg = interflow_mesh::pack::build_hub_config(&hub_pack, &hub_active, &hub_dir).unwrap();

    let audit = AuditSink::spawn(&hub_cfg.audit);
    let hub = interflow_mesh::hub::server::HubServer::new(hub_cfg, audit.clone()).unwrap();
    drop(hub);
    audit.flush().await;
    let ledger = std::fs::read_to_string(hub_dir.join("audit.jsonl")).unwrap();
    assert!(
        !ledger.contains("proposal_queue_quarantined"),
        "a healthy start must not emit quarantine events:\n{ledger}"
    );
}
