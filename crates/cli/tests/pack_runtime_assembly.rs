//! Pack-path QUIC wiring: a real rendered Credential Pack must carry the
//! manifest's QUIC decisions into the engine configs — the h2→QUIC switch
//! is pure configuration, on the hub face (EdgeConfig.quic_listen) and the
//! agent face (the signed transport default) alike.

use interflow_cli::runtime::{build_agent_args, build_edge_config, resolve_effective_transport};
use interflow_identity::credentials::ActiveCredentialSet;
use interflow_identity::issuance::IssuerStore;
use interflow_identity::manifest::Manifest;
use interflow_identity::pack::CredentialPack;
use interflow_identity::{AgentCredentialPack, IngressCredentialPack};
use interflow_mesh::config::TransportKind;
use std::collections::BTreeMap;

/// The enabled form: explicit-port control endpoint, ingress QUIC face on
/// the same port number, agent defaulting its dial to quic.
const QUIC_MANIFEST: &str = r#"
[realm]
id = "quic-e2e"
control_endpoint = "relay.example.com:16666"

[public_tls]
mode = "frontend-proxy"

[identity]
leaf_ttl = "24h"

[registrar]
endpoint = "https://registrar.example.com"

[ingress.edge]
workspaces = ["main"]
quic_listen = "0.0.0.0:16666"

[workspace.main]

[agent.desktop]
workspace = "main"
transport = "quic"

[[agent.desktop.services]]
id = "asr"
address = "127.0.0.1:8080"

[[route]]
host = "asr.example.com"
service = "main/desktop/asr"
"#;

fn issuer_under(tmp: &std::path::Path) -> IssuerStore {
    let issuer = IssuerStore::open(tmp.join("issuer"));
    issuer.ensure_realm().unwrap();
    issuer.ensure_workspace("main").unwrap();
    issuer.ensure_policy_key().unwrap();
    issuer
}

/// The wiring under test is the struct-literal leg `resolve_quic_listen`'s
/// unit tests cannot see: manifest → rendered node.toml → digest-verified
/// load → `build_edge_config` → `EdgeConfig.quic_listen`.
#[test]
fn ingress_pack_opens_the_quic_face() {
    let tmp = tempfile::tempdir().unwrap();
    let manifest = Manifest::parse(QUIC_MANIFEST).unwrap();
    let out = tmp.path().join("packs/ingress-edge");
    IngressCredentialPack::render(&issuer_under(tmp.path()), &manifest, "edge", 1, &out).unwrap();

    let pack = CredentialPack::load(&out).unwrap();
    let active = ActiveCredentialSet::load_or_bootstrap(&pack).unwrap();
    let config = build_edge_config(&pack, &active, &out).unwrap();
    assert_eq!(
        config.quic_listen,
        Some("0.0.0.0:16666".parse().unwrap()),
        "the manifest's quic_listen must reach the engine config through the pack"
    );
}

/// Agent-side wiring: a `transport = "quic"` manifest default rides the
/// pack, and the single resolution rule gives headless nodes the pack
/// default while a machine-local preference still wins (GUI parity).
#[test]
fn agent_pack_carries_the_signed_transport_default() {
    let tmp = tempfile::tempdir().unwrap();
    let manifest = Manifest::parse(QUIC_MANIFEST).unwrap();
    let out = tmp.path().join("packs/agent-desktop");
    AgentCredentialPack::render(&issuer_under(tmp.path()), &manifest, "desktop", 1, &out).unwrap();

    let pack = CredentialPack::load(&out).unwrap();
    let active = ActiveCredentialSet::load_or_bootstrap(&pack).unwrap();
    // Headless form: no profile, no preference — the pack default runs.
    let transport =
        resolve_effective_transport(None, pack.node_config.transport.as_deref()).unwrap();
    let args = build_agent_args(&pack, &active, &out, transport, None, &BTreeMap::new()).unwrap();
    assert_eq!(args.transport, TransportKind::Quic);

    // GUI form: a local h2 preference beats the pack's quic default.
    assert_eq!(
        resolve_effective_transport(
            Some(TransportKind::H2),
            pack.node_config.transport.as_deref()
        )
        .unwrap(),
        TransportKind::H2
    );
}

/// The h2-only status quo is the regression baseline: no quic_listen, no
/// transport — the engine sees None/H2 exactly as before this field pair.
#[test]
fn quic_free_manifests_stay_h2_and_off() {
    let tmp = tempfile::tempdir().unwrap();
    let plain = QUIC_MANIFEST
        .replace("\nquic_listen = \"0.0.0.0:16666\"", "")
        .replace("\ntransport = \"quic\"", "");
    let manifest = Manifest::parse(&plain).unwrap();

    let ingress_out = tmp.path().join("packs/ingress-edge");
    IngressCredentialPack::render(
        &issuer_under(tmp.path()),
        &manifest,
        "edge",
        1,
        &ingress_out,
    )
    .unwrap();
    let pack = CredentialPack::load(&ingress_out).unwrap();
    let active = ActiveCredentialSet::load_or_bootstrap(&pack).unwrap();
    let config = build_edge_config(&pack, &active, &ingress_out).unwrap();
    assert_eq!(config.quic_listen, None, "absent quic_listen stays off");

    let agent_out = tmp.path().join("packs/agent-desktop");
    AgentCredentialPack::render(
        &issuer_under(tmp.path()),
        &manifest,
        "desktop",
        1,
        &agent_out,
    )
    .unwrap();
    let pack = CredentialPack::load(&agent_out).unwrap();
    let active = ActiveCredentialSet::load_or_bootstrap(&pack).unwrap();
    let transport =
        resolve_effective_transport(None, pack.node_config.transport.as_deref()).unwrap();
    let args = build_agent_args(
        &pack,
        &active,
        &agent_out,
        transport,
        None,
        &BTreeMap::new(),
    )
    .unwrap();
    assert_eq!(args.transport, TransportKind::default());
}
