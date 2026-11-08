//! The plan face's shared corpus — the STATE FAMILIES in which the read
//! face (`plan diff` / `change_state`) and the write face (`plan apply`)
//! have historically disagreed ("the preview promised a no-op the gate
//! refuted"). Both faces' contract tests build their corpus from HERE so
//! "the same state" is literally the same bytes: the CLI's released-binary
//! test (`crates/cli/tests/plan_preview_contract.rs`) and the GUI's From
//! layer test (`src-tauri/src/contract.rs`) classify the same digests.
//!
//! The family's known members (a new backlog entry that exposes another
//! seam adds a row here — that is this module's expansion path):
//!
//! | family member | corpus state | where it leaked |
//! |---|---|---|
//! | stale baseline cache | digest disagrees, snapshot proves unchanged | plan_preview_contract.rs |
//! | stale tree, trust | deny list past the embedded CRLs | offline_lifecycle.rs |
//! | stale tree, format | retired pack.toml vintage | pack_retirement.rs |
//! | watermark divergence | dist floor above bookkeeping | policy_apply_diff.rs |
//!
//! The hub endpoint is a closed loopback port (`127.0.0.1:1`): publication
//! degrades to the manual-drop artifact — fast, deterministic, no network.
//! `remote_port` moves the mesh rule face (policy-only, invisible to the
//! strip rule); `service_port` moves a service (policy material); `realm`
//! moves the identity face.

use interflow_identity::CredentialPack;
use interflow_identity::manifest::Manifest;
use std::path::Path;

/// The corpus declaration: a mesh hub + two mesh agents + one
/// service-only agent (the service agent makes the v1/v2 strip rules
/// disagree; a mesh-only declaration would make them coincide).
#[must_use]
pub fn mesh_manifest_text(realm: &str, remote_port: u16, service_port: u16) -> String {
    format!(
        r#"
[realm]
id = "{realm}"
[identity]
mode = "offline"
leaf_ttl = "7d"
[mesh.hub.promptcn]
listen = "127.0.0.1:16666"
endpoint = "127.0.0.1:1"
[workspace.main]
[agent.svc-host]
workspace = "main"
[[agent.svc-host.services]]
id = "asr"
address = "127.0.0.1:{service_port}"
[agent.leo-mesh]
workspace = "main"
[[agent.leo-mesh.mesh_ingress]]
name = "ollama"
listen = "127.0.0.1:24001"
target_agent = "home-win"
remote_addr = "127.0.0.1:{remote_port}"
[agent.home-win]
workspace = "main"
[[agent.home-win.mesh_egress]]
name = "loopback"
target_cidr = "127.0.0.0/8"
"#
    )
}

/// Moves the hub's DIAL listener (`mesh.hub.<name>.listen`) — an
/// identity-face edit no strip rule empties, WITHOUT the realm change that
/// would violate the issuer store's one-realm binding: the knob the
/// identity-edit corpus cells turn.
#[must_use]
pub fn with_hub_listen(base: &str, listen_port: u16) -> String {
    base.replace(
        "listen = \"127.0.0.1:16666\"",
        &format!("listen = \"127.0.0.1:{listen_port}\""),
    )
}

/// Ages one pack directory back to a pre-canonical pack.toml vintage
/// (drops the `workspace` line): the strict loader must refuse it — the
/// format-staleness corpus cell.
pub fn deprecate_pack_format(pack_dir: &Path) {
    let path = pack_dir.join("pack.toml");
    let text = std::fs::read_to_string(&path).expect("pack.toml");
    let legacy = text
        .lines()
        .filter(|line| !line.starts_with("workspace"))
        .collect::<Vec<_>>()
        .join("\n");
    std::fs::write(&path, format!("{legacy}\n")).expect("rewrite pack.toml");
    assert!(
        CredentialPack::load(pack_dir).is_err(),
        "the fixture must be strict-unloadable"
    );
}

/// Plants a node state mirror's policy at `generation` — the watermark
/// divergence corpus cell (the mirror is a watermark of record the issuer
/// bookkeeping cannot see).
pub fn write_state_policy_mirror(out_root: &Path, node: &str, generation: u64) {
    let mirror = out_root
        .join("packs")
        .join(format!("agent-{node}"))
        .join("state/policy");
    std::fs::create_dir_all(&mirror).expect("state/policy dir");
    std::fs::write(
        mirror.join("policy.toml"),
        format!("generation = {generation}\n"),
    )
    .expect("state policy mirror");
}

/// Convenience wrapper for the corpus consumers that load the declaration
/// after writing [`mesh_manifest_text`] to disk.
pub fn load(path: &Path) -> Manifest {
    Manifest::load(path).expect("corpus manifest parses")
}
