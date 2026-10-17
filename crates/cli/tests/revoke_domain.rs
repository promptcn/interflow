//! The revoke command's two revocation domains, owned by different things:
//! the pack's bootstrap identities (`identity/*.crt`) and the node's renewal
//! ledger (`state/credentials`). The ledger follows the NODE across pack
//! generations — the 2026-10-13 incident had a superseded archive's state
//! pointer evict a live node — so the domain boundary is explicit: by
//! default revoke never touches the ledger; `--include-active-credentials`
//! is the operator's statement that the node's runtime credential must die.

use std::path::{Path, PathBuf};
use std::process::Command;

fn bin() -> PathBuf {
    let mut p = std::env::current_exe().expect("test bin path");
    p.pop();
    p.pop();
    p.join(format!("interflow-cli{}", std::env::consts::EXE_SUFFIX))
}

struct Run {
    success: bool,
    stdout: String,
    stderr: String,
}

fn run(args: &[&str]) -> Run {
    let output = Command::new(bin())
        .args(args)
        .output()
        .expect("spawn interflow");
    Run {
        success: output.status.success(),
        stdout: String::from_utf8_lossy(&output.stdout).into_owned(),
        stderr: String::from_utf8_lossy(&output.stderr).into_owned(),
    }
}

fn run_ok(args: &[&str]) -> Run {
    let out = run(args);
    assert!(
        out.success,
        "interflow {args:?} failed:\nstdout: {}\nstderr: {}",
        out.stdout, out.stderr,
    );
    out
}

const OFFLINE_MANIFEST: &str = r#"
[realm]
id = "promptcn"
control_endpoint = "127.0.0.1:26666"

[identity]
mode = "offline"
leaf_ttl = "90d"

[ingress.edge]
workspaces = ["default"]
listen = "127.0.0.1:18443"
control_listen = "127.0.0.1:26666"

[workspace.default]

[agent.desktop]
workspace = "default"

[[agent.desktop.services]]
id = "asr"
address = "127.0.0.1:18080"

[[route]]
host = "asr.example.com"
service = "default/desktop/asr"
"#;

fn apply(dir: &Path) -> (String, String) {
    let manifest = dir.join("interflow.toml").display().to_string();
    let issuer = dir.join("issuer").display().to_string();
    let out = dir.join("dist").display().to_string();
    std::fs::write(dir.join("interflow.toml"), OFFLINE_MANIFEST).unwrap();
    run_ok(&[
        "plan",
        "apply",
        "--manifest",
        &manifest,
        "--issuer",
        &issuer,
        "--out",
        &out,
    ]);
    (manifest, issuer)
}

/// Sows a renewal ledger under the pack's `state/credentials` — a freshly
/// issued leaf (a serial distinct from every bootstrap identity, exactly
/// what a renewed credential looks like) plus the pointer — and returns its
/// serial. This is the node-owned state an update carries across
/// generations, and what a naive revoke used to sweep into the deny list.
fn sow_ledger(pack_dir: &Path, issuer_dir: &Path) -> String {
    use interflow_identity::issuance::{IssuerStore, LeafTtl, generate_csr};
    use interflow_identity::revocation::cert_serial_hex;
    use interflow_identity::{PrincipalKind, PrincipalPath};
    let issuer = IssuerStore::open(issuer_dir);
    let principal =
        PrincipalPath::workspace_member("promptcn", "default", PrincipalKind::Agent, "desktop")
            .unwrap();
    let csr = generate_csr(&principal, &[], false).unwrap();
    let material = issuer
        .workspace_issuer("default")
        .unwrap()
        .issue_csr(&principal, &[], false, LeafTtl::default_ttl(), &csr.csr_pem)
        .unwrap();
    let sequence = pack_dir.join("state/credentials/sequences/1");
    std::fs::create_dir_all(&sequence).unwrap();
    std::fs::write(sequence.join("agent-default.crt"), &material.chain_pem).unwrap();
    std::fs::write(sequence.join("agent-default.key"), &csr.key_pem).unwrap();
    std::fs::write(
        pack_dir.join("state/credentials/current.json"),
        r#"{"sequence": 1, "updated": "2026-10-13T23:00:00Z"}"#,
    )
    .unwrap();
    cert_serial_hex(&material.chain_pem).unwrap()
}

/// Every serial recorded in the issuer store's deny list.
fn deny_list_serials(issuer_dir: &Path) -> Vec<String> {
    let text = std::fs::read_to_string(issuer_dir.join("revocations.json")).unwrap();
    #[derive(serde::Deserialize)]
    struct Entry {
        serial: String,
    }
    #[derive(serde::Deserialize)]
    struct List {
        entries: Vec<Entry>,
    }
    let list: List = serde_json::from_str(&text).unwrap();
    list.entries.into_iter().map(|e| e.serial).collect()
}

/// The serials of the pack's own bootstrap identities (`identity/*.crt`).
fn identity_serials(pack_dir: &Path) -> Vec<String> {
    use interflow_identity::revocation::cert_serial_hex;
    std::fs::read_dir(pack_dir.join("identity"))
        .unwrap()
        .filter_map(|entry| {
            let path = entry.ok()?.path();
            (path.extension().is_some_and(|e| e == "crt"))
                .then(|| cert_serial_hex(&std::fs::read_to_string(&path).unwrap()).unwrap())
        })
        .collect()
}

/// The incident replay: revoking a superseded pack (here parked as
/// `.previous`, the shape the 2026-10-13 rehearsal actually hit) must deny
/// ONLY its bootstrap identities. The state pointer follows the node's live
/// renewal ledger — whatever pack directory it happens to sit in — and
/// stays untouched, with the guidance line naming the explicit opt-in.
#[test]
fn revoke_of_an_archived_pack_spares_the_node_ledger() {
    let dir = tempfile::tempdir().expect("tempdir").keep();
    let (_, issuer) = apply(&dir);
    let pack = dir.join("dist/packs/agent-desktop");
    let ledger_serial = sow_ledger(&pack, &dir.join("issuer"));
    let previous = dir.join("dist/packs/agent-desktop.previous");
    std::fs::rename(&pack, &previous).unwrap();

    let out = run_ok(&[
        "revoke",
        "--issuer",
        &issuer,
        "--pack",
        &previous.display().to_string(),
        "--reason",
        "key-compromise",
    ]);

    let denied = deny_list_serials(&dir.join("issuer"));
    let identities = identity_serials(&previous);
    assert_eq!(
        denied, identities,
        "exactly the pack's bootstrap identities enter the deny list"
    );
    assert!(
        !denied.contains(&ledger_serial),
        "the node's live renewal serial must NOT be revoked: denied = {denied:?}"
    );
    assert!(
        out.stdout.contains("NOT revoked") && out.stdout.contains("--include-active-credentials"),
        "the guidance line must name the skipped serials and the explicit opt-in: {}",
        out.stdout
    );
    assert!(
        out.stdout.contains(&ledger_serial),
        "the skipped serial must be visible: {}",
        out.stdout
    );
}

/// The explicit kill: `--include-active-credentials` extends the revocation
/// domain to the node-owned ledger — the recording half of the hot-eviction
/// behavior the enforcement tests already cover (crl_hot_swap.rs). This is
/// the operator's unambiguous "the node's runtime credential must die".
#[test]
fn revoke_with_include_active_credentials_denies_the_ledger() {
    let dir = tempfile::tempdir().expect("tempdir").keep();
    let (_, issuer) = apply(&dir);
    let pack = dir.join("dist/packs/agent-desktop");
    let ledger_serial = sow_ledger(&pack, &dir.join("issuer"));

    let out = run_ok(&[
        "revoke",
        "--issuer",
        &issuer,
        "--pack",
        &pack.display().to_string(),
        "--reason",
        "key-compromise",
        "--include-active-credentials",
    ]);

    let denied = deny_list_serials(&dir.join("issuer"));
    assert!(
        denied.contains(&ledger_serial),
        "the ledger serial must be denied: {denied:?}"
    );
    for serial in identity_serials(&pack) {
        assert!(
            denied.contains(&serial),
            "identities stay denied: {denied:?}"
        );
    }
    assert!(
        !out.stdout.contains("NOT revoked"),
        "no skip guidance when the domain was explicitly widened: {}",
        out.stdout
    );
}

/// A pack without node state (a fresh render, a dumb-node pack) revokes
/// exactly as before — the domain split changes nothing for it.
#[test]
fn revoke_of_a_stateless_pack_is_unchanged() {
    let dir = tempfile::tempdir().expect("tempdir").keep();
    let (_, issuer) = apply(&dir);
    let pack = dir.join("dist/packs/agent-desktop");

    let out = run_ok(&[
        "revoke",
        "--issuer",
        &issuer,
        "--pack",
        &pack.display().to_string(),
        "--reason",
        "superseded",
    ]);

    assert_eq!(
        deny_list_serials(&dir.join("issuer")),
        identity_serials(&pack)
    );
    assert!(
        !out.stdout.contains("NOT revoked"),
        "no ledger guidance without a ledger: {}",
        out.stdout
    );
}
