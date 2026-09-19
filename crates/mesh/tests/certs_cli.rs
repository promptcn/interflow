//! CLI-level contract tests for `interflow-mesh certs` — the operator tool
//! that replaced `scripts/gen_certs.sh` (backlog
//! (internal design notes)).
//!
//! Covers the acceptance criteria end to end: a fresh directory goes from
//! `certs init` → `certs agent issue` to hub-configurable + GUI-configurable
//! material with no openssl involved; the issued pair completes a REAL mTLS
//! handshake against the production acceptor
//! (`interflow_core::tls::build_mtls_acceptor` — which also proves the 0600
//! permissions pass the strict key loader); the `--hub-dns` guard blocks
//! non-tty runs without an explicit ack; idempotent reruns validate instead
//! of rewriting; tampered state fails with the concrete difference.

#![allow(
    clippy::all,
    clippy::pedantic,
    clippy::nursery,
    clippy::panic,
    clippy::unwrap_used,
    clippy::expect_used,
    missing_docs,
    dead_code
)]

use interflow_testkit::tls_client_connect_with;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

/// Runs the real binary with stdin detached (deterministic non-tty guard
/// behavior regardless of how the test harness itself was invoked).
fn certs(args: &[&str]) -> std::process::Output {
    Command::new(env!("CARGO_BIN_EXE_interflow-mesh"))
        .arg("certs")
        .args(args)
        .stdin(Stdio::null())
        .output()
        .expect("failed to spawn interflow-mesh")
}

fn stdout(out: &std::process::Output) -> String {
    String::from_utf8_lossy(&out.stdout).into_owned()
}

fn stderr(out: &std::process::Output) -> String {
    String::from_utf8_lossy(&out.stderr).into_owned()
}

fn read_first_cert_der(path: &Path) -> Vec<u8> {
    let pem = std::fs::read(path).unwrap();
    rustls_pemfile::certs(&mut &pem[..])
        .next()
        .expect("PEM certificate present")
        .unwrap()
        .to_vec()
}

fn cert_cn(path: &Path) -> String {
    let der = read_first_cert_der(path);
    let (_, cert) = x509_parser::parse_x509_certificate(&der).unwrap();
    cert.subject()
        .iter_common_name()
        .next()
        .unwrap()
        .as_str()
        .unwrap()
        .to_owned()
}

fn cert_has_san(path: &Path, expected: interflow_certs::SanName) -> bool {
    let der = read_first_cert_der(path);
    let (_, cert) = x509_parser::parse_x509_certificate(&der).unwrap();
    let Some(san) = cert
        .subject_alternative_name()
        .unwrap()
        .map(|san| san.value.general_names.clone())
    else {
        return false;
    };
    san.iter().any(|gn| match (gn, &expected) {
        (x509_parser::extensions::GeneralName::DNSName(s), interflow_certs::SanName::Dns(want)) => {
            s.eq_ignore_ascii_case(want)
        }
        (
            x509_parser::extensions::GeneralName::IPAddress(b),
            interflow_certs::SanName::Ip(want),
        ) => {
            let octets = match want {
                std::net::IpAddr::V4(v4) => v4.octets().to_vec(),
                std::net::IpAddr::V6(v6) => v6.octets().to_vec(),
            };
            *b == octets.as_slice()
        }
        _ => false,
    })
}

/// Spawns the production mTLS acceptor on the issued hub pair and connects
/// the issued agent pair through testkit's protocol-level helper.
async fn handshake_succeeds(dir: &Path, server_name: &str) -> bool {
    let to_str = |p: PathBuf| p.display().to_string();
    let server_name = server_name.to_owned();
    let acceptor = interflow_core::tls::build_mtls_acceptor(
        &to_str(dir.join("hub.crt")),
        &to_str(dir.join("hub.key")),
        &to_str(dir.join("tenants/main-ca.crt")),
        interflow_core::tls::TlsMinVersion::V1_2,
    )
    .unwrap();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let server = tokio::spawn(async move {
        let (stream, _) = listener.accept().await.unwrap();
        acceptor.accept(stream).await.is_ok()
    });
    let ca = dir.join("tenants/main-ca.crt");
    let cert = dir.join("agents/handshake-agent.crt");
    let key = dir.join("agents/handshake-agent.key");
    let client = tokio::spawn(async move {
        tls_client_connect_with(&ca, &cert, &key, &server_name, addr)
            .await
            .is_ok()
    });
    server.await.unwrap() && client.await.unwrap()
}

fn init_public(dir: &Path) -> std::process::Output {
    certs(&[
        "init",
        "--tenant",
        "main",
        "--hub-dns",
        "hub.test",
        "--yes",
        "--out",
        &dir.display().to_string(),
    ])
}

/// The headline flow: fresh dir → `certs init` → `certs agent issue` →
/// layout, permissions, CN/SAN, and a real mTLS handshake against the
/// production acceptor. No openssl anywhere.
#[tokio::test]
async fn init_and_issue_produce_handshake_ready_material() {
    let dir = tempfile::tempdir().unwrap();
    let out = init_public(dir.path());
    assert!(out.status.success(), "init failed: {}", stderr(&out));
    let text = stdout(&out);
    assert!(text.contains("SECURITY"), "must print the CA-key warning");
    assert!(
        text.contains("Distribution"),
        "must print distribution sets"
    );
    assert!(text.contains("hub.test"), "must echo the requested SAN");

    let out = certs(&[
        "agent",
        "issue",
        "main",
        "handshake-agent",
        "--out",
        &dir.path().display().to_string(),
    ]);
    assert!(out.status.success(), "agent issue failed: {}", stderr(&out));

    for rel in [
        "hub.crt",
        "hub.key",
        "tenants/main-ca.crt",
        "tenants/main-ca.key",
        "agents/handshake-agent.crt",
        "agents/handshake-agent.key",
    ] {
        assert!(dir.path().join(rel).exists(), "missing {rel}");
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        for rel in [
            "hub.key",
            "tenants/main-ca.key",
            "agents/handshake-agent.key",
        ] {
            let mode = std::fs::metadata(dir.path().join(rel))
                .unwrap()
                .permissions()
                .mode();
            assert_eq!(mode & 0o777, 0o600, "{rel} must be 0600, got {mode:o}");
        }
    }
    // Filename == agent_id == CN (the hub's identity binding).
    assert_eq!(
        cert_cn(&dir.path().join("agents/handshake-agent.crt")),
        "handshake-agent"
    );
    assert!(cert_has_san(
        &dir.path().join("hub.crt"),
        interflow_certs::SanName::Dns("hub.test".to_owned())
    ));
    assert!(
        handshake_succeeds(dir.path(), "hub.test").await,
        "issued pair must complete the production mTLS handshake"
    );
}

/// The local-development default SAN covers BOTH dial forms (hostname and
/// loopback IP) and both complete the handshake.
#[tokio::test]
async fn local_default_san_handshakes_over_hostname_and_ip() {
    let dir = tempfile::tempdir().unwrap();
    let out = certs(&[
        "init",
        "--tenant",
        "main",
        "--yes",
        "--out",
        &dir.path().display().to_string(),
    ]);
    assert!(out.status.success(), "local init failed: {}", stderr(&out));
    assert!(cert_has_san(
        &dir.path().join("hub.crt"),
        interflow_certs::SanName::Dns("localhost".to_owned())
    ));
    assert!(cert_has_san(
        &dir.path().join("hub.crt"),
        interflow_certs::SanName::Ip("127.0.0.1".parse().unwrap())
    ));

    let out = certs(&[
        "agent",
        "issue",
        "main",
        "handshake-agent",
        "--out",
        &dir.path().display().to_string(),
    ]);
    assert!(out.status.success(), "agent issue failed: {}", stderr(&out));
    assert!(
        handshake_succeeds(dir.path(), "localhost").await,
        "localhost dial form must handshake"
    );
    assert!(
        handshake_succeeds(dir.path(), "127.0.0.1").await,
        "loopback-IP dial form must handshake"
    );
}

/// The 2026-09-18 footgun guard: no --hub-dns and no --yes on a non-tty
/// stdin must FAIL with guidance, never silently issue a localhost cert.
#[test]
fn hub_dns_guard_blocks_non_tty_without_yes() {
    let dir = tempfile::tempdir().unwrap();
    let out = certs(&["init", "--out", &dir.path().display().to_string()]);
    assert!(!out.status.success(), "must refuse to issue silently");
    let text = format!("{}{}", stdout(&out), stderr(&out));
    assert!(
        text.contains("--hub-dns"),
        "error must point at --hub-dns/--yes, got: {text}"
    );
    assert!(
        !dir.path().join("hub.crt").exists(),
        "nothing may be written when the guard trips"
    );
}

/// Idempotency: a rerun validates and reports instead of rewriting.
#[test]
fn rerun_is_idempotent_and_reports_already_valid() {
    let dir = tempfile::tempdir().unwrap();
    let first = init_public(dir.path());
    assert!(first.status.success());
    let ca_before = std::fs::read(dir.path().join("tenants/main-ca.crt")).unwrap();
    let hub_before = std::fs::read(dir.path().join("hub.crt")).unwrap();

    let second = init_public(dir.path());
    assert!(second.status.success(), "rerun failed: {}", stderr(&second));
    let text = stdout(&second);
    assert!(
        text.contains("already valid"),
        "rerun must report AlreadyValid, got: {text}"
    );
    assert_eq!(
        std::fs::read(dir.path().join("tenants/main-ca.crt")).unwrap(),
        ca_before,
        "validation must not rewrite the CA"
    );
    assert_eq!(
        std::fs::read(dir.path().join("hub.crt")).unwrap(),
        hub_before,
        "validation must not rewrite the hub pair"
    );
}

/// Tampered state (a key swapped in from another pair) fails with the
/// concrete difference instead of a blind skip or overwrite.
#[test]
fn tampered_hub_key_fails_with_pair_mismatch() {
    let dir = tempfile::tempdir().unwrap();
    assert!(init_public(dir.path()).status.success());
    let out = certs(&[
        "agent",
        "issue",
        "main",
        "agent-1",
        "--out",
        &dir.path().display().to_string(),
    ]);
    assert!(out.status.success());

    // Swap the hub key with the agent's key: internally valid PEM, wrong pair.
    std::fs::copy(
        dir.path().join("agents/agent-1.key"),
        dir.path().join("hub.key"),
    )
    .unwrap();
    let out = init_public(dir.path());
    assert!(!out.status.success(), "must detect the tampered pair");
    let text = format!("{}{}", stdout(&out), stderr(&out));
    assert!(
        text.contains("do not form a pair"),
        "must report the pair mismatch, got: {text}"
    );
}

/// Multi-tenant flow: `tenant new` + `agent issue` against the new CA.
#[test]
fn tenant_new_then_agent_issue_under_new_tenant() {
    let dir = tempfile::tempdir().unwrap();
    assert!(init_public(dir.path()).status.success());
    let out = certs(&[
        "tenant",
        "new",
        "acme",
        "--out",
        &dir.path().display().to_string(),
    ]);
    assert!(out.status.success(), "tenant new failed: {}", stderr(&out));
    assert!(stdout(&out).contains("[[auth.tenants]]"));

    let out = certs(&[
        "agent",
        "issue",
        "acme",
        "acme-agent",
        "--out",
        &dir.path().display().to_string(),
    ]);
    assert!(out.status.success(), "agent issue failed: {}", stderr(&out));
    let cert = dir.path().join("agents/acme-agent.crt");
    assert!(cert.exists());
    assert_eq!(cert_cn(&cert), "acme-agent");

    // Idempotent second issue.
    let out = certs(&[
        "agent",
        "issue",
        "acme",
        "acme-agent",
        "--out",
        &dir.path().display().to_string(),
    ]);
    assert!(out.status.success());
    assert!(stdout(&out).contains("already valid"));
}

/// Agent issue without a tenant CA points at the missing prerequisite.
#[test]
fn agent_issue_without_ca_gives_actionable_error() {
    let dir = tempfile::tempdir().unwrap();
    let out = certs(&[
        "agent",
        "issue",
        "main",
        "agent-1",
        "--out",
        &dir.path().display().to_string(),
    ]);
    assert!(!out.status.success());
    let text = format!("{}{}", stdout(&out), stderr(&out));
    assert!(
        text.contains("certs init"),
        "must point at `certs init`, got: {text}"
    );
}

// ---- gateway material (e2e stable anchor, RFC agent-e2e-encryption §5.2) ----

fn gateway_issue(dir: &Path, force: bool) -> std::process::Output {
    let out_str = dir.display().to_string();
    let mut args = vec!["gateway", "issue", "--out", out_str.as_str()];
    if force {
        args.push("--force");
    }
    certs(&args)
}

fn read_all_certs(path: &Path) -> Vec<Vec<u8>> {
    let pem = std::fs::read(path).unwrap();
    rustls_pemfile::certs(&mut &pem[..])
        .collect::<Result<Vec<_>, _>>()
        .unwrap()
        .into_iter()
        .map(|c| c.to_vec())
        .collect()
}

/// `certs gateway issue` produces the documented layout, a CN=edge
/// ClientAuth leaf chained (bundle) to the anchor CA, and the pair is
/// hub-plane usable: a real mTLS handshake against the production acceptor
/// with the gateway CA as the client trust root.
#[tokio::test]
async fn gateway_issue_produces_handshake_ready_material() {
    let dir = tempfile::tempdir().unwrap();
    let out = gateway_issue(dir.path(), false);
    assert!(out.status.success(), "stdout: {}", stdout(&out));

    let base = dir.path().join("gateway");
    for name in ["gateway-ca.crt", "gateway-ca.key", "edge.crt", "edge.key"] {
        assert!(base.join(name).exists(), "missing {name}");
    }
    assert_eq!(
        cert_cn(&base.join("gateway-ca.crt")),
        "Interflow tenant CA: gateway"
    );
    assert_eq!(cert_cn(&base.join("edge.crt")), "edge");

    // Chain bundle: leaf first, anchor CA last (byte-identical).
    let chain = read_all_certs(&base.join("edge.crt"));
    assert_eq!(chain.len(), 2);
    let ca_der = read_first_cert_der(&base.join("gateway-ca.crt"));
    assert_eq!(chain[1], ca_der);

    // Hub-plane proof: the gateway pair completes a real mTLS handshake
    // against the production acceptor (a testkit server pair whose client
    // trust root is the gateway CA — exactly the edge hub's `_edge` plane).
    let server_certs = interflow_testkit::certs::TestCerts::generate("gwcli", "client");
    let acceptor = interflow_core::tls::build_mtls_acceptor(
        &server_certs.server_cert_path().display().to_string(),
        &server_certs.server_key_path().display().to_string(),
        &base.join("gateway-ca.crt").display().to_string(),
        interflow_core::tls::TlsMinVersion::V1_2,
    )
    .unwrap();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let server = tokio::spawn(async move {
        let (stream, _) = listener.accept().await.unwrap();
        acceptor.accept(stream).await.is_ok()
    });
    let server_ca = std::path::PathBuf::from(server_certs.ca_path());
    let cert = base.join("edge.crt");
    let key = base.join("edge.key");
    let client = tokio::spawn(async move {
        tls_client_connect_with(&server_ca, &cert, &key, "localhost", addr)
            .await
            .is_ok()
    });
    assert!(
        server.await.unwrap() && client.await.unwrap(),
        "gateway pair must complete a hub-plane mTLS handshake"
    );
}

/// Idempotent rerun validates without rewriting; --force re-issues the
/// client pair while the anchor CA bytes stay untouched.
#[test]
fn gateway_issue_idempotent_and_force_keeps_ca() {
    let dir = tempfile::tempdir().unwrap();
    assert!(gateway_issue(dir.path(), false).status.success());
    let ca = std::fs::read(dir.path().join("gateway/gateway-ca.crt")).unwrap();
    let leaf = std::fs::read(dir.path().join("gateway/edge.crt")).unwrap();

    let rerun = gateway_issue(dir.path(), false);
    assert!(rerun.status.success());
    assert!(stdout(&rerun).contains("already valid"));
    assert_eq!(
        std::fs::read(dir.path().join("gateway/gateway-ca.crt")).unwrap(),
        ca
    );
    assert_eq!(
        std::fs::read(dir.path().join("gateway/edge.crt")).unwrap(),
        leaf
    );

    let forced = gateway_issue(dir.path(), true);
    assert!(forced.status.success());
    assert_eq!(
        std::fs::read(dir.path().join("gateway/gateway-ca.crt")).unwrap(),
        ca,
        "--force must never rebuild the anchor CA"
    );
    assert_ne!(
        std::fs::read(dir.path().join("gateway/edge.crt")).unwrap(),
        leaf
    );
    assert_eq!(cert_cn(&dir.path().join("gateway/edge.crt")), "edge");
}

/// A tampered chain bundle (foreign trailing CA) fails with the concrete
/// difference instead of silently validating.
#[test]
fn gateway_issue_tampered_bundle_fails_with_mismatch() {
    let dir = tempfile::tempdir().unwrap();
    assert!(gateway_issue(dir.path(), false).status.success());
    // Corrupt the leaf: write only the CA into edge.crt (chain of 1).
    let ca_pem = std::fs::read_to_string(dir.path().join("gateway/gateway-ca.crt")).unwrap();
    std::fs::write(dir.path().join("gateway/edge.crt"), ca_pem).unwrap();
    let out = gateway_issue(dir.path(), false);
    assert!(!out.status.success());
    let text = format!("{}{}", stdout(&out), stderr(&out));
    assert!(
        text.contains("chain bundle"),
        "must name the bundle inconsistency, got: {text}"
    );
}
