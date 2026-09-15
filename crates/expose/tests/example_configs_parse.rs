//! End-to-end validation: shipped expose example configs load and validate.
//!
//! The public reverse-tunnel scenario (`examples/reverse-tunnel-public/`)
//! migrated from mesh to the purpose-built expose binary (7263036); its
//! `profile.toml` and `routes.toml` are the shipped example configs on this
//! side and must keep parsing (deny_unknown_fields catches schema drift).
//!
//! Relative `ca_path` inside profile.toml anchors to the profile file's own
//! directory; the process CWD for these tests is the expose crate root,
//! which contains no `certs/`, so a passing existence check is itself proof
//! of CWD independence. Certificates are generated on demand
//! (`scripts/gen_certs.sh`) and never committed (policy 2026-09-15; git
//! history purged the same day), so the existence assertions only run when
//! the dev certs are present.
//!
//! Assertions are domain-agnostic: the example targets the maintainer's
//! real deployment domain in this repo and `example.com` in the published
//! export, so literal host assertions would break one of the two trees.

#![allow(
    clippy::all,
    clippy::pedantic,
    clippy::nursery,
    clippy::panic,
    clippy::unwrap_used,
    clippy::expect_used,
    missing_docs,
    dead_code,
    unused_mut
)]
use interflow_expose::edge::HostRouter;
use interflow_expose::profile;
use std::path::{Path, PathBuf};

/// The workspace root (used for examples/reverse-tunnel-public).
fn workspace_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(|p| p.parent())
        .expect("expose crate should be at <workspace>/crates/expose")
        .to_path_buf()
}

#[test]
fn public_profile_toml_loads_with_anchored_ca() {
    let base = workspace_root().join("examples/reverse-tunnel-public");
    let p = profile::load_from(&base.join("profile.toml")).expect("profile.toml should load");
    // Structural assertions only (see module docs): https scheme plus a
    // host:port authority, without pinning the literal domain.
    let hub_url = p.hub_url.as_deref().expect("profile sets hub_url");
    let authority = hub_url
        .strip_prefix("https://")
        .expect("hub_url uses https");
    assert!(
        authority.contains('.'),
        "hub host should be a domain: {authority}"
    );
    assert!(
        authority.contains(':'),
        "hub_url should carry a port: {authority}"
    );
    assert!(p.agent_id.is_some());

    // Anchoring invariant: the relative ca_path resolves against the
    // profile's own directory, absolute, independent of the process CWD.
    let ca = p.ca_path.as_deref().expect("profile sets ca_path");
    assert!(Path::new(ca).is_absolute());
    assert_eq!(ca, base.join("certs/ca.crt").display().to_string());
    // Existence is the on-demand-certs part of the invariant: only checkable
    // after `scripts/gen_certs.sh` has generated the dev set.
    if base.join("certs").exists() {
        assert!(Path::new(ca).exists());
    }
}

#[test]
fn public_routes_toml_loads_non_empty() {
    let base = workspace_root().join("examples/reverse-tunnel-public");
    let routes_path = base.join("routes.toml");
    // Expected hosts are read from the shipped file itself, keeping the test
    // valid in both the private tree and the domain-sanitized export.
    let hosts: Vec<String> = std::fs::read_to_string(&routes_path)
        .expect("routes.toml should be readable")
        .lines()
        .filter_map(|l| l.trim().strip_prefix("host = "))
        .map(|v| v.trim_matches('"').to_string())
        .collect();
    assert!(
        !hosts.is_empty(),
        "routes.toml should declare at least one host"
    );

    let router = HostRouter::load(routes_path.display().to_string().as_str())
        .expect("routes.toml should load");
    assert!(!router.is_empty());
    for host in &hosts {
        assert!(router.lookup(host).is_some(), "route for {host} missing");
    }
    assert!(router.lookup("unknown.example.com").is_none());
}
