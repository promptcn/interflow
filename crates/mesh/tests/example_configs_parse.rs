//! End-to-end validation: shipped mesh example configs load and pass validate.
//!
//! Covers the mesh crate quickstart (`crates/mesh/examples/*.toml`) and the
//! private reverse-tunnel scenario (`examples/reverse-tunnel-private/`). The
//! public scenario (`examples/reverse-tunnel-public/`) migrated to the
//! purpose-built `interflow-expose` binary (7263036) and no longer ships
//! mesh configs, so it is validated on the expose side, not here.
//!
//! Relative cert paths inside these tomls anchor to each config file's own
//! directory (`config::loader`). These tests run with the process CWD at the
//! crate root — a directory containing no `certs/` — so a passing load
//! is itself proof of CWD independence; no chdir gymnastics required.
//!
//! Dev certificates are generated on demand (`scripts/gen_certs.sh` into
//! `crates/mesh/examples/certs/`) and never committed (policy 2026-09-15;
//! git history purged the same day). The shipped-config tests below need the
//! real cert material on disk because `validate` checks existence, so they
//! skip with a note when the certs have not been generated yet — a fresh
//! clone runs them only after `gen_certs.sh`.

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
use interflow_mesh::config::{
    AGENT_CONFIG_VERSION, HUB_CONFIG_VERSION, load_agent_config, load_hub_config,
};
use std::path::{Path, PathBuf};

/// The mesh crate root (`crates/mesh/`).
fn manifest_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

/// The workspace root (used for examples/reverse-tunnel-*).
fn workspace_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(|p| p.parent())
        .expect("mesh crate should be at <workspace>/crates/mesh")
        .to_path_buf()
}

/// True when the on-demand dev certs exist (`scripts/gen_certs.sh`); the
/// shipped-config loads below skip without them (see module docs).
fn dev_certs_present() -> bool {
    manifest_root().join("examples/certs/hub.crt").exists()
}

#[test]
fn root_hub_toml_loads() {
    if !dev_certs_present() {
        eprintln!("skipping: crates/mesh/examples/certs not generated (run scripts/gen_certs.sh)");
        return;
    }
    let path = manifest_root().join("examples/hub.toml");
    let cfg = load_hub_config(&path).expect("hub.toml should load");
    assert_eq!(cfg.config_version, 3);
    assert!(!cfg.auth.allow_anonymous);
    // Path-anchoring invariant: cert paths come back absolute, pointing at
    // the config's own certs/ (crates/mesh/examples/certs/), not the CWD.
    let tls = cfg.tls.as_ref().expect("hub.toml enables tls");
    assert!(Path::new(&tls.cert_path).is_absolute());
    assert_eq!(
        tls.cert_path,
        manifest_root()
            .join("examples/certs/hub.crt")
            .display()
            .to_string()
    );
}

#[test]
fn root_agent1_toml_loads() {
    if !dev_certs_present() {
        eprintln!("skipping: crates/mesh/examples/certs not generated (run scripts/gen_certs.sh)");
        return;
    }
    let path = manifest_root().join("examples/agent-1.toml");
    let cfg = load_agent_config(&path).expect("agent-1.toml should load");
    assert_eq!(cfg.config_version, 3);
    assert_eq!(cfg.agent.id, "agent-1");
    assert!(cfg.control.enabled);
}

#[test]
fn root_agent2_toml_loads() {
    if !dev_certs_present() {
        eprintln!("skipping: crates/mesh/examples/certs not generated (run scripts/gen_certs.sh)");
        return;
    }
    let path = manifest_root().join("examples/agent-2.toml");
    let cfg = load_agent_config(&path).expect("agent-2.toml should load");
    assert_eq!(cfg.agent.id, "agent-2");
    assert!(!cfg.security.allowed_targets.is_empty());
}

/// A deployment-specific scenario directory with its own `certs/` inside;
/// it is not part of the shipped examples, so the test skips wholesale when
/// the directory is absent and discovers the agent configs by listing the
/// directory instead of hardcoding filenames.
#[test]
fn private_scenario_tomls_load() {
    let base = workspace_root().join("examples/reverse-tunnel-private");
    if !base.exists() {
        return;
    }

    let mut failures = Vec::new();
    match load_hub_config(base.join("hub.toml")) {
        Ok(cfg) if cfg.config_version == HUB_CONFIG_VERSION => {}
        Ok(cfg) => failures.push(format!(
            "hub.toml: config_version != {HUB_CONFIG_VERSION} ({})",
            cfg.config_version
        )),
        Err(e) => failures.push(format!("hub.toml: {e}")),
    }
    let mut agent_configs: Vec<PathBuf> = std::fs::read_dir(&base)
        .expect("scenario dir should be listable")
        .filter_map(|e| e.ok().map(|e| e.path()))
        .filter(|p| {
            p.file_name()
                .and_then(|n| n.to_str())
                .is_some_and(|n| n.starts_with("agent-") && n.ends_with(".toml"))
        })
        .collect();
    agent_configs.sort();
    for path in &agent_configs {
        let name = path
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("<non-utf8>");
        match load_agent_config(path) {
            Ok(cfg) if cfg.config_version == AGENT_CONFIG_VERSION => {}
            Ok(cfg) => failures.push(format!(
                "{name}: config_version != {AGENT_CONFIG_VERSION} ({})",
                cfg.config_version
            )),
            Err(e) => failures.push(format!("{name}: {e}")),
        }
    }
    assert!(
        !agent_configs.is_empty(),
        "scenario dir should contain agent-*.toml configs"
    );
    assert!(
        failures.is_empty(),
        "private scenario configs failed to load: {failures:#?}"
    );
}

#[test]
fn reject_missing_auth() {
    use interflow_mesh::config::{
        AclConfig, AuthConfig, AuthMode, HUB_CONFIG_VERSION, HubConfig, HubSecurityConfig,
        LoggingConfig, ServerConfig,
    };
    let cfg = HubConfig {
        config_version: HUB_CONFIG_VERSION,
        server: ServerConfig {
            listen_addr: "0.0.0.0:6666".parse().unwrap(),
        },
        auth: AuthConfig {
            mode: AuthMode::StaticToken,
            allow_anonymous: false,
            rate_limit_per_minute: 30,
            static_token: None,
            mtls: None,
        },
        tls: None,
        acl: AclConfig::default(),
        security: HubSecurityConfig::default(),
        heartbeat: Default::default(),
        metrics: Default::default(),
        audit: Default::default(),
        logging: LoggingConfig::default(),
        transport: Default::default(),
    };
    let err = interflow_mesh::config::validate_hub(&cfg).expect_err("should reject");
    assert!(
        err.iter()
            .any(|e| matches!(e, interflow_mesh::config::ConfigError::AuthRequired))
    );
}
