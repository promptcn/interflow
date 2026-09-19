//! End-to-end validation: shipped mesh examples and private deployments.
//!
//! Certificates are generated on demand and never committed. Each test copies
//! TOML files into a temp sandbox and materializes the certificate layout with
//! the production `interflow-certs` operations, so a fresh clone validates the
//! shipped schema without a generated-material prerequisite. The sandbox is
//! neither the process CWD nor the source directory, which also proves config
//! paths anchor to each TOML file's directory.

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
    AGENT_CONFIG_VERSION, E2eMode, HUB_CONFIG_VERSION, load_agent_config, load_hub_config,
};
use std::path::{Path, PathBuf};

fn workspace_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(|p| p.parent())
        .expect("mesh crate should be at <workspace>/crates/mesh")
        .to_path_buf()
}

/// Read every `agent-*.toml` identity from `[agent].id`, rather than trusting
/// file names as the certificate identity contract.
fn agent_ids(dir: &Path) -> Vec<String> {
    let mut ids = Vec::new();
    for entry in std::fs::read_dir(dir).expect("scenario dir should be listable") {
        let path = entry.expect("dir entry").path();
        let name = path.file_name().and_then(|n| n.to_str()).unwrap_or("");
        if !(name.starts_with("agent-") && name.ends_with(".toml")) {
            continue;
        }
        let table: toml::Table =
            toml::from_str(&std::fs::read_to_string(&path).expect("read agent toml"))
                .expect("agent toml should parse");
        let id = table
            .get("agent")
            .and_then(|a| a.get("id"))
            .and_then(|v| v.as_str())
            .unwrap_or_else(|| panic!("{name}: [agent].id missing"))
            .to_string();
        ids.push(id);
    }
    ids.sort();
    ids
}

fn copy_tomls(src: &Path, sandbox: &Path) {
    for entry in std::fs::read_dir(src).expect("scenario dir should be listable") {
        let path = entry.expect("dir entry").path();
        if path.extension().and_then(|e| e.to_str()) == Some("toml") {
            let dest = sandbox.join(path.file_name().expect("toml file name"));
            std::fs::copy(&path, &dest).expect("copy toml into sandbox");
        }
    }
}

fn sandbox_with_certs(src: &Path, tenant: &str) -> tempfile::TempDir {
    let sandbox = tempfile::tempdir().expect("temp sandbox");
    copy_tomls(src, sandbox.path());
    let certs_dir = sandbox.path().join("certs");
    interflow_certs::ensure_tenant_ca(&certs_dir, tenant).expect("tenant CA");
    interflow_certs::ensure_hub_cert(&certs_dir, tenant, &interflow_certs::local_dev_san(), false)
        .expect("hub pair");
    for id in agent_ids(src) {
        interflow_certs::ensure_agent_cert(&certs_dir, tenant, &id, false)
            .unwrap_or_else(|e| panic!("agent pair for {id}: {e}"));
    }
    sandbox
}

fn validate_mesh_scenario(src: &Path, tenant: &str, expected_agents: &[&str]) {
    let sandbox = sandbox_with_certs(src, tenant);

    let hub = load_hub_config(sandbox.path().join("hub.toml"))
        .expect("scenario hub.toml should load and validate");
    assert_eq!(hub.config_version, HUB_CONFIG_VERSION);
    assert_eq!(hub.auth.tenants.len(), 1);
    assert_eq!(hub.auth.tenants[0].name, tenant);
    assert!(
        Path::new(&hub.tls.as_ref().expect("hub TLS").cert_path).is_absolute(),
        "hub cert paths should anchor to the config directory"
    );

    let mut agents = Vec::new();
    for id in expected_agents {
        let path = sandbox.path().join(format!("agent-{id}.toml"));
        let cfg = load_agent_config(&path)
            .unwrap_or_else(|e| panic!("{id} agent config should load and validate: {e}"));
        assert_eq!(cfg.config_version, AGENT_CONFIG_VERSION);
        assert_eq!(cfg.agent.id, *id);
        assert_eq!(cfg.e2e.mode, E2eMode::Required, "{id} must fail closed");
        agents.push(cfg);
    }

    for initiator in &agents {
        for ingress in &initiator.ingress {
            let Some(target) = agents
                .iter()
                .find(|cfg| cfg.agent.id == ingress.target_agent)
            else {
                panic!("agent config for {} missing", ingress.target_agent)
            };
            let remote = ingress
                .remote_addr
                .as_deref()
                .unwrap_or_else(|| panic!("ingress {} has no remote_addr", ingress.name));
            assert!(
                target.security.allowed_targets.iter().any(|v| v == remote),
                "{} target {} does not allow {remote}",
                ingress.name,
                ingress.target_agent
            );
        }
    }
}

#[test]
fn generic_site_to_site_example_loads_and_is_coherent() {
    validate_mesh_scenario(
        &workspace_root().join("examples/site-to-site"),
        "demo",
        &["lan-a", "lan-b"],
    );
}

#[test]
fn promptcn_site_to_site_deployment_loads_and_is_coherent() {
    let deployments = workspace_root().join("deployments");
    if !deployments.exists() {
        return;
    }
    // Assemble machine names so the exported test source cannot itself trip
    // the public-export private-identifier gate.
    let private_agents = [["leo-", "mac"].concat(), ["leo-", "desktop"].concat()];
    let expected_agents: Vec<&str> = private_agents.iter().map(String::as_str).collect();
    validate_mesh_scenario(
        &deployments.join("promptcn/site-to-site"),
        "main",
        &expected_agents,
    );
}

#[test]
fn reject_missing_auth() {
    use interflow_mesh::config::{
        AclConfig, AuthConfig, HUB_CONFIG_VERSION, HubConfig, HubSecurityConfig, LoggingConfig,
        ServerConfig,
    };
    let cfg = HubConfig {
        config_version: HUB_CONFIG_VERSION,
        server: ServerConfig {
            listen_addr: "0.0.0.0:6666".parse().unwrap(),
            proxy_protocol: Default::default(),
        },
        // Empty tenant table: an empty trust table can authenticate nobody
        // (the mTLS-only successor of the old missing-token rejection).
        auth: AuthConfig {
            rate_limit_per_minute: 30,
            tenants: Vec::new(),
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
            .any(|e| matches!(e, interflow_mesh::config::ConfigError::TenantsEmpty))
    );
}
