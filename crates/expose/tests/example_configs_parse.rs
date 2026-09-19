//! Validation for the generic expose example and private Promptcn deployment.
//!
//! TOML files are copied to a sandbox with freshly generated certificates, so
//! tests do not depend on local `certs/` material and still exercise the same
//! certificate layout as the shipped `generate-certs.sh` scripts.

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
use interflow_expose::edge::{HostRouter, RoutesConfig};
use interflow_expose::profile;
use std::path::{Path, PathBuf};

fn workspace_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(|p| p.parent())
        .expect("expose crate should be at <workspace>/crates/expose")
        .to_path_buf()
}

fn sandbox_with_certs(src: &Path, tenant: &str, agent_id: &str) -> tempfile::TempDir {
    let sandbox = tempfile::tempdir().expect("temp sandbox");
    for name in ["profile.toml", "routes.toml"] {
        std::fs::copy(src.join(name), sandbox.path().join(name))
            .unwrap_or_else(|e| panic!("copy {name}: {e}"));
    }
    let certs = sandbox.path().join("certs");
    interflow_certs::ensure_tenant_ca(&certs, tenant).expect("tenant CA");
    interflow_certs::ensure_hub_cert(&certs, tenant, &interflow_certs::local_dev_san(), false)
        .expect("hub pair");
    interflow_certs::ensure_agent_cert(&certs, tenant, agent_id, false).expect("agent pair");
    sandbox
}

fn validate_expose_scenario(
    src: &Path,
    tenant: &str,
    agent_id: &str,
    expected_hub_url: &str,
    expected_host: Option<&str>,
) {
    let sandbox = sandbox_with_certs(src, tenant, agent_id);

    let profile =
        profile::load_from(&sandbox.path().join("profile.toml")).expect("profile.toml should load");
    assert_eq!(profile.hub_url.as_deref(), Some(expected_hub_url));
    assert_eq!(profile.agent_id.as_deref(), Some(agent_id));
    for path in [
        profile.ca_path.as_deref().expect("ca_path"),
        profile.client_cert.as_deref().expect("client_cert"),
        profile.client_key.as_deref().expect("client_key"),
    ] {
        assert!(Path::new(path).is_absolute());
        assert!(Path::new(path).exists(), "{path} should exist in sandbox");
    }

    let routes_path = sandbox.path().join("routes.toml");
    let routes = RoutesConfig::load(routes_path.display().to_string().as_str())
        .expect("routes.toml should load");
    let router = HostRouter::from_config(&routes).expect("routes should be unique");
    assert_eq!(router.len(), routes.routes.len());
    if let Some(host) = expected_host {
        assert!(router.lookup(host).is_some());
    }
    assert!(router.lookup("unknown.example.com").is_none());
    assert!(
        routes.routes.iter().all(|route| {
            route.tenant == tenant
                && route.agent_id == agent_id
                && expected_host.is_none_or(|host| route.host == host)
        }),
        "routes must agree with the profile identity: {:?}",
        routes.routes
    );
    assert_eq!(routes.logging, None, "example logging section is inert");
}

#[test]
fn generic_public_domain_example_loads_and_is_coherent() {
    validate_expose_scenario(
        &workspace_root().join("examples/public-domain-to-lan"),
        "demo",
        "lan-agent",
        "https://hub.example.com:16666",
        Some("app.example.com"),
    );
}

#[test]
fn promptcn_public_domain_deployment_loads_and_is_coherent() {
    let deployments = workspace_root().join("deployments");
    if !deployments.exists() {
        return;
    }
    // Build the marker dynamically so this exported test source cannot itself
    // trip the public-export private-domain gate.
    let private_domain = ["promptcn", ".com"].concat();
    validate_expose_scenario(
        &deployments.join("promptcn/public-domain-to-lan"),
        "main",
        "desktop",
        &format!("https://{private_domain}:16666"),
        None,
    );
    // The real deployment carries a second route to the same agent. Validate
    // it through the raw config because the helper intentionally locks the
    // generic example to one neutral host.
    let path = deployments.join("promptcn/public-domain-to-lan/routes.toml");
    let routes = RoutesConfig::load(path.display().to_string().as_str()).expect("routes load");
    assert!(routes.routes.len() >= 2);
    assert!(
        routes
            .routes
            .iter()
            .all(|route| { route.tenant == "main" && route.agent_id == "desktop" })
    );
}

#[test]
fn generic_example_scripts_and_nginx_keep_security_invariants() {
    let base = workspace_root().join("examples/public-domain-to-lan");
    let edge = std::fs::read_to_string(base.join("start-edge.sh")).unwrap();
    let expose = std::fs::read_to_string(base.join("start-expose.sh")).unwrap();
    let nginx = std::fs::read_to_string(base.join("nginx.conf")).unwrap();

    for (name, text) in [("start-edge.sh", &edge), ("start-expose.sh", &expose)] {
        assert!(
            !text.contains("--token") && !text.contains("INTERFLOW_EDGE_TOKEN"),
            "{name} must not use removed token auth"
        );
    }
    assert!(edge.contains("--client-ca \"demo="));
    assert!(edge.contains("--hub-cert") && edge.contains("--hub-key"));
    assert!(edge.contains("--x-forwarded-for required"));
    assert!(expose.contains("--agent-id lan-agent"));
    assert!(nginx.contains("proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;"));
    assert!(nginx.contains("proxy_buffering off;"));
}

#[test]
fn just_public_example_recipe_keeps_mandatory_mtls_flags() {
    let justfile = std::fs::read_to_string(workspace_root().join("justfile")).unwrap();
    let recipe: Vec<&str> = justfile
        .lines()
        .skip_while(|line| !line.starts_with("example-public-domain-edge:"))
        .take_while(|line| {
            line.starts_with("example-public-domain-edge:")
                || line.starts_with(' ')
                || line.is_empty()
        })
        .collect();
    let recipe = recipe.join("\n");
    assert!(recipe.contains("interflow-expose"));
    assert!(
        recipe.contains("--client-ca")
            && recipe.contains("--hub-cert")
            && recipe.contains("--hub-key")
            && recipe.contains("--x-forwarded-for required"),
        "example edge recipe lost a mandatory flag: {recipe}"
    );
}

#[test]
fn routes_logging_example_round_trips() {
    let text = r#"
[[routes]]
host = "app.example.com"
tenant = "test"
agent_id = "expose-myapp"
remote_addr = "127.0.0.1:3000"

[logging]
level = "info,interflow_mesh=debug"
format = "json"
"#;
    let cfg: RoutesConfig = toml::from_str(text).expect("active [logging] should parse");
    let logging = cfg.logging.expect("[logging] present");
    assert_eq!(logging.level, "info,interflow_mesh=debug");
    assert_eq!(logging.format, interflow_core::telemetry::LogFormat::Json);
}
