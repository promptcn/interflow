//! Coherence checks for the shipped generic example: the manifest must
//! parse and fully validate, and the helper scripts must stay on the
//! Credential-Pack path (no token auth, no raw certificate arguments).
//! (The promptcn deployment counterpart lives in
//! `private_promptcn_deployment.rs` — it reads the private `deployments/`
//! tree and never enters the public export.)

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

mod common;

#[test]
fn generic_public_domain_example_manifest_is_coherent() {
    let base = common::workspace_root().join("examples/public-domain-to-lan");
    let manifest = common::load_and_validate(&base.join("interflow.toml"));
    assert_eq!(manifest.realm.id, "example");
    assert_eq!(manifest.realm.control_endpoint, "relay.example.com:16666");
    assert_eq!(manifest.route.len(), 1);
    assert_eq!(manifest.route[0].host, "app.example.com");
    assert_eq!(manifest.route[0].service, "demo/lan-agent/web");

    // Scripts run nodes from packs only; nginx keeps the XFF + streaming
    // invariants the ingress's frontend-proxy mode relies on.
    for name in ["start-ingress.sh", "start-agent.sh"] {
        let text = std::fs::read_to_string(base.join(name)).unwrap();
        assert!(text.contains("run --pack"), "{name} must be pack-driven");
        assert!(
            !text.contains("--token") && !text.contains("INTERFLOW_EDGE_TOKEN"),
            "{name} must not use removed token auth"
        );
    }
    let nginx = std::fs::read_to_string(base.join("nginx.conf")).unwrap();
    assert!(nginx.contains("proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;"));
    assert!(nginx.contains("proxy_buffering off;"));
}

#[test]
fn just_public_example_recipes_are_pack_driven() {
    let justfile = std::fs::read_to_string(common::workspace_root().join("justfile")).unwrap();
    for recipe_name in [
        "example-public-domain-ingress",
        "example-public-domain-agent",
    ] {
        let recipe: Vec<&str> = justfile
            .lines()
            .skip_while(|line| !line.starts_with(recipe_name))
            .take_while(|line| {
                line.starts_with(recipe_name) || line.starts_with(' ') || line.is_empty()
            })
            .collect();
        let recipe = recipe.join("\n");
        assert!(
            recipe.contains("--bin interflow"),
            "{recipe_name} must build the CLI"
        );
        assert!(
            recipe.contains("--pack"),
            "{recipe_name} must run nodes from packs"
        );
    }
}
