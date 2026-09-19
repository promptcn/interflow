//! `interflow-expose init` interactive wizard.
//!
//! Two branches:
//! - Public server: generate certificates + emit a routes.toml template + an nginx config snippet + the command line for the local user
//! - Local machine: write profile.toml so `interflow-expose expose <port>` just works

use crate::profile::{Profile, save as save_profile};
use interflow_core::error::{InterflowError, Result};
use std::io::{self, BufRead, Write};
use std::path::PathBuf;

/// Maps issuance errors into the wizard's error type (the message carries
/// the concrete mismatch/remediation from interflow-certs).
#[allow(clippy::needless_pass_by_value)] // consumed conceptually: mapped into the target error
fn cert_err(e: interflow_certs::Error) -> InterflowError {
    InterflowError::config(e.to_string())
}

/// Runs the wizard. The `stdin` source is up to the caller (interactive/pipe).
pub fn run() -> Result<()> {
    println!("=== Interflow Expose setup wizard ===\n");
    println!(
        "This tool helps you generate certificates and config files so a single command can expose a local service on a public domain."
    );
    println!("\nChoose the role of this machine:");
    println!("  [1] Public server (runs interflow-expose edge, nginx in front)");
    println!("  [2] Local machine (runs interflow-expose expose <port>)");
    let role = prompt("Choice [1/2]")?;
    match role.as_str() {
        "1" => run_public_server_wizard(),
        "2" => run_local_machine_wizard(),
        other => Err(InterflowError::config(format!("unknown option: {other}"))),
    }
}

fn run_public_server_wizard() -> Result<()> {
    println!("\n--- Public server setup ---");

    let hub_domain = prompt("Domain for public access (e.g. hub.example.com)")?;
    if hub_domain.is_empty() {
        return Err(InterflowError::config("domain must not be empty"));
    }

    let public_listen_port: u16 = prompt("edge public listen port (default 8443)")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(8443);
    let internal_hub_port: u16 = prompt("internal hub listen port (default 16666)")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(16666);

    // Tenant trust entry: the wizard generates one tenant CA; the edge trusts
    // client certificates issued by it (mTLS-only — there is no token
    // authentication any more).
    let tenant_name = prompt("Tenant name for the client CA (default main)")
        .ok()
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| "main".into());
    interflow_certs::validate_name("tenant", &tenant_name).map_err(cert_err)?;

    // The wizard issues one agent certificate; its CN must equal the agent_id
    // the local machine will use (also written into the routes.toml template
    // below, so the three stay consistent by construction).
    let agent_id = prompt("Agent ID for the local machine (default expose-myapp)")
        .ok()
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| "expose-myapp".into());
    interflow_certs::validate_name("agent", &agent_id).map_err(cert_err)?;

    // QUIC plane (opt-in): one QUIC stream per tunnel stream — eliminates TCP
    // head-of-line blocking. The UDP port bypasses nginx entirely, so the
    // listen address must be publicly reachable.
    let quic_enabled = prompt_yes_no("Enable the QUIC listener for expose clients?", false)?;
    let quic_listen = if quic_enabled {
        let default_addr = format!("0.0.0.0:{internal_hub_port}");
        let addr = prompt(&format!(
            "QUIC listen address (default {default_addr}; same port number as the hub keeps the dual-stack default)"
        ))
        .ok()
        .filter(|s| !s.is_empty())
        .unwrap_or(default_addr);
        Some(addr)
    } else {
        None
    };

    let cert_dir = PathBuf::from(
        prompt("Certificate output directory (default ./certs)")
            .ok()
            .filter(|s| !s.is_empty())
            .unwrap_or_else(|| "./certs".into()),
    );

    // Generate certificates (tenant CA + hub pair + one agent client pair).
    // Idempotent: an existing, matching set is validated and reused instead
    // of being blindly overwritten (overwriting a CA would silently
    // invalidate every certificate it already issued).
    println!("\nGenerating certificates into {}...", cert_dir.display());
    let certs = interflow_certs::generate(
        &cert_dir,
        &[interflow_certs::SanName::Dns(hub_domain.clone())],
        &tenant_name,
        std::slice::from_ref(&agent_id),
    )
    .map_err(cert_err)?;

    // Write the routes.toml template
    let routes_path = "routes.toml";
    let routes_template = routes_template(&hub_domain, &tenant_name, &agent_id);
    std::fs::write(routes_path, routes_template).map_err(|e| {
        InterflowError::config(format!("failed to write {routes_path}")).with_source(e)
    })?;

    // Write the nginx snippet
    let nginx_snippet = nginx_snippet(&hub_domain, public_listen_port);
    let nginx_path = "nginx.conf.snippet";
    std::fs::write(nginx_path, nginx_snippet).map_err(|e| {
        InterflowError::config(format!("failed to write {nginx_path}")).with_source(e)
    })?;

    println!("\n✅ Setup complete. Files written:");
    println!(
        "  - Tenant CA: {} (registered on the edge below)",
        certs.ca_cert
    );
    println!(
        "     CA key:   {} (0600 — must NEVER leave this machine)",
        certs.ca_key
    );
    println!("  - Hub pair:  {} / {}", certs.hub_cert, certs.hub_key);
    for agent in &certs.agents {
        println!(
            "  - Agent {} certificate: {} / {}",
            agent.agent_id, agent.cert, agent.key
        );
    }
    println!("  - Routing table: {routes_path} (edit host / agent_id / remote_addr as needed)");
    println!("  - Nginx snippet: {nginx_path}");
    println!("\nStart edge with:");
    print!(
        "{}",
        edge_command(
            public_listen_port,
            internal_hub_port,
            routes_path,
            &tenant_name,
            &certs.ca_cert,
            &certs.hub_cert,
            &certs.hub_key,
            quic_listen.as_deref(),
        )
    );
    if quic_enabled {
        println!(
            "(QUIC plane: open the UDP port on the firewall; nginx does not carry it. \
             The certificate's SAN covers {hub_domain}.)"
        );
    }
    // The wizard issues exactly one agent pair; unwrap is the template flow.
    let agent = certs
        .agents
        .first()
        .ok_or_else(|| InterflowError::config("wizard must issue one agent certificate"))?;
    println!("\nCopy these files to the local machine (keep the agent key 0600):");
    println!("  {} / {} / {}", agent.cert, agent.key, certs.ca_cert);
    println!("\nGive this command to the local machine (exposing port 3000):");
    print!(
        "{}",
        expose_command(
            &hub_domain,
            internal_hub_port,
            &agent.cert,
            &agent.key,
            &agent.agent_id,
            &certs.ca_cert,
            quic_enabled,
        )
    );

    Ok(())
}

fn run_local_machine_wizard() -> Result<()> {
    println!("\n--- Local machine setup ---");

    let hub_url = prompt("Public hub URL (e.g. https://hub.example.com:16666)")?;
    if hub_url.is_empty() {
        return Err(InterflowError::config("hub URL must not be empty"));
    }
    let client_cert = prompt(
        "Client certificate path (issued by a tenant CA — by `interflow-mesh certs agent issue` or the public server's init wizard)",
    )?;
    if client_cert.is_empty() {
        return Err(InterflowError::config(
            "client certificate path must not be empty",
        ));
    }
    let client_key = prompt("Client key path (0600)")?;
    if client_key.is_empty() {
        return Err(InterflowError::config("client key path must not be empty"));
    }
    let agent_id =
        prompt("Agent ID (must equal the client certificate's CN and the routes.toml reference)")?;
    if agent_id.is_empty() {
        return Err(InterflowError::config("agent_id must not be empty"));
    }
    let ca_path = prompt("Hub CA certificate path (required when the hub uses a self-signed cert; only effective for https)")
        .ok()
        .filter(|s| !s.is_empty());

    // QUIC transport (opt-in): the edge must have its QUIC listener enabled.
    // The QUIC address stays unset so it derives from the hub URL's host:port
    // (the edge dual-stack default); an explicit value can be added to the
    // profile later if the edge uses a dedicated QUIC port.
    let transport = if prompt_yes_no(
        "Use the QUIC transport toward the hub? (edge must have its QUIC listener enabled)",
        false,
    )? {
        Some(interflow_mesh::config::TransportKind::Quic)
    } else {
        None
    };

    let profile = Profile {
        hub_url: Some(hub_url),
        client_cert: Some(client_cert),
        client_key: Some(client_key),
        agent_id: Some(agent_id),
        ca_path,
        local_ports: None,
        transport,
        hub_quic_addr: None,
    };
    save_profile(&profile)
        .map_err(|e| InterflowError::config("failed to write profile").with_source(e))?;

    println!("\n✅ Profile saved. You can now expose a local service with a single command:");
    println!("  interflow-expose expose 3000");
    Ok(())
}

fn prompt(label: &str) -> Result<String> {
    print!("{label}: ");
    io::stdout().flush()?;
    let stdin = io::stdin();
    let mut line = String::new();
    stdin.lock().read_line(&mut line)?;
    Ok(line.trim().to_string())
}

/// The routes.toml template written by the public-server wizard (pure
/// builder — unit-locked against the v4 schema, especially the required
/// `tenant` field).
fn routes_template(hub_domain: &str, tenant: &str, agent_id: &str) -> String {
    format!(
        r#"# Edge routing table: each public domain → (tenant, agent_id) of the
# remote expose client + its local service address. The tenant must match the
# CA that issued the agent's client certificate (`--client-ca <tenant>=...`).
#
# Optional [logging] section (same schema as hub.toml): when present, SIGHUP
# hot-reloads `level` (e.g. "info,interflow_mesh=debug" to chase hub-side
# session rebuilds); a `format` change needs a restart.

[[routes]]
host = "{hub_domain}"
tenant = "{tenant}"
agent_id = "{agent_id}"             # agent_id used by the local expose
remote_addr = "127.0.0.1:3000"     # listen address of the local service

# [logging]
# level = "info"
"#
    )
}

/// The edge startup command printed by the wizard (pure builder). Always
/// carries the v4-mandatory TLS pair + tenant trust entry; XFF restoration
/// is the standard nginx HTTP `proxy_pass` topology's real-IP mechanism.
#[allow(clippy::too_many_arguments)]
fn edge_command(
    public_listen_port: u16,
    internal_hub_port: u16,
    routes_path: &str,
    tenant: &str,
    ca_cert: &str,
    hub_cert: &str,
    hub_key: &str,
    quic_listen: Option<&str>,
) -> String {
    let mut lines = vec![
        "  interflow-expose edge \\".to_string(),
        format!("    --listen 0.0.0.0:{public_listen_port} \\"),
        format!("    --hub-listen 0.0.0.0:{internal_hub_port} \\"),
        format!("    --routes {routes_path} \\"),
        format!("    --client-ca {tenant}={ca_cert} \\"),
        format!("    --hub-cert {hub_cert} \\"),
        format!("    --hub-key {hub_key} \\"),
        "    --x-forwarded-for required".to_string(),
    ];
    if let Some(addr) = quic_listen {
        lines.push(format!("    --quic-listen {addr}"));
    }
    lines.join("\n") + "\n"
}

/// The expose client command printed by the wizard (pure builder). The hub
/// plane is mTLS + TLS: the URL must be https and the client pair is
/// mandatory.
#[allow(clippy::too_many_arguments)]
fn expose_command(
    hub_domain: &str,
    internal_hub_port: u16,
    agent_cert: &str,
    agent_key: &str,
    agent_id: &str,
    ca_cert: &str,
    quic: bool,
) -> String {
    let mut lines = vec![
        "  interflow-expose expose 3000 \\".to_string(),
        format!("    --hub https://{hub_domain}:{internal_hub_port} \\"),
        format!("    --client-cert {agent_cert} \\"),
        format!("    --client-key {agent_key} \\"),
        format!("    --agent-id {agent_id} \\"),
        format!("    --ca-path {ca_cert}"),
    ];
    if quic {
        lines.push("    --transport quic".to_string());
    }
    lines.join("\n") + "\n"
}

/// Yes/no prompt: empty input takes the default (mirroring the wizard's
/// "[y/N]"-style conventions; anything not starting with y/Y counts as no).
fn prompt_yes_no(label: &str, default: bool) -> Result<bool> {
    let hint = if default { "[Y/n]" } else { "[y/N]" };
    let answer = prompt(&format!("{label} {hint}"))?;
    if answer.is_empty() {
        return Ok(default);
    }
    Ok(answer.starts_with('y') || answer.starts_with('Y'))
}

/// Nginx reverse-proxy snippet. The SSE trio (`proxy_http_version` /
/// `proxy_read_timeout` / `proxy_buffering`) is indispensable: nginx's default
/// `proxy_read_timeout 60s` would cut the connection after 60s of silence,
/// ahead of the edge's stream idle budget (`--stream-idle-timeout-secs`,
/// default 300s), and the default buffering would break per-token streaming.
fn nginx_snippet(hub_domain: &str, public_listen_port: u16) -> String {
    format!(
        r"# nginx config snippet: proxy_pass public HTTPS traffic to edge
server {{
    listen 443 ssl http2;
    server_name {hub_domain};

    ssl_certificate     /path/to/fullchain.pem;   # your public certificate
    ssl_certificate_key /path/to/privkey.pem;

    location / {{
        proxy_pass http://127.0.0.1:{public_listen_port};
        proxy_set_header Host $host;
        # Real client IP for the edge's per-IP limits / caps / audit
        # (consumed with the edge's --x-forwarded-for required).
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_http_version 1.1;
        # >= edge stream idle timeout (--stream-idle-timeout-secs, default 300s); required for SSE / long silent windows
        proxy_read_timeout 6m;
        # keep per-token SSE streaming from being buffered by nginx
        proxy_buffering off;
        # no WebSocket upgrade; use the nginx stream module for L4 passthrough
    }}
}}
"
    )
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    /// The SSE trio is indispensable: nginx's default `proxy_read_timeout 60s`
    /// plus its default buffering would truncate long silent streams and
    /// break per-token streaming (§3.3 audit gap; must fail until fixed).
    #[test]
    fn nginx_snippet_contains_sse_trio() {
        let snippet = nginx_snippet("hub.example.com", 8443);
        assert!(
            snippet.contains("proxy_http_version 1.1;"),
            "missing proxy_http_version: {snippet}"
        );
        assert!(
            snippet.contains("proxy_read_timeout"),
            "missing proxy_read_timeout: {snippet}"
        );
        assert!(
            snippet.contains("proxy_buffering off;"),
            "missing proxy_buffering off: {snippet}"
        );
        // Budget alignment: read_timeout (6m) must be ≥ the edge default idle (300s = 5m)
        assert!(
            snippet.contains("proxy_read_timeout 6m;"),
            "proxy_read_timeout should be 6m (≥ edge default 300s): {snippet}"
        );
    }

    /// The snippet feeds the edge's XFF restoration — without the header
    /// the edge's `--x-forwarded-for required` would reject every request.
    #[test]
    fn nginx_snippet_forwards_real_client_ip() {
        let snippet = nginx_snippet("hub.example.com", 8443);
        assert!(
            snippet.contains("proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;"),
            "missing X-Forwarded-For: {snippet}"
        );
    }

    /// The routes template must parse under the shipped v4 schema
    /// (`deny_unknown_fields`) — the wizard output is copy-pasted verbatim.
    #[test]
    fn routes_template_parses_with_tenant() {
        let text = routes_template("hub.example.com", "main", "expose-myapp");
        let cfg: crate::edge::RoutesConfig =
            toml::from_str(&text).expect("wizard routes template should parse");
        let route = cfg.routes.first().expect("one route");
        assert_eq!(route.tenant, "main");
        assert_eq!(route.agent_id, "expose-myapp");
        assert_eq!(route.host, "hub.example.com");
    }

    /// The printed edge command carries the v4-mandatory TLS pair, the
    /// tenant trust entry, and the nginx-topology real-IP flag.
    #[test]
    fn edge_command_carries_mtls_and_real_ip_flags() {
        let cmd = edge_command(
            8443,
            16666,
            "routes.toml",
            "main",
            "certs/tenants/main-ca.crt",
            "certs/hub.crt",
            "certs/hub.key",
            None,
        );
        assert!(
            cmd.contains("--client-ca main=certs/tenants/main-ca.crt"),
            "{cmd}"
        );
        assert!(cmd.contains("--hub-cert certs/hub.crt"), "{cmd}");
        assert!(cmd.contains("--hub-key certs/hub.key"), "{cmd}");
        assert!(cmd.contains("--x-forwarded-for required"), "{cmd}");

        let quic = edge_command(
            8443,
            16666,
            "routes.toml",
            "main",
            "certs/tenants/main-ca.crt",
            "certs/hub.crt",
            "certs/hub.key",
            Some("0.0.0.0:16666"),
        );
        assert!(quic.contains("--quic-listen 0.0.0.0:16666"), "{quic}");
    }

    /// The printed expose command must use the TLS hub URL and the
    /// mandatory client pair (v4 mTLS-only).
    #[test]
    fn expose_command_is_https_mtls() {
        let cmd = expose_command(
            "hub.example.com",
            16666,
            "certs/agents/expose-myapp.crt",
            "certs/agents/expose-myapp.key",
            "expose-myapp",
            "certs/tenants/main-ca.crt",
            false,
        );
        assert!(cmd.contains("--hub https://hub.example.com:16666"), "{cmd}");
        assert!(
            cmd.contains("--client-cert certs/agents/expose-myapp.crt"),
            "{cmd}"
        );
        assert!(
            cmd.contains("--client-key certs/agents/expose-myapp.key"),
            "{cmd}"
        );
        assert!(cmd.contains("--ca-path certs/tenants/main-ca.crt"), "{cmd}");

        let quic = expose_command(
            "hub.example.com",
            16666,
            "c.crt",
            "c.key",
            "a",
            "ca.crt",
            true,
        );
        assert!(quic.contains("--transport quic"), "{quic}");
    }
}
