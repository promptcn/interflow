//! `interflow-expose init` interactive wizard.
//!
//! Two branches:
//! - Public server: generate certificates + emit a routes.toml template + an nginx config snippet + the command line for the local user
//! - Local machine: write profile.toml so `interflow-expose expose <port>` just works

use crate::cert_gen;
use crate::profile::{Profile, save as save_profile};
use interflow_core::error::{InterflowError, Result};
use std::io::{self, BufRead, Write};
use std::path::PathBuf;

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

    let agent_token = prompt("Agent token (leave empty to auto-generate)")
        .ok()
        .filter(|s| !s.is_empty())
        .unwrap_or_else(generate_token);

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

    // Generate certificates
    println!(
        "\nGenerating CA + hub certificates into {}...",
        cert_dir.display()
    );
    let certs = cert_gen::generate(&cert_dir, &hub_domain)?;

    // Write the routes.toml template
    let routes_path = "routes.toml";
    let routes_template = format!(
        r#"# Edge routing table: each public domain → agent_id of the remote expose client + local service address
# On the local machine, run `interflow-expose expose <port> --agent-id <id>` with the matching agent_id
#
# Optional [logging] section (same schema as hub.toml): when present, SIGHUP
# hot-reloads `level` (e.g. "info,interflow_mesh=debug" to chase hub-side
# session rebuilds); a `format` change needs a restart.

[[routes]]
host = "{hub_domain}"
agent_id = "expose-myapp"          # agent_id used by the local expose
remote_addr = "127.0.0.1:3000"     # listen address of the local service

# [logging]
# level = "info"
"#,
    );
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
    println!("  - Certificates: {}", certs.ca_cert);
    println!("          {}", certs.hub_cert);
    println!("          {}", certs.hub_key);
    println!("  - Routing table: {routes_path} (edit host / agent_id / remote_addr as needed)");
    println!("  - Nginx snippet: {nginx_path}");
    println!("\nStart edge with:");
    println!("  interflow-expose edge \\");
    println!("    --listen 0.0.0.0:{public_listen_port} \\");
    println!("    --hub-listen 127.0.0.1:{internal_hub_port} \\");
    println!("    --routes {routes_path} \\");
    // Keep the shell continuation alive when QUIC flags follow.
    println!(
        "    --token {agent_token}{}",
        if quic_enabled { " \\" } else { "" }
    );
    // QUIC additions: the [tls] set serves both the h2 hub plane and the QUIC
    // plane (SAN = the hub domain, so clients dialing hub_quic_addr verify it).
    if let Some(addr) = quic_listen.as_deref() {
        println!("    --hub-cert {} \\", certs.hub_cert);
        println!("    --hub-key {} \\", certs.hub_key);
        println!("    --quic-listen {addr}");
        println!(
            "\n(QUIC plane: open the UDP port on the firewall — nginx does not carry it. \
             The certificate's SAN covers {hub_domain}.)"
        );
    }
    println!("\nGive this command to the local machine (exposing port 3000):");
    println!("  interflow-expose expose 3000 \\");
    println!("    --hub http://<public-domain>:{internal_hub_port} \\");
    println!("    --token {agent_token} \\");
    println!("    --agent-id expose-myapp \\");
    println!("    --ca-path {}", certs.ca_cert);
    if quic_enabled {
        println!("    --transport quic");
    }

    Ok(())
}

fn run_local_machine_wizard() -> Result<()> {
    println!("\n--- Local machine setup ---");

    let hub_url = prompt("Public hub URL (e.g. http://hub.example.com:16666)")?;
    if hub_url.is_empty() {
        return Err(InterflowError::config("hub URL must not be empty"));
    }
    let token = prompt("Agent token")?;
    if token.is_empty() {
        return Err(InterflowError::config("token must not be empty"));
    }
    let agent_id = prompt("Agent ID (must match the one referenced in edge's routes.toml)")?;
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
        auth_token: Some(token),
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

fn generate_token() -> String {
    // 256 random bytes hex-encoded → a 64-character token, from the OS CSPRNG.
    // No UUID: a UUID is an identifier, not a secret — wrong semantics.
    let bytes: [u8; 32] = rand::random();
    format!("expose-{}", hex::encode(bytes))
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
}
