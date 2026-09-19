//! `interflow-mesh certs` — the operator-facing certificate tool
//! (design §2.4, docs/design/multi-tenant-mtls-only.md).
//!
//! One command per identity; all issuance goes through `interflow-certs`
//! (the same implementation the expose init wizard and the test kit use).
//! Every op is idempotent: existing files are validated (chain, pairing,
//! CN/SAN/EKU, validity window) and reported, never blindly skipped or
//! overwritten — mismatches fail with the concrete difference and a
//! remediation.
//!
//! Run this on an OPERATOR machine. The tenant CA private key must never
//! live on the hub host (the hub only reads public CA certificates).

use clap::Subcommand;
use interflow_certs::{
    Error, Outcome, Result, SanName, ensure_agent_cert, ensure_hub_cert, ensure_tenant_ca,
    local_dev_san,
};
use std::io::{BufRead, IsTerminal, Write};
use std::path::Path;

/// The `certs` subcommand tree (see [`crate::certs`] module docs).
#[derive(Subcommand)]
pub enum CertsCommand {
    /// Initialize a certificate directory: first tenant CA + hub server pair
    Init {
        /// Output directory (created if missing)
        #[arg(long, default_value = "certs")]
        out: std::path::PathBuf,
        /// Tenant name for the first CA
        #[arg(long, default_value = "main")]
        tenant: String,
        /// Hostname(s)/IP(s) agents use to reach the hub — becomes the hub
        /// certificate's SAN. Comma- or space-separated for multiple values.
        /// Omit only for local development (default SAN: localhost, 127.0.0.1)
        #[arg(long = "hub-dns", value_name = "NAME", value_delimiter = ',', num_args = 1..)]
        hub_dns: Vec<String>,
        /// Non-interactive: accept the local-development SAN without prompting
        #[arg(long)]
        yes: bool,
        /// Re-issue the hub pair (renewal). The tenant CA is never rebuilt
        #[arg(long)]
        force: bool,
    },
    /// Tenant CA management
    Tenant {
        #[command(subcommand)]
        command: TenantCommand,
    },
    /// Agent client certificate management
    Agent {
        #[command(subcommand)]
        command: AgentCommand,
    },
    /// Expose gateway material (e2e stable anchor)
    Gateway {
        #[command(subcommand)]
        command: GatewayCommand,
    },
}

#[derive(Subcommand)]
pub enum TenantCommand {
    /// Create an additional tenant CA under `<out>/tenants/`
    New {
        /// Tenant name (also the hub.toml `[[auth.tenants]]` name)
        name: String,
        /// Output directory
        #[arg(long, default_value = "certs")]
        out: std::path::PathBuf,
    },
}

#[derive(Subcommand)]
pub enum AgentCommand {
    /// Issue an agent client certificate: `agents/<AGENT_ID>.crt|key`
    /// (CN == AGENT_ID, ClientAuth EKU, issued by the tenant CA)
    Issue {
        /// Tenant whose CA issues the certificate
        tenant: String,
        /// Agent id — becomes the file name AND the certificate CN (the hub
        /// enforces CN == registered agent_id during the mTLS handshake)
        agent_id: String,
        /// Output directory (must contain `tenants/<TENANT>-ca.*`)
        #[arg(long, default_value = "certs")]
        out: std::path::PathBuf,
        /// Re-issue even if the pair already exists (renewal; no revocation —
        /// the previous certificate stays valid until its own expiry)
        #[arg(long)]
        force: bool,
    },
}

#[derive(Subcommand)]
pub enum GatewayCommand {
    /// Issue the stable gateway identity: `gateway/gateway-ca.crt|key` +
    /// `gateway/edge.crt|key` (a dedicated gateway CA and its CN=edge
    /// client pair; RFC docs/design/agent-e2e-encryption.md §3.4/§5.2)
    Issue {
        /// Output directory
        #[arg(long, default_value = "certs")]
        out: std::path::PathBuf,
        /// Re-issue the client pair (renewal; the gateway CA is never
        /// rebuilt — every distributed egress anchor depends on it; no
        /// revocation — the previous certificate stays valid until its own
        /// expiry)
        #[arg(long)]
        force: bool,
    },
}

/// Entry point dispatched from the binary's `main`.
pub fn run(command: CertsCommand) -> Result<()> {
    match command {
        CertsCommand::Init {
            out,
            tenant,
            hub_dns,
            yes,
            force,
        } => run_init(&out, &tenant, &hub_dns, yes, force),
        CertsCommand::Tenant {
            command: TenantCommand::New { name, out },
        } => run_tenant_new(&name, &out),
        CertsCommand::Agent {
            command:
                AgentCommand::Issue {
                    tenant,
                    agent_id,
                    out,
                    force,
                },
        } => run_agent_issue(&tenant, &agent_id, &out, force),
        CertsCommand::Gateway {
            command: GatewayCommand::Issue { out, force },
        } => run_gateway_issue(&out, force),
    }
}

fn run_init(out: &Path, tenant: &str, hub_dns: &[String], yes: bool, force: bool) -> Result<()> {
    let names = resolve_hub_names(hub_dns, yes)?;
    let san = fmt_names(&names);

    let (ca_outcome, ca) = ensure_tenant_ca(out, tenant)?;
    report_outcome(
        &format!("tenant CA ({tenant})"),
        ca_outcome,
        &ca.cert,
        &ca.key,
    );
    let (hub_outcome, hub) = ensure_hub_cert(out, tenant, &names, force)?;
    report_outcome("hub certificate", hub_outcome, &hub.cert, &hub.key);
    println!("    hub SAN: {san}");
    if force {
        println!(
            "    note: --force re-issues without revocation — the previous hub certificate \
             stays valid until its own expiry"
        );
    }

    print_tree(out);
    println!();
    println!("Distribution (minimum sets — copy nothing else):");
    println!("  - hub host:   hub.crt  hub.key  {}", ca.cert.display());
    println!(
        "  - agent host: agents/<id>.crt  agents/<id>.key  {}",
        ca.cert.display()
    );
    println!(
        "                (issued with: interflow-mesh certs agent issue {tenant} <id> --out {})",
        out.display()
    );
    print_ca_key_warning(&ca.key, tenant);
    println!();
    println!("Next steps:");
    println!("  - hub.toml:");
    println!("      [[auth.tenants]]");
    println!("      name = \"{tenant}\"");
    println!("      ca_path = \"{}\"", ca.cert.display());
    println!("      [tls]");
    println!("      cert_path = \"{}\"", hub.cert.display());
    println!("      key_path = \"{}\"", hub.key.display());
    println!(
        "  - edge CLI:   --hub-cert {} --hub-key {} \\",
        hub.cert.display(),
        hub.key.display()
    );
    println!("                --client-ca {tenant}={}", ca.cert.display());
    println!("  - agent CLI:  --ca-path {} \\", ca.cert.display());
    println!("                --client-cert agents/<id>.crt --client-key agents/<id>.key");
    Ok(())
}

fn run_tenant_new(name: &str, out: &Path) -> Result<()> {
    let (outcome, ca) = ensure_tenant_ca(out, name)?;
    report_outcome(&format!("tenant CA ({name})"), outcome, &ca.cert, &ca.key);

    println!();
    println!("hub.toml: add a trust entry for the new tenant");
    println!("  [[auth.tenants]]");
    println!("  name = \"{name}\"");
    println!("  ca_path = \"{}\"", ca.cert.display());
    println!(
        "Issue agents with: interflow-mesh certs agent issue {name} <agent-id> --out {}",
        out.display()
    );
    print_ca_key_warning(&ca.key, name);
    Ok(())
}

fn run_agent_issue(tenant: &str, agent_id: &str, out: &Path, force: bool) -> Result<()> {
    let (outcome, agent) = ensure_agent_cert(out, tenant, agent_id, force)?;
    let ca_cert = out.join("tenants").join(format!("{tenant}-ca.crt"));
    report_outcome(
        &format!("agent certificate ({tenant}/{agent_id})"),
        outcome,
        &agent.cert,
        &agent.key,
    );
    if force {
        println!(
            "    note: --force re-issues without revocation — the previous certificate stays \
             valid until its own expiry"
        );
    }

    println!();
    println!("Agent host needs (copy nothing else):");
    println!(
        "  {}  {}  {}",
        agent.cert.display(),
        agent.key.display(),
        ca_cert.display()
    );
    println!("  (keep the agent key 0600)");
    println!();
    println!("Next steps:");
    println!(
        "  - mesh agent toml: [tls] ca_path = \"{}\" \\",
        ca_cert.display()
    );
    println!(
        "    client_cert_path = \"{}\" client_key_path = \"{}\"",
        agent.cert.display(),
        agent.key.display()
    );
    println!("  - expose CLI:  interflow-expose expose 3000 \\");
    println!("    --hub <hub-url> \\");
    println!("    --client-cert {} \\", agent.cert.display());
    println!("    --client-key {} \\", agent.key.display());
    println!("    --agent-id {agent_id} \\");
    println!("    --ca-path {}", ca_cert.display());
    Ok(())
}

fn run_gateway_issue(out: &Path, force: bool) -> Result<()> {
    let (outcome, gw) = interflow_certs::ensure_gateway(out, force)?;
    report_outcome(
        "gateway anchor CA",
        if outcome == Outcome::Created {
            Outcome::Created
        } else {
            Outcome::AlreadyValid
        },
        &gw.ca_cert,
        &gw.ca_key,
    );
    // The client pair outcome may differ from the CA's under --force.
    match outcome {
        Outcome::Created => println!(
            "==> gateway client pair (edge): created {} / {}",
            gw.client_cert.display(),
            gw.client_key.display()
        ),
        Outcome::AlreadyValid => println!(
            "==> gateway client pair (edge): already valid (validated, untouched) {} / {}",
            gw.client_cert.display(),
            gw.client_key.display()
        ),
    }
    if force {
        println!(
            "    note: --force re-issued the client pair without revocation — the previous \
             pair stays valid until its own expiry; the gateway CA was NOT rebuilt"
        );
    }

    println!();
    println!("Distribution (minimum sets — copy nothing else):");
    println!(
        "  - edge host:   {}  {}",
        gw.client_cert.display(),
        gw.client_key.display()
    );
    println!("    (edge.crt is the leaf+CA chain bundle: --gateway-cert covers both the");
    println!("     principal and the hub-plane _edge trust root)");
    println!(
        "  - every required-mode egress: {} as [e2e] gateway_ca_path",
        gw.ca_cert.display()
    );
    print_ca_key_warning(&gw.ca_key, "gateway");
    println!();
    println!("Next steps:");
    println!(
        "  - edge CLI:    --gateway-cert {} --gateway-key {}",
        gw.client_cert.display(),
        gw.client_key.display()
    );
    println!("    (with the stable identity in place, gateway flows carry the inner TLS layer;");
    println!("     without it the edge uses its per-restart minted identity and required-mode");
    println!("     egresses reject gateway streams)");
    println!(
        "  - agent toml:  [e2e] gateway_ca_path = \"{}\"",
        gw.ca_cert.display()
    );
    Ok(())
}

/// The `--hub-dns` guard: without names the only legal default is the
/// local-development SAN set, and issuing it requires an explicit ack —
/// interactive y/N on a terminal, `--yes` in scripts. A public deployment
/// that forgot `--hub-dns` must stop here, not discover `NotValidForName`
/// at handshake time (the 2026-09-18 footgun this tool exists to remove).
fn resolve_hub_names(hub_dns: &[String], yes: bool) -> Result<Vec<SanName>> {
    if !hub_dns.is_empty() {
        return hub_dns
            .iter()
            .map(|n| SanName::parse(n))
            .collect::<Result<Vec<_>>>();
    }
    let san = local_dev_san();
    let rendered = fmt_names(&san);
    println!("No --hub-dns given: the hub certificate would only cover the local");
    println!("development names (SAN: {rendered}). Agents that reach the hub through a");
    println!("public hostname or IP MUST pass --hub-dns <that name>, or their TLS handshake");
    println!("fails with NotValidForName.");
    if yes {
        return Ok(san);
    }
    if !std::io::stdin().is_terminal() {
        return Err(Error::Mismatch(
            "--hub-dns is required for public deployments (and stdin is not a terminal, so \
             there is nothing to confirm) — pass --hub-dns <name>, or --yes to issue a \
             local-development certificate (SAN: localhost, 127.0.0.1)"
                .to_owned(),
        ));
    }
    if prompt_yes("Issue a local-development certificate?")? {
        Ok(san)
    } else {
        Err(Error::Mismatch(
            "aborted — pass --hub-dns <name> for public deployments".to_owned(),
        ))
    }
}

fn prompt_yes(label: &str) -> Result<bool> {
    print!("{label} [y/N]: ");
    let _ = std::io::stdout().flush();
    let mut line = String::new();
    std::io::stdin()
        .lock()
        .read_line(&mut line)
        .map_err(|e| Error::Io {
            context: "failed to read confirmation".to_owned(),
            source: e,
        })?;
    let answer = line.trim();
    Ok(answer.starts_with('y') || answer.starts_with('Y'))
}

fn report_outcome(what: &str, outcome: Outcome, cert: &Path, key: &Path) {
    match outcome {
        Outcome::Created => println!("==> {what}: created {} / {}", cert.display(), key.display()),
        Outcome::AlreadyValid => println!(
            "==> {what}: already valid (validated, untouched) {} / {}",
            cert.display(),
            key.display()
        ),
    }
}

fn fmt_names(names: &[SanName]) -> String {
    names
        .iter()
        .map(ToString::to_string)
        .collect::<Vec<_>>()
        .join(", ")
}

/// Sorted file listing under `root` (the script's `find | sort` equivalent).
fn print_tree(root: &Path) {
    println!();
    println!("Contents of {}:", root.display());
    let mut files = Vec::new();
    collect_files(root, root, &mut files);
    files.sort();
    for file in &files {
        println!("  {file}");
    }
}

fn collect_files(root: &Path, dir: &Path, out: &mut Vec<String>) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            collect_files(root, &path, out);
        } else if let Ok(rel) = path.strip_prefix(root) {
            out.push(rel.display().to_string());
        }
    }
}

fn print_ca_key_warning(ca_key: &Path, tenant: &str) {
    println!();
    println!(
        "⚠️  SECURITY: {} is the identity-minting key for tenant \"{tenant}\".",
        ca_key.display()
    );
    println!("    Run this tool on an OPERATOR machine; the hub host must NEVER hold it");
    println!("    (the hub only needs the public CA certificate for its trust entry) —");
    println!("    a leaked CA key lets anyone mint agent certificates until the CA is");
    println!("    rotated (store it offline when not issuing).");
}
