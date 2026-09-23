//! The unified identity-first `interflow` CLI.
//!
//! Beginner surface: setup / plan / ingress run / agent run / doctor.
//! Operator surface: pack / trust / rotate / revoke / identity.

mod doctor;

use clap::{Parser, Subcommand};
use interflow_cli::plan;
use interflow_cli::runtime;
use interflow_identity::pack::CredentialPack;
use interflow_identity::pack::sealed::{SealKey, install, seal};
use std::path::PathBuf;

/// Top-level `interflow` CLI.
#[derive(Parser)]
#[command(
    name = "interflow",
    version,
    about = "Identity-first tunnels: Ingress / Agent / Service / Route"
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Create a deployment manifest template (the single source of truth).
    Setup {
        /// Realm identifier (a trust domain, e.g. `promptcn`).
        #[arg(long, default_value = "promptcn")]
        realm: String,
        /// Public control endpoint hostname.
        #[arg(long, default_value = "relay.example.com")]
        control_endpoint: String,
        /// Independent identity registrar endpoint.
        #[arg(long, default_value = "https://registrar.example.com")]
        registrar_endpoint: String,
        /// First public hostname to route.
        #[arg(long, default_value = "app.example.com")]
        host: String,
        /// Name of the first agent node (the identity; see `(internal design notes)`).
        #[arg(long, default_value = "desktop")]
        agent: String,
        /// Service id + local address for the first agent.
        #[arg(long, default_value = "asr")]
        service: String,
        #[arg(long, default_value = "127.0.0.1:8080")]
        service_address: String,
        /// Output manifest path.
        #[arg(long, default_value = "interflow.toml")]
        out: PathBuf,
    },
    /// Validate or apply a deployment manifest.
    Plan {
        #[command(subcommand)]
        command: PlanCommand,
    },
    /// Run an ingress from a Credential Pack.
    Ingress {
        #[command(subcommand)]
        command: NodeCommand,
    },
    /// Run an agent from a Credential Pack.
    Agent {
        #[command(subcommand)]
        command: NodeCommand,
    },
    /// Install a node pack onto this server (idempotent; re-run = upgrade).
    Node {
        #[command(subcommand)]
        command: NodeOp,
    },
    /// Inspect and manage Credential Packs.
    Pack {
        #[command(subcommand)]
        command: PackCommand,
    },
    /// Export the realm Trust Bundle (public verification material).
    Trust {
        /// Pack whose trust material to export.
        #[arg(long)]
        pack: PathBuf,
        /// Output directory.
        #[arg(long, default_value = "trust-bundle")]
        out: PathBuf,
    },
    /// Inspect the identity a credential pack carries.
    Identity {
        #[command(subcommand)]
        command: IdentityCommand,
    },
    /// Diagnose identity, trust, routes, and connectivity in product terms.
    Doctor {
        #[command(subcommand)]
        command: doctor::DoctorCommand,
    },
    /// Rotate a node credential (issues the next pack generation).
    Rotate {
        /// Manifest describing the deployment.
        #[arg(long, default_value = "interflow.toml")]
        manifest: PathBuf,
        /// Issuer store directory (operator machine only).
        #[arg(long, default_value = "issuer")]
        issuer: PathBuf,
        /// Node to rotate: `ingress/<name>` or `agent/<name>`.
        node: String,
        /// Existing pack directory (reads the current generation).
        #[arg(long)]
        pack: Option<PathBuf>,
        /// Output pack directory.
        #[arg(long)]
        out: Option<PathBuf>,
    },
    /// Revoke a credential by pack digest (records a deny entry + CRL).
    Revoke {
        /// Issuer store directory (operator machine only).
        #[arg(long, default_value = "issuer")]
        issuer: PathBuf,
        /// The pack (directory) to revoke.
        #[arg(long)]
        pack: PathBuf,
        /// Revocation reason (recorded in the deny list).
        #[arg(long, default_value = "operator-requested")]
        reason: String,
    },
}

#[derive(Subcommand)]
enum NodeCommand {
    /// Start this node from a Credential Pack directory (a node is an
    /// identity, not a machine — a machine can run any number of them).
    Run {
        /// Credential Pack directory (or install a sealed pack first).
        #[arg(long)]
        pack: PathBuf,
    },
}

#[derive(Subcommand)]
enum NodeOp {
    /// Install a Credential Pack (directory or `.iflowpack`) into the server
    /// layout, write + enable its systemd unit and probe readiness.
    Install {
        /// Pack source: a rendered pack directory or a sealed `.iflowpack`.
        #[arg(long)]
        pack: PathBuf,
        /// Install root (system paths require root).
        #[arg(long, default_value = interflow_cli::render::DEFAULT_INSTALL_ROOT)]
        root: PathBuf,
        /// Service user the unit runs as.
        #[arg(long, default_value = interflow_cli::render::INSTALL_USER)]
        user: String,
        /// Read the passphrase interactively (sealed packs; env
        /// INTERFLOW_PACK_PASSPHRASE always works).
        #[arg(long)]
        passphrase: bool,
    },
}

#[derive(Subcommand)]
enum PlanCommand {
    /// Check the manifest without changing anything.
    Validate {
        #[arg(long, default_value = "interflow.toml")]
        manifest: PathBuf,
    },
    /// Issue identities + packs + node configs from the manifest.
    Apply {
        #[arg(long, default_value = "interflow.toml")]
        manifest: PathBuf,
        /// Issuer store directory (created if missing; keep it secret).
        #[arg(long, default_value = "issuer")]
        issuer: PathBuf,
        /// Output root for packs and proxy configs.
        #[arg(long, default_value = "dist")]
        out: PathBuf,
    },
}

#[derive(Subcommand)]
enum PackCommand {
    /// Seal a pack directory into a distributable `.iflowpack`.
    Seal {
        #[arg(long)]
        pack: PathBuf,
        #[arg(long)]
        out: PathBuf,
        /// Passphrase (reads INTERFLOW_PACK_PASSPHRASE, then prompts).
        #[arg(long)]
        passphrase: bool,
        /// age recipient (age1...) instead of a passphrase.
        #[arg(long)]
        recipient: Option<String>,
    },
    /// Install (decrypt + validate) a sealed pack.
    Install {
        #[arg(long)]
        sealed: PathBuf,
        #[arg(long)]
        out: PathBuf,
        /// Passphrase (reads INTERFLOW_PACK_PASSPHRASE, then prompts).
        #[arg(long)]
        passphrase: bool,
    },
    /// Load and fully validate a pack (digests, identity, policy).
    Inspect {
        #[arg(long)]
        pack: PathBuf,
    },
}

#[derive(Subcommand)]
enum IdentityCommand {
    /// Show the product identity of a pack (add --expert for X.509 detail).
    Inspect {
        #[arg(long)]
        pack: PathBuf,
        #[arg(long)]
        expert: bool,
    },
    /// Force one renewal cycle for diagnostics.
    Renew {
        #[arg(long)]
        pack: PathBuf,
    },
}

#[tokio::main]
async fn main() -> interflow_core::error::Result<()> {
    let cli = Cli::parse();
    match cli.command {
        Command::Setup {
            realm,
            control_endpoint,
            registrar_endpoint,
            host,
            agent,
            service,
            service_address,
            out,
        } => {
            if out.exists() {
                return Err(interflow_core::error::InterflowError::config(format!(
                    "{} already exists — refusing to overwrite a live manifest",
                    out.display()
                )));
            }
            std::fs::write(
                &out,
                plan::setup_template(
                    &realm,
                    &control_endpoint,
                    &registrar_endpoint,
                    &host,
                    &agent,
                    &service,
                    &service_address,
                ),
            )?;
            println!("Manifest template written to {}", out.display());
            println!("Next:");
            println!("  1. edit {} (realm, hostnames, services)", out.display());
            println!("  2. interflow plan apply --manifest {}", out.display());
            Ok(())
        }
        Command::Plan { command } => match command {
            PlanCommand::Validate { manifest } => {
                for line in plan::validate(&manifest)? {
                    println!("{line}");
                }
                Ok(())
            }
            PlanCommand::Apply {
                manifest,
                issuer,
                out,
            } => {
                for line in plan::apply(&manifest, &issuer, &out)? {
                    println!("{line}");
                }
                Ok(())
            }
        },
        Command::Ingress { command } => match command {
            NodeCommand::Run { pack } => runtime::run_ingress(&pack).await,
        },
        Command::Agent { command } => match command {
            NodeCommand::Run { pack } => runtime::run_agent(&pack).await,
        },
        Command::Node { command } => match command {
            NodeOp::Install {
                pack,
                root,
                user,
                passphrase,
            } => {
                let pass = read_passphrase(passphrase).ok();
                let report = interflow_cli::node_install::install(
                    &interflow_cli::node_install::NodeInstall {
                        pack,
                        root,
                        user,
                        passphrase: pass,
                    },
                )?;
                println!(
                    "✔ installed {} node {} → {}{}",
                    report.kind.as_str(),
                    report.node,
                    report.installed_to.display(),
                    if report.upgraded {
                        "  (upgraded; previous kept as .previous)"
                    } else {
                        ""
                    },
                );
                println!("  unit: {}", report.unit_path.display());
                if report.service_started {
                    println!("  service: started (systemd, ready)");
                } else {
                    println!(
                        "  service: not managed (non-system layout) — start manually if needed"
                    );
                }
                Ok(())
            }
        },
        Command::Pack { command } => match command {
            PackCommand::Seal {
                pack,
                out,
                passphrase,
                recipient,
            } => {
                let key = if let Some(recipient) = recipient {
                    SealKey::Recipient(recipient)
                } else {
                    let pass = read_passphrase(passphrase)?;
                    SealKey::Passphrase(pass)
                };
                seal(&pack, &out, &key).map_err(runtime::pack_error)?;
                println!("sealed {} → {}", pack.display(), out.display());
                Ok(())
            }
            PackCommand::Install {
                sealed,
                out,
                passphrase,
            } => {
                let pass = read_passphrase(passphrase)?;
                let installed = install(&sealed, &out, &pass).map_err(runtime::pack_error)?;
                println!(
                    "installed {} ({}, generation {}, digest {})",
                    out.display(),
                    installed.metadata.kind.as_str(),
                    installed.metadata.generation,
                    installed.pack_digest
                );
                Ok(())
            }
            PackCommand::Inspect { pack } => {
                let loaded = CredentialPack::load(&pack).map_err(runtime::pack_error)?;
                println!("{}", serde_json::to_string_pretty(&loaded.summary())?);
                Ok(())
            }
        },
        Command::Trust {
            pack: pack_dir,
            out,
        } => {
            let loaded = CredentialPack::load(&pack_dir).map_err(runtime::pack_error)?;
            loaded.trust.save(&out).map_err(runtime::pack_error)?;
            println!(
                "Trust Bundle realm={} generation={} digest={} → {}",
                loaded.trust.metadata.realm,
                loaded.trust.metadata.generation,
                loaded.trust.digest().map_err(runtime::pack_error)?,
                out.display()
            );
            Ok(())
        }
        Command::Identity { command } => match command {
            IdentityCommand::Inspect {
                pack: pack_dir,
                expert,
            } => doctor::identity_inspect(&pack_dir, expert),
            IdentityCommand::Renew { pack: pack_dir } => {
                runtime::init_node_logging();
                let report = interflow_renewal::renew_all(&pack_dir, true).await?;
                println!(
                    "renewed {} credential(s) for {}",
                    report.renewed.len(),
                    report.pack_dir.display()
                );
                for principal in report.renewed {
                    println!("  ✔ {principal}");
                }
                Ok(())
            }
        },
        Command::Doctor { command } => command.run(),
        Command::Rotate {
            manifest,
            issuer,
            node,
            pack: pack_dir,
            out,
        } => {
            for line in plan::rotate(
                &manifest,
                &issuer,
                &node,
                pack_dir.as_deref(),
                out.as_deref(),
            )? {
                println!("{line}");
            }
            Ok(())
        }
        Command::Revoke {
            issuer,
            pack: pack_dir,
            reason,
        } => {
            for line in plan::revoke(&issuer, &pack_dir, &reason)? {
                println!("{line}");
            }
            Ok(())
        }
    }
}

fn read_passphrase(interactive: bool) -> interflow_core::error::Result<String> {
    if let Ok(pass) = std::env::var("INTERFLOW_PACK_PASSPHRASE") {
        return Ok(pass);
    }
    if !interactive {
        return Err(interflow_core::error::InterflowError::config(
            "passphrase required: pass --passphrase and set INTERFLOW_PACK_PASSPHRASE \
             or enter it interactively",
        ));
    }
    eprint!("Credential Pack passphrase: ");
    let mut line = String::new();
    std::io::BufRead::read_line(&mut std::io::stdin().lock(), &mut line)?;
    let trimmed = line.trim_end_matches(['\r', '\n']).to_owned();
    if trimmed.is_empty() {
        return Err(interflow_core::error::InterflowError::config(
            "passphrase must not be empty",
        ));
    }
    Ok(trimmed)
}
