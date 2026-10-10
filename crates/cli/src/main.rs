//! The unified identity-first `interflow-cli` CLI.
//!
//! Beginner surface: setup / plan / ingress run / agent run / doctor.
//! Operator surface: pack / trust / rotate / revoke / identity.

mod doctor;

use clap::{Parser, Subcommand, ValueEnum};
use interflow_cli::plan;
use interflow_cli::runtime;
use interflow_identity::pack::CredentialPack;
use interflow_identity::pack::sealed::{SealKey, install, seal};
use std::path::PathBuf;

/// Top-level `interflow-cli` CLI.
#[derive(Parser)]
#[command(
    name = env!("CARGO_PKG_NAME"),
    version = interflow_buildinfo::VERSION_WITH_TAG,
    about = "Identity-first tunnels: Ingress / Agent / Service / Route"
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

/// Which deployment face `setup` renders a starter for.
#[derive(Subcommand, ValueEnum, Clone, Copy)]
enum SetupFace {
    /// Public hostname → LAN service (registrar-tier starter).
    Expose,
    /// Site-to-site relay (offline-tier starter).
    Mesh,
}

/// `interflow-cli audit …` subcommands.
#[derive(Subcommand)]
enum AuditCommand {
    /// Replay the hash chain across the whole ledger: every record's
    /// `record_hash` is recomputed, sequences advance, and every
    /// `previous_hash` links to the preceding record (segments in chain
    /// order, gzip segments transparent, the active file last).
    Verify {
        /// The ledger's `audit.jsonl`, or a directory containing one (a
        /// pack directory).
        path: PathBuf,
    },
}

#[derive(Subcommand)]
enum Command {
    /// Create a deployment manifest template (the single source of truth).
    Setup {
        /// Deployment face the template targets.
        #[arg(long, value_enum, default_value_t = SetupFace::Expose)]
        face: SetupFace,
        /// Realm identifier (a trust domain, e.g. `promptcn`).
        #[arg(long, default_value = "promptcn")]
        realm: String,
        /// Public control endpoint hostname (expose face).
        #[arg(long, default_value = "relay.example.com")]
        control_endpoint: String,
        /// Independent identity registrar endpoint (expose face).
        #[arg(long, default_value = "https://registrar.example.com")]
        registrar_endpoint: String,
        /// First public hostname to route (expose face).
        #[arg(long, default_value = "app.example.com")]
        host: String,
        /// Name of the first agent node (expose face; the identity; see
        /// `(internal design notes)`).
        #[arg(long, default_value = "desktop")]
        agent: String,
        /// Service id + local address for the first agent (expose face).
        #[arg(long, default_value = "asr")]
        service: String,
        #[arg(long, default_value = "127.0.0.1:8080")]
        service_address: String,
        /// Hub node name (mesh face).
        #[arg(long, default_value = "central")]
        hub_name: String,
        /// Hub dial endpoint `host:port` agents reach it at (mesh face).
        #[arg(long, default_value = "mesh.example.com:6666")]
        hub_endpoint: String,
        /// Output manifest path.
        #[arg(long, default_value = "interflow.toml")]
        out: PathBuf,
    },
    /// Validate or apply a deployment manifest.
    Plan {
        #[command(subcommand)]
        command: PlanCommand,
    },
    /// Stream-proposal queue (approve/reject from the issuer machine).
    Proposals {
        #[command(subcommand)]
        command: ProposalsCommand,
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
    /// Verify an audit ledger (hash chain across the active file and all
    /// sealed segments, gzip segments included).
    Audit {
        #[command(subcommand)]
        command: AuditCommand,
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
        /// Rebind the issuer store to this manifest when it is already bound
        /// to another one (same realm). Only for the same deployment after a
        /// move/rename — separate scenarios get their own realm + store.
        #[arg(long)]
        issuer_allow_shared: bool,
    },
    /// Revoke a credential by pack digest (records a deny entry + CRL).
    Revoke {
        /// Issuer store directory (operator machine only).
        #[arg(long, default_value = "issuer")]
        issuer: PathBuf,
        /// The pack (directory) to revoke.
        #[arg(long)]
        pack: PathBuf,
        /// Revocation reason — recorded in the deny list AND carried as the
        /// CRL's RFC 5280 reason code, so a leak emergency is
        /// distinguishable from a planned retirement downstream.
        #[arg(long, value_enum, default_value_t = RevokeReason::KeyCompromise)]
        reason: RevokeReason,
    },
    /// Manage the issuer store's encrypted backup (the deployment's entire
    /// signing capability — realm CA, workspace CAs, policy key, deny list).
    /// Every store change checkpoints automatically once configured; these
    /// commands configure, inspect, and recover.
    Issuer {
        #[command(subcommand)]
        command: IssuerCommand,
    },
}

/// The RFC 5280-aligned revocation reasons `revoke` records.
#[derive(Clone, Copy, Debug, ValueEnum)]
enum RevokeReason {
    /// Credential or key compromise — the leak-emergency default.
    #[value(name = "key-compromise")]
    KeyCompromise,
    /// The node was retired / decommissioned.
    #[value(name = "cessation-of-operation")]
    CessationOfOperation,
    /// Replaced by a newer credential (what rotation records).
    #[value(name = "superseded")]
    Superseded,
    /// Administrative removal, no RFC severity.
    #[value(name = "unspecified")]
    Unspecified,
}

impl RevokeReason {
    const fn as_reason(self) -> &'static str {
        match self {
            Self::KeyCompromise => "key-compromise",
            Self::CessationOfOperation => "cessation-of-operation",
            Self::Superseded => "superseded",
            Self::Unspecified => "unspecified",
        }
    }
}

/// `interflow-cli issuer …` subcommands.
#[derive(Subcommand)]
enum IssuerCommand {
    /// Backup lifecycle: configure, checkpoint, inspect, rekey.
    Backup {
        #[command(subcommand)]
        command: IssuerBackupCommand,
    },
    /// Decrypt + fully parse a backup archive (no restore): the pre-recovery
    /// health check. Needs the offline recovery identity.
    Verify {
        /// Backup archive to inspect.
        #[arg(long)]
        backup: PathBuf,
        /// Path to the recovery identity file (`-` reads stdin).
        #[arg(long)]
        identity: String,
    },
    /// Restore an issuer store from a backup into a fresh directory and
    /// validate every CA, the policy key, and the deny list.
    Restore {
        /// Backup archive to restore.
        #[arg(long)]
        backup: PathBuf,
        /// Path to the recovery identity file (`-` reads stdin).
        #[arg(long)]
        identity: String,
        /// Fresh target directory (must be empty or absent — a live store is
        /// never overwritten).
        #[arg(long)]
        to: PathBuf,
    },
}

#[derive(Subcommand)]
enum IssuerBackupCommand {
    /// Configure backups for a store that has none (one-time). Generates an
    /// offline identity unless `--recipient` supplies a pre-generated one.
    Init {
        /// Issuer store directory.
        #[arg(long, default_value = "issuer")]
        dir: PathBuf,
        /// Directory the versioned backups land in (default: `<dir>-backups`).
        #[arg(long)]
        backup_dir: Option<PathBuf>,
        /// age recipient (age1...) for operators who pre-generate their key —
        /// then no secret ever touches this machine.
        #[arg(long)]
        recipient: Option<String>,
        /// Also write the generated recovery identity to this path.
        #[arg(long)]
        identity_out: Option<PathBuf>,
        /// Versions to keep.
        #[arg(long, default_value_t = interflow_identity::backup::DEFAULT_RETENTION)]
        retention: u32,
    },
    /// Force a checkpoint now (belt-and-braces; mutations already do).
    Now {
        /// Issuer store directory.
        #[arg(long, default_value = "issuer")]
        dir: PathBuf,
    },
    /// Show configuration, version inventory, and whether the newest backup
    /// matches the store as it stands.
    Status {
        /// Issuer store directory.
        #[arg(long, default_value = "issuer")]
        dir: PathBuf,
    },
    /// Replace the encryption key: prints a new one-time identity, keeps the
    /// backup directory and retention, checkpoints immediately. Old backups
    /// stay readable by the OLD identity only.
    Rekey {
        /// Issuer store directory.
        #[arg(long, default_value = "issuer")]
        dir: PathBuf,
        /// Also write the new recovery identity to this path.
        #[arg(long)]
        identity_out: Option<PathBuf>,
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
    /// Append a node to the manifest — structured and non-destructive
    /// (comments and layout stay; the edited manifest must pass the full
    /// validation funnel before anything is written).
    Add {
        /// Node to add: `agent/<name>`, `ingress/<name>` or `hub/<name>`.
        node: String,
        #[arg(long, default_value = "interflow.toml")]
        manifest: PathBuf,
        /// Agent workspace (default: the manifest's sole workspace, else
        /// `default`).
        #[arg(long)]
        workspace: Option<String>,
        /// Expose service `id:address`, repeatable (e.g. asr:127.0.0.1:8080).
        #[arg(long = "service")]
        service: Vec<String>,
        /// Mesh listen rule `name:listen:remote@target-agent`, repeatable;
        /// prefix `udp/` for UDP (listen/remote are IPv4 host:port — IPv6
        /// or idle_timeout_secs tuning belong in the manifest itself).
        #[arg(long = "mesh-ingress")]
        mesh_ingress: Vec<String>,
        /// Mesh serve rule `name:host:port` or `name:ip/prefix`, repeatable;
        /// prefix `udp/` for UDP.
        #[arg(long = "mesh-egress")]
        mesh_egress: Vec<String>,
        /// Workspaces this ingress serves, comma-separated (ingress only).
        #[arg(long, value_delimiter = ',')]
        ingress_workspaces: Vec<String>,
        /// Hub dial endpoint `host:port` (hub only).
        #[arg(long)]
        endpoint: Option<String>,
    },
}

/// The operator's stream-proposal queue face (kube-CSR shape: nodes
/// propose via their GUIs; the mint stays with whoever holds the issuer
/// store — this machine).
#[derive(Subcommand)]
enum ProposalsCommand {
    /// List the hub's queue (pending + recently decided).
    List {
        #[arg(long, default_value = "interflow.toml")]
        manifest: PathBuf,
        #[arg(long, default_value = "issuer")]
        issuer: PathBuf,
    },
    /// Approve: edit the manifest (the single source of truth), apply
    /// (mint + publish), and record the decision at the hub.
    Approve {
        #[arg(long)]
        id: String,
        #[arg(long, default_value = "interflow.toml")]
        manifest: PathBuf,
        #[arg(long, default_value = "issuer")]
        issuer: PathBuf,
        #[arg(long, default_value = "dist")]
        out: PathBuf,
        #[arg(long)]
        issuer_allow_shared: bool,
    },
    /// Reject with a reason (the requester's GUI shows it as the receipt).
    Reject {
        #[arg(long)]
        id: String,
        #[arg(long)]
        reason: String,
        #[arg(long, default_value = "interflow.toml")]
        manifest: PathBuf,
        #[arg(long, default_value = "issuer")]
        issuer: PathBuf,
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
        /// Rebind the issuer store to this manifest when it is already bound
        /// to another one (same realm). Only for the same deployment after a
        /// move/rename — separate scenarios get their own realm + store.
        #[arg(long)]
        issuer_allow_shared: bool,
        /// Directory the issuer store's encrypted backup versions land in
        /// (default: `<issuer>-backups`, configured once on first apply).
        #[arg(long)]
        backup_dir: Option<PathBuf>,
        /// Use this age recipient (age1...) for backups instead of
        /// generating a new offline identity (pre-generated keys).
        #[arg(long)]
        backup_recipient: Option<String>,
        /// Also write the one-time generated recovery identity to this path
        /// (e.g. a mounted USB stick) instead of only printing it.
        #[arg(long)]
        backup_identity_out: Option<PathBuf>,
        /// Leave the issuer store without automatic backups (CI, throwaway
        /// stores) — `doctor issuer` keeps flagging it.
        #[arg(long)]
        no_issuer_backup: bool,
    },
}

#[derive(Subcommand)]
enum PackCommand {
    /// Seal a pack directory into a distributable `.iflowpack`.
    Seal {
        #[arg(long)]
        pack: PathBuf,
        /// Output file (default: beside the pack directory,
        /// `<pack dir name>.iflowpack`).
        #[arg(long)]
        out: Option<PathBuf>,
        /// Passphrase (reads INTERFLOW_PACK_PASSPHRASE, then prompts).
        #[arg(long)]
        passphrase: bool,
        /// Generate a 144-bit passphrase, seal with it, print it once —
        /// skips the prompt entirely.
        #[arg(long)]
        generate_passphrase: bool,
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
            face,
            realm,
            control_endpoint,
            registrar_endpoint,
            host,
            agent,
            service,
            service_address,
            hub_name,
            hub_endpoint,
            out,
        } => {
            if out.exists() {
                return Err(interflow_core::error::InterflowError::config(format!(
                    "{} already exists — refusing to overwrite a live manifest",
                    out.display()
                )));
            }
            let template = match face {
                SetupFace::Expose => plan::setup_template(
                    &realm,
                    &control_endpoint,
                    &registrar_endpoint,
                    &host,
                    &agent,
                    &service,
                    &service_address,
                ),
                SetupFace::Mesh => plan::setup_mesh_template(&realm, &hub_name, &hub_endpoint),
            };
            std::fs::write(&out, template)?;
            println!("Manifest template written to {}", out.display());
            println!("Next:");
            match face {
                SetupFace::Expose => {
                    println!(
                        "  1. edit {} (or append nodes: interflow-cli node add agent/<name> --service id:address)",
                        out.display()
                    );
                    println!("  2. interflow-cli plan apply --manifest {}", out.display());
                }
                // The skeleton ships no placeholder agent — the first node
                // add is what makes the mesh manifest deployable.
                SetupFace::Mesh => {
                    println!(
                        "  1. service side:   interflow-cli node add agent/<name> --mesh-egress <rule>:127.0.0.1:8080"
                    );
                    println!(
                        "     connect side:   interflow-cli node add agent/<name> --mesh-ingress <rule>:127.0.0.1:8080:127.0.0.1:8080@<peer>"
                    );
                    println!("  2. interflow-cli plan apply --manifest {}", out.display());
                }
            }
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
                issuer_allow_shared,
                backup_dir,
                backup_recipient,
                backup_identity_out,
                no_issuer_backup,
            } => {
                let backup = plan::BackupInitOptions {
                    skip: no_issuer_backup,
                    recipient: backup_recipient,
                    backup_dir,
                    identity_out: backup_identity_out,
                };
                for line in
                    plan::apply(&manifest, &issuer, &out, issuer_allow_shared, &backup)?.lines
                {
                    println!("{line}");
                }
                Ok(())
            }
        },
        Command::Proposals { command } => match command {
            ProposalsCommand::List { manifest, issuer } => {
                match plan::list_proposals(&manifest, &issuer)? {
                    None => println!("the manifest names no hub endpoint"),
                    Some(list) if list.is_empty() => println!("queue empty — no proposals"),
                    Some(list) => {
                        for p in list {
                            let status = match &p.status {
                                interflow_mesh::hub::proposals::StoredStatus::Pending => {
                                    "pending".to_string()
                                }
                                interflow_mesh::hub::proposals::StoredStatus::Approved {
                                    generation,
                                } => format!("approved (gen {generation})"),
                                interflow_mesh::hub::proposals::StoredStatus::Rejected {
                                    reason,
                                } => format!("rejected ({reason})"),
                            };
                            println!(
                                "{}  [{}]  {} wants → {} @ {} (listen {}, rule {})",
                                p.id,
                                status,
                                p.requester,
                                p.rule.target_agent,
                                p.rule.remote_addr,
                                p.rule.listen,
                                p.rule.name
                            );
                        }
                    }
                }
                Ok(())
            }
            ProposalsCommand::Approve {
                id,
                manifest,
                issuer,
                out,
                issuer_allow_shared,
            } => {
                let report =
                    plan::approve_proposal(&manifest, &issuer, &out, &id, issuer_allow_shared)?;
                for line in report.lines {
                    println!("{line}");
                }
                Ok(())
            }
            ProposalsCommand::Reject {
                id,
                reason,
                manifest,
                issuer,
            } => {
                plan::reject_proposal(&manifest, &issuer, &id, &reason)?;
                println!("rejected {id}: {reason}");
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
            NodeOp::Add {
                node,
                manifest,
                workspace,
                service,
                mesh_ingress,
                mesh_egress,
                ingress_workspaces,
                endpoint,
            } => {
                let (kind, name) = plan::AddNodeKind::parse(&node)?;
                let spec = plan::AddNodeSpec {
                    kind,
                    node: name,
                    workspace,
                    services: service
                        .iter()
                        .map(|token| parse_service_flag(token))
                        .collect::<interflow_core::error::Result<Vec<_>>>()?,
                    mesh_ingress: mesh_ingress
                        .iter()
                        .map(|token| parse_mesh_ingress_flag(token))
                        .collect::<interflow_core::error::Result<Vec<_>>>()?,
                    mesh_egress: mesh_egress
                        .iter()
                        .map(|token| parse_mesh_egress_flag(token))
                        .collect::<interflow_core::error::Result<Vec<_>>>()?,
                    ingress_workspaces,
                    hub_endpoint: endpoint,
                };
                let outcome = plan::add_node(&manifest, &spec)?;
                println!(
                    "✔ {} appended to {} (pack: packs/{}, backup: {}.bak)",
                    node,
                    manifest.display(),
                    outcome.pack_dir_name,
                    manifest.display()
                );
                println!(
                    "Next: interflow-cli plan apply --manifest {}",
                    manifest.display()
                );
                Ok(())
            }
        },
        Command::Pack { command } => match command {
            PackCommand::Seal {
                pack,
                out,
                passphrase,
                generate_passphrase,
                recipient,
            } => {
                // Default output: beside the pack directory, named after it.
                let out = out.unwrap_or_else(|| {
                    let name = pack
                        .file_name()
                        .map_or_else(|| "pack".to_owned(), |n| n.to_string_lossy().into_owned());
                    pack.with_file_name(format!("{name}.iflowpack"))
                });
                let key = if let Some(recipient) = recipient {
                    SealKey::Recipient(recipient)
                } else if generate_passphrase {
                    // Generated 144-bit, printed exactly once — the same
                    // local-terminal trust boundary as typing one in.
                    let pass = interflow_identity::pack::sealed::generate_passphrase()
                        .map_err(runtime::pack_error)?;
                    seal(&pack, &out, &SealKey::Passphrase(pass.clone()))
                        .map_err(runtime::pack_error)?;
                    println!("sealed {} → {}", pack.display(), out.display());
                    println!("passphrase (shown once): {pass}");
                    return Ok(());
                } else {
                    SealKey::Passphrase(read_passphrase(passphrase)?)
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
        Command::Audit {
            command: AuditCommand::Verify { path },
        } => {
            let files = if path.is_dir() {
                interflow_core::security::discover_audit_files(&path)
            } else {
                vec![path.clone()]
            };
            if files.is_empty() {
                println!("no audit ledger found under {}", path.display());
                return Ok(());
            }
            match interflow_core::security::verify_audit_files(&files) {
                Ok(report) => {
                    println!(
                        "✔ audit ledger verified: {} record(s) across {} file(s), {} chain(s){}",
                        report.records,
                        report.segments,
                        report.chains,
                        if report.truncated_start {
                            " (starts mid-chain: older segments were pruned by retention)"
                        } else {
                            ""
                        }
                    );
                    Ok(())
                }
                Err(e) => {
                    println!("✘ audit ledger broken: {e}");
                    std::process::exit(1);
                }
            }
        }
        Command::Doctor { command } => command.run(),
        Command::Rotate {
            manifest,
            issuer,
            node,
            pack: pack_dir,
            out,
            issuer_allow_shared,
        } => {
            for line in plan::rotate(
                &manifest,
                &issuer,
                &node,
                pack_dir.as_deref(),
                out.as_deref(),
                issuer_allow_shared,
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
            for line in plan::revoke(&issuer, &pack_dir, reason.as_reason())? {
                println!("{line}");
            }
            Ok(())
        }
        Command::Issuer { command } => run_issuer(command),
    }
}

/// Reads a recovery identity: a file path, or `-` for stdin.
fn read_identity_arg(spec: &str) -> interflow_core::error::Result<String> {
    let raw = if spec == "-" {
        let mut line = String::new();
        std::io::BufRead::read_line(&mut std::io::stdin().lock(), &mut line)?;
        line
    } else {
        std::fs::read_to_string(spec).map_err(|e| {
            interflow_core::error::InterflowError::config(format!(
                "cannot read recovery identity {spec:?}"
            ))
            .with_source(e)
        })?
    };
    let trimmed = raw.trim_end_matches(['\r', '\n']).to_owned();
    if trimmed.is_empty() {
        return Err(interflow_core::error::InterflowError::config(
            "recovery identity must not be empty",
        ));
    }
    Ok(trimmed)
}

fn print_one_time_identity(
    secret: &str,
    identity_out: Option<&PathBuf>,
) -> interflow_core::error::Result<()> {
    println!("┌─ ONE-TIME RECOVERY IDENTITY — store it OFFLINE (password manager / printed) ─┐");
    println!("│ {secret}");
    println!("│ It is the ONLY key that can restore backups. It is never stored on this");
    println!("│ machine; losing it makes every backup permanently unreadable.");
    println!("└──────────────────────────────────────────────────────────────────────────────┘");
    if let Some(out) = identity_out {
        interflow_util::atomic_write(
            out,
            format!("{secret}\n").as_bytes(),
            interflow_util::WriteMode::Set(0o600),
        )?;
        println!(
            "recovery identity also written to {} (0600) — move that medium offline",
            out.display()
        );
    }
    Ok(())
}

fn run_issuer(command: IssuerCommand) -> interflow_core::error::Result<()> {
    use interflow_identity::backup as store_backup;
    match command {
        IssuerCommand::Backup { command } => match command {
            IssuerBackupCommand::Init {
                dir,
                backup_dir,
                recipient,
                identity_out,
                retention,
            } => {
                let backup_dir =
                    backup_dir.unwrap_or_else(|| store_backup::default_backup_dir(&dir));
                if let Some(recipient) = &recipient {
                    store_backup::configure(&dir, recipient, &backup_dir, retention)
                        .map_err(runtime::pack_error)?;
                    println!(
                        "✔ backups configured → {} (recipient supplied; no secret was \
                         generated here)",
                        backup_dir.display()
                    );
                } else {
                    let identity =
                        store_backup::generate_identity().map_err(runtime::pack_error)?;
                    store_backup::configure(&dir, &identity.recipient, &backup_dir, retention)
                        .map_err(runtime::pack_error)?;
                    println!(
                        "✔ backups configured → {} — every change now checkpoints an \
                         encrypted, versioned copy",
                        backup_dir.display()
                    );
                    print_one_time_identity(&identity.secret, identity_out.as_ref())?;
                }
                Ok(())
            }
            IssuerBackupCommand::Now { dir } => {
                match store_backup::checkpoint(&dir).map_err(runtime::pack_error)? {
                    store_backup::Checkpoint::Written { path } => {
                        println!("✔ checkpoint written: {}", path.display());
                    }
                    store_backup::Checkpoint::Unchanged => {
                        println!("· newest backup already matches the store — nothing to do");
                    }
                    store_backup::Checkpoint::Unconfigured => {
                        println!("✘ this store has no backup configuration");
                        println!(
                            "Fix: `interflow-cli issuer backup init --dir {}` (or re-run plan \
                             apply)",
                            dir.display()
                        );
                        return Err(interflow_core::error::InterflowError::config(
                            "issuer store backup is not configured",
                        ));
                    }
                }
                Ok(())
            }
            IssuerBackupCommand::Status { dir } => {
                let status = store_backup::status(&dir).map_err(runtime::pack_error)?;
                let Some(cfg) = status.config else {
                    println!("✘ no backup configuration for {}", dir.display());
                    println!(
                        "Fix: `interflow-cli issuer backup init --dir {}`",
                        dir.display()
                    );
                    return Err(interflow_core::error::InterflowError::config(
                        "issuer store backup is not configured",
                    ));
                };
                {
                    println!("backup dir:  {}", cfg.backup_dir.display());
                    println!("recipient:   {}", cfg.recipient);
                    println!("retention:   {} versions", cfg.retention);
                    println!(
                        "versions:    {} (newest: {})",
                        status.versions.len(),
                        status
                            .versions
                            .last()
                            .map_or_else(|| "none yet".to_owned(), |p| p.display().to_string())
                    );
                    if status.versions.is_empty() {
                        println!(
                            "✘ no backup has landed yet — run `interflow-cli issuer backup now`"
                        );
                        return Err(interflow_core::error::InterflowError::config(
                            "no issuer store backup exists",
                        ));
                    }
                    if status.newest_is_current {
                        println!("✔ newest backup matches the current store content");
                    } else {
                        println!("✘ the store changed since the last successful backup");
                        println!(
                            "Fix: `interflow-cli issuer backup now --dir {}`",
                            dir.display()
                        );
                        return Err(interflow_core::error::InterflowError::config(
                            "issuer store backup is stale",
                        ));
                    }
                    if status.same_device == Some(true) {
                        println!(
                            "· warning: backup dir shares the disk with the store — point \
                             it at a second medium (`issuer backup init --backup-dir`)"
                        );
                    }
                    Ok(())
                }
            }
            IssuerBackupCommand::Rekey { dir, identity_out } => {
                let next = store_backup::generate_identity().map_err(runtime::pack_error)?;
                let cfg =
                    store_backup::rekey(&dir, &next.recipient).map_err(runtime::pack_error)?;
                // Checkpoint immediately so the newest version follows the
                // new key (old versions stay sealed to the old identity).
                match store_backup::checkpoint(&dir).map_err(runtime::pack_error)? {
                    store_backup::Checkpoint::Written { path } => {
                        println!(
                            "✔ rekeyed; first backup under the new key: {}",
                            path.display()
                        );
                    }
                    _ => println!("✔ rekeyed; next change checkpoints under the new key"),
                }
                println!("backups stay in {}", cfg.backup_dir.display());
                println!("old backups remain readable ONLY by the previous identity");
                print_one_time_identity(&next.secret, identity_out.as_ref())
            }
        },
        IssuerCommand::Verify { backup, identity } => {
            let identity = read_identity_arg(&identity)?;
            let report = store_backup::verify(&backup, &identity).map_err(runtime::pack_error)?;
            println!("✔ {} decrypts and parses cleanly", backup.display());
            println!(
                "members: {} files, {} private key file(s)",
                report.members.len(),
                report.key_files
            );
            for cert in &report.certs {
                println!(
                    "  cert {}: {} (expires {})",
                    cert.path, cert.subject, cert.not_after
                );
            }
            Ok(())
        }
        IssuerCommand::Restore {
            backup,
            identity,
            to,
        } => {
            let identity = read_identity_arg(&identity)?;
            let report =
                store_backup::restore(&backup, &identity, &to).map_err(runtime::pack_error)?;
            println!("✔ issuer store restored to {}", report.root.display());
            println!("  realm CA fingerprint: {}", report.realm_fingerprint);
            println!(
                "  policy signing key:   {}",
                if report.policy_key { "ok" } else { "MISSING" }
            );
            for ws in &report.workspaces {
                println!("  workspace {} CA: {}", ws.name, ws.fingerprint);
            }
            println!("  deny list: {} revocation(s)", report.revocations);
            println!(
                "Next: re-run `plan apply --issuer {}` against the restored store",
                report.root.display()
            );
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

fn flag_error(message: String) -> interflow_core::error::InterflowError {
    interflow_core::error::InterflowError::config(message)
}

/// `id:address` — the address keeps its own colons, so split at the first.
fn parse_service_flag(token: &str) -> interflow_core::error::Result<plan::AddServiceSpec> {
    let Some((id, address)) = token.split_once(':') else {
        return Err(flag_error(format!(
            "service {token:?} must look like id:address (e.g. asr:127.0.0.1:8080)"
        )));
    };
    if id.is_empty() || address.is_empty() {
        return Err(flag_error(format!(
            "service {token:?} has an empty id or address"
        )));
    }
    Ok(plan::AddServiceSpec {
        id: id.to_owned(),
        address: address.to_owned(),
    })
}

/// `[udp/]name:listen:remote@target-agent`. listen and remote are IPv4
/// host:port pairs — four colon-separated fields between the name and the
/// `@`; IPv6 targets or `idle_timeout_secs` tuning belong in the manifest
/// itself (the structured append is a shorthand, not a replacement).
fn parse_mesh_ingress_flag(token: &str) -> interflow_core::error::Result<plan::AddMeshIngressSpec> {
    let (udp, body) = match token.strip_prefix("udp/") {
        Some(rest) => (true, rest),
        None => (false, token),
    };
    let Some((body, target_agent)) = body.rsplit_once('@') else {
        return Err(flag_error(format!(
            "mesh ingress {token:?} must look like name:listen:remote@target-agent \
             (e.g. ollama:127.0.0.1:11434:127.0.0.1:11434@home-win)"
        )));
    };
    let Some((name, endpoints)) = body.split_once(':') else {
        return Err(flag_error(format!(
            "mesh ingress {token:?} has no :listen:remote after the rule name"
        )));
    };
    let fields: Vec<&str> = endpoints.split(':').collect();
    if fields.len() != 4 || fields.iter().any(|f| f.is_empty()) || name.is_empty() {
        return Err(flag_error(format!(
            "mesh ingress {token:?}: listen and remote must be IPv4 host:port pairs \
             (IPv6 → edit the manifest)"
        )));
    }
    Ok(plan::AddMeshIngressSpec {
        name: name.to_owned(),
        listen: format!("{}:{}", fields[0], fields[1]),
        udp,
        target_agent: target_agent.to_owned(),
        remote_addr: format!("{}:{}", fields[2], fields[3]),
        idle_timeout_secs: None,
    })
}

/// `[udp/]name:addr` — `addr` is one concrete `host:port` (target_addr) or
/// an `ip/prefix` range (target_cidr).
fn parse_mesh_egress_flag(token: &str) -> interflow_core::error::Result<plan::AddMeshEgressSpec> {
    let (udp, body) = match token.strip_prefix("udp/") {
        Some(rest) => (true, rest),
        None => (false, token),
    };
    let Some((name, addr)) = body.split_once(':') else {
        return Err(flag_error(format!(
            "mesh egress {token:?} must look like name:host:port or name:ip/prefix \
             (e.g. ollama:127.0.0.1:11434, loopback:127.0.0.0/8)"
        )));
    };
    if name.is_empty() || addr.is_empty() {
        return Err(flag_error(format!(
            "mesh egress {token:?} has an empty name or target"
        )));
    }
    if addr.contains('/') {
        Ok(plan::AddMeshEgressSpec {
            name: name.to_owned(),
            udp,
            target_addr: None,
            target_cidr: Some(addr.to_owned()),
        })
    } else {
        Ok(plan::AddMeshEgressSpec {
            name: name.to_owned(),
            udp,
            target_addr: Some(addr.to_owned()),
            target_cidr: None,
        })
    }
}
