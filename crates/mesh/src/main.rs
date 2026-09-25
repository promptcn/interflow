//! `interflow-mesh` CLI entry point: site-to-site TCP tunnel.
//!
//! Subcommands:
//! - `interflow-mesh hub --pack <dir>` — start the public relay from a
//!   Credential Pack (`interflow plan apply` renders the pack)
//! - `interflow-mesh agent --pack <dir>` — start a LAN agent from a
//!   Credential Pack (can carry both ingress + egress)
//! - `interflow-mesh version` — version information

use clap::{Parser, Subcommand};
use std::path::PathBuf;

/// Top-level CLI arguments.
#[derive(Parser)]
#[command(name = "interflow-mesh")]
#[command(about = "Site-to-site TCP tunnel (public hub + LAN agents)", long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

/// Subcommand enum.
#[derive(Subcommand)]
enum Commands {
    /// Start the hub (public relay between the two private networks)
    Hub {
        /// Credential Pack directory (`interflow plan apply` renders it)
        #[arg(short, long)]
        pack: PathBuf,
    },
    /// Start an agent (LAN side; carries ingress + egress rules)
    Agent {
        /// Credential Pack directory (`interflow plan apply` renders it)
        #[arg(short, long)]
        pack: PathBuf,
    },
    /// Show version information
    Version,
}

#[tokio::main]
async fn main() -> interflow_core::error::Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Commands::Hub { pack } => interflow_mesh::pack::run_hub(&pack).await,
        Commands::Agent { pack } => interflow_mesh::pack::run_agent(&pack).await,
        Commands::Version => {
            // Full identity: name anchors the binary, the shared const pins
            // the release line and exact code (`-dirty` = uncommitted
            // changes) — the same const `interflow --version` prints, so
            // the two CLIs cannot drift apart.
            println!(
                "{} {}",
                env!("CARGO_PKG_NAME"),
                interflow_buildinfo::VERSION_WITH_TAG
            );
            Ok(())
        }
    }
}
