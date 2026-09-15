//! `interflow-mesh` CLI entry point: site-to-site TCP tunnel.
//!
//! Subcommands:
//! - `interflow-mesh hub --config hub.toml` — start the public relay
//! - `interflow-mesh agent --config agent.toml` — start the LAN agent (can carry both ingress + egress)
//! - `interflow-mesh version` — version information

use clap::{Parser, Subcommand};
use interflow_core::config::paths::absolutize;
use interflow_core::telemetry;
use interflow_mesh::config::{load_agent_config, load_hub_config};
use std::path::Path;

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
    /// Start the hub server (public relay node)
    Hub {
        /// Config file path
        #[arg(short, long)]
        config: String,
    },
    /// Start the agent (LAN node, can carry both ingress + egress)
    Agent {
        /// Config file path
        #[arg(short, long)]
        config: String,
    },
    /// Show version information
    Version,
}

#[tokio::main]
async fn main() -> interflow_core::error::Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Commands::Hub { config } => {
            // Absolutize once: reload re-reads this path on SIGHUP, and the
            // stored path must not depend on a CWD the process never changes.
            let config_path = absolutize(Path::new(&config))?.display().to_string();
            let hub_config = load_hub_config(&config_path)?;
            telemetry::init_logging(&hub_config.logging.level, hub_config.logging.format);

            if hub_config.metrics.enabled {
                telemetry::init_metrics(hub_config.metrics.listen_addr, &hub_config.metrics.path);
            }

            tracing::info!(
                "Starting hub server, listening on: {}",
                hub_config.server.listen_addr
            );

            let hub_server = interflow_mesh::hub::HubServer::new(hub_config, config_path)?;

            // Shutdown signal → graceful drain (stop accepting →
            // GOAWAY/CONNECTION_CLOSE → wait for connections to close out →
            // flush the audit log). SIGHUP keeps its hot-reload semantics and
            // does not trigger shutdown.
            let shutdown = tokio_util::sync::CancellationToken::new();
            {
                let token = shutdown.clone();
                #[cfg(unix)]
                {
                    use tokio::signal::unix::{SignalKind, signal};
                    let mut sigint = signal(SignalKind::interrupt())?;
                    let mut sigterm = signal(SignalKind::terminate())?;
                    tokio::spawn(async move {
                        tokio::select! {
                            _ = sigint.recv()  => tracing::info!("Received SIGINT (signal 2), starting graceful shutdown"),
                            _ = sigterm.recv() => tracing::info!("Received SIGTERM (signal 15), starting graceful shutdown"),
                        }
                        token.cancel();
                    });
                }
                #[cfg(not(unix))]
                {
                    // Windows has no SIGTERM; listen only for Ctrl+C
                    // (equivalent to SIGINT).
                    tokio::spawn(async move {
                        if tokio::signal::ctrl_c().await.is_ok() {
                            tracing::info!(
                                "Received Ctrl+C (signal 2), starting graceful shutdown"
                            );
                            token.cancel();
                        }
                    });
                }
            }

            hub_server.run_until(shutdown).await?;
            tracing::info!("Hub has exited");
        }
        Commands::Agent { config } => {
            // Absolutize once: rule persistence and disk resync re-read this
            // path later, independent of the CWD.
            let config_path = absolutize(Path::new(&config))?.display().to_string();
            let agent_config = load_agent_config(&config_path)?;
            telemetry::init_logging(&agent_config.logging.level, agent_config.logging.format);

            tracing::info!("Starting agent: {}", agent_config.agent.id);

            let mut agent =
                interflow_mesh::agent::AgentClient::with_config_file(agent_config, config_path)?
                    .start();

            // Event pump: turn structured lifecycle events into log records.
            let mut events = agent.take_events();
            let pump = tokio::spawn(async move {
                use interflow_mesh::agent::AgentEvent;
                while let Some(ev) = events.recv().await {
                    match ev {
                        AgentEvent::StateChanged(s) => {
                            tracing::info!(state = ?s, "agent state changed");
                        }
                        AgentEvent::SessionEstablished { agent_id } => {
                            tracing::info!(agent_id, "session established");
                        }
                        AgentEvent::SessionEnded { reason } => {
                            tracing::info!(reason, "session ended");
                        }
                    }
                }
            });

            // Exit signal → graceful shutdown, preserving exit-code semantics.
            #[cfg(unix)]
            let exit_code = {
                use tokio::signal::unix::{SignalKind, signal};
                let mut sigint = signal(SignalKind::interrupt())?;
                let mut sigterm = signal(SignalKind::terminate())?;
                let mut sighup = signal(SignalKind::hangup())?;
                tokio::select! {
                    _ = sigint.recv()  => { tracing::error!("Received SIGINT (signal 2), process will exit");  130 }
                    _ = sigterm.recv() => { tracing::error!("Received SIGTERM (signal 15), process will exit"); 143 }
                    _ = sighup.recv()  => { tracing::error!("Received SIGHUP (signal 1), process will exit (common when the terminal closes)"); 129 }
                }
            };
            #[cfg(not(unix))]
            // Windows has no SIGTERM/SIGHUP; listen only for Ctrl+C
            // (equivalent to SIGINT).
            let exit_code = {
                tokio::select! {
                    _ = tokio::signal::ctrl_c() => { tracing::error!("Received Ctrl+C (signal 2), process will exit"); 130 }
                }
            };

            pump.abort();
            if let Err(e) = agent.shutdown_graceful().await {
                tracing::error!("Graceful shutdown failed: {e}");
            }
            std::process::exit(exit_code);
        }
        Commands::Version => {
            let build_date = env!("INTERFLOW_BUILD_DATE");
            let git_hash = env!("INTERFLOW_GIT_HASH");
            println!("{build_date}-{git_hash}");
        }
    }

    Ok(())
}
