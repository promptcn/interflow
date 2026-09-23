//! `interflow-soak-node` — the soak gate's process-under-test entry.
//!
//! The product CLI (`interflow-mesh`) is pack-only; the soak harness needs
//! process-level fault injection with knobs the pack path deliberately does
//! not express (impairment-proxy endpoints, the H2/QUIC matrix, pinned
//! metrics listener, per-rule idle budgets). This dev-only binary bridges
//! that gap: it receives the exact engine configuration as a JSON document
//! (the serde-serialized `HubConfig`/`AgentConfig` model — a machine
//! handoff between the soak runner and its child processes, not a product
//! configuration format) and runs the real engine with the conventional
//! signal/exit-code semantics the soak asserts against.

use clap::{Parser, Subcommand};
use interflow_mesh::config::{AgentConfig, HubConfig};
use std::path::PathBuf;

/// Top-level CLI arguments.
#[derive(Parser)]
#[command(name = "interflow-soak-node")]
#[command(about = "Soak-gate node: run the real engine from a JSON config handoff (dev-only)")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

/// Subcommand enum.
#[derive(Subcommand)]
enum Commands {
    /// Start the hub server
    Hub {
        /// JSON config handoff path (serialized `HubConfig`)
        #[arg(long)]
        json: PathBuf,
    },
    /// Start the agent
    Agent {
        /// JSON config handoff path (serialized `AgentConfig`)
        #[arg(long)]
        json: PathBuf,
    },
}

fn load_json<T: serde::de::DeserializeOwned>(
    path: &std::path::Path,
) -> interflow_core::error::Result<T> {
    let text = std::fs::read_to_string(path).map_err(|e| {
        interflow_core::error::InterflowError::config(format!("read {}", path.display()))
            .with_source(e)
    })?;
    serde_json::from_str(&text).map_err(|e| {
        interflow_core::error::InterflowError::config(format!("parse {}", path.display()))
            .with_source(e)
    })
}

#[tokio::main]
async fn main() -> interflow_core::error::Result<()> {
    let cli = Cli::parse();
    match cli.command {
        Commands::Hub { json } => run_hub(load_json(&json)?).await,
        Commands::Agent { json } => run_agent(load_json(&json)?).await,
    }
}

async fn run_hub(hub_config: HubConfig) -> interflow_core::error::Result<()> {
    interflow_core::telemetry::init_logging(&hub_config.logging.level, hub_config.logging.format);

    if hub_config.metrics.enabled {
        interflow_core::telemetry::init_metrics(
            hub_config.metrics.listen_addr,
            &hub_config.metrics.path,
        );
    }

    tracing::info!(
        "Starting hub server, listening on: {}",
        hub_config.server.listen_addr
    );

    let hub_server = interflow_mesh::hub::HubServer::new(hub_config)?;

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
            tokio::spawn(async move {
                if tokio::signal::ctrl_c().await.is_ok() {
                    tracing::info!("Received Ctrl+C (signal 2), starting graceful shutdown");
                    token.cancel();
                }
            });
        }
    }

    hub_server.run_until(shutdown).await?;
    tracing::info!("Hub has exited");
    Ok(())
}

async fn run_agent(agent_config: AgentConfig) -> interflow_core::error::Result<()> {
    interflow_core::telemetry::init_logging(
        &agent_config.logging.level,
        agent_config.logging.format,
    );

    // Soak-gate fault plan (INTERFLOW_FAULT_PLAN): installed before anything
    // runs so early-supervise faults fire too.
    interflow_core::fault::install_from_env("INTERFLOW_FAULT_PLAN");

    tracing::info!("Starting agent: {}", agent_config.agent.id);

    let mut agent = interflow_mesh::agent::AgentClient::new(agent_config)?.start();

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

    // Exit signal → graceful shutdown, preserving exit-code semantics (the
    // soak asserts the conventional 130/143/129 codes).
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
