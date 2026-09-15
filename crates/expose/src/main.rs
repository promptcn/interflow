//! `interflow-expose` CLI entry point: ngrok-style public → private-network
//! tunnel.
//!
//! Subcommands:
//! - `interflow-expose expose <port>` — local side: expose local ports via the hub
//! - `interflow-expose edge` — public side: run the HubServer + HTTP listener (behind nginx)
//! - `interflow-expose init` — interactive wizard: generate certificates / config / profile
//! - `interflow-expose version` — version information

use clap::{Parser, Subcommand};
use interflow_core::config::paths::absolutize;
use interflow_expose::client::{self, ExposeArgs};
use interflow_expose::edge::{self, DEFAULT_STREAM_IDLE_TIMEOUT_SECS, EdgeArgs, EdgeHubTls};
use interflow_expose::{init, profile};
use std::net::SocketAddr;
use std::path::Path;

/// Top-level CLI arguments.
#[derive(Parser)]
#[command(name = "interflow-expose")]
#[command(about = "Ngrok-style public domain → local service", long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

/// Subcommand enum.
#[derive(Subcommand)]
enum Commands {
    /// Local side: expose local ports on a public domain (via the hub)
    Expose {
        /// Local port(s), one or more (e.g. `3001 5174`). Multiple ports share the
        /// same agent_id; edge's routes.toml routes by host to pick the remote_addr.
        #[arg(num_args = 1..)]
        ports: Vec<u16>,
        /// Hub URL (overrides profile).
        #[arg(long)]
        hub: Option<String>,
        /// Agent token (overrides profile).
        #[arg(long)]
        token: Option<String>,
        /// Agent ID (overrides profile; defaults to expose-<host>-<rand>).
        #[arg(long)]
        agent_id: Option<String>,
        /// Trusted hub CA path (only effective for https; overrides profile).
        #[arg(long)]
        ca_path: Option<String>,
        /// Merge these arguments into profile.toml; next time plain `expose <port>` suffices.
        #[arg(long)]
        save: bool,
    },
    /// Public side: run the HubServer + HTTP listener (behind nginx proxy_pass)
    Edge {
        /// Public listen address (nginx forwards traffic here).
        #[arg(long, default_value = "0.0.0.0:8443")]
        listen: SocketAddr,
        /// Internal hub listen address (127.0.0.1 only).
        #[arg(long, default_value = "127.0.0.1:16666")]
        hub_listen: SocketAddr,
        /// Routing table toml path.
        #[arg(long)]
        routes: String,
        /// Agent token (both edge itself and remote expose clients use it to register with the hub).
        #[arg(long)]
        token: String,
        /// Hub TLS certificate (if nginx already terminates TLS, edge needs no internal TLS).
        #[arg(long)]
        hub_cert: Option<String>,
        /// Hub TLS private key.
        #[arg(long)]
        hub_key: Option<String>,
        /// Audit log JSONL path (omit to disable auditing).
        #[arg(long)]
        audit_path: Option<String>,
        /// Per-IP new-connection limit per minute (guards against connect-loop attacks; 0 = unlimited). Default 30.
        #[arg(long, default_value_t = 30)]
        new_conn_rate_per_ip_per_minute: u32,
        /// Public-stream idle timeout (seconds): the stream is torn down when neither
        /// direction has data; must be ≤ nginx proxy_read_timeout.
        /// Default 300.
        #[arg(
            long,
            default_value_t = DEFAULT_STREAM_IDLE_TIMEOUT_SECS,
            value_parser = clap::value_parser!(u64).range(1..)
        )]
        stream_idle_timeout_secs: u64,
    },
    /// Interactive wizard: generate certificates / config / profile
    Init,
    /// Show version information
    Version,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Logging init (info level by default)
    interflow_core::telemetry::init_logging("info", interflow_core::telemetry::LogFormat::Plain);

    // Route panics through tracing: the default hook only writes to stderr,
    // and you cannot tell why the agent died.
    std::panic::set_hook(Box::new(|info| {
        let loc = info.location().map_or_else(
            || "<unknown>".into(),
            |l| format!("{}:{}:{}", l.file(), l.line(), l.column()),
        );
        let payload = info
            .payload()
            .downcast_ref::<&str>()
            .copied()
            .or_else(|| {
                info.payload()
                    .downcast_ref::<String>()
                    .map(std::string::String::as_str)
            })
            .unwrap_or("<non-string panic payload>");
        tracing::error!(panic.location = %loc, panic.payload = %payload, "process panic");
    }));

    let cli = Cli::parse();

    match cli.command {
        Commands::Expose {
            ports,
            hub,
            token,
            agent_id,
            ca_path,
            save,
        } => {
            let p = profile::load()?;

            let hub_url = pick("hub", hub, p.hub_url.as_deref())
                .ok_or_else(|| "missing --hub or profile.hub_url".to_string())?;
            let auth_token = pick("token", token, p.auth_token.as_deref())
                .ok_or_else(|| "missing --token or profile.auth_token".to_string())?;
            let agent_id = pick("agent_id", agent_id, p.agent_id.as_deref())
                .unwrap_or_else(client::default_agent_id);
            // A relative --ca-path means "relative to the current directory"
            // for this run; absolutize it once so --save persists a value
            // that keeps working from any directory.
            let ca_path = match pick("ca_path", ca_path, p.ca_path.as_deref()) {
                Some(ca) => Some(absolutize(Path::new(&ca))?.display().to_string()),
                None => None,
            };
            // Fail fast on an https hub with a missing CA instead of dying
            // mid-connect (profile-internal relative paths anchor to the
            // profile directory, CLI flags to the CWD).
            if hub_url.starts_with("https")
                && let Some(ca) = &ca_path
                && !Path::new(ca).exists()
            {
                return Err(format!("--ca-path does not exist: {ca}").into());
            }

            if save {
                let new_profile = profile::Profile {
                    hub_url: Some(hub_url.clone()),
                    auth_token: Some(auth_token.clone()),
                    agent_id: Some(agent_id.clone()),
                    ca_path: ca_path.clone(),
                    local_ports: if ports.is_empty() {
                        p.local_ports.clone()
                    } else {
                        Some(ports.clone())
                    },
                };
                if let Err(e) = profile::save(&new_profile) {
                    tracing::warn!("failed to write profile (does not affect this run): {e}");
                }
            }

            let args = ExposeArgs {
                local_ports: ports,
                hub_url,
                auth_token,
                agent_id,
                ca_path,
            };

            let mut handle = client::start(&args)?;

            // Event pump: turn structured lifecycle events into logs (the
            // CLI's logging behavior derives from the state events).
            let mut events = handle.take_events();
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

            // Exit signal → graceful shutdown (exit only after all child
            // tasks have exited), preserving the original exit-code semantics.
            // Supervisor ending naturally (config error etc.) → exit code 1.
            #[cfg(unix)]
            let exit_code = {
                use tokio::signal::unix::{SignalKind, signal};
                let mut sigint = signal(SignalKind::interrupt())?;
                let mut sigterm = signal(SignalKind::terminate())?;
                let mut sighup = signal(SignalKind::hangup())?;
                tokio::select! {
                    _ = sigint.recv()  => { tracing::error!("received SIGINT  (signal 2), process will exit");  130 }
                    _ = sigterm.recv() => { tracing::error!("received SIGTERM (signal 15), process will exit"); 143 }
                    _ = sighup.recv()  => { tracing::error!("received SIGHUP  (signal 1), process will exit (common when the terminal closes)"); 129 }
                }
            };

            #[cfg(not(unix))]
            // Windows has no SIGTERM/SIGHUP; listen only for Ctrl+C (equivalent to SIGINT).
            let exit_code = {
                tokio::select! {
                    _ = tokio::signal::ctrl_c() => { tracing::error!("received Ctrl+C (signal 2), process will exit"); 130 }
                }
            };

            pump.abort();
            if let Err(e) = handle.shutdown_graceful().await {
                tracing::error!("graceful shutdown failed: {e}");
            }
            std::process::exit(exit_code);
        }
        Commands::Edge {
            listen,
            hub_listen,
            routes,
            token,
            hub_cert,
            hub_key,
            audit_path,
            new_conn_rate_per_ip_per_minute,
            stream_idle_timeout_secs,
        } => {
            let hub_tls = match (hub_cert, hub_key) {
                (Some(cert_path), Some(key_path)) => Some(EdgeHubTls {
                    cert_path,
                    key_path,
                }),
                (None, None) => None,
                _ => {
                    return Err(
                        "enabling TLS on the edge hub requires both --hub-cert and --hub-key"
                            .into(),
                    );
                }
            };
            let args = EdgeArgs {
                listen_addr: listen,
                hub_listen_addr: hub_listen,
                routes_path: routes,
                agent_token: token,
                hub_tls,
                audit_path,
                new_conn_rate_per_ip_per_minute,
                stream_idle_timeout_secs,
            };
            edge::run(args).await?;
        }
        Commands::Init => {
            init::run()?;
        }
        Commands::Version => {
            let build_date = env!("INTERFLOW_BUILD_DATE");
            let git_hash = env!("INTERFLOW_GIT_HASH");
            println!("{build_date}-{git_hash}");
        }
    }

    Ok(())
}

/// CLI flag > profile field > None. `name` is only used for error context.
fn pick(name: &str, cli: Option<String>, from_profile: Option<&str>) -> Option<String> {
    if let Some(v) = cli {
        Some(v)
    } else if let Some(v) = from_profile {
        Some(v.to_string())
    } else {
        tracing::debug!("argument {name} not provided (not set on CLI or in profile)");
        None
    }
}
