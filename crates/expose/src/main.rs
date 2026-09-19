//! `interflow-expose` CLI entry point: ngrok-style public → private-network
//! tunnel.
//!
//! Subcommands:
//! - `interflow-expose expose <port>` — local side: expose local ports via the hub
//! - `interflow-expose edge` — public side: run the HubServer + HTTP listener (behind nginx)
//! - `interflow-expose init` — interactive wizard: generate certificates / config / profile
//! - `interflow-expose version` — version information

use clap::{Parser, Subcommand, ValueEnum};
use interflow_core::config::LoggingConfig;
use interflow_core::config::paths::absolutize;
use interflow_core::telemetry::LogFormat;
use interflow_expose::client::{self, ExposeArgs};
use interflow_expose::edge::{
    self, DEFAULT_AGENT_RECOVERY_TIMEOUT_SECS, DEFAULT_STREAM_IDLE_TIMEOUT_SECS, EdgeArgs,
    EdgeHubTls, RoutesConfig,
};
use interflow_expose::{init, profile};
use interflow_mesh::config::TransportKind;
use std::net::SocketAddr;
use std::path::Path;

/// Top-level CLI arguments.
#[derive(Parser)]
#[command(name = "interflow-expose")]
#[command(about = "Ngrok-style public domain → local service", long_about = None)]
struct Cli {
    /// Initial log level: a tracing filter directive (e.g. `debug` or
    /// `info,interflow_mesh=debug`). Overrides the `[logging]` section of
    /// routes.toml (edge) at startup; the default is `info`. On SIGHUP the
    /// file's `[logging]` (when present) takes over again.
    #[arg(
        long,
        global = true,
        value_name = "FILTER",
        value_parser = parse_log_level
    )]
    log_level: Option<String>,
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
        /// Client certificate PEM path, signed by a tenant CA (overrides profile).
        #[arg(long)]
        client_cert: Option<String>,
        /// Client key PEM path (overrides profile; must be 0600).
        #[arg(long)]
        client_key: Option<String>,
        /// Agent ID (overrides profile; defaults to expose-<host>-<rand>; must equal the client certificate CN).
        #[arg(long)]
        agent_id: Option<String>,
        /// Trusted hub CA path (only effective for https; overrides profile).
        #[arg(long)]
        ca_path: Option<String>,
        /// Transport toward the hub: `h2` (default, works wherever TCP egress
        /// is allowed) or `quic` (opt-in upgrade; requires UDP egress and a
        /// TLS trust anchor — `--ca-path` or the system CA).
        #[arg(long, value_enum)]
        transport: Option<CliTransport>,
        /// Hub QUIC address (`host:port`); overrides profile. Omitted: derived
        /// from the hub URL's host:port (valid when the edge's QUIC listener
        /// shares the hub TCP port number).
        #[arg(long)]
        hub_quic_addr: Option<String>,
        /// Merge these arguments into profile.toml; next time plain `expose <port>` suffices.
        #[arg(long)]
        save: bool,
    },
    /// Public side: run the HubServer + HTTP listener (behind nginx proxy_pass)
    Edge {
        /// Public listen address (nginx forwards traffic here).
        #[arg(long, default_value = "0.0.0.0:8443")]
        listen: SocketAddr,
        /// Internal hub listen address. Default 127.0.0.1 (edge and hub in
        /// one process); use 0.0.0.0 when LAN expose agents dial in over
        /// the internet (the hub plane is mTLS + TLS).
        #[arg(long, default_value = "127.0.0.1:16666")]
        hub_listen: SocketAddr,
        /// Routing table toml path.
        #[arg(long)]
        routes: String,
        /// Tenant client-CA entry `<name>=<path>` (repeatable): expose clients
        /// of tenant <name> authenticate with certificates issued by that CA.
        /// The edge's own gateway principal is minted in memory at startup.
        #[arg(long = "client-ca", value_name = "NAME=PATH", value_parser = parse_client_ca)]
        client_ca: Vec<(String, String)>,
        /// PROXY protocol on the public listener: `off` (default), `on`
        /// (accept from trusted proxies), `required` (trusted proxies must
        /// send it). For a PROXY-capable front (LB / nginx stream) — the
        /// standard nginx HTTP proxy_pass leg cannot emit it and should use
        /// --x-forwarded-for instead.
        #[arg(long, default_value = "off")]
        proxy_protocol: String,
        /// X-Forwarded-For real-IP restoration on the public listener:
        /// `off` (default), `on` (trusted proxies; absent header falls back
        /// to the TCP peer), `required` (trusted proxies must send it). This
        /// is the standard nginx HTTP proxy_pass topology — stock nginx
        /// cannot emit the PROXY protocol on that leg.
        #[arg(long = "x-forwarded-for", value_name = "MODE", default_value = "off")]
        x_forwarded_for: interflow_core::security::XffMode,
        /// Trusted proxy CIDR shared by PROXY protocol and X-Forwarded-For
        /// (repeatable; default 127.0.0.1 + ::1).
        #[arg(long = "trusted-proxy", value_name = "CIDR")]
        trusted_proxy: Vec<String>,
        /// Hub TLS certificate (if nginx already terminates TLS, edge needs no internal TLS).
        #[arg(long)]
        hub_cert: Option<String>,
        /// Hub TLS private key.
        #[arg(long)]
        hub_key: Option<String>,
        /// Stable gateway identity certificate — the leaf+CA chain bundle
        /// from `interflow-mesh certs gateway issue` (see --gateway-key).
        /// Providing it replaces the per-restart minted identity AND opts
        /// gateway flows into the inner TLS (e2e) layer.
        #[arg(long = "gateway-cert", requires = "gateway_key")]
        gateway_cert: Option<String>,
        /// Stable gateway identity private key (see --gateway-cert).
        #[arg(long = "gateway-key", requires = "gateway_cert")]
        gateway_key: Option<String>,
        /// QUIC listen address for the embedded hub (e.g. `0.0.0.0:16666`):
        /// enables the QUIC transport for expose clients. The UDP port is
        /// exposed directly (nginx does not carry it) and requires
        /// `--hub-cert`/`--hub-key` (QUIC mandates TLS).
        #[arg(long)]
        quic_listen: Option<SocketAddr>,
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
        /// Outer health-watch timeout over the internal agent (seconds): the
        /// edge exits for a systemd restart when the agent stays
        /// non-connected with no state change at all for this long, or hits a
        /// no-retry failure. Normal reconnect cycling never trips this.
        /// Default 120.
        #[arg(
            long,
            default_value_t = DEFAULT_AGENT_RECOVERY_TIMEOUT_SECS,
            value_parser = clap::value_parser!(u64).range(1..)
        )]
        agent_recovery_timeout_secs: u64,
        /// Route-level circuit breaker: backend-failure closes (within a window)
        /// trip a route; tripped routes are closed at the edge without an Open
        /// through the tunnel until a recovery probe succeeds.
        /// (disable with --route-breaker-enabled=false)
        #[arg(long, default_value_t = true, action = clap::ArgAction::Set)]
        route_breaker_enabled: bool,
        /// Route breaker: failures within the window required to trip a route.
        #[arg(long, default_value_t = 10, value_parser = clap::value_parser!(u32).range(1..))]
        route_breaker_failure_threshold: u32,
        /// Route breaker: sliding window (seconds) for counting failures.
        #[arg(long, default_value_t = 60, value_parser = clap::value_parser!(u64).range(1..))]
        route_breaker_window_secs: u64,
        /// Route breaker: cooldown (seconds) before one recovery probe is admitted.
        #[arg(long, default_value_t = 30, value_parser = clap::value_parser!(u64).range(1..))]
        route_breaker_cooldown_secs: u64,
    },
    /// Interactive wizard: generate certificates / config / profile
    Init,
    /// Show version information
    Version,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cli = Cli::parse();

    // Logging init: explicit --log-level > routes.toml [logging] (edge) > "info".
    // Runs after Cli::parse so the flag can join the precedence chain; clap
    // prints its own errors to stderr before any subscriber exists.
    let file_logging = match &cli.command {
        Commands::Edge { routes, .. } => read_routes_logging(routes),
        _ => None,
    };
    let (level, format) = resolve_logging(cli.log_level.as_deref(), file_logging);
    interflow_core::telemetry::init_logging(&level, format);

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

    match cli.command {
        Commands::Expose {
            ports,
            hub,
            client_cert,
            client_key,
            agent_id,
            ca_path,
            transport,
            hub_quic_addr,
            save,
        } => {
            let p = profile::load()?;

            let hub_url = pick("hub", hub, p.hub_url.as_deref())
                .ok_or_else(|| "missing --hub or profile.hub_url".to_string())?;
            let client_cert = absolutized(
                &pick("client_cert", client_cert, p.client_cert.as_deref())
                    .ok_or_else(|| "missing --client-cert or profile.client_cert".to_string())?,
            )?;
            let client_key = absolutized(
                &pick("client_key", client_key, p.client_key.as_deref())
                    .ok_or_else(|| "missing --client-key or profile.client_key".to_string())?,
            )?;
            let agent_id = pick("agent_id", agent_id, p.agent_id.as_deref())
                .unwrap_or_else(client::default_agent_id);
            // CLI flag > profile > h2 default
            let transport = transport
                .map(TransportKind::from)
                .or(p.transport)
                .unwrap_or_default();
            // CLI flag > profile; None stays dynamic (derived from hub_url at
            // config-assembly time, so a hub port change tracks the hub_url)
            let hub_quic_addr = pick("hub_quic_addr", hub_quic_addr, p.hub_quic_addr.as_deref());
            // A relative --ca-path means "relative to the current directory"
            // for this run; absolutize it once so --save persists a value
            // that keeps working from any directory.
            let ca_path = pick("ca_path", ca_path, p.ca_path.as_deref())
                .map(|ca| absolutized(&ca))
                .transpose()?;
            // Fail fast on a TLS-requiring transport with a missing CA
            // instead of dying mid-connect (profile-internal relative paths
            // anchor to the profile directory, CLI flags to the CWD). QUIC
            // mandates TLS just like an https hub URL.
            if (hub_url.starts_with("https") || transport == TransportKind::Quic)
                && let Some(ca) = &ca_path
                && !Path::new(ca).exists()
            {
                return Err(format!("--ca-path does not exist: {ca}").into());
            }

            if save {
                // Persist the resolved transport (writing Some(H2) on an
                // explicit override is what makes --save faithfully revert a
                // quic profile); hub_quic_addr persists only explicit values.
                let new_profile = profile::Profile {
                    hub_url: Some(hub_url.clone()),
                    client_cert: Some(client_cert.clone()),
                    client_key: Some(client_key.clone()),
                    agent_id: Some(agent_id.clone()),
                    ca_path: ca_path.clone(),
                    local_ports: if ports.is_empty() {
                        p.local_ports.clone()
                    } else {
                        Some(ports.clone())
                    },
                    transport: Some(transport),
                    hub_quic_addr: hub_quic_addr.clone(),
                };
                if let Err(e) = profile::save(&new_profile) {
                    tracing::warn!("failed to write profile (does not affect this run): {e}");
                }
            }

            let args = ExposeArgs {
                local_ports: ports,
                hub_url,
                agent_id,
                client_cert: Some(client_cert),
                client_key: Some(client_key),
                ca_path,
                transport,
                hub_quic_addr,
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
            client_ca,
            proxy_protocol,
            x_forwarded_for,
            trusted_proxy,
            hub_cert,
            hub_key,
            gateway_cert,
            gateway_key,
            quic_listen,
            audit_path,
            new_conn_rate_per_ip_per_minute,
            stream_idle_timeout_secs,
            route_breaker_enabled,
            route_breaker_failure_threshold,
            route_breaker_window_secs,
            route_breaker_cooldown_secs,
            agent_recovery_timeout_secs,
        } => {
            let hub_tls = match (hub_cert, hub_key) {
                (Some(cert_path), Some(key_path)) => Some(EdgeHubTls {
                    cert_path: absolutized(&cert_path)?,
                    key_path: absolutized(&key_path)?,
                }),
                (None, None) => None,
                _ => {
                    return Err(
                        "enabling TLS on the edge hub requires both --hub-cert and --hub-key"
                            .into(),
                    );
                }
            };
            let gateway_identity = match (gateway_cert, gateway_key) {
                (Some(cert_path), Some(key_path)) => {
                    Some((absolutized(&cert_path)?, absolutized(&key_path)?))
                }
                (None, None) => None,
                // clap `requires` already forces pairing; unreachable arm.
                _ => {
                    return Err(
                        "the stable gateway identity requires both --gateway-cert and --gateway-key"
                            .into(),
                    );
                }
            };
            let proxy_mode = proxy_protocol
                .parse::<interflow_core::security::ProxyProtocolMode>()
                .map_err(|e| format!("invalid --proxy-protocol value: {e}"))?;
            let args = EdgeArgs {
                listen_addr: listen,
                hub_listen_addr: hub_listen,
                routes_path: routes,
                tenant_cas: client_ca,
                proxy_protocol: interflow_core::security::ProxyProtocolConfig {
                    mode: proxy_mode,
                    trusted_proxies: if trusted_proxy.is_empty() {
                        vec!["127.0.0.1".to_string(), "::1".to_string()]
                    } else {
                        trusted_proxy
                    },
                },
                x_forwarded_for,
                hub_tls,
                gateway_identity,
                quic_listen,
                audit_path,
                new_conn_rate_per_ip_per_minute,
                stream_idle_timeout_secs,
                route_breaker_enabled,
                route_breaker_failure_threshold,
                route_breaker_window_secs,
                route_breaker_cooldown_secs,
                agent_recovery_timeout_secs,
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

/// Absolutizes a path argument once (relative → CWD, leading `~` → home) so
/// `--save` persists values that keep working from any directory. The same
/// treatment for every filesystem-path argument; profile-internal relative
/// values already anchored to the profile directory at load.
fn absolutized(value: &str) -> Result<String, Box<dyn std::error::Error>> {
    Ok(absolutize(Path::new(value))?.display().to_string())
}

/// clap value parser for `--client-ca NAME=PATH`.
fn parse_client_ca(s: &str) -> Result<(String, String), String> {
    let (name, path) = s
        .split_once('=')
        .ok_or_else(|| format!("expected NAME=PATH, got {s:?}"))?;
    let valid = !name.starts_with('_')
        && !name.is_empty()
        && name.len() <= 64
        && name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_');
    if !valid {
        return Err(format!(
            "invalid tenant name {name:?} ([A-Za-z0-9_-], no leading '_')"
        ));
    }
    if path.is_empty() {
        return Err("empty CA path".to_string());
    }
    // Same normalization as every other path flag (relative → CWD, `~` →
    // home); the value never passes through a shell when quoted.
    let path = absolutize(Path::new(path))
        .map_err(|e| e.to_string())?
        .display()
        .to_string();
    Ok((name.to_string(), path))
}

/// clap value parser for `--log-level`: reject a mistyped filter at parse
/// time (exit 2 with a pointed error) instead of silently running at `info`.
fn parse_log_level(s: &str) -> Result<String, String> {
    interflow_core::telemetry::validate_log_filter(s)?;
    Ok(s.to_string())
}

/// Startup precedence: an explicit `--log-level` flag beats routes.toml's
/// `[logging]` section, which beats the built-in `info` default. The flag is
/// a full logging override (level + plain format, the CLI context); the file
/// section — when present — also owns the format and reasserts its level on
/// every later SIGHUP reload.
fn resolve_logging(flag: Option<&str>, file: Option<LoggingConfig>) -> (String, LogFormat) {
    if let Some(level) = flag {
        return (level.to_string(), LogFormat::Plain);
    }
    file.map_or_else(
        || ("info".to_string(), LogFormat::Plain),
        |l| (l.level, l.format),
    )
}

/// Best-effort pre-read of routes.toml's `[logging]` section for startup
/// precedence. A missing/broken file returns None (falls back to
/// `--log-level`/`info`); `edge::run` re-loads the same file and turns real
/// errors into hard startup failures, so this path only needs to warn.
fn read_routes_logging(routes_path: &str) -> Option<LoggingConfig> {
    match RoutesConfig::load(routes_path) {
        Ok(cfg) => cfg.logging,
        Err(e) => {
            eprintln!("warning: cannot read {routes_path} for the [logging] section: {e}");
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn file_logging(level: &str, format: LogFormat) -> LoggingConfig {
        LoggingConfig {
            level: level.to_string(),
            format,
        }
    }

    #[test]
    fn resolve_logging_flag_beats_file_beats_default() {
        // Explicit flag wins over the file, with plain format.
        assert_eq!(
            resolve_logging(Some("debug"), Some(file_logging("trace", LogFormat::Json))),
            ("debug".to_string(), LogFormat::Plain)
        );
        // No flag: the file section owns level + format.
        assert_eq!(
            resolve_logging(
                None,
                Some(file_logging("info,interflow_mesh=debug", LogFormat::Json))
            ),
            (
                "info,interflow_mesh=debug".to_string(),
                interflow_core::telemetry::LogFormat::Json
            )
        );
        // Neither: built-in default.
        assert_eq!(
            resolve_logging(None, None),
            (
                "info".to_string(),
                interflow_core::telemetry::LogFormat::Plain
            )
        );
    }
}

/// CLI-facing transport choice; maps 1:1 onto the agent config's
/// [`TransportKind`] (clap needs its own `ValueEnum`).
#[derive(Clone, Copy, PartialEq, Eq, ValueEnum)]
enum CliTransport {
    /// HTTP/2 long-lived streams (default; works wherever TCP egress works).
    H2,
    /// QUIC native streams (opt-in; eliminates TCP head-of-line blocking,
    /// requires UDP egress and TLS).
    Quic,
}

impl From<CliTransport> for TransportKind {
    fn from(v: CliTransport) -> Self {
        match v {
            CliTransport::H2 => Self::H2,
            CliTransport::Quic => Self::Quic,
        }
    }
}
