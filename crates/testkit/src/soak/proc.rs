//! Subprocess orchestration: lifecycle management for the real `interflow-mesh` hub / agent binaries.
//!
//! The soak gate's system under test = three real processes (hub + egress agent + ingress
//! agent), configured through real TOML files (the serde-serialized output of
//! `HubConfig`/`AgentConfig`), each logging to its own file under the run directory, and
//! shut down through the real SIGTERM → graceful drain path.

use crate::certs::TestCerts;
use interflow_core::protocol::StreamProto;
use interflow_core::tls::TlsMinVersion;
use interflow_mesh::config::{
    AclConfig, AclRule, AgentConfig, AgentInfo, AgentTlsConfig, AuthConfig, AuthMode,
    ControlConfig, EgressRule, HUB_CONFIG_VERSION, HeartbeatConfig, HubConfig, HubQuicConfig,
    HubSecurityConfig, HubTlsConfig, IngressRule, LoggingConfig, MetricsConfig, ServerConfig,
    TransportKind,
};
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::time::Duration;
use tokio::process::{Child, Command};

/// Hub config (real TOML): TLS + QUIC dual stack, anonymous + ACL, default heartbeat
/// (liveness deadline 75s), metrics endpoint enabled (canary assertions go through the
/// production telemetry path).
#[allow(clippy::too_many_arguments)]
pub fn hub_config(listen: SocketAddr, metrics: SocketAddr, certs: &TestCerts) -> HubConfig {
    HubConfig {
        config_version: HUB_CONFIG_VERSION,
        server: ServerConfig {
            listen_addr: listen,
        },
        auth: AuthConfig {
            mode: AuthMode::Anonymous,
            allow_anonymous: true,
            rate_limit_per_minute: 0,
            static_token: None,
            mtls: None,
        },
        tls: Some(HubTlsConfig {
            enabled: true,
            cert_path: certs.server_cert_path().display().to_string(),
            key_path: certs.server_key_path().display().to_string(),
            min_version: TlsMinVersion::V1_3,
        }),
        acl: AclConfig {
            rules: vec![
                AclRule {
                    source: "ingress".to_string(),
                    target: "egress".to_string(),
                },
                // churn agent (dedicated to the eviction scenario): the short-lived-stream
                // source, see the "churn + re-registration eviction" scenario in the runner
                AclRule {
                    source: "churn".to_string(),
                    target: "egress".to_string(),
                },
            ]
            .into_iter()
            .collect(),
        },
        security: HubSecurityConfig::default(),
        heartbeat: HeartbeatConfig::default(),
        metrics: MetricsConfig {
            enabled: true,
            listen_addr: metrics,
            path: "/metrics".to_string(),
        },
        audit: Default::default(),
        logging: LoggingConfig {
            // Own-crate debug on top of info: the QUIC transport-stats sampler
            // (CC forensics anchor, 2026-09-16 quic-stall case file) logs at
            // debug — soak is the diagnostic context where it must appear.
            level: "info,interflow_core=debug,interflow_mesh=debug".to_string(),
            format: interflow_mesh::config::LogFormat::Plain,
        },
        transport: interflow_mesh::config::HubTransportConfig {
            quic: HubQuicConfig {
                enabled: true,
                listen_addr: None,
                ..HubQuicConfig::default()
            },
            ..interflow_mesh::config::HubTransportConfig::default()
        },
    }
}

/// Egress agent config: connect target = the impairment proxy address (impairment sits on
/// the egress↔hub link), and the egress rule points at the SSE backend inside the runner.
pub fn egress_agent_config(
    hub_endpoint: SocketAddr,
    transport: TransportKind,
    certs: &TestCerts,
    backend: SocketAddr,
) -> AgentConfig {
    let mut cfg = base_agent_config("egress", hub_endpoint, transport, certs);
    cfg.egress = vec![EgressRule {
        name: "sse".to_string(),
        target_addr: backend,
        target_protocol: StreamProto::Tcp,
        udp_idle_timeout_secs: None,
    }];
    cfg
}

/// Ingress agent config: connects directly to the hub (no impairment), with a local
/// listener for consumers; the ingress rule carries an explicit idle budget (silent
/// window < idle, so streams must stay alive).
pub fn ingress_agent_config(
    hub_endpoint: SocketAddr,
    transport: TransportKind,
    certs: &TestCerts,
    listen: SocketAddr,
    backend: SocketAddr,
    idle_timeout_secs: u64,
) -> AgentConfig {
    let mut cfg = base_agent_config("ingress", hub_endpoint, transport, certs);
    cfg.ingress = vec![IngressRule {
        name: "sse".to_string(),
        listen_addr: listen,
        listen_protocol: StreamProto::Tcp,
        target_agent: "egress".to_string(),
        remote_addr: Some(backend.to_string()),
        idle_timeout_secs: Some(idle_timeout_secs),
        udp_per_ip_pps: 0,
        udp_per_ip_bytes_per_sec: 0,
        udp_egress_bytes_per_sec: 0,
    }];
    cfg
}

/// Churn agent config (eviction scenario): a separate ingress agent (id = "churn") that
/// carries short-lived streams (connect → receive a short stretch → disconnect) and is
/// periodically SIGKILLed + restarted to produce "source-side re-registration → hub
/// sweep → notify the peer" waves. Kept separate from the main ingress so the eviction
/// waves never touch the persistent consumer streams.
pub fn churn_agent_config(
    hub_endpoint: SocketAddr,
    transport: TransportKind,
    certs: &TestCerts,
    listen: SocketAddr,
    backend: SocketAddr,
) -> AgentConfig {
    let mut cfg = base_agent_config("churn", hub_endpoint, transport, certs);
    cfg.ingress = vec![IngressRule {
        name: "churn".to_string(),
        listen_addr: listen,
        listen_protocol: StreamProto::Tcp,
        target_agent: "egress".to_string(),
        remote_addr: Some(backend.to_string()),
        idle_timeout_secs: Some(60),
        udp_per_ip_pps: 0,
        udp_per_ip_bytes_per_sec: 0,
        udp_egress_bytes_per_sec: 0,
    }];
    cfg
}

fn base_agent_config(
    id: &str,
    hub_endpoint: SocketAddr,
    transport: TransportKind,
    certs: &TestCerts,
) -> AgentConfig {
    AgentConfig {
        agent: AgentInfo {
            id: id.to_string(),
            hub_url: format!("http://{hub_endpoint}"),
            transport,
            hub_quic_addr: (transport == TransportKind::Quic).then(|| hub_endpoint.to_string()),
            // handshake retransmit headroom under packet loss
            connect_timeout_secs: 10,
            ..AgentInfo::default()
        },
        control: ControlConfig {
            enabled: false,
            ..ControlConfig::default()
        },
        tls: Some(AgentTlsConfig {
            enabled: true,
            ca_path: Some(certs.ca_path().display().to_string()),
            client_cert_path: None,
            client_key_path: None,
            hub_cert_fingerprint: None,
        }),
        logging: LoggingConfig {
            // Own-crate debug on top of info: the QUIC transport-stats sampler
            // (CC forensics anchor, 2026-09-16 quic-stall case file) logs at
            // debug — soak is the diagnostic context where it must appear.
            level: "info,interflow_core=debug,interflow_mesh=debug".to_string(),
            format: interflow_mesh::config::LogFormat::Plain,
        },
        ..AgentConfig::default()
    }
}

/// Serialize a config to a TOML file.
pub fn write_toml<T: serde::Serialize>(path: &Path, cfg: &T) -> Result<(), String> {
    let text =
        toml::to_string_pretty(cfg).map_err(|e| format!("serialize {}: {e}", path.display()))?;
    std::fs::write(path, text).map_err(|e| format!("write {}: {e}", path.display()))
}

// ---------------------------------------------------------------------------
// Subprocess management
// ---------------------------------------------------------------------------

/// A process under test (a hub / agent binary).
pub struct MeshProcess {
    /// Process name ("hub" / "egress" / "ingress", used for attribution and logs).
    pub name: &'static str,
    child: Child,
    /// Log file path (both stdout and stderr are redirected here).
    pub log_path: PathBuf,
}

/// Spawn a mesh subprocess; stdout/stderr are appended to `log_path`.
/// `extra_env` is applied on top of the inherited environment (the fault
/// plan var for agent fault-injection phases).
pub fn spawn_mesh(
    bin: &Path,
    subcommand: &str,
    config_path: &Path,
    log_path: &Path,
    name: &'static str,
    extra_env: &[(&str, &str)],
) -> Result<MeshProcess, String> {
    let open = || {
        std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(log_path)
    };
    let mut cmd = Command::new(bin);
    cmd.arg(subcommand).arg("--config").arg(config_path);
    for (k, v) in extra_env {
        cmd.env(k, v);
    }
    let child = cmd
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::from(
            open().map_err(|e| format!("open log: {e}"))?,
        ))
        .stderr(std::process::Stdio::from(
            open().map_err(|e| format!("open log: {e}"))?,
        ))
        .spawn()
        .map_err(|e| format!("spawn {name} ({}){}: {e}", bin.display(), subcommand))?;
    Ok(MeshProcess {
        name,
        child,
        log_path: log_path.to_path_buf(),
    })
}

impl MeshProcess {
    /// PID (while the process is still running).
    pub fn pid(&self) -> Option<u32> {
        self.child.id()
    }

    /// Whether it has exited; when exited, returns the exit code (None if killed by signal).
    pub fn try_exit_code(&mut self) -> Option<Option<i32>> {
        match self.child.try_wait() {
            Ok(Some(status)) => Some(status.code()),
            _ => None,
        }
    }

    /// Log tail (diagnostic evidence; takes the last `max_bytes` bytes, aligned to line starts).
    pub fn log_tail(&self, max_bytes: u64) -> String {
        use std::io::{Read, Seek, SeekFrom};
        let Ok(mut f) = std::fs::File::open(&self.log_path) else {
            return String::new();
        };
        let Ok(len) = f.metadata().map(|m| m.len()) else {
            return String::new();
        };
        let start = len.saturating_sub(max_bytes);
        if f.seek(SeekFrom::Start(start)).is_err() {
            return String::new();
        }
        let mut buf = String::new();
        if f.read_to_string(&mut buf).is_err() {
            return String::new();
        }
        if start > 0 {
            // Discard the half-line produced by the truncation
            if let Some(pos) = buf.find('\n') {
                buf.drain(..=pos);
            }
        }
        buf
    }

    /// SIGKILL immediately and reap (eviction scenario: simulates an agent's abnormal
    /// death — no graceful Close, no connection-layer notification, only the hub-side
    /// death-signal path).
    pub async fn kill_and_wait(&mut self) -> Result<(), String> {
        self.child
            .start_kill()
            .map_err(|e| format!("{} SIGKILL: {e}", self.name))?;
        self.child
            .wait()
            .await
            .map_err(|e| format!("{} wait-after-kill: {e}", self.name))?;
        Ok(())
    }

    /// SIGTERM graceful shutdown: wait a bounded time for exit and return the exit code; on
    /// timeout, fall back to SIGKILL and report an error.
    pub async fn terminate_graceful(&mut self, timeout: Duration) -> Result<Option<i32>, String> {
        let Some(pid) = self.child.id() else {
            // Already exited: take the final status
            let status = self
                .child
                .wait()
                .await
                .map_err(|e| format!("{} wait: {e}", self.name))?;
            return Ok(status.code());
        };
        #[cfg(unix)]
        {
            // Use the standard kill(1) tool to send the signal, avoiding unsafe for libc::kill
            let r = tokio::process::Command::new("kill")
                .arg("-TERM")
                .arg(pid.to_string())
                .output()
                .await;
            if let Ok(out) = &r {
                if !out.status.success() {
                    return Err(format!("{} kill -TERM failed: {}", self.name, out.status));
                }
            }
        }
        #[cfg(not(unix))]
        {
            let _ = pid;
            self.child
                .start_kill()
                .map_err(|e| format!("{} kill: {e}", self.name))?;
        }
        match tokio::time::timeout(timeout, self.child.wait()).await {
            Ok(status) => status
                .map(|s| s.code())
                .map_err(|e| format!("{} wait: {e}", self.name)),
            Err(_) => {
                self.child
                    .start_kill()
                    .map_err(|e| format!("{} SIGKILL: {e}", self.name))?;
                let status = self
                    .child
                    .wait()
                    .await
                    .map_err(|e| format!("{} wait-after-kill: {e}", self.name))?;
                Err(format!(
                    "{} graceful shutdown timed out ({timeout:?}), fell back to SIGKILL (final status {status})",
                    self.name
                ))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The config must really be loadable: serialize → `load_hub_config` round-trip.
    /// If the TOML produced by soak is incompatible with the mesh parser, this fails
    /// until fixed.
    #[test]
    fn hub_config_toml_round_trips() {
        let certs = TestCerts::generate("soak-proc-test", "soak-egress");
        let listen: SocketAddr = "127.0.0.1:16666".parse().expect("listen");
        let metrics: SocketAddr = "127.0.0.1:16667".parse().expect("metrics");
        let cfg = hub_config(listen, metrics, &certs);
        let toml_text = toml::to_string_pretty(&cfg).expect("hub toml");
        let dir = std::env::temp_dir().join(format!("interflow-soak-cfg-{}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("dir");
        let path = dir.join("hub.toml");
        std::fs::write(&path, &toml_text).expect("write");
        let loaded = interflow_mesh::config::load_hub_config(&path).expect("hub round-trip");
        assert_eq!(loaded.server.listen_addr, listen);
        assert_eq!(loaded.metrics.listen_addr, metrics);
        assert!(loaded.metrics.enabled);
        assert!(loaded.tls.as_ref().is_some_and(|t| t.enabled));
        assert!(loaded.transport.quic.enabled);
        assert!(loaded.heartbeat.enabled);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn agent_configs_toml_round_trip() {
        let certs = TestCerts::generate("soak-proc-test", "soak-egress");
        let endpoint: SocketAddr = "127.0.0.1:16666".parse().expect("endpoint");
        let listen: SocketAddr = "127.0.0.1:17777".parse().expect("listen");
        let backend: SocketAddr = "127.0.0.1:18888".parse().expect("backend");

        for transport in [TransportKind::H2, TransportKind::Quic] {
            let dir = std::env::temp_dir().join(format!(
                "interflow-soak-agent-{:?}-{}",
                transport,
                std::process::id()
            ));
            std::fs::create_dir_all(&dir).expect("dir");

            let egress = egress_agent_config(endpoint, transport, &certs, backend);
            let p1 = dir.join("egress.toml");
            write_toml(&p1, &egress).expect("write egress");
            let l1 = interflow_mesh::config::load_agent_config(&p1).expect("egress round-trip");
            assert_eq!(l1.agent.id, "egress");
            assert_eq!(l1.agent.transport, transport);
            assert_eq!(l1.agent.connect_timeout_secs, 10);

            let ingress = ingress_agent_config(endpoint, transport, &certs, listen, backend, 300);
            let p2 = dir.join("ingress.toml");
            write_toml(&p2, &ingress).expect("write ingress");
            let l2 = interflow_mesh::config::load_agent_config(&p2).expect("ingress round-trip");
            assert_eq!(l2.ingress.len(), 1);
            assert_eq!(l2.ingress[0].idle_timeout_secs, Some(300));
            let _ = std::fs::remove_dir_all(&dir);
        }
    }
}
