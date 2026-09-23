//! Subprocess orchestration: lifecycle management for the soak nodes.
//!
//! The soak gate's system under test = three real processes (hub + egress agent +
//! ingress agent) run by the `interflow-soak-node` dev binary, configured through
//! the JSON engine-config handoff (the serde-serialized `HubConfig`/`AgentConfig`
//! model — a machine format between the runner and its children, not a product
//! configuration face), each logging to its own file under the run directory, and
//! shut down through the real SIGTERM → graceful drain path.

use super::error::{SoakError, SoakResult};
use crate::certs::TestCerts;
use crate::config::TEST_TENANT;
use interflow_core::protocol::StreamProto;
use interflow_core::tls::TlsMinVersion;
use interflow_mesh::config::{
    AclConfig, AgentConfig, AgentInfo, AgentTlsConfig, AuthConfig, ControlConfig, EgressRule,
    HeartbeatConfig, HubConfig, HubQuicConfig, HubSecurityConfig, HubTlsConfig, IngressRule,
    LoggingConfig, MetricsConfig, ServerConfig, TenantConfig, TransportKind,
};
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::time::Duration;
use tokio::process::{Child, Command};

/// Hub config (real TOML): TLS + QUIC dual stack, mTLS (single test tenant),
/// default heartbeat (liveness deadline 75s), metrics endpoint enabled (canary
/// assertions go through the production telemetry path).
#[allow(clippy::too_many_arguments)]
pub fn hub_config(listen: SocketAddr, metrics: SocketAddr, certs: &TestCerts) -> HubConfig {
    HubConfig {
        server: ServerConfig {
            listen_addr: listen,
            node_name: None,
            proxy_protocol: Default::default(),
        },
        auth: AuthConfig {
            rate_limit_per_minute: 0,
            tenants: vec![TenantConfig {
                name: TEST_TENANT.to_string(),
                ca_path: certs.ca_path().display().to_string(),
                crl_path: Some(certs.crl_path().display().to_string()),
                trusted_gateway: false,
            }],
        },
        tls: Some(HubTlsConfig {
            enabled: true,
            cert_path: certs.server_cert_path().display().to_string(),
            key_path: certs.server_key_path().display().to_string(),
            min_version: TlsMinVersion::V1_3,
        }),
        // Same-tenant streams are allowed by default (tenant isolation
        // policy); the soak's ingress/churn → egress pairs need no rules.
        acl: AclConfig::default(),
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
    let (client_cert, client_key) = certs.named_client_cert(id);
    AgentConfig {
        agent: AgentInfo {
            id: id.to_string(),
            hub_url: format!("https://{hub_endpoint}"),
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
            client_cert_path: Some(client_cert.display().to_string()),
            client_key_path: Some(client_key.display().to_string()),
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

/// Serialize a config to the JSON handoff file consumed by
/// `interflow-soak-node`.
pub fn write_json<T: serde::Serialize>(path: &Path, cfg: &T) -> SoakResult<()> {
    let text = serde_json::to_string(cfg)
        .map_err(|e| SoakError::msg(format!("serialize {}: {e}", path.display())))?;
    std::fs::write(path, text).map_err(|e| SoakError::msg(format!("write {}: {e}", path.display())))
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
) -> SoakResult<MeshProcess> {
    let open = || {
        std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(log_path)
    };
    let mut cmd = Command::new(bin);
    cmd.arg(subcommand).arg("--json").arg(config_path);
    for (k, v) in extra_env {
        cmd.env(k, v);
    }
    let child = cmd
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::from(open().map_err(|e| {
            SoakError::Process {
                process: name,
                message: format!("open log: {e}"),
            }
        })?))
        .stderr(std::process::Stdio::from(open().map_err(|e| {
            SoakError::Process {
                process: name,
                message: format!("open log: {e}"),
            }
        })?))
        .spawn()
        .map_err(|e| SoakError::Process {
            process: name,
            message: format!("spawn ({}){}: {e}", bin.display(), subcommand),
        })?;
    Ok(MeshProcess {
        name,
        child,
        log_path: log_path.to_path_buf(),
    })
}

impl MeshProcess {
    fn err(&self, what: &str, source: impl std::fmt::Display) -> SoakError {
        SoakError::Process {
            process: self.name,
            message: format!("{what}: {source}"),
        }
    }

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
    pub async fn kill_and_wait(&mut self) -> SoakResult<()> {
        self.child
            .start_kill()
            .map_err(|e| self.err("SIGKILL", e))?;
        self.child
            .wait()
            .await
            .map_err(|e| self.err("wait-after-kill", e))?;
        Ok(())
    }

    /// SIGTERM graceful shutdown: wait a bounded time for exit and return the exit code; on
    /// timeout, fall back to SIGKILL and report an error.
    pub async fn terminate_graceful(&mut self, timeout: Duration) -> SoakResult<Option<i32>> {
        let Some(pid) = self.child.id() else {
            // Already exited: take the final status
            let status = self.child.wait().await.map_err(|e| self.err("wait", e))?;
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
                    return Err(self.err("kill -TERM failed", &out.status.to_string()));
                }
            }
        }
        #[cfg(not(unix))]
        {
            let _ = pid;
            self.child.start_kill().map_err(|e| self.err("kill", e))?;
        }
        match tokio::time::timeout(timeout, self.child.wait()).await {
            Ok(status) => status.map(|s| s.code()).map_err(|e| self.err("wait", e)),
            Err(_) => {
                self.child
                    .start_kill()
                    .map_err(|e| self.err("SIGKILL", e))?;
                let status = self
                    .child
                    .wait()
                    .await
                    .map_err(|e| self.err("wait-after-kill", e))?;
                Err(SoakError::Process {
                    process: self.name,
                    message: format!(
                        "graceful shutdown timed out ({timeout:?}), fell back to SIGKILL \
                         (final status {status})"
                    ),
                })
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The JSON handoff must round-trip: serialize → deserialize yields the
    /// same engine config (`interflow-soak-node` deserializes exactly what
    /// these helpers serialize).
    #[test]
    fn hub_config_json_round_trips() {
        let certs = TestCerts::generate("soak-proc-test", "soak-egress");
        let listen: SocketAddr = "127.0.0.1:16666".parse().expect("listen");
        let metrics: SocketAddr = "127.0.0.1:16667".parse().expect("metrics");
        let cfg = hub_config(listen, metrics, &certs);
        let text = serde_json::to_string(&cfg).expect("hub json");
        let loaded: HubConfig = serde_json::from_str(&text).expect("hub round-trip");
        assert_eq!(loaded.server.listen_addr, listen);
        assert_eq!(loaded.metrics.listen_addr, metrics);
        assert!(loaded.metrics.enabled);
        assert!(loaded.tls.as_ref().is_some_and(|t| t.enabled));
        assert!(loaded.transport.quic.enabled);
        assert!(loaded.heartbeat.enabled);
    }

    #[test]
    fn agent_configs_json_round_trip() {
        let certs = TestCerts::generate("soak-proc-test", "soak-egress");
        let endpoint: SocketAddr = "127.0.0.1:16666".parse().expect("endpoint");
        let listen: SocketAddr = "127.0.0.1:17777".parse().expect("listen");
        let backend: SocketAddr = "127.0.0.1:18888".parse().expect("backend");

        for transport in [TransportKind::H2, TransportKind::Quic] {
            let egress = egress_agent_config(endpoint, transport, &certs, backend);
            let text = serde_json::to_string(&egress).expect("egress json");
            let l1: AgentConfig = serde_json::from_str(&text).expect("egress round-trip");
            assert_eq!(l1.agent.id, "egress");
            assert_eq!(l1.agent.transport, transport);
            assert_eq!(l1.agent.connect_timeout_secs, 10);

            let ingress = ingress_agent_config(endpoint, transport, &certs, listen, backend, 300);
            let text = serde_json::to_string(&ingress).expect("ingress json");
            let l2: AgentConfig = serde_json::from_str(&text).expect("ingress round-trip");
            assert_eq!(l2.ingress.len(), 1);
            assert_eq!(l2.ingress[0].idle_timeout_secs, Some(300));
        }
    }
}
