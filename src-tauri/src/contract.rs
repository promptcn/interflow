//! GUI boundary contract: the single source of truth for the IPC schema.
//!
//! These DTOs mirror the domain types (expose `Profile`, mesh
//! `TransportKind` / `AgentState`) so the protocol crates stay free of GUI
//! concerns; the mappings are compiler-checked via `From` impls. TS types and
//! typed invoke/event wrappers are generated from this module into
//! `src/bindings.ts` (tauri-specta) — the frontend must never hand-write a
//! copy again. The 2026-09-18 incident (GUI still sending `auth_token` after
//! the mTLS-only migration, Start/Save both failing serde) was exactly this
//! class of drift.

use interflow_expose::profile::Profile as ExposeProfile;
use interflow_mesh::agent::AgentState;
use interflow_mesh::config::TransportKind;
use serde::{Deserialize, Serialize};

/// Transport toward the hub (wire form mirrors mesh `TransportKind`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize, specta::Type)]
#[serde(rename_all = "lowercase")]
pub enum Transport {
    #[default]
    H2,
    Quic,
}

impl From<TransportKind> for Transport {
    fn from(kind: TransportKind) -> Self {
        match kind {
            TransportKind::H2 => Self::H2,
            TransportKind::Quic => Self::Quic,
        }
    }
}

impl From<Transport> for TransportKind {
    fn from(transport: Transport) -> Self {
        match transport {
            Transport::H2 => Self::H2,
            Transport::Quic => Self::Quic,
        }
    }
}

/// Persisted expose profile (mirrors expose `profile::Profile`).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize, specta::Type)]
#[serde(deny_unknown_fields, default)]
pub struct Profile {
    /// Hub URL (e.g. `https://hub.example.com:6666`).
    pub hub_url: Option<String>,
    /// Client certificate PEM path (mTLS identity; CN must equal agent_id).
    pub client_cert: Option<String>,
    /// Client key PEM path (0600).
    pub client_key: Option<String>,
    /// agent_id used by this machine's expose (edge routes.toml must
    /// reference the same id).
    pub agent_id: Option<String>,
    /// Path to the trusted hub CA certificate PEM (required when the hub uses
    /// a self-signed cert).
    pub ca_path: Option<String>,
    /// Local ports used last time (for GUI form prefill).
    pub local_ports: Option<Vec<u16>>,
    /// Transport toward the hub: `h2` (default) or `quic`.
    pub transport: Option<Transport>,
    /// Hub QUIC address (`host:port`); `None` derives it at runtime from
    /// `hub_url`'s host:port.
    pub hub_quic_addr: Option<String>,
}

impl From<ExposeProfile> for Profile {
    fn from(p: ExposeProfile) -> Self {
        Self {
            hub_url: p.hub_url,
            client_cert: p.client_cert,
            client_key: p.client_key,
            agent_id: p.agent_id,
            ca_path: p.ca_path,
            local_ports: p.local_ports,
            transport: p.transport.map(Transport::from),
            hub_quic_addr: p.hub_quic_addr,
        }
    }
}

impl From<Profile> for ExposeProfile {
    fn from(p: Profile) -> Self {
        Self {
            hub_url: p.hub_url,
            client_cert: p.client_cert,
            client_key: p.client_key,
            agent_id: p.agent_id,
            ca_path: p.ca_path,
            local_ports: p.local_ports,
            transport: p.transport.map(TransportKind::from),
            hub_quic_addr: p.hub_quic_addr,
        }
    }
}

/// Parameters for starting the tunnel (frontend form → Rust).
#[derive(Debug, Clone, Deserialize, specta::Type)]
#[serde(deny_unknown_fields)]
pub struct TunnelConfig {
    pub local_ports: Vec<u16>,
    pub hub_url: String,
    pub client_cert: String,
    pub client_key: String,
    pub agent_id: String,
    pub ca_path: Option<String>,
    /// Transport toward the hub; absent = h2 (the default).
    pub transport: Option<Transport>,
    /// Hub QUIC address; absent = derived from the hub URL's host:port.
    pub hub_quic_addr: Option<String>,
}

impl From<TunnelConfig> for interflow_expose::client::ExposeArgs {
    fn from(config: TunnelConfig) -> Self {
        Self {
            local_ports: config.local_ports,
            hub_url: config.hub_url,
            client_cert: Some(config.client_cert),
            client_key: Some(config.client_key),
            agent_id: config.agent_id,
            ca_path: config.ca_path.filter(|s| !s.is_empty()),
            transport: config
                .transport
                .map_or_else(TransportKind::default, TransportKind::from),
            hub_quic_addr: config.hub_quic_addr.filter(|s| !s.is_empty()),
        }
    }
}

/// Tunnel lifecycle state (wire form mirrors mesh `AgentState`, externally
/// tagged: `"Connecting" | { "Connected": … } | …`). `backoff_secs` narrows
/// u64 → u32: specta forbids BigInt-style exports, and a reconnect backoff
/// beyond u32::MAX seconds is meaningless.
#[derive(Debug, Clone, Serialize, Deserialize, specta::Type)]
pub enum TunnelState {
    Connecting,
    Connected { agent_id: String },
    Reconnecting { reason: String, backoff_secs: u32 },
    Stopped,
    Failed { error: String },
}

impl From<AgentState> for TunnelState {
    fn from(state: AgentState) -> Self {
        match state {
            AgentState::Connecting => Self::Connecting,
            AgentState::Connected { agent_id } => Self::Connected { agent_id },
            AgentState::Reconnecting {
                reason,
                backoff_secs,
            } => Self::Reconnecting {
                reason,
                backoff_secs: u32::try_from(backoff_secs).unwrap_or(u32::MAX),
            },
            AgentState::Stopped => Self::Stopped,
            AgentState::Failed { error } => Self::Failed { error },
        }
    }
}

/// `tunnel-state` event payload (emitted from the TunnelManager state sink).
#[derive(Debug, Clone, Serialize, Deserialize, specta::Type, tauri_specta::Event)]
#[tauri_specta(event_name = "tunnel-state")]
pub struct TunnelStateEvent(pub TunnelState);

/// `log` event payload (tracing capture pump → frontend log panel).
#[derive(Debug, Clone, Serialize, Deserialize, specta::Type, tauri_specta::Event)]
#[tauri_specta(event_name = "log")]
pub struct LogEvent(pub crate::tracing_capture::LogLine);

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    /// The DTO's serde form must stay identical to the domain enum's — the
    /// TS contract and the runtime JSON are both derived from it.
    #[test]
    fn transport_wire_form_matches_mesh() {
        assert_eq!(serde_json::to_string(&Transport::H2).unwrap(), r#""h2""#);
        assert_eq!(
            serde_json::to_string(&Transport::Quic).unwrap(),
            r#""quic""#
        );
        assert_eq!(
            serde_json::to_string(&TransportKind::H2).unwrap(),
            serde_json::to_string(&Transport::H2).unwrap()
        );
    }

    #[test]
    fn tunnel_state_wire_form_matches_agent_state() {
        let agent = AgentState::Connected {
            agent_id: "expose-mac".into(),
        };
        assert_eq!(
            serde_json::to_string(&TunnelState::from(agent.clone())).unwrap(),
            serde_json::to_string(&agent).unwrap()
        );
    }

    /// Profile round-trips through the expose type without losing fields.
    #[test]
    fn profile_dto_round_trips() {
        let dto = Profile {
            hub_url: Some("https://hub.example.com:6666".into()),
            client_cert: Some("agents/x.crt".into()),
            client_key: Some("agents/x.key".into()),
            agent_id: Some("x".into()),
            ca_path: Some("tenants/main-ca.crt".into()),
            local_ports: Some(vec![3000, 5174]),
            transport: Some(Transport::Quic),
            hub_quic_addr: None,
        };
        let expose: ExposeProfile = dto.clone().into();
        assert_eq!(Profile::from(expose), dto);
    }
}
