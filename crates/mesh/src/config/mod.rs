//! Engine configuration model.
//!
//! The structs here are the engine's shared model, constructed
//! programmatically: the mesh pack bootstrap (`pack::build_hub_config` /
//! `pack::build_agent_config`) and the embedded expose edge build them from
//! Credential Pack material. There is no file schema — the product's only
//! configuration entry is the Credential Pack.

pub mod agent;
pub mod hub;
pub mod transport;
pub mod validate;

pub use agent::{
    AgentConfig, AgentInfo, ControlConfig, EgressRule, EgressTarget, IngressRule, InnerTlsConfig,
    SecurityConfig, TlsConfig as AgentTlsConfig, TransportKind,
};
pub use hub::{
    AclConfig, AclRule, AuthConfig, HeartbeatConfig, HubConfig, HubQuicConfig, HubSecurityConfig,
    HubTransportConfig, MetricsConfig, PolicyAdminConfig, ServerConfig, TenantConfig,
    TlsConfig as HubTlsConfig,
};
pub use interflow_core::config::LoggingConfig;
pub use interflow_core::telemetry::LogFormat;
pub use transport::{AgentQuicConfig, H2TransportConfig};
pub use validate::{ConfigError, ConfigErrorList, validate_hub};
