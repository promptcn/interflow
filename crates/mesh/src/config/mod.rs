//! Configuration schemas and loading.

pub mod agent;
pub mod hub;
pub mod loader;
pub mod transport;
pub mod validate;

pub use agent::{
    AGENT_CONFIG_VERSION, AgentConfig, AgentInfo, ControlConfig, EgressRule, IngressRule,
    SecurityConfig, TlsConfig as AgentTlsConfig, TransportKind,
};
pub use hub::{
    AclConfig, AclRule, AuthConfig, AuthMode, HUB_CONFIG_VERSION, HeartbeatConfig, HubConfig,
    HubQuicConfig, HubSecurityConfig, HubTransportConfig, MetricsConfig, MtlsConfig, ServerConfig,
    StaticTokenConfig, TlsConfig as HubTlsConfig,
};
pub use interflow_core::config::LoggingConfig;
pub use interflow_core::telemetry::LogFormat;
pub use loader::{load_agent_config, load_hub_config};
pub use transport::{AgentQuicConfig, H2TransportConfig};
pub use validate::{ConfigError, ConfigErrorList, validate_agent, validate_hub};
