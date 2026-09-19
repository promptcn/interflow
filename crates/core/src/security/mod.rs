//! Security primitives: audit logging, rate limiting, connection limits,
//! and the trusted-proxy client-IP restoration (PROXY protocol /
//! X-Forwarded-For).

pub mod audit;
pub mod conn_limit;
pub mod forwarded_for;
pub mod proxy_protocol;
pub mod rate_limit;

pub use audit::{AuditEvent, AuditKind, AuditSink};
pub use conn_limit::{ConnGuard, ConnTracker};
pub use forwarded_for::{XffError, XffMode, XffPolicy, XffResolution};
pub use proxy_protocol::{
    PrefixedStream, ProxyError, ProxyOutcome, ProxyProtocolConfig, ProxyProtocolMode,
    ProxyProtocolPolicy,
};
pub use rate_limit::{AuthRateLimiter, ByteRateLimiter, EventRateLimiter, UdpIngressLimiter};
