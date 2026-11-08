//! Security primitives: audit logging, rate limiting, connection limits,
//! and the trusted-proxy client-IP restoration (PROXY protocol /
//! X-Forwarded-For).
//!
//! Every per-client budget in this layer keys on
//! [`client_key::ClientKey`] — one definition of "one client".

pub mod audit;
pub mod client_key;
pub mod conn_limit;
pub mod forwarded_for;
pub mod http_head;
pub mod proxy_protocol;
pub mod rate_limit;

pub use audit::{
    AuditEvent, AuditKind, AuditSink, AuditVerifyError, AuditVerifyReport, discover_audit_files,
    verify_audit_files,
};
pub use client_key::ClientKey;
pub use conn_limit::{ConnGuard, ConnTracker};
pub use forwarded_for::{XffError, XffMode, XffPolicy, XffResolution};
pub use http_head::{
    HeadInvalid, HeadParse, HostError, RequestHead, find_headers_end, parse_request_head,
    validated_host,
};
pub use proxy_protocol::{
    PrefixedStream, ProxyError, ProxyOutcome, ProxyProtocolConfig, ProxyProtocolMode,
    ProxyProtocolPolicy,
};
pub use rate_limit::{
    AuthRateLimiter, ByteRateLimiter, EventRateLimiter, MAX_TRACKED_CLIENTS, RateLimitScope,
    UdpIngressLimiter,
};
