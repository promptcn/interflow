//! Interflow certificate issuance — the single rcgen implementation shared by
//! the identity issuer and the test kit
//! (design §2.4, (internal design notes)).
//!
//! Two layers:
//! - [`material`]: in-memory builders (tenant CA / hub server pair / agent
//!   client pair as PEM) plus reloading a persisted CA for further issuance
//! - [`ops`]: the §2.4 on-disk layout with validate-or-create semantics
//!
//! §2.4 layout:
//! - `tenants/<tenant>-ca.crt` / `.key` — the tenant CA; the key NEVER leaves
//!   the issuing (operator) machine
//! - `hub.crt` / `hub.key` — the hub server pair
//! - `agents/<agent_id>.crt` / `.key` — one pair per agent; filename ==
//!   agent_id == CN (the hub enforces CN == registered agent_id during the
//!   mTLS handshake)

pub mod material;
pub mod ops;

pub use material::{CaMaterial, LeafMaterial, LoadedCa, build_ca};
pub use ops::{
    AgentCertPaths, AgentPaths, GATEWAY_CLIENT_CN, GatewayPaths, GeneratedCerts, Outcome,
    ensure_agent_cert, ensure_gateway, ensure_hub_cert, ensure_tenant_ca, generate,
};

use std::fmt;
use std::net::IpAddr;

/// Tenant CA validity: 10 years (rotation is a conscious act — see
/// [`Error::Expired`] for what an expired CA means operationally).
pub const CA_VALIDITY_DAYS: i64 = 3650;

/// Hub/agent leaf validity: 1 day. Short lifetimes bound a stolen
/// credential even before CRL distribution reaches every verifier.
pub const LEAF_VALIDITY_DAYS: i64 = 1;

/// Errors from issuance and from validating existing on-disk state.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error(
        "invalid {kind} name {name:?}: must be [A-Za-z0-9_-], 1-64 chars, no leading underscore"
    )]
    InvalidName { kind: String, name: String },

    #[error("{context}: {source}")]
    Io {
        context: String,
        #[source]
        source: std::io::Error,
    },

    #[error("{context}: {source}")]
    Issue {
        context: String,
        #[source]
        source: rcgen::Error,
    },

    /// A file exists but its content is not parseable as the expected
    /// certificate/key material.
    #[error("{0}")]
    Parse(String),

    /// The on-disk state does not match the request (incomplete pair,
    /// cert/key mismatch, wrong tenant/CN/SAN, certificate from a foreign
    /// CA). The message carries the concrete difference and the remediation.
    #[error("{0}")]
    Mismatch(String),

    /// An existing certificate is past its validity window; re-issue with
    /// `--force` (leaves) or rotate into a fresh directory (CA).
    #[error("{0}")]
    Expired(String),
}

pub type Result<T> = std::result::Result<T, Error>;

/// One SAN entry: a DNS name or an IP address. Agents reach the hub by
/// whatever name their `hub_url` carries — that name must be covered here or
/// the TLS handshake fails with `NotValidForName`.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum SanName {
    Dns(String),
    Ip(IpAddr),
}

impl SanName {
    /// Classifies `name` as an IP SAN when it parses as one, else a DNS SAN.
    pub fn parse(name: &str) -> Result<Self> {
        let trimmed = name.trim();
        if trimmed.is_empty() || trimmed != name {
            return Err(Error::Mismatch(format!(
                "invalid hub name {name:?}: must be a non-empty DNS name or IP address"
            )));
        }
        if let Ok(ip) = name.parse::<IpAddr>() {
            Ok(Self::Ip(ip))
        } else {
            Ok(Self::Dns(name.to_ascii_lowercase()))
        }
    }
}

impl fmt::Display for SanName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Dns(name) => f.write_str(name),
            Self::Ip(ip) => write!(f, "{ip}"),
        }
    }
}

/// The SAN set for certificates that only serve local development:
/// DNS `localhost` + IP `127.0.0.1` (both dial forms work — by hostname or by
/// loopback IP).
pub fn local_dev_san() -> Vec<SanName> {
    vec![
        SanName::Dns("localhost".to_owned()),
        SanName::Ip(IpAddr::from([127, 0, 0, 1])),
    ]
}

/// An explicit validity window. `not_before` should be backdated slightly so
/// a verifier whose clock lags still accepts freshly issued certificates.
#[derive(Debug, Clone, Copy)]
pub struct Validity {
    pub not_before: time::OffsetDateTime,
    pub not_after: time::OffsetDateTime,
}

impl Validity {
    /// A window starting one hour ago and spanning `days` from now.
    pub fn from_now(days: i64) -> Self {
        let now = time::OffsetDateTime::now_utc();
        Self {
            not_before: now - time::Duration::hours(1),
            not_after: now + time::Duration::days(days),
        }
    }

    pub fn ca_default() -> Self {
        Self::from_now(CA_VALIDITY_DAYS)
    }

    pub fn leaf_default() -> Self {
        Self::from_now(LEAF_VALIDITY_DAYS)
    }
}

/// Valid tenant/agent names: `[A-Za-z0-9_-]`, 1–64 chars, no leading `_`
/// (mirrors `TenantConfig` validation in interflow-mesh; the value becomes a
/// path segment, so the charset also rules out traversal).
pub fn validate_name(kind: &str, name: &str) -> Result<()> {
    let valid = (1..=64).contains(&name.len())
        && !name.starts_with('_')
        && name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_');
    if valid {
        Ok(())
    } else {
        Err(Error::InvalidName {
            kind: kind.to_owned(),
            name: name.to_owned(),
        })
    }
}

#[cfg(test)]
#[allow(clippy::panic, clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn san_name_parse_classifies_ips_and_dns() {
        assert_eq!(
            SanName::parse("127.0.0.1").unwrap(),
            SanName::Ip("127.0.0.1".parse::<IpAddr>().unwrap())
        );
        assert_eq!(
            SanName::parse("Hub.Example.COM").unwrap(),
            SanName::Dns("hub.example.com".to_owned())
        );
        for bad in ["", "  ", " a"] {
            assert!(SanName::parse(bad).is_err(), "{bad:?} should be rejected");
        }
    }

    #[test]
    fn local_dev_san_covers_both_dial_forms() {
        let san = local_dev_san();
        assert!(san.contains(&SanName::Dns("localhost".to_owned())));
        assert!(san.contains(&SanName::Ip("127.0.0.1".parse().unwrap())));
    }

    #[test]
    fn validate_name_rejects_traversal_and_bad_charset() {
        assert!(validate_name("tenant", "main").is_ok());
        assert!(validate_name("tenant", "Tenant_1-x").is_ok());
        for bad in ["", "_x", "a/b", "..", "a b", &"x".repeat(65)] {
            assert!(
                validate_name("tenant", bad).is_err(),
                "{bad:?} should be rejected"
            );
        }
    }
}
