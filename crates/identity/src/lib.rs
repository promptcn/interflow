//! Identity-first model objects.
//!
//! One crate, four layers:
//! - [`manifest`]: the desired-state manifest (the single
//!   source of truth for Realm / Workspace / Ingress / Agent / Service /
//!   Route).
//! - [`issuance`]: the offline realm issuer — realm issuer CA, workspace
//!   issuers, control-endpoint / ingress / agent identities with SPIFFE-like
//!   URI SAN principal paths.
//! - [`pack`] / [`trust`] / [`policy`]: Credential Packs (directory runtime
//!   format + age-sealed `.iflowpack` distribution format), versioned Trust
//!   Bundles, and signed anti-rollback runtime policy, all tied to one
//!   rotation generation per pack.
//!
//! Design contract: certificates are implementation material. Nothing in the
//! public API here speaks in CNs or file paths; everything speaks in Realm /
//! Workspace / Node / Principal / Service / Route.

pub mod credentials;
pub mod expiry;
pub mod issuance;
pub mod manifest;
pub mod pack;
pub mod policy;
pub mod revocation;
pub mod timestamp;
pub mod trust;

pub use manifest::{Manifest, RouteConfig, ServiceConfig};
pub use pack::load::PackSummary;
pub use pack::render::{AgentCredentialPack, HubCredentialPack, IngressCredentialPack};
pub use pack::{CredentialPack, IdentityEntry, PackKind, PackMetadata};
pub use trust::{TrustBundle, TrustBundleMetadata};

use std::fmt;

/// Identity-model errors, phrased in product semantics (never X.509
/// jargon). `doctor` maps these one-to-one to diagnosis/fix pairs.
///
/// Mirrors [`interflow_core::error::InterflowError`]: semantic variants
/// carry a human-readable `message` plus an optional `#[source]` root
/// cause. Build them with the same-named lowercase constructors
/// ([`Error::manifest`] etc.); when wrapping an underlying error use
/// `.with_source(e)` so the root-cause chain survives — never flatten
/// `{e}` into the message.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum Error {
    #[error("invalid {kind} name {name:?}: must be [a-z0-9][a-z0-9_-]{{0,62}} (lowercase)")]
    InvalidName { kind: &'static str, name: String },

    #[error("manifest: {message}")]
    Manifest {
        /// Human-readable description.
        message: String,
        /// Root cause, if any.
        #[source]
        source: Option<BoxError>,
    },

    #[error("credential pack: {message}")]
    Pack {
        /// Human-readable description.
        message: String,
        /// Root cause, if any.
        #[source]
        source: Option<BoxError>,
    },

    #[error("trust bundle: {message}")]
    Trust {
        /// Human-readable description.
        message: String,
        /// Root cause, if any.
        #[source]
        source: Option<BoxError>,
    },

    #[error("runtime policy: {message}")]
    Policy {
        /// Human-readable description.
        message: String,
        /// Root cause, if any.
        #[source]
        source: Option<BoxError>,
    },

    #[error("issuance: {message}")]
    Issuance {
        /// Human-readable description.
        message: String,
        /// Root cause, if any.
        #[source]
        source: Option<BoxError>,
    },

    #[error("io error at {path}")]
    Io {
        path: String,
        #[source]
        source: std::io::Error,
    },

    #[error("serialization error: {message}")]
    Serialize {
        /// Human-readable description.
        message: String,
        /// Root cause, if any.
        #[source]
        source: Option<BoxError>,
    },
}

/// Carrier for the root-cause chain of semantic identity errors.
pub type BoxError = Box<dyn std::error::Error + Send + Sync>;

impl Error {
    /// Builds a manifest error.
    pub fn manifest(message: impl Into<String>) -> Self {
        Self::Manifest {
            message: message.into(),
            source: None,
        }
    }

    /// Builds a credential-pack error.
    pub fn pack(message: impl Into<String>) -> Self {
        Self::Pack {
            message: message.into(),
            source: None,
        }
    }

    /// Builds a trust-bundle error.
    pub fn trust(message: impl Into<String>) -> Self {
        Self::Trust {
            message: message.into(),
            source: None,
        }
    }

    /// Builds a runtime-policy error.
    pub fn policy(message: impl Into<String>) -> Self {
        Self::Policy {
            message: message.into(),
            source: None,
        }
    }

    /// Builds an issuance error.
    pub fn issuance(message: impl Into<String>) -> Self {
        Self::Issuance {
            message: message.into(),
            source: None,
        }
    }

    /// Builds a serialization error.
    pub fn serialize(message: impl Into<String>) -> Self {
        Self::Serialize {
            message: message.into(),
            source: None,
        }
    }

    /// Attaches a root cause: preserves the `source()` chain so logs can
    /// expand the full causality. Only semantic variants accept a root
    /// cause; `Io` already carries one.
    #[must_use]
    pub fn with_source(self, source: impl Into<BoxError>) -> Self {
        let source = Some(source.into());
        match self {
            Self::Manifest { message, .. } => Self::Manifest { message, source },
            Self::Pack { message, .. } => Self::Pack { message, source },
            Self::Trust { message, .. } => Self::Trust { message, source },
            Self::Policy { message, .. } => Self::Policy { message, source },
            Self::Issuance { message, .. } => Self::Issuance { message, source },
            Self::Serialize { message, .. } => Self::Serialize { message, source },
            other => other,
        }
    }
}

pub type Result<T> = std::result::Result<T, Error>;

/// Validates an identifier (realm, workspace, node, service) against the
/// product naming rule: lowercase `[a-z0-9][a-z0-9_-]{0,62}`. The leading
/// `_` is reserved for internal principals and never valid in manifests.
pub fn validate_name(kind: &'static str, name: &str) -> Result<()> {
    let valid = name.len() <= 63
        && !name.is_empty()
        && name.as_bytes()[0].is_ascii_lowercase()
        && name
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_' || b == b'-');
    if valid {
        Ok(())
    } else {
        Err(Error::InvalidName {
            kind,
            name: name.to_owned(),
        })
    }
}

/// The role a principal plays in the realm.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum PrincipalKind {
    /// The control endpoint (relay) server identity, issued by the realm
    /// issuer and shared by no workspace.
    Control,
    /// A realm-scoped site-to-site hub client identity. The hub's server
    /// credential is a [`PrincipalKind::Control`] identity; this kind is the
    /// accompanying client credential that authorizes the hub's unattended
    /// renewal traffic toward the registrar (the same role ingress
    /// principals play for ingress nodes).
    Hub,
    /// A workspace-scoped public-entry principal. One credential per
    /// (ingress node, workspace).
    Ingress,
    /// A workspace member connector identity.
    Agent,
}

impl PrincipalKind {
    /// The path segment used in principal URIs.
    pub const fn segment(self) -> &'static str {
        match self {
            Self::Control => "control",
            Self::Hub => "hub",
            Self::Ingress => "ingress",
            Self::Agent => "agent",
        }
    }

    /// Parses the principal-kind segment of a principal path.
    pub fn from_segment(segment: &str) -> Option<Self> {
        match segment {
            "control" => Some(Self::Control),
            "hub" => Some(Self::Hub),
            "ingress" => Some(Self::Ingress),
            "agent" => Some(Self::Agent),
            _ => None,
        }
    }

    /// Whether principals of this kind are realm-scoped (carry no workspace).
    pub const fn is_realm_scoped(&self) -> bool {
        matches!(self, Self::Control | Self::Hub)
    }
}

impl fmt::Display for PrincipalKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.segment())
    }
}

/// A SPIFFE-like verifiable principal path:
///
/// - control endpoint: `spiffe://<realm>/control/<node>`
/// - site-to-site hub client: `spiffe://<realm>/hub/<node>`
/// - workspace member: `spiffe://<realm>/<workspace>/(ingress|agent)/<node>`
///
/// Workspace membership lives in the identity itself, so authorization
/// policy never infers it from file layout or CA naming.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct PrincipalPath {
    pub realm: String,
    /// `None` only for realm-scoped kinds ([`PrincipalKind::Control`],
    /// [`PrincipalKind::Hub`]) — they serve every workspace and belong to
    /// none.
    pub workspace: Option<String>,
    pub kind: PrincipalKind,
    pub node: String,
}

impl PrincipalPath {
    /// Builds a workspace member principal (`ingress` or `agent`).
    pub fn workspace_member(
        realm: &str,
        workspace: &str,
        kind: PrincipalKind,
        node: &str,
    ) -> Result<Self> {
        if kind.is_realm_scoped() {
            return Err(Error::issuance(format!(
                "{} principals are realm-scoped, not workspace-scoped",
                kind
            )));
        }
        validate_name("realm", realm)?;
        validate_name("workspace", workspace)?;
        validate_name("node", node)?;
        Ok(Self {
            realm: realm.to_owned(),
            workspace: Some(workspace.to_owned()),
            kind,
            node: node.to_owned(),
        })
    }

    /// Builds the realm-scoped control endpoint principal.
    pub fn control(realm: &str, node: &str) -> Result<Self> {
        Self::realm_scoped(realm, PrincipalKind::Control, node)
    }

    /// Builds the realm-scoped site-to-site hub client principal.
    pub fn hub(realm: &str, node: &str) -> Result<Self> {
        Self::realm_scoped(realm, PrincipalKind::Hub, node)
    }

    fn realm_scoped(realm: &str, kind: PrincipalKind, node: &str) -> Result<Self> {
        validate_name("realm", realm)?;
        validate_name("node", node)?;
        Ok(Self {
            realm: realm.to_owned(),
            workspace: None,
            kind,
            node: node.to_owned(),
        })
    }

    /// Parses a `spiffe://realm/...` URI into a principal path.
    pub fn parse_uri(uri: &str) -> Result<Self> {
        let rest = uri.strip_prefix("spiffe://").ok_or_else(|| {
            Error::issuance(format!("principal {uri:?}: expected a spiffe:// URI"))
        })?;
        let mut parts = rest.split('/');
        let realm = parts.next().unwrap_or_default().to_owned();
        if realm.is_empty() {
            return Err(Error::issuance(format!("principal {uri:?}: missing realm")));
        }
        let first = parts.next().unwrap_or_default();
        let (workspace, kind, node) = if let Some(kind) =
            PrincipalKind::from_segment(first).filter(PrincipalKind::is_realm_scoped)
        {
            (None, kind, parts.next().unwrap_or_default().to_owned())
        } else {
            let kind_seg = parts.next().unwrap_or_default();
            let kind = PrincipalKind::from_segment(kind_seg).ok_or_else(|| {
                Error::issuance(format!(
                    "principal {uri:?}: unknown principal kind {kind_seg:?}"
                ))
            })?;
            if kind.is_realm_scoped() {
                return Err(Error::issuance(format!(
                    "principal {uri:?}: {} principals are realm-scoped \
                     (spiffe://<realm>/{}/<node>)",
                    kind,
                    kind.segment()
                )));
            }
            (
                Some(first.to_owned()),
                kind,
                parts.next().unwrap_or_default().to_owned(),
            )
        };
        if parts.next().is_some() || node.is_empty() {
            return Err(Error::issuance(format!(
                "principal {uri:?}: expected exactly realm/[workspace/kind/]node segments"
            )));
        }
        validate_name("realm", &realm)?;
        if let Some(workspace) = &workspace {
            validate_name("workspace", workspace)?;
        }
        validate_name("node", &node)?;
        Ok(Self {
            realm,
            workspace,
            kind,
            node,
        })
    }

    /// The product-facing path form (`promptcn/main/agent/desktop`) — used
    /// in policies, doctor output, and routes.
    pub fn path(&self) -> String {
        match &self.workspace {
            Some(workspace) => format!("{}/{}/{}", self.realm, workspace, self.kind.segment()),
            None => format!("{}/{}", self.realm, self.kind.segment()),
        }
    }
}

impl fmt::Display for PrincipalPath {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.workspace {
            Some(workspace) => write!(
                f,
                "spiffe://{}/{}/{}/{}",
                self.realm,
                workspace,
                self.kind.segment(),
                self.node
            ),
            None => write!(
                f,
                "spiffe://{}/{}/{}",
                self.realm,
                self.kind.segment(),
                self.node
            ),
        }
    }
}

/// Extracts the first URI SAN from a DER certificate (the product identity).
pub fn uri_san_from_cert_der(der: &[u8]) -> Result<Option<String>> {
    match x509_parser::parse_x509_certificate(der) {
        Ok((_, cert)) => Ok(cert
            .subject_alternative_name()
            .ok()
            .flatten()
            .and_then(|san| {
                san.value.general_names.iter().find_map(|gn| match gn {
                    x509_parser::extensions::GeneralName::URI(uri) => Some(uri.to_string()),
                    _ => None,
                })
            })),
        Err(e) => Err(Error::issuance("failed to parse certificate".to_string()).with_source(e)),
    }
}

/// Reads all PEM certificates from bytes (leaf-first order preserved).
pub fn pem_certs(pem: &[u8]) -> Result<Vec<Vec<u8>>> {
    let mut certs = Vec::new();
    for cert in rustls_pemfile::certs(&mut std::io::BufReader::new(pem)) {
        let cert =
            cert.map_err(|e| Error::pack("certificate parse error".to_string()).with_source(e))?;
        certs.push(cert.as_ref().to_vec());
    }
    Ok(certs)
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn principal_uris_round_trip() {
        let control = PrincipalPath::control("promptcn", "edge").unwrap();
        assert_eq!(control.to_string(), "spiffe://promptcn/control/edge");
        assert_eq!(
            PrincipalPath::parse_uri(&control.to_string()).unwrap(),
            control
        );

        let hub = PrincipalPath::hub("promptcn", "central").unwrap();
        assert_eq!(hub.to_string(), "spiffe://promptcn/hub/central");
        assert_eq!(PrincipalPath::parse_uri(&hub.to_string()).unwrap(), hub);
        assert_eq!(hub.path(), "promptcn/hub");
        assert!(
            PrincipalPath::workspace_member("promptcn", "main", PrincipalKind::Hub, "central")
                .is_err(),
            "hub principals are realm-scoped"
        );

        let agent =
            PrincipalPath::workspace_member("promptcn", "main", PrincipalKind::Agent, "desktop")
                .unwrap();
        assert_eq!(agent.to_string(), "spiffe://promptcn/main/agent/desktop");
        assert_eq!(agent.path(), "promptcn/main/agent");
        assert_eq!(PrincipalPath::parse_uri(&agent.to_string()).unwrap(), agent);
    }

    #[test]
    fn malformed_principal_uris_rejected() {
        assert!(PrincipalPath::parse_uri("https://promptcn/main/agent/x").is_err());
        assert!(PrincipalPath::parse_uri("spiffe://promptcn/main/router/x").is_err());
        assert!(PrincipalPath::parse_uri("spiffe://promptcn/main/control/x").is_err());
        assert!(PrincipalPath::parse_uri("spiffe://promptcn/main/hub/x").is_err());
        assert!(PrincipalPath::parse_uri("spiffe://promptcn/control/x/extra").is_err());
        assert!(PrincipalPath::parse_uri("spiffe://promptcn/hub/x/extra").is_err());
    }

    #[test]
    fn names_are_lowercased_identifiers() {
        assert!(validate_name("realm", "promptcn").is_ok());
        assert!(validate_name("workspace", "main").is_ok());
        assert!(validate_name("node", "desktop-1").is_ok());
        assert!(validate_name("node", "Desktop").is_err());
        assert!(validate_name("node", "_edge").is_err());
        assert!(validate_name("node", "").is_err());
    }
}
