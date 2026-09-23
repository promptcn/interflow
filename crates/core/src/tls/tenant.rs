//! Tenant-scoped mTLS trust roots and post-handshake tenant derivation.
//!
//! Design: the handshake
//! enforces client-certificate validity against the **merged** root store of
//! all tenants (a standard rustls `WebPkiClientVerifier` — no custom verifier
//! trait, no side tables); tenant *ownership* is derived **after** the
//! handshake by re-running `verify_client_cert` against each tenant's own
//! verifier. The first tenant whose verifier accepts the chain is the
//! connection's tenant. Because derivation walks the chain-signature path,
//! appending another tenant's root certificate into the presented chain has
//! no effect — only the root that actually anchors the chain's signatures
//! claims the identity.

use crate::error::{InterflowError, Result};
use sha2::{Digest, Sha256};
use std::sync::Arc;
use tokio_rustls::TlsAcceptor;
use tokio_rustls::rustls::RootCertStore;
use tokio_rustls::rustls::pki_types::CertificateRevocationListDer;
use tokio_rustls::rustls::pki_types::{CertificateDer, UnixTime};
use tokio_rustls::rustls::server::WebPkiClientVerifier;
use tokio_rustls::rustls::server::danger::ClientCertVerifier;

/// One tenant's trust anchor: a named CA certificate set (a PEM file may
/// carry several certificates; they all belong to the same tenant).
#[derive(Debug, Clone)]
pub struct TenantTrustRoot {
    /// Tenant name (config-restricted to `[A-Za-z0-9_-]`, no leading `_`
    /// for operator-defined tenants; the `_` prefix is reserved for
    /// internal principals such as the expose edge gateway).
    pub name: Arc<str>,
    /// Gateway tenants may open streams to any tenant (the expose edge's
    /// ephemeral principal is the only legitimate user of this flag).
    pub trusted_gateway: bool,
    /// The tenant's root store (its CA public certificates).
    pub store: RootCertStore,
    /// The same certificates as `store`, kept raw for merge operations.
    certs: Vec<CertificateDer<'static>>,
    /// CRLs applied to this tenant's verifier.
    crls: Vec<CertificateRevocationListDer<'static>>,
    /// Content fingerprint of `store` (sorted per-cert SHA-256, re-hashed) —
    /// the duplicate-tenant-CA detection key.
    fingerprint: [u8; 32],
}

impl TenantTrustRoot {
    /// Builds a trust root from PEM bytes (the same multi-certificate
    /// semantics as `load_ca_roots`).
    pub fn from_pem(name: &str, trusted_gateway: bool, pem: &[u8]) -> Result<Self> {
        Self::from_pem_with_crls(name, trusted_gateway, pem, &[])
    }

    /// Builds a trust root and attaches CRLs to its verifier.
    pub fn from_pem_with_crls(
        name: &str,
        trusted_gateway: bool,
        pem: &[u8],
        crls: &[CertificateRevocationListDer<'static>],
    ) -> Result<Self> {
        let mut reader = std::io::BufReader::new(pem);
        let mut store = RootCertStore::empty();
        let mut certs = Vec::new();
        let mut cert_hashes: Vec<[u8; 32]> = Vec::new();
        for cert in rustls_pemfile::certs(&mut reader) {
            let cert: CertificateDer<'static> = cert.map_err(|e| {
                InterflowError::config("tenant CA parse error".to_string()).with_source(e)
            })?;
            let hash: [u8; 32] = Sha256::digest(cert.as_ref()).into();
            cert_hashes.push(hash);
            store.add(cert.clone()).map_err(|e| {
                InterflowError::config("tenant CA add error".to_string()).with_source(e)
            })?;
            certs.push(cert);
        }
        if certs.is_empty() {
            return Err(InterflowError::config(format!(
                "tenant '{name}': no certificates found in CA PEM"
            )));
        }
        cert_hashes.sort_unstable();
        let mut hasher = Sha256::new();
        for h in &cert_hashes {
            hasher.update(h);
        }
        Ok(Self {
            name: name.into(),
            trusted_gateway,
            store,
            certs,
            crls: crls.to_vec(),
            fingerprint: hasher.finalize().into(),
        })
    }

    /// Content fingerprint — equal iff both roots trust the identical
    /// certificate set.
    pub const fn fingerprint(&self) -> &[u8; 32] {
        &self.fingerprint
    }
}

/// A derived connection identity: which tenant's CA anchored the chain, and
/// whether that tenant is a trusted gateway.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TenantIdentity {
    /// Owning tenant name.
    pub tenant: Arc<str>,
    /// Whether the owning tenant may open streams across tenant boundaries.
    pub trusted_gateway: bool,
}

/// The per-tenant verifier set used for post-handshake tenant derivation.
#[derive(Debug)]
pub struct TenantVerifier {
    /// The trust roots (kept for `merged_roots` and name/gateway lookups).
    roots: Vec<TenantTrustRoot>,
    /// One built verifier per root, index-aligned with `roots`.
    verifiers: Vec<Arc<dyn ClientCertVerifier>>,
}

impl TenantVerifier {
    /// Builds the verifier set. Rejects two tenants trusting the identical
    /// certificate set — that configuration would make tenant ownership
    /// ambiguous (derivation would pick one silently).
    pub fn new(roots: &[TenantTrustRoot]) -> Result<Self> {
        if roots.is_empty() {
            return Err(InterflowError::config(
                "at least one [[tenants]] entry is required (an empty trust table can authenticate nobody)",
            ));
        }
        for (i, root) in roots.iter().enumerate() {
            for other in &roots[i + 1..] {
                if root.fingerprint == other.fingerprint {
                    return Err(InterflowError::config(format!(
                        "tenants '{}' and '{}' trust the identical CA certificate set; \
                         tenant ownership would be ambiguous",
                        root.name, other.name
                    )));
                }
            }
        }
        let mut verifiers = Vec::with_capacity(roots.len());
        for root in roots {
            let mut builder = WebPkiClientVerifier::builder(Arc::new(root.store.clone()));
            if !root.crls.is_empty() {
                builder = builder.with_crls(root.crls.clone());
            }
            let verifier = builder.build().map_err(|e| {
                InterflowError::config(format!(
                    "tenant '{}' client verifier build failed",
                    root.name
                ))
                .with_source(e)
            })?;
            verifiers.push(verifier);
        }
        Ok(Self {
            roots: roots.to_vec(),
            verifiers,
        })
    }

    /// The merged root store backing the handshake acceptor (all tenants).
    pub fn merged_roots(&self) -> RootCertStore {
        let mut merged = RootCertStore::empty();
        for root in &self.roots {
            for cert in &root.certs {
                let _ = merged.add(cert.clone());
            }
        }
        merged
    }

    /// Whether `name` is a trusted-gateway tenant (may open streams across
    /// tenant boundaries). Consulted by the routing layer's tenant policy.
    pub fn is_gateway_tenant(&self, name: &str) -> bool {
        self.roots
            .iter()
            .any(|r| r.trusted_gateway && &*r.name == name)
    }

    /// Derives the tenant identity of a presented client chain. `None` =
    /// no tenant claims the chain (fail-closed: the caller must reject
    /// registration). Only reachable in the hot-reload window where the
    /// handshake acceptor and the derivation set briefly disagree.
    pub fn derive(&self, chain: &[CertificateDer<'_>]) -> Option<TenantIdentity> {
        let (leaf, intermediates) = chain.split_first()?;
        let now = UnixTime::now();
        for (root, verifier) in self.roots.iter().zip(&self.verifiers) {
            if verifier
                .verify_client_cert(leaf, intermediates, now)
                .is_ok()
            {
                return Some(TenantIdentity {
                    tenant: root.name.clone(),
                    trusted_gateway: root.trusted_gateway,
                });
            }
        }
        None
    }
}

/// The complete server TLS plane, swapped atomically on reload.
///
/// The handshake acceptor (client certs required, merged roots) and the
/// tenant derivation set always belong to the same configuration generation.
pub struct TlsPlane {
    /// h2 TLS acceptor enforcing client-certificate validity.
    pub acceptor: TlsAcceptor,
    /// Tenant derivation for connections that passed the acceptor.
    pub verifier: Arc<TenantVerifier>,
    /// The acceptor's configuration, for hosts that dispatch connections
    /// into this plane from another listener (e.g. the ingress's public 443
    /// SNI-multiplexing the control endpoint).
    pub config: std::sync::Arc<tokio_rustls::rustls::ServerConfig>,
}

/// Builds the complete TLS plane from a tenant trust table: the acceptor
/// enforces client-certificate validity against the merged roots, the
/// verifier derives per-tenant ownership after the handshake.
pub fn build_tls_plane(
    cert_path: &str,
    key_path: &str,
    roots: &[TenantTrustRoot],
    min_version: crate::tls::TlsMinVersion,
) -> Result<TlsPlane> {
    let verifier = Arc::new(TenantVerifier::new(roots)?);
    let config = std::sync::Arc::new(super::server::build_mtls_server_config_with_roots(
        cert_path,
        key_path,
        &verifier.merged_roots(),
        min_version,
    )?);
    Ok(TlsPlane {
        acceptor: TlsAcceptor::from(config.clone()),
        verifier,
        config,
    })
}
