//! TLS certificate and private key loading, file permission validation,
//! `TlsAcceptor` assembly, and client certificate CN extraction.

use crate::error::{InterflowError, Result};
use std::fs::File;
use std::io::BufReader;
use std::sync::Arc;
use tokio_rustls::TlsAcceptor;
use tokio_rustls::rustls::RootCertStore;
use tokio_rustls::rustls::ServerConfig as TlsServerConfig;
use tokio_rustls::rustls::pki_types::{CertificateDer, PrivateKeyDer};
#[cfg(unix)]
use tracing::warn;

/// Loads a certificate chain from a PEM file.
///
/// With `strict=false`, overly broad permissions only produce a warning;
/// private keys should use [`load_key`] (enforces 0600).
pub(crate) fn load_certs(path: &str) -> Result<Vec<CertificateDer<'static>>> {
    check_secret_file_perms(path, Strictness::Lenient)?;
    let file = File::open(path).map_err(|e| {
        InterflowError::config(format!("failed to open certificate file {path}: {e}"))
    })?;
    let mut reader = BufReader::new(file);
    rustls_pemfile::certs(&mut reader)
        .collect::<std::result::Result<Vec<_>, _>>()
        .map_err(|e| InterflowError::config(format!("failed to load certificates: {e}")))
}

/// Loads a PKCS#8 private key from a PEM file. Enforces 0600 permissions.
pub(crate) fn load_key(path: &str) -> Result<PrivateKeyDer<'static>> {
    check_secret_file_perms(path, Strictness::Strict)?;
    let file = File::open(path).map_err(|e| {
        InterflowError::config(format!("failed to open private key file {path}: {e}"))
    })?;
    let mut reader = BufReader::new(file);
    let keys = rustls_pemfile::pkcs8_private_keys(&mut reader)
        .collect::<std::result::Result<Vec<_>, _>>()
        .map_err(|e| InterflowError::config(format!("failed to load private key: {e}")))?;

    let Some(key) = keys.into_iter().next() else {
        return Err(InterflowError::config(
            "no private key found in file".to_string(),
        ));
    };
    Ok(PrivateKeyDer::Pkcs8(key))
}

/// Loads PEM-encoded trust roots (CA) for client certificate validation.
pub(crate) fn load_ca_roots(path: &str) -> Result<RootCertStore> {
    check_secret_file_perms(path, Strictness::Lenient)?;
    let file = File::open(path)
        .map_err(|e| InterflowError::config(format!("failed to open CA file {path}: {e}")))?;
    let mut reader = BufReader::new(file);
    let mut roots = RootCertStore::empty();
    for cert in rustls_pemfile::certs(&mut reader) {
        let cert = cert.map_err(|e| InterflowError::config(format!("failed to parse CA: {e}")))?;
        roots
            .add(cert)
            .map_err(|e| InterflowError::config(format!("failed to add CA: {e}")))?;
    }
    if roots.is_empty() {
        return Err(InterflowError::config(format!(
            "no certificates found in CA file {path}"
        )));
    }
    Ok(roots)
}

/// Builds an ALPN=h2 `TlsAcceptor` from `cert_path` and `key_path` (no client cert validation).
///
/// `Ok(None)` means TLS is not enabled; `Err` means a configuration or file
/// problem.
pub fn build_tls_acceptor(cert_path: &str, key_path: &str) -> Result<Option<TlsAcceptor>> {
    let certs = load_certs(cert_path)?;
    let key = load_key(key_path)?;
    let mut config = TlsServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .map_err(|e| InterflowError::config(format!("TLS configuration error: {e}")))?;
    config.alpn_protocols = vec![b"h2".to_vec()];
    Ok(Some(TlsAcceptor::from(Arc::new(config))))
}

/// Builds a `TlsAcceptor` with mTLS enabled (client certificate validation).
///
/// - `cert_path` / `key_path`: the hub server certificate
/// - `client_ca_path`: the trusted client CA (agent client certificates are
///   issued by this CA)
///
/// If the client presents no certificate or an untrusted one at handshake,
/// rustls rejects it outright.
pub fn build_mtls_acceptor(
    cert_path: &str,
    key_path: &str,
    client_ca_path: &str,
) -> Result<TlsAcceptor> {
    let certs = load_certs(cert_path)?;
    let key = load_key(key_path)?;
    let client_roots = load_ca_roots(client_ca_path)?;

    let verifier =
        tokio_rustls::rustls::server::WebPkiClientVerifier::builder(Arc::new(client_roots))
            .build()
            .map_err(|e| InterflowError::config(format!("failed to build client verifier: {e}")))?;

    let mut config = TlsServerConfig::builder()
        .with_client_cert_verifier(verifier)
        .with_single_cert(certs, key)
        .map_err(|e| InterflowError::config(format!("mTLS configuration error: {e}")))?;
    config.alpn_protocols = vec![b"h2".to_vec()];
    Ok(TlsAcceptor::from(Arc::new(config)))
}

/// Extracts the CN (Common Name) from a client cert chain, used as the agent identity binding.
///
/// `None` means: no certificate / parse failure / no CN field.
/// The first certificate is the leaf (end-entity); the rest are
/// intermediate / root.
/// Builds a bare `rustls::ServerConfig` (for QUIC/quinn; the equivalent of
/// the tokio-rustls acceptor).
///
/// `client_ca` provides the mTLS client certificate validation roots;
/// `None` is one-way TLS.
pub fn build_rustls_server_config(
    cert_path: &str,
    key_path: &str,
    client_ca: Option<&str>,
) -> Result<rustls::ServerConfig> {
    let certs = load_certs(cert_path)?;
    let key = load_key(key_path)?;
    let builder = if let Some(ca_path) = client_ca {
        let roots = load_ca_roots(ca_path)?;
        let verifier = rustls::server::WebPkiClientVerifier::builder(Arc::new(roots))
            .build()
            .map_err(|e| {
                crate::error::InterflowError::config(format!(
                    "failed to build client certificate verifier: {e}"
                ))
            })?;
        rustls::ServerConfig::builder().with_client_cert_verifier(verifier)
    } else {
        rustls::ServerConfig::builder().with_no_client_auth()
    };
    builder.with_single_cert(certs, key).map_err(|e| {
        crate::error::InterflowError::config(format!("failed to configure server certificate: {e}"))
    })
}

/// Extracts the client certificate CN from quinn's `peer_identity()` (for mTLS identity binding).
pub fn extract_cn_from_quinn_identity(identity: Option<Box<dyn std::any::Any>>) -> Option<String> {
    let certs = identity.and_then(|any| any.downcast::<Vec<CertificateDer<'static>>>().ok())?;
    extract_cn_from_chain(&certs)
}

pub fn extract_cn_from_chain(certs: &[CertificateDer]) -> Option<String> {
    let leaf = certs.first()?;
    let (_, parsed) = x509_parser::parse_x509_certificate(leaf.as_ref()).ok()?;
    let subject = parsed.subject();
    // The OID for CN is 2.5.4.3
    subject
        .iter_common_name()
        .next()
        .and_then(|cn| cn.as_str().ok())
        .map(str::to_string)
}

/// Validation strictness for private key / certificate file permissions.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Strictness {
    /// Private key: any group/other permission bit is an error.
    Strict,
    /// Certificate: overly broad permissions only warn.
    Lenient,
}

/// Validates private key/certificate file permissions on Unix to avoid leaks.
#[cfg(unix)]
pub fn check_secret_file_perms(path: &str, strictness: Strictness) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    let meta = std::fs::metadata(path).map_err(|e| {
        InterflowError::config(format!("failed to read file metadata for {path}: {e}"))
    })?;
    let mode = meta.permissions().mode();
    // 0o077 mask: group/other must not have any permission bits
    let leak = mode & 0o077;
    if leak == 0 {
        return Ok(());
    }
    // Display-only permission mask: the full st_mode value includes file
    // type bits (e.g. 0100644); printing it directly yields a confusing
    // "mode=100644" that does not match the suggested value (2026-09-13 bug
    // doc §3, for reference)
    let perm = mode & 0o777;
    match strictness {
        Strictness::Strict => Err(InterflowError::config(format!(
            "private key file {path} has overly broad permissions (mode={perm:o}); 600 required (owner read/write only). Run chmod 600 {path}"
        ))),
        Strictness::Lenient => {
            warn!(
                "certificate file {path} has overly broad permissions (mode={perm:o}), chmod 644 recommended"
            );
            Ok(())
        }
    }
}

#[cfg(not(unix))]
#[allow(unused_variables)]
pub fn check_secret_file_perms(path: &str, strictness: Strictness) -> Result<()> {
    Ok(())
}

#[cfg(test)]
#[allow(
    clippy::panic,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::missing_docs_in_private_items
)]
mod tests {
    use super::*;

    #[test]
    fn extract_cn_from_empty_chain_is_none() {
        assert!(extract_cn_from_chain(&[]).is_none());
    }
}
