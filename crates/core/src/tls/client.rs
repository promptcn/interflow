//! TLS client-config assembly, shared by the agent's h2 and QUIC paths
//! (the counterpart of the server-side acceptor builders).
//!
//! Covers cert pinning / CA validation / the optional mTLS client
//! certificate.

use crate::error::{InterflowError, Result};
use std::fs::File;
use std::io::BufReader;

/// Builds the trust roots for client connections: the system root store
/// plus, when `ca_path` is set, a custom CA.
///
/// System-certificate load failures only warn (degraded trust); a
/// custom-CA failure is a configuration error.
fn build_root_store(ca_path: Option<&str>) -> Result<rustls::RootCertStore> {
    let mut root_store = rustls::RootCertStore::empty();
    let native_certs = rustls_native_certs::load_native_certs();
    for err in native_certs.errors {
        tracing::warn!("System certificate loading warning: {err}");
    }
    for cert in native_certs.certs {
        if let Err(e) = root_store.add(cert) {
            tracing::warn!("Failed to add system root certificate (skipping it): {e}");
        }
    }
    if let Some(ca_path) = ca_path {
        let file = File::open(ca_path).map_err(|e| {
            InterflowError::config(format!("cannot open CA certificate {ca_path}")).with_source(e)
        })?;
        let mut reader = BufReader::new(file);
        for cert in rustls_pemfile::certs(&mut reader) {
            let cert = cert.map_err(|e| {
                InterflowError::config("failed to parse CA certificate".to_string()).with_source(e)
            })?;
            root_store.add(cert).map_err(|e| {
                InterflowError::config("failed to add CA certificate".to_string()).with_source(e)
            })?;
        }
    }
    Ok(root_store)
}

/// Loads a PEM-encoded client certificate chain (for mTLS).
fn load_pem_cert_chain(path: &str) -> Result<Vec<rustls::pki_types::CertificateDer<'static>>> {
    let file = File::open(path).map_err(|e| {
        InterflowError::config(format!("cannot open client cert {path}")).with_source(e)
    })?;
    let mut reader = BufReader::new(file);
    rustls_pemfile::certs(&mut reader)
        .collect::<std::result::Result<Vec<_>, _>>()
        .map_err(|e| {
            InterflowError::config("failed to parse client cert".to_string()).with_source(e)
        })
}

/// Loads a PEM-encoded PKCS#8 private key (for mTLS).
fn load_pem_private_key(path: &str) -> Result<rustls::pki_types::PrivateKeyDer<'static>> {
    let file = File::open(path).map_err(|e| {
        InterflowError::config(format!("cannot open client key {path}")).with_source(e)
    })?;
    let mut reader = BufReader::new(file);
    let keys = rustls_pemfile::pkcs8_private_keys(&mut reader)
        .collect::<std::result::Result<Vec<_>, _>>()
        .map_err(|e| {
            InterflowError::config("failed to parse client key".to_string()).with_source(e)
        })?;
    let Some(key) = keys.into_iter().next() else {
        return Err(InterflowError::config(
            "no private key found in file".to_string(),
        ));
    };
    Ok(rustls::pki_types::PrivateKeyDer::Pkcs8(key))
}

/// Builds a rustls [`rustls::ClientConfig`] from the agent-side TLS knobs.
///
/// - `pin_hex` set: certificate pinning (bypasses CA validation, `ca_path`
///   is ignored);
/// - otherwise: CA validation over [`build_root_store`];
/// - client certificate and key both set: mTLS.
///
/// `alpn` lists the offered protocols (`h2` / the QUIC ALPN).
pub fn build_client_config(
    pin_hex: Option<&str>,
    ca_path: Option<&str>,
    client_cert_path: Option<&str>,
    client_key_path: Option<&str>,
    alpn: &[&str],
) -> Result<rustls::ClientConfig> {
    let builder = if let Some(pin) = pin_hex {
        let verifier = crate::tls::cert_pin::make_pinned_verifier(pin).map_err(|e| {
            InterflowError::config("cert pin configuration error".to_string()).with_source(e)
        })?;
        rustls::ClientConfig::builder()
            .dangerous()
            .with_custom_certificate_verifier(verifier)
    } else {
        rustls::ClientConfig::builder().with_root_certificates(build_root_store(ca_path)?)
    };
    let mut config = match (client_cert_path, client_key_path) {
        (Some(cert_path), Some(key_path)) => builder
            .with_client_auth_cert(
                load_pem_cert_chain(cert_path)?,
                load_pem_private_key(key_path)?,
            )
            .map_err(|e| {
                InterflowError::config("client certificate setup failed".to_string()).with_source(e)
            })?,
        _ => builder.with_no_client_auth(),
    };
    config.alpn_protocols = alpn.iter().map(|p| p.as_bytes().to_vec()).collect();
    Ok(config)
}
