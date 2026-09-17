//! TLS certificate and private key loading, file permission validation,
//! `TlsAcceptor` assembly, and client certificate CN extraction.

use crate::config::secret::{Strictness, check_secret_file_perms};
use crate::error::{InterflowError, Result};
use serde::{Deserialize, Serialize};
use std::fs::File;
use std::io::BufReader;
use std::sync::Arc;
use tokio_rustls::TlsAcceptor;
use tokio_rustls::rustls::RootCertStore;
use tokio_rustls::rustls::ServerConfig as TlsServerConfig;
use tokio_rustls::rustls::pki_types::{CertificateDer, PrivateKeyDer};

/// Minimum TLS protocol version accepted by a server endpoint.
///
/// This is the one knob of the server-side TLS surface that operators
/// plausibly tighten (the hub's `tls.min_version`, default 1.2); it must be
/// threaded into every server-config builder so the configured floor is the
/// floor rustls actually enforces — a `min_version` that parses but never
/// reaches the builder is worse than no knob at all.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
pub enum TlsMinVersion {
    /// TLS 1.2 or newer.
    #[serde(rename = "1.2")]
    #[default]
    V1_2,
    /// TLS 1.3 only.
    #[serde(rename = "1.3")]
    V1_3,
}

const V12_AND_NEWER: &[&tokio_rustls::rustls::SupportedProtocolVersion] = &[
    &tokio_rustls::rustls::version::TLS12,
    &tokio_rustls::rustls::version::TLS13,
];
const V13_ONLY: &[&tokio_rustls::rustls::SupportedProtocolVersion] =
    &[&tokio_rustls::rustls::version::TLS13];

impl TlsMinVersion {
    /// The rustls protocol-version list to build the server config with.
    const fn supported_versions(
        self,
    ) -> &'static [&'static tokio_rustls::rustls::SupportedProtocolVersion] {
        match self {
            Self::V1_2 => V12_AND_NEWER,
            Self::V1_3 => V13_ONLY,
        }
    }
}

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
/// `min_version` selects the enforced protocol-version floor.
///
/// `Ok(None)` means TLS is not enabled; `Err` means a configuration or file
/// problem.
pub fn build_tls_acceptor(
    cert_path: &str,
    key_path: &str,
    min_version: TlsMinVersion,
) -> Result<Option<TlsAcceptor>> {
    let certs = load_certs(cert_path)?;
    let key = load_key(key_path)?;
    let mut config =
        TlsServerConfig::builder_with_protocol_versions(min_version.supported_versions())
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
/// - `min_version`: the enforced protocol-version floor
///
/// If the client presents no certificate or an untrusted one at handshake,
/// rustls rejects it outright.
pub fn build_mtls_acceptor(
    cert_path: &str,
    key_path: &str,
    client_ca_path: &str,
    min_version: TlsMinVersion,
) -> Result<TlsAcceptor> {
    let certs = load_certs(cert_path)?;
    let key = load_key(key_path)?;
    let client_roots = load_ca_roots(client_ca_path)?;

    let verifier =
        tokio_rustls::rustls::server::WebPkiClientVerifier::builder(Arc::new(client_roots))
            .build()
            .map_err(|e| InterflowError::config(format!("failed to build client verifier: {e}")))?;

    let mut config =
        TlsServerConfig::builder_with_protocol_versions(min_version.supported_versions())
            .with_client_cert_verifier(verifier)
            .with_single_cert(certs, key)
            .map_err(|e| InterflowError::config(format!("mTLS configuration error: {e}")))?;
    config.alpn_protocols = vec![b"h2".to_vec()];
    Ok(TlsAcceptor::from(Arc::new(config)))
}

/// Builds a bare `rustls::ServerConfig` (for QUIC/quinn; the equivalent of
/// the tokio-rustls acceptor).
///
/// `client_ca` provides the mTLS client certificate validation roots;
/// `None` is one-way TLS. `min_version` selects the enforced
/// protocol-version floor.
pub fn build_rustls_server_config(
    cert_path: &str,
    key_path: &str,
    client_ca: Option<&str>,
    min_version: TlsMinVersion,
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
        rustls::ServerConfig::builder_with_protocol_versions(min_version.supported_versions())
            .with_client_cert_verifier(verifier)
    } else {
        rustls::ServerConfig::builder_with_protocol_versions(min_version.supported_versions())
            .with_no_client_auth()
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

/// Extracts the CN (Common Name) from a client cert chain, used as the agent identity binding.
///
/// `None` means: no certificate / parse failure / no CN field.
/// The first certificate is the leaf (end-entity); the rest are
/// intermediate / root.
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

#[cfg(test)]
#[allow(
    clippy::panic,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::missing_docs_in_private_items
)]
mod min_version_tests {
    use super::*;
    use std::io::Write;

    /// The enforcement proof for `min_version`: a V1_3-only acceptor must
    /// reject a client that offers only TLS 1.2 (and accept a TLS 1.3
    /// client). Before the knob was wired into
    /// `builder_with_protocol_versions`, this floor was silently ignored.
    #[tokio::test]
    async fn min_version_tls13_rejects_tls12_and_accepts_tls13() {
        // Self-signed server certificate on disk (load_key enforces 0600).
        let dir = std::env::temp_dir().join(format!("interflow-tls-minver-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let cert_path = dir.join("cert.pem");
        let key_path = dir.join("key.pem");
        {
            let server = rcgen::generate_simple_self_signed(vec!["hub.test".to_string()]).unwrap();
            let mut f = std::fs::File::create(&cert_path).unwrap();
            f.write_all(server.cert.pem().as_bytes()).unwrap();
            let mut f = std::fs::File::create(&key_path).unwrap();
            f.write_all(server.signing_key.serialize_pem().as_bytes())
                .unwrap();
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                let _ = std::fs::set_permissions(&key_path, std::fs::Permissions::from_mode(0o600));
            }
        }

        let acceptor = build_tls_acceptor(
            cert_path.to_str().unwrap(),
            key_path.to_str().unwrap(),
            TlsMinVersion::V1_3,
        )
        .unwrap()
        .unwrap();

        const TLS12_ONLY: &[&tokio_rustls::rustls::SupportedProtocolVersion] =
            &[&tokio_rustls::rustls::version::TLS12];
        const TLS13_ONLY: &[&tokio_rustls::rustls::SupportedProtocolVersion] =
            &[&tokio_rustls::rustls::version::TLS13];
        for (client_versions, should_succeed) in [(TLS12_ONLY, false), (TLS13_ONLY, true)] {
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let addr = listener.local_addr().unwrap();

            let server = tokio::spawn({
                let acceptor = acceptor.clone();
                async move {
                    let (sock, _) = listener.accept().await.unwrap();
                    let _stream = acceptor.accept(sock).await;
                }
            });

            let client_config = {
                use rustls::client::danger::{
                    HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier,
                };
                use rustls::{DigitallySignedStruct, SignatureScheme};
                #[derive(Debug)]
                struct AcceptAll;
                impl ServerCertVerifier for AcceptAll {
                    fn verify_server_cert(
                        &self,
                        _end_entity: &rustls::pki_types::CertificateDer<'_>,
                        _intermediates: &[rustls::pki_types::CertificateDer<'_>],
                        _server_name: &rustls::pki_types::ServerName<'_>,
                        _ocsp_response: &[u8],
                        _now: rustls::pki_types::UnixTime,
                    ) -> std::result::Result<ServerCertVerified, rustls::Error>
                    {
                        Ok(ServerCertVerified::assertion())
                    }
                    fn verify_tls12_signature(
                        &self,
                        _message: &[u8],
                        _cert: &rustls::pki_types::CertificateDer<'_>,
                        _dss: &DigitallySignedStruct,
                    ) -> std::result::Result<HandshakeSignatureValid, rustls::Error>
                    {
                        // Assertion-only: the rejection under test happens at
                        // version negotiation, before signatures matter.
                        Ok(HandshakeSignatureValid::assertion())
                    }
                    fn verify_tls13_signature(
                        &self,
                        _message: &[u8],
                        _cert: &rustls::pki_types::CertificateDer<'_>,
                        _dss: &DigitallySignedStruct,
                    ) -> std::result::Result<HandshakeSignatureValid, rustls::Error>
                    {
                        Ok(HandshakeSignatureValid::assertion())
                    }
                    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
                        vec![
                            SignatureScheme::RSA_PKCS1_SHA256,
                            SignatureScheme::ECDSA_NISTP256_SHA256,
                            SignatureScheme::ED25519,
                            SignatureScheme::RSA_PSS_SHA256,
                        ]
                    }
                }
                rustls::ClientConfig::builder_with_protocol_versions(client_versions)
                    .dangerous()
                    .with_custom_certificate_verifier(std::sync::Arc::new(AcceptAll))
                    .with_no_client_auth()
            };
            let client = tokio::spawn(async move {
                let connector =
                    tokio_rustls::TlsConnector::from(std::sync::Arc::new(client_config));
                let sock = tokio::net::TcpStream::connect(addr).await.unwrap();
                let server_name = rustls::pki_types::ServerName::try_from("hub.test")
                    .unwrap()
                    .to_owned();
                connector.connect(server_name, sock).await.is_ok()
            });

            server.await.unwrap();
            let ok = client.await.unwrap();
            assert_eq!(
                ok, should_succeed,
                "TLS1.2-only client against a min_version=1.3 server must be rejected"
            );
        }

        let _ = std::fs::remove_dir_all(&dir);
    }
}
