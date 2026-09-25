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
use tokio_rustls::rustls::pki_types::CertificateRevocationListDer;
use tokio_rustls::rustls::pki_types::pem::PemObject;
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
        InterflowError::config(format!("failed to open certificate file {path}")).with_source(e)
    })?;
    let mut reader = BufReader::new(file);
    rustls_pemfile::certs(&mut reader)
        .collect::<std::result::Result<Vec<_>, _>>()
        .map_err(|e| {
            InterflowError::config("failed to load certificates".to_string()).with_source(e)
        })
}

/// Loads a PKCS#8 private key from a PEM file. Enforces 0600 permissions.
pub(crate) fn load_key(path: &str) -> Result<PrivateKeyDer<'static>> {
    check_secret_file_perms(path, Strictness::Strict)?;
    let file = File::open(path).map_err(|e| {
        InterflowError::config(format!("failed to open private key file {path}")).with_source(e)
    })?;
    let mut reader = BufReader::new(file);
    let keys = rustls_pemfile::pkcs8_private_keys(&mut reader)
        .collect::<std::result::Result<Vec<_>, _>>()
        .map_err(|e| {
            InterflowError::config("failed to load private key".to_string()).with_source(e)
        })?;

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
    let file = File::open(path).map_err(|e| {
        InterflowError::config(format!("failed to open CA file {path}")).with_source(e)
    })?;
    let mut reader = BufReader::new(file);
    let mut roots = RootCertStore::empty();
    for cert in rustls_pemfile::certs(&mut reader) {
        let cert = cert
            .map_err(|e| InterflowError::config("failed to parse CA".to_string()).with_source(e))?;
        roots
            .add(cert)
            .map_err(|e| InterflowError::config("failed to add CA".to_string()).with_source(e))?;
    }
    if roots.is_empty() {
        return Err(InterflowError::config(format!(
            "no certificates found in CA file {path}"
        )));
    }
    Ok(roots)
}

/// Loads one PEM-encoded X.509 CRL.
pub fn load_crl(path: &str) -> Result<CertificateRevocationListDer<'static>> {
    let bytes = std::fs::read(path)
        .map_err(|e| InterflowError::config(format!("cannot open CRL {path}")).with_source(e))?;
    CertificateRevocationListDer::from_pem_slice(&bytes)
        .map_err(|e| InterflowError::config(format!("failed to parse CRL {path}")).with_source(e))
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
    let client_roots = load_ca_roots(client_ca_path)?;
    build_mtls_acceptor_with_roots(cert_path, key_path, &client_roots, min_version)
}

/// [`build_mtls_acceptor`] with the client trust roots supplied directly.
///
/// The multi-tenant plane merges every tenant's roots into one store —
/// `core::tls::tenant` owns the derivation of *which* tenant anchored a
/// chain.
pub(crate) fn build_mtls_acceptor_with_roots(
    cert_path: &str,
    key_path: &str,
    client_roots: &RootCertStore,
    min_version: TlsMinVersion,
) -> Result<TlsAcceptor> {
    Ok(TlsAcceptor::from(Arc::new(
        build_mtls_server_config_with_roots(cert_path, key_path, client_roots, min_version)?,
    )))
}

/// The `rustls::ServerConfig` behind [`build_mtls_acceptor_with_roots`] —
/// for listeners that dispatch connections into this plane from another
/// acceptor (e.g. the ingress's public-port SNI multiplexing).
pub(crate) fn build_mtls_server_config_with_roots(
    cert_path: &str,
    key_path: &str,
    client_roots: &RootCertStore,
    min_version: TlsMinVersion,
) -> Result<TlsServerConfig> {
    let certs = load_certs(cert_path)?;
    let key = load_key(key_path)?;

    let verifier =
        tokio_rustls::rustls::server::WebPkiClientVerifier::builder(Arc::new(client_roots.clone()))
            .build()
            .map_err(|e| {
                InterflowError::config("failed to build client verifier".to_string()).with_source(e)
            })?;

    let mut config =
        TlsServerConfig::builder_with_protocol_versions(min_version.supported_versions())
            .with_client_cert_verifier(verifier)
            .with_single_cert(certs, key)
            .map_err(|e| {
                InterflowError::config("mTLS configuration error".to_string()).with_source(e)
            })?;
    config.alpn_protocols = vec![b"h2".to_vec()];
    Ok(config)
}

/// Builds a bare `rustls::ServerConfig` for QUIC/quinn (the equivalent of
/// the tokio-rustls acceptor).
///
/// The client trust roots are supplied directly — the multi-tenant QUIC
/// plane merges every tenant's roots. `client_roots` provides the mTLS
/// client certificate validation roots; `None` is one-way TLS.
/// `min_version` selects the enforced protocol-version floor.
pub fn build_rustls_server_config_with_roots(
    cert_path: &str,
    key_path: &str,
    client_roots: Option<&RootCertStore>,
    min_version: TlsMinVersion,
) -> Result<rustls::ServerConfig> {
    let certs = load_certs(cert_path)?;
    let key = load_key(key_path)?;
    let builder = if let Some(roots) = client_roots {
        let verifier = rustls::server::WebPkiClientVerifier::builder(Arc::new(roots.clone()))
            .build()
            .map_err(|e| {
                crate::error::InterflowError::config(
                    "failed to build client certificate verifier".to_string(),
                )
                .with_source(e)
            })?;
        rustls::ServerConfig::builder_with_protocol_versions(min_version.supported_versions())
            .with_client_cert_verifier(verifier)
    } else {
        rustls::ServerConfig::builder_with_protocol_versions(min_version.supported_versions())
            .with_no_client_auth()
    };
    builder.with_single_cert(certs, key).map_err(|e| {
        crate::error::InterflowError::config("failed to configure server certificate".to_string())
            .with_source(e)
    })
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

/// Extracts the leaf certificate's validity window as unix seconds
/// `(not_before, not_after)` — the hub-side input to credential-expiry
/// phasing (the hub sees the connecting certificate and nothing else).
///
/// `None` means: no certificate / parse failure. The webpki verifier has
/// already validated the window at handshake time (expired certificates
/// never get this far); this reads it, it does not judge it.
pub fn extract_leaf_validity_from_chain(certs: &[CertificateDer]) -> Option<(i64, i64)> {
    let leaf = certs.first()?;
    let (_, parsed) = x509_parser::parse_x509_certificate(leaf.as_ref()).ok()?;
    let validity = parsed.validity();
    Some((
        validity.not_before.timestamp(),
        validity.not_after.timestamp(),
    ))
}

/// Reads the leaf certificate's subject CN from a PEM file.
///
/// The file-level counterpart of [`extract_cn_from_chain`], used for the
/// agent-side startup pre-validation of the identity binding (`agent id ==
/// certificate CN`) that the hub otherwise only enforces at registration
/// with a 403. `Err` means the file is unreadable or not a PEM cert chain;
/// `Ok(None)` means it parsed but carries no CN.
pub fn extract_cn_from_pem_file(path: &str) -> Result<Option<String>> {
    Ok(extract_cn_from_chain(&load_certs(path)?))
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
mod leaf_validity_tests {
    use super::*;

    fn leaf_chain(validity: interflow_certs::Validity) -> Vec<CertificateDer<'static>> {
        let ca =
            interflow_certs::build_ca("validity", interflow_certs::Validity::ca_default()).unwrap();
        let loaded = interflow_certs::LoadedCa::from_material(&ca).unwrap();
        let leaf = loaded
            .build_server_cert(
                &[interflow_certs::SanName::Dns("hub.test".to_owned())],
                validity,
            )
            .unwrap();
        rustls_pemfile::certs(&mut leaf.cert_pem.as_bytes())
            .collect::<std::result::Result<Vec<_>, _>>()
            .unwrap()
    }

    /// The hub-side expiry input reads exactly the issued window: a
    /// backdated leaf (90d TTL with 81d consumed) reports not_before /
    /// not_after as issued, not "now".
    #[test]
    fn reads_the_issued_validity_window() {
        let now = time::OffsetDateTime::now_utc();
        let validity = interflow_certs::Validity {
            not_before: now - time::Duration::days(81),
            not_after: now + time::Duration::days(9),
        };
        let chain = leaf_chain(validity);
        let (not_before, not_after) = extract_leaf_validity_from_chain(&chain).unwrap();
        // Second precision; the issued values, not the observation time.
        assert!((not_before - (now - time::Duration::days(81)).unix_timestamp()).abs() <= 1);
        assert!((not_after - (now + time::Duration::days(9)).unix_timestamp()).abs() <= 1);
    }

    #[test]
    fn empty_chain_is_none() {
        assert!(extract_leaf_validity_from_chain(&[]).is_none());
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
        // Server certificate on disk, CA-signed via interflow-certs (load_key
        // enforces 0600).
        let dir = std::env::temp_dir().join(format!("interflow-tls-minver-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let cert_path = dir.join("cert.pem");
        let key_path = dir.join("key.pem");
        {
            let ca = interflow_certs::build_ca("minver", interflow_certs::Validity::ca_default())
                .unwrap();
            let loaded = interflow_certs::LoadedCa::from_material(&ca).unwrap();
            let server = loaded
                .build_server_cert(
                    &[interflow_certs::SanName::Dns("hub.test".to_owned())],
                    interflow_certs::Validity::leaf_default(),
                )
                .unwrap();
            let mut f = std::fs::File::create(&cert_path).unwrap();
            f.write_all(server.cert_pem.as_bytes()).unwrap();
            let mut f = std::fs::File::create(&key_path).unwrap();
            f.write_all(server.key_pem.as_bytes()).unwrap();
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                let _ = std::fs::set_permissions(&key_path, std::fs::Permissions::from_mode(0o600));
            }
        }

        let acceptor = TlsAcceptor::from(Arc::new(
            build_rustls_server_config_with_roots(
                cert_path.to_str().unwrap(),
                key_path.to_str().unwrap(),
                None,
                TlsMinVersion::V1_3,
            )
            .unwrap(),
        ));

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
