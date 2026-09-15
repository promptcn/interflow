//! Certificate generation (pure Rust, cross-platform, no openssl dependency).
//!
//! Used by the `interflow-expose init` wizard: generates a CA + hub server
//! certificate.

use interflow_core::error::{InterflowError, Result};
use std::path::Path;

/// Wizard output: paths of the certificates written to disk.
pub struct GeneratedCerts {
    /// CA certificate PEM (referenced by ca_path on the agent side).
    pub ca_cert: String,
    /// Hub server certificate PEM.
    pub hub_cert: String,
    /// Hub server private key PEM (0600 permissions).
    pub hub_key: String,
}

/// Generates a CA + hub certificate under `cert_dir`, with fixed file names
/// `ca.crt` / `hub.crt` / `hub.key`.
///
/// `hub_common_name` is the CN of the hub certificate, usually the hub domain
/// (e.g. `hub.example.com`). A SAN (Subject Alternative Name) is also included
/// so rustls passes hostname verification.
pub fn generate(cert_dir: &Path, hub_common_name: &str) -> Result<GeneratedCerts> {
    use rcgen::{
        CertificateParams, CertifiedIssuer, DistinguishedName, DnType, KeyPair, KeyUsagePurpose,
    };

    fn rcgen_err(context: &'static str) -> impl Fn(rcgen::Error) -> InterflowError {
        move |e| InterflowError::config(context).with_source(e)
    }

    std::fs::create_dir_all(cert_dir).map_err(|e| {
        InterflowError::config("failed to create certificate directory").with_source(e)
    })?;

    // 1. CA — `CertifiedIssuer::self_signed` yields both the certificate and
    //    the `Issuer`; since rcgen 0.14, `CertificateParams::signed_by` takes
    //    an `Issuer` instead of (ca_cert, ca_key).
    let mut ca_params =
        CertificateParams::new(vec![]).map_err(rcgen_err("failed to build CA params"))?;
    ca_params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
    ca_params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
    let mut ca_dn = DistinguishedName::new();
    ca_dn.push(DnType::CommonName, "interflow-ca");
    ca_params.distinguished_name = ca_dn;
    let ca_key = KeyPair::generate().map_err(rcgen_err("failed to generate CA key"))?;
    let ca = CertifiedIssuer::self_signed(ca_params, ca_key)
        .map_err(rcgen_err("failed to self-sign CA"))?;
    let ca_pem = ca.as_ref().pem();

    // 2. Hub server cert
    // SAN holds only the user-provided hub domain (e.g. tunnel.example.com) —
    // used by remote Mac agents for CA + hostname verification. The
    // in-process edge self-dial does not use SAN/hostname but cert pinning
    // instead (see build_edge_agent_config in crates/expose/src/edge/mod.rs),
    // so loopback SANs like localhost / 127.0.0.1 are not needed here.
    let mut hub_params = CertificateParams::new(vec![hub_common_name.to_string()])
        .map_err(rcgen_err("failed to build hub certificate params"))?;
    let mut hub_dn = DistinguishedName::new();
    hub_dn.push(DnType::CommonName, hub_common_name);
    hub_params.distinguished_name = hub_dn;
    hub_params.extended_key_usages = vec![rcgen::ExtendedKeyUsagePurpose::ServerAuth];
    let hub_key = KeyPair::generate().map_err(rcgen_err("failed to generate hub key"))?;
    let hub_cert = hub_params
        .signed_by(&hub_key, &ca)
        .map_err(rcgen_err("failed to sign hub certificate"))?;
    let hub_cert_pem = hub_cert.pem();
    let hub_key_pem = hub_key.serialize_pem();

    // 3. Write to disk
    let ca_path = cert_dir.join("ca.crt");
    let hub_cert_path = cert_dir.join("hub.crt");
    let hub_key_path = cert_dir.join("hub.key");

    fn write_err(path: &Path) -> impl Fn(std::io::Error) -> InterflowError + '_ {
        move |e| {
            InterflowError::config(format!("failed to write {}", path.display())).with_source(e)
        }
    }
    std::fs::write(&ca_path, ca_pem.as_bytes()).map_err(write_err(&ca_path))?;
    std::fs::write(&hub_cert_path, hub_cert_pem.as_bytes()).map_err(write_err(&hub_cert_path))?;
    std::fs::write(&hub_key_path, hub_key_pem.as_bytes()).map_err(write_err(&hub_key_path))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut perms = std::fs::metadata(&hub_key_path)
            .map_err(|e| InterflowError::config("failed to read key metadata").with_source(e))?
            .permissions();
        perms.set_mode(0o600);
        std::fs::set_permissions(&hub_key_path, perms)
            .map_err(|e| InterflowError::config("failed to chmod 600").with_source(e))?;
    }

    Ok(GeneratedCerts {
        ca_cert: ca_path.to_string_lossy().into_owned(),
        hub_cert: hub_cert_path.to_string_lossy().into_owned(),
        hub_key: hub_key_path.to_string_lossy().into_owned(),
    })
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
    use rustls::client::WebPkiServerVerifier;
    use rustls::client::danger::ServerCertVerifier;
    use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
    use std::io::Cursor;
    use std::sync::Arc;

    /// Reads a PEM file and returns the DER of the first certificate.
    fn read_cert_der(path: &Path) -> Vec<u8> {
        let pem = std::fs::read(path).expect("failed to read certificate file");
        let mut reader = Cursor::new(&pem);
        rustls_pemfile::certs(&mut reader)
            .next()
            .expect("PEM should contain at least one certificate")
            .expect("failed to parse PEM")
            .to_vec()
    }

    /// Runs `generate` once in a temp directory and exposes `GeneratedCerts`
    /// to the closure. The TempDir's lifetime is managed by this function; it
    /// is not cleaned up before the closure returns.
    fn with_temp_certs<R>(hub: &str, f: impl FnOnce(&GeneratedCerts) -> R) -> R {
        let dir = tempfile::tempdir().unwrap();
        let certs = generate(dir.path(), hub).expect("generate should succeed");
        f(&certs)
    }

    #[test]
    fn generate_writes_three_files_with_expected_names() {
        with_temp_certs("hub.example.com", |certs| {
            assert!(certs.ca_cert.ends_with("ca.crt"));
            assert!(certs.hub_cert.ends_with("hub.crt"));
            assert!(certs.hub_key.ends_with("hub.key"));
            assert!(!std::fs::read(&certs.ca_cert).unwrap().is_empty());
            assert!(!std::fs::read(&certs.hub_cert).unwrap().is_empty());
            assert!(!std::fs::read(&certs.hub_key).unwrap().is_empty());
        });
    }

    #[test]
    fn ca_cert_is_self_signed_ca() {
        with_temp_certs("hub.example.com", |certs| {
            let der = read_cert_der(Path::new(&certs.ca_cert));
            let ca = x509_parser::parse_x509_certificate(&der).unwrap().1;
            assert!(ca.is_ca(), "CA cert must be marked isCA");
            let ku = ca
                .key_usage()
                .expect("failed to parse KeyUsage extension")
                .expect("CA cert must have a KeyUsage extension");
            assert!(ku.value.key_cert_sign(), "CA must have KeyCertSign");
            assert!(ku.value.crl_sign(), "CA must have CrlSign");
        });
    }

    #[test]
    fn hub_cert_has_correct_cn() {
        with_temp_certs("hub.example.com", |certs| {
            let der = read_cert_der(Path::new(&certs.hub_cert));
            let hub = x509_parser::parse_x509_certificate(&der).unwrap().1;
            let cn = hub
                .subject()
                .iter_common_name()
                .next()
                .expect("hub cert must have a CN")
                .as_str()
                .unwrap();
            assert_eq!(cn, "hub.example.com");
        });
    }

    #[test]
    fn hub_cert_has_san_matching_cn() {
        with_temp_certs("hub.example.com", |certs| {
            let der = read_cert_der(Path::new(&certs.hub_cert));
            let hub = x509_parser::parse_x509_certificate(&der).unwrap().1;
            let san = hub
                .subject_alternative_name()
                .expect("failed to parse SAN extension")
                .expect("hub cert must have a SAN extension");
            let has_matching_san = san.value.general_names.iter().any(|gn| {
                matches!(
                    gn,
                    x509_parser::extensions::GeneralName::DNSName(s) if *s == "hub.example.com"
                )
            });
            assert!(
                has_matching_san,
                "SAN is missing hub.example.com, got {:?}",
                san.value.general_names
            );
        });
    }

    #[test]
    fn hub_cert_has_server_auth_eku() {
        with_temp_certs("hub.example.com", |certs| {
            let der = read_cert_der(Path::new(&certs.hub_cert));
            let hub = x509_parser::parse_x509_certificate(&der).unwrap().1;
            let eku = hub
                .extended_key_usage()
                .expect("failed to parse EKU extension")
                .expect("hub cert must have an EKU extension");
            assert!(eku.value.server_auth, "EKU must include ServerAuth");
        });
    }

    #[test]
    fn hub_cert_is_not_ca() {
        with_temp_certs("hub.example.com", |certs| {
            let der = read_cert_der(Path::new(&certs.hub_cert));
            let hub = x509_parser::parse_x509_certificate(&der).unwrap().1;
            assert!(!hub.is_ca(), "hub leaf must not be a CA");
        });
    }

    #[test]
    #[cfg(unix)]
    fn hub_key_file_permissions_are_0600() {
        use std::os::unix::fs::PermissionsExt;
        with_temp_certs("hub.example.com", |certs| {
            let mode = std::fs::metadata(&certs.hub_key)
                .unwrap()
                .permissions()
                .mode();
            assert_eq!(
                mode & 0o777,
                0o600,
                "hub.key permissions are not 0600, got {mode:o}"
            );
        });
    }

    // ---- Layer 2: end-to-end chain verification (rustls WebPkiServerVerifier) ----
    // A single test covers all of: CA validity, signature chain, SAN hostname
    // match, EKU, and the validity window.

    fn build_verifier(ca_path: &str) -> Arc<dyn ServerCertVerifier> {
        let mut roots = rustls::RootCertStore::empty();
        let ca_der = read_cert_der(Path::new(ca_path));
        roots.add(CertificateDer::from(ca_der)).unwrap();
        WebPkiServerVerifier::builder(Arc::new(roots))
            .build()
            .expect("failed to build verifier")
    }

    #[test]
    fn rustls_accepts_hub_cert_signed_by_generated_ca() {
        with_temp_certs("hub.example.com", |certs| {
            let verifier = build_verifier(&certs.ca_cert);
            let hub_der = read_cert_der(Path::new(&certs.hub_cert));
            let end_entity = CertificateDer::from(hub_der);
            let name: ServerName<'static> = "hub.example.com"
                .try_into()
                .expect("hostname should parse as a ServerName");
            let result = verifier.verify_server_cert(&end_entity, &[], &name, &[], UnixTime::now());
            assert!(
                result.is_ok(),
                "rustls should accept the hub cert signed by the CA, got: {:?}",
                result.err()
            );
        });
    }

    #[test]
    fn rustls_rejects_wrong_hostname() {
        with_temp_certs("hub.example.com", |certs| {
            let verifier = build_verifier(&certs.ca_cert);
            let hub_der = read_cert_der(Path::new(&certs.hub_cert));
            let end_entity = CertificateDer::from(hub_der);
            let evil: ServerName<'static> = "evil.example.com".try_into().unwrap();
            let result = verifier.verify_server_cert(&end_entity, &[], &evil, &[], UnixTime::now());
            assert!(
                result.is_err(),
                "rustls must not accept a wrong hostname, but verification passed"
            );
        });
    }
}
