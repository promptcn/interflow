//! Cert pinning: trust only server certificates whose SHA256 fingerprint
//! matches, bypassing the system CA.
//!
//! Implements [`rustls::client::danger::ServerCertVerifier`], validating at
//! handshake that the leaf cert's SHA256 equals the configured value. Any
//! mismatch (including legitimately CA-issued certificates) fails the
//! handshake.

use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{DigitallySignedStruct, SignatureScheme};
use sha2::{Digest, Sha256};
use std::sync::Arc;

/// A cert verifier that passes only SHA256 validation.
///
/// `pinned_sha256` is the leaf cert DER SHA256.
#[derive(Debug)]
pub struct PinnedCertVerifier {
    pinned_sha256: [u8; 32],
}

/// Cert pinning parse / validation errors.
#[derive(Debug, thiserror::Error)]
pub enum PinError {
    /// Invalid fingerprint format (not 64 hex characters).
    #[error("invalid fingerprint format (64 hex characters required): {0}")]
    InvalidFingerprint(String),
}

impl PinnedCertVerifier {
    /// Constructs from a hex string. Empty / non-64-char hex → Err.
    pub fn from_hex(hex: &str) -> Result<Self, PinError> {
        let hex = hex.trim().trim_start_matches("sha256:").replace(':', "");
        if hex.len() != 64 {
            return Err(PinError::InvalidFingerprint(hex));
        }
        let mut bytes = [0u8; 32];
        for (i, chunk) in hex.as_bytes().chunks(2).enumerate() {
            let s = std::str::from_utf8(chunk)
                .map_err(|_| PinError::InvalidFingerprint(hex.clone()))?;
            let b =
                u8::from_str_radix(s, 16).map_err(|_| PinError::InvalidFingerprint(hex.clone()))?;
            bytes[i] = b;
        }
        Ok(Self {
            pinned_sha256: bytes,
        })
    }
}

impl ServerCertVerifier for PinnedCertVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        let mut hasher = Sha256::new();
        hasher.update(end_entity.as_ref());
        let actual = hasher.finalize();
        if actual.as_slice() == self.pinned_sha256 {
            Ok(ServerCertVerified::assertion())
        } else {
            Err(rustls::Error::General(format!(
                "cert pin mismatch: expected {}, got {}",
                hex::encode(self.pinned_sha256),
                hex::encode(actual)
            )))
        }
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        // Pinning does no signature validation; rustls 0.23 requires
        // dangerous verifiers to implement this. TLS 1.2 is obsolete; cert
        // pin mode is not recommended for 1.2 servers.
        Ok(HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        // Returns the common TLS 1.3 algorithm set; rustls passes actual
        // signature validation through these with a direct assertion.
        vec![
            SignatureScheme::ECDSA_NISTP256_SHA256,
            SignatureScheme::ECDSA_NISTP384_SHA384,
            SignatureScheme::ED25519,
            SignatureScheme::RSA_PSS_SHA256,
            SignatureScheme::RSA_PSS_SHA384,
            SignatureScheme::RSA_PSS_SHA512,
        ]
    }
}

/// Convenience constructor: returns an Arc<PinnedCertVerifier> to feed directly into ClientConfig::dangerous().
pub fn make_pinned_verifier(hex: &str) -> Result<Arc<PinnedCertVerifier>, PinError> {
    Ok(Arc::new(PinnedCertVerifier::from_hex(hex)?))
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
    fn parses_valid_hex() {
        let v = PinnedCertVerifier::from_hex(
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        );
        assert!(v.is_ok());
    }

    #[test]
    fn rejects_bad_length() {
        assert!(PinnedCertVerifier::from_hex("abcd").is_err());
        assert!(PinnedCertVerifier::from_hex("").is_err());
    }

    #[test]
    fn accepts_sha256_prefix() {
        let v = PinnedCertVerifier::from_hex(
            "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        );
        assert!(v.is_ok());
    }

    #[test]
    fn accepts_colon_separated() {
        let v = PinnedCertVerifier::from_hex(
            "e3:b0:c4:42:98:fc:1c:14:9a:fb:f4:c8:99:6f:b9:24:27:ae:41:e4:64:9b:93:4c:a4:95:99:1b:78:52:b8:55",
        );
        assert!(v.is_ok());
    }
}
