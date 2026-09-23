//! Credential revocation: an issuer-store deny list plus signed CRLs.
//!
//! `revoke` is a first-class lifecycle operation, not a manual CA edit: the
//! operator records the revoked credential serials, the issuer store
//! regenerates its CRLs, and every subsequently rendered Trust Bundle /
//! pack carries the CRL so verifiers fail closed.

use crate::{Error, Result};
use rcgen::{
    CertificateRevocationListParams, KeyIdMethod, RevocationReason, RevokedCertParams, SerialNumber,
};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use time::OffsetDateTime;

/// One revocation entry.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RevocationEntry {
    /// Credential serial (hex).
    pub serial: String,
    /// Which issuer signed the revoked credential (`control` or
    /// `workspace/<name>`).
    pub issuer: String,
    pub reason: String,
    pub revoked_at: String,
    /// Pack digest of the revoked pack (audit trail).
    pub pack_digest: Option<String>,
}

/// The persisted deny list (`revocations.json` in the issuer store).
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct RevocationList {
    pub entries: Vec<RevocationEntry>,
}

impl RevocationList {
    /// Loads the deny list from an issuer store (missing file = empty).
    pub fn load(issuer_root: &Path) -> Result<Self> {
        let path = issuer_root.join("revocations.json");
        match std::fs::read_to_string(&path) {
            Ok(text) => serde_json::from_str(&text)
                .map_err(|e| Error::issuance("revocations.json parse".to_string()).with_source(e)),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(Self::default()),
            Err(e) => Err(Error::Io {
                path: path.display().to_string(),
                source: e,
            }),
        }
    }

    /// Appends entries and persists atomically.
    pub fn save(&self, issuer_root: &Path) -> Result<PathBuf> {
        let path = issuer_root.join("revocations.json");
        let text = serde_json::to_string_pretty(self)
            .map_err(|e| Error::serialize("revocations".to_string()).with_source(e))?;
        // A deny list is public data (mirrors the CRLs built from it):
        // preserve existing bits, 0644 for new files.
        interflow_util::atomic_write(
            &path,
            text.as_bytes(),
            interflow_util::WriteMode::PreserveOr(0o644),
        )
        .map_err(|e| Error::Io {
            path: path.display().to_string(),
            source: e,
        })?;
        Ok(path)
    }

    pub fn is_revoked(&self, serial: &str) -> bool {
        self.entries.iter().any(|e| e.serial == serial)
    }
}

/// Builds a signed CRL PEM revoking `serials` (7-day freshness horizon).
pub fn build_crl(
    issuer: &crate::issuance::LoadedIssuer,
    serials: &[String],
    crl_number: u64,
) -> Result<String> {
    build_crl_with_horizon(issuer, serials, crl_number, time::Duration::days(7))
}

/// [`build_crl`] with an explicit freshness horizon: offline deployments
/// embed the CRL in the pack (no refresh path), so its `next_update` must
/// cover the leaf's own lifetime.
pub fn build_crl_with_horizon(
    issuer: &crate::issuance::LoadedIssuer,
    serials: &[String],
    crl_number: u64,
    next_update: time::Duration,
) -> Result<String> {
    let now = OffsetDateTime::now_utc();
    let revoked = serials
        .iter()
        .filter_map(|hex_serial| {
            hex::decode(hex_serial).ok().map(|bytes| RevokedCertParams {
                serial_number: SerialNumber::from_slice(&bytes),
                revocation_time: now,
                reason_code: Some(RevocationReason::RemoveFromCrl),
                invalidity_date: None,
            })
        })
        .collect::<Vec<_>>();
    let params = CertificateRevocationListParams {
        this_update: now,
        next_update: now + next_update,
        crl_number: SerialNumber::from(crl_number),
        issuing_distribution_point: None,
        revoked_certs: revoked,
        key_identifier_method: KeyIdMethod::Sha256,
    };
    let signing_key = rcgen::KeyPair::from_pem(issuer.key_pem())
        .map_err(|e| Error::issuance("issuer key for CRL".to_string()).with_source(e))?;
    let issuer_cert = rcgen::Issuer::from_ca_cert_pem(issuer.cert_pem(), signing_key)
        .map_err(|e| Error::issuance("issuer certificate for CRL".to_string()).with_source(e))?;
    let crl = params
        .signed_by(&issuer_cert)
        .map_err(|e| Error::issuance("CRL signing".to_string()).with_source(e))?;
    crl.pem()
        .map_err(|e| Error::issuance("CRL PEM".to_string()).with_source(e))
}

/// Serial (hex) of a PEM certificate leaf.
pub fn cert_serial_hex(cert_pem: &str) -> Result<String> {
    let der = crate::pem_certs(cert_pem.as_bytes())?
        .into_iter()
        .next()
        .ok_or_else(|| Error::issuance("certificate PEM carries no certificate".to_owned()))?;
    match x509_parser::parse_x509_certificate(&der) {
        Ok((_, cert)) => {
            let serial = cert.raw_serial();
            let canonical = if serial.first() == Some(&0) {
                &serial[1..]
            } else {
                serial
            };
            Ok(hex::encode(canonical))
        }
        Err(e) => Err(Error::issuance("certificate parse".to_string()).with_source(e)),
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use crate::issuance::IssuerStore;

    #[test]
    fn deny_list_round_trip_and_crl() {
        let dir = tempfile::tempdir().unwrap();
        let store = IssuerStore::open(dir.path());
        store.ensure_realm().unwrap();
        let mut list = RevocationList::load(dir.path()).unwrap();
        list.entries.push(RevocationEntry {
            serial: "00ff".to_owned(),
            issuer: "control".to_owned(),
            reason: "key-compromise".to_owned(),
            revoked_at: "2026-09-20T00:00:00Z".to_owned(),
            pack_digest: Some("sha256:abc".to_owned()),
        });
        list.save(dir.path()).unwrap();
        let reloaded = RevocationList::load(dir.path()).unwrap();
        assert!(reloaded.is_revoked("00ff"));
        assert!(!reloaded.is_revoked("00ee"));
        let crl = build_crl(&store.realm_issuer().unwrap(), &["00ff".to_owned()], 1).unwrap();
        assert!(crl.contains("BEGIN X509 CRL"));
    }
}
