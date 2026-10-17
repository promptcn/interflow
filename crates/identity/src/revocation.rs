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
    /// Operator-facing reason. The canonical spellings — `key-compromise`
    /// (the leak-emergency default), `cessation-of-operation`,
    /// `superseded` (rotation), `unspecified` — map onto the RFC 5280
    /// reason code the CRL carries ([`crl_reason_code`]); any other string
    /// (legacy free-text entries) signs as `unspecified`.
    pub reason: String,
    pub revoked_at: String,
    /// Pack digest of the revoked pack (audit trail).
    pub pack_digest: Option<String>,
}

/// The persisted deny list (`revocations.json` in the issuer store).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RevocationList {
    pub entries: Vec<RevocationEntry>,
    /// The number the next issued CRL carries. RFC 5280 requires CRL
    /// numbers to increase monotonically — `entries.len()`-derived numbers
    /// regress as soon as entries are ever removed (and the pre-counter
    /// call sites disagreed by ±1 among themselves). **Every mutation —
    /// addition or removal — must advance this** ([`Self::record`] does);
    /// issuance reads it without bumping, so an unchanged deny list keeps
    /// its number and consumers can read a repeated number as "no change".
    /// `0` never appears on disk: [`Self::load`] backfills absent (legacy)
    /// fields, and [`Self::default`] starts at 1.
    #[serde(default)]
    pub next_crl_number: u64,
}

impl Default for RevocationList {
    fn default() -> Self {
        Self {
            entries: Vec::new(),
            next_crl_number: 1,
        }
    }
}

impl RevocationList {
    /// Loads the deny list from an issuer store (missing file = empty).
    pub fn load(issuer_root: &Path) -> Result<Self> {
        let path = issuer_root.join("revocations.json");
        let mut list = match std::fs::read_to_string(&path) {
            Ok(text) => serde_json::from_str::<Self>(&text)
                .map_err(|e| Error::issuance("revocations.json parse".to_string()).with_source(e)),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(Self::default()),
            Err(e) => Err(Error::Io {
                path: path.display().to_string(),
                source: e,
            }),
        }?;
        if list.next_crl_number == 0 {
            // A legacy file predates the counter; the last CRL it issued
            // carried `entries.len() + 1` (the old formula), so backfill
            // exactly that — no number repeats or regresses across the
            // upgrade.
            list.next_crl_number = list.entries.len() as u64 + 1;
        }
        Ok(list)
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

    /// Records a revocation. The one mutation path: appending advances the
    /// CRL number so the next issued CRL outranks every prior one. (A
    /// future removal path must bump `next_crl_number` the same way.)
    pub fn record(&mut self, entry: RevocationEntry) {
        self.next_crl_number += 1;
        self.entries.push(entry);
    }

    pub fn is_revoked(&self, serial: &str) -> bool {
        self.entries.iter().any(|e| e.serial == serial)
    }
}

/// The RFC 5280 reason code a deny-list reason string signs as. Legacy
/// free-text entries (`operator-requested` and friends) carry no RFC
/// severity: `unspecified` is the honest code for them — never
/// `remove_from_crl`, whose RFC meaning ("removed from a delta-CRL") is
/// the opposite of a revocation.
#[must_use]
pub fn crl_reason_code(reason: &str) -> RevocationReason {
    match reason {
        "key-compromise" => RevocationReason::KeyCompromise,
        "cessation-of-operation" => RevocationReason::CessationOfOperation,
        "superseded" => RevocationReason::Superseded,
        _ => RevocationReason::Unspecified,
    }
}

/// Builds a signed CRL PEM revoking `entries` (7-day freshness horizon).
pub fn build_crl(
    issuer: &crate::issuance::LoadedIssuer,
    entries: &[RevocationEntry],
    crl_number: u64,
) -> Result<String> {
    build_crl_with_horizon(issuer, entries, crl_number, time::Duration::days(7))
}

/// [`build_crl`] with an explicit freshness horizon: offline deployments
/// embed the CRL in the pack (no refresh path), so its `next_update` must
/// cover the leaf's own lifetime.
pub fn build_crl_with_horizon(
    issuer: &crate::issuance::LoadedIssuer,
    entries: &[RevocationEntry],
    crl_number: u64,
    next_update: time::Duration,
) -> Result<String> {
    let now = OffsetDateTime::now_utc();
    let revoked = entries
        .iter()
        .filter_map(|entry| {
            hex::decode(&entry.serial)
                .ok()
                .map(|bytes| RevokedCertParams {
                    serial_number: SerialNumber::from_slice(&bytes),
                    revocation_time: now,
                    reason_code: Some(crl_reason_code(&entry.reason)),
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

/// The RFC 5280 `crl_number` a signed CRL PEM carries — the same monotonic
/// counter every issuance site mints from [`RevocationList::next_crl_number`].
/// This is the read side for material already on disk (the issuer store's
/// CRL files, a pack's embedded snapshot, a hub's live push lane):
/// consumers compare numbers to read "no change" and to refuse rollbacks.
pub fn crl_number(crl_pem: &str) -> Result<u64> {
    use x509_parser::pem::parse_x509_pem;
    use x509_parser::prelude::FromDer;
    use x509_parser::revocation_list::CertificateRevocationList;
    let (_, pem) = parse_x509_pem(crl_pem.as_bytes())
        .map_err(|e| Error::issuance("CRL PEM parse".to_string()).with_source(Box::new(e)))?;
    let (_, crl) = CertificateRevocationList::from_der(&pem.contents)
        .map_err(|e| Error::issuance("CRL parse".to_string()).with_source(Box::new(e)))?;
    crl.crl_number()
        .and_then(|n| n.to_string().parse::<u64>().ok())
        .ok_or_else(|| Error::issuance("CRL carries no readable crl_number".to_string()))
}

/// Whether a CRL in PEM form revokes the given certificate serial (hex,
/// same canonical form [`cert_serial_hex`] produces) — the pack-side
/// consumption half of the deny-list pipeline (a node checks its own leaf
/// against the CRL material it carries).
///
/// `Ok(None)` = the CRL parsed but the serial's issuer/scope could not be
/// decided here — callers treat that as "cannot judge", never as "clean".
pub fn crl_revokes_serial(crl_pem: &str, serial_hex: &str) -> Result<Option<bool>> {
    use x509_parser::pem::parse_x509_pem;
    use x509_parser::prelude::FromDer;
    use x509_parser::revocation_list::CertificateRevocationList;
    let (_, pem) = parse_x509_pem(crl_pem.as_bytes())
        .map_err(|e| Error::issuance("CRL PEM parse".to_string()).with_source(Box::new(e)))?;
    let (_, crl) = CertificateRevocationList::from_der(&pem.contents)
        .map_err(|e| Error::issuance("CRL parse".to_string()).with_source(Box::new(e)))?;
    let wanted = hex::decode(serial_hex)
        .map_err(|e| Error::issuance("serial hex".to_string()).with_source(e))?;
    // Numeric comparison: DER serial integers may carry a leading sign
    // byte on either side, and BigUint equality absorbs that.
    let wanted = x509_parser::num_bigint::BigUint::from_bytes_be(&wanted);
    Ok(Some(
        crl.iter_revoked_certificates()
            .any(|entry| entry.user_certificate == wanted),
    ))
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use crate::issuance::IssuerStore;

    fn entry(serial: &str, reason: &str) -> RevocationEntry {
        RevocationEntry {
            serial: serial.to_owned(),
            issuer: "control".to_owned(),
            reason: reason.to_owned(),
            revoked_at: "2026-10-09T00:00:00Z".to_owned(),
            pack_digest: Some("sha256:abc".to_owned()),
        }
    }

    #[test]
    fn deny_list_round_trip_and_crl() {
        let dir = tempfile::tempdir().unwrap();
        let store = IssuerStore::open(dir.path());
        store.ensure_realm().unwrap();
        let mut list = RevocationList::load(dir.path()).unwrap();
        list.record(entry("00ff", "key-compromise"));
        list.save(dir.path()).unwrap();
        let reloaded = RevocationList::load(dir.path()).unwrap();
        assert!(reloaded.is_revoked("00ff"));
        assert!(!reloaded.is_revoked("00ee"));
        assert_eq!(reloaded.next_crl_number, list.next_crl_number);
        let crl = build_crl(
            &store.realm_issuer().unwrap(),
            &reloaded.entries,
            reloaded.next_crl_number,
        )
        .unwrap();
        assert!(crl.contains("BEGIN X509 CRL"));
        // The pack-side consumption half: the built CRL answers membership
        // for exactly the recorded serials (leading-zero encodings meet).
        assert_eq!(crl_revokes_serial(&crl, "00ff").unwrap(), Some(true));
        assert_eq!(crl_revokes_serial(&crl, "ff").unwrap(), Some(true));
        assert_eq!(crl_revokes_serial(&crl, "00ee").unwrap(), Some(false));
        assert!(crl_revokes_serial("not a crl", "ff").is_err());
        // The counter read side: the on-disk number is the monotonic
        // counter, the rollback/no-change judgment key.
        assert_eq!(crl_number(&crl).unwrap(), reloaded.next_crl_number);
        assert!(crl_number("not a crl").is_err());
    }

    #[test]
    fn crl_numbers_strictly_increase_across_record_sequences() {
        let mut list = RevocationList::default();
        assert_eq!(list.next_crl_number, 1, "an empty deny list issues CRL #1");
        let mut seen = Vec::new();
        for i in 0..5 {
            list.record(entry(&format!("{i:04x}"), "key-compromise"));
            seen.push(list.next_crl_number);
        }
        assert!(
            seen.windows(2).all(|w| w[0] < w[1]),
            "every mutation advances the number: {seen:?}"
        );
        // Reading the number (what CRL issuance does) never mutates it.
        let before = list.next_crl_number;
        let _ = list.next_crl_number;
        assert_eq!(list.next_crl_number, before);
    }

    #[test]
    fn legacy_deny_list_backfills_to_the_old_formula() {
        // A pre-counter revocations.json: 3 entries, no next_crl_number
        // field. The old formula last issued `len() + 1` = 4, so the
        // backfill must land exactly there — no repeat, no regression.
        let dir = tempfile::tempdir().unwrap();
        let mut legacy = r#"{
  "entries": [
    {"serial": "0001", "issuer": "control", "reason": "operator-requested", "revoked_at": "2026-09-01T00:00:00Z", "pack_digest": null},
    {"serial": "0002", "issuer": "control", "reason": "superseded", "revoked_at": "2026-09-02T00:00:00Z", "pack_digest": null},
    {"serial": "0003", "issuer": "workspace/main", "reason": "operator-requested", "revoked_at": "2026-09-03T00:00:00Z", "pack_digest": null}
  ]
}"#
        .to_owned();
        legacy.push('\n');
        std::fs::write(dir.path().join("revocations.json"), legacy).unwrap();
        let mut list = RevocationList::load(dir.path()).unwrap();
        assert_eq!(list.entries.len(), 3);
        assert_eq!(list.next_crl_number, 4);
        // The next mutation lands strictly above the backfill.
        list.record(entry("0004", "key-compromise"));
        assert_eq!(list.next_crl_number, 5);
    }

    #[test]
    fn issued_crl_carries_the_rfc_reason_and_number() {
        let dir = tempfile::tempdir().unwrap();
        let store = IssuerStore::open(dir.path());
        store.ensure_realm().unwrap();
        let mut list = RevocationList::default();
        list.record(entry("00ff", "key-compromise"));
        list.record(entry("00ee", "cessation-of-operation"));
        list.record(entry("00dd", "superseded"));
        list.record(entry("00cc", "operator-requested")); // legacy free text
        let crl = build_crl(
            &store.realm_issuer().unwrap(),
            &list.entries,
            list.next_crl_number,
        )
        .unwrap();
        // Parse the signed CRL back: the reason codes and number are what a
        // strict consumer (rustls / RFC 5280) actually sees.
        use x509_parser::prelude::FromDer as _;
        let (_, pem) = x509_parser::pem::parse_x509_pem(crl.as_bytes()).unwrap();
        assert_eq!(pem.label, "X509 CRL");
        let (_, parsed) =
            x509_parser::revocation_list::CertificateRevocationList::from_der(&pem.contents)
                .unwrap();
        assert_eq!(
            parsed.crl_number().map(|n| n.to_string()),
            Some(list.next_crl_number.to_string()),
            "the CRL carries the monotonic counter"
        );
        let mut reasons = std::collections::BTreeMap::new();
        for revoked in parsed.iter_revoked_certificates() {
            let serial = revoked.raw_serial_as_string();
            let reason = revoked.reason_code().map(|(_, code)| code.0);
            reasons.insert(serial, reason);
        }
        // `raw_serial_as_string` spells DER serials colon-separated.
        assert_eq!(
            reasons.get("00:ff").copied().flatten(),
            Some(1),
            "key-compromise → RFC reason 1 (KeyCompromise), got {:?}",
            reasons
        );
        assert_eq!(
            reasons.get("00:ee").copied().flatten(),
            Some(5),
            "cessation-of-operation"
        );
        assert_eq!(
            reasons.get("00:dd").copied().flatten(),
            Some(4),
            "superseded"
        );
        assert_eq!(
            reasons.get("00:cc").copied().flatten(),
            None,
            "legacy free text → unspecified: rcgen omits the extension (the \
             RFC-equivalent spelling) — never removeFromCrl (8), got {:?}",
            reasons
        );
    }

    #[test]
    fn reason_mapping_is_total() {
        use RevocationReason::*;
        assert!(matches!(crl_reason_code("key-compromise"), KeyCompromise));
        assert!(matches!(
            crl_reason_code("cessation-of-operation"),
            CessationOfOperation
        ));
        assert!(matches!(crl_reason_code("superseded"), Superseded));
        // Anything else — legacy strings, typos, empty — is unspecified.
        for other in ["operator-requested", "test", "", "keyCompromise"] {
            assert!(matches!(crl_reason_code(other), Unspecified), "{other:?}");
        }
    }
}
