//! Layer 1 — in-memory issuance primitives.
//!
//! Pure PEM in / PEM out; no filesystem access, no layout knowledge. Layer 2
//! ([`crate::ops`]) and the test kit build on this, which keeps the whole
//! repository on a single signing implementation.

use std::sync::atomic::{AtomicU64, Ordering as AtomicOrdering};

use crate::{Error, Result, SanName, Validity};

static LEAF_SERIAL: AtomicU64 = AtomicU64::new(1);

fn issue_err(context: &'static str) -> impl Fn(rcgen::Error) -> Error {
    move |e| Error::Issue {
        context: context.to_owned(),
        source: e,
    }
}

/// PEM material for a freshly built tenant CA.
pub struct CaMaterial {
    pub cert_pem: String,
    pub key_pem: String,
}

/// PEM material for one leaf pair (hub server or agent client).
pub struct LeafMaterial {
    pub cert_pem: String,
    pub key_pem: String,
    pub serial_number: Vec<u8>,
}

/// Builds a self-signed tenant CA. CN = `Interflow tenant CA: {tenant}`,
/// KeyUsage = KeyCertSign + CrlSign, validity per `validity`.
pub fn build_ca(tenant: &str, validity: Validity) -> Result<CaMaterial> {
    let ca = LoadedCa::generate(tenant, validity)?;
    Ok(CaMaterial {
        cert_pem: ca.cert_pem().to_owned(),
        key_pem: ca.key_pem(),
    })
}

/// A tenant CA loaded from persisted PEM material, ready to issue further
/// leaves (the signing context is rebuilt from the certificate itself via
/// rcgen's `Issuer::from_ca_cert_pem`).
pub struct LoadedCa {
    cert_pem: String,
    issuer: rcgen::Issuer<'static, rcgen::KeyPair>,
}

impl LoadedCa {
    /// Generates a fresh self-signed CA and **retains the signing
    /// context**: later leaf issuance goes straight through the in-memory
    /// [`rcgen::Issuer`], with no PEM re-parse round-trip.
    pub fn generate(tenant: &str, validity: Validity) -> Result<Self> {
        use rcgen::{BasicConstraints, CertificateParams, DnType, IsCa, KeyPair, KeyUsagePurpose};
        crate::validate_name("tenant", tenant)?;
        let mut params =
            CertificateParams::new(vec![]).map_err(issue_err("failed to build CA params"))?;
        params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
        params
            .distinguished_name
            .push(DnType::CommonName, format!("Interflow tenant CA: {tenant}"));
        params.not_before = validity.not_before;
        params.not_after = validity.not_after;
        let key = KeyPair::generate().map_err(issue_err("failed to generate CA key"))?;
        let cert_pem = params
            .self_signed(&key)
            .map_err(issue_err("failed to self-sign CA"))?
            .pem();
        Ok(Self {
            cert_pem,
            issuer: rcgen::Issuer::new(params, key),
        })
    }

    pub fn from_material(ca: &CaMaterial) -> Result<Self> {
        Self::from_pem_pair(&ca.cert_pem, &ca.key_pem)
    }

    pub fn from_pem_pair(cert_pem: &str, key_pem: &str) -> Result<Self> {
        let key = rcgen::KeyPair::from_pem(key_pem)
            .map_err(|e| Error::Parse(format!("tenant CA private key: {e}")))?;
        let issuer = rcgen::Issuer::from_ca_cert_pem(cert_pem, key)
            .map_err(|e| Error::Parse(format!("tenant CA certificate: {e}")))?;
        Ok(Self {
            cert_pem: cert_pem.to_owned(),
            issuer,
        })
    }

    /// The CA certificate PEM (the trust anchor agents and the hub consume).
    pub fn cert_pem(&self) -> &str {
        &self.cert_pem
    }

    /// The CA private key PEM (for persisting freshly generated material).
    pub fn key_pem(&self) -> String {
        self.issuer.key().serialize_pem()
    }

    /// Issues the hub server certificate: CN = the first name, SAN = exactly
    /// the given names, EKU = ServerAuth.
    pub fn build_server_cert(&self, names: &[SanName], validity: Validity) -> Result<LeafMaterial> {
        if names.is_empty() {
            return Err(Error::Mismatch(
                "at least one hub name is required (pass --hub-dns, or use the local-development default)"
                    .to_owned(),
            ));
        }
        self.build_leaf(&names[0].to_string(), names, true, validity)
    }

    /// Issues an agent client certificate: CN == `agent_id` (the hub's
    /// identity binding), EKU = ClientAuth, no SAN (client certs are not
    /// dialed by name).
    pub fn build_client_cert(&self, agent_id: &str, validity: Validity) -> Result<LeafMaterial> {
        crate::validate_name("agent", agent_id)?;
        self.build_leaf(agent_id, &[], false, validity)
    }

    /// Issues an initially empty CRL with a one-week next-update window.
    ///
    /// Revocation entry APIs can be layered on the same rcgen CRL builder;
    /// the first shipped contract is a valid, signed CRL so verifiers can be
    /// configured fail-closed from day one.
    pub fn build_empty_crl(&self) -> Result<String> {
        use rcgen::{CertificateRevocationListParams, KeyIdMethod, SerialNumber};
        let now = time::OffsetDateTime::now_utc();
        let params = CertificateRevocationListParams {
            this_update: now,
            next_update: now + time::Duration::days(7),
            crl_number: SerialNumber::from(1u64),
            issuing_distribution_point: None,
            revoked_certs: Vec::new(),
            key_identifier_method: KeyIdMethod::Sha256,
        };
        let crl = params
            .signed_by(&self.issuer)
            .map_err(issue_err("CRL signing"))?;
        crl.pem().map_err(issue_err("CRL PEM encoding"))
    }

    /// Issues a CRL revoking the supplied leaf certificate serial.
    pub fn build_crl_revoking(&self, serial_number: &[u8]) -> Result<String> {
        use rcgen::{
            CertificateRevocationListParams, KeyIdMethod, RevocationReason, RevokedCertParams,
            SerialNumber,
        };
        let now = time::OffsetDateTime::now_utc();
        let params = CertificateRevocationListParams {
            this_update: now,
            next_update: now + time::Duration::days(7),
            crl_number: SerialNumber::from(2u64),
            issuing_distribution_point: None,
            revoked_certs: vec![RevokedCertParams {
                serial_number: SerialNumber::from_slice(serial_number),
                revocation_time: now,
                reason_code: Some(RevocationReason::KeyCompromise),
                invalidity_date: None,
            }],
            key_identifier_method: KeyIdMethod::Sha256,
        };
        params
            .signed_by(&self.issuer)
            .map_err(issue_err("revoked CRL signing"))?
            .pem()
            .map_err(issue_err("CRL PEM encoding"))
    }

    fn build_leaf(
        &self,
        cn: &str,
        names: &[SanName],
        server_auth: bool,
        validity: Validity,
    ) -> Result<LeafMaterial> {
        use rcgen::{CertificateParams, DnType, KeyPair, SerialNumber};
        // CertificateParams::new classifies each string as an IP SAN when it
        // parses as an IpAddr, else a DNS SAN.
        let san_strings: Vec<String> = names.iter().map(ToString::to_string).collect();
        let mut params = CertificateParams::new(san_strings)
            .map_err(issue_err("failed to build certificate params"))?;
        let serial = SerialNumber::from(LEAF_SERIAL.fetch_add(1, AtomicOrdering::Relaxed));
        params.serial_number = Some(serial.clone());
        params.distinguished_name.push(DnType::CommonName, cn);
        params.extended_key_usages = vec![if server_auth {
            rcgen::ExtendedKeyUsagePurpose::ServerAuth
        } else {
            rcgen::ExtendedKeyUsagePurpose::ClientAuth
        }];
        params.not_before = validity.not_before;
        params.not_after = validity.not_after;
        let key = KeyPair::generate().map_err(issue_err("failed to generate key"))?;
        let cert = params
            .signed_by(&key, &self.issuer)
            .map_err(issue_err("failed to sign certificate"))?;
        Ok(LeafMaterial {
            cert_pem: cert.pem(),
            key_pem: key.serialize_pem(),
            serial_number: serial.to_bytes(),
        })
    }
}
