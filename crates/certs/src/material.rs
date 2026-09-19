//! Layer 1 — in-memory issuance primitives.
//!
//! Pure PEM in / PEM out; no filesystem access, no layout knowledge. Layer 2
//! ([`crate::ops`]) and the test kit build on this, which keeps the whole
//! repository on a single signing implementation.

use crate::{Error, Result, SanName, Validity};

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
}

/// Builds a self-signed tenant CA. CN = `Interflow tenant CA: {tenant}`,
/// KeyUsage = KeyCertSign + CrlSign, validity per `validity`.
pub fn build_ca(tenant: &str, validity: Validity) -> Result<CaMaterial> {
    use rcgen::{
        BasicConstraints, CertificateParams, CertifiedIssuer, DnType, IsCa, KeyPair,
        KeyUsagePurpose,
    };
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
    let key_pem = key.serialize_pem();
    let issuer =
        CertifiedIssuer::self_signed(params, key).map_err(issue_err("failed to self-sign CA"))?;
    Ok(CaMaterial {
        cert_pem: issuer.pem(),
        key_pem,
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

    fn build_leaf(
        &self,
        cn: &str,
        names: &[SanName],
        server_auth: bool,
        validity: Validity,
    ) -> Result<LeafMaterial> {
        use rcgen::{CertificateParams, DnType, KeyPair};
        // CertificateParams::new classifies each string as an IP SAN when it
        // parses as an IpAddr, else a DNS SAN.
        let san_strings: Vec<String> = names.iter().map(ToString::to_string).collect();
        let mut params = CertificateParams::new(san_strings)
            .map_err(issue_err("failed to build certificate params"))?;
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
        })
    }
}
