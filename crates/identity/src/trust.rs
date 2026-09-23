//! Trust Bundles: versioned, exportable collections of *public* verification
//! material — issuer certificates, the policy verifying key, and (future)
//! CRL references. No private material ever enters a Trust Bundle.

use crate::{Error, Result};
use interflow_contract::Generation;
use interflow_util::sha256_hex;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::path::Path;

/// Trust-bundle metadata (`bundle.toml`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TrustBundleMetadata {
    pub realm: String,
    /// Rotation generation shared with the enclosing Credential Pack.
    pub generation: Generation,
    /// issuer name → `sha256:<hex>` certificate fingerprint.
    /// Names: `control` (the realm issuer) and `workspace/<name>`.
    pub issuers: BTreeMap<String, String>,
    /// ed25519 policy verifying key (hex) — the anti-rollback anchor for
    /// signed runtime policy.
    pub policy_key: String,
    pub created: String,
}

/// A loaded trust bundle: metadata plus the PEM certificate per issuer.
#[derive(Debug, Clone)]
pub struct TrustBundle {
    pub metadata: TrustBundleMetadata,
    /// issuer name → certificate PEM (matches `metadata.issuers` keys).
    pub issuers: BTreeMap<String, String>,
}

impl TrustBundle {
    /// Builds a bundle from issuer PEMs, computing fingerprints.
    pub fn build(
        realm: &str,
        generation: Generation,
        policy_key: &str,
        issuers: BTreeMap<String, String>,
    ) -> Result<Self> {
        let mut fingerprints = BTreeMap::new();
        for (name, pem) in &issuers {
            let der = crate::pem_certs(pem.as_bytes())?
                .into_iter()
                .next()
                .ok_or_else(|| {
                    Error::trust(format!("issuer {name:?}: PEM carries no certificate"))
                })?;
            fingerprints.insert(name.clone(), format!("sha256:{}", sha256_hex(&der)));
        }
        Ok(Self {
            metadata: TrustBundleMetadata {
                realm: realm.to_owned(),
                generation,
                issuers: fingerprints,
                policy_key: policy_key.to_owned(),
                created: time::OffsetDateTime::now_utc()
                    .format(&time::format_description::well_known::Rfc3339)
                    .map_err(|e| Error::trust("timestamp".to_string()).with_source(e))?,
            },
            issuers,
        })
    }

    /// Writes the bundle as a directory (`bundle.toml` + one CRT per issuer).
    pub fn save(&self, dir: &Path) -> Result<()> {
        std::fs::create_dir_all(dir).map_err(|e| Error::Io {
            path: dir.display().to_string(),
            source: e,
        })?;
        let toml = toml::to_string_pretty(&self.metadata)
            .map_err(|e| Error::serialize("trust bundle".to_string()).with_source(e))?;
        std::fs::write(dir.join("bundle.toml"), toml).map_err(|e| Error::Io {
            path: dir.join("bundle.toml").display().to_string(),
            source: e,
        })?;
        for (name, pem) in &self.issuers {
            let file = dir.join(format!("{}.crt", issuer_file_stem(name)));
            std::fs::write(&file, pem).map_err(|e| Error::Io {
                path: file.display().to_string(),
                source: e,
            })?;
        }
        Ok(())
    }

    /// Loads and verifies a bundle directory (fingerprints re-checked).
    pub fn load(dir: &Path) -> Result<Self> {
        let toml_bytes = std::fs::read(dir.join("bundle.toml")).map_err(|e| Error::Io {
            path: dir.join("bundle.toml").display().to_string(),
            source: e,
        })?;
        let metadata: TrustBundleMetadata =
            toml::from_str(&String::from_utf8_lossy(&toml_bytes))
                .map_err(|e| Error::trust("bundle.toml parse".to_string()).with_source(e))?;
        let mut issuers = BTreeMap::new();
        for name in metadata.issuers.keys() {
            let file = dir.join(format!("{}.crt", issuer_file_stem(name)));
            let pem = std::fs::read_to_string(&file).map_err(|e| Error::Io {
                path: file.display().to_string(),
                source: e,
            })?;
            issuers.insert(name.clone(), pem);
        }
        let bundle = Self { metadata, issuers };
        bundle.verify_fingerprints()?;
        Ok(bundle)
    }

    /// Re-computes every issuer fingerprint against the metadata.
    pub fn verify_fingerprints(&self) -> Result<()> {
        for (name, expected) in &self.metadata.issuers {
            let Some(pem) = self.issuers.get(name) else {
                return Err(Error::trust(format!(
                    "issuer {name:?} is declared but its certificate is missing from the bundle"
                )));
            };
            let der = crate::pem_certs(pem.as_bytes())?
                .into_iter()
                .next()
                .ok_or_else(|| {
                    Error::trust(format!("issuer {name:?}: PEM carries no certificate"))
                })?;
            let actual = format!("sha256:{}", sha256_hex(&der));
            if &actual != expected {
                return Err(Error::trust(format!(
                    "issuer {name:?} fingerprint mismatch: bundle says {expected}, certificate \
                     is {actual} — the bundle is inconsistent or was tampered with"
                )));
            }
        }
        Ok(())
    }

    /// Digest of the canonical serialized metadata.
    pub fn digest(&self) -> Result<String> {
        let toml = toml::to_string_pretty(&self.metadata)
            .map_err(|e| Error::serialize("trust bundle".to_string()).with_source(e))?;
        Ok(format!("sha256:{}", sha256_hex(toml.as_bytes())))
    }
}

fn issuer_file_stem(name: &str) -> String {
    name.replace('/', "-")
}
