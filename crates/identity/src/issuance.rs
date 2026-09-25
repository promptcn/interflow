//! The offline realm issuer (operator machine only).
//!
//! Issues every identity object with URI SAN principal paths:
//!
//! - realm issuer CA — signs the control endpoint identities (expose ingress
//!   nodes and site-to-site hub servers) plus the realm-scoped hub client
//!   principal that authorizes hub renewal traffic;
//! - workspace issuer CA (one per workspace) — signs that workspace's
//!   agents **and** its workspace-scoped ingress principals;
//! - ed25519 policy signing key — signs runtime policy snapshots.
//!
//! Hard boundary: issuer private keys live only under the issuer store on
//! the operator machine. They are never placed into Credential Packs, the
//! control endpoint, the ingress, or agents.

use crate::{Error, PrincipalKind, PrincipalPath, Result, validate_name};
use ed25519_dalek::{Signer, SigningKey, Verifier, VerifyingKey};
use interflow_contract::Generation;
use serde::{Deserialize, Serialize};

use interflow_util::sha256_hex;
use std::path::{Path, PathBuf};
use time::{Duration, OffsetDateTime};

/// CA validity: rotation is a conscious, rare act.
pub const CA_VALIDITY_DAYS: i64 = 3650;

pub const DEFAULT_LEAF_TTL_SECONDS: u64 = 24 * 60 * 60;
pub const MIN_LEAF_TTL_SECONDS: u64 = 60 * 60;
/// Registrar-mode upper bound: credentials renew unattended, so they stay
/// short-lived.
pub const MAX_LEAF_TTL_SECONDS: u64 = 24 * 60 * 60;
/// Offline-mode bounds: no registrar, so the leaf itself carries the
/// deployment's rotation cadence.
pub const OFFLINE_MIN_LEAF_TTL_SECONDS: u64 = 7 * 24 * 60 * 60;
pub const OFFLINE_MAX_LEAF_TTL_SECONDS: u64 = 365 * 24 * 60 * 60;
pub const OFFLINE_DEFAULT_LEAF_TTL_SECONDS: u64 = 90 * 24 * 60 * 60;
/// Absolute ceiling [`LeafTtl`] accepts — mode-specific bounds are enforced
/// by the manifest layer.
pub const ABSOLUTE_MAX_LEAF_TTL_SECONDS: u64 = OFFLINE_MAX_LEAF_TTL_SECONDS;

/// A bounded end-entity TTL.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LeafTtl(Duration);

impl LeafTtl {
    #[must_use]
    pub fn new(duration: Duration) -> Self {
        assert!(
            duration >= Duration::seconds(MIN_LEAF_TTL_SECONDS as i64)
                && duration <= Duration::seconds(ABSOLUTE_MAX_LEAF_TTL_SECONDS as i64),
            "leaf TTL must be between 1h and 365d"
        );
        Self(duration)
    }

    #[must_use]
    pub fn default_ttl() -> Self {
        Self(Duration::seconds(DEFAULT_LEAF_TTL_SECONDS as i64))
    }

    /// Creates a TTL from seconds, returning an error outside 1h–365d.
    pub fn from_seconds(seconds: i64) -> Result<Self> {
        if !(MIN_LEAF_TTL_SECONDS as i64..=ABSOLUTE_MAX_LEAF_TTL_SECONDS as i64).contains(&seconds)
        {
            return Err(crate::Error::issuance(
                "leaf TTL must be between 1h and 365d".to_owned(),
            ));
        }
        Ok(Self(Duration::seconds(seconds)))
    }

    #[must_use]
    pub fn duration(self) -> Duration {
        self.0
    }
}

impl Default for LeafTtl {
    fn default() -> Self {
        Self::default_ttl()
    }
}

/// A client-generated CSR and the private key that owns it.
#[derive(Debug, Clone)]
pub struct CsrMaterial {
    pub csr_pem: String,
    pub key_pem: String,
}

// ---------------------------------------------------------------------------
// In-memory material
// ---------------------------------------------------------------------------

/// A freshly issued identity: the principal plus its credential material.
#[derive(Debug, Clone)]
pub struct IdentityMaterial {
    pub principal: PrincipalPath,
    /// Leaf certificate PEM (chain anchor is distributed separately via the
    /// Trust Bundle; `chain_pem` carries leaf+issuer for bundle-style
    /// consumers).
    pub cert_pem: String,
    /// Leaf followed by the issuing CA PEM.
    pub chain_pem: String,
    pub key_pem: String,
    pub not_after: OffsetDateTime,
    pub serial: String,
}

/// A loaded issuer (realm or workspace) ready to sign leaves.
pub struct LoadedIssuer {
    cert_pem: String,
    key_pem: String,
    issuer: rcgen::Issuer<'static, rcgen::KeyPair>,
}

/// Serial-number spelling shared by every consumer: hex of the serial in
/// minimal positive-integer form (what the DER encoding writes minus
/// redundant leading zeros and the sign byte). The previous
/// `hex::encode(serial.to_bytes())` spelled the raw hash slice, which
/// mismatched the x509-parsed spelling (`canonical_serial(raw_serial())`)
/// for the ~1/256 serials whose first byte is zero — renewal confirmations
/// comparing the two spellings then spuriously rejected valid renewals.
fn canonical_serial_hex(bytes: &[u8]) -> String {
    let mut start = 0;
    while start + 1 < bytes.len() && bytes[start] == 0 {
        start += 1;
    }
    hex::encode(&bytes[start..])
}

impl LoadedIssuer {
    /// Loads an issuer from a persisted PEM pair.
    pub(crate) fn from_pem_pair(cert_pem: &str, key_pem: &str) -> Result<Self> {
        let key = rcgen::KeyPair::from_pem(key_pem)
            .map_err(|e| Error::issuance("issuer private key".to_string()).with_source(e))?;
        let issuer = rcgen::Issuer::from_ca_cert_pem(cert_pem, key)
            .map_err(|e| Error::issuance("issuer certificate".to_string()).with_source(e))?;
        Ok(Self {
            cert_pem: cert_pem.to_owned(),
            key_pem: key_pem.to_owned(),
            issuer,
        })
    }

    /// The issuer certificate PEM (a Trust Bundle entry).
    pub fn cert_pem(&self) -> &str {
        &self.cert_pem
    }

    /// The issuer private key PEM — operator machine only.
    pub fn key_pem(&self) -> &str {
        &self.key_pem
    }

    /// SHA-256 fingerprint (hex) of the issuer certificate.
    pub fn fingerprint(&self) -> Result<String> {
        let certs = crate::pem_certs(self.cert_pem.as_bytes())?;
        let der = certs
            .first()
            .ok_or_else(|| Error::issuance("issuer PEM carries no certificate".to_owned()))?;
        Ok(sha256_hex(der))
    }

    fn issue(
        &self,
        principal: &PrincipalPath,
        dns_names: &[String],
        server_auth: bool,
        ttl: LeafTtl,
    ) -> Result<IdentityMaterial> {
        use rcgen::{KeyPair, SerialNumber};

        let mut params = rcgen::CertificateParams::default();
        configure_certificate_params(&mut params, principal, dns_names, server_auth)?;
        let serial = SerialNumber::from_slice(
            &sha256_hex(
                format!(
                    "{}-{}",
                    principal,
                    OffsetDateTime::now_utc().unix_timestamp_nanos()
                )
                .as_bytes(),
            )
            .as_bytes()[..16],
        );
        params.serial_number = Some(serial.clone());
        let now = OffsetDateTime::now_utc();
        params.not_before = now - time::Duration::hours(1);
        params.not_after = now + ttl.duration();
        let key = KeyPair::generate().map_err(err("key generation"))?;
        let cert = params
            .signed_by(&key, &self.issuer)
            .map_err(err("signing"))?;
        Ok(IdentityMaterial {
            principal: principal.clone(),
            cert_pem: cert.pem(),
            chain_pem: format!("{}{}", cert.pem(), self.cert_pem),
            key_pem: key.serialize_pem(),
            not_after: params.not_after,
            serial: canonical_serial_hex(&serial.to_bytes()),
        })
    }

    pub fn issue_csr(
        &self,
        principal: &PrincipalPath,
        dns_names: &[String],
        server_auth: bool,
        ttl: LeafTtl,
        csr_pem: &str,
    ) -> Result<IdentityMaterial> {
        let requested = rcgen::CertificateSigningRequestParams::from_pem(csr_pem)
            .map_err(err("certificate signing request"))?;
        let mut params = requested.params;
        configure_certificate_params(&mut params, principal, dns_names, server_auth)?;
        let serial = rcgen::SerialNumber::from_slice(
            &sha256_hex(
                format!(
                    "{}-{}",
                    principal,
                    OffsetDateTime::now_utc().unix_timestamp_nanos()
                )
                .as_bytes(),
            )
            .as_bytes()[..16],
        );
        params.serial_number = Some(serial.clone());
        let now = OffsetDateTime::now_utc();
        params.not_before = now - time::Duration::hours(1);
        params.not_after = now + ttl.duration();
        let cert = params
            .signed_by(&requested.public_key, &self.issuer)
            .map_err(err("CSR signing"))?;
        Ok(IdentityMaterial {
            principal: principal.clone(),
            cert_pem: cert.pem(),
            chain_pem: format!("{}{}", cert.pem(), self.cert_pem),
            key_pem: String::new(),
            not_after: params.not_after,
            serial: canonical_serial_hex(&serial.to_bytes()),
        })
    }
}

fn configure_certificate_params(
    params: &mut rcgen::CertificateParams,
    principal: &PrincipalPath,
    dns_names: &[String],
    server_auth: bool,
) -> Result<()> {
    let uri: rcgen::SanType = rcgen::SanType::URI(
        principal
            .to_string()
            .parse()
            .map_err(err("principal URI SAN"))?,
    );
    let mut san_types = vec![uri];
    for name in dns_names {
        if let Ok(ip) = name.parse::<std::net::IpAddr>() {
            san_types.push(rcgen::SanType::IpAddress(ip));
        } else {
            san_types.push(rcgen::SanType::DnsName(
                name.parse().map_err(err("DNS SAN"))?,
            ));
        }
    }
    params.distinguished_name = rcgen::DistinguishedName::new();
    params.subject_alt_names = san_types;
    params
        .distinguished_name
        .push(rcgen::DnType::CommonName, principal.node.clone());
    params.extended_key_usages = vec![if server_auth {
        rcgen::ExtendedKeyUsagePurpose::ServerAuth
    } else {
        rcgen::ExtendedKeyUsagePurpose::ClientAuth
    }];
    params.serial_number = None;
    params.not_before = OffsetDateTime::UNIX_EPOCH;
    params.not_after = OffsetDateTime::UNIX_EPOCH;
    params.is_ca = rcgen::IsCa::ExplicitNoCa;
    params.key_usages = vec![rcgen::KeyUsagePurpose::DigitalSignature];
    Ok(())
}

pub fn generate_csr(
    principal: &PrincipalPath,
    dns_names: &[String],
    server_auth: bool,
) -> Result<CsrMaterial> {
    let mut params = rcgen::CertificateParams::default();
    configure_certificate_params(&mut params, principal, dns_names, server_auth)?;
    let key = rcgen::KeyPair::generate().map_err(err("key generation"))?;
    let csr = params
        .serialize_request(&key)
        .map_err(err("certificate signing request"))?;
    let csr_pem = csr.pem().map_err(err("certificate signing request PEM"))?;
    Ok(CsrMaterial {
        csr_pem,
        key_pem: key.serialize_pem(),
    })
}

fn err(context: &'static str) -> impl Fn(rcgen::Error) -> Error {
    move |e| Error::issuance(context).with_source(e)
}

// ---------------------------------------------------------------------------
// Issuer store (operator machine layout)
// ---------------------------------------------------------------------------

/// The file the store's manifest binding lives in (see [`StoreBinding`]).
const BINDING_FILE: &str = "binding.json";
const APPLIED_FILE: &str = "applied.json";

/// What `plan apply` last put into the world — the diff base that lets the
/// next apply distinguish "the manifest's identity face changed" (re-render
/// packs) from "only the mesh rule face changed" (sign + publish a policy
/// update; no identity is re-signed). Stored in the issuer store next to
/// the binding contract.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AppliedState {
    /// sha256 of the manifest with every agent's mesh rule lists emptied —
    /// the identity/trust/dial face. Unchanged + policy changed = the
    /// policy-only fast path.
    pub stripped_manifest_digest: String,
    /// The live policy generation (embedded at full render, incremented per
    /// policy-only update).
    pub policy_generation: Generation,
    /// sha256 of the live policy's canonical bytes (at `policy_generation`).
    pub policy_digest: String,
    /// node → sha256 of its rendered pack directory (SHA256SUMS content).
    #[serde(default)]
    pub packs: std::collections::BTreeMap<String, String>,
}

/// The issuer store's binding to one manifest lineage — the persisted half
/// of the trust-root isolation contract ((internal design notes), 「一个
/// realm 一个 manifest」): one store signs exactly one realm, driven by
/// exactly one manifest file. A second deployment scenario gets its own
/// realm id and its own `--issuer` directory, so a leaked pack's blast
/// radius stays inside the scenario that issued it.
///
/// `manifest_path` (canonical, absolute) is the lineage key: editing the
/// same file rebinds silently, while a *different* manifest file claiming
/// the same realm trips the guard in `plan apply`/`rotate`. The digest is
/// human context for that error message, not a second key.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StoreBinding {
    /// The realm this store was created for.
    pub realm: String,
    /// Canonical absolute path of the manifest that bound the store.
    pub manifest_path: String,
    /// sha256 of the manifest bytes at bind time (short context, not a key).
    pub manifest_digest: String,
    /// RFC 3339 timestamp of the (re)bind.
    pub bound_at: String,
}

impl StoreBinding {
    /// Captures the binding facts for `manifest` at `manifest_path` now.
    pub fn capture(manifest: &crate::manifest::Manifest, manifest_path: &Path) -> Result<Self> {
        let canonical = manifest_path
            .canonicalize()
            .unwrap_or_else(|_| manifest_path.to_owned());
        let bytes = std::fs::read(&canonical).map_err(|e| Error::Io {
            path: canonical.display().to_string(),
            source: e,
        })?;
        let bound_at = OffsetDateTime::now_utc()
            .format(&time::format_description::well_known::Rfc3339)
            .map_err(|e| Error::issuance("binding timestamp".to_string()).with_source(e))?;
        Ok(Self {
            realm: manifest.realm.id.clone(),
            manifest_path: canonical.display().to_string(),
            manifest_digest: sha256_hex(&bytes),
            bound_at,
        })
    }
}

/// The on-disk issuer store:
///
/// ```text
/// <root>/
///   realm-issuer.crt|.key      # signs control endpoint identities
///   policy-signing.key|.pub    # ed25519 runtime-policy signer
///   binding.json               # the one-realm / one-manifest contract
///   workspaces/<ws>-issuer.crt|.key
/// ```
///
/// The whole directory is operator-secret. Distribute only Trust Bundles and
/// Credential Packs rendered from it.
#[derive(Debug, Clone)]
pub struct IssuerStore {
    root: PathBuf,
}

impl IssuerStore {
    /// Opens (does not create) the store.
    pub fn open(root: impl AsRef<Path>) -> Self {
        Self {
            root: root.as_ref().to_owned(),
        }
    }

    /// The operator-store root.
    #[must_use]
    pub fn root_path(&self) -> &Path {
        &self.root
    }

    fn read(&self, rel: &str) -> Result<String> {
        let path = self.root.join(rel);
        std::fs::read_to_string(&path).map_err(|e| Error::Io {
            path: path.display().to_string(),
            source: e,
        })
    }

    fn write_private(&self, rel: &str, contents: &str) -> Result<PathBuf> {
        let path = self.root.join(rel);
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).map_err(|e| Error::Io {
                path: parent.display().to_string(),
                source: e,
            })?;
        }
        std::fs::write(&path, contents).map_err(|e| Error::Io {
            path: path.display().to_string(),
            source: e,
        })?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mut perms = std::fs::metadata(&path)
                .map_err(|e| Error::Io {
                    path: path.display().to_string(),
                    source: e,
                })?
                .permissions();
            perms.set_mode(0o600);
            std::fs::set_permissions(&path, perms).map_err(|e| Error::Io {
                path: path.display().to_string(),
                source: e,
            })?;
        }
        Ok(path)
    }

    /// Ensures the realm issuer CA and the policy signing key exist.
    /// Idempotent: existing material is loaded, never silently replaced.
    pub fn ensure_realm(&self) -> Result<()> {
        let cert = self.root.join("realm-issuer.crt");
        let key = self.root.join("realm-issuer.key");
        match (cert.exists(), key.exists()) {
            (true, true) => {
                Self::load_issuer_at(&cert, &key)?;
                Ok(())
            }
            (false, false) => {
                let material = build_ca(
                    "Interflow realm issuer",
                    CA_VALIDITY_DAYS,
                    CaProfile::Control,
                )?;
                self.write_private("realm-issuer.key", &material.key_pem)?;
                std::fs::write(self.root.join("realm-issuer.crt"), &material.cert_pem).map_err(
                    |e| Error::Io {
                        path: self.root.join("realm-issuer.crt").display().to_string(),
                        source: e,
                    },
                )?;
                Ok(())
            }
            (a, b) => Err(Error::issuance(format!(
                "incomplete realm issuer pair under {} (cert exists: {a}, key exists: {b}) — \
                 restore the missing file or use a fresh issuer directory",
                self.root.display()
            ))),
        }
    }

    /// Ensures a workspace issuer CA exists (one per workspace).
    pub fn ensure_workspace(&self, workspace: &str) -> Result<()> {
        validate_name("workspace", workspace)?;
        let rel = format!("workspaces/{workspace}-issuer");
        let cert = self.root.join(format!("{rel}.crt"));
        let key = self.root.join(format!("{rel}.key"));
        match (cert.exists(), key.exists()) {
            (true, true) => {
                Self::load_issuer_at(&cert, &key)?;
                Ok(())
            }
            (false, false) => {
                let material = build_ca(
                    &format!("Interflow workspace issuer: {workspace}"),
                    CA_VALIDITY_DAYS,
                    CaProfile::Workspace,
                )?;
                self.write_private(&format!("{rel}.key"), &material.key_pem)?;
                std::fs::write(&cert, &material.cert_pem).map_err(|e| Error::Io {
                    path: cert.display().to_string(),
                    source: e,
                })?;
                Ok(())
            }
            (a, b) => Err(Error::issuance(format!(
                "incomplete workspace issuer pair for {workspace:?} (cert exists: {a}, key \
                 exists: {b})",
            ))),
        }
    }

    /// Ensures the ed25519 policy signing keypair exists.
    pub fn ensure_policy_key(&self) -> Result<()> {
        let secret = self.root.join("policy-signing.key");
        let public = self.root.join("policy-signing.pub");
        if secret.exists() && public.exists() {
            self.policy_signer()?;
            return Ok(());
        }
        if secret.exists() || public.exists() {
            return Err(Error::issuance(
                "incomplete policy signing keypair under issuer store".to_owned(),
            ));
        }
        let mut seed = [0u8; 32];
        // `getrandom::Error` does not implement `std::error::Error`, so the
        // message is the only place the cause can surface.
        getrandom::fill(&mut seed)
            .map_err(|e| Error::issuance(format!("policy key entropy: {e}")))?;
        let signing = SigningKey::from_bytes(&seed);
        self.write_private("policy-signing.key", &hex::encode(signing.to_bytes()))?;
        std::fs::write(&public, hex::encode(signing.verifying_key().as_bytes())).map_err(|e| {
            Error::Io {
                path: public.display().to_string(),
                source: e,
            }
        })?;
        Ok(())
    }

    /// Loads the realm issuer.
    pub fn realm_issuer(&self) -> Result<LoadedIssuer> {
        Self::load_issuer_at(
            &self.root.join("realm-issuer.crt"),
            &self.root.join("realm-issuer.key"),
        )
    }

    /// Reads the store's manifest binding, if any. Stores created before
    /// bindings existed have none — the next `plan apply`/`rotate` records
    /// one.
    pub fn binding(&self) -> Result<Option<StoreBinding>> {
        let path = self.root.join(BINDING_FILE);
        let text = match std::fs::read_to_string(&path) {
            Ok(text) => text,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(e) => {
                return Err(Error::Io {
                    path: path.display().to_string(),
                    source: e,
                });
            }
        };
        serde_json::from_str(&text).map(Some).map_err(|e| {
            Error::issuance(format!(
                "issuer store {} has a malformed {BINDING_FILE} — inspect it, or rebind \
                 deliberately by re-running with the allow-shared override",
                self.root.display()
            ))
            .with_source(e)
        })
    }

    /// Records (or refreshes) the store's manifest binding, atomically:
    /// the write lands via a temp file + rename, so a crash never leaves a
    /// half-written contract behind.
    pub fn record_binding(&self, binding: &StoreBinding) -> Result<()> {
        std::fs::create_dir_all(&self.root).map_err(|e| Error::Io {
            path: self.root.display().to_string(),
            source: e,
        })?;
        let text = serde_json::to_string_pretty(binding)
            .map_err(|e| Error::issuance("binding serialization".to_string()).with_source(e))?;
        let final_path = self.root.join(BINDING_FILE);
        let tmp = self.root.join(format!(".{BINDING_FILE}.tmp"));
        std::fs::write(&tmp, text).map_err(|e| Error::Io {
            path: tmp.display().to_string(),
            source: e,
        })?;
        std::fs::rename(&tmp, &final_path).map_err(|e| Error::Io {
            path: final_path.display().to_string(),
            source: e,
        })
    }

    /// What `plan apply` last put into the world (the diff base for the
    /// policy-only fast path). `None` before the first apply.
    pub fn applied_state(&self) -> Result<Option<AppliedState>> {
        let path = self.root.join(APPLIED_FILE);
        let text = match std::fs::read_to_string(&path) {
            Ok(text) => text,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(e) => {
                return Err(Error::Io {
                    path: path.display().to_string(),
                    source: e,
                });
            }
        };
        serde_json::from_str(&text).map(Some).map_err(|e| {
            Error::issuance(format!(
                "issuer store {} has a malformed {APPLIED_FILE} — delete it and re-run apply",
                self.root.display()
            ))
            .with_source(e)
        })
    }

    /// Records the applied state, atomically (temp + rename).
    pub fn record_applied(&self, state: &AppliedState) -> Result<()> {
        std::fs::create_dir_all(&self.root).map_err(|e| Error::Io {
            path: self.root.display().to_string(),
            source: e,
        })?;
        let text = serde_json::to_string_pretty(state).map_err(|e| {
            Error::issuance("applied-state serialization".to_string()).with_source(e)
        })?;
        let final_path = self.root.join(APPLIED_FILE);
        let tmp = self.root.join(format!(".{APPLIED_FILE}.tmp"));
        std::fs::write(&tmp, text).map_err(|e| Error::Io {
            path: tmp.display().to_string(),
            source: e,
        })?;
        std::fs::rename(&tmp, &final_path).map_err(|e| Error::Io {
            path: final_path.display().to_string(),
            source: e,
        })
    }

    /// Loads one workspace's issuer.
    pub fn workspace_issuer(&self, workspace: &str) -> Result<LoadedIssuer> {
        validate_name("workspace", workspace)?;
        Self::load_issuer_at(
            &self.root.join(format!("workspaces/{workspace}-issuer.crt")),
            &self.root.join(format!("workspaces/{workspace}-issuer.key")),
        )
    }

    /// Lists persisted workspace issuer names.
    pub fn workspace_names(&self) -> Result<Vec<String>> {
        let dir = self.root.join("workspaces");
        let mut names = Vec::new();
        let entries = match std::fs::read_dir(&dir) {
            Ok(entries) => entries,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(names),
            Err(e) => {
                return Err(Error::Io {
                    path: dir.display().to_string(),
                    source: e,
                });
            }
        };
        for entry in entries {
            let entry = entry.map_err(|e| Error::Io {
                path: dir.display().to_string(),
                source: e,
            })?;
            let Some(name) = entry.file_name().to_str().map(str::to_owned) else {
                continue;
            };
            if let Some(workspace) = name.strip_suffix("-issuer.crt") {
                validate_name("workspace", workspace)?;
                names.push(workspace.to_owned());
            }
        }
        names.sort();
        Ok(names)
    }

    /// Loads the policy signing key.
    pub fn policy_signer(&self) -> Result<SigningKey> {
        let hex_seed = self.read("policy-signing.key")?;
        let mut seed = [0u8; 32];
        hex::decode_to_slice(hex_seed.trim(), &mut seed)
            .map_err(|e| Error::issuance("policy signing key".to_string()).with_source(e))?;
        Ok(SigningKey::from_bytes(&seed))
    }

    /// Loads the policy verifying key (safe to distribute).
    pub fn policy_verifier(&self) -> Result<VerifyingKey> {
        Ok(self.policy_signer()?.verifying_key())
    }

    fn load_issuer_at(cert: &Path, key: &Path) -> Result<LoadedIssuer> {
        let cert_pem = std::fs::read_to_string(cert).map_err(|e| Error::Io {
            path: cert.display().to_string(),
            source: e,
        })?;
        let key_pem = std::fs::read_to_string(key).map_err(|e| Error::Io {
            path: key.display().to_string(),
            source: e,
        })?;
        LoadedIssuer::from_pem_pair(&cert_pem, &key_pem)
    }

    /// Issues the control endpoint identity (server): URI SAN principal plus
    /// the endpoint's DNS/IP SANs so agents can dial it by hostname.
    pub fn issue_control_endpoint(
        &self,
        realm: &str,
        node: &str,
        control_endpoint: &str,
    ) -> Result<IdentityMaterial> {
        self.issue_control_endpoint_with_ttl(realm, node, control_endpoint, LeafTtl::default())
    }

    /// Issues the control endpoint identity with an explicit bounded TTL.
    pub fn issue_control_endpoint_with_ttl(
        &self,
        realm: &str,
        node: &str,
        control_endpoint: &str,
        ttl: LeafTtl,
    ) -> Result<IdentityMaterial> {
        let principal = PrincipalPath::control(realm, node)?;
        let hostnames = endpoint_hostnames(control_endpoint)?;
        self.realm_issuer()?
            .issue(&principal, &hostnames, true, ttl)
    }

    /// Issues a workspace-scoped principal (agent or ingress client) with an
    /// explicit bounded TTL.
    pub(crate) fn issue_workspace_member_with_ttl(
        &self,
        realm: &str,
        workspace: &str,
        kind: PrincipalKind,
        node: &str,
        ttl: LeafTtl,
    ) -> Result<IdentityMaterial> {
        let principal = PrincipalPath::workspace_member(realm, workspace, kind, node)?;
        self.workspace_issuer(workspace)?
            .issue(&principal, &[], false, ttl)
    }

    /// Issues the realm-scoped site-to-site hub client principal (client
    /// credential, no hostname SAN — it dials the registrar, never serves).
    /// The hub node's server credential is a separate control-endpoint
    /// identity over the hub's own dial address.
    pub fn issue_hub_member_with_ttl(
        &self,
        realm: &str,
        node: &str,
        ttl: LeafTtl,
    ) -> Result<IdentityMaterial> {
        let principal = PrincipalPath::hub(realm, node)?;
        self.realm_issuer()?.issue(&principal, &[], false, ttl)
    }
}

/// Extracts the hostname/IP SAN from a control endpoint (`https://host:port`
/// or bare `host:port`). IPv6 hosts arrive bracket-free; IP endpoints stay
/// IPs. Unparseable endpoints fail closed as issuance errors — a certificate
/// silently issued without a hostname SAN would only surface much later as
/// a confusing handshake failure.
/// The DNS SAN set for a control endpoint: exactly the endpoint's host.
pub fn endpoint_hostnames(endpoint: &str) -> Result<Vec<String>> {
    let parsed = interflow_util::parse_endpoint(endpoint)
        .map_err(|e| Error::issuance(format!("control endpoint {endpoint:?}")).with_source(e))?;
    Ok(vec![parsed.host])
}

struct CaMaterial {
    cert_pem: String,
    key_pem: String,
}

enum CaProfile {
    Control,
    Workspace,
}

fn build_ca(cn: &str, validity_days: i64, profile: CaProfile) -> Result<CaMaterial> {
    use rcgen::{
        BasicConstraints, CertificateParams, CertifiedIssuer, DnType, ExtendedKeyUsagePurpose,
        IsCa, KeyPair, KeyUsagePurpose,
    };
    let mut params =
        CertificateParams::new(Vec::<String>::new()).map_err(err("issuer CA params"))?;
    params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
    params.is_ca = IsCa::Ca(BasicConstraints::Constrained(0));
    params.extended_key_usages = vec![match profile {
        CaProfile::Control => ExtendedKeyUsagePurpose::ServerAuth,
        CaProfile::Workspace => ExtendedKeyUsagePurpose::ClientAuth,
    }];
    params.distinguished_name.push(DnType::CommonName, cn);
    let now = OffsetDateTime::now_utc();
    params.not_before = now - time::Duration::hours(1);
    params.not_after = now + time::Duration::days(validity_days);
    let key = KeyPair::generate().map_err(err("issuer key generation"))?;
    let key_pem = key.serialize_pem();
    let issuer =
        CertifiedIssuer::self_signed(params, key).map_err(err("issuer CA self-signing"))?;
    Ok(CaMaterial {
        cert_pem: issuer.pem(),
        key_pem,
    })
}

/// Signs a policy snapshot with the realm policy key.
pub fn sign_policy(signer: &SigningKey, policy_bytes: &[u8]) -> Vec<u8> {
    signer.sign(policy_bytes).to_bytes().to_vec()
}

/// Verifies a policy snapshot signature.
pub fn verify_policy_signature(
    verifier: &VerifyingKey,
    policy_bytes: &[u8],
    signature: &[u8],
) -> Result<()> {
    let sig = ed25519_dalek::Signature::from_slice(signature)
        .map_err(|e| Error::policy("malformed policy signature".to_string()).with_source(e))?;
    verifier.verify(policy_bytes, &sig).map_err(|e| {
        Error::policy("policy signature verification failed".to_string()).with_source(e)
    })
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn endpoint_hostname_extraction() {
        let ok = |input: &str| endpoint_hostnames(input).unwrap();
        assert_eq!(ok("https://example.com:16666"), vec!["example.com"]);
        assert_eq!(ok("http://example.com:16666"), vec!["example.com"]);
        assert_eq!(ok("127.0.0.1:16666"), vec!["127.0.0.1"]);
        assert_eq!(ok("example.com"), vec!["example.com"]);
        // IPv6: bracket-free host, usable directly as an IP SAN
        assert_eq!(ok("https://[2001:db8::1]:16666"), vec!["2001:db8::1"]);
        assert_eq!(ok("[::1]:16666"), vec!["::1"]);
        // path/query never leak into the SAN
        assert_eq!(
            ok("https://relay.example.com:443/base/path"),
            vec!["relay.example.com"]
        );

        // fail closed: garbage endpoints are issuance errors, not SAN-less
        // certificates
        for bad in ["", "://", "https://", "ftp://x", "host:99999", "例え.jp"] {
            assert!(endpoint_hostnames(bad).is_err(), "{bad:?} must fail closed");
        }
    }

    #[test]
    fn canonical_serial_hex_spells_the_x509_parsed_form() {
        // The registrar/pack side reads serials back from DER
        // (minimal-positive form, sign byte stripped). Issuance must spell
        // the identical string for the ~1/256 hash slices starting with a
        // zero byte.
        assert_eq!(canonical_serial_hex(&[0x0a, 0xbc, 0xde]), "0abcde");
        assert_eq!(canonical_serial_hex(&[0x00, 0x0a, 0xbc]), "0abc");
        assert_eq!(canonical_serial_hex(&[0x00, 0x00, 0x0a]), "0a");
        // MSB set: DER adds a sign byte readers strip; the hex itself is
        // unchanged
        assert_eq!(canonical_serial_hex(&[0x80, 0x01]), "8001");
        // all zeros keep one byte
        assert_eq!(canonical_serial_hex(&[0x00, 0x00]), "00");
    }

    #[test]
    fn issued_serial_round_trips_through_the_parsed_certificate() {
        let dir = tempfile::tempdir().unwrap();
        let store = IssuerStore::open(dir.path());
        store.ensure_realm().unwrap();
        let material = store
            .issue_control_endpoint("promptcn", "edge", "https://relay.example.com:16666")
            .unwrap();
        let chain = crate::pem_certs(material.cert_pem.as_bytes()).unwrap();
        let parsed = x509_parser::parse_x509_certificate(chain.first().unwrap())
            .unwrap()
            .1;
        let raw = parsed.raw_serial();
        // registrar-side spelling: minimal DER minus one sign byte
        let read_back = if raw.first() == Some(&0) {
            hex::encode(&raw[1..])
        } else {
            hex::encode(raw)
        };
        assert_eq!(material.serial, read_back);
    }

    #[test]
    fn issued_identities_carry_uri_san() {
        let dir = tempfile::tempdir().unwrap();
        let store = IssuerStore::open(dir.path());
        store.ensure_realm().unwrap();
        store.ensure_workspace("main").unwrap();
        store.ensure_policy_key().unwrap();

        let control = store
            .issue_control_endpoint("promptcn", "edge", "https://relay.example.com:16666")
            .unwrap();
        assert_eq!(
            control.principal.to_string(),
            "spiffe://promptcn/control/edge"
        );
        let der = crate::pem_certs(control.cert_pem.as_bytes())
            .unwrap()
            .remove(0);
        assert_eq!(
            crate::uri_san_from_cert_der(&der).unwrap().as_deref(),
            Some("spiffe://promptcn/control/edge")
        );

        let agent = store
            .issue_workspace_member_with_ttl(
                "promptcn",
                "main",
                PrincipalKind::Agent,
                "desktop",
                LeafTtl::default(),
            )
            .unwrap();
        assert_eq!(
            agent.principal.to_string(),
            "spiffe://promptcn/main/agent/desktop"
        );
        // Chain bundle = leaf + workspace issuer.
        assert_eq!(
            crate::pem_certs(agent.chain_pem.as_bytes()).unwrap().len(),
            2
        );
        let age = agent.not_after - OffsetDateTime::now_utc();
        assert!(age > time::Duration::hours(23));
        assert!(age <= time::Duration::hours(24));
    }

    #[test]
    fn csr_renewal_preserves_only_client_key() {
        let dir = tempfile::tempdir().unwrap();
        let store = IssuerStore::open(dir.path());
        store.ensure_workspace("main").unwrap();
        let principal =
            PrincipalPath::workspace_member("promptcn", "main", PrincipalKind::Agent, "desktop")
                .unwrap();
        let csr = generate_csr(&principal, &[], false).unwrap();
        let renewed = store
            .workspace_issuer("main")
            .unwrap()
            .issue_csr(&principal, &[], false, LeafTtl::default_ttl(), &csr.csr_pem)
            .unwrap();
        let der = crate::pem_certs(renewed.cert_pem.as_bytes())
            .unwrap()
            .remove(0);
        assert_eq!(
            crate::uri_san_from_cert_der(&der).unwrap().as_deref(),
            Some("spiffe://promptcn/main/agent/desktop")
        );
        let key = rcgen::KeyPair::from_pem(&csr.key_pem).unwrap();
        let parsed = x509_parser::parse_x509_certificate(&der).unwrap().1;
        assert_eq!(
            parsed.public_key().subject_public_key.data,
            key.public_key_raw()
        );
        assert!(renewed.key_pem.is_empty());
    }

    #[test]
    fn policy_signature_round_trip() {
        let dir = tempfile::tempdir().unwrap();
        let store = IssuerStore::open(dir.path());
        store.ensure_policy_key().unwrap();
        let signer = store.policy_signer().unwrap();
        let verifier = store.policy_verifier().unwrap();
        let policy = b"generation = 1\n";
        let sig = sign_policy(&signer, policy);
        verify_policy_signature(&verifier, policy, &sig).unwrap();
        assert!(verify_policy_signature(&verifier, b"generation = 2\n", &sig).is_err());
    }
}
