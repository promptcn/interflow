//! Runtime-owned, short-lived credentials.
//!
//! The signed pack contains immutable bootstrap identities. Renewed leaves and
//! their client-generated keys live under mutable `state/`; a sequence
//! directory plus an atomically renamed pointer makes each cert/key pair
//! switch as one observable unit.

use crate::pack::{CredentialPack, IdentityEntry};
use crate::timestamp::{rfc3339, rfc3339_now};
use crate::{Error, PrincipalPath, Result, pem_certs, uri_san_from_cert_der};
use interflow_util::sha256_hex;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use time::OffsetDateTime;

#[derive(Debug, Clone, Serialize, Deserialize)]
struct CredentialPointer {
    sequence: u64,
    updated: String,
}

#[derive(Debug, Clone)]
pub struct ActiveCredential {
    pub stem: String,
    pub principal: PrincipalPath,
    pub cert_pem: String,
    pub key_pem: String,
    pub not_after: OffsetDateTime,
    pub serial: String,
}

#[derive(Debug, Clone)]
pub struct ActiveCredentialSet {
    root: PathBuf,
    pub sequence: u64,
    pub entries: BTreeMap<String, ActiveCredential>,
}

impl ActiveCredentialSet {
    /// Loads the active sequence, falling back to a still-valid signed
    /// bootstrap sequence when mutable state is absent or damaged.
    pub fn load_or_bootstrap(pack: &CredentialPack) -> Result<Self> {
        let root = pack.dir.join("state").join("credentials");
        if let Ok(Some(active)) = Self::load_active(pack, &root) {
            Ok(active)
        } else {
            let bootstrap = Self::bootstrap_from(pack, &root, 0)?;
            let mut set = bootstrap;
            set.sequence = next_sequence(&root)?;
            set.persist_as_sequence()?;
            set.write_pointer()?;
            Ok(set)
        }
    }

    /// Loads an already-initialized active sequence without falling back to
    /// the signed bootstrap identities.
    pub fn load_existing(pack: &CredentialPack) -> Result<Option<Self>> {
        Self::load_active(pack, &pack.dir.join("state").join("credentials"))
    }

    pub fn material_paths(&self, stem: &str) -> Result<(PathBuf, PathBuf)> {
        if !self.entries.contains_key(stem) {
            return Err(Error::pack(format!(
                "active credential {stem:?} is missing"
            )));
        }
        let dir = self.sequence_dir(self.sequence);
        Ok((
            dir.join(format!("{stem}.crt")),
            dir.join(format!("{stem}.key")),
        ))
    }

    pub fn earliest_expiry(&self) -> Result<OffsetDateTime> {
        self.entries
            .values()
            .map(|entry| entry.not_after)
            .min()
            .ok_or_else(|| Error::pack("active credential set is empty".to_owned()))
    }

    pub fn serials(&self) -> Vec<String> {
        self.entries
            .values()
            .map(|entry| entry.serial.clone())
            .collect()
    }

    /// Atomically installs a registrar-issued leaf and its client-held key.
    pub fn renew(
        &mut self,
        stem: &str,
        expected: &IdentityEntry,
        cert_pem: &str,
        key_pem: &str,
        pack: &CredentialPack,
    ) -> Result<()> {
        let credential =
            validate_credential(stem, cert_pem, key_pem, expected, pack, now_allow_skew())?;
        self.sequence = next_sequence(&self.root)?;
        self.entries.insert(stem.to_owned(), credential);
        self.persist_as_sequence()?;
        self.write_pointer()?;
        self.prune_old_sequences()?;
        Ok(())
    }

    fn bootstrap_from(pack: &CredentialPack, root: &Path, sequence: u64) -> Result<Self> {
        let mut entries = BTreeMap::new();
        for (bucket, buckets) in &pack.identities {
            for (workspace, entry) in buckets {
                let stem = identity_stem(bucket, workspace);
                let credential = validate_credential(
                    &stem,
                    &entry.cert_pem,
                    &entry.key_pem,
                    entry,
                    pack,
                    now_allow_skew(),
                )?;
                entries.insert(stem, credential);
            }
        }
        Ok(Self {
            root: root.to_owned(),
            sequence,
            entries,
        })
    }

    fn load_active(pack: &CredentialPack, root: &Path) -> Result<Option<Self>> {
        let pointer_path = root.join("current.json");
        let Ok(text) = std::fs::read_to_string(&pointer_path) else {
            return Ok(None);
        };
        let pointer: CredentialPointer = serde_json::from_str(&text)
            .map_err(|e| Error::pack("active credential pointer".to_string()).with_source(e))?;
        if pointer.sequence == 0 {
            return Err(Error::pack(
                "active credential pointer must reference sequence >= 1".to_owned(),
            ));
        }
        let dir = root.join("sequences").join(pointer.sequence.to_string());
        let mut entries = BTreeMap::new();
        for (bucket, buckets) in &pack.identities {
            for (workspace, expected) in buckets {
                let stem = identity_stem(bucket, workspace);
                let cert =
                    std::fs::read_to_string(dir.join(format!("{stem}.crt"))).map_err(|e| {
                        Error::Io {
                            path: dir.join(format!("{stem}.crt")).display().to_string(),
                            source: e,
                        }
                    })?;
                let key =
                    std::fs::read_to_string(dir.join(format!("{stem}.key"))).map_err(|e| {
                        Error::Io {
                            path: dir.join(format!("{stem}.key")).display().to_string(),
                            source: e,
                        }
                    })?;
                let credential =
                    validate_credential(&stem, &cert, &key, expected, pack, now_allow_skew())?;
                entries.insert(stem, credential);
            }
        }
        Ok(Some(Self {
            root: root.to_owned(),
            sequence: pointer.sequence,
            entries,
        }))
    }

    fn sequence_dir(&self, sequence: u64) -> PathBuf {
        self.root.join("sequences").join(sequence.to_string())
    }

    fn persist_as_sequence(&self) -> Result<()> {
        let dir = self.sequence_dir(self.sequence);
        std::fs::create_dir_all(&dir).map_err(|e| Error::Io {
            path: dir.display().to_string(),
            source: e,
        })?;
        for entry in self.entries.values() {
            atomic_write(
                &dir.join(format!("{}.crt", entry.stem)),
                entry.cert_pem.as_bytes(),
                0o644,
            )?;
            atomic_write(
                &dir.join(format!("{}.key", entry.stem)),
                entry.key_pem.as_bytes(),
                0o600,
            )?;
        }
        Ok(())
    }

    fn write_pointer(&self) -> Result<()> {
        std::fs::create_dir_all(&self.root).map_err(|e| Error::Io {
            path: self.root.display().to_string(),
            source: e,
        })?;
        let pointer = CredentialPointer {
            sequence: self.sequence,
            updated: rfc3339_now()?,
        };
        let bytes = serde_json::to_vec_pretty(&pointer).map_err(|e| {
            Error::serialize("active credential pointer".to_string()).with_source(e)
        })?;
        atomic_write(&self.root.join("current.json"), &bytes, 0o644)
    }

    fn prune_old_sequences(&self) -> Result<()> {
        let sequences = self.root.join("sequences");
        let mut keep = [self.sequence, self.sequence.saturating_sub(1)];
        keep.sort_unstable();
        for entry in std::fs::read_dir(&sequences).map_err(|e| Error::Io {
            path: sequences.display().to_string(),
            source: e,
        })? {
            let entry = entry.map_err(|e| Error::Io {
                path: sequences.display().to_string(),
                source: e,
            })?;
            let Some(name) = entry.file_name().into_string().ok() else {
                continue;
            };
            let Ok(sequence) = name.parse::<u64>() else {
                continue;
            };
            if !keep.contains(&sequence) {
                let _ = std::fs::remove_dir_all(entry.path());
            }
        }
        Ok(())
    }
}

pub fn identity_stem(bucket: &str, workspace: &str) -> String {
    format!("{bucket}-{workspace}")
}

fn validate_credential(
    stem: &str,
    cert_pem: &str,
    key_pem: &str,
    expected: &IdentityEntry,
    pack: &CredentialPack,
    now: i64,
) -> Result<ActiveCredential> {
    let ders = pem_certs(cert_pem.as_bytes())?;
    let leaf = ders
        .first()
        .ok_or_else(|| Error::pack(format!("credential {stem:?} carries no certificate")))?;
    let uri = uri_san_from_cert_der(leaf)?
        .ok_or_else(|| Error::pack(format!("credential {stem:?} carries no principal URI SAN")))?;
    let principal = PrincipalPath::parse_uri(&uri)?;
    if principal != expected.principal {
        return Err(Error::pack(format!(
            "credential {stem:?} identifies {principal}, expected {}",
            expected.principal
        )));
    }
    let parsed = x509_parser::parse_x509_certificate(leaf)
        .map_err(|e| Error::pack(format!("credential {stem:?} parse")).with_source(e))?;
    let not_after = parsed.1.validity().not_after.timestamp();
    if not_after < now {
        return Err(Error::pack(format!(
            "credential {stem:?} expired at {}",
            OffsetDateTime::from_unix_timestamp(not_after)
                .map(rfc3339)
                .unwrap_or_else(|_| Ok("unknown".to_owned()))
                .unwrap_or_else(|_| "unknown".to_owned())
        )));
    }
    let key = rcgen::KeyPair::from_pem(key_pem).map_err(|e| {
        Error::pack(format!("credential {stem:?} private key parse")).with_source(e)
    })?;
    if parsed.1.public_key().subject_public_key.data != key.public_key_raw() {
        return Err(Error::pack(format!(
            "credential {stem:?} private key does not match its certificate"
        )));
    }
    let issuer_name = match principal.workspace.as_deref() {
        Some(workspace) => format!("workspace/{workspace}"),
        None => "control".to_owned(),
    };
    let issuer_pem = pack
        .trust
        .issuers
        .get(&issuer_name)
        .ok_or_else(|| Error::trust(format!("trust bundle lacks issuer {issuer_name:?}")))?;
    let issuer_der = pem_certs(issuer_pem.as_bytes())?
        .first()
        .ok_or_else(|| Error::trust(format!("issuer {issuer_name:?} has no certificate")))?
        .clone();
    let presented_issuer = ders
        .get(1)
        .ok_or_else(|| Error::pack(format!("credential {stem:?} carries no issuer chain")))?;
    if sha256_hex(presented_issuer) != sha256_hex(&issuer_der) {
        return Err(Error::pack(format!(
            "credential {stem:?} chains to an issuer outside its signed trust bundle"
        )));
    }
    Ok(ActiveCredential {
        stem: stem.to_owned(),
        principal,
        cert_pem: cert_pem.to_owned(),
        key_pem: key_pem.to_owned(),
        not_after: OffsetDateTime::from_unix_timestamp(not_after)
            .map_err(|e| Error::pack(format!("credential {stem:?} expiry")).with_source(e))?,
        serial: canonical_serial(parsed.1.raw_serial()),
    })
}

fn canonical_serial(bytes: &[u8]) -> String {
    let canonical = if bytes.first() == Some(&0) {
        &bytes[1..]
    } else {
        bytes
    };
    if canonical.is_empty() {
        "00".to_owned()
    } else {
        hex::encode(canonical)
    }
}

fn now_allow_skew() -> i64 {
    OffsetDateTime::now_utc().unix_timestamp() - 60
}

fn next_sequence(root: &Path) -> Result<u64> {
    let sequences = root.join("sequences");
    if !sequences.exists() {
        return Ok(1);
    }
    let mut max = 0;
    for entry in std::fs::read_dir(&sequences).map_err(|e| Error::Io {
        path: sequences.display().to_string(),
        source: e,
    })? {
        let entry = entry.map_err(|e| Error::Io {
            path: sequences.display().to_string(),
            source: e,
        })?;
        if let Some(sequence) = entry
            .file_name()
            .to_str()
            .and_then(|name| name.parse::<u64>().ok())
        {
            max = max.max(sequence);
        }
    }
    Ok(max + 1)
}

fn atomic_write(path: &Path, bytes: &[u8], mode: u32) -> Result<()> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).map_err(|e| Error::Io {
            path: parent.display().to_string(),
            source: e,
        })?;
    }
    // Set (not preserve): private keys and pointer files must always carry
    // their designated mode, correcting any pre-existing lax bits.
    interflow_util::atomic_write(path, bytes, interflow_util::WriteMode::Set(mode)).map_err(|e| {
        Error::Io {
            path: path.display().to_string(),
            source: e,
        }
    })
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use crate::issuance::{LeafTtl, generate_csr};
    use crate::manifest::Manifest;
    use crate::pack::render::AgentCredentialPack;

    #[test]
    fn active_sequence_rotates_atomically() {
        let tmp = tempfile::tempdir().unwrap();
        let issuer = crate::issuance::IssuerStore::open(tmp.path().join("issuer"));
        issuer.ensure_realm().unwrap();
        issuer.ensure_workspace("main").unwrap();
        issuer.ensure_policy_key().unwrap();
        let manifest = Manifest::parse(
            r#"
[realm]
id = "promptcn"
control_endpoint = "relay.example.com:16666"
[identity]
leaf_ttl = "24h"
[registrar]
endpoint = "https://registrar.example.com"
[ingress.edge]
workspaces = ["main"]
[workspace.main]
[agent.desktop]
workspace = "main"
[[agent.desktop.services]]
id = "asr"
address = "127.0.0.1:8080"
[[route]]
host = "asr.example.com"
service = "main/desktop/asr"
"#,
        )
        .unwrap();
        let out = tmp.path().join("pack");
        AgentCredentialPack::render(&issuer, &manifest, "desktop", 1, &out).unwrap();
        let pack = CredentialPack::load_runtime(&out).unwrap();
        let mut active = ActiveCredentialSet::load_or_bootstrap(&pack).unwrap();
        assert_eq!(active.sequence, 1);
        let (stable_cert, stable_key) = active.material_paths("agent-main").unwrap();
        assert!(stable_cert.is_file() && stable_key.is_file());
        let expected = pack.identities["agent"]["main"].clone();
        let old_serial = active.entries["agent-main"].serial.clone();
        let csr = generate_csr(&expected.principal, &[], false).unwrap();
        let material = issuer
            .workspace_issuer("main")
            .unwrap()
            .issue_csr(
                &expected.principal,
                &[],
                false,
                LeafTtl::default_ttl(),
                &csr.csr_pem,
            )
            .unwrap();
        active
            .renew(
                "agent-main",
                &expected,
                &material.chain_pem,
                &csr.key_pem,
                &pack,
            )
            .unwrap();
        assert_eq!(active.sequence, 2);
        assert_ne!(active.entries["agent-main"].serial, old_serial);
        let reloaded =
            ActiveCredentialSet::load_or_bootstrap(&CredentialPack::load_runtime(&out).unwrap())
                .unwrap();
        assert_eq!(reloaded.sequence, 2);
    }
}
