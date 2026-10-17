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
        match Self::load_active(pack, &root) {
            Ok(Some(active)) => Ok(active),
            Ok(None) => Self::bootstrap_and_persist(pack, &root),
            // A ledger the pack's own CRL material condemns is dead weight
            // to shed, not a load failure: quarantine it for the audit
            // trail, then re-derive a fresh sequence from the bootstrap
            // identities. This is the automated form of the incident
            // runbook's manual `mv state/credentials …` rescue — an update
            // that carried a revoked ledger across generations used to
            // leave the node presenting a dead serial forever.
            Err(Error::CredentialRevoked { sequence, serial }) => {
                quarantine_revoked_sequence(&root, sequence, &serial);
                Self::bootstrap_and_persist(pack, &root)
            }
            // Any other damage (expired leaves, a broken pointer, key
            // mismatch) keeps its silent fallback: bootstrap IS the
            // recovery path.
            Err(_) => Self::bootstrap_and_persist(pack, &root),
        }
    }

    fn bootstrap_and_persist(pack: &CredentialPack, root: &Path) -> Result<Self> {
        let mut set = Self::bootstrap_from(pack, root, 0)?;
        set.sequence = next_sequence(root)?;
        set.persist_as_sequence()?;
        set.write_pointer()?;
        Ok(set)
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
                // The bootstrap identities are the pack's own material: a
                // CRL hit means the pack itself was revoked, and there is
                // nothing left to fall back to — fail loud with the remedy
                // instead of letting the node resurrect dead material into
                // an endless reject-reconnect loop.
                if revoked_by_carried_crl(pack, &credential) {
                    return Err(Error::pack(format!(
                        "bootstrap identity {stem:?} (serial {}) is revoked by the CRL this \
                         pack carries — the pack itself is retired; rotate the node and \
                         install its new pack",
                        credential.serial
                    )));
                }
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
        // The renewal ledger is node-owned state an update carries across
        // pack generations — it can outlive its own revocation. A CRL hit
        // condemns the whole sequence (the set switches as one unit; a node
        // presents every stem), surfacing as the CredentialRevoked signal
        // `load_or_bootstrap` quarantines on.
        for credential in entries.values() {
            if revoked_by_carried_crl(pack, credential) {
                return Err(Error::CredentialRevoked {
                    sequence: pointer.sequence,
                    serial: credential.serial.clone(),
                });
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

/// Whether the CRL material this pack carries revokes `credential`'s serial.
///
/// Authority argument: the hub's handshake layer (rustls acceptor, unknown
/// status = deny) is the fail-closed enforcement of revocation. This check is
/// the *self-healing* half — a node discovering its own credential is dead
/// sheds it and falls back instead of hammering a hub that will reject it
/// forever. So every "cannot judge" outcome (no CRL material for this tier
/// yet, unreadable material, an undecidable CRL) passes: the worst result is
/// today's behavior (the hub rejects the connection), never a false kill of
/// a healthy node. The CRL source stays statically pinned by the identity
/// tier ([`crl_path_for`]) — registrar packs read the live-refresh
/// `state/crls`, offline packs the embedded `trust/crls` snapshot; a stray
/// file in the other directory never changes the verdict.
fn revoked_by_carried_crl(pack: &CredentialPack, credential: &ActiveCredential) -> bool {
    let issuer_name = match credential.principal.workspace.as_deref() {
        Some(workspace) => format!("workspace/{workspace}"),
        None => "control".to_owned(),
    };
    let stem = issuer_name.replace('/', "-");
    let Some(crl_path) = crate::pack::crl_path_for(&pack.dir, pack.metadata.identity_mode, &stem)
        .ok()
        .flatten()
    else {
        return false;
    };
    let Ok(crl_pem) = std::fs::read_to_string(&crl_path) else {
        return false;
    };
    matches!(
        crate::revocation::crl_revokes_serial(&crl_pem, &credential.serial),
        Ok(Some(true))
    )
}

/// Moves a CRL-condemned sequence directory out of `sequences/` into
/// `quarantined/<sequence>-<serial-prefix>/`. Outside `sequences/` it is
/// invisible to `next_sequence` (no number reuse) and to
/// `prune_old_sequences` (the audit trail survives) — the on-disk record
/// that a ledger was shed. Best-effort by design: a quarantine that cannot
/// be written must not block the recovery — the bootstrap fallback is the
/// point.
fn quarantine_revoked_sequence(root: &Path, sequence: u64, serial: &str) {
    let src = root.join("sequences").join(sequence.to_string());
    if !src.is_dir() {
        return;
    }
    let prefix: String = serial.chars().take(8).collect();
    let dst = root
        .join("quarantined")
        .join(format!("{sequence}-{prefix}"));
    if std::fs::create_dir_all(root.join("quarantined")).is_err() {
        return;
    }
    if dst.exists() {
        let _ = std::fs::remove_dir_all(&dst);
    }
    let _ = std::fs::rename(&src, &dst);
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
    use crate::issuance::{IssuerStore, LeafTtl, generate_csr};
    use crate::manifest::Manifest;
    use crate::pack::render::AgentCredentialPack;
    use crate::revocation::{RevocationEntry, build_crl, cert_serial_hex};

    /// Renders an agent pack under `<tmp>/pack` with both issuers live, so a
    /// test can keep signing leaves and CRLs against it. `offline` selects
    /// the identity tier (and with it the CRL source the load path reads).
    fn rendered_agent_pack(tmp: &Path, offline: bool) -> (IssuerStore, CredentialPack) {
        let issuer = IssuerStore::open(tmp.join("issuer"));
        issuer.ensure_realm().unwrap();
        issuer.ensure_workspace("main").unwrap();
        issuer.ensure_policy_key().unwrap();
        let tier = if offline {
            "[identity]\nmode = \"offline\"\nleaf_ttl = \"90d\"\n"
        } else {
            "[identity]\nleaf_ttl = \"24h\"\n[registrar]\nendpoint = \
             \"https://registrar.example.com\"\n"
        };
        let manifest = Manifest::parse(&format!(
            "[realm]\nid = \"promptcn\"\ncontrol_endpoint = \
             \"relay.example.com:16666\"\n{tier}[ingress.edge]\nworkspaces = [\"main\"]\n[workspace.\
             main]\n[agent.desktop]\nworkspace = \"main\"\n[[agent.desktop.services]]\nid = \
             \"asr\"\naddress = \"127.0.0.1:8080\"\n[[route]]\nhost = \"asr.example.com\"\n\
             service = \"main/desktop/asr\"\n"
        ))
        .unwrap();
        let out = tmp.join("pack");
        AgentCredentialPack::render(&issuer, &manifest, "desktop", 1, &out).unwrap();
        let pack = CredentialPack::load_runtime(&out).unwrap();
        (issuer, pack)
    }

    /// Renews the agent leaf once (sequence +1) and returns the new serial —
    /// the ledger entry a later CRL will condemn.
    fn renew_agent_leaf(
        issuer: &IssuerStore,
        pack: &CredentialPack,
        active: &mut ActiveCredentialSet,
    ) -> String {
        let expected = pack.identities["agent"]["main"].clone();
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
                pack,
            )
            .unwrap();
        active.entries["agent-main"].serial.clone()
    }

    /// A workspace-main CRL revoking exactly `serials` (the renewal
    /// scheduler's refresh drops such a file into the tier's CRL source).
    fn crl_revoking(issuer: &IssuerStore, serials: &[String]) -> String {
        let entries: Vec<RevocationEntry> = serials
            .iter()
            .map(|serial| RevocationEntry {
                serial: serial.clone(),
                issuer: "workspace/main".to_owned(),
                reason: "key-compromise".to_owned(),
                revoked_at: "2026-10-13T00:00:00Z".to_owned(),
                pack_digest: None,
            })
            .collect();
        build_crl(&issuer.workspace_issuer("main").unwrap(), &entries, 1).unwrap()
    }

    fn drop_crl(pack: &CredentialPack, offline: bool, crl: &str) {
        let dir = if offline {
            pack.dir.join("trust").join("crls")
        } else {
            pack.dir.join("state").join("crls")
        };
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("workspace-main.crl.pem"), crl).unwrap();
    }

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

    /// The incident at the heart of the 2026-10-13 bug: an update carried a
    /// renewal ledger whose serial the CRL condemns. Loading must quarantine
    /// the dead sequence and re-derive a fresh one from the bootstrap
    /// identities — the automated form of the manual
    /// `mv state/credentials …` rescue.
    #[test]
    fn revoked_ledger_is_quarantined_and_bootstraps_fresh() {
        let tmp = tempfile::tempdir().unwrap();
        let (issuer, pack) = rendered_agent_pack(tmp.path(), false);
        let identity_serial = cert_serial_hex(&pack.identities["agent"]["main"].cert_pem).unwrap();
        let mut active = ActiveCredentialSet::load_or_bootstrap(&pack).unwrap();
        assert_eq!(active.sequence, 1);
        let dead_serial = renew_agent_leaf(&issuer, &pack, &mut active);
        assert_eq!(active.sequence, 2);

        // The renewal scheduler's CRL refresh drops the condemning CRL into
        // the registrar tier's source (state/crls).
        drop_crl(
            &pack,
            false,
            &crl_revoking(&issuer, std::slice::from_ref(&dead_serial)),
        );
        let revived = ActiveCredentialSet::load_or_bootstrap(&pack).unwrap();
        assert_eq!(
            revived.entries["agent-main"].serial, identity_serial,
            "the fresh sequence re-derives from the pack's bootstrap identities"
        );
        let prefix: String = dead_serial.chars().take(8).collect();
        let quarantined = pack
            .dir
            .join("state/credentials/quarantined")
            .join(format!("2-{prefix}"));
        assert!(
            quarantined.join("agent-main.crt").is_file(),
            "the dead sequence stays on disk as the audit trail"
        );
        // The shed number is immediately reused for the fresh sequence (the
        // quarantined copy lives elsewhere) — what sits at sequences/2 now
        // is the re-derived bootstrap material, not the dead leaf.
        let rebuilt = std::fs::read_to_string(
            pack.dir
                .join("state/credentials/sequences/2/agent-main.crt"),
        )
        .unwrap();
        assert_eq!(cert_serial_hex(&rebuilt).unwrap(), identity_serial);
        // Idempotent: the reloaded pointer serves the fresh sequence, not a
        // quarantine loop.
        let again = ActiveCredentialSet::load_or_bootstrap(&pack).unwrap();
        assert_eq!(again.entries["agent-main"].serial, identity_serial);
    }

    /// Offline packs read the embedded trust/crls snapshot — the load-path
    /// self-heal must work through that tier's statically pinned source too.
    #[test]
    fn offline_crl_snapshot_condemns_the_ledger_too() {
        let tmp = tempfile::tempdir().unwrap();
        let (issuer, pack) = rendered_agent_pack(tmp.path(), true);
        let identity_serial = cert_serial_hex(&pack.identities["agent"]["main"].cert_pem).unwrap();
        let mut active = ActiveCredentialSet::load_or_bootstrap(&pack).unwrap();
        let dead_serial = renew_agent_leaf(&issuer, &pack, &mut active);

        drop_crl(
            &pack,
            true,
            &crl_revoking(&issuer, std::slice::from_ref(&dead_serial)),
        );

        let revived = ActiveCredentialSet::load_or_bootstrap(&pack).unwrap();
        assert_eq!(revived.entries["agent-main"].serial, identity_serial);
        let prefix: String = dead_serial.chars().take(8).collect();
        assert!(
            pack.dir
                .join("state/credentials/quarantined")
                .join(format!("2-{prefix}"))
                .is_dir()
        );
    }

    /// The check is a self-heal, not a gate: no CRL material for the tier
    /// yet, or a CRL that does not list the serial, keeps serving the active
    /// sequence exactly as before.
    #[test]
    fn ledger_without_a_crl_hit_keeps_serving() {
        let tmp = tempfile::tempdir().unwrap();
        let (issuer, pack) = rendered_agent_pack(tmp.path(), false);
        let mut active = ActiveCredentialSet::load_or_bootstrap(&pack).unwrap();
        let renewed_serial = renew_agent_leaf(&issuer, &pack, &mut active);

        // No material at all → unchanged.
        let unchanged = ActiveCredentialSet::load_or_bootstrap(&pack).unwrap();
        assert_eq!(unchanged.sequence, 2);
        assert_eq!(unchanged.entries["agent-main"].serial, renewed_serial);

        // Material that does not list the serial → unchanged (the bootstrap
        // identity's serial is a bystander: the ledger keeps serving).
        let identity_serial = cert_serial_hex(&pack.identities["agent"]["main"].cert_pem).unwrap();
        drop_crl(&pack, false, &crl_revoking(&issuer, &[identity_serial]));
        let clean = ActiveCredentialSet::load_or_bootstrap(&pack).unwrap();
        assert_eq!(clean.sequence, 2);
        assert_eq!(clean.entries["agent-main"].serial, renewed_serial);
        assert!(!pack.dir.join("state/credentials/quarantined").exists());
    }

    /// A pack whose own bootstrap identities the CRL condemns has nothing to
    /// fall back to: load fails loud with the remedy, never resurrects the
    /// dead material — and a simultaneously revoked ledger is still
    /// quarantined first (the kill-a-node semantics: evicted at the hub,
    /// unable to come back from its own disk).
    #[test]
    fn revoked_bootstrap_identity_fails_loud() {
        let tmp = tempfile::tempdir().unwrap();
        let (issuer, pack) = rendered_agent_pack(tmp.path(), false);
        let identity_serial = cert_serial_hex(&pack.identities["agent"]["main"].cert_pem).unwrap();
        let mut active = ActiveCredentialSet::load_or_bootstrap(&pack).unwrap();
        let dead_serial = renew_agent_leaf(&issuer, &pack, &mut active);

        drop_crl(
            &pack,
            false,
            &crl_revoking(&issuer, &[identity_serial.clone(), dead_serial.clone()]),
        );

        let err = ActiveCredentialSet::load_or_bootstrap(&pack).unwrap_err();
        assert!(
            err.to_string().contains("rotate the node"),
            "the remedy must lead the failure: {err}"
        );
        assert!(
            err.to_string().contains(&identity_serial),
            "the revoked serial must be named: {err}"
        );
        // The ledger was still shed before the bootstrap attempt failed.
        let prefix: String = dead_serial.chars().take(8).collect();
        assert!(
            pack.dir
                .join("state/credentials/quarantined")
                .join(format!("2-{prefix}"))
                .is_dir()
        );

        // A ledger-less pack with revoked identities fails the same way (no
        // state to shed, just the loud refusal).
        let tmp2 = tempfile::tempdir().unwrap();
        let (issuer2, pack2) = rendered_agent_pack(tmp2.path(), false);
        let identity2 = cert_serial_hex(&pack2.identities["agent"]["main"].cert_pem).unwrap();
        drop_crl(&pack2, false, &crl_revoking(&issuer2, &[identity2]));
        let err = ActiveCredentialSet::load_or_bootstrap(&pack2).unwrap_err();
        assert!(err.to_string().contains("revoked"), "{err}");
    }
}
