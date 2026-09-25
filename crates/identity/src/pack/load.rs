//! Pack loading: pack directory -> validated [`CredentialPack`].
//!
//! Load is fail-closed: metadata shape, generation cross-consistency,
//! per-file digests, identity chain anchoring, and role binding are all
//! verified before a pack is usable.

use super::{CredentialPack, IdentityEntry, NodeConfig, PackKind, PackMetadata};
use crate::policy::{RuntimePolicy, SignedPolicyFiles};
use crate::timestamp::rfc3339;
use crate::trust::TrustBundle;
use crate::{Error, PrincipalPath, Result, pem_certs, uri_san_from_cert_der};
use ed25519_dalek::VerifyingKey;
use interflow_contract::{FORMAT_VERSION, Generation};
use interflow_util::sha256_hex;
use serde::Serialize;
use std::collections::BTreeMap;
use std::path::Path;
use time::OffsetDateTime;

// ---------------------------------------------------------------------------
// Loading + role-bound validation
// ---------------------------------------------------------------------------

impl CredentialPack {
    /// Loads a pack directory and runs the full validation suite:
    /// digests, metadata, key/cert match, principal identity, chain anchor,
    /// expiry, policy signature.
    pub fn load(dir: &Path) -> Result<Self> {
        Self::load_inner(dir, true)
    }

    /// Loads a pack for node startup. A valid mutable active generation may
    /// supersede an expired bootstrap identity; without one, expiry is still
    /// enforced.
    pub fn load_runtime(dir: &Path) -> Result<Self> {
        Self::load_inner(dir, false)
    }

    fn load_inner(dir: &Path, enforce_expiry: bool) -> Result<Self> {
        let manifest_path = dir.join("pack.toml");
        let toml_text = std::fs::read_to_string(&manifest_path).map_err(|e| Error::Io {
            path: manifest_path.display().to_string(),
            source: e,
        })?;
        let metadata: PackMetadata = toml::from_str(&toml_text)
            .map_err(|e| Error::pack("pack.toml parse".to_string()).with_source(e))?;
        if metadata.format_version != FORMAT_VERSION {
            return Err(Error::pack(format!(
                "pack format_version must be {FORMAT_VERSION} (found {})",
                metadata.format_version
            )));
        }
        verify_digests(dir)?;
        let node_config: NodeConfig = toml::from_str(
            &std::fs::read_to_string(dir.join("node.toml")).map_err(|e| Error::Io {
                path: dir.join("node.toml").display().to_string(),
                source: e,
            })?,
        )
        .map_err(|e| Error::pack("node.toml parse".to_string()).with_source(e))?;
        // Pre-separation packs carry the mesh rules in node.toml. Parsed
        // (serde-known) only so this fails with the migration instruction
        // instead of a bare unknown-field error.
        if let Some(mesh) = &node_config.mesh
            && (!mesh.ingress.is_empty() || !mesh.egress.is_empty())
        {
            return Err(Error::pack(
                "this pack carries its mesh rules in node.toml — it predates the \
                 signed-policy rule face; re-render it with `plan apply` and reinstall"
                    .to_owned(),
            ));
        }
        let trust = TrustBundle::load(&dir.join("trust"))?;

        // Policy signature against the trust bundle's policy key — a pack
        // without a verifiable signature is rejected outright.
        let verifier = policy_verifier(&trust)?;
        let signed = SignedPolicyFiles::load(&dir.join("policy"), &verifier)?;
        validate_generation(metadata.generation, &trust, &signed.policy)?;
        // Authoritative policy: a newer signed bundle in `state/policy`
        // (the node-local update channel — state/ is outside SHA256SUMS on
        // purpose, the ed25519 signature is its integrity) supersedes the
        // embedded snapshot. The embedded generation is the rollback floor;
        // a bundle that fails verification or rolls back is rejected with a
        // warning and the embedded snapshot keeps serving (fail-keep).
        let (policy, policy_signature) =
            match Self::load_policy_override(dir, &verifier, signed.policy.generation) {
                Ok(Some(update)) => (update.policy, update.signature),
                Ok(None) => (signed.policy, signed.signature),
                Err(e) => {
                    tracing::warn!(
                        "rejecting policy update in state/policy (keeping the embedded \
                         snapshot): {e}"
                    );
                    (signed.policy, signed.signature)
                }
            };

        // Identity entries.
        let identity_dir = dir.join("identity");
        let mut identities: BTreeMap<String, BTreeMap<String, IdentityEntry>> = BTreeMap::new();
        let mut count = 0usize;
        for entry in std::fs::read_dir(&identity_dir).map_err(|e| Error::Io {
            path: identity_dir.display().to_string(),
            source: e,
        })? {
            let entry = entry.map_err(|e| Error::Io {
                path: identity_dir.display().to_string(),
                source: e,
            })?;
            let path = entry.path();
            if path.extension().is_none_or(|e| e != "crt") {
                continue;
            }
            let stem = path
                .file_stem()
                .and_then(|s| s.to_str())
                .ok_or_else(|| Error::pack("identity file has no name".to_owned()))?
                .to_owned();
            let key_path = path.with_extension("key");
            let cert_pem = std::fs::read_to_string(&path).map_err(|e| Error::Io {
                path: path.display().to_string(),
                source: e,
            })?;
            let key_pem = std::fs::read_to_string(&key_path).map_err(|e| Error::Io {
                path: key_path.display().to_string(),
                source: e,
            })?;
            let certs = pem_certs(cert_pem.as_bytes())?;
            let leaf = certs
                .first()
                .ok_or_else(|| Error::pack(format!("identity {stem:?}: no certificate in PEM")))?;
            let uri_san = uri_san_from_cert_der(leaf)?.ok_or_else(|| {
                Error::pack(format!(
                    "identity {stem:?}: certificate carries no principal URI SAN — \
                     re-issue the pack"
                ))
            })?;
            let (cn, not_after) = parse_leaf_summary(leaf)?;
            let identity = IdentityEntry {
                principal: PrincipalPath::parse_uri(&uri_san)?,
                cert_pem,
                key_pem,
                uri_san: Some(uri_san),
                cn,
                not_after_unix: not_after,
            };
            verify_key_matches_leaf(&identity.key_pem, leaf)
                .map_err(|e| Error::pack(format!("identity {stem:?}")).with_source(e))?;
            let (bucket, workspace) = stem.split_once('-').ok_or_else(|| {
                Error::pack(format!(
                    "identity file {stem:?} must be named <kind>-<workspace>.crt"
                ))
            })?;
            identities
                .entry(bucket.to_owned())
                .or_default()
                .insert(workspace.to_owned(), identity);
            count += 1;
        }
        if count == 0 {
            return Err(Error::pack("pack carries no identities".to_owned()));
        }

        let pack = Self {
            metadata,
            dir: dir.to_owned(),
            identities,
            trust,
            policy,
            policy_signature,
            node_config,
            pack_digest: digests_file_digest(dir)?,
        };
        pack.validate_role_binding()?;
        let enforce_expiry = enforce_expiry
            || crate::credentials::ActiveCredentialSet::load_existing(&pack)?.is_none();
        if enforce_expiry {
            pack.validate_expiry()?;
        }
        Ok(pack)
    }

    /// The identity a node runs as. For agents: their workspace principal.
    /// For ingress: the control endpoint identity. For hubs: the
    /// control-endpoint server identity (SAN = the hub dial address).
    pub fn primary_identity(&self) -> Result<&IdentityEntry> {
        match self.metadata.kind {
            PackKind::Agent => self
                .identities
                .get("agent")
                .and_then(|m| {
                    let ws = self.metadata.workspace.as_deref()?;
                    m.get(ws)
                })
                .ok_or_else(|| {
                    Error::pack(format!(
                        "agent pack for {}/{} carries no agent identity",
                        self.metadata.realm,
                        self.metadata.workspace.as_deref().unwrap_or("?"),
                    ))
                }),
            PackKind::Ingress | PackKind::Hub => self
                .identities
                .get("control")
                .and_then(|m| m.get("endpoint"))
                .ok_or_else(|| {
                    Error::pack("this pack carries no control endpoint identity".to_owned())
                }),
        }
    }

    /// The workspace-scoped ingress principals (`workspace → entry`).
    pub fn ingress_identities(&self) -> Result<&BTreeMap<String, IdentityEntry>> {
        if self.metadata.kind != PackKind::Ingress {
            return Err(Error::pack(
                "agent packs carry no ingress principals".to_owned(),
            ));
        }
        self.identities.get("ingress").ok_or_else(|| {
            Error::pack(
                "ingress pack carries no workspace principals — authorize at least one \
                 workspace in the manifest"
                    .to_owned(),
            )
        })
    }

    fn validate_role_binding(&self) -> Result<()> {
        // Role buckets.
        match self.metadata.kind {
            PackKind::Ingress => {
                if self.metadata.workspace.is_some() {
                    return Err(Error::pack(
                        "ingress packs are not bound to a single workspace — remove \
                         `workspace` from pack.toml"
                            .to_owned(),
                    ));
                }
                if self.identities.contains_key("agent") {
                    return Err(Error::pack(
                        "this ingress pack carries agent identities — an ingress pack must \
                         not contain agent credentials"
                            .to_owned(),
                    ));
                }
                if self.identities.contains_key("hub") {
                    return Err(Error::pack(
                        "this ingress pack carries hub principals — an ingress pack must \
                         not contain them"
                            .to_owned(),
                    ));
                }
                self.primary_identity()?;
                // Every ingress principal's workspace must appear in the
                // signed policy authorizations.
                for (workspace, entry) in self.ingress_identities()? {
                    let authorized = self.policy.ingress_authorizations.iter().any(|auth| {
                        auth.workspace == *workspace && auth.ingress == self.metadata.node
                    });
                    if !authorized {
                        return Err(Error::pack(format!(
                            "ingress principal {} is not authorized for workspace \
                             {workspace:?} in the signed policy",
                            entry.principal
                        )));
                    }
                    if entry.principal.workspace.as_deref() != Some(workspace) {
                        return Err(Error::pack(format!(
                            "ingress principal {} does not belong to workspace {workspace:?}",
                            entry.principal
                        )));
                    }
                }
            }
            PackKind::Agent => {
                let workspace = self.metadata.workspace.as_deref().ok_or_else(|| {
                    Error::pack("agent packs must declare their workspace".to_owned())
                })?;
                if self.identities.contains_key("control") {
                    return Err(Error::pack(
                        "this agent pack carries control endpoint identities — an agent pack \
                         must not contain them"
                            .to_owned(),
                    ));
                }
                if self.identities.contains_key("ingress") {
                    return Err(Error::pack(
                        "this agent pack carries ingress principals — an agent pack must \
                         not contain them"
                            .to_owned(),
                    ));
                }
                if self.identities.contains_key("hub") {
                    return Err(Error::pack(
                        "this agent pack carries hub principals — an agent pack must not \
                         contain them"
                            .to_owned(),
                    ));
                }
                let identity = self.primary_identity()?;
                if identity.principal.workspace.as_deref() != Some(workspace) {
                    return Err(Error::pack(format!(
                        "agent identity {} does not belong to workspace {workspace:?}",
                        identity.principal
                    )));
                }
            }
            PackKind::Hub => {
                if self.metadata.workspace.is_some() {
                    return Err(Error::pack(
                        "hub packs are not bound to a single workspace — remove `workspace` \
                         from pack.toml"
                            .to_owned(),
                    ));
                }
                if self.identities.contains_key("agent") {
                    return Err(Error::pack(
                        "this hub pack carries agent identities — a hub pack must not contain \
                         them"
                            .to_owned(),
                    ));
                }
                if self.identities.contains_key("ingress") {
                    return Err(Error::pack(
                        "this hub pack carries ingress principals — a hub pack must not \
                         contain them"
                            .to_owned(),
                    ));
                }
                self.primary_identity()?;
                // The realm-scoped hub client principal authorizes the hub's
                // renewal traffic; a hub pack without it cannot stay alive.
                let carries_hub_principal = self
                    .identities
                    .get("hub")
                    .is_some_and(|m| m.contains_key(&self.metadata.realm));
                if !carries_hub_principal {
                    return Err(Error::pack(format!(
                        "hub pack for realm {:?} carries no hub renewal principal",
                        self.metadata.realm
                    )));
                }
            }
        }
        // Realm consistency.
        for buckets in self.identities.values() {
            for entry in buckets.values() {
                if entry.principal.realm != self.metadata.realm {
                    return Err(Error::pack(format!(
                        "identity {} belongs to realm {:?}, not {:?} — this pack was \
                         assembled from mixed realms",
                        entry.principal, entry.principal.realm, self.metadata.realm
                    )));
                }
                if entry.principal.node != self.metadata.node {
                    return Err(Error::pack(format!(
                        "identity {} does not belong to node {:?} — the credential belongs \
                         to another node",
                        entry.principal, self.metadata.node
                    )));
                }
            }
        }
        Ok(())
    }

    fn validate_expiry(&self) -> Result<()> {
        let now = OffsetDateTime::now_utc().unix_timestamp();
        for buckets in self.identities.values() {
            for (name, entry) in buckets.values().enumerate() {
                let _ = name;
                if entry.not_after_unix < now {
                    let expired = OffsetDateTime::from_unix_timestamp(entry.not_after_unix)
                        .map(rfc3339)
                        .unwrap_or_else(|_| Ok("unknown".to_owned()))
                        .unwrap_or_else(|_| "unknown".to_owned());
                    return Err(Error::pack(format!(
                        "credential for {} expired at {expired} — rotate the pack \
                         (`interflow rotate`)",
                        entry.principal
                    )));
                }
            }
        }
        Ok(())
    }

    /// Human-facing inspection summary.
    pub fn summary(&self) -> PackSummary {
        PackSummary {
            kind: self.metadata.kind,
            identity: self
                .primary_identity()
                .map(|i| i.principal.to_string())
                .unwrap_or_default(),
            realm: self.metadata.realm.clone(),
            workspace: self.metadata.workspace.clone(),
            node: self.metadata.node.clone(),
            generation: self.metadata.generation,
            expires: self.metadata.expires.clone(),
            pack_digest: self.pack_digest.clone(),
        }
    }

    /// Loads the node-local policy update from `state/policy`, if one is
    /// present. Verification + anti-rollback against `floor` (the highest
    /// generation this node has accepted); errors name their category
    /// (missing files / bad signature / parse failure / rollback) for the
    /// caller's rejection log.
    fn load_policy_override(
        dir: &Path,
        verifier: &VerifyingKey,
        floor: Generation,
    ) -> Result<Option<SignedPolicyFiles>> {
        let state_policy = dir.join("state").join("policy");
        if !state_policy.join("policy.toml").is_file() {
            return Ok(None);
        }
        let signed = SignedPolicyFiles::load(&state_policy, verifier)?;
        signed.policy.check_not_rollback(floor)?;
        Ok(Some(signed))
    }

    /// The node-local policy update channel, for a running node's reload
    /// watcher: loads + verifies `state/policy` against this pack's trust
    /// bundle and enforces anti-rollback against `floor` (the highest
    /// generation the node has ever applied — at minimum the embedded
    /// snapshot's). `Ok(None)` means no update is present. A tampered or
    /// rolled-back bundle is an `Err` the watcher logs while the current
    /// policy keeps serving.
    pub fn policy_update(&self, floor: Generation) -> Result<Option<SignedPolicyFiles>> {
        let verifier = policy_verifier(&self.trust)?;
        Self::load_policy_override(&self.dir, &verifier, floor)
    }
}

/// The policy verifying key from the trust bundle (the anchor every policy
/// signature is checked against).
fn policy_verifier(trust: &TrustBundle) -> Result<VerifyingKey> {
    let key_bytes = hex::decode(trust.metadata.policy_key.trim())
        .map_err(|e| Error::trust("policy verifying key".to_string()).with_source(e))?;
    let mut key_arr = [0u8; 32];
    key_arr.copy_from_slice(&key_bytes);
    VerifyingKey::from_bytes(&key_arr)
        .map_err(|e| Error::trust("policy verifying key".to_string()).with_source(e))
}

/// Generation coherence of the pack's **embedded** signed objects: pack
/// metadata, trust bundle, and the embedded policy snapshot all carry the
/// render-time generation. A `state/policy` update supersedes the embedded
/// policy on its own generation track (≥ the embedded generation — see
/// `load_policy_override`), which is why this check runs before the override
/// is considered.
pub(crate) fn validate_generation(
    generation: Generation,
    trust: &TrustBundle,
    policy: &RuntimePolicy,
) -> Result<()> {
    if trust.metadata.generation != generation || policy.generation != generation {
        return Err(Error::pack(format!(
            "pack generation mismatch: pack={generation}, trust={}, policy={} — all signed \
             objects in one pack must share one generation",
            trust.metadata.generation, policy.generation
        )));
    }
    Ok(())
}

/// `interflow identity inspect` output.
#[derive(Debug, Clone, Serialize)]
pub struct PackSummary {
    pub kind: PackKind,
    pub identity: String,
    pub realm: String,
    pub workspace: Option<String>,
    pub node: String,
    pub expires: String,
    pub generation: Generation,
    pub pack_digest: String,
}

fn verify_digests(dir: &Path) -> Result<()> {
    let sums_path = dir.join("SHA256SUMS");
    let sums = std::fs::read_to_string(&sums_path).map_err(|e| Error::Io {
        path: sums_path.display().to_string(),
        source: e,
    })?;
    for line in sums.lines() {
        let Some((digest, rel)) = line.split_once("  ") else {
            continue;
        };
        let bytes = std::fs::read(dir.join(rel)).map_err(|e| Error::Io {
            path: dir.join(rel).display().to_string(),
            source: e,
        })?;
        let actual = sha256_hex(&bytes);
        if actual != digest {
            return Err(Error::pack(format!(
                "credential pack file {rel:?} does not match its digest — the pack is \
                 corrupted or was modified after sealing"
            )));
        }
    }
    Ok(())
}

fn digests_file_digest(dir: &Path) -> Result<String> {
    let bytes = std::fs::read(dir.join("SHA256SUMS")).map_err(|e| Error::Io {
        path: dir.join("SHA256SUMS").display().to_string(),
        source: e,
    })?;
    Ok(format!("sha256:{}", sha256_hex(&bytes)))
}

fn parse_leaf_summary(der: &[u8]) -> Result<(String, i64)> {
    match x509_parser::parse_x509_certificate(der) {
        Ok((_, cert)) => {
            let cn = cert
                .subject()
                .iter_common_name()
                .next()
                .and_then(|cn| cn.as_str().ok())
                .unwrap_or_default()
                .to_owned();
            Ok((cn, cert.validity().not_after.timestamp()))
        }
        Err(e) => Err(Error::pack("certificate parse".to_string()).with_source(e)),
    }
}

fn verify_key_matches_leaf(key_pem: &str, leaf_der: &[u8]) -> Result<()> {
    let key = rcgen::KeyPair::from_pem(key_pem)
        .map_err(|e| Error::pack("private key parse".to_string()).with_source(e))?;
    let cert_spki = match x509_parser::parse_x509_certificate(leaf_der) {
        Ok((_, cert)) => cert.public_key().subject_public_key.data.to_vec(),
        Err(e) => return Err(Error::pack("certificate parse".to_string()).with_source(e)),
    };
    if cert_spki != key.public_key_raw() {
        return Err(Error::pack(
            "the private key does not match the credential — the pack was damaged or \
             assembled from mixed identities; re-issue it"
                .to_owned(),
        ));
    }
    Ok(())
}
