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
        // Canonical per-kind shape: an ingress pack always carries a fully
        // resolved [edge] section. Its absence is a pre-canonical (or
        // mis-rendered) pack — fail closed with the recovery action instead
        // of guessing topology defaults at boot.
        if node_config.kind == PackKind::Ingress && node_config.edge.is_none() {
            return Err(Error::pack(
                "ingress pack node.toml carries no [edge] section — re-render the pack \
                 (interflow-cli plan apply); boot-time topology defaults are retired"
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
        let (policy, policy_signature, policy_from_state_channel) =
            match Self::load_policy_override(dir, &verifier, signed.policy.generation) {
                Ok(Some(update)) => (update.policy, update.signature, true),
                Ok(None) => (signed.policy, signed.signature, false),
                Err(e) => {
                    tracing::warn!(
                        "rejecting policy update in state/policy (keeping the embedded \
                         snapshot): {e}"
                    );
                    (signed.policy, signed.signature, false)
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
            policy_from_state_channel,
            node_config,
            pack_digest: digests_file_digest(dir)?,
        };
        pack.validate_role_binding()?;
        // An existing active ledger means the node presents renewed leaves,
        // so the bootstrap identities' expiry is dormant — UNLESS the ledger
        // is unusable (damaged, or revoked by the CRL the pack carries, in
        // which case the load path below sheds it and falls back to the
        // bootstrap material): then the identities are what the node will
        // actually present, and their expiry must gate the load. Either way
        // a ledger problem is "no ledger" here, never a load failure — the
        // self-heal lives in ActiveCredentialSet::load_or_bootstrap.
        let enforce_expiry = enforce_expiry
            || crate::credentials::ActiveCredentialSet::load_existing(&pack)
                .map_or(true, |ledger| ledger.is_none());
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
                         (`interflow-cli rotate`)",
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

/// `interflow-cli identity inspect` output.
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

// ---------------------------------------------------------------------------
// Format probes and the revocation lane
//
// The strict loader above is a USABILITY gate: it answers "may a node boot
// on this pack". Two operators need answers it cannot give — the apply gate
// ("is the rendered tree still in the current format?") and revocation
// ("which credentials does this directory carry, regardless of format?").
// Both are served by the lenient probes below; neither weakens the strict
// path.
// ---------------------------------------------------------------------------

/// Why a pack directory's `pack.toml` is not in the current pack format.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PackTreeStale {
    /// No pack.toml at all — the directory is not a rendered pack (or a
    /// render never completed).
    Missing,
    /// pack.toml fails the strict metadata parse — a pre-canonical pack
    /// (before the 2026-10-10 constant-field batch) or a damaged file.
    Unparseable,
    /// pack.toml declares a `format_version` the loader no longer accepts.
    Retired(u8),
}

impl PackTreeStale {
    /// The apply-gate narration: what the operator should learn from one
    /// glance at the re-render line.
    #[must_use]
    pub fn narrate(&self) -> String {
        match self {
            PackTreeStale::Missing => "pack.toml is missing".to_owned(),
            PackTreeStale::Unparseable => {
                "pack.toml does not parse as the current pack format (a retired vintage)".to_owned()
            }
            PackTreeStale::Retired(found) => {
                format!("pack.toml declares retired format_version {found}")
            }
        }
    }
}

/// Strict metadata probe for the apply gate: does `dir` carry a pack.toml in
/// the CURRENT format? "Already applied" is a claim about the observable
/// output tree, so a pack the strict loader would refuse is not "applied" in
/// any useful sense — the next apply re-renders it. `None` = current.
#[must_use]
pub fn probe_pack_format(dir: &Path) -> Option<PackTreeStale> {
    let path = dir.join("pack.toml");
    let Ok(text) = std::fs::read_to_string(&path) else {
        return Some(PackTreeStale::Missing);
    };
    let Ok(metadata) = toml::from_str::<PackMetadata>(&text) else {
        return Some(PackTreeStale::Unparseable);
    };
    if metadata.format_version != FORMAT_VERSION {
        return Some(PackTreeStale::Retired(metadata.format_version));
    }
    None
}

/// One revocable credential as found by the directory scans. Everything the
/// deny list needs comes from the certificate itself — the serial from the
/// PEM, the issuer attribution from the URI SAN — so pack.toml vintage is
/// irrelevant here by design.
#[derive(Debug, Clone)]
pub struct RevocationIdentity {
    pub principal: PrincipalPath,
    pub cert_pem: String,
}

/// Scans `identity/*.crt` for revocable credentials: the revocation lane's
/// front door. Unlike [`CredentialPack::load`] it demands only that the
/// certificates parse — a pack whose format the strict loader refuses (a
/// retired vintage, a damaged pack.toml) still carries live credentials the
/// deny list must reach. Revocation is the emergency lane; it never
/// inherits the usability gate.
pub fn scan_revocation_identities(dir: &Path) -> Result<Vec<RevocationIdentity>> {
    scan_cert_dir(&dir.join("identity"))
}

/// Scans the active (renewed) credential sequence under
/// `state/credentials` — the serials a running node actually authenticates
/// with after renewals superseded its bootstrap identities (the same leg
/// `ActiveCredentialSet::load_existing` used to feed). Best-effort: no
/// state channel or unreadable pointer → no entries, never an error that
/// could block revoking the bootstrap credentials.
#[must_use]
pub fn scan_active_credentials(dir: &Path) -> Vec<RevocationIdentity> {
    // Local shape of credentials.rs' pointer file — only the sequence
    // number matters here; `updated` is ignored by the tolerant parse.
    #[derive(serde::Deserialize)]
    struct ActivePointer {
        sequence: u64,
    }
    let pointer_path = dir.join("state").join("credentials").join("current.json");
    let Ok(text) = std::fs::read_to_string(&pointer_path) else {
        return Vec::new();
    };
    let Ok(pointer) = serde_json::from_str::<ActivePointer>(&text) else {
        return Vec::new();
    };
    let sequence_dir = dir
        .join("state")
        .join("credentials")
        .join("sequences")
        .join(pointer.sequence.to_string());
    scan_cert_dir(&sequence_dir).unwrap_or_default()
}

fn scan_cert_dir(dir: &Path) -> Result<Vec<RevocationIdentity>> {
    let mut found = Vec::new();
    for entry in std::fs::read_dir(dir).map_err(|e| Error::Io {
        path: dir.display().to_string(),
        source: e,
    })? {
        let entry = entry.map_err(|e| Error::Io {
            path: dir.display().to_string(),
            source: e,
        })?;
        let path = entry.path();
        if path.extension().is_none_or(|ext| ext != "crt") {
            continue;
        }
        let cert_pem = std::fs::read_to_string(&path).map_err(|e| Error::Io {
            path: path.display().to_string(),
            source: e,
        })?;
        let certs = pem_certs(cert_pem.as_bytes())?;
        let leaf = certs
            .first()
            .ok_or_else(|| Error::pack(format!("{}: no certificate in PEM", path.display())))?;
        let uri_san = uri_san_from_cert_der(leaf)?.ok_or_else(|| {
            Error::pack(format!(
                "{}: certificate carries no principal URI SAN — it cannot be attributed to \
                 an issuer for revocation",
                path.display()
            ))
        })?;
        found.push(RevocationIdentity {
            principal: PrincipalPath::parse_uri(&uri_san)?,
            cert_pem,
        });
    }
    Ok(found)
}

/// Lenient generation probe for `rotate`: the next generation number is
/// self-describing in pack.toml and valid across format vintages — and
/// rotate REPLACES the pack, it does not consume it, so the strict loader is
/// neither required nor appropriate there. Still fail-loud when the file is
/// not parseable TOML or carries no generation at all.
pub fn pack_generation_of(dir: &Path) -> Result<Generation> {
    #[derive(serde::Deserialize)]
    struct GenerationOnly {
        generation: Generation,
    }
    let path = dir.join("pack.toml");
    let text = std::fs::read_to_string(&path).map_err(|e| Error::Io {
        path: path.display().to_string(),
        source: e,
    })?;
    let probe: GenerationOnly = toml::from_str(&text)
        .map_err(|e| Error::pack("pack.toml parse".to_string()).with_source(e))?;
    Ok(probe.generation)
}

/// Lenient identity probe for rotate's staging cleanup: the candidate
/// directory's own pack must AGREE on `node` and `generation` before the
/// janitorial sweep may delete it — a node merely named `<x>-gen<n>` (its
/// BASE directory looks like another node's staging name) must never lose
/// its pack to the sweep. Same lenient stance as
/// [`pack_generation_of`]; a vintage pack.toml without `node` simply fails
/// the probe and the candidate is left in place.
pub fn pack_node_and_generation_of(dir: &Path) -> Result<(String, Generation)> {
    #[derive(serde::Deserialize)]
    struct NodeAndGeneration {
        node: String,
        generation: Generation,
    }
    let path = dir.join("pack.toml");
    let text = std::fs::read_to_string(&path).map_err(|e| Error::Io {
        path: path.display().to_string(),
        source: e,
    })?;
    let probe: NodeAndGeneration = toml::from_str(&text)
        .map_err(|e| Error::pack("pack.toml parse".to_string()).with_source(e))?;
    Ok((probe.node, probe.generation))
}

/// The SHA256SUMS digest as revocation-record provenance, when the file is
/// intact. Tolerant on purpose: the digest is context for humans, not a
/// gate — its absence must not block a revocation.
#[must_use]
pub fn pack_digest_of(dir: &Path) -> Option<String> {
    digests_file_digest(dir).ok()
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

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use crate::manifest::Manifest;
    use crate::pack::render::AgentCredentialPack;

    fn manifest_text() -> String {
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
"#
        .to_owned()
    }

    /// A rendered agent pack (current format) plus its pack.toml text.
    fn rendered_agent_pack(tag: &str) -> (tempfile::TempDir, std::path::PathBuf) {
        let tmp = tempfile::tempdir().unwrap();
        let issuer = crate::issuance::IssuerStore::open(tmp.path().join("issuer"));
        issuer.ensure_realm().unwrap();
        issuer.ensure_workspace("main").unwrap();
        issuer.ensure_policy_key().unwrap();
        let manifest = Manifest::parse(&manifest_text()).unwrap();
        let out = tmp.path().join(tag);
        AgentCredentialPack::render(&issuer, &manifest, "desktop", 1, &out).unwrap();
        (tmp, out)
    }

    /// Rewrites pack.toml into the pre-canonical vintage: the constant-field
    /// batch of 2026-10-10 made `workspace` (among others) always-present, so
    /// removing the line turns a current pack into one the strict loader
    /// refuses — the exact retirement shape the scans must survive.
    fn deprecate_pack_format(out: &Path) {
        let text = std::fs::read_to_string(out.join("pack.toml")).unwrap();
        let legacy = text
            .lines()
            .filter(|line| !line.starts_with("workspace"))
            .collect::<Vec<_>>()
            .join("\n");
        std::fs::write(out.join("pack.toml"), format!("{legacy}\n")).unwrap();
    }

    #[test]
    fn probe_pack_format_classifies_every_stale_shape() {
        let (_guard, out) = rendered_agent_pack("probe");
        assert_eq!(probe_pack_format(&out), None, "a current pack is current");

        std::fs::remove_file(out.join("pack.toml")).unwrap();
        assert_eq!(probe_pack_format(&out), Some(PackTreeStale::Missing));

        let (_guard, out) = rendered_agent_pack("probe-legacy");
        deprecate_pack_format(&out);
        assert_eq!(probe_pack_format(&out), Some(PackTreeStale::Unparseable));

        let (_guard, out) = rendered_agent_pack("probe-retired");
        let text = std::fs::read_to_string(out.join("pack.toml"))
            .unwrap()
            .replace("format_version = 1", "format_version = 2");
        std::fs::write(out.join("pack.toml"), text).unwrap();
        assert_eq!(probe_pack_format(&out), Some(PackTreeStale::Retired(2)));
        assert!(PackTreeStale::Retired(2).narrate().contains('2'));
    }

    #[test]
    fn revocation_scan_reaches_legacy_format_packs() {
        let (_guard, out) = rendered_agent_pack("scan");
        let expected = CredentialPack::load(&out).unwrap();
        let expected_principal = expected.primary_identity().unwrap().principal.to_string();

        let scanned = scan_revocation_identities(&out).unwrap();
        assert_eq!(scanned.len(), 1, "the agent pack carries one identity");
        assert_eq!(scanned[0].principal.to_string(), expected_principal);

        // The retirement lane: the same directory with a pack.toml the
        // strict loader refuses still yields every revocable credential.
        deprecate_pack_format(&out);
        assert!(
            CredentialPack::load(&out).is_err(),
            "fixture must be strict-unloadable"
        );
        let scanned = scan_revocation_identities(&out).unwrap();
        assert_eq!(scanned.len(), 1);
        assert_eq!(scanned[0].principal.to_string(), expected_principal);
    }

    #[test]
    fn active_credential_scan_follows_the_sequence_pointer() {
        let (_guard, out) = rendered_agent_pack("active");
        assert!(
            scan_active_credentials(&out).is_empty(),
            "no state channel → no active entries"
        );

        let creds = out.join("state").join("credentials");
        let seq = creds.join("sequences").join("1");
        std::fs::create_dir_all(&seq).unwrap();
        std::fs::copy(
            out.join("identity").join("agent-main.crt"),
            seq.join("agent-main.crt"),
        )
        .unwrap();
        std::fs::write(
            creds.join("current.json"),
            r#"{"sequence": 1, "updated": "2026-10-12T00:00:00Z"}"#,
        )
        .unwrap();

        let scanned = scan_active_credentials(&out);
        assert_eq!(scanned.len(), 1);
        assert_eq!(
            scanned[0].principal.to_string(),
            "spiffe://promptcn/main/agent/desktop"
        );

        // A damaged pointer never blocks the lane — it just yields nothing
        // (the bootstrap scan carries the revocation).
        std::fs::write(creds.join("current.json"), "{ not json").unwrap();
        assert!(scan_active_credentials(&out).is_empty());
    }

    #[test]
    fn generation_probe_reads_across_format_vintages() {
        let (_guard, out) = rendered_agent_pack("gen");
        assert_eq!(pack_generation_of(&out).unwrap(), 1);

        deprecate_pack_format(&out);
        assert_eq!(
            pack_generation_of(&out).unwrap(),
            1,
            "rotate must number the next generation from ANY vintage"
        );

        std::fs::remove_file(out.join("pack.toml")).unwrap();
        assert!(pack_generation_of(&out).is_err());
    }

    #[test]
    fn pack_digest_probe_is_provenance_not_a_gate() {
        let (_guard, out) = rendered_agent_pack("digest");
        let digest = pack_digest_of(&out).expect("a rendered pack carries SHA256SUMS");
        assert!(digest.starts_with("sha256:"));
        assert_eq!(digest, CredentialPack::load(&out).unwrap().pack_digest);

        let empty = tempfile::tempdir().unwrap();
        assert_eq!(pack_digest_of(empty.path()), None);
    }
}
