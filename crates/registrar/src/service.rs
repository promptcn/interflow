//! Durable enrollment, two-phase renewal, and registrar-owned revocation.

use crate::KeySource;
use fs2::FileExt;
use interflow_identity::issuance::{LeafTtl, LoadedIssuer, endpoint_hostnames};
use interflow_identity::pem_certs;
use interflow_identity::revocation::RevocationList;
use interflow_identity::timestamp::{parse_rfc3339, rfc3339};
use interflow_identity::{Error, PrincipalKind, PrincipalPath, Result, uri_san_from_cert_der};
use interflow_util::sha256_hex;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, HashMap};
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use time::{Duration, OffsetDateTime};

const ENROLLMENT_TTL: Duration = Duration::hours(1);
const PENDING_TTL: Duration = Duration::minutes(10);

/// A one-time enrollment authorization returned to the operator.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EnrollmentCode {
    pub code: String,
    pub realm: String,
    pub kind: String,
    pub workspace: Option<String>,
    pub node: String,
    #[serde(default, skip_serializing)]
    pub used: bool,
    pub created: String,
    pub expires: String,
}

/// The persisted form. The clear code is never stored.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
struct EnrollmentRecord {
    code_hash: String,
    realm: String,
    kind: String,
    workspace: Option<String>,
    node: String,
    used: bool,
    created: String,
    expires: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
struct EnrollmentFile {
    records: Vec<EnrollmentRecord>,
}

/// Durable, single-use enrollment administration.
pub struct EnrollmentCodes {
    path: Option<PathBuf>,
    inner: Mutex<EnrollmentFile>,
}

impl EnrollmentCodes {
    /// In-memory codes for unit tests. Production commands use [`Self::open`].
    #[must_use]
    pub fn new() -> Self {
        Self {
            path: None,
            inner: Mutex::new(EnrollmentFile::default()),
        }
    }

    /// Opens a persisted enrollment database at `path`.
    pub fn open(path: impl Into<PathBuf>) -> Result<Self> {
        let path = path.into();
        let inner = load_json(&path)?.unwrap_or_default();
        Ok(Self {
            path: Some(path),
            inner: Mutex::new(inner),
        })
    }

    pub fn create(
        &self,
        realm: &str,
        kind: PrincipalKind,
        workspace: Option<&str>,
        node: &str,
    ) -> Result<EnrollmentCode> {
        let mut entropy = [0u8; 24];
        // `getrandom::Error` does not implement `std::error::Error`, so the
        // message is the only place the cause can surface.
        getrandom::fill(&mut entropy)
            .map_err(|e| Error::issuance(format!("enrollment entropy: {e}")))?;
        let code = format!("iflow-{kind}-{}", hex::encode(entropy));
        let now = OffsetDateTime::now_utc();
        let created = rfc3339(now)?;
        let expires = rfc3339(now + ENROLLMENT_TTL)?;
        let record = EnrollmentRecord {
            code_hash: hash_code(&code),
            realm: realm.to_owned(),
            kind: kind.to_string(),
            workspace: workspace.map(str::to_owned),
            node: node.to_owned(),
            used: false,
            created: created.clone(),
            expires: expires.clone(),
        };
        let returned = EnrollmentCode {
            code,
            realm: realm.to_owned(),
            kind: kind.to_string(),
            workspace: workspace.map(str::to_owned),
            node: node.to_owned(),
            used: false,
            created,
            expires,
        };
        {
            let mut guard = self.inner.lock().expect("enrollment lock");
            if let Some(path) = &self.path {
                let file_store = load_locked::<EnrollmentFile>(path)?;
                guard.records = file_store.records;
            }
            guard.records.push(record);
            if let Some(path) = &self.path {
                save_locked(path, &*guard)?;
            }
        }
        Ok(returned)
    }

    pub fn consume(&self, code: &str) -> Result<EnrollmentCode> {
        let hash = hash_code(code);
        let mut guard = self.inner.lock().expect("enrollment lock");
        if let Some(path) = &self.path {
            let file_store = load_locked::<EnrollmentFile>(path)?;
            guard.records = file_store.records;
        }
        let now = OffsetDateTime::now_utc();
        let record = guard
            .records
            .iter_mut()
            .find(|record| record.code_hash == hash)
            .ok_or_else(|| {
                Error::issuance(
                    "unknown enrollment code — ask your administrator for one".to_owned(),
                )
            })?;
        let expires = parse_rfc3339(&record.expires)?;
        if now > expires {
            return Err(Error::issuance(format!(
                "enrollment code expired at {} — request a fresh one",
                record.expires
            )));
        }
        if record.used {
            return Err(Error::issuance(format!(
                "enrollment code has already been used (node {:?}) — request a fresh one",
                record.node
            )));
        }
        record.used = true;
        let returned = EnrollmentCode {
            code: code.to_owned(),
            realm: record.realm.clone(),
            kind: record.kind.clone(),
            workspace: record.workspace.clone(),
            node: record.node.clone(),
            used: true,
            created: record.created.clone(),
            expires: record.expires.clone(),
        };
        if let Some(path) = &self.path {
            save_locked(path, &*guard)?;
        }
        Ok(returned)
    }
}

impl Default for EnrollmentCodes {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
struct PendingRotation {
    renewal_id: String,
    old_serial: String,
    new_serial: String,
    expires: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
struct PrincipalRotation {
    current_serial: Option<String>,
    previous_serial: Option<String>,
    pending: Option<PendingRotation>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
struct RotationFile {
    principals: HashMap<String, PrincipalRotation>,
}

/// Durable current/previous/pending serial state.
pub struct RotationState {
    path: Option<PathBuf>,
    inner: Mutex<RotationFile>,
}

impl RotationState {
    #[must_use]
    pub fn new() -> Self {
        Self {
            path: None,
            inner: Mutex::new(RotationFile::default()),
        }
    }

    pub fn open(path: impl Into<PathBuf>) -> Result<Self> {
        let path = path.into();
        let inner = load_json(&path)?.unwrap_or_default();
        Ok(Self {
            path: Some(path),
            inner: Mutex::new(inner),
        })
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, RotationFile> {
        self.inner.lock().expect("rotation state lock")
    }
}

impl Default for RotationState {
    fn default() -> Self {
        Self::new()
    }
}

/// A parsed mTLS peer certificate plus its presented chain.
#[derive(Debug, Clone)]
pub struct PeerCredential {
    pub principal: PrincipalPath,
    pub serial: String,
    pub not_after: OffsetDateTime,
    pub chain_fingerprints: Vec<String>,
}

/// A certificate-issuance response. The private key stays on the caller.
#[derive(Debug, Clone, Serialize)]
pub struct IssuedCredential {
    pub principal: String,
    pub cert_pem: String,
    pub chain_pem: String,
    pub expires: String,
    pub serial: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub renewal_id: Option<String>,
}

pub struct RegistrarService<S> {
    source: S,
    enrollments: EnrollmentCodes,
    rotations: RotationState,
    ttl: LeafTtl,
    control_endpoints: ControlEndpoints,
}

/// The registrar's authority over control-identity SANs.
///
/// One deployment default endpoint plus per-node overrides — a
/// site-to-site hub node's server credential carries the hub's dial
/// address, not the expose endpoint. The registrar (not the renewing
/// client) decides which hostname a renewed control credential may carry.
#[derive(Debug, Clone)]
pub struct ControlEndpoints {
    default: String,
    hubs: BTreeMap<String, String>,
}

impl ControlEndpoints {
    pub fn new(default: impl Into<String>) -> Self {
        Self {
            default: default.into(),
            hubs: BTreeMap::new(),
        }
    }

    /// Registers one hub node's dial address as its SAN authority.
    #[must_use]
    pub fn with_hub(mut self, node: &str, endpoint: &str) -> Self {
        self.hubs.insert(node.to_owned(), endpoint.to_owned());
        self
    }

    /// The endpoint whose hostname a renewed control identity for `node`
    /// must carry.
    pub fn endpoint_for(&self, node: &str) -> &str {
        self.hubs.get(node).unwrap_or(&self.default)
    }
}

impl<S: KeySource> RegistrarService<S> {
    pub const fn new(
        source: S,
        enrollments: EnrollmentCodes,
        rotations: RotationState,
        ttl: LeafTtl,
        control_endpoints: ControlEndpoints,
    ) -> Self {
        Self {
            source,
            enrollments,
            rotations,
            ttl,
            control_endpoints,
        }
    }

    pub const fn source(&self) -> &S {
        &self.source
    }

    pub const fn ttl(&self) -> LeafTtl {
        self.ttl
    }

    pub fn enroll(&self, code: &str, csr_pem: &str) -> Result<IssuedCredential> {
        let authorization = self.enrollments.consume(code)?;
        let kind = PrincipalKind::from_segment(&authorization.kind).ok_or_else(|| {
            Error::issuance(format!("unknown enrollment kind {:?}", authorization.kind))
        })?;
        let principal = match kind {
            PrincipalKind::Agent | PrincipalKind::Ingress => {
                let workspace = authorization.workspace.as_deref().ok_or_else(|| {
                    Error::issuance(format!("{kind} enrollment requires a workspace"))
                })?;
                PrincipalPath::workspace_member(
                    &authorization.realm,
                    workspace,
                    kind,
                    &authorization.node,
                )?
            }
            PrincipalKind::Control => {
                return Err(Error::issuance(
                    "control endpoint identities are realm-issued, not enrolled".to_owned(),
                ));
            }
            PrincipalKind::Hub => {
                return Err(Error::issuance(
                    "hub identities are realm infrastructure, issued offline by \
                     `interflow plan apply` — not enrolled"
                        .to_owned(),
                ));
            }
        };
        let store = self.source.issuer_store()?;
        store.ensure_workspace(principal.workspace.as_deref().unwrap_or_default())?;
        let issuer = store.workspace_issuer(principal.workspace.as_deref().unwrap_or_default())?;
        let material = issuer.issue_csr(&principal, &[], false, self.ttl, csr_pem)?;
        self.set_current(&principal, &material.serial)?;
        audit(
            self.source.issuer_store()?.root_path(),
            "enrollment_succeeded",
            &principal,
            &material.serial,
        );
        issued(
            &material.principal,
            material.cert_pem,
            material.chain_pem,
            material.not_after,
            material.serial,
            None,
        )
    }

    pub fn renew(&self, peer: &PeerCredential, csr_pem: &str) -> Result<IssuedCredential> {
        assert_client(&peer.principal)?;
        let now = OffsetDateTime::now_utc();
        if peer.not_after <= now {
            return Err(Error::issuance(
                "the presented credential has expired — enroll a new node".to_owned(),
            ));
        }
        let store = self.source.issuer_store()?;
        if revoked(store.root_path(), &peer.serial)? {
            return Err(Error::issuance(
                "the presented credential is revoked — enrollment is required".to_owned(),
            ));
        }
        let issuer = issuer_for_principal(store, &peer.principal)?;
        verify_issuer(&issuer, peer)?;
        let mut state = self.rotations.lock();
        if let Some(path) = &self.rotations.path {
            state.principals = load_locked::<RotationFile>(path)?.principals;
        }
        let entry = state
            .principals
            .entry(peer.principal.to_string())
            .or_default();
        if let Some(pending) = &entry.pending {
            let expires = parse_rfc3339(&pending.expires)?;
            if now < expires {
                return Err(Error::issuance(
                    "a renewal is already pending for this principal — activate and confirm it \
                     first"
                        .to_owned(),
                ));
            }
            entry.pending = None;
        }
        if let Some(current) = entry.current_serial.as_ref()
            && current != &peer.serial
        {
            audit(
                store.root_path(),
                "rotation_divergence_detected",
                &peer.principal,
                &peer.serial,
            );
            return Err(Error::issuance(
                "credential is no longer the current serial for this principal".to_owned(),
            ));
        }
        let material = issuer.issue_csr(&peer.principal, &[], false, self.ttl, csr_pem)?;
        let renewal_id = sha256_hex(
            format!("{}:{}:{}", peer.principal, peer.serial, material.serial).as_bytes(),
        )[..24]
            .to_owned();
        entry.pending = Some(PendingRotation {
            renewal_id: renewal_id.clone(),
            old_serial: peer.serial.clone(),
            new_serial: material.serial.clone(),
            expires: rfc3339(now + PENDING_TTL)?,
        });
        if let Some(path) = &self.rotations.path {
            save_locked(path, &*state)?;
        }
        drop(state);
        audit(
            store.root_path(),
            "renewal_issued",
            &peer.principal,
            &material.serial,
        );
        issued(
            &material.principal,
            material.cert_pem,
            material.chain_pem,
            material.not_after,
            material.serial,
            Some(renewal_id),
        )
    }

    pub fn renew_control(
        &self,
        peer: &PeerCredential,
        target: &PrincipalPath,
        old_serial: &str,
        csr_pem: &str,
    ) -> Result<IssuedCredential> {
        if !matches!(
            peer.principal.kind,
            PrincipalKind::Ingress | PrincipalKind::Hub
        ) || peer.principal.realm != target.realm
            || peer.principal.node != target.node
            || target.kind != PrincipalKind::Control
            || target.workspace.is_some()
        {
            return Err(Error::issuance(
                "control renewal may only be authorized by an ingress or hub principal for \
                 the same realm and node"
                    .to_owned(),
            ));
        }
        let now = OffsetDateTime::now_utc();
        if peer.not_after <= now {
            return Err(Error::issuance(
                "the authorization credential has expired".to_owned(),
            ));
        }
        let store = self.source.issuer_store()?;
        if revoked(store.root_path(), &peer.serial)? {
            return Err(Error::issuance(
                "the authorization credential is revoked".to_owned(),
            ));
        }
        let peer_issuer = issuer_for_principal(store, &peer.principal)?;
        verify_issuer(&peer_issuer, peer)?;
        let issuer = store.realm_issuer()?;
        let dns_names = endpoint_hostnames(self.control_endpoints.endpoint_for(&target.node))?;
        let material = issuer.issue_csr(target, &dns_names, true, self.ttl, csr_pem)?;
        let mut state = self.rotations.lock();
        if let Some(path) = &self.rotations.path {
            state.principals = load_locked::<RotationFile>(path)?.principals;
        }
        let entry = state.principals.entry(target.to_string()).or_default();
        if let Some(pending) = &entry.pending {
            let expires = parse_rfc3339(&pending.expires)?;
            if now < expires {
                return Err(Error::issuance(
                    "a control renewal is already pending — activate and confirm it first"
                        .to_owned(),
                ));
            }
            entry.pending = None;
        }
        match entry.current_serial.as_deref() {
            Some(current) if current == old_serial => {}
            None if old_serial != "bootstrap" => {}
            _ => {
                return Err(Error::issuance(
                    "control credential is no longer the current serial".to_owned(),
                ));
            }
        }
        let id = renewal_id(target, Some(old_serial), &material.serial);
        entry.pending = Some(PendingRotation {
            renewal_id: id.clone(),
            old_serial: old_serial.to_owned(),
            new_serial: material.serial.clone(),
            expires: rfc3339(now + PENDING_TTL)?,
        });
        if let Some(path) = &self.rotations.path {
            save_locked(path, &*state)?;
        }
        drop(state);
        audit(
            store.root_path(),
            "renewal_issued",
            target,
            &material.serial,
        );
        issued(
            &material.principal,
            material.cert_pem,
            material.chain_pem,
            material.not_after,
            material.serial,
            Some(id),
        )
    }

    pub fn confirm_control(
        &self,
        peer: &PeerCredential,
        target: &PrincipalPath,
        renewal_id: &str,
        new_serial: &str,
    ) -> Result<()> {
        if !matches!(
            peer.principal.kind,
            PrincipalKind::Ingress | PrincipalKind::Hub
        ) || peer.principal.realm != target.realm
            || peer.principal.node != target.node
            || target.kind != PrincipalKind::Control
        {
            return Err(Error::issuance(
                "control confirmation is not authorized for this node's client principal"
                    .to_owned(),
            ));
        }
        let store = self.source.issuer_store()?;
        if revoked(store.root_path(), &peer.serial)? {
            return Err(Error::issuance(
                "the authorization credential is revoked".to_owned(),
            ));
        }
        let mut state = self.rotations.lock();
        if let Some(path) = &self.rotations.path {
            state.principals = load_locked::<RotationFile>(path)?.principals;
        }
        let key = target.to_string();
        let Some(entry) = state.principals.get_mut(&key) else {
            return Err(Error::issuance("no control rotation is pending".to_owned()));
        };
        let Some(pending) = entry.pending.clone() else {
            return Ok(());
        };
        if pending.renewal_id != renewal_id || pending.new_serial != new_serial {
            return Err(Error::issuance(
                "control confirmation does not match the pending renewal".to_owned(),
            ));
        }
        entry.previous_serial = Some(pending.old_serial.clone());
        entry.current_serial = Some(pending.new_serial.clone());
        entry.pending = None;
        if let Some(path) = &self.rotations.path {
            save_locked(path, &*state)?;
        }
        drop(state);
        if pending.old_serial != "bootstrap" {
            let mut list = RevocationList::load(store.root_path())?;
            if !list.is_revoked(&pending.old_serial) {
                list.entries
                    .push(interflow_identity::revocation::RevocationEntry {
                        serial: pending.old_serial,
                        issuer: "control".to_owned(),
                        reason: "superseded".to_owned(),
                        revoked_at: rfc3339(OffsetDateTime::now_utc())?,
                        pack_digest: None,
                    });
                list.save(store.root_path())?;
            }
        }
        audit(store.root_path(), "rotation_succeeded", target, new_serial);
        Ok(())
    }

    pub fn confirm(&self, peer: &PeerCredential, renewal_id: &str) -> Result<()> {
        assert_client(&peer.principal)?;
        let store = self.source.issuer_store()?;
        if revoked(store.root_path(), &peer.serial)? {
            return Err(Error::issuance(
                "revoked credentials cannot confirm rotation".to_owned(),
            ));
        }
        let issuer = issuer_for_principal(store, &peer.principal)?;
        verify_issuer(&issuer, peer)?;
        let mut state = self.rotations.lock();
        if let Some(path) = &self.rotations.path {
            state.principals = load_locked::<RotationFile>(path)?.principals;
        }
        let principal_key = peer.principal.to_string();
        let Some(entry) = state.principals.get_mut(&principal_key) else {
            return Err(Error::issuance(
                "no rotation is pending for this principal".to_owned(),
            ));
        };
        let Some(pending) = entry.pending.clone() else {
            if entry.current_serial.as_deref() == Some(peer.serial.as_str()) {
                return Ok(());
            }
            return Err(Error::issuance(
                "no rotation is pending for this principal".to_owned(),
            ));
        };
        if pending.renewal_id != renewal_id || pending.new_serial != peer.serial {
            return Err(Error::issuance(
                "the presented certificate does not match the pending renewal".to_owned(),
            ));
        }
        entry.previous_serial = Some(pending.old_serial.clone());
        entry.current_serial = Some(pending.new_serial.clone());
        entry.pending = None;
        if let Some(path) = &self.rotations.path {
            save_locked(path, &*state)?;
        }
        drop(state);
        let mut list = RevocationList::load(store.root_path())?;
        if !list.is_revoked(&pending.old_serial) {
            list.entries
                .push(interflow_identity::revocation::RevocationEntry {
                    serial: pending.old_serial,
                    issuer: issuer_name(&peer.principal),
                    reason: "superseded".to_owned(),
                    revoked_at: rfc3339(OffsetDateTime::now_utc())?,
                    pack_digest: None,
                });
            list.save(store.root_path())?;
        }
        audit(
            store.root_path(),
            "rotation_succeeded",
            &peer.principal,
            &peer.serial,
        );
        Ok(())
    }

    fn set_current(&self, principal: &PrincipalPath, serial: &str) -> Result<()> {
        let mut state = self.rotations.lock();
        if let Some(path) = &self.rotations.path {
            state.principals = load_locked::<RotationFile>(path)?.principals;
        }
        let entry = state.principals.entry(principal.to_string()).or_default();
        entry.current_serial = Some(serial.to_owned());
        entry.previous_serial = None;
        entry.pending = None;
        if let Some(path) = &self.rotations.path {
            save_locked(path, &*state)?;
        }
        Ok(())
    }
}

pub fn parse_peer(chain: &[Vec<u8>]) -> Result<PeerCredential> {
    let leaf = chain
        .first()
        .ok_or_else(|| Error::issuance("mTLS peer presented no certificate".to_owned()))?;
    let uri = uri_san_from_cert_der(leaf)?.ok_or_else(|| {
        Error::issuance("mTLS peer certificate carries no principal URI SAN".to_owned())
    })?;
    let parsed = x509_parser::parse_x509_certificate(leaf)
        .map_err(|e| Error::issuance("mTLS peer certificate parse".to_string()).with_source(e))?;
    let eku = parsed
        .1
        .extended_key_usage()
        .map_err(|e| Error::issuance("mTLS peer EKU".to_string()).with_source(e))?;
    if !eku.is_some_and(|usage| usage.value.client_auth) {
        return Err(Error::issuance(
            "mTLS peer certificate is not ClientAuth-bound".to_owned(),
        ));
    }
    let not_after = OffsetDateTime::from_unix_timestamp(parsed.1.validity().not_after.timestamp())
        .map_err(|e| Error::issuance("mTLS peer expiry".to_string()).with_source(e))?;
    Ok(PeerCredential {
        principal: PrincipalPath::parse_uri(&uri)?,
        serial: canonical_serial(parsed.1.raw_serial()),
        not_after,
        chain_fingerprints: chain.iter().map(|der| sha256_hex(der)).collect(),
    })
}

fn assert_client(principal: &PrincipalPath) -> Result<()> {
    if principal.kind == PrincipalKind::Control {
        Err(Error::issuance(
            "control endpoint identities cannot renew through the client registrar".to_owned(),
        ))
    } else {
        Ok(())
    }
}

fn issuer_for_principal(
    store: &interflow_identity::issuance::IssuerStore,
    principal: &PrincipalPath,
) -> Result<LoadedIssuer> {
    if principal.kind == PrincipalKind::Hub {
        // The hub client principal is realm-scoped: renewed by the realm
        // issuer through the same member-renewal path as workspace
        // principals.
        return store.realm_issuer();
    }
    let Some(workspace) = principal.workspace.as_deref() else {
        return Err(Error::issuance(
            "registrar renewal is workspace-scoped; control credentials renew via the \
             authorized control path"
                .to_owned(),
        ));
    };
    store.workspace_issuer(workspace)
}

fn renewal_id(principal: &PrincipalPath, old_serial: Option<&str>, new_serial: &str) -> String {
    sha256_hex(
        format!(
            "{principal}:{}:{new_serial}",
            old_serial.unwrap_or("bootstrap")
        )
        .as_bytes(),
    )[..24]
        .to_owned()
}

fn verify_issuer(issuer: &LoadedIssuer, peer: &PeerCredential) -> Result<()> {
    let issuer_der = pem_certs(issuer.cert_pem().as_bytes())?
        .first()
        .cloned()
        .ok_or_else(|| Error::issuance("issuer PEM carries no certificate".to_owned()))?;
    let fingerprint = sha256_hex(&issuer_der);
    if peer.chain_fingerprints.contains(&fingerprint) {
        Ok(())
    } else {
        Err(Error::issuance(
            "peer certificate was not issued by the expected workspace issuer".to_owned(),
        ))
    }
}

fn issuer_name(principal: &PrincipalPath) -> String {
    principal.workspace.as_deref().map_or_else(
        || "control".to_owned(),
        |workspace| format!("workspace/{workspace}"),
    )
}

fn revoked(root: &Path, serial: &str) -> Result<bool> {
    Ok(RevocationList::load(root)?.is_revoked(serial))
}

#[allow(clippy::too_many_arguments)]
fn issued(
    principal: &PrincipalPath,
    cert_pem: String,
    chain_pem: String,
    not_after: OffsetDateTime,
    serial: String,
    renewal_id: Option<String>,
) -> Result<IssuedCredential> {
    Ok(IssuedCredential {
        principal: principal.to_string(),
        cert_pem,
        chain_pem,
        expires: rfc3339(not_after)?,
        serial,
        renewal_id,
    })
}

fn hash_code(code: &str) -> String {
    sha256_hex(code.as_bytes())
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

fn load_json<T: for<'de> Deserialize<'de>>(path: &Path) -> Result<Option<T>> {
    match std::fs::read_to_string(path) {
        Ok(text) => serde_json::from_str(&text)
            .map(Some)
            .map_err(|e| Error::serialize(path.display().to_string()).with_source(e)),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(Error::Io {
            path: path.display().to_string(),
            source: e,
        }),
    }
}

fn load_locked<T: Default + for<'de> Deserialize<'de>>(path: &Path) -> Result<T> {
    let lock = std::fs::File::create(path.with_extension("lock")).map_err(|e| Error::Io {
        path: path.display().to_string(),
        source: e,
    })?;
    lock.lock_exclusive().map_err(|e| Error::Io {
        path: path.display().to_string(),
        source: e,
    })?;
    Ok(load_json::<T>(path)?.unwrap_or_default())
}

fn save_locked<T: Serialize>(path: &Path, value: &T) -> Result<()> {
    let lock = std::fs::File::create(path.with_extension("lock")).map_err(|e| Error::Io {
        path: path.display().to_string(),
        source: e,
    })?;
    lock.lock_exclusive().map_err(|e| Error::Io {
        path: path.display().to_string(),
        source: e,
    })?;
    let text = serde_json::to_vec_pretty(value)
        .map_err(|e| Error::serialize(path.display().to_string()).with_source(e))?;
    // 0600: the state file carries single-use enrollment codes; existing
    // bits are preserved, new files start private.
    interflow_util::atomic_write(path, &text, interflow_util::WriteMode::PreserveOr(0o600)).map_err(
        |e| Error::Io {
            path: path.display().to_string(),
            source: e,
        },
    )
}

fn audit(root: &Path, event: &str, principal: &PrincipalPath, serial: &str) {
    let record = serde_json::json!({
        "event": event,
        "principal": principal.to_string(),
        "serial": serial,
        "timestamp": rfc3339(OffsetDateTime::now_utc()).unwrap_or_default(),
    });
    if let Some(parent) = root.parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    use std::io::Write;
    if let Ok(mut file) = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(root.join("registrar-audit.jsonl"))
    {
        let _ = writeln!(file, "{record}");
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use crate::{EnrollmentCodes, FileKeySource, RotationState};
    use interflow_identity::issuance::LeafTtl;

    #[test]
    fn control_endpoint_san_extraction_matches_shared_parser() {
        // The renewed control certificate's SAN comes from the same shared
        // parser identity uses: IPv6-safe, port-stripped, fail closed.
        assert_eq!(
            endpoint_hostnames("https://example.com:16666").unwrap(),
            vec!["example.com".to_owned()]
        );
        assert_eq!(
            endpoint_hostnames("[2001:db8::1]:16666").unwrap(),
            vec!["2001:db8::1".to_owned()]
        );
        assert!(endpoint_hostnames("").is_err());
        assert!(endpoint_hostnames("host:99999").is_err());
    }

    #[test]
    fn enrollment_codes_are_durable_single_use() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("enrollments.json");
        let code = EnrollmentCodes::open(&path)
            .unwrap()
            .create("promptcn", PrincipalKind::Agent, Some("main"), "desktop")
            .unwrap();
        let reopened = EnrollmentCodes::open(&path).unwrap();
        let authorization = reopened.consume(&code.code).unwrap();
        assert_eq!(authorization.node, "desktop");
        assert!(reopened.consume(&code.code).is_err());
        let stored = std::fs::read_to_string(&path).unwrap();
        assert!(!stored.contains(&code.code));
    }

    #[test]
    fn csr_enroll_renew_confirm_and_revoke_previous() {
        let dir = tempfile::tempdir().unwrap();
        let issuer = dir.path().join("issuer");
        let source = FileKeySource::open(&issuer).unwrap();
        source
            .issuer_store()
            .unwrap()
            .ensure_workspace("main")
            .unwrap();
        let enrollment_path = dir.path().join("enrollments.json");
        let rotation_path = dir.path().join("rotation-state.json");
        let code = EnrollmentCodes::open(&enrollment_path)
            .unwrap()
            .create("promptcn", PrincipalKind::Agent, Some("main"), "desktop")
            .unwrap();
        let service = RegistrarService::new(
            source,
            EnrollmentCodes::open(&enrollment_path).unwrap(),
            RotationState::open(&rotation_path).unwrap(),
            LeafTtl::default_ttl(),
            ControlEndpoints::new("https://relay.test"),
        );
        let principal =
            PrincipalPath::workspace_member("promptcn", "main", PrincipalKind::Agent, "desktop")
                .unwrap();
        let initial_csr =
            interflow_identity::issuance::generate_csr(&principal, &[], false).unwrap();
        let initial = service.enroll(&code.code, &initial_csr.csr_pem).unwrap();
        let initial_chain = pem_certs(initial.chain_pem.as_bytes()).unwrap();
        let initial_peer = parse_peer(&initial_chain).unwrap();

        let renewal_csr =
            interflow_identity::issuance::generate_csr(&principal, &[], false).unwrap();
        let renewed = service.renew(&initial_peer, &renewal_csr.csr_pem).unwrap();
        assert_ne!(initial.serial, renewed.serial);
        let renewed_chain = pem_certs(renewed.chain_pem.as_bytes()).unwrap();
        let renewed_peer = parse_peer(&renewed_chain).unwrap();
        service
            .confirm(&renewed_peer, renewed.renewal_id.as_deref().unwrap())
            .unwrap();
        assert!(service.renew(&initial_peer, &renewal_csr.csr_pem).is_err());
    }

    /// The site-to-site hub lifecycle: the hub client principal renews
    /// itself through the member path (realm issuer) and authorizes the
    /// hub's control renewal with the hub's own dial address as SAN. Hub
    /// enrollment codes are rejected outright.
    #[test]
    fn hub_principal_renews_itself_and_authorizes_control_with_hub_san() {
        let dir = tempfile::tempdir().unwrap();
        let issuer = dir.path().join("issuer");
        let store = interflow_identity::issuance::IssuerStore::open(&issuer);
        store.ensure_realm().unwrap();
        let source = FileKeySource::open(&issuer).unwrap();
        let enrollment_path = dir.path().join("enrollments.json");
        let rotation_path = dir.path().join("rotation-state.json");
        let service = RegistrarService::new(
            source,
            EnrollmentCodes::open(&enrollment_path).unwrap(),
            RotationState::open(&rotation_path).unwrap(),
            LeafTtl::default_ttl(),
            ControlEndpoints::new("https://relay.test").with_hub("central", "hub.mesh.test:7777"),
        );

        // Offline-issued pack material (the `plan apply` path).
        let hub_principal = PrincipalPath::hub("promptcn", "central").unwrap();
        let hub_material = store
            .issue_hub_member_with_ttl("promptcn", "central", LeafTtl::default_ttl())
            .unwrap();
        assert_eq!(hub_material.principal, hub_principal);
        let control_target = PrincipalPath::control("promptcn", "central").unwrap();
        let control_material = store
            .issue_control_endpoint_with_ttl(
                "promptcn",
                "central",
                "hub.mesh.test:7777",
                LeafTtl::default_ttl(),
            )
            .unwrap();
        let hub_peer = parse_peer(&pem_certs(hub_material.chain_pem.as_bytes()).unwrap()).unwrap();

        // 1. The hub client principal renews itself (realm issuer path).
        let renew_csr =
            interflow_identity::issuance::generate_csr(&hub_principal, &[], false).unwrap();
        let renewed_hub = service.renew(&hub_peer, &renew_csr.csr_pem).unwrap();
        let renewed_peer =
            parse_peer(&pem_certs(renewed_hub.chain_pem.as_bytes()).unwrap()).unwrap();
        service
            .confirm(&renewed_peer, renewed_hub.renewal_id.as_deref().unwrap())
            .unwrap();

        // 2. It authorizes the control renewal (claiming the offline-issued
        //    serial, as the renewal client does); the renewed server
        //    credential carries the hub dial address, not the default.
        let control_csr = interflow_identity::issuance::generate_csr(
            &control_target,
            &["relay.test".to_owned()],
            true,
        )
        .unwrap();
        let renewed_control = service
            .renew_control(
                &renewed_peer,
                &control_target,
                &control_material.serial,
                &control_csr.csr_pem,
            )
            .unwrap();
        let leaf = pem_certs(renewed_control.chain_pem.as_bytes())
            .unwrap()
            .remove(0);
        let parsed = x509_parser::parse_x509_certificate(&leaf).unwrap().1;
        let san = parsed.subject_alternative_name().unwrap().unwrap();
        let dns: Vec<String> = san
            .value
            .general_names
            .iter()
            .filter_map(|gn| match gn {
                x509_parser::extensions::GeneralName::DNSName(d) => Some((*d).to_owned()),
                _ => None,
            })
            .collect();
        assert_eq!(dns, vec!["hub.mesh.test".to_owned()]);
        service
            .confirm_control(
                &renewed_peer,
                &control_target,
                renewed_control.renewal_id.as_deref().unwrap(),
                &renewed_control.serial,
            )
            .unwrap();

        // 3. A hub principal for a different node cannot authorize.
        let other_hub = PrincipalPath::hub("promptcn", "other").unwrap();
        let other_csr =
            interflow_identity::issuance::generate_csr(&control_target, &[], true).unwrap();
        assert!(
            service
                .renew_control(&hub_peer, &other_hub, "bootstrap", &other_csr.csr_pem)
                .is_err()
        );
        // 4. Hub enrollment codes fail closed.
        let code = EnrollmentCodes::open(&enrollment_path)
            .unwrap()
            .create("promptcn", PrincipalKind::Hub, None, "central")
            .unwrap();
        let err = service.enroll(&code.code, &renew_csr.csr_pem).unwrap_err();
        assert!(err.to_string().contains("issued offline"), "{err}");
    }
}
