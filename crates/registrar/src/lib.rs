//! The independent identity registrar.
//!
//! The registrar is not the control endpoint and never shares a host or
//! process with it: a compromised hub must not be able to mint identities.
//! Nodes enroll once with an operator-issued code and thereafter renew a
//! client-generated key pair using their current short-lived certificate.

pub mod server;
pub mod service;

pub use service::{
    ControlEndpoints, EnrollmentCode, EnrollmentCodes, IssuedCredential, PeerCredential,
    RegistrarService, RotationState, parse_peer,
};

use interflow_identity::Result;
use interflow_identity::issuance::IssuerStore;
use std::path::PathBuf;

/// Where issuer material lives. File-backed stores are the self-hosted
/// baseline; KMS/HSM/Vault adapters implement the same trait later.
pub trait KeySource: Send + Sync {
    fn issuer_store(&self) -> Result<&IssuerStore>;
}

/// Filesystem key source protected by host permissions.
pub struct FileKeySource {
    store: IssuerStore,
}

impl FileKeySource {
    pub fn open(root: impl Into<PathBuf> + AsRef<std::path::Path>) -> Result<Self> {
        let store = IssuerStore::open(root);
        store.ensure_realm()?;
        store.ensure_policy_key()?;
        Ok(Self { store })
    }
}

impl KeySource for FileKeySource {
    fn issuer_store(&self) -> Result<&IssuerStore> {
        Ok(&self.store)
    }
}
