//! Workspace-scoped ingress principal material.
//!
//! The ingress carries exactly one principal per authorized workspace —
//! the credential both registers the edge's tunnel session under that
//! workspace and drives the inner-TLS client side of every stream routed
//! to it. There is deliberately no cross-workspace identity: a stream for
//! workspace A never presents workspace B's credential.

use interflow_core::error::{InterflowError, Result};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::Mutex;

/// One workspace-scoped ingress principal (the engine's only identity
/// model since the shared-gateway track was retired).
#[derive(Debug, Clone)]
pub struct IngressPrincipal {
    /// The workspace this credential is scoped to.
    pub workspace: String,
    /// Client certificate PEM path (CN = the ingress node's engine id).
    pub cert: PathBuf,
    /// Client key PEM path (0600).
    pub key: PathBuf,
}

/// One workspace's trust anchor (its issuer CA).
#[derive(Debug, Clone)]
pub struct WorkspaceTrust {
    /// The workspace the anchor governs.
    pub workspace: String,
    /// Issuer CA PEM path — verifies that workspace's agents (and anchors
    /// the principal's own chain on the hub plane).
    pub ca: PathBuf,
}

/// The per-deployment ingress identity source: principals plus per-
/// workspace trust anchors, with a per-workspace inner-TLS material cache.
pub struct IngressIdentity {
    principals: HashMap<String, IngressPrincipal>,
    trust: HashMap<String, PathBuf>,
    cache: Mutex<HashMap<String, (u64, Arc<interflow_core::tls::InnerTlsMaterial>)>>,
}

impl IngressIdentity {
    /// Builds the identity source. Duplicate workspaces (in either the
    /// principal or the trust list) are a configuration error.
    pub fn new(principals: Vec<IngressPrincipal>, trust: Vec<WorkspaceTrust>) -> Result<Self> {
        let mut principal_map = HashMap::with_capacity(principals.len());
        for principal in principals {
            let workspace = principal.workspace.clone();
            if principal_map.insert(workspace.clone(), principal).is_some() {
                return Err(InterflowError::config(format!(
                    "duplicate ingress principal for workspace {workspace:?}"
                )));
            }
        }
        let mut trust_map = HashMap::with_capacity(trust.len());
        for anchor in trust {
            let workspace = anchor.workspace.clone();
            if trust_map.insert(workspace.clone(), anchor.ca).is_some() {
                return Err(InterflowError::config(format!(
                    "duplicate trust anchor for workspace {workspace:?}"
                )));
            }
        }
        // Every principal's chain anchors in its own workspace's issuer —
        // an anchor-less workspace cannot boot (fail closed at assembly).
        for workspace in principal_map.keys() {
            if !trust_map.contains_key(workspace) {
                return Err(InterflowError::config(format!(
                    "workspace {workspace:?} has an ingress principal but no trust anchor"
                )));
            }
        }
        Ok(Self {
            principals: principal_map,
            trust: trust_map,
            cache: Mutex::new(HashMap::new()),
        })
    }

    /// The principal for one workspace (absent = configuration error).
    pub fn principal(&self, workspace: &str) -> Result<&IngressPrincipal> {
        self.principals.get(workspace).ok_or_else(|| {
            InterflowError::config(format!(
                "workspace {workspace:?} has no ingress principal; refusing its streams"
            ))
        })
    }

    /// The inner material for one route's workspace (cached). Missing
    /// anchors and stale certificate files are configuration errors: the
    /// affected stream fails closed instead of proceeding in plaintext.
    pub fn material_for(
        &self,
        workspace: &str,
    ) -> Result<Arc<interflow_core::tls::InnerTlsMaterial>> {
        let current_sequence = self.current_sequence(workspace)?.unwrap_or(0);
        if let Some((sequence, hit)) = self
            .cache
            .lock()
            .expect("ingress identity cache")
            .get(workspace)
            && *sequence == current_sequence
        {
            return Ok(Arc::clone(hit));
        }
        let ca_path = self.trust.get(workspace).ok_or_else(|| {
            InterflowError::config(format!(
                "route workspace {workspace:?} has no trust anchor; refusing plaintext ingress stream"
            ))
        })?;
        let principal = self.principal(workspace)?;
        let Some(file_stem) = principal.cert.file_stem().and_then(|stem| stem.to_str()) else {
            return Err(InterflowError::config(format!(
                "ingress credential for workspace {workspace:?} has no stable file stem"
            )));
        };
        let Some(credentials_root) = credentials_root(&principal.cert) else {
            return Err(InterflowError::config(format!(
                "ingress credential for workspace {workspace:?} has no credential-store root"
            )));
        };
        let (cert, key) = if current_sequence == 0 {
            (principal.cert.clone(), principal.key.clone())
        } else {
            let sequence_dir = credentials_root
                .join("sequences")
                .join(current_sequence.to_string());
            (
                sequence_dir.join(format!("{file_stem}.crt")),
                sequence_dir.join(format!("{file_stem}.key")),
            )
        };
        // Anchors: the route workspace's CA only — the ingress talks to
        // exactly that workspace's agents (minimal anchor set).
        let ca = ca_path.to_string_lossy();
        let cert = cert.to_string_lossy();
        let key = key.to_string_lossy();
        let crl_path = workspace_crl(ca_path);
        let crls = if crl_path
            .as_deref()
            .is_some_and(|path| Path::new(path).is_file())
        {
            vec![interflow_core::tls::load_crl(
                crl_path.as_deref().unwrap_or_default(),
            )?]
        } else {
            Vec::new()
        };
        let material = interflow_core::tls::InnerTlsMaterial::from_paths_with_crls(
            &[ca.as_ref()],
            &cert,
            &key,
            &crls,
        )?;
        let material = Arc::new(material);
        self.cache.lock().expect("ingress identity cache").insert(
            workspace.to_string(),
            (current_sequence, Arc::clone(&material)),
        );
        Ok(material)
    }

    fn current_sequence(&self, workspace: &str) -> Result<Option<u64>> {
        let principal = self.principal(workspace)?;
        let Some(root) = credentials_root(&principal.cert) else {
            return Ok(None);
        };
        let Ok(text) = std::fs::read_to_string(root.join("current.json")) else {
            return Ok(None);
        };
        let value: serde_json::Value = serde_json::from_str(&text).map_err(|e| {
            InterflowError::config("active credential pointer".to_string()).with_source(e)
        })?;
        Ok(Some(
            value
                .get("sequence")
                .and_then(serde_json::Value::as_u64)
                .ok_or_else(|| {
                    InterflowError::config("active credential pointer lacks sequence".to_owned())
                })?,
        ))
    }
}

fn credentials_root(cert: &Path) -> Option<&Path> {
    let parent = cert.parent()?;
    if parent.file_name()? == "current" {
        parent.parent()
    } else {
        parent.parent()?.parent()
    }
}

fn workspace_crl(anchor: &Path) -> Option<String> {
    let pack_root = anchor.parent()?.parent()?;
    let stem = anchor.file_stem()?;
    let path = pack_root
        .join("state")
        .join("crls")
        .join(format!("{}.crl.pem", stem.to_string_lossy()));
    path.is_file().then(|| path.display().to_string())
}
