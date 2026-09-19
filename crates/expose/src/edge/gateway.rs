//! The edge's gateway identity: the ephemeral default and the stable
//! e2e-capable form (RFC docs/design/agent-e2e-encryption.md §3.4/§5.3).
//!
//! Default: at process start the edge mints a throwaway CA plus a
//! `CN=edge` client certificate in memory. The embedded hub trusts the CA
//! as the tenant `_edge` (`trusted_gateway = true` — the only principal
//! allowed to open streams across tenants); the edge's internal agent
//! presents the client certificate on its self-dial. No files persist
//! beyond the process, and every restart rotates the whole identity.
//!
//! Stable (`--gateway-cert/--gateway-key`, material from
//! `interflow-mesh certs gateway issue`): the files replace the mint
//! outright — same hub-plane role, but the identity survives restarts and,
//! by existing at all, opts gateway flows into the inner TLS layer (the
//! caller distinguishes the two via [`GatewayIdentity::is_stable`]).
//!
//! Issuance goes through `interflow-certs` like every other certificate in
//! the repository — the identity may be ephemeral, but there is
//! deliberately no second signing implementation.

use interflow_certs::{Validity, build_ca};
use interflow_core::error::{InterflowError, Result};
use interflow_core::tls::TenantTrustRoot;
use std::collections::HashMap;
use std::io::Write;
use std::sync::Arc;
use std::sync::Mutex;

/// The reserved tenant name of the edge gateway principal.
pub const GATEWAY_TENANT: &str = "_edge";
/// The gateway agent id (the client certificate CN).
pub const GATEWAY_AGENT: &str = "edge";

/// A gateway identity (minted or loaded).
///
/// Field docs live on the struct members; see the module docs for the two
/// forms' trust semantics.
pub struct GatewayIdentity {
    /// The trust root to register in the hub's tenant table.
    pub root: TenantTrustRoot,
    /// Client certificate path (CN = `edge`).
    pub client_cert_pem: String,
    /// Client key path.
    pub client_key_pem: String,
    /// Temp dir holding the cert/key files (removed on drop); empty for a
    /// loaded identity whose files belong to the operator.
    dir: std::path::PathBuf,
    /// Whether this identity came from `--gateway-cert/--gateway-key`
    /// (stable, e2e-capable) rather than the per-restart mint.
    stable: bool,
}

impl Drop for GatewayIdentity {
    fn drop(&mut self) {
        if !self.dir.as_os_str().is_empty() {
            let _ = std::fs::remove_dir_all(&self.dir);
        }
    }
}

fn cert_err(context: &str) -> impl Fn(interflow_certs::Error) -> InterflowError + '_ {
    move |e| InterflowError::config(format!("{context}: {e}"))
}

impl GatewayIdentity {
    /// Whether this identity is the stable, e2e-capable form (loaded from
    /// files). Gateway flows attempt the inner TLS handshake iff stable —
    /// the minted CA is anchored nowhere, so its handshakes could never
    /// verify and would only add latency.
    pub const fn is_stable(&self) -> bool {
        self.stable
    }

    /// Loads the stable identity from the `certs gateway issue` material.
    ///
    /// `cert_path` is the **chain bundle** (leaf first, the gateway CA
    /// last): the leaf is the principal; the trailing CA becomes the
    /// hub-plane `_edge` trust root (one file feeds both roles).
    pub fn load(cert_path: &str, key_path: &str) -> Result<Self> {
        let pem = std::fs::read_to_string(cert_path).map_err(|e| {
            InterflowError::config(format!("gateway cert {cert_path} read failed: {e}"))
        })?;
        let mut certs = rustls_pemfile::certs(&mut pem.as_bytes())
            .collect::<std::result::Result<Vec<_>, _>>()
            .map_err(|e| {
                InterflowError::config(format!("gateway cert {cert_path} parse failed: {e}"))
            })?;
        if certs.len() < 2 {
            return Err(InterflowError::config(format!(
                "gateway cert {cert_path}: expected the leaf+CA chain bundle from \
                 `certs gateway issue` (found {} certificate(s))",
                certs.len()
            )));
        }
        let root_der = certs.pop().expect("len checked");
        // The leaf must be the edge principal (the inner-layer CN binding
        // and the hub registration both depend on it).
        let leaf_cn = interflow_core::tls::extract_cn_from_chain(std::slice::from_ref(&certs[0]))
            .unwrap_or_default();
        if leaf_cn != GATEWAY_AGENT {
            return Err(InterflowError::config(format!(
                "gateway cert {cert_path}: leaf CN {leaf_cn:?} != {GATEWAY_AGENT:?} — this is \
                 not the `certs gateway issue` client pair"
            )));
        }
        // The bundle must be self-consistent: the leaf actually chains to
        // the trailing CA (which thereby anchors the `_edge` trust root).
        {
            use tokio_rustls::rustls::pki_types::{CertificateDer, UnixTime};
            use tokio_rustls::rustls::server::WebPkiClientVerifier;
            let mut roots = tokio_rustls::rustls::RootCertStore::empty();
            roots
                .add(CertificateDer::from(root_der.as_ref().to_vec()))
                .map_err(|e| InterflowError::config(format!("gateway anchor CA rejected: {e}")))?;
            let verifier = WebPkiClientVerifier::builder(Arc::new(roots))
                .build()
                .map_err(|e| InterflowError::config(format!("gateway verifier build: {e}")))?;
            verifier
                .verify_client_cert(&certs[0], &[], UnixTime::now())
                .map_err(|e| {
                    InterflowError::config(format!(
                        "gateway cert {cert_path}: the leaf does not chain to the trailing \
                         CA ({e}) — expected the `certs gateway issue` bundle"
                    ))
                })?;
        }
        let root_pem = last_pem_block(&pem).ok_or_else(|| {
            InterflowError::config(format!(
                "gateway cert {cert_path}: no PEM block boundaries found"
            ))
        })?;
        let root = TenantTrustRoot::from_pem(GATEWAY_TENANT, true, root_pem.as_bytes())?;

        Ok(Self {
            root,
            client_cert_pem: cert_path.to_string(),
            client_key_pem: key_path.to_string(),
            dir: std::path::PathBuf::new(),
            stable: true,
        })
    }

    /// Mints the ephemeral CA + gateway client certificate and materializes
    /// the client pair into a private temp dir (the agent-side TLS loader is
    /// path-based).
    pub fn mint() -> Result<Self> {
        // 1. Throwaway CA + gateway client certificate (CN = edge,
        //    ClientAuth EKU) — same builder the certs CLI uses.
        let ca = build_ca(GATEWAY_AGENT, Validity::leaf_default())
            .map_err(cert_err("gateway CA mint"))?;
        let loaded =
            interflow_certs::LoadedCa::from_material(&ca).map_err(cert_err("gateway CA load"))?;
        let leaf = loaded
            .build_client_cert(GATEWAY_AGENT, Validity::leaf_default())
            .map_err(cert_err("gateway certificate mint"))?;

        // 2. Trust root from the CA's public certificate.
        let root = TenantTrustRoot::from_pem(GATEWAY_TENANT, true, loaded.cert_pem().as_bytes())?;

        // 3. Materialize the client pair for the path-based TLS loader.
        let dir = std::env::temp_dir().join(format!(
            "interflow-edge-gw-{}",
            uuid::Uuid::new_v4().simple()
        ));
        std::fs::create_dir_all(&dir)
            .map_err(|e| InterflowError::config(format!("gateway temp dir create failed: {e}")))?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700));
        }
        let cert_path = dir.join("gw.crt");
        let key_path = dir.join("gw.key");
        let write = |path: &std::path::Path, bytes: &[u8], context: &str| -> Result<()> {
            let mut f = std::fs::File::create(path)
                .map_err(|e| InterflowError::config(format!("{context} failed: {e}")))?;
            f.write_all(bytes)
                .map_err(|e| InterflowError::config(format!("{context} failed: {e}")))?;
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                let mode = if path.extension().is_some_and(|ext| ext == "key") {
                    0o600
                } else {
                    0o644
                };
                let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode));
            }
            Ok(())
        };
        write(&cert_path, leaf.cert_pem.as_bytes(), "gateway cert write")?;
        write(&key_path, leaf.key_pem.as_bytes(), "gateway key write")?;

        // Re-read via paths so the caller's TlsConfig sees exactly the files.
        Ok(Self {
            root,
            client_cert_pem: cert_path.display().to_string(),
            client_key_pem: key_path.display().to_string(),
            dir,
            stable: false,
        })
    }
}

/// The last complete `-----BEGIN/END CERTIFICATE-----` block of a PEM
/// bundle, verbatim (the trailing CA of the gateway chain bundle).
fn last_pem_block(pem: &str) -> Option<String> {
    let begin = "-----BEGIN CERTIFICATE-----";
    let end = "-----END CERTIFICATE-----";
    let last_begin = pem.rfind(begin)?;
    let last_end = pem[last_begin..].find(end)? + last_begin + end.len();
    Some(pem[last_begin..last_end].to_string())
}

/// Per-deployment gateway inner-TLS material (present iff the stable
/// identity was loaded).
///
/// Holds the gateway client pair plus a per-tenant anchor cache (each
/// route's tenant CA from `--client-ca`, the inner anchor for verifying
/// that tenant's agents).
pub struct EdgeE2e {
    cert_path: String,
    key_path: String,
    /// tenant name → CA PEM path.
    tenant_cas: HashMap<String, String>,
    cache: Mutex<HashMap<String, Arc<interflow_core::tls::InnerTlsMaterial>>>,
}

impl EdgeE2e {
    /// Builds the per-deployment material source.
    pub fn new(cert_path: String, key_path: String, tenant_cas: HashMap<String, String>) -> Self {
        Self {
            cert_path,
            key_path,
            tenant_cas,
            cache: Mutex::new(HashMap::new()),
        }
    }

    /// The inner material for one route's tenant (cached); `None` when the
    /// tenant has no `--client-ca` anchor (the route cannot do inner TLS —
    /// logged, and the stream proceeds plain).
    pub fn material_for(&self, tenant: &str) -> Option<Arc<interflow_core::tls::InnerTlsMaterial>> {
        if let Some(hit) = self.cache.lock().expect("e2e cache").get(tenant) {
            return Some(Arc::clone(hit));
        }
        let ca_path = self.tenant_cas.get(tenant)?;
        // Anchors: the route tenant's CA only — the gateway talks to exactly
        // that tenant's agents (minimal anchor set, audit item RFC §8.2 #4).
        let material = interflow_core::tls::InnerTlsMaterial::from_paths(
            &[ca_path.as_str()],
            &self.cert_path,
            &self.key_path,
        )
        .ok()?;
        let material = Arc::new(material);
        self.cache
            .lock()
            .expect("e2e cache")
            .insert(tenant.to_string(), Arc::clone(&material));
        Some(material)
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn minted_root_is_gateway_tenant() {
        let gw = GatewayIdentity::mint().unwrap();
        assert_eq!(&*gw.root.name, GATEWAY_TENANT);
        assert!(gw.root.trusted_gateway);
        assert!(!gw.is_stable());
        // The client pair materialized as readable files.
        assert!(std::path::Path::new(&gw.client_cert_pem).exists());
        assert!(std::path::Path::new(&gw.client_key_pem).exists());
    }

    #[test]
    fn every_mint_rotates_the_identity() {
        let a = GatewayIdentity::mint().unwrap();
        let b = GatewayIdentity::mint().unwrap();
        assert_ne!(a.client_cert_pem, b.client_cert_pem);
    }

    /// The stable identity loads from `certs gateway issue` material and
    /// rejects non-bundle / wrong-principal inputs.
    #[test]
    fn stable_identity_loads_from_gateway_issue_material() {
        let dir = tempfile_gw_dir();
        interflow_certs::ensure_gateway(&dir, false).unwrap();
        let cert = dir.join("gateway/edge.crt").display().to_string();
        let key = dir.join("gateway/edge.key").display().to_string();

        let gw = GatewayIdentity::load(&cert, &key).unwrap();
        assert!(gw.is_stable());
        assert_eq!(&*gw.root.name, GATEWAY_TENANT);
        assert!(gw.root.trusted_gateway);

        // A plain leaf (no chain bundle) is rejected.
        let leaf_only = dir.join("leaf-only.crt");
        let pem = std::fs::read_to_string(&cert).unwrap();
        let marker = "-----BEGIN CERTIFICATE-----";
        let second = pem[marker.len()..].find(marker).unwrap() + marker.len();
        std::fs::write(&leaf_only, &pem[..second]).unwrap();
        assert!(GatewayIdentity::load(&leaf_only.display().to_string(), &key).is_err());
    }

    fn tempfile_gw_dir() -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "interflow-edge-gw-load-{}-{}",
            std::process::id(),
            uuid::Uuid::new_v4().simple()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }
}
