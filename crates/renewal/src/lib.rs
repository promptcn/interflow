//! Unattended short-lived credential renewal.
//!
//! Node-runtime lifecycle, shared by every pack-driven binary (the expose
//! `interflow` CLI and the site-to-site `interflow-mesh` binary): workspace
//! members and realm-scoped hub principals renew themselves through
//! `/v1/renew`; control-endpoint identities renew through the authorized
//! `/v1/renew-control` path. The scheduler runs beside the engine and turns
//! renewal and CRL updates into a graceful process exit so the supervisor
//! restarts onto the new material — no TLS session outlives the credential
//! that created it.

use interflow_core::error::{InterflowError, Result};
use interflow_identity::credentials::ActiveCredentialSet;
use interflow_identity::issuance::generate_csr;
use interflow_identity::pack::{CredentialPack, IdentityEntry};
use serde::Deserialize;
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::time::Duration;

#[derive(Debug, Clone, Deserialize)]
struct IssuedResponse {
    principal: String,
    cert_pem: String,
    chain_pem: String,
    expires: String,
    serial: String,
    renewal_id: Option<String>,
}

#[derive(Debug, Clone)]
pub struct RenewalReport {
    pub pack_dir: PathBuf,
    pub renewed: Vec<String>,
}

/// Pack load/validation failures are configuration-class (unrecoverable at
/// boot); keep the identity error as the source-chain root.
pub fn pack_error(e: interflow_identity::Error) -> InterflowError {
    InterflowError::config("credential pack error").with_source(e)
}

fn config_error(context: impl Into<String>) -> InterflowError {
    InterflowError::config(context)
}

fn map_identity<T>(result: interflow_identity::Result<T>) -> Result<T> {
    result.map_err(pack_error)
}

fn map_request(e: reqwest::Error) -> InterflowError {
    InterflowError::connection("registrar request failed").with_source(e)
}

fn tls_identity(cert_pem: &str, key_pem: &str) -> Result<reqwest::Identity> {
    let pem = format!("{cert_pem}{key_pem}");
    reqwest::Identity::from_pem(pem.as_bytes())
        .map_err(|e| config_error(format!("registrar client identity: {e}")))
}

fn client(_endpoint: &str, ca_pem: &str, cert_pem: &str, key_pem: &str) -> Result<reqwest::Client> {
    let certificate = reqwest::Certificate::from_pem(ca_pem.as_bytes())
        .map_err(|e| config_error(format!("registrar trust anchor: {e}")))?;
    reqwest::Client::builder()
        .add_root_certificate(certificate)
        .identity(tls_identity(cert_pem, key_pem)?)
        .build()
        .map_err(|e| config_error(format!("registrar HTTPS client: {e}")))
}

async fn post_json<T: serde::de::DeserializeOwned>(
    endpoint: &str,
    ca_pem: &str,
    cert_pem: &str,
    key_pem: &str,
    path: &str,
    body: &(impl serde::Serialize + Sync),
) -> Result<T> {
    let response = client(endpoint, ca_pem, cert_pem, key_pem)?
        .post(format!("{endpoint}{path}"))
        .json(body)
        .send()
        .await
        .map_err(map_request)?;
    let status = response.status();
    if !status.is_success() {
        let text = response.text().await.unwrap_or_default();
        return Err(InterflowError::connection(format!(
            "registrar {path} returned {status}: {text}"
        )));
    }
    response.json().await.map_err(map_request)
}

fn registrar_endpoint(pack: &CredentialPack) -> Result<String> {
    pack.metadata.registrar_endpoint.clone().ok_or_else(|| {
        config_error("identity.mode = \"offline\" — this pack has no registrar; credentials do                       not renew, rotate them instead")
    })
}

fn control_ca(pack: &CredentialPack) -> Result<String> {
    pack.trust
        .issuers
        .get("control")
        .cloned()
        .ok_or_else(|| config_error("pack carries no control issuer"))
}

async fn refresh_crls(pack: &CredentialPack) -> Result<bool> {
    let endpoint = registrar_endpoint(pack)?;
    let ca = control_ca(pack)?;
    let certificate = reqwest::Certificate::from_pem(ca.as_bytes())
        .map_err(|e| config_error(format!("registrar trust anchor: {e}")))?;
    let response: BTreeMap<String, String> = reqwest::Client::builder()
        .add_root_certificate(certificate)
        .build()
        .map_err(|e| config_error(format!("registrar HTTPS client: {e}")))?
        .get(format!("{endpoint}/v1/crls"))
        .send()
        .await
        .map_err(map_request)?
        .error_for_status()
        .map_err(map_request)?
        .json()
        .await
        .map_err(map_request)?;
    let dir = pack.dir.join("state").join("crls");
    std::fs::create_dir_all(&dir)?;
    let mut changed = false;
    for issuer_name in pack.trust.issuers.keys() {
        let Some((_, pem)) = response.iter().find(|(key, _)| {
            key.strip_prefix(issuer_name.as_str())
                .is_some_and(|suffix| suffix.starts_with('-'))
        }) else {
            continue;
        };
        let path = dir.join(format!("{}.crl.pem", issuer_name.replace('/', "-")));
        let old = std::fs::read(&path).unwrap_or_default();
        let new = pem.as_bytes();
        if old.as_slice() != new {
            // CRLs are public data: preserve existing bits, 0644 for new files
            interflow_util::atomic_write(&path, new, interflow_util::WriteMode::PreserveOr(0o644))?;
            changed = true;
        }
    }
    Ok(changed)
}

fn control_hostname(pack: &CredentialPack) -> Result<String> {
    control_endpoint_hostname(pack.metadata.control_endpoint.trim())
}

/// Fail closed: a CSR whose hostname SAN is derived from a garbled endpoint
/// would renew a certificate that cannot validate.
fn control_endpoint_hostname(endpoint: &str) -> Result<String> {
    interflow_util::parse_endpoint(endpoint)
        .map(|parsed| parsed.host)
        .map_err(|e| config_error(format!("control endpoint {endpoint:?}: {e}")))
}

fn expected_entries(pack: &CredentialPack) -> Vec<(String, IdentityEntry)> {
    let mut out = Vec::new();
    for (bucket, buckets) in &pack.identities {
        for (workspace, entry) in buckets {
            let stem = interflow_identity::credentials::identity_stem(bucket, workspace);
            out.push((stem, entry.clone()));
        }
    }
    out
}

async fn renew_workspace_one(
    pack: &CredentialPack,
    active: &mut ActiveCredentialSet,
    stem: &str,
    expected: &IdentityEntry,
) -> Result<bool> {
    let (cert_path, key_path) = map_identity(active.material_paths(stem))?;
    let cert_pem = std::fs::read_to_string(cert_path)?;
    let key_pem = std::fs::read_to_string(key_path)?;
    let csr = map_identity(generate_csr(&expected.principal, &[], false))?;
    let response: IssuedResponse = post_json(
        &registrar_endpoint(pack)?,
        &control_ca(pack)?,
        &cert_pem,
        &key_pem,
        "/v1/renew",
        &serde_json::json!({ "csr_pem": csr.csr_pem }),
    )
    .await?;
    if response.principal != expected.principal.to_string() {
        return Err(config_error(
            "registrar returned a credential for the wrong principal",
        ));
    }
    let _ = (&response.cert_pem, &response.expires);
    let renewal_id = response
        .renewal_id
        .clone()
        .ok_or_else(|| config_error("registrar renewal response lacks renewal_id"))?;
    map_identity(active.renew(stem, expected, &response.chain_pem, &csr.key_pem, pack))?;
    let (new_cert_path, new_key_path) = map_identity(active.material_paths(stem))?;
    let new_cert = std::fs::read_to_string(new_cert_path)?;
    let new_key = std::fs::read_to_string(new_key_path)?;
    let _: serde_json::Value = post_json(
        &registrar_endpoint(pack)?,
        &control_ca(pack)?,
        &new_cert,
        &new_key,
        "/v1/confirm",
        &serde_json::json!({ "renewal_id": renewal_id }),
    )
    .await?;
    Ok(true)
}

async fn renew_control_one(
    pack: &CredentialPack,
    active: &mut ActiveCredentialSet,
    authorizer_stem: &str,
    stem: &str,
    expected: &IdentityEntry,
) -> Result<()> {
    let (auth_cert_path, auth_key_path) = map_identity(active.material_paths(authorizer_stem))?;
    let auth_cert = std::fs::read_to_string(auth_cert_path)?;
    let auth_key = std::fs::read_to_string(auth_key_path)?;
    let old = active
        .entries
        .get(stem)
        .ok_or_else(|| config_error("control active credential is missing"))?;
    let csr = map_identity(generate_csr(
        &expected.principal,
        &[control_hostname(pack)?],
        true,
    ))?;
    let response: IssuedResponse = post_json(
        &registrar_endpoint(pack)?,
        &control_ca(pack)?,
        &auth_cert,
        &auth_key,
        "/v1/renew-control",
        &serde_json::json!({
            "csr_pem": csr.csr_pem,
            "old_serial": old.serial,
        }),
    )
    .await?;
    if response.principal != expected.principal.to_string() {
        return Err(config_error(
            "registrar returned a control credential for the wrong principal",
        ));
    }
    let _ = (&response.cert_pem, &response.expires);
    let renewal_id = response
        .renewal_id
        .clone()
        .ok_or_else(|| config_error("control renewal response lacks renewal_id"))?;
    map_identity(active.renew(stem, expected, &response.chain_pem, &csr.key_pem, pack))?;
    let _: serde_json::Value = post_json(
        &registrar_endpoint(pack)?,
        &control_ca(pack)?,
        &auth_cert,
        &auth_key,
        "/v1/confirm-control",
        &serde_json::json!({
            "renewal_id": renewal_id,
            "new_serial": response.serial,
        }),
    )
    .await?;
    Ok(())
}

pub async fn renew_all(pack_dir: &Path, force: bool) -> Result<RenewalReport> {
    let pack = CredentialPack::load_runtime(pack_dir).map_err(pack_error)?;
    if pack.metadata.identity_mode == interflow_identity::manifest::IdentityMode::Offline {
        return Err(config_error(
            "identity.mode = \"offline\" — credentials do not renew; `interflow rotate` issues \
             the next generation",
        ));
    }
    let mut active = ActiveCredentialSet::load_or_bootstrap(&pack).map_err(pack_error)?;
    let entries = expected_entries(&pack);
    let ttl = Duration::from_secs(pack.metadata.leaf_ttl_secs);
    let earliest = active.earliest_expiry().map_err(pack_error)?;
    let remaining = (earliest - time::OffsetDateTime::now_utc())
        .whole_seconds()
        .max(0);
    let remaining_u64 = u64::try_from(remaining).unwrap_or_default();
    if !force && Duration::from_secs(remaining_u64) > ttl / 2 {
        return Ok(RenewalReport {
            pack_dir: pack_dir.to_owned(),
            renewed: Vec::new(),
        });
    }

    let mut renewed = Vec::new();
    for (stem, expected) in entries.clone() {
        if expected.principal.kind == interflow_identity::PrincipalKind::Control {
            continue;
        }
        // Workspace members and the realm-scoped hub principal both renew
        // themselves through /v1/renew (the registrar picks the issuer).
        if renew_workspace_one(&pack, &mut active, &stem, &expected).await? {
            renewed.push(expected.principal.to_string());
        }
    }
    // Control-endpoint identities (expose ingress nodes and mesh hubs) renew
    // through the authorized path: an ingress principal or the hub client
    // principal of the same node vouches for the request.
    if pack.metadata.kind == interflow_identity::pack::PackKind::Ingress
        || pack.metadata.kind == interflow_identity::pack::PackKind::Hub
    {
        let authorizer_stem = entries
            .iter()
            .find(|(_, entry)| {
                matches!(
                    entry.principal.kind,
                    interflow_identity::PrincipalKind::Ingress
                        | interflow_identity::PrincipalKind::Hub
                )
            })
            .map(|(stem, _)| stem.clone())
            .ok_or_else(|| {
                config_error("pack has no client principal to authorize control renewal")
            })?;
        for (stem, expected) in entries.clone() {
            if expected.principal.kind == interflow_identity::PrincipalKind::Control {
                renew_control_one(&pack, &mut active, &authorizer_stem, &stem, &expected).await?;
                renewed.push(expected.principal.to_string());
            }
        }
    }
    Ok(RenewalReport {
        pack_dir: pack_dir.to_owned(),
        renewed,
    })
}

/// Single-node-process default: attribution is the pack's node name.
pub async fn renewal_scheduler(pack_dir: &Path) -> Result<()> {
    renewal_scheduler_with_log_name(pack_dir, None).await
}

/// [`renewal_scheduler`] with an embedder-supplied log attribution name.
///
/// The GUI hosts several nodes in one process and keys captured lines on
/// the `node` field, so same-name nodes in different realms/workspaces need
/// distinct values; `None` = the pack's node name (the CLI/binary default).
pub async fn renewal_scheduler_with_log_name(
    pack_dir: &Path,
    log_name: Option<String>,
) -> Result<()> {
    // Offline deployments (pack metadata decides — GUI/CLI wiring stays
    // identical): no registrar to renew against and no freshness bound to
    // enforce; watch expiry and remind the operator instead.
    {
        let pack = CredentialPack::load_runtime(pack_dir).map_err(pack_error)?;
        if pack.metadata.identity_mode == interflow_identity::manifest::IdentityMode::Offline {
            return offline_watch(pack_dir, log_name).await;
        }
    }
    const BACKOFF: [Duration; 5] = [
        Duration::from_secs(60),
        Duration::from_mins(2),
        Duration::from_mins(4),
        Duration::from_mins(8),
        Duration::from_mins(15),
    ];
    const CRL_POLL: Duration = Duration::from_secs(60);
    const CRL_STALENESS_BOUND: Duration = Duration::from_hours(1);
    let mut failures = 0usize;
    let mut last_crl_success = std::time::Instant::now();
    loop {
        let pack = CredentialPack::load_runtime(pack_dir).map_err(pack_error)?;
        // Node name for log attribution (see the fn docs above).
        let node = log_name.as_deref().unwrap_or(pack.metadata.node.as_str());
        let active = ActiveCredentialSet::load_or_bootstrap(&pack).map_err(pack_error)?;
        let expiry = active.earliest_expiry().map_err(pack_error)?;
        let ttl = Duration::from_secs(pack.metadata.leaf_ttl_secs);
        let half_ttl = i64::try_from(ttl.as_secs() / 2).unwrap_or(i64::MAX);
        let threshold = expiry - time::Duration::seconds(half_ttl);
        let warning_ttl = i64::try_from(ttl.as_secs() / 10).unwrap_or(i64::MAX);
        let warning = expiry - time::Duration::seconds(warning_ttl);
        let now = time::OffsetDateTime::now_utc();
        if now >= expiry {
            return Err(InterflowError::connection(
                "active credential expired — refusing to continue without renewal",
            ));
        }

        match refresh_crls(&pack).await {
            Ok(true) => {
                tracing::info!(
                    node,
                    "crl_updated: restarting credential verification plane"
                );
                return Ok(());
            }
            Ok(false) => {
                last_crl_success = std::time::Instant::now();
            }
            Err(e) => {
                tracing::warn!(node, "crl_stale: {e}");
                if last_crl_success.elapsed() >= CRL_STALENESS_BOUND {
                    return Err(InterflowError::connection(
                        "CRL freshness bound exceeded — refusing unrevocable credentials",
                    ));
                }
            }
        }

        if now < threshold {
            let until_renewal = Duration::from_secs(
                u64::try_from((threshold - now).whole_seconds().max(0)).unwrap_or_default(),
            );
            tokio::time::sleep(until_renewal.min(CRL_POLL)).await;
            continue;
        }
        if now >= warning {
            tracing::warn!(node, "credential_expiry_warning: less than 10% TTL remains");
        }
        match renew_all(pack_dir, false).await {
            Ok(report) => {
                tracing::info!(
                    node,
                    renewed = ?report.renewed,
                    "rotation_succeeded: generation_active=true"
                );
                // Returning lets the foreground process perform its graceful
                // shutdown path; the installed unit restarts it with the newly
                // selected generation. Existing TLS sessions are therefore not
                // allowed to outlive the credential that created them.
                return Ok(());
            }
            Err(e) => {
                failures += 1;
                tracing::error!(node, "rotation_failed: {e}");
                let backoff = BACKOFF[(failures - 1).min(BACKOFF.len() - 1)];
                tokio::time::sleep(backoff.min(CRL_POLL)).await;
            }
        }
    }
}

/// The offline twin of the renewal scheduler: nothing renews, nothing is
/// fetched. Credentials live until their own expiry (fail-closed there,
/// exactly like the registrar tier); the operator rotates before that.
async fn offline_watch(pack_dir: &Path, log_name: Option<String>) -> Result<()> {
    const CHECK: Duration = Duration::from_secs(3600);
    let mut warned = false;
    loop {
        let pack = CredentialPack::load_runtime(pack_dir).map_err(pack_error)?;
        let node = log_name.as_deref().unwrap_or(pack.metadata.node.as_str());
        let active = ActiveCredentialSet::load_or_bootstrap(&pack).map_err(pack_error)?;
        let expiry = active.earliest_expiry().map_err(pack_error)?;
        let now = time::OffsetDateTime::now_utc();
        if now >= expiry {
            return Err(InterflowError::connection(
                "active credential expired — offline credentials do not renew; rotate with \
                 `interflow rotate`",
            ));
        }
        let ttl = pack.metadata.leaf_ttl_secs;
        let remaining = (expiry - now).whole_seconds().max(0);
        if !warned && ttl > 0 && u64::try_from(remaining).unwrap_or(u64::MAX) <= ttl * 8 / 10 {
            warned = true;
            tracing::warn!(
                node,
                "credential_expiry_warning: less than 20% of the leaf lifetime remains — \
                 rotate with `interflow rotate` before {}",
                expiry
                    .format(&time::format_description::well_known::Rfc3339)
                    .unwrap_or_default()
            );
        }
        tokio::time::sleep(CHECK).await;
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn control_hostname_extraction_is_ipv6_safe_and_fail_closed() {
        let host = |endpoint: &str| control_endpoint_hostname(endpoint).unwrap();
        assert_eq!(host("https://relay.example.com:16666"), "relay.example.com");
        assert_eq!(host("relay.example.com"), "relay.example.com");
        assert_eq!(host("127.0.0.1:16666"), "127.0.0.1");
        assert_eq!(host("[2001:db8::1]:16666"), "2001:db8::1");

        for bad in ["", "https://", "ftp://x", "host:99999", "例え.jp"] {
            assert!(
                control_endpoint_hostname(bad).is_err(),
                "{bad:?} must fail closed"
            );
        }
    }
}
