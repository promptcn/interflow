//! Layer 2 — the §2.4 on-disk layout with validate-or-create semantics.
//!
//! Every `ensure_*` op is idempotent: when the target files already exist
//! they are VALIDATED (pairing, issuer chain, CN/SAN/EKU, validity window —
//! real rustls verification, not name heuristics) and reported as
//! [`Outcome::AlreadyValid`]; partial or inconsistent state is a hard error
//! with the concrete difference and a remediation, never a silent skip or a
//! blind overwrite. `--force` (re-issue) is passed in by the CLI as needed.

use crate::material::{LoadedCa, build_ca};
use crate::{Error, Result, SanName, Validity};
use std::collections::BTreeSet;
use std::net::IpAddr;
use std::path::{Path, PathBuf};

/// Paths of a tenant CA pair under `<out>/tenants/`.
#[derive(Debug, Clone)]
pub struct TenantCaPaths {
    pub cert: PathBuf,
    pub key: PathBuf,
}

/// Paths of the hub server pair at `<out>/hub.crt|key`.
#[derive(Debug, Clone)]
pub struct HubPaths {
    pub cert: PathBuf,
    pub key: PathBuf,
}

/// Paths of one agent's client pair under `<out>/agents/`.
#[derive(Debug, Clone)]
pub struct AgentPaths {
    pub cert: PathBuf,
    pub key: PathBuf,
}

/// What an `ensure_*` op found/did.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Outcome {
    /// The pair was issued and written.
    Created,
    /// The pair already existed and passed full validation.
    AlreadyValid,
}

/// Wizard-facing bundle: paths of everything under `cert_dir` after
/// [`generate`].
pub struct GeneratedCerts {
    /// Tenant CA certificate PEM (registered on the edge via `--client-ca`;
    /// also the `ca_path` trust anchor for expose clients).
    pub ca_cert: String,
    /// Tenant CA private key PEM (0600; required to issue further agent
    /// certificates — kept on this machine only).
    pub ca_key: String,
    /// Hub server certificate PEM.
    pub hub_cert: String,
    /// Hub server private key PEM (0600 permissions).
    pub hub_key: String,
    /// Agent client certificates (CN == agent_id, ClientAuth EKU; key 0600).
    pub agents: Vec<AgentCertPaths>,
}

/// Paths of one agent's client certificate pair.
pub struct AgentCertPaths {
    pub agent_id: String,
    pub cert: String,
    pub key: String,
}

/// Generates the tenant CA + hub pair + one client certificate per agent
/// under `cert_dir` (§2.4 layout).
///
/// Thin composite over the `ensure_*` ops (validate-or-create) — the expose
/// init wizard and test fixtures share the exact code path with the CLI.
pub fn generate(
    cert_dir: &Path,
    hub_names: &[SanName],
    tenant: &str,
    agent_ids: &[String],
) -> Result<GeneratedCerts> {
    let (_, ca) = ensure_tenant_ca(cert_dir, tenant)?;
    let (_, hub) = ensure_hub_cert(cert_dir, tenant, hub_names, false)?;
    let mut agents = Vec::with_capacity(agent_ids.len());
    for agent_id in agent_ids {
        let (_, paths) = ensure_agent_cert(cert_dir, tenant, agent_id, false)?;
        agents.push(AgentCertPaths {
            agent_id: agent_id.clone(),
            cert: paths.cert.display().to_string(),
            key: paths.key.display().to_string(),
        });
    }
    Ok(GeneratedCerts {
        ca_cert: ca.cert.display().to_string(),
        ca_key: ca.key.display().to_string(),
        hub_cert: hub.cert.display().to_string(),
        hub_key: hub.key.display().to_string(),
        agents,
    })
}

/// Ensures the tenant CA `tenants/<tenant>-ca.crt|key` exists (never
/// re-issued: a replaced CA would silently invalidate every certificate
/// issued by the old one — rotation means a fresh directory).
pub fn ensure_tenant_ca(out_dir: &Path, tenant: &str) -> Result<(Outcome, TenantCaPaths)> {
    crate::validate_name("tenant", tenant)?;
    let paths = tenant_ca_paths(out_dir, tenant);
    match (paths.cert.exists(), paths.key.exists()) {
        (false, false) => {
            if let Some(parent) = paths.cert.parent() {
                std::fs::create_dir_all(parent).map_err(|e| Error::Io {
                    context: format!("failed to create {}", parent.display()),
                    source: e,
                })?;
            }
            let material = build_ca(tenant, Validity::ca_default())?;
            write_cert(&paths.cert, &material.cert_pem)?;
            write_private_key(&paths.key, &material.key_pem)?;
            Ok((Outcome::Created, paths))
        }
        (true, true) => {
            validate_existing_ca(&paths, tenant)?;
            Ok((Outcome::AlreadyValid, paths))
        }
        (true, false) | (false, true) => Err(Error::Mismatch(incomplete_pair_msg(
            "tenant CA",
            &paths.cert,
            &paths.key,
        ))),
    }
}

/// Ensures the hub server pair `hub.crt|key` exists, issued by the tenant CA.
///
/// The tenant CA must already exist and validate (hub certificates are
/// always CA-issued; a missing CA is a `certs init` / `certs tenant new`
/// prerequisite, not something to silently self-create). `force` re-issues
/// the pair — the renewal path — and never touches the CA.
pub fn ensure_hub_cert(
    out_dir: &Path,
    tenant: &str,
    names: &[SanName],
    force: bool,
) -> Result<(Outcome, HubPaths)> {
    crate::validate_name("tenant", tenant)?;
    if names.is_empty() {
        return Err(Error::Mismatch(
            "at least one hub name is required (pass --hub-dns, or use the local-development default)"
                .to_owned(),
        ));
    }
    let ca_paths = tenant_ca_paths(out_dir, tenant);
    if !ca_paths.cert.exists() || !ca_paths.key.exists() {
        return Err(Error::Mismatch(format!(
            "tenant CA for {tenant} not found under {} — run `certs init` (or `certs tenant new {tenant}`) first",
            ca_paths.cert.display()
        )));
    }
    validate_existing_ca(&ca_paths, tenant)?;
    let ca = load_ca(&ca_paths)?;

    let paths = HubPaths {
        cert: out_dir.join("hub.crt"),
        key: out_dir.join("hub.key"),
    };
    match (paths.cert.exists(), paths.key.exists()) {
        (true, true) if !force => {
            validate_existing_hub(&paths, &ca_paths, names)?;
            Ok((Outcome::AlreadyValid, paths))
        }
        // (false, false): fresh issue; (true, true): --force re-issue.
        (false, false) | (true, true) => {
            issue_hub(&paths, &ca, names)?;
            Ok((Outcome::Created, paths))
        }
        (true, false) | (false, true) => Err(Error::Mismatch(incomplete_pair_msg(
            "hub certificate",
            &paths.cert,
            &paths.key,
        ))),
    }
}

/// Ensures the agent client pair `agents/<agent_id>.crt|key` exists, issued
/// by the tenant CA (CN == agent_id, ClientAuth EKU). The tenant CA must
/// already exist and validate. `force` re-issues the pair.
pub fn ensure_agent_cert(
    out_dir: &Path,
    tenant: &str,
    agent_id: &str,
    force: bool,
) -> Result<(Outcome, AgentPaths)> {
    crate::validate_name("tenant", tenant)?;
    crate::validate_name("agent", agent_id)?;
    let ca_paths = tenant_ca_paths(out_dir, tenant);
    if !ca_paths.cert.exists() || !ca_paths.key.exists() {
        return Err(Error::Mismatch(format!(
            "tenant CA for {tenant} not found under {} — run `certs init` (or `certs tenant new {tenant}`) first",
            ca_paths.cert.display()
        )));
    }
    validate_existing_ca(&ca_paths, tenant)?;
    let ca = load_ca(&ca_paths)?;

    let agents_dir = out_dir.join("agents");
    let paths = AgentPaths {
        cert: agents_dir.join(format!("{agent_id}.crt")),
        key: agents_dir.join(format!("{agent_id}.key")),
    };
    match (paths.cert.exists(), paths.key.exists()) {
        (true, true) if !force => {
            validate_existing_agent(&paths, &ca_paths, agent_id)?;
            Ok((Outcome::AlreadyValid, paths))
        }
        // (false, false): fresh issue; (true, true): --force re-issue.
        (false, false) | (true, true) => {
            issue_agent(&agents_dir, &paths, &ca, agent_id)?;
            Ok((Outcome::Created, paths))
        }
        (true, false) | (false, true) => Err(Error::Mismatch(incomplete_pair_msg(
            "agent certificate",
            &paths.cert,
            &paths.key,
        ))),
    }
}

/// Paths of the gateway material under `<out>/gateway/`.
///
/// - `gateway-ca.crt|key`: the stable gateway anchor CA. Distributed to
///   every `required`-mode egress as `[e2e] gateway_ca_path` (public
///   material).
/// - `edge.crt|key`: the gateway client pair (CN == `edge`, the expose
///   edge's principal). `edge.crt` is a **chain bundle** (leaf first, the
///   CA last) so the edge can load both its leaf and its hub-plane `_edge`
///   trust root from the single `--gateway-cert` file.
#[derive(Debug, Clone)]
pub struct GatewayPaths {
    /// The gateway anchor CA certificate (public).
    pub ca_cert: PathBuf,
    /// The gateway anchor CA private key (identity-minting key: offline
    /// custody discipline, same as a tenant CA key).
    pub ca_key: PathBuf,
    /// The gateway client certificate chain bundle (leaf + CA).
    pub client_cert: PathBuf,
    /// The gateway client private key.
    pub client_key: PathBuf,
}

/// The gateway client certificate's CN — the expose edge's agent principal
/// (`expose::edge::gateway::GATEWAY_AGENT`). The inner-layer CN binding
/// ties gateway streams to exactly this identity.
pub const GATEWAY_CLIENT_CN: &str = "edge";

/// The tenant name stamped into the gateway CA's subject (purely
/// descriptive; `build_ca` prefixes it with "Interflow tenant CA:").
const GATEWAY_CA_NAME: &str = "gateway";

/// Ensures the gateway material `gateway/gateway-ca.crt|key` +
/// `gateway/edge.crt|key` exists: a dedicated gateway CA plus its client
/// pair (RFC docs/design/agent-e2e-encryption.md §3.4/§5.2).
///
/// Independent of the tenant CAs (cross-tenant principal, own anchor).
/// `force` re-issues the client pair only — never the CA (a replaced CA
/// would silently un-anchor every egress that distributes it).
pub fn ensure_gateway(out_dir: &Path, force: bool) -> Result<(Outcome, GatewayPaths)> {
    let dir = out_dir.join("gateway");
    let paths = GatewayPaths {
        ca_cert: dir.join("gateway-ca.crt"),
        ca_key: dir.join("gateway-ca.key"),
        client_cert: dir.join("edge.crt"),
        client_key: dir.join("edge.key"),
    };

    // Anchor CA: create-or-validate, never re-issue (not even with --force).
    let ca_as_tenant = TenantCaPaths {
        cert: paths.ca_cert.clone(),
        key: paths.ca_key.clone(),
    };
    let ca = match (paths.ca_cert.exists(), paths.ca_key.exists()) {
        (false, false) => {
            std::fs::create_dir_all(&dir).map_err(|e| Error::Io {
                context: format!("failed to create {}", dir.display()),
                source: e,
            })?;
            let material = build_ca(GATEWAY_CA_NAME, Validity::ca_default())?;
            write_cert(&paths.ca_cert, &material.cert_pem)?;
            write_private_key(&paths.ca_key, &material.key_pem)?;
            LoadedCa::from_material(&material)?
        }
        (true, true) => {
            validate_existing_ca(&ca_as_tenant, GATEWAY_CA_NAME)?;
            load_ca(&ca_as_tenant)?
        }
        (true, false) | (false, true) => {
            return Err(Error::Mismatch(incomplete_pair_msg(
                "gateway CA",
                &paths.ca_cert,
                &paths.ca_key,
            )));
        }
    };

    match (paths.client_cert.exists(), paths.client_key.exists()) {
        (true, true) if !force => {
            validate_existing_gateway_client(&paths, &ca)?;
            Ok((Outcome::AlreadyValid, paths))
        }
        (false, false) | (true, true) => {
            issue_gateway_client(&paths, &ca)?;
            Ok((Outcome::Created, paths))
        }
        (true, false) | (false, true) => Err(Error::Mismatch(incomplete_pair_msg(
            "gateway client certificate",
            &paths.client_cert,
            &paths.client_key,
        ))),
    }
}

// ---------------------------------------------------------------------------
// Internals
// ---------------------------------------------------------------------------

fn tenant_ca_paths(out_dir: &Path, tenant: &str) -> TenantCaPaths {
    let tenants_dir = out_dir.join("tenants");
    TenantCaPaths {
        cert: tenants_dir.join(format!("{tenant}-ca.crt")),
        key: tenants_dir.join(format!("{tenant}-ca.key")),
    }
}

fn load_ca(paths: &TenantCaPaths) -> Result<LoadedCa> {
    let cert_pem = std::fs::read_to_string(&paths.cert).map_err(|e| io_err(&paths.cert)(e))?;
    let key_pem = std::fs::read_to_string(&paths.key).map_err(|e| io_err(&paths.key)(e))?;
    LoadedCa::from_pem_pair(&cert_pem, &key_pem)
}

fn issue_hub(paths: &HubPaths, ca: &LoadedCa, names: &[SanName]) -> Result<()> {
    let material = ca.build_server_cert(names, Validity::leaf_default())?;
    write_cert(&paths.cert, &material.cert_pem)?;
    write_private_key(&paths.key, &material.key_pem)
}

fn issue_agent(agents_dir: &Path, paths: &AgentPaths, ca: &LoadedCa, agent_id: &str) -> Result<()> {
    let material = ca.build_client_cert(agent_id, Validity::leaf_default())?;
    std::fs::create_dir_all(agents_dir).map_err(|e| Error::Io {
        context: format!("failed to create {}", agents_dir.display()),
        source: e,
    })?;
    write_cert(&paths.cert, &material.cert_pem)?;
    write_private_key(&paths.key, &material.key_pem)
}

/// Issues the gateway client pair. `edge.crt` is the leaf + CA chain
/// bundle (the edge loads its leaf and its `_edge` trust root from this
/// one file via `--gateway-cert`).
fn issue_gateway_client(paths: &GatewayPaths, ca: &LoadedCa) -> Result<()> {
    let material = ca.build_client_cert(GATEWAY_CLIENT_CN, Validity::leaf_default())?;
    let chain = format!("{}{}", material.cert_pem, ca.cert_pem());
    write_cert(&paths.client_cert, &chain)?;
    write_private_key(&paths.client_key, &material.key_pem)
}

fn io_err(path: &Path) -> impl Fn(std::io::Error) -> Error + '_ {
    move |e| Error::Io {
        context: format!("failed to read {}", path.display()),
        source: e,
    }
}

fn write_err(path: &Path) -> impl Fn(std::io::Error) -> Error + '_ {
    move |e| Error::Io {
        context: format!("failed to write {}", path.display()),
        source: e,
    }
}

fn write_cert(path: &Path, pem: &str) -> Result<()> {
    std::fs::write(path, pem.as_bytes()).map_err(write_err(path))
}

/// Writes a private key PEM and enforces 0600 on Unix.
fn write_private_key(path: &Path, pem: &str) -> Result<()> {
    std::fs::write(path, pem.as_bytes()).map_err(write_err(path))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut perms = std::fs::metadata(path)
            .map_err(|e| Error::Io {
                context: "failed to read key metadata".to_owned(),
                source: e,
            })?
            .permissions();
        perms.set_mode(0o600);
        std::fs::set_permissions(path, perms).map_err(|e| Error::Io {
            context: "failed to chmod 600".to_owned(),
            source: e,
        })?;
    }
    Ok(())
}

fn incomplete_pair_msg(what: &str, cert: &Path, key: &Path) -> String {
    let (existing, missing) = if cert.exists() {
        (cert, key)
    } else {
        (key, cert)
    };
    format!(
        "incomplete {what} pair: {} exists but {} is missing — an earlier run was \
         interrupted; delete the leftover file or pick a fresh --out directory",
        existing.display(),
        missing.display()
    )
}

/// Reads the first PEM certificate from `path` as DER.
fn read_cert_der(path: &Path) -> Result<Vec<u8>> {
    let pem = std::fs::read(path).map_err(io_err(path))?;
    match rustls_pemfile::certs(&mut std::io::Cursor::new(&pem)).next() {
        Some(Ok(cert)) => Ok(cert.to_vec()),
        Some(Err(e)) => Err(Error::Parse(format!("certificate {}: {e}", path.display()))),
        None => Err(Error::Parse(format!(
            "certificate {}: no PEM certificate found",
            path.display()
        ))),
    }
}

fn read_key_pair(path: &Path) -> Result<rcgen::KeyPair> {
    let pem = std::fs::read_to_string(path).map_err(io_err(path))?;
    rcgen::KeyPair::from_pem(&pem)
        .map_err(|e| Error::Parse(format!("private key {}: {e}", path.display())))
}

fn with_parsed_cert<T>(
    der: &[u8],
    f: impl FnOnce(&x509_parser::certificate::X509Certificate<'_>) -> Result<T>,
) -> Result<T> {
    match x509_parser::parse_x509_certificate(der) {
        Ok((_, cert)) => f(&cert),
        Err(e) => Err(Error::Parse(format!("failed to parse certificate: {e}"))),
    }
}

fn ext_err(e: &x509_parser::error::X509Error) -> Error {
    Error::Parse(format!("failed to parse certificate extension: {e}"))
}

fn cert_cn(der: &[u8]) -> Result<String> {
    let cn = with_parsed_cert(der, |cert| {
        Ok(cert
            .subject()
            .iter_common_name()
            .next()
            .and_then(|cn| cn.as_str().ok().map(str::to_owned)))
    })?;
    cn.map(|s| s.to_ascii_lowercase())
        .ok_or_else(|| Error::Parse("certificate has no CN".to_owned()))
}

fn cert_is_ca(der: &[u8]) -> Result<bool> {
    with_parsed_cert(der, |cert| Ok(cert.is_ca()))
}

fn cert_has_key_cert_sign(der: &[u8]) -> Result<bool> {
    with_parsed_cert(der, |cert| {
        Ok(cert
            .key_usage()
            .map_err(|e| ext_err(&e))?
            .is_some_and(|ku| ku.value.key_cert_sign()))
    })
}

fn cert_eku(der: &[u8]) -> Result<(bool, bool)> {
    let eku = with_parsed_cert(der, |cert| {
        let eku = cert.extended_key_usage().map_err(|e| ext_err(&e))?;
        Ok(eku.map(|eku| (eku.value.server_auth, eku.value.client_auth)))
    })?;
    eku.ok_or_else(|| Error::Mismatch("certificate has no EKU extension".to_owned()))
}

fn cert_san_set(der: &[u8]) -> Result<BTreeSet<SanName>> {
    let san = with_parsed_cert(der, |cert| {
        let san = cert.subject_alternative_name().map_err(|e| ext_err(&e))?;
        Ok(san.map(|san| {
            san.value
                .general_names
                .iter()
                .filter_map(|gn| match gn {
                    x509_parser::extensions::GeneralName::DNSName(s) => {
                        Some(SanName::Dns(s.to_ascii_lowercase()))
                    }
                    x509_parser::extensions::GeneralName::IPAddress(b) => ip_from_bytes(b),
                    _ => None,
                })
                .collect::<BTreeSet<_>>()
        }))
    })?;
    san.ok_or_else(|| Error::Parse("certificate has no SAN extension".to_owned()))
}

fn ip_from_bytes(b: &[u8]) -> Option<SanName> {
    match b.len() {
        4 => {
            let mut a = [0u8; 4];
            a.copy_from_slice(b);
            Some(SanName::Ip(IpAddr::from(a)))
        }
        16 => {
            let mut a = [0u8; 16];
            a.copy_from_slice(b);
            Some(SanName::Ip(IpAddr::from(a)))
        }
        _ => None,
    }
}

fn cert_not_after_unix(der: &[u8]) -> Result<i64> {
    with_parsed_cert(der, |cert| Ok(cert.validity().not_after.timestamp()))
}

/// The certificate's public key must be the one in the key file.
fn check_pair_matches(
    what: &str,
    cert_path: &Path,
    key_path: &Path,
    der: &[u8],
    key: &rcgen::KeyPair,
) -> Result<()> {
    let key_raw = key.public_key_raw().to_vec();
    let matches = with_parsed_cert(der, |cert| {
        Ok(cert
            .tbs_certificate
            .subject_pki
            .subject_public_key
            .data
            .as_ref()
            == key_raw.as_slice())
    })?;
    if matches {
        Ok(())
    } else {
        Err(Error::Mismatch(format!(
            "{what}: {} and {} do not form a pair (public keys differ) — restore the \
             original files, or re-issue with --force",
            cert_path.display(),
            key_path.display()
        )))
    }
}

fn validate_existing_ca(paths: &TenantCaPaths, tenant: &str) -> Result<()> {
    let der = read_cert_der(&paths.cert)?;
    let key = read_key_pair(&paths.key)?;
    check_pair_matches("tenant CA", &paths.cert, &paths.key, &der, &key)?;

    let what = format!("tenant CA {tenant}");
    if !cert_is_ca(&der)? {
        return Err(Error::Mismatch(format!(
            "{what}: {} is not a CA certificate (missing CA basic constraints) — expected \
             a certificate issued by `interflow-mesh certs`",
            paths.cert.display()
        )));
    }
    if !cert_has_key_cert_sign(&der)? {
        return Err(Error::Mismatch(format!(
            "{what}: {} lacks the KeyCertSign key usage — expected a certificate issued \
             by `interflow-mesh certs`",
            paths.cert.display()
        )));
    }
    let expected_cn = format!("interflow tenant ca: {tenant}");
    let actual_cn = cert_cn(&der)?;
    if actual_cn != expected_cn {
        return Err(Error::Mismatch(format!(
            "{what}: {} belongs to a different tenant (CN {actual_cn:?}, expected \
             {expected_cn:?}) — pass the matching --tenant, or pick a fresh --out directory",
            paths.cert.display()
        )));
    }
    if cert_not_after_unix(&der)? < time::OffsetDateTime::now_utc().unix_timestamp() {
        return Err(Error::Expired(format!(
            "{what} has expired — rotation: pick a fresh --out directory and re-issue \
             the hub pair and every agent certificate (there is no revocation; the old \
             CA simply ages out once nothing trusts it)"
        )));
    }
    Ok(())
}

fn validate_existing_hub(
    paths: &HubPaths,
    ca_paths: &TenantCaPaths,
    requested: &[SanName],
) -> Result<()> {
    let der = read_cert_der(&paths.cert)?;
    let key = read_key_pair(&paths.key)?;
    check_pair_matches("hub certificate", &paths.cert, &paths.key, &der, &key)?;

    if cert_is_ca(&der)? {
        return Err(Error::Mismatch(format!(
            "hub certificate: {} is a CA certificate — expected a server leaf",
            paths.cert.display()
        )));
    }
    let (server_auth, _) = cert_eku(&der)?;
    if !server_auth {
        return Err(Error::Mismatch(format!(
            "hub certificate: {} does not carry the ServerAuth EKU",
            paths.cert.display()
        )));
    }
    let requested_set: BTreeSet<_> = requested.iter().cloned().collect();
    let actual_set = cert_san_set(&der)?;
    if actual_set != requested_set {
        let actual = fmt_san_set(&actual_set);
        let wanted = fmt_san_set(&requested_set);
        return Err(Error::Mismatch(format!(
            "hub certificate: SAN [{actual}] != requested [{wanted}] — pass the names \
             the existing certificate was issued for, or re-issue with --force"
        )));
    }
    let expected_cn = requested[0].to_string().to_ascii_lowercase();
    let actual_cn = cert_cn(&der)?;
    if actual_cn != expected_cn {
        return Err(Error::Mismatch(format!(
            "hub certificate: CN {actual_cn:?} != requested {expected_cn:?}"
        )));
    }

    let ca_der = read_cert_der(&ca_paths.cert)?;
    verify_leaf_against_ca("hub certificate", &ca_der, &der, Some(&requested[0]))
}

fn validate_existing_agent(
    paths: &AgentPaths,
    ca_paths: &TenantCaPaths,
    agent_id: &str,
) -> Result<()> {
    let der = read_cert_der(&paths.cert)?;
    let key = read_key_pair(&paths.key)?;
    let what = format!("agent certificate {agent_id}");
    check_pair_matches(&what, &paths.cert, &paths.key, &der, &key)?;

    if cert_is_ca(&der)? {
        return Err(Error::Mismatch(format!(
            "{what}: {} is a CA certificate — expected a client leaf",
            paths.cert.display()
        )));
    }
    let (_, client_auth) = cert_eku(&der)?;
    if !client_auth {
        return Err(Error::Mismatch(format!(
            "{what}: {} does not carry the ClientAuth EKU",
            paths.cert.display()
        )));
    }
    let actual_cn = cert_cn(&der)?;
    if actual_cn != agent_id.to_ascii_lowercase() {
        return Err(Error::Mismatch(format!(
            "{what}: CN {actual_cn:?} != agent id {agent_id:?} (the hub binds identity \
             to CN == agent_id) — re-issue with --force"
        )));
    }

    let ca_der = read_cert_der(&ca_paths.cert)?;
    verify_leaf_against_ca(&what, &ca_der, &der, None)
}

/// Validates the on-disk gateway client pair: the `edge.crt` chain bundle
/// must be leaf-first with the gateway CA last, the leaf must carry
/// CN == `edge` + ClientAuth EKU and match the key, and the chain must
/// actually verify.
fn validate_existing_gateway_client(paths: &GatewayPaths, _ca: &LoadedCa) -> Result<()> {
    let chain = read_cert_chain(&paths.client_cert)?;
    if chain.len() < 2 {
        return Err(Error::Mismatch(format!(
            "gateway client certificate {}: expected a chain bundle (leaf first, gateway \
             CA last) — found {} certificate(s); re-issue with --force",
            paths.client_cert.display(),
            chain.len()
        )));
    }
    let (leaf, rest) = chain.split_first().expect("len checked");
    let what = "gateway client certificate";
    let key = read_key_pair(&paths.client_key)?;
    check_pair_matches(what, &paths.client_cert, &paths.client_key, leaf, &key)?;

    if cert_is_ca(leaf)? {
        return Err(Error::Mismatch(format!(
            "{what}: {} leaf is a CA certificate — expected a client leaf",
            paths.client_cert.display()
        )));
    }
    let (_, client_auth) = cert_eku(leaf)?;
    if !client_auth {
        return Err(Error::Mismatch(format!(
            "{what}: {} does not carry the ClientAuth EKU",
            paths.client_cert.display()
        )));
    }
    let actual_cn = cert_cn(leaf)?;
    if actual_cn != GATEWAY_CLIENT_CN {
        return Err(Error::Mismatch(format!(
            "{what}: CN {actual_cn:?} != {GATEWAY_CLIENT_CN:?} (the expose edge's \
             principal; the inner-layer CN binding depends on it) — re-issue with --force"
        )));
    }

    // The trailing CA must be the anchor CA itself (byte-identical DER).
    let ca_der = read_cert_der(&paths.ca_cert)?;
    let trailing: &[u8] = rest.last().expect("len checked");
    if trailing != ca_der.as_slice() {
        return Err(Error::Mismatch(format!(
            "{what}: {} does not end with the gateway CA — the chain bundle is \
             inconsistent; re-issue with --force",
            paths.client_cert.display()
        )));
    }
    verify_leaf_against_ca(what, &ca_der, leaf, None)
}

/// Reads **all** PEM certificates from `path` as DER (chain order).
fn read_cert_chain(path: &Path) -> Result<Vec<Vec<u8>>> {
    let pem = std::fs::read(path).map_err(io_err(path))?;
    rustls_pemfile::certs(&mut std::io::Cursor::new(&pem))
        .collect::<std::result::Result<Vec<_>, _>>()
        .map(|certs| certs.into_iter().map(|c| c.to_vec()).collect())
        .map_err(|e| Error::Parse(format!("certificate {}: {e}", path.display())))
}

fn fmt_san_set(set: &BTreeSet<SanName>) -> String {
    set.iter()
        .map(ToString::to_string)
        .collect::<Vec<_>>()
        .join(", ")
}

/// Real chain verification through rustls's webpki verifiers — signature,
/// validity window, EKU compatibility, and (for server leaves) the hostname.
fn verify_leaf_against_ca(
    what: &str,
    ca_der: &[u8],
    leaf_der: &[u8],
    server_name: Option<&SanName>,
) -> Result<()> {
    use rustls::client::danger::ServerCertVerifier;
    use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
    use std::sync::Arc;

    let mut roots = rustls::RootCertStore::empty();
    roots
        .add(CertificateDer::from(ca_der.to_vec()))
        .map_err(|e| Error::Parse(format!("tenant CA rejected by rustls: {e}")))?;
    let leaf = CertificateDer::from(leaf_der.to_vec());
    let result = if let Some(name) = server_name {
        let verifier = rustls::client::WebPkiServerVerifier::builder(Arc::new(roots))
            .build()
            .map_err(|e| Error::Parse(format!("verifier build: {e}")))?;
        let sn = ServerName::try_from(name.to_string())
            .map_err(|e| Error::Parse(format!("hub name {name}: {e}")))?;
        verifier
            .verify_server_cert(&leaf, &[], &sn, &[], UnixTime::now())
            .map(|_| ())
    } else {
        let verifier = rustls::server::WebPkiClientVerifier::builder(Arc::new(roots))
            .build()
            .map_err(|e| Error::Parse(format!("verifier build: {e}")))?;
        verifier
            .verify_client_cert(&leaf, &[], UnixTime::now())
            .map(|_| ())
    };
    result.map_err(|e| map_verify_error(what, &e))
}

fn map_verify_error(what: &str, e: &rustls::Error) -> Error {
    if let rustls::Error::InvalidCertificate(
        rustls::CertificateError::Expired | rustls::CertificateError::ExpiredContext { .. },
    ) = e
    {
        Error::Expired(format!(
            "{what} is expired — re-issue with --force (the tenant CA is kept; previously \
             issued certificates stay valid until their own expiry)"
        ))
    } else {
        Error::Mismatch(format!(
            "{what} does not verify against the tenant CA ({e}) — it was issued by a \
             different CA; restore the matching files or pick a fresh --out directory"
        ))
    }
}

#[cfg(test)]
#[allow(
    clippy::panic,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::missing_docs_in_private_items
)]
mod tests {
    use super::*;
    use rustls::client::WebPkiServerVerifier;
    use rustls::client::danger::ServerCertVerifier;
    use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
    use std::io::Cursor;
    use std::sync::Arc;

    fn names(values: &[&str]) -> Vec<SanName> {
        values.iter().map(|v| SanName::parse(v).unwrap()).collect()
    }

    /// Reads a PEM file and returns the DER of the first certificate.
    fn read_cert_der_at(path: &Path) -> Vec<u8> {
        let pem = std::fs::read(path).expect("failed to read certificate file");
        rustls_pemfile::certs(&mut Cursor::new(&pem))
            .next()
            .expect("PEM should contain at least one certificate")
            .expect("failed to parse PEM")
            .to_vec()
    }

    fn generate_in(dir: &Path, hub: &[&str]) -> GeneratedCerts {
        generate(dir, &names(hub), "main", &[])
            .unwrap_or_else(|e| panic!("generate should succeed: {e}"))
    }

    #[test]
    fn generate_writes_section_2_4_layout() {
        let dir = tempfile::tempdir().unwrap();
        let certs = generate(
            dir.path(),
            &names(&["hub.example.com"]),
            "acme",
            &["expose-myapp".to_owned()],
        )
        .unwrap();
        assert!(certs.ca_cert.ends_with("tenants/acme-ca.crt"));
        assert!(certs.ca_key.ends_with("tenants/acme-ca.key"));
        assert!(certs.hub_cert.ends_with("hub.crt"));
        assert!(certs.hub_key.ends_with("hub.key"));
        assert_eq!(certs.agents.len(), 1);
        assert_eq!(certs.agents[0].agent_id, "expose-myapp");
        assert!(certs.agents[0].cert.ends_with("agents/expose-myapp.crt"));
        assert!(certs.agents[0].key.ends_with("agents/expose-myapp.key"));
        for path in [
            &certs.ca_cert,
            &certs.ca_key,
            &certs.hub_cert,
            &certs.hub_key,
            &certs.agents[0].cert,
            &certs.agents[0].key,
        ] {
            assert!(
                !std::fs::read(path).unwrap().is_empty(),
                "{path} should not be empty"
            );
        }
    }

    #[test]
    fn agent_cert_cn_equals_agent_id_with_client_auth_eku() {
        let dir = tempfile::tempdir().unwrap();
        let certs = generate(
            dir.path(),
            &names(&["hub.example.com"]),
            "main",
            &["expose-myapp".to_owned()],
        )
        .unwrap();
        let der = read_cert_der_at(Path::new(&certs.agents[0].cert));
        let agent = x509_parser::parse_x509_certificate(&der).unwrap().1;
        let cn = agent
            .subject()
            .iter_common_name()
            .next()
            .expect("agent cert must have a CN")
            .as_str()
            .unwrap();
        assert_eq!(cn, "expose-myapp");
        let eku = agent
            .extended_key_usage()
            .expect("failed to parse EKU extension")
            .expect("agent cert must have an EKU extension");
        assert!(eku.value.client_auth, "agent EKU must include ClientAuth");
        assert!(
            !eku.value.server_auth,
            "agent EKU must not include ServerAuth"
        );
    }

    #[test]
    #[cfg(unix)]
    fn private_keys_are_0600() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let certs = generate(
            dir.path(),
            &names(&["hub.example.com"]),
            "main",
            &["expose-myapp".to_owned()],
        )
        .unwrap();
        for path in [&certs.ca_key, &certs.hub_key, &certs.agents[0].key] {
            let mode = std::fs::metadata(path).unwrap().permissions().mode();
            assert_eq!(
                mode & 0o777,
                0o600,
                "{path} permissions are not 0600, got {mode:o}"
            );
        }
    }

    #[test]
    fn ca_cert_is_self_signed_ca() {
        let dir = tempfile::tempdir().unwrap();
        let certs = generate_in(dir.path(), &["hub.example.com"]);
        let der = read_cert_der_at(Path::new(&certs.ca_cert));
        let ca = x509_parser::parse_x509_certificate(&der).unwrap().1;
        assert!(ca.is_ca(), "CA cert must be marked isCA");
        let ku = ca
            .key_usage()
            .expect("failed to parse KeyUsage extension")
            .expect("CA cert must have a KeyUsage extension");
        assert!(ku.value.key_cert_sign(), "CA must have KeyCertSign");
        assert!(ku.value.crl_sign(), "CA must have CrlSign");
        let cn = ca
            .subject()
            .iter_common_name()
            .next()
            .expect("CA must have a CN")
            .as_str()
            .unwrap();
        assert_eq!(cn, "Interflow tenant CA: main");
    }

    #[test]
    fn hub_cert_has_correct_cn() {
        let dir = tempfile::tempdir().unwrap();
        let certs = generate_in(dir.path(), &["hub.example.com"]);
        let der = read_cert_der_at(Path::new(&certs.hub_cert));
        assert_eq!(cert_cn(&der).unwrap(), "hub.example.com");
    }

    #[test]
    fn hub_cert_san_covers_requested_dns_and_ip() {
        let dir = tempfile::tempdir().unwrap();
        let certs = generate_in(dir.path(), &["hub.example.com", "10.0.0.5"]);
        let der = read_cert_der_at(Path::new(&certs.hub_cert));
        let san = cert_san_set(&der).unwrap();
        assert!(san.contains(&SanName::Dns("hub.example.com".to_owned())));
        assert!(san.contains(&SanName::Ip("10.0.0.5".parse().unwrap())));
        assert_eq!(san.len(), 2);
    }

    #[test]
    fn hub_cert_has_server_auth_eku() {
        let dir = tempfile::tempdir().unwrap();
        let certs = generate_in(dir.path(), &["hub.example.com"]);
        let der = read_cert_der_at(Path::new(&certs.hub_cert));
        let (server_auth, client_auth) = cert_eku(&der).unwrap();
        assert!(server_auth, "EKU must include ServerAuth");
        assert!(!client_auth, "EKU must not include ClientAuth");
    }

    #[test]
    fn hub_cert_is_not_ca() {
        let dir = tempfile::tempdir().unwrap();
        let certs = generate_in(dir.path(), &["hub.example.com"]);
        let der = read_cert_der_at(Path::new(&certs.hub_cert));
        assert!(!cert_is_ca(&der).unwrap(), "hub leaf must not be a CA");
    }

    #[test]
    #[cfg(unix)]
    fn hub_key_file_permissions_are_0600() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let certs = generate_in(dir.path(), &["hub.example.com"]);
        let mode = std::fs::metadata(&certs.hub_key)
            .unwrap()
            .permissions()
            .mode();
        assert_eq!(
            mode & 0o777,
            0o600,
            "hub.key permissions are not 0600, got {mode:o}"
        );
    }

    // ---- Layer 2: chain verification through rustls (webpki verifiers) ----

    fn build_verifier(ca_path: &str) -> Arc<dyn ServerCertVerifier> {
        let mut roots = rustls::RootCertStore::empty();
        let ca_der = read_cert_der_at(Path::new(ca_path));
        roots.add(CertificateDer::from(ca_der)).unwrap();
        WebPkiServerVerifier::builder(Arc::new(roots))
            .build()
            .expect("failed to build verifier")
    }

    #[test]
    fn rustls_accepts_hub_cert_signed_by_generated_ca() {
        let dir = tempfile::tempdir().unwrap();
        let certs = generate_in(dir.path(), &["hub.example.com"]);
        let verifier = build_verifier(&certs.ca_cert);
        let hub_der = read_cert_der_at(Path::new(&certs.hub_cert));
        let end_entity = CertificateDer::from(hub_der);
        let name: ServerName<'static> = "hub.example.com"
            .try_into()
            .expect("hostname should parse as a ServerName");
        let result = verifier.verify_server_cert(&end_entity, &[], &name, &[], UnixTime::now());
        assert!(
            result.is_ok(),
            "rustls should accept the hub cert signed by the CA, got: {:?}",
            result.err()
        );
    }

    #[test]
    fn rustls_rejects_wrong_hostname() {
        let dir = tempfile::tempdir().unwrap();
        let certs = generate_in(dir.path(), &["hub.example.com"]);
        let verifier = build_verifier(&certs.ca_cert);
        let hub_der = read_cert_der_at(Path::new(&certs.hub_cert));
        let end_entity = CertificateDer::from(hub_der);
        let evil: ServerName<'static> = "evil.example.com".try_into().unwrap();
        let result = verifier.verify_server_cert(&end_entity, &[], &evil, &[], UnixTime::now());
        assert!(
            result.is_err(),
            "rustls must not accept a wrong hostname, but verification passed"
        );
    }

    #[test]
    fn issued_certificates_carry_explicit_validity() {
        let dir = tempfile::tempdir().unwrap();
        let certs = generate_in(dir.path(), &["hub.example.com"]);
        let der = read_cert_der_at(Path::new(&certs.hub_cert));
        let now = time::OffsetDateTime::now_utc().unix_timestamp();
        let not_after = cert_not_after_unix(&der).unwrap();
        let year = 365 * 24 * 3600;
        // Leaf default: 1 year (rcgen's own default would span to year 4096).
        assert!(
            (not_after - now).abs() < year + 24 * 3600,
            "leaf validity should be ~1 year, got not_after {not_after} (now {now})"
        );
    }

    // ---- Idempotency semantics ----

    #[test]
    fn second_run_is_already_valid_and_files_unchanged() {
        let dir = tempfile::tempdir().unwrap();
        let certs = generate(
            dir.path(),
            &names(&["hub.example.com"]),
            "main",
            &["agent-1".to_owned()],
        )
        .unwrap();
        let before: Vec<Vec<u8>> = [&certs.ca_cert, &certs.hub_cert, &certs.agents[0].cert]
            .iter()
            .map(|p| std::fs::read(p).unwrap())
            .collect();

        let (ca_outcome, _) = ensure_tenant_ca(dir.path(), "main").unwrap();
        let (hub_outcome, _) =
            ensure_hub_cert(dir.path(), "main", &names(&["hub.example.com"]), false).unwrap();
        let (agent_outcome, _) = ensure_agent_cert(dir.path(), "main", "agent-1", false).unwrap();
        assert_eq!(ca_outcome, Outcome::AlreadyValid);
        assert_eq!(hub_outcome, Outcome::AlreadyValid);
        assert_eq!(agent_outcome, Outcome::AlreadyValid);

        let after: Vec<Vec<u8>> = [&certs.ca_cert, &certs.hub_cert, &certs.agents[0].cert]
            .iter()
            .map(|p| std::fs::read(p).unwrap())
            .collect();
        assert_eq!(before, after, "validation must not rewrite files");
    }

    #[test]
    fn incomplete_pairs_error_instead_of_partial_skip() {
        let dir = tempfile::tempdir().unwrap();
        let certs = generate_in(dir.path(), &["hub.example.com"]);

        std::fs::remove_file(&certs.hub_key).unwrap();
        let err =
            ensure_hub_cert(dir.path(), "main", &names(&["hub.example.com"]), false).unwrap_err();
        assert!(
            err.to_string().contains("incomplete"),
            "should report the incomplete pair, got: {err}"
        );

        std::fs::remove_file(&certs.ca_key).unwrap();
        let err = ensure_tenant_ca(dir.path(), "main").unwrap_err();
        assert!(
            err.to_string().contains("incomplete"),
            "should report the incomplete pair, got: {err}"
        );
    }

    #[test]
    fn swapped_key_is_detected() {
        let dir_a = tempfile::tempdir().unwrap();
        let dir_b = tempfile::tempdir().unwrap();
        let a = generate_in(dir_a.path(), &["hub.example.com"]);
        let b = generate_in(dir_b.path(), &["hub.example.com"]);
        // Same names, different key: the pair no longer matches.
        std::fs::copy(&b.hub_key, &a.hub_key).unwrap();
        let err =
            ensure_hub_cert(dir_a.path(), "main", &names(&["hub.example.com"]), false).unwrap_err();
        assert!(
            err.to_string().contains("do not form a pair"),
            "should detect the key swap, got: {err}"
        );
    }

    #[test]
    fn foreign_ca_agent_cert_is_detected() {
        let dir_a = tempfile::tempdir().unwrap();
        let dir_b = tempfile::tempdir().unwrap();
        let a = generate(
            dir_a.path(),
            &names(&["hub.example.com"]),
            "main",
            &["agent-1".to_owned()],
        )
        .unwrap();
        let b = generate(
            dir_b.path(),
            &names(&["hub.example.com"]),
            "main",
            &["agent-1".to_owned()],
        )
        .unwrap();
        // Both dirs are internally valid; mixing b's agent pair into a's
        // layout must fail validation (different issuing CA).
        std::fs::copy(&b.agents[0].cert, &a.agents[0].cert).unwrap();
        std::fs::copy(&b.agents[0].key, &a.agents[0].key).unwrap();
        let err = ensure_agent_cert(dir_a.path(), "main", "agent-1", false).unwrap_err();
        assert!(
            matches!(err, Error::Mismatch(_)),
            "foreign-CA agent cert should be a Mismatch, got: {err}"
        );
    }

    #[test]
    fn hub_san_mismatch_errors_with_diff() {
        let dir = tempfile::tempdir().unwrap();
        generate_in(dir.path(), &["hub.example.com"]);
        let err =
            ensure_hub_cert(dir.path(), "main", &names(&["other.example.com"]), false).unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("SAN") && msg.contains("other.example.com"),
            "should report the SAN difference, got: {msg}"
        );
    }

    #[test]
    fn expired_hub_cert_reports_expired_then_force_reissues() {
        let dir = tempfile::tempdir().unwrap();
        let (_, ca_paths) = ensure_tenant_ca(dir.path(), "main").unwrap();
        let ca = load_ca(&ca_paths).unwrap();
        let now = time::OffsetDateTime::now_utc();
        let expired = ca
            .build_server_cert(
                &names(&["hub.example.com"]),
                Validity {
                    not_before: now - time::Duration::days(3),
                    not_after: now - time::Duration::days(1),
                },
            )
            .unwrap();
        let hub = HubPaths {
            cert: dir.path().join("hub.crt"),
            key: dir.path().join("hub.key"),
        };
        write_cert(&hub.cert, &expired.cert_pem).unwrap();
        write_private_key(&hub.key, &expired.key_pem).unwrap();

        let err =
            ensure_hub_cert(dir.path(), "main", &names(&["hub.example.com"]), false).unwrap_err();
        assert!(
            matches!(err, Error::Expired(_)),
            "expired cert should map to Expired with --force guidance, got: {err}"
        );

        let (outcome, _) =
            ensure_hub_cert(dir.path(), "main", &names(&["hub.example.com"]), true).unwrap();
        assert_eq!(outcome, Outcome::Created);
        let (outcome, _) =
            ensure_hub_cert(dir.path(), "main", &names(&["hub.example.com"]), false).unwrap();
        assert_eq!(outcome, Outcome::AlreadyValid);
    }

    #[test]
    fn force_hub_reissue_keeps_ca_bytes() {
        let dir = tempfile::tempdir().unwrap();
        let certs = generate_in(dir.path(), &["hub.example.com"]);
        let ca_before = std::fs::read(&certs.ca_cert).unwrap();
        let hub_before = std::fs::read(&certs.hub_cert).unwrap();

        let (outcome, _) =
            ensure_hub_cert(dir.path(), "main", &names(&["hub.example.com"]), true).unwrap();
        assert_eq!(outcome, Outcome::Created);
        assert_eq!(
            std::fs::read(&certs.ca_cert).unwrap(),
            ca_before,
            "force must never rewrite the tenant CA"
        );
        assert_ne!(
            std::fs::read(&certs.hub_cert).unwrap(),
            hub_before,
            "force should re-issue the hub pair"
        );
    }

    #[test]
    fn agent_issue_against_generated_layout_round_trips() {
        // The wizard flow: generate (CA + hub), then keep issuing agents with
        // the persisted CA — the `certs agent issue` path.
        let dir = tempfile::tempdir().unwrap();
        generate_in(dir.path(), &["hub.example.com"]);
        for id in ["agent-1", "agent-2"] {
            let (outcome, paths) = ensure_agent_cert(dir.path(), "main", id, false).unwrap();
            assert_eq!(outcome, Outcome::Created);
            assert!(paths.cert.ends_with(format!("agents/{id}.crt")));
            let der = read_cert_der_at(&paths.cert);
            assert_eq!(cert_cn(&der).unwrap(), id);
        }
    }

    #[test]
    fn missing_ca_gives_actionable_error() {
        let dir = tempfile::tempdir().unwrap();
        let err = ensure_agent_cert(dir.path(), "main", "agent-1", false).unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("certs init") && msg.contains("not found"),
            "should point at the missing prerequisite, got: {msg}"
        );
    }

    // ---- gateway material ----

    #[test]
    fn gateway_issue_layout_and_content() {
        let dir = tempfile::tempdir().unwrap();
        let (outcome, paths) = ensure_gateway(dir.path(), false).unwrap();
        assert_eq!(outcome, Outcome::Created);
        let base = dir.path().join("gateway");
        assert_eq!(paths.ca_cert, base.join("gateway-ca.crt"));
        assert_eq!(paths.client_cert, base.join("edge.crt"));

        // CA: descriptive subject; client leaf: CN == edge + ClientAuth,
        // chain bundle = leaf + CA (verified through rustls).
        let ca_der = read_cert_der_at(&paths.ca_cert);
        assert_eq!(
            cert_cn(&ca_der).unwrap(),
            "interflow tenant ca: gateway",
            "build_ca subject convention"
        );
        let chain = read_cert_chain(&paths.client_cert).unwrap();
        assert_eq!(chain.len(), 2, "leaf + CA bundle");
        assert_eq!(cert_cn(&chain[0]).unwrap(), GATEWAY_CLIENT_CN);
        assert!(!cert_is_ca(&chain[0]).unwrap());
        let (_, client_auth) = cert_eku(&chain[0]).unwrap();
        assert!(client_auth);
        assert_eq!(chain[1], ca_der, "trailing cert is the anchor CA");

        // 0600 on both keys.
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            for key in [&paths.ca_key, &paths.client_key] {
                let mode = std::fs::metadata(key).unwrap().permissions().mode() & 0o777;
                assert_eq!(mode, 0o600);
            }
        }
    }

    #[test]
    fn gateway_rerun_is_idempotent_and_force_keeps_ca() {
        let dir = tempfile::tempdir().unwrap();
        ensure_gateway(dir.path(), false).unwrap();
        let ca_before = std::fs::read(dir.path().join("gateway/gateway-ca.crt")).unwrap();
        let client_before = std::fs::read(dir.path().join("gateway/edge.crt")).unwrap();

        let (outcome, _) = ensure_gateway(dir.path(), false).unwrap();
        assert_eq!(outcome, Outcome::AlreadyValid);
        assert_eq!(
            std::fs::read(dir.path().join("gateway/gateway-ca.crt")).unwrap(),
            ca_before,
            "idempotent rerun must not rewrite bytes"
        );
        assert_eq!(
            std::fs::read(dir.path().join("gateway/edge.crt")).unwrap(),
            client_before
        );

        // --force re-issues the client pair only; the anchor CA is never
        // replaced (every distributed egress anchor would silently break).
        let (outcome, _) = ensure_gateway(dir.path(), true).unwrap();
        assert_eq!(outcome, Outcome::Created);
        assert_eq!(
            std::fs::read(dir.path().join("gateway/gateway-ca.crt")).unwrap(),
            ca_before,
            "force must not touch the CA"
        );
        let chain = read_cert_chain(&dir.path().join("gateway/edge.crt")).unwrap();
        assert_eq!(cert_cn(&chain[0]).unwrap(), GATEWAY_CLIENT_CN);
    }

    #[test]
    fn gateway_tampered_chain_trails_mismatch() {
        let dir = tempfile::tempdir().unwrap();
        ensure_gateway(dir.path(), false).unwrap();
        // Swap the trailing CA for a foreign one: the bundle consistency
        // check must name it.
        let foreign = build_ca("other", Validity::ca_default()).unwrap();
        let original = std::fs::read_to_string(dir.path().join("gateway/edge.crt")).unwrap();
        let marker = "-----BEGIN CERTIFICATE-----";
        let second = original[marker.len()..]
            .find(marker)
            .expect("bundle carries two certs")
            + marker.len();
        let leaf_part = original[..second].to_string();
        std::fs::write(
            dir.path().join("gateway/edge.crt"),
            format!("{leaf_part}{}", foreign.cert_pem),
        )
        .unwrap();
        let err = ensure_gateway(dir.path(), false).unwrap_err();
        assert!(
            err.to_string().contains("does not end with the gateway CA"),
            "got: {err}"
        );
    }

    #[test]
    fn gateway_incomplete_pair_is_actionable() {
        let dir = tempfile::tempdir().unwrap();
        ensure_gateway(dir.path(), false).unwrap();
        std::fs::remove_file(dir.path().join("gateway/edge.key")).unwrap();
        let err = ensure_gateway(dir.path(), false).unwrap_err();
        assert!(
            err.to_string()
                .contains("incomplete gateway client certificate"),
            "got: {err}"
        );
    }
}
