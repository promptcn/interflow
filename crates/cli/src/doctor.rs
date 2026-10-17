//! `interflow-cli doctor` — identity-first diagnostics.
//!
//! Technical failures are mapped back to product semantics: identity
//! membership, trust generation, route resolution, credential expiry — with
//! a concrete fix for every ✘.

use clap::Subcommand;
use interflow_cli::outln;
use interflow_identity::pack::{CredentialPack, PackKind};
use interflow_identity::policy::PolicyService;
use sha2::{Digest, Sha256};
use std::io::{Read as _, Write as _};
use std::net::TcpStream;
use std::path::PathBuf;
use std::time::Duration;

use crate::doctor_link::LinkArgs;

#[derive(Subcommand)]
pub enum DoctorCommand {
    /// Diagnose one node's credential pack (identity, trust, policy, role).
    Ingress {
        #[arg(long)]
        pack: PathBuf,
    },
    Agent {
        #[arg(long)]
        pack: PathBuf,
    },
    /// Diagnose a site-to-site hub's credential pack (identity, trust table,
    /// admission policy).
    Hub {
        #[arg(long)]
        pack: PathBuf,
    },
    /// Diagnose one route: policy resolution + target existence + DNS hint.
    Route {
        host: String,
        #[arg(long)]
        pack: PathBuf,
    },
    /// Diagnose a pack's trust bundle (fingerprints, generation, CRLs).
    Trust {
        #[arg(long)]
        pack: PathBuf,
    },
    /// Diagnose the issuer store's backup health (operator machine): is it
    /// configured, current, on a second medium — and, with the offline
    /// identity, does the newest backup actually decrypt and parse?
    Issuer {
        /// Issuer store directory.
        #[arg(long, default_value = "issuer")]
        dir: PathBuf,
        /// Path to the offline recovery identity (`-` for stdin): enables a
        /// full trial-decrypt of the newest backup — the only way to know a
        /// backup is real instead of presumed.
        #[arg(long)]
        identity: Option<String>,
    },
    /// Detect engine processes still running a replaced binary — the
    /// disk-swap trap (换盘不换进程): `node install` restarts only its own
    /// unit, so a binary swapped under ANOTHER unit keeps serving the old
    /// build until someone restarts it. Read-only; run it any time after
    /// handling binaries by hand.
    Stale,
    /// The three-layer link diagnostic — authentication (DNS, TCP/UDP
    /// split, mTLS, clock), authorization (watermarks, CRL), data plane
    /// (one real request) — with the handbook's readings attached.
    Link {
        #[command(flatten)]
        args: LinkArgs,
    },
}

impl DoctorCommand {
    pub fn run(self) -> interflow_core::error::Result<()> {
        match self {
            Self::Ingress { pack } => check_node(&pack, PackKind::Ingress),
            Self::Agent { pack } => check_node(&pack, PackKind::Agent),
            Self::Hub { pack } => check_node(&pack, PackKind::Hub),
            Self::Route { host, pack } => check_route(&host, &pack),
            Self::Trust { pack } => check_trust(&pack),
            Self::Issuer { dir, identity } => check_issuer_backup(&dir, identity.as_deref()),
            Self::Stale => check_stale_exec(),
            Self::Link { args } => args.run(),
        }
    }
}

/// The disk-swap reading shared by [`Self::Stale`] and `check_node`:
/// findings are a ✘ with the restart commands as the fix; a clean scan is
/// a ✔ on Linux and a `·` platform note elsewhere (never a fake clean).
// Off Linux the section cannot fail (no /proc) — the wrap is for the
// Linux error path.
#[cfg_attr(not(target_os = "linux"), allow(clippy::unnecessary_wraps))]
fn stale_disk_section() -> interflow_core::error::Result<()> {
    #[cfg(target_os = "linux")]
    {
        let findings = interflow_cli::stale_exec::detect_stale_engine_processes(
            std::path::Path::new(interflow_cli::render::ENGINE_BIN_DIR),
        );
        if findings.is_empty() {
            outln!(
                "✔ every running engine process matches the disk under {}",
                interflow_cli::render::ENGINE_BIN_DIR
            );
            return Ok(());
        }
        outln!(
            "✘ {} engine process(es) still run a replaced binary (binary swapped, process \
             never restarted):",
            findings.len()
        );
        for finding in &findings {
            outln!("  · {}", finding.describe());
        }
        outln!();
        outln!("Diagnosis:");
        outln!(
            "  replacing a file on disk does nothing to the process already running it — the \
             kernel keeps the old code mapped until the unit restarts."
        );
        outln!(
            "  `node install` restarts only its own unit, so a binary swapped under another \
             unit (the edge unit execs interflow-cli; mesh units exec interflow-mesh) keeps \
             serving the old build."
        );
        outln!();
        outln!("Fix:");
        let mut targets: Vec<&str> = findings.iter().filter_map(|f| f.restart_target()).collect();
        targets.sort_unstable();
        targets.dedup();
        if targets.is_empty() {
            outln!("  no product unit owns the stale process(es) — restart them by pid.");
        } else {
            let commands: Vec<String> = targets
                .iter()
                .map(|u| format!("systemctl restart {u}"))
                .collect();
            outln!("  {}", commands.join(" && "));
            outln!(
                "  (or let the next `node install --restart-units` do it; verify afterwards \
                 with `interflow-cli doctor stale`)"
            );
        }
        Err(interflow_core::error::InterflowError::config(
            "engine processes still run a replaced binary",
        ))
    }
    #[cfg(not(target_os = "linux"))]
    {
        outln!("· disk-swap check: Linux-only (/proc exe scan) — skipped on this platform");
        Ok(())
    }
}

/// `doctor stale` — the standalone disk-swap reading; see
/// [`DoctorCommand::Stale`].
fn check_stale_exec() -> interflow_core::error::Result<()> {
    outln!("Interflow doctor — disk-swap detection (换盘不换进程)");
    outln!();
    stale_disk_section()?;
    outln!();
    outln!("All checks passed.");
    Ok(())
}

/// The issuer store's backup health: configuration → versions → currency →
/// (optionally) a real trial-decrypt of the newest version. Every ✘ carries
/// a fix; the same-device warning is the one disk-loss blind spot the
/// default layout cannot fix by itself.
fn check_issuer_backup(
    dir: &std::path::Path,
    identity: Option<&str>,
) -> interflow_core::error::Result<()> {
    use interflow_identity::backup as store_backup;
    outln!("Interflow doctor — issuer store backup");
    let status = store_backup::status(dir).map_err(interflow_cli::runtime::pack_error)?;
    let Some(cfg) = status.config else {
        outln!(
            "✘ issuer store {} has no backup configuration",
            dir.display()
        );
        outln!("  every CA key in it exists in exactly one copy — losing the directory");
        outln!("  means re-issuing the entire mesh from a fresh root");
        outln!("Fix:");
        outln!(
            "  interflow-cli issuer backup init --dir {} (or re-run plan apply)",
            dir.display()
        );
        return Err(interflow_core::error::InterflowError::config(
            "issuer store is not backed up",
        ));
    };
    outln!("✔ backup configured → {}", cfg.backup_dir.display());
    if status.versions.is_empty() {
        outln!("✘ no backup version has landed yet");
        outln!(
            "Fix: interflow-cli issuer backup now --dir {}",
            dir.display()
        );
        return Err(interflow_core::error::InterflowError::config(
            "issuer store backup is configured but empty",
        ));
    }
    outln!(
        "✔ {} version(s) (newest: {})",
        status.versions.len(),
        status.versions.last().map_or_else(
            || "-".to_owned(),
            |p| p.file_name().map_or_else(
                || p.display().to_string(),
                |n| n.to_string_lossy().into_owned()
            )
        )
    );
    if status.same_device == Some(true) {
        outln!("· backup dir shares the disk with the store — one disk failure takes both;");
        outln!(
            "  move it to a second medium when you can: interflow-cli issuer backup relocate \
             --dir {} --backup-dir <second-medium>",
            dir.display()
        );
    }
    if !status.newest_is_current {
        outln!("✘ the store changed since the last successful backup");
        outln!("  (a checkpoint failed, or backups were pruned past it)");
        outln!(
            "Fix: interflow-cli issuer backup now --dir {}",
            dir.display()
        );
        return Err(interflow_core::error::InterflowError::config(
            "issuer store backup is stale",
        ));
    }
    outln!("✔ newest backup matches the current store content");
    if let Some(identity_spec) = identity {
        // Trial-decrypt: the Schrödinger's-backup check — a backup nobody
        // has ever restored from is only presumed good.
        let newest = status
            .versions
            .last()
            .ok_or_else(|| interflow_core::error::InterflowError::config("no backup to drill"))?;
        let identity = if identity_spec == "-" {
            let mut line = String::new();
            std::io::BufRead::read_line(&mut std::io::stdin().lock(), &mut line)?;
            line.trim_end_matches(['\r', '\n']).to_owned()
        } else {
            std::fs::read_to_string(identity_spec).map_err(|e| {
                interflow_core::error::InterflowError::config(format!(
                    "cannot read recovery identity {identity_spec:?}"
                ))
                .with_source(e)
            })?
        };
        let report =
            store_backup::verify(newest, &identity).map_err(interflow_cli::runtime::pack_error)?;
        outln!(
            "✔ drill: newest backup decrypts and parses — {} member(s), {} cert(s), {} key file(s)",
            report.members.len(),
            report.certs.len(),
            report.key_files
        );
    } else {
        outln!("· drill: pass --identity <offline-key-file> to trial-decrypt the newest backup");
    }
    outln!("All checks passed.");
    Ok(())
}

fn check_node(pack_dir: &std::path::Path, expected: PackKind) -> interflow_core::error::Result<()> {
    outln!("Interflow doctor");
    // Load failures are diagnosed in identity terms.
    let pack = match CredentialPack::load_runtime(pack_dir) {
        Ok(pack) => pack,
        Err(e) => {
            outln!(
                "✘ Credential Pack at {} failed validation",
                pack_dir.display()
            );
            outln!();
            outln!("Diagnosis:");
            outln!("  {e}");
            outln!();
            outln!("Fix:");
            outln!("  re-issue with `interflow-cli plan apply` (or `interflow-cli rotate`)");
            return Err(
                interflow_core::error::InterflowError::config("doctor failed").with_source(e),
            );
        }
    };
    let kind_ok = pack.metadata.kind == expected;
    outln!(
        "Realm {} · {} {}",
        pack.metadata.realm,
        pack.metadata.kind.as_str(),
        pack.metadata.node
    );
    outln!();
    outln!("✔ Pack digest verified ({})", pack.pack_digest);

    if !kind_ok {
        outln!();
        outln!("Diagnosis: this pack belongs to another node role.");
        let mesh_role = pack.metadata.kind == PackKind::Hub || pack.node_config.mesh.is_some();
        outln!(
            "Fix: start it with `{}`",
            interflow_cli::render::node_exec_start(
                pack.metadata.kind,
                mesh_role,
                &pack_dir.display().to_string(),
            )
        );
        return Err(interflow_core::error::InterflowError::config(
            "role mismatch",
        ));
    }
    let primary = pack
        .primary_identity()
        .map_err(interflow_cli::runtime::pack_error)?;
    outln!(
        "✔ Identity {} (generation {})",
        primary.principal,
        pack.metadata.generation
    );
    outln!("  bootstrap expires {}", pack.metadata.expires);
    if let Ok(active) =
        interflow_identity::credentials::ActiveCredentialSet::load_or_bootstrap(&pack)
    {
        let expiry = active
            .earliest_expiry()
            .map_err(interflow_cli::runtime::pack_error)?;
        let expiry_text = expiry
            .format(&time::format_description::well_known::Rfc3339)
            .map_err(|e| {
                interflow_core::error::InterflowError::config("timestamp").with_source(e)
            })?;
        // Phase + action line: the same 20%/10% thresholds every surface
        // shows (identity's expiry module is the single source).
        let health = interflow_identity::expiry::leaf_phase_from_ttl(
            expiry.unix_timestamp(),
            pack.metadata.leaf_ttl_secs,
            interflow_identity::expiry::now_unix(),
        );
        let remaining = interflow_identity::expiry::format_remaining(health.remaining_secs);
        use interflow_identity::expiry::LeafPhase;
        let (glyph, action) = match (health.phase, pack.metadata.registrar_endpoint.as_deref()) {
            (LeafPhase::Healthy, _) => ("✔", String::new()),
            (LeafPhase::Warn, Some(endpoint)) => (
                "·",
                format!(" — renewal keeps retrying; check the registrar at {endpoint}"),
            ),
            (LeafPhase::Warn, None) => (
                "·",
                " — offline tier: rotate manually with `interflow-cli rotate`".to_string(),
            ),
            (LeafPhase::Critical, Some(_)) => (
                "✘",
                " — renewal has not landed; the node stops serving at expiry".to_string(),
            ),
            (LeafPhase::Critical, None) => (
                "✘",
                " — offline tier: rotate NOW with `interflow-cli rotate`; the node stops \
                 serving at expiry"
                    .to_string(),
            ),
        };
        outln!("{glyph} Active credentials expire {expiry_text} ({remaining} left{action})");
        match pack.metadata.registrar_endpoint.as_deref() {
            Some(endpoint) => outln!("  registrar: {endpoint}"),
            None => outln!("  registrar: none (offline tier — rotate manually before expiry)"),
        }
    }
    outln!(
        "  principal URI SAN verified: {}",
        primary.uri_san.as_deref().unwrap_or("(missing)")
    );
    outln!(
        "✔ Trust bundle verified ({})",
        pack.trust
            .digest()
            .map_err(interflow_cli::runtime::pack_error)?
    );
    outln!(
        "✔ Runtime policy verified ({} route(s))",
        pack.policy.routes.len()
    );
    outln!("  policy signature verified against the realm policy key");
    // Role-specific wiring.
    match pack.metadata.kind {
        PackKind::Ingress => {
            let principals = pack
                .ingress_identities()
                .map_err(interflow_cli::runtime::pack_error)?;
            for (workspace, entry) in principals {
                outln!(
                    "✔ Workspace authorization {workspace} via {}",
                    entry.principal
                );
            }
            match pack.node_config.public_tls.as_str() {
                "acme" => outln!("✔ Public TLS: automatic ACME (ensure 80/443 reachable)"),
                "frontend-proxy" => {
                    outln!("✔ Public TLS: frontend proxy (X-Forwarded-For enabled)");
                    xff_precheck(&pack)?;
                }
                "manual" => {
                    outln!("  note: manual public TLS — certificates are your responsibility");
                }
                _ => {}
            }
        }
        PackKind::Agent => {
            for service in &pack.node_config.services {
                outln!("✔ Service {} at {}", service.id, service.address);
            }
            if let Some(mesh) = &pack.node_config.mesh {
                outln!("  hub: {}", mesh.hub_endpoint);
                // Rules display from the AUTHORITATIVE policy face —
                // node.toml carries dial info only.
                for rule in pack
                    .policy
                    .mesh
                    .iter()
                    .filter(|s| s.source_agent == pack.metadata.node)
                {
                    outln!(
                        "✔ Mesh forward {} listening {} → agent {} at {}",
                        rule.name,
                        rule.listen,
                        rule.target_agent,
                        rule.remote_addr
                    );
                }
                for offer in pack
                    .policy
                    .mesh_egress
                    .iter()
                    .filter(|o| o.agent == pack.metadata.node)
                {
                    let authorization = offer
                        .target_cidr
                        .as_deref()
                        .or(offer.target_addr.as_deref())
                        .unwrap_or("");
                    outln!(
                        "✔ Mesh serve {} at {} (offered to peers)",
                        offer.name,
                        authorization
                    );
                }
            }
        }
        PackKind::Hub => {
            if let Some(listen) = &pack.node_config.listen {
                outln!("✔ Hub listening on {listen}");
            }
            // The tenant trust table: every workspace the hub admits.
            for name in pack.trust.metadata.issuers.keys() {
                if let Some(workspace) = name.strip_prefix("workspace/") {
                    outln!("✔ Admits workspace {workspace} (issuer-anchored)");
                }
            }
            outln!(
                "✔ Admission policy: {} signed mesh stream(s)",
                pack.policy.mesh.len()
            );
            let hub_renewal = pack.identities.get("hub").and_then(|m| m.values().next());
            if let Some(entry) = hub_renewal {
                outln!("✔ Renewal principal {}", entry.principal);
            }
        }
    }
    // The disk-swap reading rides every node check too (read-only; a ✔ on
    // Linux, a platform note elsewhere).
    stale_disk_section()?;
    outln!();
    outln!("All checks passed.");
    Ok(())
}

// ---------------------------------------------------------------------------
// Frontend-proxy live precheck: unmask a missing X-Forwarded-For before
// users meet an unexplained 502.
//
// Two probes from this machine:
// A. direct to the ingress's public listen WITHOUT X-Forwarded-For —
//    fail-closed enforcement must reject it (stream closed before any HTTP
//    status). Confirms the ambush is armed.
// B. through the local front proxy (127.0.0.1:443, real route SNI + Host) —
//    an HTTP response proves the proxy injects the header; nginx turns an
//    ingress-side rejection into its own 502, which is exactly the browser
//    symptom this check names.
// ---------------------------------------------------------------------------

#[derive(Debug)]
enum DirectOutcome {
    Refused,
    /// The stream closed before any HTTP status — fail-closed rejection.
    Denied,
    Answered(String),
    Timeout,
}

#[derive(Debug)]
enum ProxyOutcome {
    Refused,
    Answered {
        status: String,
        from_nginx: bool,
    },
    /// Something accepted the connection then closed it without an HTTP
    /// response — the fail-closed signature (browsers see a 502).
    UpstreamClosed,
    TlsFailed(String),
    Timeout,
}

fn xff_precheck(pack: &CredentialPack) -> interflow_core::error::Result<()> {
    let Some(listen) = pack.node_config.listen.clone() else {
        return Ok(());
    };
    let Some(host) = pack.policy.routes.first().map(|r| r.host.clone()) else {
        return Ok(());
    };
    outln!("  XFF precheck (frontend proxy):");
    // Probe A — only continue when fail-closed is confirmed armed, otherwise
    // probe B's failure could mean anything.
    let armed = match probe_direct_no_xff(&listen, &host) {
        DirectOutcome::Refused => {
            outln!("    · skipped: nothing listening on {listen} — start the ingress and re-run");
            return Ok(());
        }
        DirectOutcome::Denied => {
            outln!("    ✔ fail-closed armed: a direct no-header probe was rejected");
            true
        }
        DirectOutcome::Answered(status) => {
            outln!(
                "    note: a direct no-header probe got `{status}` — XFF enforcement looks \
                 inactive for this topology"
            );
            false
        }
        DirectOutcome::Timeout => {
            outln!("    note: direct probe timed out — inconclusive");
            false
        }
    };
    match probe_via_proxy(&host, 443) {
        ProxyOutcome::Refused => {
            outln!(
                "    · proxy probe skipped: nothing on 127.0.0.1:443 — wire nginx in when ready"
            );
        }
        ProxyOutcome::Answered { status, from_nginx } => {
            let via = if from_nginx { " (via nginx)" } else { "" };
            outln!("    ✔ proxy chain live{via}: `{status}` — X-Forwarded-For injected");
        }
        ProxyOutcome::UpstreamClosed => {
            if armed {
                outln!("    ✘ the proxy reached the ingress but the stream was closed:");
                outln!("      the fronting proxy does NOT inject X-Forwarded-For");
                outln!();
                outln!("      Fix (nginx):");
                outln!("        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;");
                outln!("      in the {host} server block — see the rendered");
                outln!("      nginx/http/interflow-vhost-*.conf from interflow-cli plan apply");
                return Err(interflow_core::error::InterflowError::config(
                    "fronting proxy does not inject X-Forwarded-For",
                ));
            }
            outln!("    note: proxy closed the stream without a response — inconclusive");
        }
        ProxyOutcome::TlsFailed(reason) => {
            outln!("    note: TLS to 127.0.0.1:443 failed ({reason}) — is the front live?");
        }
        ProxyOutcome::Timeout => {
            outln!("    note: proxy probe timed out — inconclusive");
        }
    }
    Ok(())
}

fn probe_direct_no_xff(listen: &str, host: &str) -> DirectOutcome {
    let Ok(addr) =
        interflow_cli::node_install::probe_address(listen).parse::<std::net::SocketAddr>()
    else {
        return DirectOutcome::Timeout;
    };
    let Ok(mut stream) = TcpStream::connect_timeout(&addr, Duration::from_secs(2)) else {
        return DirectOutcome::Refused;
    };
    let _ = stream.set_write_timeout(Some(Duration::from_secs(3)));
    let _ = stream.set_read_timeout(Some(Duration::from_secs(3)));
    let request = format!("GET / HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n");
    if stream.write_all(request.as_bytes()).is_err() {
        return DirectOutcome::Denied;
    }
    let mut buf = [0u8; 256];
    match stream.read(&mut buf) {
        Ok(0) => DirectOutcome::Denied,
        Ok(n) => DirectOutcome::Answered(
            String::from_utf8_lossy(&buf[..n])
                .lines()
                .next()
                .unwrap_or("")
                .to_owned(),
        ),
        Err(e)
            if matches!(
                e.kind(),
                std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
            ) =>
        {
            DirectOutcome::Timeout
        }
        Err(_) => DirectOutcome::Denied,
    }
}

fn probe_via_proxy(host: &str, port: u16) -> ProxyOutcome {
    let Ok(stream) = TcpStream::connect(("127.0.0.1", port)) else {
        return ProxyOutcome::Refused;
    };
    let _ = stream.set_write_timeout(Some(Duration::from_secs(3)));
    let _ = stream.set_read_timeout(Some(Duration::from_secs(3)));
    let Ok(name) = rustls::pki_types::ServerName::try_from(host.to_owned()) else {
        return ProxyOutcome::TlsFailed("invalid server name".to_owned());
    };
    let Ok(mut conn) =
        rustls::ClientConnection::new(std::sync::Arc::new(insecure_client_config()), name)
    else {
        return ProxyOutcome::TlsFailed("client setup".to_owned());
    };
    let mut stream = stream;
    let mut tls = rustls::Stream::new(&mut conn, &mut stream);
    let request = format!("GET / HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n");
    if tls.write_all(request.as_bytes()).is_err() {
        return ProxyOutcome::TlsFailed("handshake or write".to_owned());
    }
    let mut buf = vec![0u8; 2048];
    match tls.read(&mut buf) {
        Ok(0) => ProxyOutcome::UpstreamClosed,
        Ok(n) => {
            let head = String::from_utf8_lossy(&buf[..n]).to_string();
            let status = head.lines().next().unwrap_or("").to_owned();
            let from_nginx = head.to_ascii_lowercase().contains("server: nginx");
            // nginx's own 502 page means the upstream (ingress) closed
            // without a response — the missing-XFF signature.
            if from_nginx && status.contains(" 502 ") {
                ProxyOutcome::UpstreamClosed
            } else {
                ProxyOutcome::Answered { status, from_nginx }
            }
        }
        Err(e)
            if matches!(
                e.kind(),
                std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
            ) =>
        {
            ProxyOutcome::Timeout
        }
        Err(_) => ProxyOutcome::UpstreamClosed,
    }
}

/// A TLS client config that accepts any server certificate — the precheck
/// dials 127.0.0.1 with the route's name, so hostname validation would
/// always fail; the probe's verdict never depends on certificate identity.
fn insecure_client_config() -> rustls::ClientConfig {
    #[derive(Debug)]
    struct NoVerify;
    impl rustls::client::danger::ServerCertVerifier for NoVerify {
        fn verify_server_cert(
            &self,
            _end_entity: &rustls::pki_types::CertificateDer<'_>,
            _intermediates: &[rustls::pki_types::CertificateDer<'_>],
            _server_name: &rustls::pki_types::ServerName<'_>,
            _ocsp_response: &[u8],
            _now: rustls::pki_types::UnixTime,
        ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
            Ok(rustls::client::danger::ServerCertVerified::assertion())
        }
        fn verify_tls12_signature(
            &self,
            _message: &[u8],
            _cert: &rustls::pki_types::CertificateDer<'_>,
            _dss: &rustls::DigitallySignedStruct,
        ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
            Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
        }
        fn verify_tls13_signature(
            &self,
            _message: &[u8],
            _cert: &rustls::pki_types::CertificateDer<'_>,
            _dss: &rustls::DigitallySignedStruct,
        ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
            Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
        }
        fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
            use rustls::SignatureScheme::{
                ECDSA_NISTP256_SHA256, ECDSA_NISTP384_SHA384, ED25519, RSA_PKCS1_SHA256,
                RSA_PKCS1_SHA384, RSA_PKCS1_SHA512, RSA_PSS_SHA256, RSA_PSS_SHA384, RSA_PSS_SHA512,
            };
            vec![
                RSA_PKCS1_SHA256,
                RSA_PKCS1_SHA384,
                RSA_PKCS1_SHA512,
                ECDSA_NISTP256_SHA256,
                ECDSA_NISTP384_SHA384,
                ED25519,
                RSA_PSS_SHA256,
                RSA_PSS_SHA384,
                RSA_PSS_SHA512,
            ]
        }
    }
    rustls::ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(std::sync::Arc::new(NoVerify))
        .with_no_client_auth()
}

fn check_route(host: &str, pack_dir: &std::path::Path) -> interflow_core::error::Result<()> {
    let pack =
        CredentialPack::load_runtime(pack_dir).map_err(interflow_cli::runtime::pack_error)?;
    outln!("Route {host}");
    outln!();
    let Some(route) = pack
        .policy
        .routes
        .iter()
        .find(|r| r.host.eq_ignore_ascii_case(host))
    else {
        outln!(
            "✘ No route for {host} in the signed policy (generation {})",
            pack.policy.generation
        );
        outln!();
        outln!("Diagnosis: the ingress policy predates this hostname.");
        outln!(
            "Fix: add [[route]] to the manifest, then `interflow-cli plan apply` and restart the ingress."
        );
        return Err(interflow_core::error::InterflowError::config(
            "route not found",
        ));
    };
    outln!("✔ Route policy entry: {} → {}", route.host, route.service);
    let Some(service) = find_service(&pack.policy.services, &route.service) else {
        outln!("✘ Route references unknown service {}", route.service);
        outln!("Fix: declare [[agent.<node>.services]] and re-apply.");
        return Err(interflow_core::error::InterflowError::config(
            "unknown service",
        ));
    };
    // The signed policy carries the service id only; where the agent dials
    // is node-side. On the agent's own pack, report the node.toml default
    // and note that a local preference may override it; on an ingress pack
    // (the usual vantage point for route diagnosis) the address is simply
    // not this machine's to know.
    let declared = pack
        .node_config
        .services
        .iter()
        .find(|s| s.id == service.id);
    match declared {
        Some(s) => outln!(
            "✔ Service {} (declared by agent {}) — default address {} (a local \
             preference on the agent machine may override it)",
            service.id,
            service.agent,
            s.address
        ),
        None if pack.metadata.kind == interflow_identity::pack::PackKind::Agent => {
            outln!(
                "✘ Service {} is signed but missing from node.toml",
                service.id
            );
            outln!(
                "Fix: re-run `interflow-cli plan apply` — the pack's policy and node halves drifted."
            );
            return Err(interflow_core::error::InterflowError::config(
                "service missing from node.toml",
            ));
        }
        None => outln!(
            "✔ Service {} (declared by agent {}) — dial target resolved on the agent \
             machine (pack default or a local preference)",
            service.id,
            service.agent
        ),
    }
    let authorized = pack
        .policy
        .ingress_authorizations
        .iter()
        .any(|a| a.workspace == service.workspace);
    if !authorized {
        outln!(
            "✘ Ingress is not authorized for workspace {}",
            service.workspace
        );
        outln!("Fix: add the workspace to [ingress.<node>].workspaces and re-apply.");
        return Err(interflow_core::error::InterflowError::config(
            "workspace not authorized",
        ));
    }
    outln!(
        "✔ Ingress principal authorized for workspace {}",
        service.workspace
    );
    if host.parse::<std::net::IpAddr>().is_err() {
        outln!("  DNS check: point {host} at this ingress's public address");
    }
    if pack.node_config.public_tls == "acme" {
        outln!("  ACME: the ingress terminates HTTPS itself");
        outln!(
            "    - ports 80 (HTTP-01 + redirect) and 443 (TLS-ALPN-01 + traffic) must reach it directly — no front proxy in front"
        );
        outln!(
            "    - certificates/issues renew automatically; cache lives under state/acme in the pack directory"
        );
        if let Some(email) = &pack.node_config.public_tls_email {
            outln!("    - account contact: {email}");
        }
        if pack.node_config.public_tls_directory != interflow_util::LETS_ENCRYPT_PRODUCTION {
            outln!(
                "    - directory override: {}",
                pack.node_config.public_tls_directory
            );
        }
    }
    outln!();
    outln!("Route checks passed.");
    Ok(())
}

fn check_trust(pack_dir: &std::path::Path) -> interflow_core::error::Result<()> {
    let pack = CredentialPack::load(pack_dir).map_err(interflow_cli::runtime::pack_error)?;
    outln!("Trust Bundle (realm {})", pack.trust.metadata.realm);
    outln!();
    pack.trust
        .verify_fingerprints()
        .map_err(interflow_cli::runtime::pack_error)?;
    for (name, fingerprint) in &pack.trust.metadata.issuers {
        outln!("✔ {name}: {fingerprint}");
    }
    outln!(
        "  policy key: {}",
        &pack.trust.metadata.policy_key[..16.min(pack.trust.metadata.policy_key.len())]
    );
    outln!(
        "  generation: {} (digest {})",
        pack.trust.metadata.generation,
        pack.trust
            .digest()
            .map_err(interflow_cli::runtime::pack_error)?
    );
    // CRL presence (issuer-store produced CRLs land in the pack's trust dir).
    for entry in std::fs::read_dir(pack_dir.join("trust"))
        .into_iter()
        .flatten()
    {
        let Ok(entry) = entry else { continue };
        if entry.path().extension().is_some_and(|e| e == "pem") {
            let name = entry.file_name().into_string().unwrap_or_default();
            if name.contains("crl") {
                outln!("✔ CRL present: {name}");
            }
        }
    }
    outln!();
    outln!("Trust checks passed.");
    Ok(())
}

pub fn identity_inspect(
    pack_dir: &std::path::Path,
    expert: bool,
) -> interflow_core::error::Result<()> {
    let pack = CredentialPack::load(pack_dir).map_err(interflow_cli::runtime::pack_error)?;
    let summary = pack.summary();
    outln!("Identity: {}", product_path(&pack, &summary.identity));
    outln!("Kind: {}", summary.kind.as_str());
    if let Some(workspace) = &summary.workspace {
        outln!("Workspace: {workspace}");
    }
    outln!("Node: {}", summary.node);
    outln!("Realm: {}", summary.realm);
    outln!("Credential generation: {}", summary.generation);
    outln!("Bootstrap expires: {}", summary.expires);
    let active = interflow_identity::credentials::ActiveCredentialSet::load_or_bootstrap(&pack)
        .map_err(interflow_cli::runtime::pack_error)?;
    let expiry = active
        .earliest_expiry()
        .map_err(interflow_cli::runtime::pack_error)?;
    let health = interflow_identity::expiry::leaf_phase_from_ttl(
        expiry.unix_timestamp(),
        pack.metadata.leaf_ttl_secs,
        interflow_identity::expiry::now_unix(),
    );
    outln!(
        "Active credentials expire: {} ({} left, {})",
        expiry,
        interflow_identity::expiry::format_remaining(health.remaining_secs),
        health.phase.as_str()
    );
    match pack.metadata.registrar_endpoint.as_deref() {
        Some(endpoint) => outln!("Registrar: {endpoint}"),
        None => outln!("Registrar: none (offline tier — rotate with `interflow-cli rotate`)"),
    }
    outln!("Pack digest: {}", summary.pack_digest);
    if expert {
        outln!("Embedded Trust / Policy generation: {}", summary.generation);
        outln!();
        for buckets in pack.identities.values() {
            for entry in buckets.values() {
                let der = interflow_identity::pem_certs(entry.cert_pem.as_bytes())
                    .map_err(interflow_cli::runtime::pack_error)?
                    .into_iter()
                    .next();
                if let Some(der) = der {
                    outln!(
                        "SPKI fingerprint: sha256:{} ({})",
                        hex::encode(Sha256::digest(&der)),
                        entry.principal
                    );
                }
                outln!("Certificate chain (leaf first):");
                for (i, der) in interflow_identity::pem_certs(entry.cert_pem.as_bytes())
                    .map_err(interflow_cli::runtime::pack_error)?
                    .into_iter()
                    .enumerate()
                {
                    outln!("  #{i}: {} bytes (DER)", der.len());
                }
            }
        }
        outln!("Policy signature: {} bytes", pack.policy_signature.len());
    }
    Ok(())
}

/// `spiffe://promptcn/main/agent/desktop` → `promptcn/main/agent/desktop`.
fn product_path(_pack: &CredentialPack, uri: &str) -> String {
    uri.strip_prefix("spiffe://").unwrap_or(uri).to_owned()
}

fn find_service<'a>(services: &'a [PolicyService], reference: &str) -> Option<&'a PolicyService> {
    services
        .iter()
        .find(|s| format!("{}/{}/{}", s.workspace, s.agent, s.id) == reference)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn direct_probe_classifies_denial_vs_answer() {
        // A server that closes on connect = fail-closed denial.
        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
        let addr = listener.local_addr().expect("addr");
        let server = std::thread::spawn(move || {
            if let Ok((socket, _)) = listener.accept() {
                drop(socket);
            }
        });
        assert!(matches!(
            probe_direct_no_xff(&addr.to_string(), "x.example.com"),
            DirectOutcome::Denied
        ));
        server.join().expect("server thread");

        // A server that answers HTTP = answered.
        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
        let addr = listener.local_addr().expect("addr");
        let server = std::thread::spawn(move || {
            if let Ok((mut socket, _)) = listener.accept() {
                let mut buf = [0u8; 512];
                let _ = std::io::Read::read(&mut socket, &mut buf);
                let response = "HTTP/1.1 503 Service Unavailable\r\nContent-Length: 0\r\n\r\n";
                let _ = std::io::Write::write_all(&mut socket, response.as_bytes());
            }
        });
        let outcome = probe_direct_no_xff(&addr.to_string(), "x.example.com");
        assert!(
            matches!(&outcome, DirectOutcome::Answered(status) if status.starts_with("HTTP/1.1 503")),
            "expected an HTTP answer, got {outcome:?}"
        );
        server.join().expect("server thread");
    }

    #[test]
    fn proxy_probe_reports_refused_when_nothing_listens() {
        // Grab a free port by binding and dropping.
        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
        let port = listener.local_addr().expect("addr").port();
        drop(listener);
        assert!(matches!(
            probe_via_proxy("x.example.com", port),
            ProxyOutcome::Refused
        ));
    }
}
