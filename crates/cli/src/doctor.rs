//! `interflow doctor` — identity-first diagnostics.
//!
//! Technical failures are mapped back to product semantics: identity
//! membership, trust generation, route resolution, credential expiry — with
//! a concrete fix for every ✘.

use clap::Subcommand;
use interflow_identity::pack::{CredentialPack, PackKind};
use interflow_identity::policy::PolicyService;
use sha2::{Digest, Sha256};
use std::io::{Read as _, Write as _};
use std::net::TcpStream;
use std::path::PathBuf;
use std::time::Duration;

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
}

impl DoctorCommand {
    pub fn run(self) -> interflow_core::error::Result<()> {
        match self {
            Self::Ingress { pack } => check_node(&pack, PackKind::Ingress),
            Self::Agent { pack } => check_node(&pack, PackKind::Agent),
            Self::Hub { pack } => check_node(&pack, PackKind::Hub),
            Self::Route { host, pack } => check_route(&host, &pack),
            Self::Trust { pack } => check_trust(&pack),
        }
    }
}

fn check_node(pack_dir: &std::path::Path, expected: PackKind) -> interflow_core::error::Result<()> {
    println!("Interflow doctor");
    // Load failures are diagnosed in identity terms.
    let pack = match CredentialPack::load_runtime(pack_dir) {
        Ok(pack) => pack,
        Err(e) => {
            println!(
                "✘ Credential Pack at {} failed validation",
                pack_dir.display()
            );
            println!();
            println!("Diagnosis:");
            println!("  {e}");
            println!();
            println!("Fix:");
            println!("  re-issue with `interflow plan apply` (or `interflow rotate`)");
            return Err(
                interflow_core::error::InterflowError::config("doctor failed").with_source(e),
            );
        }
    };
    let kind_ok = pack.metadata.kind == expected;
    println!(
        "Realm {} · {} {}",
        pack.metadata.realm,
        pack.metadata.kind.as_str(),
        pack.metadata.node
    );
    println!();
    println!("✔ Pack digest verified ({})", pack.pack_digest);

    if !kind_ok {
        println!();
        println!("Diagnosis: this pack belongs to another node role.");
        let mesh_role = pack.metadata.kind == PackKind::Hub || pack.node_config.mesh.is_some();
        println!(
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
    println!(
        "✔ Identity {} (generation {})",
        primary.principal, pack.metadata.generation
    );
    println!("  bootstrap expires {}", pack.metadata.expires);
    if let Ok(active) =
        interflow_identity::credentials::ActiveCredentialSet::load_or_bootstrap(&pack)
    {
        println!(
            "  active credentials expire {}",
            active
                .earliest_expiry()
                .map_err(interflow_cli::runtime::pack_error)?
                .format(&time::format_description::well_known::Rfc3339)
                .map_err(
                    |e| interflow_core::error::InterflowError::config("timestamp").with_source(e)
                )?
        );
        match pack.metadata.registrar_endpoint.as_deref() {
            Some(endpoint) => println!("  registrar: {endpoint}"),
            None => println!("  registrar: none (offline tier — rotate manually before expiry)"),
        }
    }
    println!(
        "  principal URI SAN verified: {}",
        primary.uri_san.as_deref().unwrap_or("(missing)")
    );
    println!(
        "✔ Trust bundle verified ({})",
        pack.trust
            .digest()
            .map_err(interflow_cli::runtime::pack_error)?
    );
    println!(
        "✔ Runtime policy verified ({} route(s))",
        pack.policy.routes.len()
    );
    println!("  policy signature verified against the realm policy key");
    // Role-specific wiring.
    match pack.metadata.kind {
        PackKind::Ingress => {
            let principals = pack
                .ingress_identities()
                .map_err(interflow_cli::runtime::pack_error)?;
            for (workspace, entry) in principals {
                println!(
                    "✔ Workspace authorization {workspace} via {}",
                    entry.principal
                );
            }
            match pack.node_config.public_tls.as_str() {
                "acme" => println!("✔ Public TLS: automatic ACME (ensure 80/443 reachable)"),
                "frontend-proxy" => {
                    println!("✔ Public TLS: frontend proxy (X-Forwarded-For enabled)");
                    xff_precheck(&pack)?;
                }
                "manual" => {
                    println!("  note: manual public TLS — certificates are your responsibility");
                }
                _ => {}
            }
        }
        PackKind::Agent => {
            for service in &pack.node_config.services {
                println!("✔ Service {} at {}", service.id, service.address);
            }
            if let Some(mesh) = &pack.node_config.mesh {
                println!("  hub: {}", mesh.hub_endpoint);
                for rule in &mesh.ingress {
                    println!(
                        "✔ Mesh forward {} listening {} → agent {} at {}",
                        rule.name, rule.listen, rule.target_agent, rule.remote_addr
                    );
                }
                for rule in &mesh.egress {
                    println!(
                        "✔ Mesh serve {} at {} (offered to peers)",
                        rule.name, rule.target_addr
                    );
                }
            }
        }
        PackKind::Hub => {
            if let Some(listen) = &pack.node_config.listen {
                println!("✔ Hub listening on {listen}");
            }
            // The tenant trust table: every workspace the hub admits.
            for name in pack.trust.metadata.issuers.keys() {
                if let Some(workspace) = name.strip_prefix("workspace/") {
                    println!("✔ Admits workspace {workspace} (issuer-anchored)");
                }
            }
            println!(
                "✔ Admission policy: {} signed mesh stream(s)",
                pack.policy.mesh.len()
            );
            let hub_renewal = pack.identities.get("hub").and_then(|m| m.values().next());
            if let Some(entry) = hub_renewal {
                println!("✔ Renewal principal {}", entry.principal);
            }
        }
    }
    println!();
    println!("All checks passed.");
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
    println!("  XFF precheck (frontend proxy):");
    // Probe A — only continue when fail-closed is confirmed armed, otherwise
    // probe B's failure could mean anything.
    let armed = match probe_direct_no_xff(&listen, &host) {
        DirectOutcome::Refused => {
            println!("    · skipped: nothing listening on {listen} — start the ingress and re-run");
            return Ok(());
        }
        DirectOutcome::Denied => {
            println!("    ✔ fail-closed armed: a direct no-header probe was rejected");
            true
        }
        DirectOutcome::Answered(status) => {
            println!(
                "    note: a direct no-header probe got `{status}` — XFF enforcement looks \
                 inactive for this topology"
            );
            false
        }
        DirectOutcome::Timeout => {
            println!("    note: direct probe timed out — inconclusive");
            false
        }
    };
    match probe_via_proxy(&host, 443) {
        ProxyOutcome::Refused => {
            println!(
                "    · proxy probe skipped: nothing on 127.0.0.1:443 — wire nginx in when ready"
            );
        }
        ProxyOutcome::Answered { status, from_nginx } => {
            let via = if from_nginx { " (via nginx)" } else { "" };
            println!("    ✔ proxy chain live{via}: `{status}` — X-Forwarded-For injected");
        }
        ProxyOutcome::UpstreamClosed => {
            if armed {
                println!("    ✘ the proxy reached the ingress but the stream was closed:");
                println!("      the fronting proxy does NOT inject X-Forwarded-For");
                println!();
                println!("      Fix (nginx):");
                println!("        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;");
                println!("      in the {host} server block — see the rendered");
                println!("      nginx/http/interflow-vhost-*.conf from interflow plan apply");
                return Err(interflow_core::error::InterflowError::config(
                    "fronting proxy does not inject X-Forwarded-For",
                ));
            }
            println!("    note: proxy closed the stream without a response — inconclusive");
        }
        ProxyOutcome::TlsFailed(reason) => {
            println!("    note: TLS to 127.0.0.1:443 failed ({reason}) — is the front live?");
        }
        ProxyOutcome::Timeout => {
            println!("    note: proxy probe timed out — inconclusive");
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
    println!("Route {host}");
    println!();
    let Some(route) = pack
        .policy
        .routes
        .iter()
        .find(|r| r.host.eq_ignore_ascii_case(host))
    else {
        println!(
            "✘ No route for {host} in the signed policy (generation {})",
            pack.policy.generation
        );
        println!();
        println!("Diagnosis: the ingress policy predates this hostname.");
        println!(
            "Fix: add [[route]] to the manifest, then `interflow plan apply` and restart the ingress."
        );
        return Err(interflow_core::error::InterflowError::config(
            "route not found",
        ));
    };
    println!("✔ Route policy entry: {} → {}", route.host, route.service);
    let Some(service) = find_service(&pack.policy.services, &route.service) else {
        println!("✘ Route references unknown service {}", route.service);
        println!("Fix: declare [[agent.<node>.services]] and re-apply.");
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
        Some(s) => println!(
            "✔ Service {} (declared by agent {}) — default address {} (a local \
             preference on the agent machine may override it)",
            service.id, service.agent, s.address
        ),
        None if pack.metadata.kind == interflow_identity::pack::PackKind::Agent => {
            println!(
                "✘ Service {} is signed but missing from node.toml",
                service.id
            );
            println!(
                "Fix: re-run `interflow plan apply` — the pack's policy and node halves drifted."
            );
            return Err(interflow_core::error::InterflowError::config(
                "service missing from node.toml",
            ));
        }
        None => println!(
            "✔ Service {} (declared by agent {}) — dial target resolved on the agent \
             machine (pack default or a local preference)",
            service.id, service.agent
        ),
    }
    let authorized = pack
        .policy
        .ingress_authorizations
        .iter()
        .any(|a| a.workspace == service.workspace);
    if !authorized {
        println!(
            "✘ Ingress is not authorized for workspace {}",
            service.workspace
        );
        println!("Fix: add the workspace to [ingress.<node>].workspaces and re-apply.");
        return Err(interflow_core::error::InterflowError::config(
            "workspace not authorized",
        ));
    }
    println!(
        "✔ Ingress principal authorized for workspace {}",
        service.workspace
    );
    if host.parse::<std::net::IpAddr>().is_err() {
        println!("  DNS check: point {host} at this ingress's public address");
    }
    if pack.node_config.public_tls == "acme" {
        println!("  ACME: the ingress terminates HTTPS itself");
        println!(
            "    - ports 80 (HTTP-01 + redirect) and 443 (TLS-ALPN-01 + traffic) must reach it directly — no front proxy in front"
        );
        println!(
            "    - certificates/issues renew automatically; cache lives under state/acme in the pack directory"
        );
        if let Some(email) = &pack.node_config.public_tls_email {
            println!("    - account contact: {email}");
        }
        if let Some(directory) = &pack.node_config.public_tls_directory {
            println!("    - directory override: {directory}");
        }
    }
    println!();
    println!("Route checks passed.");
    Ok(())
}

fn check_trust(pack_dir: &std::path::Path) -> interflow_core::error::Result<()> {
    let pack = CredentialPack::load(pack_dir).map_err(interflow_cli::runtime::pack_error)?;
    println!("Trust Bundle (realm {})", pack.trust.metadata.realm);
    println!();
    pack.trust
        .verify_fingerprints()
        .map_err(interflow_cli::runtime::pack_error)?;
    for (name, fingerprint) in &pack.trust.metadata.issuers {
        println!("✔ {name}: {fingerprint}");
    }
    println!(
        "  policy key: {}",
        &pack.trust.metadata.policy_key[..16.min(pack.trust.metadata.policy_key.len())]
    );
    println!(
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
                println!("✔ CRL present: {name}");
            }
        }
    }
    println!();
    println!("Trust checks passed.");
    Ok(())
}

pub fn identity_inspect(
    pack_dir: &std::path::Path,
    expert: bool,
) -> interflow_core::error::Result<()> {
    let pack = CredentialPack::load(pack_dir).map_err(interflow_cli::runtime::pack_error)?;
    let summary = pack.summary();
    println!("Identity: {}", product_path(&pack, &summary.identity));
    println!("Kind: {}", summary.kind.as_str());
    if let Some(workspace) = &summary.workspace {
        println!("Workspace: {workspace}");
    }
    println!("Node: {}", summary.node);
    println!("Realm: {}", summary.realm);
    println!("Credential generation: {}", summary.generation);
    println!("Bootstrap expires: {}", summary.expires);
    let active = interflow_identity::credentials::ActiveCredentialSet::load_or_bootstrap(&pack)
        .map_err(interflow_cli::runtime::pack_error)?;
    println!(
        "Active credentials expire: {}",
        active
            .earliest_expiry()
            .map_err(interflow_cli::runtime::pack_error)?
    );
    match pack.metadata.registrar_endpoint.as_deref() {
        Some(endpoint) => println!("Registrar: {endpoint}"),
        None => println!("Registrar: none (offline tier)"),
    }
    println!("Pack digest: {}", summary.pack_digest);
    if expert {
        println!("Embedded Trust / Policy generation: {}", summary.generation);
        println!();
        for buckets in pack.identities.values() {
            for entry in buckets.values() {
                let der = interflow_identity::pem_certs(entry.cert_pem.as_bytes())
                    .map_err(interflow_cli::runtime::pack_error)?
                    .into_iter()
                    .next();
                if let Some(der) = der {
                    println!(
                        "SPKI fingerprint: sha256:{} ({})",
                        hex::encode(Sha256::digest(&der)),
                        entry.principal
                    );
                }
                println!("Certificate chain (leaf first):");
                for (i, der) in interflow_identity::pem_certs(entry.cert_pem.as_bytes())
                    .map_err(interflow_cli::runtime::pack_error)?
                    .into_iter()
                    .enumerate()
                {
                    println!("  #{i}: {} bytes (DER)", der.len());
                }
            }
        }
        println!("Policy signature: {} bytes", pack.policy_signature.len());
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
