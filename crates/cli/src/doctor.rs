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
use std::collections::BTreeMap;
use std::path::PathBuf;

use crate::doctor_link::LinkArgs;

#[derive(Subcommand)]
pub enum DoctorCommand {
    /// Diagnose one node's credential pack (identity, trust, policy, role).
    Ingress {
        #[arg(long)]
        pack: PathBuf,
        /// nginx public-certificate directory — the rendered vhosts
        /// reference `/etc/nginx/certs/<host>.{crt,key}` by default;
        /// override it when the deployed layout differs.
        #[arg(long = "certs-dir")]
        certs_dir: Option<PathBuf>,
        /// The deployed nginx interflow fragment root (its `http/` and
        /// `stream/` subdirectories) — reconciled against the current
        /// render set: superseded leftovers and conflicting server names
        /// are named before include order decides which vintage serves.
        #[arg(long = "nginx-dir")]
        nginx_dir: Option<PathBuf>,
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
    /// Diagnose the MACHINE's interflow footprint: every interflow unit and
    /// pack directory accounted for by an installed set and the signed
    /// fleet roster — retirement/rename leftovers are named with their
    /// cleanup instruction before they race for ports at the next boot.
    /// Read-only; `node retire` is the cleanup.
    Host {
        /// Install root (system paths; tests override).
        #[arg(long, default_value = interflow_cli::render::DEFAULT_INSTALL_ROOT)]
        root: PathBuf,
    },
    /// Diagnose one route: policy resolution + target existence + DNS hint
    /// and (frontend-proxy) the host's public certificate material.
    Route {
        host: String,
        #[arg(long)]
        pack: PathBuf,
        /// nginx public-certificate directory — the rendered vhosts
        /// reference `/etc/nginx/certs/<host>.{crt,key}` by default;
        /// override it when the deployed layout differs.
        #[arg(long = "certs-dir")]
        certs_dir: Option<PathBuf>,
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
    /// One agent's event biography from the hub's audit ledger — the
    /// incident timeline as one query (registered / evicted / policy
    /// pulls / pauses / maintenance…), newest first.
    Biography {
        /// The agent's qualified id (`workspace/node`).
        agent: String,
        /// The lookback window ("30m" / "12h" / "2d"; default 2d).
        #[arg(long)]
        since: Option<String>,
        /// Manifest describing the deployment (names the hub endpoint).
        #[arg(long, default_value = "interflow.toml")]
        manifest: PathBuf,
        /// Issuer store directory (mints the control credential).
        #[arg(long, default_value = "issuer")]
        issuer: PathBuf,
    },
}

impl DoctorCommand {
    pub fn run(self) -> interflow_core::error::Result<()> {
        match self {
            Self::Ingress {
                pack,
                certs_dir,
                nginx_dir,
            } => check_node(
                &pack,
                PackKind::Ingress,
                &certs_dir.unwrap_or_else(|| PathBuf::from(DEFAULT_CERTS_DIR)),
                &nginx_dir.unwrap_or_else(|| PathBuf::from(DEFAULT_NGINX_DIR)),
            ),
            Self::Agent { pack } => check_node(
                &pack,
                PackKind::Agent,
                &PathBuf::from(DEFAULT_CERTS_DIR),
                &PathBuf::from(DEFAULT_NGINX_DIR),
            ),
            Self::Hub { pack } => check_node(
                &pack,
                PackKind::Hub,
                &PathBuf::from(DEFAULT_CERTS_DIR),
                &PathBuf::from(DEFAULT_NGINX_DIR),
            ),
            Self::Host { root } => check_host(&root),
            Self::Route {
                host,
                pack,
                certs_dir,
            } => check_route(
                &host,
                &pack,
                &certs_dir.unwrap_or_else(|| PathBuf::from(DEFAULT_CERTS_DIR)),
            ),
            Self::Trust { pack } => check_trust(&pack),
            Self::Issuer { dir, identity } => check_issuer_backup(&dir, identity.as_deref()),
            Self::Stale => check_stale_exec(),
            Self::Link { args } => args.run(),
            Self::Biography {
                agent,
                since,
                manifest,
                issuer,
            } => crate::doctor_biography::run(&agent, since.as_deref(), &manifest, &issuer),
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

fn check_node(
    pack_dir: &std::path::Path,
    expected: PackKind,
    certs_dir: &std::path::Path,
    nginx_dir: &std::path::Path,
) -> interflow_core::error::Result<()> {
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
                    // Local reads before the dial: a failed XFF probe must
                    // never mask a certificate-material problem — and the
                    // fragment-set reconciliation must fire before anything
                    // trusts a superseded vintage to be the current one.
                    cert_material_all_routes(&pack, certs_dir)?;
                    nginx_fragment_reconciliation(&pack, pack_dir.parent(), nginx_dir)?;
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

/// `doctor host` — the machine-level reconciliation face: units and packs
/// against the installed set and the signed fleet roster. The same sweep
/// `node install` runs at its close; here it is the check itself.
#[allow(clippy::unnecessary_wraps)] // subcommand dispatch shape
fn check_host(root: &std::path::Path) -> interflow_core::error::Result<()> {
    let system_target = root == std::path::Path::new(interflow_cli::render::DEFAULT_INSTALL_ROOT);
    let unit_dir = if system_target {
        PathBuf::from("/etc/systemd/system")
    } else {
        root.join("systemd")
    };
    outln!(
        "Host reconciliation — interflow units and packs under {}:",
        root.display()
    );
    let findings = interflow_cli::host_reconcile::scan(&unit_dir, &root.join("packs"));
    if findings.is_empty() {
        outln!("  ✔ no orphans: every interflow unit and pack on this host is accounted for");
        return Ok(());
    }
    for finding in &findings {
        outln!("  {}", finding.describe());
    }
    outln!();
    outln!("  Cleanup: interflow-cli node retire --pack <root>/packs/<kind>-<node> — archives the");
    outln!("  pack (never deletes) and removes the unit; nothing is removed without it.");
    Ok(())
}

// ---------------------------------------------------------------------------
// Frontend-proxy live precheck: unmask a missing X-Forwarded-For before
// users meet an unexplained 502.
// ((internal design notes) P0-2;
//  (internal design notes);
//  (internal design notes))
//
// Two probes from this machine:
// A. direct to the ingress's public listen WITHOUT X-Forwarded-For —
//    fail-closed enforcement must reject it (stream closed before any HTTP
//    status). Confirms the ambush is armed.
// B. through the local front proxy (127.0.0.1:443, real route SNI + Host),
//    once per route in the signed policy. A 502 here is a THREE-cause
//    signal — a stripped header makes fail-closed reject every route, a
//    dead backing service behind a correctly injected one 502s the same,
//    and so does an OFFLINE agent (no registration leg: whatever its
//    backends do, the ingress has nothing to dial through) — so any route
//    that answers proves the header, and only an all-closed sweep may
//    raise the flag. Before it does, the ingress's OWN live registry is
//    consulted (`GET /agents` on its local control endpoint): which legs
//    exist is a fact the edge already knows — no probe can tell, and the
//    journal can only guess.
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

/// One probed route: its public host, the backing service the ingress dials
/// for it, the agent that service lives on (as the signed policy resolves
/// it — the registration face's key), and what the front proxy did with the
/// probe.
struct RouteProbe {
    host: String,
    service: String,
    agent: Option<String>,
    outcome: ProxyOutcome,
}

/// One route-agent's live registration reading, taken straight from the
/// ingress's own registry (`GET /agents` on its local control endpoint) —
/// a fact the edge already knows, never something to infer from probes.
#[derive(Debug, Clone, PartialEq, Eq)]
enum AgentLeg {
    /// Registered and reachable — the leg is up; a dead backend is then
    /// the route's own story.
    Online,
    /// Registered but past reconnect grace — eviction pending; dials
    /// through it fail all the same.
    RegisteredNotReachable,
    /// The registry holds no such agent — the leg is gone (authoritative:
    /// the ingress itself says so).
    NotRegistered,
    /// The face could not be read (control endpoint did not answer, no
    /// principal material) — the reason, for the note line. Never an
    /// accusation: without a reading the two-cause narrative stands.
    Unknown(String),
}

impl AgentLeg {
    /// The offline readings — the leg cannot carry any route, so its
    /// routes' backend checks are meaningless until it reconnects.
    const fn offline(&self) -> bool {
        matches!(self, Self::NotRegistered | Self::RegisteredNotReachable)
    }
}

/// The multi-route precheck verdict. A 502 through the proxy is a
/// multi-cause signal — a missing X-Forwarded-For makes fail-closed reject
/// every route, but a dead backing service behind an injected header (or an
/// offline agent: no registration leg to dial through) produces the same
/// nginx 502 — so only a route that ANSWERED can prove the header, and an
/// all-closed sweep may never assert a single cause. The agent-offline axis
/// is settled at narration time by the live registration face, not by this
/// classification.
#[derive(Debug)]
enum XffVerdict {
    /// At least one route answered through the chain — with fail-closed
    /// armed, that is impossible without the injected header.
    Proven { host: String, status: String },
    /// Every probed route closed without an HTTP response — the dual-cause
    /// form (armed ⇒ red with both causes; otherwise inconclusive).
    AllClosed,
    /// No route answered, but not every route closed either (timeouts, TLS
    /// failures) — nothing may be asserted.
    Inconclusive,
}

fn xff_classify(probes: &[RouteProbe]) -> XffVerdict {
    if let Some(probe) = probes
        .iter()
        .find(|p| matches!(p.outcome, ProxyOutcome::Answered { .. }))
    {
        if let ProxyOutcome::Answered { status, .. } = &probe.outcome {
            return XffVerdict::Proven {
                host: probe.host.clone(),
                status: status.clone(),
            };
        }
        unreachable!("the find above guarantees the Answered shape");
    }
    if !probes.is_empty()
        && probes
            .iter()
            .all(|p| matches!(p.outcome, ProxyOutcome::UpstreamClosed))
    {
        return XffVerdict::AllClosed;
    }
    XffVerdict::Inconclusive
}

/// Whether this probe's agent carries an offline reading — the leg is
/// gone (or as good as), so the route's backend check is meaningless until
/// it reconnects.
fn probe_agent_offline(probe: &RouteProbe, face: &BTreeMap<String, AgentLeg>) -> bool {
    probe
        .agent
        .as_deref()
        .is_some_and(|agent| face.get(agent).is_some_and(AgentLeg::offline))
}

/// The all-closed narrative: every cause side by side with its
/// discriminating action, and the nginx directive framed as the hypothesis
/// it is — never as the verdict. With no offline reading the form is the
/// byte-stable two-cause one (the regression anchor); when the live
/// registry says a route's agent is gone, the agent cause joins the list,
/// the registry's word is prepended, that agent's routes lose their
/// backend-check instruction (meaningless until the leg returns), and the
/// nginx hypothesis stays gated behind every leg being back.
fn closed_sweep_lines(probes: &[RouteProbe], face: &BTreeMap<String, AgentLeg>) -> Vec<String> {
    let any_offline = probes.iter().any(|p| probe_agent_offline(p, face));
    let mut lines = vec![format!(
        "✘ every proxy probe closed without an HTTP response (browsers see 502) — {} possible \
         causes:",
        if any_offline { "three" } else { "two" }
    )];
    lines.push(
        "  · the fronting proxy strips X-Forwarded-For (fail-closed then rejects every \
         route), or"
            .to_owned(),
    );
    if any_offline {
        lines.push(
            "  · a route's agent is not registered with this ingress (the leg is gone — its \
             routes 502 whatever their backends), or"
                .to_owned(),
        );
    }
    lines.push(
        "  · every probed route's backing service is down (the ingress dials a dead local \
         service)"
            .to_owned(),
    );
    if any_offline {
        lines.push(
            "  This ingress's own registry (GET /agents on the local control endpoint) \
             already knows:"
                .to_owned(),
        );
        for (agent, leg) in face {
            match leg {
                AgentLeg::NotRegistered => lines.push(format!(
                    "    ✘ {agent} is not registered with this ingress — start the node first; \
                     the per-route service checks for its routes are meaningless until it \
                     reconnects"
                )),
                AgentLeg::RegisteredNotReachable => lines.push(format!(
                    "    ✘ {agent} is registered but not reachable (past reconnect grace — \
                     eviction pending); treat its routes like offline until it settles"
                )),
                AgentLeg::Online => {}
                AgentLeg::Unknown(reason) => lines.push(format!(
                    "    · {agent}: agent state unknown ({reason}) — no accusation without a \
                     reading"
                )),
            }
        }
    }
    lines.push("  Probed routes — discriminate here before editing any config:".to_owned());
    for probe in probes {
        let action = if probe_agent_offline(probe, face) {
            "agent offline above — re-check after it reconnects".to_owned()
        } else {
            format!(
                "doctor route {} — or start the service on its agent machine",
                probe.host
            )
        };
        lines.push(format!(
            "    · {} → {}  ({action})",
            probe.host, probe.service
        ));
    }
    let first = probes.first().map_or("route", |p| p.host.as_str());
    let gate = if any_offline {
        "only when every agent is registered and every service is confirmed running"
    } else {
        "only when every service is confirmed running"
    };
    lines.push(format!(
        "  A route that answered above would have PROVEN the header injected; {gate} is the \
         proxy the cause — then (nginx):"
    ));
    lines.push("    proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;".to_owned());
    lines.push(format!(
        "  in the {first} server block — see nginx/http/interflow-vhost-*.conf from plan \
         apply/stage."
    ));
    lines
}

/// Marks every agent in the face un-readable with `reason` — the shared
/// degradation for everything before the per-workspace queries.
fn mark_all_unknown(face: &mut BTreeMap<String, AgentLeg>, reason: &str) {
    for leg in face.values_mut() {
        *leg = AgentLeg::Unknown(reason.to_owned());
    }
}

/// The all-`Unknown` face for the probes' agents — the never-fail floor of
/// the blocking wrapper.
fn unknown_face(probes: &[RouteProbe]) -> BTreeMap<String, AgentLeg> {
    probes
        .iter()
        .filter_map(|p| p.agent.clone())
        .map(|agent| {
            (
                agent,
                AgentLeg::Unknown("the registration face could not run".to_owned()),
            )
        })
        .collect()
}

/// The live registration face: resolves every probed route through the
/// signed policy's typed service mapping (the same resolution the runtime
/// dials by), then asks the ingress's own control endpoint — once per
/// workspace — which of those agents it currently holds (`GET /agents`,
/// pinned to the control cert the pack itself carries: the edge self-dial
/// trust model). Every failure folds into [`AgentLeg::Unknown`]: the face
/// refines the all-closed narrative, it never blocks or fails the
/// precheck.
async fn registration_face(
    pack: &CredentialPack,
    probes: &[RouteProbe],
) -> BTreeMap<String, AgentLeg> {
    // workspace → the qualified agent ids wanted from its roster
    let mut wanted: BTreeMap<String, Vec<String>> = BTreeMap::new();
    let mut face: BTreeMap<String, AgentLeg> = BTreeMap::new();
    for probe in probes {
        let Some(service) = pack.policy.find_service(&probe.service) else {
            continue; // an unresolvable reference names no agent
        };
        let qualified = format!("{}/{}", service.workspace, service.agent);
        if !face.contains_key(&qualified) {
            face.insert(qualified.clone(), AgentLeg::Unknown(String::new()));
            wanted
                .entry(service.workspace.clone())
                .or_default()
                .push(qualified);
        }
    }
    if wanted.is_empty() {
        return face;
    }
    let Some(control_listen) = pack.node_config.control_listen.clone() else {
        mark_all_unknown(&mut face, "the pack carries no control_listen address");
        return face;
    };
    // Read-only load: a diagnostic never bootstraps credentials.
    let Ok(Some(active)) =
        interflow_identity::credentials::ActiveCredentialSet::load_existing(pack)
    else {
        mark_all_unknown(&mut face, "no active credential set in the pack");
        return face;
    };
    let Ok((control_cert, _)) = active.material_paths("control-endpoint") else {
        mark_all_unknown(&mut face, "the pack carries no control-endpoint material");
        return face;
    };
    let fingerprint =
        match interflow_core::tls::sha256_of_pem_cert(&control_cert, "control endpoint") {
            Ok(fingerprint) => fingerprint,
            Err(e) => {
                mark_all_unknown(&mut face, &e.to_string());
                return face;
            }
        };
    for (workspace, agents) in &wanted {
        let roster = async {
            let (cert, key) = active
                .material_paths(&format!("ingress-{workspace}"))
                .map_err(|e| format!("no ingress-{workspace} principal in the pack: {e}"))?;
            interflow_mesh::hub::http::query_agents(
                &control_listen,
                interflow_mesh::hub::policy::ServerTrust::Pinned(&fingerprint),
                &cert,
                &key,
            )
            .await
            .map_err(|e| e.to_string())
        }
        .await;
        match roster {
            Ok(entries) => {
                for qualified in agents {
                    let leg = match entries.iter().find(|entry| entry.agent == *qualified) {
                        Some(entry) if entry.online => AgentLeg::Online,
                        Some(_) => AgentLeg::RegisteredNotReachable,
                        None => AgentLeg::NotRegistered,
                    };
                    face.insert(qualified.clone(), leg);
                }
            }
            Err(reason) => {
                for qualified in agents {
                    face.insert(qualified.clone(), AgentLeg::Unknown(reason.clone()));
                }
            }
        }
    }
    face
}

/// Drives [`registration_face`] on a dedicated thread with its own
/// current-thread runtime — the `ControlCredential::call` discipline, so
/// the sync doctor consults the registry without nesting runtimes. Any
/// failure (including a panicked thread) degrades to all-`Unknown`, never
/// fails the precheck.
fn registration_face_blocking(
    pack: &CredentialPack,
    probes: &[RouteProbe],
) -> BTreeMap<String, AgentLeg> {
    std::thread::scope(|scope| {
        scope
            .spawn(|| {
                let Ok(rt) = tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                else {
                    return unknown_face(probes);
                };
                rt.block_on(registration_face(pack, probes))
            })
            .join()
            .unwrap_or_else(|_| unknown_face(probes))
    })
}

fn xff_precheck(pack: &CredentialPack) -> interflow_core::error::Result<()> {
    let Some(listen) = pack.node_config.listen.clone() else {
        return Ok(());
    };
    if pack.policy.routes.is_empty() {
        return Ok(());
    }
    outln!("  XFF precheck (frontend proxy):");
    // Probe A — only meaningful when fail-closed is confirmed armed, otherwise
    // probe B's failure could mean anything. The route it dials is incidental
    // (any host hits the same enforcement); the first route is as good as any.
    let probe_host = pack.policy.routes[0].host.clone();
    let armed = match probe_direct_no_xff(&listen, &probe_host) {
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
    // Probe B — EVERY route, one cheap local TLS probe each. A blind
    // first-route-only probe turns a down dev-server on route 1 into a
    // "fix your nginx" instruction about a correct config; any answered
    // route settles the question the other way. Each probe carries its
    // route's agent (the policy's own typed resolution) so the all-closed
    // narrative can consult the registration face per agent.
    let mut probes = Vec::new();
    for route in &pack.policy.routes {
        let outcome = probe_via_proxy(&route.host, 443);
        if matches!(outcome, ProxyOutcome::Refused) {
            outln!(
                "    · proxy probe skipped: nothing on 127.0.0.1:443 — wire nginx in when ready"
            );
            return Ok(());
        }
        probes.push(RouteProbe {
            host: route.host.clone(),
            service: route.service.clone(),
            agent: pack
                .policy
                .find_service(&route.service)
                .map(|s| format!("{}/{}", s.workspace, s.agent)),
            outcome,
        });
    }
    match xff_classify(&probes) {
        XffVerdict::Proven { host, status } => {
            let from_nginx = probes.iter().any(|p| {
                matches!(&p.outcome, ProxyOutcome::Answered { from_nginx: true, .. }
                    if p.host == host)
            });
            let via = if from_nginx { " (via nginx)" } else { "" };
            let more = if probes.len() > 1 {
                format!(
                    " (proven by {host} of {} routes — the others may be down without \
                     implicating the proxy)",
                    probes.len()
                )
            } else {
                String::new()
            };
            outln!("    ✔ proxy chain live{via}: `{status}` — X-Forwarded-For injected{more}");
        }
        XffVerdict::AllClosed => {
            if armed {
                // Before either remaining cause is asserted, ask the
                // ingress itself which legs exist — its live registry is
                // the authoritative word, and an offline agent makes every
                // per-route backend check beneath it meaningless.
                let face = registration_face_blocking(pack, &probes);
                outln!();
                for line in closed_sweep_lines(&probes, &face) {
                    outln!("    {line}");
                }
                let offline: Vec<&str> = face
                    .iter()
                    .filter(|(_, leg)| leg.offline())
                    .map(|(agent, _)| agent.as_str())
                    .collect();
                if offline.is_empty() {
                    return Err(interflow_core::error::InterflowError::config(
                        "every proxy probe closed without a response — either the fronting \
                         proxy strips X-Forwarded-For or every probed route's backing service \
                         is down",
                    ));
                }
                return Err(interflow_core::error::InterflowError::config(format!(
                    "every proxy probe closed without a response — agent(s) {} not registered \
                     with this ingress — start the node(s) first; otherwise either the \
                     fronting proxy strips X-Forwarded-For or every probed route's backing \
                     service is down",
                    offline.join(", ")
                )));
            }
            outln!(
                "    note: every proxy probe closed without a response — inconclusive \
                 (fail-closed not confirmed armed)"
            );
        }
        XffVerdict::Inconclusive => {
            for probe in &probes {
                match &probe.outcome {
                    ProxyOutcome::TlsFailed(reason) => outln!(
                        "    note: {} — TLS to 127.0.0.1:443 failed ({reason}) — is the front \
                         live?",
                        probe.host
                    ),
                    ProxyOutcome::Timeout => {
                        outln!(
                            "    note: {} — proxy probe timed out — inconclusive",
                            probe.host
                        );
                    }
                    _ => {}
                }
            }
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
    let Some(mut stream) = crate::probe::connect(addr, crate::probe::LOCAL) else {
        return DirectOutcome::Refused;
    };
    match crate::probe::get(&mut stream, host, "/", 256) {
        // The status line is all this face reads.
        crate::probe::ProbeRead::Answered(chunk) => {
            DirectOutcome::Answered(crate::probe::status_line(&chunk))
        }
        crate::probe::ProbeRead::WriteFailed
        | crate::probe::ProbeRead::Closed
        | crate::probe::ProbeRead::IoFailed(_) => DirectOutcome::Denied,
        crate::probe::ProbeRead::Timeout => DirectOutcome::Timeout,
    }
}

fn probe_via_proxy(host: &str, port: u16) -> ProxyOutcome {
    let Some(stream) = crate::probe::connect(
        std::net::SocketAddr::from(([127, 0, 0, 1], port)),
        crate::probe::LOCAL,
    ) else {
        return ProxyOutcome::Refused;
    };
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
    // Read wide: this face sniffs `Server: nginx` beyond the status line.
    match crate::probe::get(&mut tls, host, "/", 2048) {
        crate::probe::ProbeRead::Answered(head) => {
            let status = crate::probe::status_line(&head);
            let from_nginx = head.to_ascii_lowercase().contains("server: nginx");
            // nginx's own 502 page means the upstream (ingress) closed
            // without a response — the missing-XFF signature.
            if from_nginx && status.contains(" 502 ") {
                ProxyOutcome::UpstreamClosed
            } else {
                ProxyOutcome::Answered { status, from_nginx }
            }
        }
        crate::probe::ProbeRead::Closed | crate::probe::ProbeRead::IoFailed(_) => {
            ProxyOutcome::UpstreamClosed
        }
        crate::probe::ProbeRead::Timeout => ProxyOutcome::Timeout,
        crate::probe::ProbeRead::WriteFailed => {
            ProxyOutcome::TlsFailed("handshake or write".to_owned())
        }
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

fn check_route(
    host: &str,
    pack_dir: &std::path::Path,
    certs_dir: &std::path::Path,
) -> interflow_core::error::Result<()> {
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
    if pack.node_config.public_tls == "frontend-proxy" {
        // The route's public TLS terminates on this machine's nginx — the
        // certificate material is route trust material (a non-frontend
        // pack carries an empty mode here and stays silent).
        let deployed = if pack.metadata.kind == PackKind::Ingress {
            deployed_vhost_cert_paths(&pack.metadata.node)
        } else {
            None
        };
        let resolved = resolve_cert_paths(host, deployed.as_deref(), certs_dir);
        if resolved.diverges {
            outln!(
                "ℹ the deployed vhost fragment loads {} + {}, not the {} convention — the \
                 fragment was hand-edited (or --certs-dir points elsewhere); checking what \
                 nginx actually loads",
                resolved.cert.display(),
                resolved.key.display(),
                certs_dir.display()
            );
        }
        let now = interflow_identity::expiry::now_unix();
        let ok = cert_material_section(host, &resolved, "", now);
        if !ok {
            return Err(interflow_core::error::InterflowError::config(
                "certificate material problem",
            ));
        }
    }
    outln!();
    outln!("Route checks passed.");
    Ok(())
}

// ---------------------------------------------------------------------------
// Public certificate material — the frontend-proxy trust face
//
// Every [[route]] host terminates public TLS on nginx with a certificate
// the operator places by hand (certbot + install). Obtaining, placing and
// reconciling that material lived entirely outside the tool; here it
// becomes one read-only section: presence, SAN coverage, cert/key pairing,
// validity — plus the certbot renewal-coverage note. Local reads only, no
// dial; doctor diagnoses, it never renews or re-places.
// ---------------------------------------------------------------------------

/// The certificate directory the rendered vhosts reference — the
/// `--certs-dir` default.
const DEFAULT_CERTS_DIR: &str = "/etc/nginx/certs";
/// Where the deployed vhost fragments live (deployment.md's copy target):
/// nginx's own record of which certificate files it loads.
const DEPLOYED_VHOST_DIR: &str = "/etc/nginx/interflow/http";
/// certbot's renewal-config directory — the renew-timer coverage check.
const LETSENCRYPT_RENEWAL_DIR: &str = "/etc/letsencrypt/renewal";
/// The public-certificate expiry warn line, in days: Let's Encrypt
/// certificates live 90 days and renew around the 30-day mark — two weeks
/// out is the last comfortable re-placement window.
const CERT_RENEW_WARN_DAYS: i64 = 14;

/// One certificate file pair, resolved to what nginx actually loads.
struct ResolvedCertPaths {
    cert: std::path::PathBuf,
    key: std::path::PathBuf,
    /// The deployed fragment references paths that differ from the
    /// convention under `--certs-dir` — the reconciliation ℹ fires.
    diverges: bool,
}

/// The certificate paths each `server` block of one deployed vhost
/// fragment references, keyed by its `server_name` — nginx's own truth,
/// line-scanned (our rendered shape; hand-edits stay parseable as long as
/// the `ssl_certificate` directive lines survive). `None` when the
/// fragment is not on this machine.
fn deployed_vhost_cert_paths(
    node: &str,
) -> Option<Vec<(String, std::path::PathBuf, std::path::PathBuf)>> {
    vhost_cert_paths_in(std::path::Path::new(DEPLOYED_VHOST_DIR), node)
}

/// [`deployed_vhost_cert_paths`] with the fragment directory injected —
/// the unit-testable core.
fn vhost_cert_paths_in(
    vhost_dir: &std::path::Path,
    node: &str,
) -> Option<Vec<(String, std::path::PathBuf, std::path::PathBuf)>> {
    let text =
        std::fs::read_to_string(vhost_dir.join(format!("interflow-vhost-{node}.conf"))).ok()?;
    let mut out = Vec::new();
    let mut server_name: Option<String> = None;
    let mut cert: Option<std::path::PathBuf> = None;
    let mut key: Option<std::path::PathBuf> = None;
    let mut flush = |server_name: &mut Option<String>,
                     cert: &mut Option<std::path::PathBuf>,
                     key: &mut Option<std::path::PathBuf>| {
        if let (Some(name), Some(cert), Some(key)) = (server_name.take(), cert.take(), key.take())
            && !name.is_empty()
        {
            out.push((name, cert, key));
        }
    };
    for line in text.lines() {
        let line = line.trim();
        if line == "server {" {
            flush(&mut server_name, &mut cert, &mut key);
            continue;
        }
        let Some((directive, value)) = nginx_directive(line) else {
            continue;
        };
        match directive {
            "server_name" => {
                // The rendered shape carries exactly one name per block.
                server_name = value.split_whitespace().next().map(str::to_owned);
            }
            "ssl_certificate" => cert = Some(std::path::PathBuf::from(value)),
            "ssl_certificate_key" => key = Some(std::path::PathBuf::from(value)),
            _ => {}
        }
    }
    flush(&mut server_name, &mut cert, &mut key);
    Some(out)
}

/// One nginx directive line, split: `ssl_certificate  /path/to.crt;` →
/// `("ssl_certificate", "/path/to/crt")`. Exact-name match on the first
/// token (so `ssl_certificate_key` never masquerades as
/// `ssl_certificate`).
fn nginx_directive(line: &str) -> Option<(&str, &str)> {
    let line = line.strip_suffix(';')?;
    let (name, value) = line.split_once(char::is_whitespace)?;
    Some((name, value.trim()))
}

// ---------------------------------------------------------------------------
// nginx fragment-set reconciliation — the deployed directories against the
// current render set.
//
// The correct form is a SET (shared trio + this host's ingress vhosts); the
// copy-in workflow is additive, so a rename leaves the old vhost behind and
// which vintage serves a name is decided by include glob order — an
// accident. Everything here names facts and leaves removal to the operator.
// ---------------------------------------------------------------------------

/// The deployed nginx interflow root — the `--nginx-dir` default; its
/// `http/` and `stream/` subdirectories are deployment.md's copy targets.
const DEFAULT_NGINX_DIR: &str = "/etc/nginx/interflow";

/// One `server` block found in a deployed http fragment: the file it lives
/// in, its listen address, and every name it declares.
struct DeployedServer {
    file: String,
    listen: String,
    names: Vec<String>,
}

/// Line-scans the deployed `interflow-*.conf` files under one http fragment
/// directory for `server` blocks — the same rendered-shape tolerance as
/// [`vhost_cert_paths_in`] (hand-edits stay readable while the directive
/// lines survive).
fn deployed_http_servers(http_dir: &std::path::Path) -> Vec<DeployedServer> {
    let mut out = Vec::new();
    let Ok(entries) = std::fs::read_dir(http_dir) else {
        return out;
    };
    // Deterministic order — verdict lines join these file names, and a
    // read_dir order must never decide the spelling of a finding.
    let mut files: Vec<std::path::PathBuf> = entries
        .flatten()
        .map(|entry| entry.path())
        .filter(|path| {
            path.file_name()
                .and_then(|n| n.to_str())
                .is_some_and(|name| {
                    name.starts_with("interflow-")
                        && std::path::Path::new(name).extension()
                            == Some(std::ffi::OsStr::new("conf"))
                })
        })
        .collect();
    files.sort();
    for path in files {
        let Some(file) = path.file_name().and_then(|n| n.to_str()).map(str::to_owned) else {
            continue;
        };
        let Ok(text) = std::fs::read_to_string(&path) else {
            continue;
        };
        let mut listen: Option<String> = None;
        let mut names: Vec<String> = Vec::new();
        let mut flush = |listen: &mut Option<String>, names: &mut Vec<String>| {
            if let Some(listen) = listen.take()
                && !names.is_empty()
            {
                out.push(DeployedServer {
                    file: file.clone(),
                    listen,
                    names: std::mem::take(names),
                });
            }
        };
        for line in text.lines() {
            let line = line.trim();
            if line == "server {" {
                flush(&mut listen, &mut names);
                continue;
            }
            let Some((directive, value)) = nginx_directive(line) else {
                continue;
            };
            match directive {
                "listen" => listen = value.split_whitespace().next().map(str::to_owned),
                "server_name" => {
                    names.extend(value.split_whitespace().map(str::to_owned));
                }
                _ => {}
            }
        }
        flush(&mut listen, &mut names);
    }
    out
}

/// The deployed `interflow-*.conf` file names under one fragment directory.
fn deployed_conf_names(dir: &std::path::Path) -> Vec<String> {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return Vec::new();
    };
    let mut names: Vec<String> = entries
        .flatten()
        .filter_map(|entry| entry.file_name().to_str().map(str::to_owned))
        .filter(|name| {
            name.starts_with("interflow-")
                && std::path::Path::new(name).extension() == Some(std::ffi::OsStr::new("conf"))
        })
        .collect();
    names.sort();
    names
}

/// One finding of the fragment-set reconciliation, in emission order.
/// Warning-level findings are advisory lines; conflicts are the red line.
#[derive(Debug, PartialEq, Eq)]
enum FragmentFinding {
    /// Deployed under this directory but not in the render set's slice for
    /// it — a superseded leftover, or a render-set file misplaced here
    /// from its own directory.
    SupersededFile {
        dir: interflow_cli::render::FragmentDir,
        file: String,
    },
    /// In the render set's slice for this directory but not deployed.
    MissingFile {
        dir: interflow_cli::render::FragmentDir,
        file: String,
    },
    /// The same `listen` + `server_name` in two deployed files.
    ConflictingServerName {
        listen: String,
        name: String,
        files: Vec<String>,
    },
    /// A signed route no deployed fragment serves.
    RouteWithoutServer { host: String },
    /// A deployed `server_name` no signed route declares.
    ServerWithoutRoute { name: String },
}

impl FragmentFinding {
    /// Conflicts are the red line: nginx warns and ignores the later
    /// definition, so a silently-not-serving block is already loaded.
    const fn is_red(&self) -> bool {
        matches!(self, Self::ConflictingServerName { .. })
    }
}

/// The fragment-set reconciliation's whole verdict: nothing deployed yet
/// (a note, not findings), or the findings against the deployed set —
/// empty means in form. Printing and the red error live at the edge,
/// never in the core.
enum FragmentReconciliation {
    NothingDeployed,
    Findings(Vec<FragmentFinding>),
}

/// The fragment-set reconciliation. `packs_root` (the pack directory's
/// parent) is the host's own record of which ingress nodes are installed
/// here — the vhost set a render would produce for THIS machine. Conflicts
/// (the same `listen` + `server_name` in two files) are red: nginx ignores
/// the later file's block, so one of them is silently not serving.
fn nginx_fragment_reconciliation(
    pack: &CredentialPack,
    packs_root: Option<&std::path::Path>,
    nginx_dir: &std::path::Path,
) -> interflow_core::error::Result<()> {
    outln!("  nginx fragment set:");
    let findings = match fragment_set_reconciliation(
        &pack.metadata.node,
        &pack.policy.routes,
        packs_root,
        nginx_dir,
    ) {
        FragmentReconciliation::NothingDeployed => {
            outln!(
                "    · nothing deployed under {} — wire the fragments in when ready",
                nginx_dir.display()
            );
            return Ok(());
        }
        FragmentReconciliation::Findings(findings) => findings,
    };
    for line in fragment_findings_lines(&findings, nginx_dir) {
        outln!("{line}");
    }
    if findings.iter().any(FragmentFinding::is_red) {
        return Err(interflow_core::error::InterflowError::config(
            "conflicting server names across deployed nginx fragments — a superseded \
             fragment is still loaded",
        ));
    }
    Ok(())
}

/// [`nginx_fragment_reconciliation`]'s injectable core — everything but the
/// pack handle: this node, the signed routes, the host's packs root, the
/// deployed fragment root. Computes the verdict without printing: the unit
/// matrix asserts on the findings, the wrapper renders the lines. Each
/// deployed directory reconciles against ITS OWN slice of the render set —
/// the single source types every fragment with its directory, so a file is
/// never checked against a directory it does not belong to.
/// (internal design notes)
fn fragment_set_reconciliation(
    node: &str,
    routes: &[interflow_identity::policy::PolicyRoute],
    packs_root: Option<&std::path::Path>,
    nginx_dir: &std::path::Path,
) -> FragmentReconciliation {
    let dir_paths =
        interflow_cli::render::FragmentDir::ALL.map(|dir| (dir, nginx_dir.join(dir.as_str())));
    if dir_paths.iter().all(|(_, path)| !path.is_dir()) {
        return FragmentReconciliation::NothingDeployed;
    }
    let mut ingress_nodes = vec![node.to_owned()];
    if let Some(root) = packs_root {
        for node in interflow_cli::host_reconcile::installed_ingress_nodes(root) {
            if !ingress_nodes.contains(&node) {
                ingress_nodes.push(node);
            }
        }
    }
    let mut expected: std::collections::BTreeMap<
        interflow_cli::render::FragmentDir,
        std::collections::BTreeSet<String>,
    > = std::collections::BTreeMap::new();
    for rel in interflow_cli::render::nginx_fragment_rel_paths(&ingress_nodes) {
        expected.entry(rel.dir).or_default().insert(rel.file);
    }

    let mut findings = Vec::new();
    for (dir, dir_path) in &dir_paths {
        let deployed = deployed_conf_names(dir_path);
        if deployed.is_empty() && !dir_path.is_dir() {
            continue;
        }
        let empty = std::collections::BTreeSet::new();
        let expected_here = expected.get(dir).unwrap_or(&empty);
        for file in &deployed {
            if !expected_here.contains(file) {
                findings.push(FragmentFinding::SupersededFile {
                    dir: *dir,
                    file: file.clone(),
                });
            }
        }
        for file in expected_here {
            if !deployed.contains(file) {
                findings.push(FragmentFinding::MissingFile {
                    dir: *dir,
                    file: file.clone(),
                });
            }
        }
    }

    // Conflicting server names (§3c): nginx warns and ignores the later
    // definition — exactly the silent-vintage-wins accident this section
    // exists to surface as a red, readable verdict.
    let http_dir = nginx_dir.join(interflow_cli::render::FragmentDir::Http.as_str());
    let servers = deployed_http_servers(&http_dir);
    let mut by_listen_name: std::collections::BTreeMap<(String, String), Vec<String>> =
        std::collections::BTreeMap::new();
    for server in &servers {
        for name in &server.names {
            by_listen_name
                .entry((server.listen.clone(), name.clone()))
                .or_default()
                .push(server.file.clone());
        }
    }
    for ((listen, name), files) in &by_listen_name {
        if files.len() > 1 {
            findings.push(FragmentFinding::ConflictingServerName {
                listen: listen.clone(),
                name: name.clone(),
                files: files.clone(),
            });
        }
    }
    // Semantic drift the file-name set cannot see: deployed names no signed
    // route declares, and signed routes no deployed fragment serves.
    let declared: std::collections::BTreeSet<&str> = by_listen_name
        .keys()
        .map(|(_, name)| name.as_str())
        .collect();
    for route in routes {
        if !declared.contains(route.host.as_str()) {
            findings.push(FragmentFinding::RouteWithoutServer {
                host: route.host.clone(),
            });
        }
    }
    let signed: std::collections::BTreeSet<&str> =
        routes.iter().map(|route| route.host.as_str()).collect();
    for name in declared {
        if !signed.contains(name) {
            findings.push(FragmentFinding::ServerWithoutRoute {
                name: name.to_owned(),
            });
        }
    }
    FragmentReconciliation::Findings(findings)
}

/// The readable verdict lines for one reconciliation's findings — a pure
/// function of the findings (the `closed_sweep_lines` discipline), so the
/// message surface is unit-testable without capturing stdout. The texts
/// are the operator-facing contract; keep them byte-stable.
fn fragment_findings_lines(
    findings: &[FragmentFinding],
    nginx_dir: &std::path::Path,
) -> Vec<String> {
    findings
        .iter()
        .map(|finding| match finding {
            FragmentFinding::SupersededFile { dir, file } => format!(
                "    ⚠ superseded fragment {dir}/{file} is deployed but not in the \
                 current render set — remove it; its server names race the current set \
                 on include order"
            ),
            FragmentFinding::MissingFile { dir, file } => format!(
                "    ⚠ expected fragment nginx/{dir}/{file} is not deployed under {} — \
                 copy the current render in",
                nginx_dir.display()
            ),
            FragmentFinding::ConflictingServerName {
                listen,
                name,
                files,
            } => format!(
                "    ✘ conflicting server name \"{name}\" on {listen}: defined in both \
                 {} — nginx ignores the later one; one of these files is superseded",
                files.join(" and ")
            ),
            FragmentFinding::RouteWithoutServer { host } => format!(
                "    ⚠ route {host} has no server_name in any deployed interflow \
                 fragment — the current render set is not fully deployed"
            ),
            FragmentFinding::ServerWithoutRoute { name } => format!(
                "    ⚠ a deployed fragment serves \"{name}\", which no signed route \
                 declares — superseded route in a superseded (or hand-edited) fragment"
            ),
        })
        .collect()
}

/// Where the certificate files for `host` live: the deployed fragment's
/// own paths when it names this host (a divergence from the convention is
/// flagged), the rendered convention otherwise.
fn resolve_cert_paths(
    host: &str,
    deployed: Option<&[(String, std::path::PathBuf, std::path::PathBuf)]>,
    certs_dir: &std::path::Path,
) -> ResolvedCertPaths {
    let conventional = |certs_dir: &std::path::Path| ResolvedCertPaths {
        cert: certs_dir.join(format!("{host}.crt")),
        key: certs_dir.join(format!("{host}.key")),
        diverges: false,
    };
    let Some(entry) = deployed.and_then(|blocks| {
        blocks
            .iter()
            .find(|(name, _, _)| name.eq_ignore_ascii_case(host))
    }) else {
        return conventional(certs_dir);
    };
    let convention = conventional(certs_dir);
    ResolvedCertPaths {
        cert: entry.1.clone(),
        key: entry.2.clone(),
        diverges: entry.1 != convention.cert || entry.2 != convention.key,
    }
}

/// One host's certificate material verdict — the pure logic over the
/// facts, boundary-testable; the wording lives in
/// [`report_cert_material`].
#[derive(Debug, PartialEq, Eq)]
enum CertMaterialVerdict {
    /// Covered, paired and valid — days remaining until notAfter.
    Green(i64),
    /// Valid but inside the renewal warn window.
    Warn(i64),
    /// Past notAfter — days since it lapsed.
    Expired(i64),
    /// notBefore lies in the future.
    NotYetValid,
    /// The .crt and/or .key never landed on the convention path.
    Missing { cert: bool, key: bool },
    /// The file(s) exist but do not parse; the message names why.
    Unparseable(String),
    /// The certificate's SAN set does not cover the host — the names it
    /// actually covers, for the verdict to show.
    SanMismatches(Vec<String>),
    /// The .crt and .key do not form a pair (two issuances' files).
    PairMismatch,
}

fn classify_cert_material(
    host: &str,
    cert_path: &std::path::Path,
    key_path: &std::path::Path,
    now_unix: i64,
) -> CertMaterialVerdict {
    let (cert_present, key_present) = (cert_path.is_file(), key_path.is_file());
    if !cert_present || !key_present {
        return CertMaterialVerdict::Missing {
            cert: cert_present,
            key: key_present,
        };
    }
    let material = match interflow_certs::inspect_public_pair(cert_path, key_path) {
        Ok(material) => material,
        Err(e) => return CertMaterialVerdict::Unparseable(e.to_string()),
    };
    if !interflow_certs::san_set_covers(&material.sans, host) {
        let mut names: Vec<String> = material
            .sans
            .iter()
            .map(std::string::ToString::to_string)
            .collect();
        names.sort();
        return CertMaterialVerdict::SanMismatches(names);
    }
    if !material.pair_matches {
        return CertMaterialVerdict::PairMismatch;
    }
    if material.not_before_unix > now_unix {
        return CertMaterialVerdict::NotYetValid;
    }
    let remaining = material.not_after_unix - now_unix;
    if remaining <= 0 {
        return CertMaterialVerdict::Expired(-remaining / 86_400);
    }
    let days = remaining / 86_400;
    if days <= CERT_RENEW_WARN_DAYS {
        CertMaterialVerdict::Warn(days)
    } else {
        CertMaterialVerdict::Green(days)
    }
}

/// Reports one verdict in doctor's voice. Returns false only for a ✘ —
/// ⚠ (the renewal window) and · notes never fail a check.
fn report_cert_material(
    host: &str,
    verdict: &CertMaterialVerdict,
    resolved: &ResolvedCertPaths,
    indent: &str,
) -> bool {
    let sub = format!("{indent}  ");
    match verdict {
        CertMaterialVerdict::Green(days) => {
            outln!(
                "{indent}✔ certificate material for {host} — SAN covers, pair matches, valid ({days} days remain)"
            );
            true
        }
        CertMaterialVerdict::Warn(days) => {
            outln!(
                "{indent}⚠ certificate material for {host} expires in {days} day(s) — inside the renewal window"
            );
            outln!(
                "{sub}Fix: renew and re-place it (certbot renew, then the install -m644/-m600 pair), then reload nginx"
            );
            true
        }
        CertMaterialVerdict::Expired(days) => {
            outln!(
                "{indent}✘ certificate material for {host} EXPIRED {days} day(s) ago — nginx serves handshake failures, not the site"
            );
            outln!(
                "{sub}Fix: sudo certbot certonly --nginx -d {host}, then sudo install -m644 /etc/letsencrypt/live/{host}/fullchain.pem {} && sudo install -m600 /etc/letsencrypt/live/{host}/privkey.pem {} && sudo nginx -t && sudo systemctl reload nginx",
                resolved.cert.display(),
                resolved.key.display()
            );
            false
        }
        CertMaterialVerdict::NotYetValid => {
            outln!(
                "{indent}✘ certificate material for {host} is not valid yet (notBefore in the future) — a clock skew or a misplaced future issuance"
            );
            outln!(
                "{sub}Fix: check the machine clock (timedatectl), or re-place the current certificate pair"
            );
            false
        }
        CertMaterialVerdict::Missing { cert, key } => {
            let missing = if !cert && !key {
                format!(
                    "neither {} nor {} exists",
                    resolved.cert.display(),
                    resolved.key.display()
                )
            } else if !cert {
                format!("{} is missing", resolved.cert.display())
            } else {
                format!("{} is missing", resolved.key.display())
            };
            outln!("{indent}✘ certificate material for {host} is incomplete — {missing}");
            outln!(
                "{sub}Diagnosis: the vhost terminates TLS with these files; certbot obtained (or can obtain) a certificate, but the placement step never ran — or ran halfway."
            );
            outln!(
                "{sub}Fix: sudo certbot certonly --nginx -d {host}, then sudo install -m644 /etc/letsencrypt/live/{host}/fullchain.pem {} && sudo install -m600 /etc/letsencrypt/live/{host}/privkey.pem {} && sudo nginx -t && sudo systemctl reload nginx",
                resolved.cert.display(),
                resolved.key.display()
            );
            false
        }
        CertMaterialVerdict::Unparseable(why) => {
            outln!("{indent}✘ certificate material for {host} does not parse — {why}");
            outln!(
                "{sub}Fix: re-obtain the pair (sudo certbot certonly --nginx -d {host}) and re-place both files"
            );
            false
        }
        CertMaterialVerdict::SanMismatches(names) => {
            outln!(
                "{indent}✘ the certificate at {} does not cover {host} — its SANs are [{}]",
                resolved.cert.display(),
                names.join(", ")
            );
            outln!(
                "{sub}Diagnosis: the certificate was issued for other names; clients fail the handshake while the server stays silent."
            );
            outln!(
                "{sub}Fix: sudo certbot certonly --nginx -d {host} and re-place the pair, or correct [[route]].host"
            );
            false
        }
        CertMaterialVerdict::PairMismatch => {
            outln!(
                "{indent}✘ {} and {} do not form a pair (public keys differ) — two issuances' files met on disk",
                resolved.cert.display(),
                resolved.key.display()
            );
            outln!(
                "{sub}Fix: re-place both files from the SAME issuance (/etc/letsencrypt/live/{host}/fullchain.pem + privkey.pem), then reload nginx"
            );
            false
        }
    }
}

/// The certbot reconciliation note: when a renewal config directory exists
/// on this machine but holds no entry for the host, the renewal timer does
/// not cover it — a · note, never a failure (non-certbot deployments stay
/// silent: no directory, no claim).
fn certbot_renewal_note(host: &str, indent: &str) {
    let renewal_dir = std::path::Path::new(LETSENCRYPT_RENEWAL_DIR);
    certbot_renewal_note_in(host, renewal_dir, indent);
}

/// [`certbot_renewal_note`] with the directory injected — the unit-testable
/// core.
fn certbot_renewal_note_in(host: &str, renewal_dir: &std::path::Path, indent: &str) {
    if renewal_dir.is_dir() && !renewal_dir.join(format!("{host}.conf")).is_file() {
        outln!(
            "{indent}· no certbot renewal config for {host} — the renewal timer does not cover this host; renew and re-place by hand, or issue it under certbot"
        );
    }
}

/// One host's full certificate material section: classify, report, note.
fn cert_material_section(
    host: &str,
    resolved: &ResolvedCertPaths,
    indent: &str,
    now_unix: i64,
) -> bool {
    let verdict = classify_cert_material(host, &resolved.cert, &resolved.key, now_unix);
    let ok = report_cert_material(host, &verdict, resolved, indent);
    certbot_renewal_note(host, indent);
    ok
}

/// Every route the ingress terminates, each with its certificate material
/// — every ingress's vhost serves the full route list, so this is the
/// machine's whole public hostname surface. Local reads; called before
/// the XFF dial so a probe failure cannot mask material problems.
fn cert_material_all_routes(
    pack: &CredentialPack,
    certs_dir: &std::path::Path,
) -> interflow_core::error::Result<()> {
    let deployed = deployed_vhost_cert_paths(&pack.metadata.node);
    let now = interflow_identity::expiry::now_unix();
    outln!("  Certificate material (frontend proxy):");
    let mut ok = true;
    for route in &pack.policy.routes {
        let resolved = resolve_cert_paths(&route.host, deployed.as_deref(), certs_dir);
        if resolved.diverges {
            outln!(
                "    ℹ the deployed vhost fragment loads {} + {}, not the {} convention — checking what nginx actually loads",
                resolved.cert.display(),
                resolved.key.display(),
                certs_dir.display()
            );
        }
        ok &= cert_material_section(&route.host, &resolved, "    ", now);
    }
    if ok {
        Ok(())
    } else {
        Err(interflow_core::error::InterflowError::config(
            "certificate material problem",
        ))
    }
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
    use interflow_cli::render::FragmentDir;

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

    // -----------------------------------------------------------------------
    // Certificate material — the verdict matrix and the path reconciliation
    // -----------------------------------------------------------------------

    use interflow_certs::material::LoadedCa;

    /// Issues a cert/key pair with an exact validity window (half-day
    /// margins keep the day-count boundaries locked regardless of the
    /// seconds the issuance itself takes).
    fn issue_pair(
        san: &str,
        not_before: time::OffsetDateTime,
        not_after: time::OffsetDateTime,
    ) -> (String, String) {
        let ca = LoadedCa::generate(
            "doctor-test",
            interflow_certs::Validity::from_now(interflow_certs::CA_VALIDITY_DAYS),
        )
        .expect("test CA");
        let leaf = ca
            .build_server_cert(
                &[interflow_certs::SanName::parse(san).expect("san")],
                interflow_certs::Validity {
                    not_before,
                    not_after,
                },
            )
            .expect("test leaf");
        (leaf.cert_pem, leaf.key_pem)
    }

    fn write_pair(dir: &std::path::Path, host: &str, cert: &str, key: &str) {
        std::fs::write(dir.join(format!("{host}.crt")), cert).expect("write crt");
        std::fs::write(dir.join(format!("{host}.key")), key).expect("write key");
    }

    fn at(base: i64, offset_secs: i64) -> time::OffsetDateTime {
        time::OffsetDateTime::from_unix_timestamp(base + offset_secs).expect("timestamp")
    }

    /// The verdict matrix: green/warn/expired at the day boundaries, the
    /// not-yet-valid window, missing halves, SAN mismatch, pairing, and
    /// unparseable bytes.
    #[test]
    fn cert_verdict_matrix() {
        let dir = tempfile::tempdir().expect("tempdir");
        let now = interflow_identity::expiry::now_unix();
        let host = "app.example.com";

        // 15.5 days remain — green, 15 days.
        let (cert, key) = issue_pair(host, at(now, -3600), at(now, 15 * 86_400 + 43_200));
        write_pair(dir.path(), host, &cert, &key);
        assert_eq!(
            classify_cert_material(
                host,
                &dir.path().join(format!("{host}.crt")),
                &dir.path().join(format!("{host}.key")),
                now
            ),
            CertMaterialVerdict::Green(15)
        );

        // Exactly 14 days remain — the warn window's open edge.
        let (cert, key) = issue_pair(host, at(now, -3600), at(now, 14 * 86_400 + 43_200));
        write_pair(dir.path(), host, &cert, &key);
        assert_eq!(
            classify_cert_material(
                host,
                &dir.path().join(format!("{host}.crt")),
                &dir.path().join(format!("{host}.key")),
                now
            ),
            CertMaterialVerdict::Warn(14)
        );

        // A day over the edge — green again.
        let (cert, key) = issue_pair(host, at(now, -3600), at(now, 16 * 86_400 + 43_200));
        write_pair(dir.path(), host, &cert, &key);
        assert_eq!(
            classify_cert_material(
                host,
                &dir.path().join(format!("{host}.crt")),
                &dir.path().join(format!("{host}.key")),
                now
            ),
            CertMaterialVerdict::Green(16)
        );

        // Expired a day ago.
        let (cert, key) = issue_pair(host, at(now, -90 * 86_400), at(now, -86_400 - 43_200));
        write_pair(dir.path(), host, &cert, &key);
        assert_eq!(
            classify_cert_material(
                host,
                &dir.path().join(format!("{host}.crt")),
                &dir.path().join(format!("{host}.key")),
                now
            ),
            CertMaterialVerdict::Expired(1)
        );

        // Not yet valid.
        let (cert, key) = issue_pair(host, at(now, 3600), at(now, 90 * 86_400));
        write_pair(dir.path(), host, &cert, &key);
        assert_eq!(
            classify_cert_material(
                host,
                &dir.path().join(format!("{host}.crt")),
                &dir.path().join(format!("{host}.key")),
                now
            ),
            CertMaterialVerdict::NotYetValid
        );

        // SAN does not cover the host (a wildcard for another zone).
        let (cert, key) = issue_pair("*.other.example.com", at(now, -3600), at(now, 90 * 86_400));
        write_pair(dir.path(), host, &cert, &key);
        assert_eq!(
            classify_cert_material(
                host,
                &dir.path().join(format!("{host}.crt")),
                &dir.path().join(format!("{host}.key")),
                now
            ),
            CertMaterialVerdict::SanMismatches(vec!["*.other.example.com".to_owned()])
        );

        // A wildcard SAN DOES cover a single-label subdomain.
        let (cert, key) = issue_pair("*.example.com", at(now, -3600), at(now, 90 * 86_400));
        write_pair(dir.path(), host, &cert, &key);
        assert_eq!(
            classify_cert_material(
                host,
                &dir.path().join(format!("{host}.crt")),
                &dir.path().join(format!("{host}.key")),
                now
            ),
            CertMaterialVerdict::Green(90)
        );

        // Pairing: two issuances' files meet on disk.
        let (cert_a, _) = issue_pair(host, at(now, -3600), at(now, 90 * 86_400));
        let (_, key_b) = issue_pair(host, at(now, -3600), at(now, 91 * 86_400));
        write_pair(dir.path(), host, &cert_a, &key_b);
        assert_eq!(
            classify_cert_material(
                host,
                &dir.path().join(format!("{host}.crt")),
                &dir.path().join(format!("{host}.key")),
                now
            ),
            CertMaterialVerdict::PairMismatch
        );

        // Missing halves — clear the pair the pairing step left behind.
        std::fs::remove_file(dir.path().join(format!("{host}.crt"))).expect("remove crt");
        std::fs::remove_file(dir.path().join(format!("{host}.key"))).expect("remove key");
        assert_eq!(
            classify_cert_material(
                host,
                &dir.path().join(format!("{host}.crt")),
                &dir.path().join("nowhere.key"),
                now
            ),
            CertMaterialVerdict::Missing {
                cert: false,
                key: false
            }
        );
        std::fs::write(dir.path().join(format!("{host}.crt")), "not a cert\n").expect("crt");
        assert_eq!(
            classify_cert_material(
                host,
                &dir.path().join(format!("{host}.crt")),
                &dir.path().join("nowhere.key"),
                now
            ),
            CertMaterialVerdict::Missing {
                cert: true,
                key: false
            }
        );

        // Present but unparseable.
        std::fs::write(dir.path().join(format!("{host}.crt")), "still not a cert\n").expect("crt");
        std::fs::write(dir.path().join(format!("{host}.key")), "nor a key\n").expect("key");
        assert!(matches!(
            classify_cert_material(
                host,
                &dir.path().join(format!("{host}.crt")),
                &dir.path().join(format!("{host}.key")),
                now
            ),
            CertMaterialVerdict::Unparseable(_)
        ));
    }

    /// The deployed-fragment reconciliation: the fragment's own
    /// ssl_certificate lines are nginx's truth; a divergence from the
    /// convention is flagged; a hand-edited fragment stays parseable; no
    /// fragment falls back to the convention.
    #[test]
    fn deployed_fragment_reconciliation() {
        let dir = tempfile::tempdir().expect("tempdir");
        let certs_dir = dir.path().join("certs");
        std::fs::create_dir_all(&certs_dir).expect("mkdir");

        // No fragment on the machine → the convention.
        let resolved = resolve_cert_paths("app.example.com", None, &certs_dir);
        assert_eq!(resolved.cert, certs_dir.join("app.example.com.crt"));
        assert!(!resolved.diverges);

        // The rendered shape: convention paths → no divergence.
        let rendered = format!(
            "# Generated by interflow-cli — frontend-proxy vhosts for ingress edge.\n\
             server {{\n\
             \x20   server_name app.example.com;\n\
             \x20   ssl_certificate     {};\n\
             \x20   ssl_certificate_key {};\n\
             }}\n",
            certs_dir.join("app.example.com.crt").display(),
            certs_dir.join("app.example.com.key").display()
        );
        std::fs::create_dir_all(dir.path().join("vhost")).expect("mkdir");
        std::fs::write(
            dir.path().join("vhost/interflow-vhost-edge.conf"),
            &rendered,
        )
        .expect("write");
        let blocks = vhost_cert_paths_in(&dir.path().join("vhost"), "edge").expect("parses");
        let resolved = resolve_cert_paths("app.example.com", Some(&blocks), &certs_dir);
        assert_eq!(resolved.cert, certs_dir.join("app.example.com.crt"));
        assert!(
            !resolved.diverges,
            "the rendered shape references the convention"
        );

        // A hand-edited fragment pointing at letsencrypt's live dir → the
        // divergence flag (checked against the --certs-dir convention).
        let hand_edited = rendered.replace(
            &certs_dir.join("app.example.com.crt").display().to_string(),
            "/etc/letsencrypt/live/app.example.com/fullchain.pem",
        );
        std::fs::write(
            dir.path().join("vhost/interflow-vhost-edge.conf"),
            hand_edited,
        )
        .expect("write");
        let blocks = vhost_cert_paths_in(&dir.path().join("vhost"), "edge").expect("parses");
        let resolved = resolve_cert_paths("app.example.com", Some(&blocks), &certs_dir);
        assert_eq!(
            resolved.cert,
            std::path::PathBuf::from("/etc/letsencrypt/live/app.example.com/fullchain.pem")
        );
        assert!(
            resolved.diverges,
            "a hand-edited path diverges from the convention"
        );

        // The directive split: ssl_certificate_key never masquerades as
        // ssl_certificate.
        assert_eq!(
            nginx_directive("ssl_certificate_key /x/y.key;"),
            Some(("ssl_certificate_key", "/x/y.key"))
        );
        assert_eq!(
            nginx_directive("ssl_certificate /x/y.crt;"),
            Some(("ssl_certificate", "/x/y.crt"))
        );
        assert_eq!(nginx_directive("listen 443;"), Some(("listen", "443")));
        assert_eq!(nginx_directive("server {"), None);
    }

    /// The certbot renewal note fires only when the renewal directory
    /// exists on this machine and holds no entry for the host.
    #[test]
    fn certbot_renewal_note_covers_only_present_directories() {
        let dir = tempfile::tempdir().expect("tempdir");
        // No letsencrypt directory at all → silent (non-certbot machine).
        certbot_renewal_note_in("app.example.com", &dir.path().join("renewal"), "  ");
        // Directory present, no entry → the note fires; an entry → silent.
        let renewal = dir.path().join("renewal");
        std::fs::create_dir_all(&renewal).expect("mkdir");
        certbot_renewal_note_in("app.example.com", &renewal, "  ");
        std::fs::write(renewal.join("app.example.com.conf"), "cert = ...").expect("write");
        certbot_renewal_note_in("app.example.com", &renewal, "  ");
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

    /// The multi-route acceptance matrix
    /// ((internal design notes) §4;
    ///  (internal design notes) §4):
    /// a healthy route proves injection; an all-closed sweep is multi-cause;
    /// a genuinely missing header is the same all-closed shape — red, but
    /// with every cause named and the nginx directive framed as hypothesis.
    /// The route's agent is the first two segments of its well-formed
    /// service reference (what the policy's typed resolution yields).
    fn route_probe(host: &str, service: &str, outcome: ProxyOutcome) -> RouteProbe {
        let segments: Vec<&str> = service.split('/').collect();
        let agent = (segments.len() >= 3).then(|| segments[..2].join("/"));
        RouteProbe {
            host: host.to_owned(),
            service: service.to_owned(),
            agent,
            outcome,
        }
    }

    /// A face builder: `agent → leg`.
    fn face(pairs: &[(&str, AgentLeg)]) -> BTreeMap<String, AgentLeg> {
        pairs
            .iter()
            .map(|(agent, leg)| ((*agent).to_owned(), AgentLeg::clone(leg)))
            .collect()
    }

    #[test]
    fn one_answered_route_proves_xff_even_with_the_rest_closed() {
        let probes = vec![
            route_probe(
                "inbox.example.com",
                "default/inbox-ai/app",
                ProxyOutcome::UpstreamClosed,
            ),
            route_probe(
                "mail.example.com",
                "default/email-marketing/app",
                ProxyOutcome::Answered {
                    status: "HTTP/1.1 200 OK".to_owned(),
                    from_nginx: true,
                },
            ),
            route_probe(
                "vault.example.com",
                "default/know-vault/app",
                ProxyOutcome::UpstreamClosed,
            ),
        ];
        match xff_classify(&probes) {
            XffVerdict::Proven { host, status } => {
                assert_eq!(host, "mail.example.com", "the proving route is named");
                assert_eq!(status, "HTTP/1.1 200 OK");
            }
            XffVerdict::AllClosed | XffVerdict::Inconclusive => {
                unreachable!("the find above guarantees an Answered probe classifies as Proven")
            }
        }
    }

    #[test]
    fn all_closed_is_dual_cause_never_a_single_accusation() {
        let probes = vec![
            route_probe(
                "inbox.example.com",
                "default/inbox-ai/app",
                ProxyOutcome::UpstreamClosed,
            ),
            route_probe(
                "mail.example.com",
                "default/email-marketing/app",
                ProxyOutcome::UpstreamClosed,
            ),
        ];
        assert!(matches!(xff_classify(&probes), XffVerdict::AllClosed));
        // No registration reading: the two-cause form, byte-stable.
        let lines = closed_sweep_lines(&probes, &BTreeMap::new()).join("\n");
        // Both causes, joined disjunctively — no single-cause verdict.
        assert!(lines.contains("two possible causes"), "{lines}");
        assert!(lines.contains("X-Forwarded-For"), "{lines}");
        assert!(
            lines.contains(" or\n"),
            "the causes are alternatives: {lines}"
        );
        assert!(lines.contains("backing service is down"), "{lines}");
        // Every route and its service is named with a discriminating action.
        assert!(
            lines.contains("inbox.example.com → default/inbox-ai/app"),
            "{lines}"
        );
        assert!(
            lines.contains("mail.example.com → default/email-marketing/app"),
            "{lines}"
        );
        assert!(lines.contains("doctor route inbox.example.com"), "{lines}");
        // The nginx directive rides along only as the second hypothesis.
        assert!(
            lines.contains("proxy_set_header X-Forwarded-For"),
            "{lines}"
        );
        assert!(
            lines.contains("confirmed running"),
            "the fix must be gated on the service check: {lines}"
        );
    }

    /// The third-cause matrix
    ///:
    /// the registry's own word is prepended, the offline agent's routes
    /// lose their backend-check instruction, and the registered agents'
    /// routes keep theirs.
    #[test]
    fn an_offline_agent_is_prepended_and_its_route_checks_downgraded() {
        let probes = vec![
            route_probe(
                "inbox.example.com",
                "main/home-expose/inbox-ai",
                ProxyOutcome::UpstreamClosed,
            ),
            route_probe(
                "vault.example.com",
                "main/other-agent/know-vault",
                ProxyOutcome::UpstreamClosed,
            ),
        ];
        let offline = face(&[
            ("main/home-expose", AgentLeg::NotRegistered),
            ("main/other-agent", AgentLeg::Online),
        ]);
        let lines = closed_sweep_lines(&probes, &offline).join("\n");
        // The agent cause joins the list, disjunctively.
        assert!(lines.contains("three possible causes"), "{lines}");
        assert!(
            lines.contains("a route's agent is not registered with this ingress"),
            "{lines}"
        );
        // The registry's authoritative word leads, with the backlog's
        // start-the-node-first instruction.
        assert!(
            lines.contains(
                "✘ main/home-expose is not registered with this ingress — start the node \
                 first"
            ),
            "{lines}"
        );
        // The offline agent's route loses its backend-check instruction…
        let inbox_line = lines
            .lines()
            .find(|l| l.contains("inbox.example.com → main/home-expose/inbox-ai"))
            .unwrap_or_default();
        assert!(
            inbox_line.contains("agent offline above — re-check after it reconnects"),
            "{lines}"
        );
        assert!(
            !inbox_line.contains("or start the service"),
            "a backend check on a legless route is noise: {lines}"
        );
        // …while the registered agent's route keeps it.
        let vault_line = lines
            .lines()
            .find(|l| l.contains("vault.example.com → main/other-agent/know-vault"))
            .unwrap_or_default();
        assert!(
            vault_line.contains("doctor route vault.example.com — or start the service"),
            "{lines}"
        );
        // The nginx hypothesis is gated behind the legs coming back.
        assert!(
            lines.contains("every agent is registered and every service is confirmed running"),
            "{lines}"
        );
    }

    /// A not-reachable leg (past reconnect grace, eviction pending) is
    /// downgraded like an offline one — dials through it fail all the same.
    #[test]
    fn a_not_reachable_agent_downgrades_its_routes_too() {
        let probes = vec![route_probe(
            "inbox.example.com",
            "main/home-expose/inbox-ai",
            ProxyOutcome::UpstreamClosed,
        )];
        let drifting = face(&[("main/home-expose", AgentLeg::RegisteredNotReachable)]);
        let lines = closed_sweep_lines(&probes, &drifting).join("\n");
        assert!(lines.contains("three possible causes"), "{lines}");
        assert!(
            lines.contains("main/home-expose is registered but not reachable"),
            "{lines}"
        );
        assert!(
            lines.contains("agent offline above — re-check after it reconnects"),
            "{lines}"
        );
        assert!(
            !lines.contains("or start the service"),
            "the route's backend check is meaningless until the leg settles: {lines}"
        );
    }

    /// An online or unreadable face never accuses: the output is the
    /// two-cause form, byte-for-byte.
    #[test]
    fn an_online_or_silent_face_keeps_the_dual_cause_form() {
        let probes = vec![
            route_probe(
                "inbox.example.com",
                "main/home-expose/inbox-ai",
                ProxyOutcome::UpstreamClosed,
            ),
            route_probe(
                "vault.example.com",
                "main/other-agent/know-vault",
                ProxyOutcome::UpstreamClosed,
            ),
        ];
        let anchor = closed_sweep_lines(&probes, &BTreeMap::new()).join("\n");
        let online = face(&[
            ("main/home-expose", AgentLeg::Online),
            ("main/other-agent", AgentLeg::Online),
        ]);
        assert_eq!(
            closed_sweep_lines(&probes, &online).join("\n"),
            anchor,
            "an all-online registry changes nothing"
        );
        let silent = face(&[
            (
                "main/home-expose",
                AgentLeg::Unknown("agents list query timed out".to_owned()),
            ),
            ("main/other-agent", AgentLeg::Online),
        ]);
        let unknown_lines = closed_sweep_lines(&probes, &silent).join("\n");
        assert_eq!(
            unknown_lines, anchor,
            "an unreadable face is never an accusation"
        );
    }

    #[test]
    fn mixed_timeouts_without_answers_are_inconclusive() {
        let probes = vec![
            route_probe("a.example.com", "w/a/a", ProxyOutcome::UpstreamClosed),
            route_probe("b.example.com", "w/b/b", ProxyOutcome::Timeout),
        ];
        assert!(matches!(xff_classify(&probes), XffVerdict::Inconclusive));
        let empty: Vec<RouteProbe> = Vec::new();
        assert!(matches!(xff_classify(&empty), XffVerdict::Inconclusive));
    }

    // -----------------------------------------------------------------------
    // nginx fragment-set reconciliation
    // ((internal design notes) §4 matrix;
    //  the matrix's hole — the all-present state — is
    //  (internal design notes))
    // -----------------------------------------------------------------------

    fn route(host: &str) -> interflow_identity::policy::PolicyRoute {
        interflow_identity::policy::PolicyRoute {
            host: host.to_owned(),
            service: format!("default/desktop/{host}"),
        }
    }

    /// Deploys the current render set (real rendered bodies) for one ingress
    /// node under a temp `--nginx-dir`.
    fn deploy_current_fragments(nginx_dir: &std::path::Path, node: &str) {
        let manifest = interflow_identity::Manifest::parse(
            r#"
[realm]
id = "promptcn"
control_endpoint = "127.0.0.1:26666"
[public_tls]
mode = "frontend-proxy"
[identity]
mode = "offline"
[ingress.edge]
workspaces = ["default"]
listen = "127.0.0.1:18443"
[workspace.default]
[agent.desktop]
workspace = "default"
[[agent.desktop.services]]
id = "asr"
address = "127.0.0.1:18080"
[[agent.desktop.services]]
id = "mail"
address = "127.0.0.1:18025"
[[route]]
host = "asr.example.com"
service = "default/desktop/asr"
[[route]]
host = "mail.example.com"
service = "default/desktop/mail"
"#,
        )
        .unwrap();
        let sha = interflow_util::sha256_hex(b"reconcile");
        for fragment in
            interflow_cli::render::nginx_fragment_set(&manifest, &sha, Some(&[node.to_owned()]))
                .unwrap()
        {
            // rel paths are staging-tree-relative ("nginx/http/…"); the
            // deployed root IS the "nginx/" level.
            let deployed_rel = fragment.rel.strip_prefix("nginx/").unwrap();
            let path = nginx_dir.join(deployed_rel);
            std::fs::create_dir_all(path.parent().unwrap()).unwrap();
            std::fs::write(path, fragment.body).unwrap();
        }
    }

    /// The findings for one fully-deployed reconciliation — the matrix
    /// asserts on the structured verdict, never on captured output.
    fn findings_of(
        routes: &[interflow_identity::policy::PolicyRoute],
        nginx_dir: &std::path::Path,
    ) -> Vec<FragmentFinding> {
        match fragment_set_reconciliation("edge", routes, None, nginx_dir) {
            FragmentReconciliation::Findings(findings) => Some(findings),
            FragmentReconciliation::NothingDeployed => None,
        }
        .expect("the matrix deploys before reconciling")
    }

    /// The in-form state: deployed set == render set ⇒ ZERO findings. This
    /// is the live-traffic shape the cross-directory bug false-alarmed on —
    /// every shared file checked against a directory it does not belong
    /// to — and the one state the original matrix never asserted on
    #[test]
    fn a_fully_deployed_set_reconciles_with_zero_findings() {
        let tmp = tempfile::tempdir().unwrap();
        let nginx_dir = tmp.path().join("nginx");
        deploy_current_fragments(&nginx_dir, "edge");
        let routes = vec![route("asr.example.com"), route("mail.example.com")];
        assert!(
            findings_of(&routes, &nginx_dir).is_empty(),
            "all four files in place, each in its own directory"
        );
    }

    /// Any one file removed ⇒ exactly one MissingFile, naming the file and
    /// the directory it belongs to. (The :80 block and the vhost hold the
    /// route names for each other, so no semantic finding tags along.)
    #[test]
    fn each_missing_fragment_is_one_finding_in_its_own_directory() {
        for (dir, file, deployed_path) in [
            (
                FragmentDir::Stream,
                "interflow-stream.conf",
                "stream/interflow-stream.conf",
            ),
            (
                FragmentDir::Http,
                "interflow-http.conf",
                "http/interflow-http.conf",
            ),
            (
                FragmentDir::Http,
                "interflow-shared.conf",
                "http/interflow-shared.conf",
            ),
            (
                FragmentDir::Http,
                "interflow-vhost-edge.conf",
                "http/interflow-vhost-edge.conf",
            ),
        ] {
            let tmp = tempfile::tempdir().unwrap();
            let nginx_dir = tmp.path().join("nginx");
            deploy_current_fragments(&nginx_dir, "edge");
            std::fs::remove_file(nginx_dir.join(deployed_path)).unwrap();
            let routes = vec![route("asr.example.com"), route("mail.example.com")];
            assert_eq!(
                findings_of(&routes, &nginx_dir),
                vec![FragmentFinding::MissingFile {
                    dir,
                    file: file.to_owned(),
                }],
                "removing {deployed_path} is one finding, in its own directory"
            );
        }
    }

    /// The rename leftover: the old vhost (same server names, old node
    /// slot) still deployed ⇒ named as superseded AND its names conflict
    /// with the current vhost — the red line (the epoch-2 redeploy's
    /// exact shape).
    #[test]
    fn superseded_files_are_named_and_conflicts_are_red() {
        let tmp = tempfile::tempdir().unwrap();
        let nginx_dir = tmp.path().join("nginx");
        deploy_current_fragments(&nginx_dir, "edge");
        let routes = vec![route("asr.example.com"), route("mail.example.com")];
        std::fs::copy(
            nginx_dir.join("http/interflow-vhost-edge.conf"),
            nginx_dir.join("http/interflow-vhost-old.conf"),
        )
        .unwrap();
        let findings = findings_of(&routes, &nginx_dir);
        assert!(
            findings.contains(&FragmentFinding::SupersededFile {
                dir: FragmentDir::Http,
                file: "interflow-vhost-old.conf".to_owned(),
            }),
            "the leftover file is named: {findings:?}"
        );
        assert!(
            findings.iter().any(|finding| matches!(
                finding,
                FragmentFinding::ConflictingServerName { files, .. }
                    if files.contains(&"interflow-vhost-old.conf".to_owned())
                        && files.contains(&"interflow-vhost-edge.conf".to_owned())
            )),
            "the conflict names both files: {findings:?}"
        );
        assert!(
            findings.iter().any(FragmentFinding::is_red),
            "a loaded superseded vhost is red: {findings:?}"
        );
    }

    /// A render-set file deployed in the WRONG directory: named superseded
    /// where it sits and missing where it belongs — the state name-based
    /// directory guessing can never get right, and the proof that
    /// membership comes with the typed single source, not the file name.
    #[test]
    fn a_fragment_deployed_in_the_wrong_directory_is_named_on_both_ends() {
        let tmp = tempfile::tempdir().unwrap();
        let nginx_dir = tmp.path().join("nginx");
        deploy_current_fragments(&nginx_dir, "edge");
        std::fs::rename(
            nginx_dir.join("stream/interflow-stream.conf"),
            nginx_dir.join("http/interflow-stream.conf"),
        )
        .unwrap();
        let routes = vec![route("asr.example.com"), route("mail.example.com")];
        assert_eq!(
            findings_of(&routes, &nginx_dir),
            vec![
                FragmentFinding::SupersededFile {
                    dir: FragmentDir::Http,
                    file: "interflow-stream.conf".to_owned(),
                },
                FragmentFinding::MissingFile {
                    dir: FragmentDir::Stream,
                    file: "interflow-stream.conf".to_owned(),
                },
            ]
        );
    }

    /// Semantic drift the file-name set cannot see: a deployed name no
    /// signed route declares, and a deployed set with no signed routes at
    /// all. Warning-level findings, never failures.
    #[test]
    fn unsigned_deployed_names_are_findings() {
        let tmp = tempfile::tempdir().unwrap();
        let nginx_dir = tmp.path().join("nginx");
        deploy_current_fragments(&nginx_dir, "edge");
        // ghost deployed but unsigned ⇒ ServerWithoutRoute; the :80 block
        // still declares both signed names, so nothing else tags along.
        let vhost = nginx_dir.join("http/interflow-vhost-edge.conf");
        let text = std::fs::read_to_string(&vhost).unwrap();
        std::fs::write(
            &vhost,
            text.replace("mail.example.com", "ghost.example.com"),
        )
        .unwrap();
        let routes = vec![route("asr.example.com"), route("mail.example.com")];
        assert_eq!(
            findings_of(&routes, &nginx_dir),
            vec![FragmentFinding::ServerWithoutRoute {
                name: "ghost.example.com".to_owned(),
            }]
        );

        // No signed routes at all: every deployed name is unsigned.
        let tmp_fresh = tempfile::tempdir().unwrap();
        let nginx_fresh = tmp_fresh.path().join("nginx");
        deploy_current_fragments(&nginx_fresh, "edge");
        assert_eq!(
            findings_of(&[], &nginx_fresh),
            vec![
                FragmentFinding::ServerWithoutRoute {
                    name: "asr.example.com".to_owned(),
                },
                FragmentFinding::ServerWithoutRoute {
                    name: "mail.example.com".to_owned(),
                },
            ]
        );
    }

    /// Nothing deployed: a skip note, never findings or an error (the
    /// operator may run doctor before wiring the front).
    #[test]
    fn absent_nginx_dirs_skip_with_a_note() {
        let tmp = tempfile::tempdir().unwrap();
        let nginx_dir = tmp.path().join("nginx");
        assert!(matches!(
            fragment_set_reconciliation("edge", &[], None, &nginx_dir),
            FragmentReconciliation::NothingDeployed
        ));
    }

    /// The message surface is the operator-facing contract: each finding
    /// renders its stable line, quoting the file's own directory and a
    /// concrete fix.
    #[test]
    fn findings_lines_quote_the_directory_and_the_fix() {
        let lines = fragment_findings_lines(
            &[
                FragmentFinding::MissingFile {
                    dir: FragmentDir::Stream,
                    file: "interflow-stream.conf".to_owned(),
                },
                FragmentFinding::SupersededFile {
                    dir: FragmentDir::Http,
                    file: "interflow-vhost-old.conf".to_owned(),
                },
            ],
            std::path::Path::new("/etc/nginx/interflow"),
        );
        assert_eq!(lines.len(), 2);
        assert!(
            lines[0].contains(
                "expected fragment nginx/stream/interflow-stream.conf is not deployed \
                 under /etc/nginx/interflow"
            ),
            "{}",
            lines[0]
        );
        assert!(
            lines[1].contains("superseded fragment http/interflow-vhost-old.conf"),
            "{}",
            lines[1]
        );
    }
}
