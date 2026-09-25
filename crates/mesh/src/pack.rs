//! `interflow-mesh hub/agent --pack` — Credential Pack → engine bootstrap.
//!
//! The product site-to-site path. The user-facing model never sees
//! certificate paths or tenant tables: the pack supplies the identity,
//! trust, and signed policy; this module maps it onto the mesh engine
//! configuration. Engine inputs still address material by path — the pack
//! directory and the active-credential sequences materialize those files,
//! so the bytes the issuer signed are the bytes the engine runs.
//!
//! Lifecycle runs beside the engine: [`interflow_renewal::renewal_scheduler`]
//! renews at 50% TTL and turns renewal / CRL updates into a graceful
//! process exit, so the supervisor restarts the node onto the new material.

use crate::config::{
    AclConfig, AclRule, AgentConfig, AgentInfo, AgentTlsConfig, AuthConfig, EgressRule,
    EgressTarget, HubConfig, HubTlsConfig, IngressRule, InnerTlsConfig, ServerConfig, TenantConfig,
};
use crate::hub::HubServer;
use interflow_core::config::AuditConfig;
use interflow_core::error::{InterflowError, Result};
use interflow_core::protocol::StreamProto;
use interflow_core::tls::TlsMinVersion;
use interflow_identity::credentials::ActiveCredentialSet;
use interflow_identity::manifest::MeshProtocol;
use interflow_identity::pack::{CredentialPack, PackKind};
use interflow_identity::policy::RuntimePolicy;
use std::net::SocketAddr;
use std::path::Path;

/// Pack load/validation failures are configuration-class (unrecoverable at
/// boot); keep the identity error as the source-chain root.
pub fn pack_error(e: interflow_identity::Error) -> InterflowError {
    interflow_renewal::pack_error(e)
}

fn config_error(context: impl Into<String>) -> InterflowError {
    InterflowError::config(context)
}

/// Env-filter logging for pack-driven nodes (packs carry no logging
/// section).
pub fn init_pack_logging() {
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
    let _ = tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .with_target(false)
        .try_init();
}

const fn stream_proto(protocol: MeshProtocol) -> StreamProto {
    match protocol {
        MeshProtocol::Tcp => StreamProto::Tcp,
        MeshProtocol::Udp => StreamProto::Udp,
    }
}

fn parse_addr(value: &str, what: &str) -> Result<SocketAddr> {
    value.parse().map_err(|e| {
        config_error(format!(
            "signed policy mesh rule has an invalid {what} {value:?}"
        ))
        .with_source(e)
    })
}

/// Builds the hub engine configuration from a fully validated hub pack.
///
/// The tenant trust table is derived from the pack's trust bundle (one
/// workspace = one issuer-anchored tenant); cross-workspace admission comes
/// from the **signed** runtime policy. Nothing is hand-placed on the hub
/// host.
pub fn build_hub_config(
    pack: &CredentialPack,
    active: &ActiveCredentialSet,
    pack_dir: &Path,
) -> Result<HubConfig> {
    if pack.metadata.kind != PackKind::Hub {
        return Err(InterflowError::config(format!(
            "this is an {} pack — it cannot start as a mesh hub (role-bound)",
            pack.metadata.kind.as_str()
        )));
    }
    let trust_dir = pack_dir.join("trust");

    // Tenant trust table: one entry per workspace issuer in the bundle, plus
    // the reserved `control` tenant (the realm issuer's control principals —
    // the policy publication face; data-plane endpoints reject it).
    // CRLs: live refresh first, the rotate-embedded snapshot otherwise.
    let mut tenants = Vec::new();
    for name in pack.trust.metadata.issuers.keys() {
        let Some(workspace) = name.strip_prefix("workspace/") else {
            continue;
        };
        let anchor = trust_dir.join(format!("{}.crt", name.replace('/', "-")));
        let crl = interflow_identity::pack::crl_path_for(pack_dir, &name.replace('/', "-"));
        tenants.push(TenantConfig {
            name: workspace.to_owned(),
            ca_path: anchor.display().to_string(),
            crl_path: crl.as_ref().map(|p| p.display().to_string()),
            trusted_gateway: false,
        });
    }
    if tenants.is_empty() {
        return Err(InterflowError::config(
            "hub pack carries no workspace trust anchor — declare mesh rules on at least one \
             agent and re-apply",
        ));
    }
    let control_crl = interflow_identity::pack::crl_path_for(pack_dir, "control");
    tenants.push(TenantConfig {
        name: crate::hub::state::CONTROL_TENANT.to_owned(),
        ca_path: trust_dir.join("control.crt").display().to_string(),
        crl_path: control_crl.as_ref().map(|p| p.display().to_string()),
        trusted_gateway: false,
    });

    // Server credential: the control-endpoint identity (renewed sequences
    // materialize under the pack's active state).
    let (cert, key) = active
        .material_paths("control-endpoint")
        .map_err(pack_error)?;
    let listen: SocketAddr = pack
        .node_config
        .listen
        .as_deref()
        .unwrap_or("0.0.0.0:6666")
        .parse()
        .map_err(|e| {
            InterflowError::config(format!(
                "hub listen address {:?} is invalid",
                pack.node_config.listen
            ))
            .with_source(e)
        })?;

    // Cross-workspace admission derives from the signed policy (same-
    // workspace streams are allowed by the engine's default; the empty rule
    // set means full inter-workspace isolation).
    let acl = policy_acl(&pack.policy);

    let config = HubConfig {
        server: ServerConfig {
            listen_addr: listen,
            // Log attribution for embedders hosting several nodes in one
            // process (the GUI keys captured events on this name).
            node_name: Some(pack.metadata.node.clone()),
            proxy_protocol: Default::default(),
        },
        auth: AuthConfig {
            rate_limit_per_minute: Default::default(),
            tenants,
        },
        tls: Some(HubTlsConfig {
            enabled: true,
            cert_path: cert.display().to_string(),
            key_path: key.display().to_string(),
            min_version: TlsMinVersion::V1_3,
        }),
        acl,
        security: Default::default(),
        heartbeat: Default::default(),
        transport: Default::default(),
        metrics: Default::default(),
        audit: AuditConfig {
            enabled: true,
            path: Some(pack_dir.join("audit.jsonl").display().to_string()),
            // Rotation defaults (64 MiB / keep 32 / gzip) apply — a
            // long-lived hub ledger must never grow unbounded.
            rotation: Default::default(),
        },
        // The policy publication face: the trust bundle's policy key + the
        // node-local update channel (the same files the reload watcher
        // polls). The floor starts at the authoritative policy generation
        // this hub loaded (state/policy override included).
        policy: crate::config::PolicyAdminConfig {
            verifier_key_hex: Some(pack.trust.metadata.policy_key.clone()),
            state_policy_dir: Some(pack_dir.join("state").join("policy")),
            embedded_policy_dir: Some(pack_dir.join("policy")),
            generation: pack.policy.generation,
        },
        logging: Default::default(),
    };
    crate::config::validate::validate_hub(&config)
        .map_err(|e| config_error("hub pack renders an invalid engine config").with_source(e))?;
    Ok(config)
}

/// Builds the mesh agent engine configuration from a fully validated
/// mesh-role agent pack.
///
/// The pack is the single source of node material: identity (workspace
/// principal), trust anchors (hub realm anchor outer, workspace anchors
/// inner), the hub dial target, and the local ingress/egress rules.
pub fn build_agent_config(
    pack: &CredentialPack,
    active: &ActiveCredentialSet,
    pack_dir: &Path,
) -> Result<AgentConfig> {
    if pack.metadata.kind != PackKind::Agent {
        return Err(InterflowError::config(format!(
            "this is an {} pack — it cannot start as a mesh agent (role-bound)",
            pack.metadata.kind.as_str()
        )));
    }
    let workspace = pack
        .metadata
        .workspace
        .as_deref()
        .ok_or_else(|| config_error("agent pack is missing its workspace"))?;
    let mesh = pack.node_config.mesh.as_ref().ok_or_else(|| {
        config_error(
            "this agent pack carries no site-to-site rules — it is an expose agent; run it \
                 with `interflow agent run --pack`",
        )
    })?;
    let trust_dir = pack_dir.join("trust");

    let (cert, key) = active
        .material_paths(&format!("agent-{workspace}"))
        .map_err(pack_error)?;

    // Inner peer anchors: the agent's own workspace plus every peer
    // workspace riding in the trust bundle (cross-worksite flows). The hub
    // plane anchor (the realm issuer) stays out of the inner set.
    let own_anchor = trust_dir.join(format!("workspace-{workspace}.crt"));
    let mut extra_trusted_cas = Vec::new();
    let mut crl_paths = Vec::new();
    for name in pack.trust.metadata.issuers.keys() {
        let Some(peer) = name.strip_prefix("workspace/") else {
            continue;
        };
        let anchor = trust_dir.join(format!("{}.crt", name.replace('/', "-")));
        if let Some(crl) = interflow_identity::pack::crl_path_for(pack_dir, &name.replace('/', "-"))
        {
            crl_paths.push(crl.display().to_string());
        }
        if peer != workspace {
            extra_trusted_cas.push(anchor.display().to_string());
        }
    }

    let mut ingress = Vec::new();
    for rule in policy_ingress_rules(&pack.policy, &pack.metadata.node, workspace)? {
        ingress.push(rule);
    }
    let (egress, allowed_targets) = policy_egress_rules(&pack.policy, &pack.metadata.node)?;

    let config = AgentConfig {
        agent: AgentInfo {
            id: pack.metadata.node.clone(),
            hub_url: normalize_endpoint(&mesh.hub_endpoint),
            ..AgentInfo::default()
        },
        ingress,
        egress,
        // The signed pack policy is the rule truth: the local control API
        // stays off (no token to manage, no loopback mutation surface).
        control: crate::config::ControlConfig {
            enabled: false,
            ..crate::config::ControlConfig::default()
        },
        security: crate::config::SecurityConfig { allowed_targets },
        tls: Some(AgentTlsConfig {
            enabled: true,
            ca_path: Some(trust_dir.join("control.crt").display().to_string()),
            client_cert_path: Some(cert.display().to_string()),
            client_key_path: Some(key.display().to_string()),
            hub_cert_fingerprint: None,
        }),
        inner_tls: InnerTlsConfig {
            ingress_ca_path: Some(own_anchor.display().to_string()),
            extra_trusted_cas,
            crl_paths,
            ..InnerTlsConfig::default()
        },
        ..AgentConfig::default()
    };
    crate::config::validate::validate_agent(&config)
        .map_err(|e| config_error("agent pack renders an invalid engine config").with_source(e))?;
    Ok(config)
}

fn normalize_endpoint(endpoint: &str) -> String {
    if endpoint.contains("://") {
        endpoint.to_owned()
    } else {
        format!("https://{endpoint}")
    }
}

/// The hub's cross-workspace admission table, derived from the signed
/// policy's stream face.
///
/// Same-workspace streams need no rule (the engine's default allows them);
/// an empty rule set means full inter-workspace isolation. Shared by
/// startup assembly and the signed-policy reload — the hub consults the
/// live table on every Open.
pub fn policy_acl(policy: &RuntimePolicy) -> AclConfig {
    let mut acl = AclConfig::default();
    for stream in &policy.mesh {
        if stream.source_workspace != stream.target_workspace {
            acl.rules.insert(AclRule {
                source_tenant: stream.source_workspace.clone(),
                source: stream.source_agent.clone(),
                target_tenant: stream.target_workspace.clone(),
                target: stream.target_agent.clone(),
            });
        }
    }
    acl
}

/// How often the node-local policy update channel (`state/policy`) is
/// polled — the renewal scheduler's polling discipline (no platform watch
/// dependencies); one interval of latency is well inside the product goal
/// for policy changes ("minutes, not days").
const POLICY_WATCH_INTERVAL: std::time::Duration = std::time::Duration::from_secs(10);

/// Fingerprint of a policy channel directory: both files' mtime + length.
/// `None` when the channel is absent. Shared by the reload watchers and
/// the hub's serve cache (fingerprint unchanged → the verified bytes are
/// unchanged).
pub(crate) fn policy_channel_fingerprint(
    policy_dir: &Path,
) -> Option<(std::time::SystemTime, u64, std::time::SystemTime, u64)> {
    let toml_meta = std::fs::metadata(policy_dir.join("policy.toml")).ok()?;
    let sig_meta = std::fs::metadata(policy_dir.join("policy.sig")).ok()?;
    Some((
        toml_meta.modified().ok()?,
        toml_meta.len(),
        sig_meta.modified().ok()?,
        sig_meta.len(),
    ))
}

/// Spawns the signed-policy reload watcher for a running mesh agent.
///
/// Two distribution channels, one applying path: the node-local file
/// channel (`state/policy`) and — when a tunnel facade is supplied — the
/// hub's control-plane pull (`GET /policy`), which is how an update
/// published at the hub reaches every agent with zero physical touches (an
/// offline agent catches up on its first connected tick). Each tick
/// verifies candidates against the pack's trust bundle and the
/// anti-rollback floor, then hands the derived rules to
/// [`AgentClient::apply_policy`]. Rejection is fail-keep: a tampered
/// signature, a rollback, or an undervivable rule face is logged (with its
/// category) while the current policy keeps serving.
pub fn spawn_policy_reload(
    pack_dir: &Path,
    client: crate::agent::AgentClient,
    tunnel: Option<interflow_core::tunnel::AgentTunnel>,
) -> Result<tokio::task::JoinHandle<()>> {
    let pack = CredentialPack::load_runtime(pack_dir).map_err(pack_error)?;
    let node = pack.metadata.node.clone();
    let workspace = pack.metadata.workspace.clone().unwrap_or_default();
    let verifier_key = pack.trust.metadata.policy_key.clone();
    let mut seen = pack.policy.generation;
    let dir = pack_dir.to_owned();
    Ok(tokio::spawn(async move {
        let policy_dir = dir.join("state/policy");
        let mut fingerprint = policy_channel_fingerprint(&policy_dir);
        loop {
            tokio::time::sleep(POLICY_WATCH_INTERVAL).await;

            // Channel 1: the node-local file drop.
            let current = policy_channel_fingerprint(&policy_dir);
            if current != fingerprint {
                fingerprint = current;
                try_reload(&dir, &node, &workspace, &client, &mut seen).await;
            }

            // Channel 2: the hub's control plane, as a conditional request:
            // the hub answers 304 (mapped to None here) while the caller
            // already holds the serving generation. A pull that fails
            // (older hub, QUIC transport, session mid-rebuild) is skipped
            // for this tick — the next tick retries.
            if let Some(tunnel) = &tunnel
                && let Ok(Some(fetch)) = tunnel.pull_policy(seen).await
                && fetch.generation > seen
            {
                match RuntimePolicy::verify_with_hex_key(
                    &fetch.body,
                    &fetch.signature,
                    &verifier_key,
                ) {
                    Ok(policy) => {
                        if let Err(e) = policy.check_not_rollback(seen) {
                            tracing::warn!(
                                "policy pull: rejecting hub-served generation {} (keeping \
                                 current): {e}",
                                fetch.generation
                            );
                        } else {
                            // Persist into the node-local channel first: the
                            // applying path (and any restart) reads exactly
                            // these files.
                            let channel_dir = dir.join("state/policy");
                            if let Err(e) = std::fs::create_dir_all(&channel_dir) {
                                tracing::warn!("policy pull: cannot persist update: {e}");
                            } else {
                                let write = |name: &str, bytes: &[u8]| {
                                    let path = channel_dir.join(name);
                                    let tmp = channel_dir.join(format!("{name}.tmp"));
                                    std::fs::write(&tmp, bytes)
                                        .and_then(|()| std::fs::rename(&tmp, &path))
                                };
                                if let Err(e) = write("policy.toml", &fetch.body)
                                    .and_then(|()| write("policy.sig", &fetch.signature))
                                {
                                    tracing::warn!("policy pull: persisting update failed: {e}");
                                } else {
                                    fingerprint = policy_channel_fingerprint(&policy_dir);
                                    tracing::info!(
                                        target: "audit",
                                        generation = fetch.generation,
                                        "policy pull: accepted hub-served update into the \
                                         node-local channel"
                                    );
                                    try_reload(&dir, &node, &workspace, &client, &mut seen).await;
                                }
                            }
                        }
                    }
                    Err(e) => {
                        tracing::warn!(
                            "policy pull: rejecting hub-served bytes (keeping current): {e}"
                        );
                    }
                }
            }
        }
    }))
}

/// One apply attempt from the node-local channel: reload the pack (trust
/// bundle + update channel), verify + anti-rollback check, derive, apply.
/// `seen` advances only on a successful application.
async fn try_reload(
    dir: &Path,
    node: &str,
    workspace: &str,
    client: &crate::agent::AgentClient,
    seen: &mut u64,
) {
    // Re-load the pack for the trust bundle + update channel; a torn copy
    // mid-write fails here and is retried next tick.
    let Ok(pack) = CredentialPack::load_runtime(dir) else {
        tracing::warn!("policy reload: pack reload failed (torn update?), keeping current policy");
        return;
    };
    match pack.policy_update(*seen) {
        Ok(Some(update)) => {
            let generation = update.policy.generation;
            match (
                policy_ingress_rules(&update.policy, node, workspace),
                policy_egress_rules(&update.policy, node),
            ) {
                (Ok(ingress), Ok((egress, allowed))) => {
                    let signature = interflow_util::sha256_hex(&update.signature);
                    tracing::info!(
                        target: "audit",
                        generation,
                        signature_fingerprint = %signature,
                        ingress_rules = ingress.len(),
                        egress_rules = egress.len(),
                        "policy reload: applying signed policy update"
                    );
                    client.apply_policy(ingress, egress, allowed).await;
                    *seen = generation;
                }
                (Err(e), _) | (_, Err(e)) => {
                    // The signed face is unusable on this node — keep the
                    // current policy; a corrected re-drop (new fingerprint)
                    // retries cleanly.
                    tracing::error!(
                        "policy reload: update does not derive valid rules, keeping current \
                         policy: {e}"
                    );
                }
            }
        }
        Ok(None) => {}
        Err(e) => {
            tracing::warn!("policy reload: rejecting update (keeping current policy): {e}");
        }
    }
}

/// Spawns the signed-policy reload watcher for a running hub.
///
/// Swaps the cross-workspace admission table under the shared-config lock
/// (effective on the next Open — never a listener rebuild). Same fail-keep
/// contract as the agent watcher.
pub fn spawn_hub_policy_reload(
    pack_dir: &Path,
    hub: &HubServer,
) -> Result<tokio::task::JoinHandle<()>> {
    let pack = CredentialPack::load_runtime(pack_dir).map_err(pack_error)?;
    let mut seen = pack.policy.generation;
    let shared = hub.shared_config();
    let dir = pack_dir.to_owned();
    Ok(tokio::spawn(async move {
        let policy_dir = dir.join("state/policy");
        let mut fingerprint = policy_channel_fingerprint(&policy_dir);
        loop {
            tokio::time::sleep(POLICY_WATCH_INTERVAL).await;
            let current = policy_channel_fingerprint(&policy_dir);
            if current == fingerprint {
                continue;
            }
            fingerprint = current;
            let Ok(pack) = CredentialPack::load_runtime(&dir) else {
                tracing::warn!(
                    "policy reload: pack reload failed (torn update?), keeping current policy"
                );
                continue;
            };
            match pack.policy_update(seen) {
                Ok(Some(update)) => {
                    let generation = update.policy.generation;
                    let acl = policy_acl(&update.policy);
                    let rules = acl.rules.len();
                    let mut config = shared.write().await;
                    config.acl = acl;
                    drop(config);
                    tracing::info!(
                        target: "audit",
                        generation,
                        acl_rules = rules,
                        "hub policy reload: cross-workspace admission table swapped"
                    );
                    seen = generation;
                }
                Ok(None) => {}
                Err(e) => {
                    tracing::warn!(
                        "hub policy reload: rejecting update (keeping current policy): {e}"
                    );
                }
            }
        }
    }))
}

/// Derives one agent's engine ingress rules from the signed policy's stream
/// face — its own listen-side rows (`source_agent == node`).
///
/// The single derivation for both startup assembly and the hot-reload path;
/// cross-workspace targets travel tenant-qualified on the wire (a bare id
/// resolves into the source's own tenant at the hub), with the workspace
/// pairing taken from the signed row itself, never local guess.
pub fn policy_ingress_rules(
    policy: &RuntimePolicy,
    node: &str,
    workspace: &str,
) -> Result<Vec<IngressRule>> {
    let mut ingress = Vec::new();
    for stream in &policy.mesh {
        if stream.source_agent != node {
            continue;
        }
        let target_agent = if stream.target_workspace == workspace {
            stream.target_agent.clone()
        } else {
            format!("{}/{}", stream.target_workspace, stream.target_agent)
        };
        ingress.push(IngressRule {
            name: stream.name.clone(),
            listen_addr: parse_addr(&stream.listen, "listen address")?,
            listen_protocol: stream_proto(stream.protocol),
            target_agent,
            remote_addr: Some(stream.remote_addr.clone()),
            idle_timeout_secs: stream.idle_timeout_secs,
            udp_per_ip_pps: Default::default(),
            udp_per_ip_bytes_per_sec: Default::default(),
            udp_egress_bytes_per_sec: Default::default(),
        });
    }
    Ok(ingress)
}

/// Derives one agent's engine egress rules and its egress allowlist from the
/// signed policy's egress face (`agent == node`).
///
/// The allowlist entry is the offer itself — one concrete address, or a
/// range that widens the offer to every address (any port) inside it.
/// Single derivation for startup and hot reload, so the two can never
/// drift.
pub fn policy_egress_rules(
    policy: &RuntimePolicy,
    node: &str,
) -> Result<(Vec<EgressRule>, Vec<String>)> {
    let mut egress = Vec::new();
    let mut allowed_targets = Vec::new();
    for offer in &policy.mesh_egress {
        if offer.agent != node {
            continue;
        }
        let target = match (&offer.target_addr, &offer.target_cidr) {
            (Some(addr), None) => EgressTarget::Addr(parse_addr(addr, "target address")?),
            (None, Some(cidr)) => EgressTarget::Cidr(cidr.parse().map_err(|e| {
                config_error(format!(
                    "mesh egress offer {:?}: target_cidr {cidr:?}",
                    offer.name
                ))
                .with_source(e)
            })?),
            // The signer-side validator rejects both-empty / both-present;
            // a signed policy carrying one is foreign or tampered — refuse
            // rather than guess.
            _ => {
                return Err(config_error(format!(
                    "mesh egress offer {:?}: exactly one of target_addr / target_cidr is \
                     required",
                    offer.name
                )));
            }
        };
        allowed_targets.push(offer.authorization().to_owned());
        egress.push(EgressRule {
            name: offer.name.clone(),
            target,
            target_protocol: stream_proto(offer.protocol),
            udp_idle_timeout_secs: offer.udp_idle_timeout_secs,
        });
    }
    Ok((egress, allowed_targets))
}

/// `interflow-mesh hub --pack <dir>`: engine + renewal scheduler, whichever
/// finishes first wins (renewal/CRL updates exit gracefully so the
/// supervisor restarts onto the new material).
pub async fn run_hub(pack_dir: &Path) -> Result<()> {
    init_pack_logging();
    let pack = CredentialPack::load_runtime(pack_dir).map_err(pack_error)?;
    let active = ActiveCredentialSet::load_or_bootstrap(&pack).map_err(pack_error)?;
    let config = build_hub_config(&pack, &active, pack_dir)?;
    tracing::info!(
        listen = %config.server.listen_addr,
        tenants = config.auth.tenants.len(),
        "starting mesh hub from credential pack {}",
        pack.metadata.node
    );
    let plane = crate::hub::server::build_runtime_tls_plane(&config)?;
    let hub = HubServer::with_tls_plane(config, plane)?;
    let mut policy_watcher = spawn_hub_policy_reload(pack_dir, &hub)?;

    let shutdown = tokio_util::sync::CancellationToken::new();
    {
        let token = shutdown.clone();
        #[cfg(unix)]
        {
            use tokio::signal::unix::{SignalKind, signal};
            let mut sigint = signal(SignalKind::interrupt())?;
            let mut sigterm = signal(SignalKind::terminate())?;
            tokio::spawn(async move {
                tokio::select! {
                    _ = sigint.recv() => tracing::info!("received SIGINT, starting graceful shutdown"),
                    _ = sigterm.recv() => tracing::info!("received SIGTERM, starting graceful shutdown"),
                }
                token.cancel();
            });
        }
        #[cfg(not(unix))]
        {
            tokio::spawn(async move {
                if tokio::signal::ctrl_c().await.is_ok() {
                    tracing::info!("received Ctrl+C, starting graceful shutdown");
                    token.cancel();
                }
            });
        }
    }

    let (ready_tx, ready_rx) = tokio::sync::oneshot::channel();
    let hub_run = hub.run_until_signalled(shutdown, ready_tx);
    tokio::pin!(hub_run);
    // READY=1 once the TCP + QUIC listeners are bound (releases a
    // Type=notify start job; no-op outside systemd). A pre-bind failure
    // resolves the run instead.
    let started = tokio::select! {
        res = &mut hub_run => return res,
        ready = ready_rx => ready
            .map_err(|_| InterflowError::config("hub exited before signalling readiness")),
    };
    started?;
    interflow_util::systemd::notify_ready();

    tokio::select! {
        result = &mut hub_run => result,
        result = interflow_renewal::renewal_scheduler(pack_dir) => result,
        // The watcher only ever returns by panic — that is a structural
        // defect worth failing the process over rather than silently
        // freezing the policy channel.
        joined = &mut policy_watcher => {
            joined.map_err(|e| {
                InterflowError::config("hub policy watcher task failed").with_source(e)
            })?;
            Err(InterflowError::config(
                "hub policy watcher exited unexpectedly (no update loop exit exists)",
            ))
        }
    }
}

/// `interflow-mesh agent --pack <dir>`: engine + renewal scheduler with the
/// conventional agent signal semantics (SIGINT/SIGTERM/SIGHUP exit codes).
pub async fn run_agent(pack_dir: &Path) -> Result<()> {
    init_pack_logging();
    let pack = CredentialPack::load_runtime(pack_dir).map_err(pack_error)?;
    if pack.metadata.kind != PackKind::Agent {
        return Err(InterflowError::config(format!(
            "this is an {} pack — it cannot start as a mesh agent (role-bound)",
            pack.metadata.kind.as_str()
        )));
    }
    let active = ActiveCredentialSet::load_or_bootstrap(&pack).map_err(pack_error)?;
    let config = build_agent_config(&pack, &active, pack_dir)?;
    let hub_url = config.agent.hub_url.clone();
    let rules = config.ingress.len() + config.egress.len();
    let has_ingress_listeners = !config.ingress.is_empty();
    let client = crate::agent::AgentClient::new(config)?;
    let mut agent = client.clone().start();
    let mut policy_watcher = spawn_policy_reload(pack_dir, client, Some(agent.tunnel()))?;
    println!(
        "mesh agent {} started: {} rule(s) → {}",
        pack.metadata.node, rules, hub_url
    );

    // READY=1: agents dial out (nothing ever probed them), so readiness is
    // the local serving face — every configured ingress listener bound.
    // Hub connectivity stays out of the gate by design: sessions are
    // supervised reconnects, and the old install probes never gated on
    // them either. With no listeners the supervisor itself is the service.
    if has_ingress_listeners && !agent.wait_ingress_ready().await {
        return Err(InterflowError::connection(format!(
            "mesh agent {} stopped before its ingress listeners were bound",
            pack.metadata.node
        )));
    }
    interflow_util::systemd::notify_ready();

    let mut events = agent.take_events();
    let pump = tokio::spawn(async move {
        use crate::agent::AgentEvent;
        while let Some(ev) = events.recv().await {
            match ev {
                AgentEvent::StateChanged(state) => {
                    tracing::info!(state = ?state, "agent state changed");
                }
                AgentEvent::SessionEstablished { agent_id } => {
                    tracing::info!(agent_id, "session established");
                }
                AgentEvent::SessionEnded { reason } => {
                    tracing::info!(reason, "session ended");
                }
            }
        }
    });

    // Renewal scheduler runs beside the engine: its completion (renewal or
    // CRL update) is a clean restart cycle; signals exit with the
    // conventional codes.
    let scheduler_pack_dir = pack_dir.to_owned();
    let mut scheduler =
        tokio::spawn(
            async move { interflow_renewal::renewal_scheduler(&scheduler_pack_dir).await },
        );
    tokio::select! {
        () = wait_for_shutdown_signal() => {
            policy_watcher.abort();
            pump.abort();
            if let Err(e) = agent.shutdown_graceful().await {
                tracing::error!("graceful shutdown failed: {e}");
            }
            // Exit codes preserved from the TOML-face binary semantics.
            std::process::exit(130)
        }
        joined = &mut scheduler => {
            policy_watcher.abort();
            pump.abort();
            agent.shutdown_graceful().await?;
            joined.map_err(|e| {
                InterflowError::config("renewal scheduler task failed").with_source(e)
            })??;
            Ok(())
        }
        // The watcher only ever returns by panic — fail the process rather
        // than silently freezing the policy channel.
        joined = &mut policy_watcher => {
            pump.abort();
            agent.shutdown_graceful().await?;
            joined.map_err(|e| {
                InterflowError::config("policy watcher task failed").with_source(e)
            })?;
            Err(InterflowError::config(
                "policy watcher exited unexpectedly (no update loop exit exists)",
            ))
        }
    }
}

/// Waits for a shutdown signal (SIGINT/SIGTERM/SIGHUP on Unix).
async fn wait_for_shutdown_signal() {
    #[cfg(unix)]
    {
        use tokio::signal::unix::{SignalKind, signal};
        let mut sigint = signal(SignalKind::interrupt()).expect("SIGINT handler");
        let mut sigterm = signal(SignalKind::terminate()).expect("SIGTERM handler");
        let mut sighup = signal(SignalKind::hangup()).expect("SIGHUP handler");
        tokio::select! {
            _ = sigint.recv() => {},
            _ = sigterm.recv() => {},
            _ = sighup.recv() => {},
        }
    }
    #[cfg(not(unix))]
    {
        let _ = tokio::signal::ctrl_c().await;
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use interflow_identity::issuance::IssuerStore;
    use interflow_identity::manifest::Manifest;
    use interflow_identity::pack::render::{AgentCredentialPack, HubCredentialPack};

    fn cross_workspace_manifest(endpoint: &str, listen: &str) -> Manifest {
        Manifest::parse(&format!(
            r#"
[realm]
id = "test"
[registrar]
endpoint = "https://registrar.example.com"
[mesh.hub.central]
listen = "{listen}"
endpoint = "{endpoint}"
[workspace.alpha]
[workspace.beta]
[agent.lan-a]
workspace = "alpha"
[[agent.lan-a.mesh_ingress]]
name = "svc"
listen = "127.0.0.1:3001"
target_agent = "lan-b"
remote_addr = "127.0.0.1:3000"
[agent.lan-b]
workspace = "beta"
[[agent.lan-b.mesh_egress]]
name = "svc"
target_addr = "127.0.0.1:3000"
"#
        ))
        .unwrap()
    }

    fn issuer(tmp: &tempfile::TempDir) -> IssuerStore {
        let issuer = IssuerStore::open(tmp.path().join("issuer"));
        issuer.ensure_realm().unwrap();
        issuer.ensure_workspace("alpha").unwrap();
        issuer.ensure_workspace("beta").unwrap();
        issuer.ensure_policy_key().unwrap();
        issuer
    }

    #[test]
    fn hub_config_derives_tenants_acl_and_tls_from_pack() {
        let tmp = tempfile::tempdir().unwrap();
        let issuer = issuer(&tmp);
        let manifest = cross_workspace_manifest("hub.example.com:6666", "0.0.0.0:6666");
        let out = tmp.path().join("packs/hub-central");
        HubCredentialPack::render(&issuer, &manifest, "central", 1, &out).unwrap();
        let pack = CredentialPack::load_runtime(&out).unwrap();
        let active = ActiveCredentialSet::load_or_bootstrap(&pack).unwrap();

        let config = build_hub_config(&pack, &active, &out).unwrap();
        assert_eq!(
            config.server.listen_addr,
            "0.0.0.0:6666".parse::<SocketAddr>().unwrap()
        );
        // Tenant table: one issuer-anchored entry per workspace (plus the
        // reserved control tenant), paths inside the pack.
        let mut names: Vec<&str> = config
            .auth
            .tenants
            .iter()
            .map(|t| t.name.as_str())
            .collect();
        names.sort_unstable();
        assert_eq!(names, vec!["alpha", "beta", "control"]);
        for tenant in &config.auth.tenants {
            assert!(
                tenant.ca_path.contains("trust/workspace-")
                    || tenant.ca_path.contains("trust/control.crt"),
                "unexpected tenant anchor: {}",
                tenant.ca_path
            );
            assert!(!tenant.trusted_gateway);
        }
        // Cross-workspace stream → one ACL rule; same-workspace needs none.
        assert_eq!(config.acl.rules.len(), 1);
        let rule = config.acl.rules.iter().next().unwrap();
        assert_eq!(rule.source_tenant, "alpha");
        assert_eq!(rule.target_tenant, "beta");
        assert_eq!(rule.target, "lan-b");
        // Server credential from the active control identity; modern TLS.
        let tls = config.tls.as_ref().unwrap();
        assert!(tls.cert_path.contains("state/credentials"));
        assert_eq!(tls.min_version, TlsMinVersion::V1_3);

        assert_eq!(config.policy.generation, 1);
        assert!(config.policy.verifier_key_hex.is_some());
        // Same-workspace deployments stay isolated with an empty rule set.
        let same = Manifest::parse(
            r#"
[realm]
id = "test"
[registrar]
endpoint = "https://registrar.example.com"
[mesh.hub.central]
endpoint = "hub.example.com:6666"
[workspace.alpha]
[agent.lan-a]
workspace = "alpha"
[[agent.lan-a.mesh_ingress]]
name = "svc"
listen = "127.0.0.1:3001"
target_agent = "lan-b"
remote_addr = "127.0.0.1:3000"
[agent.lan-b]
workspace = "alpha"
[[agent.lan-b.mesh_egress]]
name = "svc"
target_addr = "127.0.0.1:3000"
"#,
        )
        .unwrap();
        let out2 = tmp.path().join("packs/hub-same");
        HubCredentialPack::render(&issuer, &same, "central", 1, &out2).unwrap();
        let pack2 = CredentialPack::load_runtime(&out2).unwrap();
        let active2 = ActiveCredentialSet::load_or_bootstrap(&pack2).unwrap();
        let config2 = build_hub_config(&pack2, &active2, &out2).unwrap();
        assert!(config2.acl.rules.is_empty());
        assert_eq!(config2.auth.tenants.len(), 2, "alpha + control");
    }

    #[test]
    fn agent_config_maps_rules_anchors_and_allowlist() {
        let tmp = tempfile::tempdir().unwrap();
        let issuer = issuer(&tmp);
        let manifest = cross_workspace_manifest("hub.example.com:6666", "0.0.0.0:6666");
        let out = tmp.path().join("packs/agent-lan-a");
        AgentCredentialPack::render(&issuer, &manifest, "lan-a", 1, &out).unwrap();
        let pack = CredentialPack::load_runtime(&out).unwrap();
        let active = ActiveCredentialSet::load_or_bootstrap(&pack).unwrap();

        let config = build_agent_config(&pack, &active, &out).unwrap();
        assert_eq!(config.agent.id, "lan-a");
        assert_eq!(config.agent.hub_url, "https://hub.example.com:6666");
        assert_eq!(config.ingress.len(), 1);
        // Cross-workspace target is tenant-qualified on the wire.
        assert_eq!(config.ingress[0].target_agent, "beta/lan-b");
        assert_eq!(
            config.ingress[0].remote_addr.as_deref(),
            Some("127.0.0.1:3000")
        );
        assert_eq!(
            config.security.allowed_targets,
            Vec::<String>::new(),
            "lan-a offers no egress rule"
        );
        // Outer plane: hub anchor is the realm issuer; client pair from the
        // active sequence.
        let tls = config.tls.as_ref().unwrap();
        assert!(
            tls.ca_path
                .as_deref()
                .unwrap()
                .ends_with("trust/control.crt")
        );
        assert!(
            tls.client_cert_path
                .as_ref()
                .unwrap()
                .contains("state/credentials")
        );
        // Inner plane: own workspace anchor + cross-workspace peer; the
        // realm anchor must not appear.
        assert!(
            config
                .inner_tls
                .ingress_ca_path
                .as_deref()
                .unwrap()
                .ends_with("trust/workspace-alpha.crt")
        );
        assert_eq!(config.inner_tls.extra_trusted_cas.len(), 1);
        assert!(config.inner_tls.extra_trusted_cas[0].ends_with("trust/workspace-beta.crt"));

        // The egress side carries the allowlist.
        let out_b = tmp.path().join("packs/agent-lan-b");
        AgentCredentialPack::render(&issuer, &manifest, "lan-b", 1, &out_b).unwrap();
        let pack_b = CredentialPack::load_runtime(&out_b).unwrap();
        let active_b = ActiveCredentialSet::load_or_bootstrap(&pack_b).unwrap();
        let config_b = build_agent_config(&pack_b, &active_b, &out_b).unwrap();
        assert_eq!(config_b.egress.len(), 1);
        assert_eq!(
            config_b.security.allowed_targets,
            vec!["127.0.0.1:3000".to_owned()]
        );
        assert_eq!(config_b.ingress.len(), 0);

        // An expose agent pack has no mesh rules: clean startup error.
        let expose = Manifest::parse(
            r#"
[realm]
id = "test"
control_endpoint = "relay.example.com"
[registrar]
endpoint = "https://registrar.example.com"
[workspace.alpha]
[agent.desktop]
workspace = "alpha"
[[agent.desktop.services]]
id = "web"
address = "127.0.0.1:18080"
[ingress.edge]
workspaces = ["alpha"]
[[route]]
host = "web.example.com"
service = "alpha/desktop/web"
"#,
        )
        .unwrap();
        let out_d = tmp.path().join("packs/agent-desktop");
        AgentCredentialPack::render(&issuer, &expose, "desktop", 1, &out_d).unwrap();
        let pack_d = CredentialPack::load_runtime(&out_d).unwrap();
        let active_d = ActiveCredentialSet::load_or_bootstrap(&pack_d).unwrap();
        let err = build_agent_config(&pack_d, &active_d, &out_d).unwrap_err();
        assert!(err.to_string().contains("expose agent"), "{err}");
    }
}
