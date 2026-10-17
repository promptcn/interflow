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
    EgressTarget, HubConfig, HubQuicConfig, HubTlsConfig, HubTransportConfig, IngressRule,
    InnerTlsConfig, PolicyPlaneConfig, ServerConfig, TenantConfig, TransportKind,
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
    // CRLs: the identity tier statically pins the source directory
    // (registrar: state/crls live refresh; offline: trust/crls snapshot —
    // missing snapshot there fails loud as a render defect).
    let mut tenants = Vec::new();
    for name in pack.trust.metadata.issuers.keys() {
        let Some(workspace) = name.strip_prefix("workspace/") else {
            continue;
        };
        let anchor = trust_dir.join(format!("{}.crt", name.replace('/', "-")));
        let crl = interflow_identity::pack::crl_path_for(
            pack_dir,
            pack.metadata.identity_mode,
            &name.replace('/', "-"),
        )
        .map_err(pack_error)?;
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
    let control_crl =
        interflow_identity::pack::crl_path_for(pack_dir, pack.metadata.identity_mode, "control")
            .map_err(pack_error)?;
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
    // The renderer always writes `listen` on a hub pack; a missing value is
    // a pre-2026-10 pack — fail loudly with the recovery action instead of
    // silently binding a default address.
    let listen: SocketAddr = pack
        .node_config
        .listen
        .as_deref()
        .ok_or_else(|| {
            config_error(
                "hub pack node.toml carries no listen address — re-render the pack \
                 (interflow-cli plan apply); the silent 0.0.0.0:6666 fallback is retired",
            )
        })?
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

    // The QUIC face is the manifest's opt-in: a signed `quic_listen` means
    // enabled, bound exactly there (same port number as the TCP listen is
    // the convention, different stack). Validation upstream already
    // rejected loopback/port-0 forms; this leg is parse only.
    let transport = match &pack.node_config.quic_listen {
        Some(raw) => HubTransportConfig {
            quic: HubQuicConfig {
                enabled: true,
                listen_addr: Some(raw.parse().map_err(|e| {
                    config_error(format!("hub quic_listen address {raw:?} is invalid"))
                        .with_source(e)
                })?),
                ..HubQuicConfig::default()
            },
            ..HubTransportConfig::default()
        },
        None => HubTransportConfig::default(),
    };

    let config = HubConfig {
        server: ServerConfig {
            listen_addr: listen,
            // Log attribution for embedders hosting several nodes in one
            // process (the GUI keys captured events on this name).
            node_name: Some(pack.metadata.node.clone()),
            // The declared identity the control-plane answer self-reports;
            // survives the GUI's `node_name` overwrite above.
            hub_name: Some(pack.metadata.node.clone()),
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
        transport,
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
            // The ACL hot-swap watcher runs intrinsically from this — the
            // config, not the embedder, declares the capability.
            pack_dir: Some(pack_dir.to_owned()),
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
                 with `interflow-cli agent run --pack`",
        )
    })?;
    let trust_dir = pack_dir.join("trust");

    let (cert, key) = active
        .material_paths(&format!("agent-{workspace}"))
        .map_err(pack_error)?;

    // Inner peer anchors: the agent's own workspace plus every peer
    // workspace riding in the trust bundle (cross-worksite flows). The hub
    // plane anchor (the realm issuer) stays out of the inner set. The CRL
    // source follows the identity tier (static, never probed).
    let own_anchor = trust_dir.join(format!("workspace-{workspace}.crt"));
    let mut extra_trusted_cas = Vec::new();
    let mut crl_paths = Vec::new();
    for name in pack.trust.metadata.issuers.keys() {
        let Some(peer) = name.strip_prefix("workspace/") else {
            continue;
        };
        let anchor = trust_dir.join(format!("{}.crt", name.replace('/', "-")));
        if let Some(crl) = interflow_identity::pack::crl_path_for(
            pack_dir,
            pack.metadata.identity_mode,
            &name.replace('/', "-"),
        )
        .map_err(pack_error)?
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

    // The canonical dial default rides node.toml verbatim (render-time
    // resolved: "h2" / "quic", never absent); `quic` derives the hub's UDP
    // dial address from the signed hub endpoint (manifest validation already
    // required its explicit port — this leg stays total for hand-built packs
    // by failing loud).
    let transport = TransportKind::parse_dial(Some(pack.node_config.transport.as_str()))
        .map_err(config_error)?;
    let hub_quic_addr = (transport == TransportKind::Quic)
        .then(|| {
            derive_quic_addr(&mesh.hub_endpoint).ok_or_else(|| {
                config_error(format!(
                    "[agent] transport = \"quic\" requires a hub endpoint carrying an explicit \
                     port — the QUIC dial address derives from it (got {:?})",
                    mesh.hub_endpoint
                ))
            })
        })
        .transpose()?;

    let config = AgentConfig {
        agent: AgentInfo {
            id: pack.metadata.node.clone(),
            hub_url: normalize_endpoint(&mesh.hub_endpoint),
            transport,
            hub_quic_addr,
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
        // The signed-policy plane rides the config itself: the engine's
        // start path spawns the watcher from this field — the pack pipeline
        // declares the capability, no embedding surface wires it.
        policy: Some(PolicyPlaneConfig {
            pack_dir: pack_dir.to_owned(),
        }),
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

/// Derives the hub's QUIC (UDP) dial address from a signed hub endpoint.
///
/// Scheme stripped, host kept verbatim (IPv6 keeps its brackets), explicit
/// port required — `None` when the endpoint carries none (implicit 80/443
/// cannot be assumed for UDP). Manifest validation rejects that
/// combination upstream; this stays total for engine-TOML callers. The
/// single source for both the headless pack path and the GUI preference
/// fallback.
#[must_use]
pub fn derive_quic_addr(endpoint: &str) -> Option<String> {
    let no_scheme = endpoint
        .trim()
        .trim_start_matches("https://")
        .trim_start_matches("http://");
    if let Some((host, tail)) = no_scheme
        .strip_prefix('[')
        .and_then(|rest| rest.split_once(']'))
    {
        // IPv6: [::1]:port
        let port = tail.trim_start_matches(':');
        return (!port.is_empty()).then(|| format!("[{host}]:{port}"));
    }
    match no_scheme.rsplit_once(':') {
        Some((_, port)) if !port.is_empty() && port.bytes().all(|b| b.is_ascii_digit()) => {
            Some(no_scheme.to_string())
        }
        _ => None,
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

/// Spawns the signed-policy reload watcher for a running hub.
///
/// Swaps the cross-workspace admission table under the shared-config lock
/// (effective on the next Open — never a listener rebuild). Same fail-keep
/// contract as the agent watcher. Spawned onto `tracker` and ending with
/// `shutdown` — the hub's run future owns both, so the watcher is intrinsic
/// to a pack-built hub's lifecycle (no embedder wiring exists to forget).
pub(crate) fn spawn_hub_policy_reload(
    pack_dir: &Path,
    shared: crate::hub::SharedHubConfig,
    shutdown: &tokio_util::sync::CancellationToken,
    tracker: &tokio_util::task::TaskTracker,
) {
    let dir = pack_dir.to_owned();
    let shutdown = shutdown.clone();
    tracker.spawn(async move {
        let policy_dir = dir.join("state/policy");
        let mut fingerprint = policy_channel_fingerprint(&policy_dir);
        // The anti-rollback watermark; `None` = not yet armed (the pack was
        // unreadable at spawn — retried each tick, a torn update defers the
        // plane instead of killing it).
        let mut seen: Option<u64> = None;
        loop {
            tokio::select! {
                () = shutdown.cancelled() => return,
                () = tokio::time::sleep(crate::agent::policy_watch::POLICY_WATCH_INTERVAL) => {}
            }
            let Some(watermark) = seen else {
                match CredentialPack::load_runtime(&dir) {
                    Ok(pack) => {
                        seen = Some(pack.policy.generation);
                        tracing::info!(
                            build = %interflow_buildinfo::BUILD_TAG,
                            watermark = pack.policy.generation,
                            interval_secs =
                                crate::agent::policy_watch::POLICY_WATCH_INTERVAL.as_secs(),
                            "hub policy watcher armed (cross-workspace admission hot-swap)"
                        );
                    }
                    Err(e) => {
                        tracing::debug!(
                            "hub policy watcher: pack unreadable, arming deferred: {}",
                            interflow_util::format_chain(&pack_error(e))
                        );
                    }
                }
                continue;
            };
            let current = policy_channel_fingerprint(&policy_dir);
            if current == fingerprint {
                continue;
            }
            fingerprint = current;
            let Ok(pack) = CredentialPack::load_runtime(&dir) else {
                tracing::warn!(
                    "hub policy reload: pack reload failed (torn update?), keeping current \
                     policy"
                );
                continue;
            };
            match pack.policy_update(watermark) {
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
                    seen = Some(generation);
                }
                Ok(None) => {}
                Err(e) => {
                    tracing::warn!(
                        "hub policy reload: rejecting update (keeping current policy): {e}"
                    );
                }
            }
        }
    });
}

/// Spawns a signed-policy watcher for embedding surfaces.
///
/// Every policy the node-local channel applies (verified +
/// anti-rollback-checked through the same pack-load funnel the hub's own
/// reload runs) is handed to `apply`. The expose edge's host-routing
/// hot-swap rides this — the engine crate keeps its "no identity-crate
/// dependency" layering while still reacting to verified generations (the
/// callback receives the already-trusted type through this crate's API
/// surface).
pub fn spawn_policy_apply_watch(
    pack_dir: &Path,
    shutdown: &tokio_util::sync::CancellationToken,
    log_name: &str,
    apply: impl Fn(&RuntimePolicy) + Send + Sync + 'static,
) {
    let dir = pack_dir.to_owned();
    let shutdown = shutdown.clone();
    let log_name = log_name.to_owned();
    tokio::spawn(async move {
        let policy_dir = dir.join("state/policy");
        let mut fingerprint = policy_channel_fingerprint(&policy_dir);
        let mut seen: Option<u64> = None;
        loop {
            tokio::select! {
                () = shutdown.cancelled() => return,
                () = tokio::time::sleep(crate::agent::policy_watch::POLICY_WATCH_INTERVAL) => {}
            }
            let Some(watermark) = seen else {
                if let Ok(pack) = CredentialPack::load_runtime(&dir) {
                    seen = Some(pack.policy.generation);
                }
                continue;
            };
            let current = policy_channel_fingerprint(&policy_dir);
            if current == fingerprint {
                continue;
            }
            fingerprint = current;
            let Ok(pack) = CredentialPack::load_runtime(&dir) else {
                tracing::warn!(
                    node = %log_name,
                    "policy apply watch: pack reload failed (torn update?), keeping current"
                );
                continue;
            };
            match pack.policy_update(watermark) {
                Ok(Some(update)) => {
                    let generation = update.policy.generation;
                    apply(&update.policy);
                    seen = Some(generation);
                    tracing::info!(
                        node = %log_name,
                        generation,
                        "policy apply watch: handed verified generation to the embedder"
                    );
                }
                Ok(None) => {}
                Err(e) => {
                    tracing::warn!(
                        node = %log_name,
                        "policy apply watch: rejecting update (keeping current): {e}"
                    );
                }
            }
        }
    });
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

/// Derives an expose agent's egress rules from the signed policy's service
/// list (`agent == node`) × the node-side address table.
///
/// One rule per service, named by the id (the edge's
/// `TargetSelector::Service(id)` resolves against these names), target =
/// override ?? signed default ?? pack default.
///
/// A service id with no resolvable address is **skipped with a warning**,
/// not a rejection — a hot-added service on a legacy policy (no signed
/// address) and no pack entry simply waits for an address to arrive via
/// the override channel; the rest of the policy still applies
/// (fail-forward, not fail-closed: the id set is signed truth, the address
/// is a node fact). Single derivation for startup and hot reload, like
/// [`policy_egress_rules`].
pub fn policy_service_egress_rules(
    policy: &RuntimePolicy,
    node: &str,
    addresses: &crate::config::ServiceAddresses,
) -> Result<(Vec<EgressRule>, Vec<String>)> {
    let mut egress = Vec::new();
    let mut allowed_targets = Vec::new();
    for service in &policy.services {
        if service.agent != node {
            continue;
        }
        let Some(target) = addresses.resolve(&service.id, service.address.as_deref()) else {
            tracing::warn!(
                node,
                service = %service.id,
                "service declared by policy has no resolvable address (no override, no signed \
                 default, no pack default) — skipped until an address arrives"
            );
            continue;
        };
        allowed_targets.push(target.to_string());
        egress.push(EgressRule {
            name: service.id.clone(),
            target: EgressTarget::Addr(target),
            target_protocol: StreamProto::Tcp,
            udp_idle_timeout_secs: None,
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
    // The serving-lineage origin, stated at startup (2026-10-07 fix): a
    // reinstall that lost the node-local state channel used to be visible
    // only by reverse-engineering agent inverted-watermark WARNs. `state
    // lineage` = the node-local channel survived (the upgrade contract);
    // `pack snapshot` = serving from the embedded render (fresh install,
    // or a lineage loss — check whether state/ was expected to survive).
    tracing::info!(
        node = %pack.metadata.node,
        generation = pack.policy.generation,
        origin = if pack.policy_from_state_channel { "state lineage" } else { "pack snapshot" },
        "serving policy gen {} (from {})",
        pack.policy.generation,
        if pack.policy_from_state_channel { "state lineage" } else { "pack snapshot" },
    );
    let plane = crate::hub::server::build_runtime_tls_plane(&config)?;
    // Composition root: the hub process's one audit writer, spawned from
    // the pack-declared destination (config.audit is data; the spawn
    // decision lives here and here only).
    let audit = interflow_core::security::AuditSink::spawn(&config.audit);
    let hub = HubServer::with_tls_plane(config, plane, audit)?;
    // Captured before the run future consumes the server: the Arc fields
    // the CRL hot-swap hook acts on are the same ones the run's rebuilt
    // state carries.
    let hub_state_handle = hub.state_handle();
    // The signed-policy ACL watcher is intrinsic to the hub's run future
    // (the config's policy plane names the pack) — nothing to spawn or
    // select over here.

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

    // CRL updates from the pull lane hot-swap the verification plane in
    // place (the hub is the one fleet member whose TLS material may change
    // under it without a restart); credential renewals below still exit
    // onto the supervisor restart.
    let crl_state = hub_state_handle.clone();
    let crl_hook: interflow_renewal::CrlChangeHook = std::sync::Arc::new(move || {
        let crl_state = crl_state.clone();
        Box::pin(async move {
            match crate::hub::crl::reload_tls_plane(&crl_state).await {
                Ok(report) => tracing::info!(
                    evicted = ?report.evicted,
                    "crl_updated: verification plane hot-swapped (no restart)"
                ),
                Err(e) => tracing::error!("crl_reload_failed (the old plane keeps verifying): {e}"),
            }
        })
    });

    tokio::select! {
        result = &mut hub_run => result,
        result = interflow_renewal::renewal_scheduler_with_crl_reload(
            pack_dir,
            None,
            Some(crl_hook),
        ) => result,
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
    // The signed-policy watcher rides the engine itself (the config's
    // policy plane) — nothing to spawn or fail over here.
    let mut agent = crate::agent::AgentClient::new(config)?.start();
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
            pump.abort();
            if let Err(e) = agent.shutdown_graceful().await {
                tracing::error!("graceful shutdown failed: {e}");
            }
            // Exit codes preserved from the TOML-face binary semantics.
            std::process::exit(130)
        }
        joined = &mut scheduler => {
            pump.abort();
            agent.shutdown_graceful().await?;
            joined.map_err(|e| {
                InterflowError::config("renewal scheduler task failed").with_source(e)
            })??;
            Ok(())
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

    /// The hub's signed `quic_listen` maps onto the engine's QUIC face:
    /// absent keeps the h2-only default; present enables the listener at
    /// exactly the signed address.
    #[test]
    fn hub_config_opens_the_quic_face_from_the_signed_pack() {
        let tmp = tempfile::tempdir().unwrap();
        let issuer = issuer(&tmp);

        // Absent: the h2-only status quo.
        let plain = cross_workspace_manifest("hub.example.com:6666", "0.0.0.0:6666");
        let out = tmp.path().join("packs/hub-plain");
        HubCredentialPack::render(&issuer, &plain, "central", 1, &out).unwrap();
        let pack = CredentialPack::load_runtime(&out).unwrap();
        let active = ActiveCredentialSet::load_or_bootstrap(&pack).unwrap();
        let config = build_hub_config(&pack, &active, &out).unwrap();
        assert!(
            !config.transport.quic.enabled,
            "no signed quic_listen means the QUIC face stays closed"
        );
        assert_eq!(config.transport.quic.listen_addr, None);

        // Present: enabled, bound exactly at the signed address (same port
        // number as the TCP listen is the convention — different stack).
        let mut quic = cross_workspace_manifest("hub.example.com:6666", "0.0.0.0:6666");
        quic.mesh.hub.get_mut("central").unwrap().quic_listen = Some("0.0.0.0:6666".to_owned());
        let out2 = tmp.path().join("packs/hub-quic");
        HubCredentialPack::render(&issuer, &quic, "central", 1, &out2).unwrap();
        let pack2 = CredentialPack::load_runtime(&out2).unwrap();
        let active2 = ActiveCredentialSet::load_or_bootstrap(&pack2).unwrap();
        let config2 = build_hub_config(&pack2, &active2, &out2).unwrap();
        assert!(config2.transport.quic.enabled);
        assert_eq!(
            config2.transport.quic.listen_addr,
            Some("0.0.0.0:6666".parse::<SocketAddr>().unwrap())
        );
    }

    /// A mesh agent's signed transport default flows into the engine dial:
    /// `quic` carries the hub's UDP address, derived from the signed hub
    /// endpoint (scheme stripped); the absent default stays h2 with no
    /// QUIC address.
    #[test]
    fn agent_config_dials_quic_from_the_signed_default() {
        let tmp = tempfile::tempdir().unwrap();
        let issuer = issuer(&tmp);

        // Absent transport: h2 with no QUIC dial address.
        let plain = cross_workspace_manifest("hub.example.com:6666", "0.0.0.0:6666");
        let out = tmp.path().join("packs/agent-plain");
        AgentCredentialPack::render(&issuer, &plain, "lan-a", 1, &out).unwrap();
        let pack = CredentialPack::load_runtime(&out).unwrap();
        let active = ActiveCredentialSet::load_or_bootstrap(&pack).unwrap();
        let config = build_agent_config(&pack, &active, &out).unwrap();
        assert_eq!(config.agent.transport, TransportKind::H2);
        assert_eq!(config.agent.hub_quic_addr, None);

        // Quic default: the dial address derives from the signed hub
        // endpoint — the full-URL form proves the scheme strip.
        let mut quic = cross_workspace_manifest("https://hub.example.com:6666", "0.0.0.0:6666");
        quic.mesh.hub.get_mut("central").unwrap().quic_listen = Some("0.0.0.0:6666".to_owned());
        quic.agent.get_mut("lan-a").unwrap().transport =
            Some(interflow_identity::manifest::AgentTransport::Quic);
        let out2 = tmp.path().join("packs/agent-quic");
        AgentCredentialPack::render(&issuer, &quic, "lan-a", 1, &out2).unwrap();
        let pack2 = CredentialPack::load_runtime(&out2).unwrap();
        let active2 = ActiveCredentialSet::load_or_bootstrap(&pack2).unwrap();
        let config2 = build_agent_config(&pack2, &active2, &out2).unwrap();
        assert_eq!(config2.agent.transport, TransportKind::Quic);
        assert_eq!(
            config2.agent.hub_quic_addr.as_deref(),
            Some("hub.example.com:6666"),
            "the QUIC dial address is the signed endpoint, scheme stripped"
        );
        // A quic default against an implicit-port endpoint fails loud
        // (manifest validation normally prevents this; hand-built packs
        // still get a clear boot error).
        let mut implicit = cross_workspace_manifest("hub.example.com", "0.0.0.0:6666");
        implicit.agent.get_mut("lan-a").unwrap().transport =
            Some(interflow_identity::manifest::AgentTransport::Quic);
        let out3 = tmp.path().join("packs/agent-implicit");
        AgentCredentialPack::render(&issuer, &implicit, "lan-a", 1, &out3).unwrap();
        let pack3 = CredentialPack::load_runtime(&out3).unwrap();
        let active3 = ActiveCredentialSet::load_or_bootstrap(&pack3).unwrap();
        let err = build_agent_config(&pack3, &active3, &out3).unwrap_err();
        assert!(err.to_string().contains("explicit port"), "{err}");
    }

    #[test]
    fn quic_addr_derivation_strips_scheme_and_requires_a_port() {
        assert_eq!(
            derive_quic_addr("hub.example.com:6666").as_deref(),
            Some("hub.example.com:6666")
        );
        assert_eq!(
            derive_quic_addr("https://hub.example.com:6666").as_deref(),
            Some("hub.example.com:6666")
        );
        assert_eq!(
            derive_quic_addr("http://hub.example.com:6666").as_deref(),
            Some("hub.example.com:6666")
        );
        assert_eq!(
            derive_quic_addr("https://[2001:db8::1]:6666").as_deref(),
            Some("[2001:db8::1]:6666"),
            "IPv6 hosts keep their brackets"
        );
        assert_eq!(
            derive_quic_addr("hub.example.com"),
            None,
            "an implicit port cannot be assumed for UDP"
        );
    }
}
