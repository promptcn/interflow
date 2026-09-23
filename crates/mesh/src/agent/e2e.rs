//! The e2e (agent↔agent inner TLS) runtime: startup assembly of the shared
//! material plus the per-stream role entry points used by ingress/egress.
//!
//! RFC (internal design notes). Everything here is
//! startup-only (no hot reload): the material is the `[tls]` client pair
//! plus the merged anchor set. Anchor selection: when dedicated inner
//! anchors (`[inner_tls] ingress_ca_path` / `extra_trusted_cas`) are
//! configured, exactly those anchor the inner plane — pack-driven
//! bootstrap uses this to keep the outer hub anchor (the realm issuer)
//! out of the agent↔agent plane. Otherwise the single-CA model applies:
//! `[tls] ca_path` anchors both planes, the same file the agent already
//! holds for the hub plane; no new key material is introduced either way.

use crate::config::AgentConfig;
use interflow_core::error::Result;
use interflow_core::tls::{
    InnerTlsMaterial, classify_handshake_error, inner_client_config, inner_quic_client_config,
    inner_server_config_unbound,
};
use std::collections::HashMap;
use std::sync::Arc;
use std::sync::Mutex;
use std::time::Duration;
use tokio_rustls::TlsAcceptor;
use tokio_rustls::TlsConnector;
use tokio_rustls::rustls::ClientConfig;

/// Metric family: successful inner handshakes.
pub(crate) const METRIC_HANDSHAKES: &str = "interflow_agent_e2e_handshakes_total";
/// Metric family: failed/absent inner handshakes, with a coarse cause.
pub(crate) const METRIC_HANDSHAKE_FAILURES: &str = "interflow_agent_e2e_handshake_failures_total";

/// Stream side labels for the metric families above.
pub(crate) const SIDE_INGRESS: &str = "ingress";
pub(crate) const SIDE_EGRESS: &str = "egress";

/// The stream never asked for e2e (no `FLAG_E2E`) while this side runs
/// `required` — a stripped-flag downgrade, closed fail-closed (RFC §4/A5).
pub(crate) const REASON_NOT_NEGOTIATED: &str = "not_negotiated";

pub(crate) fn record_handshake_ok(side: &'static str) {
    metrics::counter!(METRIC_HANDSHAKES, "side" => side).increment(1);
}

pub(crate) fn record_handshake_failure(side: &'static str, reason: &'static str) {
    metrics::counter!(METRIC_HANDSHAKE_FAILURES, "side" => side, "reason" => reason).increment(1);
}

/// Coarse failure bucket from the handshake error (timeout decided by the
/// caller — the deadline wrapper has no rustls error to classify).
pub(crate) fn failure_reason_of(error: &std::io::Error) -> &'static str {
    if error.kind() == std::io::ErrorKind::TimedOut {
        "timeout"
    } else {
        classify_handshake_error(error)
    }
}

/// The bare agent id from a possibly tenant-qualified one
/// (`"tenant/agent"` → `"agent"`; a bare id passes through). Both the
/// ingress rule target and the egress-side Open source arrive qualified on
/// the wire; the inner-layer CN binding is the bare id (same as the hub's
/// identity binding).
pub(crate) fn bare_agent_id(id: &str) -> &str {
    id.rsplit_once('/').map_or(id, |(_, bare)| bare)
}

/// Per-agent mandatory inner-TLS state assembled once at startup.
pub struct E2eRuntime {
    /// Handshake deadline for both roles (RFC §3.5).
    pub handshake_timeout: Duration,
    material: Arc<InnerTlsMaterial>,
    source_principal: String,
    quic_client_configs: Arc<Mutex<HashMap<String, Arc<ClientConfig>>>>,
}

impl E2eRuntime {
    /// Assembles the runtime from the validated agent config. The
    /// prerequisites (tls pair + ca_path) are enforced by config validation;
    /// failure here is a startup error, not per-stream.
    pub fn from_config(cfg: &AgentConfig) -> Result<Arc<Self>> {
        let Some(tls) = cfg.tls.as_ref() else {
            return Err(interflow_core::error::InterflowError::config(
                "inner TLS requires [tls] (validator bypassed?)",
            ));
        };
        let (Some(cert), Some(key)) = (&tls.client_cert_path, &tls.client_key_path) else {
            return Err(interflow_core::error::InterflowError::config(
                "inner TLS requires the [tls] client pair (validator bypassed?)",
            ));
        };
        let mut anchors: Vec<String> = Vec::new();
        if cfg.inner_tls.ingress_ca_path.is_some() || !cfg.inner_tls.extra_trusted_cas.is_empty() {
            // Dedicated inner anchors are authoritative: the outer hub
            // anchor (`[tls] ca_path`) must not leak into the peer plane.
            if let Some(gw) = &cfg.inner_tls.ingress_ca_path {
                anchors.push(gw.clone());
            }
            anchors.extend(cfg.inner_tls.extra_trusted_cas.iter().cloned());
        } else {
            // Single-CA model (engine default): the hub-plane CA anchors
            // both planes.
            if let Some(ca) = &tls.ca_path {
                anchors.push(ca.clone());
            }
        }
        let refs: Vec<&str> = anchors.iter().map(String::as_str).collect();
        let mut crls = Vec::new();
        for path in &cfg.inner_tls.crl_paths {
            crls.push(interflow_core::tls::load_crl(path)?);
        }
        let material = InnerTlsMaterial::from_paths_with_crls(&refs, cert, key, &crls)?;
        Ok(Arc::new(Self {
            handshake_timeout: Duration::from_secs(cfg.inner_tls.handshake_timeout_secs),
            material: Arc::new(material),
            source_principal: bare_agent_id(&cfg.agent.id).to_owned(),
            quic_client_configs: Arc::default(),
        }))
    }

    /// Inner TLS client connector for one stream (ingress role): the
    /// expected peer CN is the Open target's bare agent id.
    pub(crate) fn client_connector(&self, expected_peer_cn: &str) -> Result<TlsConnector> {
        Ok(TlsConnector::from(Arc::new(inner_client_config(
            &self.material,
            expected_peer_cn,
        )?)))
    }

    /// Source-opaque inner TLS acceptor. Chain verification still happens in
    /// the handshake; the encrypted [`InnerStreamHello`] binds CN and
    /// fingerprint immediately after establishment.
    pub fn server_acceptor_unbound(&self) -> Result<TlsAcceptor> {
        Ok(TlsAcceptor::from(Arc::new(inner_server_config_unbound(
            &self.material,
        )?)))
    }

    /// Startup-assembled inner TLS material used by the UDP inner QUIC layer.
    pub(crate) const fn material(&self) -> &Arc<InnerTlsMaterial> {
        &self.material
    }

    pub(crate) fn source_principal(&self) -> &str {
        &self.source_principal
    }

    /// Returns a reusable inner QUIC client config for one expected peer.
    ///
    /// Cloning rustls config preserves its session-store `Arc`, so association
    /// rebuilds can resume while the CN-specific cache remains isolated.
    pub(crate) fn quic_client_config(&self, expected_peer_cn: &str) -> Result<ClientConfig> {
        let mut cache = self
            .quic_client_configs
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if let Some(config) = cache.get(expected_peer_cn) {
            return Ok((**config).clone());
        }
        let config = Arc::new(inner_quic_client_config(&self.material, expected_peer_cn)?);
        if cache.len() >= 128 {
            cache.clear();
        }
        cache.insert(expected_peer_cn.to_owned(), Arc::clone(&config));
        Ok((*config).clone())
    }

    /// Fingerprint of the leaf certificate this principal presents.
    pub fn local_fingerprint(&self) -> [u8; 32] {
        self.material.leaf_fingerprint()
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn bare_agent_id_strips_tenant_prefix() {
        assert_eq!(bare_agent_id("acme/api-1"), "api-1");
        assert_eq!(bare_agent_id("_edge/edge"), "edge");
        assert_eq!(bare_agent_id("api-1"), "api-1");
    }
}
