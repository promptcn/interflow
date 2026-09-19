//! The e2e (agent↔agent inner TLS) runtime: startup assembly of the shared
//! material plus the per-stream role entry points used by ingress/egress.
//!
//! RFC docs/design/agent-e2e-encryption.md. Everything here is
//! startup-only (no hot reload): the material is the `[tls]` client pair
//! plus the merged anchor set (`[tls] ca_path` ∪ `[e2e] gateway_ca_path` ∪
//! `[e2e] extra_trusted_cas` — the same file the agent already holds for
//! the hub plane; no new key material is introduced).

use crate::config::{AgentConfig, E2eMode};
use interflow_core::error::Result;
use interflow_core::tls::{
    InnerTlsMaterial, classify_handshake_error, inner_client_config, inner_server_config,
};
use std::sync::Arc;
use std::time::Duration;
use tokio_rustls::TlsAcceptor;
use tokio_rustls::TlsConnector;

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

/// Per-agent e2e state assembled once at startup; `None` (via
/// [`E2eRuntime::from_config`]) when the mode is off.
pub struct E2eRuntime {
    /// The configured mode (fail-closed semantics only exist for
    /// `required`; `opportunistic` is the migration window).
    pub mode: E2eMode,
    /// Handshake deadline for both roles (RFC §3.5).
    pub handshake_timeout: Duration,
    material: Arc<InnerTlsMaterial>,
}

impl E2eRuntime {
    /// Assembles the runtime from the validated agent config; `Ok(None)`
    /// when e2e is off. The prerequisites (tls pair + ca_path) are enforced
    /// by config validation — fail here is a startup error, not per-stream.
    pub fn from_config(cfg: &AgentConfig) -> Result<Option<Arc<Self>>> {
        if !cfg.e2e.enabled() {
            return Ok(None);
        }
        let Some(tls) = cfg.tls.as_ref() else {
            return Err(interflow_core::error::InterflowError::config(
                "[e2e] enabled without [tls] (validator bypassed?)",
            ));
        };
        let (Some(cert), Some(key)) = (&tls.client_cert_path, &tls.client_key_path) else {
            return Err(interflow_core::error::InterflowError::config(
                "[e2e] enabled without the [tls] client pair (validator bypassed?)",
            ));
        };
        let mut anchors: Vec<String> = Vec::new();
        if let Some(ca) = &tls.ca_path {
            anchors.push(ca.clone());
        }
        if let Some(gw) = &cfg.e2e.gateway_ca_path {
            anchors.push(gw.clone());
        }
        anchors.extend(cfg.e2e.extra_trusted_cas.iter().cloned());
        let refs: Vec<&str> = anchors.iter().map(String::as_str).collect();
        let material = InnerTlsMaterial::from_paths(&refs, cert, key)?;
        Ok(Some(Arc::new(Self {
            mode: cfg.e2e.mode,
            handshake_timeout: Duration::from_secs(cfg.e2e.handshake_timeout_secs),
            material: Arc::new(material),
        })))
    }

    /// Inner TLS client connector for one stream (ingress role): the
    /// expected peer CN is the Open target's bare agent id.
    pub fn client_connector(&self, expected_peer_cn: &str) -> Result<TlsConnector> {
        Ok(TlsConnector::from(Arc::new(inner_client_config(
            &self.material,
            expected_peer_cn,
        )?)))
    }

    /// Inner TLS server acceptor for one stream (egress role): the
    /// expected client CN is the Open frame's declared source agent.
    pub fn server_acceptor(&self, expected_client_cn: &str) -> Result<TlsAcceptor> {
        Ok(TlsAcceptor::from(Arc::new(inner_server_config(
            &self.material,
            expected_client_cn,
        )?)))
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
