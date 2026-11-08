//! The agent↔agent inner TLS layer (e2e encryption of tunnel payloads).
//!
//! Design: after the Open frame
//! and before any payload flows, the two agents run a TLS 1.3 handshake
//! *inside* the tunnel stream (handshake bytes ride the stream as ordinary
//! Data frames; the hub only ever sees ciphertext). Both sides present their
//! regular agent client certificate pair (leaf CN == agent id, no SAN, EKU
//! ClientAuth) — which is exactly why peer verification uses
//! **client-cert semantics** ([`WebPkiClientVerifier`]: chain anchoring,
//! validity, EKU — no SAN/server-name matching, same standard as the hub's
//! `tenant::derive`), plus the per-stream identity binding this layer adds:
//!
//! - the leaf CN must equal the agent id the stream *declares* for the peer
//!   (the Open frame's target on the ingress side, its source on the egress
//!   side) — a malicious hub cannot redirect, impersonate, or MITM without
//!   the offline CA's private key;
//! - the chain must anchor into this side's configured anchor set
//!   (own-tenant CA ∪ gateway anchor ∪ cross-tenant exception anchors).
//!
//! Handshake configs are derived per stream (the expected CN is per-stream),
//! TLS 1.3 only, session resumption disabled (the client's placeholder
//! [`INNER_SERVER_NAME`] is shared across peers — a resumed session would
//! skip certificate verification entirely; resumption is future work, RFC
//! §10.8), and 0-RTT/early data is not enabled (RFC §3.5: a relay-position
//! replay must yield nothing but a key the attacker cannot open).

use crate::error::{InterflowError, Result};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::sync::Arc;
use std::sync::{Mutex, OnceLock};
use tokio_rustls::rustls::ClientConfig;
use tokio_rustls::rustls::RootCertStore;
use tokio_rustls::rustls::ServerConfig;
use tokio_rustls::rustls::SignatureScheme;
use tokio_rustls::rustls::pki_types::CertificateDer;
use tokio_rustls::rustls::pki_types::PrivateKeyDer;
use tokio_rustls::rustls::pki_types::{CertificateRevocationListDer, UnixTime};
use tokio_rustls::rustls::server::WebPkiClientVerifier;
use tokio_rustls::rustls::server::danger::ClientCertVerifier;
use tokio_rustls::rustls::version::TLS13;

use super::server::extract_cn_from_chain;

/// Placeholder server name for inner TLS client connections. The real
/// identity binding is the CN check (agent ids may contain `_` and are not
/// valid DNS names); the verifier ignores this value.
pub const INNER_SERVER_NAME: &str = "interflow-inner";
/// ALPN used by the UDP inner QUIC association.
pub const INNER_QUIC_ALPN: &str = "interflow-inner-quic-v1";

/// One side's complete inner-TLS material: the anchor set for verifying
/// peers plus our own certificate pair for presenting ourselves.
///
/// Assembled once at startup from the configuration (the agent's `[tls]`
/// pair is reused verbatim — no new key material); per-stream configs are
/// derived from it by [`inner_client_config`] / [`inner_server_config`].
/// (Not `Clone`: `PrivateKeyDer` is not cloneable as a whole; configs take
/// a `clone_key()` copy.)
///
/// Derived-config caches (2026-11-04 hot-path audit §2.1) are embedded in
/// the material itself: the anchor set, CRLs and own pair are material-wide
/// invariants, so every derived config is a pure function of
/// `(material, expected CN)` — rebuilt only on a cache miss and shared as
/// [`Arc`] afterwards. Invalidation is identity-keyed: a rebuilt material
/// (the expose edge's per-workspace sequence rotation) is a fresh instance
/// with fresh (empty) caches. Cache policy: per-CN maps hold at most
/// [`CONFIG_CACHE_CAP`] entries, cleared wholesale on overflow (deployment
/// agent counts are bounded; a cleared entry rebuilds on next use).
///
/// The per-stream **full handshake** security design is untouched: TCP
/// configs keep resumption disabled (the shared placeholder SNI makes a
/// resumed session skip verification), QUIC configs keep the per-CN
/// deterministic SNI with its isolated in-memory session store.
pub struct InnerTlsMaterial {
    /// The merged anchor set (own-tenant CA ∪ gateway anchor ∪ extra
    /// cross-tenant anchors) for verifying the peer's chain.
    pub roots: RootCertStore,
    /// CRLs applied to every inner peer verification.
    pub crls: Vec<CertificateRevocationListDer<'static>>,
    /// Our certificate pair (the regular agent client pair; leaf CN == agent
    /// id), presented to the peer during the inner handshake.
    pub cert_chain: Vec<CertificateDer<'static>>,
    /// The private key of [`Self::cert_chain`]'s leaf.
    pub key: PrivateKeyDer<'static>,
    /// The chain verifier shared by every derived config (anchor set + CRLs
    /// are material-wide): built once, wrapped per expected CN.
    webpki_verifier: OnceLock<Arc<dyn ClientCertVerifier>>,
    /// CN-agnostic server acceptor (TCP shape, no ALPN): identical for every
    /// stream, built once.
    unbound_server_config: OnceLock<Arc<ServerConfig>>,
    /// CN-agnostic server config carrying the inner-QUIC ALPN (the inner UDP
    /// association acceptor): built once.
    unbound_quic_server_config: OnceLock<Arc<ServerConfig>>,
    /// Per-expected-CN TCP client configs (ingress role).
    client_configs: Mutex<HashMap<String, Arc<ClientConfig>>>,
    /// Per-expected-CN QUIC client configs (inner UDP association role; the
    /// per-CN session store lives inside the shared config).
    quic_client_configs: Mutex<HashMap<String, Arc<ClientConfig>>>,
}

impl std::fmt::Debug for InnerTlsMaterial {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // The derived-config caches are summarized (the verifiers/configs
        // they hold are not Debug); every material field is represented.
        f.debug_struct("InnerTlsMaterial")
            .field("roots", &self.roots)
            .field("crls", &self.crls.len())
            .field("cert_chain", &self.cert_chain.len())
            .field("key", &"<private>")
            .field(
                "webpki_verifier",
                &self.webpki_verifier.get().map(|_| "built"),
            )
            .field(
                "unbound_server_config",
                &self.unbound_server_config.get().map(|_| "built"),
            )
            .field(
                "unbound_quic_server_config",
                &self.unbound_quic_server_config.get().map(|_| "built"),
            )
            .field(
                "client_configs",
                &self.client_configs.lock().map(|c| c.len()),
            )
            .field(
                "quic_client_configs",
                &self.quic_client_configs.lock().map(|c| c.len()),
            )
            .finish()
    }
}

/// Per-CN derived-config cache bound. Overflow clears the whole map (the
/// pre-existing `E2eRuntime` QUIC cache policy, now shared by every
/// derived-config kind).
const CONFIG_CACHE_CAP: usize = 128;

impl InnerTlsMaterial {
    /// Loads the material from disk: every entry of `anchor_paths` is merged
    /// into the anchor set (multi-certificate PEM semantics, same as the
    /// hub-plane CA loading), and `cert_path`/`key_path` is our own pair.
    pub fn from_paths(anchor_paths: &[&str], cert_path: &str, key_path: &str) -> Result<Self> {
        Self::from_paths_with_crls(anchor_paths, cert_path, key_path, &[])
    }

    pub fn from_paths_with_crls(
        anchor_paths: &[&str],
        cert_path: &str,
        key_path: &str,
        crls: &[CertificateRevocationListDer<'static>],
    ) -> Result<Self> {
        let mut roots = RootCertStore::empty();
        for path in anchor_paths {
            for cert in super::server::load_certs(path)? {
                let _ = roots.add(cert);
            }
        }
        if roots.is_empty() {
            return Err(InterflowError::config(
                "inner TLS: the anchor set is empty (no [tls].ca_path / gateway / extra anchors)",
            ));
        }
        let cert_chain = super::server::load_certs(cert_path)?;
        let key = super::server::load_key(key_path)?;
        Ok(Self::from_parts(roots, crls.to_vec(), cert_chain, key))
    }

    /// Assembles from already-loaded parts (the loader above, and tests
    /// that mint material in memory). The derived-config caches start
    /// empty; the shared verifier builds lazily on first use.
    pub(crate) fn from_parts(
        roots: RootCertStore,
        crls: Vec<CertificateRevocationListDer<'static>>,
        cert_chain: Vec<CertificateDer<'static>>,
        key: PrivateKeyDer<'static>,
    ) -> Self {
        Self {
            roots,
            crls,
            cert_chain,
            key,
            webpki_verifier: OnceLock::new(),
            unbound_server_config: OnceLock::new(),
            unbound_quic_server_config: OnceLock::new(),
            client_configs: Mutex::new(HashMap::new()),
            quic_client_configs: Mutex::new(HashMap::new()),
        }
    }

    /// The chain verifier shared by every derived config (anchor set + CRLs
    /// are material-wide invariants). Built once per material; per-CN
    /// verifiers are this [`Arc`] plus the expected-CN string.
    fn shared_webpki_verifier(&self) -> Result<&Arc<dyn ClientCertVerifier>> {
        if let Some(built) = self.webpki_verifier.get() {
            return Ok(built);
        }
        // Build outside the cell (a failure must not poison it), then race
        // the insertion — concurrent first users both build a valid
        // verifier; the loser's instance is simply dropped.
        let mut builder = WebPkiClientVerifier::builder(Arc::new(self.roots.clone()));
        if !self.crls.is_empty() {
            builder = builder.with_crls(self.crls.clone());
        }
        let built = builder.build().map_err(|e| {
            InterflowError::config("inner TLS verifier build failed".to_string()).with_source(e)
        })?;
        Ok(self.webpki_verifier.get_or_init(move || built))
    }

    /// Cached-map insertion with the shared overflow policy: at capacity the
    /// whole map clears (bounded agent populations; a cleared entry rebuilds
    /// on its next use).
    fn cache_insert<T>(cache: &Mutex<HashMap<String, Arc<T>>>, cn: &str, value: Arc<T>) -> Arc<T> {
        let mut map = cache
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if map.len() >= CONFIG_CACHE_CAP {
            map.clear();
        }
        let shared = Arc::clone(&value);
        map.insert(cn.to_owned(), value);
        shared
    }

    /// The cached per-CN TCP client config (ingress role). First use for a
    /// CN pays one full assembly; every later use is an [`Arc`] clone.
    pub fn client_config(&self, expected_peer_cn: &str) -> Result<Arc<ClientConfig>> {
        {
            let cache = self
                .client_configs
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            if let Some(hit) = cache.get(expected_peer_cn) {
                return Ok(Arc::clone(hit));
            }
        }
        let verifier = Arc::new(InnerPeerVerifier::new(
            Arc::clone(self.shared_webpki_verifier()?),
            Some(expected_peer_cn),
        ));
        let mut config = ClientConfig::builder_with_protocol_versions(&[&TLS13])
            .dangerous()
            .with_custom_certificate_verifier(verifier)
            .with_client_auth_cert(self.cert_chain.clone(), self.key.clone_key())
            .map_err(|e| {
                InterflowError::config("inner TLS client config error".to_string()).with_source(e)
            })?;
        // Placeholder server name is shared across all peers: a resumed session
        // would skip certificate verification. Disable resumption outright
        // (listed as future work in the RFC §10.8).
        config.resumption = tokio_rustls::rustls::client::Resumption::disabled();
        Ok(Self::cache_insert(
            &self.client_configs,
            expected_peer_cn,
            Arc::new(config),
        ))
    }

    /// The cached per-CN QUIC client config (inner UDP association role).
    /// The per-CN session store rides inside the shared config [`Arc`], so
    /// association rebuilds resume while CN isolation is preserved.
    pub fn quic_client_config(&self, expected_peer_cn: &str) -> Result<Arc<ClientConfig>> {
        {
            let cache = self
                .quic_client_configs
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            if let Some(hit) = cache.get(expected_peer_cn) {
                return Ok(Arc::clone(hit));
            }
        }
        let verifier = Arc::new(InnerPeerVerifier::new(
            Arc::clone(self.shared_webpki_verifier()?),
            Some(expected_peer_cn),
        ));
        let mut config = ClientConfig::builder_with_protocol_versions(&[&TLS13])
            .dangerous()
            .with_custom_certificate_verifier(verifier)
            .with_client_auth_cert(self.cert_chain.clone(), self.key.clone_key())
            .map_err(|e| {
                InterflowError::config("inner QUIC client config error".to_string()).with_source(e)
            })?;
        config.alpn_protocols = vec![INNER_QUIC_ALPN.as_bytes().to_vec()];
        config.resumption = tokio_rustls::rustls::client::Resumption::in_memory_sessions(64);
        config.enable_early_data = false;
        Ok(Self::cache_insert(
            &self.quic_client_configs,
            expected_peer_cn,
            Arc::new(config),
        ))
    }

    /// One-shot server-config assembly over the shared verifier (both unbound
    /// cache variants and the test-facing bound builder).
    fn build_server_config(&self, verifier: InnerPeerVerifier) -> Result<ServerConfig> {
        ServerConfig::builder_with_protocol_versions(&[&TLS13])
            .with_client_cert_verifier(Arc::new(verifier))
            .with_single_cert(self.cert_chain.clone(), self.key.clone_key())
            .map_err(|e| {
                InterflowError::config("inner TLS server config error".to_string()).with_source(e)
            })
    }

    /// The cached CN-agnostic server acceptor (TCP shape, no ALPN) — the
    /// egress role's per-stream acceptor is an [`Arc`] clone.
    pub fn unbound_server_config(&self) -> Result<&Arc<ServerConfig>> {
        if let Some(built) = self.unbound_server_config.get() {
            return Ok(built);
        }
        let verifier = InnerPeerVerifier::new(Arc::clone(self.shared_webpki_verifier()?), None);
        let built = Arc::new(self.build_server_config(verifier)?);
        Ok(self.unbound_server_config.get_or_init(move || built))
    }

    /// The cached CN-agnostic server config carrying the inner-QUIC ALPN —
    /// the inner UDP association acceptor.
    pub fn unbound_quic_server_config(&self) -> Result<&Arc<ServerConfig>> {
        if let Some(built) = self.unbound_quic_server_config.get() {
            return Ok(built);
        }
        let verifier = InnerPeerVerifier::new(Arc::clone(self.shared_webpki_verifier()?), None);
        let mut config = self.build_server_config(verifier)?;
        config.alpn_protocols = vec![INNER_QUIC_ALPN.as_bytes().to_vec()];
        let built = Arc::new(config);
        Ok(self.unbound_quic_server_config.get_or_init(move || built))
    }

    /// SHA-256 fingerprint of the leaf certificate presented by this side.
    pub fn leaf_fingerprint(&self) -> [u8; 32] {
        Sha256::digest(self.cert_chain.first().map_or(&[][..], |c| c.as_ref())).into()
    }
}

/// The per-stream peer verifier: client-cert-semantics chain validation
/// (delegated to [`WebPkiClientVerifier`] — signature methods included,
/// unlike the pinning verifier's assertions) plus the CN identity binding.
///
/// One type serves both roles (the ingress verifies the egress's server
/// certificate via [`ServerCertVerifier`], the egress verifies the
/// ingress's client certificate via [`ClientCertVerifier`]) because the
/// presented certificates are ordinary agent client pairs on both sides.
#[derive(Debug)]
pub(super) struct InnerPeerVerifier {
    /// The wrapped rustls verifier doing chain/validity/EKU verification
    /// against the material's anchor set.
    webpki: Arc<dyn ClientCertVerifier>,
    /// The agent id the stream declared for the peer (identity binding).
    expected_cn: Option<String>,
}

impl InnerPeerVerifier {
    /// Chain-anchors-then-CN: the wrapped verifier's failure means the peer
    /// is not who the stream claims (wrong tenant CA, foreign root, expired,
    /// …); a passing chain with the wrong CN means the hub redirected or
    /// mis-reported the peer — both fail the handshake.
    fn verify_chain_and_cn(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
    ) -> std::result::Result<(), tokio_rustls::rustls::Error> {
        self.webpki
            .verify_client_cert(end_entity, intermediates, UnixTime::now())?;
        let cn = extract_cn_from_chain(std::slice::from_ref(end_entity)).unwrap_or_default();
        if self
            .expected_cn
            .as_ref()
            .is_none_or(|expected| cn.eq_ignore_ascii_case(expected))
        {
            Ok(())
        } else {
            Err(tokio_rustls::rustls::Error::General(format!(
                "inner TLS: peer certificate CN '{cn}' does not match the stream's declared peer '{}'",
                self.expected_cn.as_deref().unwrap_or("")
            )))
        }
    }

    /// Builds the verifier for an expected peer CN over a shared chain
    /// verifier (the material's prebuilt [`Arc`] — constructing this type
    /// no longer clones the anchor store or rebuilds webpki).
    fn new(webpki: Arc<dyn ClientCertVerifier>, expected_cn: Option<&str>) -> Self {
        Self {
            webpki,
            expected_cn: expected_cn.map(str::to_string),
        }
    }
}

impl tokio_rustls::rustls::client::danger::ServerCertVerifier for InnerPeerVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        _server_name: &tokio_rustls::rustls::pki_types::ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> std::result::Result<
        tokio_rustls::rustls::client::danger::ServerCertVerified,
        tokio_rustls::rustls::Error,
    > {
        self.verify_chain_and_cn(end_entity, intermediates)?;
        Ok(tokio_rustls::rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &tokio_rustls::rustls::DigitallySignedStruct,
    ) -> std::result::Result<
        tokio_rustls::rustls::client::danger::HandshakeSignatureValid,
        tokio_rustls::rustls::Error,
    > {
        self.webpki.verify_tls12_signature(message, cert, dss)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &tokio_rustls::rustls::DigitallySignedStruct,
    ) -> std::result::Result<
        tokio_rustls::rustls::client::danger::HandshakeSignatureValid,
        tokio_rustls::rustls::Error,
    > {
        self.webpki.verify_tls13_signature(message, cert, dss)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.webpki.supported_verify_schemes()
    }
}

impl tokio_rustls::rustls::server::danger::ClientCertVerifier for InnerPeerVerifier {
    fn root_hint_subjects(&self) -> &[tokio_rustls::rustls::DistinguishedName] {
        &[]
    }

    fn verify_client_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        _now: UnixTime,
    ) -> std::result::Result<
        tokio_rustls::rustls::server::danger::ClientCertVerified,
        tokio_rustls::rustls::Error,
    > {
        self.verify_chain_and_cn(end_entity, intermediates)?;
        Ok(tokio_rustls::rustls::server::danger::ClientCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &tokio_rustls::rustls::DigitallySignedStruct,
    ) -> std::result::Result<
        tokio_rustls::rustls::client::danger::HandshakeSignatureValid,
        tokio_rustls::rustls::Error,
    > {
        self.webpki.verify_tls12_signature(message, cert, dss)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &tokio_rustls::rustls::DigitallySignedStruct,
    ) -> std::result::Result<
        tokio_rustls::rustls::client::danger::HandshakeSignatureValid,
        tokio_rustls::rustls::Error,
    > {
        self.webpki.verify_tls13_signature(message, cert, dss)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.webpki.supported_verify_schemes()
    }
}

/// Derives the inner TLS **client** config (ingress side) for one stream:
/// the expected peer is the Open frame's target agent.
///
/// Cached per expected CN on the material (see [`InnerTlsMaterial`]): steady
/// state is an [`Arc`] clone, not a rebuild.
pub fn inner_client_config(
    material: &InnerTlsMaterial,
    expected_peer_cn: &str,
) -> Result<Arc<ClientConfig>> {
    material.client_config(expected_peer_cn)
}

/// Derives the inner **QUIC** client config for one expected peer (cached
/// per CN, see [`InnerTlsMaterial`]).
///
/// The inner peer verifier still checks the full certificate chain and leaf CN
/// on every full handshake. Resumption is keyed by a 128-bit deterministic SNI
/// derived from that expected CN, so a session established for one peer cannot
/// be replayed against another peer. 0-RTT remains disabled.
pub fn inner_quic_client_config(
    material: &InnerTlsMaterial,
    expected_peer_cn: &str,
) -> Result<Arc<ClientConfig>> {
    material.quic_client_config(expected_peer_cn)
}

/// Derives the inner TLS **server** config (egress side) for one stream.
///
/// The expected peer is the Open frame's declared source agent. Test-facing
/// shape (production accepts any CN and binds identity in the encrypted
/// inner hello); uncached by design.
pub fn inner_server_config(
    material: &InnerTlsMaterial,
    expected_client_cn: &str,
) -> Result<ServerConfig> {
    let verifier = Arc::new(InnerPeerVerifier::new(
        Arc::clone(material.shared_webpki_verifier()?),
        Some(expected_client_cn),
    ));
    ServerConfig::builder_with_protocol_versions(&[&TLS13])
        .with_client_cert_verifier(verifier)
        .with_single_cert(material.cert_chain.clone(), material.key.clone_key())
        .map_err(|e| {
            InterflowError::config("inner TLS server config error".to_string()).with_source(e)
        })
}

/// A stable DNS-shaped SNI that uniquely partitions resumption by expected CN.
pub fn inner_quic_server_name(expected_peer_cn: &str) -> String {
    let digest = Sha256::digest(expected_peer_cn.as_bytes());
    format!("inner-{}", hex::encode(&digest[..16]))
}

/// Derives an inner TLS **server** config that accepts any CN anchored to the
/// configured trust set.
///
/// inner TLS hides the source principal behind an opaque circuit token, so the
/// egress cannot pre-bind the expected CN. Chain validation is still mandatory
/// at handshake time; the encrypted inner hello then requires the claimed
/// principal and fingerprint to match the certificate that was just verified.
///
/// Cached on the material (see [`InnerTlsMaterial`]): the egress's per-stream
/// acceptor is an [`Arc`] clone.
pub fn inner_server_config_unbound(material: &InnerTlsMaterial) -> Result<Arc<ServerConfig>> {
    Ok(Arc::clone(material.unbound_server_config()?))
}

/// [`inner_server_config_unbound`] with the inner-QUIC ALPN attached — the
/// inner UDP association acceptor's config (cached on the material).
pub fn inner_quic_server_config_unbound(material: &InnerTlsMaterial) -> Result<Arc<ServerConfig>> {
    Ok(Arc::clone(material.unbound_quic_server_config()?))
}

/// Buckets an inner-handshake failure into a metrics reason label.
///
/// `timeout` is decided by the caller (the handshake deadline wrapper);
/// this classifies the error itself: certificate/verification failures are
/// the peer not being who the stream claims (`peer_verify`), framing-level
/// failures are the stream not speaking inner TLS at all (`protocol` —
/// old peers' banner bytes, an active attacker's garbage).
pub fn classify_handshake_error(err: &std::io::Error) -> &'static str {
    use tokio_rustls::rustls::Error as RustlsError;
    let Some(rustls_err) = err.get_ref().and_then(|e| e.downcast_ref::<RustlsError>()) else {
        return "protocol";
    };
    match rustls_err {
        // The CN-mismatch marker comes from this module's verifier; other
        // certificate failures are the peer not being who the stream
        // claims; everything else is framing-level (old peers' banner
        // bytes, an attacker's garbage).
        RustlsError::InvalidCertificate(_) => "peer_verify",
        RustlsError::General(msg) if msg.contains("does not match") => "peer_verify",
        _ => "protocol",
    }
}

#[cfg(test)]
#[allow(clippy::panic, clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use interflow_certs::{LoadedCa, Validity, build_ca};
    use tokio_rustls::TlsAcceptor;
    use tokio_rustls::TlsConnector;
    use tokio_rustls::rustls::pki_types::ServerName;

    /// Parses a leaf+CA chain PEM into a certificate chain and its PKCS#8 key.
    fn parse_pair(
        chain_pem: &str,
        key_pem: &str,
    ) -> (Vec<CertificateDer<'static>>, PrivateKeyDer<'static>) {
        let mut reader = std::io::BufReader::new(chain_pem.as_bytes());
        let chain: Vec<CertificateDer<'static>> = rustls_pemfile::certs(&mut reader)
            .collect::<std::result::Result<_, _>>()
            .expect("parse chain");
        let mut key_reader = std::io::BufReader::new(key_pem.as_bytes());
        let key = rustls_pemfile::pkcs8_private_keys(&mut key_reader)
            .next()
            .expect("parse key")
            .expect("key PEM");
        (chain, PrivateKeyDer::Pkcs8(key))
    }

    /// Mints two independent tenant CAs; agents' pairs are signed by CA A.
    struct Fixture {
        ca_a: LoadedCa,
        ca_b: LoadedCa,
        cert_a: Vec<CertificateDer<'static>>,
        key_a: PrivateKeyDer<'static>,
    }

    fn fixture() -> Fixture {
        let validity = Validity::from_now(30);
        let ca_a = LoadedCa::from_material(&build_ca("tenant-a", validity).expect("build CA A"))
            .expect("load CA A");
        let ca_b = LoadedCa::from_material(&build_ca("tenant-b", validity).expect("build CA B"))
            .expect("load CA B");
        let leaf = ca_a
            .build_client_cert("agent-1", validity)
            .expect("issue pair");
        let (cert_a, key_a) = parse_pair(
            &format!("{}{}", leaf.cert_pem, ca_a.cert_pem()),
            &leaf.key_pem,
        );
        Fixture {
            ca_a,
            ca_b,
            cert_a,
            key_a,
        }
    }

    /// agent-1's material anchoring CA A only.
    fn material(fx: &Fixture) -> InnerTlsMaterial {
        let mut roots = RootCertStore::empty();
        let mut reader = std::io::BufReader::new(fx.ca_a.cert_pem().as_bytes());
        for cert in rustls_pemfile::certs(&mut reader)
            .collect::<std::result::Result<Vec<_>, _>>()
            .unwrap()
        {
            let _ = roots.add(cert);
        }
        InnerTlsMaterial::from_parts(roots, Vec::new(), fx.cert_a.clone(), fx.key_a.clone_key())
    }

    fn expired_material(fx: &Fixture) -> InnerTlsMaterial {
        let past = Validity {
            not_before: time::OffsetDateTime::now_utc() - time::Duration::days(10),
            not_after: time::OffsetDateTime::now_utc() - time::Duration::days(5),
        };
        let leaf = fx
            .ca_a
            .build_client_cert("agent-1", past)
            .expect("expired cert");
        let (chain, key) = parse_pair(
            &format!("{}{}", leaf.cert_pem, fx.ca_a.cert_pem()),
            &leaf.key_pem,
        );
        let mut mat = material(fx);
        mat.cert_chain = chain;
        mat.key = key;
        mat
    }

    /// Verifier matrix, called directly on the shared check (the same path
    /// both roles run through `verify_chain_and_cn`).
    fn verify(
        mat: &InnerTlsMaterial,
        expected_cn: &str,
        chain: &[CertificateDer<'static>],
    ) -> std::result::Result<(), tokio_rustls::rustls::Error> {
        let verifier = InnerPeerVerifier::new(
            Arc::clone(mat.shared_webpki_verifier().unwrap()),
            Some(expected_cn),
        );
        let (leaf, intermediates) = chain.split_first().unwrap();
        verifier.verify_chain_and_cn(leaf, intermediates)
    }

    #[test]
    fn good_chain_and_matching_cn_passes() {
        let fx = fixture();
        let mat = material(&fx);
        assert!(verify(&mat, "agent-1", &fx.cert_a).is_ok());
        // CN comparison is case-insensitive (x509 CN casing is a convention).
        assert!(verify(&mat, "AGENT-1", &fx.cert_a).is_ok());
    }

    #[test]
    fn wrong_cn_fails_even_with_valid_chain() {
        let fx = fixture();
        let mat = material(&fx);
        let err = verify(&mat, "agent-2", &fx.cert_a).unwrap_err();
        assert!(err.to_string().contains("does not match"), "{err}");
    }

    #[test]
    fn foreign_tenant_root_is_rejected() {
        let fx = fixture();
        let mat = material(&fx); // anchors: CA A only
        let leaf = fx
            .ca_b
            .build_client_cert("agent-1", Validity::from_now(30))
            .unwrap();
        let (chain_b, _) = parse_pair(
            &format!("{}{}", leaf.cert_pem, fx.ca_b.cert_pem()),
            &leaf.key_pem,
        ); // CN matches, wrong CA
        assert!(verify(&mat, "agent-1", &chain_b).is_err());
    }

    #[test]
    fn expired_leaf_is_rejected() {
        let fx = fixture();
        let mat = expired_material(&fx);
        assert!(verify(&mat, "agent-1", &mat.cert_chain).is_err());
    }

    /// Appending a foreign root into the presented chain must not change
    /// the outcome in either direction (same discipline as tenant.rs: the
    /// anchoring root is the one that actually signs the path).
    #[test]
    fn appended_foreign_root_has_no_effect() {
        let fx = fixture();
        let mat = material(&fx);
        fn pem_certs(pem: &str) -> Vec<CertificateDer<'static>> {
            let mut reader = std::io::BufReader::new(pem.as_bytes());
            rustls_pemfile::certs(&mut reader)
                .collect::<std::result::Result<_, _>>()
                .unwrap()
        }
        let mut with_foreign = fx.cert_a.clone();
        with_foreign.extend(pem_certs(fx.ca_b.cert_pem()));
        assert!(verify(&mat, "agent-1", &with_foreign).is_ok());

        let leaf = fx
            .ca_b
            .build_client_cert("agent-1", Validity::from_now(30))
            .unwrap();
        let (chain_b, _) = parse_pair(
            &format!("{}{}", leaf.cert_pem, fx.ca_b.cert_pem()),
            &leaf.key_pem,
        );
        let mut b_plus_a = chain_b;
        b_plus_a.extend(pem_certs(fx.ca_a.cert_pem()));
        assert!(verify(&mat, "agent-1", &b_plus_a).is_err());
    }

    /// Full in-memory handshake: client config (expected CN = server's
    /// agent id) against server config (expected CN = client's agent id)
    /// over a duplex stream — proves the config builders compose with
    /// tokio-rustls, and that a CN mismatch kills the handshake at the
    /// TLS layer, not just at the direct verifier call.
    #[tokio::test]
    async fn full_handshake_round_trip_and_cn_mismatch() {
        let fx = fixture();
        let mat = material(&fx); // agent-1's material, anchors = CA A
        let leaf2 = fx
            .ca_a
            .build_client_cert("agent-2", Validity::from_now(30))
            .unwrap();
        let (cert_2, key_2) = parse_pair(
            &format!("{}{}", leaf2.cert_pem, fx.ca_a.cert_pem()),
            &leaf2.key_pem,
        );
        // same tenant anchor set
        let mat_2 = InnerTlsMaterial::from_parts(mat.roots.clone(), Vec::new(), cert_2, key_2);

        let (client_side, server_side) = tokio::io::duplex(4096);
        let client = tokio::spawn(async move {
            let name = ServerName::try_from(INNER_SERVER_NAME.to_string()).unwrap();
            TlsConnector::from(inner_client_config(&mat, "agent-2").unwrap())
                .connect(name, client_side)
                .await
        });
        let server = tokio::spawn(async move {
            TlsAcceptor::from(Arc::new(inner_server_config(&mat_2, "agent-1").unwrap()))
                .accept(server_side)
                .await
        });
        let (c, s) = (client.await.unwrap(), server.await.unwrap());
        c.as_ref().expect("client handshake");
        s.as_ref().expect("server handshake");

        // Mismatch: the server expects a different client CN.
        let (mat3, mat4) = (material(&fx), material(&fx));
        let (client_side, server_side) = tokio::io::duplex(4096);
        let client = tokio::spawn(async move {
            let name = ServerName::try_from(INNER_SERVER_NAME.to_string()).unwrap();
            TlsConnector::from(inner_client_config(&mat3, "agent-2").unwrap())
                .connect(name, client_side)
                .await
        });
        let server = tokio::spawn(async move {
            TlsAcceptor::from(Arc::new(
                inner_server_config(&mat4, "someone-else").unwrap(),
            ))
            .accept(server_side)
            .await
        });
        let (c, s) = (client.await.unwrap(), server.await.unwrap());
        assert!(
            c.is_err() || s.is_err(),
            "CN mismatch must fail the handshake"
        );
    }

    /// §2.1 cache semantics: same expected CN serves the same `Arc`
    /// (no rebuild); different CNs get distinct configs; the unbound
    /// server configs build once and share; the QUIC variants keep their
    /// resumption/ALPN posture.
    #[test]
    fn derived_configs_are_cached_per_cn() {
        let fx = fixture();
        let mat = material(&fx);

        let a1 = inner_client_config(&mat, "agent-2").unwrap();
        let a2 = inner_client_config(&mat, "agent-2").unwrap();
        assert!(Arc::ptr_eq(&a1, &a2), "same CN must hit the cache");

        let b = inner_client_config(&mat, "agent-3").unwrap();
        assert!(!Arc::ptr_eq(&a1, &b), "different CNs are distinct configs");

        let q1 = inner_quic_client_config(&mat, "agent-2").unwrap();
        let q2 = inner_quic_client_config(&mat, "agent-2").unwrap();
        assert!(Arc::ptr_eq(&q1, &q2));
        assert!(!q1.enable_early_data, "0-RTT stays disabled");
        assert!(
            q1.alpn_protocols
                .iter()
                .any(|p| p == INNER_QUIC_ALPN.as_bytes()),
            "QUIC client config carries the inner QUIC ALPN"
        );

        let s1 = inner_server_config_unbound(&mat).unwrap();
        let s2 = inner_server_config_unbound(&mat).unwrap();
        assert!(Arc::ptr_eq(&s1, &s2), "the unbound acceptor builds once");

        let qs = inner_quic_server_config_unbound(&mat).unwrap();
        assert!(
            !Arc::ptr_eq(&s1, &qs),
            "TCP and QUIC-ALPN variants are separate caches"
        );
        assert!(
            qs.alpn_protocols
                .iter()
                .any(|p| p == INNER_QUIC_ALPN.as_bytes()),
            "the QUIC server variant carries the ALPN"
        );
    }

    /// The per-CN cache clears wholesale at [`CONFIG_CACHE_CAP`]: the 129th
    /// distinct CN evicts everything (bounded memory; a cleared entry
    /// rebuilds on its next use).
    #[test]
    fn config_cache_clears_at_capacity() {
        let fx = fixture();
        let mat = material(&fx);
        for i in 0..CONFIG_CACHE_CAP {
            inner_client_config(&mat, &format!("agent-{i}")).unwrap();
        }
        {
            let cache = mat
                .client_configs
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            assert_eq!(cache.len(), CONFIG_CACHE_CAP);
        }
        let overflow = inner_client_config(&mat, "agent-overflow").unwrap();
        {
            let cache = mat
                .client_configs
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            assert!(
                cache.len() <= CONFIG_CACHE_CAP,
                "overflow must clear the map, not grow past the cap"
            );
            assert!(
                cache.contains_key("agent-overflow"),
                "the inserting caller always lands its entry"
            );
        }
        let again = inner_client_config(&mat, "agent-overflow").unwrap();
        assert!(
            Arc::ptr_eq(&overflow, &again),
            "re-hit after clear is stable"
        );
    }
}
