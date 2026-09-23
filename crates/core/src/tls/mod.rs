//! TLS utilities: cert pinning, server certificate loading, mTLS, tenant
//! trust roots, the agent↔agent inner TLS layer, and CN extraction.

pub mod cert_pin;
pub mod client;
pub mod inner;
pub mod server;
pub mod tenant;

pub use cert_pin::{PinError, PinnedCertVerifier, make_pinned_verifier};
pub use inner::{
    INNER_QUIC_ALPN, INNER_SERVER_NAME, InnerTlsMaterial, classify_handshake_error,
    inner_client_config, inner_quic_client_config, inner_quic_server_name, inner_server_config,
    inner_server_config_unbound,
};
pub use server::{
    TlsMinVersion, build_mtls_acceptor, build_rustls_server_config_with_roots,
    extract_cn_from_chain, extract_cn_from_pem_file, load_crl,
};
pub use tenant::{TenantIdentity, TenantTrustRoot, TenantVerifier, TlsPlane, build_tls_plane};
