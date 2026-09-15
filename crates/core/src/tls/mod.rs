//! TLS utilities: cert pinning, server certificate loading, mTLS, and CN extraction.

pub mod cert_pin;
pub mod server;

pub use cert_pin::{PinError, PinnedCertVerifier, make_pinned_verifier};
pub use server::{
    Strictness, build_mtls_acceptor, build_rustls_server_config, build_tls_acceptor,
    check_secret_file_perms, extract_cn_from_chain, extract_cn_from_quinn_identity,
};
