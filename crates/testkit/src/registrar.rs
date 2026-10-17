//! In-process registrar fixture.
//!
//! One spawn shape for every test that needs a live registrar: issuer
//! provisioning, the dead-then-alive port doctrine, `serve_on` handoff and
//! a readiness probe that asserts. The port belongs to THIS fixture's
//! listener from its first moment — there is no probe/drop/rebind window
//! for a concurrently-spawned test process (nextest runs each test in its
//! own process) or the kernel's ephemeral allocator to steal, which is
//! exactly the race the 2026-09-24 ephemeral-port TOCTOU migration
//! eradicated everywhere else.

use interflow_identity::issuance::{IssuerStore, LeafTtl};
use interflow_registrar::server::{self, ServeOptions};
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio_rustls::TlsConnector;
use tokio_rustls::rustls::RootCertStore;
use tokio_rustls::rustls::pki_types::ServerName;
use tokio_util::sync::CancellationToken;

/// Readiness budget, house convention (`stack.rs` uses the same shape).
const READY_TIMEOUT: Duration = Duration::from_secs(10);

/// A live in-process registrar: bound, serving, and shut down through its
/// token. The tempdir lives as long as the handle.
pub struct RegistrarFixture {
    addr: SocketAddr,
    endpoint: String,
    ca_pem: String,
    issuer_dir: PathBuf,
    #[expect(dead_code, reason = "holds the tempdir alive for the serve task")]
    dir: tempfile::TempDir,
    serve: tokio::task::JoinHandle<interflow_identity::Result<()>>,
    shutdown: CancellationToken,
}

/// The knobs fixtures actually vary; everything else is fixed shape.
#[derive(Clone)]
pub struct RegistrarFixtureOptions {
    pub ttl: LeafTtl,
    pub control_endpoint: String,
    pub hub_endpoints: std::collections::BTreeMap<String, String>,
}

impl Default for RegistrarFixtureOptions {
    fn default() -> Self {
        Self {
            ttl: LeafTtl::default_ttl(),
            control_endpoint: "127.0.0.1:16666".to_owned(),
            hub_endpoints: Default::default(),
        }
    }
}

/// Provisions an issuer store and serves the registrar on a fresh
/// loopback port. Installs the test logging sink and the process-default
/// TLS provider (idempotent).
pub async fn spawn_registrar(options: RegistrarFixtureOptions) -> RegistrarFixture {
    crate::logging::init_test_logging();
    let _ = tokio_rustls::rustls::crypto::aws_lc_rs::default_provider().install_default();
    let dir = tempfile::tempdir().expect("registrar tempdir");
    let issuer_dir = dir.path().join("issuer");
    let issuer = IssuerStore::open(&issuer_dir);
    issuer.ensure_realm().expect("ensure realm");
    issuer.ensure_workspace("main").expect("ensure workspace");
    issuer.ensure_policy_key().expect("ensure policy key");
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind registrar listener");
    let addr = listener.local_addr().expect("registrar local addr");
    let endpoint = format!("https://{addr}");
    let tls = issuer
        .issue_control_endpoint("test", "registrar", &endpoint)
        .expect("registrar TLS identity");
    std::fs::write(dir.path().join("registrar.crt"), &tls.chain_pem).expect("write registrar crt");
    std::fs::write(dir.path().join("registrar.key"), &tls.key_pem).expect("write registrar key");
    let shutdown = CancellationToken::new();
    let serve = tokio::spawn(server::serve_on(
        issuer_dir.clone(),
        ServeOptions {
            listen: addr,
            public_endpoint: endpoint.clone(),
            tls_cert: dir.path().join("registrar.crt"),
            tls_key: dir.path().join("registrar.key"),
            ttl: options.ttl,
            control_endpoint: options.control_endpoint,
            hub_endpoints: options.hub_endpoints,
        },
        listener,
        shutdown.clone(),
    ));
    let ca_pem = issuer
        .realm_issuer()
        .expect("realm issuer")
        .cert_pem()
        .to_owned();
    RegistrarFixture {
        addr,
        endpoint,
        ca_pem,
        issuer_dir,
        dir,
        serve,
        shutdown,
    }
}

impl RegistrarFixture {
    /// The serving address (`https://127.0.0.1:{port}`).
    pub fn endpoint(&self) -> &str {
        &self.endpoint
    }

    /// The realm CA PEM, for client trust stores.
    pub fn ca_pem(&self) -> &str {
        &self.ca_pem
    }

    /// The issuer store directory (enrollment codes, audit ledger).
    pub fn issuer_dir(&self) -> &Path {
        &self.issuer_dir
    }

    /// Waits until the registrar answers `GET /health` over TLS, asserting
    /// with the serve task's state and the recent log tail on timeout —
    /// a registrar that never becomes ready must never fail silently.
    pub async fn wait_ready(&self) {
        let mut roots = RootCertStore::empty();
        let mut ca_bytes = self.ca_pem.as_bytes();
        let certs: Vec<_> = rustls_pemfile::certs(&mut ca_bytes)
            .collect::<std::result::Result<_, _>>()
            .expect("parse realm CA PEM");
        roots.add_parsable_certificates(certs);
        let connector = TlsConnector::from(Arc::new(
            tokio_rustls::rustls::ClientConfig::builder()
                .with_root_certificates(roots)
                .with_no_client_auth(),
        ));
        let deadline = tokio::time::Instant::now() + READY_TIMEOUT;
        loop {
            if health_probe(self.addr, &connector).await {
                return;
            }
            assert!(
                tokio::time::Instant::now() < deadline,
                "registrar at {} never answered /health within {READY_TIMEOUT:?}; \
                 serve task finished: {}; recent logs:\n{}",
                self.endpoint,
                self.serve.is_finished(),
                crate::logging::recent_lines().join("\n")
            );
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    }

    /// Makes the registrar unreachable: cancels the token and aborts the
    /// serve task (the failure-path tests' "registrar down" lever).
    pub fn kill(&self) {
        self.shutdown.cancel();
        self.serve.abort();
    }

    /// Graceful shutdown: stops accepting, drains in-flight connections,
    /// and surfaces a serve-side error if the task ended in one.
    pub async fn shutdown(self) -> interflow_identity::Result<()> {
        self.shutdown.cancel();
        match self.serve.await {
            Ok(result) => result,
            Err(join) => panic!("registrar serve task failed: {join}"),
        }
    }
}

/// One manual-rustls `GET /health` roundtrip (the same client shape
/// `proxy_protocol.rs` pioneered): TCP → TLS → HTTP/1. Any failure along
/// the way is a not-ready answer, retried by `wait_ready`.
async fn health_probe(addr: SocketAddr, connector: &TlsConnector) -> bool {
    let Ok(tcp) = tokio::net::TcpStream::connect(addr).await else {
        return false;
    };
    let Ok(mut tls) = connector.connect(ServerName::from(addr.ip()), tcp).await else {
        return false;
    };
    let request = format!("GET /health HTTP/1.1\r\nHost: {addr}\r\nConnection: close\r\n\r\n");
    if tls.write_all(request.as_bytes()).await.is_err() {
        return false;
    }
    let mut response = Vec::new();
    if tls.read_to_end(&mut response).await.is_err() {
        return false;
    }
    response.starts_with(b"HTTP/1.1 200") || response.starts_with(b"HTTP/1.0 200")
}
