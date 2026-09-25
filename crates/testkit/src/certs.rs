//! Self-signed certificates: CA + SAN(localhost/127.0.0.1) server + client on
//! demand (CN = agent id).
//!
//! Issuance goes through `interflow-certs` — the same implementation behind
//! internal issuance — so test certificates
//! have production shape (ServerAuth/ClientAuth EKU, explicit validity).
//!
//! Directory isolation: each generation uses its own temp directory (an
//! in-process atomic sequence number + a caller-provided tag), so parallel
//! tests/scenarios never mix up certificates. Private key files are set to
//! 0600 as the hub's validation requires.

use std::path::{Path, PathBuf};

/// One generated certificate set (material held as PEM strings; files written on demand).
pub struct TestCerts {
    dir: PathBuf,
    /// Per-CN issued-cert cache: parallel tests share one `TestCerts` (via a
    /// `OnceLock`); re-issuing would rewrite the same files concurrently and
    /// hand a reader a half-written PEM.
    issued: std::sync::Mutex<std::collections::HashMap<String, (PathBuf, PathBuf)>>,
    /// The retained signing context — leaf issuance (named clients,
    /// revocation material) signs in memory instead of re-parsing the
    /// persisted CA PEM on every call.
    ca: interflow_certs::LoadedCa,
    server_cert: String,
    server_key: String,
    client_cert: String,
    client_key: String,
}

fn write_file(path: &Path, content: &str, secret: bool) -> PathBuf {
    std::fs::write(path, content).unwrap_or_else(|e| panic!("write {}: {e}", path.display()));
    #[cfg(unix)]
    if secret {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600));
    }
    let _ = secret;
    path.to_path_buf()
}

impl TestCerts {
    /// Generate CA + server certificate + a default client certificate (`client_cn` is
    /// usually the agent id; mTLS CN-binding tests depend on it).
    pub fn generate(tag: &str, client_cn: &str) -> TestCerts {
        static SEQ: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        let seq = SEQ.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let dir =
            std::env::temp_dir().join(format!("interflow-{tag}-{}-{seq}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap_or_else(|e| panic!("cert dir: {e}"));

        let loaded =
            interflow_certs::LoadedCa::generate(tag, interflow_certs::Validity::ca_default())
                .unwrap_or_else(|e| panic!("test CA: {e}"));
        // Server: SAN covers localhost + 127.0.0.1 (SNI works with either IP
        // or hostname — the local-development dial forms).
        let server = loaded
            .build_server_cert(
                &interflow_certs::local_dev_san(),
                interflow_certs::Validity::leaf_default(),
            )
            .unwrap_or_else(|e| panic!("test server cert: {e}"));
        // Client (CN = caller-specified, usually the agent id)
        let client = loaded
            .build_client_cert(client_cn, interflow_certs::Validity::leaf_default())
            .unwrap_or_else(|e| panic!("test client cert: {e}"));
        let crl = loaded
            .build_empty_crl()
            .unwrap_or_else(|e| panic!("test CRL: {e}"));

        let certs = TestCerts {
            issued: std::sync::Mutex::new(std::collections::HashMap::new()),
            ca: loaded,
            server_cert: server.cert_pem,
            server_key: server.key_pem,
            client_cert: client.cert_pem,
            client_key: client.key_pem,
            dir,
        };

        write_file(&certs.dir.join("ca.pem"), certs.ca.cert_pem(), false);
        write_file(&certs.dir.join("ca.crl"), &crl, false);
        write_file(&certs.dir.join("server.pem"), &certs.server_cert, false);
        write_file(&certs.dir.join("server.key"), &certs.server_key, true);
        certs
    }

    /// CA certificate path (the agent-side `ca_path`).
    pub fn ca_path(&self) -> PathBuf {
        self.dir.join("ca.pem")
    }

    /// Valid CRL path for the test tenant CA.
    pub fn crl_path(&self) -> PathBuf {
        self.dir.join("ca.crl")
    }

    /// Server certificate path (the hub-side `cert_path`).
    pub fn server_cert_path(&self) -> PathBuf {
        self.dir.join("server.pem")
    }

    /// Server private key path (the hub-side `key_path`).
    pub fn server_key_path(&self) -> PathBuf {
        self.dir.join("server.key")
    }

    /// The default client certificate (the one built with `client_cn` at construction).
    pub fn client_paths(&self) -> (PathBuf, PathBuf) {
        let cert = write_file(&self.dir.join("client.pem"), &self.client_cert, false);
        let key = write_file(&self.dir.join("client.key"), &self.client_key, true);
        (cert, key)
    }

    /// Sign another client certificate with the CA under a given CN (each identity for
    /// multi-agent mTLS).
    pub fn named_client_cert(&self, cn: &str) -> (PathBuf, PathBuf) {
        // Hold the lock across issue + cache: parallel tests calling this for
        // the same CN must never both issue (two different keys racing onto
        // the same paths = cert/key mismatch on disk).
        let mut cache = self.issued.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(pair) = cache.get(cn) {
            return pair.clone();
        }
        let pair = self.issue_client_cert(cn);
        cache.insert(cn.to_string(), pair.clone());
        pair
    }

    /// Issues (uncached) a client certificate under `cn`.
    fn issue_client_cert(&self, cn: &str) -> (PathBuf, PathBuf) {
        let pair = self
            .ca
            .build_client_cert(cn, interflow_certs::Validity::leaf_default())
            .unwrap_or_else(|e| panic!("test client cert: {e}"));

        let cert_path = write_file(
            &self.dir.join(format!("client-{cn}.pem")),
            &pair.cert_pem,
            false,
        );
        let key_path = write_file(
            &self.dir.join(format!("client-{cn}.key")),
            &pair.key_pem,
            true,
        );
        (cert_path, key_path)
    }

    /// Issues an uncached client pair and a CRL revoking exactly that leaf.
    pub fn revoked_client_material(&self, cn: &str) -> (PathBuf, PathBuf, PathBuf) {
        let leaf = self
            .ca
            .build_client_cert(cn, interflow_certs::Validity::leaf_default())
            .unwrap_or_else(|e| panic!("revoked client: {e}"));
        let crl = self
            .ca
            .build_crl_revoking(&leaf.serial_number)
            .unwrap_or_else(|e| panic!("revoked CRL: {e}"));
        let cert_path = write_file(
            &self.dir.join(format!("revoked-{cn}.pem")),
            &leaf.cert_pem,
            false,
        );
        let key_path = write_file(
            &self.dir.join(format!("revoked-{cn}.key")),
            &leaf.key_pem,
            true,
        );
        let crl_path = write_file(&self.dir.join(format!("revoked-{cn}.crl")), &crl, false);
        (cert_path, key_path, crl_path)
    }
}

/// Protocol-level test helper: connects a TLS client stream to `addr`,
/// presenting the client certificate issued for `cn` (the hub is mTLS-only;
/// plain h2 handshakes are rejected at the TLS layer). Verifies the server
/// against the CA under the name `localhost`.
pub async fn tls_client_connect(
    certs: &TestCerts,
    cn: &str,
    addr: std::net::SocketAddr,
) -> std::io::Result<tokio_rustls::client::TlsStream<tokio::net::TcpStream>> {
    let (cert_path, key_path) = certs.named_client_cert(cn);
    tls_client_connect_with(&certs.ca_path(), &cert_path, &key_path, "localhost", addr).await
}

/// Path-parameterized variant of [`tls_client_connect`]: connects with an
/// arbitrary certificate triple and server name (used to handshake-test
/// operator-issued material).
pub async fn tls_client_connect_with(
    ca_path: &Path,
    client_cert_path: &Path,
    client_key_path: &Path,
    server_name: &str,
    addr: std::net::SocketAddr,
) -> std::io::Result<tokio_rustls::client::TlsStream<tokio::net::TcpStream>> {
    let connector = tls_connector(ca_path, client_cert_path, client_key_path)?;
    let tcp = tokio::net::TcpStream::connect(addr).await?;
    let server_name =
        rustls::pki_types::ServerName::try_from(server_name.to_string()).expect("server name");
    connector.connect(server_name, tcp).await
}

/// Builds the mTLS client connector from a certificate triple (the shared
/// body of the TLS connect helpers).
fn tls_connector(
    ca_path: &Path,
    client_cert_path: &Path,
    client_key_path: &Path,
) -> std::io::Result<tokio_rustls::TlsConnector> {
    let cert_pem = std::fs::read(client_cert_path)?;
    let key_pem = std::fs::read(client_key_path)?;
    let ca_pem = std::fs::read(ca_path)?;

    let mut roots = rustls::RootCertStore::empty();
    for c in rustls_pemfile::certs(&mut &ca_pem[..]) {
        let _ = roots.add(c.expect("ca cert"));
    }
    let client_cert: Vec<_> = rustls_pemfile::certs(&mut &cert_pem[..])
        .collect::<Result<_, _>>()
        .expect("client cert");
    let key = rustls_pemfile::private_key(&mut &key_pem[..])
        .expect("client key")
        .expect("client key present");

    let config = rustls::ClientConfig::builder()
        .with_root_certificates(roots)
        .with_client_auth_cert(client_cert, key)
        .expect("client auth");
    Ok(tokio_rustls::TlsConnector::from(std::sync::Arc::new(
        config,
    )))
}

/// Which PROXY protocol preamble [`tls_client_connect_pp`] writes before
/// the TLS ClientHello.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PpVersion {
    /// Text line — what stock nginx stream (`proxy_protocol on;`) emits.
    V1,
    /// Binary header — signature + fixed header + address payload, for
    /// fronts that speak v2.
    V2,
}

/// Protocol-level test helper with a PROXY protocol preamble: connects to
/// `addr`, writes the preamble for `source_ip` (the "real client" the
/// front vouches for), then runs the same mTLS handshake as
/// [`tls_client_connect`]. Exercises the pre-TLS sniff stages of
/// pp-fronted listeners (hub control endpoint, edge public listener).
pub async fn tls_client_connect_pp(
    certs: &TestCerts,
    cn: &str,
    addr: std::net::SocketAddr,
    source_ip: std::net::IpAddr,
    version: PpVersion,
) -> std::io::Result<tokio_rustls::client::TlsStream<tokio::net::TcpStream>> {
    let (cert_path, key_path) = certs.named_client_cert(cn);
    let connector = tls_connector(&certs.ca_path(), &cert_path, &key_path)?;
    let mut tcp = tokio::net::TcpStream::connect(addr).await?;
    tokio::io::AsyncWriteExt::write_all(&mut tcp, &pp_preamble(source_ip, version)).await?;
    let server_name =
        rustls::pki_types::ServerName::try_from("localhost".to_string()).expect("server name");
    connector.connect(server_name, tcp).await
}

/// Hand-built preamble bytes (testkit keeps the ppp crate out of its
/// dependency graph; both versions are tiny fixed layouts).
fn pp_preamble(source: std::net::IpAddr, version: PpVersion) -> Vec<u8> {
    match version {
        PpVersion::V1 => match source {
            std::net::IpAddr::V4(ip) => {
                format!("PROXY TCP4 {ip} 10.0.0.1 47115 443\r\n").into_bytes()
            }
            std::net::IpAddr::V6(ip) => {
                format!("PROXY TCP6 {ip} 2001:db8::1 47115 443\r\n").into_bytes()
            }
        },
        PpVersion::V2 => {
            let mut h = Vec::new();
            h.extend_from_slice(&[
                0x0D, 0x0A, 0x0D, 0x0A, 0x00, 0x0D, 0x0A, 0x51, 0x55, 0x49, 0x54, 0x0A,
            ]);
            h.push(0x21); // ver2 cmd PROXY
            match source {
                std::net::IpAddr::V4(ip) => {
                    h.push(0x11); // fam TCP4
                    h.extend_from_slice(&12u16.to_be_bytes()); // payload length
                    h.extend_from_slice(&ip.octets());
                    h.extend_from_slice(&[10, 0, 0, 1]); // destination
                }
                std::net::IpAddr::V6(ip) => {
                    h.push(0x21); // fam TCP6
                    h.extend_from_slice(&36u16.to_be_bytes()); // payload length
                    h.extend_from_slice(&ip.octets());
                    h.extend_from_slice(&[
                        0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1,
                    ]); // 2001:db8::1
                }
            }
            h.extend_from_slice(&47115u16.to_be_bytes()); // source port
            h.extend_from_slice(&443u16.to_be_bytes()); // destination port
            h
        }
    }
}
