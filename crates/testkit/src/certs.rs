//! rcgen self-signed certificates: CA + SAN(127.0.0.1/localhost) server + client on
//! demand (CN = agent id).
//!
//! Directory isolation: each generation uses its own temp directory (an in-process
//! atomic sequence number + a caller-provided tag), so parallel tests/scenarios never
//! mix up certificates. Private key files are set to 0600 as the hub's validation
//! requires.

use std::path::{Path, PathBuf};

/// One generated certificate set (material held as PEM strings; files written on demand).
pub struct TestCerts {
    dir: PathBuf,
    ca_cn: String,
    ca_pem: String,
    ca_key: String,
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
        use rcgen::{CertificateParams, DnType, DnValue, Issuer, KeyPair};

        static SEQ: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        let seq = SEQ.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let dir =
            std::env::temp_dir().join(format!("interflow-{tag}-{}-{seq}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap_or_else(|e| panic!("cert dir: {e}"));

        // CA
        let ca_cn = format!("Interflow {tag} CA");
        let mut ca_params = CertificateParams::default();
        ca_params
            .distinguished_name
            .push(DnType::CommonName, DnValue::Utf8String(ca_cn.clone()));
        ca_params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        let ca_key = KeyPair::generate().expect("ca key");
        let ca_cert = ca_params.self_signed(&ca_key).expect("ca cert");

        // server: SAN covers localhost + 127.0.0.1 (SNI works with either IP or hostname;
        // CertificateParams::new parses strings as IP/DNS automatically)
        let server_params =
            CertificateParams::new(vec!["localhost".to_string(), "127.0.0.1".to_string()])
                .expect("server params");
        let server_key = KeyPair::generate().expect("server key");
        let issuer = Issuer::from_params(&ca_params, &ca_key);
        let server_cert = server_params
            .signed_by(&server_key, &issuer)
            .expect("server cert");

        // client (CN = caller-specified, usually the agent id)
        let mut client_params = CertificateParams::default();
        client_params.distinguished_name.push(
            DnType::CommonName,
            DnValue::Utf8String(client_cn.to_string()),
        );
        let client_key = KeyPair::generate().expect("client key");
        let client_cert = client_params
            .signed_by(&client_key, &issuer)
            .expect("client cert");

        let certs = TestCerts {
            ca_cn,
            ca_pem: ca_cert.pem(),
            ca_key: ca_key.serialize_pem(),
            server_cert: server_cert.pem(),
            server_key: server_key.serialize_pem(),
            client_cert: client_cert.pem(),
            client_key: client_key.serialize_pem(),
            dir,
        };

        write_file(&certs.dir.join("ca.pem"), &certs.ca_pem, false);
        write_file(&certs.dir.join("server.pem"), &certs.server_cert, false);
        write_file(&certs.dir.join("server.key"), &certs.server_key, true);
        certs
    }

    /// CA certificate path (the agent-side `ca_path`).
    pub fn ca_path(&self) -> PathBuf {
        self.dir.join("ca.pem")
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
        use rcgen::{CertificateParams, DnType, DnValue, Issuer, KeyPair};

        // Rebuild the same CA parameters as generate (same DN + same key → same issuer subject)
        let mut ca_params = CertificateParams::default();
        ca_params
            .distinguished_name
            .push(DnType::CommonName, DnValue::Utf8String(self.ca_cn.clone()));
        ca_params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        let ca_key = KeyPair::from_pem(&self.ca_key).expect("ca key parse");
        let issuer = Issuer::from_params(&ca_params, ca_key);

        let mut params = CertificateParams::default();
        params
            .distinguished_name
            .push(DnType::CommonName, DnValue::Utf8String(cn.to_string()));
        let key = KeyPair::generate().expect("client key");
        let cert = params.signed_by(&key, &issuer).expect("client cert");

        let cert_path = write_file(
            &self.dir.join(format!("client-{cn}.pem")),
            &cert.pem(),
            false,
        );
        let key_path = write_file(
            &self.dir.join(format!("client-{cn}.key")),
            &key.serialize_pem(),
            true,
        );
        (cert_path, key_path)
    }
}
