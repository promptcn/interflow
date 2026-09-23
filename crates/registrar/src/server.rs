//! Small mTLS HTTPS registrar API.

use crate::{FileKeySource, KeySource, RegistrarService};
use bytes::Bytes;
use http_body_util::{BodyExt, Full};
use hyper::body::Incoming;
use hyper::server::conn::http1;
use hyper::{Request, Response, StatusCode};
use hyper_util::rt::TokioIo;
use interflow_identity::PrincipalPath;
use interflow_identity::Result;
use interflow_identity::issuance::LeafTtl;
use interflow_identity::revocation::{RevocationList, build_crl};
use interflow_identity::{pem_certs, uri_san_from_cert_der};
use serde::Deserialize;
use std::collections::{BTreeMap, BTreeSet};
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;
use time::OffsetDateTime;
use tokio::net::TcpListener;
use tokio_rustls::TlsAcceptor;
use tokio_rustls::rustls::crypto::aws_lc_rs;
use tokio_rustls::rustls::pki_types::{CertificateDer, PrivateKeyDer};
use tokio_rustls::rustls::server::WebPkiClientVerifier;
use tokio_rustls::rustls::{RootCertStore, ServerConfig};

#[derive(Clone)]
pub struct ServeOptions {
    pub listen: SocketAddr,
    pub public_endpoint: String,
    pub tls_cert: PathBuf,
    pub tls_key: PathBuf,
    pub ttl: LeafTtl,
    pub control_endpoint: String,
    /// Site-to-site hub nodes whose renewed server credentials carry the
    /// hub's dial address instead of the deployment control endpoint
    /// (`node → endpoint`).
    pub hub_endpoints: std::collections::BTreeMap<String, String>,
}

#[derive(Deserialize)]
struct EnrollRequest {
    code: String,
    csr_pem: String,
}

#[derive(Deserialize)]
struct RenewRequest {
    csr_pem: String,
}

#[derive(Deserialize)]
struct RenewControlRequest {
    csr_pem: String,
    old_serial: String,
}

#[derive(Deserialize)]
struct ConfirmRequest {
    renewal_id: String,
}

#[derive(Deserialize)]
struct ConfirmControlRequest {
    renewal_id: String,
    new_serial: String,
}

pub async fn serve(issuer: PathBuf, options: ServeOptions) -> Result<()> {
    let source = FileKeySource::open(&issuer)?;
    let enrollments = crate::EnrollmentCodes::open(issuer.join("enrollments.json"))?;
    let rotations = crate::RotationState::open(issuer.join("rotation-state.json"))?;
    let mut control_endpoints =
        crate::service::ControlEndpoints::new(options.control_endpoint.clone());
    for (node, endpoint) in &options.hub_endpoints {
        control_endpoints = control_endpoints.with_hub(node, endpoint);
    }
    let state = Arc::new(RegistrarService::new(
        source,
        enrollments,
        rotations,
        options.ttl,
        control_endpoints,
    ));
    let acceptor = Arc::new(tokio::sync::RwLock::new(build_acceptor(
        state.source(),
        &options,
    )?));
    let rotation_source = FileKeySource::open(&issuer)?;
    let rotation_options = options.clone();
    tokio::spawn(registrar_tls_rotation(
        rotation_source,
        rotation_options,
        Arc::clone(&acceptor),
    ));
    let listener =
        TcpListener::bind(options.listen)
            .await
            .map_err(|e| interflow_identity::Error::Io {
                path: options.listen.to_string(),
                source: e,
            })?;
    tracing::info!("registrar listening on https://{}", options.listen);
    loop {
        let (stream, _) = listener
            .accept()
            .await
            .map_err(|e| interflow_identity::Error::Io {
                path: options.listen.to_string(),
                source: e,
            })?;
        let acceptor = acceptor.read().await.clone();
        let Ok(tls_stream) = acceptor.accept(stream).await else {
            tracing::warn!("registrar TLS handshake failed");
            continue;
        };
        let peer = tls_stream
            .get_ref()
            .1
            .peer_certificates()
            .map(|certs| certs.iter().map(|cert| cert.to_vec()).collect::<Vec<_>>());
        let state = Arc::clone(&state);
        tokio::spawn(async move {
            let service = hyper::service::service_fn(move |request| {
                let state = Arc::clone(&state);
                let peer = peer.clone();
                async move { handle(request, state, peer).await }
            });
            if let Err(e) = http1::Builder::new()
                .serve_connection(TokioIo::new(tls_stream), service)
                .await
            {
                tracing::warn!("registrar HTTP request failed: {e}");
            }
        });
    }
}

async fn registrar_tls_rotation(
    source: FileKeySource,
    options: ServeOptions,
    acceptor: Arc<tokio::sync::RwLock<TlsAcceptor>>,
) {
    loop {
        let Ok(expiry) = certificate_expiry(&options.tls_cert) else {
            tracing::error!("cannot read registrar TLS certificate expiry; rotation stopped");
            return;
        };
        let now = OffsetDateTime::now_utc();
        if expiry <= now {
            tracing::error!("registrar TLS certificate expired; rotation stopped");
            return;
        }
        let threshold =
            expiry - time::Duration::seconds(options.ttl.duration().whole_seconds() / 2);
        if now < threshold {
            tokio::time::sleep(Duration::from_secs(
                u64::try_from((threshold - now).whole_seconds().max(0)).unwrap_or_default(),
            ))
            .await;
        }
        match rotate_registrar_tls(&source, &options) {
            Ok(()) => match build_acceptor(&source, &options) {
                Ok(next) => {
                    *acceptor.write().await = next;
                    tracing::info!("registrar_tls_rotated");
                }
                Err(e) => {
                    tracing::error!(
                        "registrar TLS reload failed: {}",
                        interflow_util::format_chain(&e)
                    );
                    tokio::time::sleep(Duration::from_secs(60)).await;
                }
            },
            Err(e) => {
                tracing::error!(
                    "registrar TLS rotation failed: {}",
                    interflow_util::format_chain(&e)
                );
                tokio::time::sleep(Duration::from_secs(60)).await;
            }
        }
    }
}

fn rotate_registrar_tls(source: &FileKeySource, options: &ServeOptions) -> Result<()> {
    let cert_pem =
        std::fs::read_to_string(&options.tls_cert).map_err(|e| interflow_identity::Error::Io {
            path: options.tls_cert.display().to_string(),
            source: e,
        })?;
    let der = pem_certs(cert_pem.as_bytes())?
        .into_iter()
        .next()
        .ok_or_else(|| {
            interflow_identity::Error::issuance("registrar TLS PEM has no certificate".to_owned())
        })?;
    let uri = uri_san_from_cert_der(&der)?.ok_or_else(|| {
        interflow_identity::Error::issuance(
            "registrar TLS certificate has no principal URI SAN".to_owned(),
        )
    })?;
    let principal = PrincipalPath::parse_uri(&uri)?;
    let material = source.issuer_store()?.issue_control_endpoint_with_ttl(
        &principal.realm,
        &principal.node,
        &options.public_endpoint,
        LeafTtl::default_ttl(),
    )?;
    atomic_write(&options.tls_cert, material.chain_pem.as_bytes(), 0o644)?;
    atomic_write(&options.tls_key, material.key_pem.as_bytes(), 0o600)?;
    Ok(())
}

fn certificate_expiry(path: &Path) -> Result<OffsetDateTime> {
    let pem = std::fs::read_to_string(path).map_err(|e| interflow_identity::Error::Io {
        path: path.display().to_string(),
        source: e,
    })?;
    let der = pem_certs(pem.as_bytes())?
        .into_iter()
        .next()
        .ok_or_else(|| {
            interflow_identity::Error::issuance("registrar TLS PEM has no certificate".to_owned())
        })?;
    let parsed = x509_parser::parse_x509_certificate(&der).map_err(|e| {
        interflow_identity::Error::issuance("registrar TLS parse".to_string()).with_source(e)
    })?;
    OffsetDateTime::from_unix_timestamp(parsed.1.validity().not_after.timestamp()).map_err(|e| {
        interflow_identity::Error::issuance("registrar TLS expiry".to_string()).with_source(e)
    })
}

fn atomic_write(path: &Path, bytes: &[u8], mode: u32) -> Result<()> {
    // Set (not preserve): the rotated TLS key/cert must always carry their
    // designated mode, correcting any pre-existing lax bits.
    interflow_util::atomic_write(path, bytes, interflow_util::WriteMode::Set(mode)).map_err(|e| {
        interflow_identity::Error::Io {
            path: path.display().to_string(),
            source: e,
        }
    })
}

async fn handle(
    request: Request<Incoming>,
    state: Arc<RegistrarService<FileKeySource>>,
    peer: Option<Vec<Vec<u8>>>,
) -> std::result::Result<Response<Full<Bytes>>, std::convert::Infallible> {
    let path = request.uri().path();
    let method = request.method().clone();
    let result = match (method.as_str(), path) {
        ("POST", "/v1/enroll") => {
            let body = read_body(request).await;
            let parsed: EnrollRequest = match body.and_then(|bytes| parse_json(&bytes)) {
                Ok(parsed) => parsed,
                Err(e) => return Ok(error(e)),
            };
            state
                .enroll(&parsed.code, &parsed.csr_pem)
                .and_then(|credential| json_response(&credential))
        }
        ("POST", "/v1/renew") => {
            let Some(chain) = peer else {
                return Ok(error("certificate renewal requires a client certificate"));
            };
            let parsed_peer = crate::service::parse_peer(&chain);
            let body = read_body(request).await;
            let parsed: RenewRequest = match body.and_then(|bytes| parse_json(&bytes)) {
                Ok(parsed) => parsed,
                Err(e) => return Ok(error(e)),
            };
            parsed_peer
                .and_then(|peer| state.renew(&peer, &parsed.csr_pem))
                .and_then(|credential| json_response(&credential))
        }
        ("POST", "/v1/renew-control") => {
            let Some(chain) = peer else {
                return Ok(error("control renewal requires a client certificate"));
            };
            let parsed_peer = crate::service::parse_peer(&chain);
            let body = read_body(request).await;
            let parsed: RenewControlRequest = match body.and_then(|bytes| parse_json(&bytes)) {
                Ok(parsed) => parsed,
                Err(e) => return Ok(error(e)),
            };
            parsed_peer
                .and_then(|peer| {
                    let target = interflow_identity::PrincipalPath::control(
                        &peer.principal.realm,
                        &peer.principal.node,
                    )?;
                    state.renew_control(&peer, &target, &parsed.old_serial, &parsed.csr_pem)
                })
                .and_then(|credential| json_response(&credential))
        }
        ("POST", "/v1/confirm") => {
            let Some(chain) = peer else {
                return Ok(error("rotation confirmation requires a client certificate"));
            };
            let parsed_peer = crate::service::parse_peer(&chain);
            let body = read_body(request).await;
            let parsed: ConfirmRequest = match body.and_then(|bytes| parse_json(&bytes)) {
                Ok(parsed) => parsed,
                Err(e) => return Ok(error(e)),
            };
            parsed_peer
                .and_then(|peer| state.confirm(&peer, &parsed.renewal_id))
                .and_then(|()| json_response(&serde_json::json!({"confirmed": true})))
        }
        ("POST", "/v1/confirm-control") => {
            let Some(chain) = peer else {
                return Ok(error("control confirmation requires a client certificate"));
            };
            let parsed_peer = crate::service::parse_peer(&chain);
            let body = read_body(request).await;
            let parsed: ConfirmControlRequest = match body.and_then(|bytes| parse_json(&bytes)) {
                Ok(parsed) => parsed,
                Err(e) => return Ok(error(e)),
            };
            parsed_peer
                .and_then(|peer| {
                    let target = interflow_identity::PrincipalPath::control(
                        &peer.principal.realm,
                        &peer.principal.node,
                    )?;
                    state.confirm_control(&peer, &target, &parsed.renewal_id, &parsed.new_serial)
                })
                .and_then(|()| json_response(&serde_json::json!({"confirmed": true})))
        }
        ("GET", "/v1/crls") => crls(&state).and_then(|value| json_response(&value)),
        ("GET", "/health") => json_response(&serde_json::json!({"status":"ok"})),
        _ => Err(interflow_identity::Error::issuance(format!(
            "unknown registrar endpoint {method} {path}"
        ))),
    };
    Ok(match result {
        Ok(response) => response,
        Err(e) => {
            tracing::warn!("registrar rejected request: {e}");
            error(e)
        }
    })
}

async fn read_body(request: Request<Incoming>) -> Result<Vec<u8>> {
    let bytes = request.into_body().collect().await.map_err(|e| {
        interflow_identity::Error::issuance("request body".to_string()).with_source(e)
    })?;
    Ok(bytes.to_bytes().to_vec())
}

fn parse_json<T: for<'de> Deserialize<'de>>(bytes: &[u8]) -> Result<T> {
    serde_json::from_slice(bytes).map_err(|e| {
        interflow_identity::Error::serialize("request JSON".to_string()).with_source(e)
    })
}

fn json_response<T: serde::Serialize>(value: &T) -> Result<Response<Full<Bytes>>> {
    let bytes = serde_json::to_vec(value).map_err(|e| {
        interflow_identity::Error::serialize("response JSON".to_string()).with_source(e)
    })?;
    Response::builder()
        .status(StatusCode::OK)
        .header("content-type", "application/json")
        .body(Full::new(Bytes::from(bytes)))
        .map_err(|e| interflow_identity::Error::serialize("response".to_string()).with_source(e))
}

fn error<E: std::fmt::Display>(e: E) -> Response<Full<Bytes>> {
    let body = serde_json::json!({"error": e.to_string()});
    let bytes = Bytes::from(body.to_string());
    Response::builder()
        .status(StatusCode::BAD_REQUEST)
        .header("content-type", "application/json")
        .body(Full::new(bytes))
        .unwrap_or_else(|_| Response::new(Full::new(Bytes::new())))
}

fn build_acceptor(source: &FileKeySource, options: &ServeOptions) -> Result<TlsAcceptor> {
    let store = source.issuer_store()?;
    let mut roots = RootCertStore::empty();
    add_issuer(&mut roots, store.realm_issuer()?.cert_pem())?;
    for workspace in store.workspace_names()? {
        add_issuer(&mut roots, store.workspace_issuer(&workspace)?.cert_pem())?;
    }
    let provider = Arc::new(aws_lc_rs::default_provider());
    let verifier =
        WebPkiClientVerifier::builder_with_provider(Arc::new(roots), Arc::clone(&provider))
            .allow_unauthenticated()
            .build()
            .map_err(|e| {
                interflow_identity::Error::issuance("registrar client verifier".to_string())
                    .with_source(e)
            })?;
    let certs = load_certs(&options.tls_cert)?;
    let key = load_key(&options.tls_key)?;
    let config = ServerConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .map_err(|e| {
            interflow_identity::Error::issuance("registrar TLS versions".to_string()).with_source(e)
        })?
        .with_client_cert_verifier(verifier)
        .with_single_cert(certs, key)
        .map_err(|e| {
            interflow_identity::Error::issuance("registrar TLS material".to_string()).with_source(e)
        })?;
    Ok(TlsAcceptor::from(Arc::new(config)))
}

fn add_issuer(roots: &mut RootCertStore, pem: &str) -> Result<()> {
    for der in pem_certs(pem.as_bytes())? {
        roots.add(CertificateDer::from(der)).map_err(|e| {
            interflow_identity::Error::issuance("registrar trust root".to_string()).with_source(e)
        })?;
    }
    Ok(())
}

fn load_certs(path: &Path) -> Result<Vec<CertificateDer<'static>>> {
    let bytes = std::fs::read(path).map_err(|e| interflow_identity::Error::Io {
        path: path.display().to_string(),
        source: e,
    })?;
    let mut cursor = std::io::Cursor::new(bytes);
    let certs: Vec<_> = rustls_pemfile::certs(&mut cursor)
        .collect::<std::result::Result<_, _>>()
        .map_err(|e| {
            interflow_identity::Error::issuance(path.display().to_string()).with_source(e)
        })?;
    if certs.is_empty() {
        return Err(interflow_identity::Error::issuance(format!(
            "{} carries no PEM certificate",
            path.display()
        )));
    }
    Ok(certs)
}

fn load_key(path: &Path) -> Result<PrivateKeyDer<'static>> {
    let bytes = std::fs::read(path).map_err(|e| interflow_identity::Error::Io {
        path: path.display().to_string(),
        source: e,
    })?;
    let mut cursor = std::io::Cursor::new(bytes);
    rustls_pemfile::private_key(&mut cursor)
        .map_err(|e| {
            interflow_identity::Error::issuance(path.display().to_string()).with_source(e)
        })?
        .ok_or_else(|| {
            interflow_identity::Error::issuance(format!(
                "{} carries no private key",
                path.display()
            ))
        })
}

fn crls(state: &RegistrarService<FileKeySource>) -> Result<BTreeMap<String, String>> {
    let store = state.source().issuer_store()?;
    let list = RevocationList::load(store.root_path())?;
    let mut by_issuer: BTreeMap<String, Vec<String>> = BTreeMap::new();
    for entry in &list.entries {
        by_issuer
            .entry(entry.issuer.clone())
            .or_default()
            .push(entry.serial.clone());
    }
    let mut out = BTreeMap::new();
    let mut issuers = BTreeSet::from(["control".to_owned()]);
    issuers.extend(
        store
            .workspace_names()?
            .into_iter()
            .map(|workspace| format!("workspace/{workspace}")),
    );
    issuers.extend(by_issuer.keys().cloned());
    for issuer_name in issuers {
        let issuer = match issuer_name.as_str() {
            "control" => store.realm_issuer()?,
            workspace => store.workspace_issuer(workspace.trim_start_matches("workspace/"))?,
        };
        let serials = by_issuer.get(&issuer_name).cloned().unwrap_or_default();
        let number = list.entries.len() as u64 + 1;
        let fingerprint = issuer.fingerprint()?.chars().take(16).collect::<String>();
        let crl = build_crl(&issuer, &serials, number)?;
        out.insert(format!("{issuer_name}-{fingerprint}"), crl);
    }
    Ok(out)
}
