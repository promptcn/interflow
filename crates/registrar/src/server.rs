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
use tokio::io::AsyncReadExt;
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
        let (mut stream, peer) =
            listener
                .accept()
                .await
                .map_err(|e| interflow_identity::Error::Io {
                    path: options.listen.to_string(),
                    source: e,
                })?;
        // The nginx stream fragment fronts this listener with PROXY
        // protocol on every SNI-map target; discard the framing before the
        // TLS acceptor sees the wire. Loopback-only, so plain direct
        // connections (the stand-alone deployment) are untouched.
        if let Err(reason) = consume_proxy_header(&mut stream, peer).await {
            tracing::warn!("registrar PROXY protocol framing failed ({reason}): peer={peer}");
            continue;
        }
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

/// PROXY protocol v2 signature (12 bytes): `\r\n\r\n\0\r\nQUIT\n`. Framing
/// twin of `interflow-core`'s parser — this crate deliberately does not
/// depend on interflow-core (registrar keeps its dependency surface
/// minimal), so the two agree on the wire shape only; policy stays on the
/// core side and this side makes no trust decisions.
const PROXY_V2_SIG: [u8; 12] = [
    0x0D, 0x0A, 0x0D, 0x0A, 0x00, 0x0D, 0x0A, 0x51, 0x55, 0x49, 0x54, 0x0A,
];
/// v1 (text) preamble prefix.
const PROXY_V1_PREFIX: &[u8; 6] = b"PROXY ";
/// v1 line cap including the CRLF (spec limit; bounds how far the framing
/// scan is willing to look).
const PROXY_V1_MAX: usize = 108;
/// v2 total cap: fixed header plus declared payload.
const PROXY_V2_MAX: usize = 1024;
/// Same budget discipline as the edge/hub pre-TLS sniff stages (slow
/// loris preamble dribble must not hold an accept slot).
const PROXY_READ_BUDGET: Duration = Duration::from_secs(10);

/// Peeks until `buf.len()` bytes are visible at the front of the stream
/// (peek never consumes, and always returns bytes from the front, so the
/// fill is tracked as the high-water mark, not a cursor).
async fn peek_exact(
    stream: &tokio::net::TcpStream,
    buf: &mut [u8],
) -> std::result::Result<usize, &'static str> {
    let mut seen = 0usize;
    while seen < buf.len() {
        let n = stream
            .peek(buf)
            .await
            .map_err(|_| "read error while peeking preamble")?;
        if n == 0 {
            return Err("EOF while peeking preamble");
        }
        seen = seen.max(n);
    }
    Ok(seen)
}

/// Discards a PROXY protocol (v1 or v2) preamble from the front of the
/// stream when the loopback front (nginx stream SNI dispatch, which emits
/// the preamble on every map target) sent one. Framing only: the source
/// address is dropped — the registrar makes no per-IP decisions, so a
/// `PROXY UNKNOWN` line carries exactly as much information as a real one.
///
/// Discrimination is by first byte: `0x0D` starts the v2 signature, `P`
/// starts the v1 text; a TLS ClientHello (`0x16`) or any other byte is a
/// direct connection and passes through untouched. A preamble that
/// announces itself but never completes (timeout / EOF / over the caps) is
/// dropped fail-closed; a prefix that diverges mid-way is handed to the
/// TLS layer, which rejects it as garbage anyway.
async fn consume_proxy_header(
    stream: &mut tokio::net::TcpStream,
    peer: SocketAddr,
) -> std::result::Result<(), &'static str> {
    if !peer.ip().is_loopback() {
        // Only the same-host nginx fronts this listener; a remote peer has
        // no legitimate preamble and gets the plain TLS treatment.
        return Ok(());
    }
    tokio::time::timeout(PROXY_READ_BUDGET, async {
        let mut first = [0u8; 1];
        peek_exact(stream, &mut first).await?;
        match first[0] {
            // v2: 12-byte signature, then ver/cmd + fam/proto + u16 length
            // in the 16-byte fixed header; consume exactly the fixed part
            // plus the declared payload.
            0x0D => {
                let mut fixed = [0u8; 16];
                peek_exact(stream, &mut fixed).await?;
                if fixed[..12] != PROXY_V2_SIG {
                    // Started like the signature but diverged: not a
                    // preamble we recognize.
                    return Ok(());
                }
                let len = u16::from_be_bytes([fixed[14], fixed[15]]) as usize;
                let total = 16 + len;
                if total > PROXY_V2_MAX {
                    return Err("v2 header exceeds size cap");
                }
                let mut header = vec![0u8; total];
                stream
                    .read_exact(&mut header)
                    .await
                    .map_err(|_| "EOF inside v2 header")?;
                Ok(())
            }
            // v1: text line; watch (without consuming) for the CRLF within
            // the cap, then read exactly through it so the TLS bytes that
            // follow are never touched.
            b'P' => {
                let mut window = [0u8; PROXY_V1_MAX];
                loop {
                    let n = stream
                        .peek(&mut window)
                        .await
                        .map_err(|_| "read error while peeking preamble")?;
                    if n == 0 {
                        return Err("EOF inside v1 header");
                    }
                    if n >= PROXY_V1_PREFIX.len()
                        && window[..PROXY_V1_PREFIX.len()] != *PROXY_V1_PREFIX
                    {
                        // "P..." that is not "PROXY ": plain bytes.
                        return Ok(());
                    }
                    if let Some(pos) = window[..n].windows(2).position(|w| w == b"\r\n") {
                        let mut line = vec![0u8; pos + 2];
                        stream
                            .read_exact(&mut line)
                            .await
                            .map_err(|_| "EOF inside v1 header")?;
                        return Ok(());
                    }
                    if n >= PROXY_V1_MAX {
                        return Err("v1 header exceeds size cap");
                    }
                    // Peek blocks until more bytes arrive; the outer
                    // timeout bounds a preamble that never completes.
                }
            }
            // TLS ClientHello (0x16) or anything else: direct connection.
            _ => Ok(()),
        }
    })
    .await
    .map_err(|_| "read budget exceeded while consuming preamble")?
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
