use crate::agent::rules::{EgressRuleView, IngressRuleView, RuleChangeError};
use crate::config::{EgressRule, IngressRule};
use bytes::Bytes;
use http_body_util::{BodyExt, Full};
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper::{Method, Request, Response, StatusCode};
use hyper_util::rt::TokioIo;
use serde::Deserialize;
use std::net::SocketAddr;
use tokio::net::TcpListener;
use tokio::sync::{mpsc, oneshot};
use tracing::{error, info};

// Control-port request body cap: 64 KiB (rule objects are tiny)
const MAX_CONTROL_BODY: usize = 64 * 1024;

/// Acknowledgment error for change commands: the HTTP layer maps status
/// codes from this.
#[derive(Debug, thiserror::Error)]
pub enum ControlOpError {
    /// Applying the rule failed (listen port already in use, etc.) -> 400.
    #[error("{0}")]
    Apply(String),
    /// Rule not found -> 404.
    #[error("rule not found: {0}")]
    NotFound(String),
}

impl From<RuleChangeError> for ControlOpError {
    fn from(e: RuleChangeError) -> Self {
        match e {
            RuleChangeError::NotFound(name) => Self::NotFound(name),
        }
    }
}

#[derive(Debug)]
pub enum RuleCommand<R, V> {
    /// Add (or replace by same name) a rule; replies Ok once it is in
    /// effect.
    Add(R, oneshot::Sender<Result<(), ControlOpError>>),
    /// Remove a rule; replies `NotFound` when absent.
    Remove(String, oneshot::Sender<Result<(), ControlOpError>>),
    /// List rules (with origin annotations).
    List(oneshot::Sender<Vec<V>>),
    // There is deliberately no Sync/push variant: the rule store is the
    // desired-state truth and the handlers reconcile from it level-triggered
    // (subscribing to the store's change notification + a periodic tick).
    // A pushed snapshot was a best-effort edge whose loss silently split
    // desired from actual state until the next session rebuild
}

/// The ingress plane's command shape (typed alias — consumers match on it
/// exactly as before).
pub type IngressCommand = RuleCommand<IngressRule, IngressRuleView>;
/// The egress plane's command shape (typed alias).
pub type EgressCommand = RuleCommand<EgressRule, EgressRuleView>;

pub struct ControlServer {
    listen_addr: SocketAddr,
    /// Log attribution (`AgentInfo::effective_log_name`): every control-API
    /// line carries it, so operator actions are visible in the GUI "This
    /// node" view of the node they targeted.
    node: String,
    ingress_tx: Option<mpsc::Sender<IngressCommand>>,
    egress_tx: Option<mpsc::Sender<EgressCommand>>,
    tunnel: interflow_core::tunnel::AgentTunnel,
    auth_token: Option<String>,
}

impl ControlServer {
    pub const fn new(
        listen_addr: SocketAddr,
        node: String,
        ingress_tx: Option<mpsc::Sender<IngressCommand>>,
        egress_tx: Option<mpsc::Sender<EgressCommand>>,
        tunnel: interflow_core::tunnel::AgentTunnel,
        auth_token: Option<String>,
    ) -> Self {
        Self {
            listen_addr,
            node,
            ingress_tx,
            egress_tx,
            tunnel,
            auth_token,
        }
    }

    pub async fn run(self) -> Result<(), interflow_core::error::InterflowError> {
        let listener = TcpListener::bind(self.listen_addr).await?;
        info!(node = %self.node, "Control API listening on: {}", self.listen_addr);

        let node = self.node;
        let ingress_tx = self.ingress_tx.clone();
        let egress_tx = self.egress_tx.clone();
        let tunnel = self.tunnel.clone();
        let auth_token = self.auth_token.clone();

        loop {
            let (stream, _) = listener.accept().await?;
            let io = TokioIo::new(stream);
            let ingress_tx = ingress_tx.clone();
            let egress_tx = egress_tx.clone();
            let tunnel = tunnel.clone();
            let auth_token = auth_token.clone();
            let node = node.clone();

            tokio::task::spawn(async move {
                let log_node = node.clone();
                if let Err(err) = http1::Builder::new()
                    .serve_connection(
                        io,
                        service_fn(move |req| {
                            handle_request(
                                req,
                                node.clone(),
                                ingress_tx.clone(),
                                egress_tx.clone(),
                                tunnel.clone(),
                                auth_token.clone(),
                            )
                        }),
                    )
                    .await
                {
                    error!(node = %log_node, "Error serving connection: {:?}", err);
                }
            });
        }
    }
}

async fn handle_request(
    req: Request<hyper::body::Incoming>,
    node: String,
    ingress_tx: Option<mpsc::Sender<IngressCommand>>,
    egress_tx: Option<mpsc::Sender<EgressCommand>>,
    tunnel: interflow_core::tunnel::AgentTunnel,
    auth_token: Option<String>,
) -> std::result::Result<Response<Full<Bytes>>, hyper::Error> {
    let (parts, body) = req.into_parts();
    let method = parts.method;
    let path = parts.uri.path();

    // Auth: when a token is configured, every write/read endpoint requires a
    // Bearer. The control port binds 127.0.0.1 by default, but if the user
    // switches it to an external listener, the lack of auth would expose the
    // rule add/remove endpoints.
    if let Some(token) = &auth_token {
        let provided = parts
            .headers
            .get("Authorization")
            .and_then(|v| v.to_str().ok())
            .and_then(|s| s.strip_prefix("Bearer "));
        let ok = match provided {
            Some(p) => {
                let a = p.as_bytes();
                let b = token.as_bytes();
                a.len() == b.len() && {
                    use subtle::ConstantTimeEq;
                    a.ct_eq(b).unwrap_u8() == 1
                }
            }
            None => false,
        };
        if !ok {
            return Ok(response(StatusCode::UNAUTHORIZED, "Unauthorized"));
        }
    }

    // Control-port request body cap (defined at the top of the module)
    match (method, path) {
        (Method::GET, "/agents") => {
            // The hub's agents control plane, read over this session's
            // tunnel — the same trait method for both transports, so the
            // local HTTP face works identically for h2 and QUIC agents
            // (the former h2-only pass-through answered 501 on QUIC).
            // Re-serialized from the transport-uniform type; the JSON shape
            // is field-for-field what the hub serves.
            match tunnel.list_agents().await {
                Ok(list) => {
                    let json = serde_json::to_vec(&list).unwrap_or_else(|_| b"[]".to_vec());
                    Ok(Response::builder()
                        .status(StatusCode::OK)
                        .header("content-type", "application/json")
                        .body(Full::new(Bytes::from(json)))
                        .unwrap())
                }
                Err(e) => {
                    error!(node = %node, "Failed to fetch agents from hub: {}", e);
                    Ok(response(
                        StatusCode::BAD_GATEWAY,
                        &format!("Failed to fetch agents from hub: {e}"),
                    ))
                }
            }
        }
        (Method::GET, "/ingress") => {
            if let Some(tx) = ingress_tx {
                let (resp_tx, resp_rx) = oneshot::channel();
                if let Err(e) = tx.send(IngressCommand::List(resp_tx)).await {
                    error!(node = %node, "Failed to send ingress command: {}", e);
                    return Ok(response(
                        StatusCode::INTERNAL_SERVER_ERROR,
                        "Internal Error",
                    ));
                }
                match resp_rx.await {
                    Ok(views) => {
                        info!(node = %node, "Listing {} ingress rules", views.len());
                        let json =
                            serde_json::to_string(&views).unwrap_or_else(|_| "[]".to_string());
                        Ok(Response::builder()
                            .status(StatusCode::OK)
                            .header("content-type", "application/json")
                            .body(Full::new(Bytes::from(json)))
                            .unwrap())
                    }
                    Err(e) => {
                        error!(node = %node, "Failed to receive ingress result: {}", e);
                        Ok(response(
                            StatusCode::INTERNAL_SERVER_ERROR,
                            "Internal Error",
                        ))
                    }
                }
            } else {
                Ok(response(StatusCode::NOT_IMPLEMENTED, "Ingress not enabled"))
            }
        }
        (Method::GET, "/egress") => {
            if let Some(tx) = egress_tx {
                let (resp_tx, resp_rx) = oneshot::channel();
                if let Err(e) = tx.send(EgressCommand::List(resp_tx)).await {
                    error!(node = %node, "Failed to send egress command: {}", e);
                    return Ok(response(
                        StatusCode::INTERNAL_SERVER_ERROR,
                        "Internal Error",
                    ));
                }
                match resp_rx.await {
                    Ok(views) => {
                        info!(node = %node, "Listing {} egress rules", views.len());
                        let json =
                            serde_json::to_string(&views).unwrap_or_else(|_| "[]".to_string());
                        Ok(Response::builder()
                            .status(StatusCode::OK)
                            .header("content-type", "application/json")
                            .body(Full::new(Bytes::from(json)))
                            .unwrap())
                    }
                    Err(e) => {
                        error!(node = %node, "Failed to receive egress result: {}", e);
                        Ok(response(
                            StatusCode::INTERNAL_SERVER_ERROR,
                            "Internal Error",
                        ))
                    }
                }
            } else {
                Ok(response(StatusCode::NOT_IMPLEMENTED, "Egress not enabled"))
            }
        }
        (Method::POST, "/ingress") => {
            if let Some(tx) = ingress_tx {
                match parse_body::<IngressRule>(body).await {
                    Ok(rule) => {
                        info!(node = %node, "Received add ingress rule request: {}", rule.name);
                        let (resp_tx, resp_rx) = oneshot::channel();
                        if let Err(e) = tx.send(IngressCommand::Add(rule, resp_tx)).await {
                            error!(node = %node, "Failed to send ingress command: {}", e);
                            return Ok(response(
                                StatusCode::INTERNAL_SERVER_ERROR,
                                "Internal Error",
                            ));
                        }
                        Ok(await_op(&node, resp_rx.await, "Ingress rule added"))
                    }
                    Err(e) => Ok(response(StatusCode::BAD_REQUEST, &e.to_string())),
                }
            } else {
                Ok(response(StatusCode::NOT_IMPLEMENTED, "Ingress not enabled"))
            }
        }
        (Method::POST, "/egress") => {
            if let Some(tx) = egress_tx {
                match parse_body::<EgressRule>(body).await {
                    Ok(rule) => {
                        info!(node = %node, "Received add egress rule request: {}", rule.name);
                        let (resp_tx, resp_rx) = oneshot::channel();
                        if let Err(e) = tx.send(EgressCommand::Add(rule, resp_tx)).await {
                            error!(node = %node, "Failed to send egress command: {}", e);
                            return Ok(response(
                                StatusCode::INTERNAL_SERVER_ERROR,
                                "Internal Error",
                            ));
                        }
                        Ok(await_op(&node, resp_rx.await, "Egress rule added"))
                    }
                    Err(e) => Ok(response(StatusCode::BAD_REQUEST, &e.to_string())),
                }
            } else {
                Ok(response(StatusCode::NOT_IMPLEMENTED, "Egress not enabled"))
            }
        }
        (Method::DELETE, path) if path.starts_with("/ingress/") => {
            if let Some(tx) = ingress_tx {
                let name = path.trim_start_matches("/ingress/").to_string();
                info!(node = %node, "Received remove ingress rule request: {}", name);
                let (resp_tx, resp_rx) = oneshot::channel();
                if let Err(e) = tx.send(IngressCommand::Remove(name, resp_tx)).await {
                    error!(node = %node, "Failed to send ingress command: {}", e);
                    return Ok(response(
                        StatusCode::INTERNAL_SERVER_ERROR,
                        "Internal Error",
                    ));
                }
                Ok(await_op(&node, resp_rx.await, "Ingress rule removed"))
            } else {
                Ok(response(StatusCode::NOT_IMPLEMENTED, "Ingress not enabled"))
            }
        }
        (Method::DELETE, path) if path.starts_with("/egress/") => {
            if let Some(tx) = egress_tx {
                let name = path.trim_start_matches("/egress/").to_string();
                info!(node = %node, "Received remove egress rule request: {}", name);
                let (resp_tx, resp_rx) = oneshot::channel();
                if let Err(e) = tx.send(EgressCommand::Remove(name, resp_tx)).await {
                    error!(node = %node, "Failed to send egress command: {}", e);
                    return Ok(response(
                        StatusCode::INTERNAL_SERVER_ERROR,
                        "Internal Error",
                    ));
                }
                Ok(await_op(&node, resp_rx.await, "Egress rule removed"))
            } else {
                Ok(response(StatusCode::NOT_IMPLEMENTED, "Egress not enabled"))
            }
        }
        _ => Ok(response(StatusCode::NOT_FOUND, "Not Found")),
    }
}

/// Await a change acknowledgment and map it to an HTTP response: Ok -> 200;
/// Apply -> 400; NotFound -> 404; channel closed -> 500.
fn await_op(
    node: &str,
    receipt: std::result::Result<
        std::result::Result<(), ControlOpError>,
        oneshot::error::RecvError,
    >,
    ok_body: &str,
) -> Response<Full<Bytes>> {
    match receipt {
        Ok(Ok(())) => response(StatusCode::OK, ok_body),
        Ok(Err(e)) => {
            let status = match &e {
                ControlOpError::Apply(_) => StatusCode::BAD_REQUEST,
                ControlOpError::NotFound(_) => StatusCode::NOT_FOUND,
            };
            response(status, &interflow_util::format_chain(&e))
        }
        Err(e) => {
            error!(node = %node, "Failed to receive rule change result: {}", e);
            response(StatusCode::INTERNAL_SERVER_ERROR, "Internal Error")
        }
    }
}

async fn parse_body<T: for<'a> Deserialize<'a>>(
    body: hyper::body::Incoming,
) -> interflow_core::error::Result<T> {
    let bytes = match http_body_util::Limited::new(body, MAX_CONTROL_BODY)
        .collect()
        .await
    {
        Ok(c) => c.to_bytes(),
        Err(e) => {
            return Err(interflow_core::error::InterflowError::connection(
                "failed to read request body",
            )
            .with_source(e));
        }
    };
    serde_json::from_slice(&bytes).map_err(interflow_core::error::InterflowError::Json)
}

fn response(status: StatusCode, body: &str) -> Response<Full<Bytes>> {
    Response::builder()
        .status(status)
        .body(Full::new(Bytes::from(body.to_string())))
        .unwrap()
}
