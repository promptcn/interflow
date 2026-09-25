//! Consumer-side mirrors of the hub's operator HTTP contracts, plus the
//! single shared e2e client for `GET /agents`.
//!
//! The mirror types are deliberately independent of the producer types in
//! `interflow_mesh::hub::http` (they must NOT be imported from there): the
//! e2e guards deserialize real wire bytes into these hand-written shapes,
//! so any producer-side contract drift — rename, retype, removal, or an
//! additive field (`deny_unknown_fields`) — fails the guards in the same
//! commit. This is the hub-HTTP-surface analog of the GUI bindings drift
//! guard (`bindings_ts_is_fresh`); see
//! (internal design notes).

use http_body_util::BodyExt;
use hyper::client::conn::http2::SendRequest;
use hyper::{Request, Response};
use interflow_core::tunnel::H2RequestBody;
use serde::Deserialize;

/// One `GET /agents` entry as a consumer reads it (mirror of
/// `interflow_mesh::hub::http::AgentListEntry`).
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AgentListEntry {
    /// Qualified agent id (`tenant/agent`).
    pub agent: String,
    /// Credential health parsed from the registration certificate; null
    /// when the leaf did not parse.
    pub leaf_expiry: Option<LeafExpiry>,
}

/// The `leaf_expiry` object (mirror of
/// `interflow_mesh::hub::http::LeafExpiry`).
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LeafExpiry {
    pub not_after_unix: i64,
    pub remaining_secs: i64,
    pub phase: LeafPhaseWire,
}

/// The phase spelling on the wire — strict on purpose: an unknown string
/// (e.g. a renamed phase) fails deserialization instead of passing
/// silently. Mirrors `interflow_identity::expiry::LeafPhase::as_str`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LeafPhaseWire {
    /// More than the warn ratio of the TTL remains.
    Healthy,
    /// Less than the warn ratio remains — rotate soon.
    Warn,
    /// Less than the critical ratio remains (or already expired).
    Critical,
}

/// Whether a listing contains the given qualified agent id — the
/// membership check every e2e guard expresses over `/agents` (the
/// qualified id is the listing's identity key).
pub fn has_agent(list: &[AgentListEntry], qualified: &str) -> bool {
    list.iter().any(|e| e.agent == qualified)
}

/// `GET /agents` over an established mTLS h2 connection — the single
/// shared implementation (request plumbing + status assertion +
/// contract-guarded deserialization). Divergent per-file copies of this
/// helper are how the 2026-09-25 shape drift stayed unfound.
pub async fn list_agents(snd: &mut SendRequest<H2RequestBody>) -> Vec<AgentListEntry> {
    snd.ready().await.expect("ready");
    let req = Request::builder()
        .method("GET")
        .uri("/agents")
        .body(interflow_core::tunnel::empty_request_body())
        .unwrap();
    let resp: Response<hyper::body::Incoming> = snd.send_request(req).await.expect("agents");
    assert!(
        resp.status().is_success(),
        "authenticated identity should be able to list its own tenant"
    );
    let body = resp.into_body().collect().await.expect("body").to_bytes();
    serde_json::from_slice(&body).expect("agents json")
}
