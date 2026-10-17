//! HTTP clients for tests.
//!
//! One construction point for every reqwest client a test builds: it must
//! never honor ambient proxy configuration. Test traffic targets in-process
//! servers on loopback; on hosts where Docker Desktop (or a corporate
//! environment) injects `http(s)_proxy`, reqwest's default env-proxy honor
//! reroutes those requests to a proxy that cannot reach the container's
//! own loopback — the 2026-10-17 registrar Linux backlog turned out to be
//! exactly this hijack, invisible on the server side (zero accepts) and
//! fatal on the client side (fast opaque EOF).

/// A reqwest client builder that dials directly, ignoring any ambient
/// proxy environment. Tests add their trust anchors and identities on
/// top; everything loopback-bound goes through here so the class stays
/// fixed once.
pub fn direct_client() -> reqwest::ClientBuilder {
    reqwest::Client::builder().no_proxy()
}
