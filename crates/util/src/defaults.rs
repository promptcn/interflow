//! Deployment topology defaults shared by the renderer and the engine.
//!
//! These constants pin the **render-time** defaults a Credential Pack carries
//! (`node.toml`'s `[edge]` section resolves them, so the artifact always names
//! concrete values) and the engine's hand-built fallbacks. They live in util —
//! the one crate both the identity renderer and the expose engine depend on —
//! so the two sides can never drift apart.

/// Default per-IP new-connection rate limit per minute for direct topologies
/// (the edge itself terminates the public listener).
///
/// The browser's own HTTP keepalive keeps new connections rare, and there is
/// no front proxy to shield the listener, so a tight cap preserves most of
/// its connect-loop defense.
pub const DEFAULT_NEW_CONN_RATE_PER_IP_PER_MINUTE: u32 = 30;

/// Default per-IP new-connection rate limit per minute for fronted topologies
/// (nginx/`proxy_pass` in front).
///
/// Each proxied request opens a **new** edge connection (conn → tunnel stream
/// is one-to-one; the front cannot reuse them), so a single user's normal SPA
/// browsing alone exceeds the direct default. 600/min matches the reference
/// front's own `limit_req 10r/s` — the edge gate aligns with what the front
/// lets through anyway, while still capping connect floods
/// (see (internal design notes)).
pub const DEFAULT_FRONTED_NEW_CONN_RATE_PER_IP_PER_MINUTE: u32 = 600;

/// The default public-HTTPS ACME directory (Let's Encrypt production).
///
/// The renderer writes this URL into `node.toml` whenever the manifest leaves
/// `public_tls.directory` unset, so a canonical pack always names the concrete
/// directory it will dial.
pub const LETS_ENCRYPT_PRODUCTION: &str = "https://acme-v02.api.letsencrypt.org/directory";
