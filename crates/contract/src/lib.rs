//! Shared internal contracts for Interflow.
//!
//! These values describe Interflow-owned machine formats. They deliberately do
//! not track the product release version: a release can change behavior
//! without changing a wire or pack format, and a format break must not be
//! inferred from an ordinary release bump.

/// The compatibility epoch for every Interflow-defined machine format.
///
/// This is a marker, not a history: a breaking change to the data-plane
/// frame, inner-stream hello, or Credential Pack layout **redefines the
/// format in place** — peers and packs are rebuilt together (Interflow is
/// deployed as one realm at a time), and the value stays where it is.
/// Endpoints and packs carrying any other value are rejected fail-closed
/// rather than migrated.
pub const FORMAT_VERSION: u8 = 1;

/// A rotation generation.
///
/// The value is monotonic within a deployment's signed objects. A Credential
/// Pack and the Trust Bundle and Runtime Policy embedded in it must carry the
/// same generation. A Runtime Policy *update* (delivered outside the pack —
/// `state/policy` or the control plane) rides the same counter on its own
/// cadence: it must be ≥ the embedded snapshot's generation, and every node
/// refuses anything older than the highest it has applied.
pub type Generation = u64;

/// Capability bits for the QUIC Hello/HelloAck handshake (u32 bitfield on the
/// wire, big-endian).
pub mod caps {
    /// The peer supports the QUIC DATAGRAM fast path for small Data frames
    /// (RFC 9221; eligibility additionally requires an OpenAck on the stream
    /// and the hub-side toggle).
    pub const DATAGRAM: u32 = 1 << 0;
}

/// Close reason codes — the u8 payload of a Close frame
///
/// One shared table so the agent egress producer, the hub relay, and edge
/// consumers cannot drift. The snake_case token spellings live in
/// `interflow-core`'s `CloseReason` (metrics labels); code 0 doubles as
/// "ordinary close" and the fallback for unknown codes.
pub mod close_reason_code {
    /// Ordinary close (peer Close frame, reason-less close, unknown code).
    pub const CLOSE_FRAME: u8 = 0;
    /// No matching egress rule.
    pub const NO_TARGET: u8 = 1;
    /// Denied by security policy (allowed_targets / SSRF blocklist).
    pub const SECURITY_DENIED: u8 = 2;
    /// Dialing the backend failed (resolve / connect / handshake).
    pub const CONNECT_FAILED: u8 = 3;
    /// Backend write timeout.
    pub const BACKEND_WRITE_TIMEOUT: u8 = 4;
    /// Backend connection closed / EOF.
    pub const BACKEND_CLOSED: u8 = 5;
    /// Dispatch poisoned (consumer stalled past its timeout).
    pub const DISPATCH_POISON: u8 = 6;
    /// Stream-open rate limit.
    pub const RATE_LIMITED: u8 = 7;
    /// Per-target circuit breaker OPEN.
    pub const TARGET_CIRCUIT_OPEN: u8 = 8;
    /// Local concurrent stream cap.
    pub const LOCAL_LIMIT: u8 = 9;
    /// UDP forwarder idle timeout.
    pub const UDP_IDLE: u8 = 10;
    /// Session end (token cancelled); local release only.
    pub const SESSION_CLOSED: u8 = 11;
    /// The inner agent↔agent TLS handshake failed, timed out, or never
    /// happened on a stream that required it (fail-closed).
    pub const E2E_HANDSHAKE_FAILED: u8 = 12;
}

/// Error frame codes — the u16 prefix of an Error frame payload.
pub mod error_code {
    /// Registration rejected (identity / tenant / quota).
    pub const REGISTER_REJECTED: u16 = 0x0001;
    /// Generic protocol violation.
    pub const PROTOCOL_VIOLATION: u16 = 0x0002;
}
