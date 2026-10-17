//! Shared internal contracts for Interflow.
//!
//! These values describe Interflow-owned machine formats. They deliberately do
//! not track the product release version: a release can change behavior
//! without changing a wire or pack format, and a format break must not be
//! inferred from an ordinary release bump.

/// The compatibility epoch for every Interflow-defined machine format
/// (data-plane frames, the inner-stream hello, Credential Pack metadata).
///
/// A **monotonic epoch**, not an in-place marker: a breaking change to any
/// of those formats bumps this value, and every peer and pack moves together
/// following the coordinated-upgrade runbook — endpoints and packs carrying
/// any other value are rejected fail-closed rather than migrated. While the
/// protocol is in its `0.x` churn phase the check is strict equality on both
/// sides (a mixed-version realm fails closed at the first frame); additive
/// evolution — unknown frame types, unknown flag bits, unknown JSON keys,
/// unknown caps bits — never bumps the epoch (documentation/versioning.md,
/// "Format epoch"). A breaking change must pair the bump with a MINOR
/// release and a CHANGELOG migration section.
pub const FORMAT_VERSION: u8 = 1;

/// The generational-handle contract.
///
/// The single compare-before-mutate pattern shared by every
/// rotation-guarded surface (policy generation watermark, session channel
/// generation, circuit witness).
pub mod generation;
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
///
/// Additive wire features are gated here, never by epoch bumps: a sender may
/// use a new wire feature only once the peer advertised the bit (the
/// handshake ANDs both sides; unknown bits are ignored, not rejected). A
/// change that cannot be expressed as an addition is breaking and bumps
/// `FORMAT_VERSION` instead — there is no third kind (documentation/versioning.md,
/// "Additive changes never bump the epoch").
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
