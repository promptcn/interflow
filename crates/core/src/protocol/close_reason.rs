//! Typed close reason for tunnel stream Close frames.
//!
//! Single source of truth for the reason codes the agent egress produces
//! ([`CloseReason::as_code`]) and every consumer classifies by
//! ([`CloseReason::from_code`]). Until 2026-09-17 the enum lived privately in
//! the mesh egress and downstream consumers (the expose edge route breaker)
//! matched raw strings against hand-copied token lists — adding a reason could
//! silently drift between producer and consumers
//!. The wire format
//! carries the reason as a single u8 code
//! from the shared `interflow_contract::close_reason_code` table; the
//! snake_case tokens below remain the metrics labels.
//!
//! Wire compatibility: hub and agent deploy as one paired build (single
//! format epoch, no version skew) — any code this build does not recognize
//! is treated as the ordinary reason-less close
//! ([`CloseReason::CloseFrame`]). The hub stays code-opaque (length-checked
//! relay) and does not interpret this enum.

use interflow_contract::close_reason_code as code;
use std::fmt;

/// Why a tunnel stream ended (agent egress producer → hub relay → edge
/// consumer).
///
/// Doubles as the reason tag of `interflow_egress_stream_closed_total` and the
/// open-drop counter `interflow_agent_open_dropped_total`; do not rename
/// tokens without a metrics migration.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CloseReason {
    /// No matching egress rule.
    NoTarget,
    /// Denied by security policy (allowed_targets / SSRF blocklist).
    SecurityDenied,
    /// Dialing the backend failed (resolve / connect / handshake).
    ConnectFailed,
    /// Close frame from the peer (normal close, no echo).
    CloseFrame,
    /// Backend write timeout.
    BackendWriteTimeout,
    /// Backend connection closed / EOF.
    BackendClosed,
    /// Dispatch poisoned (consumer stalled past its timeout).
    DispatchPoison,
    /// Stream-open rate limit.
    RateLimited,
    /// Per-target circuit breaker OPEN (connect-phase failures clustered on
    /// this target; rejected pre-dial without consuming the open budget).
    TargetCircuitOpen,
    /// Local concurrent stream cap.
    LocalLimit,
    /// UDP forwarder idle timeout.
    UdpIdle,
    /// Session end (token cancelled): no Close echo (the tunnel is dead);
    /// local release only.
    SessionClosed,
    /// The inner agent↔agent TLS handshake (e2e encryption) failed, timed
    /// out, or never happened on a stream that required it — the stream is
    /// closed instead of degrading to plaintext (fail-closed; RFC
    /// (internal design notes) §3.5/§4).
    E2eHandshakeFailed,
}

impl CloseReason {
    /// The metrics label / display token for this reason.
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::NoTarget => "no_target",
            Self::SecurityDenied => "security_denied",
            Self::ConnectFailed => "connect_failed",
            Self::CloseFrame => "close_frame",
            Self::BackendWriteTimeout => "backend_write_timeout",
            Self::BackendClosed => "backend_closed",
            Self::DispatchPoison => "dispatch_poison",
            Self::RateLimited => "rate_limited",
            Self::TargetCircuitOpen => "target_circuit_open",
            Self::LocalLimit => "local_limit",
            Self::UdpIdle => "udp_idle",
            Self::SessionClosed => "session_closed",
            Self::E2eHandshakeFailed => "e2e_handshake_failed",
        }
    }

    /// The u8 Close payload code (the shared
    /// `interflow_contract::close_reason_code` table).
    pub const fn as_code(&self) -> u8 {
        match self {
            Self::CloseFrame => code::CLOSE_FRAME,
            Self::NoTarget => code::NO_TARGET,
            Self::SecurityDenied => code::SECURITY_DENIED,
            Self::ConnectFailed => code::CONNECT_FAILED,
            Self::BackendWriteTimeout => code::BACKEND_WRITE_TIMEOUT,
            Self::BackendClosed => code::BACKEND_CLOSED,
            Self::DispatchPoison => code::DISPATCH_POISON,
            Self::RateLimited => code::RATE_LIMITED,
            Self::TargetCircuitOpen => code::TARGET_CIRCUIT_OPEN,
            Self::LocalLimit => code::LOCAL_LIMIT,
            Self::UdpIdle => code::UDP_IDLE,
            Self::SessionClosed => code::SESSION_CLOSED,
            Self::E2eHandshakeFailed => code::E2E_HANDSHAKE_FAILED,
        }
    }

    /// Decodes a u8 Close payload code. Code 0 and any unrecognized code
    /// decode to the ordinary reason-less close ([`CloseReason::CloseFrame`])
    /// — peers are deployed as one paired build, so an unknown code is not a
    /// newer-peer case to preserve, just an ordinary close.
    pub const fn from_code(value: u8) -> Self {
        match value {
            code::NO_TARGET => Self::NoTarget,
            code::SECURITY_DENIED => Self::SecurityDenied,
            code::CONNECT_FAILED => Self::ConnectFailed,
            code::BACKEND_WRITE_TIMEOUT => Self::BackendWriteTimeout,
            code::BACKEND_CLOSED => Self::BackendClosed,
            code::DISPATCH_POISON => Self::DispatchPoison,
            code::RATE_LIMITED => Self::RateLimited,
            code::TARGET_CIRCUIT_OPEN => Self::TargetCircuitOpen,
            code::LOCAL_LIMIT => Self::LocalLimit,
            code::UDP_IDLE => Self::UdpIdle,
            code::SESSION_CLOSED => Self::SessionClosed,
            code::E2E_HANDSHAKE_FAILED => Self::E2eHandshakeFailed,
            _ => Self::CloseFrame,
        }
    }

    /// Decodes a Close frame payload slice (exactly one code byte expected;
    /// empty or longer payloads are the ordinary close — the hub relays
    /// length-checked, agents produce exactly one byte).
    pub const fn from_payload(payload: &[u8]) -> Self {
        match payload {
            [b] => Self::from_code(*b),
            _ => Self::CloseFrame,
        }
    }
}

impl fmt::Display for CloseReason {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

#[cfg(test)]
#[allow(clippy::panic, clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    /// Every defined reason round-trips through the wire code.
    #[test]
    fn codes_round_trip() {
        let known = [
            CloseReason::NoTarget,
            CloseReason::SecurityDenied,
            CloseReason::ConnectFailed,
            CloseReason::CloseFrame,
            CloseReason::BackendWriteTimeout,
            CloseReason::BackendClosed,
            CloseReason::DispatchPoison,
            CloseReason::RateLimited,
            CloseReason::TargetCircuitOpen,
            CloseReason::LocalLimit,
            CloseReason::UdpIdle,
            CloseReason::SessionClosed,
            CloseReason::E2eHandshakeFailed,
        ];
        // Codes are pairwise distinct — the table cannot drift into aliasing.
        let mut codes: Vec<u8> = known.iter().map(CloseReason::as_code).collect();
        codes.sort_unstable();
        codes.dedup();
        assert_eq!(codes.len(), known.len(), "reason codes must be distinct");
        for reason in &known {
            assert_eq!(
                CloseReason::from_code(reason.as_code()),
                *reason,
                "code {} must round-trip",
                reason.as_code()
            );
            assert_eq!(CloseReason::from_payload(&[reason.as_code()]), *reason);
        }
    }

    #[test]
    fn unknown_codes_and_malformed_payloads_decode_to_ordinary_close() {
        // Paired single-epoch deploys: an unrecognized code has no
        // newer-peer meaning to preserve — it is an ordinary close.
        assert_eq!(CloseReason::from_code(13), CloseReason::CloseFrame);
        assert_eq!(CloseReason::from_code(255), CloseReason::CloseFrame);
        assert_eq!(
            CloseReason::from_code(code::CLOSE_FRAME),
            CloseReason::CloseFrame
        );
        // Empty / oversized payloads: ordinary close.
        assert_eq!(CloseReason::from_payload(&[]), CloseReason::CloseFrame);
        assert_eq!(
            CloseReason::from_payload(&[code::CONNECT_FAILED, 0]),
            CloseReason::CloseFrame
        );
    }

    /// Tokens must stay `snake_case` words — they end up as metrics label
    /// values.
    #[test]
    fn tokens_are_metrics_label_safe() {
        let all = [
            CloseReason::NoTarget,
            CloseReason::SecurityDenied,
            CloseReason::ConnectFailed,
            CloseReason::CloseFrame,
            CloseReason::BackendWriteTimeout,
            CloseReason::BackendClosed,
            CloseReason::DispatchPoison,
            CloseReason::RateLimited,
            CloseReason::TargetCircuitOpen,
            CloseReason::LocalLimit,
            CloseReason::UdpIdle,
            CloseReason::SessionClosed,
            CloseReason::E2eHandshakeFailed,
        ];
        for reason in all {
            let token = reason.as_str();
            assert!(
                token
                    .bytes()
                    .all(|b| b.is_ascii_lowercase() || b == b'_' || b.is_ascii_digit()),
                "token {token} must be a lowercase snake_case word"
            );
        }
    }
}
