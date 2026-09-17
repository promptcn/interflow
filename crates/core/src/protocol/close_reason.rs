//! Typed close reason for tunnel stream Close frames (the `CLOSE:{sid}:{token}`
//! payload).
//!
//! Single source of truth for the reason tokens the agent egress produces
//! ([`CloseReason::as_str`]) and every consumer classifies by
//! ([`CloseReason::from_token`]). Until 2026-09-17 the enum lived privately in
//! the mesh egress and downstream consumers (the expose edge route breaker)
//! matched raw strings against hand-copied token lists — adding a reason could
//! silently drift between producer and consumers
//! (docs/bug/2026-09-17-edge-route-breaker-stuck-open.md).
//!
//! Wire compatibility: tokens are plain ASCII words in the Close payload. An
//! unknown token from a newer peer decodes to [`CloseReason::Other`] and
//! round-trips unchanged — never a protocol error. The hub stays token-opaque
//! (charset-validating relay) and does not interpret this enum.

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
    /// A token this build does not know (newer peer); preserved verbatim so
    /// relays and logs never lie about what the peer said.
    Other(String),
}

impl CloseReason {
    /// The wire token / metrics label for this reason.
    pub fn as_str(&self) -> &str {
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
            Self::Other(token) => token,
        }
    }

    /// Decodes a wire token; the empty token is the ordinary reason-less
    /// close ([`CloseReason::CloseFrame`]), and anything unrecognized becomes
    /// [`CloseReason::Other`] carrying the token verbatim (forward
    /// compatibility).
    pub fn from_token(token: &str) -> Self {
        match token {
            // The empty token is the ordinary reason-less close; "close_frame"
            // is its canonical name (both decode identically).
            "" | "close_frame" => Self::CloseFrame,
            "no_target" => Self::NoTarget,
            "security_denied" => Self::SecurityDenied,
            "connect_failed" => Self::ConnectFailed,
            "backend_write_timeout" => Self::BackendWriteTimeout,
            "backend_closed" => Self::BackendClosed,
            "dispatch_poison" => Self::DispatchPoison,
            "rate_limited" => Self::RateLimited,
            "target_circuit_open" => Self::TargetCircuitOpen,
            "local_limit" => Self::LocalLimit,
            "udp_idle" => Self::UdpIdle,
            "session_closed" => Self::SessionClosed,
            other => Self::Other(other.to_string()),
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

    /// Every defined token round-trips through the codec; unknown tokens are
    /// preserved verbatim (a newer peer's reason must survive an older relay).
    #[test]
    fn tokens_round_trip() {
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
        ];
        for reason in &known {
            assert_eq!(
                CloseReason::from_token(reason.as_str()),
                *reason,
                "token {} must round-trip",
                reason.as_str()
            );
        }
    }

    #[test]
    fn unknown_token_becomes_other_and_survives_relay() {
        let decoded = CloseReason::from_token("new_future_reason");
        assert_eq!(decoded, CloseReason::Other("new_future_reason".into()));
        // Round-trips verbatim: an older relay never mangles a newer reason.
        assert_eq!(
            CloseReason::from_token(decoded.as_str()),
            CloseReason::Other("new_future_reason".into())
        );
    }

    /// The empty token is the ordinary reason-less close on the wire
    /// (`CLOSE:{sid}:`), so it must decode to `CloseFrame`, never to a
    /// *named* reason or `Other`.
    #[test]
    fn empty_token_is_the_ordinary_close() {
        assert_eq!(CloseReason::from_token(""), CloseReason::CloseFrame);
        // And CloseFrame itself still round-trips through the empty token.
        assert_eq!(CloseReason::CloseFrame.as_str(), "close_frame");
        assert_eq!(
            CloseReason::from_token(CloseReason::CloseFrame.as_str()),
            CloseReason::CloseFrame
        );
    }

    /// Tokens must stay `snake_case` words — they end up as metrics label
    /// values and hub `close_reason_of` only relays `[A-Za-z0-9_.-]+`.
    #[test]
    fn tokens_are_metrics_label_safe() {
        for reason in [
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
        ] {
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
