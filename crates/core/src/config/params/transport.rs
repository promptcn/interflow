//! Transport profile: h2/QUIC transport-layer tuning, single-sourced for
//! both endpoints.
//!
//! Before this module, each endpoint carried its own copies: the agent's h2
//! keepalive (5s/10s) and the hub's (10s/20s) were asymmetric hard-coded
//! values that ignored each other and bypassed the `[heartbeat]` config; the
//! QUIC idle/keepalive values existed once in the hub TOML schema and once
//! as hard-coded constants in the agent-side QUIC client — and because QUIC
//! negotiates the idle timeout as the *minimum* of both endpoints, tuning
//! the hub-side knob above the agent-side constant silently did nothing.
//!
//! One profile, used by both ends, removes both classes of drift. The TOML
//! schemas (mesh `[transport]` on hub and agent) override fields of this
//! profile; anything not exposed in TOML references the same defaults.
//!
//! Cross-layer invariants (enforced by tests below):
//! - keepalive timeout > keepalive interval (both transports);
//! - transport-layer keepalive timeout < app-layer heartbeat dead line
//!   (75s at the default cadence): a dead TCP/QUIC connection is always
//!   detected at the transport layer before the application layer gives up;
//! - h2 stream window < h2 connection window.

use std::time::Duration;

/// Default h2 HTTP/2 PING keepalive interval, both endpoints.
///
/// The agent side proved 5s (sleep-wake dead-connection detection,
/// 2026-08-19); the hub now uses the same value so both ends detect a dead
/// connection equally fast.
pub const DEFAULT_H2_KEEPALIVE_INTERVAL: Duration = Duration::from_secs(5);

/// Default h2 keepalive timeout (interval + this = give up), both endpoints.
pub const DEFAULT_H2_KEEPALIVE_TIMEOUT: Duration = Duration::from_secs(10);

/// Default h2 per-stream initial window. hyper's default 64KiB is the
/// bottleneck at ~300Mbps over a 50ms-RTT path; 2MiB covers that BDP.
pub const DEFAULT_H2_STREAM_WINDOW: u32 = 2 * 1024 * 1024;

/// Default h2 per-connection initial window; strictly above the stream
/// window so multiple streams can keep their windows filled concurrently.
pub const DEFAULT_H2_CONNECTION_WINDOW: u32 = 4 * 1024 * 1024;

/// Default QUIC idle timeout (milliseconds), both endpoints.
///
/// QUIC negotiates the *minimum* of the two endpoints' idle timeouts — a
/// value above this on one side alone has no effect, which is why both
/// sides source it from here. Follows the frp default (backlog §6.4).
pub const DEFAULT_QUIC_IDLE_TIMEOUT_MS: u32 = 30_000;

/// Default QUIC keepalive interval, both endpoints; must stay strictly below
/// the idle timeout or keepalives cannot preempt it. Follows the frp default.
pub const DEFAULT_QUIC_KEEPALIVE_INTERVAL: Duration = Duration::from_secs(10);

/// Transport-layer tuning shared verbatim by the hub and agent endpoints.
///
/// Fields mirror the TOML `[transport]` schema; the [`Default`] impl is the
/// single source every construction site (hub accept, agent client, QUIC
/// endpoints on both sides) starts from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TransportProfile {
    /// h2 HTTP/2 PING keepalive interval.
    pub h2_keepalive_interval: Duration,
    /// h2 keepalive timeout: no PING ACK within `interval + timeout` → the
    /// connection is dead.
    pub h2_keepalive_timeout: Duration,
    /// h2 per-stream initial flow-control window (bytes).
    pub h2_stream_window: u32,
    /// h2 per-connection initial flow-control window (bytes).
    pub h2_connection_window: u32,
    /// QUIC idle timeout in milliseconds (negotiated as the endpoints'
    /// minimum).
    pub quic_idle_timeout_ms: u32,
    /// QUIC keepalive interval.
    pub quic_keepalive_interval: Duration,
}

impl Default for TransportProfile {
    fn default() -> Self {
        Self {
            h2_keepalive_interval: DEFAULT_H2_KEEPALIVE_INTERVAL,
            h2_keepalive_timeout: DEFAULT_H2_KEEPALIVE_TIMEOUT,
            h2_stream_window: DEFAULT_H2_STREAM_WINDOW,
            h2_connection_window: DEFAULT_H2_CONNECTION_WINDOW,
            quic_idle_timeout_ms: DEFAULT_QUIC_IDLE_TIMEOUT_MS,
            quic_keepalive_interval: DEFAULT_QUIC_KEEPALIVE_INTERVAL,
        }
    }
}

/// Default client-facing write-stall tolerance.
///
/// How long a tunnel client (mesh ingress response path / expose edge public
/// listener) waits on a stalled downstream write before declaring the stream
/// dead. Sits inside the write-stall family ordering (per-stream 10s <
/// session-level 30s < hub channel-send 30s eviction), previously duplicated
/// as same-named literals in mesh and expose.
pub const DEFAULT_CLIENT_WRITE_STALL_TIMEOUT: Duration = Duration::from_secs(10);

/// Floor for the derived new-stream event channel capacity (see
/// [`incoming_channel_cap`]).
pub const INCOMING_CHANNEL_CAP_FLOOR: usize = 256;

/// Capacity of the agent's new-stream event channel, derived from the
/// configured local concurrent-stream limit (`max_incoming_streams`).
///
/// A legitimate whole-table stream-creation burst must pass the channel in
/// one go instead of tripping the bounded hand-off wait.
///
/// `0` (unlimited streams) cannot size a channel to infinity and falls back
/// to [`INCOMING_CHANNEL_CAP_FLOOR`]; backlog beyond capacity remains bounded
/// by the transport's hand-off timeout either way.
#[must_use]
pub const fn incoming_channel_cap(max_incoming_streams: usize) -> usize {
    if max_incoming_streams > INCOMING_CHANNEL_CAP_FLOOR {
        max_incoming_streams
    } else {
        INCOMING_CHANNEL_CAP_FLOOR
    }
}

#[cfg(test)]
#[allow(clippy::panic, clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use crate::config::params::liveness::HeartbeatCadence;

    /// Keepalive timing invariants: timeout outlasts interval on both
    /// transports, and transport-layer detection stays strictly inside the
    /// app-layer heartbeat dead line.
    #[test]
    fn keepalive_timing_invariants() {
        let p = TransportProfile::default();
        assert!(p.h2_keepalive_timeout > p.h2_keepalive_interval);
        assert!(
            Duration::from_millis(u64::from(p.quic_idle_timeout_ms)) > p.quic_keepalive_interval,
            "QUIC keepalive must preempt the idle timeout"
        );

        let dead_line = HeartbeatCadence::DEFAULT.dead_line();
        assert!(
            p.h2_keepalive_interval + p.h2_keepalive_timeout < dead_line,
            "h2 keepalive must detect a dead connection before the app-layer dead line"
        );
        assert!(
            p.quic_keepalive_interval + Duration::from_millis(u64::from(p.quic_idle_timeout_ms))
                < dead_line,
            "QUIC keepalive must detect a dead connection before the app-layer dead line"
        );
    }

    /// h2 window sizing: the connection window strictly exceeds the stream
    /// window.
    #[test]
    fn h2_window_invariants() {
        let p = TransportProfile::default();
        assert!(p.h2_connection_window > p.h2_stream_window);
    }

    /// The derived event-channel capacity covers the whole table for any
    /// finite stream limit and falls back to the floor for 0/unlimited.
    #[test]
    fn incoming_cap_covers_stream_table() {
        assert_eq!(incoming_channel_cap(0), INCOMING_CHANNEL_CAP_FLOOR);
        assert_eq!(incoming_channel_cap(1), INCOMING_CHANNEL_CAP_FLOOR);
        assert_eq!(incoming_channel_cap(256), INCOMING_CHANNEL_CAP_FLOOR);
        assert_eq!(incoming_channel_cap(512), 512);
        assert!(incoming_channel_cap(4096) >= 4096);
    }
}
