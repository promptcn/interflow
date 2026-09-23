//! Canonical parameter layer: single-source defaults and derivations for
//! every tunable that more than one module cares about.
//!
//! Four families live here (see the submodule docs for the rationale and
//! the pre-unification history):
//!
//! - [`liveness`]: the heartbeat cadence and the whole derived chain
//!   (dead line → poll watchdog → task stall → recovery budget);
//! - [`transport`]: the h2/QUIC transport profile shared by both endpoints,
//!   plus the derived new-stream channel capacity;
//! - [`breaker`]: circuit-breaker policies with named, documented defaults;
//! - [`shutdown`]: the bounded session wind-down budget.
//!
//! Rules of the house:
//! 1. A value that more than one crate references is defined exactly once,
//!    here (or re-exported from here).
//! 2. When parameter B is mathematically dependent on parameter A, B is
//!    *derived* from A in code — never independently configured, never
//!    kept consistent by comments.
//! 3. Invariants between parameters are locked by tests in this module, so
//!    a future edit that breaks the chain fails CI instead of production.

pub mod breaker;
pub mod liveness;
pub mod shutdown;
pub mod transport;

pub use breaker::BreakerPolicy;
pub use liveness::{
    BACKOFF_CAP, BACKOFF_FLOOR, HEARTBEAT_DISABLED_POLL, HEARTBEAT_SUMMARY_PERIOD,
    HeartbeatCadence, RECOVERY_MARGIN_SECS, TASK_STALL_FALLBACK_SECS, WATCHDOG_MARGIN_SECS,
    recovery_budget,
};
pub use shutdown::ShutdownBudget;
pub use transport::{
    DEFAULT_CLIENT_WRITE_STALL_TIMEOUT, DEFAULT_H2_CONNECTION_WINDOW,
    DEFAULT_H2_KEEPALIVE_INTERVAL, DEFAULT_H2_KEEPALIVE_TIMEOUT, DEFAULT_H2_STREAM_WINDOW,
    DEFAULT_QUIC_IDLE_TIMEOUT_MS, DEFAULT_QUIC_KEEPALIVE_INTERVAL, INCOMING_CHANNEL_CAP_FLOOR,
    TransportProfile, incoming_channel_cap,
};
