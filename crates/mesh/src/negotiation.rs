//! Capability negotiation via the register response (hub → agent, introduced
//! 2026-09-13 with the definitive fix for data-plane stalls).
//!
//! The `POST /register` response body evolved from the plain-text
//! `"Registered"` to a JSON capability declaration. The agent parses it
//! best-effort: on parse failure (a legacy hub's plain-text response) it falls
//! back to legacy behavior — Pong goes through the `POST /pong` endpoint and
//! the poll watchdog uses a fixed fallback value. The hub always keeps the
//! `/pong` endpoint and accepts both kinds of Pong, so version skew is
//! compatible in both directions:
//!
//! | Combination | Behavior |
//! |---|---|
//! | New hub + new agent | Pong rides the upstream data stream; the watchdog is derived from the advertised cadence |
//! | New hub + legacy agent | The legacy agent ignores the response body; Pong goes through the `/pong` endpoint |
//! | Legacy hub + new agent | Text response fails to parse → legacy fallback |

use serde::{Deserialize, Serialize};

/// The `POST /register` response body (capability declaration).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RegisterResponse {
    /// Pong may be returned via upstream frames on `/stream/up` — the
    /// heartbeat reply itself proves the agent→hub data path is alive.
    /// `false` / unset = `POST /pong` endpoint only (which only proves the h2
    /// connection layer).
    #[serde(default)]
    pub pong_via_upload: bool,
    /// Hub heartbeat cadence. Unset = heartbeat disabled (the poll stream is
    /// legitimately silent; the agent watchdog should be disabled).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub heartbeat: Option<HeartbeatAd>,
}

/// The advertised hub heartbeat cadence.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub struct HeartbeatAd {
    /// Heartbeat interval (seconds).
    pub interval_secs: u64,
    /// Number of consecutive Pings allowed to go missing before declaring
    /// death (dead line = `interval*(max_missed+1)`).
    pub max_missed: u32,
}

/// Register response parse outcome.
///
/// Distinguishes "legacy hub (no capability declaration)" from "modern hub
/// with heartbeat disabled" — the agent-side behavior differs (the latter
/// should disable the watchdog; the former needs the fallback value).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Negotiated {
    /// The body is not capability JSON (legacy hub plain text) — legacy
    /// behavior.
    Legacy,
    /// The capability JSON parsed successfully.
    Modern(RegisterResponse),
}

/// Legacy hub fallback watchdog (seconds): covers the default heartbeat
/// cadence's 75s dead line + margin.
const LEGACY_WATCHDOG_SECS: u64 = 120;

/// Margin (seconds) added to the dead line for the negotiated watchdog:
/// tolerates a single tick of jitter / scheduling delay.
const NEGO_WATCHDOG_MARGIN_SECS: u64 = 30;

impl Negotiated {
    /// Parses the register response body best-effort: any parse failure is
    /// treated as a legacy hub.
    pub fn parse(body: &[u8]) -> Self {
        match serde_json::from_slice::<RegisterResponse>(body) {
            Ok(r) => Self::Modern(r),
            Err(_) => Self::Legacy,
        }
    }

    /// Whether Pong is returned via the upstream data stream.
    pub const fn pong_via_upload(&self) -> bool {
        matches!(self, Self::Modern(r) if r.pong_via_upload)
    }

    /// Poll receive-side watchdog timeout derivation:
    /// - Modern hub with heartbeat enabled: `interval*(max_missed+1) + margin`
    ///   (extra room for jitter beyond the dead line);
    /// - Modern hub with heartbeat disabled: the poll stream is legitimately
    ///   silent (no Pings), so the watchdog is disabled;
    /// - Legacy hub (no declaration): a fixed fallback value.
    ///
    /// Returns [`std::time::Duration::ZERO`] to indicate disabled.
    pub fn poll_watchdog(&self) -> std::time::Duration {
        match self {
            Self::Legacy => std::time::Duration::from_secs(LEGACY_WATCHDOG_SECS),
            Self::Modern(r) => match r.heartbeat {
                Some(hb) => std::time::Duration::from_secs(
                    hb.interval_secs * u64::from(hb.max_missed + 1) + NEGO_WATCHDOG_MARGIN_SECS,
                ),
                None => std::time::Duration::ZERO,
            },
        }
    }
}

#[cfg(test)]
#[allow(clippy::panic, clippy::unwrap_used)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[test]
    fn legacy_text_body_falls_back() {
        assert_eq!(Negotiated::parse(b"Registered"), Negotiated::Legacy);
        assert_eq!(Negotiated::parse(b""), Negotiated::Legacy);
    }

    #[test]
    fn modern_full_body_parses() {
        let n = Negotiated::parse(
            br#"{"pong_via_upload":true,"heartbeat":{"interval_secs":15,"max_missed":4}}"#,
        );
        let Negotiated::Modern(r) = &n else {
            panic!("should parse as Modern");
        };
        assert!(r.pong_via_upload);
        assert_eq!(
            r.heartbeat,
            Some(HeartbeatAd {
                interval_secs: 15,
                max_missed: 4
            })
        );
    }

    #[test]
    fn heartbeat_absent_means_disabled() {
        let n = Negotiated::parse(br#"{"pong_via_upload":true}"#);
        assert!(n.pong_via_upload());
        // Heartbeat disabled: the poll stream is legitimately silent; the
        // watchdog is disabled
        assert_eq!(n.poll_watchdog(), Duration::ZERO);
    }

    #[test]
    fn watchdog_derivation_matrix() {
        // Modern hub with heartbeat enabled: dead line 15*(4+1)=75s + 30s margin
        let n = Negotiated::parse(br#"{"heartbeat":{"interval_secs":15,"max_missed":4}}"#);
        assert_eq!(n.poll_watchdog(), Duration::from_secs(105));
        // Legacy hub: fixed fallback
        assert_eq!(Negotiated::Legacy.poll_watchdog(), Duration::from_mins(2));
        // Aggressive parameters also derive correctly
        let n = Negotiated::parse(br#"{"heartbeat":{"interval_secs":1,"max_missed":0}}"#);
        assert_eq!(n.poll_watchdog(), Duration::from_secs(31));
    }

    #[test]
    fn pong_via_upload_defaults_off_for_legacy() {
        assert!(!Negotiated::Legacy.pong_via_upload());
        // Explicit false
        let n = Negotiated::parse(br#"{"pong_via_upload":false}"#);
        assert!(!n.pong_via_upload());
    }

    #[test]
    fn unknown_fields_are_forward_compatible() {
        // Fields a future hub adds must not break an older agent's parsing
        let n = Negotiated::parse(
            br#"{"pong_via_upload":true,"heartbeat":{"interval_secs":15,"max_missed":4},"future_field":42}"#,
        );
        assert!(matches!(n, Negotiated::Modern(_)));
    }
}
