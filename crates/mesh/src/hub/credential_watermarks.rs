//! The hub's credential watermarks — the fleet faces' material for the
//! credential-expiry face
//!
//! "Don't forget to rotate" was a discipline: the expiry date lived in
//! `identity inspect --pack` (a command someone must remember to run)
//! and in the deployment handbook's hosts-comment block. The hub
//! already parses every connecting agent's leaf validity window from
//! the mTLS chain at registration — this table simply retains the LAST
//! SEEN window per agent, so the expiry is a first-class fleet level:
//! online legs refresh it on every registration, offline legs keep
//! their last window (the ledger-only remembrance shape — the countdown
//! matters most exactly while the node is down, and `not_after` is
//! absolute: time does not pause for an offline leg).
//!
//! Tier inference: the two legal TTL bands are disjoint (registrar
//! 1h–24h, offline 7d–365d), so the certificate's own validity span
//! identifies the tier — a span under
//! [`REGISTRAR_SPAN_BOUNDARY_SECS`] reads registrar (well above the
//! 24h ceiling with clock-skew margin), anything longer offline. No
//! new reporting: the chain at registration IS the report.
//!
//! Bump discipline (see `hub::floor_clock`): first sighting, or a
//! CHANGED window (a rotation landed — the new leaf's `not_after` is
//! fleet news). A steady re-registration presenting the same leaf
//! refreshes `last_seen_unix` and bumps nothing.

use std::collections::{BTreeMap, HashMap};
use std::sync::Mutex;

/// A validity span under this reads registrar-tier (the band's legal
/// ceiling is 24h; the boundary sits far above it so ordinary clock
/// skew between issuance and observation cannot misclassify).
pub const REGISTRAR_SPAN_BOUNDARY_SECS: i64 = 3 * 86_400;

/// One agent's last-seen credential window.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CredentialWatermark {
    /// The leaf's `notBefore` (unix seconds).
    pub not_before_unix: i64,
    /// The leaf's `notAfter` (unix seconds) — the countdown's target.
    pub not_after_unix: i64,
    /// The leaf's serial (hex), when the chain carried one (rotation
    /// correlation material).
    pub serial_hex: Option<String>,
    /// Unix seconds of the last registration that presented this window.
    pub last_seen_unix: u64,
}

/// The tier a validity span implies — the pure judgment shared by the
/// face, doctor, and the GUI.
pub const fn tier_from_span(span_secs: i64) -> &'static str {
    if span_secs < REGISTRAR_SPAN_BOUNDARY_SECS {
        "registrar"
    } else {
        "offline"
    }
}

/// The shared table.
///
/// In-memory by design — the same restart contract as the sibling
/// watermark faces: every online leg's next registration refills its row
/// within one reconnect, first-sighting bump included.
pub struct CredentialWatermarks {
    inner: Mutex<HashMap<String, CredentialWatermark>>,
    floor: crate::hub::floor_clock::FloorClock,
}

impl CredentialWatermarks {
    pub fn new(floor: crate::hub::floor_clock::FloorClock) -> Self {
        Self {
            inner: Mutex::new(HashMap::new()),
            floor,
        }
    }

    /// Records one registration's observed window. Bumps only on the
    /// first sighting or a changed window (a rotation).
    pub fn record(
        &self,
        agent: &str,
        not_before_unix: i64,
        not_after_unix: i64,
        serial_hex: Option<String>,
        now_unix: u64,
    ) {
        let mut inner = self
            .inner
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let face_changed = if let Some(row) = inner.get_mut(agent) {
            let changed =
                row.not_before_unix != not_before_unix || row.not_after_unix != not_after_unix;
            row.not_before_unix = not_before_unix;
            row.not_after_unix = not_after_unix;
            row.serial_hex = serial_hex;
            row.last_seen_unix = now_unix;
            changed
        } else {
            inner.insert(
                agent.to_owned(),
                CredentialWatermark {
                    not_before_unix,
                    not_after_unix,
                    serial_hex,
                    last_seen_unix: now_unix,
                },
            );
            true
        };
        drop(inner);
        if face_changed {
            self.floor.bump();
        }
    }

    /// The face: every agent that ever registered, deterministic order.
    pub fn face(&self) -> BTreeMap<String, CredentialWatermark> {
        let inner = self
            .inner
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        inner.iter().map(|(k, v)| (k.clone(), v.clone())).collect()
    }
}

#[cfg(test)]
#[allow(
    clippy::panic,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::missing_docs_in_private_items
)]
mod tests {
    use super::*;

    fn marks() -> (CredentialWatermarks, crate::hub::floor_clock::FloorClock) {
        let clock = crate::hub::floor_clock::FloorClock::new();
        (CredentialWatermarks::new(clock.clone()), clock)
    }

    #[test]
    fn bump_discipline_first_sighting_steady_rotation() {
        let (marks, clock) = marks();
        marks.record("site/a", 1_000, 1_000 + 86_400, Some("aa".into()), 1_002);
        assert_eq!(clock.version(), 1, "first sighting is face-visible");
        // Steady re-registration, same leaf: refresh only.
        marks.record("site/a", 1_000, 1_000 + 86_400, Some("aa".into()), 1_500);
        assert_eq!(clock.version(), 1);
        // A rotation (new window): news.
        marks.record("site/a", 1_500, 1_500 + 86_400, Some("bb".into()), 1_600);
        assert_eq!(clock.version(), 2);
        let face = marks.face();
        assert_eq!(face.get("site/a").unwrap().not_after_unix, 1_500 + 86_400);
        assert_eq!(face.get("site/a").unwrap().last_seen_unix, 1_600);
    }

    #[test]
    fn tier_inference_splits_the_disjoint_bands() {
        assert_eq!(tier_from_span(45), "registrar");
        assert_eq!(tier_from_span(24 * 3600), "registrar");
        assert_eq!(
            tier_from_span(REGISTRAR_SPAN_BOUNDARY_SECS - 1),
            "registrar"
        );
        assert_eq!(tier_from_span(REGISTRAR_SPAN_BOUNDARY_SECS), "offline");
        assert_eq!(tier_from_span(90 * 86_400), "offline");
    }
}
