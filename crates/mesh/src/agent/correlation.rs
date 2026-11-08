//! The agent-side correlation id — the cross-machine grep key
//!
//! The hub's audit rows and journal lines carry the connection's circuit
//! (32 hex); the agent's stream-level logs carried only the stream id —
//! cross-machine alignment meant timestamps. This module publishes the
//! agent's CURRENT circuit as a process-global 8-hex short form (the
//! same vocabulary the hub's `circuit=…` lines and the biography's
//! `d92d3f05…` rows use), set once per registration, so one grep hits
//! both machines' logs for the same session.
//!
//! Only the EXISTING id's exposure is unified — no new id space, and
//! the wire is untouched (log-line change only, per the backlog's
//! boundary).

use interflow_core::protocol::{CircuitToken, StreamId};
use std::sync::OnceLock;

static SHORT_CIRCUIT: OnceLock<String> = OnceLock::new();

/// Publishes the session's circuit (8-hex prefix).
///
/// Called at every registration response; the OnceLock keeps the FIRST
/// session's id for the process's lifetime (a process that re-registers
/// keeps one grep key; per-session churn would defeat the one-grep goal).
pub fn set_circuit(circuit: &CircuitToken) {
    let _ = SHORT_CIRCUIT.set(short_hex(&circuit.to_hex()));
}

/// The current session's short circuit id (8 hex), when registered.
pub fn short_circuit() -> Option<&'static str> {
    SHORT_CIRCUIT.get().map(String::as_str)
}

/// The 8-hex prefix of a full hex id (the display form everywhere).
pub fn short_hex(full: &str) -> String {
    full.chars().take(8).collect()
}

/// The stream-log correlation fragment: `circuit d92d3f05 · stream
/// 1a2b3c4d…` — both sides of one grep, one line.
pub fn stream_note(stream_id: &StreamId) -> String {
    let circuit = short_circuit().unwrap_or("-");
    format!(
        "circuit {circuit} · stream {}…",
        short_hex(&stream_id.to_hex())
    )
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn short_forms_match_the_hub_vocabulary() {
        let full = "d92d3f051234567890abcdef12345678";
        assert_eq!(short_hex(full), "d92d3f05");
        assert_eq!(short_hex("short"), "short");
    }

    #[test]
    fn stream_note_carries_both_keys() {
        // The OnceLock is process-global; this test only asserts the
        // unregistered form (the registered form needs a live session).
        let sid = StreamId::from_bytes([1u8; 16]);
        let note = stream_note(&sid);
        assert!(note.starts_with("circuit "), "{note}");
        assert!(note.contains("stream 01010101…"), "{note}");
    }
}
