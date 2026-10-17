//! Test-process tracing sink.
//!
//! The in-process fixtures (registrar `serve`, hub, agents) report their
//! failure paths through `tracing` events; without a subscriber those lines
//! are dropped and a hung fixture is undiagnosable (the 2026-10-17 registrar
//! Linux backlog was prolonged exactly by that blindness). This installs a
//! global fmt subscriber that mirrors every event to stderr AND a bounded
//! in-memory ring — green runs stay silent because nextest only prints
//! captured output on failure, a red run carries the server-side story
//! (handshake errors, watcher pull failures) next to the assertion, and a
//! fixture's readiness panic can embed [`recent_lines`] so the failure
//! stands alone. `RUST_LOG` overrides the default `info` filter for
//! deep-diving a single test.

use std::collections::VecDeque;
use std::sync::{Mutex, OnceLock};

/// How many recent log lines the ring keeps for panic messages.
const RING_CAP: usize = 64;

static RING: Mutex<VecDeque<String>> = Mutex::new(VecDeque::new());

/// Copies every formatted event to stderr and the ring.
struct TeeWriter;

impl std::io::Write for TeeWriter {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        let _ = std::io::stderr().write_all(buf);
        if let Ok(mut ring) = RING.lock() {
            ring.push_back(String::from_utf8_lossy(buf).trim().to_owned());
            while ring.len() > RING_CAP {
                ring.pop_front();
            }
        }
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        std::io::stderr().flush()
    }
}

/// Installs the test logging subscriber once per test process. Idempotent:
/// later calls (other tests in the same `cargo test` process) are no-ops.
pub fn init_test_logging() {
    static ONCE: OnceLock<()> = OnceLock::new();
    ONCE.get_or_init(|| {
        let filter = tracing_subscriber::EnvFilter::try_from_default_env()
            .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info"));
        let _ = tracing::subscriber::set_global_default(
            tracing_subscriber::fmt()
                .with_env_filter(filter)
                .with_ansi(false)
                .with_writer(|| TeeWriter)
                .finish(),
        );
    });
}

/// The ring's current contents, oldest first — for embedding into panic
/// messages when a fixture fails.
pub fn recent_lines() -> Vec<String> {
    RING.lock()
        .map(|ring| ring.iter().cloned().collect())
        .unwrap_or_default()
}
