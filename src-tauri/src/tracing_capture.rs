//! tracing capture layer: captures library-level tracing events into the GUI (no stdout output).
//!
//! The GUI process never calls `interflow_core::telemetry::init_logging` (the global subscriber);
//! instead, it assembles its own Registry + EnvFilter + GuiLogLayer.

use serde::Serialize;
use std::collections::VecDeque;
use std::sync::Mutex;
use tauri::{AppHandle, Emitter, Manager};
use tracing::field::Visit;
use tracing::{Event, Level, Subscriber};
use tracing_subscriber::layer::Context;
use tracing_subscriber::prelude::*;
use tracing_subscriber::{EnvFilter, Layer};

/// A single log line pushed to the frontend.
#[derive(Clone, Debug, Serialize)]
pub struct LogLine {
    pub ts: String,
    pub level: String,
    pub target: String,
    pub message: String,
}

/// Rust-side ring buffer (replayed when the frontend starts/reconnects).
pub struct LogBuffer {
    inner: Mutex<VecDeque<LogLine>>,
}

const MAX_LINES: usize = 2000;

impl LogBuffer {
    pub fn new() -> Self {
        Self {
            inner: Mutex::new(VecDeque::with_capacity(MAX_LINES)),
        }
    }

    pub fn snapshot(&self) -> Vec<LogLine> {
        self.inner
            .lock()
            .map(|buf| buf.iter().cloned().collect())
            .unwrap_or_default()
    }

    fn push(&self, line: LogLine) {
        if let Ok(mut buf) = self.inner.lock() {
            if buf.len() == MAX_LINES {
                buf.pop_front();
            }
            buf.push_back(line);
        }
    }
}

struct GuiLogLayer {
    tx: tokio::sync::mpsc::Sender<LogLine>,
}

impl GuiLogLayer {
    fn send(&self, line: LogLine) {
        // Even if the frontend is gone, the observed library code must not be affected; when full, the
        // oldest lines are dropped (the channel itself never drops — buffer truncation is the fallback).
        let _ = self.tx.try_send(line);
    }
}

struct MessageVisitor {
    message: String,
}

impl Visit for MessageVisitor {
    fn record_debug(&mut self, field: &tracing::field::Field, value: &dyn std::fmt::Debug) {
        if field.name() == "message" {
            self.message = format!("{value:?}");
        }
    }

    fn record_str(&mut self, field: &tracing::field::Field, value: &str) {
        if field.name() == "message" {
            self.message = value.to_string();
        }
    }
}

impl<S: Subscriber> Layer<S> for GuiLogLayer {
    fn on_event(&self, event: &Event<'_>, _ctx: Context<'_, S>) {
        let mut visitor = MessageVisitor {
            message: String::new(),
        };
        event.record(&mut visitor);
        if visitor.message.is_empty() {
            return;
        }
        self.send(LogLine {
            ts: rfc3339_now(),
            level: level_name(*event.metadata().level()),
            target: event.metadata().target().to_string(),
            message: visitor.message,
        });
    }
}

fn level_name(level: Level) -> String {
    match level {
        Level::ERROR => "ERROR".into(),
        Level::WARN => "WARN".into(),
        Level::INFO => "INFO".into(),
        Level::DEBUG => "DEBUG".into(),
        Level::TRACE => "TRACE".into(),
    }
}

/// RFC3339 UTC timestamp, byte-identical to the CLI/journal fmt timer
/// (tracing_subscriber's default `SystemTime` timer): `2026-09-17T03:31:59.123456Z`.
/// Sharing the formatter is what lets GUI lines correlate with hub-side
/// journalctl lines at microsecond precision. No new dependency — `SystemTime`
/// is the fmt layer's default timer.
fn rfc3339_now() -> String {
    use tracing_subscriber::fmt::format::Writer;
    use tracing_subscriber::fmt::time::FormatTime;
    let mut buf = String::new();
    // `Writer::new` borrows the buffer as the same `fmt::Write` sink the fmt
    // layer passes its default timer in normal CLI/journal logging.
    let _ = tracing_subscriber::fmt::time::SystemTime.format_time(&mut Writer::new(&mut buf));
    buf
}

/// Initialize the global subscriber: only the GUI capture layer is attached.
pub fn init(log_tx: tokio::sync::mpsc::Sender<LogLine>) {
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));
    tracing_subscriber::registry()
        .with(filter)
        .with(GuiLogLayer { tx: log_tx })
        .init();
}

/// Log pump: channel → ring buffer + `log` event pushed to the frontend.
pub async fn pump(app: AppHandle, mut rx: tokio::sync::mpsc::Receiver<LogLine>) {
    while let Some(line) = rx.recv().await {
        if let Some(state) = app.try_state::<super::SharedState>() {
            let Ok(guard) = state.lock() else {
                return;
            };
            guard.logs.push(line.clone());
        }
        let _ = app.emit("log", &line);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The timestamp must be the exact RFC3339 UTC shape the CLI/journal
    /// timer emits (`2026-09-17T03:31:59.123456Z`, 27 bytes), so GUI lines
    /// correlate with journalctl lines at microsecond precision.
    #[test]
    fn rfc3339_now_matches_journal_timer_shape() {
        let ts = rfc3339_now();
        let b = ts.as_bytes();
        assert_eq!(b.len(), 27, "unexpected length: {ts:?}");
        let separators = [
            (4usize, b'-'),
            (7, b'-'),
            (10, b'T'),
            (13, b':'),
            (16, b':'),
            (19, b'.'),
            (26, b'Z'),
        ];
        for (i, c) in separators {
            assert_eq!(b[i], c, "unexpected byte at {i}: {ts:?}");
        }
        for (i, &c) in b.iter().enumerate() {
            if !separators.iter().any(|(j, _)| *j == i) {
                assert!(c.is_ascii_digit(), "expected digit at {i}: {ts:?}");
            }
        }
    }
}
