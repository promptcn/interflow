//! Fault-tolerant stdout for the CLI: a closed pipe downgrades OUTPUT,
//! never WORK.
//!
//! `interflow-cli issuer backup rekey | head -3` closes the pipe the
//! moment `head` is satisfied; the next write returns `BrokenPipe`. Rust's
//! `println!` panics on that — mid-command, potentially between side
//! effects (config written, checkpoint still pending). This layer instead
//! marks stdout dead and silently drops every later line: the command runs
//! to completion and exits through its normal path, because the work was
//! requested and only the reading was abandoned.
//! (internal design notes).
//!
//! Boundary: stdout only. stderr (`eprint!`/`eprintln!`) and stdin are
//! untouched — a closed stderr is outside the pipe-early-close scenario,
//! and those few call sites (passphrase prompts, session logs) keep their
//! loud failure mode on purpose.

use std::io::Write as _;
use std::sync::atomic::{AtomicBool, Ordering};

static STDOUT_DEAD: AtomicBool = AtomicBool::new(false);

/// Writes one line to stdout, or drops it once stdout is dead. Any write
/// error — not just `BrokenPipe` — trips the flag: a stdout that failed
/// once does not heal mid-process.
pub fn write_line(args: std::fmt::Arguments) {
    if STDOUT_DEAD.load(Ordering::Relaxed) {
        return;
    }
    let mut out = std::io::stdout().lock();
    if writeln!(out, "{args}").is_err() {
        STDOUT_DEAD.store(true, Ordering::Relaxed);
    }
}

/// Whether the reader abandoned our stdout. A command that finished all
/// its work may mention this in a summary; nothing may branch into
/// skipping work because of it.
#[must_use]
pub fn stdout_lost() -> bool {
    STDOUT_DEAD.load(Ordering::Relaxed)
}

/// `println!` for stdout that a closed pipe silences instead of panicking
/// mid-command (see the module docs). All CLI stdout goes through this.
#[macro_export]
macro_rules! outln {
    () => {
        $crate::out::write_line(format_args!(""))
    };
    ($($arg:tt)*) => {
        $crate::out::write_line(format_args!($($arg)*))
    };
}
