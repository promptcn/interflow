//! Version-face parity: `--version`, `-V` and the `version` subcommand are
//! three entrances to one byte-identical line,
//! `interflow-mesh <VERSION_WITH_TAG>` — the same const every binary's
//! `--version` prints (scripts/check_version_surface.py holds the
//! attribute on every clap root; this test holds the printed line).
//! Backlog: (internal design notes).

use std::process::Command;

/// Run the real binary and return its stdout, requiring a clean exit.
fn version_line(args: &[&str]) -> String {
    let output = Command::new(env!("CARGO_BIN_EXE_interflow-mesh"))
        .args(args)
        .output()
        .expect("spawn interflow-mesh");
    assert!(
        output.status.success(),
        "{args:?}: exited with {status}",
        status = output.status
    );
    String::from_utf8(output.stdout).expect("version line is UTF-8")
}

#[test]
fn flag_short_flag_and_subcommand_print_the_same_line() {
    let expected = format!(
        "{} {}\n",
        env!("CARGO_PKG_NAME"),
        interflow_buildinfo::VERSION_WITH_TAG
    );
    assert_eq!(version_line(&["--version"]), expected);
    assert_eq!(version_line(&["-V"]), expected);
    assert_eq!(version_line(&["version"]), expected);
}
