//! Broken-pipe discipline: the reader closing stdout early must silence
//! OUTPUT, never abort WORK — the regression of
//! (internal design notes).
//!
//! The pre-fix behavior panicked on the first EPIPE
//! (`failed printing to stdout: Broken pipe`), potentially between side
//! effects of a multi-step command. These drills close the pipe after the
//! first line and assert the command still runs to completion.

use std::io::{BufRead as _, BufReader};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

fn bin() -> PathBuf {
    let mut p = std::env::current_exe().expect("test bin path");
    p.pop(); // deps/
    p.pop(); // tests/
    p.join(format!("interflow-cli{}", std::env::consts::EXE_SUFFIX))
}

/// Spawns the CLI, consumes exactly one stdout line, then closes the pipe:
/// the child's next write gets EPIPE, exactly like `| head -1`.
fn run_with_pipe_closed_after_first_line(args: &[&str]) -> std::process::Output {
    let mut child = Command::new(bin())
        .args(args)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn interflow");
    let stdout = child.stdout.take().expect("piped stdout");
    let mut first_line = String::new();
    {
        let mut reader = BufReader::new(stdout);
        reader
            .read_line(&mut first_line)
            .expect("read the first line");
    } // the reader (and its pipe fd) is gone — every later write is EPIPE
    child.wait_with_output().expect("child finishes")
}

fn assert_no_panic(output: &std::process::Output) {
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        !stderr.contains("panicked") && !stderr.contains("Broken pipe"),
        "a closed stdout must be silenced, not panicked on:\nstderr: {stderr}"
    );
}

#[test]
fn truncated_status_output_does_not_panic() {
    // `issuer backup status` prints several lines; the second one lands on
    // the closed pipe.
    let dir = tempfile::tempdir().expect("tempdir");
    let root = dir.path().join("issuer");
    let identity = interflow_identity::backup::generate_identity().expect("identity");
    interflow_identity::backup::configure(
        &root,
        &identity.recipient,
        &dir.path().join("issuer-backups"),
        interflow_identity::backup::DEFAULT_RETENTION,
    )
    .expect("configure");
    interflow_identity::issuance::IssuerStore::open(&root)
        .ensure_realm()
        .expect("realm");

    let output = run_with_pipe_closed_after_first_line(&[
        "issuer",
        "backup",
        "status",
        "--dir",
        &root.display().to_string(),
    ]);
    assert!(
        output.status.success(),
        "work completes; only output was lost"
    );
    assert_no_panic(&output);
}

#[test]
fn closed_stdout_never_aborts_the_rekey_sequence() {
    // rekey is the exact field scenario: several prints interleaved with
    // irreversible side effects (config rekeyed, first checkpoint under
    // the new key, one-time identity written). The pipe dies after line
    // one — everything must still land.
    let dir = tempfile::tempdir().expect("tempdir");
    let root = dir.path().join("issuer");
    let identity = interflow_identity::backup::generate_identity().expect("identity");
    let backup_dir = dir.path().join("issuer-backups");
    interflow_identity::backup::configure(
        &root,
        &identity.recipient,
        &backup_dir,
        interflow_identity::backup::DEFAULT_RETENTION,
    )
    .expect("configure");
    interflow_identity::issuance::IssuerStore::open(&root)
        .ensure_realm()
        .expect("realm");
    let identity_out = dir.path().join("offline-identity.txt");

    let output = run_with_pipe_closed_after_first_line(&[
        "issuer",
        "backup",
        "rekey",
        "--dir",
        &root.display().to_string(),
        "--identity-out",
        &identity_out.display().to_string(),
    ]);
    assert!(output.status.success());
    assert_no_panic(&output);

    // Every side effect past the dead pipe completed: the identity file
    // (written and announced LAST, after the banner prints)…
    let new_secret =
        std::fs::read_to_string(&identity_out).expect("the one-time identity file landed");
    // …and the first checkpoint under the new key, which the new identity
    // must be able to read. The version inventory comes from the library's
    // own ordering (name-timestamp, then mtime for same-second writes) —
    // sorting the paths lexically would order same-second versions by their
    // content hashes, a coin flip that picks the pre-rekey version half the
    // time (the exact hazard list_versions' tiebreak exists for).
    let status = interflow_identity::backup::status(&root).expect("status");
    assert!(
        !status.versions.is_empty(),
        "the rekey drill wrote versions: {:?}",
        status.versions
    );
    let newest = status
        .versions
        .last()
        .expect("a version exists")
        .display()
        .to_string();
    assert!(
        interflow_identity::backup::verify(Path::new(&newest), new_secret.trim()).is_ok(),
        "the post-rekey checkpoint {newest} is sealed to the new identity"
    );
}
