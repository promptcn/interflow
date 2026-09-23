//! systemd service readiness notification (`sd_notify` protocol).
//!
//! Engines run under `Type=notify` units (see `interflow-cli` render): the
//! process signals `READY=1` once every listener it serves is bound, and
//! systemd holds the start job (and thus `node install`) until then. This is
//! the readiness channel that replaces TCP liveness probing — no synthetic
//! connections, no fake `TLS handshake failed` warnings in the logs.
//!
//! The protocol is one unix-datagram write (systemd's `sd_notify(3)` without
//! libsystemd): connect to `$NOTIFY_SOCKET`, send `READY=1\n`. Outside systemd
//! (GUI, manual runs, tests) the variable is unset and this is a no-op.
//! Non-unix targets have no systemd, so readiness signalling there is
//! unconditionally inert.

/// Notify the service manager that this process is ready.
///
/// Returns `false` when there is no `NOTIFY_SOCKET` (not running under a
/// `Type=notify` unit) or the notification could not be delivered — readiness
/// signalling is best-effort by design, never a startup failure.
#[cfg(unix)]
pub fn notify_ready() -> bool {
    match std::env::var("NOTIFY_SOCKET") {
        Ok(socket) if !socket.is_empty() => send_ready(&socket),
        _ => false,
    }
}

/// Non-unix targets: there is no systemd to notify, so readiness is vacuous.
#[cfg(not(unix))]
pub fn notify_ready() -> bool {
    false
}

#[cfg(unix)]
fn send_ready(socket: &str) -> bool {
    use std::os::unix::net::UnixDatagram;
    // systemd uses `@` as a prefix marker for the abstract namespace, where
    // the path is NUL-terminated bytes rather than a filesystem path.
    let path = if let Some(abstract_name) = socket.strip_prefix('@') {
        format!("\0{abstract_name}")
    } else {
        socket.to_owned()
    };
    let Ok(datagram) = UnixDatagram::unbound() else {
        return false;
    };
    if datagram.connect(path).is_err() {
        return false;
    }
    datagram.send(b"READY=1\n").is_ok()
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use std::os::unix::net::UnixDatagram;

    #[test]
    fn sends_ready_line_to_a_bound_socket() {
        let dir = tempfile::tempdir().expect("tempdir");
        let socket_path = dir.path().join("notify.sock");
        let receiver = UnixDatagram::bind(&socket_path).expect("bind receiver");
        assert!(send_ready(socket_path.to_str().expect("utf-8 path")));

        let mut buf = [0u8; 32];
        let (len, _) = receiver.recv_from(&mut buf).expect("recv");
        assert_eq!(&buf[..len], b"READY=1\n");
    }

    #[test]
    fn undeliverable_socket_is_reported_not_panicked() {
        let dir = tempfile::tempdir().expect("tempdir");
        let socket_path = dir.path().join("absent.sock");
        assert!(!send_ready(socket_path.to_str().expect("utf-8 path")));
    }
}
