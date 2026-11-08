//! The one blocking HTTP/1.1 probe kernel every doctor face uses.
//!
//! A probe needs "send one GET with `Connection: close`, read the first
//! chunk, classify" over a deliberately minimal client: no proxy
//! environment, no redirects, no keep-alive — the verdict must depend only
//! on the dialed listener. Three hand-rolled variants of this loop (the XFF
//! direct and front-proxy probes, the data-plane `http_get`) had drifted on
//! buffer caps and timeout classification; they now share this kernel and
//! keep only their outcome vocabularies.

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::time::Duration;

/// Connect and read/write budgets for one probe.
#[derive(Debug, Clone, Copy)]
pub struct ProbeTiming {
    pub connect: Duration,
    pub stream: Duration,
}

/// The XFF precheck dials a local listener, which answers or refuses fast.
pub const LOCAL: ProbeTiming = ProbeTiming {
    connect: Duration::from_secs(2),
    stream: Duration::from_secs(3),
};

/// The data-plane probe's traffic crosses a tunnel; it gets room to breathe.
pub const THROUGH_TUNNEL: ProbeTiming = ProbeTiming {
    connect: Duration::from_secs(5),
    stream: Duration::from_secs(5),
};

/// What the first read after the request said.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProbeRead {
    /// Bytes came back — the lossy text of the first chunk (cap-bounded).
    Answered(String),
    /// Writing the request failed.
    WriteFailed,
    /// The peer closed without a byte.
    Closed,
    /// The read timed out.
    Timeout,
    /// Any other I/O failure (carries `e.to_string()`; faces that do not
    /// narrate it discard the text).
    IoFailed(String),
}

/// The first line of a response chunk — the status line every face reads.
#[must_use]
pub fn status_line(chunk: &str) -> String {
    chunk.lines().next().unwrap_or("").to_owned()
}

/// Connects with a deadline and arms the read/write timeouts; `None` counts
/// as refused (nothing listening).
#[must_use]
pub fn connect(addr: SocketAddr, timing: ProbeTiming) -> Option<TcpStream> {
    let Ok(stream) = TcpStream::connect_timeout(&addr, timing.connect) else {
        return None;
    };
    let _ = stream.set_read_timeout(Some(timing.stream));
    let _ = stream.set_write_timeout(Some(timing.stream));
    Some(stream)
}

/// Writes `GET <path>` with `Connection: close` and classifies the first
/// read. `host_header` is spelled exactly as the probed vhost must see it;
/// `cap` bounds the first chunk (faces that sniff more than the status line
/// read wider).
pub fn get<S>(stream: &mut S, host_header: &str, path: &str, cap: usize) -> ProbeRead
where
    S: Read + Write,
{
    let request =
        format!("GET {path} HTTP/1.1\r\nHost: {host_header}\r\nConnection: close\r\n\r\n");
    if stream.write_all(request.as_bytes()).is_err() {
        return ProbeRead::WriteFailed;
    }
    let mut buf = vec![0u8; cap];
    match stream.read(&mut buf) {
        Ok(0) => ProbeRead::Closed,
        Ok(n) => ProbeRead::Answered(String::from_utf8_lossy(&buf[..n]).into_owned()),
        Err(e)
            if matches!(
                e.kind(),
                std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
            ) =>
        {
            ProbeRead::Timeout
        }
        Err(e) => ProbeRead::IoFailed(e.to_string()),
    }
}
