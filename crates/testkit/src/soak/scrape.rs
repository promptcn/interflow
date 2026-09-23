//! Hub `/metrics` scraping and Prometheus text parsing (the production telemetry
//! path, not a test recorder).
//!
//! The soak heartbeat-canary assertions (supervisor_restarts == 0, pings monotonically
//! growing) read the hub process's real metrics endpoint — the same data production
//! operators see.

use super::error::{SoakError, SoakResult};
use std::net::SocketAddr;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

/// Scrape the metrics endpoint once and return the response body (Prometheus text format).
pub async fn scrape(addr: SocketAddr, path: &str) -> SoakResult<String> {
    let mut sock = tokio::net::TcpStream::connect(addr)
        .await
        .map_err(|e| SoakError::Scrape {
            addr,
            message: format!("connect: {e}"),
        })?;
    let req = format!("GET {path} HTTP/1.1\r\nHost: {addr}\r\nConnection: close\r\n\r\n");
    sock.write_all(req.as_bytes())
        .await
        .map_err(|e| SoakError::Scrape {
            addr,
            message: format!("write: {e}"),
        })?;
    let mut raw = Vec::new();
    sock.read_to_end(&mut raw)
        .await
        .map_err(|e| SoakError::Scrape {
            addr,
            message: format!("read: {e}"),
        })?;
    let text = String::from_utf8_lossy(&raw);
    let (_, body) = text
        .split_once("\r\n\r\n")
        .ok_or_else(|| SoakError::Scrape {
            addr,
            message: "missing HTTP header separator".to_string(),
        })?;
    Ok(body.to_string())
}

/// Sum a counter family: adds up `name` (no labels) and every `name{...}` line of the
/// same family. Skips HELP/TYPE lines starting with `#`. Returns None if the family is
/// absent.
#[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
pub fn counter_value(text: &str, name: &str) -> Option<u64> {
    let mut sum = 0u64;
    let mut found = false;
    for line in text.lines() {
        if line.starts_with('#') {
            continue;
        }
        let Some((metric, value)) = line.split_once(' ') else {
            continue;
        };
        let family = metric.split('{').next().unwrap_or(metric);
        if family == name {
            let v: f64 = value.trim().parse().ok()?;
            sum += v as u64;
            found = true;
        }
    }
    found.then_some(sum)
}

#[cfg(test)]
mod tests {
    use super::*;

    const FIXTURE: &str = "\
# HELP interflow_hub_heartbeat_pings_sent pings
# TYPE interflow_hub_heartbeat_pings_sent counter
interflow_hub_heartbeat_pings_sent 41
# TYPE interflow_hub_pong_received counter
interflow_hub_pong_received{path=\"endpoint\"} 3
interflow_hub_pong_received{path=\"upload\"} 38
interflow_hub_heartbeat_supervisor_restarts 0
";

    #[test]
    fn unlabeled_counter_reads_value() {
        assert_eq!(
            counter_value(FIXTURE, "interflow_hub_heartbeat_pings_sent"),
            Some(41)
        );
        assert_eq!(
            counter_value(FIXTURE, "interflow_hub_heartbeat_supervisor_restarts"),
            Some(0)
        );
    }

    #[test]
    fn labeled_counter_sums_family() {
        assert_eq!(
            counter_value(FIXTURE, "interflow_hub_pong_received"),
            Some(41)
        );
    }

    #[test]
    fn missing_counter_returns_none() {
        assert_eq!(counter_value(FIXTURE, "interflow_hub_absent"), None);
    }
}
