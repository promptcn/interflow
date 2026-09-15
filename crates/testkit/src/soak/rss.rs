//! Per-process RSS sampling (the data source for the soak gate's memory-drift assertion).
//!
//! The processes being sampled are **other processes** (hub / agent subprocesses), via
//! each platform's standard system interface: on Linux, VmRSS from
//! `/proc/<pid>/status`; on macOS, `ps -o rss=`. This is the standard way to sample an
//! external process (memory-stats and friends can only sample the current process);
//! unsupported platforms return None, and the caller downgrades to skipping the
//! assertion instead of failing.

/// Sample the target process's current RSS (bytes). Returns None if the process does not
/// exist or the platform is unsupported.
pub async fn sample_rss(pid: u32) -> Option<u64> {
    #[cfg(target_os = "linux")]
    {
        tokio::task::spawn_blocking(move || read_proc_status_rss(pid))
            .await
            .ok()
            .flatten()
    }
    #[cfg(target_os = "macos")]
    {
        ps_rss(pid).await
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    {
        let _ = pid;
        None
    }
}

/// Sample this process's own RSS (recorded for the runner itself; same interface as the
/// processes under test, keeping the criterion consistent).
pub async fn self_rss() -> Option<u64> {
    sample_rss(std::process::id()).await
}

/// Sample the target process's current open-fd count (the direct observable of orphaned-
/// stream leaks).
///
/// Same per-platform strategy as [`sample_rss`]: on Linux, count the entries of the
/// `/proc/<pid>/fd` directory; on macOS, count the lines of `lsof -n -p <pid>` (which
/// include constant entries like cwd/txt — the assertion only looks at the **growth**,
/// so the baseline offset is irrelevant); unsupported platforms return None (the
/// assertion downgrades to skipped).
pub async fn sample_fd_count(pid: u32) -> Option<u64> {
    #[cfg(target_os = "linux")]
    {
        tokio::task::spawn_blocking(move || count_linux_fds(pid))
            .await
            .ok()
            .flatten()
    }
    #[cfg(target_os = "macos")]
    {
        lsof_fd_count(pid).await
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    {
        let _ = pid;
        None
    }
}

#[cfg(target_os = "linux")]
fn count_linux_fds(pid: u32) -> Option<u64> {
    let entries = std::fs::read_dir(format!("/proc/{pid}/fd")).ok()?;
    Some(entries.filter_map(Result::ok).count() as u64)
}

#[cfg(target_os = "macos")]
async fn lsof_fd_count(pid: u32) -> Option<u64> {
    let out = tokio::process::Command::new("lsof")
        .args(["-n", "-p", &pid.to_string()])
        .output()
        .await
        .ok()?;
    if !out.status.success() {
        return None;
    }
    Some(String::from_utf8_lossy(&out.stdout).lines().count() as u64)
}

#[cfg(target_os = "linux")]
fn read_proc_status_rss(pid: u32) -> Option<u64> {
    let text = std::fs::read_to_string(format!("/proc/{pid}/status")).ok()?;
    parse_vm_rss(&text)
}

/// Parse VmRSS (kB) from `/proc/<pid>/status` text → bytes.
/// The line looks like `VmRSS:\t  123456 kB`.
pub fn parse_vm_rss(status: &str) -> Option<u64> {
    let line = status.lines().find(|l| l.starts_with("VmRSS:"))?;
    let rest = line["VmRSS:".len()..].trim().trim_end_matches("kB").trim();
    let kb: u64 = rest.parse().ok()?;
    kb.checked_mul(1024)
}

#[cfg(target_os = "macos")]
async fn ps_rss(pid: u32) -> Option<u64> {
    let out = tokio::process::Command::new("ps")
        .args(["-o", "rss=", "-p", &pid.to_string()])
        .output()
        .await
        .ok()?;
    if !out.status.success() {
        return None;
    }
    parse_ps_rss(&String::from_utf8_lossy(&out.stdout))
}

/// Parse `ps -o rss=` output (kB, a single number line) → bytes.
pub fn parse_ps_rss(output: &str) -> Option<u64> {
    let kb: u64 = output.trim().parse().ok()?;
    kb.checked_mul(1024)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn vm_rss_parses_kilobytes_line() {
        let status = "Name:\tinterflow-mesh\nVmPeak:\t  200000 kB\nVmRSS:\t\t 123456 kB\n";
        assert_eq!(parse_vm_rss(status), Some(123456 * 1024));
    }

    #[test]
    fn vm_rss_missing_returns_none() {
        assert_eq!(parse_vm_rss("Name:\tx\n"), None);
        assert_eq!(parse_vm_rss(""), None);
    }

    #[test]
    fn ps_rss_parses_single_number() {
        assert_eq!(parse_ps_rss("  9999\n"), Some(9999 * 1024));
        assert_eq!(parse_ps_rss("32768"), Some(32768 * 1024));
        assert_eq!(parse_ps_rss(""), None);
        assert_eq!(parse_ps_rss("PID RSS\n"), None);
    }

    #[cfg(unix)]
    #[tokio::test(flavor = "multi_thread")]
    async fn sampling_own_pid_returns_positive() {
        let rss = self_rss().await;
        assert!(
            rss.is_some_and(|b| b > 0),
            "this process's RSS must be sampleable and positive"
        );
    }

    #[cfg(unix)]
    #[tokio::test(flavor = "multi_thread")]
    async fn fd_sampling_own_pid_returns_positive() {
        let fds = sample_fd_count(std::process::id()).await;
        assert!(
            fds.is_some_and(|n| n >= 3),
            "this process's fd count must be sampleable (>= the std trio)"
        );
    }
}
