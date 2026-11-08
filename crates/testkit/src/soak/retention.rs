//! Run-directory hygiene for the soak gate: capacity-bounded retention of
//! past runs' logs and post-run compression of the current run's logs.
//!
//! Evidence discipline: every run's `results.json` and config handoffs stay
//! forever — only the bulky `logs/` subtrees age out, oldest first, and the
//! newest [`KEEP_NEWEST_RUNS`] completed runs are never touched. The cap is
//! by capacity, not age, for the same reason the target-dir GC is
//! (2026-10-10 record): an active working set is only bounded by bytes.
//! Compression keeps a run's evidence complete at a fraction of the bytes;
//! `log_tails` on the failure paths reads raw files before this step runs.

use flate2::Compression;
use flate2::write::GzEncoder;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};

/// Completed runs whose logs are never pruned regardless of the cap.
pub const KEEP_NEWEST_RUNS: usize = 3;

/// `soak-YYYYmmdd-HHMMSS` — the runner's default run-directory name. Only
/// these are retention candidates; `soak-ci` (CI `--out`) and the curated,
/// git-tracked benchmark directories never match.
pub fn is_soak_run_dir_name(name: &str) -> bool {
    let Some(stamp) = name.strip_prefix("soak-") else {
        return false;
    };
    let b = stamp.as_bytes();
    b.len() == 15
        && b[..8].iter().all(u8::is_ascii_digit)
        && b[8] == b'-'
        && b[9..].iter().all(u8::is_ascii_digit)
}

/// `(file name, bytes)` of every regular file directly inside a scenario's
/// `logs/` directory (the per-file split is what makes a budget breach
/// attributable).
pub fn logs_dir_files(logs_dir: &Path) -> Vec<(String, u64)> {
    let Ok(entries) = fs::read_dir(logs_dir) else {
        return Vec::new();
    };
    let mut files: Vec<(String, u64)> = entries
        .flatten()
        .filter_map(|e| {
            let meta = e.metadata().ok()?;
            meta.is_file()
                .then(|| (e.file_name().to_string_lossy().into_owned(), meta.len()))
        })
        .collect();
    files.sort();
    files
}

/// Bytes held by every `<run>/<scenario>/logs/` subtree of one run.
pub fn run_log_bytes(run_dir: &Path) -> u64 {
    scenario_logs_dirs(run_dir)
        .iter()
        .map(|logs| dir_bytes_recursive(logs))
        .sum()
}

fn scenario_logs_dirs(run_dir: &Path) -> Vec<PathBuf> {
    let Ok(entries) = fs::read_dir(run_dir) else {
        return Vec::new();
    };
    entries
        .flatten()
        .map(|e| e.path().join("logs"))
        .filter(|p| p.is_dir())
        .collect()
}

fn dir_bytes_recursive(dir: &Path) -> u64 {
    let Ok(entries) = fs::read_dir(dir) else {
        return 0;
    };
    entries
        .flatten()
        .map(|e| match e.metadata() {
            Ok(m) if m.is_dir() => dir_bytes_recursive(&e.path()),
            Ok(m) => m.len(),
            Err(_) => 0,
        })
        .sum()
}

/// What retention did before this run started (recorded in the artifact).
#[derive(Debug, Default, serde::Serialize)]
pub struct RetentionReport {
    pub cap_bytes: u64,
    pub before_bytes: u64,
    pub after_bytes: u64,
    /// Run-directory names whose `logs/` subtrees were removed, oldest first.
    pub pruned: Vec<String>,
    /// Completed runs shielded from pruning (the newest ones).
    pub protected: usize,
}

/// Remove the oldest runs' `logs/` subtrees under `bench_results` until the
/// total fits `cap_bytes`. `current_run` (the directory this run is about
/// to fill) is not a candidate and does not consume a protected slot, so
/// the shield always covers [`KEEP_NEWEST_RUNS`] *completed* runs.
pub fn prune_soak_logs(
    bench_results: &Path,
    cap_bytes: u64,
    current_run: Option<&Path>,
) -> RetentionReport {
    let mut runs: Vec<PathBuf> = fs::read_dir(bench_results)
        .map(|entries| {
            entries
                .flatten()
                .map(|e| e.path())
                .filter(|p| p.is_dir())
                .filter(|p| {
                    p.file_name()
                        .and_then(|n| n.to_str())
                        .is_some_and(is_soak_run_dir_name)
                })
                .filter(|p| current_run.is_none_or(|cur| !same_dir(p, cur)))
                .collect()
        })
        .unwrap_or_default();
    // Fixed-width stamps: lexical order is chronological order.
    runs.sort();

    let sizes: Vec<u64> = runs.iter().map(|r| run_log_bytes(r)).collect();
    let mut total: u64 = sizes.iter().sum();
    let mut report = RetentionReport {
        cap_bytes,
        before_bytes: total,
        after_bytes: total,
        pruned: Vec::new(),
        protected: runs.len().min(KEEP_NEWEST_RUNS),
    };
    let prunable = runs.len().saturating_sub(KEEP_NEWEST_RUNS);
    for (run, size) in runs.iter().zip(&sizes).take(prunable) {
        if total <= cap_bytes {
            break;
        }
        for logs in scenario_logs_dirs(run) {
            // Best-effort: a half-removed subtree is recounted next run.
            let _ = fs::remove_dir_all(&logs);
        }
        total = total.saturating_sub(*size);
        report.pruned.push(
            run.file_name()
                .map(|n| n.to_string_lossy().into_owned())
                .unwrap_or_default(),
        );
    }
    report.after_bytes = total;
    report
}

fn same_dir(a: &Path, b: &Path) -> bool {
    match (a.canonicalize(), b.canonicalize()) {
        (Ok(a), Ok(b)) => a == b,
        _ => a == b,
    }
}

/// Outcome of compressing one run's logs (stdout summary; the artifact is
/// written before this step so a compression fault can never cost it).
#[derive(Debug, Default)]
pub struct CompressReport {
    pub files: usize,
    pub before_bytes: u64,
    pub after_bytes: u64,
    /// Files left raw because gzip failed, with the error.
    pub failed: Vec<(PathBuf, String)>,
}

/// gzip every `*.log` under `run_dir/*/logs/` into `*.log.gz`, removing the
/// raw file only after the compressed one is complete and in place.
pub fn compress_run_logs(run_dir: &Path) -> CompressReport {
    let mut report = CompressReport::default();
    for logs in scenario_logs_dirs(run_dir) {
        let Ok(entries) = fs::read_dir(&logs) else {
            continue;
        };
        for path in entries.flatten().map(|e| e.path()) {
            if !path.is_file() || path.extension().is_none_or(|x| x != "log") {
                continue;
            }
            match gzip_file(&path) {
                Ok((before, after)) => {
                    report.files += 1;
                    report.before_bytes += before;
                    report.after_bytes += after;
                }
                Err(e) => report.failed.push((path, e.to_string())),
            }
        }
    }
    report
}

fn gzip_file(path: &Path) -> io::Result<(u64, u64)> {
    let gz_path = path.with_extension("log.gz");
    let tmp_path = path.with_extension("log.gz.tmp");
    let result = (|| {
        let mut input = io::BufReader::new(fs::File::open(path)?);
        let before = input.get_ref().metadata()?.len();
        let tmp = fs::File::create(&tmp_path)?;
        let mut encoder = GzEncoder::new(io::BufWriter::new(tmp), Compression::fast());
        io::copy(&mut input, &mut encoder)?;
        let mut writer = encoder.finish()?;
        io::Write::flush(&mut writer)?;
        let after = writer.get_ref().metadata()?.len();
        drop(writer);
        fs::rename(&tmp_path, &gz_path)?;
        fs::remove_file(path)?;
        Ok((before, after))
    })();
    if result.is_err() {
        let _ = fs::remove_file(&tmp_path);
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Read;

    fn fake_run(root: &Path, name: &str, log_bytes: usize) -> PathBuf {
        let run = root.join(name);
        let logs = run.join("h2").join("logs");
        fs::create_dir_all(&logs).expect("mkdir logs");
        fs::write(logs.join("hub.log"), vec![b'x'; log_bytes]).expect("hub.log");
        fs::write(run.join("h2").join("hub.json"), b"{}").expect("hub.json");
        fs::write(run.join("results.json"), b"{}").expect("results.json");
        run
    }

    #[test]
    fn run_dir_name_matches_only_the_runner_stamp() {
        assert!(is_soak_run_dir_name("soak-20260916-111354"));
        for other in [
            "soak-ci",
            "soak-2026091-111354",
            "soak-20260916-11135",
            "soak-20260916-11135a",
            "soak-20260916_111354",
            "baseline-20260711-130854",
            "2026-09-13-quic-vs-h2-loss",
            "soak-",
        ] {
            assert!(!is_soak_run_dir_name(other), "{other} must not match");
        }
    }

    #[test]
    fn prune_removes_oldest_logs_only_and_shields_the_newest_runs() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let root = tmp.path();
        let names = [
            "soak-20260913-000001",
            "soak-20260914-000001",
            "soak-20260915-000001",
            "soak-20260916-000001",
            "soak-20260917-000001",
        ];
        for n in names {
            fake_run(root, n, 1000);
        }
        // Not a candidate: the curated benchmark directory and the CI out dir.
        fake_run(root, "baseline-20260711-130854", 1000);
        fake_run(root, "soak-ci", 1000);
        // The run about to start: empty, must not consume a protected slot.
        let current = root.join("soak-20260918-000001");
        fs::create_dir_all(&current).expect("current");

        // Cap 0 would prune everything prunable — the shield must still hold.
        let report = prune_soak_logs(root, 0, Some(&current));
        assert_eq!(report.before_bytes, 5000);
        assert_eq!(report.pruned, vec![names[0], names[1]]);
        assert_eq!(report.protected, KEEP_NEWEST_RUNS);
        assert_eq!(report.after_bytes, 3000);
        for pruned in &names[..2] {
            let run = root.join(pruned);
            assert!(!run.join("h2").join("logs").exists(), "{pruned} logs gone");
            assert!(run.join("results.json").exists(), "{pruned} results kept");
            assert!(
                run.join("h2").join("hub.json").exists(),
                "{pruned} handoff kept"
            );
        }
        for kept in &names[2..] {
            assert!(
                root.join(kept).join("h2/logs/hub.log").exists(),
                "{kept} shielded"
            );
        }
        assert!(
            root.join("baseline-20260711-130854/h2/logs/hub.log")
                .exists()
        );
        assert!(root.join("soak-ci/h2/logs/hub.log").exists());
    }

    #[test]
    fn prune_stops_once_under_cap() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let root = tmp.path();
        for (i, size) in [1000usize, 1000, 1000, 1000, 1000, 1000].iter().enumerate() {
            fake_run(root, &format!("soak-2026091{i}-000001"), *size);
        }
        // 6000 bytes, cap 4500: dropping the oldest run (→5000) is not enough,
        // the second (→4000) is; the third prunable run must survive.
        let report = prune_soak_logs(root, 4500, None);
        assert_eq!(report.pruned.len(), 2);
        assert_eq!(report.after_bytes, 4000);
        assert!(root.join("soak-20260912-000001/h2/logs/hub.log").exists());
    }

    #[test]
    fn prune_is_a_no_op_under_cap() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let root = tmp.path();
        for i in 0..5 {
            fake_run(root, &format!("soak-2026091{i}-000001"), 10);
        }
        let report = prune_soak_logs(root, 1 << 20, None);
        assert!(report.pruned.is_empty());
        assert_eq!(report.before_bytes, report.after_bytes);
    }

    #[test]
    fn compress_replaces_raw_logs_losslessly() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let run = fake_run(tmp.path(), "soak-20260916-111354", 0);
        let logs = run.join("h2").join("logs");
        let line = "2026-09-16T03:13:56.748172Z DEBUG interflow_mesh::hub::routing: Data frame\n";
        let body = line.repeat(2000);
        fs::write(logs.join("hub.log"), &body).expect("hub.log");
        fs::write(logs.join("notes.txt"), b"not a log").expect("notes.txt");

        let report = compress_run_logs(&run);
        assert_eq!(report.files, 1, "only *.log files are compressed");
        assert!(report.failed.is_empty(), "{:?}", report.failed);
        assert_eq!(report.before_bytes, body.len() as u64);
        assert!(report.after_bytes < report.before_bytes / 10);
        assert!(!logs.join("hub.log").exists());
        assert!(logs.join("notes.txt").exists());

        let gz = fs::File::open(logs.join("hub.log.gz")).expect("gz");
        let mut restored = String::new();
        flate2::read::GzDecoder::new(gz)
            .read_to_string(&mut restored)
            .expect("inflate");
        assert_eq!(restored, body);
        // The per-file listing now sees the compressed artifact.
        let files = logs_dir_files(&logs);
        assert!(files.iter().any(|(n, _)| n == "hub.log.gz"));
    }
}
