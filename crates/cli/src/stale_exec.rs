//! 换盘不换进程检测 — the disk-swap detector (needrestart semantics).
//!
//! Replacing a binary on disk does nothing to the process already running
//! it: the kernel keeps the old inode mapped until the unit restarts. In
//! this deployment's shape the trap is structural — `node install` restarts
//! only its OWN unit, while the edge face's unit
//! (`interflow-ingress-edge`) execs `interflow-cli` and the mesh units exec
//! `interflow-mesh`, so a `interflow-cli` disk swap leaves the edge serving
//! the OLD build until someone remembers `systemctl restart` (the
//! 2026-10-12 §10.8 case: journal self-reporting an old build string two
//! handoffs after the swap).
//!
//! This module is the product's answer: after any install-class command,
//! scan the machine for engine processes whose executable no longer matches
//! the disk, name the owning unit, and (with `--restart-units`) restart
//! them. Detection is belt AND braces:
//!
//! - the kernel's `(deleted)` marker on `/proc/<pid>/exe` (rename-style
//!   replacement — what `install(1)` and our build scripts produce), AND
//! - an inode comparison between `/proc/<pid>/exe` and the file currently
//!   at that path (an in-place overwrite the deleted marker cannot see).
//!
//! Only processes running one of the engine binary names count — an
//! unrelated replaced binary on the box is not this product's alert to
//! raise. All pure logic is parameterized by `proc_root` so tests stage a
//! fake `/proc` tree instead of needing root and a real systemd.

use std::path::{Path, PathBuf};

/// The engine binary names any node unit may exec
/// ([`crate::render::node_engine_binary`]'s range).
pub const ENGINE_BINARIES: [&str; 3] = ["interflow-cli", "interflow-mesh", "interflow-registrar"];

/// Why a process reads as stale.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StaleEvidence {
    /// `/proc/<pid>/exe` carries the kernel's `(deleted)` marker — the
    /// file was unlinked or renamed over while the process kept running
    /// (the `install(1)`/`mv` replacement shape).
    DeletedMarker,
    /// The process's exe inode differs from the file now at the same path
    /// — an in-place overwrite the deleted marker cannot see.
    InodeMismatch,
}

impl StaleEvidence {
    /// The one-line reading, phrased for the operator's journal.
    pub const fn describe(self) -> &'static str {
        match self {
            Self::DeletedMarker => "its binary was replaced on disk (deleted marker)",
            Self::InodeMismatch => "its binary was overwritten in place (inode changed)",
        }
    }
}

/// One finding: a running engine process whose executable is not what the
/// disk now holds.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StaleFinding {
    /// The offending pid.
    pub pid: u32,
    /// The exe path the process runs (the `(deleted)` marker stripped).
    pub exe: PathBuf,
    /// The owning `interflow-*.service` unit when derivable from the
    /// process's cgroup — the exact thing to restart.
    pub unit: Option<String>,
    /// How staleness was established.
    pub evidence: StaleEvidence,
}

impl StaleFinding {
    /// The operator-facing one-liner.
    pub fn describe(&self) -> String {
        let unit = self.unit.as_deref().unwrap_or("(no unit — manual process)");
        format!(
            "{unit} (pid {}) still runs the OLD disk: {} {}",
            self.pid,
            self.exe.display(),
            self.evidence.describe()
        )
    }

    /// The restart target for `--restart-units`: an owned product unit,
    /// `None` for a manually started process (a restart would be guesswork).
    pub fn restart_target(&self) -> Option<&str> {
        self.unit
            .as_deref()
            .filter(|u| u.starts_with("interflow-") && u.ends_with(".service"))
    }
}

/// Scans a `/proc` tree for engine processes whose executable no longer
/// matches the disk.
///
/// `proc_root` is injectable (tests stage a fake tree); production passes
/// `/proc`. `engine_dir` narrows the blast radius to binaries in the
/// deployment's engine bin dir (e.g. `/usr/local/bin`) — `None` scans any
/// path. Unreadable entries (other users' `/proc/<pid>/exe` without
/// privileges) are skipped silently: a partial scan still names everything
/// the caller has the right to see, which on the root-run install path is
/// everything.
pub fn scan_stale_processes(proc_root: &Path, engine_dir: Option<&Path>) -> Vec<StaleFinding> {
    let mut findings = Vec::new();
    let Ok(entries) = std::fs::read_dir(proc_root) else {
        return findings;
    };
    for entry in entries.flatten() {
        let name = entry.file_name();
        let Some(pid) = name.to_str().and_then(|n| n.parse::<u32>().ok()) else {
            continue;
        };
        let proc_dir = proc_root.join(&name);
        let Some(link) = read_exe_link(&proc_dir) else {
            continue;
        };
        // Engine binaries only: a replaced `nginx` on this box is not this
        // product's alert.
        if !link
            .file_name()
            .and_then(|n| n.to_str())
            .is_some_and(|n| ENGINE_BINARIES.contains(&n))
        {
            continue;
        }
        if let Some(dir) = engine_dir
            && link.parent() != Some(dir)
        {
            continue;
        }
        let Some(evidence) = classify(&proc_dir, &link) else {
            continue;
        };
        findings.push(StaleFinding {
            pid,
            exe: link,
            unit: owning_unit(&proc_dir),
            evidence,
        });
    }
    // Unit-owned findings first (the restartable ones), None-units after;
    // within a group, deterministic by pid.
    findings.sort_by(|a, b| {
        let units = match (&a.unit, &b.unit) {
            (Some(x), Some(y)) => x.cmp(y),
            (Some(_), None) => std::cmp::Ordering::Less,
            (None, Some(_)) => std::cmp::Ordering::Greater,
            (None, None) => std::cmp::Ordering::Equal,
        };
        units.then(a.pid.cmp(&b.pid))
    });
    findings
}

/// The real-machine entry point: engine processes under the deployment's
/// bin dir. Linux-only in substance — other platforms have no `/proc` and
/// the scan reads clean (a no-op, never an error).
pub fn detect_stale_engine_processes(bin_dir: &Path) -> Vec<StaleFinding> {
    // Off Linux there is no /proc to walk: the scan reads clean.
    #[cfg(not(target_os = "linux"))]
    let proc_root = Path::new("/nonexistent-proc");
    #[cfg(target_os = "linux")]
    let proc_root = Path::new("/proc");
    scan_stale_processes(proc_root, Some(bin_dir))
}

/// Reads `<proc>/<pid>/exe` as a path, stripping the kernel's
/// `" (deleted)"` marker when present. `None` = unreadable (permissions,
/// kernel thread) or not a UTF-8 path — skip, never guess.
fn read_exe_link(proc_dir: &Path) -> Option<PathBuf> {
    let raw = std::fs::read_link(proc_dir.join("exe")).ok()?;
    let text = raw.to_str()?;
    Some(PathBuf::from(
        text.strip_suffix(" (deleted)").unwrap_or(text),
    ))
}

/// Belt AND braces staleness test: the deleted marker the kernel stamps on
/// rename-style replacements, plus the inode comparison that also catches
/// in-place overwrites. `None` = the process matches the disk (fresh) or
/// nothing can be proven (both stats failed) — no false alarms.
fn classify(proc_dir: &Path, exe: &Path) -> Option<StaleEvidence> {
    if std::fs::read_link(proc_dir.join("exe"))
        .ok()
        .and_then(|l| l.to_str().map(str::to_owned))
        .is_some_and(|l| l.ends_with(" (deleted)"))
    {
        return Some(StaleEvidence::DeletedMarker);
    }
    let running = std::fs::metadata(proc_dir.join("exe")).ok()?;
    let on_disk = std::fs::metadata(exe).ok()?;
    // std::fs::Metadata has no portable dev/ino accessor; on Unix compare
    // through the extension trait. Same (dev, ino) at the same path = the
    // process IS the disk's binary.
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if (running.dev(), running.ino()) == (on_disk.dev(), on_disk.ino()) {
            return None;
        }
        Some(StaleEvidence::InodeMismatch)
    }
    #[cfg(not(unix))]
    {
        let _ = (running, on_disk);
        None
    }
}

/// Derives the owning `interflow-*.service` from the process's cgroup file
/// (`0::/system.slice/interflow-ingress-edge.service`). Only product units
/// are attributed — a dev-machine process inside some `user@1000.service`
/// session reports no unit rather than a wrong one.
fn owning_unit(proc_dir: &Path) -> Option<String> {
    let cgroup = std::fs::read_to_string(proc_dir.join("cgroup")).ok()?;
    cgroup
        .lines()
        // "hierarchy:controllers:path" — the path is after the last ':'.
        .filter_map(|line| line.rsplit_once(':').map(|(_, path)| path))
        .flat_map(|path| path.split('/'))
        .find(|seg| seg.starts_with("interflow-") && seg.ends_with(".service"))
        .map(str::to_owned)
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    /// Stages one fake `/proc/<pid>` entry: an `exe` symlink (target given
    /// verbatim, so tests can forge the `(deleted)` marker) and an optional
    /// cgroup file.
    fn stage_pid(proc_root: &Path, pid: &str, exe_target: &str, cgroup: Option<&str>) {
        let dir = proc_root.join(pid);
        std::fs::create_dir_all(&dir).unwrap();
        std::os::unix::fs::symlink(exe_target, dir.join("exe")).unwrap();
        if let Some(cgroup) = cgroup {
            std::fs::write(dir.join("cgroup"), cgroup).unwrap();
        }
    }

    /// The full decision table over a staged tree: fresh processes and
    /// unrelated binaries stay silent; both replacement shapes are named
    /// with their owning unit; the engine-dir filter and cgroup variants
    /// behave.
    #[test]
    fn scan_classifies_replacements_and_ignores_the_rest() {
        let tmp = tempfile::tempdir().unwrap();
        let bin = tmp.path().join("bin");
        let proc_root = tmp.path().join("proc");
        std::fs::create_dir_all(&bin).unwrap();
        std::fs::create_dir_all(&proc_root).unwrap();

        // A real on-disk engine binary — the same-inode baseline.
        let cli = bin.join("interflow-cli");
        std::fs::write(&cli, b"fresh").unwrap();

        let system_slice = "0::/system.slice/interflow-ingress-edge.service\n";
        // pid 1: fresh (exe == disk inode) — no finding, cgroup or not.
        stage_pid(&proc_root, "101", cli.to_str().unwrap(), Some(system_slice));
        // pid 2: deleted marker (rename-style replacement).
        stage_pid(
            &proc_root,
            "102",
            &format!("{} (deleted)", cli.display()),
            Some(system_slice),
        );
        // pid 3: the exe path is simply GONE (no marker) — nothing can be
        // proven about a replacement, so silence, never a guess. (The
        // in-place-overwrite inode case needs the kernel's exec-time inode
        // pinning — covered by the real-process test below.)
        stage_pid(
            &proc_root,
            "103",
            tmp.path().join("gone/interflow-cli").to_str().unwrap(),
            None,
        );
        // pid 4: unrelated replaced binary — not our alert.
        stage_pid(
            &proc_root,
            "104",
            "/usr/bin/sleep (deleted)",
            Some(system_slice),
        );
        // pid 5: engine name but outside the engine dir — skipped by the
        // dir filter.
        stage_pid(&proc_root, "105", "/opt/dev/interflow-mesh (deleted)", None);
        // pid 6: deleted marker, no cgroup at all — finding without a unit.
        stage_pid(
            &proc_root,
            "106",
            &format!("{} (deleted)", cli.display()),
            None,
        );
        // pid 7: cgroup WITHOUT a product unit (a user session) — finding,
        // unit attribution refuses to guess.
        stage_pid(
            &proc_root,
            "107",
            &format!("{} (deleted)", cli.display()),
            Some("0::/user.slice/user-1000.slice/user@1000.service/app.slice/x.service"),
        );
        // Not-a-pid directory: ignored by the numeric filter.
        std::fs::create_dir_all(proc_root.join("irq")).unwrap();

        let findings = scan_stale_processes(&proc_root, Some(&bin));
        let pids: Vec<u32> = findings.iter().map(|f| f.pid).collect();
        assert_eq!(pids, vec![102, 106, 107], "findings: {findings:?}");

        let by_pid = |pid: u32| findings.iter().find(|f| f.pid == pid).unwrap();
        assert_eq!(by_pid(102).evidence, StaleEvidence::DeletedMarker);
        assert_eq!(
            by_pid(102).unit.as_deref(),
            Some("interflow-ingress-edge.service")
        );
        assert_eq!(by_pid(102).exe, cli);
        assert_eq!(by_pid(106).unit, None);
        assert_eq!(
            by_pid(107).unit,
            None,
            "a user-session cgroup is not attributed as a product unit"
        );
        assert_eq!(by_pid(106).restart_target(), None);
        assert_eq!(
            by_pid(102).restart_target(),
            Some("interflow-ingress-edge.service")
        );

        // Without the dir filter, the out-of-tree dev binary counts too.
        let all = scan_stale_processes(&proc_root, None);
        assert_eq!(
            all.iter().map(|f| f.pid).collect::<Vec<_>>(),
            vec![102, 105, 106, 107]
        );
    }

    /// The §10.8 acceptance shape end to end: name the unit that needs the
    /// restart, in operator-readable words.
    #[test]
    fn findings_read_as_operator_lines() {
        let finding = StaleFinding {
            pid: 1234,
            exe: PathBuf::from("/usr/local/bin/interflow-cli"),
            unit: Some("interflow-ingress-edge.service".to_owned()),
            evidence: StaleEvidence::DeletedMarker,
        };
        let line = finding.describe();
        assert!(line.contains("interflow-ingress-edge.service"), "{line}");
        assert!(line.contains("1234"), "{line}");
        assert!(line.contains("OLD"), "{line}");
    }

    /// Legacy (v1) cgroup lines and multi-segment paths still attribute the
    /// innermost product unit.
    #[test]
    fn cgroup_parsing_variants() {
        let tmp = tempfile::tempdir().unwrap();
        let proc_dir = tmp.path().join("9");
        std::fs::create_dir_all(&proc_dir).unwrap();
        std::fs::write(
            proc_dir.join("cgroup"),
            "1:name=systemd:/system.slice/interflow-hub-promptcn.service\n",
        )
        .unwrap();
        assert_eq!(
            owning_unit(&proc_dir).as_deref(),
            Some("interflow-hub-promptcn.service")
        );
        std::fs::write(
            proc_dir.join("cgroup"),
            "0::/system.slice/interflow-agent-x.service/interflow.scope\n",
        )
        .unwrap();
        assert_eq!(
            owning_unit(&proc_dir).as_deref(),
            Some("interflow-agent-x.service"),
            "innermost product unit wins over enclosing scopes"
        );
    }

    /// A missing/empty proc root is a clean scan, never an error.
    #[test]
    fn missing_proc_root_scans_clean() {
        assert!(scan_stale_processes(Path::new("/nonexistent-proc"), None).is_empty());
    }

    /// The real-machine shape on Linux: spawn a process from a staged
    /// binary, replace the file in place, and the scan must name the pid
    /// with the inode evidence (the deleted-marker path needs the kernel,
    /// the inode path needs only a real /proc).
    #[cfg(target_os = "linux")]
    #[test]
    fn real_process_replacement_is_detected() {
        use std::process::{Command, Stdio};

        let tmp = tempfile::tempdir().unwrap();
        let bin = tmp.path().join("bin");
        std::fs::create_dir_all(&bin).unwrap();
        let fake_engine = bin.join("interflow-mesh");
        // A long-lived stand-in binary: `sleep`.
        std::fs::write(&fake_engine, std::fs::read("/bin/sleep").unwrap()).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&fake_engine, std::fs::Permissions::from_mode(0o755)).unwrap();
        }
        let mut child = Command::new(&fake_engine)
            .arg("30")
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap();
        let fresh = scan_stale_processes(Path::new("/proc"), Some(&bin));
        assert!(
            !fresh.iter().any(|f| f.pid == child.id()),
            "a just-started process is not stale: {fresh:?}"
        );
        // In-place replacement: new inode at the same path.
        std::fs::write(
            tmp.path().join("replacement"),
            std::fs::read("/bin/sleep").unwrap(),
        )
        .unwrap();
        std::fs::rename(tmp.path().join("replacement"), &fake_engine).unwrap();
        let stale = scan_stale_processes(Path::new("/proc"), Some(&bin));
        let hit = stale.iter().find(|f| f.pid == child.id());
        assert!(
            hit.is_some_and(|f| f.evidence == StaleEvidence::InodeMismatch),
            "the replaced-disk process must be named: {stale:?}"
        );
        let _ = child.kill();
        let _ = child.wait();
    }
}
