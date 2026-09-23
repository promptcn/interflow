//! `interflow node install` — install (or upgrade) a node pack onto this
//! server.
//!
//! The pack is self-describing: its kind, node name and mesh role derive the
//! systemd unit (via [`crate::render`]), so a server never needs the
//! manifest. This command is the *only* writer and enabler of node units —
//! `install.sh` deliberately installs none (the pack landing is what binds
//! a node to a machine). Idempotent by design:
//!
//! - first run  — creates the layout, installs the pack, enables + starts
//!   the unit (systemd's `Type=notify` start job blocks until the engine
//!   itself signals `READY=1`, or fails after `TimeoutStartSec`);
//! - re-run     — swaps in the new pack (previous install moves to
//!   `<kind>-<node>.previous`), restarts, same readiness contract;
//! - user/group creation never duplicates (same guard as `install.sh`).
//!
//! There is deliberately no readiness probing here: the engines state their
//! own readiness (`sd_notify`), so install learns it from systemd's start
//! job instead of manufacturing TCP connections against the just-started
//! listeners (which used to surface as misleading `TLS handshake failed`
//! warnings in the node's own logs).
//!
//! System paths (the default root `/srv/interflow` + `/etc/systemd/system`)
//! require root; `--root <dir>` selects a self-contained layout for tests
//! and containers, skipping user/systemctl management entirely.

use crate::render;
use interflow_identity::pack::CredentialPack;
use interflow_identity::pack::PackKind;
use std::path::{Path, PathBuf};

/// Options for [`install`].
pub struct NodeInstall {
    /// Pack source: a rendered pack directory or a sealed `.iflowpack`.
    pub pack: PathBuf,
    /// Install root (default `/srv/interflow`; tests override).
    pub root: PathBuf,
    /// Service user the unit runs as.
    pub user: String,
    /// Passphrase for sealed sources (env `INTERFLOW_PACK_PASSPHRASE`).
    pub passphrase: Option<String>,
}

/// What one install run did — printed by the CLI, asserted by tests.
pub struct InstallReport {
    pub kind: PackKind,
    pub node: String,
    pub installed_to: PathBuf,
    /// An existing install was replaced (upgrade).
    pub upgraded: bool,
    pub unit_path: PathBuf,
    /// The unit was started/restarted through systemd this run (with
    /// `Type=notify`, a successful start already implies READY=1).
    pub service_started: bool,
}

impl NodeInstall {
    fn system_target(&self) -> bool {
        self.root == Path::new(render::DEFAULT_INSTALL_ROOT)
    }
}

/// Installs the pack described by `opts` onto this machine.
pub fn install(opts: &NodeInstall) -> interflow_core::error::Result<InstallReport> {
    let system_target = opts.system_target();
    if system_target && !running_as_root() {
        return Err(interflow_core::error::InterflowError::config(
            "installing into system paths requires root — re-run with sudo, or pass \
             --root <dir> for a self-contained (non-systemd) layout",
        ));
    }
    let packs_root = opts.root.join("packs");
    std::fs::create_dir_all(&packs_root)?;

    // Stage the pack under the install root so the final swap is an atomic
    // Stage the pack under the install root so the final swap is an atomic
    // same-filesystem rename. The staged copy also tells us who we are
    // installing (kind/node derive the unit and the target name).
    let staging = packs_root.join(format!(".staging-install-{}", std::process::id()));
    if staging.exists() {
        std::fs::remove_dir_all(&staging)?;
    }
    let staged_path = staging.join("pack");
    let pack = stage_pack(&opts.pack, &staged_path, opts.passphrase.as_deref())?;
    let kind = pack.metadata.kind;
    let node = pack.metadata.node.clone();
    let mesh_role = kind == PackKind::Hub || pack.node_config.mesh.is_some();
    drop(pack);

    if system_target {
        ensure_system_user(&opts.user)?;
    }

    // Swap in: existing install becomes `<kind>-<node>.previous`.
    let target = packs_root.join(format!("{}-{node}", kind.as_str()));
    let upgraded = target.exists();
    commit_staged(&staging, &staged_path, &target, false)?;
    if system_target {
        chown_tree(&target, &opts.user)?;
    }

    // Unit: the same pure function `plan apply` rendered on the operator
    // machine — the pack re-derives it, so dist and server cannot drift.
    let unit_name = format!("interflow-{}-{node}.service", kind.as_str());
    let unit_dir = if system_target {
        PathBuf::from("/etc/systemd/system")
    } else {
        opts.root.join("systemd")
    };
    std::fs::create_dir_all(&unit_dir)?;
    let unit_path = unit_dir.join(&unit_name);
    std::fs::write(
        &unit_path,
        render::node_unit(&opts.root.display().to_string(), kind, &node, mesh_role),
    )?;

    // Service management: only for the real system layout on a systemd box.
    // `Type=notify`: restart / enable --now block until the engine signals
    // READY=1 (listeners bound) or TimeoutStartSec — readiness is the
    // service's own statement, surfaced here as systemctl's exit status.
    let service_started = system_target && systemctl_available();
    if service_started {
        systemctl(&["daemon-reload"])?;
        let started = if systemctl(&["is-active", "--quiet", &unit_name]).is_ok() {
            systemctl(&["restart", &unit_name])
        } else {
            systemctl(&["enable", "--now", &unit_name])
        };
        if let Err(e) = started {
            return Err(interflow_core::error::InterflowError::config(format!(
                "{e} — inspect: journalctl -u {unit_name} -n 50"
            )));
        }
    }

    Ok(InstallReport {
        kind,
        node,
        installed_to: target,
        upgraded,
        unit_path,
        service_started,
    })
}

/// Atomically swaps a staged pack directory into `target`.
///
/// Optionally carries the node-local `state/` over from the current
/// install, rotates the previous install to `<target>.previous`, renames
/// the staged copy in, and tightens key permissions. Staging and target
/// share a filesystem (the caller stages next to the target), so the final
/// move is a rename.
///
/// `preserve_state` carries the active credential set, ACME certificates
/// and CRL snapshots across the swap — what an in-place *update* of a
/// running node wants (`node install` upgrades pass `false`: a fresh
/// server install starts from the pack's own material).
pub fn commit_staged(
    staging_root: &Path,
    staged: &Path,
    target: &Path,
    preserve_state: bool,
) -> interflow_core::error::Result<()> {
    if preserve_state && target.is_dir() {
        let old_state = target.join("state");
        if old_state.is_dir() {
            copy_dir_recursive(&old_state, &staged.join("state"))?;
        }
    }
    if target.exists() {
        let backup = backup_path(target);
        if backup.exists() {
            std::fs::remove_dir_all(&backup)?;
        }
        std::fs::rename(target, &backup)?;
    }
    std::fs::rename(staged, target)?;
    std::fs::remove_dir_all(staging_root)?;
    tighten_keys(target)?;
    Ok(())
}

/// One-shot [`commit_staged`]: stage, validate, swap into `target`.
///
/// Returns the pack as installed at `target`. This is the "update a known
/// install in place" primitive (the GUI's update-local-node action).
pub fn swap_pack_into(
    source: &Path,
    target: &Path,
    passphrase: Option<&str>,
    preserve_state: bool,
) -> interflow_core::error::Result<CredentialPack> {
    let staging = target
        .parent()
        .unwrap_or_else(|| Path::new("."))
        .join(format!(".staging-swap-{}", std::process::id()));
    if staging.exists() {
        std::fs::remove_dir_all(&staging)?;
    }
    let staged = staging.join("pack");
    stage_pack(source, &staged, passphrase)?;
    commit_staged(&staging, &staged, target, preserve_state)?;
    CredentialPack::load_runtime(target).map_err(crate::runtime::pack_error)
}

/// `<dir>` → sibling `<dir>.previous` (same parent, same filesystem).
fn backup_path(target: &Path) -> PathBuf {
    let name = format!(
        "{}.previous",
        target
            .file_name()
            .map_or_else(|| "pack".into(), |n| n.to_string_lossy().into_owned())
    );
    target.parent().unwrap_or_else(|| Path::new(".")).join(name)
}

/// Copies / decrypts the pack source into `staged` and validates it through
/// the same funnel the start path uses.
fn stage_pack(
    source: &Path,
    staged: &Path,
    passphrase: Option<&str>,
) -> interflow_core::error::Result<CredentialPack> {
    if source.extension().is_some_and(|e| e == "iflowpack") {
        let pass = passphrase.ok_or_else(|| {
            interflow_core::error::InterflowError::config(
                "sealed pack: set INTERFLOW_PACK_PASSPHRASE or pass --passphrase",
            )
        })?;
        interflow_identity::pack::sealed::install(source, staged, pass)
            .map_err(crate::runtime::pack_error)
    } else if source.is_dir() {
        copy_dir_recursive(source, staged)?;
        CredentialPack::load_runtime(staged).map_err(crate::runtime::pack_error)
    } else {
        Err(interflow_core::error::InterflowError::config(format!(
            "pack source {} is neither a pack directory nor a .iflowpack",
            source.display()
        )))
    }
}

/// Wildcard listen hosts become loopback addresses (doctor dials from this
/// machine when diagnosing a node's listeners).
pub fn probe_address(listen: &str) -> String {
    listen
        .replace("0.0.0.0:", "127.0.0.1:")
        .replace("[::]:", "[::1]:")
}

fn running_as_root() -> bool {
    std::process::Command::new("id")
        .arg("-u")
        .output()
        .is_ok_and(|o| String::from_utf8_lossy(&o.stdout).trim() == "0")
}

fn systemctl_available() -> bool {
    std::process::Command::new("systemctl")
        .arg("--version")
        .output()
        .is_ok_and(|o| o.status.success())
}

fn systemctl(args: &[&str]) -> interflow_core::error::Result<()> {
    let output = std::process::Command::new("systemctl")
        .args(args)
        .output()?;
    if output.status.success() {
        Ok(())
    } else {
        Err(interflow_core::error::InterflowError::config(format!(
            "systemctl {args:?} failed: {}",
            String::from_utf8_lossy(&output.stderr).trim(),
        )))
    }
}

fn ensure_system_user(user: &str) -> interflow_core::error::Result<()> {
    // Groups and users mirror install.sh: system group + system user, never
    // duplicated on re-runs.
    let group_exists = std::process::Command::new("getent")
        .arg("group")
        .arg(user)
        .output()
        .is_ok_and(|o| o.status.success());
    if !group_exists {
        run_checked(
            std::process::Command::new("groupadd").args(["--system", user]),
            "groupadd",
        )?;
    }
    let user_exists = std::process::Command::new("id")
        .arg(user)
        .output()
        .is_ok_and(|o| o.status.success());
    if !user_exists {
        run_checked(
            std::process::Command::new("useradd")
                .args(["--system", "--gid", user])
                .args(["--home-dir", render::DEFAULT_INSTALL_ROOT])
                .args(["--shell", "/usr/sbin/nologin"])
                .arg(user),
            "useradd",
        )?;
    }
    Ok(())
}

fn run_checked(
    command: &mut std::process::Command,
    name: &str,
) -> interflow_core::error::Result<()> {
    let status = command.status()?;
    if status.success() {
        Ok(())
    } else {
        Err(interflow_core::error::InterflowError::config(format!(
            "{name} failed with {status}"
        )))
    }
}

/// Tightens every private key under the installed pack to 0600 (same rule
/// as sealed installs; a no-op for already-tight packs).
fn tighten_keys(dir: &Path) -> interflow_core::error::Result<()> {
    for entry in std::fs::read_dir(dir)? {
        let entry = entry?;
        let path = entry.path();
        if path.is_dir() {
            tighten_keys(&path)?;
        } else if path.extension().is_some_and(|e| e == "key") {
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                let mut perms = std::fs::metadata(&path)?.permissions();
                perms.set_mode(0o600);
                std::fs::set_permissions(&path, perms)?;
            }
        }
    }
    Ok(())
}

/// Recursively gives the tree to the service user (system layout only).
#[cfg(unix)]
fn chown_tree(dir: &Path, user: &str) -> interflow_core::error::Result<()> {
    let uid_gid = || -> interflow_core::error::Result<(u32, u32)> {
        let lookup = |flag: &str| -> interflow_core::error::Result<u32> {
            let out = std::process::Command::new("id")
                .args([flag, user])
                .output()?;
            String::from_utf8_lossy(&out.stdout)
                .trim()
                .parse::<u32>()
                .map_err(|e| {
                    interflow_core::error::InterflowError::config(format!(
                        "id {flag} {user} lookup failed"
                    ))
                    .with_source(e)
                })
        };
        Ok((lookup("-u")?, lookup("-g")?))
    };
    let (uid, gid) = uid_gid()?;
    fn walk(dir: &Path, uid: u32, gid: u32) -> interflow_core::error::Result<()> {
        std::os::unix::fs::chown(dir, Some(uid), Some(gid))?;
        for entry in std::fs::read_dir(dir)? {
            let path = entry?.path();
            if path.is_dir() {
                walk(&path, uid, gid)?;
            } else {
                std::os::unix::fs::chown(&path, Some(uid), Some(gid))?;
            }
        }
        Ok(())
    }
    walk(dir, uid, gid)
}

#[cfg(not(unix))]
fn chown_tree(_dir: &Path, _user: &str) -> interflow_core::error::Result<()> {
    Ok(())
}

fn copy_dir_recursive(src: &Path, dst: &Path) -> interflow_core::error::Result<()> {
    std::fs::create_dir_all(dst)?;
    for entry in std::fs::read_dir(src)? {
        let entry = entry?;
        let path = entry.path();
        let target = dst.join(entry.file_name());
        if path.is_dir() {
            copy_dir_recursive(&path, &target)?;
        } else {
            std::fs::copy(&path, &target)?;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wildcard_listens_probe_over_loopback() {
        assert_eq!(probe_address("0.0.0.0:8443"), "127.0.0.1:8443");
        assert_eq!(probe_address("127.0.0.1:16666"), "127.0.0.1:16666");
    }
}
