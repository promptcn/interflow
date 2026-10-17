//! Rust-authored user-facing strings, in both GUI languages.
//!
//! Scope: the surfaces Rust itself renders or authors — the tray menu,
//! its tooltip/toast, and command-layer errors tied to a user action's
//! input (a missing path, an unsupported action). Engine diagnostics,
//! log lines, and infra failures (state-lock poisoning, serialize
//! errors) stay English on purpose: they are cross-referenced against
//! the CLI and log files, which speak one vocabulary — interactive
//! chrome is localized, diagnostics are not.
//!
//! Both languages are one struct — the compiler enforces that `EN` and
//! `ZH` carry every field, so a new string cannot ship half-translated.
//! Lookup reads the prefs file at point of use ([`current`]): every
//! caller sits on a cold path (menu rebuilds on state transitions,
//! error construction), so the tiny read beats a cache that could drift
//! from the file the frontend also writes.
//!
//! Product vocabulary (Credential Pack, manifest, hub, realm, leaf,
//! agent kind names, QUIC/TLS) stays English in both languages — the
//! terms anchor to the pack contents and the CLI, which never translate.

use crate::gui_prefs::Lang;

/// Interpolated strings carry `{name}` placeholders — the same
/// convention the frontend's `t(key, params)` uses, one interpolation
/// vocabulary across the IPC boundary.
pub struct Strings {
    // ---- tray ---------------------------------------------------------
    /// Menu row: stop every running node.
    pub tray_stop_all: &'static str,
    /// Menu row: bring the main window back.
    pub tray_show: &'static str,
    /// Menu row: quit the app.
    pub tray_quit: &'static str,
    /// Tooltip line for the most urgent expiring leaf. Placeholders:
    /// `{name}`, `{remaining}`, `{phase}` — the remaining-time and phase
    /// words stay in the shared expiry vocabulary ("3d", "warn") either
    /// way, mirroring doctor output.
    pub tray_leaf_left: &'static str,
    /// Windows-only first-hide toast: title and body.
    #[cfg_attr(not(target_os = "windows"), allow(dead_code))]
    pub toast_title: &'static str,
    #[cfg_attr(not(target_os = "windows"), allow(dead_code))]
    pub toast_body: &'static str,
    // ---- command errors (user-action inputs) ---------------------------
    /// A typed path that does not exist. Placeholders: `{label}`, `{path}`
    /// — the error shows the user's original input, not the expansion.
    pub err_path_not_exists: &'static str,
    pub label_credential_pack_dir: &'static str,
    pub label_source_pack_dir: &'static str,
    /// File read/write wrappers around io errors. Placeholders: `{path}`,
    /// `{err}` (the io chain stays English — it is the diagnostic).
    pub err_read: &'static str,
    pub err_write: &'static str,
    /// The one io error the UI can name in the user's language: ENOENT's
    /// "No such file or directory (os error 2)" is English on every OS.
    /// Placeholder: `{path}`.
    pub err_not_found: &'static str,
    /// Manifest-creation refusal (the CLI setup semantic: never overwrite
    /// a live manifest). Placeholder: `{path}`.
    pub err_manifest_exists: &'static str,
    /// `deployment_set_current` on a folder without `interflow.toml`.
    /// Placeholders: `{path}`.
    pub err_not_deployment: &'static str,
    /// Hostname lookup failure. Placeholder: `{err}`.
    pub err_hostname: &'static str,
    /// The Downloads directory could not be resolved (seal-to-downloads).
    pub err_downloads_dir: &'static str,
    /// A node id the manager no longer knows.
    pub err_unknown_node: &'static str,
    /// The node disappeared mid pack-update (removed from another path).
    pub err_node_vanished: &'static str,
    /// Prefs were sent for a node kind that has none (hub/ingress).
    pub err_agent_prefs_only: &'static str,
}

pub const EN: Strings = Strings {
    tray_stop_all: "Stop all",
    tray_show: "Show main window",
    tray_quit: "Quit",
    tray_leaf_left: "{name}: leaf {remaining} left ({phase})",
    toast_title: "Interflow is still running",
    toast_body: "The window was tucked into the system tray — click the tray icon to bring it back.",
    err_path_not_exists: "{label} does not exist: {path}",
    label_credential_pack_dir: "Credential Pack directory",
    label_source_pack_dir: "source pack directory",
    err_read: "read {path}: {err}",
    err_write: "write {path}: {err}",
    err_not_found: "File not found: {path}",
    err_manifest_exists: "manifest already exists — refusing to overwrite: {path}",
    err_not_deployment: "not a deployment folder (no interflow.toml inside): {path}",
    err_hostname: "hostname unavailable: {err}",
    err_downloads_dir: "cannot resolve the Downloads directory",
    err_unknown_node: "unknown node",
    err_node_vanished: "node vanished during update",
    err_agent_prefs_only: "only agent nodes have local preferences — what this node is \
                           (identity, services) still comes entirely from its pack",
};

pub const ZH: Strings = Strings {
    tray_stop_all: "全部停止",
    tray_show: "显示主窗口",
    tray_quit: "退出",
    tray_leaf_left: "{name}:leaf 剩余 {remaining}({phase})",
    toast_title: "Interflow 仍在运行",
    toast_body: "窗口已收进系统托盘——点击托盘图标即可找回。",
    err_path_not_exists: "{label} 不存在:{path}",
    label_credential_pack_dir: "Credential Pack 目录",
    label_source_pack_dir: "来源 pack 目录",
    err_read: "读取 {path} 失败:{err}",
    err_write: "写入 {path} 失败:{err}",
    err_not_found: "文件不存在:{path}",
    err_manifest_exists: "manifest 已存在——拒绝覆盖:{path}",
    err_not_deployment: "不是部署文件夹（缺少 interflow.toml）：{path}",
    err_hostname: "无法获取主机名:{err}",
    err_downloads_dir: "无法定位「下载」目录",
    err_unknown_node: "未知节点",
    err_node_vanished: "更新过程中节点消失了",
    err_agent_prefs_only: "只有 agent 节点有本地偏好——节点本身是什么(身份、服务)始终完全由它的 pack 决定",
};

pub const fn strings(lang: Lang) -> &'static Strings {
    match lang {
        Lang::En => &EN,
        Lang::Zh => &ZH,
    }
}

/// The strings for the persisted language (the prefs file is the single
/// source of truth; see the module comment for why there is no cache).
pub fn current() -> &'static Strings {
    strings(crate::gui_prefs::load().language)
}

/// Substitutes `{name}` placeholders; an unknown placeholder is left
/// verbatim so a template/args mismatch is visible, not silent.
pub fn render(template: &str, args: &[(&str, &str)]) -> String {
    let mut out = template.to_string();
    for (name, value) in args {
        out = out.replace(&format!("{{{name}}}"), value);
    }
    out
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    /// Named placeholders substitute in any order; unknown ones stay
    /// visible (a template/args drift must not eat content silently).
    #[test]
    fn render_substitutes_named_placeholders() {
        let out = render("{b} then {a}", &[("a", "1"), ("b", "2")]);
        assert_eq!(out, "2 then 1");
        assert_eq!(render("{missing}", &[("a", "1")]), "{missing}");
        // A value containing a placeholder-looking token must not recurse.
        assert_eq!(render("{a}", &[("a", "{a}")]), "{a}");
    }

    /// Both languages cover the same vocabulary and pick by lang — the
    /// struct shape enforces completeness at compile time; this pins the
    /// selection itself.
    #[test]
    fn strings_select_by_language() {
        assert_eq!(strings(Lang::En).tray_quit, "Quit");
        assert_eq!(strings(Lang::Zh).tray_quit, "退出");
        assert_eq!(
            strings(Lang::Zh).err_path_not_exists,
            "{label} 不存在:{path}"
        );
    }
}
