#!/usr/bin/env python3
"""Enforce the CHANGELOG accumulation contract (documentation/versioning.md,
"CHANGELOG").

The contract's floor: whenever commits after the bump commit — the commit
that introduced the newest versioned section heading — touched product
surfaces, the CHANGELOG must have gained at least one entry line since that
same commit. Where the entry lives is style, not substance: the documented
home is `## [Unreleased]`, but folding into the still-unreleased current
section counts too (the 0.11.0 settlement did exactly that). What the floor
forbids is the drift this guard was built on: 47 commits — 18 of them
user-visible — landing after a bump with the changelog untouched, and
nothing anywhere going red.

Product surfaces are a denylist: everything tracked except the private docs/
and deployments/ trees, repo infrastructure (scripts/, .github/, .cargo/,
CI/build configs, lockfiles, local-only files) and generated/output
directories. A batch touching only excluded paths owes nothing; a batch
touching product surfaces pays with at least one honest entry line. There
is deliberately no marker or opt-out syntax — an escape hatch is how the
drift comes back.

Runs identically in the private tree (granular commits; `just ci` and the
export preflight) and the public tree (one commit per export; public CI):
the rule is diff-based on both sides, so it holds under both history shapes.
Shallow histories fail toward the strict side — if the section's introducing
commit is outside the shallow window, the oldest visible commit that carries
the heading becomes the bump and everything after it counts.

Fail-closed: not a git repo, no commits, no versioned section, no bump
commit found, or a versioned section in the working tree that HEAD does not
have (a bump in progress — commit it) are all failures, never passes.
"""

from __future__ import annotations

import re
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

HEADING_RE = re.compile(r"(?m)^## \[([^\]]+)\]")
ENTRY_LINE_RE = re.compile(r"^\+\s*- \S")

# Paths that are not product surfaces: touching them owes no changelog
# entry. Top-level directories first …
PRODUCT_EXCLUDED_DIRS = (
    "docs",           # private archives — never export
    "deployments",    # private real-deployment configs — never export
    "scripts",        # repo tooling and guards
    ".github",        # CI workflows
    ".cargo",         # toolchain config
    "fuzz",           # fuzz harnesses
    "bench-results",  # benchmark output (runtime path, not tracked content)
    "artifacts",      # local build artifacts
    "logs",           # runtime logs
    "data",           # runtime data
    "dist",           # generated frontend bundle
    "node_modules",
    "target",
)
# … then root-level files (build/CI config, lockfiles, legal, local-only).
PRODUCT_EXCLUDED_ROOT_FILES = {
    "justfile",
    "rustfmt.toml",
    "clippy.toml",
    "deny.toml",
    ".gitleaks.toml",
    ".gitignore",
    ".dockerignore",
    "tsconfig.json",
    "vite.config.ts",
    "Cargo.lock",
    "package-lock.json",
    "LICENSE",
    "CLAUDE.md",  # per-machine local file, not in git
}


def is_product_path(path: str) -> bool:
    top = path.split("/", 1)[0]
    if "/" not in path:
        return path not in PRODUCT_EXCLUDED_ROOT_FILES
    return top not in PRODUCT_EXCLUDED_DIRS


def git(root: Path, *args: str) -> str:
    """Run git, returning stdout; an OSError/CalledProcessError propagates to
    the caller's fail-closed handling."""
    result = subprocess.run(
        ["git", "-C", str(root), *args],
        capture_output=True,
        text=True,
    )
    if result.returncode != 0:
        raise RuntimeError(f"git {' '.join(args)} failed: {result.stderr.strip()}")
    return result.stdout


def heading_count(text: str, version: str) -> int:
    return len(re.findall(rf"(?m)^## \[{re.escape(version)}\]", text))


def top_version(text: str) -> str | None:
    versioned = [h for h in HEADING_RE.findall(text) if h.strip().lower() != "unreleased"]
    return versioned[0] if versioned else None


def find_bump_commit(root: Path, version: str) -> str | None:
    """The newest commit where the '## [version]' heading went 0 -> 1."""
    shas = git(root, "log", "--format=%H", "--", "CHANGELOG.md").split()
    for sha in shas:
        content = git(root, "show", f"{sha}:CHANGELOG.md")
        if heading_count(content, version) < 1:
            continue
        parent = f"{sha}^"
        try:
            parent_content = git(root, "show", f"{parent}:CHANGELOG.md")
        except RuntimeError:
            parent_content = ""  # root commit, or parent predates the file
        if heading_count(parent_content, version) == 0:
            return sha
    return None


def check(root: Path) -> tuple[int, list[str]]:
    """Returns (exit_code, message_lines)."""
    try:
        git(root, "rev-parse", "--git-dir")
        head_changelog = git(root, "show", "HEAD:CHANGELOG.md")
    except (OSError, RuntimeError) as exc:
        return 1, [f"fail-closed: {exc}"]
    try:
        worktree_changelog = (root / "CHANGELOG.md").read_text(encoding="utf-8")
    except OSError:
        return 1, ["fail-closed: CHANGELOG.md is missing from the working tree"]

    version = top_version(head_changelog)
    if version is None:
        return 1, ["fail-closed: HEAD's CHANGELOG.md has no versioned section (## [X.Y.Z] - date)"]
    worktree_version = top_version(worktree_changelog)
    if worktree_version != version:
        return 1, [
            "fail-closed: the working tree's newest versioned section "
            f"[{worktree_version}] differs from HEAD's [{version}] — commit the "
            "version bump (or the reversion) first; this guard judges committed "
            "history only"
        ]

    try:
        bump = find_bump_commit(root, version)
    except (OSError, RuntimeError) as exc:
        return 1, [f"fail-closed: {exc}"]
    if bump is None:
        return 1, [
            f"fail-closed: no commit in history introduces the '## [{version}]' "
            "heading — history rewritten?"
        ]
    bump_short = git(root, "rev-parse", "--short", bump).strip()

    try:
        changed = [p for p in git(root, "diff", "--name-only", bump, "HEAD").splitlines() if p]
        product = [p for p in changed if is_product_path(p)]
    except (OSError, RuntimeError) as exc:
        return 1, [f"fail-closed: {exc}"]

    if not product:
        total = git(root, "rev-list", "--count", f"{bump}..HEAD").strip()
        return 0, [
            f"changelog debt clean: no product-surface commits since the "
            f"[{version}] bump ({bump_short}; {total} commit(s) after it touched "
            "only excluded paths)"
        ]

    diff = git(root, "diff", bump, "HEAD", "--", "CHANGELOG.md")
    entries = sum(1 for line in diff.splitlines() if ENTRY_LINE_RE.match(line))
    if entries:
        return 0, [
            f"changelog debt clean: {len(product)} product-surface path(s) changed "
            f"since the [{version}] bump ({bump_short}) and the CHANGELOG gained "
            f"{entries} entry line(s)"
        ]

    commits = git(
        root, "log", "--oneline", "--no-decorate", f"{bump}..HEAD", "--", *product
    ).splitlines()
    listing = "\n".join(f"  {c}" for c in commits[:10])
    more = f"\n  … and {len(commits) - 10} more" if len(commits) > 10 else ""
    return 1, [
        f"changelog debt: product surfaces changed since the [{version}] bump "
        f"({bump_short}) but the CHANGELOG gained no entry line:",
        f"{listing}{more}",
        "pay the debt: add entry line(s) under '## [Unreleased]' (or fold into "
        f"the still-unreleased [{version}] section) — see "
        "documentation/versioning.md, \"CHANGELOG\"",
    ]


# ---------- self-test ----------
# Each scenario builds a throwaway git fixture (build_guard.sh --self-test
# precedent) and asserts check()'s verdict on it.

BASE_CHANGELOG = """\
# Changelog

## [Unreleased]

### Fixed

- existing entry that predates the scenario.

## [1.0.0] - 2026-01-01

### Added

- the initial release.
"""

SELF_TEST_CASES: list[tuple[str, int, str]] = []


def _scenario(name: str):
    def register(fn):
        SELF_TEST_CASES.append((name, fn))
        return fn

    return register


def _write(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


def _commit(repo: Path, message: str) -> None:
    git(repo, "add", "-A")
    git(repo, "commit", "-m", message)


def _base_repo() -> Path:
    repo = Path(tempfile.mkdtemp(prefix="changelog-debt-"))
    git(repo, "init", "-q", "-b", "main")
    git(repo, "config", "user.email", "selftest@example.invalid")
    git(repo, "config", "user.name", "selftest")
    _write(repo / "CHANGELOG.md", BASE_CHANGELOG)
    _write(repo / "src" / "main.rs", "fn main() {}\n")
    _commit(repo, "release 1.0.0 (bump: introduces ## [1.0.0])")
    return repo


@_scenario("no-commits-after-bump")
def _(report) -> None:
    repo = _base_repo()  # HEAD == bump
    code, _ = check(repo)
    report(code == 0, "HEAD == bump must pass with zero commits after it")


@_scenario("excluded-paths-after-bump")
def _(report) -> None:
    repo = _base_repo()
    _write(repo / "docs" / "notes.md", "private archive\n")
    _write(repo / "scripts" / "tool.py", "# tooling\n")
    _write(repo / ".github" / "ci.yml", "jobs: {}\n")
    _write(repo / "justfile", "x:\n")
    _write(repo / "Cargo.lock", "version = 4\n")
    _commit(repo, "docs and infra only")
    code, lines = check(repo)
    report(code == 0, "docs/scripts/CI/lockfile-only commits owe no entry", lines)


@_scenario("unrecorded-product-commit")
def _(report) -> None:
    repo = _base_repo()
    _write(repo / "src" / "feature.rs", "pub fn feature() {}\n")
    _commit(repo, "feat: the feature nobody recorded")
    code, lines = check(repo)
    report(code == 1, "a product commit with no changelog gain must fail", lines)
    joined = "\n".join(lines)
    report("feat: the feature nobody recorded" in joined, "the offending commit is named", lines)


@_scenario("recorded-in-unreleased")
def _(report) -> None:
    repo = _base_repo()
    _write(repo / "src" / "feature.rs", "pub fn feature() {}\n")
    _write(repo / "CHANGELOG.md", BASE_CHANGELOG.replace(
        "- existing entry that predates the scenario.",
        "- existing entry that predates the scenario.\n- the recorded feature.",
    ))
    _commit(repo, "feat: the recorded feature")
    code, lines = check(repo)
    report(code == 0, "a product commit with an [Unreleased] entry passes", lines)


@_scenario("folded-into-current-section")
def _(report) -> None:
    repo = _base_repo()
    _write(repo / "src" / "feature.rs", "pub fn feature() {}\n")
    _write(repo / "CHANGELOG.md", BASE_CHANGELOG.replace(
        "- the initial release.", "- the initial release.\n- the settled feature.",
    ))
    _commit(repo, "feat: the settled feature (folded into 1.0.0)")
    code, lines = check(repo)
    report(code == 0, "settlement folded into the unreleased current section passes", lines)


@_scenario("uncommitted-bump-section")
def _(report) -> None:
    repo = _base_repo()
    _write(repo / "src" / "feature.rs", "pub fn feature() {}\n")
    _commit(repo, "feat: unrecorded (debt left unpaid on purpose)")
    _write(repo / "CHANGELOG.md", BASE_CHANGELOG.replace(
        "## [1.0.0] - 2026-01-01", "## [2.0.0] - 2026-02-02\n\n### Added\n\n- placeholder.\n\n## [1.0.0] - 2026-01-01",
    ))  # uncommitted promotion: worktree top != HEAD top
    code, lines = check(repo)
    report(code == 1, "an uncommitted version section must fail closed", lines)
    report("commit the version bump" in "\n".join(lines), "the failure names the remedy", lines)


@_scenario("not-a-git-repo")
def _(report) -> None:
    repo = Path(tempfile.mkdtemp(prefix="changelog-debt-nogit-"))
    _write(repo / "CHANGELOG.md", BASE_CHANGELOG)
    code, lines = check(repo)
    report(code == 1, "a plain directory without git must fail closed", lines)


def self_test() -> int:
    failures = 0

    def report(ok: bool, what: str, lines: list[str] | None = None) -> None:
        nonlocal failures
        print(f"{'ok  ' if ok else 'FAIL'} {what}")
        if not ok:
            failures += 1
            for line in lines or []:
                print(f"     {line}")

    for name, fn in SELF_TEST_CASES:
        print(f"--- {name}")
        fn(report)

    if failures:
        print(f"FAIL: {failures} self-test assertion(s)")
        return 1
    print("changelog-debt self-test: all scenarios passed")
    return 0


def main(argv: list[str]) -> int:
    if argv == ["--self-test"]:
        return self_test()
    if argv:
        print("usage: check_changelog_debt.py [--self-test]", file=sys.stderr)
        return 2
    code, lines = check(ROOT)
    for line in lines:
        print(line)
    return code


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
