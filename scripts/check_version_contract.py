#!/usr/bin/env python3
"""Enforce Interflow's version and rotation contract.

The product version has one source, Interflow-owned machine formats share one
compatibility epoch, and signed objects use one rotation generation. This
guard prevents localized counters and legacy field names from creeping back.

The CHANGELOG's newest versioned section must equal the workspace version —
this replaces the old hand-mirrored example cell in the versioning doc, so a
version bump that forgets the changelog promotion fails here instead of
shipping notes that lag the tag (documentation/versioning.md, "CHANGELOG").
Two structural rules ride the same section of the contract: the file must
open with a `## [Unreleased]` section (entries accumulate there between
releases — the shape the debt guard in scripts/check_changelog_debt.py
builds on), and it must never reference the private docs/ tree: the
changelog ships with the export and is never trim-stripped, so a docs/
pointer would export as a dead link (export gate 5 fails it late; this
check fails it at commit time).

Internal crate dependencies are part of the same contract: nothing is
published to crates.io (the source export is the distribution), so each one
is declared once in [workspace.dependencies] as a bare path spec and
inherited by members with `interflow-x.workspace = true`. A version literal
anywhere is a bump-time drift trap — the v0.11.0 bump left 39 stale
member-manifest pins and broke every cargo invocation at HEAD.

Local migration counters (documentation/versioning.md, "Local migration
counters") are the one sanctioned second kind of version. A counter whose
name hits FORBIDDEN_TERMS is exempt only in its registered file and only
while that file cites the legitimizing section by anchor — see
LOCAL_MIGRATION_COUNTERS below. documentation/ ships verbatim with the export,
so this script's inputs and validation are identical in the private tree and
the public CI run.
"""

from __future__ import annotations

import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SELF = Path(__file__).resolve().relative_to(ROOT).as_posix()

FORBIDDEN_TERMS = (
    "config_version",
    "schema_version",
    "FRAME_VERSION",
    "PACK_SCHEMA_VERSION",
    "HUB_CONFIG_VERSION",
    "CONFIG_VERSION",
    "WIRE_VERSION",
    "PROTOCOL_VERSION",
    "PACK_FORMAT_VERSION",
    "trust_revision",
    "policy_revision",
    "revision",
)

FORMAT_DECLARATION = re.compile(r"^\s*pub\s+const\s+FORMAT_VERSION\b", re.MULTILINE)

# The contract document this guard enforces — and the anchor target every
# local-counter declaration cites. It lives in documentation/ (the born-public
# directory that ships with the export), so both trees validate against the
# same file.
VERSIONING_DOC = Path("documentation/versioning.md")

# Declarative exemptions for local migration counters
# (documentation/versioning.md, "Local migration counters"). The terms stay in
# FORBIDDEN_TERMS; an entry suppresses its term in its file only while that
# file cites the legitimizing section by anchor — the citation in natural
# link form (documentation/versioning.md#…) IS the marker. Registration
# without the marker, the marker without registration, or an entry whose
# heading no longer exists in the doc all fail the scan. The "config_version"
# entry covers the serde default fn `legacy_config_version`: mapping an
# absent on-disk field to v1 is the other half of the counter's declaration,
# not a separate counter.
LOCAL_MIGRATION_COUNTERS = {
    ("crates/identity/src/backup.rs", "CONFIG_VERSION"): "Local migration counters",
    ("crates/identity/src/backup.rs", "config_version"): "Local migration counters",
}

# Keep-a-Changelog headings: "## [Unreleased]" or "## [X.Y.Z] - YYYY-MM-DD".
CHANGELOG_HEADING = re.compile(r"(?m)^## \[([^\]]+)\]")

ACTIVE_ROOTS = (
    Path("CHANGELOG.md"),
    Path("README.md"),
    Path("THREAT_MODEL.md"),
    Path("SECURITY.md"),
    Path("docs"),
    Path("documentation"),
    Path("examples"),
    Path("src"),
    Path("src-tauri/src"),
    Path("crates"),
    Path("scripts"),
)

HISTORICAL_DIRS = {
    "docs/backlog",
    "docs/development",
    "docs/bug",
    "docs/references",
    "docs/product",
}

GENERATED_DIRS = {
    "target",
    "node_modules",
    "dist",
    "bench-results",
}

TEXT_SUFFIXES = {".rs", ".ts", ".tsx", ".md", ".toml", ".sh", ".yml", ".yaml", ".json"}
TEXT_NAMES = {"justfile", "dockerfile"}


def toml_section(text: str, name: str) -> str:
    match = re.search(
        rf"(?ms)^\[{re.escape(name)}\]\s*$(.*?)(?=^\[|\Z)",
        text,
    )
    return match.group(1) if match else ""


def workspace_members(text: str) -> list[str]:
    section = toml_section(text, "workspace")
    match = re.search(r"(?m)^\s*members\s*=\s*\[(.*?)\]", section, re.DOTALL)
    if not match:
        return []
    return re.findall(r'"([^"]+)"', match.group(1))


def fail(messages: list[str]) -> int:
    if messages:
        print("version contract violations:", file=sys.stderr)
        for message in messages:
            print(f"  {message}", file=sys.stderr)
        return 1
    print("version contract clean")
    return 0


def is_active(path: Path) -> bool:
    rel = path.relative_to(ROOT).as_posix()
    return not any(
        rel == directory or rel.startswith(directory + "/")
        for directory in HISTORICAL_DIRS | GENERATED_DIRS
    )


def active_files() -> list[Path]:
    files: set[Path] = set()
    for root_name in ACTIVE_ROOTS:
        root = ROOT / root_name
        if not root.exists():
            continue
        if root.is_file():
            paths = [root]
        else:
            paths = [p for p in root.rglob("*") if p.is_file()]
        for path in paths:
            rel = path.relative_to(ROOT).as_posix()
            if rel == SELF or not is_active(path):
                continue
            if path.name.lower() in TEXT_NAMES or path.suffix.lower() in TEXT_SUFFIXES:
                files.add(path)
    return sorted(files)


def changelog_top_version() -> str | None:
    """The newest versioned section heading in CHANGELOG.md, if any.

    `[Unreleased]` does not count: entries accumulate there between releases
    and are promoted to a versioned section by the bump commit.
    """
    changelog = ROOT / "CHANGELOG.md"
    if not changelog.exists():
        return None
    headings = CHANGELOG_HEADING.findall(changelog.read_text(encoding="utf-8"))
    versioned = [h for h in headings if h.strip().lower() != "unreleased"]
    return versioned[0] if versioned else None


def changelog_structure_violations(text: str) -> list[str]:
    """The changelog's two always-on shape rules (documentation/versioning.md,
    "CHANGELOG"): `## [Unreleased]` opens the file — the accumulation point
    the bump commit promotes — and no line may reference the private docs/
    tree (the file exports verbatim and is never trim-stripped, so a docs/
    pointer ships as a dead link; this is the commit-time twin of the
    exporter's docs/ gate)."""
    findings: list[str] = []
    headings = CHANGELOG_HEADING.findall(text)
    if headings and headings[0].strip().lower() != "unreleased":
        findings.append(
            "CHANGELOG.md:1: must open with '## [Unreleased]' — entries accumulate "
            "there between releases (see documentation/versioning.md, \"CHANGELOG\")"
        )
    for lineno, line in enumerate(text.splitlines(), start=1):
        if re.search(r"docs/[A-Za-z0-9_.-]", line):
            findings.append(
                f"CHANGELOG.md:{lineno}: references the private docs/ tree — the "
                "changelog exports verbatim, so write self-contained entries"
            )
    return findings


def heading_anchor(heading: str) -> str:
    """GitHub-style anchor of a markdown heading."""
    slug = re.sub(r"[^\w\s-]", "", heading.strip().lower())
    return slug.replace(" ", "-")


def local_counter_exemptions(messages: list[str]) -> set[tuple[str, str]]:
    """Resolve LOCAL_MIGRATION_COUNTERS against the contract doc and the
    registered files. Each entry must name an existing section and a file
    that cites the section anchor; anything less stays a violation."""
    headings = set(
        re.findall(r"(?m)^## (.+?)\s*$", (ROOT / VERSIONING_DOC).read_text(encoding="utf-8"))
    )
    exempt: set[tuple[str, str]] = set()
    for (rel, term), heading in LOCAL_MIGRATION_COUNTERS.items():
        if heading not in headings:
            messages.append(
                f"{VERSIONING_DOC.as_posix()}: local-counter exemption for {rel}:{term} "
                f"cites section {heading!r} that does not exist"
            )
            continue
        path = ROOT / rel
        if not path.is_file():
            messages.append(f"local-counter exemption names missing file {rel}")
            continue
        marker = f"{VERSIONING_DOC.as_posix()}#{heading_anchor(heading)}"
        if marker not in path.read_text(encoding="utf-8"):
            messages.append(
                f"{rel}: registered local counter {term!r} must cite {marker} "
                "at its declaration"
            )
            continue
        exempt.add((rel, term))
    return exempt


def born_public_violations() -> list[str]:
    """documentation/ ships verbatim with the export, so it must be born
    public: no file there may reference the private docs/ tree. Nothing in
    the directory is ever export-trimmed; a private reference would ship as
    a dangling pointer."""
    findings: list[str] = []
    for path in sorted((ROOT / "documentation").rglob("*")):
        if not path.is_file():
            continue
        rel = path.relative_to(ROOT).as_posix()
        for lineno, line in enumerate(
            path.read_text(encoding="utf-8", errors="replace").splitlines(), start=1
        ):
            if re.search(r"docs/[A-Za-z0-9_.-]", line):
                findings.append(
                    f"{rel}:{lineno}: born-public file references the private docs/ tree"
                )
    return findings


def member_internal_dep_violations(member: str, text: str) -> list[str]:
    """Internal dependencies are inherited from the single root
    [workspace.dependencies] declaration (`interflow-x.workspace = true`;
    `features`/`optional` may sit beside the inherited spec). Any other
    member-manifest declaration is a literal spec — path or version — that
    can drift from the workspace version; the v0.11.0 bump left 39 stale
    pins across the tree and broke every cargo invocation at HEAD."""
    findings: list[str] = []
    package_name = re.search(r'^name = "(interflow-[\w-]+)"', text, re.M)
    for lineno, line in enumerate(text.splitlines(), start=1):
        match = re.match(r"^\s*(interflow-[\w-]+)\s*(\.|=)", line)
        if not match:
            continue
        name, joined = match.group(1), match.group(2)
        rest = line[match.end() :].strip()
        # The tokio-style self dev-dependency (`{ path = ".", features = … }`)
        # turns this crate's own features on for its integration tests. It
        # names the package itself, so there is no workspace version to
        # drift from — the one literal spec a member may carry.
        if (
            package_name
            and name == package_name.group(1)
            and rest.startswith("{")
            and re.search(r'\bpath\s*=\s*"\."', rest)
        ):
            continue
        inherited = (joined == "." and rest == "workspace = true") or (
            rest.startswith("{") and re.search(r"\bworkspace\s*=\s*true\b", rest)
        )
        if not inherited:
            findings.append(
                f"{member}/Cargo.toml:{lineno}: internal dependency {name} must be "
                f"inherited (`{name}.workspace = true`), not declared with a "
                "literal spec"
            )
    return findings


def root_internal_dep_violations(text: str) -> list[str]:
    """The one place an internal dependency may be declared is
    [workspace.dependencies], and the spec must be path-only: nothing is
    published to crates.io (the source export is the distribution), so no
    version literal needs to exist. If publishing ever starts, add the
    `version` key here — one file — and flip this check to value-match the
    workspace version."""
    findings: list[str] = []
    in_deps = False
    for lineno, line in enumerate(text.splitlines(), start=1):
        if line.startswith("["):
            in_deps = line.strip() == "[workspace.dependencies]"
            continue
        if not in_deps:
            continue
        match = re.match(r"^\s*(interflow-[\w-]+)\s*=\s*\{(.*)\}\s*$", line)
        if match and re.search(r"\bversion\s*=", match.group(2)):
            findings.append(
                f"Cargo.toml:{lineno}: {match.group(1)} declaration must stay "
                "path-only — a version literal drifts on every bump (add one "
                "only when publishing starts)"
            )
    return findings


def main() -> int:
    messages: list[str] = []

    cargo_text = (ROOT / "Cargo.toml").read_text(encoding="utf-8")
    workspace_package = toml_section(cargo_text, "workspace.package")
    version_match = re.search(r'(?m)^\s*version\s*=\s*"([^"]+)"\s*$', workspace_package)
    workspace_version = version_match.group(1) if version_match else None
    if not workspace_version:
        messages.append("Cargo.toml: [workspace.package].version is required")

    package_json = json.loads((ROOT / "package.json").read_text(encoding="utf-8"))
    npm_version = package_json.get("version")
    if workspace_version != npm_version:
        messages.append(
            f"package.json version {npm_version!r} must equal workspace version {workspace_version!r}"
        )

    package_lock = json.loads((ROOT / "package-lock.json").read_text(encoding="utf-8"))
    lock_version = package_lock.get("packages", {}).get("", {}).get("version")
    if workspace_version != lock_version:
        messages.append(
            f"package-lock root version {lock_version!r} must equal {workspace_version!r}"
        )

    if not (ROOT / "CHANGELOG.md").exists():
        messages.append("CHANGELOG.md is required (Keep-a-Changelog, exported)")
    else:
        changelog_text = (ROOT / "CHANGELOG.md").read_text(encoding="utf-8")
        messages.extend(changelog_structure_violations(changelog_text))
        top = changelog_top_version()
        if top is None:
            messages.append("CHANGELOG.md has no versioned section (## [X.Y.Z] - date)")
        elif workspace_version != top:
            messages.append(
                f"CHANGELOG newest versioned section {top!r} must equal workspace version {workspace_version!r}"
            )

    if not (ROOT / VERSIONING_DOC).is_file():
        messages.append(
            f"{VERSIONING_DOC.as_posix()} is required — it is the contract this guard enforces"
        )
        exempt: set[tuple[str, str]] = set()
    else:
        exempt = local_counter_exemptions(messages)
        messages.extend(born_public_violations())

    messages.extend(root_internal_dep_violations(cargo_text))

    members = workspace_members(cargo_text)
    for member in members:
        manifest_path = ROOT / member / "Cargo.toml"
        if not manifest_path.exists():
            messages.append(f"{member}: Cargo.toml is missing")
            continue
        manifest_text = manifest_path.read_text(encoding="utf-8")
        package_section = toml_section(manifest_text, "package")
        if re.search(r"(?m)^\s*version\s*=\s*\"", package_section):
            messages.append(f"{member}/Cargo.toml: package version must inherit from workspace")
        if not re.search(r"(?m)^\s*version\.workspace\s*=\s*true\s*$", package_section):
            messages.append(f"{member}/Cargo.toml: package version must inherit from workspace")
        messages.extend(member_internal_dep_violations(member, manifest_text))

    for path in active_files():
        rel = path.relative_to(ROOT).as_posix()
        try:
            text = path.read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError):
            continue
        for lineno, line in enumerate(text.splitlines(), start=1):
            for term in FORBIDDEN_TERMS:
                if term in line and (rel, term) not in exempt:
                    messages.append(f"{rel}:{lineno}: forbidden legacy term {term!r}")
        if FORMAT_DECLARATION.search(text) and rel != "crates/contract/src/lib.rs":
            messages.append(f"{rel}: FORMAT_VERSION may only be declared by interflow-contract")

    return fail(messages)


if __name__ == "__main__":
    raise SystemExit(main())
