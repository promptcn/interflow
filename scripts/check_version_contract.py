#!/usr/bin/env python3
"""Enforce Interflow's version and rotation contract.

The product version has one source, Interflow-owned machine formats share one
compatibility epoch, and signed objects use one rotation generation. This
guard prevents localized counters and legacy field names from creeping back.
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

ACTIVE_ROOTS = (
    Path("README.md"),
    Path("THREAT_MODEL.md"),
    Path("SECURITY.md"),
    Path("docs"),
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

    members = workspace_members(cargo_text)
    for member in members:
        manifest_path = ROOT / member / "Cargo.toml"
        if not manifest_path.exists():
            messages.append(f"{member}: Cargo.toml is missing")
            continue
        package_section = toml_section(manifest_path.read_text(encoding="utf-8"), "package")
        if re.search(r"(?m)^\s*version\s*=\s*\"", package_section):
            messages.append(f"{member}/Cargo.toml: package version must inherit from workspace")
        if not re.search(r"(?m)^\s*version\.workspace\s*=\s*true\s*$", package_section):
            messages.append(f"{member}/Cargo.toml: package version must inherit from workspace")

    for path in active_files():
        rel = path.relative_to(ROOT).as_posix()
        try:
            text = path.read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError):
            continue
        for lineno, line in enumerate(text.splitlines(), start=1):
            for term in FORBIDDEN_TERMS:
                if term in line:
                    messages.append(f"{rel}:{lineno}: forbidden legacy term {term!r}")
        if FORMAT_DECLARATION.search(text) and rel != "crates/contract/src/lib.rs":
            messages.append(f"{rel}: FORMAT_VERSION may only be declared by interflow-contract")

    return fail(messages)


if __name__ == "__main__":
    raise SystemExit(main())
