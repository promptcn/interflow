#!/usr/bin/env python3
"""Enforce the CLI version-surface contract (documentation/versioning.md,
"Product version").

Every clap `Parser` root in the workspace must declare
`version = interflow_buildinfo::VERSION_WITH_TAG`, so `--version` (and its
`-V` short form) answers `name <semver> (<build tag>)` with the one shared
build identity on every binary — the same line `interflow-mesh version`
and `interflow-cli --version` print. Two drift shapes are the contract's
targets, both already paid for once:

- **No version face**: `interflow-mesh` shipped a `version` subcommand but
  no flag until 2026-11-01 — one product, two CLIs, two ways to ask
 .
- **A bare `version`**: clap's default takes CARGO_PKG_VERSION and prints
  a tag-less semver, leaving "which code is this" unanswered — the exact
  regression (internal design notes) closed.

The rule is fail-closed with no opt-out syntax (the shape
check_changelog_debt.py argued for): a Parser root without the shared
const violates wherever it lives — dev CLIs (soak, the benches) and
product CLIs answer version the same way, and a guard with an escape
hatch is how the drift comes back. The scan covers every workspace
member's `src/` and `benches/` trees (integration tests never ship a CLI;
fuzz/ is excluded from the workspace entirely). Zero Parser roots found
is itself a failure: it means the walker went blind, not that the
contract holds.

Runs identically in the private tree (`just version-surface`, `just ci`,
the export preflight) and the public tree (public CI): the inputs —
crate sources — ship verbatim with the export.
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

PINNED_VERSION = re.compile(
    r"version\s*=\s*interflow_buildinfo::VERSION_WITH_TAG"
)
# clap's default `version` (no `=`): tag-less CARGO_PKG_VERSION — reported
# as its own shape so the message names the actual regression.
BARE_VERSION = re.compile(r"(?<![\w:])version\b(?!\s*=)")
# `#[derive(Parser)]` / `#[derive(clap::Parser)]` / `#[derive(Parser, Debug)]`
DERIVE_RE = re.compile(r"#\[derive\(([^)]*)\)\]")
# The root's `#[command(...)]` attributes sit between the derive and the
# struct declaration; the struct keyword bounds the harvest. Nested `Args`
# structs and `Subcommand` enums derive other traits and are not roots.
STRUCT_RE = re.compile(r"\b(?:pub(?:\([^)]*\))?\s+)?struct\b")
COMMAND_OPEN_RE = re.compile(r"#\[command\(")


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


def command_attribute_bodies(text: str, start: int, bound: int) -> list[str]:
    """Full `#[command(...)]` bodies in `[start, bound)`.

    Parentheses nest (`env!("CARGO_PKG_NAME")`), so each body is read with
    a depth counter instead of a regex.
    """
    bodies: list[str] = []
    pos = start
    while True:
        opened = COMMAND_OPEN_RE.search(text, pos, bound)
        if opened is None:
            return bodies
        depth = 0
        for i in range(opened.end() - 1, min(bound, len(text))):
            if text[i] == "(":
                depth += 1
            elif text[i] == ")":
                depth -= 1
                if depth == 0:
                    bodies.append(text[opened.end():i])
                    pos = i + 1
                    break
        else:
            # Unterminated attribute inside the window — return what closed;
            # the missing pinned version below reports the site either way.
            return bodies


def parser_root_violations(rel: str, text: str) -> list[str]:
    findings: list[str] = []
    for derive in DERIVE_RE.finditer(text):
        traits = [t.strip() for t in derive.group(1).split(",")]
        if not any(t == "Parser" or t.endswith("::Parser") for t in traits):
            continue
        struct = STRUCT_RE.search(text, derive.end())
        bound = struct.start() if struct else len(text)
        joined = "\n".join(command_attribute_bodies(text, derive.end(), bound))
        lineno = text.count("\n", 0, derive.start()) + 1
        if PINNED_VERSION.search(joined):
            continue
        if BARE_VERSION.search(joined):
            findings.append(
                f"{rel}:{lineno}: Parser root sets a bare `version` (clap "
                "default: CARGO_PKG_VERSION, no build tag) — pin it: "
                "version = interflow_buildinfo::VERSION_WITH_TAG"
            )
        else:
            findings.append(
                f"{rel}:{lineno}: Parser root has no version face — add "
                "version = interflow_buildinfo::VERSION_WITH_TAG to its "
                "#[command(...)] so `--version`/`-V` answers with the "
                "shared build identity"
            )
    return findings


def fail(messages: list[str]) -> int:
    if messages:
        print("version surface violations:", file=sys.stderr)
        for message in messages:
            print(f"  {message}", file=sys.stderr)
        return 1
    print("version surface clean")
    return 0


def main() -> int:
    messages: list[str] = []

    cargo_text = (ROOT / "Cargo.toml").read_text(encoding="utf-8")
    members = workspace_members(cargo_text)
    if not members:
        return fail(["Cargo.toml: [workspace].members is required to locate CLIs"])

    roots_seen = 0
    for member in members:
        base = ROOT / member
        for sub in ("src", "benches"):
            tree = base / sub
            if not tree.is_dir():
                continue
            for path in sorted(tree.rglob("*.rs")):
                rel = path.relative_to(ROOT).as_posix()
                try:
                    text = path.read_text(encoding="utf-8")
                except (OSError, UnicodeDecodeError):
                    continue
                roots_seen += sum(
                    1
                    for derive in DERIVE_RE.finditer(text)
                    if any(
                        t.strip() == "Parser" or t.strip().endswith("::Parser")
                        for t in derive.group(1).split(",")
                    )
                )
                messages.extend(parser_root_violations(rel, text))

    if roots_seen == 0:
        messages.append(
            "no clap Parser roots found in any workspace member — the walker "
            "is blind, not the contract satisfied"
        )

    return fail(messages)


if __name__ == "__main__":
    raise SystemExit(main())
