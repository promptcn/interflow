#!/usr/bin/env python3
"""Product-language guard: user-facing surfaces never use design generation
numbers (v4/v5/v6).

Interflow has exactly one deployment model. Design-generation labels are
internal archaeology: they may live in the dated archive under docs/
(backlog / development / bug / product — historical records are never
rewritten) and in machine schema fields, but they must not leak into product
language: README, user docs, examples, CLI help/strings, or GUI strings.

Runs green in both the private tree (docs/ present) and the public export
(docs/ absent): every scanned root is optional.

Usage: python3 scripts/check_product_language.py [repo-root]
Exit: 0 clean, 1 findings (listed as path:line:text).
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

# Design generations that must never appear in product language.
PATTERN = re.compile(r"(?i)(?<![A-Za-z0-9_])[vV][456](?![A-Za-z0-9_])")

# IPv4/IPv6/uuid-v4 are legitimate version words, not design generations.
LEGIT_CONTEXT = re.compile(r"(?i)ipv?\d|ipaddr|uuid")

# Source files: only comments and string literals carry user-facing language;
# identifiers like IpAddr::V4 or a local `v6` are not product words.
SOURCE_SUFFIXES = {".rs", ".ts", ".tsx"}

# File suffixes treated as plain text surfaces.
TEXT_SUFFIXES = {".md", ".toml", ".sh", ".conf", ".yml", ".yaml", ".json"}

# Exact filenames without a useful suffix.
EXACT_NAMES = {"justfile", "dockerfile"}

# User-facing roots (all optional — the public export has no docs/).
ROOTS = [
    "README.md",
    "THREAT_MODEL.md",
    "SECURITY.md",
    "justfile",
    "Dockerfile",
    "docs",
    "examples",
    "src",
    "src-tauri/src",
    "crates",
    "scripts",
]

# Historical archive / generated / third-party trees that are exempt.
EXEMPT_DIRS = {
    "docs/backlog",
    "docs/development",
    "docs/bug",
    "docs/references",
    "docs/product",
    "node_modules",
    "target",
    "dist",
    "bench-results",
    "deployments",
}

# Generated or lock files that may legitimately carry other tooling's
# version language.
EXEMPT_FILES = {"package-lock.json"}


def iter_files(root: Path) -> list[Path]:
    out: list[Path] = []
    for name in ROOTS:
        path = root / name
        if not path.exists():
            continue
        if path.is_file():
            out.append(path)
            continue
        for p in path.rglob("*"):
            if not p.is_file():
                continue
            rel = p.relative_to(root).as_posix()
            if any(rel == d or rel.startswith(d + "/") for d in EXEMPT_DIRS):
                continue
            if p.name in EXEMPT_FILES:
                continue
            if p.name.lower() in EXACT_NAMES or p.suffix.lower() in (
                SOURCE_SUFFIXES | TEXT_SUFFIXES
            ):
                out.append(p)
    return sorted(set(out))


def string_regions(line: str) -> list[tuple[int, int]]:
    """Naive double-quoted string regions (enough for guard purposes)."""
    regions: list[tuple[int, int]] = []
    start = None
    escaped = False
    for i, ch in enumerate(line):
        if escaped:
            escaped = False
        elif ch == "\\":
            escaped = True
        elif ch == '"':
            if start is None:
                start = i
            else:
                regions.append((start, i + 1))
                start = None
    if start is not None:
        regions.append((start, len(line)))
    return regions


def source_line_hits(line: str) -> list[re.Match[str]]:
    hits: list[re.Match[str]] = []
    regions = string_regions(line)
    in_string = lambda i: any(a <= i < b for a, b in regions)
    # Comment part: first // outside a string.
    comment_at = None
    for i in range(len(line) - 1):
        if line[i : i + 2] == "//" and not in_string(i):
            comment_at = i
            break
    for m in PATTERN.finditer(line):
        if LEGIT_CONTEXT.search(line[: m.start()][-64:]):
            continue
        if comment_at is not None and m.start() > comment_at:
            hits.append(m)
        elif in_string(m.start()):
            hits.append(m)
    return hits


def text_line_hits(line: str) -> list[re.Match[str]]:
    return [
        m
        for m in PATTERN.finditer(line)
        if not LEGIT_CONTEXT.search(line)
    ]


def main() -> int:
    root = Path(sys.argv[1]) if len(sys.argv) > 1 else Path(__file__).resolve().parent.parent
    findings: list[str] = []
    for path in iter_files(root):
        try:
            text = path.read_text(encoding="utf-8")
        except (UnicodeDecodeError, OSError):
            continue
        source = path.suffix.lower() in SOURCE_SUFFIXES and path.name.lower() not in EXACT_NAMES
        for lineno, line in enumerate(text.splitlines(), start=1):
            hits = source_line_hits(line) if source else text_line_hits(line)
            if hits:
                rel = path.relative_to(root).as_posix()
                findings.append(f"{rel}:{lineno}:{line.strip()}")
    if findings:
        print("design generation numbers leaked into product language:", file=sys.stderr)
        for f in findings:
            print(f"  {f}", file=sys.stderr)
        print(
            "\nspeak in product concepts (identity, pack, ingress, agent, service,\n"
            "route) — generation labels belong only in the dated archive and\n"
            "machine schema fields.",
            file=sys.stderr,
        )
        return 1
    print("product language clean: no design generation labels")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
