#!/usr/bin/env python3
"""Single source of the public-export trim patterns for README.md / justfile.

docs/ never exports, and some private-only tooling must not appear in the
public tree — the exporter rewrites those references in the PUBLISHED copies
instead of maintaining two documents. This module is the one place those
transformations live:

- export_public.sh applies them to the exported copies (`--apply-readme` /
  `--apply-justfile`).
- `just ci` and the export preflight dry-run `--verify` against the PRIVATE
  tree so pattern drift fails at commit time, not at export time (a pattern
  once drifted for days because nothing checked it between exports).

Each pattern must match its private source EXACTLY once. `--verify` is a
private-tree check by design: the published copies have the patterns applied
and will not match.
"""

from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

# (name, old, new) — applied to the public copy of README.md.
README_TRIMS = [
    (
        "layout-tree",
        "├── examples/      ← generic, runnable scenario examples\n"
        "├── deployments/   ← environment-specific deployment configs (private)\n"
        "├── docs/          ← backlog (research / TODO) / development (implementation notes) / product (decision records)\n",
        "├── examples/      ← generic, runnable scenario examples\n",
    ),
    (
        "quickstart-doc-guides",
        "See\n[docs/identity-first.md](docs/identity-first.md) for packs, rotation,\n"
        "revocation, `doctor`, and the registrar; see [docs/versioning.md](docs/versioning.md)\n"
        "for the product-version / format-version / generation model.",
        "See the deployment guide for packs, rotation, revocation, `doctor`, and\n"
        "the registrar; see the versioning guide for the product-version /\n"
        "format-version / generation model.",
    ),
    (
        "adr-binary-size",
        'both transports available by default": `docs/product/2026-09-12-binary-size-positioning.md`',
        'both transports available by default"',
    ),
    (
        "adr-plugin-system",
        "keeping the hub pure: `docs/product/2026-09-12-plugin-system-positioning.md`",
        "keeping the hub pure",
    ),
    (
        "wire-format-ref",
        "reason codes — docs/design/wire-format.md)",
        "reason codes)",
    ),
    (
        "comparison-anchors",
        "anchors in `docs/backlog/2026-09-11-udp-and-quic-research.md`.",
        "anchors in [THREAT_MODEL.md](THREAT_MODEL.md).",
    ),
    (
        "techstack-config-reference",
        "defaults single-sourced in code — see `docs/config-reference.md`)",
        "defaults single-sourced in code)",
    ),
]

# (name, old, new) — applied to the public copy of justfile. The
# config-reference guard drives a private-side script against a private-side
# doc (neither exports), so the recipe and its `ci` dependency drop out of
# the public tree; version-contract reads docs/versioning.md (also private).
JUSTFILE_TRIMS = [
    (
        "config-reference-recipe",
        "# Config-reference drift guard (docs/config-reference.md never exports, so\n"
        "# public CI cannot run it — enforced here and by export_public.sh preflight)\n"
        "config-reference:\n"
        "    python3 scripts/check_config_reference.py\n"
        "\n",
        "",
    ),
    (
        "ci-line",
        "ci: fmt-check lint test config-reference version-contract product-language doc-surfaces\n",
        "ci: fmt-check lint test product-language doc-surfaces\n",
    ),
]


def apply_to_file(path: Path, trims: list[tuple[str, str, str]]) -> None:
    text = path.read_text(encoding="utf-8")
    for name, old, new in trims:
        n = text.count(old)
        if n != 1:
            sys.exit(f"FAIL: trim pattern {name!r} matched {n} times (expected 1) in {path}")
        text = text.replace(old, new)
    path.write_text(text, encoding="utf-8")


def verify(private_root: Path) -> int:
    failures = 0
    for file_name, trims in (("README.md", README_TRIMS), ("justfile", JUSTFILE_TRIMS)):
        path = private_root / file_name
        if not path.is_file():
            print(f"FAIL: {file_name} missing under {private_root}")
            return 1
        text = path.read_text(encoding="utf-8")
        for name, old, _new in trims:
            n = text.count(old)
            if n != 1:
                failures += 1
            print(f"{'OK' if n == 1 else 'MISMATCH':8} {file_name}: {name}: {n} match(es)")
    if failures:
        print("FAIL: export trim patterns drifted from the private sources — update export_trim.py together with README.md/justfile")
        return 1
    print("export trim patterns verified: each matches the private tree exactly once")
    return 0


def main(argv: list[str]) -> int:
    if argv == ["--verify"]:
        return verify(ROOT)
    if len(argv) == 2 and argv[0] == "--apply-readme":
        apply_to_file(Path(argv[1]), README_TRIMS)
        print("==> README trimmed for the public tree")
        return 0
    if len(argv) == 2 and argv[0] == "--apply-justfile":
        apply_to_file(Path(argv[1]), JUSTFILE_TRIMS)
        print("==> justfile trimmed for the public tree")
        return 0
    print(
        "usage: export_trim.py --verify | --apply-readme <path> | --apply-justfile <path>",
        file=sys.stderr,
    )
    return 2


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
