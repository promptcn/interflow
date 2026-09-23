#!/usr/bin/env python3
"""Retired-surface deny-list for user-facing docs.

User-facing documentation must not teach CLI flags, binary names, or config
shapes that no longer exist — they died with the `interflow-expose` binary
and the pre-v6 configuration model, and every one of them resurfaced at
least once after the migration. The dated archives under docs/ (backlog /
bug / development / design / deployment / product) are exempt: they are
records, not user docs.

Wired into `just ci` and the public-export preflight. Also ships with the
public export, where private-only targets simply do not exist and are
skipped.
"""

from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

# Retired CLI flags / binary / command shapes (the `interflow-expose` binary
# and the pre-v6 surface; `--transport` is the flag form — the live config
# field is `transport = "…"` in TOML).
RETIRED_TERMS = (
    "interflow-expose",
    # Engine TOML file face (removed 2026-09-22 with the other old-format
    # compatibility paths): the mesh CLI is pack-only.
    "--config",
    "hub.toml",
    "agent.toml",
    "routes.toml",
    "generate-certs.sh",
    "--quic-listen",
    "--transport",
    "--stream-idle-timeout-secs",
    "--proxy-protocol",
    "--x-forwarded-for",
    "--trusted-proxy",
    "--log-level",
    "--client-ca",
    "--hub-cert",
    "--hub-key",
    "--gateway-cert",
    "--gateway-ca",
    "pki import",
)

# Engine-level config shape: legitimate in the expert reference and the
# engine examples, never in product docs.
MESH_ONLY_TERMS = ("[[auth.tenants]]",)

# Product docs: every retired surface, plus engine-only shapes.
PRODUCT_TARGETS: tuple[tuple[Path, tuple[str, ...]], ...] = (
    (Path("README.md"), RETIRED_TERMS + MESH_ONLY_TERMS),
    (Path("examples"), RETIRED_TERMS + MESH_ONLY_TERMS),
    (Path("docs/identity-first.md"), RETIRED_TERMS + MESH_ONLY_TERMS),
    (Path("docs/deployment.md"), RETIRED_TERMS + MESH_ONLY_TERMS),
    (Path("docs/config-reference.md"), RETIRED_TERMS),
    (Path("docs/versioning.md"), RETIRED_TERMS + MESH_ONLY_TERMS),
    (Path("crates/mesh/dev-examples"), RETIRED_TERMS),
)

# Engineering docs: the crate name `interflow-expose` is legitimate here
# (the lib lives on); flags and engine shapes are still checked.
ENGINEERING_TERMS = tuple(t for t in RETIRED_TERMS if t != "interflow-expose")
ENGINEERING_TARGETS: tuple[tuple[Path, tuple[str, ...]], ...] = (
    (Path("SECURITY.md"), ENGINEERING_TERMS),
    (Path("THREAT_MODEL.md"), ENGINEERING_TERMS),
)


def iter_markdown(target: Path):
    if target.is_file():
        yield target
        return
    for path in sorted(target.rglob("*.md")):
        if "certs" in path.parts:
            continue  # generated material is never scanned
        yield path


def main() -> int:
    violations: list[str] = []
    for target, terms in PRODUCT_TARGETS + ENGINEERING_TARGETS:
        path = ROOT / target
        if not path.exists():
            continue  # private-only target absent in the public export
        for doc in iter_markdown(path):
            rel = doc.relative_to(ROOT)
            text = doc.read_text(encoding="utf-8")
            for lineno, line in enumerate(text.splitlines(), 1):
                for term in terms:
                    if term in line:
                        violations.append(
                            f"{rel}:{lineno}: retired surface {term!r}: {line.strip()[:90]}"
                        )
    if violations:
        print("retired surface references in user-facing docs:")
        for violation in violations:
            print(f"  {violation}")
        return 1
    print("doc surfaces clean: no retired CLI/binary/config references")
    return 0


if __name__ == "__main__":
    sys.exit(main())
