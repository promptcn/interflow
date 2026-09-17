#!/usr/bin/env python3
"""Config-reference drift guard.

Extracts every `pub <field>: <type>` declaration from the config-schema
sources and verifies each field name appears in docs/config-reference.md.
A schema change that adds, renames, or removes a field without updating
the reference fails this script (wire it into CI after `cargo test`).

Field NAMES are guarded mechanically; field DEFAULTS are not — the code
(`Default` impls, single-sourced in core `config::params`) is the truth
for values, the reference mirrors it at review time.
"""

import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SCHEMA_FILES = [
    "crates/mesh/src/config/hub.rs",
    "crates/mesh/src/config/agent.rs",
    "crates/mesh/src/config/transport.rs",
]
REFERENCE = ROOT / "docs" / "config-reference.md"

FIELD_RE = re.compile(r"^\s+pub\s+(?:r#)?(\w+)\s*:", re.MULTILINE)


def schema_fields(path: Path) -> list[str]:
    """Field names declared before the test module (production schema only)."""
    text = path.read_text(encoding="utf-8")
    cut = text.find("#[cfg(test)]")
    if cut != -1:
        text = text[:cut]
    return FIELD_RE.findall(text)


def main() -> int:
    reference = REFERENCE.read_text(encoding="utf-8")
    missing: list[str] = []
    for rel in SCHEMA_FILES:
        for field in schema_fields(ROOT / rel):
            # The reference must mention the field as a code span.
            if f"`{field}`" not in reference:
                missing.append(f"{rel}: `{field}`")
    if missing:
        print("docs/config-reference.md is missing schema fields:")
        for m in missing:
            print(f"  - {m}")
        print(
            "\nThe config schema changed without updating the reference. "
            "Update docs/config-reference.md (field list, defaults, and the "
            "reload contract) to match."
        )
        return 1
    fields = sum(len(schema_fields(ROOT / rel)) for rel in SCHEMA_FILES)
    print(f"config reference covers all {fields} schema fields")
    return 0


if __name__ == "__main__":
    sys.exit(main())
