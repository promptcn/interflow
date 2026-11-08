#!/usr/bin/env python3
"""Binary-roster single-source guard.

The release binaries live in exactly one list — `scripts/lib/binaries.list`.
The build scripts derive their `--bin` flags and ship loops from it;
`.github/workflows/release.yml` cannot read files into its `run:` steps, so
it stays hand-written, and THIS guard asserts the two spellings can never
drift: the workflow names every roster member (plus their Windows `.exe`
selves) and no binary-shaped stranger. Adding a binary means editing the
roster and the workflow together — the guard reddens the moment only one of
the two is touched.

Also asserts the build scripts carry no literal `--bin interflow-` flags
(the roster is their only source).
"""

import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
ROSTER = ROOT / "scripts/lib/binaries.list"
WORKFLOW = ROOT / ".github/workflows/release.yml"
BUILD_SCRIPTS = [
    ROOT / "scripts/build-linux.sh",
    ROOT / "scripts/build-macos.sh",
    ROOT / "scripts/build-windows.sh",
]
# The binary names' suffixes — a workflow token ending in one of these (with
# or without `.exe`) is a release binary and must sit on the roster.
BINARY_STEMS = ("interflow-cli", "interflow-mesh", "interflow-registrar")


def fail(message: str) -> None:
    print(f"binary roster: {message}")
    sys.exit(1)


def main() -> None:
    roster = [
        line.strip()
        for line in ROSTER.read_text().splitlines()
        if line.strip() and not line.startswith("#")
    ]
    if not roster:
        fail("scripts/lib/binaries.list carries no binaries")
    roster_set = set(roster)
    if len(roster) != len(roster_set):
        fail("scripts/lib/binaries.list carries duplicates")

    # The build scripts source the roster and never spell a --bin flag.
    for script in BUILD_SCRIPTS:
        text = script.read_text()
        if "lib/binaries.list" not in text:
            fail(f"{script.name} does not source lib/binaries.list")
        if re.search(r"--bin interflow-", text):
            fail(
                f"{script.name} spells a literal --bin interflow- flag; "
                "the roster is the only source"
            )

    # The workflow names exactly the roster (base + .exe forms), nothing else.
    workflow = WORKFLOW.read_text()
    named = set(re.findall(r"interflow-[a-z0-9._-]+", workflow))
    binary_shaped = {
        name
        for name in named
        if name.rsplit(".", 1)[0] in BINARY_STEMS or name in BINARY_STEMS
    }
    missing = roster_set - named
    extra = binary_shaped - roster_set - {f"{b}.exe" for b in roster_set}
    if missing:
        fail(
            f".github/workflows/release.yml never names {sorted(missing)} — add "
            "them to the build and stage steps (roster: scripts/lib/binaries.list)"
        )
    if extra:
        fail(
            f".github/workflows/release.yml names {sorted(extra)} which the "
            "roster does not carry — update the roster or the workflow"
        )
    print(f"binary roster clean: {len(roster)} binaries, one list, workflow in lockstep")


if __name__ == "__main__":
    main()
