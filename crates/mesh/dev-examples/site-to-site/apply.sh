#!/usr/bin/env bash
# Product path: render Credential Packs from the manifest (operator machine).
# Output lands in ./dist (git-ignored): hub + agent packs + systemd units.
# The issuer/ directory is the offline issuer store — keep it secret.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CLI_BIN="${INTERFLOW_CLI_BIN:-$SCRIPT_DIR/../../../../target/release/interflow}"

exec "$CLI_BIN" plan apply \
  --manifest "$SCRIPT_DIR/interflow.toml" \
  --issuer "$SCRIPT_DIR/issuer" \
  --out "$SCRIPT_DIR/dist"
