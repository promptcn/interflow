#!/usr/bin/env bash
# Start the public ingress node from its Credential Pack.

set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "$0")" && pwd)"
INTERFLOW_BIN="${INTERFLOW_BIN:-interflow}"
PACK="${INTERFLOW_INGRESS_PACK:-$SCRIPT_DIR/dist/packs/ingress-edge}"

exec "$INTERFLOW_BIN" ingress run --pack "$PACK"
