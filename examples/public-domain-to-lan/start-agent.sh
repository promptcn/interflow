#!/usr/bin/env bash
# Start the in-network agent from its Credential Pack.

set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "$0")" && pwd)"
INTERFLOW_BIN="${INTERFLOW_BIN:-interflow}"
PACK="${INTERFLOW_AGENT_PACK:-$SCRIPT_DIR/dist/packs/agent-lan-agent}"

exec "$INTERFLOW_BIN" agent run --pack "$PACK"
