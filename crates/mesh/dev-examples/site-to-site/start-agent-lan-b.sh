#!/usr/bin/env bash
# Start the LAN B egress agent.

set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "$0")" && pwd)"
MESH_BIN="${INTERFLOW_MESH_BIN:-interflow-mesh}"

exec "$MESH_BIN" agent --pack "$SCRIPT_DIR/dist/packs/agent-lan-b"
