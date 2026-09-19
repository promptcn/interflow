#!/usr/bin/env bash
# Start the site-to-site example hub.

set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "$0")" && pwd)"
MESH_BIN="${INTERFLOW_MESH_BIN:-interflow-mesh}"

exec "$MESH_BIN" hub --config "$SCRIPT_DIR/hub.toml"
