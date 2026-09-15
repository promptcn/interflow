#!/bin/bash
# Start interflow-expose expose (LAN-machine side) — production-ready
#
# Purpose: expose the local 8080 port behind a public domain via the public
# edge hub. agent_id comes from profile.toml (it must match the edge's
# routes.toml).
#
# On first run, --save persists the arguments into ~/.config/interflow/profile.toml;
# afterwards `expose <port>` alone is enough.

set -euo pipefail

cd "$(dirname "$0")"

: "${INTERFLOW_EDGE_TOKEN:?INTERFLOW_EDGE_TOKEN must be set (same value as the public edge side)}"
export INTERFLOW_EDGE_TOKEN

LOCAL_PORT="${1:-8080}"                          # local service port

exec /usr/local/bin/interflow-expose expose "${LOCAL_PORT}" \
    --hub https://example.com:16666 \
    --token "${INTERFLOW_EDGE_TOKEN}" \
    --agent-id desktop \
    --ca-path certs/ca.crt \
    --save
