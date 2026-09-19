#!/usr/bin/env bash
# Start the LAN expose agent for the public-domain-to-lan example.

set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "$0")" && pwd)"
if [ -n "${INTERFLOW_CERTS_DIR:-}" ]; then
    case "$INTERFLOW_CERTS_DIR" in
        /*) CERTS="$INTERFLOW_CERTS_DIR" ;;
        *) CERTS="$SCRIPT_DIR/$INTERFLOW_CERTS_DIR" ;;
    esac
else
    CERTS="$SCRIPT_DIR/certs"
fi
EXPOSE_BIN="${INTERFLOW_EXPOSE_BIN:-interflow-expose}"
HUB_URL="${INTERFLOW_HUB_URL:-https://hub.example.com:16666}"
LOCAL_PORT="${1:-3000}"

exec "$EXPOSE_BIN" expose "$LOCAL_PORT" \
    --hub "$HUB_URL" \
    --client-cert "$CERTS/agents/lan-agent.crt" \
    --client-key "$CERTS/agents/lan-agent.key" \
    --agent-id lan-agent \
    --ca-path "$CERTS/tenants/demo-ca.crt"
