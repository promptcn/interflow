#!/usr/bin/env bash
# Start the public-server edge for the public-domain-to-lan example.

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
AUDIT_PATH="${INTERFLOW_AUDIT_PATH:-/tmp/interflow-example-edge-audit.jsonl}"

exec "$EXPOSE_BIN" edge \
    --listen 0.0.0.0:8443 \
    --hub-listen 0.0.0.0:16666 \
    --routes "$SCRIPT_DIR/routes.toml" \
    --client-ca "demo=$CERTS/tenants/demo-ca.crt" \
    --hub-cert "$CERTS/hub.crt" \
    --hub-key "$CERTS/hub.key" \
    --x-forwarded-for required \
    --audit-path "$AUDIT_PATH" \
    --new-conn-rate-per-ip-per-minute 30
